import os
import re
import json
import base64
import hashlib
import urllib.parse
import requests
import yaml
from concurrent.futures import ThreadPoolExecutor

# ========================================================
# 1. 通用节点链接反向解码器 (支持明文与复杂参数解析)
# ========================================================
def parse_v2ray_url(url):
    url = url.strip()
    if not url:
        return None
    try:
        if url.startswith("vmess://"):
            b64_content = url.replace("vmess://", "")
            b64_content += "=" * ((4 - len(b64_content) % 4) % 4)
            dec_json = base64.b64decode(b64_content).decode("utf-8")
            j = json.loads(dec_json)
            return {
                "name": j.get("ps", "VMess Node"),
                "type": "vmess",
                "server": j.get("add"),
                "port": int(j.get("port", 443)),
                "uuid": j.get("id"),
                "alterId": int(j.get("aid", 0)),
                "cipher": "auto",
                "tls": True if j.get("tls") == "tls" else False,
                "network": j.get("net", "tcp"),
                "ws-opts": {"path": j.get("path", "")} if j.get("net") == "ws" else None
            }
        elif url.startswith("ss://"):
            if "#" in url:
                url, name_part = url.split("#", 1)
                name = urllib.parse.unquote(name_part)
            else:
                name = "Shadowsocks Node"
                
            stripped_url = url.replace("ss://", "")
            if "@" in stripped_url:
                credentials, server_part = stripped_url.split("@", 1)
                credentials += "=" * ((4 - len(credentials) % 4) % 4)
                dec_cred = base64.b64decode(credentials).decode("utf-8")
                cipher, password = dec_cred.split(":", 1)
                server, port = server_part.split(":", 1)
                return {
                    "name": name,
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": cipher,
                    "password": password
                }
    except Exception:
        pass
    return None

# ========================================================
# 2. 核心清洗与指纹去重逻辑 (根据服务器+端口+密码计算MD5)
# ========================================================
def get_node_fingerprint(node):
    try:
        server = node.get("server") or ""
        port = str(node.get("port") or "")
        uuid = node.get("uuid") or node.get("password") or ""
        if not server or not port:
            return None
        return hashlib.md5(f"{server}:{port}:{uuid}".encode("utf-8")).hexdigest()
    except Exception:
        return None

def rename_node(name, index):
    name = name.upper()
    if any(k in name for k in ["香港", "HK", "HONGKONG"]):
        return f"🇭🇰 HK-香港 {index:02d}"
    elif any(k in name for k in ["日本", "JP", "JAPAN"]):
        return f"🇯🇵 JP-日本 {index:02d}"
    elif any(k in name for k in ["美国", "US", "UNITED STATES"]):
        return f"🇺🇸 US-美国 {index:02d}"
    elif any(k in name for k in ["台湾", "TW", "TAIWAN"]):
        return f"🇹🇼 TW-台湾 {index:02d}"
    elif any(k in name for k in ["新加坡", "SG", "SINGAPORE"]):
        return f"🇸🇬 SG-新加坡 {index:02d}"
    elif any(k in name for k in ["韩国", "KR", "KOREA"]):
        return f"🇰🇷 KR-韩国 {index:02d}"
    else:
        return f"🌐 🌍 其它地区 {index:02d}"

def unique_and_clean_nodes(raw_nodes):
    seen_fingerprints = set()
    cleaned_nodes = []
    geo_counters = {}
    
    for node in raw_nodes:
        if not node:
            continue
        fingerprint = get_node_fingerprint(node)
        if not fingerprint or fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)
        
        orig_name = node.get("name", "🚀 节点")
        temp_name = rename_node(orig_name, 1)
        geo_key = temp_name.split()[0]
        
        geo_counters[geo_key] = geo_counters.get(geo_key, 0) + 1
        node["name"] = rename_node(orig_name, geo_counters[geo_key])
        
        cleaned_nodes.append(node)
    return cleaned_nodes

# ========================================================
# 3. AI 规则集分流生成 (针对 OpenAI / Claude 定制策略)
# ========================================================
def generate_clash_yaml(nodes, output_path):
    all_node_names = [node["name"] for node in nodes]
    if not all_node_names:
        all_node_names = ["DIRECT"]

    ai_friendly_nodes = [
        name for name in all_node_names 
        if any(k in name for k in ["🇺🇸", "🇯🇵", "🇸🇬", "TW"])
    ]
    if not ai_friendly_nodes:
        ai_friendly_nodes = all_node_names

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "mixed-port": 7893,
        "proxies": nodes,
        "proxy-groups": [
            {
                "name": "🚀 🛑 代理节点全局代理",
                "type": "select",
                "proxies": ["🔮 自动选择", "🤖 OpenAI/Claude 专用"] + all_node_names
            },
            {
                "name": "🔮 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": all_node_names
            },
            {
                "name": "🤖 OpenAI/Claude 专用",
                "type": "select",
                "proxies": ai_friendly_nodes + ["🚀 🛑 代理节点全局代理"]
            },
            {
                "name": "⚓ 漏网之鱼(国内直连)",
                "type": "select",
                "proxies": ["DIRECT", "🚀 🛑 代理节点全局代理"]
            }
        ],
        "rules": [
            "DOMAIN-SUFFIX,openai.com,🤖 OpenAI/Claude 专用",
            "DOMAIN-SUFFIX,chatgpt.com,🤖 OpenAI/Claude 专用",
            "DOMAIN-SUFFIX,oaistatic.com,🤖 OpenAI/Claude 专用",
            "DOMAIN-SUFFIX,oaiusercontent.com,🤖 OpenAI/Claude 专用",
            "DOMAIN-KEYWORD,openai,🤖 OpenAI/Claude 专用",
            "DOMAIN-SUFFIX,anthropic.com,🤖 OpenAI/Claude 专用",
            "DOMAIN-SUFFIX,claude.ai,🤖 OpenAI/Claude 专用",
            "DOMAIN-KEYWORD,claude,🤖 OpenAI/Claude 专用",
            "GEOIP,CN,DIRECT",
            "MATCH,⚓ 漏网之鱼(国内直连)"
        ]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

# ========================================================
# 4. 高并发全网基础源多线程抓取引擎
# ========================================================
def fetch_url(url):
    local_nodes = []
    try:
        res = requests.get(url, timeout=8)
        if res.status_code == 200:
            content = res.text.strip()
            try:
                content += "=" * ((4 - len(content) % 4) % 4)
                decoded = base64.b64decode(content).decode("utf-8")
            except Exception:
                decoded = content
            
            for line in decoded.splitlines():
                parsed = parse_v2ray_url(line)
                if parsed:
                    local_nodes.append(parsed)
    except Exception:
        pass
    return local_nodes

def fetch_all_nodes():
    print("🌐 开始从全网优质高存活配置源实时拉取节点...")
    target_urls = [
        "https://raw.githubusercontent.com/vpei/Free-Node-Merge/main/out/node.txt",
        "https://raw.githubusercontent.com/FreeNodes/FreeNodes.github.io/main/sub/shadowrocket.txt",
        "https://raw.githubusercontent.com/w1770946466/Auto_Proxy/main/Long_term_subscription_num",
        "https://raw.githubusercontent.com/tuji666/v2ray-url/main/v2ray.txt"
    ]
    
    all_nodes = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = executor.map(fetch_url, target_urls)
        for nodes in results:
            all_nodes.extend(nodes)
            
    print(f"📥 全网原始抓取完毕，共捞回 {len(all_nodes)} 个节点")
    return all_nodes

def main():
    print("🎬 启动 100% 自研纯净节点清洗分流引擎...")
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. 独家自主抓取
    raw_nodes = fetch_all_nodes()

    # 2. 核心清洗与指纹去重
    cleaned_nodes = unique_and_clean_nodes(raw_nodes)

    if not cleaned_nodes:
        cleaned_nodes = [{
            "name": "🌐 🚀 节点池正在初始化中-请稍后刷新",
            "type": "ss",
            "server": "127.0.0.1",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "test"
        }]

    # 3. 输出高效 Clash 策略组 YAML
    generate_clash_yaml(cleaned_nodes, os.path.join(output_dir, "clash.yaml"))
    
    # 4. 逆向编码，输出通用客户端 Base64 订阅文本
    node_txt_path = os.path.join(output_dir, "node.txt")
    raw_links = []
    for n in cleaned_nodes:
        if n["type"] == "ss":
            cred = base64.b64encode(f"{n['cipher']}:{n['password']}".encode("utf-8")).decode("utf-8")
            raw_links.append(f"ss://{cred}@{n['server']}:{n['port']}#{urllib.parse.quote(n['name'])}")
        elif n["type"] == "vmess":
            v_json = {
                "v": "2", "ps": n["name"], "add": n["server"], "port": str(n["port"]),
                "id": n["uuid"], "aid": str(n["alterId"]), "scy": "auto",
                "net": n["network"], "type": "none", "host": "", "path": n.get("ws-opts", {}).get("path", "") if n.get("ws-opts") else "",
                "tls": "tls" if n["tls"] else ""
            }
            v_b64 = base64.b64encode(json.dumps(v_json).encode("utf-8")).decode("utf-8")
            raw_links.append(f"vmess://{v_b64}")
            
    b64_subscribe = base64.b64encode("\n".join(raw_links).encode("utf-8")).decode("utf-8")
    with open(node_txt_path, "w", encoding="utf-8") as f:
        f.write(b64_subscribe)
        
    print(f"✅ 独立引擎大获全胜！成果已成功输出至 [{output_dir}] 文件夹。")

if __name__ == "__main__":
    main()
