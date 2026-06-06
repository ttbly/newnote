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
# 1. 强力节点链接反向解码器 (完美兼容各种非标准 Base64 变体)
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
            
            # 兼容底层不同爬虫源的字段命名差异
            server = j.get("add") or j.get("host")
            port = j.get("port")
            uuid = j.get("id")
            if not server or not port or not uuid:
                return None
                
            return {
                "name": j.get("ps", "VMess Node"),
                "type": "vmess",
                "server": str(server).strip(),
                "port": int(port),
                "uuid": str(uuid).strip(),
                "alterId": int(j.get("aid", 0)),
                "cipher": "auto",
                "tls": True if str(j.get("tls")).lower() in ["tls", "1", "true"] else False,
                "network": j.get("net", "tcp"),
                "ws-opts": {"path": j.get("path", "")} if j.get("net") == "ws" else None,
                "sni": j.get("sni", ""),
                "host": j.get("host", "")
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
                if ":" not in credentials:
                    credentials += "=" * ((4 - len(credentials) % 4) % 4)
                    credentials = base64.b64decode(credentials).decode("utf-8")
                cipher, password = credentials.split(":", 1)
                server, port = server_part.split(":", 1)
                return {
                    "name": name,
                    "type": "ss",
                    "server": server.strip(),
                    "port": int(port),
                    "cipher": cipher.strip(),
                    "password": password.strip()
                }
    except Exception:
        pass
    return None

# ========================================================
# 2. 核心清洗与指纹去重逻辑
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
# 3. AI 规则集分流生成 (Clash 配置)
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
# 4. 高鲜度动态节点抓取源 (剔除死节点多发的静态归档)
# ========================================================
def fetch_url(url):
    local_nodes = []
    try:
        # 模拟标准浏览器 Request，防止抓取时被目标源直接干扰
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            content = res.text.strip()
            # 解决部分订阅源强行多重 Base64 加密的问题
            for _ in range(3):
                try:
                    padding_needed = (4 - len(content) % 4) % 4
                    content += "=" * padding_needed
                    content = base64.b64decode(content).decode("utf-8").strip()
                except Exception:
                    break
            
            # 使用更鲁棒的正则分隔符切分行
            for line in re.split(r'[\n\r]+', content):
                line = line.strip()
                if line:
                    parsed = parse_v2ray_url(line)
                    if parsed:
                        local_nodes.append(parsed)
    except Exception:
        pass
    return local_nodes

def fetch_all_nodes():
    print("🌐 开始从高时效、高鲜度动态活节点源拉取节点...")
    # 更换了全网每日高频率更新、高存活率的公共源
    target_urls = [
        "https://raw.githubusercontent.com/Yuandong666/v2ray-node/main/v2ray.txt",
        "https://raw.githubusercontent.com/JackZeng9/free-nodes/main/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/sssub/sub/master/v2ray",
        "https://raw.githubusercontent.com/vless-node/vless/main/sub/sub_merge.txt"
    ]
    
    all_nodes = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = executor.map(fetch_url, target_urls)
        for nodes in results:
            all_nodes.extend(nodes)
            
    print(f"📥 动态抓取洗炼完毕，基础池捕获 {len(all_nodes)} 个节点")
    return all_nodes

def main():
    print("🎬 启动全新重构的 V2RayN 高兼容清洗分流引擎...")
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. 动态拉取高鲜度源
    raw_nodes = fetch_all_nodes()

    # 2. 深度去重清洗
    cleaned_nodes = unique_and_clean_nodes(raw_nodes)

    if not cleaned_nodes:
        cleaned_nodes = [{
            "name": "🌐 🚀 节点初始化失败-请确认网络并重新运行 Actions",
            "type": "ss",
            "server": "127.0.0.1",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "test"
        }]

    # 3. 输出 Clash 格式 YAML
    generate_clash_yaml(cleaned_nodes, os.path.join(output_dir, "clash.yaml"))
    
    # 4. 逆向重构 V2RayN 严苛的标准协议链接
    raw_links = []
    for n in cleaned_nodes:
        if n["type"] == "ss":
            cred = base64.b64encode(f"{n['cipher']}:{n['password']}".encode("utf-8")).decode("utf-8")
            raw_links.append(f"ss://{cred}@{n['server']}:{n['port']}#{urllib.parse.quote(n['name'])}")
        elif n["type"] == "vmess":
            # 严格按照 V2RayN 的标准规范定义字段，消除因字段缺失导致的客户端解析异常（-1报错）
            v_json = {
                "v": "2", 
                "ps": n["name"], 
                "add": n["server"], 
                "port": str(n["port"]),
                "id": n["uuid"], 
                "aid": str(n["alterId"]), 
                "scy": "auto",                    # 必须声明加密方式为 auto
                "net": n["network"], 
                "type": "none", 
                "host": n.get("host", ""), 
                "path": n.get("ws-opts", {}).get("path", "") if n.get("ws-opts") else "",
                "tls": "tls" if n["tls"] else "",
                "sni": n.get("sni", n["server"]), # 如果sni为空，强制用 server IP/域名补齐
                "alpn": "",
                "fp": "chrome",                   # 强制注入 Chrome 指纹绕过主动探测
                "allowInsecure": 1                # 强制放行不合规证书（注：部分新内核必须为数字 1 而非字符串 "1"）
            }
            v_b64 = base64.b64encode(json.dumps(v_json, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            raw_links.append(f"vmess://{v_b64}")
            
    # 输出明文订阅文件
    plain_nodes_text = "\n".join(raw_links)
    node_plain_path = os.path.join(output_dir, "nodes_plain.txt")
    with open(node_plain_path, "w", encoding="utf-8") as f:
        f.write(plain_nodes_text)
    print(f"📝 高鲜度明文文件已更新至 [{node_plain_path}]")

    # 输出 V2RayN 标准 Base64 加密订阅
    node_txt_path = os.path.join(output_dir, "node.txt")
    b64_subscribe = base64.b64encode(plain_nodes_text.encode("utf-8")).decode("utf-8")
    with open(node_txt_path, "w", encoding="utf-8") as f:
        f.write(b64_subscribe)
        
    print(f"✅ 全新优化版大功告成！所有成果均已完美输出至 [{output_dir}] 目录。")

if __name__ == "__main__":
    main()
