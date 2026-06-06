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
# 1. 强力节点链接反向解码器 (全面支持 VMess / VLESS / SS)
# ========================================================
def parse_v2ray_url(url):
    url = url.strip()
    if not url:
        return None
    try:
        # ---- VMess 协议解析 ----
        if url.startswith("vmess://"):
            b64_content = url.replace("vmess://", "")
            b64_content += "=" * ((4 - len(b64_content) % 4) % 4)
            dec_json = base64.b64decode(b64_content).decode("utf-8")
            j = json.loads(dec_json)
            
            server = j.get("add") or j.get("host") or ""
            if not server:
                return None
                
            return {
                "name": j.get("ps", "VMess Node"),
                "type": "vmess",
                "server": str(server).strip(),
                "port": int(j.get("port", 443)),
                "uuid": str(j.get("id", "")).strip(),
                "alterId": int(j.get("aid", 0)),
                "cipher": "auto",
                "tls": True if str(j.get("tls")).lower() in ["tls", "1", "true"] else False,
                "network": j.get("net", "tcp"),
                "ws-opts": {"path": j.get("path", "")} if j.get("net") == "ws" else None,
                "sni": j.get("sni", ""),
                "host": j.get("host", "")
            }
            
        # ---- VLESS 协议解析 ----
        elif url.startswith("vless://"):
            if "#" in url:
                url, name_part = url.split("#", 1)
                name = urllib.parse.unquote(name_part)
            else:
                name = "VLESS Node"
                
            rest = url.replace("vless://", "")
            if "@" in rest:
                uuid, server_part = rest.split("@", 1)
                
                if "?" in server_part:
                    server_port, query_part = server_part.split("?", 1)
                    query_params = dict(urllib.parse.parse_qsl(query_part))
                else:
                    server_port = server_part
                    query_params = {}
                    
                if ":" in server_port:
                    server, port = server_port.split(":", 1)
                else:
                    server, port = server_port, "443"
                
                return {
                    "name": name,
                    "type": "vless",
                    "server": server.strip(),
                    "port": int(port),
                    "uuid": uuid.strip(),
                    "tls": True if query_params.get("security") in ["tls", "xtls", "reality"] else False,
                    "network": query_params.get("type", "tcp"),
                    "ws-opts": {"path": query_params.get("path", "")} if query_params.get("type") == "ws" else None,
                    "sni": query_params.get("sni", ""),
                    "host": query_params.get("host", ""),
                    "flow": query_params.get("flow", ""),
                    "pbk": query_params.get("pbk", ""),
                    "sid": query_params.get("sid", ""),
                    "security": query_params.get("security", "none")
                }

        # ---- Shadowsocks 协议解析 ----
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
                
                if ":" in server_part:
                    server, port = server_part.split(":", 1)
                else:
                    server, port = server_part, "8388"
                    
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
        if not server or not port:
            return None
        return hashlib.md5(f"{server}:{port}".encode("utf-8")).hexdigest()
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
# 3. Clash 配置文件生成
# ========================================================
def generate_clash_yaml(nodes, output_path):
    all_node_names = [node["name"] for node in nodes]
    if not all_node_names:
        all_node_names = ["DIRECT"]

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
                "proxies": ["🔮 自动选择"] + all_node_names
            },
            {
                "name": "🔮 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": all_node_names
            }
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 🛑 代理节点全局代理"
        ]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

# ========================================================
# 4. 强力抓取逻辑 (无限解密 Base64，拥抱一切明文/密文源)
# ========================================================
def fetch_url(url):
    local_nodes = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code == 200:
            content = res.text.strip()
            
            # 强力层级解密循环：如果是 Base64 订阅就自动解开，多层也无所谓
            for _ in range(5):
                if "vmess://" in content or "vless://" in content or "ss://" in content:
                    break
                try:
                    padded = content + "=" * ((4 - len(content) % 4) % 4)
                    content = base64.b64decode(padded).decode("utf-8").strip()
                except:
                    break
            
            # 正则宽泛提取所有节点链接
            raw_links = re.findall(r'(vmess://[^\s<>"]+|vless://[^\s<>"]+|ss://[^\s<>"]+)', content)
            if not raw_links:
                # 兜底：按行切割
                raw_links = [line.strip() for line in content.splitlines() if line.strip()]

            for line in raw_links:
                parsed = parse_v2ray_url(line)
                if parsed:
                    local_nodes.append(parsed)
    except:
        pass
    return local_nodes

def fetch_all_nodes():
    print("🌐 启动强力不挑食源抓取...")
    # 换用全网最稳定、极具韧性的三大全协议公开源
    target_urls = [
        "https://raw.githubusercontent.com/tuji-source/Tuji/main/Tuji.txt",
        "https://raw.githubusercontent.com/boxjs/proxy/main/sub/shadowsocks.txt",
        "https://raw.githubusercontent.com/vless-node/vless/main/sub/sub_merge.txt"
    ]
    
    all_nodes = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = executor.map(fetch_url, target_urls)
        for nodes in results:
            all_nodes.extend(nodes)
            
    return all_nodes

def main():
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    raw_nodes = fetch_all_nodes()
    cleaned_nodes = unique_and_clean_nodes(raw_nodes)

    print(f"📊 过滤清洗完成，最终保留有效节点：{len(cleaned_nodes)} 个")

    if not cleaned_nodes:
        cleaned_nodes = [{
            "name": "🌐 🚀 节点池当前无可用活节点-请等待下一次构建",
            "type": "ss",
            "server": "127.0.0.1",
            "port": 8388,
            "cipher": "aes-256-gcm",
            "password": "test"
        }]

    generate_clash_yaml(cleaned_nodes, os.path.join(output_dir, "clash.yaml"))
    
    raw_links = []
    for n in cleaned_nodes:
        if n["type"] == "ss":
            cred = base64.b64encode(f"{n['cipher']}:{n['password']}".encode("utf-8")).decode("utf-8")
            raw_links.append(f"ss://{cred}@{n['server']}:{n['port']}#{urllib.parse.quote(n['name'])}")
            
        elif n["type"] == "vmess":
            v_json = {
                "v": "2", "ps": n["name"], "add": n["server"], "port": str(n["port"]),
                "id": n["uuid"], "aid": str(n["alterId"]), "scy": "auto",
                "net": n["network"], "type": "none", "host": n.get("host", ""), 
                "path": n.get("ws-opts", {}).get("path", "") if n.get("ws-opts") else "",
                "tls": "tls" if n["tls"] else "", "sni": n.get("sni", n["server"]), "allowInsecure": 1
            }
            v_b64 = base64.b64encode(json.dumps(v_json, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            raw_links.append(f"vmess://{v_b64}")
            
        elif n["type"] == "vless":
            query_map = {
                "security": n["security"], "type": n["network"], "headerType": "none", "fp": "chrome", "allowInsecure": "1"
            }
            if n.get("flow"): query_map["flow"] = n["flow"]
            if n.get("pbk"): query_map["pbk"] = n["pbk"]
            if n.get("sid"): query_map["sid"] = n["sid"]
            if n.get("ws-opts") and n["ws-opts"].get("path"): query_map["path"] = n["ws-opts"]["path"]
            if n.get("host"): query_map["host"] = n["host"]
            if n.get("sni"): query_map["sni"] = n["sni"]
            elif n["tls"]: query_map["sni"] = n["server"]
                
            query_str = urllib.parse.urlencode(query_map)
            raw_links.append(f"vless://{n['uuid']}@{n['server']}:{n['port']}?{query_str}#{urllib.parse.quote(n['name'])}")
            
    plain_nodes_text = "\n".join(raw_links)
    with open(os.path.join(output_dir, "nodes_plain.txt"), "w", encoding="utf-8") as f:
        f.write(plain_nodes_text)

    b64_subscribe = base64.b64encode(plain_nodes_text.encode("utf-8")).decode("utf-8")
    with open(os.path.join(output_dir, "node.txt"), "w", encoding="utf-8") as f:
        f.write(b64_subscribe)
        
    print("✅ 终极稳健版运行完毕。")

if __name__ == "__main__":
    main()
