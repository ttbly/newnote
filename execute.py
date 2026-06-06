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
            
            server = j.get("add") or j.get("host")
            if not server or "vless://" in str(server):
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
                    
                server, port = server_port.split(":", 1)
                
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
# 3. Clash 配置文件生成 (分流 AI 规则)
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
# 4. 高频自动化测速过滤源 (解决全网 -1 核心痛点)
# ========================================================
def fetch_url(url):
    local_nodes = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            content = res.text.strip()
            for _ in range(3):
                try:
                    padding_needed = (4 - len(content) % 4) % 4
                    content += "=" * padding_needed
                    content = base64.b64decode(content).decode("utf-8").strip()
                except Exception:
                    break
            
            raw_links = re.findall(r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+)', content)
            if not raw_links:
                raw_links = re.split(r'[\n\r]+', content)

            for line in raw_links:
                line = line.strip()
                if line:
                    parsed = parse_v2ray_url(line)
                    if parsed:
                        local_nodes.append(parsed)
    except Exception:
        pass
    return local_nodes

def fetch_all_nodes():
    print("🌐 开始从【高频测速清洗池】拉取动态存活节点...")
    # 替换为全网机器人真实连通、定时过滤死节点的优质源
    target_urls = [
        "https://raw.githubusercontent.com/w1770946466/Auto_Proxy/main/Long_term_subscription_num/v2ray.txt",
        "https://raw.githubusercontent.com/zk666222/shadowsocks/master/v2ray.txt",
        "
