#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_nodes.py
多源代理节点订阅聚合脚本（支持明文 / Base64 / Clash YAML）

功能：
- 并行拉取、内容哈希增量跳过
- t.me/s/ 频道最多翻 N 页
- GitHub 仓库链接自动尝试 raw README.md
- 可选：正文里的 http(s) 订阅链接再展开一层（优化了跳过 <5 节点的限制条件）
- 本轮更新 → nodes_update/；累计全量 → nodes/
- 按协议分类，每 NODES_PER_FILE 个拆分
- 指纹设计加入 server 和 port，避免不同服务器被错误合并
- 完整度与官方标准严格校验重构（洗白过滤残缺节点，完整保留 WS/gRPC 等核心参数与 Trojan 特殊密码）
- 全量目录写入前增加数量暴跌保护
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse
import urllib.parse

import requests
import yaml

# ======================== 配置区域 ========================
SOURCES_URL = "https://raw.githubusercontent.com/qjlxg/results/refs/heads/main/sources.txt"

NODES_DIR = Path("nodes")                 # 累计全量
UPDATE_DIR = Path("nodes_update")        # 仅本轮有更新的节点
STATS_CSV = NODES_DIR / "stats.csv"
CHANGELOG = NODES_DIR / "changelog.md"
HASH_FILE = NODES_DIR / "source_hashes.json"
FP_FILE = NODES_DIR / "seen_fingerprints.json"

MAX_WORKERS = 12
NODES_PER_FILE = 18000
REQUEST_TIMEOUT = 25

TG_MAX_PAGES = 5
TG_PAGE_DELAY = 0.4

ENABLE_SECOND_HOP = True
SECOND_HOP_MAX = 15

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36"
)

BEIJING_TZ = timezone(timedelta(hours=8))

SECOND_HOP_SKIP_KEYWORDS = (
    "img.shields.io",
    "shields.io",
    "github.com/stars",
    "github.com/stargazers",
    "github.com/blob/",
    "/LICENSE",
    "play.google.com",
    "apps.apple.com",
    "badge",
    ".png",
    ".jpg",
    ".svg",
    ".gif",
    ".webp",
    "buymeacoffee",
    "paypal.com",
    "twitter.com",
    "x.com/",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "my.telegram.org",
)

# ======================== 工具 ========================
def now_beijing() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def safe_b64decode(data: str) -> Optional[str]:
    data = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        decoded = base64.b64decode(data, validate=False)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return printable / len(text) > 0.85


def load_subscriptions() -> List[str]:
    print(f"[信息] 正在获取远程订阅源列表: {SOURCES_URL}")
    try:
        resp = requests.get(
            SOURCES_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f"[错误] 无法获取远程订阅源列表: {e}")
        sys.exit(1)

    urls = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        urls.append(line)
    print(f"[信息] 共加载 {len(urls)} 个订阅源")
    return urls


def is_telegram_s(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.netloc.lower() in ("t.me", "www.t.me") and p.path.startswith("/s/")
    except Exception:
        return False


def is_github_repo_home(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.netloc.lower() not in ("github.com", "www.github.com"):
            return False
        parts = [x for x in p.path.strip("/").split("/") if x]
        return len(parts) == 2
    except Exception:
        return False


def github_raw_readme_candidates(url: str) -> List[str]:
    p = urlparse(url)
    parts = [x for x in p.path.strip("/").split("/") if x]
    if len(parts) < 2:
        return []
    owner, repo = parts[0], parts[1].removesuffix(".git")
    out = []
    for branch in ("main", "master"):
        for name in ("README.md", "readme.md", "README.MD"):
            out.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{name}")
    return out


def fetch_url(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        try:
            text = resp.content.decode("utf-8")
        except UnicodeDecodeError:
            text = resp.content.decode("utf-8", errors="ignore")
        return url, text, None
    except Exception as e:
        return url, None, str(e)


def fetch_telegram_pages(url: str, max_pages: int = TG_MAX_PAGES) -> Tuple[str, Optional[str], Optional[str]]:
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html"}
    all_html: List[str] = []
    current = url.split("?")[0].rstrip("/")
    seen_before: Set[str] = set()

    try:
        for page in range(max_pages):
            resp = requests.get(current, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()
            html = resp.content.decode("utf-8", errors="ignore")
            all_html.append(html)

            if page >= max_pages - 1:
                break

            befores = re.findall(
                r'(?:href|data-before)=["\']?(?:https://t\.me/s/[^"\']*\?before=)?(\d+)',
                html,
                flags=re.I,
            )
            next_before = None
            for b in befores:
                if b not in seen_before:
                    next_before = b
                    break
            if not next_before:
                ids = re.findall(r'data-post="[^"]+/(\d+)"', html)
                if ids:
                    try:
                        next_before = str(min(int(x) for x in ids))
                    except ValueError:
                        next_before = None
            if not next_before or next_before in seen_before:
                break
            seen_before.add(next_before)
            base = url.split("?")[0].rstrip("/")
            current = f"{base}?before={next_before}"
            time.sleep(TG_PAGE_DELAY)

        return url, "\n".join(all_html), None
    except Exception as e:
        if all_html:
            return url, "\n".join(all_html), None
        return url, None, str(e)


def fetch_github_readme(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    for raw in github_raw_readme_candidates(url):
        _, text, err = fetch_url(raw)
        if text and not err and len(text.strip()) > 20:
            return url, text, None
    return fetch_url(url)


def fetch_source_content(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    if is_telegram_s(url):
        return fetch_telegram_pages(url, TG_MAX_PAGES)
    if is_github_repo_home(url):
        return fetch_github_readme(url)
    return fetch_url(url)


SHARE_LINK_PATTERN = re.compile(
    r"(?:^|[\s\"'<>])("
    r"(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|wireguard|wg)://[^\s\"'<>]+"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

HTTP_URL_PATTERN = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)


def extract_share_links(text: str) -> List[str]:
    links = []
    for m in SHARE_LINK_PATTERN.finditer(text):
        link = m.group(1).rstrip(".,;)]}>'\"")
        if link:
            links.append(link)
    return links


def extract_http_urls(text: str) -> List[str]:
    return [m.group(0).rstrip(".,;)]}>'\"") for m in HTTP_URL_PATTERN.finditer(text)]


def should_skip_second_hop(url: str) -> bool:
    low = url.lower()
    for kw in SECOND_HOP_SKIP_KEYWORDS:
        if kw.lower() in low:
            return True
    if "github.com/" in low and "raw.githubusercontent.com" not in low:
        if "/blob/" in low:
            return False
        return True
    return False


def blob_to_raw(url: str) -> Optional[str]:
    m = re.match(
        r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)",
        url,
        re.I,
    )
    if not m:
        return None
    owner, repo, branch, path = m.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def parse_clash_yaml(text: str) -> List[str]:
    links = []
    try:
        text = text.lstrip("\ufeff")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return links
        proxies = data.get("proxies") or data.get("Proxy") or []
        if not isinstance(proxies, list):
            return links
        for p in proxies:
            if not isinstance(p, dict):
                continue
            link = clash_proxy_to_share_link(p)
            if link:
                links.append(link)
    except Exception:
        pass
    return links


def clash_proxy_to_share_link(p: dict) -> Optional[str]:
    t = (p.get("type") or "").lower()
    name = p.get("name") or "node"
    server = p.get("server") or p.get("servername") or ""
    port = p.get("port")
    if not server or not port:
        return None
    try:
        if t == "ss":
            method = p.get("cipher") or p.get("method") or "aes-256-gcm"
            password = p.get("password") or ""
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            return f"ss://{userinfo}@{server}:{port}#{name}"
        if t == "ssr":
            return None
        if t == "vmess":
            ws_opts = p.get("ws-opts") or {}
            ws_headers = ws_opts.get("headers") or {}
            conf = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": p.get("uuid") or p.get("id") or "",
                "aid": str(p.get("alterId") or p.get("alterid") or 0),
                "scy": p.get("cipher") or "auto",
                "net": p.get("network") or "tcp",
                "type": "none",
                "host": ws_headers.get("Host") or p.get("host") or "",
                "path": ws_opts.get("path") or p.get("path") or "",
                "tls": "tls" if p.get("tls") else "",
                "sni": p.get("servername") or p.get("sni") or "",
            }
            raw = json.dumps(conf, ensure_ascii=False, separators=(",", ":"))
            return f"vmess://{base64.b64encode(raw.encode()).decode()}"
        if t == "vless":
            uuid = p.get("uuid") or ""
            params = []
            if p.get("tls"):
                params.append("security=tls")
            if p.get("flow"):
                params.append(f"flow={p['flow']}")
            net = p.get("network")
            if net:
                params.append(f"type={net}")
            
            servername = p.get("servername") or p.get("sni")
            if servername:
                params.append(f"sni={servername}")

            # 完整保留 VLESS 的 ws-opts, grpc-opts 等参数映射
            if net == "ws":
                ws_opts = p.get("ws-opts") or {}
                if ws_opts.get("path"):
                    params.append(f"path={ws_opts['path']}")
                ws_headers = ws_opts.get("headers") or {}
                if ws_headers.get("Host"):
                    params.append(f"host={ws_headers['Host']}")
            elif p.get("path"):
                params.append(f"path={p['path']}")
            if p.get("host"):
                params.append(f"host={p['host']}")

            grpc_opts = p.get("grpc-opts") or {}
            if grpc_opts.get("grpc-service-name"):
                params.append(f"serviceName={grpc_opts['grpc-service-name']}")

            return f"vless://{uuid}@{server}:{port}?{'&'.join(params)}#{name}"
        if t == "trojan":
            password = p.get("password") or ""
            params = []
            servername = p.get("sni") or p.get("servername")
            if servername:
                params.append(f"sni={servername}")
            
            net = p.get("network")
            if net:
                params.append(f"type={net}")
            if net == "ws":
                ws_opts = p.get("ws-opts") or {}
                if ws_opts.get("path"):
                    params.append(f"path={ws_opts['path']}")
                ws_headers = ws_opts.get("headers") or {}
                if ws_headers.get("Host"):
                    params.append(f"host={ws_headers['Host']}")
            elif p.get("path"):
                params.append(f"path={p['path']}")

            return f"trojan://{password}@{server}:{port}?{'&'.join(params)}#{name}"
        if t in ("hysteria", "hysteria2", "hy2"):
            auth = p.get("password") or p.get("auth") or ""
            protocol = "hysteria2" if t != "hysteria" else "hysteria"
            return f"{protocol}://{auth}@{server}:{port}#{name}"
        if t == "tuic":
            return f"tuic://{p.get('uuid') or ''}:{p.get('password') or ''}@{server}:{port}#{name}"
    except Exception:
        return None
    return None


def detect_and_parse(content: str) -> List[str]:
    content = content.strip()
    if not content:
        return []
    links = extract_share_links(content)
    if len(links) >= 3:
        return links
    decoded = safe_b64decode(content)
    if decoded and is_mostly_printable(decoded):
        links = extract_share_links(decoded)
        if links:
            return links
        if "proxies:" in decoded or "Proxy:" in decoded:
            return parse_clash_yaml(decoded)
    if "proxies:" in content or "Proxy:" in content or content.lstrip().startswith("{"):
        ylinks = parse_clash_yaml(content)
        if ylinks:
            return ylinks
    if not links:
        pure = re.sub(r"^#.*$", "", content, flags=re.MULTILINE).strip()
        decoded = safe_b64decode(pure)
        if decoded:
            links = extract_share_links(decoded)
            if not links and ("proxies:" in decoded or "Proxy:" in decoded):
                links = parse_clash_yaml(decoded)
    return links


def expand_second_hop(content: str, origin_url: str) -> List[str]:
    if not ENABLE_SECOND_HOP:
        return []
    candidates: List[str] = []
    seen = set()
    for u in extract_http_urls(content):
        if should_skip_second_hop(u):
            raw = blob_to_raw(u)
            if raw and raw not in seen:
                seen.add(raw)
                candidates.append(raw)
            continue
        if u.rstrip("/") == origin_url.rstrip("/"):
            continue
        if u in seen:
            continue
        seen.add(u)
        candidates.append(u)
        if len(candidates) >= SECOND_HOP_MAX:
            break

    extra: List[str] = []
    for u in candidates:
        if is_telegram_s(u):
            _, text, err = fetch_telegram_pages(u, max_pages=min(2, TG_MAX_PAGES))
        elif is_github_repo_home(u):
            _, text, err = fetch_github_readme(u)
        else:
            _, text, err = fetch_url(u)
        if err or not text:
            continue
        extra.extend(detect_and_parse(text))
    return extra


def normalize_link(link: str) -> str:
    link = link.strip()
    if "#" in link:
        return link.split("#", 1)[0]
    return link


def get_protocol(link: str) -> str:
    m = re.match(r"^([a-z0-9]+)://", link, re.IGNORECASE)
    if not m:
        return "unknown"
    proto = m.group(1).lower()
    if proto == "hy2":
        return "hysteria2"
    if proto == "wg":
        return "wireguard"
    return proto


# ======================== 官方标准严格校验与重构模块 ========================

def strict_validate_and_normalize_vmess(uri: str) -> Optional[str]:
    """严格校验并标准重构 VMess 节点"""
    try:
        if not uri.startswith("vmess://"):
            return None
        b64_part = uri[8:].split("#")[0].strip()
        pad = 4 - len(b64_part) % 4
        if pad != 4:
            b64_part += "=" * pad
        
        decoded_bytes = base64.b64decode(b64_part, validate=True)
        cfg = json.loads(decoded_bytes.decode("utf-8"))
        
        required_fields = ["v", "add", "port", "id"]
        for field in required_fields:
            if field not in cfg or not str(cfg[field]).strip():
                return None
                
        add = str(cfg["add"]).strip().lower()
        if add in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
            return None

        port = int(cfg["port"])
        if not (1 <= port <= 65535):
            return None
            
        uuid_str = str(cfg["id"]).strip()
        uuid_regex = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
        if not uuid_regex.match(uuid_str):
            return None

        standard_cfg = {
            "v": str(cfg.get("v", "2")),
            "ps": str(cfg.get("ps", f"vmess-{add}")).strip(),
            "add": add,
            "port": str(port),
            "id": uuid_str,
            "aid": str(cfg.get("aid", 0)),
            "scy": str(cfg.get("scy", "auto")),
            "net": str(cfg.get("net", "tcp")),
            "type": str(cfg.get("type", "none")),
            "host": str(cfg.get("host", "")),
            "path": str(cfg.get("path", "")),
            "tls": str(cfg.get("tls", "")),
            "sni": str(cfg.get("sni", ""))
        }
        raw_json = json.dumps(standard_cfg, ensure_ascii=False, separators=(",", ":"))
        encoded_b64 = base64.b64encode(raw_json.encode("utf-8")).decode("utf-8").rstrip("=")
        return f"vmess://{encoded_b64}#{urllib.parse.quote(standard_cfg['ps'])}"
    except Exception:
        return None


def strict_validate_and_normalize_vless_trojan(uri: str) -> Optional[str]:
    """严格校验并标准重构 VLESS / Trojan 节点（支持 Trojan 特殊密码 unquote 与安全 URL 编码）"""
    try:
        proto = "vless" if uri.startswith("vless://") else "trojan"
        p = urlparse(uri)
        
        user_info = p.username
        if not user_info:
            return None
        if proto == "trojan":
            user_info = unquote(user_info)
            user_info = urllib.parse.quote(user_info, safe="")

        server = p.hostname
        port = p.port
        
        if not server or not port:
            return None
        server = server.lower()
        if server in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
            return None
        if not (1 <= port <= 65535):
            return None
            
        if proto == "vless":
            uuid_regex = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
            if not uuid_regex.match(user_info.strip()):
                return None

        q = parse_qs(p.query)
        clean_q = []
        allowed_params = ["type", "security", "encryption", "sni", "host", "path", "flow", "fp", "alpn", "serviceName", "packetEncoding", "authority", "mode"]
        for k in allowed_params:
            if k in q and q[k]:
                clean_q.append(f"{k}={q[k][0]}")
                
        query_str = "&".join(clean_q)
        if query_str:
            query_str = "?" + query_str
            
        name = unquote(p.fragment).strip() if p.fragment else f"{proto}-{server}"
        encoded_name = f"#{urllib.parse.quote(name)}" if name else ""
        
        return f"{proto}://{user_info}@{server}:{port}{query_str}{encoded_name}"
    except Exception:
        return None


def strict_validate_and_normalize_node(link: str) -> Optional[str]:
    """总校验入口：严格按照官方标准校验并重构节点，剔除 Reality 与残缺节点"""
    link = link.strip()
    low = link.lower()
    
    if "security=reality" in low or "security%3dreality" in low:
        return None

    if link.startswith("vmess://"):
        return strict_validate_and_normalize_vmess(link)
    elif link.startswith("vless://") or link.startswith("trojan://"):
        return strict_validate_and_normalize_vless_trojan(link)
    elif link.startswith("ss://") or link.startswith("hysteria2://") or link.startswith("hy2://") or link.startswith("tuic://"):
        try:
            p = urlparse(link)
            server = p.hostname
            if not server:
                return None
            server = server.lower()
            if server in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
                return None
            port = p.port
            if port and (1 <= port <= 65535):
                return link
        except Exception:
            pass
    return None


# ======================== 指纹生成辅助 ========================
def parse_uri_to_proxy(uri: str) -> Optional[dict]:
    uri = uri.strip()
    if not uri:
        return None
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:].split("#")[0]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return {
                "type": "vmess",
                "uuid": cfg.get("id"),
                "server": str(cfg.get("add", "")).strip().lower(),
                "port": str(cfg.get("port", "")).strip(),
                "path": cfg.get("path") or "",
                "servername": cfg.get("sni") or cfg.get("host") or ""
            }
        except Exception:
            return None
    elif uri.startswith(("vless://", "trojan://", "tuic://", "hysteria2://", "hy2://", "ss://")):
        try:
            p = urlparse(uri)
            proto = get_protocol(uri)
            q = parse_qs(p.query)
            path = unquote((q.get("path") or [""])[0])
            host = (q.get("sni") or q.get("host") or [""])[0]
            return {
                "type": proto,
                "uuid": p.username or "",
                "server": (p.hostname or "").lower(),
                "port": str(p.port or ""),
                "path": path,
                "servername": host
            }
        except Exception:
            return None
    return None


def node_fingerprint(proxy: dict) -> str:
    """核心指纹：加入 server 和 port，避免不同服务器被错误合并"""
    t = (proxy.get("type") or "").lower()
    uid = (proxy.get("uuid") or "").strip().lower()
    server = (proxy.get("server") or "").strip().lower()
    port = (proxy.get("port") or "").strip()
    path = (proxy.get("path") or "").strip()
    host = (proxy.get("servername") or "").strip().lower()
    return f"{t}|{uid}|{server}|{port}|{path}|{host}"


def get_link_fingerprint(link: str) -> str:
    proxy = parse_uri_to_proxy(link)
    if proxy:
        return node_fingerprint(proxy)
    return "raw|" + normalize_link(link)


def load_seen_fingerprints() -> Set[str]:
    if FP_FILE.exists():
        try:
            with open(FP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return set(data)
        except Exception:
            pass
    return set()


def save_seen_fingerprints(fps: Set[str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    with open(FP_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(list(fps)), f, ensure_ascii=False, indent=2)


# ======================== 原有持久化与处理逻辑 ========================
def load_previous_hashes() -> Dict[str, str]:
    if HASH_FILE.exists():
        try:
            with open(HASH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_hashes(hashes: Dict[str, str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    with open(HASH_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)


def process_one_source(url: str, prev_hashes: Dict[str, str]) -> dict:
    result = {
        "url": url,
        "count": 0,
        "status": "ok",
        "error": "",
        "skipped": False,
        "hash": "",
        "links": [],
    }

    low = url.lower()
    if any(k in low for k in (
        "img.shields.io", "shields.io/badge", "play.google.com",
        "apps.apple.com", ".png", ".svg", ".jpg",
    )):
        result["status"] = "skipped"
        result["skipped"] = True
        result["error"] = "noise url"
        return result

    _, content, err = fetch_source_content(url)
    if err or content is None:
        result["status"] = "error"
        result["error"] = err or "empty content"
        return result

    h = content_hash(content)
    result["hash"] = h

    if prev_hashes.get(url) == h:
        result["skipped"] = True
        result["status"] = "skipped"
        return result

    links = detect_and_parse(content)
    # 修复：移除原先的 len(links) < 5 限制，只要开启二级展开且内容有 URL 就尝试按需展开
    if ENABLE_SECOND_HOP:
        links.extend(expand_second_hop(content, url))

    seen = set()
    unique = []
    for link in links:
        norm = normalize_link(link)
        if norm not in seen:
            seen.add(norm)
            unique.append(link)

    result["count"] = len(unique)
    result["links"] = unique
    return result


def _clear_protocol_dirs(root: Path):
    if not root.exists():
        return
    for item in root.iterdir():
        if item.is_dir():
            for f in item.glob("*.txt"):
                f.unlink()
            try:
                item.rmdir()
            except OSError:
                pass


def _write_links_by_protocol(root: Path, links: List[str], label: str) -> int:
    root.mkdir(parents=True, exist_ok=True)
    groups: Dict[str, List[str]] = {}
    for link in links:
        proto = get_protocol(link)
        groups.setdefault(proto, []).append(link)

    total_files = 0
    for proto, plinks in sorted(groups.items()):
        if not plinks:
            continue
        unique = list(dict.fromkeys(plinks))
        proto_dir = root / proto
        proto_dir.mkdir(parents=True, exist_ok=True)
        for i in range(0, len(unique), NODES_PER_FILE):
            chunk = unique[i : i + NODES_PER_FILE]
            idx = i // NODES_PER_FILE + 1
            filename = proto_dir / f"{idx:03d}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")
            total_files += 1
            print(f"  → [{label}] {proto}/{filename.name}  ({len(chunk)} 个)")
    return total_files


def load_existing_nodes(root: Path) -> List[str]:
    if not root.exists():
        return []
    links: List[str] = []
    for f in sorted(root.rglob("*.txt")):
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and "://" in line:
                    links.append(line)
        except Exception:
            pass
    return links


def save_nodes_update_only(update_links: List[str]):
    print(f"\n[信息] 写入本轮更新 → {UPDATE_DIR}/ （共 {len(update_links)} 个节点）")
    _clear_protocol_dirs(UPDATE_DIR)
    UPDATE_DIR.mkdir(parents=True, exist_ok=True)
    if not update_links:
        print("  → 本轮无更新，nodes_update/ 已清空")
        return
    n = _write_links_by_protocol(UPDATE_DIR, update_links, "更新")
    print(f"[完成] nodes_update/ 共 {n} 个文件")


def save_nodes_cumulative(update_links: List[str]):
    old = load_existing_nodes(NODES_DIR)
    seen: Set[str] = set()
    merged: List[str] = []
    for link in old + update_links:
        norm = normalize_link(link)
        if norm not in seen:
            seen.add(norm)
            merged.append(link)

    if old and len(merged) < len(old) * 0.7:
        print(f"⚠️ 警告：合并后节点数 {len(merged)} 比历史 {len(old)} 下降超过 30%，跳过覆盖全量目录，防止数据被洗掉。")
        print(f"   本轮更新节点仍会写入 nodes_update/，请检查后再手动处理。")
        return

    print(f"\n[信息] 写入累计全量 → {NODES_DIR}/ （旧 {len(old)} + 本轮 {len(update_links)} → 合并后 {len(merged)}）")
    _clear_protocol_dirs(NODES_DIR)
    n = _write_links_by_protocol(NODES_DIR, merged, "全量")
    print(f"[完成] nodes/ 共 {n} 个文件")


def write_stats(results: List[dict]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = STATS_CSV.exists()
    with open(STATS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "url", "count", "status", "error", "skipped"])
        ts = now_beijing()
        for r in results:
            writer.writerow([ts, r["url"], r["count"], r["status"], r.get("error", ""), r.get("skipped", False)])


def write_changelog(results: List[dict], prev_hashes: Dict[str, str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    lines = [f"## 运行时间：{now_beijing()} (北京时间)\n"]
    updated = [r for r in results if not r.get("skipped") and r["status"] == "ok"]
    skipped = [r for r in results if r.get("skipped")]
    errors = [r for r in results if r["status"] == "error"]
    lines.append(f"- 成功更新：{len(updated)} 个源")
    lines.append(f"- 内容未变/噪音跳过：{len(skipped)} 个源")
    lines.append(f"- 拉取失败：{len(errors)} 个源")
    lines.append(f"- TG 频道最多翻页：{TG_MAX_PAGES}")
    lines.append(f"- 二级订阅展开：{'开' if ENABLE_SECOND_HOP else '关'}\n")
    if updated:
        lines.append("### 本次有更新的源\n")
        for r in updated:
            lines.append(f"- `{r['url']}` → **{r['count']}** 个节点")
        lines.append("")
    if errors:
        lines.append("### 失败的源\n")
        for r in errors:
            lines.append(f"- `{r['url']}` : {r.get('error', '')}")
        lines.append("")
    old = CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else ""
    with open(CHANGELOG, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n---\n\n" + old)


def main():
    print(f"========== collect_nodes 开始运行 {now_beijing()} ==========")
    print(f"  TG_MAX_PAGES={TG_MAX_PAGES}  ENABLE_SECOND_HOP={ENABLE_SECOND_HOP}  SECOND_HOP_MAX={SECOND_HOP_MAX}")
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    UPDATE_DIR.mkdir(parents=True, exist_ok=True)

    seen_fps = load_seen_fingerprints()
    print(f"[信息] 已加载历史指纹: {len(seen_fps)} 个")

    urls = load_subscriptions()
    prev_hashes = load_previous_hashes()
    results = []
    all_links: List[str] = []
    seen_global: Set[str] = set()
    new_fps_this_run: Set[str] = set()

    print(f"[信息] 开始并行拉取（workers={MAX_WORKERS}）...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(process_one_source, url, prev_hashes): url for url in urls}
        for future in as_completed(future_map):
            r = future.result()
            results.append(r)
            if r.get("skipped"):
                print(f"  [跳过] {r['url'][:70]}... ({r.get('error') or '内容未变化'})")
            elif r["status"] == "error":
                print(f"  [失败] {r['url'][:70]}... → {r.get('error')}")
            else:
                print(f"  [成功] {r['url'][:70]}... → {r['count']} 节点")
                for link in r["links"]:
                    norm = normalize_link(link)
                    if norm not in seen_global:
                        seen_global.add(norm)
                        
                        validated_link = strict_validate_and_normalize_node(link)
                        if not validated_link:
                            continue
                            
                        fp = get_link_fingerprint(validated_link)
                        # 修复：改为仅在本轮生命周期内做去重，不再因为历史文件永远屏蔽消逝后又重现的节点
                        if fp not in new_fps_this_run:
                            new_fps_this_run.add(fp)
                            all_links.append(validated_link)

    # 仅更新历史指纹库以备统计参考，而不作为拦截新节点的绝对死胡同
    if new_fps_this_run:
        seen_fps.update(new_fps_this_run)
        save_seen_fingerprints(seen_fps)
        print(f"[信息] 本轮收集指纹: {len(new_fps_this_run)} 个，累计指纹总数: {len(seen_fps)}")
    else:
        print(f"[信息] 本轮没有发现服务器指纹")

    new_hashes = dict(prev_hashes)
    for r in results:
        if r["hash"] and r["status"] in ("ok", "skipped") and r.get("error") != "noise url":
            new_hashes[r["url"]] = r["hash"]
    save_hashes(new_hashes)

    print(f"\n[信息] 本轮真正新节点（官方标准校验 + 指纹去重后）: {len(all_links)} 个")
    save_nodes_update_only(all_links)
    save_nodes_cumulative(all_links)
    write_stats(results)
    write_changelog(results, prev_hashes)

    print(f"========== 运行结束 {now_beijing()} ==========")
    print(f"下游请优先使用: {UPDATE_DIR}/")
    print(f"完整累计在:     {NODES_DIR}/")
    if not all_links:
        print("提示：本轮无新服务器，后续 generator 和测活脚本可直接跳过，节省时间。")


if __name__ == "__main__":
    main()
