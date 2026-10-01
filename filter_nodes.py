#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import copy
import glob
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml

DEFAULT_INPUT_PATTERNS = ["nodes"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
VALID_POOL_FILE = ".valid_pool.json"
INVALID_POOL_FILE = ".invalid_pool.json"
DEFAULT_BATCH_SIZE = 300
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")
API_HOST = "127.0.0.1"
API_PORT = 9097
API_SECRET = "test-only-secret"
TIMEOUT_MS = 3000
CONCURRENCY = 32
TCP_WORKERS = 64
TCP_CHUNK = 2000
TCP_TIMEOUT = 0.6

CORE_FINGERPRINT_KEYS = (
    "type", "server", "port", "uuid", "password", "cipher", "alterId",
    "protocol", "obfs", "protocol-param", "obfs-param", "private-key",
    "public-key", "ip", "username", "psk"
)

TEST_GROUPS = [
    ("基础连通性", [("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"), ("Google 204", "https://www.google.com/generate_204")]),
    ("实际网站", [("Google 首页", "https://www.google.com/"), ("Telegram", "https://t.me/telegram/")])
]

SKIP_TCP_TYPES = frozenset({"hysteria2", "hy2", "tuic", "wireguard", "mieru", "warp"})
NODE_FILE_EXTS = {".txt", ".list", ".conf", ".yaml", ".yml"}
SKIP_FILENAMES = frozenset({
    "filtered_nodes.yaml", "gem.yaml", ".tested_progress.json", ".valid_pool.json",
    ".invalid_pool.json", "seen_fingerprints.json", "source_hashes.json", "stats.csv",
    "changelog.md", "readme.md", "license", "license.md"
})


def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S]"), msg, flush=True)


def safe_name(name):
    return str(name or "node").strip() or "node"


def b64decode_pad(s):
    s = (s or "").strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s)


def fingerprint(proxy):
    obj = {k: proxy[k] for k in CORE_FINGERPRINT_KEYS if k in proxy and proxy[k] is not None}
    for opt_key in ("ws-opts", "grpc-opts", "h2-opts", "http-opts", "xhttp-opts", "plugin-opts", "reality-opts"):
        if opt_key in proxy and isinstance(proxy[opt_key], dict):
            obj[opt_key] = proxy[opt_key]
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_node_by_official_standard(node):
    if not isinstance(node, dict):
        return False
    ptype = str(node.get("type", "")).lower().strip()
    server = str(node.get("server", "") or "").strip()
    port = node.get("port")
    if not ptype:
        return False
    if ptype == "wireguard":
        if not node.get("private-key"):
            return False
        return bool(node.get("peers") or (server and node.get("public-key")))
    if ptype == "mieru":
        return bool(server and node.get("username") and node.get("password") and (port or node.get("port-range")))
    if not server:
        return False
    try:
        if not (1 <= int(port) <= 65535):
            return False
    except (TypeError, ValueError):
        return False
    if ptype == "ss":
        return bool(node.get("cipher") and node.get("password"))
    if ptype == "ssr":
        return bool(node.get("cipher") and node.get("password") and node.get("protocol") and node.get("obfs"))
    if ptype in ("vmess", "vless"):
        return bool(node.get("uuid"))
    if ptype in ("trojan", "hysteria2", "hy2", "anytls"):
        return bool(node.get("password"))
    if ptype == "tuic":
        return bool(node.get("uuid") or node.get("password"))
    return False


def _qget(query, *keys, default=None):
    for k in keys:
        v = query.get(k)
        if v:
            return v[0] if isinstance(v, list) else v
    return default


def _apply_transport_opts(node, network, query):
    network = (network or "tcp").lower()
    if network and network != "tcp":
        node["network"] = network
    if network == "ws":
        opts = {}
        if (path := _qget(query, "path", "ws-path")):
            opts["path"] = path
        if (host := _qget(query, "host", "Host")):
            opts["headers"] = {"Host": host}
        if opts:
            node["ws-opts"] = opts
    elif network == "grpc":
        if (svc := _qget(query, "serviceName", "service-name", "grpc-service-name")):
            node["grpc-opts"] = {"grpc-service-name": svc}
    elif network == "h2":
        opts = {}
        if (path := _qget(query, "path")):
            opts["path"] = path
        if (host := _qget(query, "host")):
            opts["host"] = [host] if isinstance(host, str) else host
        if opts:
            node["h2-opts"] = opts
    elif network == "http":
        opts = {}
        if (path := _qget(query, "path")):
            opts["path"] = [path] if isinstance(path, str) else path
        if (host := _qget(query, "host")):
            opts["headers"] = {"Host": [host]}
        if opts:
            node["http-opts"] = opts
    elif network in ("xhttp", "splithttp"):
        node["network"] = "xhttp"
        opts = {}
        if (path := _qget(query, "path")):
            opts["path"] = path
        if (host := _qget(query, "host")):
            opts["host"] = host
        if (mode := _qget(query, "mode")):
            opts["mode"] = mode
        if opts:
            node["xhttp-opts"] = opts


def parse_ssr_link(line):
    raw = line[6:].strip()
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    try:
        decoded = b64decode_pad(raw).decode("utf-8", errors="ignore")
    except Exception:
        return None
    main, _, query_str = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        return None
    try:
        port = int(parts[1])
    except ValueError:
        return None
    try:
        password = b64decode_pad(":".join(parts[5:])).decode("utf-8", errors="ignore")
    except Exception:
        password = ":".join(parts[5:])
    node = {
        "name": f"SSR-{parts[0]}", "type": "ssr", "server": parts[0],
        "port": port, "protocol": parts[2], "cipher": parts[3],
        "obfs": parts[4], "password": password
    }
    if query_str:
        qs = urllib.parse.parse_qs(query_str)
        def _b64_param(k):
            if (v := qs.get(k, [None])[0]):
                try:
                    return b64decode_pad(v).decode("utf-8", errors="ignore")
                except Exception:
                    return v
            return None
        if (rem := _b64_param("remarks")): node["name"] = rem
        if (obf := _b64_param("obfsparam")): node["obfs-param"] = obf
        if (pro := _b64_param("protoparam")): node["protocol-param"] = pro
    return node


def parse_share_link(line):
    line = (line or "").strip()
    if not line or line.startswith(("#", "//")):
        return None
    try:
        if line.startswith("ss://"):
            main_part = line[5:]
            fragment = ""
            if "#" in main_part:
                main_part, fragment = main_part.split("#", 1)
                fragment = urllib.parse.unquote(fragment)
            if "@" not in main_part:
                try:
                    decoded = b64decode_pad(main_part).decode("utf-8", errors="ignore")
                    if "@" in decoded:
                        main_part = decoded
                except Exception:
                    pass
            if "@" in main_part:
                userinfo, hostport = main_part.rsplit("@", 1)
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                else:
                    try:
                        decoded_ui = b64decode_pad(userinfo).decode("utf-8", errors="ignore")
                        method, password = decoded_ui.split(":", 1) if ":" in decoded_ui else (decoded_ui, "")
                    except Exception:
                        method, password = userinfo, ""
                server, port_s = hostport.rsplit(":", 1) if ":" in hostport else (hostport, None)
                if server and port_s:
                    return {"name": fragment or f"SS-{server}", "type": "ss", "server": server, "port": int(port_s), "cipher": method, "password": password}
        elif line.startswith("ssr://"):
            return parse_ssr_link(line)
        elif line.startswith("vmess://"):
            config = json.loads(b64decode_pad(line[8:]).decode("utf-8", errors="ignore"))
            net = (config.get("net") or "tcp").lower()
            node = {
                "name": config.get("ps") or f"Vmess-{config.get('add', 'node')}",
                "type": "vmess", "server": config.get("add"), "port": int(config.get("port", 443)),
                "uuid": config.get("id"), "alterId": int(config.get("aid", 0)),
                "cipher": config.get("scy") or config.get("security") or "auto", "skip-cert-verify": True
            }
            if net and net != "tcp":
                node["network"] = net
            if str(config.get("tls", "")).lower() in ("tls", "1", "true"):
                node["tls"] = True
                if (sni := config.get("sni") or config.get("host") or config.get("peer")):
                    node["servername"] = sni
            if net == "ws" and (path := config.get("path")):
                node["ws-opts"] = {"path": path, **({"headers": {"Host": host}} if (host := config.get("host")) else {})}
            elif net == "grpc" and (svc := config.get("path") or config.get("serviceName")):
                node["grpc-opts"] = {"grpc-service-name": svc}
            elif net == "h2" and (path := config.get("path")):
                node["h2-opts"] = {"path": path, **({"host": [host] if isinstance(host, str) else host} if (host := config.get("host")) else {})}
            elif net == "http" and (path := config.get("path")):
                node["http-opts"] = {"path": [path] if isinstance(path, str) else path, **({"headers": {"Host": [host]}} if (host := config.get("host")) else {})}
            return node if validate_node_by_official_standard(node) else None
        else:
            parsed = urllib.parse.urlparse(line)
            scheme = (parsed.scheme or "").lower()
            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            node = None
            if scheme in ("hysteria2", "hy2"):
                node = {
                    "name": fragment or f"Hy2-{server}", "type": "hysteria2", "server": server, "port": port,
                    "password": password or _qget(query, "auth", default=""), "skip-cert-verify": True,
                    **({"sni": sni} if (sni := _qget(query, "sni")) else {}),
                    **({"obfs": obfs} if (obfs := _qget(query, "obfs")) else {}),
                    **({"obfs-password": op} if (op := _qget(query, "obfs-password")) else {})
                }
            elif scheme == "vless":
                node = {
                    "name": fragment or f"Vless-{server}", "type": "vless", "server": server, "port": port,
                    "uuid": password, "client-fingerprint": _qget(query, "fp", default="chrome"), "skip-cert-verify": True,
                    **({"tls": True} if (_qget(query, "security") in ("tls", "reality") or "encryption" in query) else {}),
                    **({"servername": sni} if (sni := _qget(query, "sni")) else {}),
                    **({"flow": flow} if (flow := _qget(query, "flow")) else {})
                }
                if _qget(query, "security") == "reality":
                    ropts = {}
                    if (pbk := _qget(query, "pbk")): ropts["public-key"] = pbk
                    if (sid := _qget(query, "sid")): ropts["short-id"] = sid
                    if ropts: node["reality-opts"] = ropts
                _apply_transport_opts(node, _qget(query, "type", "network", default="tcp"), query)
            elif scheme == "trojan":
                node = {
                    "name": fragment or f"Trojan-{server}", "type": "trojan", "server": server, "port": port,
                    "password": password, "skip-cert-verify": True,
                    **({"sni": sni} if (sni := _qget(query, "sni")) else {})
                }
                _apply_transport_opts(node, _qget(query, "type", "network", default="tcp"), query)
            elif scheme == "tuic":
                node = {
                    "name": fragment or f"Tuic-{server}", "type": "tuic", "server": server, "port": port,
                    "uuid": password, "password": parsed.password or "", "skip-cert-verify": True,
                    **({"sni": sni} if (sni := _qget(query, "sni")) else {}),
                    **({"congestion-controller": cc} if (cc := _qget(query, "congestion_control", "congestion-controller")) else {})
                }
            elif scheme == "anytls":
                node = {
                    "name": fragment or f"AnyTLS-{server}", "type": "anytls", "server": server, "port": port,
                    "password": password, "skip-cert-verify": True, "udp": True,
                    **({"sni": sni} if (sni := _qget(query, "sni")) else {}),
                    **({"client-fingerprint": fp} if (fp := _qget(query, "fp")) else {})
                }
            elif scheme == "mieru":
                node = {
                    "name": fragment or f"Mieru-{server}", "type": "mieru", "server": server,
                    "username": password or _qget(query, "username", default=""),
                    "password": parsed.password or _qget(query, "password", default=""),
                    "transport": _qget(query, "transport", default="TCP"),
                    "multiplexing": _qget(query, "multiplexing", default="MULTIPLEXING_LOW"),
                    "udp": True, **({"port-range": pr} if (pr := _qget(query, "port-range")) else {"port": port})
                }
            if node and validate_node_by_official_standard(node):
                return node
    except Exception:
        return None
    return None


def normalize_yaml_node(raw):
    if not isinstance(raw, dict):
        return None
    ptype = str(raw.get("type", "")).lower().strip()
    if not ptype:
        return None
    node = dict(raw)
    node["type"] = "hysteria2" if ptype == "hy2" else ptype
    if node["type"] in ("vmess", "vless", "trojan"):
        net = (node.get("network") or "tcp").lower()
        if net == "ws" and "ws-opts" not in node and (path := node.pop("ws-path", None)):
            node["ws-opts"] = {"path": path, **({"headers": node.pop("ws-headers")} if "ws-headers" in node else {})}
        elif net == "grpc" and "grpc-opts" not in node and (svc := node.pop("grpc-service-name", None)):
            node["grpc-opts"] = {"grpc-service-name": svc}
    return node if validate_node_by_official_standard(node) else None


def collect_files(inputs, output_filename="filtered_nodes.yaml"):
    skip_names = set(SKIP_FILENAMES) | {output_filename}
    files = set()
    for item in inputs:
        p = Path(item).expanduser()
        p = (Path.cwd() / p).resolve() if not p.is_absolute() else p.resolve()
        if not p.exists():
            continue
        if p.is_file() and not p.name.lower().startswith(".") and p.name.lower() not in skip_names and p.suffix.lower() in NODE_FILE_EXTS:
            files.add(p)
        elif p.is_dir():
            for fp in p.rglob("*"):
                if fp.is_file() and not fp.name.lower().startswith(".") and fp.name.lower() not in skip_names and fp.suffix.lower() in NODE_FILE_EXTS:
                    files.add(fp.resolve())
    return sorted(str(f) for f in files)


def quick_tcp_check(server, port, timeout=TCP_TIMEOUT):
    try:
        with socket.create_connection((str(server), int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def load_nodes_line_by_line(path):
    nodes, reject, scanned, blank = [], 0, 0, 0
    ext = Path(path).suffix.lower()
    try:
        if ext in (".yaml", ".yml"):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            proxies = data.get("proxies", data) if isinstance(data, (dict, list)) else []
            scanned = len(proxies)
            for raw in proxies:
                if (node := normalize_yaml_node(raw)):
                    nodes.append(node)
                else:
                    reject += 1
        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    scanned += 1
                    stripped = line.strip()
                    if not stripped or stripped.startswith(("#", "//")):
                        blank += 1
                        continue
                    if (node := parse_share_link(stripped)):
                        nodes.append(node)
                    else:
                        reject += 1
    except Exception as e:
        log(f"读取失败: {path}: {e}")
    return nodes, scanned, reject, blank


def stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps, batch_size):
    seen_fps = set()
    def check_node_tcp(node):
        if node.get("_inherited_valid") or str(node.get("type", "")).lower() in SKIP_TCP_TYPES or not (port := node.get("port")):
            return node
        return node if quick_tcp_check(node.get("server"), port) else None

    for path in files:
        file_nodes, _, _, _ = load_nodes_line_by_line(path)
        file_passed_list = []
        for node in file_nodes:
            if (fp := fingerprint(node)) in tested_fps or fp in invalid_pool or fp in seen_fps:
                continue
            seen_fps.add(fp)
            if fp in valid_pool:
                node["_inherited_valid"] = True
            file_passed_list.append(node)
        
        chunk = []
        for node in file_passed_list:
            if node.get("_inherited_valid") or str(node.get("type", "")).lower() in SKIP_TCP_TYPES:
                yield node
                continue
            chunk.append(node)
            if len(chunk) >= TCP_CHUNK:
                for res in ThreadPoolExecutor(max_workers=TCP_WORKERS).map(check_node_tcp, chunk):
                    if res: yield res
                chunk = []
        if chunk:
            for res in ThreadPoolExecutor(max_workers=TCP_WORKERS).map(check_node_tcp, chunk):
                if res: yield res


def write_test_config(nodes, path):
    config = {
        "mixed-port": 7898, "allow-lan": False, "mode": "rule", "log-level": "error",
        "ipv6": False, "unified-delay": True, "tcp-concurrent": True,
        "external-controller": f"{API_HOST}:{API_PORT}", "secret": API_SECRET, "proxies": nodes
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def wait_api(proc):
    url = f"http://{API_HOST}:{API_PORT}/version"
    end_time = time.time() + 25
    while time.time() < end_time:
        if proc.poll() is not None:
            raise RuntimeError(f"Mihomo 提前退出: {proc.returncode}")
        try:
            if requests.get(url, headers={"Authorization": f"Bearer {API_SECRET}"}, timeout=1.5).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(0.25)
    raise TimeoutError("等待 Mihomo API 超时")


def test_one(node):
    name = node["name"]
    delays = []
    try:
        for _, tests in TEST_GROUPS:
            for _, url in tests:
                r = requests.get(f"http://{API_HOST}:{API_PORT}/proxies/{urllib.parse.quote(name, safe='')}/delay",
                                 params={"timeout": TIMEOUT_MS, "url": url, "expected": "200-299"},
                                 headers={"Authorization": f"Bearer {API_SECRET}"}, timeout=TIMEOUT_MS / 1000 + 4)
                r.raise_for_status()
                if (d := r.json().get("delay")) and isinstance(d, int) and d > 0:
                    delays.append(d)
                else:
                    raise RuntimeError("无效 delay")
    except Exception as e:
        return {"name": name, "node": node, "ok": False, "error": str(e)}
    return {"name": name, "node": node, "ok": True, "avg": round(sum(delays) / len(delays), 1)}


def unique_names(nodes):
    used, counters = set(), {}
    for node in nodes:
        base = safe_name(node.get("name"))
        if base not in used:
            node["name"], used, counters[base] = base, used | {base}, 1
            continue
        i = counters.get(base, 1)
        while (candidate := f"{base} #{i}") in used:
            i += 1
        node["name"], used, counters[base] = candidate, used | {candidate}, i + 1
    return nodes


def save_batch_yaml(good_nodes, batch_idx):
    out_dir = Path("generated/batches")
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / f"filtered_batch_{batch_idx:03d}.yaml"
    data = {
        "proxies": good_nodes,
        "proxy-groups": [{"name": "CF-Nest-Batch", "type": "select", "proxies": [p["name"] for p in good_nodes] or ["DIRECT"]}],
        "rules": ["MATCH,CF-Nest-Batch"]
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return filepath


def load_pool(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def save_pool(path, pool_set):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(pool_set), f)


def process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx):
    good_nodes = []
    unique_names(batch_slice)
    with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        proc = None
        try:
            write_test_config(batch_slice, config_path)
            proc = subprocess.Popen([args.mihomo, "-d", temp_dir, "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_api(proc)
            with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                futures = [executor.submit(test_one, node) for node in batch_slice]
                for index, future in enumerate(as_completed(futures), 1):
                    res = future.result()
                    node_fp = fingerprint(res["node"])
                    tested_fps.add(node_fp)
                    if res["ok"]:
                        valid_pool.add(node_fp)
                        good_nodes.append(res["node"])
                    else:
                        invalid_pool.add(node_fp)
                    if index % 50 == 0:
                        save_pool(CHECKPOINT_FILE, tested_fps)
                        save_pool(VALID_POOL_FILE, valid_pool)
                        save_pool(INVALID_POOL_FILE, invalid_pool)
        except Exception:
            pass
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
    save_pool(CHECKPOINT_FILE, tested_fps)
    save_pool(VALID_POOL_FILE, valid_pool)
    save_pool(INVALID_POOL_FILE, invalid_pool)
    return good_nodes


def build_final_aio_streamed(output_path):
    output = Path(output_path).resolve()
    temp_output = str(output) + ".tmp"
    all_names, seen_name = [], set()
    for bfile in sorted(glob.glob("generated/batches/filtered_batch_*.yaml")):
        with open(bfile, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for p in data.get("proxies", []):
            if (n := p.get("name")) and n not in seen_name:
                all_names.append(n)
                seen_name.add(n)

    config_skeleton = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info",
        "ipv6": False, "unified-delay": True, "tcp-concurrent": True,
        "dns": {
            "enable": True, "ipv6": False, "listen": "0.0.0.0:53", "enhanced-mode": "fake-ip",
            "nameserver": ["223.5.5.5", "119.29.29.29"], "fallback": ["1.1.1.1", "8.8.8.8"]
        },
        "rule-providers": {
            "reject-ads": {
                "type": "http", "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
                "path": "./rules/reject_ads.yaml", "interval": 86400
            },
            "china-list": {
                "type": "http", "behavior": "domain",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
                "path": "./rules/china_list.yaml", "interval": 86400
            },
            "china-ip": {
                "type": "http", "behavior": "ipcidr",
                "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cnip.txt",
                "path": "./rules/china_ip.yaml", "interval": 86400
            }
        },
        "proxy-groups": [
            {"name": "节点选择", "type": "select", "proxies": all_names if all_names else ["DIRECT"]},
            {"name": "自动选择", "type": "url-test", "proxies": all_names if all_names else ["DIRECT"], "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000},
            {"name": "去广告", "type": "select", "proxies": ["REJECT", "DIRECT"]},
            {"name": "国内直连", "type": "select", "proxies": ["DIRECT", "节点选择"]},
            {"name": "国外代理", "type": "select", "proxies": ["节点选择", "自动选择", "DIRECT"]}
        ],
        "rules": [
            "RULE-SET,reject-ads,去广告",
            "RULE-SET,china-list,国内直连",
            "RULE-SET,china-ip,国内直连",
            "MATCH,国外代理"
        ]
    }

    with open(temp_output, "w", encoding="utf-8") as out_f:
        yaml.safe_dump({k: v for k, v in config_skeleton.items() if k != "proxies"}, out_f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        out_f.write("proxies:\n")
        total_proxies, written_names = 0, set()
        for bfile in sorted(glob.glob("generated/batches/filtered_batch_*.yaml")):
            with open(bfile, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for p in data.get("proxies", []):
                if (n := p.get("name")) and n not in written_names:
                    written_names.add(n)
                    for line in yaml.safe_dump([p], allow_unicode=True, sort_keys=False, default_flow_style=False).strip().splitlines():
                        out_f.write(f"  {line}\n")
                    total_proxies += 1
    os.replace(temp_output, output)
    log(f"成功生成配置: {output} (共 {total_proxies} 个节点)")
    return total_proxies


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="*", help="输入路径")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--mihomo", default=MIHOMO_BIN)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()

    files = collect_files(args.inputs if args.inputs else DEFAULT_INPUT_PATTERNS, args.output)
    if not files:
        raise SystemExit("错误：未找到输入节点文件。")
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"错误：找不到 Mihomo: {args.mihomo}")

    tested_fps = load_pool(CHECKPOINT_FILE)
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)

    for old_b in glob.glob("generated/batches/filtered_batch_*.yaml"):
        try:
            os.remove(old_b)
        except Exception:
            pass

    batch_idx, batch_slice = 1, []
    try:
        log("开始流式处理节点与测速...")
        for node in stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps, max(1, int(args.batch_size))):
            node = copy.deepcopy(node)
            node.pop("_inherited_valid", None)
            batch_slice.append(node)
            if len(batch_slice) >= max(1, int(args.batch_size)):
                if (processed_good := process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx)):
                    save_batch_yaml(processed_good, batch_idx)
                batch_idx, batch_slice = batch_idx + 1, []
        if batch_slice:
            if (processed_good := process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx)):
                save_batch_yaml(processed_good, batch_idx)
    finally:
        save_pool(CHECKPOINT_FILE, tested_fps)
        save_pool(VALID_POOL_FILE, valid_pool)
        save_pool(INVALID_POOL_FILE, invalid_pool)

    if not glob.glob("generated/batches/filtered_batch_*.yaml"):
        raise SystemExit("错误：没有生成任何有效批次文件。")

    if build_final_aio_streamed(args.output) == 0:
        raise SystemExit("错误：最终配置节点数为 0。")
    
    log("全部流程执行完毕！")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
