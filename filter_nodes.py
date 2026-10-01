#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V6 全目录海量节点审计与清洗引擎
- 协议：ss / ssr / vmess / vless / trojan / hysteria2 / tuic / anytls / mieru / wireguard
- 传输层：完善 VMess/VLESS 的 ws / grpc / h2 / http / xhttp 参数
- ShadowTLS：作为 SS 的 plugin 支持
"""

import argparse
import copy
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import base64
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml

DEFAULT_INPUT_PATTERNS = ["nodes"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
VALID_POOL_FILE = ".valid_pool.json"
INVALID_POOL_FILE = ".invalid_pool.json"
BATCH_SIZE = 300
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")
API_HOST, API_PORT, API_SECRET = "127.0.0.1", 9097, "test-only-secret"
TIMEOUT_MS, CONCURRENCY = 3000, 32

# 指纹只取核心身份字段，避免 skip-cert-verify / sni 写法差异导致重复测
CORE_FINGERPRINT_KEYS = (
    "type", "server", "port", "uuid", "password", "cipher", "alterId",
    "protocol", "obfs", "protocol-param", "obfs-param",
    "private-key", "public-key", "ip", "username", "psk",
)

TEST_GROUPS = [
    ("基础连通性", [
        ("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"),
        ("Google 204", "https://www.google.com/generate_204"),
    ]),
    ("实际网站", [
        ("Google 首页", "https://www.google.com/"),
        ("Telegram", "https://t.me/telegram/"),
    ]),
]

# UDP / 无传统 TCP 握手的协议，跳过 TCP 预检
SKIP_TCP_TYPES = {"hysteria2", "hy2", "tuic", "wireguard", "mieru", "warp"}


def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S]"), msg, flush=True)


def safe_name(name):
    return str(name or "node").strip() or "node"


def b64decode_pad(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s)


def fingerprint(proxy):
    obj = {}
    for k in CORE_FINGERPRINT_KEYS:
        if k in proxy and proxy[k] is not None:
            obj[k] = proxy[k]
    # 对 ws/grpc 等路径也纳入指纹，避免同 host 不同 path 被合并
    for opt_key in ("ws-opts", "grpc-opts", "h2-opts", "http-opts", "xhttp-opts", "plugin-opts"):
        if opt_key in proxy and isinstance(proxy[opt_key], dict):
            obj[opt_key] = proxy[opt_key]
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_node_by_official_standard(node):
    if not isinstance(node, dict):
        return False
    ptype = str(node.get("type", "")).lower().strip()
    server = str(node.get("server", "") or "").strip()
    port = node.get("port")

    if not ptype:
        return False

    # wireguard / mieru 的 port 可能用 port-range
    if ptype == "wireguard":
        if not node.get("private-key"):
            return False
        # 简化写法需要 server+port+public-key；多 peer 写法需要 peers
        if node.get("peers"):
            return True
        if not server or not node.get("public-key"):
            return False
    elif ptype == "mieru":
        if not server:
            return False
        if not node.get("username") or not node.get("password"):
            return False
        if not port and not node.get("port-range"):
            return False
    else:
        if not server:
            return False
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                return False
        except (TypeError, ValueError):
            return False

    if ptype == "ss":
        if not node.get("cipher") or not node.get("password"):
            return False
    elif ptype == "ssr":
        if not node.get("cipher") or not node.get("password"):
            return False
        if not node.get("protocol") or not node.get("obfs"):
            return False
    elif ptype in ("vmess", "vless"):
        if not node.get("uuid"):
            return False
    elif ptype == "trojan":
        if not node.get("password"):
            return False
    elif ptype in ("hysteria2", "hy2"):
        if not node.get("password"):
            return False
    elif ptype == "tuic":
        if not node.get("uuid") and not node.get("password"):
            return False
    elif ptype == "anytls":
        if not node.get("password"):
            return False
    elif ptype in ("wireguard", "mieru"):
        pass
    else:
        return False
    return True


def _apply_transport_opts(node, network, query):
    """根据 network 填充 ws/grpc/h2/http/xhttp 选项（query 来自 URI 查询参数）"""
    network = (network or "tcp").lower()
    if network and network != "tcp":
        node["network"] = network

    if network == "ws":
        opts = {}
        path = query.get("path", query.get("ws-path", [None]))[0] if isinstance(query, dict) else None
        if path:
            opts["path"] = path
        host = None
        if isinstance(query, dict):
            host = (query.get("host") or query.get("Host") or [None])[0]
        if host:
            opts["headers"] = {"Host": host}
        if opts:
            node["ws-opts"] = opts
    elif network == "grpc":
        opts = {}
        svc = None
        if isinstance(query, dict):
            svc = (query.get("serviceName") or query.get("service-name") or query.get("grpc-service-name") or [None])[0]
        if svc:
            opts["grpc-service-name"] = svc
        if opts:
            node["grpc-opts"] = opts
    elif network == "h2":
        opts = {}
        if isinstance(query, dict):
            path = (query.get("path") or [None])[0]
            host = (query.get("host") or [None])[0]
            if path:
                opts["path"] = path
            if host:
                opts["host"] = [host] if isinstance(host, str) else host
        if opts:
            node["h2-opts"] = opts
    elif network == "http":
        opts = {}
        if isinstance(query, dict):
            path = (query.get("path") or [None])[0]
            host = (query.get("host") or [None])[0]
            if path:
                opts["path"] = [path] if isinstance(path, str) else path
            if host:
                opts["headers"] = {"Host": [host]}
        if opts:
            node["http-opts"] = opts
    elif network in ("xhttp", "splithttp"):
        node["network"] = "xhttp"
        opts = {}
        if isinstance(query, dict):
            path = (query.get("path") or [None])[0]
            host = (query.get("host") or [None])[0]
            mode = (query.get("mode") or [None])[0]
            if path:
                opts["path"] = path
            if host:
                opts["host"] = host
            if mode:
                opts["mode"] = mode
        if opts:
            node["xhttp-opts"] = opts


def parse_ssr_link(line):
    """ssr://base64(server:port:protocol:method:obfs:base64(password)/?params)"""
    raw = line[6:].strip()
    if "#" in raw:
        raw, _ = raw.split("#", 1)
    try:
        decoded = b64decode_pad(raw).decode("utf-8", errors="ignore")
    except Exception:
        return None

    main, _, query_str = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        return None
    server, port_s, protocol, method, obfs = parts[0], parts[1], parts[2], parts[3], parts[4]
    password_b64 = ":".join(parts[5:])  # 密码段可能含冒号
    try:
        password = b64decode_pad(password_b64).decode("utf-8", errors="ignore")
    except Exception:
        password = password_b64

    try:
        port = int(port_s)
    except ValueError:
        return None

    node = {
        "name": f"SSR-{server}",
        "type": "ssr",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
        "protocol": protocol,
        "obfs": obfs,
    }

    if query_str:
        qs = urllib.parse.parse_qs(query_str)
        def _b64_param(key):
            v = qs.get(key, [None])[0]
            if not v:
                return None
            try:
                return b64decode_pad(v).decode("utf-8", errors="ignore")
            except Exception:
                return v

        remarks = _b64_param("remarks")
        if remarks:
            node["name"] = remarks
        obfsparam = _b64_param("obfsparam")
        if obfsparam:
            node["obfs-param"] = obfsparam
        protoparam = _b64_param("protoparam")
        if protoparam:
            node["protocol-param"] = protoparam

    return node


def parse_share_link(line):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    node = None
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
                if ":" in hostport:
                    server, port_s = hostport.rsplit(":", 1)
                else:
                    server, port_s = hostport, None
                if server and port_s:
                    node = {
                        "name": fragment or f"SS-{server}",
                        "type": "ss",
                        "server": server,
                        "port": int(port_s),
                        "cipher": method,
                        "password": password,
                    }

        elif line.startswith("ssr://"):
            node = parse_ssr_link(line)

        elif line.startswith("vmess://"):
            raw_b64 = line[8:]
            config = json.loads(b64decode_pad(raw_b64).decode("utf-8", errors="ignore"))
            node = {
                "name": config.get("ps") or f"Vmess-{config.get('add', 'node')}",
                "type": "vmess",
                "server": config.get("add"),
                "port": int(config.get("port", 443)),
                "uuid": config.get("id"),
                "alterId": int(config.get("aid", 0)),
                "cipher": config.get("scy") or config.get("security") or "auto",
                "skip-cert-verify": True,
            }
            net = (config.get("net") or "tcp").lower()
            if net and net != "tcp":
                node["network"] = net
            if config.get("tls") in ("tls", "1", True, "true"):
                node["tls"] = True
                sni = config.get("sni") or config.get("host") or config.get("peer")
                if sni:
                    node["servername"] = sni
            # 传输层
            if net == "ws":
                opts = {}
                if config.get("path"):
                    opts["path"] = config["path"]
                host = config.get("host")
                if host:
                    opts["headers"] = {"Host": host}
                if opts:
                    node["ws-opts"] = opts
            elif net == "grpc":
                opts = {}
                svc = config.get("path") or config.get("serviceName")
                if svc:
                    opts["grpc-service-name"] = svc
                if opts:
                    node["grpc-opts"] = opts
            elif net == "h2":
                opts = {}
                if config.get("path"):
                    opts["path"] = config["path"]
                host = config.get("host")
                if host:
                    opts["host"] = [host] if isinstance(host, str) else host
                if opts:
                    node["h2-opts"] = opts
            elif net == "http":
                opts = {}
                if config.get("path"):
                    opts["path"] = [config["path"]] if isinstance(config["path"], str) else config["path"]
                host = config.get("host")
                if host:
                    opts["headers"] = {"Host": [host]}
                if opts:
                    node["http-opts"] = opts

        else:
            parsed = urllib.parse.urlparse(line)
            scheme = parsed.scheme.lower()
            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username or ""
            uuid = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""

            if scheme in ("hysteria2", "hy2"):
                node = {
                    "name": fragment or f"Hy2-{server}",
                    "type": "hysteria2",
                    "server": server,
                    "port": port,
                    "password": password or (query.get("auth") or [""])[0],
                    "skip-cert-verify": True,
                }
                if "sni" in query:
                    node["sni"] = query["sni"][0]
                if "obfs" in query:
                    node["obfs"] = query["obfs"][0]
                if "obfs-password" in query:
                    node["obfs-password"] = query["obfs-password"][0]

            elif scheme == "vless":
                node = {
                    "name": fragment or f"Vless-{server}",
                    "type": "vless",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "client-fingerprint": (query.get("fp") or ["chrome"])[0],
                    "skip-cert-verify": True,
                }
                security = (query.get("security") or [""])[0].lower()
                if security in ("tls", "reality") or "encryption" in query:
                    node["tls"] = True
                if "sni" in query:
                    node["servername"] = query["sni"][0]
                if "flow" in query:
                    node["flow"] = query["flow"][0]
                if security == "reality":
                    ropts = {}
                    if "pbk" in query:
                        ropts["public-key"] = query["pbk"][0]
                    if "sid" in query:
                        ropts["short-id"] = query["sid"][0]
                    if ropts:
                        node["reality-opts"] = ropts
                net = (query.get("type") or query.get("network") or ["tcp"])[0]
                _apply_transport_opts(node, net, query)

            elif scheme == "trojan":
                node = {
                    "name": fragment or f"Trojan-{server}",
                    "type": "trojan",
                    "server": server,
                    "port": port,
                    "password": password,
                    "skip-cert-verify": True,
                }
                if "sni" in query:
                    node["sni"] = query["sni"][0]
                net = (query.get("type") or query.get("network") or ["tcp"])[0]
                _apply_transport_opts(node, net, query)

            elif scheme == "tuic":
                node = {
                    "name": fragment or f"Tuic-{server}",
                    "type": "tuic",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "password": parsed.password or "",
                    "skip-cert-verify": True,
                }
                if "sni" in query:
                    node["sni"] = query["sni"][0]
                if "congestion_control" in query or "congestion-controller" in query:
                    node["congestion-controller"] = (
                        query.get("congestion_control") or query.get("congestion-controller") or ["bbr"]
                    )[0]

            elif scheme == "anytls":
                node = {
                    "name": fragment or f"AnyTLS-{server}",
                    "type": "anytls",
                    "server": server,
                    "port": port,
                    "password": password,
                    "skip-cert-verify": True,
                    "udp": True,
                }
                if "sni" in query:
                    node["sni"] = query["sni"][0]
                if "fp" in query:
                    node["client-fingerprint"] = query["fp"][0]

            elif scheme == "mieru":
                # 自定义或少见 URI，尽量从 query 取
                node = {
                    "name": fragment or f"Mieru-{server}",
                    "type": "mieru",
                    "server": server,
                    "username": uuid or (query.get("username") or [""])[0],
                    "password": parsed.password or (query.get("password") or [""])[0],
                    "transport": (query.get("transport") or ["TCP"])[0],
                    "multiplexing": (query.get("multiplexing") or ["MULTIPLEXING_LOW"])[0],
                    "udp": True,
                }
                if "port-range" in query:
                    node["port-range"] = query["port-range"][0]
                else:
                    node["port"] = port

            elif scheme in ("ss",) and "plugin" in query:
                # 带 plugin 的 ss 链接已在 ss:// 分支处理；此处兜底
                pass

    except Exception:
        pass

    return node if node and validate_node_by_official_standard(node) else None


def normalize_yaml_node(node):
    """对 YAML 读入的节点做轻量规范化，补全常见字段别名"""
    if not isinstance(node, dict):
        return None
    ptype = str(node.get("type", "")).lower().strip()
    if not ptype:
        return None
    node = dict(node)
    node["type"] = ptype

    # hy2 别名
    if ptype == "hy2":
        node["type"] = "hysteria2"

    # ShadowTLS 作为 SS plugin 时保留 plugin / plugin-opts
    if ptype == "ss" and node.get("plugin") == "shadow-tls":
        pass  # 保持原样，validate 已通过 cipher+password

    # VMess/VLESS 网络层字段兼容
    if ptype in ("vmess", "vless", "trojan"):
        net = (node.get("network") or "tcp").lower()
        if net == "ws" and "ws-opts" not in node and node.get("ws-path"):
            opts = {"path": node.pop("ws-path", "/")}
            if node.get("ws-headers"):
                opts["headers"] = node.pop("ws-headers")
            node["ws-opts"] = opts
        if net == "grpc" and "grpc-opts" not in node and node.get("grpc-service-name"):
            node["grpc-opts"] = {"grpc-service-name": node.pop("grpc-service-name")}

    if not validate_node_by_official_standard(node):
        return None
    return node


def collect_files(inputs, output_filename="filtered_nodes.yaml", skip_filename="gem.yaml"):
    files = set()
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for ext in ("*.txt", "*.yaml", "*.yml", "*.conf", "*.list"):
                for f in p.rglob(ext):
                    if f.name not in (output_filename, skip_filename):
                        files.add(f.resolve())
        else:
            if p.exists() and p.name not in (output_filename, skip_filename):
                files.add(p.resolve())
    return sorted([str(f) for f in files])


def quick_tcp_check(server, port, timeout=0.6):
    try:
        with socket.create_connection((str(server), int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps):
    seen_fps = set()
    file_stats = {}
    total_raw_scanned = 0
    total_raw_valid = 0
    total_inherited = 0
    total_tcp_filtered = 0
    total_passed_tcp = 0
    total_already_tested = 0

    def check_node_tcp(node):
        if node.get("_inherited_valid"):
            return node
        ptype = str(node.get("type", "")).lower()
        if ptype in SKIP_TCP_TYPES:
            return node
        # mieru 可能只有 port-range
        port = node.get("port")
        if not port:
            return node
        return node if quick_tcp_check(node.get("server"), port) else None

    for path in files:
        path_key = str(path)
        file_scanned_count = 0
        file_valid_count = 0
        file_nodes = []

        if path_key.endswith((".yaml", ".yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    proxies = data.get("proxies", [])
                    file_scanned_count = len(proxies)
                    for raw in proxies:
                        node = normalize_yaml_node(raw)
                        if node:
                            file_nodes.append(node)
            except Exception as e:
                log(f"❌ YAML 文件读取失败: {path}: {e}")
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        file_scanned_count += 1
                        node = parse_share_link(line)
                        if node:
                            file_nodes.append(node)
            except Exception as e:
                log(f"❌ 文本文件读取失败: {path}: {e}")

        total_raw_scanned += file_scanned_count
        file_passed_list = []
        for node in file_nodes:
            fp = fingerprint(node)
            if fp in tested_fps or fp in invalid_pool or fp in seen_fps:
                if fp in tested_fps or fp in invalid_pool:
                    total_already_tested += 1
                continue
            seen_fps.add(fp)
            total_raw_valid += 1
            file_valid_count += 1

            if fp in valid_pool:
                node["_inherited_valid"] = True
                total_inherited += 1
                total_passed_tcp += 1
                file_passed_list.append(node)
                continue
            file_passed_list.append(node)

        file_stats[path_key] = {"scanned": file_scanned_count, "valid": file_valid_count}
        try:
            rel = Path(path_key).relative_to(Path.cwd())
        except ValueError:
            rel = path_key
        log(f"📂 [源文件扫描] {rel} -> 原始行数/条目: {file_scanned_count} | 提取合规未测: {file_valid_count}")

        chunk = []
        for node in file_passed_list:
            if node.get("_inherited_valid"):
                yield node
                continue
            chunk.append(node)
            if len(chunk) >= 2000:
                for res in flush_tcp_chunk(chunk, check_node_tcp):
                    if res:
                        total_passed_tcp += 1
                        yield res
                    else:
                        total_tcp_filtered += 1
                chunk = []
        if chunk:
            for res in flush_tcp_chunk(chunk, check_node_tcp):
                if res:
                    total_passed_tcp += 1
                    yield res
                else:
                    total_tcp_filtered += 1

    expected_batches = (total_passed_tcp + BATCH_SIZE - 1) // BATCH_SIZE if total_passed_tcp > 0 else 0
    log(f"\n==================== 📊 全库物料盘点与总账统计报告 ====================")
    log(f"📁 扫描输入源文件总数: {len(files)} 个")
    for p, st in file_stats.items():
        rel_name = Path(p).name
        log(f"   - 📄 [{rel_name}] 原始扫描: {st['scanned']} 条 | 有效提取: {st['valid']} 条")
    log(f"-----------------------------------------------------------------")
    log(f"📦 累计全网检索原始总条目数: {total_raw_scanned} 条")
    log(f"🛑 历史缓存已测/失效拦截(跳过): {total_already_tested} 条")
    log(f"🔍 本轮合规标准质检总新增: {total_raw_valid} 条")
    log(f"♻️ 历史白名单继承命中: {total_inherited} 条")
    log(f"⚡ TCP 离线预检剔除死节点: {total_tcp_filtered} 条")
    log(f"🎯 最终进入本轮 Mihomo 测速总池: {total_passed_tcp} 条")
    log(f"📦 本轮动态划分测速总批次: {expected_batches} 批 (每批 {BATCH_SIZE} 条)")
    log(f"=================================================================\n")


def flush_tcp_chunk(chunk, check_func):
    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(check_func, node): node for node in chunk}
        for future in as_completed(futures):
            yield future.result()


def write_test_config(nodes, path):
    config = {
        "mixed-port": 7898,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "external-controller": f"{API_HOST}:{API_PORT}",
        "secret": API_SECRET,
        "proxies": nodes,
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def wait_api(proc):
    url = f"http://{API_HOST}:{API_PORT}/version"
    end_time = time.time() + 25
    while time.time() < end_time:
        if proc.poll() is not None:
            raise RuntimeError(f"Mihomo 提前退出，returncode={proc.returncode}")
        try:
            if requests.get(url, headers={"Authorization": f"Bearer {API_SECRET}"}, timeout=1.5).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(0.25)
    raise TimeoutError("等待 Mihomo API 超时")


def api_delay(name, url):
    encoded_name = urllib.parse.quote(name, safe="")
    api_url = f"http://{API_HOST}:{API_PORT}/proxies/{encoded_name}/delay"
    params = {"timeout": TIMEOUT_MS, "url": url, "expected": "200-299"}
    response = requests.get(
        api_url,
        params=params,
        headers={"Authorization": f"Bearer {API_SECRET}"},
        timeout=TIMEOUT_MS / 1000 + 4,
    )
    response.raise_for_status()
    data = response.json()
    delay = data.get("delay")
    if not isinstance(delay, int) or delay <= 0:
        raise RuntimeError(f"无效 delay: {data}")
    return delay


def test_one(node):
    name, delays = node["name"], []
    for stage, tests in TEST_GROUPS:
        for label, url in tests:
            try:
                delays.append(api_delay(name, url))
            except Exception as e:
                return {"name": name, "node": node, "ok": False, "error": str(e)}
    if len(delays) != sum(len(t) for _, t in TEST_GROUPS):
        return {"name": name, "node": node, "ok": False, "error": "测试数量不全"}
    return {"name": name, "node": node, "ok": True, "avg": round(sum(delays) / len(delays), 1)}


def save_batch_yaml(good_nodes, batch_idx):
    out_dir = Path("generated/batches")
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / f"filtered_batch_{batch_idx:03d}.yaml"
    data = {
        "proxies": good_nodes,
        "proxy-groups": [
            {
                "name": "CF-Nest-Batch",
                "type": "select",
                "proxies": [p["name"] for p in good_nodes] or ["DIRECT"],
            }
        ],
        "rules": ["MATCH,CF-Nest-Batch"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    log(f"💾 合格批次已保存: {filepath} (共留存 {len(good_nodes)} 个优质节点)")
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


def unique_names(nodes):
    """批内/跨批统一去重命名"""
    used = set()
    counters = {}
    for node in nodes:
        base = safe_name(node.get("name"))
        if base not in used:
            node["name"] = base
            used.add(base)
            counters[base] = 1
            continue
        i = counters.get(base, 1)
        while True:
            candidate = f"{base} #{i}"
            if candidate not in used:
                node["name"] = candidate
                used.add(candidate)
                counters[base] = i + 1
                break
            i += 1
    return nodes


def build_final_aio_streamed(output_path):
    output = Path(output_path).resolve()
    temp_output = str(output) + ".tmp"
    log("📦 正在以流式方式合并所有批次生成最终 AIO 配置...")

    all_names = []
    seen_name = set()
    for bfile in sorted(glob.glob("generated/batches/filtered_batch_*.yaml")):
        with open(bfile, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                for p in data.get("proxies", []):
                    n = p.get("name")
                    if n and n not in seen_name:
                        all_names.append(n)
                        seen_name.add(n)

    config_skeleton = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": all_names if all_names else ["DIRECT"],
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": all_names if all_names else ["DIRECT"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "timeout": 5000,
            },
            {
                "name": "🇨🇳 国内直连",
                "type": "select",
                "proxies": ["DIRECT", "🚀 节点选择"],
            },
            {
                "name": "🌍 国外代理",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择", "DIRECT"],
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🌍 国外代理",
        ],
    }

    with open(temp_output, "w", encoding="utf-8") as out_f:
        header_data = {k: v for k, v in config_skeleton.items() if k != "proxies"}
        yaml.safe_dump(header_data, out_f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        out_f.write("proxies:\n")
        total_proxies = 0
        written_names = set()
        for bfile in sorted(glob.glob("generated/batches/filtered_batch_*.yaml")):
            with open(bfile, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    for p in data.get("proxies", []):
                        n = p.get("name")
                        if not n or n in written_names:
                            continue
                        written_names.add(n)
                        p_str = yaml.safe_dump([p], allow_unicode=True, sort_keys=False, default_flow_style=False)
                        for line in p_str.strip().splitlines():
                            out_f.write(f"  {line}\n")
                        total_proxies += 1

    os.replace(temp_output, output)
    log(f"🏁 最终聚合 YAML 已生成: {output}\n✅ 累计保留优质节点总数: {total_proxies}")
    return total_proxies


def process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx):
    good_nodes = []
    unique_names(batch_slice)

    log(f"\n🚀 [第 {batch_idx} 批] 启动 Mihomo 实例测试，当前批次节点数: {len(batch_slice)}")
    with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        proc = None
        try:
            write_test_config(batch_slice, config_path)
            proc = subprocess.Popen(
                [args.mihomo, "-d", temp_dir, "-f", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            wait_api(proc)
            with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                futures = [executor.submit(test_one, node) for node in batch_slice]
                for index, future in enumerate(as_completed(futures), 1):
                    res = future.result()
                    node = res["node"]
                    node_fp = fingerprint(node)
                    tested_fps.add(node_fp)
                    if res["ok"]:
                        log(f"✅ [{index}/{len(futures)}] {res['name']} | avg={res['avg']}ms")
                        valid_pool.add(node_fp)
                        good_nodes.append(node)
                    else:
                        invalid_pool.add(node_fp)
        except Exception as e:
            # 启动失败：只标记 tested，不永久拉黑，下次可重试
            log(f"❌ [第 {batch_idx} 批] Mihomo 异常: {e} -> 本批跳过（不写入 invalid 永久黑名单）")
            for node in batch_slice:
                tested_fps.add(fingerprint(node))
            good_nodes = []
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


def main():
    parser = argparse.ArgumentParser(description="V6 节点审计清洗引擎（扩展协议 + 传输层）")
    parser.add_argument("inputs", nargs="*", help="目录或文件路径")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--mihomo", default=MIHOMO_BIN)
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    args = parser.parse_args()

    global BATCH_SIZE
    BATCH_SIZE = max(1, args.batch_size)

    inputs = args.inputs if args.inputs else DEFAULT_INPUT_PATTERNS
    files = collect_files(inputs, args.output, "gem.yaml")
    if not files:
        raise SystemExit("❌ 没有找到任何输入节点文件")
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"❌ 找不到 Mihomo: {args.mihomo}")

    tested_fps = load_pool(CHECKPOINT_FILE)
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)

    log("🚀 启动 V6 全目录海量物料审计与清洗引擎...")
    log("📋 支持协议: ss / ssr / vmess / vless / trojan / hysteria2 / tuic / anytls / mieru / wireguard")
    log("📋 传输层: ws / grpc / h2 / http / xhttp + ShadowTLS(plugin)")

    for old_b in glob.glob("generated/batches/filtered_batch_*.yaml"):
        try:
            os.remove(old_b)
        except Exception:
            pass

    batch_idx = 1
    batch_slice = []

    try:
        for node in stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps):
            node = copy.deepcopy(node)
            node.pop("_inherited_valid", None)
            batch_slice.append(node)

            if len(batch_slice) >= BATCH_SIZE:
                processed_good = process_batch_with_mihomo(
                    batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx
                )
                if processed_good:
                    save_batch_yaml(processed_good, batch_idx)
                batch_idx += 1
                batch_slice = []

        if batch_slice:
            processed_good = process_batch_with_mihomo(
                batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx
            )
            if processed_good:
                save_batch_yaml(processed_good, batch_idx)
            batch_idx += 1
    finally:
        save_pool(CHECKPOINT_FILE, tested_fps)
        save_pool(VALID_POOL_FILE, valid_pool)
        save_pool(INVALID_POOL_FILE, invalid_pool)

    if not glob.glob("generated/batches/filtered_batch_*.yaml"):
        log("⚠ 没有任何节点通过测试。")
        return 2

    if build_final_aio_streamed(args.output) == 0:
        log("⚠ 没有任何节点通过测试。")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())