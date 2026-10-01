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
    "type",
    "server",
    "port",
    "uuid",
    "password",
    "cipher",
    "alterId",
    "protocol",
    "obfs",
    "protocol-param",
    "obfs-param",
    "private-key",
    "public-key",
    "ip",
    "username",
    "psk",
)

TEST_GROUPS = [
    (
        "基础连通性",
        [
            ("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"),
            ("Google 204", "https://www.google.com/generate_204"),
        ],
    ),
    (
        "实际网站",
        [
            ("Google 首页", "https://www.google.com/"),
            ("Telegram", "https://t.me/telegram/"),
        ],
    ),
]

SKIP_TCP_TYPES = frozenset(
    {"hysteria2", "hy2", "tuic", "wireguard", "mieru", "warp"}
)

NODE_FILE_EXTS = {
    ".txt",
    ".list",
    ".conf",
    ".csv",
    ".yaml",
    ".yml",
    ".json",
    ".log",
    ".data",
    ".nodes",
    ".sub",
}


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
    obj = {}
    for k in CORE_FINGERPRINT_KEYS:
        if k in proxy and proxy[k] is not None:
            obj[k] = proxy[k]
    for opt_key in (
        "ws-opts",
        "grpc-opts",
        "h2-opts",
        "http-opts",
        "xhttp-opts",
        "plugin-opts",
        "reality-opts",
    ):
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
    if ptype == "wireguard":
        if not node.get("private-key"):
            return False
        if node.get("peers"):
            return True
        if not server or not node.get("public-key"):
            return False
        return True
    if ptype == "mieru":
        if not server:
            return False
        if not node.get("username") or not node.get("password"):
            return False
        if not port and not node.get("port-range"):
            return False
        return True
    if not server:
        return False
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            return False
    except (TypeError, ValueError):
        return False
    if ptype == "ss":
        return bool(node.get("cipher") and node.get("password"))
    if ptype == "ssr":
        return bool(
            node.get("cipher")
            and node.get("password")
            and node.get("protocol")
            and node.get("obfs")
        )
    if ptype in ("vmess", "vless"):
        return bool(node.get("uuid"))
    if ptype == "trojan":
        return bool(node.get("password"))
    if ptype in ("hysteria2", "hy2"):
        return bool(node.get("password"))
    if ptype == "tuic":
        return bool(node.get("uuid") or node.get("password"))
    if ptype == "anytls":
        return bool(node.get("password"))
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
        path = _qget(query, "path", "ws-path")
        if path:
            opts["path"] = path
        host = _qget(query, "host", "Host")
        if host:
            opts["headers"] = {"Host": host}
        if opts:
            node["ws-opts"] = opts
    elif network == "grpc":
        opts = {}
        svc = _qget(query, "serviceName", "service-name", "grpc-service-name")
        if svc:
            opts["grpc-service-name"] = svc
        if opts:
            node["grpc-opts"] = opts
    elif network == "h2":
        opts = {}
        path = _qget(query, "path")
        host = _qget(query, "host")
        if path:
            opts["path"] = path
        if host:
            opts["host"] = [host] if isinstance(host, str) else host
        if opts:
            node["h2-opts"] = opts
    elif network == "http":
        opts = {}
        path = _qget(query, "path")
        host = _qget(query, "host")
        if path:
            opts["path"] = [path] if isinstance(path, str) else path
        if host:
            opts["headers"] = {"Host": [host]}
        if opts:
            node["http-opts"] = opts
    elif network in ("xhttp", "splithttp"):
        node["network"] = "xhttp"
        opts = {}
        path = _qget(query, "path")
        host = _qget(query, "host")
        mode = _qget(query, "mode")
        if path:
            opts["path"] = path
        if host:
            opts["host"] = host
        if mode:
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
    server = parts[0]
    port_s = parts[1]
    protocol = parts[2]
    method = parts[3]
    obfs = parts[4]
    password_b64 = ":".join(parts[5:])
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
    line = (line or "").strip()
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
                        decoded_ui = b64decode_pad(userinfo).decode(
                            "utf-8", errors="ignore"
                        )
                        if ":" in decoded_ui:
                            method, password = decoded_ui.split(":", 1)
                        else:
                            method, password = decoded_ui, ""
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
            config = json.loads(
                b64decode_pad(raw_b64).decode("utf-8", errors="ignore")
            )
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
            if str(config.get("tls", "")).lower() in ("tls", "1", "true"):
                node["tls"] = True
                sni = config.get("sni") or config.get("host") or config.get("peer")
                if sni:
                    node["servername"] = sni
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
                    p = config["path"]
                    opts["path"] = [p] if isinstance(p, str) else p
                host = config.get("host")
                if host:
                    opts["headers"] = {"Host": [host]}
                if opts:
                    node["http-opts"] = opts
        else:
            parsed = urllib.parse.urlparse(line)
            scheme = (parsed.scheme or "").lower()
            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username or ""
            uuid = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            fragment = (
                urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            )
            if scheme in ("hysteria2", "hy2"):
                node = {
                    "name": fragment or f"Hy2-{server}",
                    "type": "hysteria2",
                    "server": server,
                    "port": port,
                    "password": password or _qget(query, "auth", default=""),
                    "skip-cert-verify": True,
                }
                sni = _qget(query, "sni")
                if sni:
                    node["sni"] = sni
                obfs = _qget(query, "obfs")
                if obfs:
                    node["obfs"] = obfs
                obfs_pw = _qget(query, "obfs-password")
                if obfs_pw:
                    node["obfs-password"] = obfs_pw
            elif scheme == "vless":
                node = {
                    "name": fragment or f"Vless-{server}",
                    "type": "vless",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "client-fingerprint": _qget(query, "fp", default="chrome"),
                    "skip-cert-verify": True,
                }
                security = (_qget(query, "security", default="") or "").lower()
                if security in ("tls", "reality") or "encryption" in query:
                    node["tls"] = True
                sni = _qget(query, "sni")
                if sni:
                    node["servername"] = sni
                flow = _qget(query, "flow")
                if flow:
                    node["flow"] = flow
                if security == "reality":
                    ropts = {}
                    pbk = _qget(query, "pbk")
                    sid = _qget(query, "sid")
                    if pbk:
                        ropts["public-key"] = pbk
                    if sid:
                        ropts["short-id"] = sid
                    if ropts:
                        node["reality-opts"] = ropts
                net = _qget(query, "type", "network", default="tcp")
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
                sni = _qget(query, "sni")
                if sni:
                    node["sni"] = sni
                net = _qget(query, "type", "network", default="tcp")
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
                sni = _qget(query, "sni")
                if sni:
                    node["sni"] = sni
                cc = _qget(query, "congestion_control", "congestion-controller")
                if cc:
                    node["congestion-controller"] = cc
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
                sni = _qget(query, "sni")
                if sni:
                    node["sni"] = sni
                fp = _qget(query, "fp")
                if fp:
                    node["client-fingerprint"] = fp
            elif scheme == "mieru":
                node = {
                    "name": fragment or f"Mieru-{server}",
                    "type": "mieru",
                    "server": server,
                    "username": uuid or _qget(query, "username", default=""),
                    "password": parsed.password
                    or _qget(query, "password", default=""),
                    "transport": _qget(query, "transport", default="TCP"),
                    "multiplexing": _qget(
                        query, "multiplexing", default="MULTIPLEXING_LOW"
                    ),
                    "udp": True,
                }
                pr = _qget(query, "port-range")
                if pr:
                    node["port-range"] = pr
                else:
                    node["port"] = port
    except Exception:
        return None
    if node and validate_node_by_official_standard(node):
        return node
    return None


def normalize_yaml_node(raw):
    if not isinstance(raw, dict):
        return None
    ptype = str(raw.get("type", "")).lower().strip()
    if not ptype:
        return None
    node = dict(raw)
    node["type"] = ptype
    if ptype == "hy2":
        node["type"] = "hysteria2"
        ptype = "hysteria2"
    if ptype in ("vmess", "vless", "trojan"):
        net = (node.get("network") or "tcp").lower()
        if net == "ws" and "ws-opts" not in node and node.get("ws-path"):
            opts = {"path": node.pop("ws-path", "/")}
            if node.get("ws-headers"):
                opts["headers"] = node.pop("ws-headers")
            node["ws-opts"] = opts
        if (
            net == "grpc"
            and "grpc-opts" not in node
            and node.get("grpc-service-name")
        ):
            node["grpc-opts"] = {
                "grpc-service-name": node.pop("grpc-service-name")
            }
    if not validate_node_by_official_standard(node):
        return None
    return node


def is_skip_file(name, skip_names):
    if name in skip_names:
        return True
    lower = name.lower()
    if lower in (
        "seen_fingerprints.json",
        "source_hashes.json",
        "changelog.md",
        "readme.md",
        "license",
        "license.md",
    ):
        return True
    if lower.startswith("."):
        return True
    return False


def is_node_source_file(fp):
    name = fp.name
    ext = fp.suffix.lower()
    if ext in NODE_FILE_EXTS:
        return True
    if ext == "":
        return True
    return False


def collect_files(inputs, output_filename="filtered_nodes.yaml", skip_filename="gem.yaml"):
    skip_names = {
        output_filename,
        skip_filename,
        CHECKPOINT_FILE,
        VALID_POOL_FILE,
        INVALID_POOL_FILE,
        "filtered_nodes.yaml",
        "gem.yaml",
    }
    files = set()
    dir_count = 0
    for item in inputs:
        p = Path(item).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        else:
            p = p.resolve()
        log(f"[收集] 输入路径: {p} exists={p.exists()} is_dir={p.is_dir()} is_file={p.is_file()}")
        if not p.exists():
            log(f"[收集] 路径不存在，跳过: {p}")
            continue
        if p.is_file():
            if not is_skip_file(p.name, skip_names) and is_node_source_file(p):
                files.add(p)
            continue
        if p.is_dir():
            for root, dirs, filenames in os.walk(str(p), followlinks=True):
                dirs.sort()
                dir_count += 1
                root_path = Path(root)
                try:
                    rel_root = root_path.relative_to(Path.cwd())
                except ValueError:
                    rel_root = root_path
                matched_here = []
                for name in filenames:
                    if is_skip_file(name, skip_names):
                        continue
                    fp = root_path / name
                    if not fp.is_file():
                        continue
                    if is_node_source_file(fp):
                        files.add(fp.resolve())
                        matched_here.append(name)
                log(
                    f"[收集] 目录 {rel_root} 子目录数={len(dirs)} "
                    f"文件数={len(filenames)} 命中源文件={len(matched_here)}"
                )
                if matched_here and len(matched_here) <= 20:
                    for n in matched_here:
                        log(f"         -> {n}")
                elif matched_here:
                    for n in matched_here[:10]:
                        log(f"         -> {n}")
                    log(f"         -> ... 另有 {len(matched_here) - 10} 个文件")
    sorted_files = sorted(str(f) for f in files)
    log(f"[收集] 共遍历目录 {dir_count} 个，最终源文件 {len(sorted_files)} 个")
    for i, fpath in enumerate(sorted_files, 1):
        try:
            rel = Path(fpath).relative_to(Path.cwd())
        except ValueError:
            rel = fpath
        log(f"   [{i:04d}] {rel}")
    if len(sorted_files) <= 1:
        log("[收集] 警告: 源文件过少。请确认 nodes 下 ss/vmess/vless/trojan/hysteria2/tuic 等子目录已完整拉取且内含 txt 文件")
    return sorted_files


def quick_tcp_check(server, port, timeout=TCP_TIMEOUT):
    try:
        with socket.create_connection((str(server), int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def flush_tcp_chunk(chunk, check_func):
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as executor:
        futures = {executor.submit(check_func, node): node for node in chunk}
        for future in as_completed(futures):
            yield future.result()


def load_text_nodes_from_file(path):
    nodes = []
    reject = 0
    scanned = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        log(f"读取失败: {path}: {e}")
        return nodes, 0, 0
    if path.lower().endswith((".yaml", ".yml")):
        try:
            data = yaml.safe_load(content) or {}
        except Exception as e:
            log(f"YAML 解析失败: {path}: {e}")
            return nodes, 0, 0
        if isinstance(data, dict):
            proxies = data.get("proxies") or []
            scanned = len(proxies)
            for raw in proxies:
                node = normalize_yaml_node(raw)
                if node:
                    nodes.append(node)
                else:
                    reject += 1
        elif isinstance(data, list):
            scanned = len(data)
            for raw in data:
                node = normalize_yaml_node(raw)
                if node:
                    nodes.append(node)
                else:
                    reject += 1
        return nodes, scanned, reject
    if path.lower().endswith(".json"):
        try:
            data = json.loads(content)
        except Exception:
            data = None
        if isinstance(data, dict) and "proxies" in data:
            proxies = data.get("proxies") or []
            scanned = len(proxies)
            for raw in proxies:
                node = normalize_yaml_node(raw)
                if node:
                    nodes.append(node)
                else:
                    reject += 1
            return nodes, scanned, reject
        if isinstance(data, list):
            scanned = len(data)
            for raw in data:
                if isinstance(raw, dict):
                    node = normalize_yaml_node(raw)
                elif isinstance(raw, str):
                    node = parse_share_link(raw)
                else:
                    node = None
                if node:
                    nodes.append(node)
                else:
                    reject += 1
            return nodes, scanned, reject
    for line in content.splitlines():
        scanned += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        node = parse_share_link(line)
        if node:
            nodes.append(node)
        else:
            if "://" in stripped:
                reject += 1
    return nodes, scanned, reject


def stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps, batch_size):
    seen_fps = set()
    file_stats = {}
    total_raw_scanned = 0
    total_raw_valid = 0
    total_rejected_standard = 0
    total_inherited = 0
    total_tcp_filtered = 0
    total_passed_tcp = 0
    total_already_tested = 0
    total_skip_tcp_type = 0

    def check_node_tcp(node):
        if node.get("_inherited_valid"):
            return node
        ptype = str(node.get("type", "")).lower()
        if ptype in SKIP_TCP_TYPES:
            return node
        port = node.get("port")
        if not port:
            return node
        return node if quick_tcp_check(node.get("server"), port) else None

    for path in files:
        path_key = str(path)
        file_nodes, file_scanned_count, file_reject_count = load_text_nodes_from_file(
            path_key
        )
        total_raw_scanned += file_scanned_count
        total_rejected_standard += file_reject_count
        file_valid_count = 0
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
        file_stats[path_key] = {
            "scanned": file_scanned_count,
            "valid": file_valid_count,
            "reject": file_reject_count,
        }
        try:
            rel = Path(path_key).relative_to(Path.cwd())
        except ValueError:
            rel = path_key
        log(
            f"[源文件扫描] {rel} -> 原始: {file_scanned_count} "
            f"| 官方标准合规: {file_valid_count} "
            f"| 标准剔除: {file_reject_count}"
        )
        chunk = []
        for node in file_passed_list:
            if node.get("_inherited_valid"):
                yield node
                continue
            ptype = str(node.get("type", "")).lower()
            if ptype in SKIP_TCP_TYPES:
                total_skip_tcp_type += 1
                total_passed_tcp += 1
                yield node
                continue
            chunk.append(node)
            if len(chunk) >= TCP_CHUNK:
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
    expected_batches = (
        (total_passed_tcp + batch_size - 1) // batch_size if total_passed_tcp > 0 else 0
    )
    log("")
    log("==================== 全库物料盘点与总账统计报告 ====================")
    log(f"扫描输入源文件总数: {len(files)} 个")
    for p, st in file_stats.items():
        log(
            f"   - [{Path(p).name}] 原始: {st['scanned']} "
            f"| 合规: {st['valid']} | 标准剔除: {st['reject']}"
        )
    log("-----------------------------------------------------------------")
    log(f"累计原始总条目数: {total_raw_scanned} 条")
    log(f"官方标准不合规直接排除: {total_rejected_standard} 条")
    log(f"历史已测/黑名单拦截(跳过): {total_already_tested} 条")
    log(f"本轮合规新增(去重后): {total_raw_valid} 条")
    log(f"历史白名单继承命中: {total_inherited} 条")
    log(f"跳过TCP预检的协议节点: {total_skip_tcp_type} 条")
    log(f"TCP预检剔除死节点: {total_tcp_filtered} 条")
    log(f"最终进入 Mihomo 测速总池: {total_passed_tcp} 条")
    log(f"本轮测速总批次: {expected_batches} 批 (每批 {batch_size} 条)")
    log("=================================================================")
    log("")


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
        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def wait_api(proc):
    url = f"http://{API_HOST}:{API_PORT}/version"
    end_time = time.time() + 25
    while time.time() < end_time:
        if proc.poll() is not None:
            raise RuntimeError(f"Mihomo 提前退出，returncode={proc.returncode}")
        try:
            r = requests.get(
                url,
                headers={"Authorization": f"Bearer {API_SECRET}"},
                timeout=1.5,
            )
            if r.ok:
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
    name = node["name"]
    delays = []
    for _stage, tests in TEST_GROUPS:
        for _label, url in tests:
            try:
                delays.append(api_delay(name, url))
            except Exception as e:
                return {
                    "name": name,
                    "node": node,
                    "ok": False,
                    "error": str(e),
                }
    expected = sum(len(t) for _, t in TEST_GROUPS)
    if len(delays) != expected:
        return {
            "name": name,
            "node": node,
            "ok": False,
            "error": "测试数量不全",
        }
    return {
        "name": name,
        "node": node,
        "ok": True,
        "avg": round(sum(delays) / len(delays), 1),
    }


def unique_names(nodes):
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
        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
    log(f"合格批次已保存: {filepath} (共留存 {len(good_nodes)} 个优质节点)")
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


def process_batch_with_mihomo(
    batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx
):
    good_nodes = []
    unique_names(batch_slice)
    log(
        f"[第 {batch_idx} 批] 启动 Mihomo 实例测试，"
        f"当前批次节点数: {len(batch_slice)}"
    )
    with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        proc = None
        try:
            write_test_config(batch_slice, config_path)
            proc = subprocess.Popen(
                [args.mihomo, "-d", temp_dir, "-f", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_api(proc)
            with ThreadPoolExecutor(
                max_workers=max(1, args.concurrency)
            ) as executor:
                futures = [
                    executor.submit(test_one, node) for node in batch_slice
                ]
                for index, future in enumerate(as_completed(futures), 1):
                    res = future.result()
                    node = res["node"]
                    node_fp = fingerprint(node)
                    tested_fps.add(node_fp)
                    if res["ok"]:
                        log(
                            f"[{index}/{len(futures)}] {res['name']} "
                            f"| avg={res['avg']}ms"
                        )
                        valid_pool.add(node_fp)
                        good_nodes.append(node)
                    else:
                        invalid_pool.add(node_fp)
                    if index % 50 == 0:
                        save_pool(CHECKPOINT_FILE, tested_fps)
                        save_pool(VALID_POOL_FILE, valid_pool)
                        save_pool(INVALID_POOL_FILE, invalid_pool)
        except Exception as e:
            log(
                f"[第 {batch_idx} 批] Mihomo 异常: {e} "
                f"-> 已完成结果已落盘，未测完的节点下次可重试"
            )
            good_nodes = list(good_nodes)
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
    log("正在以流式方式合并所有批次生成最终 AIO 配置...")
    all_names = []
    seen_name = set()
    batch_files = sorted(glob.glob("generated/batches/filtered_batch_*.yaml"))
    for bfile in batch_files:
        with open(bfile, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            for p in data.get("proxies") or []:
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
                "name": "节点选择",
                "type": "select",
                "proxies": all_names if all_names else ["DIRECT"],
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "proxies": all_names if all_names else ["DIRECT"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "timeout": 5000,
            },
            {
                "name": "国内直连",
                "type": "select",
                "proxies": ["DIRECT", "节点选择"],
            },
            {
                "name": "国外代理",
                "type": "select",
                "proxies": ["节点选择", "自动选择", "DIRECT"],
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,国外代理",
        ],
    }
    with open(temp_output, "w", encoding="utf-8") as out_f:
        header_data = {k: v for k, v in config_skeleton.items() if k != "proxies"}
        yaml.safe_dump(
            header_data,
            out_f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
        out_f.write("proxies:\n")
        total_proxies = 0
        written_names = set()
        for bfile in batch_files:
            with open(bfile, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                continue
            for p in data.get("proxies") or []:
                n = p.get("name")
                if not n or n in written_names:
                    continue
                written_names.add(n)
                p_str = yaml.safe_dump(
                    [p],
                    allow_unicode=True,
                    sort_keys=False,
                    default_flow_style=False,
                )
                for line in p_str.strip().splitlines():
                    out_f.write(f"  {line}\n")
                total_proxies += 1
    os.replace(temp_output, output)
    log(f"最终聚合 YAML 已生成: {output}")
    log(f"累计保留优质节点总数: {total_proxies}")
    return total_proxies


def main():
    parser = argparse.ArgumentParser(
        description="V6 节点审计清洗引擎（递归扫描协议子目录）"
    )
    parser.add_argument("inputs", nargs="*", help="目录或文件路径，默认 nodes")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--mihomo", default=MIHOMO_BIN)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()
    batch_size = max(1, int(args.batch_size))
    inputs = args.inputs if args.inputs else DEFAULT_INPUT_PATTERNS
    log(f"工作目录 cwd={Path.cwd()}")
    log(f"输入参数 inputs={inputs}")
    files = collect_files(inputs, args.output, "gem.yaml")
    if not files:
        raise SystemExit(
            "没有找到任何输入节点文件。请确认当前目录下存在 nodes/ss、nodes/vmess 等子目录，且目录内有 txt/yaml 文件。可用: ls -laR nodes"
        )
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"找不到 Mihomo: {args.mihomo}")
    tested_fps = load_pool(CHECKPOINT_FILE)
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)
    log("启动 V6 全目录海量物料审计与清洗引擎...")
    log(
        f"历史池加载: tested={len(tested_fps)} valid={len(valid_pool)} "
        f"invalid={len(invalid_pool)}"
    )
    log(
        "支持协议: ss / ssr / vmess / vless / trojan / "
        "hysteria2 / tuic / anytls / mieru / wireguard"
    )
    for old_b in glob.glob("generated/batches/filtered_batch_*.yaml"):
        try:
            os.remove(old_b)
        except Exception:
            pass
    batch_idx = 1
    batch_slice = []
    try:
        for node in stream_merge_and_tcp_filter(
            files, invalid_pool, valid_pool, tested_fps, batch_size
        ):
            node = copy.deepcopy(node)
            node.pop("_inherited_valid", None)
            batch_slice.append(node)
            if len(batch_slice) >= batch_size:
                processed_good = process_batch_with_mihomo(
                    batch_slice,
                    args,
                    tested_fps,
                    valid_pool,
                    invalid_pool,
                    batch_idx,
                )
                if processed_good:
                    save_batch_yaml(processed_good, batch_idx)
                batch_idx += 1
                batch_slice = []
        if batch_slice:
            processed_good = process_batch_with_mihomo(
                batch_slice,
                args,
                tested_fps,
                valid_pool,
                invalid_pool,
                batch_idx,
            )
            if processed_good:
                save_batch_yaml(processed_good, batch_idx)
    finally:
        save_pool(CHECKPOINT_FILE, tested_fps)
        save_pool(VALID_POOL_FILE, valid_pool)
        save_pool(INVALID_POOL_FILE, invalid_pool)
    if not glob.glob("generated/batches/filtered_batch_*.yaml"):
        log("没有任何节点通过测试。")
        return 2
    if build_final_aio_streamed(args.output) == 0:
        log("没有任何节点通过测试。")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
