#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

IP_SOURCES = {
    "1only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/104.19.87.14344.txt",
  
}

NODES_DIR = Path("nodes_update")
TEMPLATE_FILE: Optional[Path] = None # 例如 Path("nodes/vmess/001.txt")，Path("nodes/vless/001.txt") nodes/trojan/001.txt None 表示自动扫描

OUTPUT_DIR = Path("generated")
PROBE_IP_COUNT = 99000
TEST_PORTS = [443,]
MAX_NODES_PER_FILE = 5000
TEST_IP_LIMIT = 5000
PROGRESS_EVERY = 200
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"


def fetch_ips(url: str, limit: int = 0) -> List[str]:
    ips: List[str] = []
    seen = set()
    try:
        print(f"  获取 IP: {url}")
        resp = requests.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            clean = line.split("#", 1)[0].strip()
            if ":" in clean:
                host, port_part = clean.rsplit(":", 1)
                try:
                    int(port_part)
                    clean = host.strip()
                except ValueError:
                    pass
            if clean and clean not in seen:
                seen.add(clean)
                ips.append(clean)
                if limit and len(ips) >= limit:
                    break
        print(f"    → {len(ips)} 个")
    except Exception as e:
        print(f"    → 失败: {e}")
    return ips


def parse_vmess_uri(uri: str) -> Optional[dict]:
    try:
        b64 = uri[8:].split("#")[0]
        pad = 4 - len(b64) % 4
        if pad != 4:
            b64 += "=" * pad
        cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
        name = cfg.get("ps") or f"vmess-{cfg.get('add', 'node')}"
        host = cfg.get("host") or ""
        port = int(cfg.get("port") or 443)
        tls = str(cfg.get("tls", "")).lower() == "tls" or port in (443, 8443, 2053, 2083, 2087, 2096)
        proxy = {
            "name": name,
            "server": cfg.get("add"),
            "port": port,
            "type": "vmess",
            "uuid": cfg.get("id"),
            "alterId": int(cfg.get("aid") or 0),
            "cipher": cfg.get("scy") or "auto",
            "udp": True,
            "tls": tls,
            "skip-cert-verify": True,
            "network": cfg.get("net") or "ws",
        }
        if tls:
            proxy["servername"] = host or cfg.get("add")
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {
                "path": cfg.get("path") or "/?ed=2560",
                "headers": {"Host": host} if host else {},
            }
        return proxy
    except Exception:
        return None


def parse_trojan_uri(uri: str) -> Optional[dict]:
    try:
        p = urlparse(uri)
        password = p.username
        server = p.hostname
        port = p.port or 443
        name = unquote(p.fragment) if p.fragment else f"trojan-{server}"
        q = parse_qs(p.query)
        security = (q.get("security") or ["tls"])[0]
        net = (q.get("type") or ["ws"])[0]
        sni = (q.get("sni") or [""])[0]
        host = (q.get("host") or [""])[0]
        path = unquote((q.get("path") or ["/?ed=2560"])[0])
        fp = (q.get("fp") or ["chrome"])[0]
        tls = security == "tls" or port in (443, 8443, 2053, 2083, 2087, 2096)
        proxy = {
            "name": name,
            "server": server,
            "port": port,
            "type": "trojan",
            "password": password,
            "network": net,
            "udp": True,
            "tls": tls,
            "skip-cert-verify": True,
            "client-fingerprint": fp,
        }
        if tls:
            proxy["servername"] = sni or host or server
        if net == "ws":
            ws = {"path": path or "/?ed=2560"}
            if host:
                ws["headers"] = {"Host": host}
            proxy["ws-opts"] = ws
        return proxy
    except Exception:
        return None


def parse_vless_uri(uri: str) -> Optional[dict]:
    try:
        p = urlparse(uri)
        uuid = p.username
        server = p.hostname
        port = p.port or 443
        name = unquote(p.fragment) if p.fragment else f"vless-{server}"
        q = parse_qs(p.query)
        net = (q.get("type") or ["ws"])[0]
        security = (q.get("security") or ["tls"])[0]
        sni = (q.get("sni") or [""])[0]
        host = (q.get("host") or [""])[0]
        path = unquote((q.get("path") or ["/?ed=2560"])[0])
        tls = security == "tls" or port in (443, 8443, 2053, 2083, 2087, 2096)
        proxy = {
            "name": name,
            "server": server,
            "port": port,
            "type": "vless",
            "uuid": uuid,
            "network": net,
            "udp": True,
            "tls": tls,
            "skip-cert-verify": True,
        }
        if tls:
            proxy["servername"] = sni or host or server
        if net == "ws":
            ws = {"path": path or "/?ed=2560"}
            if host:
                ws["headers"] = {"Host": host}
            proxy["ws-opts"] = ws
        return proxy
    except Exception:
        return None


def parse_uri(uri: str) -> Optional[dict]:
    uri = uri.strip()
    if not uri:
        return None
    if uri.startswith("vmess://"):
        return parse_vmess_uri(uri)
    if uri.startswith("trojan://"):
        return parse_trojan_uri(uri)
    if uri.startswith("vless://"):
        return parse_vless_uri(uri)
    return None


def load_templates() -> List[dict]:
    proxies: List[dict] = []
    files: List[Path] = []

    if TEMPLATE_FILE and TEMPLATE_FILE.exists():
        files = [TEMPLATE_FILE]
    elif NODES_DIR.exists():
        files = sorted(NODES_DIR.rglob("*.txt"))
    else:
        print(f"[错误] 找不到模板目录 {NODES_DIR} 或文件 {TEMPLATE_FILE}")
        return []

    for fp in files:
        content = fp.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            continue
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and data.get("proxies"):
                proxies.extend([p for p in data["proxies"] if isinstance(p, dict)])
                print(f"  [YAML] {fp}: {len(data['proxies'])} 个")
                continue
        except Exception:
            pass
        n = 0
        for line in content.splitlines():
            p = parse_uri(line.strip())
            if p:
                proxies.append(p)
                n += 1
        if n:
            print(f"  [链接] {fp}: {n} 个")
            continue
        clean = re.sub(r"\s+", "", content)
        for pad in ("", "=", "==", "==="):
            try:
                decoded = base64.b64decode(clean + pad).decode("utf-8", errors="ignore")
                break
            except Exception:
                decoded = ""
        if decoded:
            for line in decoded.splitlines():
                p = parse_uri(line.strip())
                if p:
                    proxies.append(p)

    print(f"[信息] 模板合计 {len(proxies)} 个节点")
    return proxies


def node_fingerprint(node: dict) -> str:
    t = (node.get("type") or "").lower()
    uid = (node.get("uuid") or node.get("password") or "").strip().lower()
    path = ""
    host = ""
    if isinstance(node.get("ws-opts"), dict):
        path = node["ws-opts"].get("path") or ""
        headers = node["ws-opts"].get("headers") or {}
        if isinstance(headers, dict):
            host = headers.get("Host") or ""
    host = host or node.get("servername") or node.get("sni") or ""
    # 用 + 代替 |，避免被 Colab 正则截断
    return f"{t}+{uid}+{path}+{host}".lower()


def dedupe_by_fingerprint(proxies: List[dict]) -> List[dict]:
    seen = set()
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        t = (p.get("type") or "").lower()
        if t not in ("vmess", "vless", "trojan"):
            continue
        fp = node_fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(p)
    print(f"[信息] 指纹去重后 {len(out)} 个基础节点（原 {len(proxies)}）")
    return out


def adapt_node(node: dict, server: str, port: int) -> dict:
    new_node = copy.deepcopy(node)
    new_node["server"] = server
    new_node["port"] = port

    if port in (443, 8443, 2053, 2083, 2087, 2096):
        new_node["tls"] = True
        new_node["skip-cert-verify"] = True
        domain = (
            node.get("servername")
            or node.get("sni")
            or (node.get("ws-opts") or {}).get("headers", {}).get("Host")
        )
        if domain:
            new_node["servername"] = domain
            if new_node.get("type") == "trojan":
                new_node["sni"] = domain
        for fp_key in ["client-fingerprint", "fingerprint"]:
            if fp_key in node:
                new_node[fp_key] = node[fp_key]
                break
    else:
        new_node["tls"] = False
        for k in ("client-fingerprint", "servername", "sni", "alpn", "reality-opts", "flow", "fingerprint"):
            new_node.pop(k, None)

    if "ws-opts" in new_node:
        ws = new_node["ws-opts"]
        path = ws.get("path") or "/?ed=2560"
        host = None
        if isinstance(ws.get("headers"), dict):
            host = ws["headers"].get("Host")
        if not host:
            host = node.get("servername") or node.get("sni")
        clean = {"path": path}
        if host:
            clean["headers"] = {"Host": host}
        new_node["ws-opts"] = clean

    base_name = node.get("name") or "node"
    # 只改这一处：不再截断指纹，完整保留
    fp_short = node_fingerprint(node)
    new_node["name"] = f"{base_name} | IP={server} | PORT={port} | FP={fp_short}"
    return new_node


def save_yaml(proxies: List[dict], filepath: Path):
    data = {
        "proxies": proxies,
        "proxy-groups": [{
            "name": "CF-Nest",
            "type": "select",
            "proxies": [p["name"] for p in proxies] or ["DIRECT"],
        }],
        "rules": ["MATCH,CF-Nest"],
    }
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False, width=1200)
    print(f"  → 保存 {filepath.name}（{len(proxies)} 个）")


def generate_probe(base_nodes: List[dict], ips: List[str], source_name: str):
    use_ips = ips[:PROBE_IP_COUNT]
    if not use_ips:
        print(f"  [probe] 无 IP，跳过")
        return

    print(f"\n[probe] 源={source_name} 基础节点={len(base_nodes)} 探路IP={len(use_ips)} 端口={TEST_PORTS}")
    batch: List[dict] = []
    file_idx = 1
    total = 0
    out_dir = OUTPUT_DIR / "probe"
    out_dir.mkdir(parents=True, exist_ok=True)

    for base in base_nodes:
        for ip in use_ips:
            for port in TEST_PORTS:
                batch.append(adapt_node(base, ip, port))
                total += 1
                if total % PROGRESS_EVERY == 0:
                    print(f"  已生成 {total} ...")
                if len(batch) >= MAX_NODES_PER_FILE:
                    path = out_dir / f"cf_nest_{source_name}_probe_{file_idx:02d}.yaml"
                    save_yaml(batch, path)
                    batch = []
                    file_idx += 1

    if batch:
        path = out_dir / f"cf_nest_{source_name}_probe_{file_idx:02d}.yaml"
        save_yaml(batch, path)

    print(f"  [probe/{source_name}] 合计 {total} 个节点")


def main():
    print("=" * 60)
    print(" 节点去重 + 仅生成探路包（已精简）")
    print("=" * 60)

    raw = load_templates()
    if not raw:
        return
    base_nodes = dedupe_by_fingerprint(raw)
    if not base_nodes:
        print("去重后无可用节点")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 运行前清空 generated/probe 下所有的文件，以免上次运行的结果混在一起
    out_probe_dir = OUTPUT_DIR / "probe"
    if out_probe_dir.exists():
        for p in out_probe_dir.glob("*"):
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass

    for name, url in IP_SOURCES.items():
        ips = fetch_ips(url, TEST_IP_LIMIT)
        if not ips:
            continue
        # 仅生成探路包，剔除全量包
        generate_probe(base_nodes, ips, name)

    print("\n完成。输出目录：")
    print(f"  探路包: {OUTPUT_DIR}/probe/")


if __name__ == "__main__":
    main()
