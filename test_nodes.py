#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mihomo AIO 节点合并 / 测速 / 国内分流 / 客户端去广告 V1 (严格 3 网址全部通过版)

核心流程：
1. 合并多个 Clash/Mihomo YAML
2. 按完整节点配置指纹去重
3. 启动 Mihomo
4. 对真实节点进行 3 个严选 URL 延迟测试（必须全部通过）
5. 筛选可用节点
6. 按平均延迟排序
7. 生成可直接导入 Mihomo/Clash Meta 类客户端的完整配置
8. 加入国内 DNS / 国内直连 / GFW 代理 / 广告拦截
9. 用 Mihomo 再次加载最终 YAML 做配置校验
10. 校验通过后才安全替换输出文件
"""

import argparse
import hashlib
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ============================================================
# 基础配置 (针对 GitHub Actions 环境优化的 3 个严选稳定测速网址)
# ============================================================

TEST_URLS = [
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
]

TIMEOUT_MS = 6000

GROUP_TYPES = {
    "Selector",
    "URLTest",
    "Fallback",
    "Relay",
    "LoadBalance",
    "Compatible",
    "Pass",
    "ShadowTLS",
    "Reject",
    "Direct",
}

SKIP_NAMES = {
    "GLOBAL",
    "DIRECT",
    "REJECT",
    "PASS",
}

AUTHOR = "wzmwayne & 老前辈定制"
REPO = "https://github.com/qjlxg/Releases"


# ============================================================
# 国内 / 广告规则
# ============================================================

CN_DOMAIN_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
)

CN_IP_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
)

PRIVATE_DOMAIN_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs"
)

PRIVATE_IP_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs"
)

GFW_DOMAIN_URL = (
    "https://raw.githubusercontent.com/"
    "wwqgtxx/clash-rules/release/gfw.mrs"
)

ADS_URL = (
    "https://testingcf.jsdelivr.net/gh/"
    "gogyt/Mihomo@main/geo/geosite/category-ads-all.mrs"
)


# ============================================================
# 工具
# ============================================================

def now_beijing():
    return time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.gmtime(time.time() + 8 * 3600),
    )


def find_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def api_get(port, secret, path, timeout=10):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}"
    )
    req.add_header(
        "Authorization",
        f"Bearer {secret}",
    )

    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def find_mihomo():
    candidates = [
        os.environ.get("MIHOMO_BIN"),
        "/usr/local/bin/mihomo",
        "/usr/bin/mihomo",
        "/tmp/mihomo",
        "mihomo",
    ]

    for p in candidates:
        if not p:
            continue

        if os.path.isfile(p):
            return p

        if p == "mihomo":
            try:
                result = subprocess.run(
                    ["mihomo", "-v"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    text=True,
                )
                if result.returncode == 0:
                    return "mihomo"
            except Exception:
                pass

    raise SystemExit(
        "[FAIL] 未找到 mihomo 内核。"
    )


# ============================================================
# YAML
# ============================================================

def load_yaml(path):
    import yaml

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"不是有效的 YAML 配置: {path}")

    return data


def dump_yaml(data, path):
    import yaml

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            data,
            f,
            Dumper=yaml.SafeDumper,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )


# ============================================================
# 节点指纹与清洗
# ============================================================

def normalize_value(v):
    if isinstance(v, dict):
        return {
            str(k): normalize_value(v[k])
            for k in sorted(v.keys(), key=str)
        }

    if isinstance(v, list):
        return [
            normalize_value(x)
            for x in v
        ]

    return v


def node_fingerprint(proxy):
    ignore_keys = {"name"}
    clean = {}
    for k, v in proxy.items():
        if k in ignore_keys:
            continue
        clean[str(k)] = normalize_value(v)

    raw = json.dumps(
        clean,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def valid_proxy(proxy):
    if not isinstance(proxy, dict):
        return False, "不是对象"
    if not proxy.get("name"):
        return False, "缺少 name"
    if not proxy.get("type"):
        return False, "缺少 type"
    return True, ""


def collect_proxies(inputs):
    merged = {}
    stats = {
        "files": 0, "raw": 0, "valid": 0,
        "duplicate": 0, "invalid": 0, "skipped": 0,
    }

    for inp in inputs:
        stats["files"] += 1
        try:
            data = load_yaml(inp)
        except Exception as e:
            print(f"[WARN] 无法读取 {inp}: {e}")
            continue

        proxies = data.get("proxies", [])
        if not isinstance(proxies, list):
            continue

        for p in proxies:
            stats["raw"] += 1
            ok, _ = valid_proxy(p)
            if not ok:
                stats["invalid"] += 1
                continue

            name = str(p.get("name", ""))
            if name.startswith("说明-") or name in SKIP_NAMES:
                stats["skipped"] += 1
                continue

            fp = node_fingerprint(p)
            if fp in merged:
                stats["duplicate"] += 1
                continue

            merged[fp] = p
            stats["valid"] += 1

    return list(merged.values()), stats


# ============================================================
# 严格 3 个网址全部通过的测速逻辑
# ============================================================

def test_node(port, secret, name):
    q = urllib.parse.quote(name, safe="")
    delays = []

    for test_url in TEST_URLS:
        url_q = urllib.parse.quote(test_url, safe="")
        try:
            data = api_get(
                port,
                secret,
                f"/proxies/{q}/delay?timeout={TIMEOUT_MS}&url={url_q}",
                timeout=TIMEOUT_MS / 1000 + 4,
            )
            delay = data.get("delay")
            if delay is None:
                return name, None
            
            delay = int(delay)
            if delay <= 0:
                return name, None
            
            delays.append(delay)
        except Exception:
            # 只要其中一个报错或超时，直接判定该节点不合格
            return name, None

    # 必须所有测试网址都成功返回延迟
    if len(delays) != len(TEST_URLS):
        return name, None

    return name, int(sum(delays) / len(delays))


# ============================================================
# Mihomo 运行及配置生成
# ============================================================

def build_test_config(port, secret, proxies):
    return {
        "mixed-port": port + 1,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "ipv6": False,
        "external-controller": f"127.0.0.1:{port}",
        "secret": secret,
        "proxies": proxies,
        "rules": ["MATCH,DIRECT"],
    }


def start_mihomo(mihomo, config_path, workdir):
    return subprocess.Popen(
        [mihomo, "-d", workdir, "-f", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_mihomo(proc, port, secret, timeout_seconds=60):
    end = time.time() + timeout_seconds
    while time.time() < end:
        try:
            api_get(port, secret, "/version", timeout=3)
            return True
        except Exception:
            if proc.poll() is not None:
                return False
            time.sleep(0.5)
    return False


def get_testable_names(port, secret):
    proxies_map = {}
    for _ in range(10):
        try:
            proxies_map = api_get(port, secret, "/proxies").get("proxies", {})
            if proxies_map:
                break
        except Exception:
            proxies_map = {}
        time.sleep(0.5)

    names = []
    for name, info in proxies_map.items():
        if name in SKIP_NAMES:
            continue
        if not isinstance(info, dict):
            continue
        if info.get("type") in GROUP_TYPES:
            continue
        names.append(name)
    return names


def build_client_config(good, test_count, input_count):
    good_names = [p["name"] for p in good]
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "keep-alive-idle": 600,
        "keep-alive-interval": 15,
        "profile": {
            "store-selected": True,
            "store-fake-ip": True,
        },
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "fallback": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
            "fake-ip-filter": ["+.lan", "+.local", "+.localhost", "+.home.arpa", "+.internal"],
        },
        "proxies": good,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🔰 故障转移"] + good_names,
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": TEST_URLS[0],
                "interval": 300,
                "tolerance": 50,
                "lazy": False,
                "proxies": good_names,
            },
            {
                "name": "🔰 故障转移",
                "type": "fallback",
                "url": TEST_URLS[0],
                "interval": 300,
                "lazy": False,
                "proxies": good_names,
            },
            {
                "name": "🛑 广告拦截",
                "type": "select",
                "proxies": ["REJECT", "DIRECT"],
            },
            {
                "name": "🇨🇳 国内直连",
                "type": "select",
                "proxies": ["DIRECT", "🚀 节点选择"],
            },
            {
                "name": "🌍 国外代理",
                "type": "select",
                "proxies": ["🚀 节点选择", "DIRECT"],
            },
        ],
        "rule-providers": {
            "广告": {"type": "http", "behavior": "domain", "format": "mrs", "url": ADS_URL, "path": "./rule-providers/ads.mrs", "interval": 86400},
            "国内域名": {"type": "http", "behavior": "domain", "format": "mrs", "url": CN_DOMAIN_URL, "path": "./rule-providers/cn.mrs", "interval": 86400},
            "国内IP": {"type": "http", "behavior": "ipcidr", "format": "mrs", "url": CN_IP_URL, "path": "./rule-providers/cn_ip.mrs", "interval": 86400},
            "私有域名": {"type": "http", "behavior": "domain", "format": "mrs", "url": PRIVATE_DOMAIN_URL, "path": "./rule-providers/private.mrs", "interval": 86400},
            "私有IP": {"type": "http", "behavior": "ipcidr", "format": "mrs", "url": PRIVATE_IP_URL, "path": "./rule-providers/private_ip.mrs", "interval": 86400},
            "GFW": {"type": "http", "behavior": "domain", "format": "mrs", "url": GFW_DOMAIN_URL, "path": "./rule-providers/gfw.mrs", "interval": 86400},
        },
        "rules": [
            "RULE-SET,广告,🛑 广告拦截",
            "RULE-SET,私有域名,DIRECT",
            "RULE-SET,私有IP,DIRECT,no-resolve",
            "RULE-SET,国内域名,🇨🇳 国内直连",
            "RULE-SET,国内IP,🇨🇳 国内直连,no-resolve",
            "RULE-SET,GFW,🌍 国外代理",
            "MATCH,🚀 节点选择",
        ],
    }
    cfg["# AIO_INFO"] = {
        "source": AUTHOR,
        "repository": REPO,
        "generated_at_beijing": now_beijing(),
        "input_files": input_count,
        "tested_nodes": test_count,
        "available_nodes": len(good),
        "test_urls": TEST_URLS,
    }
    return cfg


def validate_final_config(mihomo, config_path):
    with tempfile.TemporaryDirectory(prefix="mihomo_validate_") as td:
        cfg_copy = os.path.join(td, "config.yaml")
        import shutil
        shutil.copy2(config_path, cfg_copy)
        port = find_free_port()
        secret = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24))

        data = load_yaml(cfg_copy)
        data["external-controller"] = f"127.0.0.1:{port}"
        data["secret"] = secret
        dump_yaml(data, cfg_copy)

        proc = None
        try:
            proc = start_mihomo(mihomo, cfg_copy, td)
            if not wait_mihomo(proc, port, secret, timeout_seconds=30):
                return False, "Mihomo 无法加载最终配置"
            try:
                version = api_get(port, secret, "/version", timeout=5)
                if not isinstance(version, dict):
                    return False, "Mihomo API 返回异常"
            except Exception as e:
                return False, f"最终配置 API 校验失败: {e}"
            return True, "Mihomo 配置加载验证成功"
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


def safe_write_yaml(data, output):
    output = os.path.abspath(output)
    out_dir = os.path.dirname(output)
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=out_dir, suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            import yaml
            yaml.dump(data, f, Dumper=yaml.SafeDumper, allow_unicode=True, default_flow_style=False, sort_keys=False)
        return tmp_path
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def main():
    ap = argparse.ArgumentParser(description="Mihomo AIO 节点合并 + 测速 + 校验")
    ap.add_argument("inputs", nargs="+", help="输入的 Clash/Mihomo YAML")
    ap.add_argument("-o", "--output", required=True, help="输出 AIO YAML")
    ap.add_argument("--concurrency", type=int, default=32, help="测速并发")
    ap.add_argument("--top", type=int, default=0, help="只输出前 N 个节点；0 表示全部可用")
    args = ap.parse_args()

    print("=" * 70)
    print(" Mihomo AIO 严格 3 网址全部通过版")
    print("=" * 70)

    proxies, stats = collect_proxies(args.inputs)
    print(f"[1/6] 合并完成：有效节点 {stats['valid']} 个")
    if not proxies:
        raise SystemExit("[FAIL] 没有任何可测试节点")

    mihomo = find_mihomo()
    port = find_free_port()
    secret = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24))
    test_cfg = build_test_config(port, secret, proxies)

    with tempfile.TemporaryDirectory(prefix="mihomo_aio_test_") as td:
        cfg_path = os.path.join(td, "config.yaml")
        dump_yaml(test_cfg, cfg_path)

        print(f"[2/6] 启动测速内核 (127.0.0.1:{port})...")
        proc = start_mihomo(mihomo, cfg_path, td)
        try:
            if not wait_mihomo(proc, port, secret, timeout_seconds=60):
                raise SystemExit("[FAIL] Mihomo API 未就绪")

            names = get_testable_names(port, secret)
            print(f"[3/6] 识别到待测节点: {len(names)} 个")

            print(f"[4/6] 开始严格 3 网址并发测速 (并发 {args.concurrency})...")
            ok = {}
            done = 0
            total = len(names)
            interval = max(1, total // 50)

            with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                futs = {ex.submit(test_node, port, secret, name): name for name in names}
                for fut in as_completed(futs):
                    try:
                        name, delay = fut.result()
                    except Exception:
                        name = futs[fut]
                        delay = None

                    done += 1
                    if delay is not None:
                        ok[name] = delay

                    if done % interval == 0 or done == total:
                        pct = done * 100 // total
                        print(f"      进度 {done}/{total} ({pct}%) 3网全通可用: {len(ok)}", flush=True)

            if not ok:
                raise SystemExit("[FAIL] 没有节点通过全部 3 个测速网址")

            good = [p for p in proxies if p.get("name") in ok]
            good.sort(key=lambda p: ok[p["name"]])
            if args.top > 0:
                good = good[:args.top]

            print(f"[5/6] 正在生成并校验最终客户端配置...")
            aio = build_client_config(good=good, test_count=len(names), input_count=len(args.inputs))
            tmp_output = safe_write_yaml(aio, args.output)

            valid, message = validate_final_config(mihomo, tmp_output)
            if not valid:
                if os.path.exists(tmp_output):
                    os.remove(tmp_output)
                raise SystemExit(f"[FAIL] 最终配置校验失败: {message}")

            os.replace(tmp_output, args.output)
            print(f"[6/6] 生成完毕！可用节点: {len(good)}/{len(names)}")
            print("=" * 70)

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
