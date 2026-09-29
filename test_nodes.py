#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mihomo AIO 节点合并 / 测速 / 国内分流 / 客户端去广告 V1

核心流程：
1. 合并多个 Clash/Mihomo YAML
2. 按完整节点配置指纹去重
3. 启动 Mihomo
4. 对真实节点进行 3 URL 延迟测试
5. 筛选可用节点
6. 按延迟排序
7. 生成可直接导入 Mihomo/Clash Meta 类客户端的完整配置
8. 加入国内 DNS / 国内直连 / GFW 代理 / 广告拦截
9. 用 Mihomo 再次加载最终 YAML 做配置校验
10. 校验通过后才安全替换输出文件

来源：
https://github.com/wzmwayne/proxy-node
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
# 基础配置
# ============================================================

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/generate_204",
]

TIMEOUT_MS = 5000

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

AUTHOR = "wzmwayne"
REPO = "https://github.com/wzmwayne/proxy-node"


# ============================================================
# 国内 / 广告规则
# ============================================================

# 中国域名
CN_DOMAIN_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
)

# 中国 IP
CN_IP_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
)

# 私有域名
PRIVATE_DOMAIN_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs"
)

# 私有 IP
PRIVATE_IP_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs"
)

# GFW
GFW_DOMAIN_URL = (
    "https://raw.githubusercontent.com/"
    "wwqgtxx/clash-rules/release/gfw.mrs"
)

# Mihomo 广告规则
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

        # PATH 中的 mihomo
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
        "[FAIL] 未找到 mihomo 内核。\n"
        "请设置环境变量 MIHOMO_BIN，或将 mihomo 放到 "
        "/usr/local/bin/mihomo、/usr/bin/mihomo、/tmp/mihomo"
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
# 节点完整指纹
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
    """
    不再使用：
        type + server + port

    而是对节点完整配置做指纹。

    这样可以避免：

    同 server/port
    不同 password
    不同 uuid
    不同 ws-path
    不同 sni
    不同 servername
    不同 reality
    不同 grpc-service-name

    被错误合并。
    """

    ignore_keys = {
        "name",
    }

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

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# 节点清洗
# ============================================================

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
        "files": 0,
        "raw": 0,
        "valid": 0,
        "duplicate": 0,
        "invalid": 0,
        "skipped": 0,
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
            print(f"[WARN] {inp} 的 proxies 不是列表")
            continue

        for p in proxies:
            stats["raw"] += 1

            ok, reason = valid_proxy(p)

            if not ok:
                stats["invalid"] += 1
                continue

            name = str(p.get("name", ""))

            if (
                name.startswith("说明-")
                or name in SKIP_NAMES
            ):
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
# Mihomo API 测速
# ============================================================

def test_node(port, secret, name):
    q = urllib.parse.quote(
        name,
        safe="",
    )

    delays = []

    for test_url in TEST_URLS:
        url_q = urllib.parse.quote(
            test_url,
            safe="",
        )

        try:
            data = api_get(
                port,
                secret,
                f"/proxies/{q}/delay"
                f"?timeout={TIMEOUT_MS}"
                f"&url={url_q}",
                timeout=TIMEOUT_MS / 1000 + 8,
            )

            delay = data.get("delay")

            if delay is None:
                return name, None

            delay = int(delay)

            if delay <= 0:
                return name, None

            delays.append(delay)

        except Exception:
            return name, None

    if not delays:
        return name, None

    return (
        name,
        int(sum(delays) / len(delays)),
    )


# ============================================================
# 临时 Mihomo 测试配置
# ============================================================

def build_test_config(
    port,
    secret,
    proxies,
):
    return {
        "mixed-port": port + 1,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "ipv6": False,

        "external-controller":
            f"127.0.0.1:{port}",

        "secret": secret,

        "proxies": proxies,

        "rules": [
            "MATCH,DIRECT",
        ],
    }


# ============================================================
# 启动 Mihomo
# ============================================================

def start_mihomo(
    mihomo,
    config_path,
    workdir,
):
    proc = subprocess.Popen(
        [
            mihomo,
            "-d",
            workdir,
            "-f",
            config_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return proc


def wait_mihomo(
    proc,
    port,
    secret,
    timeout_seconds=60,
):
    end = time.time() + timeout_seconds

    while time.time() < end:
        try:
            api_get(
                port,
                secret,
                "/version",
                timeout=3,
            )
            return True

        except Exception:
            if proc.poll() is not None:
                return False

            time.sleep(0.5)

    return False


# ============================================================
# 获取真实代理
# ============================================================

def get_testable_names(
    port,
    secret,
):
    proxies_map = {}

    for _ in range(10):
        try:
            proxies_map = api_get(
                port,
                secret,
                "/proxies",
            ).get("proxies", {})

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

        ptype = info.get("type")

        if ptype in GROUP_TYPES:
            continue

        names.append(name)

    return names


# ============================================================
# 客户端配置生成
# ============================================================

def build_client_config(
    good,
    test_count,
    input_count,
):
    """
    生成真正的客户端配置。

    不生成 fake Trojan。
    不把说明文字塞进 proxies。
    不暴露 external-controller。
    """

    good_names = [
        p["name"]
        for p in good
    ]

    cfg = {
        # ----------------------------------------------------
        # 基础
        # ----------------------------------------------------
        "mixed-port": 7890,

        "allow-lan": False,

        "mode": "rule",

        "log-level": "info",

        "ipv6": False,

        # ----------------------------------------------------
        # 连接优化
        # ----------------------------------------------------
        "unified-delay": True,

        "tcp-concurrent": True,

        "keep-alive-idle": 600,

        "keep-alive-interval": 15,

        # ----------------------------------------------------
        # 配置持久化
        # ----------------------------------------------------
        "profile": {
            "store-selected": True,
            "store-fake-ip": True,
        },

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------
        "dns": {
            "enable": True,

            "ipv6": False,

            "enhanced-mode": "fake-ip",

            "fake-ip-range": "198.18.0.1/16",

            "default-nameserver": [
                "223.5.5.5",
                "119.29.29.29",
            ],

            "nameserver": [
                "https://doh.pub/dns-query",
                "https://dns.alidns.com/dns-query",
            ],

            "fallback": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
            ],

            "fallback-filter": {
                "geoip": True,
                "geoip-code": "CN",
            },

            "fake-ip-filter": [
                "+.lan",
                "+.local",
                "+.localhost",
                "+.home.arpa",
                "+.internal",
            ],
        },

        # ----------------------------------------------------
        # 真实节点
        # ----------------------------------------------------
        "proxies": good,

        # ----------------------------------------------------
        # 策略组
        # ----------------------------------------------------
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": [
                    "♻️ 自动选择",
                    "🔰 故障转移",
                ] + good_names,
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
                "proxies": [
                    "REJECT",
                    "DIRECT",
                ],
            },

            {
                "name": "🇨🇳 国内直连",
                "type": "select",
                "proxies": [
                    "DIRECT",
                    "🚀 节点选择",
                ],
            },

            {
                "name": "🌍 国外代理",
                "type": "select",
                "proxies": [
                    "🚀 节点选择",
                    "DIRECT",
                ],
            },
        ],

        # ----------------------------------------------------
        # Rule Providers
        # ----------------------------------------------------
        "rule-providers": {
            "广告": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": ADS_URL,
                "path": "./rule-providers/ads.mrs",
                "interval": 86400,
            },

            "国内域名": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": CN_DOMAIN_URL,
                "path": "./rule-providers/cn.mrs",
                "interval": 86400,
            },

            "国内IP": {
                "type": "http",
                "behavior": "ipcidr",
                "format": "mrs",
                "url": CN_IP_URL,
                "path": "./rule-providers/cn_ip.mrs",
                "interval": 86400,
            },

            "私有域名": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": PRIVATE_DOMAIN_URL,
                "path": "./rule-providers/private.mrs",
                "interval": 86400,
            },

            "私有IP": {
                "type": "http",
                "behavior": "ipcidr",
                "format": "mrs",
                "url": PRIVATE_IP_URL,
                "path": "./rule-providers/private_ip.mrs",
                "interval": 86400,
            },

            "GFW": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": GFW_DOMAIN_URL,
                "path": "./rule-providers/gfw.mrs",
                "interval": 86400,
            },
        },

        # ----------------------------------------------------
        # 分流规则
        #
        # 顺序非常重要：
        # 广告 → 私有 → 国内 → GFW → 其他
        # ----------------------------------------------------
        "rules": [
            # 广告
            "RULE-SET,广告,🛑 广告拦截",

            # 私有网络
            "RULE-SET,私有域名,DIRECT",
            "RULE-SET,私有IP,DIRECT,no-resolve",

            # 中国大陆
            "RULE-SET,国内域名,🇨🇳 国内直连",
            "RULE-SET,国内IP,🇨🇳 国内直连,no-resolve",

            # GFW
            "RULE-SET,GFW,🌍 国外代理",

            # 最终兜底
            "MATCH,🚀 节点选择",
        ],
    }

    # --------------------------------------------------------
    # metadata 放在配置里，而不是伪装成 proxy
    # --------------------------------------------------------
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


# ============================================================
# Mihomo 最终配置校验
# ============================================================

def validate_final_config(
    mihomo,
    config_path,
):
    """
    最终 YAML 不直接相信 Python 写出来就是正确的。

    重新启动 Mihomo 加载它。
    能启动并读取 /version 才算通过。
    """

    with tempfile.TemporaryDirectory(
        prefix="mihomo_validate_"
    ) as td:

        cfg_copy = os.path.join(
            td,
            "config.yaml",
        )

        import shutil

        shutil.copy2(
            config_path,
            cfg_copy,
        )

        port = find_free_port()

        secret = "".join(
            random.choices(
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789",
                k=24,
            )
        )

        # 注意：
        # 为了校验，我们动态插入 controller。
        # 不修改最终文件。
        data = load_yaml(cfg_copy)

        data["external-controller"] = (
            f"127.0.0.1:{port}"
        )

        data["secret"] = secret

        dump_yaml(
            data,
            cfg_copy,
        )

        proc = None

        try:
            proc = start_mihomo(
                mihomo,
                cfg_copy,
                td,
            )

            if not wait_mihomo(
                proc,
                port,
                secret,
                timeout_seconds=30,
            ):
                return False, "Mihomo 无法加载最终配置"

            try:
                version = api_get(
                    port,
                    secret,
                    "/version",
                    timeout=5,
                )

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


# ============================================================
# 安全输出
# ============================================================

def safe_write_yaml(
    data,
    output,
):
    output = os.path.abspath(output)

    out_dir = os.path.dirname(output)

    os.makedirs(
        out_dir,
        exist_ok=True,
    )

    fd, tmp_path = tempfile.mkstemp(
        dir=out_dir,
        suffix=".yaml",
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as f:

            import yaml

            yaml.dump(
                data,
                f,
                Dumper=yaml.SafeDumper,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )

        return tmp_path

    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

        raise


# ============================================================
# 主程序
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description=(
            "Mihomo AIO 节点合并 + 测速 + "
            "国内分流 + 客户端广告拦截"
        )
    )

    ap.add_argument(
        "inputs",
        nargs="+",
        help="输入的 Clash/Mihomo YAML",
    )

    ap.add_argument(
        "-o",
        "--output",
        required=True,
        help="输出 AIO YAML",
    )

    ap.add_argument(
        "--concurrency",
        type=int,
        default=32,
        help="测速并发，默认 32",
    )

    ap.add_argument(
        "--top",
        type=int,
        default=0,
        help=(
            "只输出前 N 个节点；"
            "0 表示全部可用节点"
        ),
    )

    args = ap.parse_args()

    if args.concurrency < 1:
        raise SystemExit(
            "[FAIL] --concurrency 必须 >= 1"
        )

    if args.top < 0:
        raise SystemExit(
            "[FAIL] --top 必须 >= 0"
        )

    # --------------------------------------------------------
    # 检查 PyYAML
    # --------------------------------------------------------
    try:
        import yaml
    except ImportError:
        raise SystemExit(
            "[FAIL] 缺少 PyYAML，请执行：pip install pyyaml"
        )

    print()
    print("=" * 70)
    print(" Mihomo AIO 节点合并 / 测速 / 国内分流 / 客户端去广告 V1")
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # 1. 合并
    # --------------------------------------------------------
    print("[1/6] 正在读取并合并节点...")

    proxies, stats = collect_proxies(
        args.inputs
    )

    print(
        f"      输入文件: {stats['files']}"
    )

    print(
        f"      原始节点: {stats['raw']}"
    )

    print(
        f"      有效节点: {stats['valid']}"
    )

    print(
        f"      重复节点: {stats['duplicate']}"
    )

    print(
        f"      无效节点: {stats['invalid']}"
    )

    print(
        f"      跳过节点: {stats['skipped']