#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import os
import random
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    "MetaCubeX/meta-rules-dat/meta/geo/geosite/gfw.mrs"
)

ADS_URL = (
    "https://raw.githubusercontent.com/"
    "MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"
)


# ============================================================
# 时间 / 端口
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


# ============================================================
# Mihomo API
# ============================================================

def api_get(port, secret, path, timeout=10):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}"
    )

    req.add_header(
        "Authorization",
        f"Bearer {secret}",
    )

    with urllib.request.urlopen(
        req,
        timeout=timeout,
    ) as r:
        return json.loads(r.read())


# ============================================================
# 找 Mihomo
# ============================================================

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
                r = subprocess.run(
                    ["mihomo", "-v"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5,
                )

                if r.returncode == 0:
                    return "mihomo"

            except Exception:
                pass

    raise SystemExit(
        "[FAIL] 未找到 mihomo 内核，请设置 MIHOMO_BIN。"
    )


# ============================================================
# YAML
# ============================================================

def load_yaml(path):
    import yaml

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"不是有效 YAML 配置: {path}"
        )

    return data


def dump_yaml(data, path):
    import yaml

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
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

def normalize_value(value):
    if isinstance(value, dict):
        return {
            str(k): normalize_value(value[k])
            for k in sorted(value, key=str)
        }

    if isinstance(value, list):
        return [
            normalize_value(x)
            for x in value
        ]

    return value


def node_fingerprint(proxy):
    """
    除 name 外，对整个节点配置做 SHA256。

    避免仅使用：
        type + server + port

    导致不同 UUID / password / path / sni /
    servername / reality 等节点被错误合并。
    """

    clean = {
        str(k): normalize_value(v)
        for k, v in proxy.items()
        if k != "name"
    }

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
# 节点检查
# ============================================================

def valid_proxy(proxy):
    if not isinstance(proxy, dict):
        return False

    if not proxy.get("name"):
        return False

    if not proxy.get("type"):
        return False

    return True


# ============================================================
# 合并节点
# ============================================================

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
            print(
                f"[WARN] 无法读取 {inp}: {e}"
            )
            continue

        proxies = data.get(
            "proxies",
            [],
        )

        if not isinstance(proxies, list):
            print(
                f"[WARN] {inp} 的 proxies 不是列表"
            )
            continue

        for proxy in proxies:
            stats["raw"] += 1

            if not valid_proxy(proxy):
                stats["invalid"] += 1
                continue

            name = str(
                proxy.get("name", "")
            )

            if (
                name.startswith("说明-")
                or name in SKIP_NAMES
            ):
                stats["skipped"] += 1
                continue

            fingerprint = node_fingerprint(
                proxy
            )

            if fingerprint in merged:
                stats["duplicate"] += 1
                continue

            merged[fingerprint] = proxy
            stats["valid"] += 1

    return list(merged.values()), stats


# ============================================================
# 节点测速
# ============================================================

def test_node(port, secret, name):
    encoded_name = urllib.parse.quote(
        name,
        safe="",
    )

    delays = []

    for test_url in TEST_URLS:
        encoded_url = urllib.parse.quote(
            test_url,
            safe="",
        )

        try:
            data = api_get(
                port,
                secret,
                (
                    f"/proxies/{encoded_name}/delay"
                    f"?timeout={TIMEOUT_MS}"
                    f"&url={encoded_url}"
                ),
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

    if len(delays) != len(TEST_URLS):
        return name, None

    return (
        name,
        int(sum(delays) / len(delays)),
    )


# ============================================================
# 临时测速配置
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
    return subprocess.Popen(
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


def wait_mihomo(
    proc,
    port,
    secret,
    timeout_seconds=60,
):
    deadline = (
        time.time()
        + timeout_seconds
    )

    while time.time() < deadline:
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
# 获取 Mihomo 实际识别的节点
# ============================================================

def get_testable_names(
    port,
    secret,
):
    proxies_map = {}

    for _ in range(10):
        try:
            result = api_get(
                port,
                secret,
                "/proxies",
            )

            proxies_map = result.get(
                "proxies",
                {},
            )

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


# ============================================================
# 生成最终客户端配置
# ============================================================

def build_client_config(
    good,
    test_count,
    input_count,
):
    good_names = [
        proxy["name"]
        for proxy in good
    ]

    config = {
        # ====================================================
        # 基础
        # ====================================================

        "mixed-port": 7890,

        "allow-lan": False,

        "mode": "rule",

        "log-level": "info",

        "ipv6": False,

        # ====================================================
        # 连接
        # ====================================================

        "unified-delay": True,

        "tcp-concurrent": True,

        # ====================================================
        # Profile
        # ====================================================

        "profile": {
            "store-selected": True,
            "store-fake-ip": True,
        },

        # ====================================================
        # DNS
        # ====================================================

        "dns": {
            "enable": True,

            "ipv6": False,

            "enhanced-mode": "fake-ip",

            "fake-ip-range":
                "198.18.0.1/16",

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

        # ====================================================
        # 真实节点
        #
        # 这里直接使用测速通过的原始节点对象。
        # 不生成 fake Trojan。
        # ====================================================

        "proxies": good,

        # ====================================================
        # Proxy Groups
        # ====================================================

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

        # ====================================================
        # Rule Providers
        # ====================================================

        "rule-providers": {
            "广告": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": ADS_URL,
                "path":
                    "./rule-providers/ads.mrs",
                "interval": 86400,
            },

            "国内域名": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": CN_DOMAIN_URL,
                "path":
                    "./rule-providers/cn.mrs",
                "interval": 86400,
            },

            "国内IP": {
                "type": "http",
                "behavior": "ipcidr",
                "format": "mrs",
                "url": CN_IP_URL,
                "path":
                    "./rule-providers/cn_ip.mrs",
                "interval": 86400,
            },

            "私有域名": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url":
                    PRIVATE_DOMAIN_URL,
                "path":
                    "./rule-providers/private.mrs",
                "interval": 86400,
            },

            "私有IP": {
                "type": "http",
                "behavior": "ipcidr",
                "format": "mrs",
                "url": PRIVATE_IP_URL,
                "path":
                    "./rule-providers/private_ip.mrs",
                "interval": 86400,
            },

            "GFW": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": GFW_DOMAIN_URL,
                "path":
                    "./rule-providers/gfw.mrs",
                "interval": 86400,
            },
        },

        # ====================================================
        # Rules
        #
        # 顺序：
        # 广告
        # 私有
        # 国内
        # GFW
        # 最终代理
        # ====================================================

        "rules": [
            "RULE-SET,广告,REJECT",

            "RULE-SET,私有域名,DIRECT",

            "RULE-SET,私有IP,DIRECT,no-resolve",

            "RULE-SET,国内域名,🇨🇳 国内直连",

            "RULE-SET,国内IP,🇨🇳 国内直连,no-resolve",

            "RULE-SET,GFW,🌍 国外代理",

            "MATCH,🚀 节点选择",
        ],

        # ====================================================
        # 生成信息
        # ====================================================

        "AIO_INFO": {
            "source": AUTHOR,

            "repository": REPO,

            "generated_at_beijing":
                now_beijing(),

            "input_files":
                input_count,

            "tested_nodes":
                test_count,

            "available_nodes":
                len(good),
        },
    }

    return config


# ============================================================
# 最终配置 Mihomo 二次校验
# ============================================================

def validate_final_config(
    mihomo,
    config_path,
):
    """
    将最终 YAML 交给 Mihomo 再加载一次。

    注意：
    这里只是校验，不修改真正输出文件。
    external-controller / secret 只写入临时副本。
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
                (
                    "abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789"
                ),
                k=24,
            )
        )

        data = load_yaml(
            cfg_copy
        )

        data[
            "external-controller"
        ] = f"127.0.0.1:{port}"

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
                if proc.poll() is not None:
                    return (
                        False,
                        "Mihomo 加载最终配置后立即退出",
                    )

                return (
                    False,
                    "Mihomo 无法加载最终配置",
                )

            try:
                version = api_get(
                    port,
                    secret,
                    "/version",
                    timeout=5,
                )

                if not isinstance(
                    version,
                    dict,
                ):
                    return (
                        False,
                        "Mihomo API 返回异常",
                    )

            except Exception as e:
                return (
                    False,
                    f"最终配置 API 校验失败: {e}",
                )

            return (
                True,
                "Mihomo 配置加载验证成功",
            )

        finally:
            if proc is not None:
                proc.terminate()

                try:
                    proc.wait(
                        timeout=5
                    )

                except subprocess.TimeoutExpired:
                    proc.kill()


# ============================================================
# 安全写入
# ============================================================

def safe_write_yaml(
    data,
    output,
):
    output = os.path.abspath(
        output
    )

    out_dir = (
        os.path.dirname(output)
        or "."
    )

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
        if os.path.exists(
            tmp_path
        ):
            os.remove(
                tmp_path
            )

        raise


# ============================================================
# 主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Mihomo AIO 节点合并 + "
            "测速 + 国内分流 + "
            "客户端广告拦截"
        )
    )

    parser.add_argument(
        "inputs",
        nargs="+",
        help="输入 Clash/Mihomo YAML",
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="输出 AIO YAML",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=32,
        help="测速并发，默认 32",
    )

    parser.add_argument(
        "--top",
        type=int,
        default=0,
        help="只输出前 N 个，0=全部",
    )

    args = parser.parse_args()

    if args.concurrency < 1:
        raise SystemExit(
            "[FAIL] --concurrency 必须 >= 1"
        )

    if args.top < 0:
        raise SystemExit(
            "[FAIL] --top 必须 >= 0"
        )

    # --------------------------------------------------------
    # PyYAML
    # --------------------------------------------------------

    try:
        import yaml  # noqa: F401

    except ImportError:
        raise SystemExit(
            "[FAIL] 缺少 PyYAML，请先安装: pip install pyyaml"
        )

    print()
    print("=" * 70)
    print(
        " Mihomo AIO 节点合并 / 测速 / "
        "国内分流 / 客户端去广告 V1"
    )
    print("=" * 70)
    print()

    # ========================================================
    # 1. 合并
    # ========================================================

    print(
        "[1/6] 正在读取并合并节点..."
    )

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
        f"      跳过节点: {stats['skipped']}"
    )

    print(
        f"      最终待测: {len(proxies)}"
    )

    if not proxies:
        raise SystemExit(
            "[FAIL] 没有任何可测试节点"
        )

    # ========================================================
    # 2. Mihomo
    # ========================================================

    mihomo = find_mihomo()

    print()
    print(
        f"[2/6] Mihomo 内核: {mihomo}"
    )

    # ========================================================
    # 3. 启动临时 Mihomo
    # ========================================================

    port = find_free_port()

    secret = "".join(
        random.choices(
            (
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789"
            ),
            k=24,
        )
    )

    test_config = build_test_config(
        port,
        secret,
        proxies,
    )

    with tempfile.TemporaryDirectory(
        prefix="mihomo_aio_test_"
    ) as td:

        config_path = os.path.join(
            td,
            "config.yaml",
        )

        dump_yaml(
            test_config,
            config_path,
        )

        print(
            f"[3/6] 启动 Mihomo 测速内核 "
            f"(127.0.0.1:{port})..."
        )

        proc = start_mihomo(
            mihomo,
            config_path,
            td,
        )

        try:
            if not wait_mihomo(
                proc,
                port,
                secret,
                timeout_seconds=60,
            ):
                raise SystemExit(
                    "[FAIL] Mihomo API 未就绪。"
                    "请检查 Mihomo 内核或输入节点配置。"
                )

            names = get_testable_names(
                port,
                secret,
            )

            print(
                f"      Mihomo 实际识别节点: {len(names)}"
            )

            if not names:
                raise SystemExit(
                    "[FAIL] Mihomo 没有识别到可测试节点"
                )

            # =================================================
            # 4. 测速
            # =================================================

            print()
            print(
                f"[4/6] 开始测试 {len(names)} 个节点"
            )

            print(
                f"      测试网址: {len(TEST_URLS)} 个"
            )

            for url in TEST_URLS:
                print(
                    f"      - {url}"
                )

            print(
                f"      并发: {args.concurrency}"
            )

            ok = {}

            done = 0
            total = len(names)

            interval = max(
                1,
                total // 50,
            )

            with ThreadPoolExecutor(
                max_workers=args.concurrency
            ) as executor:

                futures = {
                    executor.submit(
                        test_node,
                        port,
                        secret,
                        name,
                    ): name
                    for name in names
                }

                for future in as_completed(
                    futures
                ):

                    try:
                        name, delay = (
                            future.result()
                        )

                    except Exception:
                        name = futures[
                            future
                        ]

                        delay = None

                    done += 1

                    if delay is not None:
                        ok[name] = delay

                    if (
                        done % interval == 0
                        or done == total
                    ):

                        pct = (
                            done
                            * 100
                            // total
                        )

                        print(
                            f"      进度 "
                            f"{done}/{total} "
                            f"({pct}%) "
                            f"可用 {len(ok)}",
                            flush=True,
                        )

            print()

            print(
                f"      三网址全部通过: {len(ok)}"
            )

            if not ok:
                raise SystemExit(
                    "[FAIL] 全部节点测试失败，"
                    "不生成 AIO"
                )

            # =================================================
            # 按平均延迟排序
            # =================================================

            good = [
                proxy
                for proxy in proxies
                if proxy.get("name") in ok
            ]

            good.sort(
                key=lambda proxy:
                    ok[proxy["name"]]
            )

            if args.top > 0:
                good = good[
                    :args.top
                ]

            print(
                f"      最终输出节点: {len(good)}"
            )

            print()
            print(
                "      延迟最快节点:"
            )

            for i, proxy in enumerate(
                good[:20],
                1,
            ):

                print(
                    f"      {i:>2}. "
                    f"{proxy['name']} "
                    f"{ok.get(proxy['name'], '-')} ms"
                )

            if not good:
                raise SystemExit(
                    "[FAIL] 没有可输出节点"
                )

            # =================================================
            # 5. 生成最终客户端配置
            # =================================================

            print()

            print(
                "[5/6] 正在生成最终客户端配置..."
            )

            aio = build_client_config(
                good=good,
                test_count=len(names),
                input_count=len(
                    args.inputs
                ),
            )

            tmp_output = safe_write_yaml(
                aio,
                args.output,
            )

            print(
                "      YAML 已生成，"
                "开始 Mihomo 二次加载校验..."
            )

            valid, message = (
                validate_final_config(
                    mihomo,
                    tmp_output,
                )
            )

            if not valid:
                if os.path.exists(
                    tmp_output
                ):
                    os.remove(
                        tmp_output
                    )

                raise SystemExit(
                    f"[FAIL] 最终配置校验失败: "
                    f"{message}"
                )

            print(
                f"      ✓ {message}"
            )

            # =================================================
            # 原子替换
            # =================================================

            os.replace(
                tmp_output,
                os.path.abspath(
                    args.output
                ),
            )

            # =================================================
            # 6. 完成
            # =================================================

            print()

            print(
                "[6/6] AIO 配置生成完成"
            )

            print()

            print("=" * 70)

            print(
                f"输出文件: {args.output}"
            )

            print(
                f"最终节点: {len(good)}"
            )

            print(
                f"测速通过: "
                f"{len(ok)}/{len(names)}"
            )

            print(
                f"更新时间: "
                f"{now_beijing()} (北京时间)"
            )

            print("=" * 70)

            print()

            print(
                "配置包含:"
            )

            print(
                "  ✓ 原始真实节点"
            )

            print(
                "  ✓ 完整节点参数"
            )

            print(
                "  ✓ 完整配置指纹去重"
            )

            print(
                "  ✓ 国内 DNS"
            )

            print(
                "  ✓ 国内域名/IP 直连"
            )

            print(
                "  ✓ GFW 域名代理"
            )

            print(
                "  ✓ 客户端广告域名拦截"
            )

            print(
                "  ✓ 自动选择"
            )

            print(
                "  ✓ 故障转移"
            )

            print(
                "  ✓ Mihomo 二次加载校验"
            )

            print()

        finally:
            proc.terminate()

            try:
                proc.wait(
                    timeout=5
                )

            except subprocess.TimeoutExpired:
                proc.kill()


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            "\n[STOP] 用户中断"
        )

    except SystemExit:
        raise

    except Exception as e:
        print(
            f"\n[FAIL] "
            f"{type(e).__name__}: {e}"
        )
        raise