#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import glob
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml


# ============================================================
# 基础配置
# ============================================================

API_HOST = "127.0.0.1"
API_PORT = 9097
MIXED_PORT = 7898
SECRET = "diag-secret"

TIMEOUT_MS = 8000

# 真实数据传输测试
DATA_BYTES = 1024 * 1024
DATA_URL = "https://speed.cloudflare.com/__down?bytes=1048576"


# ============================================================
# 6 个严格 HTTP 测试
#
# 6/6 全部成功才进入真实数据测试
# ============================================================

TESTS = [
    (
        "基础1-gstatic",
        "https://www.gstatic.com/generate_204",
    ),
    (
        "基础2-cloudflare",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ),
    (
        "基础3-google204",
        "https://www.google.com/generate_204",
    ),
    (
        "网站1-google",
        "https://www.google.com/",
    ),
    (
        "网站2-youtube",
        "https://www.youtube.com/",
    ),
    (
        "网站3-github",
        "https://github.com/",
    ),
]


# ============================================================
# 日志
# ============================================================

def log(message):
    print(
        time.strftime(
            "[%Y-%m-%d %H:%M:%S]"
        ),
        message,
        flush=True,
    )


# ============================================================
# 完整节点指纹
#
# name 不参与指纹
#
# 因此同 IP/端口但不同：
# uuid
# password
# path
# sni
# tls
# ws-opts
# reality-opts
# 等配置
#
# 都不会被误删。
# ============================================================

def fingerprint(node):
    data = {
        k: v
        for k, v in node.items()
        if k != "name"
    }

    raw = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# 查找输入文件
# ============================================================

def load_files(patterns):
    result = []
    seen = set()

    for pattern in patterns:

        for path in glob.glob(
            pattern,
            recursive=True,
        ):

            if not os.path.isfile(path):
                continue

            real = os.path.realpath(path)

            if real in seen:
                continue

            seen.add(real)
            result.append(path)

    return sorted(result)


# ============================================================
# 合并节点
#
# 原节点完整复制。
# 不重建节点。
# ============================================================

def merge_nodes(files):

    result = []

    seen = set()

    name_counter = Counter()

    for path in files:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:

            data = yaml.safe_load(f) or {}

        proxies = data.get(
            "proxies",
            [],
        )

        if not isinstance(
            proxies,
            list,
        ):
            continue

        log(
            f"📄 {path}: "
            f"{len(proxies)} 个节点"
        )

        for raw in proxies:

            if not isinstance(
                raw,
                dict,
            ):
                continue

            if not raw.get("type"):
                continue

            if not raw.get("server"):
                continue

            if not raw.get("port"):
                continue

            node = copy.deepcopy(raw)

            fp = fingerprint(node)

            if fp in seen:
                continue

            seen.add(fp)

            base_name = str(
                node.get("name")
                or "node"
            )

            name_counter[
                base_name
            ] += 1

            count = name_counter[
                base_name
            ]

            if count == 1:

                node["name"] = (
                    base_name
                )

            else:

                node["name"] = (
                    f"{base_name} #{count}"
                )

            result.append(node)

    return result


# ============================================================
# 测试用 Mihomo 配置
#
# 重点：
# DNS 已加入诊断配置。
#
# 原节点直接放入 proxies。
# 不改节点字段。
# ============================================================

def write_test_config(
    nodes,
    path,
):

    config = {

        "mixed-port": MIXED_PORT,

        "allow-lan": False,

        "mode": "rule",

        "log-level": "warning",

        # 诊断阶段先关闭 IPv6
        "ipv6": False,

        "unified-delay": True,

        # 减少 DNS 多地址并发带来的变量
        "tcp-concurrent": False,

        "external-controller":
            f"{API_HOST}:{API_PORT}",

        "secret": SECRET,

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
                "tls://1.1.1.1",
                "tls://8.8.8.8",
            ],

            # 专门用于解析代理节点域名
            "proxy-server-nameserver": [
                "https://doh.pub/dns-query",
                "https://dns.alidns.com/dns-query",
            ],

            "fallback-filter": {
                "geoip": True,
                "geoip-code": "CN",
                "domain": [
                    "+.google.com",
                    "+.youtube.com",
                    "+.github.com",
                ],
            },
        },

        # ====================================================
        # 原始节点
        # ====================================================

        "proxies": nodes,

        # ====================================================
        # 单独测试选择组
        # ====================================================

        "proxy-groups": [
            {
                "name": "__DIAG_SELECT__",
                "type": "select",
                "proxies": [
                    node["name"]
                    for node in nodes
                ],
            }
        ],
    }

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:

        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False,
        )


# ============================================================
# 等待 Mihomo API
# ============================================================

def wait_api(proc):

    url = (
        f"http://{API_HOST}:{API_PORT}"
        "/version"
    )

    deadline = (
        time.time() + 20
    )

    while time.time() < deadline:

        if proc.poll() is not None:

            raise RuntimeError(
                "Mihomo 提前退出"
            )

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization":
                    f"Bearer {SECRET}"
                },
                timeout=1,
            )

            if response.ok:
                return

        except requests.RequestException:
            pass

        time.sleep(0.25)

    raise TimeoutError(
        "Mihomo API 启动超时"
    )


# ============================================================
# Mihomo API
# ============================================================

def api_request(
    method,
    path,
    **kwargs,
):

    headers = kwargs.pop(
        "headers",
        {},
    )

    headers["Authorization"] = (
        f"Bearer {SECRET}"
    )

    return requests.request(
        method,
        (
            f"http://{API_HOST}:{API_PORT}"
            f"{path}"
        ),
        headers=headers,
        **kwargs,
    )


# ============================================================
# 单 URL delay 测试
#
# 注意：
# 503 不再只显示一句 Service Unavailable。
# 会把 Mihomo 返回内容一起记录下来。
# ============================================================

def delay_test(
    name,
    url,
):

    encoded_name = (
        urllib.parse.quote(
            name,
            safe="",
        )
    )

    path = (
        f"/proxies/{encoded_name}/delay"
    )

    response = api_request(
        "GET",
        path,
        params={
            "timeout": TIMEOUT_MS,
            "url": url,
            "expected": "200-299",
        },
        timeout=(
            TIMEOUT_MS / 1000
        ) + 5,
    )

    if response.status_code != 200:

        body = response.text[:1000]

        raise RuntimeError(
            f"Mihomo API HTTP "
            f"{response.status_code}: "
            f"{body}"
        )

    try:

        data = response.json()

    except Exception:

        raise RuntimeError(
            "Mihomo 返回非 JSON: "
            f"{response.text[:1000]}"
        )

    delay = data.get(
        "delay"
    )

    if not isinstance(
        delay,
        int,
    ):

        raise RuntimeError(
            "没有有效 delay: "
            f"{data}"
        )

    if delay <= 0:

        raise RuntimeError(
            f"delay 无效: {delay}"
        )

    return delay


# ============================================================
# 一个节点严格 6/6
# ============================================================

def test_one(node):

    name = node["name"]

    delays = []

    for label, url in TESTS:

        try:

            delay = delay_test(
                name,
                url,
            )

            delays.append(
                delay
            )

        except Exception as e:

            return {
                "ok": False,
                "name": name,
                "node": node,
                "failed": label,
                "url": url,
                "error": str(e),
                "delays": delays,
            }

    if len(delays) != 6:

        return {
            "ok": False,
            "name": name,
            "node": node,
            "failed": "6/6数量检查",
            "url": "",
            "error":
                f"只有 {len(delays)}/6",
            "delays": delays,
        }

    return {
        "ok": True,
        "name": name,
        "node": node,
        "avg": round(
            sum(delays) / 6,
            1,
        ),
        "delays": delays,
    }


# ============================================================
# 真实数据传输测试
#
# 这里不再测 delay。
#
# 而是：
# 1. 选择具体节点
# 2. 通过 Mihomo mixed-port
# 3. 真正下载数据
# 4. 必须收到完整 1MB
#
# 专门筛掉：
#
# "延迟很低，但是没有数据"
#
# 的节点。
# ============================================================

def data_test(name):

    group = (
        "__DIAG_SELECT__"
    )

    encoded_group = (
        urllib.parse.quote(
            group,
            safe="",
        )
    )

    response = api_request(
        "PUT",
        f"/proxies/{encoded_group}",
        json={
            "name": name
        },
        timeout=5,
    )

    if response.status_code not in (
        200,
        204,
    ):

        return (
            False,
            0,
            (
                "选择节点失败 "
                f"HTTP {response.status_code}: "
                f"{response.text[:500]}"
            ),
        )

    proxy_url = (
        f"http://"
        f"{API_HOST}:{MIXED_PORT}"
    )

    start = time.time()

    received = 0

    try:

        with requests.get(
            DATA_URL,
            proxies={
                "http": proxy_url,
                "https": proxy_url,
            },
            stream=True,
            timeout=(
                8,
                20,
            ),
        ) as response:

            response.raise_for_status()

            for chunk in response.iter_content(
                chunk_size=65536
            ):

                if not chunk:
                    continue

                received += len(
                    chunk
                )

                if (
                    received
                    >= DATA_BYTES
                ):
                    break

        elapsed = max(
            time.time() - start,
            0.001,
        )

        speed = (
            received
            / elapsed
            / 1024
            / 1024
        )

        if received < DATA_BYTES:

            return (
                False,
                received,
                (
                    "实际只收到 "
                    f"{received} bytes"
                ),
            )

        return (
            True,
            received,
            f"{speed:.2f} MB/s",
        )

    except Exception as e:

        return (
            False,
            received,
            str(e),
        )


# ============================================================
# 主程序
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "inputs",
        nargs="+",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="diagnostic_passed.yaml",
    )

    parser.add_argument(
        "--report",
        default="diagnostic_report.json",
    )

    parser.add_argument(
        "--mihomo",
        default=os.environ.get(
            "MIHOMO_BIN",
            "mihomo",
        ),
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=16,
    )

    parser.add_argument(
        "--data-check-top",
        type=int,
        default=50,
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Mihomo
    # --------------------------------------------------------

    if (
        not shutil.which(args.mihomo)
        and not os.path.isfile(
            args.mihomo
        )
    ):

        raise SystemExit(
            f"❌ 找不到 Mihomo: "
            f"{args.mihomo}"
        )

    # --------------------------------------------------------
    # 输入文件
    # --------------------------------------------------------

    files = load_files(
        args.inputs
    )

    if not files:

        raise SystemExit(
            "❌ 没有找到输入 YAML"
        )

    # --------------------------------------------------------
    # 合并
    # --------------------------------------------------------

    nodes = merge_nodes(
        files
    )

    if not nodes:

        raise SystemExit(
            "❌ 没有可测试节点"
        )

    log(
        f"📦 待测节点: "
        f"{len(nodes)}"
    )

    # --------------------------------------------------------
    # 启动 Mihomo
    # --------------------------------------------------------

    with tempfile.TemporaryDirectory(
        prefix="mihomo_diag_"
    ) as temp_dir:

        config_path = (
            Path(temp_dir)
            / "config.yaml"
        )

        write_test_config(
            nodes,
            config_path,
        )

        log(
            "🚀 启动 Mihomo..."
        )

        proc = subprocess.Popen(
            [
                args.mihomo,
                "-d",
                temp_dir,
                "-f",
                str(config_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:

            wait_api(proc)

            log(
                "✅ Mihomo 已启动"
            )

            log(
                "🌐 DNS 诊断配置："
                "Fake-IP + DoH + "
                "proxy-server-nameserver"
            )

            log(
                "🚫 IPv6: OFF"
            )

            log(
                "🧪 第一阶段："
                "6/6 HTTP 严格测试"
            )

            # ------------------------------------------------
            # 第一阶段
            # ------------------------------------------------

            results = []

            total = len(nodes)

            with ThreadPoolExecutor(
                max_workers=max(
                    1,
                    args.concurrency,
                )
            ) as executor:

                futures = [
                    executor.submit(
                        test_one,
                        node,
                    )
                    for node in nodes
                ]

                for index, future in enumerate(
                    as_completed(futures),
                    1,
                ):

                    result = (
                        future.result()
                    )

                    results.append(
                        result
                    )

                    if result["ok"]:

                        log(
                            f"✅ "
                            f"[{index}/{total}] "
                            f"{result['name']} "
                            f"| 6/6 "
                            f"| avg="
                            f"{result['avg']}ms"
                        )

                    else:

                        log(
                            f"❌ "
                            f"[{index}/{total}] "
                            f"{result['name']} "
                            f"| "
                            f"{result['failed']} "
                            f"| "
                            f"{result['error'][:300]}"
                        )

            passed = sorted(
                [
                    x
                    for x in results
                    if x["ok"]
                ],
                key=lambda x:
                    x["avg"],
            )

            log(
                "📊 第一阶段完成："
                f"{len(passed)}/"
                f"{len(nodes)} "
                "通过 6/6"
            )

            # ------------------------------------------------
            # 第二阶段
            # ------------------------------------------------

            check_count = min(
                len(passed),
                max(
                    0,
                    args.data_check_top,
                ),
            )

            log(
                "📥 第二阶段："
                "真实数据传输测试"
            )

            log(
                f"📌 本轮实际下载测试："
                f"{check_count} 个节点"
            )

            data_results = []

            for item in passed[
                :check_count
            ]:

                ok, received, message = (
                    data_test(
                        item["name"]
                    )
                )

                record = {
                    "name":
                        item["name"],
                    "avg":
                        item["avg"],
                    "data_ok":
                        ok,
                    "bytes":
                        received,
                    "data_result":
                        message,
                    "delays":
                        item["delays"],
                }

                data_results.append(
                    record
                )

                if ok:

                    log(
                        f"📥 ✅ "
                        f"{item['name']} "
                        f"| {message} "
                        f"| bytes={received}"
                    )

                else:

                    log(
                        f"📥 ❌ "
                        f"{item['name']} "
                        f"| {message} "
                        f"| bytes={received}"
                    )

            # ------------------------------------------------
            # 最终节点
            # ------------------------------------------------

            data_good = {
                x["name"]
                for x in data_results
                if x["data_ok"]
            }

            final_nodes = [
                x["node"]
                for x in passed
                if x["name"]
                in data_good
            ]

            # ------------------------------------------------
            # 报告
            # ------------------------------------------------

            report = {
                "input_files":
                    files,

                "total_nodes":
                    len(nodes),

                "http_6of6":
                    len(passed),

                "data_checked":
                    len(data_results),

                "data_passed":
                    len(final_nodes),

                "results":
                    results,

                "data_results":
                    data_results,
            }

            with open(
                args.report,
                "w",
                encoding="utf-8",
            ) as f:

                json.dump(
                    report,
                    f,
                    ensure_ascii=False,
                    indent=2,
                )

            log(
                f"📄 诊断报告: "
                f"{args.report}"
            )

            # ------------------------------------------------
            # 最终 YAML
            # ------------------------------------------------

            if not final_nodes:

                log(
                    "⚠️ 没有节点通过真实数据测试"
                )

                log(
                    "⚠️ 不覆盖原输出文件"
                )

                return 2

            names = [
                node["name"]
                for node in final_nodes
            ]

            final_config = {

                "mixed-port": 7890,

                "allow-lan": False,

                "mode": "rule",

                "log-level": "info",

                "ipv6": False,

                "unified-delay": True,

                "tcp-concurrent": False,

                "profile": {
                    "store-selected": True,
                    "store-fake-ip": True,
                },

                "dns": {

                    "enable": True,

                    "ipv6": False,

                    "enhanced-mode":
                        "fake-ip",

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
                        "tls://1.1.1.1",
                        "tls://8.8.8.8",
                    ],

                    "proxy-server-nameserver": [
                        "https://doh.pub/dns-query",
                        "https://dns.alidns.com/dns-query",
                    ],
                },

                # 原节点完整保留
                "proxies":
                    final_nodes,

                "proxy-groups": [

                    {
                        "name":
                            "🚀 节点选择",
                        "type":
                            "select",
                        "proxies":
                            names,
                    },

                    {
                        "name":
                            "♻️ 自动选择",
                        "type":
                            "url-test",
                        "proxies":
                            names,
                        "url":
                            "https://www.gstatic.com/generate_204",
                        "interval":
                            300,
                        "timeout":
                            8000,
                        "expected-status":
                            "200-299",
                    },

                    {
                        "name":
                            "🌍 国外代理",
                        "type":
                            "select",
                        "proxies": [
                            "🚀 节点选择",
                            "♻️ 自动选择",
                            "DIRECT",
                        ],
                    },
                ],

                "rules": [
                    "DOMAIN-SUFFIX,cn,DIRECT",
                    "GEOIP,CN,DIRECT",
                    "MATCH,🌍 国外代理",
                ],
            }

            temp_output = (
                str(args.output)
                + ".tmp"
            )

            with open(
                temp_output,
                "w",
                encoding="utf-8",
            ) as f:

                yaml.safe_dump(
                    final_config,
                    f,
                    allow_unicode=True,
                    sort_keys=False,
                )

            os.replace(
                temp_output,
                args.output,
            )

            log(
                "================================"
            )

            log(
                f"🎯 第一阶段 6/6: "
                f"{len(passed)}"
            )

            log(
                f"🎯 第二阶段真实数据: "
                f"{len(final_nodes)}"
            )

            log(
                f"💾 最终输出: "
                f"{args.output}"
            )

            log(
                "================================"
            )

        finally:

            if proc.poll() is None:

                proc.terminate()

                try:

                    proc.wait(
                        timeout=5
                    )

                except subprocess.TimeoutExpired:

                    proc.kill()

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )