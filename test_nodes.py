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

DEFAULT_INPUT_PATTERNS = ["*.yaml", "*.yml"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"

MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")

API_HOST = "127.0.0.1"
API_PORT = 9097
API_SECRET = "test-only-secret"

TIMEOUT_MS = 8000
CONCURRENCY = 16


# ============================================================
# 严格测试地址
#
# 第一阶段：基础连通性
# 第二阶段：实际网站
#
# 6 个全部通过才保留
# ============================================================

TEST_GROUPS = [
    (
        "基础连通性",
        [
            ("Google gstatic", "https://www.gstatic.com/generate_204"),
            ("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"),
            ("Google 204", "https://www.google.com/generate_204"),
        ],
    ),
    (
        "实际网站",
        [
            ("Google 首页", "https://www.google.com/"),
            ("YouTube", "https://www.youtube.com/"),
            ("GitHub", "https://github.com/"),
        ],
    ),
]

ALL_TESTS = [
    (stage, label, url)
    for stage, tests in TEST_GROUPS
    for label, url in tests
]


# ============================================================
# 日志
# ============================================================

def log(msg):
    print(
        time.strftime("[%Y-%m-%d %H:%M:%S]"),
        msg,
        flush=True,
    )


# ============================================================
# 节点名称
# ============================================================

def safe_name(name):
    s = str(name or "node").strip()
    return s or "node"


# ============================================================
# 完整节点指纹
#
# 注意：
# name 不参与指纹。
#
# 所以：
# 同 server + port，
# 但 uuid/password/path/sni/tls 等不同，
# 不会被误删。
# ============================================================

def fingerprint(proxy):
    obj = {
        k: v
        for k, v in proxy.items()
        if k != "name"
    }

    raw = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# 读取 YAML
# ============================================================

def load_yaml_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        return []

    proxies = data.get("proxies", [])

    if not isinstance(proxies, list):
        return []

    return proxies


# ============================================================
# 收集输入文件
# ============================================================

def collect_files(inputs):
    files = []

    for item in inputs:
        matches = glob.glob(
            item,
            recursive=True,
        )

        if matches:
            files.extend(matches)
        elif os.path.isfile(item):
            files.append(item)

    seen = set()
    result = []

    for path in files:
        real = os.path.realpath(path)

        if real not in seen:
            seen.add(real)
            result.append(path)

    return sorted(result)


# ============================================================
# 合并节点
#
# 原节点字段和值不主动修改。
#
# 仅：
# 1. 删除完全重复节点
# 2. 如果两个不同节点名字完全相同，
#    为保证 Mihomo 的 name 唯一，
#    只修改 name。
# ============================================================

def merge_nodes(files):

    result = []

    seen_fp = set()

    name_count = {}

    stats = {
        "files": 0,
        "raw": 0,
        "invalid": 0,
        "duplicate": 0,
        "kept": 0,
    }

    for path in files:

        stats["files"] += 1

        try:
            nodes = load_yaml_file(path)

        except Exception as e:
            log(
                f"❌ YAML 读取失败: {path}: {e}"
            )
            continue

        log(
            f"📄 {path}: {len(nodes)} 个节点"
        )

        for node in nodes:

            stats["raw"] += 1

            if not isinstance(node, dict):
                stats["invalid"] += 1
                continue

            if not node.get("type"):
                stats["invalid"] += 1
                continue

            if not node.get("server"):
                stats["invalid"] += 1
                continue

            if not node.get("port"):
                stats["invalid"] += 1
                continue

            # 深拷贝，避免修改原始对象
            node = copy.deepcopy(node)

            # 完整节点指纹
            fp = fingerprint(node)

            # 完全相同才删除
            if fp in seen_fp:
                stats["duplicate"] += 1
                continue

            seen_fp.add(fp)

            # ------------------------------------------------
            # 名称处理
            #
            # 除了重复名称，不碰其它字段。
            # ------------------------------------------------

            base = safe_name(
                node.get("name")
            )

            count = name_count.get(
                base,
                0,
            )

            if count:

                new_name = (
                    f"{base} #{count + 1}"
                )

                while new_name in name_count:
                    count += 1
                    new_name = (
                        f"{base} #{count + 1}"
                    )

                node["name"] = new_name

                name_count[new_name] = 1
                name_count[base] = count + 1

            else:

                node["name"] = base
                name_count[base] = 1

            result.append(node)

            stats["kept"] += 1

    return result, stats


# ============================================================
# 生成 Mihomo 测试配置
#
# 注意：
# 这里仅用于测试。
#
# 原节点对象直接放进去，不重新拼接节点参数。
# ============================================================

def write_test_config(nodes, path):

    config = {
        "mixed-port": 7898,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "external-controller": (
            f"{API_HOST}:{API_PORT}"
        ),
        "secret": API_SECRET,
        "proxies": nodes,
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
            default_flow_style=False,
        )


# ============================================================
# 等待 Mihomo API
# ============================================================

def wait_api(proc):

    url = (
        f"http://{API_HOST}:{API_PORT}"
        "/version"
    )

    end_time = time.time() + 20

    while time.time() < end_time:

        if proc.poll() is not None:

            raise RuntimeError(
                "Mihomo 提前退出，"
                f"returncode={proc.returncode}"
            )

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization":
                    f"Bearer {API_SECRET}"
                },
                timeout=1.5,
            )

            if response.ok:
                return

        except requests.RequestException:
            pass

        time.sleep(0.25)

    raise TimeoutError(
        "等待 Mihomo API 超时"
    )


# ============================================================
# 单次 URL 测试
#
# expected=200-299
#
# 只有目标网站返回 2xx，
# 才算真正通过。
# ============================================================

def api_delay(name, url):

    encoded_name = urllib.parse.quote(
        name,
        safe="",
    )

    api_url = (
        f"http://{API_HOST}:{API_PORT}"
        f"/proxies/{encoded_name}/delay"
    )

    params = {
        "timeout": TIMEOUT_MS,
        "url": url,
        "expected": "200-299",
    }

    response = requests.get(
        api_url,
        params=params,
        headers={
            "Authorization":
            f"Bearer {API_SECRET}"
        },
        timeout=TIMEOUT_MS / 1000 + 5,
    )

    response.raise_for_status()

    data = response.json()

    delay = data.get("delay")

    if not isinstance(delay, int):
        raise RuntimeError(
            f"无有效 delay: {data}"
        )

    if delay <= 0:
        raise RuntimeError(
            f"delay 无效: {delay}"
        )

    return delay


# ============================================================
# 单节点严格测试
#
# 6 个地址必须全部成功。
#
# 任何一个失败：
# 立即淘汰。
# ============================================================

def test_one(node):

    name = node["name"]

    delays = []

    for stage, tests in TEST_GROUPS:

        for label, url in tests:

            try:

                delay = api_delay(
                    name,
                    url,
                )

                delays.append(delay)

            except Exception as e:

                return {
                    "name": name,
                    "node": node,
                    "ok": False,
                    "stage": stage,
                    "label": label,
                    "url": url,
                    "error": str(e),
                    "delays": delays,
                }

    # 必须正好 6 个
    if len(delays) != 6:

        return {
            "name": name,
            "node": node,
            "ok": False,
            "stage": "最终检查",
            "label": "6/6 数量不足",
            "url": "",
            "error": (
                f"实际成功 {len(delays)}/6"
            ),
            "delays": delays,
        }

    return {
        "name": name,
        "node": node,
        "ok": True,
        "avg": round(
            sum(delays) / len(delays),
            1,
        ),
        "delays": delays,
    }


# ============================================================
# 最终 YAML Mihomo 启动校验
#
# 注意：
# 只验证，不修改最终 YAML。
# ============================================================

def validate_final_config(
    path,
    mihomo_bin,
):

    with tempfile.TemporaryDirectory(
        prefix="mihomo_validate_"
    ) as temp_dir:

        test_config = (
            Path(temp_dir)
            / "config.yaml"
        )

        shutil.copy2(
            path,
            test_config,
        )

        command = [
            mihomo_bin,
            "-d",
            temp_dir,
            "-f",
            str(test_config),
        ]

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:

            time.sleep(2.5)

            if proc.poll() is not None:

                stdout, stderr = (
                    proc.communicate(
                        timeout=2
                    )
                )

                message = (
                    stderr
                    or stdout
                    or "mihomo exited"
                )

                raise RuntimeError(
                    message.strip()[-4000:]
                )

        finally:

            if proc.poll() is None:

                proc.terminate()

                try:
                    proc.wait(timeout=3)

                except subprocess.TimeoutExpired:

                    proc.kill()

        return True


# ============================================================
# 生成最终客户端 YAML
#
# 注意：
# good 里面的 node 对象就是原节点对象。
#
# 不重建：
# server
# port
# uuid
# password
# cipher
# tls
# sni
# servername
# path
# network
# ws-opts
# grpc-opts
# reality-opts
# 等全部保留。
# ============================================================

def build_output(
    good,
    output,
):

    names = [
        node["name"]
        for node in good
    ]

    config = {

        # ----------------------------------------------------
        # 基础客户端
        # ----------------------------------------------------

        "mixed-port": 7890,

        "allow-lan": False,

        "mode": "rule",

        "log-level": "info",

        "ipv6": False,

        "unified-delay": True,

        "tcp-concurrent": True,

        "find-process-mode": "strict",

        # ----------------------------------------------------
        # 保存选择
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

            "fake-ip-range":
                "198.18.0.1/16",

            "nameserver": [
                "223.5.5.5",
                "119.29.29.29",
                "https://doh.pub/dns-query",
                "https://dns.alidns.com/dns-query",
            ],

            "fallback": [
                "1.1.1.1",
                "8.8.8.8",
            ],

            "fallback-filter": {
                "geoip": True,
                "geoip-code": "CN",
                "geosite": ["gfw"],
            },
        },

        # ----------------------------------------------------
        # 关键：
        # 这里直接写入通过测试的原始节点。
        # 不重新构造节点。
        # ----------------------------------------------------

        "proxies": good,

        # ----------------------------------------------------
        # 节点组
        # ----------------------------------------------------

        "proxy-groups": [

            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": names,
            },

            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": names,
                "url":
                    "https://www.gstatic.com/generate_204",
                "interval": 300,
                "timeout": 5000,
                "expected-status": "200-299",
                "tolerance": 50,
            },

            {
                "name": "🔰 故障转移",
                "type": "fallback",
                "proxies": names,
                "url":
                    "https://www.gstatic.com/generate_204",
                "interval": 300,
                "timeout": 5000,
                "expected-status": "200-299",
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
                    "♻️ 自动选择",
                    "🔰 故障转移",
                    "DIRECT",
                ],
            },
        ],

        # ----------------------------------------------------
        # 客户端广告拦截
        # ----------------------------------------------------

        "rule-providers": {

            "广告": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",

                "url":
                    "https://raw.githubusercontent.com/"
                    "MetaCubeX/meta-rules-dat/"
                    "meta/geo/geosite/"
                    "category-ads-all.mrs",

                "path":
                    "./rules/ads.mrs",

                "interval": 86400,
            },
        },

        # ----------------------------------------------------
        # 路由
        # ----------------------------------------------------

        "rules": [

            # 广告
            "RULE-SET,广告,REJECT",

            # 中国大陆域名
            "DOMAIN-SUFFIX,cn,DIRECT",

            # 中国大陆 IP
            "GEOIP,CN,DIRECT",

            # 其它全部走代理
            "MATCH,🌍 国外代理",
        ],
    }

    # --------------------------------------------------------
    # 先写临时文件
    # --------------------------------------------------------

    temp_output = (
        str(output) + ".tmp"
    )

    with open(
        temp_output,
        "w",
        encoding="utf-8",
    ) as f:

        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

    return temp_output


# ============================================================
# 主程序
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "inputs",
        nargs="*",
        help="YAML 文件或 glob",
    )

    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=CONCURRENCY,
    )

    parser.add_argument(
        "--mihomo",
        default=MIHOMO_BIN,
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # 输入文件
    # --------------------------------------------------------

    inputs = (
        args.inputs
        or DEFAULT_INPUT_PATTERNS
    )

    files = collect_files(inputs)

    if not files:

        raise SystemExit(
            "❌ 没有找到输入 YAML"
        )

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
    # 合并
    # --------------------------------------------------------

    nodes, stats = merge_nodes(
        files
    )

    if not nodes:

        raise SystemExit(
            "❌ 没有可测试节点"
        )

    log(
        "📦 原始节点: "
        f"{stats['raw']} | "
        "无效: "
        f"{stats['invalid']} | "
        "完全重复: "
        f"{stats['duplicate']} | "
        "待测: "
        f"{len(nodes)}"
    )

    # --------------------------------------------------------
    # 启动 Mihomo
    # --------------------------------------------------------

    with tempfile.TemporaryDirectory(
        prefix="mihomo_test_"
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
            "🚀 启动 Mihomo 测试实例..."
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
                "🧪 严格测试模式："
                "6/6 全部通过才保留"
            )

            log(
                f"⚡ 并发测试: "
                f"{args.concurrency}"
            )

            results = []

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

                total = len(futures)

                for index, future in enumerate(
                    as_completed(futures),
                    1,
                ):

                    result = future.result()

                    results.append(result)

                    if result["ok"]:

                        log(
                            f"✅ "
                            f"[{index}/{total}] "
                            f"{result['name']} | "
                            "6/6 | "
                            f"avg="
                            f"{result['avg']}ms"
                        )

                    else:

                        log(
                            f"❌ "
                            f"[{index}/{total}] "
                            f"{result['name']} | "
                            f"{result['stage']} / "
                            f"{result['label']} | "
                            f"{result['error'][:180]}"
                        )

            # ------------------------------------------------
            # 只有 6/6 才进入 good
            # ------------------------------------------------

            good = [
                result["node"]
                for result in results
                if result["ok"]
            ]

        finally:

            if proc.poll() is None:

                proc.terminate()

                try:

                    proc.wait(
                        timeout=5
                    )

                except subprocess.TimeoutExpired:

                    proc.kill()

    # ========================================================
    # 统计
    # ========================================================

    failed = [
        result
        for result in results
        if not result["ok"]
    ]

    log(
        "🏁 测试结束: "
        f"{len(good)}/{len(nodes)} "
        "个节点通过 6/6"
    )

    if failed:

        counter = Counter(
            (
                result["stage"],
                result["label"],
            )
            for result in failed
        )

        log("📊 淘汰原因统计:")

        for (
            stage,
            label,
        ), count in counter.most_common():

            log(
                f"   ❌ {count} 个: "
                f"{stage} / {label}"
            )

    # ========================================================
    # 一个都没通过
    #
    # 不覆盖旧文件。
    # ========================================================

    if not good:

        log(
            "⚠️ 没有任何节点通过 6/6。"
        )

        log(
            "⚠️ 不生成、不覆盖最终 YAML。"
        )

        return 2

    # ========================================================
    # 生成最终配置
    # ========================================================

    output = Path(
        args.output
    ).resolve()

    temp_output = build_output(
        good,
        output,
    )

    try:

        # ----------------------------------------------------
        # 最终 Mihomo 启动校验
        # ----------------------------------------------------

        log(
            "🔍 正在进行最终 Mihomo "
            "配置启动校验..."
        )

        validate_final_config(
            temp_output,
            args.mihomo,
        )

        # ----------------------------------------------------
        # 校验成功以后才覆盖
        # ----------------------------------------------------

        os.replace(
            temp_output,
            output,
        )

    except Exception as e:

        try:
            os.remove(temp_output)
        except OSError:
            pass

        log(
            "❌ 最终配置校验失败："
            f"{e}"
        )

        log(
            "❌ 不覆盖原来的输出文件。"
        )

        return 3

    # ========================================================
    # 完成
    # ========================================================

    log(
        "✅ 最终 YAML 已生成:"
        f" {output}"
    )

    log(
        f"✅ 最终保留节点: "
        f"{len(good)}"
    )

    log(
        "✅ 每个保留节点均通过 "
        "6/6 测试。"
    )

    log(
        "✅ 节点内部配置未主动重写。"
    )

    log(
        "ℹ️ 如果不同来源存在完全相同节点，"
        "仅删除重复副本。"
    )

    log(
        "ℹ️ 如果不同节点名称相同，"
        "仅给名称追加 #2/#3，"
        "其余节点参数保持不变。"
    )

    return 0


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    raise SystemExit(
        main()
    )