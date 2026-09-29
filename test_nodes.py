#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import copy
import random
import shutil
import tempfile
import subprocess
import signal
from pathlib import Path
from urllib.parse import quote

import requests
import yaml


# ============================================================
# 配置
# ============================================================

BASE = Path("/content/drive/MyDrive/AssetProject/scripts")

INPUT_DIR = BASE / "generated" / "probe"
OUTPUT_DIR = BASE / "data"

INPUT_GLOB = "cf_nest_1only_probe_*.yaml"

OUTPUT_YAML = OUTPUT_DIR / "cf_nest_download_probe_100.yaml"
REPORT_JSON = OUTPUT_DIR / "cf_nest_download_probe_100_report.json"

MIHOMO = os.environ.get(
    "MIHOMO_BIN",
    str(BASE / "mihomo_speed" / "mihomo")
)

# ============================================================
# 本轮只抽样 100 个
# ============================================================

TEST_COUNT = 100

# 每个节点实际下载至少 1 MB 才算通过
DOWNLOAD_BYTES = 1024 * 1024

# Cloudflare 实际下载接口
DOWNLOAD_URL = (
    "https://speed.cloudflare.com/__down?bytes=1048576"
)

# Mihomo
MIXED_PORT = 7898
API_PORT = 9097

# 超时
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 12

# 切换节点后等待 Mihomo 生效
SELECT_WAIT = 0.25

# None = 每次随机抽样
# 如果以后想固定同一批节点，可以改成整数，例如 20260929
RANDOM_SEED = None


# ============================================================
# DNS
# ============================================================

DNS = {
    "enable": True,
    "ipv6": False,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",

    "default-nameserver": [
        "223.5.5.5",
        "119.29.29.29"
    ],

    "nameserver": [
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query"
    ],

    "fallback": [
        "tls://1.1.1.1",
        "tls://8.8.8.8"
    ],

    "proxy-server-nameserver": [
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query"
    ],

    "fallback-filter": {
        "geoip": True,
        "geoip-code": "CN",
        "geosite": ["gfw"],
        "domain": [
            "+.google.com",
            "+.youtube.com",
            "+.github.com"
        ]
    }
}


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "Chrome/151 Safari/537.36"
    )
}


# ============================================================
# 日志
# ============================================================

def log(message):
    print(
        time.strftime("[%Y-%m-%d %H:%M:%S]"),
        message,
        flush=True
    )


def die(message):
    log("❌ " + message)
    raise SystemExit(1)


# ============================================================
# 读取节点
# ============================================================

def load_nodes():

    files = sorted(INPUT_DIR.glob(INPUT_GLOB))

    if not files:
        die(
            f"找不到输入文件："
            f"{INPUT_DIR}/{INPUT_GLOB}"
        )

    nodes = []
    seen = set()

    for file in files:

        try:
            data = yaml.safe_load(
                file.read_text(encoding="utf-8")
            ) or {}

        except Exception as e:
            log(f"⚠️ 跳过无法读取 {file}: {e}")
            continue

        arr = (
            data.get("proxies", [])
            if isinstance(data, dict)
            else []
        )

        log(
            f"📄 {file}: {len(arr)} 个节点"
        )

        for proxy in arr:

            if not isinstance(proxy, dict):
                continue

            if not proxy.get("type"):
                continue

            if not proxy.get("server"):
                continue

            # 完整复制原节点
            node = copy.deepcopy(proxy)

            # 去重：
            # 只排除 name，其他所有配置都参与指纹
            fingerprint_data = {
                k: v
                for k, v in node.items()
                if k != "name"
            }

            fingerprint = json.dumps(
                fingerprint_data,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":")
            )

            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            nodes.append(node)

    log(f"📦 去重后节点：{len(nodes)}")

    return nodes


# ============================================================
# 确保 Mihomo 节点名称唯一
# 不改变节点本身参数
# ============================================================

def unique_names(nodes):

    used = {}

    for node in nodes:

        original = str(
            node.get("name")
            or (
                f"{node.get('type', 'proxy')}-"
                f"{node.get('server', '')}-"
                f"{node.get('port', '')}"
            )
        )

        if original not in used:

            used[original] = 1
            node["name"] = original

        else:

            used[original] += 1
            node["name"] = (
                f"{original} #{used[original]}"
            )

    return nodes


# ============================================================
# 生成 Mihomo 测试配置
# ============================================================

def make_config(nodes, path, external=True):

    config = {
        "mixed-port": MIXED_PORT,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,

        "dns": DNS,

        # 原始节点完整放进去
        "proxies": nodes,

        # 一个节点一个节点切换
        "proxy-groups": [
            {
                "name": "__DOWNLOAD_TEST__",
                "type": "select",
                "proxies": [
                    node["name"]
                    for node in nodes
                ]
            }
        ],

        "rules": [
            "MATCH,__DOWNLOAD_TEST__"
        ]
    }

    if external:
        config["external-controller"] = (
            f"127.0.0.1:{API_PORT}"
        )

    path.write_text(
        yaml.safe_dump(
            config,
            allow_unicode=True,
            sort_keys=False
        ),
        encoding="utf-8"
    )


# ============================================================
# 启动 Mihomo
# ============================================================

def start_mihomo(config_path):

    if not Path(MIHOMO).exists():
        die(f"Mihomo 不存在：{MIHOMO}")

    os.chmod(MIHOMO, 0o755)

    process = subprocess.Popen(
        [
            MIHOMO,
            "-f",
            str(config_path)
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )

    api = (
        f"http://127.0.0.1:{API_PORT}"
    )

    session = requests.Session()

    for _ in range(60):

        try:

            response = session.get(
                api + "/version",
                timeout=1
            )

            if response.ok:
                return process, session

        except Exception:
            pass

        time.sleep(0.2)

    try:
        process.terminate()
    except Exception:
        pass

    die("Mihomo API 启动超时")


# ============================================================
# 停止 Mihomo
# ============================================================

def stop_mihomo(process):

    if not process:
        return

    try:

        os.killpg(
            process.pid,
            signal.SIGTERM
        )

        process.wait(timeout=5)

    except Exception:

        try:
            process.kill()
        except Exception:
            pass


# ============================================================
# 切换节点
# ============================================================

def select_node(session, name):

    url = (
        f"http://127.0.0.1:{API_PORT}"
        f"/proxies/"
        f"{quote('__DOWNLOAD_TEST__', safe='')}"
    )

    response = session.put(
        url,
        json={"name": name},
        timeout=5
    )

    response.raise_for_status()

    time.sleep(SELECT_WAIT)


# ============================================================
# 核心：
# 只测试“实际下载”
#
# 不测：
# ❌ 延迟
# ❌ Google 204
# ❌ YouTube
# ❌ GitHub
# ❌ 网站打开速度
#
# 只看：
# ✅ 能不能真正收到至少 1 MB 数据
# ============================================================

def test_download(session, node):

    name = node["name"]

    try:

        # 切换到当前节点
        select_node(
            session,
            name
        )

        # 通过 Mihomo 本地代理实际下载
        response = session.get(
            DOWNLOAD_URL,

            headers=HEADERS,

            stream=True,

            timeout=(
                CONNECT_TIMEOUT,
                READ_TIMEOUT
            ),

            proxies={
                "http": (
                    f"http://127.0.0.1:{MIXED_PORT}"
                ),
                "https": (
                    f"http://127.0.0.1:{MIXED_PORT}"
                )
            }
        )

        status = response.status_code

        received = 0

        if not (
            200 <= status < 300
        ):

            response.close()

            return (
                False,
                received,
                status,
                f"HTTP {status}"
            )

        # 真正读取数据
        for chunk in response.iter_content(
            chunk_size=65536
        ):

            if not chunk:
                continue

            received += len(chunk)

            # 收到 1 MB 就算通过
            if received >= DOWNLOAD_BYTES:
                break

        response.close()

        if received >= DOWNLOAD_BYTES:

            return (
                True,
                received,
                status,
                "OK"
            )

        return (
            False,
            received,
            status,
            (
                f"下载不足 "
                f"{received}/{DOWNLOAD_BYTES} bytes"
            )
        )

    except Exception as e:

        return (
            False,
            0,
            None,
            f"{type(e).__name__}: {e}"
        )


# ============================================================
# YAML 最终校验
# ============================================================

def validate_yaml(path):

    try:

        data = yaml.safe_load(
            path.read_text(
                encoding="utf-8"
            )
        )

        assert isinstance(data, dict)

        assert isinstance(
            data.get("proxies"),
            list
        )

        return len(
            data["proxies"]
        )

    except Exception as e:

        log(
            f"❌ YAML 校验失败：{e}"
        )

        return 0


# ============================================================
# 主程序
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # 读取全部节点
    # --------------------------------------------------------

    nodes = load_nodes()

    nodes = unique_names(nodes)

    if not nodes:
        die("没有可测试节点")

    # --------------------------------------------------------
    # 随机抽样固定数量
    # --------------------------------------------------------

    test_count = min(
        TEST_COUNT,
        len(nodes)
    )

    rng = random.Random(
        RANDOM_SEED
    )

    sample = rng.sample(
        nodes,
        test_count
    )

    log(
        f"🎯 本轮随机抽样：{test_count} 个"
    )

    log(
        "⚠️ 这 100 个全部测试完"
    )

    log(
        "⚠️ 不因为找到成功节点而提前停止"
    )

    log(
        "⚠️ 最终把所有成功节点全部输出"
    )

    log(
        "🌐 唯一测试标准："
        f"实际下载 ≥ {DOWNLOAD_BYTES // 1024} KB"
    )

    # --------------------------------------------------------
    # 临时目录
    # --------------------------------------------------------

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="mihomo_download_probe_"
        )
    )

    config_path = (
        temp_dir / "config.yaml"
    )

    # --------------------------------------------------------
    # 生成测试配置
    # --------------------------------------------------------

    make_config(
        sample,
        config_path
    )

    process = None
    results = []
    passed_nodes = []

    try:

        # ----------------------------------------------------
        # 启动 Mihomo
        # ----------------------------------------------------

        log("🚀 启动 Mihomo...")

        process, session = start_mihomo(
            config_path
        )

        # ----------------------------------------------------
        # 100 个全部测试
        # ----------------------------------------------------

        for index, node in enumerate(
            sample,
            1
        ):

            ok, received, status, error = (
                test_download(
                    session,
                    node
                )
            )

            result = {
                "index": index,
                "name": node["name"],
                "type": node.get("type"),
                "server": node.get("server"),
                "port": node.get("port"),
                "success": ok,
                "received_bytes": received,
                "http_status": status,
                "error": error
            }

            results.append(result)

            if ok:

                # 完整复制原始节点
                passed_nodes.append(
                    copy.deepcopy(node)
                )

                log(
                    f"✅ [{index}/{test_count}] "
                    f"{node['name']} | "
                    f"下载 "
                    f"{received / 1024:.1f} KB"
                )

            else:

                log(
                    f"❌ [{index}/{test_count}] "
                    f"{node['name']} | "
                    f"{error}"
                )

    finally:

        stop_mihomo(
            process
        )

        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )

    # ========================================================
    # 输出结果
    # ========================================================

    if not passed_nodes:

        log(
            f"⚠️ {test_count} 个节点全部"
            "未通过真实下载测试"
        )

        log(
            "⚠️ 不生成空的节点文件"
        )

    else:

        # ----------------------------------------------------
        # 最终客户端 YAML
        # ----------------------------------------------------

        final_config = {

            "mixed-port": 7890,

            "allow-lan": True,

            "mode": "rule",

            "log-level": "info",

            "ipv6": False,

            "dns": DNS,

            # ------------------------------------------------
            # 这里直接使用测试通过的原节点
            # 不重新拼接 VLESS / WS / TLS
            # ------------------------------------------------
            "proxies": passed_nodes,

            "proxy-groups": [

                {
                    "name": "🚀 节点选择",
                    "type": "select",
                    "proxies": [
                        node["name"]
                        for node in passed_nodes
                    ] + [
                        "DIRECT"
                    ]
                },

                {
                    "name": "🇨🇳 国内直连",
                    "type": "select",
                    "proxies": [
                        "DIRECT",
                        "🚀 节点选择"
                    ]
                },

                {
                    "name": "🌍 国外代理",
                    "type": "select",
                    "proxies": [
                        "🚀 节点选择",
                        "DIRECT"
                    ]
                }
            ],

            "rules": [
                "DOMAIN-SUFFIX,cn,DIRECT",
                "GEOIP,CN,DIRECT",
                "MATCH,🌍 国外代理"
            ]
        }

        # ----------------------------------------------------
        # 临时输出
        # ----------------------------------------------------

        temp_output = (
            OUTPUT_YAML.with_suffix(
                ".tmp.yaml"
            )
        )

        temp_output.write_text(
            yaml.safe_dump(
                final_config,
                allow_unicode=True,
                sort_keys=False
            ),
            encoding="utf-8"
        )

        # ----------------------------------------------------
        # 校验
        # ----------------------------------------------------

        valid_count = validate_yaml(
            temp_output
        )

        if valid_count != len(
            passed_nodes
        ):

            die(
                "最终 YAML 校验数量异常，"
                "拒绝覆盖正式输出"
            )

        os.replace(
            temp_output,
            OUTPUT_YAML
        )

        log(
            f"📤 成功节点已输出："
            f"{OUTPUT_YAML}"
        )

    # ========================================================
    # 保存详细测试报告
    # ========================================================

    report = {

        "test_count": test_count,

        "success_count": len(
            passed_nodes
        ),

        "failed_count": (
            test_count -
            len(passed_nodes)
        ),

        "download_url": DOWNLOAD_URL,

        "required_bytes": DOWNLOAD_BYTES,

        "results": results,

        "passed_names": [
            node["name"]
            for node in passed_nodes
        ]
    }

    REPORT_JSON.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    # ========================================================
    # 最终统计
    # ========================================================

    log("=" * 60)

    log(
        f"🏁 本轮测试完成"
    )

    log(
        f"📦 实际测试：{test_count}"
    )

    log(
        f"✅ 真实下载成功："
        f"{len(passed_nodes)}"
    )

    log(
        f"❌ 真实下载失败："
        f"{test_count - len(passed_nodes)}"
    )

    log(
        f"📄 测试报告："
        f"{REPORT_JSON}"
    )

    if passed_nodes:

        log(
            f"📱 客户端测试文件："
            f"{OUTPUT_YAML}"
        )

    log(
        "📌 注意：GitHub 测试环境与手机客户端环境不同，"
        "本轮只负责筛掉明显无法实际传输数据的节点；"
        "最终可用性以客户端实测为准。"
    )


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    main()