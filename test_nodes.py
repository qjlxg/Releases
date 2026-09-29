#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 基于代理节点合并与真实下载测试 (GitHub Actions 专用抽样版)

import argparse
import json
import os
import random
import socket
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

# ============================================================
# 配置参数
# ============================================================

# 每次最多随机测试的节点数量（如 100 个）
TEST_COUNT = 100

# Cloudflare 实际下载测试接口
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1048576"  # 请求 1MB
# 每个节点实际下载接收到多少字节就算通过 (512 KB)
REQUIRED_BYTES = 512 * 1024 

CONNECT_TIMEOUT = 8
READ_TIMEOUT = 12

GROUP_TYPES = {
    "Selector", "URLTest", "Fallback", "Relay", "LoadBalance", "Compatible",
    "Pass", "ShadowTLS", "Reject", "Direct",
}
SKIP_NAMES = {"GLOBAL", "DIRECT", "REJECT", "PASS"}
AUTHOR = "wzmwayne & 老前辈定制"
REPO = "https://github.com/qjlxg/Releases"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/115.0.0.0 Safari/537.36"
    )
}


def find_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def api_get(port, secret, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def select_node(port, secret, name):
    """通过 Mihomo API 切换当前测速组的节点"""
    q_group = urllib.parse.quote("__DOWNLOAD_TEST__", safe="")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/proxies/{q_group}",
        data=json.dumps({"name": name}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT"
    )
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    with urllib.request.urlopen(req, timeout=5) as r:
        pass


def test_download_node(mixed_port, api_port, secret, name):
    """核心测试：通过本地 mihomo 代理下载文件，看能否真正读到数据"""
    try:
        # 1. 切换节点
        select_node(api_port, secret, name)
        time.sleep(0.2)  # 等待节点切换生效

        # 2. 构造带代理的请求
        proxy_handler = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{mixed_port}",
            "https": f"http://127.0.0.1:{mixed_port}",
        })
        opener = urllib.request.build_opener(proxy_handler)
        
        req = urllib.request.Request(DOWNLOAD_URL, headers=HEADERS)
        
        start_time = time.time()
        received = 0
        
        # 3. 打开连接并尝试读取一小部分数据
        with opener.open(req, timeout=CONNECT_TIMEOUT) as resp:
            if not (200 <= resp.status < 300):
                return name, None
            
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                received += len(chunk)
                if received >= REQUIRED_BYTES:
                    break
                if time.time() - start_time > READ_TIMEOUT:
                    break

        if received >= REQUIRED_BYTES:
            cost_ms = int((time.time() - start_time) * 1000)
            return name, cost_ms
        
        return name, None
    except Exception:
        return name, None


def fake_proxy(name):
    return {
        "name": name,
        "type": "trojan",
        "server": "127.0.0.1",
        "port": 443,
        "password": "dummy",
        "udp": True,
        "skip-cert-verify": True,
    }


def find_mihomo():
    for p in [os.environ.get("MIHOMO_BIN"), "./mihomo", "/usr/local/bin/mihomo", "/tmp/mihomo", "mihomo"]:
        if p and os.path.isfile(p):
            return p
    return "mihomo"


def main():
    ap = argparse.ArgumentParser(description="mihomo 节点真实下载测试 + AIO 合并")
    ap.add_argument("inputs", nargs="+", help="清洗后的各来源 clash.yaml")
    ap.add_argument("-o", "--output", required=True, help="输出 AIO clash.yaml")
    ap.add_argument("--concurrency", type=int, default=16, help="真实下载测试并发数")
    args = ap.parse_args()

    # 1. 读取并合并所有输入源的节点
    merged = {}
    for inp in args.inputs:
        if not os.path.exists(inp):
            print(f"[WARN] 输入文件不存在，跳过: {inp}")
            continue
        with open(inp, encoding="utf-8") as f:
            d = yaml.safe_load(f) or {}
        for p in d.get("proxies", []):
            if not isinstance(p, dict) or not p.get("name"):
                continue
            if str(p["name"]).startswith("说明-"):
                continue
            key = (p.get("type"), p.get("server"), p.get("port"))
            if key not in merged:
                merged[key] = p
                
    proxies = list(merged.values())
    print(f"[1/4] 合并后去重总节点数: {len(proxies)}")
    if not proxies:
        raise SystemExit("[FAIL] 无任何节点可测")

    # 2. 随机抽样限制数量（例如最多测 100 个）
    if len(proxies) > TEST_COUNT:
        proxies = random.sample(proxies, TEST_COUNT)
    print(f"🎯 本轮抽样测试节点数: {len(proxies)}")

    mihomo = find_mihomo()
    api_port = find_free_port()
    mixed_port = api_port + 1
    secret = "".join(random.choices(string.ascii_letters + string.digits, k=16))

    # 3. 构造用于真实下载测试的 Mihomo 配置
    test_cfg = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": secret,
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "__DOWNLOAD_TEST__",
                "type": "select",
                "proxies": [p["name"] for p in proxies]
            }
        ],
        "rules": ["MATCH,__DOWNLOAD_TEST__"],
    }
    
    print(f"[2/4] 启动 mihomo 内核进行真实下载测试 (控制端口: {api_port}, 混合代理端口: {mixed_port})")
    with tempfile.TemporaryDirectory() as td:
        cfg_path = os.path.join(td, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(test_cfg, f, Dumper=yaml.SafeDumper, allow_unicode=False, sort_keys=False)
        
        if os.path.isfile(mihomo):
            os.chmod(mihomo, 0o755)

        proc = subprocess.Popen(
            [mihomo, "-d", td, "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            ready = False
            for _ in range(120):
                try:
                    api_get(api_port, secret, "/version")
                    ready = True
                    break
                except Exception:
                    if proc.poll() is not None:
                        raise SystemExit("[FAIL] mihomo 进程提前退出")
                    time.sleep(0.5)
            if not ready:
                raise SystemExit("[FAIL] mihomo API 未就绪")

            # 安全获取测速组的节点名称列表
            names = []
            for _ in range(10):
                try:
                    group_info = api_get(api_port, secret, "/proxies/__DOWNLOAD_TEST__")
                    # group_info["all"] 是一个包含节点名字符串的列表
                    names = [n for n in group_info.get("all", []) if n not in SKIP_NAMES]
                except Exception:
                    names = []
                if names:
                    break
                time.sleep(0.5)

            if not names:
                raise SystemExit("[FAIL] Mihomo 中未解析到有效代理节点")

            print(f"[3/4] 开始对 {len(names)} 个抽样节点进行【真实下载测试】(并发 {args.concurrency})")
            ok = {}
            done = 0
            total = len(names)
            interval = max(1, total // 50)
            
            # 并发执行下载测试
            with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                futs = {ex.submit(test_download_node, mixed_port, api_port, secret, n): n for n in names}
                for fut in as_completed(futs):
                    name, cost = fut.result()
                    done += 1
                    if cost is not None:
                        ok[name] = cost
                    if done % interval == 0 or done == total:
                        pct = done * 100 // total
                        print(f"     进度 {done}/{total} ({pct}%) 可用 {len(ok)}", flush=True)
                        
            print(f"     真实下载通过节点: {len(ok)}")
            if not ok:
                raise SystemExit("[FAIL] 全部抽样节点真实下载测试失败，不生成 AIO")

            # 4. 排序并组装最终的 AIO 配置文件
            good = [p for p in proxies if p["name"] in ok]
            good.sort(key=lambda p: ok[p["name"]])
            good_names = [p["name"] for p in good]
            
            now = time.strftime("%Y-%m-%d %H:%M", time.gmtime(time.time() + 8 * 3600))
            fake_names = [
                f"说明-来源: AIO 精选(抽样测速 {len(names)} 个)",
                f"说明-测试: {len(ok)}/{len(names)} 节点通过真实下载测试",
                f"说明-更新时间: {now} (CST)",
                f"说明-作者: {AUTHOR}",
                f"说明-仓库: {REPO}",
            ]
            fakes = [fake_proxy(n) for n in fake_names]
            
            aio = {
                "mixed-port": 7890,
                "allow-lan": False,
                "mode": "rule",
                "log-level": "info",
                "ipv6": False,
                "external-controller": "127.0.0.1:9090",
                "proxies": fakes + good,
                "proxy-groups": [
                    {"name": "说明", "type": "select", "proxies": fake_names},
                    {"name": "🚀 节点选择", "type": "select", "proxies": good_names},
                    {
                        "name": "♻️ 自动选择",
                        "type": "url-test",
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": 300,
                        "proxies": good_names,
                    },
                ],
                "rules": ["MATCH,🚀 节点选择"],
            }
            
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                yaml.dump(aio, f, Dumper=yaml.SafeDumper, allow_unicode=False, default_flow_style=False, sort_keys=False)
            print(f"[4/4] AIO 已写入 {args.output}: {len(good)} 个可用节点")
            
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
