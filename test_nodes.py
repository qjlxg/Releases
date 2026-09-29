#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mihomo 节点延迟连通测试 + AIO 合并 (GitHub Actions 专用极速版)

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

# 每次随机抽样测试 200 个节点
TEST_COUNT = 2000

# 测试网址（通过 Mihomo API 测延迟，只要能通就代表可用）
TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
TIMEOUT_MS = 5000

GROUP_TYPES = {
    "Selector", "URLTest", "Fallback", "Relay", "LoadBalance", "Compatible",
    "Pass", "ShadowTLS", "Reject", "Direct",
}
SKIP_NAMES = {"GLOBAL", "DIRECT", "REJECT", "PASS"}
AUTHOR = "wzmwayne & 老前辈定制"
REPO = "https://github.com/qjlxg/Releases"


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


def test_node_delay(port, secret, name):
    """通过 Mihomo API 测试节点的延迟，确保多网址通过"""
    q_name = urllib.parse.quote(name, safe="")
    delays = []
    for test_url in TEST_URLS:
        url_q = urllib.parse.quote(test_url, safe="")
        try:
            data = api_get(port, secret, f"/proxies/{q_name}/delay?timeout={TIMEOUT_MS}&url={url_q}")
            delay = data.get("delay")
            if delay is not None:
                delays.append(delay)
            else:
                return name, None
        except Exception:
            return name, None
    return name, int(sum(delays) / len(delays))


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
    ap = argparse.ArgumentParser(description="mihomo 节点延迟测试 + AIO 合并")
    ap.add_argument("inputs", nargs="+", help="清洗后的各来源 clash.yaml")
    ap.add_argument("-o", "--output", required=True, help="输出 AIO clash.yaml")
    ap.add_argument("--concurrency", type=int, default=32, help="测速并发数")
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

    # 2. 随机抽样限制数量（抽样 200 个）
    if len(proxies) > TEST_COUNT:
        proxies = random.sample(proxies, TEST_COUNT)
    print(f"🎯 本轮随机抽样测试节点数: {len(proxies)}")

    mihomo = find_mihomo()
    api_port = find_free_port()
    secret = "".join(random.choices(string.ascii_letters + string.digits, k=16))

    # 3. 构造用于测速的 Mihomo 配置
    test_cfg = {
        "mixed-port": api_port + 1,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": secret,
        "proxies": proxies,
        "rules": ["MATCH,DIRECT"],
    }
    
    print(f"[2/4] 启动 mihomo 内核 (控制端口: {api_port})")
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

            # 获取所有待测节点名称
            proxies_map = {}
            for _ in range(10):
                try:
                    proxies_map = api_get(api_port, secret, "/proxies")["proxies"]
                except Exception:
                    proxies_map = {}
                if proxies_map:
                    break
                time.sleep(0.5)
                
            names = [
                n for n, info in proxies_map.items()
                if n not in SKIP_NAMES and info.get("type") not in GROUP_TYPES
            ]

            if not names:
                raise SystemExit("[FAIL] Mihomo 中未解析到有效代理节点")

            print(f"[3/4] 开始对 {len(names)} 个抽样节点进行测速 (并发 {args.concurrency})")
            ok = {}
            done = 0
            total = len(names)
            interval = max(1, total // 50)
            
            # 并发执行测速
            with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                futs = {ex.submit(test_node_delay, api_port, secret, n): n for n in names}
                for fut in as_completed(futs):
                    name, delay = fut.result()
                    done += 1
                    if delay is not None:
                        ok[name] = delay
                    if done % interval == 0 or done == total:
                        pct = done * 100 // total
                        print(f"     进度 {done}/{total} ({pct}%) 可用 {len(ok)}", flush=True)
                        
            print(f"     可用节点: {len(ok)}")
            if not ok:
                raise SystemExit("[FAIL] 全部抽样节点测试失败，不生成 AIO")

            # 4. 排序并组装最终的 AIO 配置文件
            good = [p for p in proxies if p["name"] in ok]
            good.sort(key=lambda p: ok[p["name"]])
            good_names = [p["name"] for p in good]
            
            now = time.strftime("%Y-%m-%d %H:%M", time.gmtime(time.time() + 8 * 3600))
            fake_names = [
                f"说明-来源: AIO 精选(抽样测速 {len(names)} 个)",
                f"说明-测试: {len(ok)}/{len(names)} 节点通过测试",
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
                        "url": TEST_URLS[0],
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
