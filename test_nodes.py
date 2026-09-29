#!/usr/bin/env python3
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


TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/generate_204",
]
TIMEOUT_MS = 5000
GROUP_TYPES = {
    "Selector", "URLTest", "Fallback", "Relay", "LoadBalance", "Compatible",
    "Pass", "ShadowTLS", "Reject", "Direct",
}
SKIP_NAMES = {"GLOBAL", "DIRECT", "REJECT", "PASS"}

# 需要过滤掉的广告、推广、返利、加群等敏感字眼关键词列表
AD_KEYWORDS = [
    "广告", "推介", "返利", "群", "加Q", "加V", "电报", "TG", "t.me", 
    "http", "www", ".com", ".net", "赞助", "机场", "买", "续费", "vps",
    "定制", "联系", "老板", "频道", "公告", "说明", "订阅"
]


def find_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def api_get(port, secret, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    req.add_header("Authorization", f"Bearer {secret}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def test_node(port, secret, name):
    q = urllib.parse.quote(name, safe="")
    delays = []
    for test_url in TEST_URLS:
        url_q = urllib.parse.quote(test_url, safe="")
        try:
            data = api_get(port, secret, f"/proxies/{q}/delay?timeout={TIMEOUT_MS}&url={url_q}")
            delay = data.get("delay")
            if delay is not None:
                delays.append(delay)
            else:
                return name, None
        except Exception:
            return name, None
    return name, int(sum(delays) / len(delays))


def is_ad_node(name):
    """检查节点名称是否包含广告或推广信息"""
    name_lower = str(name).lower()
    for kw in AD_KEYWORDS:
        if kw.lower() in name_lower:
            return True
    return False


def find_mihomo():
    for p in [os.environ.get("MIHOMO_BIN"), "/usr/local/bin/mihomo", "/tmp/mihomo", "mihomo"]:
        if p and os.path.isfile(p):
            return p
    raise SystemExit("[FAIL] 未找到 mihomo 内核(设置 MIHOMO_BIN 或安装到 /usr/local/bin/mihomo)")


def main():
    ap = argparse.ArgumentParser(description="mihomo 内核节点测试 + 去广告清洗")
    ap.add_argument("inputs", nargs="+", help="清洗后的各来源 clash.yaml")
    ap.add_argument("-o", "--output", required=True, help="输出 AIO clash.yaml")
    ap.add_argument("--concurrency", type=int, default=32)
    args = ap.parse_args()

    import yaml

    merged = {}
    for inp in args.inputs:
        with open(inp, encoding="utf-8") as f:
            d = yaml.safe_load(f)
        for p in d.get("proxies", []):
            if not isinstance(p, dict) or not p.get("name"):
                continue
            name = str(p["name"])
            # 排除说明节点以及带广告、推广字眼的节点
            if name.startswith("说明-") or is_ad_node(name):
                continue
            key = (p.get("type"), p.get("server"), p.get("port"))
            if key not in merged:
                merged[key] = p
    proxies = list(merged.values())
    print(f"[1/4] 合并并去除广告后待测节点: {len(proxies)}")
    if not proxies:
        raise SystemExit("[FAIL] 无任何有效节点可测")

    mihomo = find_mihomo()
    port = find_free_port()
    secret = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    test_cfg = {
        "mixed-port": port + 1,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{port}",
        "secret": secret,
        "proxies": proxies,
        "rules": ["MATCH,DIRECT"],
    }
    print(f"[2/4] 启动 mihomo (external-controller 127.0.0.1:{port})")
    with tempfile.TemporaryDirectory() as td:
        cfg_path = os.path.join(td, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(test_cfg, f, Dumper=yaml.SafeDumper, allow_unicode=False, sort_keys=False)
        proc = subprocess.Popen(
            [mihomo, "-d", td, "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            ready = False
            for _ in range(120):
                try:
                    api_get(port, secret, "/version")
                    ready = True
                    break
                except Exception:
                    if proc.poll() is not None:
                        raise SystemExit("[FAIL] mihomo 进程提前退出")
                    time.sleep(0.5)
            if not ready:
                raise SystemExit("[FAIL] mihomo API 未就绪")

            proxies_map = {}
            for _ in range(10):
                try:
                    proxies_map = api_get(port, secret, "/proxies")["proxies"]
                except Exception:
                    proxies_map = {}
                if proxies_map:
                    break
                time.sleep(0.5)
            names = [
                n for n, info in proxies_map.items()
                if n not in SKIP_NAMES and info.get("type") not in GROUP_TYPES
            ]
            print(f"[3/4] 开始测试 {len(names)} 个节点 -> 3个测试网址 (并发 {args.concurrency})")
            ok = {}
            done = 0
            total = len(names)
            interval = max(1, total // 50)
            with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                futs = {ex.submit(test_node, port, secret, n): n for n in names}
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
                raise SystemExit("[FAIL] 全部节点测试失败(检查网络/节点质量),不生成 AIO")

            good = [p for p in proxies if p["name"] in ok]
            good.sort(key=lambda p: ok[p["name"]])
            good_names = [p["name"] for p in good]
            
            aio = {
                "mixed-port": 7890,
                "allow-lan": False,
                "mode": "rule",
                "log-level": "info",
                "ipv6": False,
                "external-controller": "127.0.0.1:9090",
                "proxies": good,
                "proxy-groups": [
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
            
            # 使用临时文件安全写入，避免原地覆盖损坏文件
            out_dir = os.path.dirname(args.output) or "."
            fd, tmp_out = tempfile.mkstemp(dir=out_dir, suffix=".yaml")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    yaml.dump(aio, f, Dumper=yaml.SafeDumper, allow_unicode=False, default_flow_style=False, sort_keys=False)
                os.replace(tmp_out, args.output)
            except Exception:
                if os.path.exists(tmp_out):
                    os.remove(tmp_out)
                raise

            print(f"[4/4] 纯净版 AIO 已写入 {args.output}: {len(good)} 个可用节点")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
