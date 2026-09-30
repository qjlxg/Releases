#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, copy, glob, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, yaml

DEFAULT_INPUT_PATTERNS = ["*.yaml", "*.yml"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")
API_HOST, API_PORT, API_SECRET = "127.0.0.1", 9097, "test-only-secret"
TIMEOUT_MS, CONCURRENCY = 8000, 16

TEST_GROUPS = [
    ("基础连通性", [("Google gstatic", "https://www.gstatic.com/generate_204"), ("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"), ("Google 204", "https://www.google.com/generate_204")]),
    ("实际网站", [("Google 首页", "https://www.google.com/"), ("YouTube", "https://www.youtube.com/"), ("GitHub", "https://t.me/telegram/")])
]
ALL_TESTS = [(stage, label, url) for stage, tests in TEST_GROUPS for label, url in tests]

def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S]"), msg, flush=True)

def safe_name(name):
    return str(name or "node").strip() or "node"

def fingerprint(proxy):
    obj = {k: v for k, v in proxy.items() if k != "name"}
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def load_yaml_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict): return []
    proxies = data.get("proxies", [])
    return proxies if isinstance(proxies, list) else []

def collect_files(inputs):
    files = []
    for item in inputs:
        matches = glob.glob(item, recursive=True)
        if matches: files.extend(matches)
        elif os.path.isfile(item): files.append(item)
    seen, result = set(), []
    for path in files:
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            result.append(path)
    return sorted(result)

def merge_nodes(files):
    result, seen_fp, name_count = [], set(), {}
    stats = {"files": 0, "raw": 0, "invalid": 0, "duplicate": 0, "kept": 0}
    for path in files:
        stats["files"] += 1
        try:
            nodes = load_yaml_file(path)
        except Exception as e:
            log(f"❌ YAML 读取失败: {path}: {e}")
            continue
        log(f"📄 {path}: {len(nodes)} 个节点")
        for node in nodes:
            stats["raw"] += 1
            if not isinstance(node, dict) or not node.get("type") or not node.get("server") or not node.get("port"):
                stats["invalid"] += 1
                continue
            node = copy.deepcopy(node)
            fp = fingerprint(node)
            if fp in seen_fp:
                stats["duplicate"] += 1
                continue
            seen_fp.add(fp)
            base = safe_name(node.get("name"))
            count = name_count.get(base, 0)
            if count:
                new_name = f"{base} #{count + 1}"
                while new_name in name_count:
                    count += 1
                    new_name = f"{base} #{count + 1}"
                node["name"] = new_name
                name_count[new_name] = 1
                name_count[base] = count + 1
            else:
                node["name"] = base
                name_count[base] = 1
            result.append(node)
            stats["kept"] += 1
    return result, stats

def write_test_config(nodes, path):
    config = {
        "mixed-port": 7898, "allow-lan": False, "mode": "rule", "log-level": "error",
        "ipv6": False, "unified-delay": True, "tcp-concurrent": True,
        "external-controller": f"{API_HOST}:{API_PORT}", "secret": API_SECRET, "proxies": nodes
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

def wait_api(proc):
    url = f"http://{API_HOST}:{API_PORT}/version"
    end_time = time.time() + 20
    while time.time() < end_time:
        if proc.poll() is not None:
            raise RuntimeError(f"Mihomo 提前退出，returncode={proc.returncode}")
        try:
            if requests.get(url, headers={"Authorization": f"Bearer {API_SECRET}"}, timeout=1.5).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(0.25)
    raise TimeoutError("等待 Mihomo API 超时")

def api_delay(name, url):
    encoded_name = urllib.parse.quote(name, safe="")
    api_url = f"http://{API_HOST}:{API_PORT}/proxies/{encoded_name}/delay"
    params = {"timeout": TIMEOUT_MS, "url": url, "expected": "200-299"}
    response = requests.get(api_url, params=params, headers={"Authorization": f"Bearer {API_SECRET}"}, timeout=TIMEOUT_MS / 1000 + 5)
    response.raise_for_status()
    data = response.json()
    delay = data.get("delay")
    if not isinstance(delay, int) or delay <= 0:
        raise RuntimeError(f"无效 delay: {data}")
    return delay

def test_one(node):
    name, delays = node["name"], []
    for stage, tests in TEST_GROUPS:
        for label, url in tests:
            try:
                delays.append(api_delay(name, url))
            except Exception as e:
                return {"name": name, "node": node, "ok": False, "stage": stage, "label": label, "url": url, "error": str(e), "delays": delays}
    if len(delays) != 6:
        return {"name": name, "node": node, "ok": False, "stage": "最终检查", "label": "6/6 数量不足", "url": "", "error": f"实际成功 {len(delays)}/6", "delays": delays}
    return {"name": name, "node": node, "ok": True, "avg": round(sum(delays) / len(delays), 1), "delays": delays}

def validate_final_config(path, mihomo_bin):
    with tempfile.TemporaryDirectory(prefix="mihomo_validate_") as temp_dir:
        test_config = Path(temp_dir) / "config.yaml"
        shutil.copy2(path, test_config)
        proc = subprocess.Popen([mihomo_bin, "-d", temp_dir, "-f", str(test_config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(2.5)
            if proc.poll() is not None:
                _, stderr = proc.communicate(timeout=2)
                raise RuntimeError((stderr or "mihomo exited").strip()[-4000:])
        finally:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: proc.kill()
        return True

def build_output(good, output):
    names = [node["name"] for node in good]
    config = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info",
        "ipv6": False, "unified-delay": True, "tcp-concurrent": True, "find-process-mode": "strict",
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True, "ipv6": False, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["223.5.5.5", "119.29.29.29", "https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "fallback": ["1.1.1.1", "8.8.8.8"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN", "geosite": ["gfw"]}
        },
        "proxies": good,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": names},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000, "expected-status": "200-299", "tolerance": 50},
            {"name": "🔰 故障转移", "type": "fallback", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000, "expected-status": "200-299"},
            {"name": "🇨🇳 国内直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
            {"name": "🌍 国外代理", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择", "🔰 故障转移", "DIRECT"]}
        ],
        "rule-providers": {
            "广告": {
                "type": "http", "behavior": "domain", "format": "mrs",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs",
                "path": "./rules/ads.mrs", "interval": 86400
            }
        },
        "rules": ["RULE-SET,广告,REJECT", "DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,🌍 国外代理"]
    }
    temp_output = str(output) + ".tmp"
    with open(temp_output, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return temp_output

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="*", help="YAML 文件或 glob")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--mihomo", default=MIHOMO_BIN)
    args = parser.parse_args()

    files = collect_files(args.inputs or DEFAULT_INPUT_PATTERNS)
    if not files: raise SystemExit("❌ 没有找到输入 YAML")
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"❌ 找不到 Mihomo: {args.mihomo}")

    nodes, stats = merge_nodes(files)
    if not nodes: raise SystemExit("❌ 没有可测试节点")
    log(f"📦 原始节点: {stats['raw']} | 无效: {stats['invalid']} | 完全重复: {stats['duplicate']} | 待测: {len(nodes)}")

    with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        write_test_config(nodes, config_path)
        log("🚀 启动 Mihomo 测试实例...")
        proc = subprocess.Popen([args.mihomo, "-d", temp_dir, "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            wait_api(proc)
            log("🧪 严格测试模式：6/6 全部通过才保留")
            results = []
            with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                futures = [executor.submit(test_one, node) for node in nodes]
                total = len(futures)
                for index, future in enumerate(as_completed(futures), 1):
                    res = future.result()
                    results.append(res)
                    if res["ok"]:
                        log(f"✅ [{index}/{total}] {res['name']} | 6/6 | avg={res['avg']}ms")
            good = [res["node"] for res in results if res["ok"]]
        finally:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill()

    failed = [res for res in results if not res["ok"]]
    log(f"🏁 测试结束: {len(good)}/{len(nodes)} 个节点通过 6/6")
    if failed:
        counter = Counter((res["stage"], res["label"]) for res in failed)
        log("📊 淘汰原因统计:")
        for (stage, label), count in counter.most_common():
            log(f"    ❌ {count} 个: {stage} / {label}")

    if not good:
        log("⚠️ 没有任何节点通过 6/6。\n⚠️ 不生成、不覆盖最终 YAML。")
        return 2

    output = Path(args.output).resolve()
    temp_output = build_output(good, output)
    try:
        log("🔍 正在进行最终 Mihomo 配置启动校验...")
        validate_final_config(temp_output, args.mihomo)
        os.replace(temp_output, output)
    except Exception as e:
        try: os.remove(temp_output)
        except OSError: pass
        log(f"❌ 最终配置校验失败：{e}\n❌ 不覆盖原来的输出文件。")
        return 3

    log(f"✅ 最终 YAML 已生成: {output}\n✅ 最终保留节点: {len(good)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
