#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, copy, glob, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, yaml

DEFAULT_INPUT_PATTERNS = ["*.yaml", "*.yml"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
BATCH_SIZE = 10000  # 每批测试的节点数，防止内存爆炸
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

def save_batch_yaml(good_nodes, batch_idx):
    out_dir = Path("generated/batches")
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / f"filtered_batch_{batch_idx:03d}.yaml"
    data = {
        "proxies": good_nodes,
        "proxy-groups": [{
            "name": "CF-Nest-Batch",
            "type": "select",
            "proxies": [p["name"] for p in good_nodes] or ["DIRECT"],
        }],
        "rules": ["MATCH,CF-Nest-Batch"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    log(f"💾 第 {batch_idx} 批次合格节点已单独保存到: {filepath}（共 {len(good_nodes)} 个）")
    return filepath

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def save_checkpoint(tested_fps):
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
        json.dump(list(tested_fps), f)

def build_final_aio(all_good_nodes, output_path):
    names = [node["name"] for node in all_good_nodes]
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
        "proxies": all_good_nodes,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": names},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000, "expected-status": "200-299", "tolerance": 50},
            {"name": "🔰 故障转移", "type": "fallback", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000, "expected-status": "200-299"},
            {"name": "🇨🇳 国内直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
            {"name": "🌍 国外代理", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择", "🔰 故障转移", "DIRECT"]}
        ],
        "rule-providers": {
            "ads": {
                "type": "http", "behavior": "domain", "format": "mrs",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs",
                "path": "./rules/ads.mrs", "interval": 86400
            }
        },
        "rules": ["RULE-SET,ads,REJECT", "DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,🌍 国外代理"]
    }
    temp_output = str(output_path) + ".tmp"
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
    log(f"📦 原始节点: {stats['raw']} | 去重后待测总数: {len(nodes)}")

    # 加载断点记录（已测过的节点指纹）
    tested_fps = load_checkpoint()
    log(f"🔄 断点续传加载完成：历史已测过 {len(tested_fps)} 个节点")

    # 过滤掉已经测过的节点
    remaining_nodes = [n for n in nodes if fingerprint(n) not in tested_fps]
    log(f"⏳ 本次实际需要测试的节点数: {len(remaining_nodes)}")

    if not remaining_nodes:
        log("🎉 所有节点都已经测试完毕！无需重复运行。")
        return 0

    all_good_nodes = []
    # 如果之前有生成过批次文件，可以把它们加载进来合并到最终输出中
    existing_batch_files = glob.glob("generated/batches/filtered_batch_*.yaml")
    for bfile in existing_batch_files:
        all_good_nodes.extend(load_yaml_file(bfile))

    # 按 BATCH_SIZE 分批循环
    total_batches = (len(remaining_nodes) + BATCH_SIZE - 1) // BATCH_SIZE
    batch_idx = 1
    # 根据已有的批次文件名自动推断当前批次编号
    if existing_batch_files:
        batch_idx = len(existing_batch_files) + 1

    for i in range(0, len(remaining_nodes), BATCH_SIZE):
        batch_slice = remaining_nodes[i:i + BATCH_SIZE]
        current_batch_num = batch_idx
        batch_idx += 1

        log(f"\n🚀 正在处理第 [{current_batch_num}/{total_batches + (current_batch_num - 1)}] 批次，本批节点数: {len(batch_slice)}")

        with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            write_test_config(batch_slice, config_path)
            log("🚀 启动 Mihomo 测试实例...")
            proc = subprocess.Popen([args.mihomo, "-d", temp_dir, "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                wait_api(proc)
                log("🧪 严格测试模式：6/6 全部通过才保留")
                results = []
                with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                    futures = [executor.submit(test_one, node) for node in batch_slice]
                    total_f = len(futures)
                    for index, future in enumerate(as_completed(futures), 1):
                        res = future.result()
                        results.append(res)
                        # 顺便记录该节点的指纹，无论成功失败均算已测过，避免死循环
                        tested_fps.add(fingerprint(res["node"]))
                        if res["ok"]:
                            log(f"✅ [{index}/{total_f}] {res['name']} | 6/6 | avg={res['avg']}ms")
                
                batch_good = [res["node"] for res in results if res["ok"]]
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try: proc.wait(timeout=5)
                    except subprocess.TimeoutExpired: proc.kill()

        # 每跑完一批，立刻保存断点状态（防止中途中断丢进度）
        save_checkpoint(tested_fps)

        # 每跑完一批，立刻把合格节点单独存为一个批次文件
        if batch_good:
            save_batch_yaml(batch_good, current_batch_num)
            all_good_nodes.extend(batch_good)
        else:
            log(f"⚠️ 第 {current_batch_num} 批次没有节点通过 6/6 测试。")

    if not all_good_nodes:
        log("⚠️️ 没有任何节点通过 6/6 测试，不生成最终 AIO 文件。")
        return 2

    # 生成最终总合集
    output = Path(args.output).resolve()
    temp_output = build_final_aio(all_good_nodes, output)
    try:
        os.replace(temp_output, output)
    except Exception as e:
        log(f"❌ 生成最终 AIO 失败：{e}")
        return 3

    log(f"🏁 全部批次测试完毕！\n✅ 最终聚合 YAML 已生成: {output}\n✅ 累计保留优质节点: {len(all_good_nodes)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
