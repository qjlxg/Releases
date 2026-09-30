#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, copy, glob, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, yaml

DEFAULT_INPUT_PATTERNS = ["*.yaml", "*.yml"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
VALID_POOL_FILE = ".valid_pool.json"
INVALID_POOL_FILE = ".invalid_pool.json"
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

def core_fingerprint(proxy):
    """🔑 提取核心配置特征（剔除 server, port, name），用于识别多 IP 套娃的同构配置"""
    obj = {k: v for k, v in proxy.items() if k not in ("name", "server", "port")}
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
    
    # 只要 6 个测试点全部成功通过，不论延迟高低，一律判定为可用（绝不因延迟误判）
    if len(delays) != 6:
        return {"name": name, "node": node, "ok": False, "stage": "最终检查", "label": "6/6 数量不足", "url": "", "error": f"实际成功 {len(delays)}/6", "delays": delays}
    
    avg_delay = round(sum(delays) / len(delays), 1)
    return {"name": name, "node": node, "ok": True, "avg": avg_delay, "delays": delays}

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

def load_pool(path):
    """加载白名单或黑名单历史库"""
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def save_pool(path, pool_set):
    """保存白名单或黑名单历史库"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(pool_set), f)

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

    tested_fps = load_checkpoint()
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)
    log(f"🔄 历史库加载完成：白名单(已验证) {len(valid_pool)} 个 | 黑名单(已失效) {len(invalid_pool)} 个")

    # 🔑 步骤一：增量过滤（黑白名单与去重拦截）
    untested_nodes = []
    white_inherited_nodes = []
    
    for node in nodes:
        fp = fingerprint(node)
        cfp = core_fingerprint(node)
        
        # 1. 命中黑名单：直接丢弃
        if cfp in invalid_pool:
            continue
        
        # 2. 命中白名单：老面孔免测，直接归入有效组
        if cfp in valid_pool:
            white_inherited_nodes.append(node)
            tested_fps.add(fp)
            continue
            
        # 3. 检查断点续传已测过的
        if fp in tested_fps:
            continue
            
        untested_nodes.append(node)

    log(f"⏳ 经黑白名单过滤后，本次需进行智能短路测速的全新节点数: {len(untested_nodes)} (白名单直接继承: {len(white_inherited_nodes)} 个)")

    if not untested_nodes and not white_inherited_nodes:
        log("🎉 所有节点都已经处理完毕！无需重复运行。")
        return 0

    # 🔑 步骤二：智能短路测速（针对全新节点按核心配置分组）
    # 将同构配置（套娃 IP）归类到同一个分组里：{ core_fp: [node1, node2, ...] }
    groups_by_core = {}
    for node in untested_nodes:
        cfp = core_fingerprint(node)
        groups_by_core.setdefault(cfp, []).append(node)

    batch_test_nodes = []
    # 策略：每个同构配置只挑选 1 个代表 IP 参加测速
    for cfp, group_nodes in groups_by_core.items():
        batch_test_nodes.append(group_nodes[0])

    new_tested_good_nodes = []
    if batch_test_nodes:
        total_batches = (len(batch_test_nodes) + BATCH_SIZE - 1) // BATCH_SIZE
        batch_idx = 1
        existing_batch_files = glob.glob("generated/batches/filtered_batch_*.yaml")
        if existing_batch_files:
            batch_idx = len(existing_batch_files) + 1

        for i in range(0, len(batch_test_nodes), BATCH_SIZE):
            batch_slice = batch_test_nodes[i:i + BATCH_SIZE]
            current_batch_num = batch_idx
            batch_idx += 1

            log(f"\n🚀 正在处理第 [{current_batch_num} 分区] 测速批次，代表节点数: {len(batch_slice)}")

            with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
                config_path = Path(temp_dir) / "config.yaml"
                write_test_config(batch_slice, config_path)
                log("🚀 启动 Mihomo 测试实例...")
                proc = subprocess.Popen([args.mihomo, "-d", temp_dir, "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                try:
                    wait_api(proc)
                    log("🧪 连通性测试（代表 IP 验证：6/6 全部通过即判定该配置有效）")
                    results = []
                    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                        futures = [executor.submit(test_one, node) for node in batch_slice]
                        total_f = len(futures)
                        for index, future in enumerate(as_completed(futures), 1):
                            res = future.result()
                            results.append(res)
                            tested_fps.add(fingerprint(res["node"]))
                            if res["ok"]:
                                log(f"✅ [{index}/{total_f}] {res['name']} | 6/6 | avg={res['avg']}ms")
                    
                    # 遍历测速结果，实现短路逻辑并全量保留套娃 IP
                    for res in results:
                        node = res["node"]
                        cfp = core_fingerprint(node)
                        if res["ok"]:
                            # 1. 测通：将该核心配置加入白名单
                            valid_pool.add(cfp)
                            # 2. 核心：把该配置对应的【全部套娃 IP 节点】全部捞出来放入合格列表！
                            if cfp in groups_by_core:
                                new_tested_good_nodes.extend(groups_by_core[cfp])
                        else:
                            # 不通：将该核心配置加入黑名单
                            invalid_pool.add(cfp)
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                        try: proc.wait(timeout=5)
                        except subprocess.TimeoutExpired: proc.kill()

            save_checkpoint(tested_fps)
            save_pool(VALID_POOL_FILE, valid_pool)
            save_pool(INVALID_POOL_FILE, invalid_pool)

    # 🔑 步骤三：结果合并输出
    all_good_nodes = []
    existing_batch_files = glob.glob("generated/batches/filtered_batch_*.yaml")
    for bfile in existing_batch_files:
        all_good_nodes.extend(load_yaml_file(bfile))

    # 合并白名单继承的老节点以及这次新测通的节点
    combined_new_nodes = white_inherited_nodes + new_tested_good_nodes
    if combined_new_nodes:
        # 重新按批次归档保存
        current_batch_num = len(existing_batch_files) + 1 if existing_batch_files else 1
        save_batch_yaml(combined_new_nodes, current_batch_num)
        all_good_nodes.extend(combined_new_nodes)

    if not all_good_nodes:
        log("⚠ 没有任何节点通过测试，不生成最终 AIO 文件。")
        return 2

    output = Path(args.output).resolve()
    temp_output = build_final_aio(all_good_nodes, output)
    try:
        os.replace(temp_output, output)
    except Exception as e:
        log(f"❌ 生成最终 AIO 失败：{e}")
        return 3

    log(f"🏁 全部流程完毕！\n✅ 最终聚合 YAML 已生成: {output}\n✅ 累计保留优质节点: {len(all_good_nodes)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
