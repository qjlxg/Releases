#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, copy, glob, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.parse, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, yaml

# 默认扫描目录（根据截图中的协议文件夹）
DEFAULT_INPUT_PATTERNS = ["hysteria2/**/*.txt", "ss/**/*.txt", "trojan/**/*.txt", "tuic/**/*.txt", "vless/**/*.txt", "vmess/**/*.txt", "*.yaml", "*.yml"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
VALID_POOL_FILE = ".valid_pool.json"
INVALID_POOL_FILE = ".invalid_pool.json"
BATCH_SIZE = 10000
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")
API_HOST, API_PORT, API_SECRET = "127.0.0.1", 9097, "test-only-secret"
TIMEOUT_MS, CONCURRENCY = 8000, 16

TEST_GROUPS = [
    ("基础连通性", [("Google gstatic", "https://www.gstatic.com/generate_204"), ("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"), ("Google 204", "https://www.google.com/generate_204")]),
    ("实际网站", [("Google 首页", "https://www.google.com/"), ("YouTube", "https://www.youtube.com/"), ("Telegram", "https://t.me/telegram/")])
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
    obj = {k: v for k, v in proxy.items() if k not in ("name", "server", "port")}
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def parse_share_link(line):
    """解析各类分享链接（hysteria2, vless, vmess, trojan, tuic, ss 等）转为 Mihomo 字典"""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    
    try:
        parsed = urllib.parse.urlparse(line)
        scheme = parsed.scheme.lower()
        
        # 1. Hysteria2
        if scheme == "hysteria2" or scheme == "hy2":
            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "name": urllib.parse.unquote(parsed.fragment) or f"Hy2-{server}",
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": password,
                "skip-cert-verify": True
            }
            if "sni" in query: node["sni"] = query["sni"][0]
            if "insecure" in query and query["insecure"][0] == "0": node["skip-cert-verify"] = False
            if "obfs" in query: node["obfs"] = query["obfs"][0]
            if "obfs-password" in query: node["obfs-password"] = query["obfs-password"][0]
            return node

        # 2. VLESS
        elif scheme == "vless":
            server = parsed.hostname
            port = parsed.port or 443
            uuid = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "name": urllib.parse.unquote(parsed.fragment) or f"Vless-{server}",
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "client-fingerprint": query.get("fp", ["chrome"])[0],
                "skip-cert-verify": True
            }
            if query.get("security", [""])[0] == "tls" or "encryption" in query:
                node["tls"] = True
                if "sni" in query: node["servername"] = query["sni"][0]
            if query.get("type", [""])[0] == "ws":
                node["network"] = "ws"
                ws_opts = {}
                if "path" in query: ws_opts["path"] = query["path"][0]
                if "host" in query: ws_opts["headers"] = {"Host": query["host"][0]}
                if ws_opts: node["ws-opts"] = ws_opts
            return node

        # 3. Trojan
        elif scheme == "trojan":
            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "name": urllib.parse.unquote(parsed.fragment) or f"Trojan-{server}",
                "type": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "skip-cert-verify": True
            }
            if "sni" in query: node["sni"] = query["sni"][0]
            return node

        # 4. Tuic
        elif scheme == "tuic":
            server = parsed.hostname
            port = parsed.port or 443
            uuid = parsed.username or ""
            password = parsed.password or ""
            query = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "name": urllib.parse.unquote(parsed.fragment) or f"Tuic-{server}",
                "type": "tuic",
                "server": server,
                "port": port,
                "uuid": uuid,
                "password": password,
                "skip-cert-verify": True
            }
            if "congestion_control" in query: node["congestion-control"] = query["congestion_control"][0]
            if "sni" in query: node["sni"] = query["sni"][0]
            return node

        # 5. 兼容读取标准的 YAML 文本或兼容段落
    except Exception:
        pass
    return None

def load_nodes_from_file(path):
    nodes = []
    path_str = str(path)
    if path_str.endswith((".yaml", ".yml")):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            p_list = data.get("proxies", [])
            if isinstance(p_list, list):
                nodes.extend(p_list)
    else:
        # 处理 TXT 分享链接文件以及 Base64 订阅格式
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
        
        # 尝试 Base64 解码（防备某些 txt 是整段订阅内容）
        try:
            if not content.startswith("http") and len(content) > 20:
                decoded = base64.b64decode(content + "==").decode("utf-8", errors="ignore")
                if "://" in decoded:
                    content = decoded
        except Exception:
            pass

        for line in content.splitlines():
            node = parse_share_link(line)
            if node:
                nodes.append(node)
    return nodes

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
            nodes = load_nodes_from_file(path)
        except Exception as e:
            log(f"❌ 文件读取失败: {path}: {e}")
            continue
        log(f"📄 {path}: 解析出 {len(nodes)} 个节点")
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
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def save_pool(path, pool_set):
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
        "rules": ["DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,🌍 国外代理"]
    }
    temp_output = str(output_path) + ".tmp"
    with open(temp_output, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return temp_output

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="*", help="TXT/YAML 文件或 glob")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--mihomo", default=MIHOMO_BIN)
    args = parser.parse_args()

    files = collect_files(args.inputs or DEFAULT_INPUT_PATTERNS)
    if not files: raise SystemExit("❌ 没有找到输入节点文件")
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"❌ 找不到 Mihomo: {args.mihomo}")

    nodes, stats = merge_nodes(files)
    if not nodes: raise SystemExit("❌ 没有可测试节点")
    log(f"📦 扫描文件数: {stats['files']} | 原始节点: {stats['raw']} | 去重后待测总数: {len(nodes)}")

    tested_fps = load_checkpoint()
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)

    untested_nodes = []
    white_inherited_nodes = []

    for node in nodes:
        fp = fingerprint(node)
        cfp = core_fingerprint(node)
        if cfp in invalid_pool: continue
        if cfp in valid_pool:
            white_inherited_nodes.append(node)
            tested_fps.add(fp)
            continue
        if fp in tested_fps: continue
        untested_nodes.append(node)

    log(f"⏳ 本次需测速全新节点: {len(untested_nodes)} (白名单直接继承: {len(white_inherited_nodes)} 个)")

    if not untested_nodes and not white_inherited_nodes:
        log("🎉 所有节点都已经处理完毕！")
        return 0

    groups_by_core = {}
    for node in untested_nodes:
        cfp = core_fingerprint(node)
        groups_by_core.setdefault(cfp, []).append(node)

    batch_test_nodes = [group_nodes[0] for group_nodes in groups_by_core.values()]
    new_tested_good_nodes = []

    try:
        if batch_test_nodes:
            batch_idx = 1
            existing_batch_files = glob.glob("generated/batches/filtered_batch_*.yaml")
            if existing_batch_files: batch_idx = len(existing_batch_files) + 1

            for i in range(0, len(batch_test_nodes), BATCH_SIZE):
                batch_slice = batch_test_nodes[i:i + BATCH_SIZE]
                current_batch_num = batch_idx
                batch_idx += 1

                with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
                    config_path = Path(temp_dir) / "config.yaml"
                    write_test_config(batch_slice, config_path)
                    proc = subprocess.Popen([args.mihomo, "-d", temp_dir, "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                    try:
                        wait_api(proc)
                        results = []
                        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                            futures = [executor.submit(test_one, node) for node in batch_slice]
                            for index, future in enumerate(as_completed(futures), 1):
                                res = future.result()
                                results.append(res)
                                tested_fps.add(fingerprint(res["node"]))
                                if res["ok"]:
                                    log(f"✅ [{index}/{len(futures)}] {res['name']} | avg={res['avg']}ms")

                        for res in results:
                            node = res["node"]
                            cfp = core_fingerprint(node)
                            if res["ok"]:
                                valid_pool.add(cfp)
                                if cfp in groups_by_core:
                                    new_tested_good_nodes.extend(groups_by_core[cfp])
                            else:
                                invalid_pool.add(cfp)
                    finally:
                        if proc.poll() is None:
                            proc.terminate()
                            try: proc.wait(timeout=5)
                            except subprocess.TimeoutExpired: proc.kill()

                save_checkpoint(tested_fps)
                save_pool(VALID_POOL_FILE, valid_pool)
                save_pool(INVALID_POOL_FILE, invalid_pool)
    finally:
        save_checkpoint(tested_fps)
        save_pool(VALID_POOL_FILE, valid_pool)
        save_pool(INVALID_POOL_FILE, invalid_pool)

    all_good_nodes = []
    existing_batch_files = glob.glob("generated/batches/filtered_batch_*.yaml")
    for bfile in existing_batch_files:
        all_good_nodes.extend(load_nodes_from_file(bfile))

    combined_new_nodes = white_inherited_nodes + new_tested_good_nodes
    if combined_new_nodes:
        current_batch_num = len(existing_batch_files) + 1 if existing_batch_files else 1
        save_batch_yaml(combined_new_nodes, current_batch_num)
        all_good_nodes.extend(combined_new_nodes)

    if not all_good_nodes:
        log("⚠ 没有任何节点通过测试。")
        return 2

    output = Path(args.output).resolve()
    temp_output = build_final_aio(all_good_nodes, output)
    os.replace(temp_output, output)
    log(f"🏁 最终聚合 YAML 已生成推送到根目录: {output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
