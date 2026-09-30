import argparse, copy, glob, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.parse, base64, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, yaml

DEFAULT_INPUT_PATTERNS = ["nodes"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
VALID_POOL_FILE = ".valid_pool.json"
INVALID_POOL_FILE = ".invalid_pool.json"
BATCH_SIZE = 300  # 锁死在 300-400 之间，保护 Mihomo 内存
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "mihomo")
API_HOST, API_PORT, API_SECRET = "127.0.0.1", 9097, "test-only-secret"
TIMEOUT_MS, CONCURRENCY = 3000, 32

TEST_GROUPS = [
    ("基础连通性", [("Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"), ("Google 204", "https://www.google.com/generate_204")]),
    ("实际网站", [("Google 首页", "https://www.google.com/"), ("Telegram", "https://t.me/telegram/")])
]

def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S]"), msg, flush=True)

def safe_name(name):
    return str(name or "node").strip() or "node"

def fingerprint(proxy):
    # 严格使用完整指纹，禁止剔除 server/port 产生模板连坐误判
    obj = {k: v for k, v in proxy.items() if k != "name"}
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def validate_node_by_official_standard(node):
    """
    严格按照各大协议官方标准对节点进行硬性质检：
    不符合标准的直接返回 False，在入库第一关被拦截，绝不污染后续测试。
    """
    if not isinstance(node, dict):
        return False
    
    ptype = str(node.get("type", "")).lower().strip()
    server = str(node.get("server", "")).strip()
    port = node.get("port")

    # 1. 基础公共硬性指标
    if not ptype or not server:
        return False
    
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            return False
    except (TypeError, ValueError):
        return False

    # 2. 协议专属官方标准校验
    if ptype == "ss":
        if not node.get("cipher") or not node.get("password"):
            return False
    elif ptype == "vmess":
        if not node.get("uuid"):
            return False
    elif ptype == "vless":
        if not node.get("uuid"):
            return False
    elif ptype == "trojan":
        if not node.get("password"):
            return False
    elif ptype in ("hysteria2", "hy2"):
        if not node.get("password"):
            return False
    elif ptype == "tuic":
        if not node.get("uuid") and not node.get("password"):
            return False
    else:
        # 遇到未知或冷门协议，直接按标准不通过处理，避免未知风险
        return False

    return True

def parse_share_link(line):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None

    node = None
    try:
        if line.startswith("ss://"):
            main_part = line[5:]
            fragment = ""
            if "#" in main_part:
                main_part, fragment = main_part.split("#", 1)
                fragment = urllib.parse.unquote(fragment)

            if "@" not in main_part:
                missing_padding = len(main_part) % 4
                if missing_padding:
                    main_part += "=" * (4 - missing_padding)
                try:
                    decoded = base64.b64decode(main_part).decode("utf-8", errors="ignore")
                    if "@" in decoded:
                        main_part = decoded
                except Exception:
                    pass

            if "@" in main_part:
                userinfo, hostport = main_part.rsplit("@", 1)
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                else:
                    try:
                        missing_padding = len(userinfo) % 4
                        if missing_padding:
                            userinfo += "=" * (4 - missing_padding)
                        decoded_user = base64.b64decode(userinfo).decode("utf-8", errors="ignore")
                        method, password = decoded_user.split(":", 1)
                    except Exception:
                        return None

                if ":" in hostport:
                    server, port_str = hostport.rsplit(":", 1)
                    port = int(port_str)
                else:
                    return None

                node = {
                    "name": fragment or f"SS-{server}",
                    "type": "ss",
                    "server": server,
                    "port": port,
                    "cipher": method,
                    "password": password
                }

        elif line.startswith("vmess://"):
            raw_b64 = line[8:]
            missing_padding = len(raw_b64) % 4
            if missing_padding:
                raw_b64 += "=" * (4 - missing_padding)
            decoded_bytes = base64.b64decode(raw_b64)
            config = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))

            node = {
                "name": config.get("ps") or f"Vmess-{config.get('add', 'node')}",
                "type": "vmess",
                "server": config.get("add"),
                "port": int(config.get("port", 443)),
                "uuid": config.get("id"),
                "alterId": int(config.get("aid", 0)),
                "cipher": "auto",
                "skip-cert-verify": True
            }
            net = config.get("net", "tcp")
            if net: node["network"] = net
            if config.get("tls") == "tls" or config.get("tls") == "1":
                node["tls"] = True
                if config.get("sni"): node["servername"] = config["sni"]
            if net == "ws":
                ws_opts = {}
                if config.get("path"): ws_opts["path"] = config["path"]
                if config.get("host"): ws_opts["headers"] = {"Host": config["host"]}
                if ws_opts: node["ws-opts"] = ws_opts

        else:
            parsed = urllib.parse.urlparse(line)
            scheme = parsed.scheme.lower()

            if scheme in ("hysteria2", "hy2"):
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
    except Exception:
        return None

    # 必须通过官方硬性标准检验
    if node and validate_node_by_official_standard(node):
        return node
    return None

def stream_load_nodes_from_file(path, invalid_pool, valid_pool, tested_fps, seen_fps):
    path_str = str(path)
    if path_str.endswith((".yaml", ".yml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                for node in data.get("proxies", []):
                    if validate_node_by_official_standard(node):
                        yield from process_single_node(node, invalid_pool, valid_pool, tested_fps, seen_fps)
        except Exception as e:
            log(f"❌ YAML 文件读取失败: {path}: {e}")
    else:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    node = parse_share_link(line)
                    if node:
                        yield from process_single_node(node, invalid_pool, valid_pool, tested_fps, seen_fps)
        except Exception as e:
            log(f"❌ 文本文件读取失败: {path}: {e}")

def process_single_node(node, invalid_pool, valid_pool, tested_fps, seen_fps):
    fp = fingerprint(node)

    if fp in invalid_pool:
        return
    if fp in seen_fps:
        return
    seen_fps.add(fp)

    if fp in valid_pool:
        node["_inherited_valid"] = True
        yield node
        return

    if fp in tested_fps:
        return

    yield node

def collect_files(inputs, output_filename="filtered_nodes.yaml", skip_filename="gem.yaml"):
    files = set()
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for ext in ("*.txt", "*.yaml", "*.yml"):
                for f in p.rglob(ext):
                    if f.name != output_filename and f.name != skip_filename:
                        files.add(f.resolve())
        else:
            path_obj = Path(item)
            if path_obj.name != output_filename and path_obj.name != skip_filename:
                files.add(path_obj.resolve())
    return sorted([str(f) for f in files])

def quick_tcp_check(server, port, timeout=0.6):
    try:
        with socket.create_connection((str(server), int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps):
    seen_fps = set()
    stats = {"files": len(files), "raw_valid": 0, "tcp_filtered": 0, "inherited": 0, "passed_tcp": 0}

    def check_node_tcp(node):
        if node.get("_inherited_valid"):
            return node
        protocol = node.get("type", "").lower()
        if protocol in ("hysteria2", "hy2", "tuic", "warp"):
            return node
        if quick_tcp_check(node.get("server"), node.get("port")):
            return node
        return None

    chunk_size = 5000
    current_chunk = []

    for path in files:
        log(f"📄 正在扫描源文件: {path}")
        for node in stream_load_nodes_from_file(path, invalid_pool, valid_pool, tested_fps, seen_fps):
            stats["raw_valid"] += 1
            if node.get("_inherited_valid"):
                stats["inherited"] += 1
                stats["passed_tcp"] += 1
                yield node
                continue

            current_chunk.append(node)
            if len(current_chunk) >= chunk_size:
                yield from flush_tcp_chunk(current_chunk, check_node_tcp, stats)
                current_chunk = []

    if current_chunk:
        yield from flush_tcp_chunk(current_chunk, check_node_tcp, stats)

    log(f"\n==================== 📊 物料盘点与官方标准质检报表 ====================")
    log(f"📁 扫描输入源文件总数: {stats['files']} 个")
    log(f"🔍 通过官方标准质检的合规节点: {stats['raw_valid']} 条")
    log(f"♻️ 白名单直接继承命中: {stats['inherited']} 条")
    log(f"⚡ TCP 离线预检剔除: {stats['tcp_filtered']} 条")
    log(f"🎯 最终进入 Mihomo 测速池总数: {stats['passed_tcp']} 条")
    expected_batches = (stats['passed_tcp'] + BATCH_SIZE - 1) // BATCH_SIZE if stats['passed_tcp'] > 0 else 0
    log(f"📦 按每批 {BATCH_SIZE} 条计算，预计总测试批次数: {expected_batches} 批")
    log(f"=================================================================\n")

def flush_tcp_chunk(chunk, check_func, stats):
    passed = []
    with ThreadPoolExecutor(max_workers=128) as executor:
        futures = {executor.submit(check_func, node): node for node in chunk}
        for future in as_completed(futures):
            res = future.result()
            if res:
                passed.append(res)
                stats["passed_tcp"] += 1
            else:
                stats["tcp_filtered"] += 1
    for p in passed:
        yield p

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
    end_time = time.time() + 25
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
    response = requests.get(api_url, params=params, headers={"Authorization": f"Bearer {API_SECRET}"}, timeout=TIMEOUT_MS / 1000 + 4)
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
                return {"name": name, "node": node, "ok": False, "error": str(e)}

    expected_total_tests = sum(len(tests) for _, tests in TEST_GROUPS)
    if len(delays) != expected_total_tests:
        return {"name": name, "node": node, "ok": False, "error": "测试数量不全"}

    avg_delay = round(sum(delays) / len(delays), 1)
    return {"name": name, "node": node, "ok": True, "avg": avg_delay}

def save_batch_yaml(good_nodes, batch_idx):
    out_dir = Path("generated/batches")
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / f"filtered_batch_{batch_idx:03d}.yaml"
    data = {
        "proxies": good_nodes,
        "proxy-groups": [{"name": "CF-Nest-Batch", "type": "select", "proxies": [p["name"] for p in good_nodes] or ["DIRECT"]}],
        "rules": ["MATCH,CF-Nest-Batch"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    log(f"💾 合格批次已保存: {filepath} (共留存 {len(good_nodes)} 个优质节点)")
    return filepath

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

def build_final_aio_streamed(output_path):
    output = Path(output_path).resolve()
    temp_output = str(output) + ".tmp"
    
    log("📦 正在以流式方式合并所有批次生成最终 AIO 配置...")
    
    all_names = []
    for bfile in sorted(glob.glob("generated/batches/filtered_batch_*.yaml")):
        with open(bfile, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                for p in data.get("proxies", []):
                    if "name" in p:
                        all_names.append(p["name"])

    config_skeleton = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info",
        "ipv6": False, "unified-delay": True, "tcp-concurrent": True,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": all_names if all_names else ["DIRECT"]},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": all_names if all_names else ["DIRECT"], "url": "https://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000},
            {"name": "🇨🇳 国内直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
            {"name": "🌍 国外代理", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择", "DIRECT"]}
        ],
        "rules": ["DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,🌍 国外代理"]
    }

    with open(temp_output, "w", encoding="utf-8") as out_f:
        header_data = {k: v for k, v in config_skeleton.items() if k != "proxies"}
        yaml.safe_dump(header_data, out_f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
        out_f.write("proxies:\n")
        total_proxies = 0
        for bfile in sorted(glob.glob("generated/batches/filtered_batch_*.yaml")):
            with open(bfile, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    for p in data.get("proxies", []):
                        p_str = yaml.safe_dump([p], allow_unicode=True, sort_keys=False, default_flow_style=False)
                        for line in p_str.strip().splitlines():
                            out_f.write(f"  {line}\n")
                        total_proxies += 1

    os.replace(temp_output, output)
    log(f"🏁 最终聚合 YAML 已生成: {output}\n✅ 累计保留优质节点总数: {total_proxies}")
    return total_proxies

def process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx):
    good_nodes = []
    
    # 局部名称去重
    batch_name_count = {}
    for node in batch_slice:
        base = safe_name(node.get("name"))
        count = batch_name_count.get(base, 0)
        if count:
            new_name = f"{base} #{count + 1}"
            while new_name in batch_name_count:
                count += 1
                new_name = f"{base} #{count + 1}"
            node["name"] = new_name
            batch_name_count[new_name] = 1
            batch_name_count[base] = count + 1
        else:
            node["name"] = base
            batch_name_count[base] = 1

    log(f"\n🚀 [第 {batch_idx} 批] 启动 Mihomo 实例测试，当前批次节点数: {len(batch_slice)}")
    with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir:
        config_path = Path(temp_dir) / "config.yaml"
        try:
            write_test_config(batch_slice, config_path)
            proc = subprocess.Popen([args.mihomo, "-d", temp_dir, "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            wait_api(proc)
            with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
                futures = [executor.submit(test_one, node) for node in batch_slice]
                for index, future in enumerate(as_completed(futures), 1):
                    res = future.result()
                    node = res["node"]
                    node_fp = fingerprint(node)
                    
                    tested_fps.add(node_fp)

                    if res["ok"]:
                        log(f"✅ [{index}/{len(futures)}] {res['name']} | avg={res['avg']}ms")
                        valid_pool.add(node_fp)
                        good_nodes.append(node)
                    else:
                        invalid_pool.add(node_fp)
        except Exception as e:
            log(f"❌ [第 {batch_idx} 批] Mihomo 运行异常崩溃或配置解析失败: {e}")
            log(f"🛡️ 已启用容错保护：自动将当前批次全部标记为无效并安全跳过，防止流水线中断。")
            for node in batch_slice:
                invalid_pool.add(fingerprint(node))
            good_nodes = []
        finally:
            if 'proc' in locals() and proc and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill()

    save_pool(CHECKPOINT_FILE, tested_fps)
    save_pool(VALID_POOL_FILE, valid_pool)
    save_pool(INVALID_POOL_FILE, invalid_pool)
    return good_nodes

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="*", help="目录或文件路径")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    parser.add_argument("-c", "--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--mihomo", default=MIHOMO_BIN)
    args = parser.parse_args()

    files = collect_files(args.inputs or DEFAULT_INPUT_PATTERNS, args.output, "gem.yaml")
    if not files: raise SystemExit("❌ 没有找到输入节点文件")
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"❌ 找不到 Mihomo: {args.mihomo}")

    tested_fps = load_pool(CHECKPOINT_FILE)
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)

    log("🚀 启动 V2 终极流式漏斗清洗引擎（官方标准质检 + 统计看板 + 防崩版）...")

    batch_slice = []
    batch_idx = len(glob.glob("generated/batches/filtered_batch_*.yaml")) + 1

    try:
        for node in stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps):
            node = copy.deepcopy(node)
            node.pop("_inherited_valid", None)

            batch_slice.append(node)

            if len(batch_slice) >= BATCH_SIZE:
                processed_good = process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx)
                if processed_good:
                    save_batch_yaml(processed_good, batch_idx)
                batch_idx += 1
                batch_slice = []

        if batch_slice:
            processed_good = process_batch_with_mihomo(batch_slice, args, tested_fps, valid_pool, invalid_pool, batch_idx)
            if processed_good:
                save_batch_yaml(processed_good, batch_idx)
            batch_idx += 1

    finally:
        save_pool(CHECKPOINT_FILE, tested_fps)
        save_pool(VALID_POOL_FILE, valid_pool)
        save_pool(INVALID_POOL_FILE, invalid_pool)

    batches = glob.glob("generated/batches/filtered_batch_*.yaml")
    if not batches:
        log("⚠ 没有任何节点通过测试。")
        return 2

    total_good = build_final_aio_streamed(args.output)
    if total_good == 0:
        log("⚠ 没有任何节点通过测试。")
        return 2

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
