import argparse, copy, glob, hashlib, json, os, shutil, subprocess, tempfile, time, urllib.parse, base64, socket, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, yaml

DEFAULT_INPUT_PATTERNS = ["nodes"]
DEFAULT_OUTPUT = "filtered_nodes.yaml"
CHECKPOINT_FILE = ".tested_progress.json"
VALID_POOL_FILE = ".valid_pool.json"
INVALID_POOL_FILE = ".invalid_pool.json"
BATCH_SIZE = 300
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
    obj = {k: v for k, v in proxy.items() if k != "name"}
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def is_valid_uuid(val):
    if not isinstance(val, str):
        return False
    uuid_pattern = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    return bool(uuid_pattern.match(val.strip()))

def validate_node_by_official_standard(node):
    """
    严格按照官方标准对节点参数进行合规校验，不达标视为废节点直接剔除
    """
    if not isinstance(node, dict):
        return False
    ptype = str(node.get("type", "")).lower().strip()
    server = str(node.get("server", "")).strip()
    port = node.get("port")

    if not ptype or not server or server.lower() in ("none", "null", "127.0.0.1", "localhost", "0.0.0.0"):
        return False
    
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            return False
    except (TypeError, ValueError):
        return False

    if ptype == "ss":
        if not node.get("cipher") or not node.get("password"): 
            return False
    elif ptype == "ssr":
        if not node.get("server") or not node.get("port") or not node.get("password") or not node.get("cipher") or not node.get("protocol") or not node.get("obfs"):
            return False
    elif ptype in ("vmess", "vless"):
        uuid_val = str(node.get("uuid", ""))
        if not is_valid_uuid(uuid_val): 
            return False
    elif ptype == "trojan":
        if not node.get("password") or len(str(node.get("password"))) < 1: 
            return False
    elif ptype in ("hysteria2", "hy2"):
        if not node.get("password") or len(str(node.get("password"))) < 1: 
            return False
    elif ptype == "tuic":
        if not node.get("uuid") and not node.get("password"): 
            return False
    elif ptype == "snell":
        if not node.get("preshared-key") and not node.get("psk"): 
            return False
    else:
        return False
    return True

def decode_base64_safe(data):
    data = data.strip()
    for padding in ("", "=", "==", "==="):
        try:
            padded = data + padding
            return base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            continue
    return ""

def parse_share_link(line):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    node = None
    try:
        # 1. Shadowsocks (ss://)
        if line.startswith("ss://"):
            main_part = line[5:]
            fragment = ""
            if "#" in main_part:
                main_part, fragment = main_part.split("#", 1)
                fragment = urllib.parse.unquote(fragment)
            
            if "@" not in main_part:
                decoded = decode_base64_safe(main_part)
                if "@" in decoded: 
                    main_part = decoded

            if "@" in main_part:
                userinfo, hostport = main_part.rsplit("@", 1)
                method, password = "", ""
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                else:
                    dec_user = decode_base64_safe(userinfo)
                    if ":" in dec_user:
                        method, password = dec_user.split(":", 1)
                
                if ":" in hostport:
                    server, port_str = hostport.rsplit(":", 1)
                    if server and port_str.isdigit():
                        node = {
                            "name": fragment or f"SS-{server}", "type": "ss", 
                            "server": server.strip("[]"), "port": int(port_str), 
                            "cipher": method.strip(), "password": password.strip()
                        }

        # 2. ShadowsocksR (ssr://)
        elif line.startswith("ssr://"):
            main_part = line[6:]
            decoded = decode_base64_safe(main_part)
            if ":" in decoded and "/" in decoded:
                # 格式: host:port:protocol:method:obfs:password_base64/?params
                parts = decoded.split("/?", 1)
                base_info = parts[0]
                query_str = parts[1] if len(parts) > 1 else ""
                
                sub_parts = base_info.split(":")
                if len(sub_parts) >= 6:
                    server = sub_parts[0]
                    port = int(sub_parts[1])
                    protocol = sub_parts[2]
                    method = sub_parts[3]
                    obfs = sub_parts[4]
                    password = decode_base64_safe(sub_parts[5])
                    
                    query = urllib.parse.parse_qs(query_str)
                    node_name = f"SSR-{server}"
                    if "remarks" in query:
                        node_name = decode_base64_safe(query["remarks"][0]) or node_name

                    node = {
                        "name": urllib.parse.unquote(node_name), "type": "ssr",
                        "server": server.strip("[]"), "port": port, "password": password,
                        "cipher": method, "protocol": protocol, "obfs": obfs
                    }

        # 3. Vmess (vmess://)
        elif line.startswith("vmess://"):
            raw_b64 = line[8:]
            decoded_json = decode_base64_safe(raw_b64)
            if decoded_json:
                config = json.loads(decoded_json)
                server = config.get("add")
                port = config.get("port")
                if server and port:
                    node = {
                        "name": config.get("ps") or f"Vmess-{server}",
                        "type": "vmess", "server": str(server).strip("[]"), "port": int(port),
                        "uuid": config.get("id"), "alterId": int(config.get("aid", 0)), 
                        "cipher": config.get("scy") or "auto", "skip-cert-verify": True
                    }
                    net = config.get("net", "tcp")
                    if net: node["network"] = net
                    if config.get("tls") in ("tls", "1", True):
                        node["tls"] = True
                        if config.get("sni"): node["servername"] = config["sni"]

        # 4. 通用 URL 协议解析 (vless, trojan, hysteria2, hy2, tuic, snell)
        else:
            parsed = urllib.parse.urlparse(line)
            scheme = parsed.scheme.lower()
            server = parsed.hostname
            port = parsed.port
            password = parsed.username or ""
            uuid = parsed.username or ""
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.unquote(parsed.fragment)

            if not server or not port:
                return None

            if scheme in ("hysteria2", "hy2"):
                # hy2 有时密码在 query 中 (auth=xxx) 或直接作为 username
                hy2_pass = password
                if not hy2_pass and "auth" in query:
                    hy2_pass = query["auth"][0]
                node = {
                    "name": fragment or f"Hy2-{server}", "type": "hysteria2", 
                    "server": server, "port": port, "password": hy2_pass, "skip-cert-verify": True
                }
                if "sni" in query: node["sni"] = query["sni"][0]
                if "up" in query: node["up"] = query["up"][0]
                if "down" in query: node["down"] = query["down"][0]

            elif scheme == "vless":
                node = {
                    "name": fragment or f"Vless-{server}", "type": "vless", 
                    "server": server, "port": port, "uuid": uuid, 
                    "client-fingerprint": query.get("fp", ["chrome"])[0], "skip-cert-verify": True
                }
                if query.get("security", [""])[0] in ("tls", "reality") or "encryption" in query:
                    node["tls"] = True
                    if "sni" in query: node["servername"] = query["sni"][0]
                    if "security" in query and query["security"][0] == "reality":
                        if "pbk" in query:
                            node["reality-opts"] = {"public-key": query["pbk"][0]}
                        if "sid" in query:
                            node.setdefault("reality-opts", {})["short-id"] = query["sid"][0]

            elif scheme == "trojan":
                node = {
                    "name": fragment or f"Trojan-{server}", "type": "trojan", 
                    "server": server, "port": port, "password": password, "skip-cert-verify": True
                }
                if "sni" in query: node["sni"] = query["sni"][0]

            elif scheme == "tuic":
                tuic_pass = parsed.password or query.get("password", [""])[0]
                node = {
                    "name": fragment or f"Tuic-{server}", "type": "tuic", 
                    "server": server, "port": port, "uuid": uuid, 
                    "password": tuic_pass, "skip-cert-verify": True
                }
                if "congestion_control" in query:
                    node["congestion-control"] = query["congestion_control"][0]

            elif scheme == "snell":
                psk = query.get("psk", [""])[0] or password
                node = {
                    "name": fragment or f"Snell-{server}", "type": "snell",
                    "server": server, "port": port, "psk": psk
                }
                if "version" in query:
                    node["version"] = int(query["version"][0])

    except Exception:
        pass

    # 严格根据官方标准过滤，不达标直接抛弃
    return node if node and validate_node_by_official_standard(node) else None

def collect_files(inputs, output_filename="filtered_nodes.yaml", skip_filename="gem.yaml"):
    files = set()
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            for ext in ("*.txt", "*.yaml", "*.yml", "*.conf", "*.list"):
                for f in p.rglob(ext):
                    if f.name not in (output_filename, skip_filename):
                        files.add(f.resolve())
        else:
            if p.exists() and p.name not in (output_filename, skip_filename):
                files.add(p.resolve())
    return sorted([str(f) for f in files])

def quick_tcp_check(server, port, timeout=0.6):
    try:
        with socket.create_connection((str(server), int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def stream_merge_and_tcp_filter(files, invalid_pool, valid_pool, tested_fps):
    seen_fps = set()
    file_stats = {}
    total_raw_scanned = 0
    total_raw_valid = 0
    total_inherited = 0
    total_tcp_filtered = 0
    total_passed_tcp = 0
    total_already_tested = 0

    def check_node_tcp(node):
        if node.get("_inherited_valid"): return node
        if node.get("type", "").lower() in ("hysteria2", "hy2", "tuic", "warp"): return node
        return node if quick_tcp_check(node.get("server"), node.get("port")) else None

    for path in files:
        path_key = str(path)
        file_scanned_count = 0
        file_valid_count = 0
        file_nodes = []

        if path_key.endswith((".yaml", ".yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    proxies = data.get("proxies", [])
                    file_scanned_count = len(proxies)
                    for node in proxies:
                        if validate_node_by_official_standard(node):
                            file_nodes.append(node)
            except Exception as e:
                log(f"❌ YAML 文件读取失败: {path}: {e}")
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content_lines = f.readlines()
                
                full_text = "".join(content_lines).strip()
                if full_text and not any(full_text.startswith(x) for x in ("ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria2://", "hy2://", "tuic://", "snell://")):
                    decoded_sub = decode_base64_safe(full_text)
                    if "://" in decoded_sub:
                        content_lines = decoded_sub.splitlines()

                for line in content_lines:
                    file_scanned_count += 1
                    node = parse_share_link(line)
                    if node:
                        file_nodes.append(node)
            except Exception as e:
                log(f"❌ 文本文件读取失败: {path}: {e}")

        total_raw_scanned += file_scanned_count
        file_passed_list = []
        for node in file_nodes:
            fp = fingerprint(node)
            if fp in tested_fps or fp in invalid_pool or fp in seen_fps:
                if fp in tested_fps or fp in invalid_pool:
                    total_already_tested += 1
                continue
            seen_fps.add(fp)
            total_raw_valid += 1
            file_valid_count += 1

            if fp in valid_pool:
                node["_inherited_valid"] = True
                total_inherited += 1
                total_passed_tcp += 1
                file_passed_list.append(node)
                continue
            file_passed_list.append(node)

        file_stats[path_key] = {"scanned": file_scanned_count, "valid": file_valid_count}
        log(f"📂 [源文件扫描] {Path(path_key).relative_to(Path.cwd()) if Path(path_key).is_relative_to(Path.cwd()) else path_key} -> 原始行数/条目: {file_scanned_count} | 合规有效提取: {file_valid_count}")

        chunk = []
        for node in file_passed_list:
            if node.get("_inherited_valid"):
                yield node
                continue
            chunk.append(node)
            if len(chunk) >= 2000:
                for res in flush_tcp_chunk(chunk, check_node_tcp):
                    if res:
                        total_passed_tcp += 1
                        yield res
                    else:
                        total_tcp_filtered += 1
                chunk = []
        if chunk:
            for res in flush_tcp_chunk(chunk, check_node_tcp):
                if res:
                    total_passed_tcp += 1
                    yield res
                else:
                    total_tcp_filtered += 1

    expected_batches = (total_passed_tcp + BATCH_SIZE - 1) // BATCH_SIZE if total_passed_tcp > 0 else 0
    log(f"\n==================== 📊 全库物料盘点与总账统计报告 ====================")
    log(f"📁 扫描输入源文件总数: {len(files)} 个")
    for p, st in file_stats.items():
        rel_name = Path(p).name
        log(f"   - 📄 [{rel_name}] 原始扫描: {st['scanned']} 条 | 合规有效提取: {st['valid']} 条")
    log(f"-----------------------------------------------------------------")
    log(f"📦 累计全网检索原始总条目数: {total_raw_scanned} 条")
    log(f"🛑 历史缓存已测/失效拦截(跳过): {total_already_tested} 条")
    log(f"🔍 严格官方标准质检通过: {total_raw_valid} 条")
    log(f"♻️ 历史白名单继承命中: {total_inherited} 条")
    log(f"⚡ TCP 离线预检剔除死节点: {total_tcp_filtered} 条")
    log(f"🎯 最终进入本轮 Mihomo 测速总池: {total_passed_tcp} 条")
    log(f"📦 本轮动态划分测速总批次: {expected_batches} 批 (每批 {BATCH_SIZE} 条)")
    log(f"=================================================================\n")

def flush_tcp_chunk(chunk, check_func):
    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(check_func, node): node for node in chunk}
        for future in as_completed(futures):
            yield future.result()

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
    if len(delays) != sum(len(t) for _, t in TEST_GROUPS):
        return {"name": name, "node": node, "ok": False, "error": "测试数量不全"}
    return {"name": name, "node": node, "ok": True, "avg": round(sum(delays) / len(delays), 1)}

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
                    if "name" in p: all_names.append(p["name"])

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
            log(f"❌ [第 {batch_idx} 批] Mihomo 异常: {e} -> 自动容错跳过当前批次")
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

    inputs = args.inputs if args.inputs else DEFAULT_INPUT_PATTERNS
    files = collect_files(inputs, args.output, "gem.yaml")
    if not files: raise SystemExit("❌ 没有找到任何输入节点文件")
    if not shutil.which(args.mihomo) and not os.path.isfile(args.mihomo):
        raise SystemExit(f"❌ 找不到 Mihomo: {args.mihomo}")

    tested_fps = load_pool(CHECKPOINT_FILE)
    valid_pool = load_pool(VALID_POOL_FILE)
    invalid_pool = load_pool(INVALID_POOL_FILE)

    log("🚀 启动 V6 严苛官方标准多协议物料审计与清洗引擎...")

    batch_slice = []
    for old_b in glob.glob("generated/batches/filtered_batch_*.yaml"):
        try: os.remove(old_b)
        except Exception: pass

    batch_idx = 1

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

    if not glob.glob("generated/batches/filtered_batch_*.yaml"):
        log("⚠ 没有任何节点通过测试。")
        return 2

    if build_final_aio_streamed(args.output) == 0:
        log("⚠ 没有任何节点通过测试。")
        return 2

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
