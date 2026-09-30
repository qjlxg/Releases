#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, copy, glob, hashlib, json, os, pathlib, yaml

DEFAULT_INPUT_DIR = "generated/probe"
DEFAULT_OUTPUT_DIR = "nodes_unique"

def log(msg):
    import time
    print(time.strftime("[%Y-%m-%d %H:%M:%S]"), msg, flush=True)

def safe_name(name):
    return str(name or "node").strip() or "node"

def fingerprint(proxy):
    # 排除名称干扰，通过核心配置计算指纹进行绝对去重
    obj = {k: v for k, v in proxy.items() if k != "name"}
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def load_yaml_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict): return []
    proxies = data.get("proxies", [])
    return proxies if isinstance(proxies, list) else []

def main():
    parser = argparse.ArgumentParser(description="提取并去重 generated/probe 下的唯一节点")
    parser.add_argument("-i", "--input-dir", default=DEFAULT_INPUT_DIR, help="输入目录")
    parser.add_argument("-o", "--output-dir", default=DEFAULT_OUTPUT_DIR, help="输出目录")
    args = parser.parse_args()

    input_path = pathlib.Path(args.input_dir)
    output_path = pathlib.Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # 查找输入目录下所有的 yaml/yml 文件
    pattern_yaml = str(input_path / "*.yaml")
    pattern_yml = str(input_path / "*.yml")
    files = glob.glob(pattern_yaml) + glob.glob(pattern_yml)

    if not files:
        log(f"❌ 在 {args.input_dir} 目录下没有找到任何 YAML 文件")
        return 0

    log(f"📄 发现 {len(files)} 个源文件，开始加载与全局去重...")

    seen_fp = set()
    unique_nodes = []
    name_count = {}
    total_raw = 0

    for path in sorted(files):
        nodes = load_yaml_file(path)
        total_raw += len(nodes)
        log(f"  -> 读取 {path}: {len(nodes)} 个节点")
        for node in nodes:
            if not isinstance(node, dict) or not node.get("type") or not node.get("server") or not node.get("port"):
                continue
            node = copy.deepcopy(node)
            fp = fingerprint(node)
            if fp in seen_fp:
                continue
            seen_fp.add(fp)

            # 规范化节点名称，防止重名冲突
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

            unique_nodes.append(node)

    log(f"📊 统计结果：原始总数 {total_raw} | 全局去重后唯一节点数 {len(unique_nodes)}")

    # 保存到输出目录（可以按每 10000 个节点分批保存，或者存为一个总文件）
    # 这里咱们仿照您的习惯，按批次或直接存为一个干净的综合 YAML 文件
    out_file = output_path / "unique_nodes_all.yaml"
    data = {
        "proxies": unique_nodes,
        "proxy-groups": [{
            "name": "Unique-Nodes",
            "type": "select",
            "proxies": [p["name"] for p in unique_nodes] or ["DIRECT"],
        }],
        "rules": ["MATCH,Unique-Nodes"],
    }
    with open(out_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    log(f"💾 唯一节点已成功保存到: {out_file}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())