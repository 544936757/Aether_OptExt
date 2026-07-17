#!/usr/bin/env python3
"""
Aether OptExt - 一键编译 + 打包脚本
用法: python build.py
输出: out/Aether-OptExt_YYYYMMDD_HHMMSS.zip
"""

import os
import sys
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
OUT_DIR = SCRIPT_DIR / "out"
MODULE_DIR = SCRIPT_DIR / "magisk_module"
MODULE_ZIP = OUT_DIR / f"Aether-OptExt_{datetime.now():%Y%m%d_%H%M%S}.zip"
TARGET = "aarch64-linux-android"


# ============================================================
# 多拓扑配置生成
# ============================================================

# 主要移动端 CPU 拓扑 (覆盖 2020-2026 主流 SoC)
# 格式: "little+mid+big" = ([little cores], [mid cores], [big cores])
# 按频率分级: little(低频节能) < mid(中频均衡) < big(高频性能)
# 核心编号从 0 开始，假设最多 8-10 核
# 每个拓扑定义: ([little], [mid], [big], effi_range, perf_range)
# effi_range - 非游戏应用用核范围
# perf_range - 游戏渲染线程用核范围
TOPOLOGIES = {
    # ═══ 8 核 ═══
    "4+3+1": ([0,1,2,3], [4,5,6], [7], "0-5", "6-7"),  # 骁龙865/888/8G1
    "3+4+1": ([0,1,2],   [3,4,5,6], [7], "0-5", "6-7"),  # 部分天玑
    "4+4":   ([0,1,2,3], [], [4,5,6,7], "0-3", "4-7"),  # 天玑8000/8300
    "6+2":   ([0,1,2,3,4,5], [], [6,7], "0-5", "6-7"),  # 骁龙680/695
    "2+6":   ([0,1], [], [2,3,4,5,6,7], "0-1", "2-7"),  # 低端(省电核少)
    "4+2+2": ([0,1,2,3], [4,5], [6,7], "0-5", "6-7"),  # Exynos990/Tensor

    # ═══ 10 核 ═══
    "4+3+2+1": ([0,1,2,3], [4,5,6,7,8], [9], "0-7", "8-9"),  # Exynos2400
}


def parse_cpu_range(spec):
    """解析 '0-3,6-7' 为 [0,1,2,3,6,7]"""
    result = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                s, e = part.split('-', 1)
                result.extend(range(int(s.strip()), int(e.strip()) + 1))
            except ValueError:
                continue  # 跳过非法范围如 "0/5"
        else:
            try:
                result.append(int(part))
            except ValueError:
                continue
    return result


def format_cpu_range(cpus):
    """将 [0,1,2,3,6,7] 格式化为 '0-3,6-7'"""
    if not cpus:
        return ""
    cpus = sorted(set(cpus))
    parts = []
    start = end = cpus[0]
    for c in cpus[1:]:
        if c == end + 1:
            end = c
        else:
            parts.append(f"{start}-{end}" if start != end else str(start))
            start = end = c
    parts.append(f"{start}-{end}" if start != end else str(start))
    return ",".join(parts)


def remap_cpus(cpu_list, from_topo, to_topo):
    """将 CPU 编号从一种拓扑映射到另一种拓扑
    - 同核心数: 物理核心 0-7 不变，只变集群标签，无需重映射
    - 不同核心数: 按集群角色映射，超出部分分配到最大可用核心
    """
    from_l, from_m, from_b, _, _ = TOPOLOGIES[from_topo]
    to_l, to_m, to_b, _, _ = TOPOLOGIES[to_topo]

    from_all = from_l + from_m + from_b
    to_all = to_l + to_m + to_b

    # 同核心数：物理核心编号不变
    if len(from_all) == len(to_all):
        return cpu_list

    # 不同核心数：构建角色映射
    max_core = max(to_all) if to_all else 0
    mapping = {}

    # 按角色映射 (little→little, mid→mid, big→big)
    for idx, core in enumerate(from_l):
        mapping[core] = to_l[idx] if idx < len(to_l) else to_l[-1] if to_l else max_core
    for idx, core in enumerate(from_m):
        mapping[core] = to_m[idx] if idx < len(to_m) else (to_m[-1] if to_m else max_core)
    for idx, core in enumerate(from_b):
        mapping[core] = to_b[idx] if idx < len(to_b) else (to_b[-1] if to_b else max_core)

    result = []
    for c in cpu_list:
        if c in mapping:
            result.append(mapping[c])
        else:
            # 不在映射表中：取同角色中最近的核心
            result.append(min(max_core, c))
    return result


def remap_config(entries, from_topo, to_topo):
    """将整个配置从一种拓扑映射到另一种"""
    if from_topo == to_topo:
        return entries

    result = []
    for entry in entries:
        new_entry = {
            "friendly": entry["friendly"],
            "packages": list(entry["packages"]),
            "cpuset": {
                "other": remap_range(entry["cpuset"]["other"], from_topo, to_topo),
                "comm": {}
            }
        }
        for cpus, threads in entry["cpuset"].get("comm", {}).items():
            new_cpus = remap_range(cpus, from_topo, to_topo)
            new_entry["cpuset"]["comm"][new_cpus] = list(threads)
        result.append(new_entry)
    return result


def remap_range(spec, from_topo, to_topo):
    """将一个 CPU 范围字符串从一种拓扑映射到另一种"""
    cpus = parse_cpu_range(spec)
    mapped = remap_cpus(cpus, from_topo, to_topo)
    return format_cpu_range(mapped)


def is_game(entry):
    name = entry.get('friendly', '')
    pkgs = str(entry.get('packages', []))
    game_keywords = [
        '原神', '崩坏', '星穹', '绝区零', '王者', '和平精英', '鸣潮',
        '幻塔', 'PUBG', '英雄联盟', '穿越火线', '金铲铲', 'QQ飞车',
        '蛋仔派对', '暗区突围', '永劫无间', '晶核', '无畏契约', '高能英雄',
        '巅峰极速', '元梦之星', '香肠派对', '火影忍者', '航海王',
        '光遇', '逆水寒', '明日方舟', '碧蓝航线', '阴阳师', '地下城',
        '使命召唤', '部落冲突', '跑跑卡丁车', '第五人格', '英魂之刃',
        '决战平安京', '王牌竞速', '三国杀', '英雄杀', '荒野乱斗',
        '少女前线', '碧蓝档案', '蔚蓝档案', '重返未来', '尘白禁区',
        '三角洲', 'COD', 'NBA', 'PES', '欢乐', '斗地主', '麻将',
        '传奇', '大话', '梦幻', '问道', '诛仙', '节奏大师',
    ]
    game_pkg_prefixes = [
        'com.tencent.tmgp', 'com.miHoYo', 'com.kurogame', 'com.netease.',
        'com.gameloft', 'com.supercell', 'com.blizzard', 'com.activision',
        'com.dragonli', 'com.papegames', 'com.ztgame',
        'com.levelinfinite', 'com.hottagames',
    ]
    for kw in game_keywords:
        if kw in name or kw in pkgs:
            return True
    for prefix in game_pkg_prefixes:
        if any(p.startswith(prefix) for p in entry.get('packages', [])):
            return True
    return False

def gen_topology_configs():
    """生成多拓扑配置文件到模块 config/ 目录"""
    config_dir = MODULE_DIR / "config"
    # 清理旧配置
    if config_dir.exists():
        import shutil
        shutil.rmtree(config_dir)
    config_dir.mkdir()

    # 读取默认配置
    default_file = MODULE_DIR / "threads.json"
    if not default_file.exists():
        warn("threads.json 不存在，跳过配置生成")
        return

    import json
    with open(default_file, encoding='utf-8') as f:
        raw = json.load(f)
    # 支持新格式 {features, rules} 和旧格式 [...] 
    entries = raw if isinstance(raw, list) else raw.get("rules", raw)

    default_topo = "4+3+1"
    default_cores = sum(len(g) for g in TOPOLOGIES[default_topo][:3])
    _ = default_cores  # unused
    count = 0
    FEATURES = {"ebpf": True, "auto-for-none": True}

    def wrap_rules(entries):
        return {"features": FEATURES, "rules": entries}

    for topo_name, (_, _, _, effi, perf) in TOPOLOGIES.items():
        if topo_name == default_topo:
            opt = wrap_rules(entries)
            with open(config_dir / f"{topo_name}.json", 'w', encoding='utf-8') as f:
                json.dump(opt, f, ensure_ascii=False, indent=2)
            count += 1
            continue

        opt = []
        for e in entries:
            if is_game(e):
                adapted = remap_config([e], default_topo, topo_name)
                opt.append(adapted[0])
            else:
                # 非游戏：保留完整规则，只重映射核心号
                adapted = remap_config([e], default_topo, topo_name)
                opt.append(adapted[0])

        with open(config_dir / f"{topo_name}.json", 'w', encoding='utf-8') as f:
            json.dump(wrap_rules(opt), f, ensure_ascii=False, indent=2)
        count += 1

    info(f"共 {count} 个拓扑配置文件")
def info(msg):    print(f"[INFO] {msg}")
def warn(msg):    print(f"[WARN] {msg}")
def error(msg):   print(f"[ERROR] {msg}")
def die(msg):     error(msg); sys.exit(1)


def check_deps():
    """检查 Rust 和编译目标"""
    info("检查依赖...")

    if not shutil.which("rustc"):
        die("请安装 Rust: https://rustup.rs")
    if not shutil.which("cargo"):
        die("请安装 Cargo")

    result = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True, text=True
    )
    if TARGET not in result.stdout:
        info(f"添加编译目标 {TARGET}...")
        subprocess.run(["rustup", "target", "add", TARGET], check=True)


def find_ndk():
    """自动检测 Android NDK"""
    candidates = [
        os.environ.get("ANDROID_NDK_HOME"),
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path.home() / "Android/Sdk"),
        str(Path.home() / "AppData/Local/Android/Sdk"),
        "C:/Users/shenz/AppData/Local/Android/Sdk",
    ]

    for base in candidates:
        if not base:
            continue
        base = Path(base)

        # 直接指向 NDK 根目录
        if (base / "toolchains/llvm/prebuilt").exists():
            ndk_dir = base
        else:
            # 在 SDK 的 ndk/ 子目录下找
            ndk_versions = sorted(base.glob("ndk/*"), reverse=True)
            if not ndk_versions:
                ndk_versions = sorted(base.glob("ndk-bundle/*"), reverse=True)
            ndk_dir = ndk_versions[0] if ndk_versions else None

        if ndk_dir is None:
            continue

        # 检测 host tag
        for tag in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-aarch64"]:
            toolchain = ndk_dir / "toolchains/llvm/prebuilt" / tag
            if not toolchain.exists():
                continue
            linker = toolchain / "bin" / f"aarch64-linux-android21-clang"
            if sys.platform == "win32":
                linker = linker.with_suffix(".cmd")
            if linker.exists():
                info(f"找到 NDK: {ndk_dir}")
                return ndk_dir, tag, linker

    warn("未找到 NDK，将使用主机编译器（仅限测试）")
    return None, None, None


def build(ndk_info):
    """交叉编译"""
    info("编译 Aether OptExt...")
    os.chdir(SCRIPT_DIR)

    env = os.environ.copy()

    if ndk_info:
        ndk_dir, host_tag, linker = ndk_info
        toolchain = ndk_dir / "toolchains/llvm/prebuilt" / host_tag
        env["CC_aarch64_linux_android"] = str(linker)
        env["AR_aarch64_linux_android"] = str(toolchain / "bin/llvm-ar")

        # 写入 .cargo/config.toml
        cargo_dir = SCRIPT_DIR / ".cargo"
        cargo_dir.mkdir(exist_ok=True)
        linker_str = str(linker).replace("\\", "\\\\")
        (cargo_dir / "config.toml").write_text(
            f"[target.{TARGET}]\nlinker = \"{linker_str}\"\n"
        )
        info(f"linker: {linker}")
    else:
        warn("无 NDK，编译主机版本（不可用于 Android）")

    result = subprocess.run(
        ["cargo", "build", "--target", TARGET, "--release"],
        env=env
    )
    if result.returncode != 0:
        die("编译失败")

    info("编译成功")


def clean():
    """清理旧构建产物"""
    for f in OUT_DIR.glob("*"):
        f.unlink()
    # 清理模块目录下的旧二进制（保留同名文件）
    for f in MODULE_DIR.glob("Aether_OptExt*"):
        f.unlink()
    info("已清理旧构建产物")


def fix_line_ending(path):
    """将文本文件转成 Unix 换行符"""
    with open(path, 'rb') as f:
        data = f.read()
    if b'\r\n' in data:
        data = data.replace(b'\r\n', b'\n')
        with open(path, 'wb') as f:
            f.write(data)
        return True
    return False


def package():
    """打包 Magisk 模块"""
    info("打包 Magisk 模块...")

    # 二进制路径
    binary = SCRIPT_DIR / "target" / TARGET / "release" / "aether-optext"
    if not binary.exists():
        binary = SCRIPT_DIR / "target" / "release" / "aether-optext"
    if not binary.exists():
        die("编译产物未找到")

    # 清理旧模块
    OUT_DIR.mkdir(exist_ok=True)
    MODULE_ZIP.unlink(missing_ok=True)

    # 复制二进制到模块目录
    binary_dst = MODULE_DIR / "aether-optext"
    shutil.copy2(binary, binary_dst)
    os.chmod(binary_dst, 0o755)

    # 文本文件转 Unix 换行符（防止 Android shell 报错）
    for f in MODULE_DIR.glob("**/*"):
        if f.suffix in (".sh", ".prop", ".json", ".md") or f.name == "updater-script":
            if fix_line_ending(f):
                info(f"转换换行符: {f.name}")

    # 构建 zip
    with zipfile.ZipFile(MODULE_ZIP, "w", zipfile.ZIP_STORED) as z:
        for root, dirs, files in os.walk(MODULE_DIR):
            for f in files:
                full = Path(root) / f
                rel = str(full.relative_to(MODULE_DIR))
                if rel.startswith(".") or "/." in rel or "\\." in rel:
                    continue
                # 二进制用编译出的替换
                if rel.replace("\\", "/") == "aether-optext":
                    z.write(binary, "aether-optext")
                else:
                    z.write(full, rel)

    size = MODULE_ZIP.stat().st_size
    info(f"模块: {MODULE_ZIP} ({size/1024:.1f} KB)")


def show_manifest():
    """显示模块内容"""
    print()
    info("模块内容:")
    with zipfile.ZipFile(MODULE_ZIP) as z:
        for i in z.infolist():
            print(f"  {i.filename:40s} {i.file_size:>8d}B")
    print()


def main():
    print()
    print("============================================")
    print(f"   Aether OptExt v{VERSION} Build Tool")
    print("============================================")
    print()

    check_deps()
    ndk_info = find_ndk()
    build(ndk_info)
    gen_topology_configs()
    clean()
    package()
    show_manifest()

    info("全部完成！")


if __name__ == "__main__":
    main()
