#!/system/bin/sh
# Magisk 模块安装脚本 — Aether OptExt

set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/aether-optext 0 0 0755

# 自动检测 CPU 拓扑 (通过 cpufreq policy 集群)
detect_topology() {
    local counts=""
    for policy in /sys/devices/system/cpu/cpufreq/policy[0-9]*; do
        [ -d "$policy" ] || continue
        local cpus=$(cat "$policy/related_cpus" 2>/dev/null)
        [ -z "$cpus" ] && continue
        # 计算该集群核心数
        local count=0
        for c in $(echo "$cpus" | tr ',' ' ' | tr '-' ' '); do
            count=$((count + 1))
        done
        # 如果有 range 如 "0-5" 则计算区间长度
        if echo "$cpus" | grep -q '-'; then
            local start=$(echo "$cpus" | cut -d'-' -f1)
            local end=$(echo "$cpus" | cut -d'-' -f2)
            count=$((end - start + 1))
        fi
        counts="$counts $count"
    done

    # policy 编号即集群顺序 (policy0=little, 依次递增)
    local topo=$(echo "$counts" | xargs | tr ' ' '\n' | tr '\n' '+' | sed 's/^+//;s/+$//')
    [ -z "$topo" ] && topo="unknown"
    echo "$topo"
}

# 部署配置文件
TARGET="/sdcard/Android/Aether"
mkdir -p "$TARGET"

TOPOLOGY=$(detect_topology)
ui_print "- 检测到 CPU 拓扑: $TOPOLOGY"

# 查找匹配的拓扑配置
CONFIG_SRC="$MODPATH/config/${TOPOLOGY}.json"
if [ -f "$CONFIG_SRC" ]; then
    ui_print "- 使用拓扑适配配置: $TOPOLOGY"
else
    CONFIG_SRC="$MODPATH/threads.json"
    ui_print "- 使用默认配置"
fi

cp "$CONFIG_SRC" "$TARGET/threads.json" 2>/dev/null
ui_print "- 配置文件已部署到 $TARGET"

ui_print "- Aether OptExt v0713-Dev 安装完成"
ui_print "- 日志文件: /sdcard/Android/Aether/threads_log.txt"
