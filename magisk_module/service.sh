#!/system/bin/sh
# Aether OptExt — 开机启动守护进程

MODDIR=${0%/*}
CONFIG="/sdcard/Android/Aether/threads.json"

# 等待系统完全就绪 (开机 + /sdcard 可写)
wait_until_login() {
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 2.5
    done
    local test_file="/sdcard/Android/.PERMISSION_TEST_AETHER"
    true >"$test_file"
    while [ ! -f "$test_file" ]; do
        sleep 0.25
        true >"$test_file"
    done
    rm "$test_file"
}

wait_until_login

# 清理旧日志
rm -f /sdcard/Android/Aether/threads_log.txt 2>/dev/null

# 确保配置文件存在
mkdir -p "/sdcard/Android/Aether" 2>/dev/null
[ ! -f "$CONFIG" ] && [ -f "$MODDIR/threads.json" ] && cp "$MODDIR/threads.json" "$CONFIG" 2>/dev/null
[ ! -f "$CONFIG" ] && CONFIG="$MODDIR/threads.json"

# 杀旧进程 (只匹配进程名，不匹配路径，避免杀自己)
pkill "aether-optext" 2>/dev/null
sleep 1

if [ -f "$MODDIR/aether-optext" ]; then
    "$MODDIR/aether-optext" -c "$CONFIG" -s 2 &
    echo "[Aether] 已启动 PID $!"
fi
