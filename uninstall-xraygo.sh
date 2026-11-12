#!/bin/bash
# uninstall-xraygo.sh
# 只卸载 xray-go-isolated 装的东西：
#   - 服务 xraygo（systemd / OpenRC）
#   - 易分享的 cloudflared 服务
#   - 目录 /etc/xraygo
# 绝不触碰甬哥 argosbx：/root/agsbx、xr.service、sb.service、argo.service

set -u

RED='\033[1;91m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}$1${NC}"; }
warn() { echo -e "${YELLOW}$1${NC}"; }
err()  { echo -e "${RED}$1${NC}"; }

[ "$(id -u)" -ne 0 ] && { err "请用 root 运行：sudo bash $0"; exit 1; }

WORK_DIR="/etc/xraygo"
SVC="xraygo"
CF_SVC="cloudflared"

echo "=========================================="
echo " 卸载 xray-go-isolated"
echo " 目录 : $WORK_DIR"
echo " 服务 : $SVC / $CF_SVC"
echo "=========================================="
echo

if [ -d "$WORK_DIR" ]; then
    warn "如需保留配置，请先另开窗口备份："
    warn "  cp -a $WORK_DIR /root/xraygo.bak.\$(date +%s)"
    echo
fi

# ---------- 1. systemd ----------
if pidof systemd >/dev/null 2>&1; then
    echo "[1/4] systemd：停止并禁用服务"
    systemctl disable --now "$SVC" 2>/dev/null
    systemctl disable --now "$CF_SVC" 2>/dev/null
    rm -f "/etc/systemd/system/${SVC}.service"
    rm -f "/etc/systemd/system/${CF_SVC}.service"
    systemctl daemon-reload 2>/dev/null
    systemctl reset-failed 2>/dev/null
    echo "      完成"
else
    echo "[1/4] 未检测到 systemd，跳过"
fi

# ---------- 2. OpenRC ----------
if command -v rc-service >/dev/null 2>&1; then
    echo "[2/4] OpenRC：停止并移除服务"
    rc-service "$SVC" stop 2>/dev/null
    rc-update del "$SVC" default 2>/dev/null
    rm -f "/etc/init.d/${SVC}"
    rc-service "$CF_SVC" stop 2>/dev/null
    rc-update del "$CF_SVC" default 2>/dev/null
    rm -f "/etc/init.d/${CF_SVC}"
    echo "      完成"
else
    echo "[2/4] 未检测到 OpenRC，跳过"
fi

# ---------- 3. 精确杀进程 ----------
# 关键：这里绝不能写成 pkill -9 -f xray / pkill -9 -f cloudflared，
# 那会把甬哥的 /root/agsbx/xray 和 /root/agsbx/cloudflared 一起杀掉。
echo "[3/4] 清理残留进程（只匹配 $WORK_DIR）"
pkill -9 -f "${WORK_DIR}/xray" 2>/dev/null
pkill -9 -f "${WORK_DIR}/cloudflared" 2>/dev/null
for P in /proc/[0-9]*; do
    [ -L "$P/exe" ] || continue
    T=$(readlink -f "$P/exe" 2>/dev/null) || continue
    case "$T" in
        "${WORK_DIR}"/*) kill -9 "$(basename "$P")" 2>/dev/null ;;
    esac
done
rm -f /run/xraygo.pid
echo "      完成"

# ---------- 4. 删目录 ----------
echo "[4/4] 删除安装目录"
rm -rf "$WORK_DIR"
echo "      完成"

# ---------- 校验 ----------
echo
echo "---------- 校验 ----------"
if [ -d /root/agsbx ]; then
    ok "  /root/agsbx 保留（甬哥 argosbx 未受影响）"
else
    warn "  /root/agsbx 不存在（你可能没装过甬哥脚本）"
fi

for s in xr sb argo; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${s}.service"; then
        ok "  ${s}.service 保留"
    fi
done

if ss -lntp 2>/dev/null | grep -q ':8001'; then
    warn "  8001 端口仍被占用，检查：ss -lntp | grep 8001"
else
    ok "  8001 端口已释放"
fi

echo
ok "xray-go-isolated 卸载完成"
warn "Cloudflare 面板里指向 http://localhost:8001 的那条 Public Hostname 需自行删除"
warn "如需彻底清理，可到 Zero Trust → Networks → Tunnels 删除对应 tunnel"
