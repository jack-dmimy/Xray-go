#!/bin/bash
# ==========================================================================
# xray-go-cert.sh —— 在原 xray-go.sh 基础上增加「域名证书 / DNS API」与
# 「Vless-xhttp-tls-TCP/UDP 套 CDN」能力，证书目录沿用甬哥 /root/ygkkkca 约定
#
# 新增参数（关键字与值之间可带等号也可不带，推荐带等号）：
#   h2=443 / h2=y      开启 TCP(h2/http1.1) XHTTP inbound；443 系端口才可套 CDN
#   certmode=dns_cf    Cloudflare DNS API（环境变量 CF_Account_ID + CF_Token）
#   certmode=dns_dp    DNSPod DNS API（环境变量 DP_Id + DP_Key）
#   certmode=dns_ali   阿里云 DNS API（环境变量 Ali_Key + Ali_Secret）
#   certmode=standalone 独立 80 端口申请单域名证书（域名须先解析到本机且关闭 CDN）
#   certmode=manual    直接复用已申请好的 /root/ygkkkca/cert.crt + private.key（缺证书仍回退自签）
#   certmode=yg        强制使用甬哥 acme-yg 申请的 /root/ygkkkca 证书：
#                      缺证书时自动调起 acme-yg 交互脚本，仍未申请成功则「拒绝安装」，
#                      绝不回退自签证书；并校验证书有效期、公私钥配对、SAN 与 SNI 匹配
#   certdomain=xxx.com 证书域名 / 节点 sni + host；certmode=yg 下【可省略】，
#                      脚本自动读 ca.log，再兜底从证书 SAN 提取真实域名。
#                      ⚠️ 文档里的 node.example.com 只是占位符，照抄会被 SAN 校验拒绝；
#                         不确定就干脆不传 certdomain
#   cfport=2053        客户端连 CF 边缘的端口（默认 443，443 被封可换 2053/2083/2087/2096/8443）
#   coexist=1          与甬哥 argosbx 共存模式：只清理本脚本的 cloudflared（不用全局 pkill），
#                      且 cloudflared.service 不启用开机自启、安装后不自动启动，
#                      由 systemctl start/stop cloudflared 手动切换「当前只用哪一条」
#   uuid=yg           强制复用甬哥 /root/agsbx/uuid（读不到就拒绝安装，绝不随机）
#   uuid=<标准UUID>   直接指定 UUID；也支持环境变量前置写法 uuid=<UUID> bash xray-go-cert.sh ...
#   uuid=auto         默认值：环境变量 → 甬哥 /root/agsbx/uuid → 都没有才随机
#   uuid=ask          运行时交互录入；uuid=random 强制随机（原版行为）
#   h3 / reality / argoprotocol / argoport / argodomain / argotoken 保持原样
#
# 示例：
#   CF_Account_ID=xxx CF_Token=yyy bash xray-go-cert.sh \
#     certmode=dns_cf certdomain=node.example.com \
#     h3=8443 h2=443 \
#     argodomain=argo.example.com argotoken=eyJ...
#   先装甬哥 vless-ws-tls-argo，再用甬哥证书脚本 + 本脚本（强制证书 + 共存）：
#     bash xray-go-cert.sh certmode=yg h2=443 coexist=1 \
#       argodomain=<你的隧道域名> argotoken=<你的TOKEN> argoprotocol=http2 \
#       argoport=<你的回源端口> uuid=<你的UUID>
#     certdomain / reality / cfport 可省略（证书域名自动读、默认不装 Reality、CF 边缘默认 443）；
#     ⚠️ argoport 不能省：本脚本已取消默认 8001，必须自己设。<...> 必须换成真实值，不能照抄。
# 说明：随机端口用字母 y（如 h3=y）；裸数字按 H3、REALITY 顺序分配
#       argo 默认 protocol=quic；启用 Argo 时 argoport 必填，没有默认值
#       argoport=9000  自定义 Argo 本地监听端口（1-65535，仅 127.0.0.1，无需放行公网）
#       argoport=ask   运行时交互式录入端口（需 SSH 交互终端；不设默认值，输错会重问）
#       不传 argoport 且是交互终端 → 同样弹出录入；非交互（curl|bash）→ 直接报错退出，
#       绝不会静默使用 8001，避免与 CF 面板 service 端口不一致
#       旧写法 port"9000" / port9000 同样有效
#       ⚠️ 改了 argoport，必须同步把 CF 面板 Public Hostname 的 service 改成
#          http://localhost:<新端口>，否则 Argo 节点全部 502/404
#       UUID 记录文件：/etc/xray/uuid.txt；甬哥 UUID 文件：/root/agsbx/uuid
#       ⚠️ 复用甬哥 UUID 只代表两套节点 id 相同：甬哥是 VLESS ENC（encryption+flow），
#          本脚本是 encryption=none，客户端参数不可互换；且 path 会与甬哥 xupt/xcpt 同名，
#          若打算用「同一 hostname 按 path 分流」，请改用两个不同子域名或自行改 path 后缀
# ==========================================================================

export LANG=en_US.UTF-8
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
red() { echo -e "\e[1;91m$1\033[0m"; }

# Cloudflare 安全代理源（由“易分享”创建）
GITHUB_PROXY=('https://ess.ieshare.workers.dev/')

download_file() {
    local output_path="$1"
    local official_url="$2"
    
    # 智能文件校验函数
    validate_file() {
        local path="$1"
        # 如果文件不存在或大小为 0，直接判定失败
        [ ! -s "$path" ] && return 1
        
        if [[ "$path" == *.zip ]]; then
            # 校验 zip 文件
            head -c 2 "$path" | grep -q "PK"
        else
            # 校验二进制文件
            local fsize=$(stat -c%s "$path" 2>/dev/null || stat -f%z "$path" 2>/dev/null || echo 0)
            [ "$fsize" -gt 5000000 ]
        fi
    }

    # 清理残留垃圾文件
    clean_garbage() {
        [ -f "$output_path" ] && rm -f "$output_path"
    }

   # 1. 优先尝试：GitHub 官方源

    echo "连接 GitHub 官方源中..."
    # 给予充足的超时时间：连接超时 15 秒，总下载限时 120 秒
    if curl -sL --connect-timeout 15 --max-time 120 -o "$output_path" "$official_url"; then
        if validate_file "$output_path"; then
            green "下载+校验成功！"
            return 0
        else
            yellow "校验失败，切换 Cloudflare 安全代理..."
            clean_garbage
        fi
    else
        yellow "连接超时，切换 Cloudflare 安全代理..."
        clean_garbage
    fi
    
    # 2. 备选尝试：Cloudflare 安全代理源
    for proxy in "${GITHUB_PROXY[@]}"; do
        local proxy_url="${proxy}${official_url}"
        if curl -sL --connect-timeout 15 --max-time 120 -o "$output_path" "$proxy_url"; then
            if validate_file "$output_path"; then
                green "下载+校验成功！"
                return 0
            else
                yellow "校验失败，已清除残留..."
                clean_garbage
            fi
        fi
done
    # 3. 全部失败
    red "下载或校验失败，请检查网络，稍后再试！"
    clean_garbage
    return 1
}

ARG_H2=""
ARG_H3=""
ARG_REALITY=""
ARG_CERT_MODE="self"
ARG_CERT_DOMAIN=""
ARG_CF_PORT="443"
ARG_ARGO_PROTOCOL="quic"
ARG_ARGO_PORT=""
ARG_ARGO_DOMAIN=""
ARG_ARGO_TOKEN=""
ARG_COEXIST=""
ARG_UUID=""

# 智能解析复合与关键字参数
for arg in "$@"; do
    clean_arg="${arg//\"/}"
    clean_arg="${clean_arg//\'/}"
    
    if [[ "$clean_arg" =~ ^[uU][uU][iI][dD](.*)$ ]]; then
        ARG_UUID="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[hH]3(.*)$ ]]; then
        ARG_H3="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[hH]2(.*)$ ]]; then
        ARG_H2="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[cC][eE][rR][tT][mM][oO][dD][eE](.*)$ ]]; then
        ARG_CERT_MODE="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[cC][eE][rR][tT][dD][oO][mM][aA][iI][nN](.*)$ ]]; then
        ARG_CERT_DOMAIN="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[cC][fF][pP][oO][rR][tT](.*)$ ]]; then
        ARG_CF_PORT="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[rR][eE][aA][lL][iI][tT][yY](.*)$ ]]; then
        ARG_REALITY="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^argo[pP][rR][oO][tT][oO][cC][oO][lL](.*)$ ]] || [[ "$clean_arg" =~ ^[pP][rR][oO][tT][oO][cC][oO][lL](.*)$ ]]; then
        ARG_ARGO_PROTOCOL="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^argo[pP][oO][rR][tT](.*)$ ]] || [[ "$clean_arg" =~ ^[pP][oO][rR][tT](.*)$ ]]; then
        ARG_ARGO_PORT="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^argo[dD][oO][mM][aA][iI][nN](.*)$ ]] || [[ "$clean_arg" =~ ^[dD][oO][mM][aA][iI][nN](.*)$ ]]; then
        ARG_ARGO_DOMAIN="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^argo[tT][oO][kK][eE][nN](.*)$ ]] || [[ "$clean_arg" =~ ^[tT][oO][kK][eE][nN](.*)$ ]]; then
        ARG_ARGO_TOKEN="${BASH_REMATCH[1]#=}"
    elif [[ "$clean_arg" =~ ^[cC][oO][eE][xX][iI][sS][tT](.*)$ ]]; then
        ARG_COEXIST="${BASH_REMATCH[1]#=}"
        [ -z "$ARG_COEXIST" ] && ARG_COEXIST="1"
    elif [[ "$clean_arg" =~ ^[0-9]+$ ]] || [[ "$clean_arg" =~ ^[yYnN]$ ]]; then
        if [ -z "$ARG_H3" ]; then
            ARG_H3="$clean_arg"
        elif [ -z "$ARG_REALITY" ]; then
            ARG_REALITY="$clean_arg"
        fi
    fi
done

parse_port() {
    local input="$1"
    [ -z "$input" ] && echo "" && return
    if [ "$input" = "n" ] || [ "$input" = "N" ]; then
        echo ""
    elif [ "$input" = "y" ] || [ "$input" = "Y" ]; then
        shuf -i 1000-65000 -n 1
    elif [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "$input"
    else
        echo ""
    fi
}

h3_port=$(parse_port "$ARG_H3")
h2_port=$(parse_port "$ARG_H2")
reality_port=$(parse_port "$ARG_REALITY")

argo_port="${ARG_ARGO_PORT}"
argo_protocol="${ARG_ARGO_PROTOCOL:-quic}"
argo_domain="${ARG_ARGO_DOMAIN}"
argo_token="${ARG_ARGO_TOKEN}"

# ---- Argo 本地回源端口：必须由用户自己设定，已取消默认 8001 ----
# 启用 Argo 时：argoport=<端口> 显式指定；未指定则弹交互录入；
# 非交互环境（curl|bash、无人值守）直接报错退出，绝不静默套用任何默认端口。
argo_need_port=false
[ -n "$argo_domain" ] && [ -n "$argo_token" ] && argo_need_port=true

if [ "$argo_need_port" = true ]; then
    if [ -z "$argo_port" ] || [[ "$argo_port" =~ ^[aA][sS][kK]$ ]]; then
        if [ ! -t 0 ]; then
            red "Argo 本地回源端口必须自己设置：请在命令里加 argoport=<端口>（1-65535）"
            red "本脚本已取消默认 8001；若想现场录入，请 SSH 登录后直接运行（或传 argoport=ask）"
            red "该端口必须与 CF 面板 Public Hostname 的 service http://localhost:<端口> 一致"
            exit 1
        fi
        while true; do
            read -r -p "请输入 Argo 本地回源端口（1-65535，需与 CF 面板 service 一致）：" input_argo_port
            if [[ "$input_argo_port" =~ ^[0-9]+$ ]] && \
               [ "$input_argo_port" -ge 1 ] && [ "$input_argo_port" -le 65535 ]; then
                argo_port="$input_argo_port"
                break
            fi
            yellow "输入无效：必须是 1-65535 的纯数字，不能留空（本脚本不设默认端口）"
        done
    fi
    # 合法性校验：必须是 1-65535 的纯数字，否则会写出非法 config.json 导致 Xray 起不来
    if ! [[ "$argo_port" =~ ^[0-9]+$ ]] || [ "$argo_port" -lt 1 ] || [ "$argo_port" -gt 65535 ]; then
        red "argoport 必须是 1-65535 的纯数字（当前值：$argo_port）"
        exit 1
    fi
    # 不能与本次同时安装的其它 inbound 端口重复
    for used_port in "$h3_port" "$h2_port" "$reality_port"; do
        if [ -n "$used_port" ] && [ "$used_port" = "$argo_port" ]; then
            red "端口冲突：argoport=$argo_port 与 h3/h2/reality 的端口相同，请换一个"
            exit 1
        fi
    done
    green "Argo 本地回源端口：$argo_port（由你设定；CF 面板 service 必须填 http://localhost:$argo_port）"
else
    [ -n "$argo_port" ] && yellow "未启用 Argo（缺 argodomain/argotoken），忽略 argoport=$argo_port"
    argo_port=""
fi

coexist=false
case "$ARG_COEXIST" in
    1|y|Y|yes|YES|on|true) coexist=true ;;
esac

# Argo 4个变量校验：协议、端口、域名、Token必须齐全，否则放弃Argo部署
enable_argo=false
if [ -n "$argo_port" ] && [ -n "$argo_domain" ] && [ -n "$argo_token" ] && [ -n "$argo_protocol" ]; then
    enable_argo=true
fi

if [ -z "$h3_port" ] && [ -z "$h2_port" ] && [ -z "$reality_port" ] && [ "$enable_argo" = false ]; then
    yellow "提示：未检测到任何有效变量（H2、H3、REALITY及Argo隧道均未启用）。"
    exit 0
fi

# ============================================================
# UUID 来源（默认复用甬哥 /root/agsbx/uuid，不再每次随机）
# 优先级：命令行 uuid= > 环境变量 uuid=/UUID= > 甬哥文件 > 随机
# ============================================================
YG_UUID_FILE="${YG_UUID_FILE:-/root/agsbx/uuid}"
if [ ! -s "$YG_UUID_FILE" ] && [ -s "${HOME}/agsbx/uuid" ]; then
    YG_UUID_FILE="${HOME}/agsbx/uuid"
fi

norm_uuid() {
    local u
    u=$(printf '%s' "$1" | tr -d '[:space:]' | tr 'A-F' 'a-f')
    if [[ "$u" =~ ^[0-9a-f]{32}$ ]]; then
        printf '%s-%s-%s-%s-%s' "${u:0:8}" "${u:8:4}" "${u:12:4}" "${u:16:4}" "${u:20:12}"
    else
        printf '%s' "$u"
    fi
}

# 随机 UUID：优先内核接口，容器/裁剪系统里依次回退 uuidgen、openssl、/dev/urandom
gen_random_uuid() {
    local h
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr 'A-F' 'a-f'
    elif command -v openssl >/dev/null 2>&1; then
        h=$(openssl rand -hex 16)
        printf '%s-%s-%s-%s-%s' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
    elif [ -r /dev/urandom ]; then
        h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
        printf '%s-%s-%s-%s-%s' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
    fi
}

read_yg_uuid() {
    [ -s "$YG_UUID_FILE" ] || return 1
    norm_uuid "$(tr -d '[:space:]' < "$YG_UUID_FILE")"
}

uuid_mode="${ARG_UUID}"
uuid_from_env=false
if [ -z "$uuid_mode" ]; then
    if [ -n "${uuid:-}" ]; then
        uuid_mode="$uuid"; uuid_from_env=true
    elif [ -n "${UUID:-}" ]; then
        uuid_mode="$UUID"; uuid_from_env=true
    fi
fi

uuid=""
uuid_source=""
uuid_reused=false
case "$uuid_mode" in
    ""|auto|AUTO)
        if [ -s "$YG_UUID_FILE" ]; then
            uuid="$(read_yg_uuid)"
            uuid_source="甬哥 $YG_UUID_FILE（自动复用）"
            uuid_reused=true
        else
            uuid="$(gen_random_uuid)"
            uuid_source="随机生成（未检测到甬哥 UUID 文件；可传 uuid=yg 强制复用）"
        fi
        ;;
    yg|YG|yongge|agsbx|file|FILE)
        if [ ! -s "$YG_UUID_FILE" ]; then
            red "uuid=yg：未检测到甬哥 UUID 文件 $YG_UUID_FILE，拒绝安装（不生成随机 UUID）"
            red "请先安装甬哥 argosbx，或改用 uuid=<你的UUID> / uuid=random"
            exit 1
        fi
        uuid="$(read_yg_uuid)"
        uuid_source="甬哥 $YG_UUID_FILE（强制复用）"
        uuid_reused=true
        ;;
    ask|ASK)
        if [ ! -t 0 ]; then
            red "uuid=ask 需要交互式终端：请 SSH 登录后直接运行，或改用 uuid=<你的UUID> / uuid=yg"
            exit 1
        fi
        read -r -p "请输入 UUID（直接回车=读取甬哥 $YG_UUID_FILE）：" input_uuid
        if [ -z "$input_uuid" ]; then
            [ -s "$YG_UUID_FILE" ] || { red "甬哥 UUID 文件 $YG_UUID_FILE 不存在"; exit 1; }
            uuid="$(read_yg_uuid)"
            uuid_source="甬哥 $YG_UUID_FILE（交互回车读取）"
            uuid_reused=true
        else
            uuid="$(norm_uuid "$input_uuid")"
            uuid_source="交互录入"
        fi
        ;;
    random|RANDOM|rand|RAND)
        uuid="$(gen_random_uuid)"
        uuid_source="强制随机生成（原版行为）"
        ;;
    *)
        uuid="$(norm_uuid "$uuid_mode")"
        if [ "$uuid_from_env" = true ]; then
            uuid_source="环境变量 uuid= 指定"
        else
            uuid_source="命令行 uuid= 指定"
        fi
        ;;
esac

if ! [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    red "UUID 格式不合法：$uuid"
    red "要求标准 8-4-4-4-12 十六进制（或 32 位无横线），例如 12345678-1234-4abc-8def-0123456789ab"
    exit 1
fi
green "UUID：$uuid（来源：$uuid_source）"

# ============================================================
# 证书模块（模仿甬哥 argosbx / acme-yg 的 /root/ygkkkca 约定）
# certmode=self       自签证书（原版行为，仅适合直连，allowInsecure=1）
# certmode=standalone  80 端口 standalone 申请单域名证书（LE）
# certmode=dns_cf      Cloudflare DNS API（需 CF_Account_ID + CF_Token）
# certmode=dns_dp      腾讯云 DNSPod（需 DP_Id + DP_Key）
# certmode=dns_ali     阿里云（需 Ali_Key + Ali_Secret）
# certmode=manual      直接复用已申请好的 /root/ygkkkca 证书（缺证书仍回退自签）
# certmode=yg          强制使用甬哥 acme-yg 证书，缺证书拒绝安装，绝不回退自签
# ============================================================
CERT_DIR="/root/ygkkkca"
CERT_FILE="${CERT_DIR}/cert.crt"
KEY_FILE="${CERT_DIR}/private.key"
CA_LOG="${CERT_DIR}/ca.log"
cert_mode="${ARG_CERT_MODE}"
cert_domain="${ARG_CERT_DOMAIN}"
work_dir="/etc/xray"
argo_domain="${ARG_ARGO_DOMAIN}"
YG_ACME_URL="https://raw.githubusercontent.com/yonggekkk/acme-yg/main/acme.sh"

# ---- certmode=yg：必须有甬哥 acme-yg 签发的真证书才能继续 ----
if [ "$cert_mode" = "yg" ]; then
    [[ $EUID -eq 0 ]] || { red "certmode=yg 必须在 root 用户下运行"; exit 1; }

    if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
        yellow "未检测到 /root/ygkkkca 证书，准备调用甬哥 acme-yg 证书脚本（交互式）"
        if [ ! -t 0 ]; then
            red "acme-yg 是交互式菜单脚本，当前不是交互终端，无法自动调起"
            red "请先单独执行：bash <(curl -Ls $YG_ACME_URL)"
            red "菜单依次选 1 → 3（DNS API 域名证书），完成后用 certmode=yg 重跑本脚本"
            exit 1
        fi
        bash <(curl -Ls "$YG_ACME_URL")
        echo
    fi

    # 仍未拿到证书就拒绝安装，绝不生成自签证书
    if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
        red "certmode=yg：仍未检测到 /root/ygkkkca/cert.crt + private.key，拒绝安装"
        red "请先完成申请：bash <(curl -Ls $YG_ACME_URL)"
        exit 1
    fi

    # 域名来源：显式 certdomain > ca.log > 证书 SAN
    # 证书里已经签好域名时，certdomain 完全可以不传（「证书里已设置域名」即此场景）
    if [ -z "$cert_domain" ]; then
        cert_domain=$(cat "$CA_LOG" 2>/dev/null | tr -d ' \r\n\t')
    fi

    # 证书本身：能解析、未过期、公私钥成对
    command -v openssl >/dev/null 2>&1 || { red "缺少 openssl，无法校验证书"; exit 1; }
    openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1 || { red "cert.crt 不是有效的 X509 证书"; exit 1; }
    openssl x509 -in "$CERT_FILE" -noout -checkend 0 >/dev/null 2>&1 || { red "cert.crt 已过期，请重新申请"; exit 1; }
    cert_pub=$(openssl x509 -in "$CERT_FILE" -pubkey -noout 2>/dev/null)
    key_pub=$(openssl pkey -in "$KEY_FILE" -pubout -passin pass: 2>/dev/null)
    if [ -z "$cert_pub" ] || [ "$cert_pub" != "$key_pub" ]; then
        red "cert.crt 与 private.key 不是一对（确认 acme-yg 申请成功、文件未被覆盖）"
        exit 1
    fi

    # SAN 明细：既用于 SNI 自动提取，也用于后面的匹配校验
    cert_san=$(openssl x509 -in "$CERT_FILE" -noout -text 2>/dev/null | \
               grep -A1 'Subject Alternative Name' | tail -1 | tr ',' '\n' | tr -d ' ')

    # ca.log 缺失 / 记成泛域名 / IP 时，直接从证书 SAN 取第一个具体 DNS 名
    if [ -z "$cert_domain" ] || [[ "$cert_domain" == *'*'* ]] || \
       [[ "$cert_domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$cert_domain" == *:* ]]; then
        cert_domain_auto=$(printf '%s\n' "$cert_san" | sed -n 's/^DNS:\([^*][^ ]*\)$/\1/p' | head -1)
        if [ -n "$cert_domain_auto" ]; then
            yellow "certdomain 未传或 ca.log 无效，自动采用证书 SAN 域名：$cert_domain_auto"
            cert_domain="$cert_domain_auto"
        fi
    fi
    # 泛域名证书无法猜出具体子域，仍需显式指定
    if [ -z "$cert_domain" ] || [[ "$cert_domain" == *'*'* ]] || \
       [[ "$cert_domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$cert_domain" == *:* ]]; then
        red "certmode=yg：SNI 不能为空 / 通配符 / IP（当前值：'$cert_domain'）"
        red "若是泛域名证书，请显式传 certdomain=证书覆盖的具体子域名"
        red "证书 SAN：$cert_san"
        exit 1
    fi

    if [ -n "$cert_san" ]; then
        if ! echo "$cert_san" | grep -Fq "DNS:$cert_domain"; then
            cert_parent=$(echo "$cert_domain" | cut -d. -f2-)
            if ! echo "$cert_san" | grep -Fq "DNS:*.$cert_parent"; then
                red "证书 SAN 不包含 $cert_domain（SNI 不匹配，客户端会报证书错误）"
                red "证书 SAN：$cert_san"
                red "若照抄了示例 certdomain=node.example.com，请改成真实域名；最省事是不传 certdomain，让脚本自动读取"
                exit 1
            fi
        fi
    fi
    green "certmode=yg 校验通过：$cert_domain（甬哥 /root/ygkkkca 真证书）"
fi

if { [ "$cert_mode" = "standalone" ] || [[ "$cert_mode" == dns_* ]]; } && \
   { [ ! -s "$CERT_FILE" ] || [ "$(cat "$CA_LOG" 2>/dev/null)" != "$cert_domain" ]; }; then
    [[ $EUID -eq 0 ]] || { red "申请证书必须在 root 用户下运行"; exit 1; }
    [ -n "$cert_domain" ] || { red "申请证书必须提供 certdomain=你的域名"; exit 1; }
    green "正在通过 acme.sh（${cert_mode}）为 ${cert_domain} 申请 Let's Encrypt ECC 证书..."
    if [ ! -s "$HOME/.acme.sh/acme.sh" ]; then
        curl -s https://get.acme.sh | sh -s email="admin@${cert_domain}" >/dev/null 2>&1
    fi
    ACME="$HOME/.acme.sh/acme.sh"
    [ -s "$ACME" ] || { red "acme.sh 安装失败，请检查网络"; exit 1; }
    "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1
    if [ "$cert_mode" = "standalone" ]; then
        # 独立 80 端口模式：先释放 80，域名必须已解析到本机（灰云 / 关闭 CDN）
        if command -v fuser >/dev/null 2>&1; then fuser -k 80/tcp >/dev/null 2>&1 || true; fi
        "$ACME" --issue -d "$cert_domain" --standalone -k ec-256 --server letsencrypt --insecure || { red "证书申请失败"; exit 1; }
    else
        "$ACME" --issue --dns "$cert_mode" -d "$cert_domain" -k ec-256 --server letsencrypt --insecure || { red "证书申请失败，请检查 DNS API 凭证"; exit 1; }
    fi
    mkdir -p "$CERT_DIR"
    "$ACME" --install-cert -d "$cert_domain" --ecc \
        --key-file "$KEY_FILE" --fullchain-file "$CERT_FILE" \
        --reloadcmd "systemctl restart xray" || { red "证书安装失败"; exit 1; }
    echo "$cert_domain" > "$CA_LOG"
    (crontab -l 2>/dev/null | grep -v 'acme.sh --cron'; echo "0 0 * * * $ACME --cron >/dev/null 2>&1") | crontab -
fi

if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
    tls_cert="$CERT_FILE"
    tls_key="$KEY_FILE"
    if [ -z "$cert_domain" ]; then
        cert_domain=$(cat "$CA_LOG" 2>/dev/null | tr -d ' \r\n\t')
    fi
    if [ -z "$cert_domain" ] || [[ "$cert_domain" == *'*'* ]]; then
        cert_domain=$(openssl x509 -in "$CERT_FILE" -noout -text 2>/dev/null | \
                      grep -A1 'Subject Alternative Name' | tail -1 | tr ',' '\n' | tr -d ' ' | \
                      sed -n 's/^DNS:\([^*][^ ]*\)$/\1/p' | head -1)
    fi
    [ -n "$cert_domain" ] || cert_domain="$argo_domain"
    sni="$cert_domain"
    insecure="0"
    green "已启用域名证书：$cert_domain（/root/ygkkkca），节点 insecure=0"
else
    tls_cert="${work_dir}/cert.pem"
    tls_key="${work_dir}/private.key"
    sni="bing.com"
    insecure="1"
    yellow "未检测到域名证书，回退自签证书（bing.com），节点 allowInsecure=1，不可套 CDN"
fi

work_dir="/etc/xray"
[[ $EUID -ne 0 ]] && red "请在root用户下运行" && exit 1

# 1. 初始化（systemctl stop xray 只作用于本脚本的 xray.service，不影响甬哥 xr.service）
systemctl stop xray 2>/dev/null || rc-service xray stop 2>/dev/null || true
if [ "$coexist" = true ]; then
    pkill -9 -f "${work_dir}/cloudflared" 2>/dev/null || true
    yellow "共存模式：仅清理 /etc/xray/cloudflared，其它 cloudflared（含甬哥 argo.service）保持运行"
else
    pkill -9 -f cloudflared 2>/dev/null || true
fi

green "正在初始化环境，请耐心等待..."
if command -v apt >/dev/null 2>&1; then
    apt update -y >/dev/null 2>&1
    apt install -y curl wget unzip openssl iptables coreutils >/dev/null 2>&1
elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget unzip openssl iptables coreutils >/dev/null 2>&1
elif command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    apk add --no-cache bash curl wget unzip openssl iptables coreutils >/dev/null 2>&1
else
    red "未识别的系统包管理器，无法自动安装依赖！"
    exit 1
fi

# 保险校验：确保核心工具已就绪
for cmd in curl unzip openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        red "错误：系统缺少必要组件 [$cmd]，且自动安装失败，请手动安装后重试！"
        exit 1
    fi
done

# 2. 下载 Xray-core
echo "正在下载 Xray-core..."
mkdir -p "${work_dir}"
ARCH_RAW=$(uname -m)
case "${ARCH_RAW}" in
    'x86_64' | 'amd64') ARCH='64' ;;
    'aarch64' | 'arm64') ARCH='arm64-v8a' ;;
    *) ARCH='64' ;;
esac

download_file "${work_dir}/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH}.zip" || exit 1
unzip -qo "${work_dir}/xray.zip" -d "${work_dir}/" && rm -f "${work_dir}/xray.zip"
chmod +x ${work_dir}/xray

# 如果开启了 Argo，下载 cloudflared
if [ "$enable_argo" = true ]; then
    echo "正在下载 Cloudflared..."
    ARCH_CF=$(uname -m)
    case "${ARCH_CF}" in
        'x86_64' | 'amd64') CF_ARCH='amd64' ;;
        'aarch64' | 'arm64') CF_ARCH='arm64' ;;
        *) CF_ARCH='amd64' ;;
    esac
    download_file "${work_dir}/cloudflared" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" || exit 1
    chmod +x "${work_dir}/cloudflared"
fi

# 3. 写入已解析的 UUID（不再随机生成）、自签证书与密钥对
echo "写入 UUID（来源：$uuid_source）、自签证书及密钥对..."
h3_path="${uuid}-xu" 
argo_path="${uuid}-argo"
h2_path="${uuid}-xc"
ym_vl_re="addons.mozilla.org"

# 仅在未使用域名证书时才生成自签证书
if [ "$sni" = "bing.com" ]; then
    openssl ecparam -genkey -name prime256v1 -out "${work_dir}/private.key"
    openssl req -new -x509 -days 3650 -key "${work_dir}/private.key" -out "${work_dir}/cert.pem" -subj "/CN=bing.com"
fi

# Reality 密钥对
key_pair=$("${work_dir}/xray" x25519)
private_key_x=$(echo "$key_pair" | awk -F':' '/PrivateKey/ {print $2}' | xargs)
public_key_x=$(echo "$key_pair" | awk -F':' '/Password/ {print $2}' | xargs)
short_id_x=$(date +%s%N | sha256sum | cut -c 1-8)

# 4. 构建多 Inbound 配置 (TCP-Reality-Vision + H3-XHTTP + Argo-XHTTP)

inbounds_arr=()

if [ -n "$reality_port" ]; then
    inbounds_arr+=( "{
      \"tag\": \"tcp-reality\",
      \"listen\": \"::\",
      \"port\": $reality_port,
      \"protocol\": \"vless\",
      \"settings\": {
        \"clients\": [{\"id\": \"$uuid\", \"flow\": \"xtls-rprx-vision\"}],
        \"decryption\": \"none\"
      },
      \"streamSettings\": {
        \"network\": \"tcp\",
        \"security\": \"reality\",
        \"realitySettings\": {
          \"fingerprint\": \"chrome\",
          \"target\": \"$ym_vl_re:443\",
          \"serverNames\": [\"$ym_vl_re\"],
          \"privateKey\": \"$private_key_x\",
          \"shortIds\": [\"$short_id_x\"]
        }
      },
      \"sniffing\": {\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"], \"metadataOnly\": false}
    }" )
fi

if [ -n "$h3_port" ]; then
    inbounds_arr+=( "{
      \"tag\": \"xhttp-h3\",
      \"listen\": \"::\",
      \"port\": $h3_port,
      \"protocol\": \"vless\",
      \"settings\": {
        \"clients\": [{\"id\": \"$uuid\", \"flow\": \"\"}],
        \"decryption\": \"none\"
      },
      \"streamSettings\": {
        \"network\": \"xhttp\",
        \"security\": \"tls\",
        \"xhttpSettings\": {
          \"mode\": \"auto\",
          \"path\": \"/$h3_path\"
        },
        \"tlsSettings\": {
          \"alpn\": [\"h3\"],
          \"certificates\": [{\"certificateFile\": \"$tls_cert\", \"keyFile\": \"$tls_key\"}]
        }
      },
      \"sniffing\": {\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"], \"metadataOnly\": false}
    }" )
fi

# 模仿甬哥 Vless-xhttp-tls-TCP/UDP：TCP(h2/http1.1) 直连 + CDN 回源，用同一张证书
if [ -n "$h2_port" ]; then
    inbounds_arr+=( "{
      \"tag\": \"xhttp-h23\",
      \"listen\": \"::\",
      \"port\": $h2_port,
      \"protocol\": \"vless\",
      \"settings\": {
        \"clients\": [{\"id\": \"$uuid\", \"flow\": \"\"}],
        \"decryption\": \"none\"
      },
      \"streamSettings\": {
        \"network\": \"xhttp\",
        \"security\": \"tls\",
        \"xhttpSettings\": {
          \"mode\": \"auto\",
          \"path\": \"/$h2_path\"
        },
        \"tlsSettings\": {
          \"alpn\": [\"h2\", \"http/1.1\"],
          \"certificates\": [{\"certificateFile\": \"$tls_cert\", \"keyFile\": \"$tls_key\"}]
        }
      },
      \"sniffing\": {\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"], \"metadataOnly\": false}
    }" )
fi

if [ "$enable_argo" = true ]; then
    inbounds_arr+=( "{
      \"tag\": \"xhttp-argo\",
      \"listen\": \"127.0.0.1\",
      \"port\": $argo_port,
      \"protocol\": \"vless\",
      \"settings\": {
        \"clients\": [{\"id\": \"$uuid\"}],
        \"decryption\": \"none\"
      },
      \"streamSettings\": {
        \"network\": \"xhttp\",
        \"security\": \"none\",
        \"xhttpSettings\": {
          \"path\": \"/$argo_path\",
          \"mode\": \"auto\"
        }
      },
      \"sniffing\": {\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"], \"metadataOnly\": false}
    }" )
fi

inbounds_json=$(IFS=,; echo "${inbounds_arr[*]}")

cat > "${work_dir}/config.json" << EOF
{
  "log": {
    "loglevel": "warning",
    "error": "${work_dir}/xray.log"
  },
  "inbounds": [
    $inbounds_json
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
EOF

# 5. 配置系统服务并启动
if pidof systemd >/dev/null 2>&1 || [ -d /etc/systemd/system ]; then
    green "正在启动 Xray-core..."
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=${work_dir}/xray run -config ${work_dir}/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now xray
else
    green "正在启动 Xray-core..."
    cat > /etc/init.d/xray << 'EOF'
#!/sbin/openrc-run
description="Xray Service"
command="/etc/xray/xray"
command_args="run -config /etc/xray/config.json"
pidfile="/run/xray.pid"
command_background="yes"

depend() {
    need net
}
EOF
    chmod +x /etc/init.d/xray
    rc-update add xray default
    rc-service xray restart
fi

# 根据协议自动分配连接数：quic 默认 1，http2 设为 4
argo_connections="1"
argo_proto_lower=$(echo "$argo_protocol" | tr '[:upper:]' '[:lower:]')
if [ "$argo_proto_lower" = "http2" ]; then
    argo_connections="4"
fi

# 如果开启了 Argo，启动 cloudflared 服务
if [ "$enable_argo" = true ]; then
    green "正在启动 Cloudflare Argo 固定隧道 (协议: ${argo_protocol}, 连接数: ${argo_connections})..."
    
    # 写入标准的 systemd 服务文件
    cat <<EOF > /etc/systemd/system/cloudflared.service
[Unit]
Description=Cloudflare Tunnels Service
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=${work_dir}/cloudflared tunnel --no-autoupdate --retries 5 --grace-period 1s --protocol ${argo_protocol} --ha-connections ${argo_connections} run --token ${argo_token}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # 重载配置并启动托管服务
    systemctl daemon-reload
    if [ "$coexist" = true ]; then
        systemctl disable cloudflared >/dev/null 2>&1 || true
        systemctl stop cloudflared >/dev/null 2>&1 || true
        yellow "共存模式：cloudflared.service 已创建，但未启用开机自启、未启动"
        yellow "切换到易分享：systemctl stop argo; systemctl start cloudflared"
        yellow "切回甬哥：    systemctl stop cloudflared; systemctl start argo"
    else
        systemctl enable --now cloudflared
    fi
fi

# 6. 放行对应的防火墙端口 (仅直连端口需要放行，Argo 不需要)

for p in "$h3_port" "$h2_port" "$reality_port"; do
    [ -z "$p" ] && continue
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow $p/tcp >/dev/null 2>&1
        ufw allow $p/udp >/dev/null 2>&1
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -A INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null
        iptables -A INPUT -p udp --dport $p -j ACCEPT 2>/dev/null
    fi
done

# 7. 获取 IP 并输出节点链接与 Base64 编码
echo "获取 Base 64 节点链接中..."
raw_ip=$(curl -4 -sm 2 ip.sb || curl -6 -sm 2 ip.sb)
if [[ "$raw_ip" =~ : ]]; then
    server_ip="[$raw_ip]"
else
    server_ip="$raw_ip"
fi

# 定义小型大写字母映射表
declare -A sc=([A]=ᴀ [B]=ʙ [C]=ᴄ [D]=ᴅ [E]=ᴇ [F]=ꜰ [G]=ɢ [H]=ʜ [I]=ɪ [J]=ᴊ [K]=ᴋ [L]=ʟ [M]=ᴍ [N]=ɴ [O]=ᴏ [P]=ᴘ [Q]=ꞯ [R]=ʀ [S]=ꜱ [T]=ᴛ [U]=ᴜ [V]=ᴠ [W]=ᴡ [X]=x [Y]=ʏ [Z]=ᴢ)

# 多源 GeoIP 获取：优先 ipinfo，失败后回退 ip.sb
uc=$(curl -sm 3 "https://ipinfo.io/country" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
if [ -z "$uc" ] || [ ${#uc} -ne 2 ]; then
    uc=$(curl -sm 3 "https://api.ip.sb/geoip" | grep -o '"country_code":"[^"]*"' | cut -d'"' -f4 | tr '[:lower:]' '[:upper:]')
fi

isp="${sc[${uc:0:1}]}${sc[${uc:1:1}]}"
[[ -z "$isp" ]] && isp="ɴᴅ"

ESS="ᴇꜱꜱ"
cfip_h2="www.visa.com.hk"
cfip_h3="www.teamviewer.com"
cfport="${ARG_CF_PORT:-443}"
[[ "$cfport" =~ ^[0-9]+$ ]] || cfport="443"

> "${work_dir}/url.txt"
echo "$uuid" > "${work_dir}/uuid.txt"
if [ "$enable_argo" = true ]; then
    echo "$argo_port" > "${work_dir}/argo_port.txt"
    echo "http://localhost:${argo_port}" > "${work_dir}/cf_service.txt"
fi
[ -n "$reality_port" ] && echo "vless://${uuid}@${server_ip}:${reality_port}?encryption=none&security=reality&sni=${ym_vl_re}&fp=chrome&pbk=${public_key_x}&sid=${short_id_x}&type=tcp&flow=xtls-rprx-vision#${isp}%20Reality Vision%20${ESS}" >> "${work_dir}/url.txt"
[ -n "$h3_port" ] && echo "vless://${uuid}@${server_ip}:${h3_port}?encryption=none&security=tls&sni=${sni}&alpn=h3&fp=chrome&type=xhttp&mode=auto&path=/${h3_path}&allowInsecure=${insecure}#${isp}%20H3-XHTTP%20${ESS}" >> "${work_dir}/url.txt"
if [ -n "$h2_port" ]; then
    echo "vless://${uuid}@${server_ip}:${h2_port}?encryption=none&security=tls&sni=${sni}&fp=chrome&type=xhttp&mode=auto&path=/${h2_path}&allowInsecure=${insecure}#${isp}%20XHTTP-TCP%20${ESS}" >> "${work_dir}/url.txt"
    if [ "$insecure" = "0" ]; then
        case "$h2_port" in
        443|2053|2083|2087|2096|8443)
            echo "vless://${uuid}@${cfip_h2}:${h2_port}?encryption=none&security=tls&sni=${sni}&host=${sni}&fp=chrome&type=xhttp&mode=auto&path=/${h2_path}&allowInsecure=0#${isp}%20XHTTP-CDN-TCP%20${ESS}" >> "${work_dir}/url.txt"
            echo "vless://${uuid}@${cfip_h3}:${h2_port}?encryption=none&security=tls&sni=${sni}&host=${sni}&alpn=h3&fp=chrome&type=xhttp&mode=auto&path=/${h2_path}&allowInsecure=0#${isp}%20XHTTP-CDN-UDP%20${ESS}" >> "${work_dir}/url.txt"
            ;;
        esac
    fi
fi
if [ "$enable_argo" = true ]; then
    echo "vless://${uuid}@${cfip_h2}:${cfport}?encryption=none&security=tls&alpn=h2&sni=${argo_domain}&fp=chrome&type=xhttp&mode=auto&host=${argo_domain}&path=/${argo_path}#${isp}%20H2-Argo XHTTP%20${ESS}" >> "${work_dir}/url.txt"
    echo "vless://${uuid}@${cfip_h3}:${cfport}?encryption=none&security=tls&alpn=h3&sni=${argo_domain}&fp=chrome&type=xhttp&mode=auto&host=${argo_domain}&path=/${argo_path}#${isp}%20H3-Argo XHTTP%20${ESS}" >> "${work_dir}/url.txt"
fi

base64_str=$(cat "${work_dir}/url.txt" | base64 | tr -d '\n' | tr -d '\r')

clear
green "=========================================================================================="
green " Base64 节点链接 Xray-core "
green "=========================================================================================="
green "$base64_str"
green "=========================================================================================="
echo " UUID：$uuid（来源：$uuid_source）"
echo " UUID 记录文件：${work_dir}/uuid.txt"
if [ "$uuid_reused" = true ]; then
    yellow " 已复用甬哥 UUID：两套节点 id 相同，但甬哥是 VLESS ENC（encryption+flow），本脚本是 encryption=none，客户端参数不可互换"
    yellow " 本脚本 path 为 /${uuid}-xu、/${uuid}-xc、/${uuid}-argo；若甬哥也开了 xupt/xcpt，前两个 path 会同名，按 path 分流请用不同子域名"
fi
echo " 证书模式：$cert_mode | SNI：$sni | allowInsecure=$insecure"
echo " 证书文件：$tls_cert / $tls_key"
if [ "$cert_mode" = "yg" ]; then
    green " 强制证书已生效：缺少 /root/ygkkkca 真证书时本脚本会直接拒绝安装"
    if [ -z "$h2_port" ] && [ -z "$h3_port" ] && [ -z "$reality_port" ]; then
        yellow " 当前仅有 Argo 明文 inbound，证书已校验但未用于 TLS inbound（TLS 由 CF 边缘终结）"
    fi
    yellow " 甬哥 acme-yg 不带 --reloadcmd，证书续期后需手动重载：systemctl restart xray"
    yellow " 建议补：bash ~/.acme.sh/acme.sh --install-cert -d $cert_domain --ecc --key-file $KEY_FILE --fullchain-file $CERT_FILE --reloadcmd \"systemctl restart xray\""
    yellow " 若甬哥 xr/sb 也用这套证书，reloadcmd 里请一并加上 systemctl restart xr sb"
fi
[ -n "$h2_port" ] && echo " H2(TCP) 端口：$h2_port；套 CDN 需：CF 开启 HTTP/3、SSL 模式 Full(strict)、回源端口为 443 系"
[ -n "$h3_port" ] && echo " H3(UDP) 端口：$h3_port；直连请放行该端口的 UDP（云面板安全组也要放行）"
if [ "$enable_argo" = true ]; then
    echo " Argo 本地端口：$argo_port（仅监听 127.0.0.1，无需放行公网）；客户端连 CF 边缘端口：$cfport"
    echo " 端口记录文件：${work_dir}/argo_port.txt"
    green " CF 面板 Public Hostname 的 service 请原样填：http://localhost:${argo_port}"
    echo " 该值已写入 ${work_dir}/cf_service.txt，可直接复制；用 cat ${work_dir}/cf_service.txt 查看"
    yellow " 重要：run --token 是远端管理隧道，回源映射存在 CF 云端，脚本读不到也改不了，必须人工核对"
    echo " 端口一致性自检（两条）："
    echo "   ss -lntp | grep ${argo_port}     # 应看到 xray 监听 127.0.0.1:${argo_port}"
    echo "   一键比对：echo 本地=\$(cat ${work_dir}/argo_port.txt) CF=\$(journalctl -u cloudflared -n 200 --no-pager | grep -oE 'http://localhost:[0-9]+' | tail -1)"
    echo "   journalctl -u cloudflared -n 50 --no-pager | grep -iE 'refused|502|origin'"
    yellow " 若日志出现 connection refused / 502，就是 CF 面板端口与本地不一致；改过 argoport 必须同步改面板"
    yellow " 注意：节点链接里的 $cfport 是客户端连 CF 边缘的端口，与回源端口 $argo_port 完全无关，不要改错"
fi
[ "$coexist" = true ] && echo " 共存模式：本脚本 cloudflared 未自启，用 systemctl start/stop cloudflared 手动切换"
echo " 单条节点明文见：${work_dir}/url.txt"

echo " 一键卸载 (如需移除，请执行以下指令)："
yellow " bash <(curl -Ls https://raw.githubusercontent.com/eishare/Xray-go/main/uninstall.sh)"
