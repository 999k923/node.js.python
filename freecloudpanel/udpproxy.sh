#!/bin/bash

# 使用说明:
# 安卓 Karing 到设置→TLS→打开跳过证书验证
# 1. 移除文件夹所有文件。
# 2. 将当前文件 (udpproxy.sh) 上传进文件夹。
# 3. 设置启动命令: bash udpproxy.sh
# 4. 选择你想使用的协议 hy2 or tuic。（推荐tuic，内存占用低）
# 5. 复制生成的链接到代理工具并启用。
# 6. 如若想换协议，得删除proxy_flie文件夹再重新启动。

set -euo pipefail
IFS=$'\n\t'

# ===================== 创建工作目录 =====================
WORK_DIR="proxy_files"
mkdir -p "$WORK_DIR"
echo "📁 工作目录: $WORK_DIR"


# ===================== 配置常量 =====================
MASQ_DOMAINS=(
    "www.microsoft.com" "www.cloudflare.com" "www.bing.com"
    "www.apple.com" "www.amazon.com" "www.wikipedia.org"
    "cdnjs.cloudflare.com" "cdn.jsdelivr.net" "static.cloudflareinsights.com"
    "www.speedtest.net"
)
MASQ_DOMAIN=${MASQ_DOMAINS[$RANDOM % ${#MASQ_DOMAINS[@]}]}

# ===================== 服务选择 =====================
SELECTED_SERVICE=""
LINK_FILE=""

# 检查是否存在标记文件
if [[ -f "$WORK_DIR/hy2_link.txt" ]]; then
    SELECTED_SERVICE="hy2"
    LINK_FILE="$WORK_DIR/hy2_link.txt"
    echo "📂 检测到 hy2_link.txt，自动选择 Hysteria 2 服务"
elif [[ -f "$WORK_DIR/tuic_link.txt" ]]; then
    SELECTED_SERVICE="tuic"
    LINK_FILE="$WORK_DIR/tuic_link.txt"
    echo "📂 检测到 tuic_link.txt，自动选择 TUIC 服务"
else
    # 如果没有标记文件，让用户选择服务
    echo "🚀 统一代理服务部署"
    echo "请选择要运行的服务:"
    echo "1) Hysteria 2"
    echo "2) TUIC v5 over QUIC (推荐)"
    read -rp "请输入选项 (1-2): " choice
    case "$choice" in
        1)
            SELECTED_SERVICE="hy2"
            LINK_FILE="$WORK_DIR/hy2_link.txt"
            ;;
        2)
            SELECTED_SERVICE="tuic"
            LINK_FILE="$WORK_DIR/tuic_link.txt"
            ;;
        *) 
            echo "❌ 无效选择: $choice"
            exit 1
            ;;
    esac
    echo "✅ 选择服务: $SELECTED_SERVICE"
fi

# 根据选择设置标记文件（如果不存在）
if [[ ! -f "$LINK_FILE" ]]; then
    touch "$LINK_FILE"
    # 移除其他服务的标记文件
    rm -f "$WORK_DIR/hy2_link.txt" "$WORK_DIR/tuic_link.txt" 2>/dev/null || true
    touch "$LINK_FILE"
fi

echo "🎯 随机选择SNI伪装域名: $MASQ_DOMAIN"

# ===================== 服务特定变量 =====================
DEFAULT_PORT="28888"
if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
    HY2_VERSION="app%2Fv2.6.3"
    SERVER_CONFIG="$WORK_DIR/server.json"
    CERT_PEM="$WORK_DIR/c.pem"
    KEY_PEM="$WORK_DIR/k.pem"
    AUTH_PASSWORD=""
    HY2_BIN=""
    SERVICE_PORT=""
elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
    SERVER_TOML="$WORK_DIR/server.toml"
    CERT_PEM="$WORK_DIR/tuic-cert.pem"
    KEY_PEM="$WORK_DIR/tuic-key.pem"
    TUIC_BIN="$WORK_DIR/tuic-server"
    TUIC_UUID=""
    TUIC_PASSWORD=""
    SERVICE_PORT=""
fi

# ===================== 加载现有配置 =====================
load_existing_config() {
    if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
        if [[ -f "$SERVER_CONFIG" ]]; then
            local config_port=$(grep '"listen":' "$SERVER_CONFIG" | sed -E 's/.*":([0-9]+)".*/\1/' || echo "")
            AUTH_PASSWORD=$(grep '"password":' "$SERVER_CONFIG" | sed -E 's/.*"password": "([^"]+)".*/\1/' || echo "")
            if [[ -n "$config_port" && -n "$AUTH_PASSWORD" ]]; then
                SERVICE_PORT="$config_port"
                echo "📂 检测到已有配置，加载成功。"
                echo "✅ 端口: $SERVICE_PORT"
                echo "✅ 密码: (已加载)"
                return 0
            fi
        fi
        return 1
    elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
        if [[ -f "$SERVER_TOML" ]]; then
            local config_port=$(grep '^server = ' "$SERVER_TOML" | sed -E 's/.*:(.*)\"/\1/')
            TUIC_UUID=$(grep '^\[users\]' -A1 "$SERVER_TOML" | tail -n1 | awk '{print $1}')
            TUIC_PASSWORD=$(grep '^\[users\]' -A1 "$SERVER_TOML" | tail -n1 | awk -F'"' '{print $2}')
            if [[ -n "$config_port" && -n "$TUIC_UUID" && -n "$TUIC_PASSWORD" ]]; then
                SERVICE_PORT="$config_port"
                echo "📂 检测到已有配置，加载中..."
                echo "✅ 端口: $SERVICE_PORT"
                echo "✅ UUID: $TUIC_UUID"
                echo "✅ 密码: $TUIC_PASSWORD"
                return 0
            fi
        fi
        return 1
    fi
}

# ===================== 端口设置 (非交互式, 环境变量优先) =====================
set_port() {
    local env_port="${SERVER_PORT:-}"
    if [[ -n "$env_port" ]]; then
        SERVICE_PORT="$env_port"
        if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
            echo "ℹ️ 从环境变量读取 Hysteria 2 端口: $SERVICE_PORT"
        else
            echo "✅ 从环境变量读取 TUIC(QUIC) 端口: $SERVICE_PORT"
        fi
    else
        SERVICE_PORT="$DEFAULT_PORT"
        echo "ℹ️ 未设置 SERVER_PORT 环境变量，使用默认端口: $SERVICE_PORT"
    fi
}

# ===================== 统一证书生成 (带过期检测) =====================
generate_certificate() {
    local cert_exists=false
    local key_exists=false
    local cert_valid=true
    
    if [[ -f "$CERT_PEM" ]]; then
        cert_exists=true
    fi
    if [[ -f "$KEY_PEM" ]]; then
        key_exists=true
    fi
    
    if [[ "$cert_exists" == true && "$key_exists" == true ]]; then
        # 检查证书是否过期
        if openssl x509 -checkend 0 -noout -in "$CERT_PEM" 2>/dev/null; then
            echo "🔐 检测到有效证书，跳过生成"
            return 0
        else
            echo "🔐 检测到证书已过期，重新生成..."
            cert_valid=false
        fi
    else
        echo "🔐 证书或私钥不存在，生成新证书..."
        cert_valid=false
    fi
    
    local cert_days=90
    if [[ "$SELECTED_SERVICE" == "tuic" ]]; then
        cert_days=365
    fi
    
    if [[ "$cert_valid" == false ]]; then
        echo "🔐 生成自签证书(ECDSA-P256, $cert_days天)..."
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$KEY_PEM" -out "$CERT_PEM" -subj "/CN=$MASQ_DOMAIN" -days "$cert_days" -nodes >/dev/null 2>&1
        chmod 600 "$KEY_PEM"
        chmod 644 "$CERT_PEM"
        echo "✅ 证书生成完成"
    fi
}

# ===================== 二进制文件下载 =====================
check_binary() {
    if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
        local os_name arch url
        os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
        case "$os_name" in
            linux*) os_name="linux" ;;
            darwin*) os_name="darwin" ;;
            *) echo "❌ 不支持的操作系统: $os_name"; return 1 ;;
        esac
        arch=$(uname -m)
        case "$arch" in
            x86_64|amd64) arch="amd64" ;;
            aarch64|arm64) arch="arm64" ;;
            *) echo "❌ 不支持的架构: $arch"; return 1 ;;
        esac
        
        HY2_BIN="$WORK_DIR/hysteria-$os_name-$arch"
        
        if [[ -x "$HY2_BIN" ]]; then
            echo "✅ 已找到 hysteria-server"
            return 0
        fi
        
        echo "📥 未找到 hysteria-server，正在下载 $HY2_VERSION 版本..."
        url="https://github.com/apernet/hysteria/releases/download/$HY2_VERSION/hysteria-linux-amd64"
        
        if command -v curl >/dev/null 2>&1; then
            if curl -L -f --connect-timeout 30 -o "$HY2_BIN" "$url"; then
                chmod +x "$HY2_BIN"
                echo "✅ hysteria-server 下载完成"
                return 0
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget --timeout=30 -O "$HY2_BIN" "$url"; then
                chmod +x "$HY2_BIN"
                echo "✅ hysteria-server 下载完成"
                return 0
            fi
        fi
        
        echo "❌ 下载失败。请检查网络或手动下载 $url"
        return 1
    elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
        if [[ -x "$TUIC_BIN" ]]; then
            echo "✅ 已找到 tuic-server"
            return 0
        fi
        echo "📥 未找到 tuic-server，正在下载..."
        ARCH=$(uname -m)
        if [[ "$ARCH" != "x86_64" ]]; then
            echo "❌ 暂不支持架构: $ARCH"
            exit 1
        fi
        TUIC_URL="https://github.com/Itsusinn/tuic/releases/download/v1.3.5/tuic-server-x86_64-linux"
        if curl -L -f -o "$TUIC_BIN" "$TUIC_URL"; then
            chmod +x "$TUIC_BIN"
            echo "✅ tuic-server 下载完成"
        else
            echo "❌ 下载失败，请手动下载 $TUIC_URL"
            exit 1
        fi
    fi
}

# ===================== 配置生成 =====================
generate_config() {
    if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
        cat > "$SERVER_CONFIG" << EOF
{
    "listen": ":$SERVICE_PORT",
    "tls": {
        "cert": "$CERT_PEM",
        "key": "$KEY_PEM",
        "alpn": ["h3"]
    },
    "auth": {
        "type": "password",
        "password": "$AUTH_PASSWORD"
    },
    "quic": {
        "max_idle_timeout": "20s",
        "keep_alive_period": "10s",
        "disable_path_mtu_discovery": false,
        "initial_stream_window_size": 4194304,
        "initial_connection_window_size": 8388608,
        "max_streams": 8,
        "handshake_timeout": "5s",
        "disable_stateless_reset": false,
        "initial_max_data": 4194304,
        "initial_max_stream_data": 2097152
    },
    "masquerade": {
        "type": "proxy",
        "proxy": {
            "url": "https://$MASQ_DOMAIN",
            "rewriteHost": true
        }
    },
    "log": {
        "level": "warn",
        "timestamp": true,
        "output": "stderr"
    }
}
EOF
    elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
        cat > "$SERVER_TOML" <<EOF
log_level = "off"
server = "0.0.0.0:${SERVICE_PORT}"

udp_relay_ipv6 = false
zero_rtt_handshake = true
dual_stack = false
auth_timeout = "10s"
task_negotiation_timeout = "5s"
gc_interval = "10s"
gc_lifetime = "10s"
max_external_packet_size = 8192

[users]
${TUIC_UUID} = "${TUIC_PASSWORD}"

[tls]
self_sign = false
certificate = "$CERT_PEM"
private_key = "$KEY_PEM"
alpn = ["h3"]

[restful]
addr = "127.0.0.1:${SERVICE_PORT}"
secret = "$(openssl rand -hex 16)"
maximum_clients_per_user = 999999999

[quic]
initial_mtu = 1500
min_mtu = 1200
gso = true
pmtu = true
send_window = 33554432
receive_window = 16777216
max_idle_time = "20s"

[quic.congestion_control]
controller = "bbr"
initial_window = 4194304
EOF
    fi
}

# ===================== 链接生成 =====================
generate_link() {
    local ip="$1"
    if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
        local link="hysteria2://$AUTH_PASSWORD@$ip:$SERVICE_PORT?sni=$MASQ_DOMAIN&alpn=h3&insecure=1#Hy2-JSON"
        echo "$link" > "$LINK_FILE"
        echo ""
        echo "📱 Hysteria 2 链接已生成并保存到 $LINK_FILE"
        echo "🔗 订阅链接："
        echo "$link"
        echo ""
    elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
        local link="tuic://${TUIC_UUID}:${TUIC_PASSWORD}@${ip}:${SERVICE_PORT}?congestion_control=bbr&alpn=h3&allowInsecure=1&sni=${MASQ_DOMAIN}&udp_relay_mode=native&disable_sni=0&reduce_rtt=1&max_udp_relay_packet_size=8192#TUIC-HIGH-PERF-${ip}"
        echo "$link" > "$LINK_FILE"
        echo ""
        echo "📱 TUIC 链接已生成并保存到 $LINK_FILE"
        echo "🔗 订阅链接："
        echo "$link"
        echo ""
    fi
}

# ===================== 后台守护进程 =====================
run_daemon() {
    if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
        echo -e "\n✅ Hysteria 2 服务正在启动..."
        # 启动服务，保留日志输出
        "./$HY2_BIN" server -c "$SERVER_CONFIG" > "$WORK_DIR/${SELECTED_SERVICE}.log" 2>&1 &
        local service_pid=$!
        echo "✅ Hysteria 2 服务已在后台启动，日志文件: $WORK_DIR/${SELECTED_SERVICE}.log"
        
        # 创建监控进程
        (
            while true; do
                if ! kill -0 $service_pid 2>/dev/null; then
                    echo "⚠️ Hysteria 2 服务已退出，5秒后重启..."
                    echo "⚠️ 请检查日志文件: $WORK_DIR/${SELECTED_SERVICE}.log"
                    sleep 5
                    "./$HY2_BIN" server -c "$SERVER_CONFIG" > "$WORK_DIR/${SELECTED_SERVICE}.log" 2>&1 &
                    service_pid=$!
                    echo "✅ Hysteria 2 服务已重启"
                fi
                sleep 5
            done
        ) &
        local monitor_pid=$!
        
    elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
        echo "✅ TUIC 服务正在启动..."
        # 启动服务，保留日志输出
        "$TUIC_BIN" -c "$SERVER_TOML" > "$WORK_DIR/${SELECTED_SERVICE}.log" 2>&1 &
        local service_pid=$!
        echo "✅ TUIC 服务已在后台启动，日志文件: $WORK_DIR/${SELECTED_SERVICE}.log"
        
        # 创建监控进程
        (
            while true; do
                if ! kill -0 $service_pid 2>/dev/null; then
                    echo "⚠️ TUIC 服务已退出，5秒后重启..."
                    echo "⚠️ 请检查日志文件: $WORK_DIR/${SELECTED_SERVICE}.log"
                    sleep 5
                    "$TUIC_BIN" -c "$SERVER_TOML" > "$WORK_DIR/${SELECTED_SERVICE}.log" 2>&1 &
                    service_pid=$!
                    echo "✅ TUIC 服务已重启"
                fi
                sleep 5
            done
        ) &
        local monitor_pid=$!
    fi
}

# ===================== 获取服务器 IP =====================
get_server_ip() {
    local ip
    if command -v curl >/dev/null 2>&1; then
        ip=$(curl -s --connect-timeout 5 https://api.ipify.org)
    elif command -v wget >/dev/null 2>&1; then
        ip=$(wget -qO- --timeout=5 https://api.ipify.org)
    fi
    
    if [[ -n "$ip" && "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        echo "$ip"
    else
        echo "YOUR_SERVER_IP"
    fi
}

# ===================== 主函数 =====================
main() {
    local server_ip
    
    # 始终优先设置端口为环境变量
    set_port
    
    if ! load_existing_config; then
        echo "⚙️ 第一次运行，开始初始化..."
        
        if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
            AUTH_PASSWORD=$(openssl rand -hex 16)
            echo "🔑 自动生成密码: $AUTH_PASSWORD"
        elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
            TUIC_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || openssl rand -hex 16)"
            TUIC_PASSWORD="$(openssl rand -hex 16)"
            echo "🔑 UUID: $TUIC_UUID"
            echo "🔑 密码: $TUIC_PASSWORD"
        fi
        
        generate_certificate || exit 1
        check_binary || exit 1
        generate_config
    else
        # 检查环境变量端口变更 (环境变量优先)
        local env_port="${SERVER_PORT:-}"
        if [[ -n "$env_port" && "$env_port" != "$SERVICE_PORT" ]]; then
            echo "⚙️ 检测到环境变量端口变更 ($env_port)，更新配置..."
            SERVICE_PORT="$env_port"
            if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
                AUTH_PASSWORD=$(grep '"password":' "$SERVER_CONFIG" | sed -E 's/.*"password": "([^"]+)".*/\1/')
            else
                TUIC_UUID=$(grep '^\[users\]' -A1 "$SERVER_TOML" | tail -n1 | awk '{print $1}')
                TUIC_PASSWORD=$(grep '^\[users\]' -A1 "$SERVER_TOML" | tail -n1 | awk -F'"' '{print $2}')
            fi
            generate_config
        fi
        generate_certificate || exit 1
        check_binary || exit 1
    fi
    
    server_ip=$(get_server_ip)
    
    # 启动守护进程（后台运行）
    run_daemon &
    
    # 等待服务启动
    echo "⏳ 等待服务启动..."
    sleep 3
    
    # 打印部署信息
    echo ""
    echo "🎉 部署信息概要"
    echo "========================================"
    echo "🌐 服务器: $server_ip:$SERVICE_PORT"
    if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
        echo "🔑 密码: $AUTH_PASSWORD"
        echo "📱 v2rayN / Clouder 链接:"
    else
        echo "🔑 UUID: $TUIC_UUID"
        echo "🔑 密码: $TUIC_PASSWORD"
    fi
    echo "🎯 SNI/伪装域名: $MASQ_DOMAIN"
    echo "========================================"
    
    # 生成链接文件
    generate_link "$server_ip"
    
    echo ""
    echo "✅ 服务已启动，链接文件已生成！"
    echo "📝 如有问题，请查看日志文件: $WORK_DIR/${SELECTED_SERVICE}.log"
    echo ""
    
    # 保持前台运行，防止容器退出
    while true; do
        sleep 30
        # 定期检查服务状态
        if [[ "$SELECTED_SERVICE" == "hy2" ]]; then
            if ! pgrep -f "hysteria.*server" >/dev/null; then
                echo "⚠️ 检测到 Hysteria 2 服务已停止"
                break
            fi
        elif [[ "$SELECTED_SERVICE" == "tuic" ]]; then
            if ! pgrep -f "tuic-server" >/dev/null; then
                echo "⚠️ 检测到 TUIC 服务已停止"
                break
            fi
        fi
    done
}

main "$@"
