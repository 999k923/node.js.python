#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# =========================================================
# 固定隧道参数（留空走临时隧道 trycloudflare）
# =========================================================
ARGO_TOKEN="${ARGO_TOKEN:-}"                # 固定隧道 token；留空=临时隧道
ARGO_DOMAIN_FIXED="${ARGO_DOMAIN_FIXED:-}"  # 固定隧道域名（Public Hostname 绑定的域名）
ARGO_PORT="${ARGO_PORT:-8880}"              # Argo 转发到本地 sing-box WS inbound 端口
SINGLE_PORT_UDP="${SINGLE_PORT_UDP:-tuic}"  # 单端口 UDP：tuic / hy2

# =========================================================
# Nezha V1（只保留 V1）
# 说明：
# - v1: 只需要 NEZHA_SERVER 和 NEZHA_KEY
# - NEZHA_PORT（v0 用）即使填了也会被忽略
# =========================================================
NEZHA_SERVER=""   # 例如 nezha.xxx.com:8008
NEZHA_KEY=""         # v1: NZ_CLIENT_SECRET
NEZHA_PORT="${NEZHA_PORT:-}"       # v0 变量（忽略）

# =========================================================
# CF 优选域名列表
# =========================================================
CF_DOMAINS=(
  "cf.090227.xyz"
  "cf.877774.xyz"
  "cf.130519.xyz"
  "cf.008500.xyz"
  "store.ubi.com"
  "saas.sin.fan"
)

# =========================================================
# 切换到脚本目录（兼容 python 调起时的 cwd）
# =========================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export FILE_PATH="${SCRIPT_DIR}/.npm"
mkdir -p "$FILE_PATH"

# =========================================================
# 工具检测：curl / wget / python3 / openssl
# =========================================================
have() { command -v "$1" >/dev/null 2>&1; }

CURL_AVAILABLE=false
WGET_AVAILABLE=false
PY_AVAILABLE=false
OPENSSL_AVAILABLE=false

have curl && CURL_AVAILABLE=true
have wget && WGET_AVAILABLE=true
have python3 && PY_AVAILABLE=true
have openssl && OPENSSL_AVAILABLE=true

if [ "$CURL_AVAILABLE" = false ] && [ "$WGET_AVAILABLE" = false ]; then
  echo "[错误] 缺少下载工具：需要 curl 或 wget" >&2
  exit 1
fi

if [ "$PY_AVAILABLE" = false ]; then
  echo "[错误] 缺少 python3（订阅服务使用 python3）" >&2
  exit 1
fi

is_number() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

# =========================================================
# 退出时清理后台进程（更适合被 python 管理）
# =========================================================
HTTP_PID=""
SB_PID=""
ARGO_PID=""
NEZHA_PID=""

cleanup() {
  set +e
  [ -n "${HTTP_PID:-}" ] && kill "${HTTP_PID}" >/dev/null 2>&1 || true
  [ -n "${ARGO_PID:-}" ] && kill "${ARGO_PID}" >/dev/null 2>&1 || true
  [ -n "${SB_PID:-}" ] && kill "${SB_PID}" >/dev/null 2>&1 || true
  [ -n "${NEZHA_PID:-}" ] && kill "${NEZHA_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# =========================================================
# http 请求工具封装（curl/wget 兼容）
# =========================================================
http_get() {
  local url="$1"
  if [ "$CURL_AVAILABLE" = true ]; then
    curl -fsSL --max-time 10 "$url"
  else
    wget -qO- --timeout=10 "$url"
  fi
}

http_download() {
  local url="$1" output="$2"
  if [ -x "$output" ]; then
    return 0
  fi
  echo "[下载] $output..."
  if [ "$CURL_AVAILABLE" = true ]; then
    curl -L -sS --max-time 60 -o "$output" "$url"
  else
    wget -q --timeout=60 -O "$output" "$url"
  fi
  chmod +x "$output"
  echo "[下载] $output 完成"
}

http_ping_https() {
  local domain="$1"
  if [ "$CURL_AVAILABLE" = true ]; then
    curl -s --max-time 2 -o /dev/null "https://$domain" 2>/dev/null
  else
    wget -q --timeout=2 --spider "https://$domain" 2>/dev/null
  fi
}

# =========================================================
# 基础参数校验（只在固定隧道时强制）
# =========================================================
if [ -n "${ARGO_TOKEN:-}" ]; then
  if [ -z "${ARGO_DOMAIN_FIXED:-}" ]; then
    echo "[错误] 使用固定隧道时必须填写 ARGO_DOMAIN_FIXED（固定域名）" >&2
    exit 1
  fi
  if ! is_number "$ARGO_PORT"; then
    echo "[错误] ARGO_PORT 必须是数字" >&2
    exit 1
  fi
fi

# =========================================================
# 获取公网 IP
# =========================================================
echo "[网络] 获取公网 IP..."
PUBLIC_IP="$(http_get "https://ipv4.ip.sb" 2>/dev/null || true)"
[ -z "$PUBLIC_IP" ] && PUBLIC_IP="$(http_get "https://api.ipify.org" 2>/dev/null || true)"
[ -z "$PUBLIC_IP" ] && { echo "[错误] 无法获取公网 IP" >&2; exit 1; }
echo "[网络] 公网 IP: $PUBLIC_IP"

# =========================================================
# CF 优选：随机选择可用域名
# =========================================================
select_random_cf_domain() {
  local available=()
  for domain in "${CF_DOMAINS[@]}"; do
    if http_ping_https "$domain"; then
      available+=("$domain")
    fi
  done
  if [ ${#available[@]} -gt 0 ]; then
    echo "${available[$((RANDOM % ${#available[@]}))]}"
  else
    echo "${CF_DOMAINS[0]}"
  fi
}

echo "[CF优选] 测试中..."
BEST_CF_DOMAIN="$(select_random_cf_domain)"
echo "[CF优选] $BEST_CF_DOMAIN"

# =========================================================
# 获取端口（平台提供 SERVER_PORT）
# =========================================================
PORTS_STRING="${SERVER_PORT:-}"
read -r -a AVAILABLE_PORTS <<< "$PORTS_STRING"
PORT_COUNT=${#AVAILABLE_PORTS[@]}
[ $PORT_COUNT -eq 0 ] && echo "[错误] 未找到端口（需要平台提供 SERVER_PORT）" >&2 && exit 1
echo "[端口] 发现 $PORT_COUNT 个: ${AVAILABLE_PORTS[*]}"

# =========================================================
# 端口分配逻辑（TCP/UDP 同号复用允许）
# =========================================================
if [ $PORT_COUNT -eq 1 ]; then
  UDP_PORT=${AVAILABLE_PORTS[0]}
  TUIC_PORT=""
  HY2_PORT=""
  [[ "$SINGLE_PORT_UDP" == "tuic" ]] && TUIC_PORT=$UDP_PORT || HY2_PORT=$UDP_PORT
  REALITY_PORT=""
  HTTP_PORT=${AVAILABLE_PORTS[0]}
  SINGLE_PORT_MODE=true
else
  TUIC_PORT=${AVAILABLE_PORTS[0]}
  HY2_PORT=${AVAILABLE_PORTS[1]}
  REALITY_PORT=${AVAILABLE_PORTS[0]}
  HTTP_PORT=${AVAILABLE_PORTS[1]}
  SINGLE_PORT_MODE=false
fi

# =========================================================
# UUID（持久化）
# =========================================================
UUID_FILE="${FILE_PATH}/uuid.txt"
if [ -f "$UUID_FILE" ]; then
  UUID="$(cat "$UUID_FILE")"
else
  UUID="$(cat /proc/sys/kernel/random/uuid)"
  echo "$UUID" > "$UUID_FILE"
fi
echo "[UUID] $UUID"

# =========================================================
# 架构检测 & 下载
# =========================================================
ARCH="$(uname -m)"
if [[ "$ARCH" == "aarch64" ]]; then
  BASE_URL="https://arm64.ssss.nyc.mn"
  ARGO_ARCH="arm64"
else
  BASE_URL="https://amd64.ssss.nyc.mn"
  ARGO_ARCH="amd64"
fi

SB_FILE="${FILE_PATH}/sb"
ARGO_FILE="${FILE_PATH}/cloudflared"

http_download "${BASE_URL}/sb" "$SB_FILE"
http_download "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARGO_ARCH}" "$ARGO_FILE"

# =========================================================
# Reality 密钥（多端口才需要）
# =========================================================
if [ "$SINGLE_PORT_MODE" = false ]; then
  echo "[密钥] 检查中..."
  KEY_FILE="${FILE_PATH}/key.txt"
  if [ -f "$KEY_FILE" ]; then
    private_key="$(grep "PrivateKey:" "$KEY_FILE" | awk '{print $2}')"
    public_key="$(grep "PublicKey:" "$KEY_FILE" | awk '{print $2}')"
  else
    output="$("$SB_FILE" generate reality-keypair)"
    echo "$output" > "$KEY_FILE"
    private_key="$(echo "$output" | awk '/PrivateKey:/ {print $2}')"
    public_key="$(echo "$output" | awk '/PublicKey:/ {print $2}')"
  fi
  echo "[密钥] 已就绪"
fi

# =========================================================
# 证书生成（用于 TUIC/HY2）
# =========================================================
echo "[证书] 生成中..."
if [ "$OPENSSL_AVAILABLE" = true ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
    -keyout "${FILE_PATH}/private.key" \
    -out "${FILE_PATH}/cert.pem" \
    -days 3650 -subj "/CN=www.bing.com" >/dev/null 2>&1
else
  printf -- "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/+siNnfBYsdUYsoAoGCCqGSM49\nAwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASAnngZreoQDF16ARa/\nTsyLyFoPkhTxSbehH/OBEjHtSZGaDhMqQ==\n-----END EC PRIVATE KEY-----\n" > "${FILE_PATH}/private.key"
  printf -- "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgIUFWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwMTAxMDEwMTAwWhcNMzUwMTAxMDEw\nMTAwWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgJ54Ga3qEAxdegEWv07Mi8ha\nD5IU8Um3oR/zgRIx7UmRmg4TKkOjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\nBfGbgrkMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgrkMNzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIARDAJvg0vd/ytrQVvEcSm6XTlB+\neQ6OFb9LbLYL9Zi+AiB+foMbi4y/0YUQlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n-----END CERTIFICATE-----\n" > "${FILE_PATH}/cert.pem"
fi
echo "[证书] 已就绪"

# =========================================================
# ISP（仅用于节点命名）
# =========================================================
ISP="Node"
if [ "$CURL_AVAILABLE" = true ]; then
  JSON_DATA="$(curl -s --max-time 2 -H "Referer: https://speed.cloudflare.com/" https://speed.cloudflare.com/meta 2>/dev/null || true)"
  if [ -n "$JSON_DATA" ]; then
    ORG="$(echo "$JSON_DATA" | sed -n 's/.*"asOrganization":"\([^"]*\)".*/\1/p')"
    CITY="$(echo "$JSON_DATA" | sed -n 's/.*"city":"\([^"]*\)".*/\1/p')"
    if [ -n "${ORG:-}" ] && [ -n "${CITY:-}" ]; then
      ISP="${ORG}-${CITY}"
    fi
  fi
fi
[ -z "${ISP:-}" ] && ISP="Node"

# =========================================================
# 生成订阅文件
# =========================================================
generate_sub() {
  local argo_domain="$1"
  : > "${FILE_PATH}/list.txt"

  [ -n "${TUIC_PORT:-}" ] && echo "tuic://${UUID}:admin@${PUBLIC_IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#TUIC-${ISP}" >> "${FILE_PATH}/list.txt"
  [ -n "${HY2_PORT:-}" ] && echo "hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1#Hysteria2-${ISP}" >> "${FILE_PATH}/list.txt"
  [ -n "${REALITY_PORT:-}" ] && echo "vless://${UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&type=tcp#Reality-${ISP}" >> "${FILE_PATH}/list.txt"

  if [ -n "${argo_domain:-}" ]; then
    echo "vless://${UUID}@${BEST_CF_DOMAIN}:443?encryption=none&security=tls&sni=${argo_domain}&type=ws&host=${argo_domain}&path=%2F${UUID}-vless#Argo-${ISP}" >> "${FILE_PATH}/list.txt"
  fi

  cp "${FILE_PATH}/list.txt" "${FILE_PATH}/sub.txt"
}

# =========================================================
# Python 订阅服务（替代 node，兼容 host）
# =========================================================
PY_SERVER="${FILE_PATH}/server.py"
cat > "$PY_SERVER" <<'PYEOF'
import http.server, socketserver, sys, os
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
BIND = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
SUB_PATH = sys.argv[3] if len(sys.argv) > 3 else ""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/sub" in self.path or (SUB_PATH and f"/{SUB_PATH}" in self.path):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            try:
                with open(os.path.join(os.path.dirname(__file__), "sub.txt"), "r", encoding="utf-8") as f:
                    self.wfile.write(f.read().encode("utf-8"))
            except Exception:
                self.wfile.write(b"error")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        return

with socketserver.TCPServer((BIND, PORT), Handler) as httpd:
    httpd.serve_forever()
PYEOF

echo "[HTTP] 启动订阅服务 (端口 $HTTP_PORT)..."
python3 "$PY_SERVER" "$HTTP_PORT" "0.0.0.0" "$UUID" >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1
echo "[HTTP] 已启动 PID: $HTTP_PID"

# =========================================================
# sing-box 配置
# =========================================================
echo "[CONFIG] 生成配置..."
INBOUNDS=""

if [ -n "${TUIC_PORT:-}" ]; then
  INBOUNDS="{
    \"type\": \"tuic\",
    \"tag\": \"tuic-in\",
    \"listen\": \"::\",
    \"listen_port\": ${TUIC_PORT},
    \"users\": [{\"uuid\": \"${UUID}\", \"password\": \"admin\"}],
    \"congestion_control\": \"bbr\",
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"],
      \"certificate_path\": \"${FILE_PATH}/cert.pem\",
      \"key_path\": \"${FILE_PATH}/private.key\"
    }
  }"
fi

if [ -n "${HY2_PORT:-}" ]; then
  [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
  INBOUNDS="${INBOUNDS}{
    \"type\": \"hysteria2\",
    \"tag\": \"hy2-in\",
    \"listen\": \"::\",
    \"listen_port\": ${HY2_PORT},
    \"users\": [{\"password\": \"${UUID}\"}],
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"],
      \"certificate_path\": \"${FILE_PATH}/cert.pem\",
      \"key_path\": \"${FILE_PATH}/private.key\"
    }
  }"
fi

if [ -n "${REALITY_PORT:-}" ]; then
  [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
  INBOUNDS="${INBOUNDS}{
    \"type\": \"vless\",
    \"tag\": \"vless-reality-in\",
    \"listen\": \"::\",
    \"listen_port\": ${REALITY_PORT},
    \"users\": [{\"uuid\": \"${UUID}\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true,
      \"server_name\": \"www.nazhumi.com\",
      \"reality\": {
        \"enabled\": true,
        \"handshake\": {\"server\": \"www.nazhumi.com\", \"server_port\": 443},
        \"private_key\": \"${private_key}\",
        \"short_id\": [\"\"]
      }
    }
  }"
fi

# Argo 本地 WS inbound（cloudflared 转发目标）
[ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
INBOUNDS="${INBOUNDS}{
  \"type\": \"vless\",
  \"tag\": \"vless-argo-in\",
  \"listen\": \"127.0.0.1\",
  \"listen_port\": ${ARGO_PORT},
  \"users\": [{\"uuid\": \"${UUID}\"}],
  \"transport\": {\"type\": \"ws\", \"path\": \"/${UUID}-vless\"}
}"

cat > "${FILE_PATH}/config.json" <<CFGEOF
{
  "log": {"level": "warn"},
  "inbounds": [${INBOUNDS}],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
CFGEOF

echo "[SING-BOX] 启动中..."
"$SB_FILE" run -c "${FILE_PATH}/config.json" >/dev/null 2>&1 &
SB_PID=$!
sleep 2
if ! kill -0 "$SB_PID" 2>/dev/null; then
  echo "[SING-BOX] 启动失败" >&2
  exit 1
fi
echo "[SING-BOX] 已启动 PID: $SB_PID"

# =========================================================
# Nezha V1：下载 + 配置 + 启动
# =========================================================
NEZHA_BIN="${FILE_PATH}/nezha-agent"
NEZHA_CFG="${FILE_PATH}/config.yaml"
NEZHA_LOG="${FILE_PATH}/nezha.log"

is_tls_port() {
  local p="$1"
  case "$p" in
    443|8443|2096|2087|2083|2053) return 0 ;;
    *) return 1 ;;
  esac
}

start_nezha_v1() {
  if [ -z "${NEZHA_SERVER:-}" ] || [ -z "${NEZHA_KEY:-}" ]; then
    echo "[Nezha] 未配置 NEZHA_SERVER/NEZHA_KEY，跳过"
    return 0
  fi

  if [ -n "${NEZHA_PORT:-}" ]; then
    echo "[Nezha] 检测到 NEZHA_PORT（V0 参数），已忽略，仅运行 V1"
  fi

  local port=""
  if [[ "$NEZHA_SERVER" == *:* ]]; then
    port="${NEZHA_SERVER##*:}"
  fi

  local tls="false"
  if [ -n "$port" ] && is_tls_port "$port"; then
    tls="true"
  fi

  echo "[Nezha] 下载 V1 agent..."
  http_download "${BASE_URL}/v1" "$NEZHA_BIN"

  cat > "$NEZHA_CFG" <<EOF
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}
EOF

  echo "[Nezha] 启动 V1 agent（tls=${tls}）..."
  nohup "$NEZHA_BIN" -c "$NEZHA_CFG" >"$NEZHA_LOG" 2>&1 &
  NEZHA_PID=$!
  sleep 1

  if ! kill -0 "$NEZHA_PID" 2>/dev/null; then
    echo "[Nezha] 启动失败，最近日志："
    tail -n 80 "$NEZHA_LOG" || true
    # 不强制退出：哪吒失败不影响主程序（你想强制退出可改成 return 1）
    return 0
  fi

  echo "[Nezha] 已启动 PID: $NEZHA_PID"
  return 0
}

start_nezha_v1

# =========================================================
# Argo：固定 or 临时（临时隧道用 tee 输出，强制 IPv4）
# =========================================================
ARGO_LOG="${FILE_PATH}/argo.log"
ARGO_DOMAIN=""

if [ -n "${ARGO_TOKEN:-}" ]; then
  echo "[Argo] 固定隧道模式：token run（不带 --url，强制 ipv4+http2）"
  ARGO_DOMAIN="$ARGO_DOMAIN_FIXED"

  echo "[提醒] Cloudflare 后台必须配置："
  echo "  Public Hostname = ${ARGO_DOMAIN_FIXED}"
  echo "  Service = http://localhost:${ARGO_PORT}"

  ARGO_TOKEN="$(printf '%s' "$ARGO_TOKEN" | tr -d '\r\n')"

  "$ARGO_FILE" tunnel \
    --no-autoupdate \
    --loglevel info \
    --edge-ip-version 4 \
    --protocol http2 \
    run --token "$ARGO_TOKEN" 2>&1 | tee "$ARGO_LOG" &
  ARGO_PID=$!
  sleep 2

  if ! kill -0 "$ARGO_PID" 2>/dev/null; then
    echo "[Argo] 固定隧道启动失败：" >&2
    tail -n 200 "$ARGO_LOG" || true
    exit 1
  fi
else
  echo "[Argo] 临时隧道模式：trycloudflare"

  echo "[Argo] cloudflared --version:"
  "$ARGO_FILE" --version || { echo "[Argo] ❌ cloudflared 无法执行"; exit 1; }

  echo "[Argo] 启动 cloudflared（强制 IPv4 + http2）..."
  "$ARGO_FILE" tunnel \
    --edge-ip-version 4 \
    --protocol http2 \
    --no-autoupdate \
    --url "http://127.0.0.1:${ARGO_PORT}" \
    2>&1 | tee "$ARGO_LOG" &
  ARGO_PID=$!

  for i in {1..45}; do
    sleep 1
    ARGO_DOMAIN="$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_LOG" | head -1 | sed 's|https://||' || true)"
    [ -n "${ARGO_DOMAIN:-}" ] && break
  done

  if [ -z "${ARGO_DOMAIN:-}" ]; then
    echo "[Argo] ❌ 临时隧道域名获取失败（45s 内未拿到 trycloudflare 域名）" >&2
    echo "[Argo] argo.log (last 200 lines):"
    tail -n 200 "$ARGO_LOG" || true
    exit 1
  fi
fi

echo "[Argo] 域名: $ARGO_DOMAIN"

# =========================================================
# 生成订阅并输出
# =========================================================
generate_sub "$ARGO_DOMAIN"
SUB_URL="http://${PUBLIC_IP}:${HTTP_PORT}/sub"

echo ""
echo "==================================================="
echo "订阅链接: $SUB_URL"
echo "Argo 域名: $ARGO_DOMAIN"
echo "==================================================="
echo ""

# 保持前台：面板会认为主进程活着
wait "$SB_PID"
