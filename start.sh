#!/bin/bash
set -eo pipefail

# =========================================================
# 只需要在这里填：固定隧道参数（留空就走临时隧道）
# =========================================================

# 固定隧道 Token（留空 = 临时隧道 trycloudflare）
ARGO_TOKEN=""   # <- 这里填你 Zero Trust 里复制的 token；留空则临时隧道

# 固定隧道域名（Zero Trust / Tunnels / Public Hostname 里绑定的域名）
ARGO_DOMAIN_FIXED=""

# Argo 本地端口（cloudflared 转发到本地 sing-box 的 WS inbound）
# 你 Cloudflare 后台 Service 用的 http://localhost:8880，那么这里就必须是 8880
ARGO_PORT="8880"

# 单端口模式 UDP 协议选择：tuic / hy2
SINGLE_PORT_UDP="tuic"

# =========================================================
# Nezha V1（直接写死：留空=不安装）
# =========================================================
NEZHA_SERVER=""   # 例如：nezha.xxx.com:8008
NEZHA_KEY=""      # 例如：NZ_CLIENT_SECRET
# v0 不需要，必须留空
NEZHA_PORT=""# v0不支持 必须留空，只能支持V1

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
# 工具检测（✅ 修复点 1：补上 CURL_AVAILABLE）
# =========================================================
CURL_AVAILABLE=false
command -v curl >/dev/null 2>&1 && CURL_AVAILABLE=true

is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }

# =========================================================
# 切换到脚本目录
# =========================================================
cd "$(dirname "$0")"
export FILE_PATH="${PWD}/.npm"
mkdir -p "$FILE_PATH"

# =========================================================
# 基础参数校验（只在固定隧道时强制）
# =========================================================
if [ -n "$ARGO_TOKEN" ]; then
  if [ -z "$ARGO_DOMAIN_FIXED" ]; then
    echo "[错误] 使用固定隧道时必须填写 ARGO_DOMAIN_FIXED（固定域名）"
    exit 1
  fi
  if ! is_number "$ARGO_PORT"; then
    echo "[错误] ARGO_PORT 必须是数字"
    exit 1
  fi
fi

# =========================================================
# 获取公网 IP
# =========================================================
echo "[网络] 获取公网 IP..."
PUBLIC_IP=$(curl -s --max-time 5 ipv4.ip.sb || curl -s --max-time 5 api.ipify.org || echo "")
[ -z "$PUBLIC_IP" ] && echo "[错误] 无法获取公网 IP" && exit 1
echo "[网络] 公网 IP: $PUBLIC_IP"

# =========================================================
# CF 优选：随机选择可用域名
# =========================================================
select_random_cf_domain() {
  local available=()
  for domain in "${CF_DOMAINS[@]}"; do
    if curl -s --max-time 2 -o /dev/null "https://$domain" 2>/dev/null; then
      available+=("$domain")
    fi
  done
  [ ${#available[@]} -gt 0 ] && echo "${available[$((RANDOM % ${#available[@]}))]}" || echo "${CF_DOMAINS[0]}"
}

echo "[CF优选] 测试中..."
BEST_CF_DOMAIN=$(select_random_cf_domain)
echo "[CF优选] $BEST_CF_DOMAIN"

# =========================================================
# 获取端口（平台提供 SERVER_PORT）
# =========================================================
[ -n "${SERVER_PORT:-}" ] && PORTS_STRING="$SERVER_PORT" || PORTS_STRING=""
read -ra AVAILABLE_PORTS <<< "$PORTS_STRING"
PORT_COUNT=${#AVAILABLE_PORTS[@]}
[ $PORT_COUNT -eq 0 ] && echo "[错误] 未找到端口（需要平台提供 SERVER_PORT）" && exit 1
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
[ -f "$UUID_FILE" ] && UUID=$(cat "$UUID_FILE") || { UUID=$(cat /proc/sys/kernel/random/uuid); echo "$UUID" > "$UUID_FILE"; }
echo "[UUID] $UUID"

# =========================================================
# 架构检测 & 下载
# =========================================================
ARCH=$(uname -m)
[[ "$ARCH" == "aarch64" ]] && BASE_URL="https://arm64.ssss.nyc.mn" || BASE_URL="https://amd64.ssss.nyc.mn"
[[ "$ARCH" == "aarch64" ]] && ARGO_ARCH="arm64" || ARGO_ARCH="amd64"

SB_FILE="${FILE_PATH}/sb"
ARGO_FILE="${FILE_PATH}/cloudflared"

download_file() {
  local url=$1 output=$2
  [ -x "$output" ] && return 0
  echo "[下载] $output..."
  curl -L -sS --max-time 60 -o "$output" "$url" && chmod +x "$output" && echo "[下载] $output 完成" && return 0
  echo "[下载] $output 失败" && return 1
}

download_file "${BASE_URL}/sb" "$SB_FILE"
download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARGO_ARCH}" "$ARGO_FILE"

# =========================================================
# Reality 密钥（多端口才需要）
# =========================================================
if [ "$SINGLE_PORT_MODE" = false ]; then
  echo "[密钥] 检查中..."
  KEY_FILE="${FILE_PATH}/key.txt"
  if [ -f "$KEY_FILE" ]; then
    private_key=$(grep "PrivateKey:" "$KEY_FILE" | awk '{print $2}')
    public_key=$(grep "PublicKey:" "$KEY_FILE" | awk '{print $2}')
  else
    output=$("$SB_FILE" generate reality-keypair)
    echo "$output" > "$KEY_FILE"
    private_key=$(echo "$output" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$output" | awk '/PublicKey:/ {print $2}')
  fi
  echo "[密钥] 已就绪"
fi

# =========================================================
# 证书生成（用于 TUIC/HY2）
# =========================================================
echo "[证书] 生成中..."
if command -v openssl >/dev/null 2>&1; then
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
  JSON_DATA=$(curl -s --max-time 2 -H "Referer: https://speed.cloudflare.com/" https://speed.cloudflare.com/meta 2>/dev/null || true)
  if [ -n "$JSON_DATA" ]; then
    ORG=$(echo "$JSON_DATA" | sed -n 's/.*"asOrganization":"\([^"]*\)".*/\1/p')
    CITY=$(echo "$JSON_DATA" | sed -n 's/.*"city":"\([^"]*\)".*/\1/p')
    if [ -n "$ORG" ] && [ -n "$CITY" ]; then
      ISP="${ORG}-${CITY}"
    fi
  fi
fi
[ -z "$ISP" ] && ISP="Node"

# =========================================================
# 生成订阅文件
# =========================================================
generate_sub() {
  local argo_domain="$1"
  > "${FILE_PATH}/list.txt"

  [ -n "$TUIC_PORT" ] && echo "tuic://${UUID}:admin@${PUBLIC_IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#TUIC-${ISP}" >> "${FILE_PATH}/list.txt"
  [ -n "$HY2_PORT" ] && echo "hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1#Hysteria2-${ISP}" >> "${FILE_PATH}/list.txt"
  [ -n "$REALITY_PORT" ] && echo "vless://${UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&type=tcp#Reality-${ISP}" >> "${FILE_PATH}/list.txt"

  [ -n "$argo_domain" ] && echo "vless://${UUID}@${BEST_CF_DOMAIN}:443?encryption=none&security=tls&sni=${argo_domain}&type=ws&host=${argo_domain}&path=%2F${UUID}-vless#Argo-${ISP}" >> "${FILE_PATH}/list.txt"

  cat "${FILE_PATH}/list.txt" > "${FILE_PATH}/sub.txt"
}

# =========================================================
# HTTP 订阅服务（node）
# =========================================================
cat > "${FILE_PATH}/server.js" <<JSEOF
const http = require('http');
const fs = require('fs');
const port = process.argv[2] || 8080;
const bind = process.argv[3] || '0.0.0.0';
http.createServer((req, res) => {
  if (req.url.includes('/sub') || req.url.includes('/${UUID}')) {
    res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});
    try { res.end(fs.readFileSync('${FILE_PATH}/sub.txt', 'utf8')); } catch(e) { res.end('error'); }
  } else { res.writeHead(404); res.end('404'); }
}).listen(port, bind, () => console.log('HTTP on ' + bind + ':' + port));
JSEOF

echo "[HTTP] 启动订阅服务 (端口 $HTTP_PORT)..."
node "${FILE_PATH}/server.js" "$HTTP_PORT" 0.0.0.0 &
HTTP_PID=$!
sleep 1
echo "[HTTP] 已启动"

# =========================================================
# sing-box 配置
# =========================================================
echo "[CONFIG] 生成配置..."
INBOUNDS=""

if [ -n "$TUIC_PORT" ]; then
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

if [ -n "$HY2_PORT" ]; then
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

if [ -n "$REALITY_PORT" ]; then
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
"$SB_FILE" run -c "${FILE_PATH}/config.json" &
SB_PID=$!
sleep 2
if ! kill -0 $SB_PID 2>/dev/null; then
  echo "[SING-BOX] 启动失败"
  exit 1
fi
echo "[SING-BOX] 已启动 PID: $SB_PID"

# =========================================================
# Nezha V1（下载 + 配置 + 启动）
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
  download_file "${BASE_URL}/v1" "$NEZHA_BIN"

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
    # 不强制退出：哪吒失败不影响主程序
    return 0
  fi

  echo "[Nezha] 已启动 PID: $NEZHA_PID"
  return 0
}

start_nezha_v1

# =========================================================
# Argo：固定 or 临时（⚠️ 临时分支只保留这一套修复逻辑）
# =========================================================
ARGO_LOG="${FILE_PATH}/argo.log"
ARGO_DOMAIN=""

if [ -n "$ARGO_TOKEN" ]; then
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
    run --token "$ARGO_TOKEN" >"$ARGO_LOG" 2>&1 &
  ARGO_PID=$!
  sleep 2

  if ! kill -0 "$ARGO_PID" 2>/dev/null; then
    echo "[Argo] 固定隧道启动失败："
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
    echo "[Argo] ❌ 临时隧道域名获取失败（45s 内未拿到 trycloudflare 域名）"
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

wait $SB_PID
