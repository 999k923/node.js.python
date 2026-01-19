#!/bin/bash
set -eo pipefail

# =========================================================
# 只需要在这里填：固定隧道参数（留空就走临时隧道）
# =========================================================

# 固定隧道 Token（留空 = 临时隧道 trycloudflare）
ARGO_TOKEN=""   # <- 这里填你 Zero Trust 里复制的 token；留空则临时隧道

# 固定隧道域名（Zero Trust / Tunnels / Public Hostname 里绑定的域名）
ARGO_DOMAIN_FIXED=""

# Argo 本地端口（cloudflared 转发到本地服务）
ARGO_PORT="8880"

# =========================================================
# Nezha V1（直接写死：留空=不安装）
# =========================================================
NEZHA_SERVER=""   # 例如：nezha.xxx.com:8008
NEZHA_KEY=""      # 例如：NZ_CLIENT_SECRET
# v0 不需要，必须留空
NEZHA_PORT=""     # v0不支持 必须留空，只能支持V1

# =========================================================
# 切换到脚本目录
# =========================================================
cd "$(dirname "$0")"

select_writable_dir() {
  local preferred_dir="$1"
  if [ -n "$preferred_dir" ] && mkdir -p "$preferred_dir" 2>/dev/null; then
    echo "$preferred_dir"
    return 0
  fi
  return 1
}

FILE_PATH=""
if ! FILE_PATH=$(select_writable_dir "${HOME:-}/.sb-nj"); then
  FILE_PATH=$(select_writable_dir "${XDG_CACHE_HOME:-/tmp}/sb-nj") || FILE_PATH="/tmp/sb-nj"
  mkdir -p "$FILE_PATH"
fi

# =========================================================
# 基础参数校验（只在固定隧道时强制）
# =========================================================
if [ -n "$ARGO_TOKEN" ]; then
  if [ -z "$ARGO_DOMAIN_FIXED" ]; then
    echo "[错误] 使用固定隧道时必须填写 ARGO_DOMAIN_FIXED（固定域名）"
    exit 1
  fi
  if ! [[ "$ARGO_PORT" =~ ^[0-9]+$ ]]; then
    echo "[错误] ARGO_PORT 必须是数字"
    exit 1
  fi
fi

# =========================================================
# 获取公网 IP（优先 PUBLIC_IP 环境变量）
# =========================================================
get_public_ip() {
  if [ -n "${PUBLIC_IP:-}" ]; then
    echo "$PUBLIC_IP"
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -s --max-time 5 ipv4.ip.sb || curl -s --max-time 5 api.ipify.org || true
    return 0
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO- --timeout=5 ipv4.ip.sb || wget -qO- --timeout=5 api.ipify.org || true
    return 0
  fi

  node -e "const https=require('https');const urls=['https://ipv4.ip.sb','https://api.ipify.org'];const get=u=>new Promise(r=>https.get(u,res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>r(d.trim()));}).on('error',()=>r('')));(async()=>{for(const u of urls){const v=await get(u);if(v){process.stdout.write(v);return}}})();" || true
}

echo "[网络] 获取公网 IP..."
PUBLIC_IP=$(get_public_ip)
[ -z "${PUBLIC_IP:-}" ] && echo "[错误] 无法获取公网 IP" && exit 1
echo "[网络] 公网 IP: $PUBLIC_IP"

# =========================================================
# UUID（持久化，仅用于日志输出）
# =========================================================
UUID_FILE="${FILE_PATH}/uuid.txt"
[ -f "$UUID_FILE" ] && UUID=$(cat "$UUID_FILE") || { UUID=$(cat /proc/sys/kernel/random/uuid); echo "$UUID" > "$UUID_FILE"; }
echo "[UUID] $UUID"

# =========================================================
# 下载工具（cloudflared / nezha）
# =========================================================
ARCH=$(uname -m)
[[ "$ARCH" == "aarch64" ]] && BASE_URL="https://arm64.ssss.nyc.mn" || BASE_URL="https://amd64.ssss.nyc.mn"
[[ "$ARCH" == "aarch64" ]] && ARGO_ARCH="arm64" || ARGO_ARCH="amd64"

ARGO_FILE="${FILE_PATH}/cloudflared"
NEZHA_BIN="${FILE_PATH}/nezha-agent"

node_download() {
  local url="$1"
  local output="$2"
  node -e "const fs=require('fs');const https=require('https');const url=process.argv[1];const out=process.argv[2];const file=fs.createWriteStream(out);https.get(url,res=>{if(res.statusCode>=300&&res.statusCode<400&&res.headers.location){return https.get(res.headers.location,r=>r.pipe(file));}if(res.statusCode!==200){console.error('HTTP '+res.statusCode);process.exit(1);}res.pipe(file);}).on('error',err=>{console.error(err.message);process.exit(1);});" "$url" "$output"
}

download_file() {
  local url=$1
  local output=$2
  [ -x "$output" ] && return 0
  echo "[下载] $output..."
  if command -v curl >/dev/null 2>&1; then
    curl -L -sS --max-time 120 -o "$output" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$output" "$url"
  else
    node_download "$url" "$output"
  fi
  chmod +x "$output"
  echo "[下载] $output 完成"
}

download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARGO_ARCH}" "$ARGO_FILE"

# =========================================================
# 本地占位服务（供 Argo 转发）
# =========================================================
cat > "${FILE_PATH}/argo_server.js" <<'JSEOF'
const http = require('http');
const port = process.argv[2] || 8880;
http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8'});
  res.end('ok');
}).listen(port, '127.0.0.1', () => {
  console.log('[Argo] 本地服务已启动: 127.0.0.1:' + port);
});
JSEOF

node "${FILE_PATH}/argo_server.js" "$ARGO_PORT" &
ARGO_HTTP_PID=$!

# =========================================================
# Nezha V1（下载 + 配置 + 启动）
# =========================================================
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

  cat > "$NEZHA_CFG" <<NEZHA_EOF
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
NEZHA_EOF

  echo "[Nezha] 启动 V1 agent（tls=${tls}）..."
  nohup "$NEZHA_BIN" -c "$NEZHA_CFG" >"$NEZHA_LOG" 2>&1 &
  NEZHA_PID=$!
  sleep 1

  if ! kill -0 "$NEZHA_PID" 2>/dev/null; then
    echo "[Nezha] 启动失败，最近日志："
    tail -n 80 "$NEZHA_LOG" || true
    return 0
  fi

  echo "[Nezha] 已启动 PID: $NEZHA_PID"
  return 0
}

start_nezha_v1

# =========================================================
# Argo：固定 or 临时
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
# 节点信息输出（日志可复制）
# =========================================================
cat <<INFO

===================================================
节点信息（日志可复制）
vless://${UUID}@${ARGO_DOMAIN}:443?encryption=none&security=tls&sni=${ARGO_DOMAIN}&type=ws&host=${ARGO_DOMAIN}&path=%2F${UUID}-vless
===================================================
INFO

wait $ARGO_PID
