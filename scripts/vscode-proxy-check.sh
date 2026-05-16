#!/usr/bin/env bash
# 文件功能：
# - 检查 VS Code/Codex 环境里的代理配置和本地代理端口可用性。
# 执行流程：
# 1. 打印 .vscode/settings.json。
# 2. 打印环境变量代理。
# 3. 测试直连外网。
# 4. 依次探测常见 HTTP/SOCKS 本地代理端口。
set -u

# PORTS：常见本地代理监听端口候选。
PORTS=(7890 7891 1080 10808 20171 9090 8080)
# URL：用于探测外网连通性的轻量 endpoint。
URL="https://api.ipify.org"

echo "[1/4] VS Code workspace proxy settings"
if [[ -f .vscode/settings.json ]]; then
  cat .vscode/settings.json
else
  echo "missing .vscode/settings.json"
fi

echo
echo "[2/4] Environment proxy variables"
env | grep -iE '^(http_proxy|https_proxy|all_proxy|no_proxy)=' || echo "(none)"

echo
echo "[3/4] Direct connectivity"
DIRECT=$(curl -sS --max-time 6 "$URL" 2>/dev/null || true)
if [[ -n "$DIRECT" ]]; then
  echo "direct_ok $DIRECT"
else
  echo "direct_failed"
fi

echo
echo "[4/4] Local proxy probes"
FOUND=0 # FOUND：是否探测到至少一个本地代理。
for p in "${PORTS[@]}"; do
  # HTTP_IP/SOCKS_IP：分别通过 HTTP 和 SOCKS5 代理探测到的公网 IP。
  HTTP_IP=$(curl -sS --max-time 6 -x "http://127.0.0.1:$p" "$URL" 2>/dev/null || true)
  SOCKS_IP=$(curl -sS --max-time 6 --proxy "socks5h://127.0.0.1:$p" "$URL" 2>/dev/null || true)
  if [[ -n "$HTTP_IP" ]]; then
    FOUND=1
    echo "http_ok 127.0.0.1:$p ip=$HTTP_IP"
  fi
  if [[ -n "$SOCKS_IP" ]]; then
    FOUND=1
    echo "socks5_ok 127.0.0.1:$p ip=$SOCKS_IP"
  fi
done

if [[ "$FOUND" -eq 0 ]]; then
  echo "no_local_proxy_detected"
  echo "hint: start your VPN client and enable local proxy or TUN/system proxy mode"
fi
