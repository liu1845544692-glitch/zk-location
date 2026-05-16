#!/usr/bin/env bash
# 文件功能：
# - 自动探测可用本地代理，并写入 VS Code workspace settings。
# 执行流程：
# 1. 创建 .vscode 目录。
# 2. choose_proxy 按常见端口探测 HTTP/SOCKS5。
# 3. 找到代理则写入 http.proxy；找不到则写入无 proxy 的 fallback 配置。
set -u

# PORTS：常见本地代理端口候选。
PORTS=(7890 7891 1080 10808 20171 9090 8080)
# URL：用于验证代理是否可访问外网。
URL="https://api.ipify.org"
# SETTINGS_FILE：VS Code workspace 配置文件。
SETTINGS_FILE=".vscode/settings.json"

mkdir -p .vscode

choose_proxy() {
  # p：当前探测的本地端口。
  for p in "${PORTS[@]}"; do
    if curl -sS --max-time 6 -x "http://127.0.0.1:$p" "$URL" >/dev/null 2>&1; then
      echo "http://127.0.0.1:$p"
      return 0
    fi
    if curl -sS --max-time 6 --proxy "socks5h://127.0.0.1:$p" "$URL" >/dev/null 2>&1; then
      echo "socks5://127.0.0.1:$p"
      return 0
    fi
  done
  return 1
}

PROXY=$(choose_proxy || true) # PROXY：探测成功的代理 URL，可能为空。

if [[ -n "$PROXY" ]]; then
  cat > "$SETTINGS_FILE" <<JSON
{
  "http.proxy": "$PROXY",
  "http.proxySupport": "override",
  "http.systemCertificates": true
}
JSON
  echo "proxy_configured $PROXY"
  cat "$SETTINGS_FILE"
else
  cat > "$SETTINGS_FILE" <<JSON
{
  "http.proxySupport": "override",
  "http.systemCertificates": true
}
JSON
  echo "no_local_proxy_detected"
  echo "fallback_config_written_without_http_proxy"
  cat "$SETTINGS_FILE"
  exit 2
fi
