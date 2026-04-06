#!/bin/bash
# Nginx 安全配置检查
# 使用方法:
#   ./nginx_check.sh           # 本地执行
#   ./nginx_check.sh --remote user@ip  # 通过SSH远程执行
#   ./nginx_check.sh --json    # JSON输出

set -e

# 参数解析
OUTPUT_MODE="human"
REMOTE_HOST=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --json)
            OUTPUT_MODE="json"
            shift
            ;;
        --remote)
            REMOTE_HOST="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# 执行命令的包装函数
run_cmd() {
    if [ -n "$REMOTE_HOST" ]; then
        ssh -o StrictHostKeyChecking=accept-new "$REMOTE_HOST" "$1" 2>/dev/null || echo ""
    else
        eval "$1" 2>/dev/null || echo ""
    fi
}

if [ "$OUTPUT_MODE" = "json" ]; then
    echo "🔍 正在检查 Nginx 安全配置..." >&2
    FINDINGS="[]"
else
    echo "=== Nginx 安全配置检查 ==="
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    [ -n "$REMOTE_HOST" ] && echo "目标: $REMOTE_HOST"
    echo ""
fi

# 检查 Nginx 是否安装
NGINX_INSTALLED=$(run_cmd "which nginx")
if [ -z "$NGINX_INSTALLED" ]; then
    if [ "$OUTPUT_MODE" = "json" ]; then
        echo '{"timestamp": "'$TIMESTAMP'", "status": "SKIPPED", "message": "Nginx not installed"}'
    else
        echo "⏭️  Nginx 未安装，跳过检查"
    fi
    exit 0
fi

# 1. 检查版本暴露
check_version_token() {
    local result=$(run_cmd "grep -r 'server_tokens' /etc/nginx/ 2>/dev/null | grep -v '#' | head -1")
    local version_exposed="true"

    if echo "$result" | grep -q "off"; then
        version_exposed="false"
    fi

    if [ "$OUTPUT_MODE" = "json" ]; then
        if [ "$version_exposed" = "true" ]; then
            finding='{"id": "NGINX-001", "type": "VERSION_EXPOSED", "severity": "MEDIUM", "description": "Nginx version is exposed in HTTP headers", "recommendation": "Add server_tokens off; to nginx.conf"}'
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]' 2>/dev/null || echo "[]")
        fi
    else
        if [ "$version_exposed" = "true" ]; then
            echo "[🟡 中危] Nginx 版本号暴露"
            echo "  └─ 建议: 在 nginx.conf 中添加 server_tokens off;"
        else
            echo "[✅] 版本号已隐藏"
        fi
    fi
}

# 2. 检查请求限流配置
check_rate_limit() {
    local result=$(run_cmd "grep -r 'limit_req' /etc/nginx/ 2>/dev/null | grep -v '#' | head -1")
    local has_rate_limit="false"

    if [ -n "$result" ]; then
        has_rate_limit="true"
    fi

    if [ "$OUTPUT_MODE" = "json" ]; then
        if [ "$has_rate_limit" = "false" ]; then
            finding='{"id": "NGINX-002", "type": "NO_RATE_LIMIT", "severity": "MEDIUM", "description": "No rate limiting configured, vulnerable to brute force and CC attacks", "recommendation": "Configure limit_req_zone and limit_req directives"}'
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]' 2>/dev/null || echo "[]")
        fi
    else
        if [ "$has_rate_limit" = "false" ]; then
            echo "[🟡 中危] 未配置请求限流"
            echo "  └─ 建议: 配置 limit_req_zone 防止 CC 攻击和暴力破解"
        else
            echo "[✅] 已配置请求限流"
        fi
    fi
}

# 3. 检查敏感文件保护
check_sensitive_files() {
    local result=$(run_cmd "grep -rE 'location.*\.(env|yml|yaml|git|htaccess)' /etc/nginx/ 2>/dev/null | grep -v '#' | head -5")
    local has_protection="false"

    if echo "$result" | grep -q "deny"; then
        has_protection="true"
    fi

    if [ "$OUTPUT_MODE" = "json" ]; then
        if [ "$has_protection" = "false" ]; then
            finding='{"id": "NGINX-003", "type": "SENSITIVE_FILES_EXPOSED", "severity": "HIGH", "description": "Sensitive files (.env, .yml, .git) may be accessible via web", "recommendation": "Add deny rules for sensitive file extensions"}'
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]' 2>/dev/null || echo "[]")
        fi
    else
        if [ "$has_protection" = "false" ]; then
            echo "[🟠 高危] 敏感文件可能通过 Web 访问"
            echo "  └─ 建议: 在 Nginx 中添加 .env/.yml/.git 的 deny 规则"
        else
            echo "[✅] 敏感文件保护已配置"
        fi
    fi
}

# 4. 检查 SSL/TLS 配置
check_ssl() {
    local ssl_config=$(run_cmd "grep -rE 'ssl_protocols|ssl_ciphers' /etc/nginx/ 2>/dev/null | grep -v '#' | head -2")

    if [ "$OUTPUT_MODE" != "json" ]; then
        if [ -n "$ssl_config" ]; then
            echo "[✅] SSL/TLS 配置已设置"
            echo "$ssl_config" | while read line; do
                echo "  └─ $line"
            done
        else
            echo "[ℹ️] 未检测到 SSL 配置（可能使用 HTTP 或在其他位置配置）"
        fi
    fi
}

# 5. 检查隐藏文件访问
check_hidden_files() {
    local result=$(run_cmd "grep -r 'location ~ /\.' /etc/nginx/ 2>/dev/null | grep -v '#' | head -1")
    local has_protection="false"

    if echo "$result" | grep -q "deny"; then
        has_protection="true"
    fi

    if [ "$OUTPUT_MODE" = "json" ]; then
        if [ "$has_protection" = "false" ]; then
            finding='{"id": "NGINX-004", "type": "HIDDEN_FILES_EXPOSED", "severity": "MEDIUM", "description": "Hidden files (.git, .htaccess, .env) directories may be accessible", "recommendation": "Add location ~ /\\. { deny all; }"}'
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]' 2>/dev/null || echo "[]")
        fi
    else
        if [ "$has_protection" = "false" ]; then
            echo "[🟡 中危] 隐藏目录/文件可能可访问"
            echo "  └─ 建议: 添加 location ~ /\\. { deny all; }"
        else
            echo "[✅] 隐藏文件访问已阻止"
        fi
    fi
}

# 执行所有检查
check_version_token
check_rate_limit
check_sensitive_files
check_ssl
check_hidden_files

# 输出结果
if [ "$OUTPUT_MODE" = "json" ]; then
    cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "status": "COMPLETE",
  "findings": $FINDINGS,
  "summary": {
    "total_findings": $(echo "$FINDINGS" | jq 'length' 2>/dev/null || echo "0")
  }
}
EOF
else
    echo ""
    echo "================================"
    total=$(echo "$FINDINGS" | jq 'length' 2>/dev/null || echo "0")
    if [ "$total" -gt 0 ]; then
        echo "⚠️  发现 $total 个 Nginx 安全配置问题"
    else
        echo "✅ Nginx 安全配置检查通过"
    fi
fi