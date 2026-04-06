#!/bin/bash
# 源站 IP 暴露检测
# 检测域名是否通过 CDN 保护，以及源站真实 IP 是否暴露
# 使用方法:
#   ./source_ip_check.sh example.com
#   ./source_ip_check.sh example.com --json

set -e

# 参数解析
DOMAIN=""
OUTPUT_MODE="human"

while [[ $# -gt 0 ]]; do
    case $1 in
        --json)
            OUTPUT_MODE="json"
            shift
            ;;
        -*)
            shift
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    echo "用法: $0 <域名> [--json]"
    echo "示例: $0 example.com --json"
    exit 1
fi

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# 依赖检查
for cmd in dig curl; do
    if ! command -v $cmd &>/dev/null; then
        if [ "$OUTPUT_MODE" = "json" ]; then
            echo "{\"error\": \"$cmd is required\", \"status\": \"FAILED\"}"
        else
            echo "[错误] 需要安装 $cmd"
        fi
        exit 1
    fi
done

if [ "$OUTPUT_MODE" = "json" ]; then
    echo "🔍 正在检测 $DOMAIN 的源站 IP 暴露情况..." >&2
else
    echo "=== 源站 IP 暴露检测 ==="
    echo "域名: $DOMAIN"
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
fi

# 获取域名解析的 IP
DOMAIN_IPS=$(dig +short "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.' | tr '\n' ',' | sed 's/,$//')

if [ -z "$DOMAIN_IPS" ]; then
    if [ "$OUTPUT_MODE" = "json" ]; then
        echo "{\"timestamp\": \"$TIMESTAMP\", \"domain\": \"$DOMAIN\", \"status\": \"FAILED\", \"error\": \"Domain does not resolve\"}"
    else
        echo "[错误] 域名无法解析"
    fi
    exit 1
fi

# 检查是否使用 Cloudflare
is_cloudflare_ip() {
    local ip="$1"
    # Cloudflare IP 段
    local cf_ranges=(
        "173.245.48.0/20"
        "103.21.244.0/22"
        "103.22.200.0/22"
        "103.31.4.0/22"
        "141.101.64.0/18"
        "108.162.192.0/18"
        "190.93.240.0/20"
        "188.114.96.0/20"
        "197.234.240.0/22"
        "198.41.128.0/17"
        "162.158.0.0/15"
        "104.16.0.0/13"
        "104.24.0.0/14"
        "172.64.0.0/13"
        "131.0.72.0/22"
    )

    # 简化检查：Cloudflare IP 通常以特定前缀开头
    for range in "${cf_ranges[@]}"; do
        local prefix=$(echo "$range" | cut -d'.' -f1-2)
        if [[ "$ip" == "$prefix"* ]]; then
            return 0
        fi
    done
    return 1
}

# 检查 IP 归属
check_ip_owner() {
    local ip="$1"
    # 使用 ipinfo.io API（免费版有限额）
    local info=$(curl -s "https://ipinfo.io/$ip/json" 2>/dev/null || echo "{}")

    if echo "$info" | grep -q "Cloudflare"; then
        echo "Cloudflare"
    elif echo "$info" | grep -q "Amazon"; then
        echo "AWS"
    elif echo "$info" | grep -q "Google"; then
        echo "Google"
    elif echo "$info" | grep -q "Alibaba"; then
        echo "阿里云"
    elif echo "$info" | grep -q "Tencent"; then
        echo "腾讯云"
    else
        # 默认检查 Cloudflare IP 段
        if is_cloudflare_ip "$ip"; then
            echo "Cloudflare"
        else
            echo "Unknown"
        fi
    fi
}

# 分析结果
FINDINGS="[]"
USES_CDN="false"
CDN_PROVIDER=""
EXPOSED_IPS=""

IFS=',' read -ra IPS <<< "$DOMAIN_IPS"
for ip in "${IPS[@]}"; do
    [ -z "$ip" ] && continue

    owner=$(check_ip_owner "$ip")

    if [ "$OUTPUT_MODE" = "json" ]; then
        echo "  IP: $ip -> $owner" >&2
    else
        echo "  📍 $ip ($owner)"
    fi

    if [ "$owner" = "Cloudflare" ]; then
        USES_CDN="true"
        CDN_PROVIDER="Cloudflare"
    else
        # 非 CDN IP，可能是源站暴露
        if [ "$owner" != "Unknown" ] && [ "$owner" != "Cloudflare" ]; then
            EXPOSED_IPS="$EXPOSED_IPS$ip,"
            if [ "$OUTPUT_MODE" = "json" ]; then
                finding="{\"id\": \"IP-EXPOSED\", \"type\": \"SOURCE_IP_EXPOSED\", \"severity\": \"HIGH\", \"ip\": \"$ip\", \"owner\": \"$owner\", \"description\": \"Potential source IP exposed: $ip ($owner)\", \"recommendation\": \"Configure CDN to hide source IP, restrict server firewall to CDN IPs only\"}"
                FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]' 2>/dev/null || echo "[]")
            fi
        fi
    fi
done

EXPOSED_IPS=$(echo "$EXPOSED_IPS" | sed 's/,$//')

# 输出结果
if [ "$OUTPUT_MODE" = "json" ]; then
    cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "domain": "$DOMAIN",
  "status": "COMPLETE",
  "resolved_ips": "$DOMAIN_IPS",
  "uses_cdn": $USES_CDN,
  "cdn_provider": "$CDN_PROVIDER",
  "exposed_source_ips": "$EXPOSED_IPS",
  "findings": $FINDINGS,
  "summary": {
    "total_findings": $(echo "$FINDINGS" | jq 'length' 2>/dev/null || echo "0"),
    "source_ip_exposed": $([ -n "$EXPOSED_IPS" ] && echo "true" || echo "false")
  }
}
EOF
else
    echo ""
    echo "================================"
    if [ "$USES_CDN" = "true" ]; then
        echo "✅ 域名使用 CDN 保护 ($CDN_PROVIDER)"
    else
        echo "⚠️  域名未使用 CDN 保护"
    fi

    if [ -n "$EXPOSED_IPS" ]; then
        echo "🟠 检测到可能的源站 IP: $EXPOSED_IPS"
        echo "   攻击者可绕过 CDN 直接攻击源站！"
        echo ""
        echo "修复建议:"
        echo "  1. 在服务器防火墙中只允许 CDN IP 访问"
        echo "  2. 修改源站 IP（如果已被公开）"
        echo "  3. 使用 Cloudflare 的源站保护功能"
    else
        echo "✅ 未检测到源站 IP 暴露"
    fi
fi