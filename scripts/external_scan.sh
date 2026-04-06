#!/bin/bash
# 外部端口扫描 - 在本机执行，扫描远程服务器公网暴露端口
# 使用方法:
#   ./external_scan.sh <目标公网IP>
#   ./external_scan.sh 104.250.159.108
#   ./external_scan.sh 104.250.159.108 --json
#
# 依赖: nmap (Windows 用户可用 WSL 或安装 Nmap for Windows)

set -e

# 参数解析
TARGET_IP=""
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
            if [ -z "$TARGET_IP" ]; then
                TARGET_IP="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$TARGET_IP" ]; then
    echo "用法: $0 <目标公网IP> [--json]"
    echo "示例: $0 104.250.159.108 --json"
    exit 1
fi

# 敏感端口列表
SENSITIVE_PORTS="9200,9300,6379,6380,27017,2375,2376,2379,2380,19530,11211,3306,5432,8088,9000,9001"

# 依赖检查
if ! command -v nmap &>/dev/null; then
    if [ "$OUTPUT_MODE" = "json" ]; then
        echo '{"error": "nmap is required. Install with: winget install nmap or use WSL", "status": "FAILED"}'
    else
        echo "[错误] 需要安装 nmap"
        echo "Windows: winget install nmap 或从 https://nmap.org/download.html 下载"
        echo "Linux/WSL: sudo apt install nmap"
    fi
    exit 1
fi

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

if [ "$OUTPUT_MODE" = "json" ]; then
    echo "🔍 正在从本机扫描 $TARGET_IP 的敏感端口..." >&2
else
    echo "=== 外部端口安全扫描 ==="
    echo "目标: $TARGET_IP"
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
fi

# 执行 Nmap 扫描
# -Pn: 跳过主机发现（假设主机在线）
# -sT: TCP 连接扫描（兼容性最好，无需 root）
# -T4: 快速扫描
# --open: 只显示开放端口
SCAN_OUTPUT=$(nmap -Pn -sT -T4 --open -p "$SENSITIVE_PORTS" "$TARGET_IP" 2>/dev/null || echo "")

# 解析结果
OPEN_PORTS=""
FINDINGS="[]"
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0

# 从 nmap 输出提取开放端口
OPEN_PORTS=$(echo "$SCAN_OUTPUT" | grep -E "^[0-9]+/tcp" | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

# 检查每个开放端口
if [ -n "$OPEN_PORTS" ]; then
    IFS=',' read -ra PORTS <<< "$OPEN_PORTS"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | tr -d ' ')
        [ -z "$port" ] && continue

        # 确定服务和风险等级
        service=""
        severity="HIGH"
        case $port in
            2375|2376) service="Docker-Daemon"; severity="CRITICAL" ;;
            9200|9300) service="Elasticsearch"; severity="CRITICAL" ;;
            6379|6380) service="Redis"; severity="CRITICAL" ;;
            27017) service="MongoDB"; severity="CRITICAL" ;;
            2379|2380) service="etcd"; severity="HIGH" ;;
            19530) service="Milvus"; severity="HIGH" ;;
            11211) service="Memcached"; severity="HIGH" ;;
            8088) service="Hadoop-YARN"; severity="HIGH" ;;
            3306) service="MySQL"; severity="HIGH" ;;
            5432) service="PostgreSQL"; severity="HIGH" ;;
            9000|9001) service="MinIO"; severity="MEDIUM" ;;
            *) service="Unknown"; severity="MEDIUM" ;;
        esac

        if [ "$OUTPUT_MODE" = "json" ]; then
            finding=$(cat <<EOF
{
  "id": "EXT-$port",
  "type": "EXTERNAL_EXPOSED",
  "severity": "$severity",
  "port": $port,
  "service": "$service",
  "description": "$service port $port is accessible from public internet",
  "recommendation": "Close port or restrict access via firewall/security group"
}
EOF
)
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]' 2>/dev/null || echo "[]")
            case "$severity" in
                CRITICAL) ((CRITICAL_COUNT++)) ;;
                HIGH) ((HIGH_COUNT++)) ;;
                MEDIUM) ((MEDIUM_COUNT++)) ;;
            esac
        else
            icon=""
            case "$severity" in
                CRITICAL) icon="🔴 极危" ;;
                HIGH) icon="🟠 高危" ;;
                MEDIUM) icon="🟡 中危" ;;
            esac
            echo "[$icon] 端口 $port ($service) 从公网可访问！"
        fi
    done
else
    if [ "$OUTPUT_MODE" != "json" ]; then
        echo "✅ 未检测到敏感端口从公网暴露"
    fi
fi

# 输出结果
if [ "$OUTPUT_MODE" = "json" ]; then
    cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "target": "$TARGET_IP",
  "status": "COMPLETE",
  "scan_type": "external",
  "open_ports": "$OPEN_PORTS",
  "findings": $FINDINGS,
  "summary": {
    "total_findings": $(echo "$FINDINGS" | jq 'length' 2>/dev/null || echo "0"),
    "critical": $CRITICAL_COUNT,
    "high": $HIGH_COUNT,
    "medium": $MEDIUM_COUNT
  }
}
EOF
else
    echo ""
    echo "================================"
    if [ -n "$OPEN_PORTS" ]; then
        echo "⚠️  检测到 $(echo "$OPEN_PORTS" | tr ',' '\n' | wc -l) 个敏感端口公网暴露！"
        echo "请立即检查服务器防火墙和云安全组配置"
    else
        echo "✅ 结论: 敏感端口未从公网暴露"
    fi
fi