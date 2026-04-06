#!/bin/bash
# 端口扫描脚本 - 检测公网暴露的敏感端口
# 使用方法:
#   ./port_scan.sh           # 人类可读输出
#   ./port_scan.sh --json    # LLM友好JSON输出（仅stdout输出JSON）
#   ./port_scan.sh --verbose # 详细输出
#
# ⚠️ 流分离规范：
#   --json 模式下，所有非JSON文本必须重定向到stderr (>&2)
#   只有最终的JSON结果才能输出到stdout
#   这样确保 Claude Code 能正确解析JSON输出

set -e

# 解析参数
OUTPUT_MODE="human"
VERBOSE=""

# 依赖检查
if [ "$OUTPUT_MODE" = "json" ] && ! command -v jq &>/dev/null; then
    echo '{"error": "jq is required for JSON output mode. Install with: apt-get install jq", "status": "FAILED"}'
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --json)
            OUTPUT_MODE="json"
            shift
            ;;
        --verbose)
            VERBOSE="1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

SENSITIVE_PORTS="9200 9300 6379 6380 27017 2375 2376 2379 2380 19530 11211 3306 5432 8088 9000 9001"
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# 初始化JSON数组
if [ "$OUTPUT_MODE" = "json" ]; then
    FINDINGS="[]"
    CRITICAL_COUNT=0
    HIGH_COUNT=0
    MEDIUM_COUNT=0
    # 调试信息输出到stderr
    echo "🔍 正在扫描端口..." >&2
else
    echo "=== 端口安全扫描 ==="
    echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
fi

# 辅助函数：添加发现项
add_finding() {
    local id="$1"
    local type="$2"
    local severity="$3"
    local port="$4"
    local service="$5"
    local bind="$6"
    local description="$7"
    local recommendation="$8"

    if [ "$OUTPUT_MODE" = "json" ]; then
        local finding=$(cat <<EOF
{
  "id": "$id",
  "type": "$type",
  "severity": "$severity",
  "port": $port,
  "service": "$service",
  "bind_address": "$bind",
  "description": "$description",
  "recommendation": "$recommendation"
}
EOF
)
        FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]')
        case "$severity" in
            CRITICAL) ((CRITICAL_COUNT++)) ;;
            HIGH) ((HIGH_COUNT++)) ;;
            MEDIUM) ((MEDIUM_COUNT++)) ;;
        esac
    else
        local risk_label=""
        case "$severity" in
            CRITICAL) risk_label="🔴 极危" ;;
            HIGH) risk_label="🟠 高危" ;;
            MEDIUM) risk_label="🟡 中危" ;;
        esac
        echo "[$risk_label] 端口 $port ($service) 绑定到 $bind"
        echo "  └─ $description"
    fi
}

# 检查敏感端口暴露
check_sensitive_ports() {
    local finding_id=0

    for port in $SENSITIVE_PORTS; do
        # 获取端口对应的服务名
        local service=""
        case $port in
            9200|9300) service="Elasticsearch" ;;
            6379|6380) service="Redis" ;;
            27017) service="MongoDB" ;;
            2375|2376) service="Docker-Daemon" ;;
            2379|2380) service="etcd" ;;
            19530) service="Milvus" ;;
            11211) service="Memcached" ;;
            3306) service="MySQL" ;;
            5432) service="PostgreSQL" ;;
            8088) service="Hadoop-YARN" ;;
            9000|9001) service="MinIO" ;;
            *) service="Unknown" ;;
        esac

        # 检查IPv4暴露
        if netstat -tlnp 2>/dev/null | grep -q "0.0.0.0:$port"; then
            ((finding_id++))
            local severity="HIGH"
            local desc="$service 端口暴露到公网"
            local rec="重新绑定到 127.0.0.1"

            # Docker Daemon是极危
            if [ "$service" = "Docker-Daemon" ]; then
                severity="CRITICAL"
                desc="Docker Daemon API暴露，可导致容器逃逸"
                rec="立即关闭TCP端口或启用TLS认证"
            fi

            add_finding "FIND-$(printf '%03d' $finding_id)" "PORT_EXPOSED" "$severity" "$port" "$service" "0.0.0.0" "$desc" "$rec"
        fi

        # 检查IPv6暴露
        if netstat -tlnp 2>/dev/null | grep -q ":::$port"; then
            ((finding_id++))
            add_finding "FIND-$(printf '%03d' $finding_id)" "PORT_EXPOSED_IPV6" "HIGH" "$port" "$service" "::" "$service 端口通过IPv6暴露" "绑定到 127.0.0.1 或禁用IPv6"
        fi
    done
}

# 检查Docker绕过UFW
check_docker_bypass() {
    local docker_user=$(iptables -L DOCKER-USER -n 2>/dev/null)
    if echo "$docker_user" | grep -q "RETURN"; then
        if [ "$OUTPUT_MODE" = "json" ]; then
            local finding=$(cat <<EOF
{
  "id": "FIND-DOCKER-UFW",
  "type": "DOCKER_BYPASS_UFW",
  "severity": "HIGH",
  "description": "Docker is bypassing UFW firewall rules",
  "recommendation": "Modify container port bindings to 127.0.0.1"
}
EOF
)
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]')
            ((HIGH_COUNT++))
        else
            echo ""
            echo "--- Docker防火墙状态 ---"
            echo "[警告] Docker绕过UFW防火墙！必须修改容器端口绑定"
        fi
    fi
}

# 检查无认证服务
check_unauth_services() {
    if [ "$OUTPUT_MODE" != "json" ]; then
        echo ""
        echo "--- 无认证服务探测 ---"
    fi

    # Elasticsearch
    if curl -s -m 2 http://127.0.0.1:9200 > /dev/null 2>&1; then
        local es_response=$(curl -s -m 2 http://127.0.0.1:9200 2>/dev/null)
        if echo "$es_response" | grep -q "name"; then
            if [ "$OUTPUT_MODE" = "json" ]; then
                local finding=$(cat <<EOF
{
  "id": "FIND-ES-NOAUTH",
  "type": "NO_AUTHENTICATION",
  "severity": "CRITICAL",
  "service": "Elasticsearch",
  "port": 9200,
  "description": "Elasticsearch running without authentication",
  "recommendation": "Enable X-Pack Security or restrict to localhost"
}
EOF
)
                FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]')
                ((CRITICAL_COUNT++))
            else
                echo "[🔴 极危] Elasticsearch无认证运行"
            fi
        fi
    fi

    # Redis
    if echo "PING" | nc -w 2 127.0.0.1 6379 2>/dev/null | grep -q "PONG"; then
        if [ "$OUTPUT_MODE" = "json" ]; then
            local finding=$(cat <<EOF
{
  "id": "FIND-REDIS-NOAUTH",
  "type": "NO_AUTHENTICATION",
  "severity": "CRITICAL",
  "service": "Redis",
  "port": 6379,
  "description": "Redis running without password protection",
  "recommendation": "Set strong password with --requirepass"
}
EOF
)
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]')
            ((CRITICAL_COUNT++))
        else
            echo "[🔴 极危] Redis无密码保护"
        fi
    fi

    # Docker Daemon
    if curl -s -m 2 http://127.0.0.1:2375/version > /dev/null 2>&1; then
        if [ "$OUTPUT_MODE" = "json" ]; then
            local finding=$(cat <<EOF
{
  "id": "FIND-DOCKERD-EXPOSED",
  "type": "DOCKER_DAEMON_EXPOSED",
  "severity": "CRITICAL",
  "service": "Docker-Daemon",
  "port": 2375,
  "description": "Docker Daemon API exposed without authentication - full host compromise possible",
  "recommendation": "Immediately disable TCP listener or enable TLS"
}
EOF
)
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]')
            ((CRITICAL_COUNT++))
        else
            echo "[🔴 极危] Docker Daemon无认证暴露！"
        fi
    fi
}

# 检查勒索索引
check_ransom_indices() {
    if curl -s -m 2 "http://127.0.0.1:9200/_cat/indices" 2>/dev/null | grep -q "read_me"; then
        if [ "$OUTPUT_MODE" = "json" ]; then
            local finding=$(cat <<EOF
{
  "id": "FIND-RANSOM",
  "type": "RANSOMWARE_DETECTED",
  "severity": "CRITICAL",
  "description": "Ransom index 'read_me' detected - server may be compromised",
  "recommendation": "Investigate immediately, restore from backup if necessary"
}
EOF
)
            FINDINGS=$(echo "$FINDINGS" | jq --argjson f "$finding" '. + [$f]')
            ((CRITICAL_COUNT++))
        else
            echo ""
            echo "[🔴 极危] 检测到勒索索引 read_me！"
        fi
    fi
}

# 执行检查
check_sensitive_ports
check_docker_bypass
check_unauth_services
check_ransom_indices

# 输出结果
if [ "$OUTPUT_MODE" = "json" ]; then
    cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "status": "COMPLETE",
  "findings": $FINDINGS,
  "docker_bypassing_ufw": $(iptables -L DOCKER-USER -n 2>/dev/null | grep -q "RETURN" && echo "true" || echo "false"),
  "ransom_indices_detected": $(curl -s -m 2 "http://127.0.0.1:9200/_cat/indices" 2>/dev/null | grep -q "read_me" && echo "true" || echo "false"),
  "summary": {
    "total_findings": $(echo "$FINDINGS" | jq 'length'),
    "critical": $CRITICAL_COUNT,
    "high": $HIGH_COUNT,
    "medium": $MEDIUM_COUNT
  }
}
EOF
else
    echo ""
    if [ $(echo "$FINDINGS" | jq 'length' 2>/dev/null || echo "0") -eq 0 ]; then
        echo "=== ✅ 结论: 未发现敏感端口暴露 ==="
    else
        echo "=== ⚠️ 结论: 发现 $(echo "$FINDINGS" | jq 'length') 个风险项，需要修复！ ==="
    fi
fi