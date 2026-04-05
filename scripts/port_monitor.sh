#!/bin/bash
# 端口暴露监控脚本
# 定期检测敏感端口是否暴露到公网

ALERT_FILE="${ALERT_FILE:-/www/backup/logs/port_alert.log}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
SENSITIVE_PORTS="9200 9300 6379 6380 27017 2375 2376 2379 2380 19530 11211 3306 5432"

log_alert() {
    local port="$1"
    local type="$2"
    local msg="警报：端口 $port 绑定到 $type 公网地址！"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$ALERT_FILE"

    if [ -n "$WEBHOOK_URL" ]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"$msg\"}" > /dev/null 2>&1
    fi
}

RISK_FOUND=0

for port in $SENSITIVE_PORTS; do
    # 检查IPv4暴露
    if netstat -tlnp 2>/dev/null | grep -q "0.0.0.0:$port"; then
        log_alert "$port" "0.0.0.0 (IPv4)"
        RISK_FOUND=1
    fi

    # 检查IPv6暴露（重要盲区）
    if netstat -tlnp 2>/dev/null | grep -q ":::$port"; then
        log_alert "$port" ":: (IPv6)"
        RISK_FOUND=1
    fi
done

# 检查Docker容器端口绑定
for port in $SENSITIVE_PORTS; do
    if docker ps --format "{{.Ports}}" 2>/dev/null | grep -qE "0\.0\.0\.0:$port|::$port"; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 警报：Docker容器暴露端口 $port 到公网！" >> "$ALERT_FILE"
        RISK_FOUND=1
    fi
done

# 检查勒索索引（如果ES运行）
if curl -s -m 5 "http://127.0.0.1:9200/_cat/indices" 2>/dev/null | grep -q "read_me"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 严重：检测到勒索索引！" >> "$ALERT_FILE"
    RISK_FOUND=1
fi

exit $RISK_FOUND