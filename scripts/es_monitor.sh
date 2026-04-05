#!/bin/bash
# Elasticsearch索引监控脚本
# 检测索引异常删除、勒索索引出现

INDEX_NAME="${INDEX_NAME:-moredoc-v2}"
ALERT_FILE="${ALERT_FILE:-/www/backup/logs/es_alert.log}"
LOG_FILE="${LOG_FILE:-/www/backup/logs/es_monitor.log}"
WEBHOOK_URL="${WEBHOOK_URL:-}"  # 钉钉/微信webhook

log_alert() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$ALERT_FILE"

    # 发送通知（如果配置了webhook）
    if [ -n "$WEBHOOK_URL" ]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"$msg\"}" > /dev/null 2>&1
    fi
}

# 检查ES是否运行
if ! curl -s -m 5 "http://127.0.0.1:9200/_cluster/health" > /dev/null 2>&1; then
    log_alert "严重：ES服务无响应！"
    exit 1
fi

# 获取当前文档数
DOC_COUNT=$(curl -s -m 5 "http://127.0.0.1:9200/$INDEX_NAME/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2)

# 处理无效响应
if [ -z "$DOC_COUNT" ] || ! [[ "$DOC_COUNT" =~ ^[0-9]+$ ]]; then
    DOC_COUNT=0
    # 检查索引是否存在
    if ! curl -s -m 5 "http://127.0.0.1:9200/$INDEX_NAME" 2>/dev/null | grep -q "error"; then
        log_alert "严重：索引 $INDEX_NAME 不存在！"
    fi
fi

# 获取上次记录的文档数
LAST_COUNT_FILE="/tmp/es_last_count"
if [ -f "$LAST_COUNT_FILE" ]; then
    LAST_COUNT=$(cat "$LAST_COUNT_FILE")
    if ! [[ "$LAST_COUNT" =~ ^[0-9]+$ ]]; then
        LAST_COUNT=0
    fi

    # 文档数异常减少检测（减少超过50%且减少超过100篇）
    if [ "$LAST_COUNT" -gt 100 ] && [ "$DOC_COUNT" -gt 0 ] && [ "$DOC_COUNT" -lt $((LAST_COUNT / 2)) ]; then
        log_alert "警报：索引文档数异常减少！从 $LAST_COUNT 降到 $DOC_COUNT"
    fi
fi

# 记录当前文档数
echo "$DOC_COUNT" > "$LAST_COUNT_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 文档数: $DOC_COUNT" >> "$LOG_FILE"

# 检查勒索索引是否存在（Meow Attack特征）
if curl -s -m 5 "http://127.0.0.1:9200/_cat/indices" 2>/dev/null | grep -q "read_me"; then
    log_alert "警报：检测到勒索索引 read_me！服务器可能已被攻击！"
fi

# 检查其他可疑索引名称
SUSPICIOUS_INDICES=$(curl -s -m 5 "http://127.0.0.1:9200/_cat/indices" 2>/dev/null | grep -E "contact_me|restore_me|backup_me|delete_me" | awk '{print $3}')
if [ -n "$SUSPICIOUS_INDICES" ]; then
    log_alert "警报：检测到可疑索引：$SUSPICIOUS_INDICES"
fi