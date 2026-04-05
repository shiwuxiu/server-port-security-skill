# Docker 端口安全修复指南

本文档提供各类Docker服务的端口安全修复方案，确保容器端口不会暴露到公网。

---

## 核心原则

> ⚠️ **最重要**：Docker 会直接修改 iptables，UFW 防火墙无法阻止 Docker 暴露的端口。
>
> **唯一有效的修复方式是修改容器的端口绑定到 `127.0.0.1`。**

### 端口绑定对比

| 写法 | 绑定地址 | 外部访问 |
|------|----------|----------|
| `-p 9200:9200` | 0.0.0.0 (所有接口) | ❌ 危险 |
| `-p 0.0.0.0:9200:9200` | 0.0.0.0 (所有接口) | ❌ 危险 |
| `-p 127.0.0.1:9200:9200` | 127.0.0.1 (仅本地) | ✅ 安全 |

---

## 一、Elasticsearch 修复

### 1.1 风险说明

- **端口**: 9200 (HTTP API), 9300 (Transport)
- **风险等级**: 🔴 严重
- **攻击类型**: Meow Attack 勒索攻击、数据删除

### 1.2 修复步骤

```bash
# ===== 第一步：备份现有数据 =====
# 确认数据卷位置
docker inspect elasticsearch --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}'

# 备份数据（如果有重要数据）
BACKUP_DIR="/tmp/es_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /www/web/moredoc/es_data "$BACKUP_DIR/"

# ===== 第二步：停止并删除旧容器 =====
docker stop elasticsearch
docker rm elasticsearch

# ===== 第三步：创建新容器（端口绑定本地） =====
docker run -d --name elasticsearch --restart=always \
  -p 127.0.0.1:9200:9200 \
  -p 127.0.0.1:9300:9300 \
  -e "discovery.type=single-node" \
  -e "ES_JAVA_OPTS=-Xms8g -Xmx8g" \
  -e "xpack.security.enabled=false" \
  -e "path.repo=/usr/share/elasticsearch/backup" \
  -v /www/web/moredoc/es_data:/usr/share/elasticsearch/data \
  -v /www/web/moredoc/es_backup:/usr/share/elasticsearch/backup \
  --cpus="2" \
  --memory="8g" \
  elasticsearch:8.11.0

# ===== 第四步：验证修复 =====
# 内部访问应该正常
curl -s http://127.0.0.1:9200/_cluster/health?pretty

# 外部访问应该被阻止
curl -m 5 http://<公网IP>:9200
# 期望: Connection refused 或 timeout
```

### 1.3 删除勒索索引（如果存在）

```bash
# 检查是否存在勒索索引
curl -s "http://127.0.0.1:9200/_cat/indices?v" | grep read_me

# 删除勒索索引
curl -X DELETE "http://127.0.0.1:9200/read_me"
```

### 1.4 创建快照仓库

```bash
# 创建快照仓库
curl -X PUT "http://127.0.0.1:9200/_snapshot/moredoc_snapshot" \
  -H 'Content-Type: application/json' -d '{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/backup/moredoc_snapshot",
    "compress": true
  }
}'

# 创建快照
curl -X PUT "http://127.0.0.1:9200/_snapshot/moredoc_snapshot/snapshot_$(date +%Y%m%d)?wait_for_completion=true"
```

---

## 二、Redis 修复

### 2.1 风险说明

- **端口**: 6379, 6380
- **风险等级**: 🔴 严重
- **攻击类型**: 挖矿木马、写入SSH公钥、数据篡改

### 2.2 修复步骤

```bash
# ===== 第一步：生成强密码 =====
REDIS_PASSWORD=$(openssl rand -base64 32)
echo "Redis密码已生成: $REDIS_PASSWORD"
# 重要：请保存此密码，并更新到应用配置文件！

# ===== 第二步：停止旧容器 =====
docker stop fayin-redis 2>/dev/null || true
docker rm fayin-redis 2>/dev/null || true

# ===== 第三步：创建新容器（端口绑定本地 + 密码） =====
docker run -d --name fayin-redis --restart=always \
  --network fayin_fayin-network \
  -p 127.0.0.1:6380:6379 \
  --cpus="1" \
  --memory="1g" \
  redis:7.2.4 redis-server --requirepass "$REDIS_PASSWORD"

# ===== 第四步：验证 =====
# 无密码应该被拒绝
echo "PING" | nc -w 2 127.0.0.1 6380
# 期望: NOAUTH Authentication required

# 有密码应该成功
redis-cli -h 127.0.0.1 -p 6380 -a "$REDIS_PASSWORD" PING
# 期望: PONG
```

### 2.3 更新应用配置

```yaml
# 在应用的配置文件中更新Redis密码
# 例如: docker-compose.yml 或 .env 文件
redis:
  password: "YOUR_GENERATED_PASSWORD"
```

---

## 三、etcd 修复

### 3.1 风险说明

- **端口**: 2379 (Client), 2380 (Peer)
- **风险等级**: 🟠 高
- **影响**: Milvus 依赖，可能导致数据丢失

### 3.2 修复步骤

```bash
# ===== 第一步：备份数据 =====
BACKUP_DIR="/tmp/etcd_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
tar -czvf "$BACKUP_DIR/etcd_data.tar.gz" /var/lib/etcd

# ===== 第二步：停止并删除旧容器 =====
docker stop etcd 2>/dev/null || true
docker rm etcd 2>/dev/null || true

# ===== 第三步：创建新容器 =====
docker run -d --name etcd --restart=always \
  -p 127.0.0.1:2379:2379 \
  -p 127.0.0.1:2380:2380 \
  -e ALLOW_NONE_AUTHENTICATION=yes \
  -e ETCD_ADVERTISE_CLIENT_URLS=http://etcd:2379 \
  -e ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379 \
  -v /var/lib/etcd:/etcd \
  --cpus="1" \
  --memory="512m" \
  quay.io/coreos/etcd:v3.5.5

# ===== 第四步：验证 =====
curl -s http://127.0.0.1:2379/health
# 期望: {"health":"true"}
```

---

## 四、Milvus 修复

### 4.1 风险说明

- **端口**: 19530 (gRPC), 9091 (Metrics)
- **风险等级**: 🟠 高
- **影响**: 向量数据泄露

### 4.2 修复步骤

```bash
# ===== 第一步：备份数据 =====
BACKUP_DIR="/tmp/milvus_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
tar -czvf "$BACKUP_DIR/milvus_data.tar.gz" /var/lib/milvus

# ===== 第二步：停止并删除旧容器 =====
docker stop milvus 2>/dev/null || true
docker rm milvus 2>/dev/null || true

# ===== 第三步：创建新容器 =====
docker run -d --name milvus --restart=always \
  -p 127.0.0.1:19530:19530 \
  -p 127.0.0.1:9091:9091 \
  -e ETCD_ENDPOINTS=etcd:2379 \
  -e COMMON_STORAGETYPE=local \
  -v /var/lib/milvus:/var/lib/milvus \
  --link etcd:etcd \
  --cpus="2" \
  --memory="4g" \
  milvusdb/milvus:v2.4.9 milvus run standalone

# ===== 第四步：验证 =====
curl -s http://127.0.0.1:9091/api/v1/health
```

---

## 五、MongoDB 修复

### 5.1 风险说明

- **端口**: 27017
- **风险等级**: 🔴 严重
- **攻击类型**: 勒索攻击

### 5.2 修复步骤

```bash
# ===== 第一步：备份数据 =====
docker exec mongodb mongodump --out /tmp/backup
docker cp mongodb:/tmp/backup ./mongodb_backup_$(date +%Y%m%d)

# ===== 第二步：创建管理员用户 =====
docker exec -it mongodb mongo admin
# 在mongo shell中执行:
# db.createUser({ user: "admin", pwd: "YOUR_STRONG_PASSWORD", roles: [{ role: "userAdminAnyDatabase", db: "admin" }] })

# ===== 第三步：停止并删除旧容器 =====
docker stop mongodb
docker rm mongodb

# ===== 第四步：创建新容器（认证 + 本地绑定） =====
docker run -d --name mongodb --restart=always \
  -p 127.0.0.1:27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=YOUR_STRONG_PASSWORD \
  -v mongodb_data:/data/db \
  --cpus="2" \
  --memory="4g" \
  mongo:7.0 --auth
```

---

## 六、MinIO 修复

### 6.1 风险说明

- **端口**: 9000 (API), 9001 (Console)
- **风险等级**: 🟡 中
- **注意**: Console 端口绝对不要暴露公网

### 6.2 修复步骤

```bash
# ===== 第一步：停止旧容器 =====
docker stop fayin-minio 2>/dev/null || true
docker rm fayin-minio 2>/dev/null || true

# ===== 第二步：创建新容器 =====
docker run -d --name fayin-minio --restart=always \
  --network fayin_fayin-network \
  -p 127.0.0.1:9002:9000 \
  -p 127.0.0.1:9003:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=YOUR_STRONG_PASSWORD \
  -v fayin_minio_data:/data \
  --cpus="1" \
  --memory="2g" \
  minio/minio server /data --console-address ':9001'

# ===== 如果 API 必须公网访问 =====
# 使用 Nginx 反向代理 + HTTPS
# 绝不直接暴露 9000 端口
```

---

## 七、Docker Compose 模板

### 7.1 安全的 docker-compose.yml 示例

```yaml
version: '3.8'

services:
  elasticsearch:
    image: elasticsearch:8.11.0
    container_name: elasticsearch
    restart: always
    ports:
      - "127.0.0.1:9200:9200"  # 只绑定本地
      - "127.0.0.1:9300:9300"
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms8g -Xmx8g
      - xpack.security.enabled=false
    volumes:
      - ./es_data:/usr/share/elasticsearch/data
      - ./es_backup:/usr/share/elasticsearch/backup
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 8G
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200/_cluster/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7.2.4
    container_name: redis
    restart: always
    ports:
      - "127.0.0.1:6379:6379"
    command: redis-server --requirepass ${REDIS_PASSWORD}
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
    security_opt:
      - no-new-privileges:true

  # ... 其他服务
```

---

## 八、验证清单

### 8.1 端口验证

```bash
# 检查所有敏感端口是否只绑定本地
netstat -tlnp | grep -E '9200|6379|6380|2379|27017|19530'

# 期望输出示例：
# tcp  0  0 127.0.0.1:9200  0.0.0.0:*  LISTEN
# tcp  0  0 127.0.0.1:6379  0.0.0.0:*  LISTEN

# 如果看到 0.0.0.0 或 ::: 说明仍然暴露
```

### 8.2 外部可达性验证

```bash
# 从其他服务器测试
curl -m 5 http://<公网IP>:9200
curl -m 5 http://<公网IP>:6379

# 或使用在线工具
# https://www.yougetsignal.com/tools/open-ports/
```

### 8.3 Docker容器验证

```bash
# 检查容器端口映射
docker ps --format "table {{.Names}}\t{{.Ports}}"

# 确保敏感端口显示为 127.0.0.1:端口->端口
```

---

## 九、常见问题

### Q1: 修改端口绑定后服务无法访问？

**A**: 检查以下几点：
1. 应用配置是否使用了 `localhost` 或 `127.0.0.1` 连接
2. 如果是容器间通信，确保在同一个 Docker network
3. 检查防火墙是否阻止了本地回环

### Q2: UFW 为什么无法阻止 Docker 端口？

**A**: Docker 默认会修改 iptables 规则，优先级高于 UFW。
- 解决方案1：修改容器端口绑定（推荐）
- 解决方案2：修改 `/etc/docker/daemon.json` 添加 `{"iptables": false}`

### Q3: 如何查看 Docker 对 iptables 的修改？

```bash
iptables -L DOCKER-USER -n
# 如果只有 RETURN，说明 Docker 完全绕过了防火墙
```

---

## 十、修复后监控

### 10.1 部署监控脚本

```bash
# 复制监控脚本到服务器
scp scripts/es_monitor.sh user@server:/www/backup/scripts/
scp scripts/port_monitor.sh user@server:/www/backup/scripts/

# 添加定时任务
crontab -e
# 添加以下行：
# */5 * * * * /www/backup/scripts/es_monitor.sh >/dev/null 2>&1
# 0 * * * * /www/backup/scripts/port_monitor.sh >/dev/null 2>&1
```

### 10.2 检查监控日志

```bash
tail -f /www/backup/logs/es_monitor.log
tail -f /www/backup/logs/port_alert.log
```