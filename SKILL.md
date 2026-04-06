---
name: server-port-security
description: |
  远程服务器安全审计工具。通过SSH扫描公网服务器端口，检测Docker绕过防火墙、
  数据库暴露（Redis/ES/Milvus）、勒索索引、无认证服务等安全隐患。

  触发场景：
  - 用户提到"端口安全"、"服务器被黑"、"勒索攻击"、"ES索引丢失"
  - 用户提到"Redis未授权"、"安全排查"、"端口扫描"、"Docker端口"
  - 用户请求"安全加固"、"防火墙配置"
  - 部署新服务后需要安全检查

  绝对不要在用户未明确授权时执行修复操作。
---

# 公网服务器端口安全维护 Skill

## LLM优化架构

### 执行通道：SSH原生集成

**设计原则**：脚本保存在本地版本库，服务器保持无状态和纯净。

```bash
# Claude Code 本地执行，通过SSH隧道远程取证
ssh -i ~/.ssh/id_rsa user@<服务器IP> 'bash -s' < scripts/port_scan.sh

# JSON输出（LLM友好）
ssh -i ~/.ssh/id_rsa user@<服务器IP> 'bash -s' < scripts/port_scan.sh -- --json
```

### 输出格式：LLM-Friendly JSON

**人类模式（默认）**：彩色表格输出
**Agent模式（`--json`）**：结构化JSON

```json
{
  "timestamp": "2026-04-06T10:00:00Z",
  "status": "COMPLETE",
  "findings": [
    {
      "id": "FIND-001",
      "type": "PORT_EXPOSED",
      "severity": "CRITICAL",
      "port": 6380,
      "service": "Redis",
      "bind_address": "0.0.0.0",
      "description": "Redis port exposed to public network",
      "recommendation": "Rebind to 127.0.0.1 and set password"
    }
  ],
  "summary": { "total_findings": 1, "critical": 1, "high": 0 }
}
```

### 护栏机制：Human-in-the-Loop

**⚠️ 绝对禁止AI越权自愈**

| 模式 | 行为 | 触发条件 |
|------|------|----------|
| 审计模式 | 只读检查，不修改 | 默认，无需确认 |
| 修复模式 | 执行修复 | **必须用户输入 `YES` 确认** |

```python
# 修复前强制确认流程
print("⚠️ Claude Code 正在尝试应用安全修复")
print("拟定操作: 重启 Redis 容器，绑定 127.0.0.1")
response = input("请输入 'YES' 确认执行: ")
if response != "YES":
    print("操作已取消")
    sys.exit(0)
```

---

## 核心原则

**⚠️ Docker绕过UFW是最大盲区**：Docker直接修改iptables，UFW无法阻止Docker暴露的端口。唯一有效的修复方式是修改容器端口绑定到 `127.0.0.1`。

## 执行模式

| 模式 | 行为 | 触发 |
|------|------|------|
| 体检模式 | 只报告，不修改 | 默认，或 `--audit` |
| 手术模式 | 执行修复，需明确确认 | `--fix` + 用户批准 |

## 执行流程

```
阶段1: 侦查 → 阶段2: 威胁匹配 → 阶段3: 深度检查 → 阶段4: 修复建议 → 阶段5: 验证报告
```

---

## 阶段1：全方位侦查

### 1.1 使用端口扫描脚本（推荐）

```bash
# 内部扫描（通过SSH执行）
ssh user@<服务器IP> 'bash -s' < scripts/port_scan.sh

# JSON输出（供LLM分析）
ssh user@<服务器IP> 'bash -s' < scripts/port_scan.sh -- --json

# 外部扫描（本机执行，检测公网暴露）
./scripts/external_scan.sh <公网IP>
./scripts/external_scan.sh <公网IP> --json
```

### 1.2 Nginx 安全检查

```bash
# 本地检查
./scripts/nginx_check.sh

# 远程检查
./scripts/nginx_check.sh --remote user@<服务器IP>

# JSON输出
./scripts/nginx_check.sh --json
```

### 1.3 源站 IP 暴露检测

```bash
# 检测域名是否通过 CDN 保护
./scripts/source_ip_check.sh example.com
./scripts/source_ip_check.sh example.com --json
```

### 1.4 手动内部端口扫描

```bash
# IPv4监听端口
netstat -tlnp | grep "0.0.0.0"

# IPv6监听端口（易被忽略）
netstat -tlnp | grep ":::"
```

### 1.3 Docker容器端口检查

```bash
# 容器端口映射
docker ps --format "table {{.Names}}\t{{.Ports}}"

# 检查绑定地址
docker ps -q | xargs -I {} docker inspect {} --format '{{.Name}}: {{.HostConfig.PortBindings}}'
```

### 1.4 Docker绕过UFW检测

```bash
iptables -L DOCKER-USER -n 2>/dev/null
# 如果只有RETURN，说明Docker绕过UFW
```

---

## 阶段2：威胁特征匹配

### 敏感端口黑名单

| 端口 | 服务 | 风险 | 攻击类型 |
|------|------|------|----------|
| 9200/9300 | Elasticsearch | 🔴严重 | 勒索攻击 |
| 6379/6380 | Redis | 🔴严重 | 挖矿木马 |
| 27017 | MongoDB | 🔴严重 | 勒索攻击 |
| 2375/2376 | Docker Daemon | 🔴严重 | 容器逃逸 |
| 2379/2380 | etcd | 🟠高 | 数据篡改 |
| 19530 | Milvus | 🟠高 | 向量数据泄露 |
| 11211 | Memcached | 🟠高 | DDoS放大 |
| 8088 | Hadoop YARN | 🟠高 | RCE |

详细端口说明见 `references/sensitive_ports.md`

### 无认证服务探测

```bash
# Elasticsearch
curl -s http://127.0.0.1:9200 && echo "[高危] ES无认证"

# Redis
echo "PING" | nc -w 2 127.0.0.1 6379 | grep -q "PONG" && echo "[高危] Redis无密码"

# Docker Daemon（最危险）
curl -s http://127.0.0.1:2375/version && echo "[极危] Docker Daemon暴露"
```

---

## 阶段3：深度安全检查

### 3.1 SSH配置

```bash
grep -E "PasswordAuthentication|PermitRootLogin|Port" /etc/ssh/sshd_config
# 密码登录开启 → 高风险
# Root登录允许 → 高风险
```

### 3.2 恶意定时任务

```bash
# 检查所有用户crontab
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v "^#" | grep -v "^$"
done

# 异常特征：curl/wget外部URL、base64解码执行、bash -i反弹shell
```

### 3.3 凭据泄露扫描

```bash
# .env文件权限
find /www -name "*.env" | xargs ls -la

# Web可访问检测
curl -s http://127.0.0.1/.env && echo "[高危] .env可Web访问"
```

### 3.4 容器安全

```bash
# 特权模式
docker inspect --format '{{.HostConfig.Privileged}}' <container>

# 资源限制
docker inspect --format '{{.HostConfig.Memory}}' <container>

# latest标签（供应链风险）
docker images | grep "latest"
```

详细检查清单见 `references/deep_checks.md`

---

## 阶段4：修复建议生成

### Docker端口修复模板

**Elasticsearch:**
```bash
docker run -d --name elasticsearch --restart=always \
  -p 127.0.0.1:9200:9200 -p 127.0.0.1:9300:9300 \
  -e "discovery.type=single-node" \
  --cpus="2" --memory="4g" \
  elasticsearch:8.11.0
```

**Redis（加密码）:**
```bash
docker run -d --name redis --restart=always \
  -p 127.0.0.1:6379:6379 \
  --cpus="1" --memory="1g" \
  redis:7.2.4 redis-server --requirepass "YOUR_STRONG_PASSWORD"
```

**etcd（先备份）:**
```bash
tar -czvf /tmp/etcd_backup_$(date +%Y%m%d).tar.gz /var/lib/etcd
docker run -d --name etcd --restart=always \
  -p 127.0.0.1:2379:2379 -p 127.0.0.1:2380:2380 \
  -e ALLOW_NONE_AUTHENTICATION=yes \
  -v /var/lib/etcd:/etcd \
  quay.io/coreos/etcd:v3.5.5
```

完整修复指南见 `references/docker_fix_guide.md`

### 监控脚本部署

使用 `scripts/es_monitor.sh` 和 `scripts/port_monitor.sh`

---

## 阶段5：验证与报告

### 修复后验证

```bash
# 端口状态
netstat -tlnp | grep -E '9200|6379|2379|19530'
# 期望: 全部显示 127.0.0.1:端口

# 外部可达性（从外部测试）
curl -m 5 http://<公网IP>:9200
# 期望: Connection refused 或 timeout

# 在线验证
# https://www.yougetsignal.com/tools/open-ports/
```

### 报告模板

```markdown
# 服务器端口安全排查报告

## 发现的风险
| 端口 | 服务 | 风险等级 | 问题 |
## 修复措施
- [x] 已完成项
- [ ] 待办项
## 后续建议
1. 云厂商安全组检查
2. 异地备份配置
```

---

## ⚠️ 破坏性操作前必须

1. **备份数据卷**：重建容器前 `tar -czvf backup.tar.gz /var/lib/<service>`
2. **确认业务依赖**：端口改为本地绑定后，确认服务间通信不受影响
3. **同步配置文件**：Redis加密码后需同步更新应用配置

---

## 告警分级（防止告警疲劳）

| 级别 | 事件类型 | 处理方式 |
|------|----------|----------|
| 🔴 CRITICAL | 勒索索引、Docker Daemon暴露、敏感端口暴露、源站IP暴露 | 立即通知 |
| 🟠 WARNING | 无限流、版本暴露、无资源限制、磁盘高 | 每日聚合报告 |
| 🟢 INFO | SSH爆破尝试、备份成功 | 仅日志 |

配置详见 `config.yaml.example`

---

## 易被忽视的盲区

| 检查项 | 检测方法 | 脚本 |
|--------|----------|------|
| 云厂商安全组 | 提醒用户检查控制台 | - |
| IPv6暴露 | `ss -tulnp \| grep ":::"` | `port_scan.sh` |
| Nginx版本暴露 | `curl -I 127.0.0.1 \| grep Server` | `nginx_check.sh` |
| Nginx无限流 | 检查 `limit_req` 配置 | `nginx_check.sh` |
| 敏感文件可访问 | 检查 `.env` 等文件保护 | `nginx_check.sh` |
| 审计日志缺失 | `systemctl status auditd` | - |
| bash_history被清空 | `ls -la ~/.bash_history` | - |
| 源站IP暴露 | 公网PING域名比对 | `source_ip_check.sh` |
| 外部端口暴露 | 本机Nmap扫描 | `external_scan.sh` |

---

## 脚本文件

| 脚本 | 用途 | 输出格式 |
|------|------|----------|
| `scripts/port_scan.sh` | 内部端口扫描 | 默认/`--json` |
| `scripts/external_scan.sh` | 外部端口扫描（本机执行） | 默认/`--json` |
| `scripts/nginx_check.sh` | Nginx 安全配置检查 | 默认/`--json` |
| `scripts/source_ip_check.sh` | 源站 IP 暴露检测 | 默认/`--json` |
| `scripts/es_monitor.sh` | ES索引监控 | 日志 |
| `scripts/port_monitor.sh` | 端口暴露监控 | 日志 |
| `scripts/fix_wrapper.py` | 修复确认包装器 | JSON |

## 参考文档

| 文档 | 用途 |
|------|------|
| `references/sensitive_ports.md` | 敏感端口详细说明 |
| `references/deep_checks.md` | 深度检查清单 |
| `references/docker_fix_guide.md` | Docker修复指南 |
| `config.yaml.example` | 配置文件模板 |