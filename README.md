# Server Port Security Skill

> 公网服务器端口安全维护 Skill - 检测并修复 Docker 绕过防火墙、数据库暴露、勒索索引等安全隐患

## 背景

基于 Elasticsearch 勒索攻击真实事件（Meow Attack）开发的安全排查工具。2026年4月，一台公网服务器因 Elasticsearch 9200 端口暴露到公网，被勒索软件攻击，索引数据被清空并创建了 `read_me` 勒索索引。

本 Skill 旨在将这次惨痛教训转化为自动化安全排查能力，防止类似事件再次发生。

## 功能特性

### 核心检测能力

| 检测项 | 脚本 | 说明 |
|--------|------|------|
| 内部端口扫描 | `port_scan.sh` | 检测服务器内部监听的敏感端口 |
| 外部端口扫描 | `external_scan.sh` | 从本机扫描服务器公网暴露端口 |
| Nginx 安全检查 | `nginx_check.sh` | 版本暴露、限流配置、敏感文件保护 |
| 源站 IP 暴露 | `source_ip_check.sh` | 检测域名 CDN 使用和源站 IP 泄露 |
| Docker 绕过 UFW | `port_scan.sh` | 检测 Docker 是否绕过防火墙 |
| 无认证服务探测 | `port_scan.sh` | Redis/ES/Docker Daemon 无密码检测 |
| 勒索索引检测 | `port_scan.sh` | 检测 `read_me` 等勒索特征 |

### 敏感端口黑名单

| 端口 | 服务 | 风险等级 | 攻击类型 |
|------|------|----------|----------|
| 2375/2376 | Docker Daemon | 🔴 严重 | 容器逃逸、完全接管 |
| 9200/9300 | Elasticsearch | 🔴 严重 | 勒索攻击、数据删除 |
| 6379/6380 | Redis | 🔴 严重 | 挖矿木马、写入SSH公钥 |
| 27017 | MongoDB | 🔴 严重 | 勒索攻击 |
| 2379/2380 | etcd | 🟠 高 | 数据篡改、Milvus崩溃 |
| 19530 | Milvus | 🟠 高 | 向量数据泄露 |
| 8088 | Hadoop YARN | 🟠 高 | RCE执行任意命令 |
| 11211 | Memcached | 🟠 高 | DDoS放大攻击 |

## 安装

### 方式一：作为 Claude Code Skill 使用

```bash
# 克隆到 Claude skills 目录
git clone https://github.com/shiwuxiu/server-port-security-skill.git ~/.claude/skills/server-port-security
```

### 方式二：独立使用

```bash
# 克隆仓库
git clone https://github.com/shiwuxiu/server-port-security-skill.git
cd server-port-security-skill
```

## 使用方法

### 1. 内部端口扫描（通过 SSH）

```bash
# 人类可读输出
ssh user@<服务器IP> 'bash -s' < scripts/port_scan.sh

# JSON 输出（LLM 友好）
ssh user@<服务器IP> 'bash -s' < scripts/port_scan.sh -- --json
```

### 2. 外部端口扫描（本机执行）

```bash
# 需要 nmap
./scripts/external_scan.sh <公网IP>

# JSON 输出
./scripts/external_scan.sh <公网IP> --json
```

### 3. Nginx 安全检查

```bash
# 本地检查
./scripts/nginx_check.sh

# 远程检查
./scripts/nginx_check.sh --remote user@<服务器IP>

# JSON 输出
./scripts/nginx_check.sh --json
```

### 4. 源站 IP 暴露检测

```bash
# 检测域名
./scripts/source_ip_check.sh example.com

# JSON 输出
./scripts/source_ip_check.sh example.com --json
```

### 5. 修复包装器（Human-in-the-Loop）

```bash
# 审计模式（只读）
python scripts/fix_wrapper.py --target <服务器IP> --mode audit

# 修复模式（需要确认）
python scripts/fix_wrapper.py --target <服务器IP> --mode fix --actions actions.json
```

## 输出格式

### JSON 输出示例

```json
{
  "timestamp": "2026-04-06T10:00:00Z",
  "status": "COMPLETE",
  "findings": [
    {
      "id": "FIND-001",
      "type": "PORT_EXPOSED",
      "severity": "CRITICAL",
      "port": 9200,
      "service": "Elasticsearch",
      "bind_address": "0.0.0.0",
      "description": "Elasticsearch port exposed to public network",
      "recommendation": "Rebind to 127.0.0.1"
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0
  }
}
```

## 告警分级

| 级别 | 事件类型 | 处理方式 |
|------|----------|----------|
| 🔴 CRITICAL | 勒索索引、Docker Daemon暴露、敏感端口暴露、源站IP暴露 | 立即通知 |
| 🟠 WARNING | 无限流、版本暴露、无资源限制、磁盘高 | 每日聚合报告 |
| 🟢 INFO | SSH爆破尝试、备份成功 | 仅日志 |

配置详见 `config.yaml.example`

## 核心原则

### ⚠️ Docker 绕过 UFW 是最大盲区

Docker 会直接修改 iptables 规则，UFW 防火墙无法阻止 Docker 暴露的端口。

**唯一有效的修复方式**：修改容器端口绑定到 `127.0.0.1`

```bash
# ❌ 危险：绑定到所有接口
-p 9200:9200

# ✅ 安全：仅绑定本地
-p 127.0.0.1:9200:9200
```

### Human-in-the-Loop 护栏

**绝对禁止 AI 越权自愈**

- 审计模式：只读检查，可自动执行
- 修复模式：**必须用户输入 `YES` 确认**

## 依赖

| 工具 | 用途 | 安装 |
|------|------|------|
| nmap | 外部端口扫描 | `winget install nmap` 或 `apt install nmap` |
| jq | JSON 处理 | `apt install jq` |
| curl | HTTP 请求 | 通常已安装 |
| dig | DNS 查询 | 通常已安装 |

## 文件结构

```
server-port-security/
├── SKILL.md                    # Skill 主文档
├── README.md                   # 本文件
├── PLAN.md                     # 设计计划
├── config.yaml.example         # 配置文件模板
├── scripts/
│   ├── port_scan.sh           # 内部端口扫描
│   ├── external_scan.sh       # 外部端口扫描
│   ├── nginx_check.sh         # Nginx 安全检查
│   ├── source_ip_check.sh     # 源站 IP 检测
│   ├── es_monitor.sh          # ES 索引监控
│   ├── port_monitor.sh        # 端口暴露监控
│   └── fix_wrapper.py         # 修复确认包装器
└── references/
    ├── sensitive_ports.md     # 敏感端口详细说明
    ├── deep_checks.md         # 深度检查清单
    └── docker_fix_guide.md    # Docker 修复指南
```

## 版本历史

| 版本 | 更新内容 |
|------|----------|
| v4.3 | 新增外部扫描、Nginx检查、源站IP检测、告警分级 |
| v4.2 | 修正废弃包和流污染 |
| v4.0 | LLM优化架构 - SSH原生集成、JSON输出、Human-in-the-Loop |
| v3.0 | 容器安全增强、镜像漏洞扫描、文件完整性监控 |
| v2.0 | SSH配置、Cron后门、Web权限、Nginx加固 |
| v1.0 | 端口扫描、Docker绑定修复、强密码 |

## License

MIT

## 参考

- [Elasticsearch 勒索攻击分析](https://www.elastic.co/blog/protecting-your-elasticsearch-deployments-from-ransomware)
- [Docker 绕过 UFW 问题](https://github.com/chaifeng/ufw-docker)
- [Meow Attack 分析](https://securitytrails.com/blog/meow-attack-deletes-databases-unprotected)