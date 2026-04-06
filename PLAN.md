# 公网服务器端口安全维护 Skill 创建计划

**创建日期**: 2026-04-06
**状态**: 设计完成，待测试
**基于**: Elasticsearch勒索攻击真实事件 (Meow Attack)
**架构版本**: v4.0 - LLM优化架构

---

## 〇、LLM优化架构设计（核心）

> ⚠️ **重要**：本Skill专为Claude Code等LLM Agent优化，确保AI能安全、高效地执行安全排查。

### 0.1 执行通道：SSH原生集成

**设计原则**：脚本保存在本地版本库，服务器保持无状态和纯净。

```bash
# Claude Code 本地执行，通过SSH隧道远程取证
ssh -i ~/.ssh/id_rsa user@104.250.159.108 'bash -s' < scripts/port_scan.sh

# 带参数执行
ssh -i ~/.ssh/id_rsa user@104.250.159.108 'bash -s' < scripts/port_scan.sh -- --json
```

**优势**：
- 脚本永远在本地版本控制中
- 服务器无需安装任何Agent
- Claude Code在本地上下文中直接推理

### 0.2 LLM-Friendly输出格式

**人类喜欢彩色表格，LLM喜欢结构化JSON**

在脚本中添加 `--json` 参数：

```bash
# 人类模式（默认）
./port_scan.sh

# Agent模式（LLM优化）
./port_scan.sh --json
```

**JSON输出格式规范**：

```json
{
  "timestamp": "2026-04-06T10:00:00Z",
  "target": "104.250.159.108",
  "status": "COMPLETE",
  "findings": [
    {
      "id": "FIND-001",
      "type": "PORT_EXPOSED",
      "severity": "CRITICAL",
      "port": 6380,
      "service": "Redis",
      "bind_address": "0.0.0.0",
      "process": "docker-proxy",
      "description": "Redis port exposed to public network without authentication",
      "recommendation": "Rebind to 127.0.0.1 and set password"
    },
    {
      "id": "FIND-002",
      "type": "DOCKER_BYPASS_UFW",
      "severity": "HIGH",
      "description": "Docker is bypassing UFW firewall",
      "recommendation": "Modify container port bindings"
    }
  ],
  "docker_bypassing_ufw": true,
  "ransom_indices_detected": false,
  "summary": {
    "total_findings": 2,
    "critical": 1,
    "high": 1,
    "medium": 0
  }
}
```

> ⚠️ **流分离规范（防止JSON解析失败）**
>
> Bash脚本中的调试信息和错误会污染JSON输出，必须严格分离：
>
> ```bash
> # 开发规范：日志归stderr，数据归stdout
>
> # ❌ 错误：混入stdout会破坏JSON格式
> echo "🔍 正在扫描端口..."
>
> # ✅ 正确：非JSON文本必须重定向到stderr
> echo "🔍 正在扫描端口..." >&2
>
> # ✅ 正确：只有最终JSON才输出到stdout
> echo "$JSON_RESULT"
> ```
>
> 这样 Claude Code 执行 `ssh user@ip 'bash -s' < scan.sh --json` 时，只会干净地捕获到合法的JSON。

### 0.3 Skill描述（Tool Description）

**Claude Code如何知道何时调用此Skill**：

```yaml
name: server-port-security
description: |
  远程服务器安全审计工具。通过SSH扫描公网服务器端口，检测Docker绕过防火墙、
  数据库暴露（Redis/ES/Milvus）、勒索索引、无认证服务等安全隐患。

  触发场景：
  - 用户提到"端口安全"、"服务器被黑"、"勒索攻击"
  - 用户提到"ES索引丢失"、"Redis未授权"
  - 用户请求"安全排查"、"端口扫描"
  - 部署新服务后需要安全检查

  绝对不要在用户未明确授权时执行修复操作。

parameters:
  target:
    type: string
    description: 服务器IP地址或主机名
    required: true

  mode:
    type: string
    enum: [audit, fix]
    default: audit
    description: |
      audit: 只读检查，不修改任何配置（默认）
      fix: 应用安全修复（需要用户明确确认）

  ssh_key:
    type: string
    description: SSH私钥路径（默认 ~/.ssh/id_rsa）

  ssh_user:
    type: string
    description: SSH用户名（默认 root）
```

### 0.4 Agentic护栏：Human-in-the-Loop

**核心原则：绝对禁止AI越权自愈**

#### 护栏机制一：扫描与修复强制分离

```bash
# 扫描（只读，可自动执行）
./server-audit.sh --target 104.250.159.108 --mode audit

# 修复（必须人工确认）
./server-audit.sh --target 104.250.159.108 --mode fix --confirm
```

#### 护栏机制二：修复前强制确认

**Skill包装器（Python示例）**：

```python
def execute_fix(target_ip, actions):
    """执行修复前必须人工确认"""

    print("=" * 60)
    print("⚠️  Claude Code 正在尝试对服务器应用安全修复")
    print(f"目标服务器: {target_ip}")
    print("=" * 60)
    print("\n拟定操作:")
    for i, action in enumerate(actions, 1):
        print(f"  {i}. {action['description']}")
        print(f"     命令: {action['command']}")
    print("\n" + "=" * 60)
    print("⚠️  这些操作将修改生产环境配置！")
    print("=" * 60)

    response = input("\n请输入 'YES' 确认执行: ")

    if response.strip() != "YES":
        print("❌ 操作已取消")
        return False

    # 只有确认后才执行
    return execute_remote_commands(target_ip, actions)
```

#### 护栏机制三：修复操作审计日志

```bash
# 每次修复操作记录到本地审计日志
echo "[$(date)] FIX_EXECUTED target=$TARGET actions=$ACTIONS user=$USER" \
  >> ~/.claude/logs/server-security-audit.log
```

### 0.5 完整工作流体验

```
┌─────────────────────────────────────────────────────────────────┐
│                    Claude Code 安全排查工作流                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  用户: "帮我排查一下 104.250.x.x 的端口安全，最近ES索引归零了"    │
│                                                                 │
│  Claude Code 自动执行:                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 1. 调用 server-port-security Skill                       │   │
│  │ 2. SSH远程执行: ./port_scan.sh --json                    │   │
│  │ 3. 解析JSON报告，发现 9200/6380 暴露                      │   │
│  │ 4. 读取本地 config.yaml (Tailscale白名单等)              │   │
│  │ 5. 生成修复方案                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Claude Code 输出:                                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 🚨 发现 2 个高危问题:                                     │   │
│  │ - Redis (6380) 绑定到 0.0.0.0，无密码                    │   │
│  │ - Docker 绕过 UFW 防火墙                                 │   │
│  │                                                         │   │
│  │ 我已生成修复脚本，将执行以下操作:                          │   │
│  │ 1. 重启 fayin-redis 容器，绑定 127.0.0.1                 │   │
│  │ 2. 设置 Redis 密码                                       │   │
│  │                                                         │   │
│  │ 是否执行修复？(输入 YES 确认)                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  用户输入: YES                                                  │
│                                                                 │
│  Claude Code 执行修复 → 验证 → 输出报告                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 一、Skill 概述

### 1.1 基本信息

| 项目 | 内容 |
|------|------|
| Skill名称 | `server-port-security` |
| Skill路径 | `D:\projects\moredoc\server-port-security\` |
| 触发场景 | 端口安全、服务器被黑、勒索攻击、安全排查、Docker端口、防火墙配置 |
| 核心价值 | 发现并修复数据库端口暴露、Docker绕过防火墙、无认证服务等安全隐患 |

### 1.2 核心问题

**Docker绕过UFW是最大盲区**：
- Docker直接修改iptables规则
- UFW防火墙无法阻止Docker暴露的端口
- 唯一有效修复：修改容器端口绑定到 `127.0.0.1`

---

## 二、文件结构

```
server-port-security/
├── SKILL.md                    # ✅ 已更新 - 包含LLM优化架构
├── config.yaml.example         # ✅ 已更新 - 告警分级配置
├── scripts/
│   ├── port_scan.sh           # ✅ 已更新 - 支持 --json 参数
│   ├── external_scan.sh       # ✅ 新增 - 外部端口扫描（本机执行）
│   ├── nginx_check.sh         # ✅ 新增 - Nginx安全配置检查
│   ├── source_ip_check.sh     # ✅ 新增 - 源站IP暴露检测
│   ├── es_monitor.sh          # ✅ 已创建 - ES索引监控
│   ├── port_monitor.sh        # ✅ 已创建 - 端口暴露监控
│   └── fix_wrapper.py         # ✅ 已修复 - SSH命令构造、EOFError处理
└── references/
    ├── sensitive_ports.md     # ✅ 已创建 - 敏感端口详细说明
    ├── deep_checks.md         # ✅ 已创建 - 深度检查清单
    └── docker_fix_guide.md    # ✅ 已创建 - Docker修复指南
```

### 2.1 配置分离设计

**为什么需要配置文件？**

安全脚本不能硬编码敏感信息：
- Webhook URL（钉钉/微信告警机器人）
- 白名单 IP 段（本地局域网 IP、Tailscale 虚拟 IP）
- 需要忽略检查的特殊端口
- Cloudflare CDN IP 段（源站防护）

---

## 三、执行流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    服务器端口安全排查流程                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  阶段1：全方位侦查（内外双向扫描）                                  │
│  ├── 1.1 内部端口扫描 (netstat/ss)                               │
│  ├── 1.2 Docker容器端口映射检查                                   │
│  ├── 1.3 IPv6端口暴露检查                                        │
│  └── 1.4 Docker绕过UFW检测                                       │
│                                                                 │
│  阶段2：威胁特征匹配                                              │
│  ├── 2.1 敏感端口特征匹配（黑名单库）                              │
│  ├── 2.2 无认证服务探测                                          │
│  └── 2.3 风险等级评定                                            │
│                                                                 │
│  阶段3：深度安全检查                                              │
│  ├── 3.1 SSH安全配置检查                                         │
│  ├── 3.2 恶意定时任务检查                                        │
│  ├── 3.3 凭据泄露扫描                                            │
│  ├── 3.4 容器安全检查                                            │
│  ├── 3.5 Web目录权限检查（新增）                                  │
│  ├── 3.6 审计日志检查（新增）                                     │
│  ├── 3.7 镜像漏洞扫描（新增）                                     │
│  └── 3.8 源站IP暴露检查                                          │
│                                                                 │
│  阶段4：修复建议生成                                              │
│  ├── 4.1 Docker端口绑定修复方案                                   │
│  ├── 4.2 密码/认证配置建议                                       │
│  ├── 4.3 源站防护建议（Cloudflare接入）                           │
│  └── 4.4 监控脚本部署                                            │
│                                                                 │
│  阶段5：验证与报告                                                │
│  ├── 5.1 修复后端口状态验证                                       │
│  ├── 5.2 外部可达性测试                                          │
│  └── 5.3 生成安全报告                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 四、敏感端口黑名单

| 端口 | 服务 | 风险等级 | 攻击类型 | 优先级 |
|------|------|----------|----------|--------|
| 2375/2376 | Docker Daemon | 🔴 严重 | 容器逃逸、完全接管 | 1 |
| 9200/9300 | Elasticsearch | 🔴 严重 | 勒索攻击、数据删除 | 2 |
| 6379/6380 | Redis | 🔴 严重 | 挖矿木马、写入SSH公钥 | 3 |
| 27017 | MongoDB | 🔴 严重 | 勒索攻击 | 4 |
| 2379/2380 | etcd | 🟠 高 | 数据篡改、Milvus崩溃 | 5 |
| 8088 | Hadoop YARN | 🟠 高 | RCE执行任意命令 | 6 |
| 19530 | Milvus | 🟠 高 | 向量数据泄露 | 7 |
| 11211 | Memcached | 🟠 高 | DDoS放大攻击 | 8 |
| 9001 | MinIO Console | 🟡 中 | 管理面板暴露 | 9 |
| 3306/5432 | MySQL/PostgreSQL | 🟡 中 | 弱口令暴破 | 10 |

---

## 五、设计哲学

### 5.1 双模式设计

| 模式 | 行为 | 触发 |
|------|------|------|
| 体检模式 | 只报告，不修改 | 默认 |
| 手术模式 | 执行修复，需确认 | `--fix` + 用户批准 |

### 5.2 幂等性设计

- 添加规则前检查是否已存在
- 修改配置前先备份原文件
- **执行1次和100次结果相同**
- 已修复项不再重复修改

### 5.3 破坏性操作防护

- 容器重建前自动备份数据卷
- 配置修改前创建备份
- 用户确认后才执行修复
- **未加 `--fix` 参数时绝对无任何变更**

---

## 六、告警分级

| 级别 | 触发条件 | 通知方式 |
|------|----------|----------|
| 🔴 Critical | read_me索引、Docker Daemon暴露、核心端口暴露 | 立即通知 |
| 🟠 Warning | 磁盘>80%、资源无限制、镜像latest | 每日报告 |
| 🟡 Info | SSH爆破尝试、日常快照成功 | 仅日志 |

---

## 七、易被忽视的盲区

| 检查项 | 风险 | 检测方法 | 修复建议 |
|--------|------|----------|----------|
| 云厂商安全组 | 最高优先级防火墙被忽略 | 提醒检查控制台 | 登录云控制台检查入站规则 |
| IPv6端口暴露 | IPv6公网地址被忽略 | `ss -tulnp \| grep ":::"` | 容器端口显式绑定IPv4 |
| Docker绕过UFW | UFW无法阻止Docker端口 | `iptables -L DOCKER-USER -n` | 修改容器端口绑定 |
| Nginx版本暴露 | CVE漏洞利用 | `curl -I \| grep Server` | `server_tokens off;` |
| Nginx无限流 | CC攻击、暴力破解 | 检查 `limit_req` 配置 | 配置请求限流 |
| .env文件可访问 | 密码泄露 | `curl http://IP/.env` | Nginx deny .env |
| bash_history被清空 | 痕迹擦除 | `ls -la ~/.bash_history` | 启用审计日志 |
| **审计日志缺失** | 无法溯源 | `systemctl status auditd` | 安装并启用auditd |
| 源站真实IP暴露 | 绕过WAF直接攻击 | 公网多节点PING比对 | 接入Cloudflare，仅放行CDN IP |

---

## 八、深度检查清单（新增补充）

### 8.1 审计日志检查

```bash
# 检查auditd状态
systemctl status auditd

# 如果未安装
apt-get install -y auditd
systemctl enable auditd
systemctl start auditd

# 配置关键文件监控
# /etc/audit/rules.d/audit.rules
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/auth.log -p wa -k logins
```

> ⚠️ **日志轮转配置（防止撑爆磁盘）**：
> 审计日志 `/var/log/audit/audit.log` 增长极快，必须配置轮转：
> ```bash
> # 编辑 /etc/audit/auditd.conf
> max_log_file = 100        # 单个日志文件最大100MB
> max_log_file_action = ROTATE  # 达到上限后轮转
> num_logs = 5              # 保留5个轮转文件
>
> # 重启生效
> systemctl restart auditd
> ```

### 8.2 Web目录权限检查

```bash
# 检查上传目录执行权限
find /www -type d -name "upload*" -exec ls -ld {} \;

# 检查Web目录所有者
ls -la /www/web/moredoc/

# 风险判断：
# - uploads目录有执行权限 → 高风险
# - Web根目录所有者为root → 中风险
```

### 8.3 容器安全增强检查

```bash
# 检查--privileged特权模式
docker inspect --format '{{.HostConfig.Privileged}}' <container>

# 检查no-new-privileges（防止容器内提权）
docker inspect --format '{{.HostConfig.SecurityOpt}}' <container>
# 应包含 "no-new-privileges:true"

# 检查资源限制
docker inspect --format '{{.HostConfig.Memory}}' <container>
docker inspect --format '{{.HostConfig.CpuQuota}}' <container>
```

### 8.4 镜像漏洞扫描

> 💡 **推荐容器化运行Trivy**：安全扫描工具最好"用完即焚"，不留垃圾。
> 无需在宿主机安装，直接挂载 docker.sock 运行：

```bash
# 扫描本地 Elasticsearch 镜像（无需安装）
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL elasticsearch:8.11.0

# 扫描 Redis 镜像
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL redis:7.2.4

# 输出 JSON 格式报告
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --format json --output /tmp/report.json <image>

# 扫描所有本地镜像
for img in $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>"); do
  echo "=== Scanning $img ==="
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy image --severity HIGH,CRITICAL "$img"
done
```

### 8.5 文件完整性监控 (AIDE)

```bash
# 安装AIDE
apt-get install -y aide

# 初始化数据库
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 每日检查
aide --check
```

> ⚠️ **必须排除动态目录（防止告警疲劳）**：
> 用户上传目录、缓存目录每天都在变动，必须显式排除，否则会产生海量误报：
> ```bash
> # /etc/aide/aide.conf
> # 监控规则
> /www/web/moredoc/ F+p+u+g+s+m+c+md5+sha1
> /etc/ p+u+g+s+m+c+md5+sha1
>
> # 排除规则（感叹号开头）
> !/www/web/moredoc/cache/
> !/www/web/moredoc/uploads/
> !/www/web/moredoc/runtime/
> !/www/web/moredoc/es_data/
> ```

### 8.6 Nginx安全配置检查

```bash
# 检查版本隐藏
grep -r "server_tokens" /etc/nginx/

# 检查限流配置
grep -r "limit_req" /etc/nginx/

# 检查敏感文件保护
grep -r "\.env" /etc/nginx/

# 建议配置：
# server_tokens off;
# limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
# location ~ /\.env { deny all; }
```

---

## 九、灾备与备份策略

### 9.1 拉取式备份（Pull-based Backup）

**原则：备份机主动拉取，生产机被动提供，备份机对生产机只读**

```
┌─────────────────┐         ┌─────────────────┐
│   公网服务器      │  ←────  │   本地NAS/备份机  │
│  (被保护对象)     │   拉取   │   (安全堡垒)     │
│                 │         │                 │
│  /www/backup/   │         │  主动SSH连接     │
│  MySQL/ES快照   │         │  定时rsync拉取   │
└─────────────────┘         └─────────────────┘
      被动                       主动
```

**配置示例（本地NAS执行）：**
```bash
# 在NAS上配置定时任务
# /etc/cron.d/backup_pull
0 3 * * * backup-user rsync -avz --delete \
  backup-user@production-server:/www/backup/ \
  /volume1/backups/moredoc/
```

> 🔒 **安全增强：创建只读权限的受限用户（SSH原生方案）**
>
> ⚠️ **注意**：`rssh` 已因安全漏洞在 Ubuntu 20.04+ 和 Debian 中被移除，使用 SSH 原生命令限制替代：
>
> ```bash
> # 1. 创建普通备份用户
> useradd -m -s /bin/bash backup-user
> chown -R backup-user:backup-user /www/backup/
> chmod -R 750 /www/backup/
>
> # 2. 切换到备份用户并设置 SSH 目录
> su - backup-user
> mkdir -p ~/.ssh && chmod 700 ~/.ssh
>
> # 3. 在 authorized_keys 中对该公钥进行"极其严苛"的限制
> # 将本地 NAS 的公钥写入，并在开头加上 command 和网络限制参数
> cat > ~/.ssh/authorized_keys << 'EOF'
> command="rsync --server --sender -vlogDtprze.iLsfxCIvu . /www/backup/",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-rsa AAAA...本地NAS公钥...
> EOF
> chmod 600 ~/.ssh/authorized_keys
> ```
>
> **效果**：该私钥只能执行向外发送数据的 rsync 命令，SSH终端登录直接被拒绝，安全性拉满且无需任何第三方包。
>
> **目的**：即使NAS意外被控，攻击者也无法通过备份链路反向破坏生产服务器。

### 9.2 不可变快照（Immutable Snapshots）

**群晖NAS配置：**
1. 控制面板 → 共享文件夹 → 选择备份文件夹
2. 快照 → 启用快照
3. **高级设置 → 启用防篡改保护**
4. 设置保留期（如7天或30天）

**效果：** 即使黑客获取root权限，也无法删除或加密保护期内的快照。

---

## 十、零信任网络架构

### 10.1 Tailscale组网

**目的：将SSH端口从公网彻底消失**

```bash
# 服务器安装Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# 本地机器同样安装并登录同一账号

# 防火墙配置（服务器）
ufw delete allow 22/tcp  # 删除公网SSH

# 仅允许来自 Tailscale 虚拟网卡接口的 SSH 流量
# 绑定网卡接口比限制IP更安全，彻底杜绝IP伪造攻击
ufw allow in on tailscale0 to any port 22
```

**效果：**
- 公网扫描器看不到任何SSH端口
- 只有同一Tailscale网络的设备可连接
- 即使SSH有0-day漏洞，外部也无法利用
- 绑定网卡接口比限制IP更安全，防止IP伪造

---

## 十一、测试计划

### 11.1 功能测试用例

| ID | 测试场景 | 预期输出 |
|----|----------|----------|
| 1 | "检查我服务器的端口安全" | 完整端口扫描报告 |
| 2 | "我的ES索引被删了，可能被黑" | 勒索攻击检测 + 修复方案 |
| 3 | "Docker容器端口怎么配置才安全" | Docker端口绑定指南 |
| 4 | 幂等性测试：连续运行三次 `--fix` | 第一次修复，后续"No changes needed" |
| 5 | 防呆测试：未加 `--fix` 运行 | 仅输出告警，系统无任何变更 |
| 6 | 深度检查：Web目录权限 | 检测uploads目录执行权限 |
| 7 | 深度检查：镜像漏洞 | Trivy扫描报告 |

### 11.2 待完成文件

- [x] `references/deep_checks.md` - 深度检查清单
- [x] `references/docker_fix_guide.md` - Docker修复指南
- [x] `scripts/external_scan.sh` - 外部端口扫描
- [x] `scripts/nginx_check.sh` - Nginx安全检查
- [x] `scripts/source_ip_check.sh` - 源站IP暴露检测
- [ ] `references/backup_strategy.md` - 备份策略指南（可选）
- [ ] 拉取式备份验证脚本（需要用户配置）

---

## 十二、Skill Roadmap

| 版本 | 功能范围 | 防护能力 | 状态 |
|------|----------|----------|------|
| v1.0 | 端口扫描、Docker绑定修复、强密码 | 挡住90%自动化扫描 | ✅ 完成 |
| v2.0 | SSH配置、Cron后门、Web权限、Nginx加固 | 挡住初级人工渗透 | ✅ 完成 |
| v3.0 | 容器资源限制、镜像版本锁定、漏洞扫描 | 架构层面强健 | ✅ 完成 |
| v4.0 | 拉取式备份、不可变快照、零信任网络 | 灾备兜底，极端情况可恢复 | ⚠️ 部分完成 |
| v4.3 | 外部扫描、Nginx检查、源站IP检测、告警分级 | 内外兼修的检测能力 | ✅ 完成 |

---

## 十三、参考文档

| 文档 | 路径 | 用途 |
|------|------|------|
| 事件调查报告 | `Moredoc-ES-索引归零排查.md` | Gemini对话记录 |
| 修复方案 | `ES_FIX_PLAN.md` | 详细修复步骤 |
| 安全修复报告 | `ES_SECURITY_FIX_REPORT.md` | 修复完成记录 |
| Skill设计推荐 | `skill设计推荐` | 设计指南 |
| Skill设计计划 | `server-port-security-skill-plan.md` | 原始设计计划 |

---

**文档版本**: 4.3
**最后更新**: 2026-04-06
**更新内容**:
- v3.0: 补充审计日志、Web目录权限、容器安全增强、镜像漏洞扫描、文件完整性监控、拉取式备份、不可变快照、零信任网络架构
- v3.1: 修正Trivy容器化运行、AIDE排除动态目录、auditd日志轮转、Tailscale网卡绑定、备份用户权限限制
- v4.0: **LLM优化架构** - SSH原生集成、JSON输出格式、Tool Description定义、Human-in-the-Loop护栏机制、Claude Code工作流设计
- v4.1: **完成所有文档** - deep_checks.md、docker_fix_guide.md、SKILL.md更新
- v4.2: **修正废弃包和流污染** - rssh替换为SSH原生命令限制、添加JSON输出流分离规范
- v4.3: **补充核心功能** - 外部端口扫描脚本、Nginx安全检查脚本、源站IP暴露检测、告警分级机制配置