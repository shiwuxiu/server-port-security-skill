# 深度安全检查清单

本文档提供系统化的深度安全检查方法，用于检测服务器上不易被发现的安全隐患。

---

## 一、SSH安全配置检查

### 1.1 检查项

| 配置项 | 安全值 | 风险等级 |
|--------|--------|----------|
| PasswordAuthentication | no | 🔴 高危 |
| PermitRootLogin | no 或 prohibit-password | 🔴 高危 |
| Port | 非默认端口（如 52222） | 🟡 中危 |
| PubkeyAuthentication | yes | - |
| PermitEmptyPasswords | no | 🔴 高危 |
| X11Forwarding | no | 🟡 中危 |

### 1.2 检测命令

```bash
# 检查SSH配置
grep -E "^(PasswordAuthentication|PermitRootLogin|Port|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding)" /etc/ssh/sshd_config

# 预期输出示例：
# PasswordAuthentication no
# PermitRootLogin prohibit-password
# Port 52222
# PubkeyAuthentication yes
# PermitEmptyPasswords no
# X11Forwarding no
```

### 1.3 风险判断

```bash
# 检查是否允许密码登录
if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
    echo "[高危] SSH允许密码登录，存在暴力破解风险"
fi

# 检查是否允许Root登录
if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
    echo "[高危] SSH允许Root登录"
fi

# 检查是否使用默认端口
if grep -q "^Port 22$" /etc/ssh/sshd_config || ! grep -q "^Port" /etc/ssh/sshd_config; then
    echo "[中危] SSH使用默认端口22，建议改为高位端口"
fi
```

### 1.4 修复方案

```bash
# 备份原配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)

# 修改配置
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#*Port.*/Port 52222/' /etc/ssh/sshd_config

# 重启SSH服务
systemctl restart sshd

# 注意：修改端口后需要更新防火墙规则
ufw allow 52222/tcp
ufw delete allow 22/tcp
```

---

## 二、恶意定时任务检查 (Cron后门)

### 2.1 常见后门特征

| 特征 | 说明 |
|------|------|
| `curl \| bash` | 从外部下载并执行脚本 |
| `wget \| sh` | 同上 |
| `base64 -d \| bash` | 解码并执行混淆代码 |
| `bash -i >& /dev/tcp/...` | 反弹Shell |
| 指向 Pastebin/Telegram | 外部命令控制 |

### 2.2 检测命令

```bash
# 检查所有用户的crontab
echo "=== 用户定时任务 ==="
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "  [用户: $user]"
done

# 检查系统定时任务目录
echo ""
echo "=== 系统定时任务目录 ==="
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.daily/ 2>/dev/null
ls -la /etc/cron.hourly/ 2>/dev/null
ls -la /etc/cron.weekly/ 2>/dev/null
ls -la /etc/cron.monthly/ 2>/dev/null

# 检查可疑内容
echo ""
echo "=== 可疑定时任务检测 ==="
find /etc/cron* -type f -exec grep -l -E "(curl|wget|base64|bash -i|/dev/tcp)" {} \; 2>/dev/null
```

### 2.3 深度分析脚本

```bash
#!/bin/bash
# cron_analysis.sh - 分析定时任务中的可疑内容

SUSPICIOUS_PATTERNS=(
    "curl.*|.*bash"
    "wget.*|.*sh"
    "base64.*-d"
    "bash -i"
    "/dev/tcp/"
    "pastebin.com"
    "t.me"
    "ngrok"
    "reverse.*shell"
)

check_cron_file() {
    local file=$1
    local line_num=0
    while IFS= read -r line; do
        ((line_num++))
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if echo "$line" | grep -qiE "$pattern"; then
                echo "[警告] $file:$line_num 匹配模式: $pattern"
                echo "  内容: $line"
            fi
        done
    done < "$file"
}

# 检查所有crontab文件
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | check_cron_file "/var/spool/cron/crontabs/$user"
done

# 检查系统目录
find /etc/cron.d /etc/cron.daily /etc/cron.hourly -type f 2>/dev/null | while read f; do
    check_cron_file "$f"
done
```

---

## 三、凭据泄露扫描

### 3.1 检查项

| 检查项 | 风险 | 检测方法 |
|--------|------|----------|
| .env文件权限 | 密码泄露 | `find /www -name "*.env" \| xargs ls -la` |
| .env可通过Web访问 | 极高危 | `curl http://IP/.env` |
| 硬编码密码 | 代码泄露 | `grep -r "password=" --include="*.py"` |
| 配置文件世界可读 | 密码泄露 | `find /www -name "*.yml" -perm -004` |
| AWS/云密钥泄露 | 极高危 | 扫描 AKIA/ASIA 模式 |

### 3.2 检测脚本

```bash
#!/bin/bash
# credential_scan.sh - 凭据泄露扫描

echo "=== 敏感文件权限检查 ==="

# 检查.env文件权限
echo "--- .env 文件 ---"
find /www -name "*.env" 2>/dev/null | while read f; do
    perms=$(stat -c "%a" "$f" 2>/dev/null || stat -f "%Lp" "$f" 2>/dev/null)
    if [ "$perms" -gt 600 ]; then
        echo "[风险] $f 权限: $perms (建议: 600)"
    fi
done

# 检查配置文件
echo ""
echo "--- 配置文件 ---"
find /www -name "*.yml" -o -name "*.yaml" -o -name "config.*" 2>/dev/null | while read f; do
    if [ -r "$f" ]; then
        # 检查是否包含密码
        if grep -q -E "(password|secret|token|api_key)" "$f" 2>/dev/null; then
            perms=$(stat -c "%a" "$f" 2>/dev/null || stat -f "%Lp" "$f" 2>/dev/null)
            if [ "$perms" -gt 640 ]; then
                echo "[风险] $f 包含敏感信息，权限: $perms"
            fi
        fi
    fi
done

# 检查Web可访问性
echo ""
echo "=== Web可访问性检查 ==="
for doc in ".env" "config.yml" "docker-compose.yml" ".git/config"; do
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/$doc" 2>/dev/null | grep -q "200"; then
        echo "[极危] $doc 可通过Web访问！"
    fi
done

# 检查硬编码密码
echo ""
echo "=== 硬编码密码检查 ==="
grep -r -l -E "(password\s*=\s*['\"][^'\"]+['\"]|PASSWORD\s*=\s*['\"][^'\"]+['\"])" \
    /www --include="*.py" --include="*.php" --include="*.js" 2>/dev/null | head -10
```

### 3.3 修复方案

```bash
# 修复文件权限
find /www -name "*.env" -exec chmod 600 {} \;
find /www -name "*.yml" -exec chmod 640 {} \;

# Nginx禁止访问敏感文件
cat >> /etc/nginx/conf.d/security.conf << 'EOF'
# 禁止访问敏感文件
location ~ /\. {
    deny all;
}
location ~* \.(env|yml|yaml|git|gitignore|md)$ {
    deny all;
}
EOF

nginx -t && systemctl reload nginx
```

---

## 四、容器安全检查

### 4.1 检查项

| 检查项 | 风险 | 安全配置 |
|--------|------|----------|
| --privileged | 容器逃逸 | 禁用 |
| 无资源限制 | 挖矿导致宿主机卡死 | 设置 --memory, --cpus |
| 挂载宿主机根目录 | 完全接管 | 禁用 |
| --network host | 网络隔离失效 | 使用bridge |
| 无 no-new-privileges | 容器内提权 | 启用 |
| 使用latest标签 | 供应链攻击 | 锁定版本号 |

### 4.2 检测脚本

```bash
#!/bin/bash
# container_security.sh - 容器安全检查

echo "=== 容器安全检查 ==="

for container in $(docker ps --format "{{.Names}}"); do
    echo ""
    echo "--- 容器: $container ---"

    # 检查特权模式
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$container")
    if [ "$privileged" = "true" ]; then
        echo "[极危] 运行在特权模式！"
    fi

    # 检查资源限制
    memory=$(docker inspect --format '{{.HostConfig.Memory}}' "$container")
    if [ "$memory" = "0" ]; then
        echo "[警告] 无内存限制"
    fi

    cpu_quota=$(docker inspect --format '{{.HostConfig.CpuQuota}}' "$container")
    if [ "$cpu_quota" = "0" ]; then
        echo "[警告] 无CPU限制"
    fi

    # 检查安全选项
    security_opt=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$container")
    if ! echo "$security_opt" | grep -q "no-new-privileges"; then
        echo "[警告] 未启用 no-new-privileges"
    fi

    # 检查网络模式
    network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container")
    if [ "$network" = "host" ]; then
        echo "[警告] 使用host网络模式"
    fi

    # 检查危险挂载
    mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$container")
    if echo "$mounts" | grep -qE "(/:|/etc:|/root:|/var/run/docker.sock)"; then
        echo "[极危] 检测到危险挂载: $mounts"
    fi
done

# 检查镜像版本
echo ""
echo "=== 镜像版本检查 ==="
docker images --format "{{.Repository}}:{{.Tag}}" | grep -E ":latest|<none>" | while read img; do
    echo "[警告] 使用latest标签或无标签: $img"
done
```

### 4.3 安全容器启动模板

```bash
# 安全的容器启动参数示例
docker run -d \
  --name myservice \
  --restart=always \
  -p 127.0.0.1:8080:8080 \           # 绑定本地
  --memory="2g" \                     # 内存限制
  --cpus="1.0" \                      # CPU限制
  --security-opt="no-new-privileges:true" \  # 禁止提权
  --cap-drop=ALL \                    # 移除所有能力
  --cap-add=NET_BIND_SERVICE \        # 仅添加必要能力
  --read-only \                       # 只读文件系统（可选）
  --tmpfs /tmp \                      # 临时文件系统
  myimage:1.2.3                       # 锁定版本
```

---

## 五、Web目录权限检查

### 5.1 检查项

| 目录/文件 | 正确权限 | 正确所有者 |
|-----------|----------|------------|
| Web根目录 | 755 | www-data:www-data |
| 上传目录 | 750 (无执行权限) | www-data:www-data |
| 配置文件 | 640 | root:www-data |
| 缓存目录 | 750 | www-data:www-data |
| 日志目录 | 750 | www-data:www-data |

### 5.2 检测脚本

```bash
#!/bin/bash
# web_directory_check.sh - Web目录权限检查

WEB_ROOT="/www/web/moredoc"

echo "=== Web目录权限检查 ==="

# 检查Web根目录所有者
root_owner=$(stat -c "%U:%G" "$WEB_ROOT" 2>/dev/null)
if [ "$root_owner" = "root:root" ]; then
    echo "[中危] Web根目录所有者为root，建议使用www-data或nginx用户"
fi

# 检查上传目录
echo ""
echo "--- 上传目录检查 ---"
find "$WEB_ROOT" -type d -name "upload*" 2>/dev/null | while read dir; do
    # 检查执行权限
    if [ -x "$dir" ]; then
        echo "[风险] 上传目录有执行权限: $dir"
    fi
    # 检查是否可写
    if [ -w "$dir" ] && [ "$(stat -c '%U' "$dir")" = "root" ]; then
        echo "[风险] 上传目录为root所有但可写: $dir"
    fi
done

# 检查缓存目录权限
echo ""
echo "--- 缓存目录检查 ---"
find "$WEB_ROOT" -type d -name "cache*" -o -name "runtime*" 2>/dev/null | while read dir; do
    perms=$(stat -c "%a" "$dir" 2>/dev/null)
    if [ "$perms" -gt 770 ]; then
        echo "[风险] 缓存目录权限过宽: $dir ($perms)"
    fi
done

# 检查是否有.php文件在静态资源目录
echo ""
echo "--- 可疑文件检查 ---"
find "$WEB_ROOT" -path "*/uploads/*" -name "*.php" 2>/dev/null | while read f; do
    echo "[极危] 上传目录中存在PHP文件: $f"
done
find "$WEB_ROOT" -path "*/cache/*" -name "*.php" 2>/dev/null | while read f; do
    echo "[风险] 缓存目录中存在PHP文件: $f"
done
```

---

## 六、审计日志检查

### 6.1 检查auditd状态

```bash
# 检查auditd是否运行
systemctl status auditd

# 检查审计规则
auditctl -l

# 检查日志大小
du -sh /var/log/audit/
```

### 6.2 推荐审计规则

```bash
# /etc/audit/rules.d/audit.rules

# 身份相关文件
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k identity

# 登录相关
-w /var/log/auth.log -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session

# 关键配置文件
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/nginx/nginx.conf -p wa -k nginx_config
-w /etc/docker/daemon.json -p wa -k docker_config

# 服务操作
-w /usr/bin/systemctl -p x -k systemd
-w /usr/bin/docker -p x -k docker
```

### 6.3 日志轮转配置

```bash
# /etc/audit/auditd.conf
max_log_file = 100
max_log_file_action = ROTATE
num_logs = 5
```

---

## 七、镜像漏洞扫描

### 7.1 使用Trivy扫描

```bash
# 容器化运行Trivy（推荐）
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL elasticsearch:8.11.0

# 扫描所有本地镜像
for img in $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>"); do
    echo "=== Scanning $img ==="
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      aquasec/trivy image --severity HIGH,CRITICAL "$img"
done

# 输出JSON报告
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --format json --output /tmp/report.json <image>
```

### 7.2 漏洞修复流程

1. 查看漏洞报告
2. 检查是否有官方补丁版本
3. 更新镜像版本
4. 重新扫描验证
5. 更新部署

---

## 八、文件完整性监控 (AIDE)

### 8.1 安装和初始化

```bash
# 安装AIDE
apt-get install -y aide

# 初始化数据库
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### 8.2 配置文件

```bash
# /etc/aide/aide.conf

# 定义监控规则
NORMAL = p+u+g+s+m+c+md5+sha1

# 监控静态代码
/www/web/moredoc/app NORMAL
/www/web/moredoc/config NORMAL
/etc/ NORMAL

# 排除动态目录（重要！）
!/www/web/moredoc/cache/
!/www/web/moredoc/uploads/
!/www/web/moredoc/runtime/
!/www/web/moredoc/es_data/
!/www/web/moredoc/logs/
!/var/log/
!/tmp/
```

### 8.3 定时检查

```bash
# 添加到crontab
0 4 * * * /usr/bin/aide --check | mail -s "AIDE Report" admin@example.com
```

---

## 九、检查清单汇总

| 类别 | 检查项 | 优先级 |
|------|--------|--------|
| SSH | 禁用密码登录 | 🔴 高 |
| SSH | 禁用Root登录 | 🔴 高 |
| Cron | 检查恶意定时任务 | 🔴 高 |
| 凭据 | .env文件权限 | 🔴 高 |
| 凭据 | 禁止Web访问敏感文件 | 🔴 高 |
| 容器 | 检查特权模式 | 🔴 高 |
| 容器 | 资源限制 | 🟠 中 |
| 容器 | 镜像版本锁定 | 🟠 中 |
| Web | 上传目录无执行权限 | 🟠 中 |
| 审计 | 启用auditd | 🟠 中 |
| 漏洞 | 镜像CVE扫描 | 🟠 中 |
| 完整性 | AIDE监控 | 🟡 低 |