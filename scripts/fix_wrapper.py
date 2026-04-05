#!/usr/bin/env python3
"""
安全修复包装器 - Human-in-the-Loop 护栏机制

确保 Claude Code 在执行任何修复操作前必须获得用户明确确认。

使用方法:
    python fix_wrapper.py --target 104.250.159.108 --mode audit
    python fix_wrapper.py --target 104.250.159.108 --mode fix --actions actions.json
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# 审计日志路径
AUDIT_LOG = Path.home() / ".claude" / "logs" / "server-security-audit.log"

def log_audit(action: str, target: str, details: str = ""):
    """记录审计日志"""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat()
    user = os.environ.get("USER", "unknown")
    log_entry = f"[{timestamp}] {action} target={target} user={user} {details}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(log_entry)

def run_ssh_command(target: str, command: str, ssh_key: str = None, ssh_user: str = "root") -> tuple:
    """通过SSH执行远程命令"""
    ssh_key = ssh_key or os.path.expanduser("~/.ssh/id_rsa")
    ssh_cmd = [
        "ssh", "-i", ssh_key, "-o", "StrictHostKeyChecking=accept-new",
        f"{ssh_user}@{target}", command
    ]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def confirm_fix(target: str, actions: list) -> bool:
    """修复前强制人工确认"""
    print("=" * 70)
    print("⚠️  Claude Code 正在尝试对服务器应用安全修复")
    print(f"目标服务器: {target}")
    print("=" * 70)
    print("\n拟定操作:")

    for i, action in enumerate(actions, 1):
        severity = action.get("severity", "MEDIUM")
        icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
        print(f"\n  {i}. {icon} [{severity}] {action.get('description', 'Unknown action')}")
        print(f"     服务: {action.get('service', 'N/A')}")
        print(f"     命令: {action.get('command', 'N/A')}")

    print("\n" + "=" * 70)
    print("⚠️  这些操作将修改生产环境配置！")
    print("⚠️  请确保你已经备份了重要数据！")
    print("=" * 70)

    print("\n请输入 'YES' 确认执行修复（其他任何输入将取消操作）:")
    try:
        response = input("> ").strip()
    except EOFError:
        response = ""

    if response == "YES":
        print("\n✅ 用户已确认，开始执行修复...")
        return True
    else:
        print(f"\n❌ 操作已取消（用户输入: '{response}'）")
        return False

def execute_fix(target: str, actions: list, ssh_key: str = None, ssh_user: str = "root") -> dict:
    """执行修复操作"""
    results = []
    for action in actions:
        command = action.get("command", "")
        if not command:
            continue

        print(f"\n执行: {action.get('description', command)}")
        returncode, stdout, stderr = run_ssh_command(target, command, ssh_key, ssh_user)

        result = {
            "action": action.get("id", "unknown"),
            "success": returncode == 0,
            "output": stdout,
            "error": stderr
        }
        results.append(result)

        if returncode == 0:
            print(f"  ✅ 成功")
        else:
            print(f"  ❌ 失败: {stderr}")

    return {"results": results, "total": len(results), "success": sum(1 for r in results if r["success"])}

def main():
    parser = argparse.ArgumentParser(description="服务器安全修复包装器")
    parser.add_argument("--target", required=True, help="目标服务器IP")
    parser.add_argument("--mode", choices=["audit", "fix"], default="audit", help="执行模式")
    parser.add_argument("--actions", help="修复操作JSON文件路径")
    parser.add_argument("--ssh-key", default="~/.ssh/id_rsa", help="SSH私钥路径")
    parser.add_argument("--ssh-user", default="root", help="SSH用户名")
    parser.add_argument("--yes", action="store_true", help="跳过确认（危险！）")

    args = parser.parse_args()

    if args.mode == "audit":
        # 审计模式：只读检查
        log_audit("AUDIT_START", args.target)

        # 执行端口扫描脚本
        script_path = Path(__file__).parent / "port_scan.sh"
        ssh_key = os.path.expanduser(args.ssh_key)

        cmd = f"bash -s < {script_path} -- --json"
        returncode, stdout, stderr = run_ssh_command(args.target, f"bash -c '{cmd}'", ssh_key, args.ssh_user)

        if returncode == 0:
            print(stdout)
            log_audit("AUDIT_COMPLETE", args.target, f"findings={len(json.loads(stdout).get('findings', []))}")
        else:
            print(json.dumps({"error": stderr, "status": "FAILED"}))
            log_audit("AUDIT_FAILED", args.target, stderr)

    elif args.mode == "fix":
        # 修复模式：需要确认
        if not args.actions:
            print(json.dumps({"error": "No actions file specified", "status": "FAILED"}))
            sys.exit(1)

        with open(args.actions) as f:
            actions = json.load(f)

        # 强制确认（除非使用了 --yes 参数）
        if not args.yes:
            if not confirm_fix(args.target, actions):
                log_audit("FIX_CANCELLED", args.target)
                print(json.dumps({"status": "CANCELLED", "message": "User cancelled the operation"}))
                sys.exit(0)

        # 执行修复
        log_audit("FIX_START", args.target, f"actions={len(actions)}")
        result = execute_fix(args.target, actions, args.ssh_key, args.ssh_user)
        log_audit("FIX_COMPLETE", args.target, f"success={result['success']}/{result['total']}")

        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()