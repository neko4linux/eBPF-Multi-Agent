#!/usr/bin/env python3
"""
Agent Detection Simulator
=========================
模拟多个 AI Agent 的系统行为，用于演示 eBPF 监控系统。
通过 procfs 接口和 HTTP API 与后端交互。

用法:
    python agent_simulator.py [--backend http://localhost:8080]
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("需要 requests 库: pip install requests")
    sys.exit(1)


# ═══════════════════════════════════════════════
# Agent 配置
# ═══════════════════════════════════════════════

@dataclass
class AgentConfig:
    name: str
    agent_type: str
    icon: str
    risk_level: str
    api_domain: str
    dangerous_ops: list
    simulation_cmds: list


AGENTS = [
    AgentConfig(
        name="Claude Code",
        agent_type="claude-code",
        icon="🟣",
        risk_level="MEDIUM",
        api_domain="api.anthropic.com",
        dangerous_ops=["curl injection", "SSH key access", "env leak", "git force push"],
        simulation_cmds=[
            "echo 'claude --interactive' > /dev/null",
            "curl -s https://api.anthropic.com/v1/messages | head -1",
            "cat ~/.ssh/id_rsa 2>/dev/null || echo 'no ssh key'",
            "env | grep -i api_key || echo 'no api key found'",
            "git push --force origin main 2>/dev/null || echo 'not a git repo'",
        ],
    ),
    AgentConfig(
        name="OpenAI Codex",
        agent_type="codex",
        icon="🟢",
        risk_level="MEDIUM",
        api_domain="api.openai.com",
        dangerous_ops=["sandbox escape", "network exfil", "credential access"],
        simulation_cmds=[
            "echo 'codex --model codex-2' > /dev/null",
            "curl -s https://api.openai.com/v1/completions | head -1",
            "chroot /tmp 2>/dev/null || echo 'chroot failed'",
            "cat ~/.aws/credentials 2>/dev/null || echo 'no aws creds'",
            "nc -l 4444 2>/dev/null & echo 'listener started'",
        ],
    ),
    AgentConfig(
        name="Gemini CLI",
        agent_type="gemini-cli",
        icon="🔵",
        risk_level="MEDIUM",
        api_domain="generativelanguage.googleapis.com",
        dangerous_ops=["GCP credential access", "billing manipulation", "data exfil"],
        simulation_cmds=[
            "echo 'gemini --model gemini-pro' > /dev/null",
            "curl -s https://generativelanguage.googleapis.com/v1/models | head -1",
            "cat ~/.gcloud/credentials.db 2>/dev/null || echo 'no gcloud creds'",
            "gcloud iam service-accounts list 2>/dev/null || echo 'no gcloud'",
        ],
    ),
    AgentConfig(
        name="Kiro CLI",
        agent_type="kiro-cli",
        icon="🟠",
        risk_level="HIGH",
        api_domain="kiro.dev",
        dangerous_ops=["AWS credential access", "IAM manipulation", "S3 exfil"],
        simulation_cmds=[
            "echo 'kiro --spec service.kiro' > /dev/null",
            "curl -s https://api.kiro.dev/v1/health | head -1",
            "aws sts get-caller-identity 2>/dev/null || echo 'no aws cli'",
            "aws s3 ls 2>/dev/null || echo 'no s3 access'",
        ],
    ),
    AgentConfig(
        name="Cursor",
        agent_type="cursor",
        icon="🟡",
        risk_level="LOW",
        api_domain="api.cursor.sh",
        dangerous_ops=["terminal execution", "workspace modification"],
        simulation_cmds=[
            "echo 'cursor --new-window .' > /dev/null",
            "curl -s https://api.cursor.sh/v1/health | head -1",
            "ls -la /proc/self/fd",
        ],
    ),
    AgentConfig(
        name="GitHub Copilot",
        agent_type="copilot",
        icon="⚫",
        risk_level="LOW",
        api_domain="copilot-proxy.githubusercontent.com",
        dangerous_ops=["code injection", "repository access"],
        simulation_cmds=[
            "echo 'gh copilot suggest' > /dev/null",
            "curl -s https://api.github.com/zen | head -1",
            "gh repo list --limit 3 2>/dev/null || echo 'no gh cli'",
        ],
    ),
    AgentConfig(
        name="Aider",
        agent_type="aider",
        icon="⚪",
        risk_level="MEDIUM",
        api_domain="api.deepseek.com",
        dangerous_ops=["file editing", "git manipulation"],
        simulation_cmds=[
            "echo 'aider --model deepseek' > /dev/null",
            "curl -s https://api.deepseek.com/v1/models | head -1",
            "git diff --stat HEAD~1 2>/dev/null || echo 'not a git repo'",
        ],
    ),
]


# ═══════════════════════════════════════════════
# 模拟器引擎
# ═══════════════════════════════════════════════

class AgentSimulator:
    def __init__(self, backend_url: str):
        self.backend = backend_url.rstrip("/")
        self.running = True
        self.events = []
        self.lock = threading.Lock()

    def check_backend(self) -> bool:
        """检查后端是否可用"""
        try:
            r = requests.get(f"{self.backend}/api/health", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def register_agent(self, agent: AgentConfig, pid: int):
        """通过后端 API 注册 Agent 检测"""
        try:
            requests.post(f"{self.backend}/api/agents/detect", json={
                "pid": pid,
                "comm": agent.agent_type,
                "cmdline": f"{agent.agent_type} --interactive --model sonnet",
                "event_type": "EXECVE",
                "detail": f"Agent {agent.name} started with PID {pid}",
            }, timeout=5)
        except Exception as e:
            print(f"  ⚠ 注册失败: {e}")

    def simulate_traffic(self, agent: AgentConfig, pid: int):
        """模拟 Agent 的网络流量"""
        try:
            requests.post(f"{self.backend}/api/agents/detect", json={
                "pid": pid,
                "comm": agent.agent_type,
                "cmdline": f"{agent.agent_type} --api-call",
                "event_type": "SSL_WRITE",
                "detail": f'{{"model":"claude-3","messages":[{{"role":"user","content":"write code"}}],"stream":true}}',
            }, timeout=5)
        except Exception:
            pass

    def simulate_anomaly(self, agent: AgentConfig, pid: int, op: str):
        """模拟异常行为"""
        event_type = "EXECVE"
        if "curl" in op or "nc" in op:
            event_type = "CONNECT"
        elif "ssh" in op or "aws" in op or "gcloud" in op:
            event_type = "OPENAT"

        try:
            requests.post(f"{self.backend}/api/agents/detect", json={
                "pid": pid,
                "comm": agent.agent_type,
                "cmdline": op,
                "event_type": event_type,
                "detail": op,
            }, timeout=5)
        except Exception:
            pass

    def run_agent(self, agent: AgentConfig, duration: int = 30):
        """运行单个 Agent 的模拟"""
        pid = os.getpid() + hash(agent.agent_type) % 10000
        print(f"\n{agent.icon} 启动 {agent.name} (模拟 PID={pid})")
        print(f"   风险等级: {agent.risk_level}")
        print(f"   API: {agent.api_domain}")

        # 注册 Agent
        self.register_agent(agent, pid)
        time.sleep(0.5)

        # 模拟正常流量
        print(f"   📡 模拟 API 流量...")
        for _ in range(3):
            self.simulate_traffic(agent, pid)
            time.sleep(0.3)

        # 模拟异常行为
        print(f"   ⚠️  模拟危险操作:")
        for cmd in agent.simulation_cmds:
            if not self.running:
                break
            print(f"      $ {cmd[:60]}...")
            self.simulate_anomaly(agent, pid, cmd)
            time.sleep(0.5)

        with self.lock:
            self.events.append({
                "agent": agent.name,
                "type": agent.agent_type,
                "pid": pid,
                "time": datetime.now().isoformat(),
                "risk": agent.risk_level,
            })

    def run_all(self, duration: int = 60):
        """并行运行所有 Agent 模拟"""
        print("=" * 60)
        print("🛡️  eBPF Multi-Agent 检测模拟器")
        print("=" * 60)

        if not self.check_backend():
            print(f"\n❌ 后端不可用: {self.backend}")
            print("   请确保后端服务已启动: make be")
            sys.exit(1)

        print(f"\n✅ 后端已连接: {self.backend}")
        print(f"📋 模拟 {len(AGENTS)} 个 Agent...")
        print(f"⏱️  预计耗时: {len(AGENTS) * 5} 秒\n")

        for agent in AGENTS:
            if not self.running:
                break
            self.run_agent(agent, duration)
            time.sleep(1)

        self.print_summary()

    def print_summary(self):
        """打印模拟结果"""
        print("\n" + "=" * 60)
        print("📊 模拟结果汇总")
        print("=" * 60)

        with self.lock:
            for evt in self.events:
                risk_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
                print(f"  {risk_icon.get(evt['risk'], '⚪')} {evt['agent']} (PID={evt['pid']}) - {evt['risk']}")

        print(f"\n  总计: {len(self.events)} 个 Agent 被模拟")
        print(f"  请查看前端仪表盘: http://localhost:5173")
        print(f"  或直接访问 API: {self.backend}/api/agents/detected")


# ═══════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="eBPF Agent Detection Simulator")
    parser.add_argument("--backend", default="http://localhost:8080", help="Backend URL")
    parser.add_argument("--duration", type=int, default=60, help="Simulation duration (seconds)")
    parser.add_argument("--agent", type=str, help="Run specific agent only")
    args = parser.parse_args()

    sim = AgentSimulator(args.backend)

    def handle_signal(sig, frame):
        print("\n\n⏹️  模拟已停止")
        sim.running = False
        sim.print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)

    if args.agent:
        agent = next((a for a in AGENTS if a.agent_type == args.agent), None)
        if agent:
            sim.run_agent(agent, args.duration)
            sim.print_summary()
        else:
            print(f"未知 Agent: {args.agent}")
            print(f"可选: {', '.join(a.agent_type for a in AGENTS)}")
            sys.exit(1)
    else:
        sim.run_all(args.duration)


if __name__ == "__main__":
    main()
