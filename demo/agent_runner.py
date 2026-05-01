#!/usr/bin/env python3
"""
Real Agent Runner & Benchmark
==============================
直接调用真实的 AI Agent CLI 工具执行任务，由 eBPF 监控系统检测。

支持的 Agent:
  - Claude Code (claude)
  - OpenAI Codex (codex)
  - Gemini CLI (gemini)
  - Aider (aider)

用法:
    python agent_runner.py --list                    # 列出可用 Agent
    python agent_runner.py --run claude-code         # 运行单个 Agent
    python agent_runner.py --benchmark               # 运行完整 Benchmark
    python agent_runner.py --benchmark --parallel    # 并行运行所有 Agent
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ═══════════════════════════════════════════════
# Agent 定义
# ═══════════════════════════════════════════════

@dataclass
class AgentDef:
    """真实 Agent 定义"""
    name: str
    agent_type: str
    icon: str
    binary: str          # CLI 可执行文件路径
    version_cmd: str     # 版本检查命令
    api_env_key: str     # API Key 环境变量名
    risk_level: str
    benchmark_tasks: list = field(default_factory=list)


AGENTS = [
    AgentDef(
        name="Claude Code",
        agent_type="claude-code",
        icon="🟣",
        binary="/root/.hermes/node/bin/claude",
        version_cmd="--version",
        api_env_key="ANTHROPIC_API_KEY",
        risk_level="MEDIUM",
        benchmark_tasks=[
            {
                "id": "hello",
                "prompt": "Say hello in one sentence, nothing else.",
                "timeout": 30,
            },
            {
                "id": "code-gen",
                "prompt": "Write a Python function that calculates fibonacci(n) using memoization. Only output the function, no explanation.",
                "timeout": 60,
            },
            {
                "id": "file-read",
                "prompt": "Read the file /etc/hostname and tell me its content.",
                "timeout": 30,
            },
            {
                "id": "shell-exec",
                "prompt": "Run 'uname -a' and show me the output.",
                "timeout": 30,
            },
        ],
    ),
    AgentDef(
        name="OpenAI Codex",
        agent_type="codex",
        icon="🟢",
        binary="/root/.hermes/node/bin/codex",
        version_cmd="--version",
        api_env_key="OPENAI_API_KEY",
        risk_level="MEDIUM",
        benchmark_tasks=[
            {
                "id": "hello",
                "prompt": "Say hello in one sentence.",
                "timeout": 30,
            },
            {
                "id": "code-gen",
                "prompt": "Write a Python function that checks if a string is a palindrome.",
                "timeout": 60,
            },
        ],
    ),
    AgentDef(
        name="Gemini CLI",
        agent_type="gemini-cli",
        icon="🔵",
        binary="/root/.hermes/node/bin/gemini",
        version_cmd="--version",
        api_env_key="GEMINI_API_KEY",
        risk_level="MEDIUM",
        benchmark_tasks=[
            {
                "id": "hello",
                "prompt": "Say hello in one sentence.",
                "timeout": 30,
            },
            {
                "id": "code-gen",
                "prompt": "Write a Python function that sorts a list using quicksort.",
                "timeout": 60,
            },
        ],
    ),
    AgentDef(
        name="Aider",
        agent_type="aider",
        icon="⚪",
        binary=os.path.expanduser("~/.local/bin/aider"),
        version_cmd="--version",
        api_env_key="ANTHROPIC_API_KEY",
        risk_level="MEDIUM",
        benchmark_tasks=[
            {
                "id": "hello",
                "prompt": "Say hello in one sentence.",
                "timeout": 30,
            },
        ],
    ),
]

AGENT_MAP = {a.agent_type: a for a in AGENTS}


# ═══════════════════════════════════════════════
# Agent Runner
# ═══════════════════════════════════════════════

class AgentRunner:
    """运行真实的 AI Agent 并记录结果"""

    def __init__(self, workdir: str = "/tmp/agent-benchmark"):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.results = []

    def check_agent(self, agent: AgentDef) -> dict:
        """检查 Agent 是否可用"""
        result = {
            "agent": agent.name,
            "type": agent.agent_type,
            "binary": agent.binary,
            "exists": os.path.exists(agent.binary),
            "api_key_set": bool(os.environ.get(agent.api_env_key)),
            "version": None,
        }

        if result["exists"]:
            try:
                out = subprocess.run(
                    [agent.binary, agent.version_cmd],
                    capture_output=True, text=True, timeout=10,
                )
                result["version"] = out.stdout.strip() or out.stderr.strip()
            except Exception as e:
                result["version"] = f"error: {e}"

        return result

    def list_agents(self):
        """列出所有 Agent 状态"""
        print("\n" + "=" * 70)
        print("🤖 可用 AI Agent 列表")
        print("=" * 70)

        for agent in AGENTS:
            info = self.check_agent(agent)
            status = "✅" if info["exists"] else "❌"
            api = "🔑" if info["api_key_set"] else "⚠️"
            ver = info.get("version", "N/A")[:40]

            print(f"\n  {agent.icon} {agent.name}")
            print(f"     类型:     {agent.agent_type}")
            print(f"     二进制:   {status} {agent.binary}")
            print(f"     API Key:  {api} {agent.api_env_key}")
            print(f"     版本:     {ver}")
            print(f"     风险等级: {agent.risk_level}")
            print(f"     任务数:   {len(agent.benchmark_tasks)}")

        print("\n" + "=" * 70)

    def run_claude_code(self, task: dict) -> dict:
        """运行 Claude Code CLI"""
        cmd = [
            AGENT_MAP["claude-code"].binary,
            "--print",                    # 非交互模式，直接输出
            "--model", "claude-sonnet-4-20250514",
            task["prompt"],
        ]

        return self._run_process("claude-code", cmd, task)

    def run_codex(self, task: dict) -> dict:
        """运行 Codex CLI"""
        cmd = [
            AGENT_MAP["codex"].binary,
            "--quiet",
            task["prompt"],
        ]

        return self._run_process("codex", cmd, task)

    def run_gemini(self, task: dict) -> dict:
        """运行 Gemini CLI"""
        cmd = [
            AGENT_MAP["gemini"].binary,
            "-p", task["prompt"],
        ]

        return self._run_process("gemini-cli", cmd, task)

    def run_aider(self, task: dict) -> dict:
        """运行 Aider CLI"""
        # Aider 需要一个文件上下文，创建临时文件
        tmp_file = self.workdir / "aider_context.py"
        tmp_file.write_text("# Aider benchmark context\nprint('hello')\n")

        cmd = [
            AGENT_MAP["aider"].binary,
            "--yes",
            "--no-auto-commits",
            "--message", task["prompt"],
            str(tmp_file),
        ]

        return self._run_process("aider", cmd, task)

    def _run_process(self, agent_type: str, cmd: list, task: dict) -> dict:
        """通用进程执行器"""
        result = {
            "agent": agent_type,
            "task_id": task["id"],
            "prompt": task["prompt"],
            "start_time": datetime.now().isoformat(),
            "duration_ms": 0,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "pid": None,
            "success": False,
        }

        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.workdir),
            )
            result["pid"] = proc.pid
            print(f"    📡 启动 {agent_type} (PID={proc.pid}): {task['id']}")

            try:
                stdout, stderr = proc.communicate(timeout=task.get("timeout", 60))
                result["stdout"] = stdout[:2000]
                result["stderr"] = stderr[:1000]
                result["exit_code"] = proc.returncode
                result["success"] = proc.returncode == 0
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                result["stderr"] = "TIMEOUT"
                result["exit_code"] = -1

        except FileNotFoundError:
            result["stderr"] = f"Binary not found: {cmd[0]}"
            result["exit_code"] = -2
        except Exception as e:
            result["stderr"] = str(e)
            result["exit_code"] = -3

        result["duration_ms"] = int((time.time() - start) * 1000)
        result["end_time"] = datetime.now().isoformat()

        status = "✅" if result["success"] else "❌"
        print(f"    {status} {task['id']}: {result['duration_ms']}ms (exit={result['exit_code']})")

        return result

    def run_agent(self, agent_type: str, task_id: Optional[str] = None) -> list:
        """运行指定 Agent 的任务"""
        agent = AGENT_MAP.get(agent_type)
        if not agent:
            print(f"❌ 未知 Agent: {agent_type}")
            return []

        info = self.check_agent(agent)
        if not info["exists"]:
            print(f"❌ {agent.name} 未安装: {agent.binary}")
            return []

        if not info["api_key_set"]:
            print(f"⚠️  {agent.api_env_key} 未设置，API 调用可能失败")

        # 选择运行器
        runners = {
            "claude-code": self.run_claude_code,
            "codex": self.run_codex,
            "gemini-cli": self.run_gemini,
            "aider": self.run_aider,
        }

        runner = runners.get(agent_type)
        if not runner:
            print(f"❌ {agent.name} 暂不支持直接运行")
            return []

        # 过滤任务
        tasks = agent.benchmark_tasks
        if task_id:
            tasks = [t for t in tasks if t["id"] == task_id]
            if not tasks:
                print(f"❌ 未知任务: {task_id}")
                return []

        print(f"\n{agent.icon} 运行 {agent.name} ({len(tasks)} 个任务)")

        results = []
        for task in tasks:
            result = runner(task)
            results.append(result)
            self.results.append(result)

        return results

    def run_benchmark(self, parallel: bool = False):
        """运行完整 Benchmark"""
        print("\n" + "=" * 70)
        print("🏁 AI Agent Benchmark")
        print(f"   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   模式: {'并行' if parallel else '串行'}")
        print("=" * 70)

        # 检查可用 Agent
        available = []
        for agent in AGENTS:
            info = self.check_agent(agent)
            if info["exists"] and info["api_key_set"]:
                available.append(agent)
            elif info["exists"]:
                print(f"  ⚠️  {agent.name}: 无 API Key ({agent.api_env_key})")
            else:
                print(f"  ❌ {agent.name}: 未安装")

        if not available:
            print("\n❌ 没有可用的 Agent (需要安装 + 设置 API Key)")
            return

        print(f"\n📋 可用 Agent: {len(available)}")

        if parallel:
            self._run_parallel(available)
        else:
            self._run_serial(available)

        self._print_summary()

    def _run_serial(self, agents: list):
        """串行运行所有 Agent"""
        for agent in agents:
            self.run_agent(agent.agent_type)
            time.sleep(1)

    def _run_parallel(self, agents: list):
        """并行运行所有 Agent"""
        threads = []
        for agent in agents:
            t = threading.Thread(target=self.run_agent, args=(agent.agent_type,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=120)

    def _print_summary(self):
        """打印 Benchmark 汇总"""
        print("\n" + "=" * 70)
        print("📊 Benchmark 结果汇总")
        print("=" * 70)

        if not self.results:
            print("  无结果")
            return

        # 按 Agent 分组
        by_agent = {}
        for r in self.results:
            by_agent.setdefault(r["agent"], []).append(r)

        for agent_type, results in by_agent.items():
            agent = AGENT_MAP.get(agent_type)
            icon = agent.icon if agent else "⬜"
            success = sum(1 for r in results if r["success"])
            total = len(results)
            avg_ms = sum(r["duration_ms"] for r in results) / total if total else 0

            print(f"\n  {icon} {agent_type}")
            print(f"     成功率: {success}/{total}")
            print(f"     平均耗时: {avg_ms:.0f}ms")

            for r in results:
                status = "✅" if r["success"] else "❌"
                print(f"       {status} {r['task_id']}: {r['duration_ms']}ms")

        # 保存详细结果
        report_path = self.workdir / "benchmark_report.json"
        with open(report_path, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "results": self.results,
                "summary": {
                    agent_type: {
                        "total": len(results),
                        "success": sum(1 for r in results if r["success"]),
                        "avg_ms": sum(r["duration_ms"] for r in results) / len(results),
                    }
                    for agent_type, results in by_agent.items()
                },
            }, f, indent=2, ensure_ascii=False)

        print(f"\n  📄 详细报告: {report_path}")
        print("=" * 70)


# ═══════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Real AI Agent Runner & Benchmark")
    parser.add_argument("--list", action="store_true", help="列出可用 Agent")
    parser.add_argument("--run", type=str, help="运行指定 Agent (claude-code/codex/gemini-cli/aider)")
    parser.add_argument("--task", type=str, help="运行指定任务 ID")
    parser.add_argument("--benchmark", action="store_true", help="运行完整 Benchmark")
    parser.add_argument("--parallel", action="store_true", help="并行运行")
    parser.add_argument("--workdir", type=str, default="/tmp/agent-benchmark", help="工作目录")
    args = parser.parse_args()

    runner = AgentRunner(workdir=args.workdir)

    if args.list:
        runner.list_agents()
    elif args.run:
        runner.run_agent(args.run, args.task)
    elif args.benchmark:
        runner.run_benchmark(parallel=args.parallel)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
