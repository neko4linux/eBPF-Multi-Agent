#!/usr/bin/env python3
"""
Ollama Cloud Runner
===================
通过 Ollama API (本地或云端) 运行 LLM 推理任务。
支持 ollama run (CLI) 和 HTTP API 两种模式。

用法:
    # 本地 Ollama
    python ollama_runner.py --list
    python ollama_runner.py --run --prompt "Hello"
    python ollama_runner.py --benchmark

    # 云端 Ollama
    python ollama_runner.py --cloud --endpoint https://your-ollama-cloud.com --run --prompt "Hello"

    # 指定模型
    python ollama_runner.py --model qwen3:0.6b --run --prompt "Hello"
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("需要 requests: pip install requests")
    sys.exit(1)


# ═══════════════════════════════════════════════
# Ollama API 客户端
# ═══════════════════════════════════════════════

class OllamaClient:
    """Ollama API 客户端 (支持本地和云端)"""

    def __init__(self, endpoint: str = "http://localhost:11434", api_key: str = ""):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY", "")
        self.headers = {"Content-Type": "application/json"}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def health(self) -> bool:
        """检查 Ollama 是否可用"""
        try:
            r = requests.get(f"{self.endpoint}/", headers=self.headers, timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list:
        """列出可用模型"""
        try:
            r = requests.get(f"{self.endpoint}/api/tags", headers=self.headers, timeout=10)
            r.raise_for_status()
            return r.json().get("models", [])
        except Exception as e:
            print(f"  ⚠️  获取模型列表失败: {e}")
            return []

    def generate(self, model: str, prompt: str, stream: bool = False, **kwargs) -> dict:
        """生成文本 (generate API)"""
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            **kwargs,
        }
        start = time.time()
        try:
            r = requests.post(
                f"{self.endpoint}/api/generate",
                headers=self.headers,
                json=payload,
                timeout=120,
            )
            r.raise_for_status()
            result = r.json()
            result["_duration_ms"] = int((time.time() - start) * 1000)
            return result
        except Exception as e:
            return {"error": str(e), "_duration_ms": int((time.time() - start) * 1000)}

    def chat(self, model: str, messages: list, stream: bool = False, **kwargs) -> dict:
        """Chat API"""
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            **kwargs,
        }
        start = time.time()
        try:
            r = requests.post(
                f"{self.endpoint}/api/chat",
                headers=self.headers,
                json=payload,
                timeout=120,
            )
            r.raise_for_status()
            result = r.json()
            result["_duration_ms"] = int((time.time() - start) * 1000)
            return result
        except Exception as e:
            return {"error": str(e), "_duration_ms": int((time.time() - start) * 1000)}

    def embeddings(self, model: str, prompt: str) -> dict:
        """获取文本嵌入"""
        payload = {"model": model, "prompt": prompt}
        try:
            r = requests.post(
                f"{self.endpoint}/api/embeddings",
                headers=self.headers,
                json=payload,
                timeout=60,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}


# ═══════════════════════════════════════════════
# Benchmark 任务
# ═══════════════════════════════════════════════

BENCHMARK_TASKS = [
    {
        "id": "gen-01-hello",
        "name": "简单问候",
        "prompt": "Say hello in one sentence.",
        "category": "generation",
        "timeout": 30,
    },
    {
        "id": "gen-02-code-python",
        "name": "Python 代码生成",
        "prompt": "Write a Python function fibonacci(n) with memoization. Only output the function code.",
        "category": "generation",
        "timeout": 60,
    },
    {
        "id": "gen-03-code-go",
        "name": "Go 代码生成",
        "prompt": "Write a Go function that checks if a string is a palindrome. Only output the function.",
        "category": "generation",
        "timeout": 60,
    },
    {
        "id": "gen-04-explain",
        "name": "代码解释",
        "prompt": "Explain what this code does in 2 sentences: import os; [f for f in os.listdir('.') if f.endswith('.py')]",
        "category": "generation",
        "timeout": 30,
    },
    {
        "id": "chat-01-system",
        "name": "System Prompt 对话",
        "messages": [
            {"role": "system", "content": "You are a security expert. Be concise."},
            {"role": "user", "content": "What are the top 3 risks of running LLM agents on a server?"},
        ],
        "category": "chat",
        "timeout": 60,
    },
    {
        "id": "chat-02-multi-turn",
        "name": "多轮对话",
        "messages": [
            {"role": "user", "content": "What is eBPF?"},
            {"role": "assistant", "content": "eBPF is a technology in the Linux kernel for running sandboxed programs."},
            {"role": "user", "content": "How can it be used for security monitoring?"},
        ],
        "category": "chat",
        "timeout": 60,
    },
    {
        "id": "embed-01",
        "name": "文本嵌入",
        "prompt": "The quick brown fox jumps over the lazy dog.",
        "category": "embedding",
        "timeout": 30,
    },
]


# ═══════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════

class OllamaRunner:
    def __init__(self, client: OllamaClient, model: str = "", workdir: str = "/tmp/agent-benchmark"):
        self.client = client
        self.model = model
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.results = []

    def list_info(self):
        """显示 Ollama 信息"""
        print("\n" + "=" * 60)
        print("🦙 Ollama Agent 信息")
        print("=" * 60)

        print(f"\n  端点: {self.client.endpoint}")
        print(f"  API Key: {'✅ 已设置' if self.client.api_key else '⚠️ 未设置'}")
        print(f"  健康检查: {'✅ 正常' if self.client.health() else '❌ 不可用'}")

        models = self.client.list_models()
        if models:
            print(f"\n  可用模型 ({len(models)}):")
            for m in models:
                size_mb = m.get("size", 0) / 1024 / 1024
                print(f"    📦 {m['name']} ({size_mb:.0f}MB)")
        else:
            print("\n  ⚠️  无可用模型 (内存不足或未拉取)")
            print("  💡 使用云端模式: --cloud --endpoint https://your-cloud.com")

        print("\n" + "=" * 60)

    def run_prompt(self, prompt: str, model: str = "") -> dict:
        """运行单个 prompt"""
        model = model or self.model
        if not model:
            return {"error": "未指定模型"}

        print(f"\n  🦙 Generate: model={model}")
        print(f"     Prompt: {prompt[:80]}...")

        result = self.client.generate(model, prompt)
        duration = result.get("_duration_ms", 0)

        if "error" in result:
            print(f"     ❌ 错误: {result['error']}")
        else:
            response = result.get("response", "")[:200]
            tokens = result.get("eval_count", 0)
            print(f"     ✅ 响应: {response}...")
            print(f"     ⏱️  耗时: {duration}ms, tokens: {tokens}")

        self.results.append({
            "task": "generate",
            "model": model,
            "prompt": prompt[:100],
            "duration_ms": duration,
            "success": "error" not in result,
            "tokens": result.get("eval_count", 0),
        })
        return result

    def run_chat(self, messages: list, model: str = "") -> dict:
        """运行 chat API"""
        model = model or self.model
        if not model:
            return {"error": "未指定模型"}

        print(f"\n  💬 Chat: model={model}")
        print(f"     Messages: {len(messages)} 条")

        result = self.client.chat(model, messages)
        duration = result.get("_duration_ms", 0)

        if "error" in result:
            print(f"     ❌ 错误: {result['error']}")
        else:
            content = result.get("message", {}).get("content", "")[:200]
            print(f"     ✅ 响应: {content}...")
            print(f"     ⏱️  耗时: {duration}ms")

        self.results.append({
            "task": "chat",
            "model": model,
            "duration_ms": duration,
            "success": "error" not in result,
        })
        return result

    def run_benchmark(self, model: str = ""):
        """运行完整 Benchmark"""
        model = model or self.model

        print("\n" + "=" * 60)
        print("🏁 Ollama Cloud Benchmark")
        print(f"   端点: {self.client.endpoint}")
        print(f"   模型: {model or '自动选择'}")
        print(f"   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        if not self.client.health():
            print("\n❌ Ollama 端点不可用")
            return

        # 自动选择模型
        if not model:
            models = self.client.list_models()
            if models:
                model = models[0]["name"]
                print(f"\n  自动选择模型: {model}")
            else:
                print("\n❌ 无可用模型")
                return

        for task in BENCHMARK_TASKS:
            print(f"\n  🧪 {task['id']}: {task['name']}")

            if task.get("category") == "chat":
                self.run_chat(task["messages"], model)
            elif task.get("category") == "embedding":
                print(f"     ⏭️  跳过 (需要 embedding 模型)")
            else:
                self.run_prompt(task["prompt"], model)

            time.sleep(0.5)

        self._print_summary(model)

    def run_cli(self, prompt: str, model: str = ""):
        """通过 CLI 运行 ollama run"""
        model = model or self.model or "qwen3:0.6b"
        cmd = ["ollama", "run", model, prompt]

        print(f"\n  🦙 CLI: {' '.join(cmd[:4])}...")

        start = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            duration = int((time.time() - start) * 1000)
            print(f"     {'✅' if result.returncode == 0 else '❌'} 耗时: {duration}ms")
            if result.stdout:
                print(f"     📤 {result.stdout[:200]}...")
            if result.stderr:
                print(f"     ⚠️  {result.stderr[:200]}")

            self.results.append({
                "task": "cli",
                "model": model,
                "duration_ms": duration,
                "success": result.returncode == 0,
            })
        except subprocess.TimeoutExpired:
            print(f"     ❌ 超时")
        except FileNotFoundError:
            print(f"     ❌ ollama 命令未找到")

    def _print_summary(self, model: str):
        """打印汇总"""
        print("\n" + "=" * 60)
        print("📊 Benchmark 结果")
        print("=" * 60)

        if not self.results:
            print("  无结果")
            return

        total = len(self.results)
        success = sum(1 for r in self.results if r.get("success"))
        avg_ms = sum(r.get("duration_ms", 0) for r in self.results) / total
        total_tokens = sum(r.get("tokens", 0) for r in self.results)

        print(f"\n  模型: {model}")
        print(f"  总任务: {total}")
        print(f"  成功: {success}/{total}")
        print(f"  平均耗时: {avg_ms:.0f}ms")
        print(f"  总 Tokens: {total_tokens}")

        print("\n  详细:")
        for r in self.results:
            status = "✅" if r.get("success") else "❌"
            print(f"    {status} {r.get('task', '?')}: {r.get('duration_ms', 0)}ms")

        # 保存报告
        report_path = self.workdir / "ollama_benchmark.json"
        with open(report_path, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "endpoint": self.client.endpoint,
                "model": model,
                "results": self.results,
            }, f, indent=2, ensure_ascii=False)

        print(f"\n  📄 报告: {report_path}")
        print("=" * 60)


# ═══════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Ollama Cloud Runner & Benchmark")
    parser.add_argument("--endpoint", default="http://localhost:11434", help="Ollama API 端点")
    parser.add_argument("--api-key", default="", help="API Key (云端认证)")
    parser.add_argument("--model", default="", help="模型名称")
    parser.add_argument("--cloud", action="store_true", help="使用云端模式")
    parser.add_argument("--list", action="store_true", help="列出信息")
    parser.add_argument("--run", action="store_true", help="运行 prompt")
    parser.add_argument("--prompt", default="", help="Prompt 内容")
    parser.add_argument("--benchmark", action="store_true", help="运行 Benchmark")
    parser.add_argument("--cli", action="store_true", help="使用 CLI 模式 (ollama run)")
    parser.add_argument("--workdir", default="/tmp/agent-benchmark")
    args = parser.parse_args()

    # 云端模式: 使用 OLLAMA_CLOUD_ENDPOINT 环境变量
    endpoint = args.endpoint
    if args.cloud:
        endpoint = os.environ.get("OLLAMA_CLOUD_ENDPOINT", endpoint)

    api_key = args.api_key or os.environ.get("OLLAMA_API_KEY", "")

    client = OllamaClient(endpoint=endpoint, api_key=api_key)
    runner = OllamaRunner(client=client, model=args.model, workdir=args.workdir)

    if args.list:
        runner.list_info()
    elif args.cli:
        prompt = args.prompt or "Say hello."
        runner.run_cli(prompt, args.model)
    elif args.run:
        prompt = args.prompt or "Say hello in one sentence."
        runner.run_prompt(prompt, args.model)
    elif args.benchmark:
        runner.run_benchmark(args.model)
    else:
        runner.list_info()


if __name__ == "__main__":
    main()
