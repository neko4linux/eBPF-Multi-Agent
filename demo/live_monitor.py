"""
eBPF Multi-Agent Anomaly Detection — 实时进程监控器
====================================================
使用 psutil 实时采集进程行为，模拟 eBPF 内核态监控
"""

import os
import sys
import time
import signal
import threading
from collections import defaultdict, deque
from datetime import datetime

import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live

console = Console()

# 监控目标: AI Agent 进程特征
AGENT_KEYWORDS = [
    "python", "node", "claude", "gemini", "gpt", "ollama",
    "agent", "llm", "openai", "anthropic", "copilot",
]

# 敏感路径
SENSITIVE_PATHS = ["/etc/shadow", "/etc/passwd", "/root/.ssh", "/etc/sudoers"]

# Shell 进程
SHELL_NAMES = {"bash", "sh", "zsh", "dash", "fish"}


class ProcessMonitor:
    """实时进程行为监控器"""

    def __init__(self, interval=1.0):
        self.interval = interval
        self.running = False
        self.agents = {}       # pid -> agent info
        self.alerts = []       # 告警历史
        self.events = deque(maxlen=500)  # 事件队列
        self.stats = defaultdict(int)
        self._prev_pids = set()

    def _is_agent_process(self, proc) -> bool:
        """判断是否为 AI Agent 进程"""
        try:
            name = proc.name().lower()
            cmdline = " ".join(proc.cmdline()).lower()
            return any(kw in name or kw in cmdline for kw in AGENT_KEYWORDS)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _get_process_info(self, proc) -> dict:
        """采集进程详细信息 (模拟 eBPF 数据采集)"""
        try:
            with proc.oneshot():
                info = {
                    "pid": proc.pid,
                    "ppid": proc.ppid(),
                    "name": proc.name(),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_mb": proc.memory_info().rss / 1024 / 1024,
                    "num_threads": proc.num_threads(),
                    "create_time": proc.create_time(),
                    "cmdline": " ".join(proc.cmdline())[:200],
                }
                # 文件描述符
                try:
                    info["num_fds"] = proc.num_fds()
                except (psutil.AccessDenied, AttributeError):
                    info["num_fds"] = 0

                # 网络连接
                try:
                    conns = proc.net_connections(kind='inet')
                    info["num_connections"] = len(conns)
                    info["connections"] = []
                    for c in conns[:10]:
                        conn_info = {
                            "fd": c.fd,
                            "family": str(c.family.name),
                            "type": str(c.type.name),
                            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                            "status": c.status,
                        }
                        info["connections"].append(conn_info)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info["num_connections"] = 0
                    info["connections"] = []

                # 打开文件
                try:
                    open_files = proc.open_files()
                    info["open_files"] = [f.path for f in open_files[:20]]
                    info["num_open_files"] = len(open_files)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info["open_files"] = []
                    info["num_open_files"] = 0

                # 子进程
                try:
                    children = proc.children(recursive=True)
                    info["num_children"] = len(children)
                    info["children"] = [f"{c.pid}:{c.name()}" for c in children[:10]]
                except psutil.NoSuchProcess:
                    info["num_children"] = 0
                    info["children"] = []

                return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _check_anomalies(self, pid, info):
        """异常检测 (规则引擎)"""
        alerts = []
        now = datetime.now().strftime("%H:%M:%S")

        # 1) Shell 进程检测
        if info["name"].lower() in SHELL_NAMES:
            alerts.append({
                "time": now, "pid": pid, "agent": info["name"],
                "type": "SHELL_SPAWN", "severity": "HIGH",
                "desc": f"检测到 Shell 进程: {info['name']}",
                "evidence": f"cmdline: {info['cmdline'][:100]}",
            })

        # 2) 敏感文件访问
        for fpath in info.get("open_files", []):
            for sp in SENSITIVE_PATHS:
                if fpath.startswith(sp):
                    alerts.append({
                        "time": now, "pid": pid, "agent": info["name"],
                        "type": "SENSITIVE_FILE_ACCESS", "severity": "HIGH",
                        "desc": f"访问敏感文件: {fpath}",
                        "evidence": f"进程 {info['name']} (PID={pid})",
                    })

        # 3) 异常网络连接
        for conn in info.get("connections", []):
            if conn["status"] == "ESTABLISHED" and conn["raddr"]:
                # 检查非标准端口
                try:
                    port = int(conn["raddr"].split(":")[-1])
                    if port < 10 and port not in (80, 443, 8080):
                        alerts.append({
                            "time": now, "pid": pid, "agent": info["name"],
                            "type": "SUSPICIOUS_NETWORK", "severity": "MEDIUM",
                            "desc": f"可疑网络连接: {conn['raddr']}",
                            "evidence": f"端口 {port} 非常规",
                        })
                except (ValueError, IndexError):
                    pass

        # 4) 资源异常
        if info["memory_mb"] > 1000:
            alerts.append({
                "time": now, "pid": pid, "agent": info["name"],
                "type": "RESOURCE_ABUSE", "severity": "MEDIUM",
                "desc": f"内存使用过高: {info['memory_mb']:.0f} MB",
                "evidence": f"进程 {info['name']} 占用 {info['memory_mb']:.0f} MB",
            })

        if info["num_children"] > 20:
            alerts.append({
                "time": now, "pid": pid, "agent": info["name"],
                "type": "RESOURCE_ABUSE", "severity": "MEDIUM",
                "desc": f"大量子进程: {info['num_children']}",
                "evidence": f"进程 {info['name']} 创建了 {info['num_children']} 个子进程",
            })

        return alerts

    def scan_once(self):
        """单次扫描"""
        current_pids = set()
        scan_results = []

        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                is_agent = self._is_agent_process(proc)

                if is_agent or True:  # 监控所有进程，标记 agent
                    info = self._get_process_info(proc)
                    if info:
                        info["is_agent"] = is_agent
                        scan_results.append(info)

                        # 检测异常
                        anomalies = self._check_anomalies(pid, info)
                        for a in anomalies:
                            self.alerts.append(a)
                            self.stats[a["type"]] += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 检测新进程
        new_pids = current_pids - self._prev_pids
        gone_pids = self._prev_pids - current_pids
        self._prev_pids = current_pids

        self.stats["total_scans"] += 1
        self.stats["total_processes"] = len(scan_results)
        self.stats["new_processes"] = len(new_pids)
        self.stats["gone_processes"] = len(gone_pids)

        return scan_results

    def run(self, duration=30):
        """运行监控"""
        self.running = True
        console.print(Panel.fit(
            "[bold cyan]eBPF Multi-Agent 实时进程监控器[/]\n"
            f"[dim]扫描间隔: {self.interval}s  |  监控时长: {duration}s[/]\n"
            "[dim]按 Ctrl+C 提前停止[/]",
            border_style="cyan",
        ))

        start = time.time()

        def generate_display():
            """生成 Rich Live 显示内容"""
            while self.running and (time.time() - start) < duration:
                results = self.scan_once()

                # 进程表
                proc_table = Table(title=f"🔍 进程快照 (共 {len(results)} 个)", show_lines=False)
                proc_table.add_column("PID", width=7)
                proc_table.add_column("名称", width=15)
                proc_table.add_column("状态", width=8)
                proc_table.add_column("CPU%", width=6)
                proc_table.add_column("内存MB", width=8)
                proc_table.add_column("线程", width=5)
                proc_table.add_column("FD", width=5)
                proc_table.add_column("连接", width=5)
                proc_table.add_column("子进程", width=6)
                proc_table.add_column("Agent", width=5)

                # 按内存排序，显示 top 15
                sorted_procs = sorted(results, key=lambda x: x.get("memory_mb", 0), reverse=True)[:15]
                for p in sorted_procs:
                    agent_tag = "[green]✓[/]" if p.get("is_agent") else "-"
                    proc_table.add_row(
                        str(p["pid"]),
                        p["name"][:15],
                        p["status"],
                        f"{p['cpu_percent']:.1f}",
                        f"{p['memory_mb']:.1f}",
                        str(p["num_threads"]),
                        str(p["num_fds"]),
                        str(p["num_connections"]),
                        str(p["num_children"]),
                        agent_tag,
                    )

                # 告警表
                alert_table = Table(title=f"🚨 告警 (共 {len(self.alerts)} 条)", show_lines=False)
                alert_table.add_column("时间", width=10)
                alert_table.add_column("PID", width=7)
                alert_table.add_column("类型", width=18)
                alert_table.add_column("级别", width=8)
                alert_table.add_column("描述", max_width=40)

                for a in list(self.alerts)[-10:]:
                    color = "red" if a["severity"] == "HIGH" else "yellow"
                    alert_table.add_row(
                        a["time"], str(a["pid"]),
                        f"[{color}]{a['type']}[/]",
                        f"[{color}]{a['severity']}[/]",
                        a["desc"][:40],
                    )

                # 统计面板
                stats_text = (
                    f"[bold]扫描次数:[/] {self.stats['total_scans']}  "
                    f"[bold]当前进程:[/] {self.stats['total_processes']}  "
                    f"[bold]新增:[/] {self.stats['new_processes']}  "
                    f"[bold]消失:[/] {self.stats['gone_processes']}\n"
                    f"[bold]告警统计:[/] "
                    + "  ".join(f"{k}={v}" for k, v in self.stats.items()
                               if k not in ('total_scans', 'total_processes',
                                            'new_processes', 'gone_processes'))
                )

                yield proc_table, alert_table, stats_text
                time.sleep(self.interval)

        try:
            for proc_table, alert_table, stats_text in generate_display():
                console.clear()
                console.print(Panel.fit(
                    "[bold cyan]eBPF Multi-Agent 实时进程监控器[/]  "
                    f"[dim]运行中... ({int(time.time() - start)}s / {duration}s)[/]",
                    border_style="cyan",
                ))
                console.print(proc_table)
                console.print()
                if self.alerts:
                    console.print(alert_table)
                console.print()
                console.print(Panel(stats_text, border_style="dim"))
        except KeyboardInterrupt:
            pass

        self.running = False
        console.print(f"\n[bold]监控结束。共扫描 {self.stats['total_scans']} 次，"
                       f"产生 {len(self.alerts)} 条告警。[/]")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="eBPF Multi-Agent 实时进程监控器")
    parser.add_argument("-i", "--interval", type=float, default=2.0, help="扫描间隔 (秒)")
    parser.add_argument("-d", "--duration", type=int, default=30, help="监控时长 (秒)")
    args = parser.parse_args()

    monitor = ProcessMonitor(interval=args.interval)
    monitor.run(duration=args.duration)


if __name__ == "__main__":
    main()
