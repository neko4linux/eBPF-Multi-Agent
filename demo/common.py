"""
eBPF Multi-Agent Anomaly Detection Framework - Common Data Structures
模拟 eBPF 内核态与用户态的数据通信结构
"""

from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional, List
import time


# ============ 事件类型 ============
class EventType(IntEnum):
    """系统事件类型 - 对应 eBPF 捕获的系统调用"""
    EXECVE = 1
    FORK = 2
    EXIT = 3
    OPENAT = 5
    UNLINKAT = 7
    CONNECT = 9
    ACCEPT = 10
    SSL_READ = 12
    SSL_WRITE = 13


# ============ 异常类型 ============
class AnomalyType(IntEnum):
    """异常检测类型"""
    LOGIC_LOOP = 1            # 逻辑死循环
    RESOURCE_ABUSE = 2        # 资源滥用
    SHELL_SPAWN = 3           # 非预期 Shell 启动
    SENSITIVE_FILE_ACCESS = 4 # 敏感文件越权访问
    WORKSPACE_VIOLATION = 5   # 工作区外文件操作
    HIGH_FREQ_API = 6         # 高频 API 调用
    SUSPICIOUS_NETWORK = 7    # 可疑网络连接
    AGENT_CONFLICT = 8        # 多智能体冲突


# ============ 严重级别 ============
class Severity(IntEnum):
    """告警严重级别"""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ============ 数据结构 ============
@dataclass
class ProcessContext:
    """进程上下文 - 模拟 eBPF 从 task_struct 读取的信息"""
    pid: int = 0
    ppid: int = 0
    tid: int = 0
    timestamp: int = 0      # 纳秒级时间戳
    comm: str = ""           # 进程名
    uid: int = 0
    gid: int = 0

    @staticmethod
    def current():
        """获取当前进程上下文（模拟 bpf_get_current_task）"""
        import os
        return ProcessContext(
            pid=os.getpid(),
            ppid=os.getppid(),
            tid=os.getpid(),
            timestamp=time.time_ns(),
            comm="demo-agent",
            uid=os.getuid(),
            gid=os.getgid(),
        )


@dataclass
class ProcessEvent:
    """进程事件 - 对应 eBPF process_events ring buffer"""
    ctx: ProcessContext = field(default_factory=ProcessContext)
    event_type: int = 0
    target_pid: int = 0
    args: str = ""
    ret_val: int = 0


@dataclass
class FileEvent:
    """文件事件 - 对应 eBPF file_events ring buffer"""
    ctx: ProcessContext = field(default_factory=ProcessContext)
    event_type: int = 0
    path: str = ""
    flags: int = 0
    mode: int = 0
    ret_val: int = 0


@dataclass
class NetworkEvent:
    """网络事件 - 对应 eBPF network_events ring buffer"""
    ctx: ProcessContext = field(default_factory=ProcessContext)
    event_type: int = 0
    family: int = 0          # AF_INET=2, AF_INET6=10
    local_port: int = 0
    remote_port: int = 0
    local_ip: str = ""
    remote_ip: str = ""
    ret_val: int = 0


@dataclass
class SSLEvent:
    """SSL/TLS 事件 - 对应 eBPF ssl_events ring buffer (uprobe)"""
    ctx: ProcessContext = field(default_factory=ProcessContext)
    event_type: int = 0
    fd: int = 0
    data_len: int = 0
    data: str = ""           # 截获的明文数据


@dataclass
class AnomalyAlert:
    """异常告警 - 对应 eBPF anomaly_alerts ring buffer"""
    timestamp: int = 0
    pid: int = 0
    tid: int = 0
    type: int = 0
    severity: int = 0
    description: str = ""
    evidence: str = ""
    prompt_context: str = ""


@dataclass
class AgentStats:
    """智能体统计信息"""
    start_time: int = 0
    last_update: int = 0
    api_call_count: int = 0
    api_call_count_1min: int = 0
    file_read_count: int = 0
    file_write_count: int = 0
    file_delete_count: int = 0
    fork_count: int = 0
    exec_count: int = 0
    shell_spawn_count: int = 0
    connect_count: int = 0
    prompt_count: int = 0
    duplicate_prompt_count: int = 0
    last_prompts: List[str] = field(default_factory=list)


@dataclass
class MonitorConfig:
    """监控配置"""
    enabled: bool = True
    monitor_all_processes: bool = True
    track_https: bool = True
    anomaly_detection_enabled: bool = True
    api_call_threshold_1min: int = 100
    api_call_threshold_5min: int = 500
    duplicate_prompt_threshold: int = 5
    sensitive_paths: List[str] = field(default_factory=lambda: [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/root/.ssh", "/etc/ssh/sshd_config",
    ])
    workspace_paths: List[str] = field(default_factory=lambda: [
        "/home/", "/root/workspace/", "/tmp/agent-workspace/",
    ])
