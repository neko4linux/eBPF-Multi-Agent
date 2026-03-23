# 基于 eBPF 的系统级多智能体异常监测框架

## 项目概述

本项目是一个基于 eBPF (Extended Berkeley Packet Filter) 技术的非侵入式监测系统，能够同时对设备中运行的多个智能体（AI Agent）进行实时观测与异常分析。

### 核心特性

- **非侵入式监控**: 利用 eBPF 技术在不修改内核源码及智能体应用程序的前提下进行监测
- **多层级数据捕获**: 贯通应用层交互与底层系统调用
- **实时异常检测**: 识别逻辑死循环、资源滥用、安全异常等
- **跨层数据关联**: 建立 Prompt 与底层操作的因果链路

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    用户态 (User Space)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ 主控制程序   │  │ 异常检测器  │  │    告警管理器       │  │
│  │ (main.c)    │  │ (detector)  │  │ (alert_manager)     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │            │
│  ┌──────┴────────────────┴─────────────────────┴──────────┐  │
│  │              Ring Buffer 事件处理                       │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    内核态 (Kernel Space)                     │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              eBPF 程序 (main.bpf.c)                      │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │ │
│  │  │ Tracepoints │  │  Kprobes   │  │    Uprobes      │  │ │
│  │  │ (syscalls)  │  │ (tcp_*)    │  │  (SSL_read/write)│  │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              BPF Maps (数据交换)                         │ │
│  │  Ring Buffers | Hash Maps | Per-CPU Arrays              │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 目录结构

```
eBPF-Multi-Agent/
├── Makefile                 # 构建配置
├── README.md                # 项目文档
├── PROGRESS.md              # 开发进度记录
├── include/
│   ├── common.h             # 公共数据结构定义
│   └── vmlinux.h            # 内核BTF类型定义（自动生成）
├── src/
│   ├── bpf/
│   │   └── main.bpf.c       # eBPF内核态程序
│   └── user/
│       ├── main.c           # 用户态主程序
│       ├── anomaly_detector.c/h   # 异常检测模块
│       ├── alert_manager.c/h      # 告警管理模块
│       ├── agent_tracker.c/h      # 智能体追踪模块
│       └── event_processor.c/h    # 事件处理模块
├── scripts/
│   └── test.sh              # 测试脚本
└── tests/                   # 测试用例
```

## 构建与运行

### 环境要求

- Linux Kernel >= 5.15
- clang >= 14
- libbpf-dev
- bpftool
- libelf-dev
- libjson-c-dev

### 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev \
    llvm clang build-essential pkg-config libjson-c-dev

# 编译安装 bpftool (如果系统包不可用)
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src && make && sudo make install
```

### 编译

```bash
# 完整编译
make all

# 仅编译 BPF 程序
make bpf

# 仅编译用户态程序
make user

# 清理
make clean
```

### 运行

```bash
# 需要 root 权限运行
sudo ./build/agent-monitor -f build/main.bpf.o

# 查看帮助
./build/agent-monitor --help
```

## 功能说明

### 1. 多层级数据捕获

#### 基础功能
- **进程监控**: execve, fork, clone 等系统调用
- **文件监控**: openat, unlinkat 等文件操作
- **网络监控**: connect, accept 等网络连接

#### 进阶功能
- **HTTPS 解密**: 通过 uprobe hook SSL_read/SSL_write 获取明文数据
- **Prompt 提取**: 从加密流量中提取 AI Agent 的 Prompt/Response

### 2. 异常检测

| 异常类型 | 描述 | 检测方法 |
|---------|------|---------|
| 逻辑死循环 | 高频 API 调用 + 重复 Prompt | 统计分析 |
| 资源滥用 | 过多文件操作/进程创建 | 阈值检测 |
| Shell 启动 | 非预期的命令行解释程序 | 进程监控 |
| 敏感文件访问 | 越权访问系统敏感文件 | 路径匹配 |
| 工作区违规 | 工作区外文件删除操作 | 路径检查 |

### 3. 告警输出

告警以 JSON 格式输出，包含：
- 时间戳
- 进程 PID/TID
- 异常类型与严重级别
- 描述与证据
- 关联的 Prompt 上下文（如有）

```json
{
  "timestamp": "2026-03-23 12:00:00",
  "pid": 12345,
  "type": "SHELL_SPAWN",
  "severity": "HIGH",
  "description": "Non-expected shell spawn detected",
  "evidence": "Shell command executed: /bin/bash"
}
```

## 性能考虑

- **轻量级设计**: 使用 Ring Buffer 高效传输事件
- **低开销**: 目标性能损耗 <= 5%
- **非阻塞**: 异步事件处理，不影响被监控进程

## 参考资料

1. Brendan Greg. BPF Performance Tools
2. Liz Rice. Learning eBPF
3. [Pixie](https://px.dev/) - Kubernetes 可观测性工具
4. [Cilium](https://cilium.io/) - 基于 eBPF 的网络/安全方案

## 许可证

Dual BSD/GPL

## 作者

2026年全国大学生计算机系统能力大赛参赛作品