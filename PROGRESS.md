# 基于 eBPF 的系统级多智能体异常监测框架 - 项目进度记录

## 项目概述

**赛题名称**: 基于 eBPF 的系统级多智能体异常监测框架与方法  
**赛题类型**: 工程型 (难度A级)  
**开始时间**: 2026-03-23  
**完成时间**: 2026-03-23

### 核心目标
构建基于eBPF的非侵入式监测系统，对多个AI Agent进行实时观测与异常分析。

---

## 环境信息

### 系统环境
- 操作系统: Ubuntu 22.04.5 LTS (WSL2)
- 内核版本: 6.6.87.2-microsoft-standard-WSL2
- 架构: x86_64

### 开发工具
- clang: 14.0.0
- bpftool: v7.7.0
- libbpf: v1.7

---

## 完成进度

### [2026-03-23] 项目完成

#### 已完成功能

**1. 多层级数据捕获 (基础+进阶)**
- [x] 进程监控: execve, fork/clone 系统调用追踪
- [x] 文件监控: openat, unlinkat 等文件操作追踪
- [x] 网络监控: connect, accept 网络连接追踪
- [x] TCP连接详情: 通过 kprobe/tcp_connect 获取 IP/端口
- [x] HTTPS解密: uprobe hook SSL_read/SSL_write

**2. 异常检测 (基础+进阶)**
- [x] 逻辑死循环检测: 高频API调用 + 重复Prompt
- [x] 资源滥用检测: 过多文件操作/进程创建
- [x] Shell启动检测: 非预期命令行解释程序
- [x] 敏感文件访问检测: 越权访问系统敏感文件
- [x] 工作区违规检测: 工作区外文件删除

**3. 告警输出与归因定位**
- [x] JSON格式告警日志
- [x] 时间戳、PID/TID、操作对象等上下文
- [x] Prompt上下文关联

---

## 项目结构

```
eBPF-Multi-Agent/
├── Makefile                 # 构建配置
├── README.md                # 项目文档
├── PROGRESS.md              # 开发进度记录
├── include/
│   ├── common.h             # 公共数据结构定义
│   └── vmlinux.h            # 内核BTF类型定义
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

---

## 技术实现要点

### eBPF 程序 (main.bpf.c)

1. **Tracepoints**: 
   - sys_enter_execve: 进程执行监控
   - sys_exit_clone: 进程创建监控
   - sys_enter_openat: 文件打开监控
   - sys_enter_unlinkat: 文件删除监控
   - sys_exit_connect: 网络连接监控

2. **Kprobes**:
   - tcp_connect: 获取TCP连接详细信息

3. **Uprobes**:
   - SSL_read: 截获HTTPS响应明文
   - SSL_write: 截获HTTPS请求明文

4. **Maps**:
   - Ring Buffers: 高效事件传输
   - Hash Maps: 智能体状态追踪
   - Per-CPU Arrays: 临时数据存储

### 用户态程序

1. **事件处理**: 从 Ring Buffer 读取并处理事件
2. **异常检测**: 基于规则和统计的异常检测
3. **告警管理**: JSON格式告警输出和日志记录
4. **智能体追踪**: 跟踪多智能体状态和统计

---

## 构建与运行

```bash
# 编译
make all

# 运行 (需要root权限)
sudo ./build/agent-monitor -f build/main.bpf.o

# 测试
sudo ./scripts/test.sh
```

---

## 参考资料
- [Pixie](https://px.dev/) - Kubernetes可观测性工具
- [Cilium](https://cilium.io/) - 基于eBPF的网络/安全方案
- BPF Performance Tools (Brendan Greg)
- Learning eBPF (Liz Rice)