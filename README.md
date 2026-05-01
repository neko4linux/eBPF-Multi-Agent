# 基于 eBPF 的系统级多智能体异常监测框架

[![Go](https://img.shields.io/badge/Go-1.24-blue)](https://go.dev/)
[![Vue](https://img.shields.io/badge/Vue-3-green)](https://vuejs.org/)
[![eBPF](https://img.shields.io/badge/eBPF-kernel-orange)](https://ebpf.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 项目概述

本项目是一个基于 eBPF (Extended Berkeley Packet Filter) 技术的非侵入式监测系统，能够同时对设备中运行的多个智能体（AI Agent）进行实时观测与异常分析。

### 核心特性

- **🤖 AI Agent 识别**: 自动识别 Claude Code, Codex, Gemini CLI, Kiro CLI, Cursor, Copilot, Aider 等主流 AI 编程助手
- **🔍 非侵入式监控**: 利用 eBPF 技术在不修改内核源码及智能体应用程序的前提下进行监测
- **📡 多层级数据捕获**: 贯通应用层交互与底层系统调用
- **⚡ 实时异常检测**: 识别逻辑死循环、资源滥用、安全异常、Prompt 注入等
- **🔗 跨层数据关联**: 建立 Prompt 与底层操作的因果链路
- **📊 ML 分类**: 集成机器学习模型进行行为分类和异常评分
- **🖥️ 实时仪表盘**: Vue 3 + WebSocket 实时数据推送

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    前端 (Vue 3 + TypeScript)                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   仪表盘    │  │ Agent 集成  │  │    告警 & 规则      │  │
│  │  Dashboard   │  │ Integration │  │  Alerts & Rules     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         └────────────────┼────────────────────┘             │
│                          │ WebSocket + REST                 │
└──────────────────────────┼──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    后端 (Go + Gin)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Agent 检测  │  │ 异常规则    │  │   跨层关联器        │  │
│  │  Detector   │  │  Rules      │  │   Correlator        │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         └────────────────┼────────────────────┘             │
│                          │ cgo                              │
└──────────────────────────┼──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    内核态 (eBPF C)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Tracepoints │  │  Kprobes   │  │    Uprobes          │  │
│  │ (syscalls)  │  │ (tcp_*)    │  │  (SSL_read/write)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              BPF Maps (Ring Buffer + Hash Maps)         │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 支持的 AI Agent

| Agent | 类型 | 风险等级 | API 域名 | 检测规则数 |
|-------|------|---------|----------|-----------|
| 🟣 Claude Code | `claude-code` | MEDIUM | api.anthropic.com | 4 |
| 🟢 OpenAI Codex | `codex` | MEDIUM | api.openai.com | 3 |
| 🔵 Gemini CLI | `gemini-cli` | MEDIUM | generativelanguage.googleapis.com | 3 |
| 🟠 Kiro CLI | `kiro-cli` | HIGH | kiro.dev / bedrock | 4 |
| 🟡 Cursor | `cursor` | LOW | api.cursor.sh | 2 |
| ⚫ GitHub Copilot | `copilot` | LOW | copilot-proxy.githubusercontent.com | 2 |
| ⚪ Aider | `aider` | MEDIUM | api.openai/anthropic/deepseek | 2 |

### 检测规则类型

- **Prompt 注入检测**: `ignore previous instructions`, `you are now a` 等越狱尝试
- **数据外传检测**: curl/wget 到非白名单域名, ngrok/pastebin 等隧道服务
- **凭证泄露检测**: 访问 `.ssh/`, `.aws/credentials`, `.gcloud/` 等敏感文件
- **提权检测**: `chmod 777`, `sudo`, `chown root` 等权限修改
- **沙箱逃逸检测**: `chroot`, `unshare`, `nsenter` 等容器逃逸

## 快速开始

### 环境要求

- Linux (内核 >= 5.10, 支持 BTF)
- Go >= 1.24
- Node.js >= 18
- Clang + LLVM
- bpftool

### 安装依赖

```bash
make install-deps
```

### 构建

```bash
# 构建全部 (eBPF + Go 后端 + Vue 前端)
make build

# 仅构建后端
make be

# 仅构建前端
make fe
```

### 运行

```bash
# 生产模式 (构建后启动)
make run

# 开发模式 (前后端并行, 热重载)
make dev

# 仅启动后端
make dev-backend

# 仅启动前端
make dev-frontend
```

### Agent 检测模拟

```bash
# 模拟多个 AI Agent 的系统行为
make demo-simulate

# 或直接运行
python3 demo/agent_simulator.py --backend http://localhost:8080

# 模拟单个 Agent
python3 demo/agent_simulator.py --agent claude-code
```

## API 接口

### 核心接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/state` | 完整仪表盘状态 |
| GET | `/api/stats` | 统计数据 |
| GET | `/api/agents` | 智能体列表 |
| GET | `/api/alerts` | 告警列表 |
| GET | `/api/events` | 事件列表 |
| GET | `/api/causal-links` | 因果关联 |
| POST | `/api/spawn/:name` | 启动智能体 |
| POST | `/api/trigger/:scenario` | 触发测试场景 |
| GET | `/api/ws` | WebSocket 实时推送 |

### Agent 集成接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/agents/profiles` | 所有 Agent 配置 |
| GET | `/api/agents/detected` | 已检测到的 Agent |
| GET | `/api/agents/rules` | 异常检测规则库 |
| GET | `/api/agents/types` | 支持的 Agent 类型 |
| POST | `/api/agents/detect` | 手动触发检测 |

## 目录结构

```
eBPF-Multi-Agent/
├── Makefile                 # 统一构建配置
├── README.md                # 项目文档
├── src/
│   ├── bpf/
│   │   └── main.bpf.c       # eBPF 内核态程序
│   └── user/                 # C 用户态程序 (legacy)
├── backend/
│   ├── cmd/main.go           # Go 后端入口
│   ├── internal/
│   │   ├── agents/           # Agent 检测引擎
│   │   │   ├── registry.go   # Agent 注册表 (8种 Agent)
│   │   │   ├── detector.go   # Agent 检测器
│   │   │   ├── anomaly_rules.go  # 异常检测规则 (25+ 规则)
│   │   │   └── prompt_parser.go  # Prompt/Response 解析
│   │   ├── handler/          # HTTP/WS 处理器
│   │   ├── service/          # 业务逻辑服务
│   │   └── model/            # 数据模型
│   └── go.mod
├── frontend/
│   ├── src/
│   │   ├── views/            # 页面组件
│   │   ├── components/       # 通用组件
│   │   ├── composables/      # Vue 组合式函数
│   │   ├── stores/           # Pinia 状态管理
│   │   └── types/            # TypeScript 类型
│   └── package.json
├── demo/
│   ├── agent_simulator.py    # Agent 检测模拟器
│   ├── ml_classifier_v2.py   # ML 分类器
│   ├── sandbox_cli.py        # 交互式沙箱
│   └── ...
└── docs/
    ├── 开发指南.md
    └── 技术架构.md
```

## 技术栈

| 层级 | 技术 | 用途 |
|------|------|------|
| 内核态 | eBPF (C) | 系统调用追踪、网络流量捕获 |
| 后端 | Go + Gin | REST API、WebSocket、Agent 检测引擎 |
| 前端 | Vue 3 + TypeScript | 实时仪表盘、数据可视化 |
| ML | Python + scikit-learn | 行为分类、异常评分 |
| 构建 | Makefile + Vite | 统一构建系统 |

## 开发

```bash
# 运行测试
make test

# 格式化代码
make fmt

# 静态分析
make vet

# Lint 检查
make lint
```

## License

MIT License
