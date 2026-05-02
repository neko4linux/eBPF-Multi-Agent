# ═══════════════════════════════════════════════════════════════
#  eBPF Multi-Agent Anomaly Detection Framework — Makefile
#  ═══════════════════════════════════════════════════════════════
#
#  架构: eBPF(C内核态) + Go(Gin后端) + Vue3(TS前端)
#
#  用法:
#    make all          — 构建全部 (eBPF + backend + frontend)
#    make dev          — 开发模式 (并行启动前后端)
#    make build        — 生产构建
#    make clean        — 清理构建产物
#    make test         — 运行测试
#    make deploy       — 构建 + 打包
#
# ═══════════════════════════════════════════════════════════════

.PHONY: all build dev clean test deploy \
        ebpflib ebpf-skel ebpf-user \
        backend backend-build backend-run \
        frontend frontend-install frontend-build frontend-dev \
        demo demo-ml demo-sandbox demo-web \
        lint fmt vet help

# ─── 版本 & 配置 ───────────────────────────────────────────────

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME:= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_FLAGS  := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# ─── 目录结构 ─────────────────────────────────────────────────

ROOT_DIR  := $(shell pwd)
EBPF_DIR  := $(ROOT_DIR)/ebpf
SRC_BPF   := $(ROOT_DIR)/src/bpf
SRC_USER  := $(ROOT_DIR)/src/user
BACKEND   := $(ROOT_DIR)/backend
FRONTEND  := $(ROOT_DIR)/frontend
BUILD_DIR := $(ROOT_DIR)/build
INCLUDE   := $(ROOT_DIR)/include

# ─── 工具链 ─────────────────────────────────────────────────

CLANG     ?= clang
GCC       ?= gcc
GO        ?= go
NPM       ?= npm
BPFTOOL   ?= bpftool
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# ─── 路径检测 ─────────────────────────────────────────────────

export PATH := /usr/local/go/bin:$(PATH)
export GOPATH := $(HOME)/go
export PATH := $(GOPATH)/bin:$(PATH)

# ═══════════════════════════════════════════════════════════════
#  默认目标
# ═══════════════════════════════════════════════════════════════

all: build

# ═══════════════════════════════════════════════════════════════
#  依赖检查
# ═══════════════════════════════════════════════════════════════

check-deps:
	@echo "🔍 检查构建依赖..."
	@command -v $(CLANG)   >/dev/null 2>&1 || (echo "❌ 缺少 clang"; exit 1)
	@command -v $(BPFTOOL) >/dev/null 2>&1 || (echo "❌ 缺少 bpftool"; exit 1)
	@command -v $(GO)      >/dev/null 2>&1 || (echo "❌ 缺少 go"; exit 1)
	@command -v node       >/dev/null 2>&1 || (echo "❌ 缺少 node"; exit 1)
	@echo "✅ 所有依赖就绪"

# ═══════════════════════════════════════════════════════════════
#  eBPF 内核态程序
# ═══════════════════════════════════════════════════════════════

# 生成 vmlinux.h (BTF 类型定义)
$(INCLUDE)/vmlinux.h:
	@echo "📦 生成 vmlinux.h..."
	@mkdir -p $(INCLUDE)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | \
		grep -v "^skipping" > $@

# BPF 编译 flags
BPF_CFLAGS := -g -O2 -Wall -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(INCLUDE) -I/usr/include/bpf

# 编译 BPF 对象文件
$(BUILD_DIR)/main.bpf.o: $(SRC_BPF)/main.bpf.c $(INCLUDE)/vmlinux.h | $(BUILD_DIR)
	@echo "🔨 编译 eBPF 内核态程序..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 生成 BPF Skeleton (Go 可直接加载)
$(INCLUDE)/main.skel.h: $(BUILD_DIR)/main.bpf.o
	@echo "🦴 生成 BPF Skeleton..."
	$(BPFTOOL) gen skeleton $< > $@

# eBPF 用户态 C 程序 (legacy, 保留兼容)
BPF_USER_CFLAGS := -g -O2 -Wall -I$(INCLUDE) -I/usr/include/bpf -I$(SRC_USER)
BPF_USER_LDFLAGS := -lbpf -lelf -lz -lpthread -ldl -ljson-c

BPF_USER_SRCS := $(wildcard $(SRC_USER)/*.c)
BPF_USER_OBJS := $(patsubst $(SRC_USER)/%.c,$(BUILD_DIR)/%.o,$(BPF_USER_SRCS))

$(BUILD_DIR)/%.o: $(SRC_USER)/%.c | $(BUILD_DIR)
	$(GCC) $(BPF_USER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/agent-monitor: $(BPF_USER_OBJS) $(BUILD_DIR)/main.bpf.o
	@echo "🔨 编译 C 用户态程序..."
	$(GCC) $(BPF_USER_CFLAGS) $^ -o $@ $(BPF_USER_LDFLAGS)

ebpflib: $(INCLUDE)/vmlinux.h $(BUILD_DIR)/main.bpf.o $(INCLUDE)/main.skel.h
ebpf-user: $(BUILD_DIR)/agent-monitor

# ═══════════════════════════════════════════════════════════════
#  Go 后端 (Gin + cgo eBPF)
# ═══════════════════════════════════════════════════════════════

# Go 模块依赖
$(BACKEND)/go.sum: $(BACKEND)/go.mod
	@echo "📦 下载 Go 依赖..."
	cd $(BACKEND) && $(GO) mod tidy

# 编译 Go 后端
$(BUILD_DIR)/server: $(BACKEND)/go.sum $(wildcard $(BACKEND)/**/*.go) | $(BUILD_DIR)
	@echo "🔨 编译 Go 后端..."
	cd $(BACKEND) && CGO_ENABLED=1 $(GO) build $(GO_FLAGS) \
		-o $(BUILD_DIR)/server ./cmd/main.go

backend: $(BUILD_DIR)/server

backend-run: $(BUILD_DIR)/server
	@echo "🚀 启动 Go 后端..."
	cd $(BUILD_DIR) && PORT=8080 ./server

# ═══════════════════════════════════════════════════════════════
#  Vue 前端 (TypeScript + Vite)
# ═══════════════════════════════════════════════════════════════

# 安装前端依赖
$(FRONTEND)/node_modules: $(FRONTEND)/package.json
	@echo "📦 安装前端依赖..."
	cd $(FRONTEND) && npm install
	@touch $@

frontend-install: $(FRONTEND)/node_modules

# 开发模式
frontend-dev: $(FRONTEND)/node_modules
	@echo "🚀 启动前端开发服务器..."
	cd $(FRONTEND) && npx vite --host

# 生产构建
$(FRONTEND)/dist: $(FRONTEND)/node_modules $(wildcard $(FRONTEND)/src/**/*)
	@echo "🔨 构建前端..."
	cd $(FRONTEND) && npx vite build

frontend-build: $(FRONTEND)/dist

# ═══════════════════════════════════════════════════════════════
#  完整构建
# ═══════════════════════════════════════════════════════════════

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# 生产构建: eBPF + Go后端 + Vue前端
build: ebpflib backend frontend-build
	@echo ""
	@echo "✅ 构建完成!"
	@echo "   eBPF:    $(BUILD_DIR)/main.bpf.o"
	@echo "   后端:    $(BUILD_DIR)/server"
	@echo "   前端:    $(FRONTEND)/dist/"
	@echo ""
	@echo "启动: make run"

# 仅 eBPF
bpf: ebpflib

# 仅后端
be: backend

# 仅前端
fe: frontend-build

# ═══════════════════════════════════════════════════════════════
#  运行
# ═══════════════════════════════════════════════════════════════

# 生产模式: Go 后端服务前端静态文件
run: build
	@echo "🛡️  启动 eBPF Multi-Agent 服务..."
	@echo "   http://localhost:8080"
	cd $(BUILD_DIR) && PORT=8080 ./server

# 开发模式: 前后端并行
dev:
	@echo "🛡️  启动开发模式..."
	@echo "   前端: http://localhost:5173"
	@echo "   后端: http://localhost:8080"
	@trap 'kill 0' EXIT; \
	 cd $(BACKEND) && $(GO) run ./cmd/main.go & \
	 cd $(FRONTEND) && npx vite --host & \
	 wait

# 仅启动后端 (开发)
dev-backend:
	cd $(BACKEND) && $(GO) run ./cmd/main.go

# 仅启动前端 (开发)
dev-frontend:
	cd $(FRONTEND) && npx vite --host

# ═══════════════════════════════════════════════════════════════
#  Python Demo & 沙箱
# ═══════════════════════════════════════════════════════════════

demo-ml:
	@echo "🤖 训练 ML 分类器..."
	cd demo && uv run python ml_classifier_v2.py

demo-sandbox:
	@echo "🎮 启动交互式沙箱..."
	cd demo && uv run python sandbox_cli.py

demo-web:
	@echo "🌐 启动 Web 仪表盘 (Python)..."
	cd demo && uv run python web_dashboard.py -p 8081

demo:
	@echo "📊 运行完整 demo..."
	cd demo && uv run python main_with_ml.py

demo-simulate:
	@echo "🤖 启动 Agent 检测模拟器..."
	python3 demo/agent_simulator.py --backend http://localhost:8080

demo-agents:
	@echo "🤖 列出可用 AI Agent..."
	python3 demo/agent_runner.py --list

demo-benchmark:
	@echo "🏁 运行 Agent Benchmark..."
	python3 demo/agent_runner.py --benchmark

demo-bench:
	@echo "🏁 运行 Benchmark Suite..."
	python3 demo/benchmark_suite.py --all

demo-ollama:
	@echo "🦙 Ollama Agent 信息..."
	python3 demo/ollama_runner.py --list

demo-ollama-bench:
	@echo "🦙 Ollama Benchmark..."
	python3 demo/ollama_runner.py --benchmark

# ═══════════════════════════════════════════════════════════════
#  测试
# ═══════════════════════════════════════════════════════════════

test: test-go test-e2e

test-go:
	@echo "🧪 运行 Go 测试..."
	cd $(BACKEND) && $(GO) test ./... -v -count=1

test-e2e:
	@echo "🧪 端到端测试..."
	@bash $(ROOT_DIR)/scripts/test.sh

test-bench:
	@echo "📊 性能基准测试..."
	cd demo && uv run python benchmark.py

# ═══════════════════════════════════════════════════════════════
#  代码质量
# ═══════════════════════════════════════════════════════════════

fmt:
	@echo "📝 格式化代码..."
	cd $(BACKEND) && $(GO) fmt ./...
	cd $(FRONTEND) && npx prettier --write "src/**/*.{ts,vue}"

vet:
	@echo "🔍 静态分析..."
	cd $(BACKEND) && $(GO) vet ./...

lint: vet
	@echo "🔍 Lint 检查..."
	cd $(FRONTEND) && npx vue-tsc --noEmit 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════
#  清理
# ═══════════════════════════════════════════════════════════════

clean:
	@echo "🗑  清理构建产物..."
	rm -rf $(BUILD_DIR)
	rm -rf $(INCLUDE)/vmlinux.h $(INCLUDE)/main.skel.h
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules
	rm -rf demo/__pycache__ demo/models/*.pkl demo/figures/*.png
	rm -f demo/demo_alerts.log demo/benchmark_report.json
	@echo "✅ 清理完成"

clean-all: clean
	rm -rf $(BACKEND)/vendor
	rm -rf demo/.venv demo/data/ADFA-LD

# ═══════════════════════════════════════════════════════════════
#  部署打包
# ═══════════════════════════════════════════════════════════════

dist: build
	@echo "📦 打包发布..."
	@mkdir -p $(BUILD_DIR)/dist
	cp $(BUILD_DIR)/server $(BUILD_DIR)/dist/
	cp -r $(FRONTEND)/dist $(BUILD_DIR)/dist/static
	cp $(BUILD_DIR)/main.bpf.o $(BUILD_DIR)/dist/ 2>/dev/null || true
	cp -r demo $(BUILD_DIR)/dist/demo 2>/dev/null || true
	cd $(BUILD_DIR) && tar czf eBPF-Multi-Agent-$(VERSION)-linux-amd64.tar.gz dist/
	@echo "✅ 打包完成: $(BUILD_DIR)/eBPF-Multi-Agent-$(VERSION)-linux-amd64.tar.gz"

# Docker 构建
docker:
	@echo "🐳 Docker 构建..."
	docker build -t ebpf-multi-agent:$(VERSION) .

# ═══════════════════════════════════════════════════════════════
#  安装系统依赖
# ═══════════════════════════════════════════════════════════════

install-deps:
	@echo "📦 安装系统依赖 (需要 root)..."
	apt-get update -qq
	apt-get install -y -qq \
		clang llvm libbpf-dev libelf-dev zlib1g-dev \
		libjson-c-dev libssl-dev libcap-dev pkg-config \
		bpftool 2>/dev/null || echo "bpftool 需要手动编译"
	@echo "📦 安装 Go..."
	@if ! command -v $(GO) >/dev/null 2>&1; then \
		curl -fsSL https://go.dev/dl/go1.24.3.linux-amd64.tar.gz | tar -C /usr/local -xz; \
		echo 'export PATH=/usr/local/go/bin:$$PATH' >> ~/.bashrc; \
	fi
	@echo "📦 安装 Node.js..."
	@if ! command -v node >/dev/null 2>&1; then \
		curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; \
		apt-get install -y nodejs; \
	fi
	@echo "✅ 依赖安装完成"

# ═══════════════════════════════════════════════════════════════
#  帮助
# ═══════════════════════════════════════════════════════════════

help:
	@echo ""
	@echo "🛡️  eBPF Multi-Agent Anomaly Detection Framework"
	@echo "══════════════════════════════════════════════════"
	@echo ""
	@echo "构建目标:"
	@echo "  make all            构建全部 (eBPF + Go + Vue)"
	@echo "  make build          同 all"
	@echo "  make bpf            仅编译 eBPF 内核态程序"
	@echo "  make be             仅编译 Go 后端"
	@echo "  make fe             仅构建 Vue 前端"
	@echo ""
	@echo "运行目标:"
	@echo "  make run            生产模式运行 (构建后启动)"
	@echo "  make dev            开发模式 (前后端并行)"
	@echo "  make dev-backend    仅启动 Go 后端"
	@echo "  make dev-frontend   仅启动 Vue 前端"
	@echo ""
	@echo "Python Demo:"
	@echo "  make demo           运行完整 demo"
	@echo "  make demo-ml        训练 ML 模型"
	@echo "  make demo-sandbox   启动交互式沙箱"
	@echo "  make demo-web       启动 Python Web 仪表盘"
	@echo "  make demo-agents    列出可用 AI Agent"
	@echo "  make demo-benchmark 运行 Agent Benchmark"
	@echo "  make demo-bench     运行 Benchmark Suite"
	@echo "  make demo-ollama    Ollama Agent 信息"
	@echo "  make demo-ollama-bench  Ollama Benchmark"
	@echo ""
	@echo "测试 & 质量:"
	@echo "  make test           运行全部测试"
	@echo "  make test-go        Go 单元测试"
	@echo "  make test-bench     性能基准测试"
	@echo "  make fmt            格式化代码"
	@echo "  make vet            静态分析"
	@echo "  make lint           Lint 检查"
	@echo ""
	@echo "部署:"
	@echo "  make dist           打包发布"
	@echo "  make docker         Docker 构建"
	@echo "  make install-deps   安装系统依赖"
	@echo ""
	@echo "清理:"
	@echo "  make clean          清理构建产物"
	@echo "  make clean-all      清理全部 (含数据集)"
	@echo ""
