# eBPF Multi-Agent Anomaly Detection Framework
# Makefile for building the project

.PHONY: all clean install test bpf user

# Compiler settings
CLANG ?= clang
LLC ?= llc
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build
BPF_DIR := $(SRC_DIR)/bpf
USER_DIR := $(SRC_DIR)/user

# Include paths
INCLUDES := -I$(INCLUDE_DIR) -I/usr/include/bpf -I$(SRC_DIR)/user

# BPF flags
BPF_CFLAGS := -g -O2 -Wall -target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	$(INCLUDES)

# User-space flags
CFLAGS := -g -O2 -Wall $(INCLUDES)
LDFLAGS := -lbpf -lelf -lz -lpthread -ldl -ljson-c

# Source files
BPF_SOURCES := $(wildcard $(BPF_DIR)/*.bpf.c)
USER_SOURCES := $(filter-out $(USER_DIR)/main.c, $(wildcard $(USER_DIR)/*.c))
MAIN_SOURCE := $(USER_DIR)/main.c

# Object files
BPF_OBJECTS := $(patsubst $(BPF_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SOURCES))
USER_OBJECTS := $(patsubst $(USER_DIR)/%.c,$(BUILD_DIR)/%.o,$(USER_SOURCES))
MAIN_OBJECT := $(BUILD_DIR)/main.o

# Main target
TARGET := $(BUILD_DIR)/agent-monitor

all: $(BUILD_DIR) bpf user

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h for BTF
$(INCLUDE_DIR)/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build BPF objects
bpf: $(BUILD_DIR) $(INCLUDE_DIR)/vmlinux.h $(BPF_OBJECTS)

$(BUILD_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BUILD_DIR) $(INCLUDE_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Build user-space objects
user: $(BUILD_DIR) $(USER_OBJECTS) $(MAIN_OBJECT) $(BPF_OBJECTS)
	$(CC) $(CFLAGS) $(MAIN_OBJECT) $(USER_OBJECTS) -o $(TARGET) $(LDFLAGS)

$(BUILD_DIR)/%.o: $(USER_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/main.o: $(USER_DIR)/main.c | $(BUILD_DIR) $(USER_OBJECTS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(INCLUDE_DIR)/vmlinux.h

install: all
	install -m 755 $(TARGET) /usr/local/bin/

test: all
	./scripts/test.sh

# Development helpers
debug:
	$(CLANG) $(BPF_CFLAGS) -S -emit-llvm $(BPF_DIR)/main.bpf.c -o $(BUILD_DIR)/main.ll

skel: $(BUILD_DIR)/main.bpf.o
	bpftool gen skeleton $< > $(INCLUDE_DIR)/main.skel.h

# Show help
help:
	@echo "Available targets:"
	@echo "  all     - Build everything (default)"
	@echo "  bpf     - Build BPF programs only"
	@echo "  user    - Build user-space program"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install to /usr/local/bin"
	@echo "  test    - Run tests"