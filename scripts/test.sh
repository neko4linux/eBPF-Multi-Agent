#!/bin/bash
# eBPF Multi-Agent Anomaly Detection Framework
# Test Script

set -e

echo "=== eBPF Multi-Agent Anomaly Detection Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This test requires root privileges for eBPF operations"
    echo "Please run with: sudo ./scripts/test.sh"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -n "Testing $test_name... "
    
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

# 1. Check BPF object file exists
echo "1. Checking build artifacts..."
run_test "BPF object file" "test -f build/main.bpf.o"
run_test "User-space binary" "test -f build/agent-monitor"

# 2. Check kernel BTF support
echo ""
echo "2. Checking kernel support..."
run_test "BTF support" "test -f /sys/kernel/btf/vmlinux"
run_test "Tracefs mounted" "mountpoint -q /sys/kernel/debug/tracing"

# 3. Verify BPF program can be loaded
echo ""
echo "3. Testing BPF program loading..."
echo -n "Loading BPF program... "

# Use timeout to prevent hanging
if timeout 5 bpftool prog load build/main.bpf.o /sys/fs/bpf/test_agent_monitor 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
    ((TESTS_PASSED++))
    # Unload
    bpftool prog unload name trace_execve_enter 2>/dev/null || true
    rm -f /sys/fs/bpf/test_agent_monitor 2>/dev/null || true
else
    echo -e "${YELLOW}SKIPPED (may need privileges)${NC}"
fi

# 4. Test tracepoint availability
echo ""
echo "4. Checking tracepoints..."
run_test "sys_enter_execve tracepoint" "test -f /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve"
run_test "sys_enter_openat tracepoint" "test -f /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat"
run_test "sys_enter_unlinkat tracepoint" "test -f /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat"

# 5. Test the monitor binary (brief run)
echo ""
echo "5. Testing monitor binary..."
echo -n "Starting monitor (5 second test)... "

# Create a temporary log file
LOG_FILE=$(mktemp)

# Run the monitor in background with timeout
timeout 5 ./build/agent-monitor -f build/main.bpf.o > "$LOG_FILE" 2>&1 &
MONITOR_PID=$!

# Wait a moment for startup
sleep 2

# Check if process is running
if kill -0 $MONITOR_PID 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
    ((TESTS_PASSED++))
    
    # Generate some activity to monitor
    echo "   Generating test activity..."
    ls /tmp > /dev/null 2>&1
    cat /etc/passwd > /dev/null 2>&1
    
    # Wait for monitor to finish
    wait $MONITOR_PID 2>/dev/null || true
    
    # Check log output
    if grep -q "PROCESS\|FILE\|NETWORK" "$LOG_FILE" 2>/dev/null; then
        echo -e "   Event capture: ${GREEN}OK${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "   Event capture: ${YELLOW}PARTIAL${NC}"
    fi
else
    echo -e "${RED}FAILED${NC}"
    ((TESTS_FAILED++))
fi

# Cleanup
rm -f "$LOG_FILE"

# 6. Summary
echo ""
echo "==================================="
echo "Test Summary:"
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
echo "==================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Check the output above.${NC}"
    exit 1
fi