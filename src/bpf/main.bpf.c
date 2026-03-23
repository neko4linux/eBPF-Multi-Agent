/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Main BPF program for system call monitoring
 * 
 * This is a non-intrusive monitoring tool that uses eBPF to observe
 * system behavior without modifying the kernel or target applications.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Maximum sizes */
#define MAX_COMM_LEN 64
#define MAX_ARGS_LEN 256
#define MAX_PATH_LEN 256
#define MAX_DATA_LEN 4096
#define MAX_AGENT_NAME_LEN 64

/* Event types */
#define EVENT_EXECVE    1
#define EVENT_FORK      2
#define EVENT_EXIT      3
#define EVENT_OPEN      4
#define EVENT_OPENAT    5
#define EVENT_UNLINK    6
#define EVENT_UNLINKAT  7
#define EVENT_RENAME    8
#define EVENT_CONNECT   9
#define EVENT_ACCEPT    10
#define EVENT_BIND      11
#define EVENT_SSL_READ  12
#define EVENT_SSL_WRITE 13

/* Anomaly types */
#define ANOMALY_LOGIC_LOOP            1
#define ANOMALY_RESOURCE_ABUSE        2
#define ANOMALY_SHELL_SPAWN           3
#define ANOMALY_SENSITIVE_FILE_ACCESS 4
#define ANOMALY_WORKSPACE_VIOLATION   5
#define ANOMALY_HIGH_FREQ_API         6

/* Severity levels */
#define SEVERITY_INFO     0
#define SEVERITY_LOW      1
#define SEVERITY_MEDIUM   2
#define SEVERITY_HIGH     3
#define SEVERITY_CRITICAL 4

/* Process context */
struct process_context {
    __u32 pid;
    __u32 ppid;
    __u32 tid;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
    __u32 uid;
    __u32 gid;
};

/* File operation data */
struct file_event_data {
    struct process_context ctx;
    __u32 event_type;
    char path[MAX_PATH_LEN];
    __u32 flags;
    __u32 mode;
    __s32 ret_val;
};

/* Network operation data */
struct network_event_data {
    struct process_context ctx;
    __u32 event_type;
    __u32 family;
    __u16 local_port;
    __u16 remote_port;
    __u32 local_ip;
    __u32 remote_ip;
    __s32 ret_val;
};

/* Process operation data */
struct process_event_data {
    struct process_context ctx;
    __u32 event_type;
    __u32 target_pid;
    char args[MAX_ARGS_LEN];
    __s32 ret_val;
};

/* SSL/TLS interception data */
struct ssl_event_data {
    struct process_context ctx;
    __u32 event_type;
    __u64 fd;
    __u32 data_len;
    char data[MAX_DATA_LEN];
};

/* Agent info */
struct agent_info {
    __u32 pid;
    char name[MAX_AGENT_NAME_LEN];
    __u64 start_time;
    __u64 last_activity;
};

/* Agent stats */
struct agent_stats {
    __u64 start_time;
    __u64 last_update;
    __u64 api_call_count;
    __u64 file_read_count;
    __u64 file_delete_count;
    __u64 fork_count;
    __u64 exec_count;
};

/* Anomaly alert */
struct anomaly_alert {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 type;
    __u32 severity;
    char description[256];
    char evidence[512];
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Ring buffers for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ssl_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} anomaly_alerts SEC(".maps");

/* Hash maps for tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct agent_info);
} agent_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct agent_stats);
} stats_map SEC(".maps");

/* Per-CPU array for temporary data */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_context);
} temp_ctx SEC(".maps");

/* Helper function to get process context */
static __always_inline struct process_context *get_process_context(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 key = 0;
    struct process_context *ctx = bpf_map_lookup_elem(&temp_ctx, &key);
    if (!ctx)
        return NULL;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ctx->pid = pid_tgid >> 32;
    ctx->tid = (__u32)pid_tgid;
    ctx->timestamp = bpf_ktime_get_ns();
    
    /* Get parent PID */
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    ctx->ppid = BPF_CORE_READ(parent, tgid);
    
    /* Get command name */
    bpf_get_current_comm(&ctx->comm, sizeof(ctx->comm));
    
    /* Get UID/GID */
    ctx->uid = bpf_get_current_uid_gid();
    ctx->gid = bpf_get_current_uid_gid() >> 32;
    
    return ctx;
}

/* ============ Process Monitoring ============ */

/* Trace execve syscall entry */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(void *ctx)
{
    struct trace_event_raw_sys_enter *sys_ctx = ctx;
    struct process_event_data *event;
    struct process_context *proc_ctx;
    
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_EXECVE;
    event->target_pid = 0;
    
    /* Read filename argument */
    const char *filename = (const char *)BPF_CORE_READ(sys_ctx, args[0]);
    bpf_probe_read_user_str(event->args, sizeof(event->args), filename);
    
    event->ret_val = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace clone syscall exit */
SEC("tracepoint/syscalls/sys_exit_clone")
int trace_clone_exit(void *ctx)
{
    struct trace_event_raw_sys_exit *sys_ctx = ctx;
    struct process_event_data *event;
    struct process_context *proc_ctx;
    __s32 ret = BPF_CORE_READ(sys_ctx, ret);
    
    if (ret <= 0)
        return 0;
    
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_FORK;
    event->target_pid = ret;
    event->args[0] = '\0';
    event->ret_val = ret;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============ File System Monitoring ============ */

/* Trace openat syscall */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(void *ctx)
{
    struct trace_event_raw_sys_enter *sys_ctx = ctx;
    struct file_event_data *event;
    struct process_context *proc_ctx;
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_OPENAT;
    
    /* Read path argument */
    const char *path = (const char *)BPF_CORE_READ(sys_ctx, args[1]);
    bpf_probe_read_user_str(event->path, sizeof(event->path), path);
    
    /* Read flags and mode */
    event->flags = (__u32)BPF_CORE_READ(sys_ctx, args[2]);
    event->mode = (__u32)BPF_CORE_READ(sys_ctx, args[3]);
    event->ret_val = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace unlinkat syscall */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat_enter(void *ctx)
{
    struct trace_event_raw_sys_enter *sys_ctx = ctx;
    struct file_event_data *event;
    struct process_context *proc_ctx;
    
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_UNLINKAT;
    
    /* Read path argument */
    const char *path = (const char *)BPF_CORE_READ(sys_ctx, args[1]);
    bpf_probe_read_user_str(event->path, sizeof(event->path), path);
    
    event->flags = (__u32)BPF_CORE_READ(sys_ctx, args[2]);
    event->mode = 0;
    event->ret_val = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============ Network Monitoring ============ */

/* Trace connect syscall exit */
SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(void *ctx)
{
    struct trace_event_raw_sys_exit *sys_ctx = ctx;
    struct network_event_data *event;
    struct process_context *proc_ctx;
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_CONNECT;
    event->ret_val = BPF_CORE_READ(sys_ctx, ret);
    event->family = 0;
    event->remote_port = 0;
    event->remote_ip = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace accept4 syscall exit */
SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept4_exit(void *ctx)
{
    struct trace_event_raw_sys_exit *sys_ctx = ctx;
    struct network_event_data *event;
    struct process_context *proc_ctx;
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_ACCEPT;
    event->ret_val = BPF_CORE_READ(sys_ctx, ret);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============ SSL/TLS Interception (uprobe) ============ */

/* Uprobe for SSL_read - uses pt_regs for argument access */
SEC("uprobe")
int uprobe_ssl_read(struct pt_regs *ctx)
{
    struct ssl_event_data *event;
    struct process_context *proc_ctx;
    void *buf;
    int num;
    
    /* Get arguments from registers (x86_64 calling convention) */
    buf = (void *)PT_REGS_PARM2(ctx);
    num = (int)PT_REGS_PARM3(ctx);
    
    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_SSL_READ;
    event->fd = PT_REGS_PARM1(ctx);
    
    /* Read the decrypted data */
    if (num > 0 && num < MAX_DATA_LEN) {
        bpf_probe_read_user(event->data, num, buf);
        event->data_len = num;
    } else {
        event->data_len = 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Uprobe for SSL_write */
SEC("uprobe")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    struct ssl_event_data *event;
    struct process_context *proc_ctx;
    const void *buf;
    int num;
    
    /* Get arguments from registers */
    buf = (const void *)PT_REGS_PARM2(ctx);
    num = (int)PT_REGS_PARM3(ctx);
    
    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_SSL_WRITE;
    event->fd = PT_REGS_PARM1(ctx);
    
    /* Read the data to be encrypted and sent */
    if (num > 0 && num < MAX_DATA_LEN) {
        bpf_probe_read_user(event->data, num, buf);
        event->data_len = num;
    } else {
        event->data_len = 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============ TCP Connect kprobe for detailed network info ============ */

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
    struct network_event_data *event;
    struct process_context *proc_ctx;
    __u16 family;
    
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    proc_ctx = get_process_context();
    if (!proc_ctx) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    __builtin_memcpy(&event->ctx, proc_ctx, sizeof(*proc_ctx));
    event->event_type = EVENT_CONNECT;
    
    /* Extract IP and port from socket */
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->family = family;
    
    if (family == 2) { /* AF_INET */
        /* Use skc_daddr and skc_dport for remote address */
        event->remote_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        event->local_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    }
    
    event->ret_val = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}