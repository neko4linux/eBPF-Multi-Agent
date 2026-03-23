/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Common header file for kernel-user communication
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef __VMLINUX_H__
/* For user-space, include standard headers */
#include <stdint.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#endif

/* Maximum sizes */
#define MAX_COMM_LEN 64
#define MAX_ARGS_LEN 256
#define MAX_PATH_LEN 256
#define MAX_DATA_LEN 4096
#define MAX_PROMPT_LEN 4096
#define MAX_AGENT_NAME_LEN 64

/* Event types */
enum event_type {
    /* Process events */
    EVENT_EXECVE = 1,
    EVENT_FORK,
    EVENT_EXIT,
    
    /* File events */
    EVENT_OPEN,
    EVENT_OPENAT,
    EVENT_UNLINK,
    EVENT_UNLINKAT,
    EVENT_RENAME,
    EVENT_CHMOD,
    EVENT_CHOWN,
    
    /* Network events */
    EVENT_CONNECT,
    EVENT_ACCEPT,
    EVENT_BIND,
    EVENT_SENDMSG,
    EVENT_RECVMSG,
    
    /* HTTPS interception events */
    EVENT_SSL_READ,
    EVENT_SSL_WRITE,
    
    /* Anomaly events */
    EVENT_ANOMALY_DETECTED = 100,
};

/* Anomaly types */
enum anomaly_type {
    ANOMALY_LOGIC_LOOP = 1,         /* 逻辑死循环 */
    ANOMALY_RESOURCE_ABUSE,         /* 资源滥用 */
    ANOMALY_SHELL_SPAWN,            /* 非预期Shell启动 */
    ANOMALY_SENSITIVE_FILE_ACCESS,  /* 敏感文件越权访问 */
    ANOMALY_WORKSPACE_VIOLATION,    /* 工作区外文件操作 */
    ANOMALY_HIGH_FREQ_API,          /* 高频API调用 */
    ANOMALY_SUSPICIOUS_NETWORK,     /* 可疑网络连接 */
    ANOMALY_AGENT_CONFLICT,         /* 多智能体冲突 */
};

/* Severity levels */
enum severity_level {
    SEVERITY_INFO = 0,
    SEVERITY_LOW = 1,
    SEVERITY_MEDIUM = 2,
    SEVERITY_HIGH = 3,
    SEVERITY_CRITICAL = 4,
};

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
    __u8 local_ip6[16];
    __u8 remote_ip6[16];
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

/* Agent identification */
struct agent_info {
    __u32 pid;
    char name[MAX_AGENT_NAME_LEN];
    __u64 start_time;
    __u64 last_activity;
    __u32 prompt_count;
    __u32 api_call_count;
};

/* Anomaly alert */
struct anomaly_alert {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    enum anomaly_type type;
    enum severity_level severity;
    char description[256];
    char evidence[512];
    char prompt_context[MAX_PROMPT_LEN];  /* Associated prompt if available */
};

/* Statistics for anomaly detection */
struct agent_stats {
    __u64 start_time;
    __u64 last_update;
    
    /* API call statistics */
    __u64 api_call_count;
    __u64 api_call_count_1min;      /* Last 1 minute */
    __u64 api_call_count_5min;      /* Last 5 minutes */
    
    /* File operation statistics */
    __u64 file_read_count;
    __u64 file_write_count;
    __u64 file_delete_count;
    
    /* Process statistics */
    __u64 fork_count;
    __u64 exec_count;
    __u64 shell_spawn_count;
    
    /* Network statistics */
    __u64 connect_count;
    __u64 bytes_sent;
    __u64 bytes_recv;
    
    /* Prompt tracking */
    __u64 prompt_count;
    __u64 duplicate_prompt_count;
    char last_prompts[10][MAX_PROMPT_LEN];
    __u32 last_prompt_idx;
};

/* Map definitions for BPF */
#define MAP_PROCESS_EVENTS    1
#define MAP_FILE_EVENTS       2
#define MAP_NETWORK_EVENTS    3
#define MAP_SSL_EVENTS        4
#define MAP_AGENT_STATS       5
#define MAP_ANOMALY_ALERTS    6
#define MAP_CONFIG            7

/* Configuration */
struct monitor_config {
    __u32 enabled;
    __u32 monitor_all_processes;
    __u32 track_https;
    __u32 anomaly_detection_enabled;
    
    /* Thresholds */
    __u32 api_call_threshold_1min;      /* API calls per minute threshold */
    __u32 api_call_threshold_5min;      /* API calls per 5 minutes threshold */
    __u32 duplicate_prompt_threshold;   /* Duplicate prompt threshold */
    
    /* Sensitive paths */
    char sensitive_paths[16][MAX_PATH_LEN];
    __u32 sensitive_path_count;
    
    /* Allowed workspace paths */
    char workspace_paths[16][MAX_PATH_LEN];
    __u32 workspace_path_count;
};

#endif /* __COMMON_H__ */