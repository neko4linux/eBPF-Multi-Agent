/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * User-space main program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <pthread.h>
#include <json-c/json.h>

#include "../../include/common.h"
#include "anomaly_detector.h"
#include "event_processor.h"
#include "alert_manager.h"
#include "agent_tracker.h"

/* Global state */
static volatile bool running = true;
static struct bpf_object *bpf_obj = NULL;
static struct ring_buffer *rb_process = NULL;
static struct ring_buffer *rb_file = NULL;
static struct ring_buffer *rb_network = NULL;
static struct ring_buffer *rb_ssl = NULL;
static struct ring_buffer *rb_anomaly = NULL;

/* Configuration */
static struct monitor_config config = {
    .enabled = 1,
    .monitor_all_processes = 1,
    .track_https = 1,
    .anomaly_detection_enabled = 1,
    .api_call_threshold_1min = 100,
    .api_call_threshold_5min = 500,
    .duplicate_prompt_threshold = 5,
    .sensitive_path_count = 0,
    .workspace_path_count = 0,
};

/* Signal handler */
static void sig_handler(int sig)
{
    running = false;
}

/* Increase RLIMIT_MEMLOCK */
static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* Format timestamp */
static void format_timestamp(__u64 timestamp_ns, char *buf, size_t len)
{
    time_t sec = timestamp_ns / 1000000000ULL;
    struct tm *tm = localtime(&sec);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm);
}

/* Process event callback */
static int process_event_cb(void *ctx, void *data, size_t len)
{
    struct process_event_data *event = data;
    char timestamp[64];
    
    format_timestamp(event->ctx.timestamp, timestamp, sizeof(timestamp));
    
    const char *event_name = "UNKNOWN";
    switch (event->event_type) {
        case EVENT_EXECVE: event_name = "EXECVE"; break;
        case EVENT_FORK: event_name = "FORK"; break;
        case EVENT_EXIT: event_name = "EXIT"; break;
    }
    
    printf("[%s] PROCESS | PID: %u | PPID: %u | TID: %u | COMM: %s | TYPE: %s | ARGS: %s\n",
           timestamp, event->ctx.pid, event->ctx.ppid, event->ctx.tid,
           event->ctx.comm, event_name, event->args);
    
    /* Track agent processes */
    agent_tracker_process_event(event);
    
    /* Check for shell spawn anomaly */
    if (event->event_type == EVENT_EXECVE) {
        if (is_shell_command(event->args)) {
            char evidence[512];
            snprintf(evidence, sizeof(evidence), "Shell command executed: %s", event->args);
            alert_manager_submit(event->ctx.pid, ANOMALY_SHELL_SPAWN, 
                                SEVERITY_HIGH, "Non-expected shell spawn detected", evidence);
        }
    }
    
    return 0;
}

/* File event callback */
static int file_event_cb(void *ctx, void *data, size_t len)
{
    struct file_event_data *event = data;
    char timestamp[64];
    
    format_timestamp(event->ctx.timestamp, timestamp, sizeof(timestamp));
    
    const char *event_name = "UNKNOWN";
    switch (event->event_type) {
        case EVENT_OPEN: event_name = "OPEN"; break;
        case EVENT_OPENAT: event_name = "OPENAT"; break;
        case EVENT_UNLINK: event_name = "UNLINK"; break;
        case EVENT_UNLINKAT: event_name = "UNLINKAT"; break;
        case EVENT_RENAME: event_name = "RENAME"; break;
    }
    
    printf("[%s] FILE | PID: %u | COMM: %s | TYPE: %s | PATH: %s | FLAGS: 0x%x\n",
           timestamp, event->ctx.pid, event->ctx.comm, event_name, 
           event->path, event->flags);
    
    /* Check for sensitive file access */
    if (is_sensitive_path(event->path)) {
        char evidence[512];
        snprintf(evidence, sizeof(evidence), "Sensitive file accessed: %s", event->path);
        alert_manager_submit(event->ctx.pid, ANOMALY_SENSITIVE_FILE_ACCESS,
                            SEVERITY_HIGH, "Sensitive file access detected", evidence);
    }
    
    /* Check for workspace violation */
    if (event->event_type == EVENT_UNLINKAT || event->event_type == EVENT_UNLINK) {
        if (is_outside_workspace(event->path)) {
            char evidence[512];
            snprintf(evidence, sizeof(evidence), "File deleted outside workspace: %s", event->path);
            alert_manager_submit(event->ctx.pid, ANOMALY_WORKSPACE_VIOLATION,
                                SEVERITY_MEDIUM, "Workspace violation detected", evidence);
        }
    }
    
    return 0;
}

/* Network event callback */
static int network_event_cb(void *ctx, void *data, size_t len)
{
    struct network_event_data *event = data;
    char timestamp[64];
    char remote_addr[64] = {0};
    
    format_timestamp(event->ctx.timestamp, timestamp, sizeof(timestamp));
    
    if (event->family == 2) { /* AF_INET */
        snprintf(remote_addr, sizeof(remote_addr), "%u.%u.%u.%u:%u",
                 (event->remote_ip >> 0) & 0xFF,
                 (event->remote_ip >> 8) & 0xFF,
                 (event->remote_ip >> 16) & 0xFF,
                 (event->remote_ip >> 24) & 0xFF,
                 event->remote_port);
    }
    
    const char *event_name = "UNKNOWN";
    switch (event->event_type) {
        case EVENT_CONNECT: event_name = "CONNECT"; break;
        case EVENT_ACCEPT: event_name = "ACCEPT"; break;
        case EVENT_BIND: event_name = "BIND"; break;
    }
    
    printf("[%s] NETWORK | PID: %u | COMM: %s | TYPE: %s | REMOTE: %s\n",
           timestamp, event->ctx.pid, event->ctx.comm, event_name, remote_addr);
    
    /* Update agent stats for API call tracking */
    agent_tracker_update_stats(event->ctx.pid, event->event_type);
    
    return 0;
}

/* SSL event callback */
static int ssl_event_cb(void *ctx, void *data, size_t len)
{
    struct ssl_event_data *event = data;
    char timestamp[64];
    
    format_timestamp(event->ctx.timestamp, timestamp, sizeof(timestamp));
    
    const char *event_name = event->event_type == EVENT_SSL_READ ? "SSL_READ" : "SSL_WRITE";
    
    /* Try to extract prompt/response from HTTPS traffic */
    char *prompt = NULL;
    char *response = NULL;
    
    if (event->data_len > 0) {
        /* Check if this looks like API traffic */
        if (is_api_traffic(event->data, event->data_len)) {
            extract_prompt_response(event->data, event->data_len, &prompt, &response);
            
            if (prompt) {
                printf("[%s] SSL | PID: %u | COMM: %s | TYPE: %s | PROMPT: %.100s...\n",
                       timestamp, event->ctx.pid, event->ctx.comm, event_name, prompt);
                
                /* Track prompt for duplicate detection */
                agent_tracker_track_prompt(event->ctx.pid, prompt);
                
                free(prompt);
            }
            if (response) {
                free(response);
            }
        }
    }
    
    return 0;
}

/* Anomaly alert callback */
static int anomaly_event_cb(void *ctx, void *data, size_t len)
{
    struct anomaly_alert *alert = data;
    char timestamp[64];
    
    format_timestamp(alert->timestamp, timestamp, sizeof(timestamp));
    
    const char *severity_str = "UNKNOWN";
    switch (alert->severity) {
        case SEVERITY_INFO: severity_str = "INFO"; break;
        case SEVERITY_LOW: severity_str = "LOW"; break;
        case SEVERITY_MEDIUM: severity_str = "MEDIUM"; break;
        case SEVERITY_HIGH: severity_str = "HIGH"; break;
        case SEVERITY_CRITICAL: severity_str = "CRITICAL"; break;
    }
    
    const char *type_str = "UNKNOWN";
    switch (alert->type) {
        case ANOMALY_LOGIC_LOOP: type_str = "LOGIC_LOOP"; break;
        case ANOMALY_RESOURCE_ABUSE: type_str = "RESOURCE_ABUSE"; break;
        case ANOMALY_SHELL_SPAWN: type_str = "SHELL_SPAWN"; break;
        case ANOMALY_SENSITIVE_FILE_ACCESS: type_str = "SENSITIVE_FILE_ACCESS"; break;
        case ANOMALY_WORKSPACE_VIOLATION: type_str = "WORKSPACE_VIOLATION"; break;
        case ANOMALY_HIGH_FREQ_API: type_str = "HIGH_FREQ_API"; break;
        case ANOMALY_SUSPICIOUS_NETWORK: type_str = "SUSPICIOUS_NETWORK"; break;
        case ANOMALY_AGENT_CONFLICT: type_str = "AGENT_CONFLICT"; break;
    }
    
    /* Output alert in JSON format for easy parsing */
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(jobj, "pid", json_object_new_int(alert->pid));
    json_object_object_add(jobj, "tid", json_object_new_int(alert->tid));
    json_object_object_add(jobj, "type", json_object_new_string(type_str));
    json_object_object_add(jobj, "severity", json_object_new_string(severity_str));
    json_object_object_add(jobj, "description", json_object_new_string(alert->description));
    json_object_object_add(jobj, "evidence", json_object_new_string(alert->evidence));
    
    if (alert->prompt_context[0] != '\0') {
        json_object_object_add(jobj, "prompt_context", json_object_new_string(alert->prompt_context));
    }
    
    printf("\n========== ANOMALY ALERT ==========\n");
    printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY));
    printf("===================================\n\n");
    
    json_object_put(jobj);
    
    /* Write to alert log file */
    alert_manager_write_log(alert);
    
    return 0;
}

/* Initialize ring buffers */
static int init_ring_buffers(struct bpf_object *obj)
{
    struct bpf_map *map;
    int err;
    
    /* Process events ring buffer */
    map = bpf_object__find_map_by_name(obj, "process_events");
    if (!map) {
        fprintf(stderr, "Failed to find process_events map\n");
        return -1;
    }
    
    rb_process = ring_buffer__new(bpf_map__fd(map), process_event_cb, NULL, NULL);
    if (!rb_process) {
        fprintf(stderr, "Failed to create process ring buffer\n");
        return -1;
    }
    
    /* File events ring buffer */
    map = bpf_object__find_map_by_name(obj, "file_events");
    if (!map) {
        fprintf(stderr, "Failed to find file_events map\n");
        return -1;
    }
    
    rb_file = ring_buffer__new(bpf_map__fd(map), file_event_cb, NULL, NULL);
    if (!rb_file) {
        fprintf(stderr, "Failed to create file ring buffer\n");
        return -1;
    }
    
    /* Network events ring buffer */
    map = bpf_object__find_map_by_name(obj, "network_events");
    if (!map) {
        fprintf(stderr, "Failed to find network_events map\n");
        return -1;
    }
    
    rb_network = ring_buffer__new(bpf_map__fd(map), network_event_cb, NULL, NULL);
    if (!rb_network) {
        fprintf(stderr, "Failed to create network ring buffer\n");
        return -1;
    }
    
    /* SSL events ring buffer */
    map = bpf_object__find_map_by_name(obj, "ssl_events");
    if (!map) {
        fprintf(stderr, "Failed to find ssl_events map\n");
        return -1;
    }
    
    rb_ssl = ring_buffer__new(bpf_map__fd(map), ssl_event_cb, NULL, NULL);
    if (!rb_ssl) {
        fprintf(stderr, "Failed to create SSL ring buffer\n");
        return -1;
    }
    
    /* Anomaly alerts ring buffer */
    map = bpf_object__find_map_by_name(obj, "anomaly_alerts");
    if (!map) {
        fprintf(stderr, "Failed to find anomaly_alerts map\n");
        return -1;
    }
    
    rb_anomaly = ring_buffer__new(bpf_map__fd(map), anomaly_event_cb, NULL, NULL);
    if (!rb_anomaly) {
        fprintf(stderr, "Failed to create anomaly ring buffer\n");
        return -1;
    }
    
    return 0;
}

/* Attach uprobes for SSL interception */
static int attach_ssl_uprobes(struct bpf_object *obj)
{
    struct bpf_program *prog;
    struct bpf_link *link;
    char libssl_path[256];
    
    /* Find libssl.so */
    FILE *fp = popen("find /usr -name 'libssl.so*' 2>/dev/null | head -1", "r");
    if (!fp) {
        fprintf(stderr, "Failed to find libssl.so\n");
        return -1;
    }
    
    if (fgets(libssl_path, sizeof(libssl_path), fp) == NULL) {
        pclose(fp);
        fprintf(stderr, "libssl.so not found\n");
        return -1;
    }
    pclose(fp);
    
    /* Remove trailing newline */
    libssl_path[strcspn(libssl_path, "\n")] = 0;
    
    printf("Found libssl at: %s\n", libssl_path);
    
    /* Attach SSL_read uprobe */
    prog = bpf_object__find_program_by_name(obj, "uprobe_ssl_read");
    if (prog) {
        link = bpf_program__attach_uprobe(prog, false, -1, libssl_path, 
                                          get_ssl_read_offset());
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach SSL_read uprobe\n");
        } else {
            printf("Attached SSL_read uprobe\n");
        }
    }
    
    /* Attach SSL_write uprobe */
    prog = bpf_object__find_program_by_name(obj, "uprobe_ssl_write");
    if (prog) {
        link = bpf_program__attach_uprobe(prog, false, -1, libssl_path,
                                          get_ssl_write_offset());
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach SSL_write uprobe\n");
        } else {
            printf("Attached SSL_write uprobe\n");
        }
    }
    
    return 0;
}

/* Main event loop */
static void event_loop(void)
{
    int err;
    
    printf("\n=== eBPF Multi-Agent Anomaly Monitor Started ===\n");
    printf("Monitoring system calls and network activity...\n\n");
    
    while (running) {
        err = ring_buffer__poll(rb_process, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling process ring buffer: %s\n", strerror(-err));
        }
        
        err = ring_buffer__poll(rb_file, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling file ring buffer: %s\n", strerror(-err));
        }
        
        err = ring_buffer__poll(rb_network, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling network ring buffer: %s\n", strerror(-err));
        }
        
        err = ring_buffer__poll(rb_ssl, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling SSL ring buffer: %s\n", strerror(-err));
        }
        
        err = ring_buffer__poll(rb_anomaly, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling anomaly ring buffer: %s\n", strerror(-err));
        }
        
        /* Run periodic anomaly detection */
        anomaly_detector_run_periodic();
    }
}

/* Cleanup */
static void cleanup(void)
{
    printf("\nCleaning up...\n");
    
    if (rb_process) ring_buffer__free(rb_process);
    if (rb_file) ring_buffer__free(rb_file);
    if (rb_network) ring_buffer__free(rb_network);
    if (rb_ssl) ring_buffer__free(rb_ssl);
    if (rb_anomaly) ring_buffer__free(rb_anomaly);
    
    if (bpf_obj) bpf_object__close(bpf_obj);
    
    alert_manager_cleanup();
    agent_tracker_cleanup();
}

int main(int argc, char **argv)
{
    int err;
    char *bpf_file = "src/bpf/main.bpf.o";
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -f <file>   BPF object file (default: %s)\n", bpf_file);
            printf("  -h          Show this help\n");
            return 0;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            bpf_file = argv[++i];
        }
    }
    
    /* Setup signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Increase memlock rlimit */
    if (bump_memlock_rlimit()) {
        return 1;
    }
    
    /* Initialize subsystems */
    if (alert_manager_init("alerts.log") < 0) {
        fprintf(stderr, "Failed to initialize alert manager\n");
        return 1;
    }
    
    if (agent_tracker_init() < 0) {
        fprintf(stderr, "Failed to initialize agent tracker\n");
        return 1;
    }
    
    if (anomaly_detector_init(&config) < 0) {
        fprintf(stderr, "Failed to initialize anomaly detector\n");
        return 1;
    }
    
    /* Load BPF program */
    printf("Loading BPF program from %s...\n", bpf_file);
    
    bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        cleanup();
        return 1;
    }
    
    err = bpf_object__load(bpf_obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        cleanup();
        return 1;
    }
    
    printf("BPF program loaded successfully\n");
    
    /* Initialize ring buffers */
    if (init_ring_buffers(bpf_obj)) {
        cleanup();
        return 1;
    }
    
    /* Attach tracepoints and kprobes */
    err = bpf_object__attach_skeleton(NULL);  /* Will use auto-attach */
    if (err) {
        /* Manual attach */
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, bpf_obj) {
            struct bpf_link *link = bpf_program__attach(prog);
            if (libbpf_get_error(link)) {
                fprintf(stderr, "Failed to attach program: %s\n", 
                        bpf_program__name(prog));
            } else {
                printf("Attached: %s\n", bpf_program__name(prog));
            }
        }
    }
    
    /* Attach SSL uprobes */
    if (config.track_https) {
        attach_ssl_uprobes(bpf_obj);
    }
    
    /* Run main event loop */
    event_loop();
    
    cleanup();
    return 0;
}