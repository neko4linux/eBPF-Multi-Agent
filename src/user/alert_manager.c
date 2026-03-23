/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Alert Manager Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "alert_manager.h"

/* Alert log file */
static FILE *g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Initialize alert manager */
int alert_manager_init(const char *log_file)
{
    g_log_file = fopen(log_file, "a");
    if (!g_log_file) {
        perror("Failed to open alert log file");
        return -1;
    }
    
    /* Write header */
    fprintf(g_log_file, "# eBPF Multi-Agent Anomaly Alert Log\n");
    fprintf(g_log_file, "# Started: %s", ctime(&(time_t){time(NULL)}));
    fflush(g_log_file);
    
    printf("Alert manager initialized, log file: %s\n", log_file);
    return 0;
}

/* Submit an anomaly alert */
int alert_manager_submit(__u32 pid, enum anomaly_type type, 
                         enum severity_level severity,
                         const char *description, const char *evidence)
{
    struct anomaly_alert alert;
    
    memset(&alert, 0, sizeof(alert));
    alert.timestamp = time(NULL) * 1000000000ULL;
    alert.pid = pid;
    alert.tid = 0;
    alert.type = type;
    alert.severity = severity;
    
    strncpy(alert.description, description, sizeof(alert.description) - 1);
    strncpy(alert.evidence, evidence, sizeof(alert.evidence) - 1);
    
    return alert_manager_write_log(&alert);
}

/* Write alert to log file */
int alert_manager_write_log(struct anomaly_alert *alert)
{
    if (!g_log_file || !alert)
        return -1;
    
    pthread_mutex_lock(&g_log_mutex);
    
    char timestamp[64];
    time_t sec = alert->timestamp / 1000000000ULL;
    struct tm *tm = localtime(&sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
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
    
    fprintf(g_log_file, 
            "{\"timestamp\":\"%s\",\"pid\":%u,\"tid\":%u,"
            "\"type\":\"%s\",\"severity\":\"%s\","
            "\"description\":\"%s\",\"evidence\":\"%s\"",
            timestamp, alert->pid, alert->tid,
            type_str, severity_str,
            alert->description, alert->evidence);
    
    if (alert->prompt_context[0] != '\0') {
        fprintf(g_log_file, ",\"prompt_context\":\"%s\"", alert->prompt_context);
    }
    
    fprintf(g_log_file, "}\n");
    fflush(g_log_file);
    
    pthread_mutex_unlock(&g_log_mutex);
    
    return 0;
}

/* Cleanup */
void alert_manager_cleanup(void)
{
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}