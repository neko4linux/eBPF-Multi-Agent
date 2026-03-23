/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Anomaly Detector Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "anomaly_detector.h"
#include "alert_manager.h"
#include "agent_tracker.h"

/* Configuration */
static struct monitor_config *g_config = NULL;

/* Shell commands list */
static const char *shell_commands[] = {
    "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/dash",
    "sh", "bash", "zsh", "dash",
    NULL
};

/* Sensitive paths list */
static const char *sensitive_paths[] = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh", "/home/*/.ssh",
    "/etc/ssh/sshd_config",
    "/proc/", "/sys/",
    "/etc/cron", "/var/spool/cron",
    NULL
};

/* Initialize anomaly detector */
int anomaly_detector_init(struct monitor_config *config)
{
    g_config = config;
    printf("Anomaly detector initialized\n");
    return 0;
}

/* Run periodic anomaly detection checks */
void anomaly_detector_run_periodic(void)
{
    /* This would iterate through all tracked agents and check for anomalies */
    /* For now, this is a placeholder for the periodic check logic */
}

/* Check for logic loop based on agent stats */
int check_logic_loop(__u32 pid, struct agent_stats *stats)
{
    if (!stats || !g_config)
        return 0;
    
    __u64 now = time(NULL) * 1000000000ULL;
    __u64 elapsed = now - stats->last_update;
    
    /* Check for high frequency API calls combined with duplicate prompts */
    if (stats->api_call_count_1min > g_config->api_call_threshold_1min &&
        stats->duplicate_prompt_count > g_config->duplicate_prompt_threshold) {
        
        char evidence[512];
        snprintf(evidence, sizeof(evidence), 
                "API calls: %lu/min, Duplicate prompts: %lu",
                stats->api_call_count_1min, stats->duplicate_prompt_count);
        
        alert_manager_submit(pid, ANOMALY_LOGIC_LOOP, SEVERITY_HIGH,
                            "Potential logic loop detected", evidence);
        return 1;
    }
    
    return 0;
}

/* Check for resource abuse */
int check_resource_abuse(__u32 pid, struct agent_stats *stats)
{
    if (!stats)
        return 0;
    
    /* Check for excessive file operations */
    if (stats->file_delete_count > 100) {
        char evidence[512];
        snprintf(evidence, sizeof(evidence),
                "File deletions: %lu", stats->file_delete_count);
        
        alert_manager_submit(pid, ANOMALY_RESOURCE_ABUSE, SEVERITY_MEDIUM,
                            "Excessive file operations detected", evidence);
        return 1;
    }
    
    /* Check for excessive process spawning */
    if (stats->fork_count > 50 || stats->shell_spawn_count > 5) {
        char evidence[512];
        snprintf(evidence, sizeof(evidence),
                "Fork count: %lu, Shell spawns: %lu",
                stats->fork_count, stats->shell_spawn_count);
        
        alert_manager_submit(pid, ANOMALY_RESOURCE_ABUSE, SEVERITY_MEDIUM,
                            "Excessive process spawning detected", evidence);
        return 1;
    }
    
    return 0;
}

/* Check for high frequency API calls */
int check_high_freq_api(__u32 pid, struct agent_stats *stats)
{
    if (!stats || !g_config)
        return 0;
    
    if (stats->api_call_count_1min > g_config->api_call_threshold_1min) {
        char evidence[512];
        snprintf(evidence, sizeof(evidence),
                "API calls in last minute: %lu (threshold: %u)",
                stats->api_call_count_1min, g_config->api_call_threshold_1min);
        
        alert_manager_submit(pid, ANOMALY_HIGH_FREQ_API, SEVERITY_MEDIUM,
                            "High frequency API calls detected", evidence);
        return 1;
    }
    
    return 0;
}

/* Check for duplicate prompts */
int check_duplicate_prompts(__u32 pid, struct agent_stats *stats)
{
    if (!stats || !g_config)
        return 0;
    
    if (stats->duplicate_prompt_count > g_config->duplicate_prompt_threshold) {
        char evidence[512];
        snprintf(evidence, sizeof(evidence),
                "Duplicate prompts: %lu (threshold: %u)",
                stats->duplicate_prompt_count, g_config->duplicate_prompt_threshold);
        
        alert_manager_submit(pid, ANOMALY_LOGIC_LOOP, SEVERITY_MEDIUM,
                            "Duplicate prompts detected - possible loop", evidence);
        return 1;
    }
    
    return 0;
}

/* Cleanup */
void anomaly_detector_cleanup(void)
{
    g_config = NULL;
}