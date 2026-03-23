/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Agent Tracker Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "agent_tracker.h"
#include "anomaly_detector.h"

/* Agent tracking hash table */
#define HASH_SIZE 1024

struct agent_entry {
    __u32 pid;
    struct agent_info info;
    struct agent_stats stats;
    struct agent_entry *next;
};

static struct agent_entry *g_agent_table[HASH_SIZE];
static pthread_mutex_t g_agent_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Hash function */
static __u32 hash_pid(__u32 pid)
{
    return pid % HASH_SIZE;
}

/* Initialize agent tracker */
int agent_tracker_init(void)
{
    memset(g_agent_table, 0, sizeof(g_agent_table));
    printf("Agent tracker initialized\n");
    return 0;
}

/* Process event for agent tracking */
void agent_tracker_process_event(struct process_event_data *event)
{
    if (!event)
        return;
    
    __u32 pid = event->ctx.pid;
    __u32 hash = hash_pid(pid);
    
    pthread_mutex_lock(&g_agent_mutex);
    
    struct agent_entry *entry = g_agent_table[hash];
    while (entry) {
        if (entry->pid == pid) {
            /* Update existing entry */
            entry->stats.last_update = event->ctx.timestamp;
            
            if (event->event_type == EVENT_EXECVE) {
                entry->stats.exec_count++;
            } else if (event->event_type == EVENT_FORK) {
                entry->stats.fork_count++;
            }
            
            pthread_mutex_unlock(&g_agent_mutex);
            return;
        }
        entry = entry->next;
    }
    
    /* Create new entry */
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_mutex_unlock(&g_agent_mutex);
        return;
    }
    
    entry->pid = pid;
    entry->info.pid = pid;
    entry->info.start_time = event->ctx.timestamp;
    entry->info.last_activity = event->ctx.timestamp;
    strncpy(entry->info.name, event->ctx.comm, MAX_AGENT_NAME_LEN - 1);
    
    entry->stats.start_time = event->ctx.timestamp;
    entry->stats.last_update = event->ctx.timestamp;
    
    entry->next = g_agent_table[hash];
    g_agent_table[hash] = entry;
    
    pthread_mutex_unlock(&g_agent_mutex);
}

/* Update agent statistics */
void agent_tracker_update_stats(__u32 pid, __u32 event_type)
{
    __u32 hash = hash_pid(pid);
    
    pthread_mutex_lock(&g_agent_mutex);
    
    struct agent_entry *entry = g_agent_table[hash];
    while (entry) {
        if (entry->pid == pid) {
            entry->stats.last_update = time(NULL) * 1000000000ULL;
            
            switch (event_type) {
                case EVENT_CONNECT:
                case EVENT_SENDMSG:
                    entry->stats.api_call_count++;
                    entry->stats.api_call_count_1min++;
                    break;
                case EVENT_OPEN:
                case EVENT_OPENAT:
                    entry->stats.file_read_count++;
                    break;
                case EVENT_UNLINK:
                case EVENT_UNLINKAT:
                    entry->stats.file_delete_count++;
                    break;
                case EVENT_FORK:
                    entry->stats.fork_count++;
                    break;
                case EVENT_EXECVE:
                    entry->stats.exec_count++;
                    break;
            }
            
            break;
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&g_agent_mutex);
}

/* Track prompt for duplicate detection */
void agent_tracker_track_prompt(__u32 pid, const char *prompt)
{
    if (!prompt)
        return;
    
    __u32 hash = hash_pid(pid);
    
    pthread_mutex_lock(&g_agent_mutex);
    
    struct agent_entry *entry = g_agent_table[hash];
    while (entry) {
        if (entry->pid == pid) {
            /* Check for duplicate */
            for (int i = 0; i < 10; i++) {
                if (strncmp(entry->stats.last_prompts[i], prompt, MAX_PROMPT_LEN) == 0) {
                    entry->stats.duplicate_prompt_count++;
                    break;
                }
            }
            
            /* Add to recent prompts */
            strncpy(entry->stats.last_prompts[entry->stats.last_prompt_idx], 
                    prompt, MAX_PROMPT_LEN - 1);
            entry->stats.last_prompt_idx = (entry->stats.last_prompt_idx + 1) % 10;
            entry->stats.prompt_count++;
            
            break;
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&g_agent_mutex);
}

/* Get agent statistics */
struct agent_stats *agent_tracker_get_stats(__u32 pid)
{
    __u32 hash = hash_pid(pid);
    
    pthread_mutex_lock(&g_agent_mutex);
    
    struct agent_entry *entry = g_agent_table[hash];
    while (entry) {
        if (entry->pid == pid) {
            pthread_mutex_unlock(&g_agent_mutex);
            return &entry->stats;
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&g_agent_mutex);
    return NULL;
}

/* Check if process is a known agent */
int agent_tracker_is_agent(__u32 pid)
{
    __u32 hash = hash_pid(pid);
    
    pthread_mutex_lock(&g_agent_mutex);
    
    struct agent_entry *entry = g_agent_table[hash];
    while (entry) {
        if (entry->pid == pid) {
            pthread_mutex_unlock(&g_agent_mutex);
            return 1;
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&g_agent_mutex);
    return 0;
}

/* Register a new agent */
int agent_tracker_register_agent(__u32 pid, const char *name)
{
    __u32 hash = hash_pid(pid);
    
    pthread_mutex_lock(&g_agent_mutex);
    
    /* Check if already exists */
    struct agent_entry *entry = g_agent_table[hash];
    while (entry) {
        if (entry->pid == pid) {
            /* Update name */
            if (name) {
                strncpy(entry->info.name, name, MAX_AGENT_NAME_LEN - 1);
            }
            pthread_mutex_unlock(&g_agent_mutex);
            return 0;
        }
        entry = entry->next;
    }
    
    /* Create new entry */
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_mutex_unlock(&g_agent_mutex);
        return -1;
    }
    
    entry->pid = pid;
    entry->info.pid = pid;
    entry->info.start_time = time(NULL) * 1000000000ULL;
    entry->info.last_activity = entry->info.start_time;
    
    if (name) {
        strncpy(entry->info.name, name, MAX_AGENT_NAME_LEN - 1);
    }
    
    entry->stats.start_time = entry->info.start_time;
    entry->stats.last_update = entry->info.start_time;
    
    entry->next = g_agent_table[hash];
    g_agent_table[hash] = entry;
    
    printf("Registered agent: PID=%u, Name=%s\n", pid, name ? name : "unknown");
    
    pthread_mutex_unlock(&g_agent_mutex);
    return 0;
}

/* Cleanup */
void agent_tracker_cleanup(void)
{
    pthread_mutex_lock(&g_agent_mutex);
    
    for (int i = 0; i < HASH_SIZE; i++) {
        struct agent_entry *entry = g_agent_table[i];
        while (entry) {
            struct agent_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        g_agent_table[i] = NULL;
    }
    
    pthread_mutex_unlock(&g_agent_mutex);
}