/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Agent Tracker Header
 */

#ifndef __AGENT_TRACKER_H__
#define __AGENT_TRACKER_H__

#include "../../include/common.h"

/* Initialize agent tracker */
int agent_tracker_init(void);

/* Process event for agent tracking */
void agent_tracker_process_event(struct process_event_data *event);

/* Update agent statistics */
void agent_tracker_update_stats(__u32 pid, __u32 event_type);

/* Track prompt for duplicate detection */
void agent_tracker_track_prompt(__u32 pid, const char *prompt);

/* Get agent statistics */
struct agent_stats *agent_tracker_get_stats(__u32 pid);

/* Check if process is a known agent */
int agent_tracker_is_agent(__u32 pid);

/* Register a new agent */
int agent_tracker_register_agent(__u32 pid, const char *name);

/* Cleanup */
void agent_tracker_cleanup(void);

#endif /* __AGENT_TRACKER_H__ */