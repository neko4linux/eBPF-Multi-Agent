/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Anomaly Detector Header
 */

#ifndef __ANOMALY_DETECTOR_H__
#define __ANOMALY_DETECTOR_H__

#include "../../include/common.h"

/* Initialize anomaly detector */
int anomaly_detector_init(struct monitor_config *config);

/* Run periodic anomaly detection checks */
void anomaly_detector_run_periodic(void);

/* Check for logic loop based on agent stats */
int check_logic_loop(__u32 pid, struct agent_stats *stats);

/* Check for resource abuse */
int check_resource_abuse(__u32 pid, struct agent_stats *stats);

/* Check for high frequency API calls */
int check_high_freq_api(__u32 pid, struct agent_stats *stats);

/* Check for duplicate prompts */
int check_duplicate_prompts(__u32 pid, struct agent_stats *stats);

/* Cleanup */
void anomaly_detector_cleanup(void);

#endif /* __ANOMALY_DETECTOR_H__ */