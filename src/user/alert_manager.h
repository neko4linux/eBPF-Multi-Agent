/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Alert Manager Header
 */

#ifndef __ALERT_MANAGER_H__
#define __ALERT_MANAGER_H__

#include "../../include/common.h"

/* Initialize alert manager */
int alert_manager_init(const char *log_file);

/* Submit an anomaly alert */
int alert_manager_submit(__u32 pid, enum anomaly_type type, 
                         enum severity_level severity,
                         const char *description, const char *evidence);

/* Write alert to log file */
int alert_manager_write_log(struct anomaly_alert *alert);

/* Cleanup */
void alert_manager_cleanup(void);

#endif /* __ALERT_MANAGER_H__ */