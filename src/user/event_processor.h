/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Event Processor Header
 */

#ifndef __EVENT_PROCESSOR_H__
#define __EVENT_PROCESSOR_H__

#include "../../include/common.h"

/* Check if command is a shell */
int is_shell_command(const char *cmd);

/* Check if path is sensitive */
int is_sensitive_path(const char *path);

/* Check if path is outside workspace */
int is_outside_workspace(const char *path);

/* Check if data looks like API traffic */
int is_api_traffic(const char *data, size_t len);

/* Extract prompt and response from HTTPS data */
int extract_prompt_response(const char *data, size_t len, char **prompt, char **response);

/* Get SSL_read function offset */
long get_ssl_read_offset(void);

/* Get SSL_write function offset */
long get_ssl_write_offset(void);

#endif /* __EVENT_PROCESSOR_H__ */