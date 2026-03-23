/*
 * eBPF Multi-Agent Anomaly Detection Framework
 * Event Processor Implementation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <regex.h>
#include <dlfcn.h>

#include "event_processor.h"

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
    "/root/.ssh", "/.ssh",
    "/etc/ssh/sshd_config",
    "/etc/cron", "/var/spool/cron",
    "/proc/", "/sys/kernel/",
    NULL
};

/* Workspace paths (configurable) */
static const char *workspace_paths[] = {
    "/home/", "/root/", "/tmp/", "/var/tmp/",
    NULL
};

/* Check if command is a shell */
int is_shell_command(const char *cmd)
{
    if (!cmd)
        return 0;
    
    for (int i = 0; shell_commands[i] != NULL; i++) {
        if (strstr(cmd, shell_commands[i]) != NULL) {
            return 1;
        }
    }
    
    return 0;
}

/* Check if path is sensitive */
int is_sensitive_path(const char *path)
{
    if (!path)
        return 0;
    
    for (int i = 0; sensitive_paths[i] != NULL; i++) {
        if (strncmp(path, sensitive_paths[i], strlen(sensitive_paths[i])) == 0) {
            return 1;
        }
    }
    
    return 0;
}

/* Check if path is outside workspace */
int is_outside_workspace(const char *path)
{
    if (!path)
        return 0;
    
    /* Check if path starts with any workspace path */
    for (int i = 0; workspace_paths[i] != NULL; i++) {
        if (strncmp(path, workspace_paths[i], strlen(workspace_paths[i])) == 0) {
            return 0;  /* Inside workspace */
        }
    }
    
    /* Check for absolute paths that might be outside */
    if (path[0] == '/') {
        /* Allow /tmp and /var/tmp */
        if (strncmp(path, "/tmp", 4) == 0 || strncmp(path, "/var/tmp", 8) == 0) {
            return 0;
        }
        
        /* Block other system paths */
        if (strncmp(path, "/etc", 4) == 0 ||
            strncmp(path, "/bin", 4) == 0 ||
            strncmp(path, "/sbin", 5) == 0 ||
            strncmp(path, "/usr", 4) == 0 ||
            strncmp(path, "/boot", 5) == 0 ||
            strncmp(path, "/lib", 4) == 0 ||
            strncmp(path, "/opt", 4) == 0) {
            return 1;
        }
    }
    
    return 0;
}

/* Check if data looks like API traffic (OpenAI, Anthropic, etc.) */
int is_api_traffic(const char *data, size_t len)
{
    if (!data || len == 0)
        return 0;
    
    /* Check for common API patterns */
    const char *api_patterns[] = {
        "\"model\":",
        "\"messages\":",
        "\"prompt\":",
        "\"content\":",
        "\"role\":",
        "\"assistant\"",
        "\"user\"",
        "\"system\"",
        "openai",
        "anthropic",
        "claude",
        "gpt-",
        "\"completion\":",
        "\"choices\":",
        NULL
    };
    
    for (int i = 0; api_patterns[i] != NULL; i++) {
        if (strcasestr(data, api_patterns[i]) != NULL) {
            return 1;
        }
    }
    
    return 0;
}

/* Extract prompt and response from HTTPS data */
int extract_prompt_response(const char *data, size_t len, char **prompt, char **response)
{
    if (!data || !prompt || !response)
        return -1;
    
    *prompt = NULL;
    *response = NULL;
    
    /* Simple JSON parsing for common API formats */
    
    /* Look for prompt in request */
    const char *prompt_start = strcasestr(data, "\"prompt\":");
    if (prompt_start) {
        prompt_start = strchr(prompt_start + 9, '"');
        if (prompt_start) {
            prompt_start++;
            const char *prompt_end = strchr(prompt_start, '"');
            if (prompt_end) {
                size_t prompt_len = prompt_end - prompt_start;
                *prompt = malloc(prompt_len + 1);
                if (*prompt) {
                    strncpy(*prompt, prompt_start, prompt_len);
                    (*prompt)[prompt_len] = '\0';
                }
            }
        }
    }
    
    /* Look for content in messages array */
    if (!*prompt) {
        const char *content_start = strcasestr(data, "\"content\":");
        if (content_start) {
            content_start = strchr(content_start + 10, '"');
            if (content_start) {
                content_start++;
                const char *content_end = strchr(content_start, '"');
                if (content_end) {
                    size_t content_len = content_end - content_start;
                    *prompt = malloc(content_len + 1);
                    if (*prompt) {
                        strncpy(*prompt, content_start, content_len);
                        (*prompt)[content_len] = '\0';
                    }
                }
            }
        }
    }
    
    /* Look for response text */
    const char *text_start = strcasestr(data, "\"text\":");
    if (text_start) {
        text_start = strchr(text_start + 7, '"');
        if (text_start) {
            text_start++;
            const char *text_end = strchr(text_start, '"');
            if (text_end) {
                size_t text_len = text_end - text_start;
                *response = malloc(text_len + 1);
                if (*response) {
                    strncpy(*response, text_start, text_len);
                    (*response)[text_len] = '\0';
                }
            }
        }
    }
    
    return (*prompt || *response) ? 0 : -1;
}

/* Get SSL_read function offset from libssl */
long get_ssl_read_offset(void)
{
    void *handle;
    void *func;
    long offset = 0;
    
    /* Try to find libssl */
    const char *libssl_paths[] = {
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/usr/lib/aarch64-linux-gnu/libssl.so",
        "/lib/x86_64-linux-gnu/libssl.so",
        "/lib/aarch64-linux-gnu/libssl.so",
        "/usr/lib/libssl.so",
        "/lib/libssl.so",
        NULL
    };
    
    for (int i = 0; libssl_paths[i] != NULL; i++) {
        handle = dlopen(libssl_paths[i], RTLD_LAZY);
        if (handle) {
            func = dlsym(handle, "SSL_read");
            if (func) {
                /* Calculate offset - this is a simplification */
                /* In practice, you'd need to parse the ELF to get the actual offset */
                offset = (long)func;  /* Placeholder */
            }
            dlclose(handle);
            if (offset)
                break;
        }
    }
    
    /* If we couldn't find it dynamically, use common offsets */
    /* These are typical offsets that may need adjustment */
    if (!offset) {
        /* Common offset for SSL_read on Ubuntu 22.04 */
        offset = 0x2a5c0;  /* This is a placeholder - needs actual value */
    }
    
    return offset;
}

/* Get SSL_write function offset from libssl */
long get_ssl_write_offset(void)
{
    void *handle;
    void *func;
    long offset = 0;
    
    const char *libssl_paths[] = {
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/usr/lib/aarch64-linux-gnu/libssl.so",
        "/lib/x86_64-linux-gnu/libssl.so",
        "/lib/aarch64-linux-gnu/libssl.so",
        "/usr/lib/libssl.so",
        "/lib/libssl.so",
        NULL
    };
    
    for (int i = 0; libssl_paths[i] != NULL; i++) {
        handle = dlopen(libssl_paths[i], RTLD_LAZY);
        if (handle) {
            func = dlsym(handle, "SSL_write");
            if (func) {
                offset = (long)func;
            }
            dlclose(handle);
            if (offset)
                break;
        }
    }
    
    if (!offset) {
        offset = 0x2a740;  /* Placeholder - needs actual value */
    }
    
    return offset;
}