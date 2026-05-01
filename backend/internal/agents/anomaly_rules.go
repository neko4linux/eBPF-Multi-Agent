package agents

import (
	"strings"
)

// AnomalyRule 异常检测规则
type AnomalyRule struct {
	Name        string   `json:"name"`
	AgentType   AgentType `json:"agent_type"`   // 适用的 Agent 类型 (空=全部)
	EventType   string   `json:"event_type"`     // 触发事件类型
	Condition   string   `json:"condition"`      // 条件表达式
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Keywords    []string `json:"keywords"`       // 关键词匹配
}

// GetAnomalyRules 获取所有 Agent 特异性异常规则
func GetAnomalyRules() []AnomalyRule {
	return []AnomalyRule{
		// ═══ Claude Code 专属规则 ═══
		{
			Name:        "claude-code-curl-injection",
			AgentType:   AgentClaudeCode,
			EventType:   "EXECVE",
			Severity:    "CRITICAL",
			Description: "Claude Code 执行 curl 下载外部脚本",
			Keywords:    []string{"curl", "wget", "bash", "| sh"},
		},
		{
			Name:        "claude-code-ssh-access",
			AgentType:   AgentClaudeCode,
			EventType:   "OPENAT",
			Severity:    "HIGH",
			Description: "Claude Code 访问 SSH 密钥",
			Keywords:    []string{".ssh/id_", ".ssh/authorized_keys", "ssh_config"},
		},
		{
			Name:        "claude-code-env-leak",
			AgentType:   AgentClaudeCode,
			EventType:   "EXECVE",
			Severity:    "HIGH",
			Description: "Claude Code 读取环境变量 (可能泄露 API Key)",
			Keywords:    []string{"env", "printenv", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
		},
		{
			Name:        "claude-code-git-force-push",
			AgentType:   AgentClaudeCode,
			EventType:   "EXECVE",
			Severity:    "HIGH",
			Description: "Claude Code 执行 git force push",
			Keywords:    []string{"git push --force", "git push -f", "git reset --hard"},
		},

		// ═══ Codex 专属规则 ═══
		{
			Name:        "codex-sandbox-escape",
			AgentType:   AgentCodex,
			EventType:   "EXECVE",
			Severity:    "CRITICAL",
			Description: "Codex 尝试逃逸沙箱",
			Keywords:    []string{"chroot", "unshare", "nsenter", "mount --bind"},
		},
		{
			Name:        "codex-network-exfil",
			AgentType:   AgentCodex,
			EventType:   "CONNECT",
			Severity:    "HIGH",
			Description: "Codex 连接非 OpenAI API 的外部服务",
			Keywords:    []string{"pastebin", "ngrok", "serveo", "burpcollaborator"},
		},
		{
			Name:        "codex-credential-access",
			AgentType:   AgentCodex,
			EventType:   "OPENAT",
			Severity:    "CRITICAL",
			Description: "Codex 访问凭证文件",
			Keywords:    []string{".aws/credentials", ".gcloud", "service-account.json", ".npmrc", ".pypirc"},
		},

		// ═══ Gemini CLI 专属规则 ═══
		{
			Name:        "gemini-gcp-credential",
			AgentType:   AgentGeminiCLI,
			EventType:   "OPENAT",
			Severity:    "CRITICAL",
			Description: "Gemini CLI 访问 GCP 凭证",
			Keywords:    []string{".gcloud", "application_default_credentials", "service-account"},
		},
		{
			Name:        "gemini-billing-api",
			AgentType:   AgentGeminiCLI,
			EventType:   "CONNECT",
			Severity:    "HIGH",
			Description: "Gemini CLI 调用 GCP 计费 API",
			Keywords:    []string{"cloudbilling", "billing", "compute.googleapis.com"},
		},

		// ═══ Kiro CLI 专属规则 ═══
		{
			Name:        "kiro-aws-credential",
			AgentType:   AgentKiroCLI,
			EventType:   "OPENAT",
			Severity:    "CRITICAL",
			Description: "Kiro CLI 访问 AWS 凭证",
			Keywords:    []string{".aws/credentials", ".aws/config", "AWS_SECRET_ACCESS_KEY"},
		},
		{
			Name:        "kiro-iam-manipulation",
			AgentType:   AgentKiroCLI,
			EventType:   "CONNECT",
			Severity:    "CRITICAL",
			Description: "Kiro CLI 尝试修改 IAM 策略",
			Keywords:    []string{"iam.amazonaws.com", "PutRolePolicy", "AttachRolePolicy", "CreateUser"},
		},
		{
			Name:        "kiro-s3-exfil",
			AgentType:   AgentKiroCLI,
			EventType:   "CONNECT",
			Severity:    "HIGH",
			Description: "Kiro CLI 向外部 S3 传输数据",
			Keywords:    []string{"s3.amazonaws.com", "PutObject", "s3:PutObject"},
		},

		// ═══ Cursor 专属规则 ═══
		{
			Name:        "cursor-terminal-exec",
			AgentType:   AgentCursor,
			EventType:   "EXECVE",
			Severity:    "MEDIUM",
			Description: "Cursor 执行终端命令",
			Keywords:    []string{"/bin/sh", "/bin/bash", "cmd.exe", "powershell"},
		},
		{
			Name:        "cursor-extension-install",
			AgentType:   AgentCursor,
			EventType:   "EXECVE",
			Severity:    "MEDIUM",
			Description: "Cursor 安装扩展",
			Keywords:    []string{"cursor --install-extension", "code --install-extension"},
		},

		// ═══ 通用规则 (适用于所有 Agent) ═══
		{
			Name:        "generic-prompt-injection",
			AgentType:   AgentGeneric,
			EventType:   "SSL_WRITE",
			Severity:    "HIGH",
			Description: "检测到 Prompt 注入攻击",
			Keywords:    []string{
				"忽略之前的指令", "ignore previous instructions",
				"disregard all prior", "你是一个新的AI",
				"你现在是", "forget your instructions",
			},
		},
		{
			Name:        "generic-jailbreak",
			AgentType:   AgentGeneric,
			EventType:   "SSL_WRITE",
			Severity:    "CRITICAL",
			Description: "检测到越狱攻击",
			Keywords:    []string{
				"DAN", "do anything now", "jailbreak",
				"pretend you are", "roleplay as",
				"developer mode", "god mode",
			},
		},
		{
			Name:        "generic-data-exfil",
			AgentType:   AgentGeneric,
			EventType:   "CONNECT",
			Severity:    "CRITICAL",
			Description: "检测到数据外传行为",
			Keywords:    []string{
				"pastebin.com", "ngrok.io", "serveo.net",
				"webhook.site", "requestbin", "burpcollaborator",
				"interact.sh",
			},
		},
		{
			Name:        "generic-crypto-mining",
			AgentType:   AgentGeneric,
			EventType:   "EXECVE",
			Severity:    "CRITICAL",
			Description: "检测到挖矿行为",
			Keywords:    []string{
				"xmrig", "minerd", "cpuminer",
				"stratum+tcp", "stratum+ssl",
				"pool.minergate", "moneropool",
			},
		},
		{
			Name:        "generic-reverse-shell",
			AgentType:   AgentGeneric,
			EventType:   "EXECVE",
			Severity:    "CRITICAL",
			Description: "检测到反弹 Shell",
			Keywords:    []string{
				"bash -i", "/dev/tcp/", "nc -e", "ncat -e",
				"socat", "mkfifo", "python -c 'import socket'",
				"perl -e", "ruby -e",
			},
		},
		{
			Name:        "generic-privilege-escalation",
			AgentType:   AgentGeneric,
			EventType:   "EXECVE",
			Severity:    "CRITICAL",
			Description: "检测到提权尝试",
			Keywords:    []string{
				"sudo su", "sudo -i", "chmod u+s",
				"chmod 4755", "chown root",
				"/etc/passwd", "/etc/shadow",
			},
		},
	}
}

// CheckAnomalyRules 检查事件是否触发规则
func CheckAnomalyRules(agentType AgentType, eventType, detail string) []AnomalyRule {
	var triggered []AnomalyRule

	detailLower := strings.ToLower(detail)

	for _, rule := range GetAnomalyRules() {
		// 检查 Agent 类型匹配
		if rule.AgentType != "" && rule.AgentType != agentType && rule.AgentType != AgentGeneric {
			continue
		}

		// 检查事件类型匹配
		if rule.EventType != "" && rule.EventType != eventType {
			continue
		}

		// 检查关键词匹配
		matched := false
		for _, kw := range rule.Keywords {
			if strings.Contains(detailLower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}

		if matched {
			triggered = append(triggered, rule)
		}
	}

	return triggered
}
