// Package agents 提供 AI Agent 检测、识别和集成
// 支持: Claude Code, Codex, Gemini CLI, Kiro CLI, Cursor, 通用 LLM Agent
package agents

import (
	"strings"
	"sync"
)

// AgentType AI Agent 类型
type AgentType string

const (
	AgentClaudeCode AgentType = "claude-code"
	AgentCodex      AgentType = "codex"
	AgentGeminiCLI  AgentType = "gemini-cli"
	AgentKiroCLI    AgentType = "kiro-cli"
	AgentCursor     AgentType = "cursor"
	AgentCopilot    AgentType = "copilot"
	AgentAider      AgentType = "aider"
	AgentContinue   AgentType = "continue"
	AgentGeneric    AgentType = "generic"
)

// AgentProfile Agent 配置文件
type AgentProfile struct {
	Type            AgentType `json:"type"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	ProcessNames    []string  `json:"process_names"`
	CmdlinePatterns []string  `json:"cmdline_patterns"`
	APIDomains      []string  `json:"api_domains"`
	APITokens       []string  `json:"api_tokens"`
	SSLHookTarget   string    `json:"ssl_hook_target"`
	DangerousOps    []string  `json:"dangerous_ops"`
	RiskLevel       string    `json:"risk_level"`
}

// AgentRegistry Agent 注册表
type AgentRegistry struct {
	mu       sync.RWMutex
	profiles map[AgentType]*AgentProfile
}

// NewAgentRegistry 创建 Agent 注册表
func NewAgentRegistry() *AgentRegistry {
	r := &AgentRegistry{
		profiles: make(map[AgentType]*AgentProfile),
	}
	r.registerDefaults()
	return r
}

func (r *AgentRegistry) registerDefaults() {
	r.Register(&AgentProfile{
		Type:        AgentClaudeCode,
		Name:        "Claude Code",
		Description: "Anthropic Claude Code CLI 编程助手",
		ProcessNames: []string{
			"claude", "claude-code", "claude_code", "anthropic",
		},
		CmdlinePatterns: []string{"claude", "anthropic", "claude-code"},
		APIDomains:      []string{"api.anthropic.com", "console.anthropic.com"},
		APITokens: []string{
			"anthropic", "claude", "messages",
			"role:assistant", "role:user",
		},
		SSLHookTarget: "libssl.so",
		DangerousOps: []string{
			"file deletion outside workspace",
			"shell command execution",
			"network exfiltration",
			"credential access",
		},
		RiskLevel: "MEDIUM",
	})

	r.Register(&AgentProfile{
		Type:        AgentCodex,
		Name:        "OpenAI Codex",
		Description: "OpenAI Codex CLI 编程助手",
		ProcessNames: []string{
			"codex", "openai-codex", "codex-cli", "openai",
		},
		CmdlinePatterns: []string{"codex", "openai", "codex-cli"},
		APIDomains:      []string{"api.openai.com"},
		APITokens: []string{
			"openai", "gpt-4", "codex",
			"model:", "messages:", "choices:",
		},
		SSLHookTarget: "libssl.so",
		DangerousOps: []string{
			"arbitrary code execution",
			"file system modification",
			"environment variable access",
		},
		RiskLevel: "MEDIUM",
	})

	r.Register(&AgentProfile{
		Type:        AgentGeminiCLI,
		Name:        "Gemini CLI",
		Description: "Google Gemini CLI 助手",
		ProcessNames: []string{
			"gemini", "gemini-cli", "gcloud", "google-gemini",
		},
		CmdlinePatterns: []string{"gemini", "generativelanguage"},
		APIDomains: []string{
			"generativelanguage.googleapis.com",
			"aiplatform.googleapis.com",
		},
		APITokens: []string{
			"gemini", "generativelanguage",
			"contents:", "parts:",
		},
		SSLHookTarget: "libssl.so",
		DangerousOps: []string{
			"Google account access",
			"Cloud resource manipulation",
			"data exfiltration via GCP",
		},
		RiskLevel: "MEDIUM",
	})

	r.Register(&AgentProfile{
		Type:        AgentKiroCLI,
		Name:        "Kiro CLI",
		Description: "AWS Kiro IDE/CLI AI 助手",
		ProcessNames:    []string{"kiro", "kiro-cli"},
		CmdlinePatterns: []string{"kiro", "kiro-cli"},
		APIDomains:      []string{"kiro.dev", "api.kiro.dev", "bedrock-runtime"},
		APITokens:       []string{"kiro", "bedrock", "claude", "spec:", "hook:"},
		SSLHookTarget:   "libssl.so",
		DangerousOps: []string{
			"AWS credential access",
			"IAM role manipulation",
			"S3 data exfiltration",
		},
		RiskLevel: "HIGH",
	})

	r.Register(&AgentProfile{
		Type:        AgentCursor,
		Name:        "Cursor",
		Description: "Cursor AI 编辑器",
		ProcessNames:    []string{"cursor", "Cursor", "cursor-server"},
		CmdlinePatterns: []string{"cursor", "Cursor.app"},
		APIDomains:      []string{"api.cursor.sh", "cursor.sh", "api.openai.com"},
		APITokens:       []string{"cursor", "copilot", "code:", "edit:"},
		SSLHookTarget:   "libssl.so",
		DangerousOps: []string{
			"workspace file modification",
			"terminal command execution",
		},
		RiskLevel: "LOW",
	})

	r.Register(&AgentProfile{
		Type:        AgentCopilot,
		Name:        "GitHub Copilot",
		Description: "GitHub Copilot 编程助手",
		ProcessNames:    []string{"copilot", "gh-copilot", "github-copilot"},
		CmdlinePatterns: []string{"copilot", "gh copilot"},
		APIDomains: []string{
			"copilot-proxy.githubusercontent.com",
			"api.github.com",
		},
		APITokens:     []string{"copilot", "github", "completions:", "suggestions:"},
		SSLHookTarget: "libssl.so",
		DangerousOps:  []string{"code suggestion injection", "repository access"},
		RiskLevel:     "LOW",
	})

	r.Register(&AgentProfile{
		Type:        AgentAider,
		Name:        "Aider",
		Description: "Aider AI 结对编程助手",
		ProcessNames:    []string{"aider", "aider-chat"},
		CmdlinePatterns: []string{"aider", "aider-chat"},
		APIDomains:      []string{"api.openai.com", "api.anthropic.com", "api.deepseek.com"},
		APITokens:       []string{"aider", "chat", "edits:", "diff:"},
		SSLHookTarget:   "libssl.so",
		DangerousOps: []string{
			"direct file editing",
			"git commit manipulation",
		},
		RiskLevel: "MEDIUM",
	})
}

func (r *AgentRegistry) Register(profile *AgentProfile) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[profile.Type] = profile
}

func (r *AgentRegistry) Get(t AgentType) *AgentProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.profiles[t]
}

func (r *AgentRegistry) GetAll() []*AgentProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*AgentProfile, 0, len(r.profiles))
	for _, p := range r.profiles {
		result = append(result, p)
	}
	return result
}

func (r *AgentRegistry) IdentifyByProcess(comm, cmdline string) AgentType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	commLower := strings.ToLower(comm)
	cmdLower := strings.ToLower(cmdline)
	for _, profile := range r.profiles {
		for _, name := range profile.ProcessNames {
			if commLower == strings.ToLower(name) {
				return profile.Type
			}
		}
		for _, pattern := range profile.CmdlinePatterns {
			if strings.Contains(cmdLower, strings.ToLower(pattern)) {
				return profile.Type
			}
		}
	}
	return AgentGeneric
}

func (r *AgentRegistry) IdentifyByDomain(domain string) AgentType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	domainLower := strings.ToLower(domain)
	for _, profile := range r.profiles {
		for _, d := range profile.APIDomains {
			if strings.Contains(domainLower, strings.ToLower(d)) {
				return profile.Type
			}
		}
	}
	return AgentGeneric
}

func (r *AgentRegistry) IdentifyByTraffic(data string) AgentType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dataLower := strings.ToLower(data)
	bestMatch := AgentGeneric
	bestScore := 0
	for _, profile := range r.profiles {
		score := 0
		for _, token := range profile.APITokens {
			if strings.Contains(dataLower, strings.ToLower(token)) {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			bestMatch = profile.Type
		}
	}
	if bestScore >= 2 {
		return bestMatch
	}
	return AgentGeneric
}
