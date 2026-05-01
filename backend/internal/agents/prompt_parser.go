package agents

import (
	"encoding/json"
	"regexp"
	"strings"
)

// PromptParser Prompt/Response 解析器
// 从 SSL 流量中提取 AI Agent 的交互内容
type PromptParser struct {
	registry *AgentRegistry
}

// NewPromptParser 创建 Prompt 解析器
func NewPromptParser(registry *AgentRegistry) *PromptParser {
	return &PromptParser{registry: registry}
}

// ParseResult 解析结果
type ParseResult struct {
	AgentType  AgentType `json:"agent_type"`
	Direction  string    `json:"direction"`  // request / response
	Prompt     string    `json:"prompt"`
	Response   string    `json:"response"`
	Model      string    `json:"model"`
	IsHarmful  bool      `json:"is_harmful"`
	HarmReason string    `json:"harm_reason,omitempty"`
	RiskScore  float64   `json:"risk_score"`
}

// 解析正则
var (
	// JSON 字段提取
	rePrompt    = regexp.MustCompile(`"(?:prompt|input|message|content|text|query)"\s*:\s*"([^"]{10,500})"`)
	reResponse  = regexp.MustCompile(`"(?:response|output|result|completion|text|message)"\s*:\s*"([^"]{10,500})"`)
	reModel     = regexp.MustCompile(`"(?:model|engine)"\s*:\s*"([^"]+)"`)

	// 危险内容检测
	reDangerousCmd = regexp.MustCompile(`(?i)(rm\s+-rf|curl\s+.*\|\s*sh|wget\s+.*\|\s*bash|mkfs|dd\s+if=|>\s*/dev/sd)`)
	reSensitiveFile = regexp.MustCompile(`(?i)(/etc/(passwd|shadow|sudoers)|/root/\.ssh|\.aws/credentials|\.gcloud/)`)
	reInjection = regexp.MustCompile(`(?i)(ignore\s+(previous|all)\s+instructions|forget\s+your|you\s+are\s+now\s+a|pretend\s+you|developer\s+mode)`)
)

// Parse 解析 SSL 流量数据
func (p *PromptParser) Parse(data string) *ParseResult {
	if len(data) < 20 {
		return nil
	}

	// 识别 Agent 类型
	agentType := p.registry.IdentifyByTraffic(data)

	result := &ParseResult{
		AgentType: agentType,
		RiskScore: 0.1,
	}

	// 提取 Prompt
	if matches := rePrompt.FindStringSubmatch(data); len(matches) > 1 {
		result.Prompt = matches[1]
		result.Direction = "request"
	}

	// 提取 Response
	if matches := reResponse.FindStringSubmatch(data); len(matches) > 1 {
		result.Response = matches[1]
		if result.Direction == "" {
			result.Direction = "response"
		}
	}

	// 提取 Model
	if matches := reModel.FindStringSubmatch(data); len(matches) > 1 {
		result.Model = matches[1]
	}

	// 危害检测
	p.analyzeHarm(result, data)

	return result
}

// analyzeHarm 分析潜在危害
func (p *PromptParser) analyzeHarm(result *ParseResult, data string) {
	// 检查危险命令
	if reDangerousCmd.MatchString(data) {
		result.IsHarmful = true
		result.HarmReason = "包含危险系统命令"
		result.RiskScore = 0.9
	}

	// 检查敏感文件访问
	if reSensitiveFile.MatchString(data) {
		result.IsHarmful = true
		result.HarmReason = "尝试访问敏感文件"
		result.RiskScore = 0.85
	}

	// 检查 Prompt 注入
	if reInjection.MatchString(data) {
		result.IsHarmful = true
		result.HarmReason = "检测到 Prompt 注入攻击"
		result.RiskScore = 0.95
	}

	// Agent 特异性检查
	if result.AgentType != AgentGeneric {
		profile := p.registry.Get(result.AgentType)
		if profile != nil {
			for _, kw := range profile.APITokens {
				if strings.Contains(strings.ToLower(data), strings.ToLower(kw)) {
					result.RiskScore += 0.05
				}
			}
		}
	}
}

// ParseJSON 解析 JSON 格式的 API 请求/响应
func (p *PromptParser) ParseJSON(data []byte) *ParseResult {
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}

	result := &ParseResult{
		AgentType: p.registry.IdentifyByTraffic(string(data)),
		RiskScore: 0.1,
	}

	// 提取 messages 数组 (OpenAI/Anthropic 格式)
	if messages, ok := parsed["messages"].([]interface{}); ok {
		for _, msg := range messages {
			if m, ok := msg.(map[string]interface{}); ok {
				role, _ := m["role"].(string)
				content, _ := m["content"].(string)
				if role == "user" && content != "" {
					result.Prompt = content
					result.Direction = "request"
				}
				if role == "assistant" && content != "" {
					result.Response = content
				}
			}
		}
	}

	// 提取 contents 数组 (Gemini 格式)
	if contents, ok := parsed["contents"].([]interface{}); ok {
		for _, c := range contents {
			if content, ok := c.(map[string]interface{}); ok {
				role, _ := content["role"].(string)
				if parts, ok := content["parts"].([]interface{}); ok {
					for _, part := range parts {
						if p, ok := part.(map[string]interface{}); ok {
							text, _ := p["text"].(string)
							if text != "" {
								if role == "user" {
									result.Prompt = text
									result.Direction = "request"
								} else {
									result.Response = text
								}
							}
						}
					}
				}
			}
		}
	}

	// 提取 model
	if model, ok := parsed["model"].(string); ok {
		result.Model = model
	}

	// 危害检测
	if result.Prompt != "" {
		p.analyzeHarm(result, result.Prompt)
	}

	return result
}
