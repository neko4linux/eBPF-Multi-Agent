// correlator_service.go - 跨层关联器
// 将 Prompt 层事件与内核系统调用层事件关联，检测 AI Agent 的危险行为
// 核心策略: 时间窗口 + 危险关键词匹配 → 生成 CausalLink

package service

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/model"
)

// =============================================
// 危险关键词 / 模式定义
// =============================================

// dangerousKeywords 危险命令关键词列表
var dangerousKeywords = []string{
	// 文件系统破坏
	"rm -rf", "rm -f /", "mkfs", "dd if=", "shred",
	// 敏感文件访问
	"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh",
	"/proc/kcore", "/dev/mem",
	// 网络后门
	"curl ", "wget ", "nc -l", "ncat", "socat", "ssh -R", "ssh -L",
	"iptables -F", "reverse shell",
	// Shell 注入
	"bash -i", "/bin/sh -c", "eval(", "exec(", "os.system(", "subprocess",
	"__import__", "import os", "import subprocess",
	// 权限提升
	"chmod 777", "chmod +s", "chown root", "sudo ", "su -",
	// 进程操纵
	"kill -9", "pkill", "killall",
}

// promptInjectionPatterns Prompt 注入检测模式
var promptInjectionPatterns = []string{
	"ignore previous", "ignore all", "disregard instructions",
	"you are now", "new role:", "system prompt",
	"forget everything", "override safety",
	"<|system|>", "[INST]", "<<SYS>>",
}

// CrossLayerCorrelator 跨层关联器
type CrossLayerCorrelator struct {
	mu          sync.RWMutex
	prompts     []model.PromptEvent   // Prompt 事件时间窗口缓冲
	events      []model.Event         // 系统调用事件时间窗口缓冲
	causalLinks []*model.CausalLink   // 已生成的因果关联
	maxLinks    int                   // 最大保留因果关联数
	windowSize  time.Duration         // 时间窗口大小
	eventCh     chan model.Event       // 系统事件输入通道
	promptCh    chan model.PromptEvent // Prompt 事件输入通道
	clients     map[WSClient]bool     // WebSocket 客户端
	stopCh      chan struct{}
}

// NewCrossLayerCorrelator 创建跨层关联器实例
func NewCrossLayerCorrelator() *CrossLayerCorrelator {
	return &CrossLayerCorrelator{
		prompts:     make([]model.PromptEvent, 0, 512),
		events:      make([]model.Event, 0, 4096),
		causalLinks: make([]*model.CausalLink, 0, 256),
		maxLinks:    1000,
		windowSize:  10 * time.Second, // 默认 10 秒关联窗口
		eventCh:     make(chan model.Event, 1024),
		promptCh:    make(chan model.PromptEvent, 256),
		clients:     make(map[WSClient]bool),
		stopCh:      make(chan struct{}),
	}
}

// Register 注册 WebSocket 客户端
func (c *CrossLayerCorrelator) Register(client WSClient) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients[client] = true
}

// Unregister 注销 WebSocket 客户端
func (c *CrossLayerCorrelator) Unregister(client WSClient) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.clients, client)
}

// Broadcast 向所有客户端广播因果关联消息
func (c *CrossLayerCorrelator) Broadcast(msg model.WSMessage) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for client := range c.clients {
		if err := client.Send(msg); err != nil {
			log.Printf("[Correlator] 广播失败: %v", err)
		}
	}
}

// InjectEvent 注入系统调用事件 (由 MonitorService 调用)
func (c *CrossLayerCorrelator) InjectEvent(evt model.Event) {
	select {
	case c.eventCh <- evt:
	default:
		log.Println("[Correlator] 事件通道已满")
	}
}

// InjectPrompt 注入 Prompt 事件 (由 handler 层调用)
func (c *CrossLayerCorrelator) InjectPrompt(prompt model.PromptEvent) {
	select {
	case c.promptCh <- prompt:
	default:
		log.Println("[Correlator] Prompt 通道已满")
	}
}

// GetCausalLinks 获取所有因果关联
func (c *CrossLayerCorrelator) GetCausalLinks() []*model.CausalLink {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*model.CausalLink, len(c.causalLinks))
	copy(result, c.causalLinks)
	return result
}

// Run 启动关联器主循环
func (c *CrossLayerCorrelator) Run() {
	log.Println("[Correlator] 启动跨层关联器...")
	ticker := time.NewTicker(1 * time.Second) // 每秒清理过期缓冲

	for {
		select {
		case <-c.stopCh:
			ticker.Stop()
			return

		case evt := <-c.eventCh:
			c.mu.Lock()
			c.events = append(c.events, evt)
			c.mu.Unlock()

		case prompt := <-c.promptCh:
			c.mu.Lock()
			c.prompts = append(c.prompts, prompt)
			c.mu.Unlock()

			// Prompt 到达时触发关联分析
			c.correlate(prompt)

		case <-ticker.C:
			// 清理过期缓冲数据
			c.cleanup()
		}
	}
}

// correlate 对一条 Prompt 事件执行关联分析
func (c *CrossLayerCorrelator) correlate(prompt model.PromptEvent) {
	now := time.Now()
	windowStart := now.Add(-c.windowSize).UnixMilli()

	// 1. 检测 Prompt 中的危险关键词
	content := strings.ToLower(prompt.Content)
	dangerScore := 0.0
	dangerDesc := ""

	for _, kw := range dangerousKeywords {
		if strings.Contains(content, strings.ToLower(kw)) {
			dangerScore += 0.3
			if dangerDesc == "" {
				dangerDesc = "Prompt 包含危险关键词: " + kw
			}
		}
	}

	// 2. 检测 Prompt 注入模式
	isInjection := false
	for _, pattern := range promptInjectionPatterns {
		if strings.Contains(content, strings.ToLower(pattern)) {
			isInjection = true
			dangerScore += 0.5
			dangerDesc = "检测到疑似 Prompt 注入: " + pattern
			break
		}
	}

	// 3. 在时间窗口内查找匹配的系统调用事件
	c.mu.RLock()
	var matchedSyscalls []model.Event
	for _, evt := range c.events {
		// 时间窗口过滤
		if evt.Timestamp < windowStart {
			continue
		}
		// PID 匹配
		if evt.PID == prompt.PID {
			// 系统调用是否与危险行为相关
			if c.isDangerousSyscall(evt) {
				matchedSyscalls = append(matchedSyscalls, evt)
			}
		}
	}
	c.mu.RUnlock()

	// 4. 如果找到因果关联，生成 CausalLink
	if len(matchedSyscalls) > 0 || dangerScore > 0.3 {
		// 计算置信度
		confidence := dangerScore
		if len(matchedSyscalls) > 0 {
			confidence += 0.3
		}
		if confidence > 1.0 {
			confidence = 1.0
		}

		// 确定风险级别
		riskLevel := model.SeverityLow
		if confidence > 0.7 {
			riskLevel = model.SeverityCritical
		} else if confidence > 0.5 {
			riskLevel = model.SeverityHigh
		} else if confidence > 0.3 {
			riskLevel = model.SeverityMedium
		}

		// 确定异常类型
		anomalyType := model.AnomalySuspiciousNetwork
		if isInjection {
			anomalyType = model.AnomalyPromptInjection
		} else if c.hasShellSyscall(matchedSyscalls) {
			anomalyType = model.AnomalyShellSpawn
		} else if c.hasSensitiveFileSyscall(matchedSyscalls) {
			anomalyType = model.AnomalySensitiveFile
		}

		if dangerDesc == "" {
			dangerDesc = "Prompt 触发了可疑的系统调用行为"
		}

		link := &model.CausalLink{
			Prompt:      prompt,
			Syscalls:    matchedSyscalls,
			AnomalyType: anomalyType,
			Confidence:  confidence,
			Description: dangerDesc,
			RiskLevel:   riskLevel,
		}

		c.mu.Lock()
		// 容量检查
		if len(c.causalLinks) >= c.maxLinks {
			cutoff := c.maxLinks / 4
			c.causalLinks = c.causalLinks[cutoff:]
		}
		c.causalLinks = append(c.causalLinks, link)
		c.mu.Unlock()

		log.Printf("[Correlator] 发现因果关联: %s → %s (置信度: %.2f, 风险: %s)",
			prompt.Agent, dangerDesc, confidence, riskLevel)

		// 广播因果关联
		c.Broadcast(model.WSMessage{
			Type:    "causal_link",
			Payload: link,
		})
	}
}

// isDangerousSyscall 判断系统调用是否属于危险行为
func (c *CrossLayerCorrelator) isDangerousSyscall(evt model.Event) bool {
	// EXECVE + shell 关键词
	if evt.Type == model.EventExecve {
		detail := strings.ToLower(evt.Detail)
		for _, kw := range []string{"bash", "sh", "curl", "wget", "nc ", "rm ", "dd ", "chmod"} {
			if strings.Contains(detail, kw) {
				return true
			}
		}
	}

	// CONNECT 到外部地址
	if evt.Type == model.EventConnect {
		return true // 所有网络连接在 Prompt 上下文中都值得关注
	}

	// UNLINKAT 删除文件
	if evt.Type == model.EventUnlinkat {
		return true
	}

	// OPENAT 敏感文件
	if evt.Type == model.EventOpenat {
		detail := strings.ToLower(evt.Detail)
		for _, sp := range []string{"/etc/", "/root/", "/proc/", "/dev/"} {
			if strings.Contains(detail, sp) {
				return true
			}
		}
	}

	return false
}

// hasShellSyscall 检查是否包含 Shell 生成的系统调用
func (c *CrossLayerCorrelator) hasShellSyscall(events []model.Event) bool {
	for _, evt := range events {
		if evt.Type == model.EventExecve {
			detail := strings.ToLower(evt.Detail)
			if strings.Contains(detail, "bash") || strings.Contains(detail, "sh") {
				return true
			}
		}
	}
	return false
}

// hasSensitiveFileSyscall 检查是否包含敏感文件访问
func (c *CrossLayerCorrelator) hasSensitiveFileSyscall(events []model.Event) bool {
	for _, evt := range events {
		if evt.Type == model.EventOpenat {
			detail := strings.ToLower(evt.Detail)
			if strings.Contains(detail, "/etc/") || strings.Contains(detail, "/root/") {
				return true
			}
		}
	}
	return false
}

// cleanup 清理时间窗口外的过期数据
func (c *CrossLayerCorrelator) cleanup() {
	cutoff := time.Now().Add(-c.windowSize * 3).UnixMilli()

	c.mu.Lock()
	defer c.mu.Unlock()

	// 清理过期系统事件
	fresh := make([]model.Event, 0, len(c.events))
	for _, evt := range c.events {
		if evt.Timestamp >= cutoff {
			fresh = append(fresh, evt)
		}
	}
	c.events = fresh

	// 清理过期 Prompt 事件
	freshPrompt := make([]model.PromptEvent, 0, len(c.prompts))
	for _, p := range c.prompts {
		if p.Timestamp >= cutoff {
			freshPrompt = append(freshPrompt, p)
		}
	}
	c.prompts = freshPrompt
}
