package agents

import (
	"log"
	"sync"
	"time"
)

// Detector Agent 检测器
// 集成到监控系统，实时检测和识别 AI Agent
type Detector struct {
	registry *AgentRegistry
	parser   *PromptParser

	mu         sync.RWMutex
	detected   map[uint32]*DetectedAgent  // PID → 检测到的 Agent
	onDetected func(*DetectedAgent)        // 检测回调
	onAnomaly  func(*AnomalyEvent)         // 异常回调
}

// DetectedAgent 检测到的 Agent
type DetectedAgent struct {
	PID         uint32    `json:"pid"`
	Name        string    `json:"name"`
	Type        AgentType `json:"type"`
	Profile     *AgentProfile `json:"profile"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	EventCount  int       `json:"event_count"`
	AlertCount  int       `json:"alert_count"`
	RiskScore   float64   `json:"risk_score"`
}

// AnomalyEvent 异常事件
type AnomalyEvent struct {
	Agent       *DetectedAgent `json:"agent"`
	Rule        AnomalyRule    `json:"rule"`
	EventDetail string         `json:"event_detail"`
	Timestamp   time.Time      `json:"timestamp"`
}

// NewDetector 创建 Agent 检测器
func NewDetector(registry *AgentRegistry) *Detector {
	return &Detector{
		registry: registry,
		parser:   NewPromptParser(registry),
		detected: make(map[uint32]*DetectedAgent),
	}
}

// OnDetected 注册检测回调
func (d *Detector) OnDetected(fn func(*DetectedAgent)) {
	d.onDetected = fn
}

// OnAnomaly 注册异常回调
func (d *Detector) OnAnomaly(fn func(*AnomalyEvent)) {
	d.onAnomaly = fn
}

// ProcessEvent 处理系统事件，检测 Agent
func (d *Detector) ProcessEvent(pid uint32, comm, cmdline, eventType, detail string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 识别 Agent 类型
	agentType := d.registry.IdentifyByProcess(comm, cmdline)

	// 如果是通用类型，尝试从流量内容识别
	if agentType == AgentGeneric && (eventType == "SSL_WRITE" || eventType == "SSL_READ") {
		agentType = d.registry.IdentifyByTraffic(detail)
	}

	// 更新或创建检测记录
	agent, exists := d.detected[pid]
	if !exists {
		profile := d.registry.Get(agentType)
		agent = &DetectedAgent{
			PID:       pid,
			Name:      comm,
			Type:      agentType,
			Profile:   profile,
			FirstSeen: time.Now(),
			RiskScore: 0.1,
		}
		d.detected[pid] = agent

		if d.onDetected != nil {
			go d.onDetected(agent)
		}
		log.Printf("[Agent检测] 发现 Agent: %s (PID=%d, Type=%s)", comm, pid, agentType)
	}

	agent.LastSeen = time.Now()
	agent.EventCount++

	// 检查异常规则
	rules := CheckAnomalyRules(agent.Type, eventType, detail)
	for _, rule := range rules {
		agent.AlertCount++
		agent.RiskScore = minFloat64(agent.RiskScore+0.1, 1.0)

		evt := &AnomalyEvent{
			Agent:       agent,
			Rule:        rule,
			EventDetail: detail,
			Timestamp:   time.Now(),
		}

		if d.onAnomaly != nil {
			go d.onAnomaly(evt)
		}

		log.Printf("[异常检测] Agent=%s PID=%d Rule=%s Severity=%s Detail=%s",
			agent.Name, pid, rule.Name, rule.Severity, detail[:minInt(len(detail), 80)])
	}
}

// ProcessSSLData 处理 SSL 流量数据
func (d *Detector) ProcessSSLData(pid uint32, data string) *ParseResult {
	result := d.parser.Parse(data)
	if result == nil {
		return nil
	}

	// 更新 Agent 信息
	d.mu.Lock()
	if agent, ok := d.detected[pid]; ok {
		if result.AgentType != AgentGeneric {
			agent.Type = result.AgentType
			agent.Profile = d.registry.Get(result.AgentType)
		}
		if result.IsHarmful {
			agent.RiskScore = max(agent.RiskScore, result.RiskScore)
		}
	}
	d.mu.Unlock()

	return result
}

// GetDetected 获取所有检测到的 Agent
func (d *Detector) GetDetected() []*DetectedAgent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*DetectedAgent, 0, len(d.detected))
	for _, a := range d.detected {
		result = append(result, a)
	}
	return result
}

// GetAgent 获取指定 PID 的 Agent
func (d *Detector) GetAgent(pid uint32) *DetectedAgent {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detected[pid]
}

// GetProfiles 获取所有 Agent 配置
func (d *Detector) GetProfiles() []*AgentProfile {
	return d.registry.GetAll()
}

func minFloat64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
