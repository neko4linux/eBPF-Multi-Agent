package model

import "time"

// EventType 事件类型
type EventType string

const (
	EventExecve   EventType = "EXECVE"
	EventFork     EventType = "FORK"
	EventExit     EventType = "EXIT"
	EventOpenat   EventType = "OPENAT"
	EventUnlinkat EventType = "UNLINKAT"
	EventConnect  EventType = "CONNECT"
	EventAccept   EventType = "ACCEPT"
	EventSSLRead  EventType = "SSL_READ"
	EventSSLWrite EventType = "SSL_WRITE"
)

// AnomalyType 异常类型
type AnomalyType string

const (
	AnomalyLogicLoop          AnomalyType = "LOGIC_LOOP"
	AnomalyResourceAbuse      AnomalyType = "RESOURCE_ABUSE"
	AnomalyShellSpawn         AnomalyType = "SHELL_SPAWN"
	AnomalySensitiveFile      AnomalyType = "SENSITIVE_FILE_ACCESS"
	AnomalyWorkspaceViolation AnomalyType = "WORKSPACE_VIOLATION"
	AnomalyHighFreqAPI        AnomalyType = "HIGH_FREQ_API"
	AnomalySuspiciousNetwork  AnomalyType = "SUSPICIOUS_NETWORK"
	AnomalyAgentConflict      AnomalyType = "AGENT_CONFLICT"
	AnomalyPromptInjection    AnomalyType = "PROMPT_INJECTION"
)

// Severity 严重级别
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ProcessContext 进程上下文 (对应 eBPF bpf_get_current_task)
type ProcessContext struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	TID       uint32 `json:"tid"`
	Timestamp int64  `json:"timestamp"`
	Comm      string `json:"comm"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
}

// Event 系统事件 (对应 eBPF Ring Buffer 事件)
type Event struct {
	Time      string      `json:"time"`
	PID       uint32      `json:"pid"`
	Agent     string      `json:"agent"`
	Type      EventType   `json:"type"`
	Detail    string      `json:"detail"`
	Extra     interface{} `json:"extra,omitempty"`
	Timestamp int64       `json:"timestamp"`
}

// Alert 异常告警
type Alert struct {
	Time        string     `json:"time"`
	PID         uint32     `json:"pid"`
	Agent       string     `json:"agent"`
	Type        AnomalyType `json:"type"`
	Severity    Severity   `json:"severity"`
	Description string     `json:"description"`
	Evidence    string     `json:"evidence"`
	PromptCtx   string     `json:"prompt_context,omitempty"`
	MLConf      float64    `json:"ml_confidence,omitempty"`
	MLType      string     `json:"ml_anomaly_type,omitempty"`
}

// Agent 智能体状态
type Agent struct {
	PID          uint32  `json:"pid"`
	Name         string  `json:"name"`
	Status       string  `json:"status"`
	ExecCount    int     `json:"exec"`
	ForkCount    int     `json:"fork"`
	FileOps      int     `json:"files"`
	FileDeletes  int     `json:"deletes"`
	NetworkConns int     `json:"network"`
	APICalls     int     `json:"api"`
	Prompts      int     `json:"prompts"`
	DupPrompts   int     `json:"dup_prompts"`
	Alerts       int     `json:"alerts"`
	CPU          float64 `json:"cpu"`
	MemMB        float64 `json:"mem"`
	StartTime    int64   `json:"start_time"`
}

// PromptEvent Prompt 事件 (应用层)
type PromptEvent struct {
	Timestamp int64  `json:"timestamp"`
	PID       uint32 `json:"pid"`
	Agent     string `json:"agent"`
	Direction string `json:"direction"` // request / response
	Content   string `json:"content"`
	Endpoint  string `json:"endpoint"`
}

// CausalLink 因果关联
type CausalLink struct {
	Prompt      PromptEvent `json:"prompt"`
	Syscalls    []Event     `json:"syscalls"`
	AnomalyType AnomalyType `json:"anomaly_type"`
	Confidence  float64     `json:"confidence"`
	Description string      `json:"description"`
	RiskLevel   Severity    `json:"risk_level"`
}

// SpawnRequest 启动 Agent 请求
type SpawnRequest struct {
	Name string `json:"name" binding:"required"`
}

// TriggerRequest 触发场景请求
type TriggerRequest struct {
	Scenario string `json:"scenario" binding:"required"`
	PID      uint32 `json:"pid,omitempty"`
}

// WSMessage WebSocket 消息
type WSMessage struct {
	Type    string      `json:"type"` // event / alert / agent_update / causal_link
	Payload interface{} `json:"payload"`
}

// DashboardState 仪表盘状态
type DashboardState struct {
	Agents      []*Agent  `json:"agents"`
	Alerts      []*Alert  `json:"alerts"`
	Events      []*Event  `json:"events"`
	Stats       Stats     `json:"stats"`
	CausalLinks []*CausalLink `json:"causal_links,omitempty"`
}

// Stats 统计
type Stats struct {
	TotalEvents int `json:"total_events"`
	TotalAlerts int `json:"total_alerts"`
	Scans       int `json:"scans"`
}

// BenchmarkResult 性能测试结果
type BenchmarkResult struct {
	Task        string  `json:"task"`
	Baseline    float64 `json:"baseline_sec"`
	Monitored   float64 `json:"monitored_sec"`
	OverheadPct float64 `json:"overhead_pct"`
	Passed      bool    `json:"passed"`
}

// HealthResponse 健康检查
type HealthResponse struct {
	Status  string    `json:"status"`
	Agents  int       `json:"agents"`
	Alerts  int       `json:"alerts"`
	Uptime  string    `json:"uptime"`
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
}
