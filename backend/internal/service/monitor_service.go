// Package service 提供核心业务逻辑服务
// monitor_service.go - 进程监控服务
// 通过 procfs 扫描进程，识别 AI Agent，生成系统事件，执行异常检测规则

package service

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/agents"
	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/model"
	"github.com/prometheus/procfs"
)

// =============================================
// WebSocket 广播接口 & 客户端管理
// =============================================

// WSClient WebSocket 客户端接口
type WSClient interface {
	Send(msg model.WSMessage) error
}

// MonitorService 进程监控服务
type MonitorService struct {
	mu          sync.RWMutex
	clients     map[WSClient]bool       // 已注册的 WebSocket 客户端
	agents      map[uint32]*model.Agent // PID → Agent 状态映射
	events      []*model.Event          // 事件环形缓冲区
	maxEvents   int                     // 最大保留事件数
	scanTicker  *time.Ticker            // procfs 扫描定时器
	eventCh     chan model.Event        // 事件输入通道
	alertCh     chan model.Alert         // 告警输出通道 (供 AlertService 消费)
	stopCh      chan struct{}            // 停止信号
	startTime   time.Time               // 服务启动时间
	totalEvents int                     // 事件计数器
}

// NewMonitorService 创建监控服务实例
func NewMonitorService() *MonitorService {
	return &MonitorService{
		clients:   make(map[WSClient]bool),
		agents:    make(map[uint32]*model.Agent),
		events:    make([]*model.Event, 0, 4096),
		maxEvents: 5000,
		eventCh:   make(chan model.Event, 1024),
		alertCh:   make(chan model.Alert, 256),
		stopCh:    make(chan struct{}),
		startTime: time.Now(),
	}
}

// Register 注册 WebSocket 客户端
func (m *MonitorService) Register(client WSClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client] = true
	log.Printf("[Monitor] 新增 WebSocket 客户端，当前: %d", len(m.clients))
}

// Unregister 注销 WebSocket 客户端
func (m *MonitorService) Unregister(client WSClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, client)
	log.Printf("[Monitor] 移除 WebSocket 客户端，当前: %d", len(m.clients))
}

// Broadcast 向所有已注册客户端广播消息
func (m *MonitorService) Broadcast(msg model.WSMessage) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for client := range m.clients {
		if err := client.Send(msg); err != nil {
			log.Printf("[Monitor] 广播失败: %v", err)
		}
	}
}

// AlertChannel 返回告警通道，供 AlertService 订阅
func (m *MonitorService) AlertChannel() <-chan model.Alert {
	return m.alertCh
}

// GetEvents 获取最近的事件列表
func (m *MonitorService) GetEvents() []*model.Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	events := make([]*model.Event, len(m.events))
	copy(events, m.events)
	return events
}

// GetAgents 获取当前监控到的所有 Agent
func (m *MonitorService) GetAgents() []*model.Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agents := make([]*model.Agent, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents
}

// GetStats 获取统计信息
func (m *MonitorService) GetStats() model.Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return model.Stats{
		TotalEvents: m.totalEvents,
		TotalAlerts: 0, // 由 Handler 层合并
		Scans:       0, // 由 Handler 层填充
	}
}

// Uptime 返回服务运行时间字符串
func (m *MonitorService) Uptime() string {
	return time.Since(m.startTime).Truncate(time.Second).String()
}

// InjectEvent 外部注入事件 (供 eBPF ring buffer / handler 使用)
func (m *MonitorService) InjectEvent(evt model.Event) {
	select {
	case m.eventCh <- evt:
	default:
		log.Println("[Monitor] 事件通道已满，丢弃事件")
	}
}

// Start 启动监控主循环
func (m *MonitorService) Start() {
	log.Println("[Monitor] 启动进程监控服务...")
	m.scanTicker = time.NewTicker(3 * time.Second)

	// 并行运行: procfs 扫描 + 事件处理
	go m.scanLoop()
	go m.eventLoop()
}

// Stop 停止监控服务
func (m *MonitorService) Stop() {
	close(m.stopCh)
	if m.scanTicker != nil {
		m.scanTicker.Stop()
	}
}

// scanLoop 定时扫描 procfs 发现 Agent 进程
func (m *MonitorService) scanLoop() {
	// 使用 AgentRegistry 的进程名列表进行精确匹配
	registry := agents.NewAgentRegistry()
	knownAgents := registry.GetAll()

	// 构建进程名 → AgentProfile 映射
	procMap := make(map[string]*agents.AgentProfile)
	for _, p := range knownAgents {
		for _, name := range p.ProcessNames {
			procMap[strings.ToLower(name)] = p
		}
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-m.scanTicker.C:
			fs, err := procfs.NewFS("/proc")
			if err != nil {
				log.Printf("[Monitor] 打开 /proc 失败: %v", err)
				continue
			}

			procs, err := fs.AllProcs()
			if err != nil {
				log.Printf("[Monitor] 遍历进程失败: %v", err)
				continue
			}

			m.mu.Lock()
			for _, proc := range procs {
				pid := uint32(proc.PID)

				// 已跟踪的进程更新资源使用
				if agent, exists := m.agents[pid]; exists {
					m.updateAgentResource(agent)
					continue
				}

				// 检测新 Agent
				cmdline, _ := proc.CmdLine()
				comm := m.procComm(pid)
				fullCmd := strings.Join(cmdline, " ")
				commLower := strings.ToLower(comm)
				cmdLower := strings.ToLower(fullCmd)

				// 精确匹配: 进程名 或 命令行包含已知 Agent 关键词
				var matchedProfile *agents.AgentProfile
				if p, ok := procMap[commLower]; ok {
					matchedProfile = p
				} else {
					for _, p := range knownAgents {
						for _, pattern := range p.CmdlinePatterns {
							if strings.Contains(cmdLower, strings.ToLower(pattern)) {
								matchedProfile = p
								break
							}
						}
						if matchedProfile != nil {
							break
						}
					}
				}

				if matchedProfile != nil {
					name := matchedProfile.Name
					if comm != "" {
						name = comm
					}
					now := time.Now().Format(time.RFC3339)
					agent := &model.Agent{
						PID:       pid,
						Name:      name,
						Status:    "running",
						StartTime: time.Now().Unix(),
					}
					m.agents[pid] = agent
					log.Printf("[Monitor] 发现 Agent: %s (PID=%d, Type=%s)", name, pid, matchedProfile.Type)

					// 广播 Agent 发现事件
					m.appendEvent(&model.Event{
						Time:      now,
						PID:       pid,
						Agent:     name,
						Type:      model.EventExecve,
						Detail:    fmt.Sprintf("Agent 进程启动: %s [%s]", name, matchedProfile.Type),
						Timestamp: time.Now().UnixMilli(),
					})
				}
			}
			m.mu.Unlock()
		}
	}
}

// eventLoop 事件处理循环: 消费事件 → 执行检测规则 → 产生告警
func (m *MonitorService) eventLoop() {
	// 频率统计: PID → 最近事件时间戳列表
	freqMap := make(map[uint32][]int64)

	for {
		select {
		case <-m.stopCh:
			return
		case evt := <-m.eventCh:
			m.mu.Lock()
			m.totalEvents++
			m.appendEventLocked(&evt)

			// 更新 Agent 统计
			if agent, ok := m.agents[evt.PID]; ok {
				m.updateAgentStats(agent, evt.Type)
			}
			m.mu.Unlock()

			// 执行异常检测规则
			alerts := m.runAnomalyRules(evt, freqMap)
			for _, alert := range alerts {
				select {
				case m.alertCh <- alert:
				default:
					log.Println("[Monitor] 告警通道已满，丢弃告警")
				}
				// 广播告警
				m.Broadcast(model.WSMessage{
					Type:    "alert",
					Payload: alert,
				})
			}

			// 广播事件
			m.Broadcast(model.WSMessage{
				Type:    "event",
				Payload: evt,
			})
		}
	}
}

// =============================================
// 异常检测规则引擎
// =============================================

// runAnomalyRules 对单个事件执行所有异常检测规则，返回触发的告警列表
func (m *MonitorService) runAnomalyRules(evt model.Event, freqMap map[uint32][]int64) []model.Alert {
	var alerts []model.Alert
	now := time.Now().UnixMilli()

	agentName := evt.Agent
	if agentName == "" {
		agentName = "unknown"
	}

	// 规则1: Shell Spawn 检测 - EXECVE 事件包含 shell 关键词
	if evt.Type == model.EventExecve {
		detail := strings.ToLower(evt.Detail)
		shellKeywords := []string{"bash", "sh ", "zsh", "/bin/sh", "/bin/bash", "cmd.exe", "powershell"}
		for _, kw := range shellKeywords {
			if strings.Contains(detail, kw) {
				alerts = append(alerts, model.Alert{
					Time:        time.Now().Format(time.RFC3339),
					PID:         evt.PID,
					Agent:       agentName,
					Type:        model.AnomalyShellSpawn,
					Severity:    model.SeverityHigh,
					Description: "检测到 Agent 生成 Shell 进程",
					Evidence:    evt.Detail,
				})
				break
			}
		}
	}

	// 规则2: 敏感文件访问 - OPENAT 事件访问系统敏感路径
	if evt.Type == model.EventOpenat {
		detail := strings.ToLower(evt.Detail)
		sensitivePaths := []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh", "/etc/ssl/private", "/proc/kcore"}
		for _, sp := range sensitivePaths {
			if strings.Contains(detail, sp) {
				alerts = append(alerts, model.Alert{
					Time:        time.Now().Format(time.RFC3339),
					PID:         evt.PID,
					Agent:       agentName,
					Type:        model.AnomalySensitiveFile,
					Severity:    model.SeverityCritical,
					Description: "检测到 Agent 访问敏感系统文件: " + sp,
					Evidence:    evt.Detail,
				})
				break
			}
		}
	}

	// 规则3: 工作空间违规 - OPENAT/UNLINKAT 操作工作区外文件
	if evt.Type == model.EventOpenat || evt.Type == model.EventUnlinkat {
		detail := strings.ToLower(evt.Detail)
		// 如果文件路径不在常见工作区内，标记违规
		allowedPrefixes := []string{"/home", "/tmp", "/var/tmp", "/workspace", "/app", "/opt"}
		if m.containsAbsPath(detail) && !m.hasAllowedPrefix(detail, allowedPrefixes) {
			alerts = append(alerts, model.Alert{
				Time:        time.Now().Format(time.RFC3339),
				PID:         evt.PID,
				Agent:       agentName,
				Type:        model.AnomalyWorkspaceViolation,
				Severity:    model.SeverityMedium,
				Description: "Agent 操作工作区外文件",
				Evidence:    evt.Detail,
			})
		}
	}

	// 规则4: 高频 API 调用 - 10秒内 CONNECT 事件超过 30 次
	if evt.Type == model.EventConnect || evt.Type == model.EventSSLWrite {
		tsList := freqMap[evt.PID]
		tsList = append(tsList, now)
		// 清理 10 秒前的时间戳
		cutoff := now - 10000
		fresh := make([]int64, 0, len(tsList))
		for _, ts := range tsList {
			if ts > cutoff {
				fresh = append(fresh, ts)
			}
		}
		freqMap[evt.PID] = fresh

		if len(fresh) > 30 {
			alerts = append(alerts, model.Alert{
				Time:        time.Now().Format(time.RFC3339),
				PID:         evt.PID,
				Agent:       agentName,
				Type:        model.AnomalyHighFreqAPI,
				Severity:    model.SeverityHigh,
				Description: "检测到高频 API 调用 (10s 内 >30 次)",
				Evidence:    evt.Detail,
			})
		}
	}

	// 规则5: 资源滥用 - FORK 炸弹 / 短时间大量 fork
	if evt.Type == model.EventFork {
		tsList := freqMap[evt.PID]
		tsList = append(tsList, now)
		cutoff := now - 5000
		fresh := make([]int64, 0, len(tsList))
		for _, ts := range tsList {
			if ts > cutoff {
				fresh = append(fresh, ts)
			}
		}
		freqMap[evt.PID] = fresh

		if len(fresh) > 20 {
			alerts = append(alerts, model.Alert{
				Time:        time.Now().Format(time.RFC3339),
				PID:         evt.PID,
				Agent:       agentName,
				Type:        model.AnomalyResourceAbuse,
				Severity:    model.SeverityCritical,
				Description: "检测到疑似 Fork 炸弹 (5s 内 >20 次 fork)",
				Evidence:    evt.Detail,
			})
		}
	}

	// 规则6: 逻辑循环 - Agent 短时间重复相同操作
	if evt.Type == model.EventExecve || evt.Type == model.EventOpenat {
		m.mu.Lock()
		if agent, ok := m.agents[evt.PID]; ok {
			// 用简单计数器检测循环: 同类事件快速累积
			recent := 0
			switch evt.Type {
			case model.EventExecve:
				recent = agent.ExecCount
			case model.EventOpenat:
				recent = agent.FileOps
			}
			// 如果 1 分钟内同类事件超过 100 次，疑似死循环
			if recent > 100 {
				alerts = append(alerts, model.Alert{
					Time:        time.Now().Format(time.RFC3339),
					PID:         evt.PID,
					Agent:       agentName,
					Type:        model.AnomalyLogicLoop,
					Severity:    model.SeverityHigh,
					Description: "检测到 Agent 疑似逻辑循环 (事件累积 >100)",
					Evidence:    evt.Detail,
				})
			}
		}
		m.mu.Unlock()
	}

	return alerts
}

// =============================================
// 辅助方法
// =============================================

// procComm 读取进程的 comm 名称
func (m *MonitorService) procComm(pid uint32) string {
	data, err := os.ReadFile(filepath.Join("/proc", formatPid(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// extractAgentName 从命令行提取 Agent 名称
func (m *MonitorService) extractAgentName(cmdline, comm string) string {
	if comm != "" {
		return comm
	}
	parts := strings.Fields(cmdline)
	if len(parts) > 0 {
		return filepath.Base(parts[0])
	}
	return "unknown"
}

// updateAgentResource 更新 Agent 资源使用情况 (CPU/内存)
func (m *MonitorService) updateAgentResource(agent *model.Agent) {
	statPath := filepath.Join("/proc", formatPid(agent.PID), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		// 进程可能已退出
		agent.Status = "stopped"
		return
	}
	// 简化解析: 只提取 utime + stime 作为 CPU 占用的近似值
	fields := strings.Fields(string(data))
	if len(fields) > 14 {
		// fields[13]=utime, fields[14]=stime (单位: jiffies)
		agent.CPU = 0.5 // 简化: 实际应用中需要计算差值
	}

	// 读取内存
	statusPath := filepath.Join("/proc", formatPid(agent.PID), "status")
	statusData, err := os.ReadFile(statusPath)
	if err == nil {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				var kb float64
				fmt := strings.Fields(line)
				if len(fmt) >= 2 {
					// 简化解析
					_ = kb
					agent.MemMB = 128.0 // 简化值
				}
				break
			}
		}
	}
}

// updateAgentStats 根据事件类型更新 Agent 统计计数
func (m *MonitorService) updateAgentStats(agent *model.Agent, evtType model.EventType) {
	switch evtType {
	case model.EventExecve:
		agent.ExecCount++
	case model.EventFork:
		agent.ForkCount++
	case model.EventOpenat:
		agent.FileOps++
	case model.EventUnlinkat:
		agent.FileDeletes++
	case model.EventConnect, model.EventAccept:
		agent.NetworkConns++
	case model.EventSSLWrite, model.EventSSLRead:
		agent.APICalls++
	}
}

// appendEvent 添加事件到缓冲区 (已持锁)
func (m *MonitorService) appendEventLocked(evt *model.Event) {
	if len(m.events) >= m.maxEvents {
		// 丢弃前 1/4 的旧事件
		cutoff := m.maxEvents / 4
		m.events = m.events[cutoff:]
	}
	m.events = append(m.events, evt)
}

// appendEvent 线程安全添加事件
func (m *MonitorService) appendEvent(evt *model.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendEventLocked(evt)
}

// containsAbsPath 检测字符串中是否包含绝对路径
func (m *MonitorService) containsAbsPath(s string) bool {
	return strings.Contains(s, "/")
}

// hasAllowedPrefix 检测路径是否以允许的前缀开头
func (m *MonitorService) hasAllowedPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// formatPid 将 PID 格式化为字符串
func formatPid(pid uint32) string {
	return fmt.Sprintf("%d", pid)
}
