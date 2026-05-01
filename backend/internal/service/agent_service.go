// agent_service.go - Agent 状态管理服务
// 管理 Agent 的生命周期: 启动/停止/终止，维护统计数据和系统调用追踪

package service

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/model"
)

// AgentService Agent 状态管理服务
type AgentService struct {
	mu       sync.RWMutex
	agents   map[uint32]*model.Agent   // PID → Agent 状态
	spawnLog []SpawnRecord             // 启动记录
	traces   map[uint32][]model.Event  // PID → 系统调用追踪链
	clients  map[WSClient]bool         // WebSocket 客户端
}

// SpawnRecord Agent 启动记录
type SpawnRecord struct {
	Name      string `json:"name"`
	PID       uint32 `json:"pid"`
	StartTime string `json:"start_time"`
	Cmd       string `json:"cmd"`
}

// NewAgentService 创建 Agent 管理服务实例
func NewAgentService() *AgentService {
	return &AgentService{
		agents:   make(map[uint32]*model.Agent),
		spawnLog: make([]SpawnRecord, 0, 64),
		traces:   make(map[uint32][]model.Event),
		clients:  make(map[WSClient]bool),
	}
}

// Register 注册 WebSocket 客户端
func (a *AgentService) Register(client WSClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients[client] = true
}

// Unregister 注销 WebSocket 客户端
func (a *AgentService) Unregister(client WSClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.clients, client)
}

// Broadcast 向所有客户端广播 Agent 状态变更
func (a *AgentService) Broadcast(msg model.WSMessage) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for client := range a.clients {
		if err := client.Send(msg); err != nil {
			log.Printf("[Agent] 广播失败: %v", err)
		}
	}
}

// GetAgents 获取所有 Agent 状态
func (a *AgentService) GetAgents() []*model.Agent {
	a.mu.RLock()
	defer a.mu.RUnlock()

	agents := make([]*model.Agent, 0, len(a.agents))
	for _, agent := range a.agents {
		agents = append(agents, agent)
	}
	return agents
}

// GetAgent 获取指定 PID 的 Agent 状态
func (a *AgentService) GetAgent(pid uint32) (*model.Agent, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	agent, ok := a.agents[pid]
	return agent, ok
}

// SpawnAgent 启动一个新的 Agent 进程
// 根据 name 选择不同的启动命令:
//   - python_agent:  启动 python3 -m agent
//   - node_agent:    启动 node agent.js
//   - claude_agent:  启动 claude-code agent
//   - gemini_agent:  启动 gemini agent
func (a *AgentService) SpawnAgent(name string) (*model.Agent, error) {
	var cmd *exec.Cmd

	switch name {
	case "python_agent":
		cmd = exec.Command("python3", "-c", fmt.Sprintf("import time; print('Agent %s started'); time.sleep(3600)", name))
	case "node_agent":
		cmd = exec.Command("node", "-e", fmt.Sprintf("console.log('Agent %s started'); setInterval(()=>{}, 1000)", name))
	case "claude_agent":
		cmd = exec.Command("sh", "-c", fmt.Sprintf("echo 'Agent %s started'; sleep 3600", name))
	case "gemini_agent":
		cmd = exec.Command("sh", "-c", fmt.Sprintf("echo 'Agent %s started'; sleep 3600", name))
	default:
		// 通用 Agent: 使用 sh -c 执行 echo + sleep
		cmd = exec.Command("sh", "-c", fmt.Sprintf("echo 'Agent %s started'; sleep 3600", name))
	}

	// 启动进程 (不等待完成)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 Agent %s 失败: %w", name, err)
	}

	pid := uint32(cmd.Process.Pid)
	now := time.Now()

	agent := &model.Agent{
		PID:       pid,
		Name:      name,
		Status:    "running",
		StartTime: now.Unix(),
	}

	a.mu.Lock()
	a.agents[pid] = agent
	a.spawnLog = append(a.spawnLog, SpawnRecord{
		Name:      name,
		PID:       pid,
		StartTime: now.Format(time.RFC3339),
		Cmd:       cmd.String(),
	})
	a.mu.Unlock()

	log.Printf("[Agent] 启动 Agent: %s (PID=%d)", name, pid)

	// 异步等待进程退出并清理
	go func() {
		err := cmd.Wait()
		a.mu.Lock()
		if ag, ok := a.agents[pid]; ok {
			if err != nil {
				ag.Status = "exited"
			} else {
				ag.Status = "stopped"
			}
		}
		a.mu.Unlock()
		log.Printf("[Agent] Agent %s (PID=%d) 退出, err=%v", name, pid, err)

		// 广播状态变更
		a.Broadcast(model.WSMessage{
			Type:    "agent_update",
			Payload: map[string]interface{}{"pid": pid, "name": name, "status": "stopped"},
		})
	}()

	// 广播 Agent 启动事件
	a.Broadcast(model.WSMessage{
		Type:    "agent_update",
		Payload: agent,
	})

	return agent, nil
}

// StopAgent 优雅停止 Agent (发送 SIGTERM)
func (a *AgentService) StopAgent(pid uint32) error {
	a.mu.RLock()
	agent, ok := a.agents[pid]
	a.mu.RUnlock()

	if !ok {
		return fmt.Errorf("Agent PID=%d 不存在", pid)
	}

	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("查找进程失败: %w", err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("发送 SIGTERM 失败: %w", err)
	}

	a.mu.Lock()
	agent.Status = "stopping"
	a.mu.Unlock()

	log.Printf("[Agent] 发送 SIGTERM 给 Agent %s (PID=%d)", agent.Name, pid)

	a.Broadcast(model.WSMessage{
		Type:    "agent_update",
		Payload: map[string]interface{}{"pid": pid, "name": agent.Name, "status": "stopping"},
	})

	return nil
}

// KillAgent 强制终止 Agent (发送 SIGKILL)
func (a *AgentService) KillAgent(pid uint32) error {
	a.mu.RLock()
	agent, ok := a.agents[pid]
	a.mu.RUnlock()

	if !ok {
		return fmt.Errorf("Agent PID=%d 不存在", pid)
	}

	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("查找进程失败: %w", err)
	}

	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("发送 SIGKILL 失败: %w", err)
	}

	a.mu.Lock()
	agent.Status = "killed"
	a.mu.Unlock()

	log.Printf("[Agent] 强制终止 Agent %s (PID=%d)", agent.Name, pid)

	a.Broadcast(model.WSMessage{
		Type:    "agent_update",
		Payload: map[string]interface{}{"pid": pid, "name": agent.Name, "status": "killed"},
	})

	return nil
}

// UpdateAgentStats 更新 Agent 的统计计数 (由 MonitorService 调用)
func (a *AgentService) UpdateAgentStats(pid uint32, evtType model.EventType) {
	a.mu.Lock()
	defer a.mu.Unlock()

	agent, ok := a.agents[pid]
	if !ok {
		return
	}

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

// RecordSyscallTrace 记录 Agent 的系统调用追踪
func (a *AgentService) RecordSyscallTrace(pid uint32, evt model.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	trace := a.traces[pid]
	// 保留最近 500 条追踪
	if len(trace) >= 500 {
		trace = trace[100:]
	}
	a.traces[pid] = append(trace, evt)
}

// GetSyscallTrace 获取 Agent 的系统调用追踪
func (a *AgentService) GetSyscallTrace(pid uint32) []model.Event {
	a.mu.RLock()
	defer a.mu.RUnlock()

	trace, ok := a.traces[pid]
	if !ok {
		return nil
	}
	result := make([]model.Event, len(trace))
	copy(result, trace)
	return result
}

// SyncFromMonitor 从 MonitorService 同步 Agent 数据
// 用于将 procfs 扫描发现的 Agent 合并到本服务
func (a *AgentService) SyncFromMonitor(agents []*model.Agent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, newAgent := range agents {
		if existing, ok := a.agents[newAgent.PID]; ok {
			// 更新已有 Agent 的统计
			existing.ExecCount = newAgent.ExecCount
			existing.ForkCount = newAgent.ForkCount
			existing.FileOps = newAgent.FileOps
			existing.FileDeletes = newAgent.FileDeletes
			existing.NetworkConns = newAgent.NetworkConns
			existing.APICalls = newAgent.APICalls
			existing.CPU = newAgent.CPU
			existing.MemMB = newAgent.MemMB
			existing.Status = newAgent.Status
		} else {
			// 新增 Agent
			a.agents[newAgent.PID] = newAgent
		}
	}
}

// IncrementAlerts 增加指定 Agent 的告警计数
func (a *AgentService) IncrementAlerts(pid uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if agent, ok := a.agents[pid]; ok {
		agent.Alerts++
	}
}

// IncrementPrompts 增加指定 Agent 的 Prompt 计数
func (a *AgentService) IncrementPrompts(pid uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if agent, ok := a.agents[pid]; ok {
		agent.Prompts++
	}
}

// GetSpawnLog 获取 Agent 启动记录
func (a *AgentService) GetSpawnLog() []SpawnRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]SpawnRecord, len(a.spawnLog))
	copy(result, a.spawnLog)
	return result
}

// ClearAll 清空所有 Agent 状态
func (a *AgentService) ClearAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agents = make(map[uint32]*model.Agent)
	a.traces = make(map[uint32][]model.Event)
	a.spawnLog = nil
}

// TriggerScenario 触发测试场景
func (a *AgentService) TriggerScenario(scenario string, pid uint32) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// 如果未指定 PID，找第一个 running 的 Agent
	if pid == 0 {
		for p, ag := range a.agents {
			if ag.Status == "running" {
				pid = p
				break
			}
		}
	}
	if pid == 0 {
		return fmt.Errorf("没有可用的 Agent，请先启动一个")
	}

	agent, ok := a.agents[pid]
	if !ok {
		return fmt.Errorf("PID=%d 不存在", pid)
	}

	// 场景触发由 MonitorService 的事件注入完成
	// 这里只记录日志
	log.Printf("[场景触发] Agent=%s PID=%d Scenario=%s", agent.Name, pid, scenario)
	return nil
}
