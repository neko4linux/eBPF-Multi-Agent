package handler

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/agents"
	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/model"
)

// ──────────────────────────────────────────────────────────────
// 服务接口定义（与 internal/service 解耦）
// ──────────────────────────────────────────────────────────────

// MonitorService 监控服务接口
type MonitorService interface {
	GetEvents() []*model.Event
	GetStats() model.Stats
	Start()
}

// AlertService 告警服务接口
type AlertService interface {
	GetAlerts() []*model.Alert
}

// AgentService 智能体管理服务接口
type AgentService interface {
	GetAgents() []*model.Agent
	SpawnAgent(name string) (*model.Agent, error)
	ClearAll()
	TriggerScenario(scenario string, pid uint32) error
}

// Correlator 跨层因果关联服务接口
type Correlator interface {
	GetCausalLinks() []*model.CausalLink
	Run()
}

// MLService 机器学习服务接口
type MLService interface {
	// 预留扩展
}

// ──────────────────────────────────────────────────────────────
// Handler 主处理器
// ──────────────────────────────────────────────────────────────

// Handler 持有所有服务引用和 WebSocket Hub
type Handler struct {
	monitorSvc MonitorService
	alertSvc   AlertService
	agentSvc   AgentService
	correlator Correlator
	mlSvc      MLService
	hub        *Hub
	startTime  time.Time
}

// NewHandler 创建 Handler 实例
func NewHandler(
	monitorSvc MonitorService,
	alertSvc AlertService,
	agentSvc AgentService,
	correlator Correlator,
	mlSvc MLService,
) *Handler {
	hub := NewHub()
	go hub.Run()

	return &Handler{
		monitorSvc: monitorSvc,
		alertSvc:   alertSvc,
		agentSvc:   agentSvc,
		correlator: correlator,
		mlSvc:      mlSvc,
		hub:        hub,
		startTime:  time.Now(),
	}
}

// SetupRouter 配置 Gin 路由并返回 HTTP Server
func (h *Handler) SetupRouter(port string) *http.Server {
	// 生产模式下使用 release 模式
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	// 注册中间件
	r.Use(RecoveryMiddleware())
	r.Use(LoggingMiddleware())
	r.Use(CORSMiddleware())

	// ─── API 路由组 ───
	api := r.Group("/api")
	{
		api.GET("/health", h.handleHealth)
		api.GET("/state", h.handleState)
		api.GET("/agents", h.handleGetAgents)
		api.GET("/alerts", h.handleGetAlerts)
		api.GET("/events", h.handleGetEvents)
		api.GET("/causal-links", h.handleGetCausalLinks)
		api.POST("/spawn/:name", h.handleSpawnAgent)
		api.POST("/trigger/:scenario", h.handleTriggerScenario)
		api.POST("/clear", h.handleClear)
		api.GET("/ws", h.handleWebSocket)

		// ─── Agent 集成 API ───
		agents := api.Group("/agents")
		{
			agents.GET("/profiles", h.handleGetAgentProfiles)
			agents.GET("/detected", h.handleGetDetectedAgents)
			agents.GET("/rules", h.handleGetAnomalyRules)
		}
	}

	// ─── 静态文件服务（生产模式） ───
	// 尝试加载前端构建产物，不存在则跳过
	r.StaticFS("/assets", http.Dir("../frontend/dist/assets"))
	r.NoRoute(func(c *gin.Context) {
		// 对于非 API 路径，尝试返回 index.html（SPA 路由支持）
		if len(c.Request.URL.Path) > 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(404, gin.H{"error": "接口不存在"})
			return
		}
		c.File("../frontend/dist/index.html")
	})

	// 创建 HTTP Server（支持优雅关闭）
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("[Handler] 路由注册完成，监听端口 :%s", port)
	return srv
}

// ──────────────────────────────────────────────────────────────
// HTTP Handler 方法
// ──────────────────────────────────────────────────────────────

// handleHealth 健康检查
func (h *Handler) handleHealth(c *gin.Context) {
	agents := h.agentSvc.GetAgents()
	alerts := h.alertSvc.GetAlerts()

	c.JSON(http.StatusOK, model.HealthResponse{
		Status:  "ok",
		Agents:  len(agents),
		Alerts:  len(alerts),
		Uptime:  time.Since(h.startTime).Truncate(time.Second).String(),
		Version: "0.1.0",
		Time:    time.Now(),
	})
}

// handleState 获取仪表盘完整状态
func (h *Handler) handleState(c *gin.Context) {
	agents := h.agentSvc.GetAgents()
	alerts := h.alertSvc.GetAlerts()
	events := h.monitorSvc.GetEvents()
	stats := h.monitorSvc.GetStats()
	causalLinks := h.correlator.GetCausalLinks()

	c.JSON(http.StatusOK, model.DashboardState{
		Agents:      agents,
		Alerts:      alerts,
		Events:      events,
		Stats:       stats,
		CausalLinks: causalLinks,
	})
}

// handleGetAgents 获取所有智能体列表
func (h *Handler) handleGetAgents(c *gin.Context) {
	c.JSON(http.StatusOK, h.agentSvc.GetAgents())
}

// handleGetAlerts 获取所有告警列表
func (h *Handler) handleGetAlerts(c *gin.Context) {
	c.JSON(http.StatusOK, h.alertSvc.GetAlerts())
}

// handleGetEvents 获取所有事件列表
func (h *Handler) handleGetEvents(c *gin.Context) {
	c.JSON(http.StatusOK, h.monitorSvc.GetEvents())
}

// handleGetCausalLinks 获取因果关联链
func (h *Handler) handleGetCausalLinks(c *gin.Context) {
	c.JSON(http.StatusOK, h.correlator.GetCausalLinks())
}

// handleSpawnAgent 启动新的智能体
func (h *Handler) handleSpawnAgent(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "智能体名称不能为空"})
		return
	}

	agent, err := h.agentSvc.SpawnAgent(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 通过 WebSocket 广播智能体更新
	h.hub.BroadcastJSON("agent_update", agent)

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"agent":  agent,
	})
}

// handleTriggerScenario 触发测试场景
func (h *Handler) handleTriggerScenario(c *gin.Context) {
	scenario := c.Param("scenario")
	if scenario == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "场景名称不能为空"})
		return
	}

	var req model.TriggerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// body 为空时也允许，使用 URL 中的 scenario
		req.Scenario = scenario
	} else if req.Scenario == "" {
		req.Scenario = scenario
	}

	if err := h.agentSvc.TriggerScenario(req.Scenario, req.PID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"scenario": req.Scenario,
	})
}

// handleClear 清除所有状态
func (h *Handler) handleClear(c *gin.Context) {
	h.agentSvc.ClearAll()

	// 通知所有客户端状态已清除
	h.hub.BroadcastJSON("clear", nil)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// handleWebSocket WebSocket 升级处理
func (h *Handler) handleWebSocket(c *gin.Context) {
	h.hub.ServeWS(c.Writer, c.Request)
}

// ─── Agent 集成 Handler ───

// handleGetAgentProfiles 获取所有 Agent 配置
func (h *Handler) handleGetAgentProfiles(c *gin.Context) {
	registry := agents.NewAgentRegistry()
	c.JSON(http.StatusOK, registry.GetAll())
}

// handleGetDetectedAgents 获取已检测到的 Agent
func (h *Handler) handleGetDetectedAgents(c *gin.Context) {
	detector := agents.NewDetector(agents.NewAgentRegistry())
	c.JSON(http.StatusOK, detector.GetDetected())
}

// handleGetAnomalyRules 获取 Agent 异常检测规则
func (h *Handler) handleGetAnomalyRules(c *gin.Context) {
	c.JSON(http.StatusOK, agents.GetAnomalyRules())
}
