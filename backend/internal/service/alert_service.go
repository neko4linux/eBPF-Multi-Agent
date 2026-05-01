// alert_service.go - 告警管理服务
// 存储、查询、清理告警，支持 WebSocket 广播和分级过滤

package service

import (
	"log"
	"sync"
	"time"

	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/model"
)

// AlertService 告警管理服务
type AlertService struct {
	mu       sync.RWMutex
	alerts   []*model.Alert         // 告警存储 (按时间倒序)
	maxAlerts int                   // 最大保留告警数
	clients  map[WSClient]bool      // WebSocket 客户端
}

// NewAlertService 创建告警服务实例
func NewAlertService() *AlertService {
	return &AlertService{
		alerts:    make([]*model.Alert, 0, 1024),
		maxAlerts: 2000,
		clients:   make(map[WSClient]bool),
	}
}

// Register 注册 WebSocket 客户端
func (a *AlertService) Register(client WSClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients[client] = true
	log.Printf("[Alert] 新增 WebSocket 客户端，当前: %d", len(a.clients))
}

// Unregister 注销 WebSocket 客户端
func (a *AlertService) Unregister(client WSClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.clients, client)
	log.Printf("[Alert] 移除 WebSocket 客户端，当前: %d", len(a.clients))
}

// Broadcast 向所有客户端广播告警消息
func (a *AlertService) Broadcast(msg model.WSMessage) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for client := range a.clients {
		if err := client.Send(msg); err != nil {
			log.Printf("[Alert] 广播失败: %v", err)
		}
	}
}

// AddAlert 添加一条告警并广播
func (a *AlertService) AddAlert(alert model.Alert) {
	a.mu.Lock()
	// 填充时间 (如果未设置)
	if alert.Time == "" {
		alert.Time = time.Now().Format(time.RFC3339)
	}

	// 追加到存储
	a.alerts = append(a.alerts, &alert)

	// 容量检查: 超出限制时裁剪旧告警
	if len(a.alerts) > a.maxAlerts {
		cutoff := a.maxAlerts / 4
		a.alerts = a.alerts[cutoff:]
	}
	a.mu.Unlock()

	log.Printf("[Alert] 新告警: [%s] %s - %s (PID=%d)",
		alert.Severity, alert.Type, alert.Description, alert.PID)

	// WebSocket 广播
	a.Broadcast(model.WSMessage{
		Type:    "alert",
		Payload: alert,
	})
}

// GetAlerts 获取所有告警
func (a *AlertService) GetAlerts() []*model.Alert {
	return a.GetAlertsWithFilter("")
}

// GetAlertsWithFilter 获取告警 (支持分级过滤)
// severity 为空字符串时返回全部
func (a *AlertService) GetAlertsWithFilter(severity string) []*model.Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if severity == "" {
		// 返回全部告警副本
		result := make([]*model.Alert, len(a.alerts))
		copy(result, a.alerts)
		return result
	}

	// 按严重级别过滤
	var result []*model.Alert
	for _, alert := range a.alerts {
		if string(alert.Severity) == severity {
			result = append(result, alert)
		}
	}
	return result
}

// GetAlertCount 获取告警总数
func (a *AlertService) GetAlertCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.alerts)
}

// GetAlertCountBySeverity 按严重级别统计告警数量
func (a *AlertService) GetAlertCountBySeverity() map[string]int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	counts := make(map[string]int)
	for _, alert := range a.alerts {
		counts[string(alert.Severity)]++
	}
	return counts
}

// ClearAlerts 清除所有告警
func (a *AlertService) ClearAlerts() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	count := len(a.alerts)
	a.alerts = make([]*model.Alert, 0, 1024)
	log.Printf("[Alert] 清除全部告警，共 %d 条", count)

	// 广播清除事件
	a.Broadcast(model.WSMessage{
		Type:    "alert_clear",
		Payload: map[string]int{"cleared": count},
	})

	return count
}

// ConsumeFromMonitor 从 MonitorService 的告警通道消费告警
// 建议在单独的 goroutine 中调用
func (a *AlertService) ConsumeFromMonitor(alertCh <-chan model.Alert) {
	log.Println("[Alert] 开始消费监控告警通道...")
	for alert := range alertCh {
		a.AddAlert(alert)
	}
}

// GetRecentAlerts 获取最近 N 条告警
func (a *AlertService) GetRecentAlerts(n int) []*model.Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()

	total := len(a.alerts)
	if n > total {
		n = total
	}

	result := make([]*model.Alert, n)
	copy(result, a.alerts[total-n:])
	return result
}
