// ml_service.go - 机器学习服务接口
// 提供 ML 分类能力的 Go 桩实现，可调用 Python 子进程进行实际推理
// 如果 Python ML 服务不可用，回退到基于规则的启发式分类

package service

import (
	"encoding/json"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/model"
)

// ClassifyResult ML 分类结果
type ClassifyResult struct {
	AnomalyType string  `json:"anomaly_type"`
	Confidence  float64 `json:"confidence"`
	IsAnomaly   bool    `json:"is_anomaly"`
}

// MLService 机器学习服务
type MLService struct {
	mu           sync.RWMutex
	available    bool   // Python ML 服务是否可用
	pythonPath   string // Python 解释器路径
	scriptPath   string // ML 推理脚本路径
	classifyFunc func(features map[string]interface{}) ClassifyResult // 可替换的分类函数
}

// NewMLService 创建 ML 服务实例
// 自动检测 Python 环境和 ML 脚本是否可用
func NewMLService() *MLService {
	svc := &MLService{
		pythonPath: "python3",
		scriptPath: "/opt/ebpf-ml/classify.py", // 默认路径
	}
	svc.detectAvailability()
	return svc
}

// detectAvailability 检测 ML 环境是否可用
func (s *MLService) detectAvailability() {
	// 检查 python3 是否存在
	if _, err := exec.LookPath(s.pythonPath); err != nil {
		log.Println("[ML] Python3 未找到，ML 服务将使用规则回退模式")
		s.available = false
		return
	}

	// 尝试导入 ML 依赖
	cmd := exec.Command(s.pythonPath, "-c", "import sklearn; import numpy; print('ok')")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ML] ML 依赖不可用: %v, 输出: %s", err, string(output))
		s.available = false
		return
	}

	s.available = true
	log.Println("[ML] ML 服务就绪 (Python + sklearn)")
}

// IsAvailable 返回 ML 服务是否可用
func (s *MLService) IsAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.available
}

// Classify 对给定特征进行分类
// 优先使用 Python ML 服务，不可用时回退到规则引擎
func (s *MLService) Classify(features map[string]interface{}) ClassifyResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.available {
		result, err := s.classifyViaPython(features)
		if err == nil {
			return result
		}
		log.Printf("[ML] Python 分类失败，回退到规则: %v", err)
	}

	// 规则回退
	return s.classifyByRules(features)
}

// ClassifyEvent 对系统事件进行分类
func (s *MLService) ClassifyEvent(evt model.Event) ClassifyResult {
	features := map[string]interface{}{
		"event_type": string(evt.Type),
		"detail":     evt.Detail,
		"pid":        evt.PID,
		"agent":      evt.Agent,
		"timestamp":  evt.Timestamp,
	}
	return s.Classify(features)
}

// ClassifyPrompt 对 Prompt 事件进行分类
func (s *MLService) ClassifyPrompt(prompt model.PromptEvent) ClassifyResult {
	features := map[string]interface{}{
		"content":    prompt.Content,
		"direction":  prompt.Direction,
		"endpoint":   prompt.Endpoint,
		"pid":        prompt.PID,
		"agent":      prompt.Agent,
		"timestamp":  prompt.Timestamp,
	}
	return s.Classify(features)
}

// classifyViaPython 通过 Python 子进程进行 ML 分类
func (s *MLService) classifyViaPython(features map[string]interface{}) (ClassifyResult, error) {
	// 将特征序列化为 JSON
	featureJSON, err := json.Marshal(features)
	if err != nil {
		return ClassifyResult{}, err
	}

	// 调用 Python 分类脚本
	ctx := make(chan struct{})
	var result ClassifyResult
	var cmdErr error

	go func() {
		defer close(ctx)
		cmd := exec.Command(s.pythonPath, s.scriptPath, string(featureJSON))
		output, err := cmd.CombinedOutput()
		if err != nil {
			cmdErr = err
			return
		}
		cmdErr = json.Unmarshal(output, &result)
	}()

	// 等待结果，最多 5 秒超时
	select {
	case <-ctx:
		if cmdErr != nil {
			return ClassifyResult{}, cmdErr
		}
		return result, nil
	case <-time.After(5 * time.Second):
		return ClassifyResult{}, &mlTimeoutError{"ML 推理超时 (5s)"}
	}
}

// classifyByRules 基于规则的启发式分类 (ML 不可用时的回退方案)
func (s *MLService) classifyByRules(features map[string]interface{}) ClassifyResult {
	detail, _ := features["detail"].(string)
	content, _ := features["content"].(string)
	combined := detail + " " + content

	// Shell 关键词 → Shell Spawn
	shellKeywords := []string{"bash", "/bin/sh", "sh -c", "cmd.exe"}
	for _, kw := range shellKeywords {
		if contains(combined, kw) {
			return ClassifyResult{
				AnomalyType: string(model.AnomalyShellSpawn),
				Confidence:  0.75,
				IsAnomaly:   true,
			}
		}
	}

	// 敏感文件 → 敏感文件访问
	sensitiveKeywords := []string{"/etc/shadow", "/etc/passwd", ".ssh/", "private"}
	for _, kw := range sensitiveKeywords {
		if contains(combined, kw) {
			return ClassifyResult{
				AnomalyType: string(model.AnomalySensitiveFile),
				Confidence:  0.80,
				IsAnomaly:   true,
			}
		}
	}

	// 网络后门关键词
	netKeywords := []string{"nc -l", "reverse", "curl ", "wget ", "socat"}
	for _, kw := range netKeywords {
		if contains(combined, kw) {
			return ClassifyResult{
				AnomalyType: string(model.AnomalySuspiciousNetwork),
				Confidence:  0.65,
				IsAnomaly:   true,
			}
		}
	}

	// Prompt 注入
	injectKeywords := []string{"ignore previous", "you are now", "forget everything"}
	for _, kw := range injectKeywords {
		if contains(combined, kw) {
			return ClassifyResult{
				AnomalyType: string(model.AnomalyPromptInjection),
				Confidence:  0.70,
				IsAnomaly:   true,
			}
		}
	}

	// 无异常
	return ClassifyResult{
		AnomalyType: "",
		Confidence:  0.10,
		IsAnomaly:   false,
	}
}

// =============================================
// 辅助类型和函数
// =============================================

// mlTimeoutError ML 超时错误
type mlTimeoutError struct {
	msg string
}

func (e *mlTimeoutError) Error() string {
	return e.msg
}

// contains 不区分大小写子串匹配
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsIgnoreCase(s, substr))
}

func containsIgnoreCase(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
