package handler

import (
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSMiddleware 返回 CORS 跨域中间件
// 开发阶段允许所有来源，生产环境应配置具体域名
func CORSMiddleware() gin.HandlerFunc {
	config := cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
	return cors.New(config)
}

// LoggingMiddleware 请求日志中间件
// 记录每个请求的方法、路径、状态码、耗时和客户端 IP
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// 处理请求
		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		if query != "" {
			path = path + "?" + query
		}

		log.Printf("[HTTP] %3d | %13v | %15s | %-7s %s",
			status, latency, clientIP, method, path)
	}
}

// RecoveryMiddleware panic 恢复中间件
// 捕获 handler 中的 panic 并返回 500 错误，防止服务崩溃
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] 捕获到 panic: %v", err)
				c.AbortWithStatusJSON(500, gin.H{
					"error": "内部服务器错误",
				})
			}
		}()
		c.Next()
	}
}
