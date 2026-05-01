package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/handler"
	"github.com/neko4linux/eBPF-Multi-Agent/backend/internal/service"
)

func main() {
	// 初始化核心服务
	monitorSvc := service.NewMonitorService()
	alertSvc := service.NewAlertService()
	agentSvc := service.NewAgentService()
	correlator := service.NewCrossLayerCorrelator()
	mlSvc := service.NewMLService()

	// 启动监控
	go monitorSvc.Start()
	go correlator.Run()

	// 初始化 HTTP Handler
	h := handler.NewHandler(monitorSvc, alertSvc, agentSvc, correlator, mlSvc)

	// 启动 Gin 服务
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := h.SetupRouter(port)

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Printf("🛡️  eBPF Multi-Agent Backend starting on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
		log.Fatal(err)
	}
}
