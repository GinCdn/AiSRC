package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	// 内嵌 IANA 时区库：Windows/裸容器无系统 zoneinfo 时 LoadLocation("Asia/Shanghai") 也能成功
	_ "time/tzdata"

	"AiSRC/config"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/router"
	"AiSRC/service/engine"

	"github.com/gin-gonic/gin"
)

// isAddrInUse 判断监听失败是否由「端口已被占用」引起。
// 跨平台双保险：优先比对 errno，其次回退到错误文案
// （Windows 为 "Only one usage of each socket address..."，类 Unix 为 "address already in use"）。
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "only one usage") || strings.Contains(msg, "address already in use")
}

// migrateModels 返回需要自动迁移的全部业务实体。
// 顺序保持「主表 → 从表」，便于 MySQL 初始化时的直观对照。
func migrateModels() []interface{} {
	return []interface{}{
		&model.Admin{},
		&model.SystemSettings{},
		&model.Task{},
		&model.Target{},
		&model.Finding{},
		&model.Review{},
		&model.Killsweep{},
		&model.TaskEvent{},
		&model.Intel{},
	}
}

func main() {
	// 1. 读取配置（失败即 panic，与 GinBlog 行为一致，避免带病启动）。
	config.Init()

	// 2. 初始化日志（必须在其他组件之前，后续组件都会写日志）。
	global.Log = core.InitLogger(config.AppConfig.Logger)
	global.Log.Infof("[boot] AiSRC 启动中，环境=%s", config.AppConfig.System.Env)

	// 2.1 按配置切换 gin 运行模式：release 下不再打印逐条路由表与调试告警。
	// 必须在 router.InitRouter()（内部 gin.New）之前调用才生效。
	if config.AppConfig.System.Env == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 3. 初始化数据库并迁移表结构。
	if err := core.MysqlInit(); err != nil {
		global.Log.Fatalf("[boot] %v", err)
	}
	if err := core.AutoMigrate(migrateModels()...); err != nil {
		global.Log.Fatalf("[boot] 数据表迁移失败：%v", err)
	}
	global.Log.Info("[boot] 数据表迁移完成")

	// 4. 初始化 JWT 签名密钥。
	if err := core.InitJWT(); err != nil {
		global.Log.Fatalf("[boot] %v", err)
	}

	// 5. 初始化全局设置行（首次启动写入 id=global 的默认行）。
	if err := engine.SaveSystemSettings(engine.LoadSystemSettings()); err != nil {
		global.Log.Warnf("[boot] 初始化全局设置失败：%v", err)
	}
	// 5.1 把设置里的运行时开关（允许 Shell 执行 / 记录噪音事件）同步进引擎，
	//     否则这些开关只在「保存设置」那一刻生效，重启后回弹默认值。
	engine.ApplyRuntimeFlags(engine.LoadSystemSettings())

	// 6. 恢复上次运行中的任务。
	engine.ManagerInstance().RestoreOnStartup()

	// 7. 启动 HTTP 服务。
	// 先显式 Listen 占住端口，成功后才打印「已启动」——否则端口冲突时会出现
	// 「已启动」紧跟着 fatal 的误导日志，让人以为服务真的起来过。
	addr := fmt.Sprintf("%s:%s", config.AppConfig.System.Host, config.AppConfig.System.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		if isAddrInUse(err) {
			global.Log.Errorf("[boot] 端口 %s 已被占用，无法启动。常见原因是上一个 AiSRC 进程尚未退出；"+
				"Windows 可执行 `taskkill /F /IM aisrc-server.exe` 结束残留进程，或在配置中改 system.port。",
				config.AppConfig.System.Port)
		}
		global.Log.Fatalf("[boot] HTTP 服务启动失败：%v", err)
	}

	srv := &http.Server{
		Handler:           router.InitRouter(),
		ReadHeaderTimeout: 20 * time.Second,
		// WebSocket 与 AI 流式响应需要长连接，因此不设 WriteTimeout。
		IdleTimeout: 120 * time.Second,
	}

	global.Log.Infof("[boot] HTTP 服务已启动：http://%s", addr)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			global.Log.Fatalf("[boot] HTTP 服务异常退出：%v", err)
		}
	}()

	// 8. 优雅退出：先停调度器（回写任务状态），再关 HTTP。
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	global.Log.Info("[boot] 收到退出信号，开始优雅关闭…")

	engine.ManagerInstance().Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		global.Log.Warnf("[boot] HTTP 服务关闭超时：%v", err)
	}
	global.Log.Info("[boot] 已安全退出")
}
