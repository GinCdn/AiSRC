package router

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"AiSRC/api"
	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/global"
	"AiSRC/middleware"
	"AiSRC/result"
	"AiSRC/service/engine"

	"github.com/gin-gonic/gin"
)

// InitRouter 装配全部 HTTP 路由。
//
// 路由分组策略参照 GinBlog：公开端点在最外层，受保护端点统一挂 AuthMiddleware，
// 需要在鉴权失败时仍给出业务错误码的端点（如 auth/status、stream）单独处理。
func InitRouter() *gin.Engine {
	r := gin.New()
	// 与原版 FastAPI 行为对齐：路径存在但方法不支持时返回 405 而非 404。
	r.HandleMethodNotAllowed = true
	r.Use(gin.Recovery())
	r.Use(middleware.Cors())
	r.Use(accessLog())
	r.Use(recoverToResult())

	// 前端构建产物托管（/ 与 /assets/* 及品牌图标）。
	registerStatic(r)

	// 未匹配路由：非 API 的 GET 回落到前端入口（支持浏览器刷新深层路由），
	// 其余统一走业务响应体 {"detail": "资源不存在"} + 404。
	r.NoRoute(func(c *gin.Context) {
		if serveSPA(c) {
			return
		}
		result.Failed(c, result.NotFound, result.SubResourceNotFound)
	})
	r.NoMethod(func(c *gin.Context) {
		result.Failed(c, result.MethodNotAllowed, result.SubMethodNotAllowed)
	})

	// ---------- 公开端点 ----------

	// 健康探针：兼容 AutoHunter 的 GET /health 与前端使用的 GET /api/health。
	r.GET("/health", api.Health)
	r.GET("/api/health", api.Health)
	r.GET("/api/about", api.About)

	// 鉴权状态与登录：未登录也要能拿到 auth_enabled / role 用于前端引导。
	//
	// ⚠️ status / logout 必须挂 OptionalAuthMiddleware：
	// 它「解析身份但不拦截」，是 /api/auth/status 能把令牌换成 role 的唯一途径。
	// 曾经漏挂 → status 恒返回 role=none → 前端每次刷新都判定未登录、弹出登录框。
	r.GET("/api/auth/status", middleware.OptionalAuthMiddleware(), api.AuthStatus)
	// 图形验证码：未认证可访问（连续失败达阈值后登录才需要它）。
	r.GET("/api/auth/captcha", api.Captcha)
	r.POST("/api/auth/login", api.Login)
	r.POST("/api/auth/logout", middleware.OptionalAuthMiddleware(), api.Logout)

	// 壁纸原图与设置 UI 资源：需能被 <img> 直接引用（浏览器不带自定义头），
	// 因此放在鉴权之外，仅做角色感知的脱敏。
	r.GET("/api/settings/ui/wallpaper/raw", api.ServeWallpaper)

	// WebSocket 实时事件流：握手鉴权在 handler 内部完成（支持 ?token= 查询参数）。
	r.GET("/api/tasks/:task_id/stream", engine.StreamHandler)

	// ---------- 受保护端点 ----------

	authed := r.Group("")
	authed.Use(middleware.AuthMiddleware())
	{
		registerTaskRoutes(authed)
		registerFindingRoutes(authed)
		registerVulnRoutes(authed)
		registerIntelRoutes(authed)
		registerProxyRoutes(authed)
		registerSettingsRoutes(authed)
		registerRuntimeLogRoutes(authed)
		registerBackupRoutes(authed)
		registerUpdateRoutes(authed)
	}

	return r
}

// registerTaskRoutes 任务与目标相关路由。
func registerTaskRoutes(g *gin.RouterGroup) {
	tasks := g.Group("/api/tasks")
	{
		tasks.POST("", api.CreateTask)
		tasks.GET("", api.ListTasks)
		tasks.PATCH("/batch/top", api.BatchToggleTaskTop)

		tasks.GET("/:task_id", api.GetTask)
		tasks.PATCH("/:task_id", api.UpdateTask)
		tasks.DELETE("/:task_id", api.DeleteTask)
		tasks.POST("/:task_id/models", api.ProbeTaskModels)
		tasks.PATCH("/:task_id/top", api.ToggleTaskTop)

		tasks.POST("/:task_id/start", api.StartTask)
		tasks.POST("/:task_id/pause", api.PauseTask)
		tasks.POST("/:task_id/stop", api.StopTask)

		tasks.GET("/:task_id/board", api.TaskBoard)
		tasks.GET("/:task_id/targets", api.TaskTargets)
		tasks.GET("/:task_id/hosts", api.TaskHosts)
		tasks.POST("/:task_id/targets/:target_id/skip", api.SkipTarget)
		tasks.POST("/:task_id/targets/:target_id/rescan", api.RescanTarget)
		tasks.POST("/:task_id/targets/:target_id/directive", api.InjectDirective)
		tasks.GET("/:task_id/targets/:target_id/trace", api.TargetTrace)
		tasks.POST("/:task_id/escalations/:finding_id/cancel", api.CancelEscalation)

		tasks.GET("/:task_id/killsweeps", api.ListKillsweeps)
		tasks.POST("/:task_id/killsweeps/:killsweep_id/invalidate", api.InvalidateKillsweep)
		tasks.POST("/:task_id/killsweeps/:killsweep_id/retry", api.RetryKillsweep)

		tasks.GET("/:task_id/findings", api.ListFindings)
		tasks.GET("/:task_id/results", api.ListResults)
		tasks.GET("/:task_id/deepen-list", api.ListDeepen)
		tasks.GET("/:task_id/review-queue", api.ListReviewQueue)
		tasks.GET("/:task_id/submit-list", api.ListSubmitList)
		tasks.GET("/:task_id/rejected", api.ListRejected)
		tasks.GET("/:task_id/archived", api.ListArchived)
	}
}

// registerFindingRoutes 漏洞详情、用户复审与 AI 报告助手路由。
func registerFindingRoutes(g *gin.RouterGroup) {
	g.GET("/api/findings/:finding_id", api.GetFinding)
	g.POST("/api/findings/:finding_id/assistant", api.FindingAssistant)
	g.POST("/api/findings/:finding_id/assistant/stream", api.FindingAssistantStream)

	results := g.Group("/api/results")
	{
		results.PATCH("/:finding_id", api.UpdateResult)
		results.POST("/:finding_id/restore", api.RestoreResult)
		results.POST("/:finding_id/deepen", api.DeepenResult)
	}
}

// registerVulnRoutes 漏洞库路由。
func registerVulnRoutes(g *gin.RouterGroup) {
	vulns := g.Group("/api/vulns")
	{
		vulns.GET("/stats", api.VulnStatsHandler)
		vulns.GET("", api.ListVulns)
		vulns.PATCH("/batch/top", api.BatchToggleVulnTop)
		vulns.PATCH("/:vuln_id/top", api.ToggleVulnTop)
	}
}

// registerIntelRoutes 情报路由。
func registerIntelRoutes(g *gin.RouterGroup) {
	intel := g.Group("/api/intel")
	{
		intel.GET("/stats", api.IntelStatsHandler)
		intel.GET("", api.ListIntel)
		intel.GET("/curate", api.IntelCuratePreview)
		intel.POST("/curate", api.CurateIntel)
		intel.DELETE("/:intel_id", api.DeleteIntel)
		intel.DELETE("", api.ClearIntel)
	}
}

// registerProxyRoutes 代理池路由。
func registerProxyRoutes(g *gin.RouterGroup) {
	proxy := g.Group("/api/proxy")
	{
		proxy.GET("", api.ListProxies)
		proxy.POST("", api.CreateProxy)
		proxy.PUT("/toggle", api.ToggleProxyPool)
		proxy.PUT("/:proxy_id", api.UpdateProxy)
		proxy.DELETE("/:proxy_id", api.DeleteProxy)
		proxy.POST("/import", api.ImportProxies)
		proxy.POST("/test", api.TestProxies)
	}
}

// registerSettingsRoutes 全局设置与工作目录路由。
func registerSettingsRoutes(g *gin.RouterGroup) {
	settings := g.Group("/api/settings")
	{
		settings.GET("", api.GetSettings)
		settings.PUT("", api.UpdateSettings)
		settings.POST("/models", api.ProbeSettingsModels)
		settings.GET("/provider-health", api.ProviderHealthHandler)
		settings.POST("/test-llm", api.TestLLM)
		settings.POST("/kali/test", api.TestKali)
		settings.POST("/llm/balance", api.LLMBalanceHandler)
		settings.GET("/workdir/stats", api.WorkdirStatsHandler)
		settings.POST("/workdir/cleanup", api.CleanupWorkdirHandler)
		settings.GET("/ui/wallpaper", api.WallpaperInfo)
		settings.POST("/ui/wallpaper", api.UploadWallpaper)
		settings.DELETE("/ui/wallpaper", api.DeleteWallpaper)
	}
}

// registerRuntimeLogRoutes 运行日志路由。
func registerRuntimeLogRoutes(g *gin.RouterGroup) {
	logs := g.Group("/api/runtime-logs")
	{
		logs.GET("/stats", api.RuntimeLogStatsHandler)
		logs.GET("", api.ListRuntimeLogs)
	}
}

// registerBackupRoutes 备份与快照路由。
func registerBackupRoutes(g *gin.RouterGroup) {
	backup := g.Group("/api/backup")
	{
		backup.GET("/status", api.BackupStatusHandler)
		backup.POST("/snapshot", api.CreateSnapshotHandler)
		backup.POST("/export", api.ExportBackupHandler)
		backup.GET("/snapshots/:name", api.DownloadSnapshotHandler)
		backup.POST("/restore", api.RestoreBackupHandler)
	}
}

// registerUpdateRoutes 在线更新路由。
func registerUpdateRoutes(g *gin.RouterGroup) {
	update := g.Group("/api/update")
	{
		update.GET("/check", api.CheckUpdateHandler)
		update.GET("/status", api.UpdateStatusHandler)
		update.POST("/run", api.RunUpdateHandler)
	}
}

// registerStatic 托管前端构建产物。
// 与原版 AutoHunter 一致：/assets/* 为带内容哈希的静态资源（可长期缓存），
// / 返回 index.html（不缓存），并内联提供品牌图标。
func registerStatic(r *gin.Engine) {
	webDir := config.WebDir()
	assetsDir := filepath.Join(webDir, "assets")
	if info, err := os.Stat(assetsDir); err == nil && info.IsDir() {
		r.Static("/assets", assetsDir)
	}

	// 品牌图标：与页面一致的内联 SVG，两个路径返回同一份，避免浏览器 404 噪音。
	favicon := func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=86400")
		c.Data(http.StatusOK, "image/svg+xml; charset=utf-8", []byte(constant.FaviconSVG))
	}
	r.GET("/favicon.svg", favicon)
	r.GET("/favicon.ico", favicon)

	r.GET("/", func(c *gin.Context) {
		if !serveIndex(c) {
			c.JSON(http.StatusOK, gin.H{"msg": "前端未构建，请运行 vite build 或使用 Docker 镜像"})
		}
	})
}

// serveIndex 输出前端入口文件。返回 false 表示产物不存在。
func serveIndex(c *gin.Context) bool {
	index := filepath.Join(config.WebDir(), "index.html")
	info, err := os.Stat(index)
	if err != nil || info.IsDir() {
		return false
	}
	c.Header("Cache-Control", "no-cache")
	c.File(index)
	return true
}

// serveSPA 把非 API 的 GET 请求回落到前端入口，使浏览器刷新深层路由不会 404。
// 返回 true 表示已处理该请求。
func serveSPA(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet {
		return false
	}
	path := c.Request.URL.Path
	// API、健康探针、WebSocket 不参与回落。
	if path == "/api" || strings.HasPrefix(path, "/api/") ||
		path == "/health" || strings.HasPrefix(path, "/health/") {
		return false
	}
	// 带扩展名的路径视为静态资源请求，缺失时按 404 处理，避免把 .js/.css 误判成页面。
	if ext := filepath.Ext(path); ext != "" {
		return false
	}
	return serveIndex(c)
}

// accessLog 统一访问日志（跳过健康探针与 WebSocket 升级请求的噪音）。
func accessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		path := c.Request.URL.Path
		if path == "/health" || path == "/api/health" {
			return
		}
		// 静态资源与图标噪音较大，不记访问日志。
		if strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/favicon") {
			return
		}
		if global.Log == nil {
			return
		}
		global.Log.Infof("[http] %s %s %d %s", c.Request.Method, path, c.Writer.Status(), c.ClientIP())
	}
}

// recoverToResult 把 panic 收敛为统一的业务错误响应，避免泄露堆栈。
func recoverToResult() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				if global.Log != nil {
					global.Log.Errorf("[panic] %s %s: %v", c.Request.Method, c.Request.URL.Path, err)
				}
				if !c.Writer.Written() {
					result.FailedWithMsg(c, result.InternalError, "服务器内部错误")
					c.AbortWithStatus(http.StatusInternalServerError)
				}
			}
		}()
		c.Next()
	}
}
