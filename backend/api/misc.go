package api

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/middleware"
	"AiSRC/model"
	"AiSRC/result"
	"AiSRC/service"
	"AiSRC/service/engine"
	"AiSRC/utils"

	"github.com/gin-gonic/gin"
)

// ===== 鉴权 =====

// AuthStatus 当前鉴权状态。
// GET /api/auth/status
func AuthStatus(c *gin.Context) {
	role := currentRole(c)
	username := ""
	if identity := middleware.CurrentIdentity(c); identity != nil {
		username = identity.Username
	}
	status := service.BuildAuthStatus(role, username)
	// 附加登录守卫状态：前端据此在打开登录框时就决定是否直接展示验证码，
	// 刷新页面也不会把「已触发验证码」的进度丢掉。
	ip := utils.ClientIP(c)
	status.LoginFailures = service.LoginFailures(ip)
	status.CaptchaRequired = status.LoginFailures >= service.CaptchaThreshold
	status.CaptchaDigits = service.CaptchaDigits
	result.Success(c, status)
}

// Captcha 下发图形验证码。
// GET /api/auth/captcha
//
// 明文只留在服务端，接口只返回渲染好的图片（data URL）与验证码 ID。
func Captcha(c *gin.Context) {
	id, code, ttl := service.NewCaptcha()
	result.Success(c, gin.H{
		"captcha_id":    id,
		"captcha_image": service.CaptchaImage(code),
		"expires_in":    int(ttl.Seconds()),
		"digits":        service.CaptchaDigits,
		"threshold":     service.CaptchaThreshold,
	})
}

// Login 账号密码登录（连续失败达阈值后强制图形验证码）。
// POST /api/auth/login
func Login(c *gin.Context) {
	var dto LoginRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	ip := utils.ClientIP(c)

	// 连续失败达阈值后必须先过验证码；VerifyCaptcha 一次性消费，
	// 同一张图既不能重复使用，也不能被反复试探。
	if service.CaptchaRequired(ip) && !service.VerifyCaptcha(dto.CaptchaID, dto.CaptchaCode) {
		failures := service.RecordLoginFailure(ip)
		result.FailedWithPayload(c, result.BadRequest, "验证码错误或已失效，请重新输入", gin.H{
			"captcha_required": true,
			"login_failures":   failures,
			"captcha_digits":   service.CaptchaDigits,
			"threshold":        service.CaptchaThreshold,
		})
		return
	}

	outcome, err := service.Login(dto.Password, dto.Username)
	if err != nil {
		if errors.Is(err, service.ErrPasswordMismatch) {
			failures := service.RecordLoginFailure(ip)
			result.FailedWithPayload(c, result.Unauthorized, err.Error(), gin.H{
				"captcha_required": failures >= service.CaptchaThreshold,
				"login_failures":   failures,
				"captcha_digits":   service.CaptchaDigits,
				"threshold":        service.CaptchaThreshold,
			})
			return
		}
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}

	service.ClearLoginFailures(ip)
	// Cookie 名与原版 AutoHunter 对齐（ah_api_token）；aisrc_token 双写作为兼容别名。
	setAuthCookies(c, outcome.Token, int(outcome.ExpiresIn))
	result.Success(c, outcome)
}

// setAuthCookies 写入鉴权 Cookie（双名），maxAge<0 表示清除。
func setAuthCookies(c *gin.Context, token string, maxAge int) {
	for _, name := range []string{"ah_api_token", "aisrc_token"} {
		c.SetCookie(name, token, maxAge, "/", "", false, true)
	}
}

// Logout 注销（递增令牌版本）。
// POST /api/auth/logout
func Logout(c *gin.Context) {
	username := ""
	if identity := middleware.CurrentIdentity(c); identity != nil {
		username = identity.Username
	}
	if username == "" {
		username = "admin"
	}
	if err := service.Logout(username); err != nil {
		// 注销失败不阻塞前端清理本地令牌。
		global.Log.Warnf("注销失败: %v", err)
	}
	setAuthCookies(c, "", -1)
	result.Success(c, gin.H{"ok": true})
}

// ===== 系统 =====

// Health 健康检查。
// GET /health
func Health(c *gin.Context) {
	dbOK := core.Db != nil
	if dbOK {
		if sqlDB, err := core.Db.DB(); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			dbOK = sqlDB.PingContext(ctx) == nil
		}
	}
	status := "ok"
	if !dbOK {
		status = "degraded"
	}
	// 原版契约是 {"ok": true}；这里保留 ok 字段并附加诊断信息，
	// 保证兼容原版前端（只判断 HTTP 状态与 ok）的同时便于运维排查。
	result.Success(c, gin.H{
		"ok":      true,
		"status":  status,
		"db":      dbOK,
		"version": constant.Version,
		"time":    utils.ToCSTISO(time.Now()),
	})
}

// About 系统信息。
// GET /api/about
func About(c *gin.Context) {
	var taskCount, findingCount, targetCount int64
	core.Db.Model(&model.Task{}).Count(&taskCount)
	core.Db.Model(&model.Finding{}).Count(&findingCount)
	core.Db.Model(&model.Target{}).Count(&targetCount)
	settings := engine.LoadSystemSettings()
	// 原版字段（name/description/author/license/credit）保持不变，另附加运行态信息。
	result.Success(c, gin.H{
		"name":           constant.AppName,
		"version":        constant.Version,
		"description":    constant.AppDescription,
		"author":         constant.AppAuthor,
		"license":        constant.AppLicense,
		"credit":         constant.Credit,
		"auth_required":  !middleware.AuthDisabled(),
		"auth_enabled":   !middleware.AuthDisabled(),
		"llm_mode":       settings.LLM.Mode,
		"default_engine": engine.NormalizeEngine(settings.Defaults.Engine),
		"counts": gin.H{
			"tasks":    taskCount,
			"targets":  targetCount,
			"findings": findingCount,
		},
		"server_time": utils.ToCSTISO(time.Now()),
	})
}

// ===== 情报 =====

// IntelStatsHandler 情报统计。
// GET /api/intel/stats
func IntelStatsHandler(c *gin.Context) {
	result.Success(c, service.IntelStats())
}

// ListIntel 情报列表。
// GET /api/intel
func ListIntel(c *gin.Context) {
	filter := service.IntelFilter{
		Kind:       queryString(c, "kind"),
		Query:      queryString(c, "q"),
		SourceHost: queryString(c, "source_host"),
		Limit:      queryInt(c, "limit", 0),
		Offset:     queryInt(c, "offset", 0),
	}
	items, total, err := service.QueryIntel(filter)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, filter.Limit, filter.Offset)
}

// IntelCuratePreview 情报整理预览。
// GET /api/intel/curate
func IntelCuratePreview(c *gin.Context) {
	result.Success(c, service.CurateIntelPreview())
}

// CurateIntel 执行情报整理。
// POST /api/intel/curate
func CurateIntel(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	result.Success(c, service.CurateIntel())
}

// DeleteIntel 删除单条情报。
// DELETE /api/intel/:intel_id
func DeleteIntel(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	if err := service.DeleteIntel(pathParam(c, "intel_id")); err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true})
}

// ClearIntel 清空情报库。
// DELETE /api/intel
func ClearIntel(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	affected, err := service.ClearIntel()
	if err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true, "removed": affected})
}

// ===== 代理池 =====

// ListProxies 代理列表。
// GET /api/proxy
func ListProxies(c *gin.Context) {
	result.Success(c, service.ProxyList())
}

// CreateProxy 新增代理。
// POST /api/proxy
func CreateProxy(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto ProxyCreateRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	enabled := true
	if dto.Enabled != nil {
		enabled = *dto.Enabled
	}
	item, err := service.AddProxy(model.ProxyItem{
		Name: dto.Name, Protocol: dto.Protocol, Host: dto.Host, Port: dto.Port,
		Username: dto.Username, Password: dto.Password, Enabled: enabled,
	})
	if err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, item)
}

// UpdateProxy 更新代理。
// PUT /api/proxy/:proxy_id
func UpdateProxy(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	proxyID := pathParam(c, "proxy_id")
	var dto ProxyUpdateRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	patch := map[string]any{}
	if dto.Name != nil {
		patch["name"] = *dto.Name
	}
	if dto.Protocol != nil {
		patch["protocol"] = *dto.Protocol
	}
	if dto.Host != nil {
		patch["host"] = *dto.Host
	}
	if dto.Port != nil {
		patch["port"] = *dto.Port
	}
	if dto.Username != nil {
		patch["username"] = *dto.Username
	}
	if dto.Password != nil {
		patch["password"] = *dto.Password
	}
	if dto.Enabled != nil {
		patch["enabled"] = *dto.Enabled
	}
	item, err := service.UpdateProxy(proxyID, patch)
	if err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, item)
}

// DeleteProxy 删除代理。
// DELETE /api/proxy/:proxy_id
func DeleteProxy(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	if err := service.DeleteProxy(pathParam(c, "proxy_id")); err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, gin.H{"ok": true})
}

// ToggleProxyPool 代理池总开关。
// PUT /api/proxy/toggle
func ToggleProxyPool(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto ProxyToggleRequest
	if err := c.ShouldBindJSON(&dto); err != nil || dto.Enabled == nil {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	view, err := service.ToggleProxyPool(*dto.Enabled)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, view)
}

// ImportProxies 批量导入代理。
// POST /api/proxy/import
func ImportProxies(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto ProxyImportRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	raw := dto.Raw
	if strings.TrimSpace(raw) == "" {
		raw = dto.Content
	}
	if strings.TrimSpace(raw) == "" {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	view, err := service.ImportProxies(raw, dto.Replace)
	if err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, view)
}

// TestProxies 代理连通性测试。
// POST /api/proxy/test
func TestProxies(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto ProxyTestRequest
	_ = c.ShouldBindJSON(&dto)
	result.Success(c, service.TestProxies(dto.IDs))
}

// ===== 设置 =====

// GetSettings 读取全局设置。
// GET /api/settings
func GetSettings(c *gin.Context) {
	result.Success(c, service.LoadSettingsView())
}

// UpdateSettings 更新全局设置。
// PUT /api/settings
func UpdateSettings(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var payload map[string]any
	if err := c.ShouldBindJSON(&payload); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	update := settingsUpdateFromPayload(payload)
	view, err := service.SaveSettings(update)
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "保存设置失败："+err.Error())
		return
	}
	global.BumpConfigVersion()
	result.Success(c, view)
}

// ProbeSettingsModels 列出全局端点可用模型。
// POST /api/settings/models
func ProbeSettingsModels(c *gin.Context) {
	var dto struct {
		BaseURL  *string `json:"base_url"`
		APIKey   *string `json:"api_key"`
		Protocol *string `json:"protocol"`
		KeyRef   *string `json:"key_ref"`
	}
	_ = c.ShouldBindJSON(&dto)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	models, err := service.ListAvailableModels(ctx, derefOr(dto.BaseURL, ""), derefOr(dto.APIKey, ""), derefOr(dto.Protocol, ""), derefOr(dto.KeyRef, ""))
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "模型列表获取失败："+err.Error())
		return
	}
	result.Success(c, gin.H{"models": ensureSlice(models)})
}

// LLMBalanceHandler 查询中转站余额（NewAPI / One API 系 billing 兼容接口）。
// POST /api/settings/llm/balance
func LLMBalanceHandler(c *gin.Context) {
	var dto struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		KeyRef  string `json:"key_ref"`
	}
	_ = c.ShouldBindJSON(&dto)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	info, err := service.LLMBalance(ctx, dto.BaseURL, dto.APIKey, dto.KeyRef)
	if err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, info)
}

// ProviderHealthHandler 端点健康快照。
// GET /api/settings/provider-health
func ProviderHealthHandler(c *gin.Context) {
	result.Success(c, service.ProviderHealth())
}

// TestLLM 测试模型端点连通性。
// POST /api/settings/test-llm
func TestLLM(c *gin.Context) {
	var dto struct {
		BaseURL  *string `json:"base_url"`
		APIKey   *string `json:"api_key"`
		Model    *string `json:"model"`
		Protocol *string `json:"protocol"`
		// Enabled 用指针：原版是 item.get("enabled", True)，缺省视为启用；
		// Go 的 bool 零值是 false，直接用 bool 会把「未传」误判成「停用」。
		Providers []struct {
			Name        string  `json:"name"`
			BaseURL     string  `json:"base_url"`
			APIKey      string  `json:"api_key"`
			Model       string  `json:"model"`
			Protocol    string  `json:"protocol"`
			Temperature float64 `json:"temperature"`
			Weight      int     `json:"weight"`
			Enabled     *bool   `json:"enabled"`
		} `json:"providers"`
	}
	_ = c.ShouldBindJSON(&dto)

	// 超时略短于前端 axios 的 60s，保证错误由后端以标准 {detail} 形态返回，
	// 而不是让前端先等到超时、拿不到诊断信息。
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()

	// providers 优先：多端点模式下前端「测试端点」只带目标端点，
	// 与原版 _test_configs 的分支顺序一致。
	// 用 != nil 而非 len>0 —— 原版判断的是 `body.providers is not None`，
	// 显式传空数组意味着「没有可用端点」，应当返回 ok=false 而不是回落全局配置。
	if dto.Providers != nil {
		providers := make([]model.LLMProvider, 0, len(dto.Providers))
		for _, item := range dto.Providers {
			providers = append(providers, model.LLMProvider{
				Name:        item.Name,
				BaseURL:     item.BaseURL,
				APIKey:      item.APIKey,
				Model:       item.Model,
				Protocol:    item.Protocol,
				Temperature: item.Temperature,
				Weight:      item.Weight,
				Enabled:     item.Enabled == nil || *item.Enabled,
			})
		}
		result.Success(c, service.TestLLMProviders(ctx, providers))
		return
	}
	result.Success(c, service.TestLLMEndpoint(ctx, derefOr(dto.BaseURL, ""), derefOr(dto.APIKey, ""), derefOr(dto.Model, ""), derefOr(dto.Protocol, "")))
}

// TestKali 测试 Kali SSH 连通性。POST /api/settings/kali/test
// 表单传什么测什么（允许保存前试连）；空值/脱敏串回落已存配置（契约：
// 收到脱敏串=未修改）。纯探测，不写任何运行时状态。
func TestKali(c *gin.Context) {
	var dto struct {
		Host       *string `json:"host"`
		Port       *int    `json:"port"`
		Username   *string `json:"username"`
		AuthType   *string `json:"auth_type"`
		Password   *string `json:"password"`
		PrivateKey *string `json:"private_key"`
	}
	_ = c.ShouldBindJSON(&dto)

	k := engine.LoadSystemSettings().Kali
	if dto.Host != nil && strings.TrimSpace(*dto.Host) != "" {
		k.Host = strings.TrimSpace(*dto.Host)
	}
	if dto.Port != nil && *dto.Port > 0 {
		k.Port = *dto.Port
	}
	if dto.Username != nil && strings.TrimSpace(*dto.Username) != "" {
		k.Username = strings.TrimSpace(*dto.Username)
	}
	if dto.AuthType != nil && strings.TrimSpace(*dto.AuthType) != "" {
		k.AuthType = strings.TrimSpace(*dto.AuthType)
	}
	if dto.Password != nil {
		if value := strings.TrimSpace(*dto.Password); value != "" && !utils.IsMaskedSecret(value) {
			k.Password = value
		}
	}
	if dto.PrivateKey != nil {
		if value := strings.TrimSpace(*dto.PrivateKey); value != "" && !utils.IsMaskedSecret(value) {
			k.PrivateKey = value
		}
	}
	result.Success(c, engine.KaliProbe(k))
}

// WorkdirStatsHandler 工作目录占用统计。
// GET /api/settings/workdir/stats
func WorkdirStatsHandler(c *gin.Context) {
	result.Success(c, service.WorkdirStats())
}

// CleanupWorkdirHandler 清理工作目录。
// POST /api/settings/workdir/cleanup
func CleanupWorkdirHandler(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	result.Success(c, service.CleanupWorkdir())
}

// WallpaperInfo 壁纸信息。
// GET /api/settings/ui/wallpaper
func WallpaperInfo(c *gin.Context) {
	settings := engine.LoadSystemSettings()
	path := service.FindWallpaper()
	result.Success(c, gin.H{
		"kind":      settings.UI.WallpaperKind,
		"url":       settings.UI.WallpaperURL,
		"fit":       settings.UI.WallpaperFit,
		"dim":       settings.UI.WallpaperDim,
		"file":      path,
		"available": path != "",
	})
}

// UploadWallpaper 上传壁纸。
// POST /api/settings/ui/wallpaper
func UploadWallpaper(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		if file, err = c.FormFile("wallpaper"); err != nil {
			result.Failed(c, result.BadRequest, result.SubMissingParam)
			return
		}
	}
	if file.Size > 12<<20 {
		result.FailedWithMsg(c, result.BadRequest, "壁纸文件过大（上限 12MB）")
		return
	}
	src, err := file.Open()
	if err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	defer src.Close()
	data, err := io.ReadAll(io.LimitReader(src, 12<<20))
	if err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	path, err := service.SaveWallpaper(file.Filename, data)
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "保存壁纸失败："+err.Error())
		return
	}
	result.Success(c, gin.H{"ok": true, "path": path, "url": service.LoadSettingsView().UI.WallpaperURL})
}

// ServeWallpaper 输出壁纸原图。
// GET /api/settings/ui/wallpaper/raw
//
// 回源加固：Content-Type 固定为白名单 image 类型 + nosniff，
// 防止伪装文件被浏览器嗅探成 HTML/SVG 执行（存储型 XSS / 文件包含）。
func ServeWallpaper(c *gin.Context) {
	path := service.FindWallpaper()
	if path == "" {
		c.Status(404)
		return
	}
	ext := filepath.Ext(path)
	if ct := service.WallpaperContentType(ext); ct != "" {
		c.Header("Content-Type", ct)
	}
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Disposition", `inline; filename="wallpaper`+ext+`"`)
	c.File(path)
}

// DeleteWallpaper 清除壁纸。
// DELETE /api/settings/ui/wallpaper
func DeleteWallpaper(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	if err := service.ClearWallpaper(); err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true})
}

// ===== 运行日志 =====

// RuntimeLogStatsHandler 日志统计。
// GET /api/runtime-logs/stats
func RuntimeLogStatsHandler(c *gin.Context) {
	result.Success(c, service.RuntimeLogStats(queryString(c, "task_id")))
}

// ListRuntimeLogs 日志列表。
// GET /api/runtime-logs
func ListRuntimeLogs(c *gin.Context) {
	filter := service.LogFilter{
		TaskID: queryString(c, "task_id"),
		Agent:  queryString(c, "agent"),
		Level:  queryString(c, "level"),
		Kind:   queryString(c, "kind"),
		Query:  queryString(c, "q"),
		Limit:  queryInt(c, "limit", 0),
		Offset: queryInt(c, "offset", 0),
	}
	items, total, err := service.QueryRuntimeLogs(filter)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, filter.Limit, filter.Offset)
}

// ===== 备份 =====

// BackupStatusHandler 备份状态。
// GET /api/backup/status
func BackupStatusHandler(c *gin.Context) {
	result.Success(c, service.BackupStatus())
}

// CreateSnapshotHandler 生成快照。
// POST /api/backup/snapshot
func CreateSnapshotHandler(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	name, err := service.CreateSnapshot()
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "生成快照失败："+err.Error())
		return
	}
	result.Success(c, gin.H{"ok": true, "name": name, "status": service.BackupStatus()})
}

// ExportBackupHandler 导出数据。
// POST /api/backup/export
func ExportBackupHandler(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	raw, name, err := service.ExportDump()
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "导出失败："+err.Error())
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+name)
	c.Data(200, "application/json; charset=utf-8", raw)
}

// DownloadSnapshotHandler 下载指定快照。
// GET /api/backup/snapshots/:name
func DownloadSnapshotHandler(c *gin.Context) {
	name := pathParam(c, "name")
	raw, err := service.ReadSnapshot(name)
	if err != nil {
		result.Failed(c, result.NotFound, result.SubResourceNotFound)
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+name)
	c.Data(200, "application/json; charset=utf-8", raw)
}

// RestoreBackupHandler 从快照 / 上传文件恢复数据。
// POST /api/backup/restore
func RestoreBackupHandler(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var raw []byte
	if file, err := c.FormFile("file"); err == nil {
		src, err := file.Open()
		if err != nil {
			result.Failed(c, result.BadRequest, result.SubInvalidFormat)
			return
		}
		defer src.Close()
		raw, err = io.ReadAll(io.LimitReader(src, 256<<20))
		if err != nil {
			result.Failed(c, result.BadRequest, result.SubInvalidFormat)
			return
		}
	} else {
		var dto struct {
			Name string `json:"name"`
			Data string `json:"data"`
		}
		if err := c.ShouldBindJSON(&dto); err != nil {
			result.Failed(c, result.BadRequest, result.SubMissingParam)
			return
		}
		if strings.TrimSpace(dto.Name) != "" {
			content, err := service.ReadSnapshot(dto.Name)
			if err != nil {
				result.FailedWithMsg(c, result.BadRequest, "快照不存在："+dto.Name)
				return
			}
			raw = content
		} else if strings.TrimSpace(dto.Data) != "" {
			raw = []byte(dto.Data)
		}
	}
	if len(raw) == 0 {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	engine.ManagerInstance().Shutdown()
	counts, err := service.RestoreSnapshot(raw)
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "恢复失败："+err.Error())
		return
	}
	result.Success(c, counts)
}

// ===== 在线更新 =====

// CheckUpdateHandler 检查更新。
// GET /api/update/check
func CheckUpdateHandler(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result.Success(c, service.CheckUpdate(ctx))
}

// RunUpdateHandler 执行更新。
// POST /api/update/run
func RunUpdateHandler(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	result.Success(c, service.RunUpdate())
}
