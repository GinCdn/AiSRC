package api

import (
	"context"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/result"
	"AiSRC/service"
	"AiSRC/service/engine"
	"AiSRC/service/llm"
	"AiSRC/utils"

	"github.com/gin-gonic/gin"
)

// CreateTask 创建任务。
// POST /api/tasks
func CreateTask(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto CreateTaskRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	name := strings.TrimSpace(dto.Name)
	if name == "" {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}

	targetSource := normalizeTargetSource(dto.TargetSource)
	engineName := engine.NormalizeEngine(dto.Engine)
	fofaQuery := strings.TrimSpace(dto.FofaQuery)
	manualTargets := cleanTargetList(dto.ManualTargets)

	if targetSource == "fofa" || targetSource == "both" {
		if fofaQuery == "" {
			result.FailedWithMsg(c, result.BadRequest, "选择测绘检索时必须填写查询语法")
			return
		}
	}
	if targetSource == "manual" || targetSource == "both" {
		if len(manualTargets) == 0 {
			result.FailedWithMsg(c, result.BadRequest, "选择手动清单时必须至少填写一个目标")
			return
		}
	}

	settings := engine.LoadSystemSettings()
	task := model.Task{
		ID:            utils.UUID(),
		Name:          utils.Truncate(name, 190),
		SrcType:       engine.NormalizeSrcType(dto.SrcType),
		VulnTypes:     normalizeVulnTypes(dto.VulnTypes),
		SrcRules:      strings.TrimSpace(dto.SrcRules),
		TargetSource:  targetSource,
		FofaQuery:     fofaQuery,
		ManualTargets: manualTargets,
		AuthBindings:  normalizeAuthBindings(dto.AuthBindings),
		ModelConfig:   dto.ModelConfig.ToModel(),
		FofaConfig:    dto.FofaConfig.ToModel(),
		Engine:        engineName,
		Concurrency:   clampInt(dto.Concurrency, 1, constant.TaskConcurrencyMax, settings.Defaults.Concurrency),
		DeepenCap:     utils.ClampDeepenCap(dto.DeepenCap),
		// 任务未显式指定时读设置页「复审通过后自动通杀」默认值（nil 语义开，对齐原版）。
		AutoKillsweep: boolOr(dto.AutoKillsweep, settings.Defaults.EffectiveAutoKillsweep()),
		Status:        constant.TaskCreated,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if task.DeepenCap == 0 {
		task.DeepenCap = settings.Defaults.DeepenCap
	}
	if task.Concurrency <= 0 {
		task.Concurrency = 3
	}
	applyEngineCredential(&task, dto.EngineConfig, engineName, settings)

	if err := core.Db.Create(&task).Error; err != nil {
		global.Log.Errorf("创建任务失败: %v", err)
		result.Failed(c, result.InternalError, result.SubDbError)
		return
	}
	engine.EmitInfo(task.ID, "collector", "collector_phase", "任务已创建，等待启动", nil)
	result.Success(c, service.BuildTaskView(&task, true))
}

// ListTasks 任务列表。
// GET /api/tasks
func ListTasks(c *gin.Context) {
	limit := queryInt(c, "limit", 0)
	offset := queryInt(c, "offset", 0)
	q := queryString(c, "q")
	items, total, err := service.ListTasks(q, limit, offset)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, limit, offset)
}

// GetTask 任务详情。
// GET /api/tasks/:task_id
func GetTask(c *gin.Context) {
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	result.Success(c, service.BuildTaskView(&task, true))
}

// UpdateTask 更新任务配置。
// PATCH /api/tasks/:task_id
func UpdateTask(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	var dto UpdateTaskRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	settings := engine.LoadSystemSettings()

	if dto.Name != nil {
		task.Name = utils.Truncate(strings.TrimSpace(*dto.Name), 190)
	}
	if dto.SrcType != nil {
		task.SrcType = engine.NormalizeSrcType(*dto.SrcType)
	}
	if dto.VulnTypes != nil {
		task.VulnTypes = normalizeVulnTypes(dto.VulnTypes)
	}
	if dto.SrcRules != nil {
		task.SrcRules = strings.TrimSpace(*dto.SrcRules)
	}
	if dto.TargetSource != nil {
		task.TargetSource = normalizeTargetSource(*dto.TargetSource)
	}
	if dto.FofaQuery != nil {
		newQuery := strings.TrimSpace(*dto.FofaQuery)
		if newQuery != task.FofaQuery {
			// 查询词变更：测绘游标与取尽标记必须重置，否则取尽粘滞会导致
			// 编辑后永远不再检索（粘滞门槛是刻意设计，只认查询变更重开）。
			// 失败退避/停机计数一并放开：改查询词=主动重试。
			task.FofaConfig.Cursor = 0
			task.FofaConfig.FofaExhausted = false
			task.FofaConfig.CurrentQuery = ""
			task.FofaConfig.EmptyStreak = 0
			task.FofaConfig.LastFofaError = ""
			task.FofaConfig.EngineFailCount = 0
			task.FofaConfig.NextRetryAt = time.Time{}
		}
		task.FofaQuery = newQuery
	}
	if dto.Engine != nil {
		newEngine := engine.NormalizeEngine(*dto.Engine)
		if newEngine != task.Engine {
			task.FofaConfig.Cursor = 0
			task.FofaConfig.FofaExhausted = false
			task.FofaConfig.EngineFailCount = 0
			task.FofaConfig.NextRetryAt = time.Time{}
		}
		task.Engine = newEngine
	}
	if dto.ManualTargets != nil {
		task.ManualTargets = cleanTargetList(dto.ManualTargets)
	}
	if dto.AuthBindings != nil {
		task.AuthBindings = mergeAuthBindings(normalizeAuthBindings(dto.AuthBindings), task.AuthBindings)
	}
	if dto.Concurrency != nil {
		task.Concurrency = clampInt(*dto.Concurrency, 1, constant.TaskConcurrencyMax, task.Concurrency)
	}
	if dto.DeepenCap != nil {
		task.DeepenCap = utils.ClampDeepenCap(*dto.DeepenCap)
	}
	if dto.AutoKillsweep != nil {
		task.AutoKillsweep = *dto.AutoKillsweep
	}
	if dto.ModelConfig != nil {
		task.ModelConfig = mergeModelConfig(task.ModelConfig, *dto.ModelConfig)
	}
	if dto.FofaConfig != nil {
		task.FofaConfig = mergeFofaConfig(task.FofaConfig, *dto.FofaConfig)
	}
	if dto.EngineConfig != nil {
		applyEngineCredential(&task, EngineConfigDTO{
			Key:     derefOr(dto.EngineConfig.Key, ""),
			BaseURL: derefOr(dto.EngineConfig.BaseURL, ""),
		}, task.Engine, settings)
	}
	task.UpdatedAt = time.Now()

	if err := core.Db.Save(&task).Error; err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, service.BuildTaskView(&task, true))
}

// DeleteTask 删除任务。
// DELETE /api/tasks/:task_id
func DeleteTask(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	if err := service.DeleteTask(taskID); err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true, "id": taskID})
}

// StartTask 启动任务。
// POST /api/tasks/:task_id/start
func StartTask(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	engine.ManagerInstance().EnsureRunning(taskID)
	_ = core.Db.First(&task, "id = ?", taskID)
	engine.EmitInfo(taskID, "orchestrator", "recover", "任务已启动", nil)
	result.Success(c, service.BuildTaskView(&task, true))
}

// PauseTask 暂停任务。
// POST /api/tasks/:task_id/pause
func PauseTask(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	engine.ManagerInstance().PauseTask(taskID, "用户手动暂停任务")
	_ = core.Db.First(&task, "id = ?", taskID)
	result.Success(c, service.BuildTaskView(&task, true))
}

// StopTask 停止任务。
// POST /api/tasks/:task_id/stop
func StopTask(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	engine.ManagerInstance().StopTask(taskID, "用户手动停止任务")
	_ = core.Db.First(&task, "id = ?", taskID)
	result.Success(c, service.BuildTaskView(&task, true))
}

// ProbeTaskModels 探测任务级模型端点可用的模型列表。
// POST /api/tasks/:task_id/models
func ProbeTaskModels(c *gin.Context) {
	taskID := pathParam(c, "task_id")
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	var dto TaskModelsProbeRequest
	_ = c.ShouldBindJSON(&dto)

	baseURL := task.ModelConfig.BaseURL
	apiKey := task.ModelConfig.APIKey
	protocol := task.ModelConfig.Protocol
	if dto.BaseURL != nil {
		baseURL = strings.TrimSpace(*dto.BaseURL)
	}
	if dto.APIKey != nil && !utils.IsMaskedSecret(*dto.APIKey) {
		apiKey = strings.TrimSpace(*dto.APIKey)
	}
	if dto.Protocol != nil {
		protocol = strings.TrimSpace(*dto.Protocol)
	}
	keyRef := ""
	if dto.KeyRef != nil {
		keyRef = strings.TrimSpace(*dto.KeyRef)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	models, err := service.ListAvailableModels(ctx, baseURL, apiKey, protocol, keyRef)
	if err != nil {
		result.FailedWithMsg(c, result.InternalError, "模型列表获取失败："+err.Error())
		return
	}
	result.Success(c, gin.H{"models": ensureSlice(models), "model": task.ModelConfig.Model})
}

// ToggleTaskTop 单任务置顶。
// PATCH /api/tasks/:task_id/top
func ToggleTaskTop(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	var dto ToggleTopRequest
	if err := c.ShouldBindJSON(&dto); err != nil || dto.IsTop == nil {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	if err := service.ToggleTaskTop(taskID, *dto.IsTop); err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true, "id": taskID, "is_top": *dto.IsTop})
}

// BatchToggleTaskTop 批量置顶任务。
// PATCH /api/tasks/batch/top
func BatchToggleTaskTop(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto BatchTopRequest
	if err := c.ShouldBindJSON(&dto); err != nil || len(dto.IDs) == 0 {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	isTop := true
	if dto.IsTop != nil {
		isTop = *dto.IsTop
	}
	affected, err := service.ToggleBatchTop("task", dto.IDs, isTop)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true, "affected": affected, "is_top": isTop})
}

// TaskBoard 任务看板。
// GET /api/tasks/:task_id/board
func TaskBoard(c *gin.Context) {
	taskID := pathParam(c, "task_id")
	board, err := service.BoardView(taskID)
	if err != nil {
		result.Failed(c, result.NotFound, result.SubTaskNotFound)
		return
	}
	result.Success(c, board)
}

// TaskTargets 任务目标列表。
// GET /api/tasks/:task_id/targets
func TaskTargets(c *gin.Context) {
	taskID := pathParam(c, "task_id")
	status := queryString(c, "status")
	limit := queryInt(c, "limit", 0)
	offset := queryInt(c, "offset", 0)
	items, total, err := service.QueryTargets(service.QueryTargetsFilter{
		TaskID: taskID, Status: status, Query: queryString(c, "q"), Limit: limit, Offset: offset,
	})
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, limit, offset)
}

// TaskHosts 任务主机聚合视图。
// GET /api/tasks/:task_id/hosts
func TaskHosts(c *gin.Context) {
	taskID := pathParam(c, "task_id")
	limit := queryInt(c, "limit", 0)
	offset := queryInt(c, "offset", 0)
	items, total, err := service.TaskHosts(taskID, limit, offset)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, limit, offset)
}

// SkipTarget 跳过目标。
// POST /api/tasks/:task_id/targets/:target_id/skip
func SkipTarget(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	targetID := pathParam(c, "target_id")
	outcome := engine.ManagerInstance().SkipTarget(taskID, targetID, "用户手动删除该目标")
	if ok, _ := outcome["ok"].(bool); !ok {
		result.Failed(c, result.NotFound, result.SubTargetNotFound)
		return
	}
	result.Success(c, outcome)
}

// RescanTarget 重新扫描终态目标（已完成/已跳过/已放弃 → 重新排队）。
// POST /api/tasks/:task_id/targets/:target_id/rescan
func RescanTarget(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	targetID := pathParam(c, "target_id")
	outcome := engine.ManagerInstance().RescanTarget(taskID, targetID)
	if ok, _ := outcome["ok"].(bool); !ok {
		reason, _ := outcome["reason"].(string)
		result.FailedWithMsg(c, result.BadRequest, reason)
		return
	}
	result.Success(c, outcome)
}

// InjectDirective 向运行中 worker 注入人工指令。
// POST /api/tasks/:task_id/targets/:target_id/directive
func InjectDirective(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	targetID := pathParam(c, "target_id")
	var dto DirectiveRequest
	if err := c.ShouldBindJSON(&dto); err != nil || strings.TrimSpace(dto.Directive) == "" {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	outcome := engine.ManagerInstance().InjectDirective(taskID, targetID, dto.Directive)
	result.Success(c, outcome)
}

// TargetTrace 目标事件轨迹。
// GET /api/tasks/:task_id/targets/:target_id/trace
func TargetTrace(c *gin.Context) {
	taskID := pathParam(c, "task_id")
	targetID := pathParam(c, "target_id")
	limit := queryInt(c, "limit", 200)
	items, err := service.TargetTrace(taskID, targetID, limit)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	result.Success(c, ensureSlice(items))
}

// CancelEscalation 取消扩大危害分析。
// POST /api/tasks/:task_id/escalations/:finding_id/cancel
func CancelEscalation(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	findingID := pathParam(c, "finding_id")
	outcome := engine.ManagerInstance().CancelEscalation(taskID, findingID, "用户取消扩大危害")
	result.Success(c, outcome)
}

// ===== 内部辅助 =====

// normalizeTargetSource 归一化目标来源。
func normalizeTargetSource(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "manual", "手动":
		return "manual"
	case "both":
		return "both"
	case "site", "单站":
		return "site"
	default:
		return "fofa"
	}
}

// normalizeVulnTypes 归一化漏洞类型列表。
// normalizeVulnTypes 清洗漏洞类型列表：去空、去重，保持调用方顺序。
//
// 与原版 AutoHunter 一致：后端不注入默认值，缺省即为空列表
// （提示词侧会把空列表按「通用」处理），默认全开是前端的表单初值行为。
func normalizeVulnTypes(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// cleanTargetList 清洗手动目标清单。
func cleanTargetList(items []string) []string {
	return utils.CleanTargetList(items)
}

// normalizeAuthBindings 规范化凭据绑定（丢弃空绑定）。
func normalizeAuthBindings(items []model.AuthBinding) []model.AuthBinding {
	out := make([]model.AuthBinding, 0, len(items))
	for _, item := range items {
		if !item.HasCredential() {
			continue
		}
		if strings.TrimSpace(item.Target) == "" {
			item.Target = "*"
		}
		out = append(out, item)
	}
	return out
}

// mergeAuthBindings 合并凭据：脱敏串代表「未修改」，沿用旧值。
func mergeAuthBindings(incoming []model.AuthBinding, existing []model.AuthBinding) []model.AuthBinding {
	old := map[string]model.AuthBinding{}
	for _, item := range existing {
		old[item.Target+"|"+item.Username] = item
	}
	out := make([]model.AuthBinding, 0, len(incoming))
	for _, item := range incoming {
		key := item.Target + "|" + item.Username
		if prev, ok := old[key]; ok {
			if utils.IsMaskedSecret(item.Password) || item.Password == "" {
				if utils.IsMaskedSecret(item.Password) {
					item.Password = prev.Password
				}
			}
			if utils.IsMaskedSecret(item.Cookie) {
				item.Cookie = prev.Cookie
			}
			if utils.IsMaskedSecret(item.Authorization) {
				item.Authorization = prev.Authorization
			}
			if utils.IsMaskedSecret(item.Raw) {
				item.Raw = prev.Raw
			}
		}
		out = append(out, item)
	}
	return out
}

// mergeModelConfig 合并任务级模型配置。
func mergeModelConfig(current model.LLMModelConfig, patch PartialModelConfigDTO) model.LLMModelConfig {
	next := current
	if patch.InheritGlobal != nil {
		next.InheritGlobal = patch.InheritGlobal
	}
	if patch.BaseURL != nil {
		next.BaseURL = strings.TrimSpace(*patch.BaseURL)
	}
	if patch.APIKey != nil {
		value := strings.TrimSpace(*patch.APIKey)
		if value == "" {
			next.APIKey = ""
		} else if !utils.IsMaskedSecret(value) {
			next.APIKey = value
		}
	}
	if patch.KeyRef != nil {
		next.KeyRef = strings.TrimSpace(*patch.KeyRef)
	}
	if patch.Model != nil {
		next.Model = strings.TrimSpace(*patch.Model)
	}
	if patch.Protocol != nil {
		next.Protocol = llm.ResolveProtocol(*patch.Protocol, next.BaseURL)
	}
	if patch.PromptVersion != nil {
		next.PromptVersion = strings.TrimSpace(*patch.PromptVersion)
	}
	if patch.Providers != nil {
		next.Providers = mergeProviders(patch.Providers, current.Providers)
	}
	return next
}

// mergeProviders 合并端点池（脱敏密钥保留旧值）。
func mergeProviders(incoming []model.LLMProvider, existing []model.LLMProvider) []model.LLMProvider {
	old := map[string]string{}
	for _, item := range existing {
		old[utils.IdentityRef(item.BaseURL, item.Name)] = item.APIKey
	}
	out := make([]model.LLMProvider, 0, len(incoming))
	for _, item := range incoming {
		item.Name = strings.TrimSpace(item.Name)
		item.BaseURL = strings.TrimSpace(item.BaseURL)
		item.Model = strings.TrimSpace(item.Model)
		if item.Name == "" {
			item.Name = utils.IdentityRef(item.BaseURL)
		}
		value := strings.TrimSpace(item.APIKey)
		if value == "" || utils.IsMaskedSecret(value) {
			if kept, ok := old[utils.IdentityRef(item.BaseURL, item.Name)]; ok {
				item.APIKey = kept
			} else {
				item.APIKey = ""
			}
		}
		item.Protocol = llm.ResolveProtocol(item.Protocol, item.BaseURL)
		if item.Weight <= 0 {
			item.Weight = 1
		}
		out = append(out, item)
	}
	return out
}

// mergeFofaConfig 合并任务级测绘配置（保留运行时翻页状态）。
func mergeFofaConfig(current model.FofaConfig, patch PartialFofaConfigDTO) model.FofaConfig {
	next := current
	if patch.Key != nil {
		value := strings.TrimSpace(*patch.Key)
		if value == "" {
			next.Key = ""
		} else if !utils.IsMaskedSecret(value) {
			next.Key = value
		}
	}
	if patch.BaseURL != nil {
		next.BaseURL = strings.TrimSpace(*patch.BaseURL)
	}
	if patch.MaxPages != nil {
		next.MaxPages = clampInt(*patch.MaxPages, 1, constant.MaxPagesMax, next.MaxPages)
	}
	if patch.PageSize != nil {
		next.PageSize = clampInt(*patch.PageSize, 1, constant.PageSizeMax, next.PageSize)
	}
	if patch.IntentMode != nil {
		next.IntentMode = strings.TrimSpace(*patch.IntentMode)
	}
	if patch.SkipSiteRecon != nil {
		next.SkipSiteRecon = *patch.SkipSiteRecon
	}
	return next
}

// applyEngineCredential 把引擎 Key / URL 落到任务或引擎设置。
func applyEngineCredential(task *model.Task, dto EngineConfigDTO, engineName string, settings *model.SystemSettings) {
	key := strings.TrimSpace(dto.Key)
	if key != "" && !utils.IsMaskedSecret(key) {
		if engineName == "fofa" {
			task.FofaConfig.Key = key
		}
		if settings.Engines == nil {
			settings.Engines = map[string]model.EngineItem{}
		}
		item := settings.Engines[engineName]
		item.Name = engineName
		item.Key = key
		item.Enabled = true
		settings.Engines[engineName] = item
		_ = engine.SaveSystemSettings(settings)
	}
	if baseURL := strings.TrimSpace(dto.BaseURL); baseURL != "" {
		task.FofaConfig.BaseURL = baseURL
	}
}

func derefOr(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}

// boolOr 指针布尔解引用：nil（未提交）时返回默认值。
func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

// clampInt 带默认值的区间夹取。
func clampInt(value, min, max, fallback int) int {
	if value <= 0 {
		value = fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
