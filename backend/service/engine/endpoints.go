package engine

import (
	"fmt"
	"strings"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// LoadSystemSettings 读取全局系统设置（单行 id=global），不存在时返回带默认值的空壳。
func LoadSystemSettings() *model.SystemSettings {
	settings := &model.SystemSettings{ID: "global"}
	if core.Db == nil {
		applySystemDefaults(settings)
		return settings
	}
	err := core.Db.First(settings, "id = ?", "global").Error
	if err != nil {
		settings = &model.SystemSettings{ID: "global"}
	}
	applySystemDefaults(settings)
	return settings
}

// SaveSystemSettings 落库全局设置（不存在则创建）。
func SaveSystemSettings(settings *model.SystemSettings) error {
	if core.Db == nil {
		return fmt.Errorf("数据库未初始化，无法保存设置")
	}
	if settings.ID == "" {
		settings.ID = "global"
	}
	return core.Db.Save(settings).Error
}

// applySystemDefaults 用配置文件补全系统设置缺省项。
func applySystemDefaults(settings *model.SystemSettings) {
	if settings.LLM.Mode == "" {
		settings.LLM.Mode = config.AppConfig.LLM.Mode
	}
	if settings.LLM.BaseURL == "" {
		settings.LLM.BaseURL = config.AppConfig.LLM.BaseURL
	}
	if settings.LLM.APIKey == "" {
		settings.LLM.APIKey = config.AppConfig.LLM.APIKey
	}
	if settings.LLM.Model == "" {
		settings.LLM.Model = config.AppConfig.LLM.Model
	}
	if settings.LLM.Protocol == "" {
		settings.LLM.Protocol = config.AppConfig.LLM.Protocol
	}
	if settings.LLM.Temperature == 0 {
		settings.LLM.Temperature = config.AppConfig.LLM.Temperature
	}
	if settings.Fofa.Key == "" {
		settings.Fofa.Key = config.AppConfig.Engine.Key
	}
	// 引擎端点已固定为官方默认（DefaultEngineBaseURL），
	// config.yaml 的 Engine.BaseURL 不再参与运行时（历史遗留字段仅保留解析）。
	if settings.Fofa.MaxPages <= 0 {
		settings.Fofa.MaxPages = config.AppConfig.Engine.MaxPages
	}
	if settings.Fofa.PageSize <= 0 {
		settings.Fofa.PageSize = config.AppConfig.Engine.PageSize
	}
	if settings.Fofa.DefaultIntentMode == "" {
		settings.Fofa.DefaultIntentMode = config.AppConfig.Engine.IntentMode
	}
	if settings.Defaults.Concurrency <= 0 {
		settings.Defaults.Concurrency = 3
	}
	if settings.Defaults.DeepenCap <= 0 {
		settings.Defaults.DeepenCap = constant.DeepenCapDefault
	}
	if settings.Defaults.Engine == "" {
		settings.Defaults.Engine = config.AppConfig.Engine.Default
	}
	if settings.Engines == nil {
		settings.Engines = map[string]model.EngineItem{}
	}
	if settings.UI.Theme == "" {
		settings.UI.Theme = "light"
	}
}

// resolveProviderKey 解析单个 provider 的实际 API Key。
// key 为空或脱敏串时按 key_ref / IdentityRef(base_url,name) 从系统配置回落：
// 先匹配系统端点池条目，未命中再退系统单端点 key——与探针路径
// ResolveLLMEndpoint 的回落语义保持一致。否则任务运行时会带着空/脱敏
// key 调 LLM 直接 401，用户被迫在任务表单重复输入系统里已存过的 key。
func resolveProviderKey(p model.LLMProvider, settings *model.SystemSettings) string {
	key := strings.TrimSpace(p.APIKey)
	if key != "" && !utils.IsMaskedSecret(key) {
		return key
	}
	// 命中系统端点池条目（按显式 key_ref，其次 IdentityRef）。
	ref := strings.TrimSpace(p.KeyRef)
	identity := utils.IdentityRef(p.BaseURL, p.Name)
	for _, provider := range settings.LLM.Providers {
		if (ref != "" && utils.IdentityRef(provider.BaseURL, provider.Name) == ref) ||
			identity == utils.IdentityRef(provider.BaseURL, provider.Name) {
			if candidate := strings.TrimSpace(provider.APIKey); candidate != "" {
				return candidate
			}
		}
	}
	// 回落系统单端点 key（同 identity 时优先级已覆盖，这里兜底）。
	if ref == "" || identity == utils.IdentityRef(settings.LLM.BaseURL) {
		return settings.LLM.APIKey
	}
	return ""
}

// endpointsFromProviders 把任务级 provider 列表转成 LLM 端点。
func endpointsFromProviders(providers []model.LLMProvider, settings *model.SystemSettings) []llm.Endpoint {
	result := make([]llm.Endpoint, 0, len(providers))
	for _, p := range providers {
		if p.Enabled == false && p.Name != "" {
			// Enabled=false 且显式配置过的端点直接跳过；空结构体视为未配置。
			if strings.TrimSpace(p.BaseURL) != "" || strings.TrimSpace(p.APIKey) != "" {
				continue
			}
		}
		if strings.TrimSpace(p.BaseURL) == "" {
			continue
		}
		result = append(result, llm.Endpoint{
			Name:        p.Name,
			BaseURL:     p.BaseURL,
			APIKey:      resolveProviderKey(p, settings),
			Model:       p.Model,
			Protocol:    llm.ResolveProtocol(p.Protocol, p.BaseURL),
			Temperature: p.Temperature,
		})
	}
	return result
}

// BuildPoolForTask 按任务级配置构造端点池；任务未单独配置时回退到全局设置。
func BuildPoolForTask(task *model.Task) *llm.Pool {
	settings := LoadSystemSettings()
	if task != nil && !task.ModelConfig.IsInherit() {
		cfg := task.ModelConfig
		if len(cfg.Providers) > 0 {
			if pool := llm.NewPool(endpointsFromProviders(cfg.Providers, settings)); pool.Size() > 0 {
				return pool
			}
		}
		singleBase := strings.TrimSpace(cfg.BaseURL)
		singleKey := strings.TrimSpace(cfg.APIKey)
		// 任务单端点 key 为空或脱敏串（编辑回显后未改）时按 key_ref /
		// IdentityRef 从系统配置回落，不能把脱敏串当真实 key 发出去。
		if singleKey == "" || utils.IsMaskedSecret(singleKey) {
			singleKey = resolveProviderKey(model.LLMProvider{
				BaseURL: singleBase,
				APIKey:  singleKey,
				KeyRef:  cfg.KeyRef,
			}, settings)
		}
		if singleBase != "" || singleKey != "" {
			if pool := llm.NewPool([]llm.Endpoint{{
				Name:        "task",
				BaseURL:     firstNonEmptyString(singleBase, settings.LLM.BaseURL),
				APIKey:      firstNonEmptyString(singleKey, settings.LLM.APIKey),
				Model:       firstNonEmptyString(cfg.Model, settings.LLM.Model),
				Protocol:    llm.ResolveProtocol(cfg.Protocol, firstNonEmptyString(singleBase, settings.LLM.BaseURL)),
				Temperature: settings.LLM.Temperature,
			}}); pool.Size() > 0 {
				return pool
			}
		}
	}
	return BuildGlobalPool()
}

// BuildGlobalPool 按全局设置构造端点池。
func BuildGlobalPool() *llm.Pool {
	settings := LoadSystemSettings()
	if len(settings.LLM.Providers) > 0 {
		if pool := llm.NewPool(endpointsFromProviders(settings.LLM.Providers, settings)); pool.Size() > 0 {
			return pool
		}
	}
	return llm.NewPool([]llm.Endpoint{{
		Name:        "global",
		BaseURL:     settings.LLM.BaseURL,
		APIKey:      settings.LLM.APIKey,
		Model:       settings.LLM.Model,
		Protocol:    llm.ResolveProtocol(settings.LLM.Protocol, settings.LLM.BaseURL),
		Temperature: settings.LLM.Temperature,
	}})
}

// BuildPoolFromRaw 用显式参数构造单端点池（用于「测试连接」「列出模型」）。
func BuildPoolFromRaw(baseURL, apiKey, modelName, protocol string) *llm.Pool {
	return llm.NewPool([]llm.Endpoint{{
		Name:     "probe",
		BaseURL:  baseURL,
		APIKey:   apiKey,
		Model:    modelName,
		Protocol: llm.ResolveProtocol(protocol, baseURL),
	}})
}

// MaskEndpoints 对外下发端点信息时脱敏 api_key。
func MaskEndpoints(endpoints []llm.Endpoint) []map[string]any {
	out := make([]map[string]any, 0, len(endpoints))
	for _, ep := range endpoints {
		out = append(out, map[string]any{
			"name":        ep.Name,
			"base_url":    ep.BaseURL,
			"model":       ep.Model,
			"protocol":    ep.Protocol,
			"api_key":     utils.MaskSecret(ep.APIKey),
			"api_key_set": strings.TrimSpace(ep.APIKey) != "",
		})
	}
	return out
}
