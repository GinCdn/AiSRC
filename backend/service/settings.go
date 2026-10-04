package service

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// SettingsView 设置页下发的完整视图（敏感字段一律脱敏）。
type SettingsView struct {
	LLM      LLMSettingsView               `json:"llm"`
	Fofa     FofaSettingsView              `json:"fofa"`
	Engines  map[string]EngineSettingsView `json:"engines"`
	Defaults model.DefaultsSettings        `json:"defaults"`
	UI       model.UISettings              `json:"ui"`
	Proxy    ProxySettingsView             `json:"proxy"`
	Persona  model.PersonaSettings         `json:"persona"`
	Skills   SkillsSettingsView            `json:"skills"`
	Ima      ImaSettingsView               `json:"ima"`
	Kali     KaliSettingsView              `json:"kali"`
	Secrets  map[string]any                `json:"secrets"`
	// AvailableEngines 全部已注册引擎清单，对齐原版 available_engines；
	// 设置页据此渲染「各引擎 API Key」区块与默认引擎下拉。
	AvailableEngines []EngineMetaView `json:"available_engines"`
}

// SkillsSettingsView 技能视图（content 明文下发——技能是提示词素材非密钥）。
type SkillsSettingsView struct {
	Enabled bool             `json:"enabled"`
	Items   []model.SkillItem `json:"items"`
}

// ImaSettingsView ima 知识库视图（key 脱敏）。
type ImaSettingsView struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	APIKeySet bool `json:"api_key_set"`
	RepoID  string `json:"repo_id"`
	TopK    int    `json:"top_k"`
}

// KaliSettingsView Kali SSH 视图（password/private_key 脱敏）。
type KaliSettingsView struct {
	Enabled      bool     `json:"enabled"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Username     string   `json:"username"`
	AuthType     string   `json:"auth_type"`
	Password     string   `json:"password"`
	PasswordSet  bool     `json:"password_set"`
	PrivateKey   string   `json:"private_key"`
	PrivateKeySet bool    `json:"private_key_set"`
	Categories   []string `json:"categories"`
	AllCategories []model.KaliCategory `json:"all_categories"`
}

// EngineMetaView 引擎元信息视图。
type EngineMetaView struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// LLMSettingsView 模型设置视图。
type LLMSettingsView struct {
	Mode        string            `json:"mode"`
	BaseURL     string            `json:"base_url"`
	APIKey      string            `json:"api_key"`
	APIKeySet   bool              `json:"api_key_set"`
	KeyRef      string            `json:"key_ref"`
	Model       string            `json:"model"`
	Protocol    string            `json:"protocol"`
	Temperature float64           `json:"temperature"`
	Providers   []LLMProviderView `json:"providers"`
}

// LLMProviderView 端点池条目视图。
type LLMProviderView struct {
	Name        string  `json:"name"`
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"`
	APIKeySet   bool    `json:"api_key_set"`
	Model       string  `json:"model"`
	Protocol    string  `json:"protocol"`
	Temperature float64 `json:"temperature"`
	Weight      int     `json:"weight"`
	Enabled     bool    `json:"enabled"`
	KeyRef      string  `json:"key_ref"`
}

// FofaSettingsView 测绘设置视图。
type FofaSettingsView struct {
	Key               string `json:"key"`
	KeySet            bool   `json:"key_set"`
	BaseURL           string `json:"base_url"`
	MaxPages          int    `json:"max_pages"`
	PageSize          int    `json:"page_size"`
	DefaultIntentMode string `json:"default_intent_mode"`
}

// EngineSettingsView 单引擎设置视图。
type EngineSettingsView struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Key         string `json:"key"`
	KeySet      bool   `json:"key_set"`
	BaseURL     string `json:"base_url"`
	Enabled     bool   `json:"enabled"`
	KeyRef      string `json:"key_ref"`
}

// ProxySettingsView 代理池视图（密码不下发）。
type ProxySettingsView struct {
	Enabled bool             `json:"enabled"`
	Proxies []map[string]any `json:"proxies"`
}

// LoadSettingsView 读取并脱敏全局设置。
func LoadSettingsView() *SettingsView {
	settings := engine.LoadSystemSettings()
	view := &SettingsView{
		LLM: LLMSettingsView{
			Mode:        firstNotEmpty(settings.LLM.Mode, "single"),
			BaseURL:     settings.LLM.BaseURL,
			APIKey:      utils.MaskSecret(settings.LLM.APIKey),
			APIKeySet:   strings.TrimSpace(settings.LLM.APIKey) != "",
			// 单端点密钥引用：新建任务选「单端点」时前端据此免重输 key，
			// 提交只带 key_ref，运行时由 resolveProviderKey 按引用解析明文。
			KeyRef:      utils.IdentityRef(settings.LLM.BaseURL),
			Model:       settings.LLM.Model,
			Protocol:    llm.ResolveProtocol(settings.LLM.Protocol, settings.LLM.BaseURL),
			Temperature: settings.LLM.Temperature,
		},
		Fofa: FofaSettingsView{
			Key:               utils.MaskSecret(settings.Fofa.Key),
			KeySet:            strings.TrimSpace(settings.Fofa.Key) != "",
			BaseURL:           engine.DefaultEngineBaseURL("fofa"),
			MaxPages:          settings.Fofa.MaxPages,
			PageSize:          settings.Fofa.PageSize,
			DefaultIntentMode: settings.Fofa.DefaultIntentMode,
		},
		Engines:  map[string]EngineSettingsView{},
		Defaults: settings.Defaults,
		UI:       settings.UI,
		Secrets:  map[string]any{},
	}
	for _, provider := range settings.LLM.Providers {
		view.LLM.Providers = append(view.LLM.Providers, LLMProviderView{
			Name:        provider.Name,
			BaseURL:     provider.BaseURL,
			APIKey:      utils.MaskSecret(provider.APIKey),
			APIKeySet:   strings.TrimSpace(provider.APIKey) != "",
			Model:       provider.Model,
			Protocol:    llm.ResolveProtocol(provider.Protocol, provider.BaseURL),
			Temperature: provider.Temperature,
			Weight:      provider.Weight,
			Enabled:     provider.Enabled,
			KeyRef:      utils.IdentityRef(provider.BaseURL, provider.Name),
		})
	}
	// engines 段必须为**每个已注册引擎**都出条目（对齐原版 settings_service.py
	// 的 engines_view 构建）：DB 里没配过的引擎也要有 display_name/key_set，
	// 否则前端「各引擎 API Key」区块渲染不出来。fofa 条目合并 fofa 段的
	// key/base_url（原版旧版兼容语义）。
	engineList := engine.ListEngines()
	view.Engines = make(map[string]EngineSettingsView, len(engineList))
	for _, info := range engineList {
		key := ""
		enabled := false
		if item, ok := settings.Engines[info.Name]; ok {
			key = item.Key
			enabled = item.Enabled
		}
		if info.Name == "fofa" {
			if strings.TrimSpace(key) == "" {
				key = settings.Fofa.Key
			}
		}
		view.Engines[info.Name] = EngineSettingsView{
			Name:        info.Name,
			DisplayName: info.DisplayName,
			Key:         utils.MaskSecret(key),
			KeySet:      strings.TrimSpace(key) != "",
			// 端点固定为官方默认，不再读用户配置（无自定义测绘端点场景）。
			BaseURL: engine.DefaultEngineBaseURL(info.Name),
			Enabled: enabled,
			KeyRef:  utils.IdentityRef(info.Name),
		}
	}
	view.AvailableEngines = make([]EngineMetaView, 0, len(engineList))
	for _, info := range engineList {
		view.AvailableEngines = append(view.AvailableEngines, EngineMetaView{
			Name:        info.Name,
			DisplayName: info.DisplayName,
		})
	}
	view.Proxy = ProxySettingsView{Enabled: settings.Proxy.Enabled, Proxies: []map[string]any{}}
	for _, item := range settings.Proxy.Proxies {
		view.Proxy.Proxies = append(view.Proxy.Proxies, map[string]any{
			"id":           item.ID,
			"name":         item.Name,
			"protocol":     item.Protocol,
			"host":         item.Host,
			"port":         item.Port,
			"username":     item.Username,
			"password":     utils.MaskSecret(item.Password),
			"has_password": strings.TrimSpace(item.Password) != "",
			"enabled":      item.Enabled,
			"display":      item.Display(),
		})
	}
	view.Persona = settings.Persona
	view.Skills = SkillsSettingsView{Enabled: settings.Skills.Enabled, Items: settings.Skills.Items}
	view.Ima = ImaSettingsView{
		Enabled:   settings.Ima.Enabled,
		BaseURL:   settings.Ima.BaseURL,
		APIKey:    utils.MaskSecret(settings.Ima.APIKey),
		APIKeySet: strings.TrimSpace(settings.Ima.APIKey) != "",
		RepoID:    settings.Ima.RepoID,
		TopK:      settings.Ima.TopK,
	}
	view.Kali = KaliSettingsView{
		Enabled:       settings.Kali.Enabled,
		Host:          settings.Kali.Host,
		Port:          settings.Kali.Port,
		Username:      settings.Kali.Username,
		AuthType:      firstNotEmpty(settings.Kali.AuthType, "password"),
		Password:      utils.MaskSecret(settings.Kali.Password),
		PasswordSet:   strings.TrimSpace(settings.Kali.Password) != "",
		PrivateKey:    utils.MaskSecret(settings.Kali.PrivateKey),
		PrivateKeySet: strings.TrimSpace(settings.Kali.PrivateKey) != "",
		Categories:    settings.Kali.Categories,
		AllCategories: model.KaliCategories,
	}
	return view
}

// SettingsUpdate 设置更新入参（全部可选，nil 表示不改）。
type SettingsUpdate struct {
	LLM *struct {
		Mode         *string             `json:"mode"`
		BaseURL      *string             `json:"base_url"`
		APIKey       *string             `json:"api_key"`
		Model        *string             `json:"model"`
		Protocol     *string             `json:"protocol"`
		Temperature  *float64            `json:"temperature"`
		Providers    []model.LLMProvider `json:"providers"`
		ProvidersSet bool                `json:"-"`
	} `json:"llm"`
	Fofa *struct {
		Key               *string `json:"key"`
		BaseURL           *string `json:"base_url"`
		MaxPages          *int    `json:"max_pages"`
		PageSize          *int    `json:"page_size"`
		DefaultIntentMode *string `json:"default_intent_mode"`
	} `json:"fofa"`
	Engines *map[string]struct {
		Key     *string `json:"key"`
		Enabled *bool   `json:"enabled"`
	} `json:"engines"`
	Defaults *model.DefaultsSettings `json:"defaults"`
	UI       *model.UISettings       `json:"ui"`
	Proxy    *struct {
		Enabled *bool             `json:"enabled"`
		Proxies []model.ProxyItem `json:"proxies"`
	} `json:"proxy"`
	Persona *model.PersonaSettings `json:"persona"`
	Skills  *struct {
		Enabled bool              `json:"enabled"`
		Items   []model.SkillItem `json:"items"`
	} `json:"skills"`
	Ima  *struct {
		Enabled *bool   `json:"enabled"`
		BaseURL *string `json:"base_url"`
		APIKey  *string `json:"api_key"`
		RepoID  *string `json:"repo_id"`
		TopK    *int    `json:"top_k"`
	} `json:"ima"`
	Kali *struct {
		Enabled    *bool    `json:"enabled"`
		Host       *string  `json:"host"`
		Port       *int     `json:"port"`
		Username   *string  `json:"username"`
		AuthType   *string  `json:"auth_type"`
		Password   *string  `json:"password"`
		PrivateKey *string  `json:"private_key"`
		Categories []string `json:"categories"`
	} `json:"kali"`
}

// SaveSettings 应用设置更新：脱敏串视为「未修改」，不会被回写。
func SaveSettings(update *SettingsUpdate) (*SettingsView, error) {
	settings := engine.LoadSystemSettings()

	if update.LLM != nil {
		if update.LLM.Mode != nil {
			settings.LLM.Mode = normalizeLLMMode(*update.LLM.Mode)
		}
		if update.LLM.BaseURL != nil {
			settings.LLM.BaseURL = strings.TrimSpace(*update.LLM.BaseURL)
		}
		if update.LLM.APIKey != nil {
			if value := strings.TrimSpace(*update.LLM.APIKey); value != "" && !utils.IsMaskedSecret(value) {
				settings.LLM.APIKey = value
			}
		}
		if update.LLM.Model != nil {
			settings.LLM.Model = strings.TrimSpace(*update.LLM.Model)
		}
		if update.LLM.Protocol != nil {
			settings.LLM.Protocol = llm.ResolveProtocol(*update.LLM.Protocol, settings.LLM.BaseURL)
		}
		if update.LLM.Temperature != nil {
			settings.LLM.Temperature = *update.LLM.Temperature
		}
		if update.LLM.Providers != nil {
			settings.LLM.Providers = mergeProviders(update.LLM.Providers, settings.LLM.Providers)
		}
	}

	if update.Fofa != nil {
		if update.Fofa.Key != nil {
			if value := strings.TrimSpace(*update.Fofa.Key); value != "" && !utils.IsMaskedSecret(value) {
				settings.Fofa.Key = value
			}
		}
		if update.Fofa.BaseURL != nil {
			settings.Fofa.BaseURL = strings.TrimSpace(*update.Fofa.BaseURL)
		}
		if update.Fofa.MaxPages != nil {
			settings.Fofa.MaxPages = clampInt(*update.Fofa.MaxPages, 1, constant.MaxPagesMax)
		}
		if update.Fofa.PageSize != nil {
			settings.Fofa.PageSize = clampInt(*update.Fofa.PageSize, 1, constant.PageSizeMax)
		}
		if update.Fofa.DefaultIntentMode != nil {
			settings.Fofa.DefaultIntentMode = strings.TrimSpace(*update.Fofa.DefaultIntentMode)
		}
	}

	if update.Engines != nil {
		if settings.Engines == nil {
			settings.Engines = map[string]model.EngineItem{}
		}
		for name, patch := range *update.Engines {
			item := settings.Engines[name]
			item.Name = name
			// base_url 不再入库：端点固定为官方默认（patch 里即使带了也忽略）。
			if patch.Enabled != nil {
				item.Enabled = *patch.Enabled
			}
			if patch.Key != nil {
				value := strings.TrimSpace(*patch.Key)
				if value == "" {
					item.Key = ""
				} else if !utils.IsMaskedSecret(value) {
					item.Key = value
				}
			}
			settings.Engines[name] = item
		}
	}

	if update.Defaults != nil {
		settings.Defaults.Concurrency = clampInt(update.Defaults.Concurrency, 1, constant.TaskConcurrencyMax)
		settings.Defaults.DeepenCap = utils.ClampDeepenCap(update.Defaults.DeepenCap)
		settings.Defaults.SkipScoreThreshold = update.Defaults.SkipScoreThreshold
		settings.Defaults.WorkerPromptVersion = strings.TrimSpace(update.Defaults.WorkerPromptVersion)
		settings.Defaults.Engine = engine.NormalizeEngine(update.Defaults.Engine)
		// 三个开关是 *bool：nil 表示前端本次未携带，保持原值不动（全量保存时前端总会带上）。
		if update.Defaults.AutoKillsweep != nil {
			settings.Defaults.AutoKillsweep = update.Defaults.AutoKillsweep
		}
		if update.Defaults.ShellEnabled != nil {
			settings.Defaults.ShellEnabled = update.Defaults.ShellEnabled
		}
		if update.Defaults.VerboseEvents != nil {
			settings.Defaults.VerboseEvents = update.Defaults.VerboseEvents
		}
	}
	if update.UI != nil {
		settings.UI = *update.UI
		settings.UI.Saved = true
	}
	if update.Proxy != nil {
		if update.Proxy.Enabled != nil {
			settings.Proxy.Enabled = *update.Proxy.Enabled
		}
		if update.Proxy.Proxies != nil {
			settings.Proxy.Proxies = mergeProxies(update.Proxy.Proxies, settings.Proxy.Proxies)
		}
	}

	if update.Persona != nil {
		settings.Persona = *update.Persona
		settings.Persona.Name = strings.TrimSpace(settings.Persona.Name)
		// Markdown 正文普遍较长：准则放宽到 5000 字（超限截断而非拒绝，保持原语义）。
		settings.Persona.Principles = utils.Truncate(settings.Persona.Principles, 5000)
	}

	if update.Skills != nil {
		skills := model.SkillsSettings{Enabled: update.Skills.Enabled, Items: update.Skills.Items}
		for i := range skills.Items {
			skills.Items[i].Name = strings.TrimSpace(skills.Items[i].Name)
			// Skill 正文不设上限：长 Markdown 完整保留，仅做首尾空白清理。
			if skills.Items[i].ID == "" {
				skills.Items[i].ID = utils.UUID()
			}
		}
		settings.Skills = skills
	}

	if update.Ima != nil {
		if update.Ima.Enabled != nil {
			settings.Ima.Enabled = *update.Ima.Enabled
		}
		if update.Ima.BaseURL != nil {
			settings.Ima.BaseURL = strings.TrimSpace(*update.Ima.BaseURL)
		}
		if update.Ima.APIKey != nil {
			if value := strings.TrimSpace(*update.Ima.APIKey); value != "" && !utils.IsMaskedSecret(value) {
				settings.Ima.APIKey = value
			}
		}
		if update.Ima.RepoID != nil {
			settings.Ima.RepoID = strings.TrimSpace(*update.Ima.RepoID)
		}
		if update.Ima.TopK != nil {
			settings.Ima.TopK = clampInt(*update.Ima.TopK, 1, 20)
		}
	}

	if update.Kali != nil {
		if update.Kali.Enabled != nil {
			settings.Kali.Enabled = *update.Kali.Enabled
		}
		if update.Kali.Host != nil {
			settings.Kali.Host = strings.TrimSpace(*update.Kali.Host)
		}
		if update.Kali.Port != nil {
			settings.Kali.Port = clampInt(*update.Kali.Port, 1, 65535)
		}
		if update.Kali.Username != nil {
			settings.Kali.Username = strings.TrimSpace(*update.Kali.Username)
		}
		if update.Kali.AuthType != nil {
			authType := strings.TrimSpace(*update.Kali.AuthType)
			if authType == "password" || authType == "key" {
				settings.Kali.AuthType = authType
			}
		}
		if update.Kali.Password != nil {
			if value := strings.TrimSpace(*update.Kali.Password); value != "" && !utils.IsMaskedSecret(value) {
				settings.Kali.Password = value
			}
		}
		if update.Kali.PrivateKey != nil {
			if value := strings.TrimSpace(*update.Kali.PrivateKey); value != "" && !utils.IsMaskedSecret(value) {
				settings.Kali.PrivateKey = value
			}
		}
		if update.Kali.Categories != nil {
			valid := map[string]bool{}
			for _, c := range model.KaliCategories {
				valid[c.Key] = true
			}
			seen := map[string]bool{}
			categories := make([]string, 0, len(update.Kali.Categories))
			for _, key := range update.Kali.Categories {
				if valid[key] && !seen[key] {
					seen[key] = true
					categories = append(categories, key)
				}
			}
			settings.Kali.Categories = categories
		}
	}

	settings.UpdatedAt = time.Now()
	if err := engine.SaveSystemSettings(settings); err != nil {
		return nil, err
	}
	// 保存后立刻同步进程内运行时开关（Shell 执行 / 噪音事件），不重启即生效。
	engine.ApplyRuntimeFlags(settings)
	return LoadSettingsView(), nil
}

// mergeProviders 合并端点池：保留旧密钥（入参为脱敏串时），新端点自动生成名称。
func mergeProviders(incoming []model.LLMProvider, existing []model.LLMProvider) []model.LLMProvider {
	old := map[string]string{}
	for _, p := range existing {
		old[utils.IdentityRef(p.BaseURL, p.Name)] = p.APIKey
	}
	out := make([]model.LLMProvider, 0, len(incoming))
	for _, p := range incoming {
		p.Name = strings.TrimSpace(p.Name)
		p.BaseURL = strings.TrimSpace(p.BaseURL)
		p.Model = strings.TrimSpace(p.Model)
		if p.Name == "" {
			p.Name = utils.SecretRef(p.BaseURL)
		}
		value := strings.TrimSpace(p.APIKey)
		if value == "" || utils.IsMaskedSecret(value) {
			if kept, ok := old[utils.IdentityRef(p.BaseURL, p.Name)]; ok {
				p.APIKey = kept
			} else {
				p.APIKey = ""
			}
		}
		p.Protocol = llm.ResolveProtocol(p.Protocol, p.BaseURL)
		if p.Weight <= 0 {
			p.Weight = 1
		}
		out = append(out, p)
	}
	return out
}

// mergeProxies 合并代理池：脱敏密码视为未修改。
func mergeProxies(incoming []model.ProxyItem, existing []model.ProxyItem) []model.ProxyItem {
	old := map[string]string{}
	for _, p := range existing {
		old[p.ID] = p.Password
	}
	if len(incoming) > constant.ProxyMaxItems {
		incoming = incoming[:constant.ProxyMaxItems]
	}
	out := make([]model.ProxyItem, 0, len(incoming))
	for _, p := range incoming {
		p.ID = strings.TrimSpace(p.ID)
		if p.ID == "" {
			p.ID = utils.UUID()
		}
		p.Host = strings.TrimSpace(p.Host)
		p.Name = strings.TrimSpace(p.Name)
		p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
		if p.Protocol == "" {
			p.Protocol = "http"
		}
		value := strings.TrimSpace(p.Password)
		if value == "" || utils.IsMaskedSecret(value) {
			if kept, ok := old[p.ID]; ok {
				p.Password = kept
			} else {
				p.Password = ""
			}
		}
		out = append(out, p)
	}
	return out
}

// normalizeLLMMode 归一化调度模式。
func normalizeLLMMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "pool", "multi", "loadbalance":
		return "pool"
	default:
		return "single"
	}
}

// ResolveEngineConfig 解析某引擎的可用配置（key / base_url）。
// 端点固定为该引擎官方默认端点（不读用户配置——测绘 API 均为官方固定入口）。
func ResolveEngineConfig(engineName string) (string, string) {
	settings := engine.LoadSystemSettings()
	name := engine.NormalizeEngine(engineName)
	if item, ok := settings.Engines[name]; ok && strings.TrimSpace(item.Key) != "" {
		return item.Key, engine.DefaultEngineBaseURL(name)
	}
	if name == "fofa" {
		return settings.Fofa.Key, engine.DefaultEngineBaseURL("fofa")
	}
	return "", engine.DefaultEngineBaseURL(name)
}

// normalizeBaseURL 端点地址归一（去尾部单个斜杠），用于 key_ref/密钥复用匹配。
func normalizeBaseURL(u string) string {
	return strings.TrimSuffix(strings.TrimSpace(u), "/")
}

// ResolveLLMEndpoint 把用户传入的端点信息解析为实际可用的 base_url 与
// 明文 API Key：入参为空或脱敏串时回落到已保存配置（key_ref 命中端点池时
// 用对应条目；单端点 key_ref 为 IdentityRef(base_url)，按 base_url 指纹
// 兜底命中同地址池条目）。ListAvailableModels / LLMBalance 共用。
func ResolveLLMEndpoint(baseURL, apiKey, keyRef string) (string, string) {
	settings := engine.LoadSystemSettings()
	if strings.TrimSpace(baseURL) == "" {
		baseURL = settings.LLM.BaseURL
	}
	if strings.TrimSpace(apiKey) == "" || utils.IsMaskedSecret(apiKey) {
		apiKey = settings.LLM.APIKey
		probe := normalizeBaseURL(baseURL)
		if keyRef != "" {
			for _, provider := range settings.LLM.Providers {
				providerURL := normalizeBaseURL(provider.BaseURL)
				// 池条目引用（IdentityRef(base_url, name)）与单端点引用（IdentityRef(base_url)）都能命中
				if utils.IdentityRef(provider.BaseURL, provider.Name) == keyRef || utils.IdentityRef(providerURL) == keyRef {
					apiKey = provider.APIKey
					if baseURL == "" {
						baseURL = provider.BaseURL
					}
					break
				}
			}
		}
		// 仍无密钥时按 base_url 指纹复用端点池中同地址条目的密钥
		if (strings.TrimSpace(apiKey) == "" || utils.IsMaskedSecret(apiKey)) && probe != "" {
			for _, provider := range settings.LLM.Providers {
				if normalizeBaseURL(provider.BaseURL) == probe && strings.TrimSpace(provider.APIKey) != "" {
					apiKey = provider.APIKey
					break
				}
			}
		}
	}
	return baseURL, apiKey
}

// ListAvailableModels 列出某端点可用的模型。
func ListAvailableModels(ctx context.Context, baseURL, apiKey, protocol, keyRef string) ([]string, error) {
	baseURL, apiKey = ResolveLLMEndpoint(baseURL, apiKey, keyRef)
	pool := engine.BuildPoolFromRaw(baseURL, apiKey, "probe", protocol)
	return pool.ListModels(ctx, baseURL, apiKey, protocol)
}

// LLMBalance 查询中转站（NewAPI / One API 系）余额与配额。
// Sub2API 等无 billing 兼容接口的网关返回 Supported=false，不作为错误。
func LLMBalance(ctx context.Context, baseURL, apiKey, keyRef string) (*llm.BillingInfo, error) {
	baseURL, apiKey = ResolveLLMEndpoint(baseURL, apiKey, keyRef)
	return llm.NewClient().Billing(ctx, baseURL, apiKey)
}

// TestLLMEndpoint 测试单个 LLM 端点连通性。
//
// 返回结构对齐原版 /api/settings/test-llm：{ok, results, error_copy}，
// 无可用端点时额外返回 error。⚠️ 顶层 ok 必不可少——原版前端与实现前端
// 都以它决定「LLM 可用 / 不可用」，漏掉会让测试通过却显示失败。
func TestLLMEndpoint(ctx context.Context, baseURL, apiKey, modelName, protocol string) map[string]any {
	settings := engine.LoadSystemSettings()
	if strings.TrimSpace(baseURL) == "" {
		baseURL = settings.LLM.BaseURL
	}
	if strings.TrimSpace(apiKey) == "" || utils.IsMaskedSecret(apiKey) {
		apiKey = settings.LLM.APIKey
	}
	if strings.TrimSpace(modelName) == "" {
		modelName = settings.LLM.Model
	}
	pool := engine.BuildPoolFromRaw(baseURL, apiKey, modelName, protocol)
	results := pool.TestAll(ctx)
	recordProbeResults(results, pool.Endpoints())
	return llmTestReport(results)
}

// TestLLMProviders 测试显式传入的端点集合（原版 providers 入参语义）。
// 多端点模式下前端「测试端点」会带上单个端点，走这条路径。
func TestLLMProviders(ctx context.Context, providers []model.LLMProvider) map[string]any {
	settings := engine.LoadSystemSettings()
	saved := settings.LLM.Providers
	endpoints := make([]llm.Endpoint, 0, len(providers))
	for index, item := range providers {
		// 严格按 enabled 过滤（对齐原版 `if item.get("enabled", True)`）；
		// 「缺省视为启用」由调用方在解析入参时补齐，此处只认最终值。
		if !item.Enabled {
			continue
		}
		apiKey := strings.TrimSpace(item.APIKey)
		if apiKey == "" || utils.IsMaskedSecret(apiKey) {
			apiKey = resolveSavedProviderKey(saved, item)
			if apiKey == "" {
				apiKey = settings.LLM.APIKey
			}
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = "llm-" + strconv.Itoa(index+1)
		}
		baseURL := strings.TrimSpace(item.BaseURL)
		endpoints = append(endpoints, llm.Endpoint{
			Name:        name,
			BaseURL:     baseURL,
			APIKey:      apiKey,
			Model:       strings.TrimSpace(item.Model),
			Protocol:    llm.ResolveProtocol(item.Protocol, baseURL),
			Temperature: item.Temperature,
			Weight:      item.Weight,
		})
	}
	pool := llm.NewPool(endpoints)
	results := pool.TestAll(ctx)
	recordProbeResults(results, pool.Endpoints())
	return llmTestReport(results)
}

// recordProbeResults 把手动测试结果写入探测注册表（与生产熔断器完全隔离，
// 只在 ProviderHealth 展示层合并下发——契约：手动测试绝不写 Health().Mark）。
// 按 name 配对端点，配不上时按 base_url+model 兜底。
func recordProbeResults(results []map[string]any, endpoints []llm.Endpoint) {
	byName := make(map[string]llm.Endpoint, len(endpoints))
	for _, ep := range endpoints {
		byName[ep.Name] = ep
	}
	for _, item := range results {
		name, _ := item["name"].(string)
		ep, ok := byName[name]
		if !ok {
			baseURL, _ := item["base_url"].(string)
			modelName, _ := item["model"].(string)
			for _, candidate := range endpoints {
				if candidate.BaseURL == baseURL && candidate.Model == modelName {
					ep = candidate
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}
		errText, _ := item["error"].(string)
		var latencyMS int64
		switch v := item["latency_ms"].(type) {
		case int64:
			latencyMS = v
		case int:
			latencyMS = int64(v)
		case float64:
			latencyMS = int64(v)
		}
		llm.Probes().Record(ep.BaseURL, ep.Model, ep.Protocol, errText, latencyMS)
	}
}

// llmTestReport 汇总单端点/多端点的测试结果，口径与原版一致：
// ok = 所有端点都通过；error_copy = 各端点诊断文本以空行拼接。
func llmTestReport(results []map[string]any) map[string]any {
	if len(results) == 0 {
		return map[string]any{
			"ok":         false,
			"results":    results,
			"error":      "未配置可用 LLM 端点",
			"error_copy": "ok=False\nerror=未配置可用 LLM 端点",
		}
	}
	allOK := true
	copies := make([]string, 0, len(results))
	for _, item := range results {
		if ok, _ := item["ok"].(bool); !ok {
			allOK = false
		}
		if copyText, _ := item["error_copy"].(string); copyText != "" {
			copies = append(copies, copyText)
		}
	}
	return map[string]any{
		"ok":         allOK,
		"results":    results,
		"error_copy": strings.Join(copies, "\n\n"),
	}
}

// resolveSavedProviderKey 在入参未带明文密钥（省略或回传脱敏串）时，
// 从已保存端点里按 name、其次按 base_url+model 回退取回真实密钥，
// 对齐原版 _preserve_provider_keys 的语义。
func resolveSavedProviderKey(saved []model.LLMProvider, incoming model.LLMProvider) string {
	name := strings.TrimSpace(incoming.Name)
	if name != "" {
		for _, item := range saved {
			if strings.TrimSpace(item.Name) == name {
				return item.APIKey
			}
		}
	}
	baseURL := strings.TrimSpace(incoming.BaseURL)
	modelName := strings.TrimSpace(incoming.Model)
	for _, item := range saved {
		if strings.TrimSpace(item.BaseURL) == baseURL && strings.TrimSpace(item.Model) == modelName {
			return item.APIKey
		}
	}
	return ""
}

// ProviderHealth 返回端点健康快照。
// 生产健康（HealthRegistry）为主，手动测试探测记录（ProbeRegistry）在展示层
// 按 base_url+model 合并进 probe_* 字段——探测记录不进生产熔断器。
func ProviderHealth() map[string]any {
	snapshots := llm.Health().All()
	items := make([]map[string]any, 0, len(snapshots))
	healthy := 0
	itemIndex := make(map[string]int, len(snapshots))
	for _, snap := range snapshots {
		if snap.Status == llm.HealthOK {
			healthy++
		}
		items = append(items, map[string]any{
			"ref":                  snap.Ref,
			"base_url":             snap.BaseURL,
			"model":                snap.Model,
			"protocol":             snap.Protocol,
			"status":               snap.Status,
			"transport_status":     snap.TransportStatus,
			"behavior_status":      snap.BehaviorStatus,
			"consecutive_failures": snap.ConsecutiveFailures,
			"cooldown_seconds":     snap.CooldownSeconds,
			"cooldown_until_ts":    snap.CooldownUntilTS,
			"last_error":           snap.LastError,
			"error_kind":           snap.ErrorKind,
			"last_seen":            snap.LastSeen,
			"success_count":        snap.SuccessCount,
			"failure_count":        snap.FailureCount,
		})
		itemIndex[snap.BaseURL+"|"+snap.Model] = len(items) - 1
	}
	// 合并手动测试探测记录：已 有健康快照的端点只补 probe_* 字段；
	// 只测试过、从未运行时调用的端点补一条 status=untested 的合成条目。
	for _, probe := range llm.Probes().All() {
		idx, hit := itemIndex[probe.BaseURL+"|"+probe.Model]
		if !hit {
			idx = len(items)
			itemIndex[probe.BaseURL+"|"+probe.Model] = idx
			items = append(items, map[string]any{
				"ref":                  probe.Ref,
				"base_url":             probe.BaseURL,
				"model":                probe.Model,
				"protocol":             probe.Protocol,
				"status":               llm.HealthUntested,
				"transport_status":     llm.HealthUntested,
				"behavior_status":      llm.HealthUntested,
				"consecutive_failures": 0,
				"cooldown_seconds":     0,
				"cooldown_until_ts":    0,
				"last_error":           "",
				"error_kind":           "",
				"last_seen":            "",
				"success_count":        0,
				"failure_count":        0,
			})
		}
		items[idx]["probe_status"] = probe.Status
		items[idx]["probe_at"] = probe.ProbedAt
		items[idx]["probe_error"] = probe.Error
		items[idx]["probe_latency_ms"] = probe.LatencyMS
	}
	active := engine.BuildGlobalPool()
	ok := 0
	for _, ep := range active.Endpoints() {
		ref := utils.IdentityRef(ep.BaseURL, ep.Model, ep.Protocol)
		if llm.Health().Available(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey) {
			ok++
		}
		_ = ref
	}
	return map[string]any{
		"items":      items,
		"total":      len(items),
		"healthy":    healthy,
		"pool_size":  active.Size(),
		"available":  ok,
		"mode":       engine.LoadSystemSettings().LLM.Mode,
		"checked_at": utils.ToCSTISO(time.Now()),
	}
}

// WorkdirStats 统计工作目录占用。
func WorkdirStats() map[string]any {
	root := config.WorkRootDir()
	var total int64
	files := 0
	dirs := 0
	var oldestName string
	var oldestTime time.Time
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dirs++
			dirPath := filepath.Join(root, entry.Name())
			if info, err := entry.Info(); err == nil {
				if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
					oldestTime = info.ModTime()
					oldestName = entry.Name()
				}
			}
			_ = filepath.Walk(dirPath, func(_ string, info os.FileInfo, err error) error {
				if err != nil || info == nil || info.IsDir() {
					return nil
				}
				total += info.Size()
				files++
				return nil
			})
		}
	}
	limit := config.AppConfig.Data.WorkMaxBytes
	usage := 0.0
	if limit > 0 {
		usage = float64(total) / float64(limit) * 100
	}
	view := map[string]any{
		"path":             root,
		"root":             root,
		"bytes":            total,
		"total_bytes":      total,
		"total_size_human": utils.HumanBytes(total),
		"files":            files,
		"total_files":      files,
		"total_dirs":       dirs,
		"limit_bytes":      limit,
		"usage_percent":    usage,
		"overflowed":       limit > 0 && total >= limit,
	}
	if !oldestTime.IsZero() {
		view["oldest_dir"] = map[string]any{
			"name":     oldestName,
			"age_days": int(time.Since(oldestTime).Hours() / 24),
		}
	}
	return view
}

// CleanupWorkdir 清理工作目录中的过期任务目录。
func CleanupWorkdir() map[string]any {
	root := config.WorkRootDir()
	retention := config.AppConfig.Data.RetentionDays
	deadline := time.Now().Add(-time.Duration(retention) * 24 * time.Hour)

	active := map[string]bool{}
	var tasks []model.Task
	core.Db.Model(&model.Task{}).
		Where("status IN ?", []string{constant.TaskRunning, constant.TaskIdle, constant.TaskPaused}).
		Pluck("id", &tasks)
	for _, t := range tasks {
		active[t.ID] = true
	}

	removed := make([]string, 0, 16)
	removedDetails := make([]map[string]any, 0, 16)
	freed := int64(0)
	scanned := 0
	failed := 0
	entries, err := os.ReadDir(root)
	if err != nil {
		return map[string]any{
			"removed": removed, "removed_count": 0, "scanned_dirs": 0,
			"deleted_dirs": 0, "failed_dirs": 0, "freed_bytes": 0,
			"freed_human": "0 B", "retention_days": retention, "error": err.Error(),
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() || active[entry.Name()] {
			continue
		}
		scanned++
		info, err := entry.Info()
		if err != nil || info.ModTime().After(deadline) {
			continue
		}
		dirPath := filepath.Join(root, entry.Name())
		dirFreed := int64(0)
		_ = filepath.Walk(dirPath, func(_ string, fi os.FileInfo, err error) error {
			if err == nil && fi != nil && !fi.IsDir() {
				dirFreed += fi.Size()
			}
			return nil
		})
		if err := os.RemoveAll(dirPath); err == nil {
			removed = append(removed, entry.Name())
			freed += dirFreed
			removedDetails = append(removedDetails, map[string]any{
				"name":       entry.Name(),
				"age_days":   int(time.Since(info.ModTime()).Hours() / 24),
				"size_bytes": dirFreed,
				"size_human": utils.HumanBytes(dirFreed),
			})
		} else {
			failed++
		}
	}
	return map[string]any{
		"removed":        removed,
		"removed_count":  len(removed),
		"scanned_dirs":   scanned,
		"deleted_dirs":   len(removed),
		"failed_dirs":    failed,
		"deleted":        removedDetails,
		"freed_bytes":    freed,
		"freed_human":    utils.HumanBytes(freed),
		"retention_days": retention,
	}
}

// ===== 图片壁纸（UI 偏好）=====

// WallpaperDir 返回壁纸目录。
func WallpaperDir() string {
	dir := strings.TrimSpace(config.AppConfig.Data.WallpaperDir)
	if dir == "" {
		dir = filepath.Join(config.WorkRootDir(), "wallpapers")
	}
	return dir
}

// wallpaperExts 壁纸扩展名白名单。
// 不收 .svg：SVG 可内嵌 <script>，经 /raw 原样回源会构成存储型 XSS。
var wallpaperExts = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".bmp":  "image/bmp",
}

// WallpaperContentType 返回扩展名对应的固定 Content-Type（未知扩展返回空）。
func WallpaperContentType(ext string) string {
	return wallpaperExts[strings.ToLower(ext)]
}

// SaveWallpaper 保存上传的壁纸文件。
//
// 安全约束（防文件上传/包含漏洞）：
//  1. 扩展名白名单（拒绝 .php/.html/.svg 等，落盘文件名固定为 wallpaper+白名单ext，无路径拼接）；
//  2. 魔数嗅探（http.DetectContentType 必须为 image/*）——改后缀伪装的 HTML/PHP/脚本直接拒绝；
//  3. 写入目录为服务端工作目录（非 web 静态根），只能经 ServeWallpaper 回源。
func SaveWallpaper(filename string, data []byte) (string, error) {
	ext := strings.ToLower(filepath.Ext(filename))
	contentType := wallpaperExts[ext]
	if contentType == "" {
		return "", errors.New("仅支持 png/jpg/jpeg/gif/webp/bmp 图片")
	}
	if sniffed := http.DetectContentType(data); !strings.HasPrefix(sniffed, "image/") {
		return "", errors.New("文件内容不是有效图片（已拒绝非图片数据）")
	}
	dir := WallpaperDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// 清掉旧扩展的壁纸，避免 FindWallpaper 命中过期文件。
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasPrefix(entry.Name(), "wallpaper.") {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
			}
		}
	}
	target := filepath.Join(dir, "wallpaper"+ext)
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return "", err
	}
	settings := engine.LoadSystemSettings()
	settings.UI.WallpaperKind = "file"
	settings.UI.WallpaperURL = "/api/settings/ui/wallpaper/raw"
	settings.UI.Saved = true
	_ = engine.SaveSystemSettings(settings)
	return target, nil
}

// ClearWallpaper 清除壁纸并重置 UI 偏好。
func ClearWallpaper() error {
	dir := WallpaperDir()
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
		}
	}
	settings := engine.LoadSystemSettings()
	settings.UI.WallpaperKind = "none"
	settings.UI.WallpaperURL = ""
	settings.UI.Saved = true
	return engine.SaveSystemSettings(settings)
}

// FindWallpaper 查找已上传的壁纸文件路径。
func FindWallpaper() string {
	dir := WallpaperDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		return filepath.Join(dir, entry.Name())
	}
	return ""
}

// ===== 小工具 =====

func firstNotEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
