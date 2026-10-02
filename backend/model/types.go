package model

import "time"

// AuthBinding 用户登录凭据绑定。target 可为 URL / host / *（全部目标默认）。
type AuthBinding struct {
	Target        string `json:"target"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Cookie        string `json:"cookie"`
	Authorization string `json:"authorization"`
	LoginURL      string `json:"login_url"`
	Raw           string `json:"raw"`
	Note          string `json:"note"`
	// MatchedBy 入队匹配时的命中方式（url / line / hostport / host / default），
	// 仅用于提示词与事件展示，不含任何凭据内容。
	MatchedBy string `json:"matched_by,omitempty"`
}

// HasCredential 判断该绑定是否含任何有效凭据内容。
func (b AuthBinding) HasCredential() bool {
	return b.Username != "" || b.Password != "" || b.Cookie != "" ||
		b.Authorization != "" || b.Raw != ""
}

// LLMProvider 端点池中的单个 LLM 端点。
type LLMProvider struct {
	Name        string  `json:"name"`
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"`
	// KeyRef 引用系统配置中已存端点的标识（IdentityRef(base_url,name)）。
	// 任务端点未自带明文 key 时，运行时按它从系统配置回落解析——
	// 用户在系统设置里存过 key 的端点，任务表单无需重复输入。
	KeyRef      string  `json:"key_ref"`
	Model       string  `json:"model"`
	Protocol    string  `json:"protocol"`
	Temperature float64 `json:"temperature"`
	Weight      int     `json:"weight"`
	Enabled     bool    `json:"enabled"`
}

// Complete 判断端点配置是否完整（可参与调度）。
func (p LLMProvider) Complete() bool {
	return p.BaseURL != "" && p.Model != "" && p.APIKey != ""
}

// LLMModelConfig 任务级模型配置。
type LLMModelConfig struct {
	// InheritGlobal 为 true 时忽略单端点字段，直接使用系统全局配置。
	InheritGlobal *bool         `json:"inherit_global,omitempty"`
	BaseURL       string        `json:"base_url,omitempty"`
	APIKey        string        `json:"api_key,omitempty"`
	// KeyRef 引用系统配置已存端点（单端点模式免重输 key，运行时回落解析）。
	KeyRef        string        `json:"key_ref,omitempty"`
	Model         string        `json:"model,omitempty"`
	Protocol      string        `json:"protocol,omitempty"`
	PromptVersion string        `json:"prompt_version,omitempty"`
	Providers     []LLMProvider `json:"providers,omitempty"`
}

// IsInherit 判断是否继承全局配置。
func (c LLMModelConfig) IsInherit() bool {
	if c.InheritGlobal != nil {
		return *c.InheritGlobal
	}
	// 未显式设置：无任何单端点字段且无端点池时视为继承全局
	return c.BaseURL == "" && c.APIKey == "" && c.Model == "" && len(c.Providers) == 0
}

// FofaConfig 测绘引擎配置（任务级）。cursor/current_query 等为翻页运行时状态。
type FofaConfig struct {
	Key               string `json:"key"`
	BaseURL           string `json:"base_url"`
	MaxPages          int    `json:"max_pages"`
	PageSize          int    `json:"page_size"`
	IntentMode        string `json:"intent_mode"`
	SkipSiteRecon     bool   `json:"skip_site_recon"`
	Cursor            int    `json:"cursor"`
	CurrentQuery      string `json:"current_query"`
	History           []int  `json:"history,omitempty"`
	EmptyStreak       int    `json:"empty_streak"`
	EmptyQueryStreak  int    `json:"empty_query_streak"`
	FofaExhausted     bool   `json:"fofa_exhausted"`
	LastFofaError     string `json:"last_fofa_error"`
	FofaAuthFailCount int    `json:"fofa_auth_fail_count"`
	DailyLimitCount   int    `json:"daily_limit_count"`
	// EngineFailCount 引擎查询连续失败次数（成功后清零；达上限停止自动重试）。
	EngineFailCount int `json:"engine_fail_count"`
	// NextRetryAt 失败退避截止时间（零值=立即可试）。同一页 5 秒盲重试的刹车：
	// 失败后按指数退避等待，期间主循环 tick 直接跳过引擎查询。
	NextRetryAt time.Time `json:"next_retry_at"`
	// IntentQuery 意图模式解析出的引擎查询语法缓存（避免每轮重复调 LLM）。
	IntentQuery string `json:"intent_query"`
	// IntentQueryFor 缓存对应的「原始意图|引擎」键，变更后自动重新解析。
	IntentQueryFor string `json:"intent_query_for,omitempty"`
	CollectorPhase string `json:"collector_phase"`
	// CollectorPhaseText 看板展示的搜集阶段文案。
	CollectorPhaseText string `json:"collector_phase_text"`
	// CollectorPhasePayload 阶段附加信息（如入队进度 x/y）。
	CollectorPhasePayload map[string]any `json:"collector_phase_payload,omitempty"`
}

// LLMRuntime 任务持久化的模型用量快照。
type LLMRuntime struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	CachedTokens     int64 `json:"cached_tokens"`
	Requests         int64 `json:"requests"`
	Errors           int64 `json:"errors"`
}

// EngineRuntime 任务持久化的测绘用量快照。
type EngineRuntime struct {
	Calls int64 `json:"calls"`
	Quota int64 `json:"quota"`
	Pages int64 `json:"pages"`
}

// RuntimeStats 任务运行统计快照（落库，重启后仍可读）。
type RuntimeStats struct {
	LLM    LLMRuntime    `json:"llm"`
	Engine EngineRuntime `json:"engine"`
}
