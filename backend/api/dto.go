package api

import (
	"strconv"
	"strings"

	"AiSRC/model"

	"github.com/gin-gonic/gin"
)

// ===== 请求 DTO（与 AutoHunter dto.py 一一对应）=====

// ModelConfigDTO 任务级模型配置。
type ModelConfigDTO struct {
	InheritGlobal *bool               `json:"inherit_global"`
	BaseURL       string              `json:"base_url"`
	APIKey        string              `json:"api_key"`
	KeyRef        string              `json:"key_ref"`
	Model         string              `json:"model"`
	Protocol      string              `json:"protocol"`
	PromptVersion string              `json:"prompt_version"`
	Providers     []model.LLMProvider `json:"providers"`
}

// ToModel 转成领域模型。
func (d ModelConfigDTO) ToModel() model.LLMModelConfig {
	return model.LLMModelConfig{
		InheritGlobal: d.InheritGlobal,
		BaseURL:       strings.TrimSpace(d.BaseURL),
		APIKey:        strings.TrimSpace(d.APIKey),
		KeyRef:        strings.TrimSpace(d.KeyRef),
		Model:         strings.TrimSpace(d.Model),
		Protocol:      strings.TrimSpace(d.Protocol),
		PromptVersion: strings.TrimSpace(d.PromptVersion),
		Providers:     d.Providers,
	}
}

// PartialModelConfigDTO 局部模型配置（PATCH 用）。
type PartialModelConfigDTO struct {
	InheritGlobal *bool               `json:"inherit_global"`
	BaseURL       *string             `json:"base_url"`
	APIKey        *string             `json:"api_key"`
	KeyRef        *string             `json:"key_ref"`
	Model         *string             `json:"model"`
	Protocol      *string             `json:"protocol"`
	PromptVersion *string             `json:"prompt_version"`
	Providers     []model.LLMProvider `json:"providers"`
}

// FofaConfigDTO 任务级测绘配置。
type FofaConfigDTO struct {
	Key           string `json:"key"`
	BaseURL       string `json:"base_url"`
	MaxPages      int    `json:"max_pages"`
	PageSize      int    `json:"page_size"`
	IntentMode    string `json:"intent_mode"`
	SkipSiteRecon bool   `json:"skip_site_recon"`
}

// ToModel 转成领域模型。
func (d FofaConfigDTO) ToModel() model.FofaConfig {
	return model.FofaConfig{
		Key:           strings.TrimSpace(d.Key),
		BaseURL:       strings.TrimSpace(d.BaseURL),
		MaxPages:      d.MaxPages,
		PageSize:      d.PageSize,
		IntentMode:    strings.TrimSpace(d.IntentMode),
		SkipSiteRecon: d.SkipSiteRecon,
	}
}

// PartialFofaConfigDTO 局部测绘配置。
type PartialFofaConfigDTO struct {
	Key           *string `json:"key"`
	BaseURL       *string `json:"base_url"`
	MaxPages      *int    `json:"max_pages"`
	PageSize      *int    `json:"page_size"`
	IntentMode    *string `json:"intent_mode"`
	SkipSiteRecon *bool   `json:"skip_site_recon"`
}

// EngineConfigDTO 引擎 Key / URL。
type EngineConfigDTO struct {
	Key     string `json:"key"`
	BaseURL string `json:"base_url"`
}

// PartialEngineConfigDTO 局部引擎配置。
type PartialEngineConfigDTO struct {
	Key     *string `json:"key"`
	BaseURL *string `json:"base_url"`
}

// CreateTaskRequest 创建任务请求。
type CreateTaskRequest struct {
	Name          string              `json:"name"`
	SrcType       string              `json:"src_type"`
	VulnTypes     []string            `json:"vuln_types"`
	SrcRules      string              `json:"src_rules"`
	TargetSource  string              `json:"target_source"`
	Engine        string              `json:"engine"`
	FofaQuery     string              `json:"fofa_query"`
	ManualTargets []string            `json:"manual_targets"`
	AuthBindings  []model.AuthBinding `json:"auth_bindings"`
	ModelConfig   ModelConfigDTO      `json:"model_config_data"`
	FofaConfig    FofaConfigDTO       `json:"fofa_config"`
	EngineConfig  EngineConfigDTO     `json:"engine_config"`
	Concurrency   int                 `json:"concurrency"`
	DeepenCap     int                 `json:"deepen_cap"`
	// 指针类型用于区分「未提交」与「显式 false」：原版默认开启通杀，
	// 若用普通 bool，前端传 false 会与「未传」无法区分。
	AutoKillsweep *bool `json:"auto_killsweep"`
}

// UpdateTaskRequest 更新任务请求（字段全可选）。
type UpdateTaskRequest struct {
	Name          *string                 `json:"name"`
	SrcType       *string                 `json:"src_type"`
	VulnTypes     []string                `json:"vuln_types"`
	SrcRules      *string                 `json:"src_rules"`
	TargetSource  *string                 `json:"target_source"`
	Engine        *string                 `json:"engine"`
	FofaQuery     *string                 `json:"fofa_query"`
	ManualTargets []string                `json:"manual_targets"`
	AuthBindings  []model.AuthBinding     `json:"auth_bindings"`
	ModelConfig   *PartialModelConfigDTO  `json:"model_config_data"`
	FofaConfig    *PartialFofaConfigDTO   `json:"fofa_config"`
	EngineConfig  *PartialEngineConfigDTO `json:"engine_config"`
	Concurrency   *int                    `json:"concurrency"`
	DeepenCap     *int                    `json:"deepen_cap"`
	AutoKillsweep *bool                   `json:"auto_killsweep"`
}

// DirectiveRequest 向运行中 worker 注入指令。
type DirectiveRequest struct {
	Directive string `json:"directive"`
}

// TaskModelsProbeRequest 探测任务级模型端点可用模型。
type TaskModelsProbeRequest struct {
	BaseURL  *string `json:"base_url"`
	APIKey   *string `json:"api_key"`
	KeyRef   *string `json:"key_ref"`
	Protocol *string `json:"protocol"`
}

// BatchTopRequest 批量置顶请求。
type BatchTopRequest struct {
	IDs   []string `json:"ids"`
	IsTop *bool    `json:"is_top"`
}

// ToggleTopRequest 单条置顶请求。
type ToggleTopRequest struct {
	IsTop *bool `json:"is_top"`
}

// RestoreRequest 恢复归档请求。
type RestoreRequest struct {
	IsTop *bool `json:"is_top"`
}

// DeepenRequest 打回深挖请求。
type DeepenRequest struct {
	Directive string `json:"directive"`
}

// UpdateResultRequest 结果字段更新请求。
type UpdateResultRequest struct {
	UserStatus   *string        `json:"user_status"`
	UserSeverity *string        `json:"user_severity"`
	UserNotes    *string        `json:"user_notes"`
	UserEdits    map[string]any `json:"user_edits"`
	Submitted    *bool          `json:"submitted"`
	IsTop        *bool          `json:"is_top"`
}

// AssistantRequest 报告助手请求。
type AssistantRequest struct {
	Message   string `json:"message"`
	FindingID string `json:"finding_id"`
}

// ProxyCreateRequest 新增代理请求。
type ProxyCreateRequest struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  *bool  `json:"enabled"`
}

// ProxyUpdateRequest 更新代理请求。
type ProxyUpdateRequest struct {
	Name     *string `json:"name"`
	Protocol *string `json:"protocol"`
	Host     *string `json:"host"`
	Port     *int    `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	Enabled  *bool   `json:"enabled"`
}

// ProxyToggleRequest 代理池总开关。
type ProxyToggleRequest struct {
	Enabled *bool `json:"enabled"`
}

// ProxyImportRequest 批量导入代理解析。
type ProxyImportRequest struct {
	Raw     string `json:"raw"`
	Content string `json:"content"`
	Replace bool   `json:"replace"`
}

// ProxyTestRequest 代理连通性测试。
type ProxyTestRequest struct {
	IDs []string `json:"ids"`
}

// LoginRequest 登录请求。
//
// 账号密码登录：Username 必须与服务端 `token.username` 一致（未配置时回落 admin），
// 不再「留空即 admin」；CaptchaID/CaptchaCode 仅在连续失败达阈值后必填（其余时候忽略）。
type LoginRequest struct {
	Password string `json:"password"`
	Username string `json:"username"`
	// CaptchaID 为 /api/auth/captcha 下发的验证码标识；CaptchaCode 为用户输入的 4 位数字。
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

// UpdateSettingsRequest 设置更新请求（透传给 service）。
type UpdateSettingsRequest struct {
	LLM      map[string]any `json:"llm"`
	Fofa     map[string]any `json:"fofa"`
	Engines  map[string]any `json:"engines"`
	Defaults map[string]any `json:"defaults"`
	UI       map[string]any `json:"ui"`
	Proxy    map[string]any `json:"proxy"`
}

// AssistStreamRequest 报告助手流式请求。
type AssistStreamRequest struct {
	Message string `json:"message"`
}

// ===== 通用请求辅助 =====

// queryInt 读取整型查询参数。
func queryInt(c *gin.Context, name string, fallback int) int {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

// queryBool 读取布尔查询参数。
func queryBool(c *gin.Context, name string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(c.Query(name)))
	if raw == "" {
		return fallback
	}
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

// queryString 读取字符串查询参数（trim）。
func queryString(c *gin.Context, name string) string {
	return strings.TrimSpace(c.Query(name))
}

// pathParam 读取路径参数。
func pathParam(c *gin.Context, name string) string {
	return strings.TrimSpace(c.Param(name))
}
