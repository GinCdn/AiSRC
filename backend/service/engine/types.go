package engine

import "AiSRC/model"

// 引擎内部使用的轻量视图对象（避免在提示词组装时携带完整 GORM 实体）。

// TaskBrief 任务摘要。
type TaskBrief struct {
	ID             string
	Name           string
	SrcType        string
	VulnTypes      []string
	SrcRules       string
	TargetSource   string
	Engine         string
	FofaQuery      string
	ManualTargets  []string
	Concurrency    int
	DeepenCap      int
	AutoKillsweep  bool
	CandidatesJSON string
}

// WorkerContext Worker 启动上下文。
type WorkerContext struct {
	TaskID          string
	TargetID        string
	URL             string
	Host            string
	Title           string
	Org             string
	SrcType         string
	VulnTypes       []string
	SrcRules        string
	AuthContext     *model.AuthBinding
	LeakedCreds     string
	IntelHint       string
	DeepenDirective string
	// 单站协作：site_* 路线目标的分工上下文（已渲染好的提示词块）。
	SiteRouteSource string
	SiteCollabBlock string
}

// FindingBrief 漏洞摘要（供审核 / 通杀 / 助手使用）。
type FindingBrief struct {
	ID              string
	TaskID          string
	TargetID        string
	VulnType        string
	Title           string
	SeverityClaimed string
	TargetURL       string
	Owner           string
	Description     string
	Steps           []string
	Poc             string
	RawRequest      string
	RawResponse     string
	AffectedScope   string
	Evidence        map[string]any
	KillChain       []map[string]any
	SelfCheck       map[string]any // worker 自检七布尔（reviewer 挽救链消费）
}

// Candidate 待评分的候选资产。
type Candidate struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Title  string `json:"title"`
	Org    string `json:"org"`
	Source string `json:"source"`
	Server string `json:"server"`
}

// ScoredTarget Collector 评分结果。
type ScoredTarget struct {
	URL            string  `json:"url"`
	Host           string  `json:"host"`
	Title          string  `json:"title"`
	Org            string  `json:"org"`
	School         string  `json:"school"`
	IsEdu          *bool   `json:"is_edu"`
	PriorityScore  float64 `json:"priority_score"`
	PriorityReason string  `json:"priority_reason"`
}

// ReviewVerdict Reviewer 输出。
type ReviewVerdict struct {
	Verdict          string   `json:"verdict"`
	Confidence       string   `json:"confidence"`
	SeverityFinal    string   `json:"severity_final"`
	Score            float64  `json:"score"`
	InScope          bool     `json:"in_scope"`
	IsDuplicate      bool     `json:"is_duplicate"`
	Reproduced       bool     `json:"reproduced"`
	IgnoreReasons    []string `json:"ignore_reasons"`
	DowngradeReasons []string `json:"downgrade_reasons"`
	ReviewerNotes    string   `json:"reviewer_notes"`
	DeepenDirective  string   `json:"deepen_directive"`
}

// KillsweepVerdict Killsweep 输出。
type KillsweepVerdict struct {
	IsKillsweep bool   `json:"is_killsweep"`
	ProductName string `json:"product_name"`
	ProductKey  string `json:"product_key"`
	Confidence  string `json:"confidence"`
	FofaQuery   string `json:"fofa_query"`
	Fingerprint string `json:"fingerprint"`
	AssetCount  int    `json:"asset_count"`
	EduCount    int    `json:"edu_count"`
	VulnSummary string `json:"vuln_summary"`
	Notes       string `json:"notes"`
}

// SubmittedFinding Worker 通过 submit_finding 工具提交的漏洞。
type SubmittedFinding struct {
	VulnType        string           `json:"vuln_type"`
	Title           string           `json:"title"`
	SeverityClaimed string           `json:"severity_claimed"`
	TargetURL       string           `json:"target_url"`
	Owner           string           `json:"owner"`
	Description     string           `json:"description"`
	Steps           []string         `json:"steps"`
	Poc             string           `json:"poc"`
	RawRequest      string           `json:"raw_request"`
	RawResponse     string           `json:"raw_response"`
	AffectedScope   string           `json:"affected_scope"`
	KillChain       []map[string]any `json:"kill_chain"`
	Evidence        map[string]any   `json:"evidence"`
	SelfCheck       map[string]any   `json:"self_check"`
	GateToken       string           `json:"gate_token"` // 3-gate 验证凭证（verify_finding 签发）
}

// ToolResult 工具执行结果。
type ToolResult struct {
	Output string
	Meta   map[string]any
	IsErr  bool
}

// ResultOK 构造成功结果。
func ResultOK(output string) ToolResult {
	return ToolResult{Output: output, Meta: map[string]any{}}
}

// ResultErr 构造失败结果。
func ResultErr(output string) ToolResult {
	return ToolResult{Output: output, Meta: map[string]any{}, IsErr: true}
}
