package model

import (
	"time"
)

// Finding worker 产出的原始漏洞。
type Finding struct {
	ID              string           `gorm:"primaryKey;size:32" json:"id"`
	TaskID          string           `gorm:"size:32;not null;index" json:"task_id"`
	TargetID        string           `gorm:"size:32;not null;index" json:"target_id"`
	WorkerID        string           `gorm:"size:64;default:''" json:"worker_id"`
	VulnType        string           `gorm:"size:80;index:ix_finding_type_status" json:"vuln_type"`
	Title           string           `gorm:"size:500" json:"title"`
	SeverityClaimed string           `gorm:"size:10" json:"severity_claimed"`
	TargetURL       string           `gorm:"size:500" json:"target_url"`
	Owner           string           `gorm:"size:300;default:''" json:"owner"`
	Description     string           `gorm:"type:text" json:"description"`
	Steps           []string         `gorm:"serializer:json" json:"steps"`
	Poc             string           `gorm:"type:text" json:"poc"`
	RawRequest      string           `gorm:"type:text" json:"raw_request"`
	RawResponse     string           `gorm:"type:text" json:"raw_response"`
	Evidence        map[string]any   `gorm:"serializer:json" json:"evidence"`
	AffectedScope   string           `gorm:"type:text" json:"affected_scope"`
	KillChain       []map[string]any `gorm:"serializer:json" json:"kill_chain"`
	AssistantMsgs   []map[string]any `gorm:"serializer:json" json:"assistant_messages"`
	SelfCheck       map[string]any   `gorm:"serializer:json" json:"self_check"`
	DedupKey        string           `gorm:"size:128;default:'';index" json:"dedup_key"`
	LLMModel        string           `gorm:"size:200;default:''" json:"llm_model"`
	LLMBaseURL      string           `gorm:"size:300;default:''" json:"llm_base_url"`
	Status          string           `gorm:"size:20;default:pending_review;index;index:ix_finding_type_status" json:"status"`
	IsTop           bool             `gorm:"default:false;index" json:"is_top"`
	CreatedAt       time.Time        `json:"-"`

	Target *Target `gorm:"foreignKey:TargetID" json:"-"`
	Review *Review `gorm:"foreignKey:FindingID" json:"-"`
}

// TableName 指定表名。
func (Finding) TableName() string { return "aisrc_finding" }

// Review 审核 agent 对 Finding 的结论，并承载用户人工复审状态。
type Review struct {
	ID            string  `gorm:"primaryKey;size:32" json:"id"`
	FindingID     string  `gorm:"size:32;not null;uniqueIndex" json:"finding_id"`
	TaskID        string  `gorm:"size:32;not null;index" json:"task_id"`
	Verdict       string  `gorm:"size:20;index" json:"verdict"` // accepted / ignored / deepen
	Confidence    string  `gorm:"size:20" json:"confidence"`    // confirmed / likely / uncertain
	SeverityFinal *string `gorm:"size:10" json:"severity_final"`
	Score         float64 `gorm:"default:0;index" json:"score"`
	// 注意：这里刻意不加 gorm:"default:true"。
	// GORM 在 Create 时会跳过带 default 标签的零值字段，让数据库默认值生效；
	// 若写成 default:true，则审核判定「超出范围」(false) 会被静默写成 true，
	// 导致非目标资产被当成有效漏洞入库。默认值改由业务层显式赋值。
	InScope          bool       `gorm:"not null" json:"in_scope"`
	IsDuplicate      bool       `gorm:"default:false" json:"is_duplicate"`
	IgnoreReasons    []string   `gorm:"serializer:json" json:"ignore_reasons"`
	DowngradeReasons []string   `gorm:"serializer:json" json:"downgrade_reasons"`
	Reproduced       bool       `gorm:"default:false" json:"reproduced"`
	ReviewerNotes    string     `gorm:"type:text" json:"reviewer_notes"`
	DeepenDirective  string     `gorm:"type:text" json:"deepen_directive"`
	ReviewedAt       *time.Time `json:"-"`

	// ===== 用户复审 =====
	UserStatus     string         `gorm:"size:20;default:pending;index" json:"user_status"`
	UserSeverity   *string        `gorm:"size:10" json:"user_severity"`
	UserNotes      string         `gorm:"type:text" json:"user_notes"`
	UserEdits      map[string]any `gorm:"serializer:json" json:"user_edits"`
	Submitted      bool           `gorm:"default:false;index" json:"submitted"`
	UserReviewedAt *time.Time     `json:"-"`
}

// TableName 指定表名。
func (Review) TableName() string { return "aisrc_review" }

// EffectiveSeverity 返回最终生效等级：用户调整 > AI 定级。
func (r Review) EffectiveSeverity() string {
	if r.UserSeverity != nil && *r.UserSeverity != "" {
		return *r.UserSeverity
	}
	if r.SeverityFinal != nil {
		return *r.SeverityFinal
	}
	return ""
}
