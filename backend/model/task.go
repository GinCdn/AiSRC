package model

import (
	"time"
)

// Task 一个挖掘任务 = 一个资产范围（测绘语法 / 域名清单）。
// running 状态下调度器永不自停，所有状态持久化以支持进程重启恢复。
type Task struct {
	ID            string         `gorm:"primaryKey;size:32" json:"id"`
	Name          string         `gorm:"size:200;not null" json:"name"`
	SrcType       string         `gorm:"size:20;default:edusrc" json:"src_type"`
	VulnTypes     []string       `gorm:"serializer:json" json:"vuln_types"`
	SrcRules      string         `gorm:"type:text" json:"src_rules"`
	TargetSource  string         `gorm:"size:20;default:fofa" json:"target_source"`
	FofaQuery     string         `gorm:"type:text" json:"fofa_query"`
	ManualTargets []string       `gorm:"serializer:json" json:"manual_targets"`
	AuthBindings  []AuthBinding  `gorm:"serializer:json" json:"auth_bindings"`
	ModelConfig   LLMModelConfig `gorm:"serializer:json;column:model_config" json:"model_config_data"`
	FofaConfig    FofaConfig     `gorm:"serializer:json" json:"fofa_config"`
	Engine        string         `gorm:"size:20;default:''" json:"engine"`
	Concurrency   int            `gorm:"default:3" json:"concurrency"`
	DeepenCap     int            `gorm:"default:2" json:"deepen_cap"`
	// 同 Review.InScope：带 default:true 会让显式传入的 false 被 GORM 跳过，
	// 因此不加 default 标签，默认值（true）由 API 层在缺省时显式写入。
	AutoKillsweep bool         `gorm:"not null" json:"auto_killsweep"`
	Status        string       `gorm:"size:20;default:created;index" json:"status"`
	IsTop         bool         `gorm:"default:false;index" json:"is_top"`
	RuntimeStats  RuntimeStats `gorm:"serializer:json" json:"runtime_stats"`
	CreatedAt     time.Time    `json:"-"`
	UpdatedAt     time.Time    `json:"-"`

	Targets []Target `gorm:"foreignKey:TaskID" json:"-"`
}

// TableName 指定表名。
func (Task) TableName() string { return "aisrc_task" }

// Target 单个待挖目标（host 级）。状态机贯穿 24x7 恢复逻辑。
type Target struct {
	ID             string           `gorm:"primaryKey;size:32" json:"id"`
	TaskID         string           `gorm:"size:32;not null;index;uniqueIndex:ux_target_task_host" json:"task_id"`
	URL            string           `gorm:"size:500" json:"url"`
	Host           string           `gorm:"size:255;index;uniqueIndex:ux_target_task_host" json:"host"` // 去重键
	IP             string           `gorm:"size:64;default:''" json:"ip"`
	Org            string           `gorm:"size:300;default:''" json:"org"`
	Title          string           `gorm:"size:500;default:''" json:"title"`
	Source         string           `gorm:"size:20;default:fofa;uniqueIndex:ux_target_task_host" json:"source"`
	IsEdu          *bool            `json:"is_edu"`
	School         string           `gorm:"size:200;default:''" json:"school"`
	PriorityScore  float64          `gorm:"default:0;index" json:"priority_score"`
	PriorityReason string           `gorm:"size:300;default:''" json:"priority_reason"`
	Status         string           `gorm:"size:20;default:queued;index" json:"status"`
	Verdict        string           `gorm:"size:20;default:''" json:"verdict"`
	RetryCount     int              `gorm:"default:0" json:"retry_count"`
	DeadReason     string           `gorm:"size:300;default:''" json:"dead_reason"`
	LastError      string           `gorm:"size:500;default:''" json:"last_error"`
	DeepenContext  map[string]any   `gorm:"serializer:json" json:"deepen_context"`
	DeepenCount    int              `gorm:"default:0" json:"deepen_count"`
	LeakedCreds    []map[string]any `gorm:"serializer:json" json:"leaked_creds"`
	AuthContext    *AuthBinding     `gorm:"serializer:json" json:"auth_context"`
	AuthStatus     map[string]any   `gorm:"serializer:json" json:"auth_status"`
	AssignedWorker string           `gorm:"size:64;default:''" json:"assigned_worker"`
	HeartbeatAt    *time.Time       `json:"-"`
	IsTop          bool             `gorm:"default:false;index" json:"is_top"`
	CreatedAt      time.Time        `json:"-"`
	UpdatedAt      time.Time        `json:"-"`

	Task     *Task     `gorm:"foreignKey:TaskID" json:"-"`
	Findings []Finding `gorm:"foreignKey:TargetID" json:"-"`
}

// TableName 指定表名。
func (Target) TableName() string { return "aisrc_target" }

// Indexes 声明复合索引（供迁移时统一创建）。
func (Target) Indexes() []string {
	return []string{"ux_target_task_host", "ix_target_status", "ix_target_priority"}
}
