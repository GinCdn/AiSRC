package model

import (
	"time"
)

// Killsweep 通杀候选：审核通过一个洞后，分析该系统是否为通用产品、能否一打一片。
// 按「产品指纹」去重——同一任务内同款系统只保留一条。
type Killsweep struct {
	ID              string           `gorm:"primaryKey;size:32" json:"id"`
	TaskID          string           `gorm:"size:32;not null;index;uniqueIndex:ux_killsweep_task_product" json:"task_id"`
	OriginFindingID string           `gorm:"size:32;default:''" json:"origin_finding_id"`
	ProductKey      string           `gorm:"size:120;default:'';index;uniqueIndex:ux_killsweep_task_product" json:"product_key"`
	ProductName     string           `gorm:"size:200;default:''" json:"product_name"`
	VulnType        string           `gorm:"size:80;default:''" json:"vuln_type"`
	VulnSummary     string           `gorm:"type:text" json:"vuln_summary"`
	FofaQuery       string           `gorm:"type:text" json:"fofa_query"`
	Fingerprint     string           `gorm:"type:text" json:"fingerprint"`
	AssetCount      int              `gorm:"default:0" json:"asset_count"`
	EduCount        int              `gorm:"default:0" json:"edu_count"`
	IsKillsweep     bool             `gorm:"default:false" json:"is_killsweep"`
	Confidence      string           `gorm:"size:20;default:''" json:"confidence"`
	VerifiedURL     string           `gorm:"size:500;default:''" json:"verified_url"`
	Verified        bool             `gorm:"default:false" json:"verified"`
	AffectedTable   []map[string]any `gorm:"serializer:json" json:"affected_table"`
	Notes           string           `gorm:"type:text" json:"notes"`
	Status          string           `gorm:"size:20;default:analyzing;index" json:"status"`
	CreatedAt       time.Time        `json:"-"`
	UpdatedAt       time.Time        `json:"-"`
}

// TableName 指定表名。
func (Killsweep) TableName() string { return "aisrc_killsweep" }

// KillsweepRetryable 判断该通杀记录是否可重启。
func KillsweepRetryable(status string, isKillsweep bool) bool {
	if status == "invalid" {
		return false
	}
	if status == "done" && isKillsweep {
		return false
	}
	return true
}

// TaskEvent 审计 / 实时日志事件。
type TaskEvent struct {
	ID      uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	TaskID  string         `gorm:"size:32;not null;index" json:"task_id"`
	Agent   string         `gorm:"size:20;default:'';index" json:"agent"`
	Level   string         `gorm:"size:10;default:info;index" json:"level"`
	Kind    string         `gorm:"size:40;default:'';index" json:"kind"`
	Message string         `gorm:"type:text" json:"message"`
	Payload map[string]any `gorm:"serializer:json" json:"payload"`
	Ts      time.Time      `gorm:"index" json:"-"`
}

// TableName 指定表名。
func (TaskEvent) TableName() string { return "aisrc_task_event" }

// Intel 全局情报库（跨任务共享），单表四类用 kind 区分。
type Intel struct {
	ID           string         `gorm:"primaryKey;size:32" json:"id"`
	Kind         string         `gorm:"size:20;index;uniqueIndex:ux_intel_dedup" json:"kind"`
	MatchKey     string         `gorm:"size:255;default:'';index;uniqueIndex:ux_intel_dedup" json:"match_key"`
	DedupHash    string         `gorm:"size:64;default:'';uniqueIndex:ux_intel_dedup" json:"dedup_hash"`
	Payload      map[string]any `gorm:"serializer:json" json:"payload"`
	Summary      string         `gorm:"size:500;default:''" json:"summary"`
	SourceHost   string         `gorm:"size:255;default:''" json:"source_host"`
	SourceTaskID string         `gorm:"size:32;default:''" json:"source_task_id"`
	Confidence   string         `gorm:"size:20;default:likely" json:"confidence"`
	HitCount     int            `gorm:"default:1;index" json:"hit_count"`
	FirstSeen    time.Time      `json:"-"`
	LastSeen     time.Time      `gorm:"index" json:"-"`
}

// TableName 指定表名。
func (Intel) TableName() string { return "aisrc_intel" }
