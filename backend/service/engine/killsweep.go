package engine

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// RunKillsweep 分析一个已过审漏洞是否构成通杀，并落库。
func RunKillsweep(ctx context.Context, pool *llm.Pool, taskID, findingID string, brief *FindingBrief) (*model.Killsweep, error) {
	record := &model.Killsweep{
		ID:              utils.UUID(),
		TaskID:          taskID,
		OriginFindingID: findingID,
		Status:          constant.KillsweepAnalyzing,
		AffectedTable:   []map[string]any{},
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	if pool == nil || pool.Size() == 0 {
		record.Status = constant.KillsweepFailed
		record.Notes = "未配置可用 LLM 端点，通杀分析未执行。"
		return record, nil
	}

	result, err := chatAndRecord(ctx, pool, llm.Request{
		Messages: []llm.Message{
			{Role: "system", Content: KillsweepSystemPrompt},
			{Role: "user", Content: BuildKillsweepUserPrompt(brief)},
		},
		MaxTokens: 4096,
	}, "")
	if err != nil {
		record.Status = constant.KillsweepFailed
		record.Notes = "通杀分析调用失败：" + utils.SanitizeSecretText(err.Error())
		return record, nil
	}

	payload, ok := ExtractJSON(result.Response.Content)
	if !ok {
		record.Status = constant.KillsweepFailed
		record.Notes = "通杀分析未返回可解析 JSON：" + utils.Truncate(result.Response.Content, 400)
		return record, nil
	}

	var verdict KillsweepVerdict
	if err := json.Unmarshal([]byte(payload), &verdict); err != nil {
		record.Status = constant.KillsweepFailed
		record.Notes = "通杀分析输出解析失败：" + err.Error()
		return record, nil
	}

	record.IsKillsweep = verdict.IsKillsweep
	record.ProductName = utils.Truncate(verdict.ProductName, 200)
	record.ProductKey = normalizeProductKey(verdict.ProductKey, verdict.ProductName)
	record.VulnType = brief.VulnType
	record.VulnSummary = verdict.VulnSummary
	record.FofaQuery = verdict.FofaQuery
	record.Fingerprint = verdict.Fingerprint
	record.AssetCount = verdict.AssetCount
	record.EduCount = verdict.EduCount
	record.Confidence = normalizeConfidence(verdict.Confidence)
	record.Notes = verdict.Notes
	record.Status = constant.KillsweepDone
	return record, nil
}

// SaveKillsweep 落库通杀记录（同任务同产品指纹只保留一条）。
func SaveKillsweep(record *model.Killsweep) error {
	if core.Db == nil {
		return nil
	}
	var existing model.Killsweep
	err := core.Db.Where("task_id = ? AND product_key = ?", record.TaskID, record.ProductKey).First(&existing).Error
	if err == nil && existing.ID != "" {
		// 同款产品：更新已有记录而非新增
		existing.IsKillsweep = record.IsKillsweep
		existing.AssetCount = record.AssetCount
		existing.EduCount = record.EduCount
		existing.FofaQuery = record.FofaQuery
		existing.Fingerprint = record.Fingerprint
		existing.VulnSummary = record.VulnSummary
		existing.Confidence = record.Confidence
		existing.Notes = record.Notes
		existing.Status = constant.KillsweepDone
		existing.UpdatedAt = time.Now().UTC()
		record.ID = existing.ID
		return core.Db.Save(&existing).Error
	}
	return core.Db.Create(record).Error
}

// normalizeProductKey 归一化产品指纹：小写、去版本号、去空白。
func normalizeProductKey(key, name string) string {
	source := strings.TrimSpace(key)
	if source == "" {
		source = strings.TrimSpace(name)
	}
	if source == "" {
		return "unknown"
	}
	lower := strings.ToLower(source)
	lower = strings.ReplaceAll(lower, " ", "")
	lower = strings.ReplaceAll(lower, "_", "")
	lower = strings.ReplaceAll(lower, "-", "")
	// 去掉 v1.2.3 / 1.2.3 / v1 形态的版本号
	fields := strings.FieldsFunc(lower, func(r rune) bool {
		return r == 'v' || r == '.' || r == '/'
	})
	cleaned := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" || isNumeric(field) {
			continue
		}
		// 过滤紧跟在字母后的纯数字串（版本号）
		if len(field) > 1 && isNumeric(field[1:]) {
			cleaned = append(cleaned, string(field[0]))
			continue
		}
		cleaned = append(cleaned, field)
	}
	result := strings.Join(cleaned, "")
	if result == "" {
		result = utils.IdentityRef(lower)
	}
	return utils.Truncate(result, 120)
}
