package engine

// 测绘结果大模型分析（对齐原版 collector_llm：候选资产归属判定与优先级评分）。
//
// 曾整条链未接线：BuildCollectorUserPrompt / TaskBrief.CandidatesJSON 定义后
// 从未被调用，测绘结果从不进大模型。本函数把测绘全部行（全字段、不截断）
// 交给 LLM 做归属/优先级/风险分析，LLM 给出的评分只调高不调低目标优先级
// （规则打分保底，模型只增强），分析全文落 collector_analysis 事件供看板查看。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// collectorAnalyzeTimeout 大模型分析单次调用超时。
const collectorAnalyzeTimeout = 180 * time.Second

// collectorPayloadMax 候选 JSON 传入上限（字节）。超过则诚实截断并警告。
const collectorPayloadMax = 200_000

// collectorTargetItem LLM 返回的单资产判定（对齐既有 CollectorSystemPrompt 的
// {"targets":[{url,host,title,org,school,is_edu,priority_score,priority_reason}]} schema）。
type collectorTargetItem struct {
	URL           string `json:"url"`
	Host          string `json:"host"`
	Title         string `json:"title"`
	Org           string `json:"org"`
	School        string `json:"school"`
	IsEdu         bool   `json:"is_edu"`
	PriorityScore int    `json:"priority_score"`
	PriorityReason string `json:"priority_reason"`
}

// AnalyzeEngineResults 把测绘全部结果交给大模型分析（入队收尾调用，失败仅警告不阻断）。
func AnalyzeEngineResults(ctx context.Context, task *model.Task, pool *llm.Pool, engineName, query, fields string, rows [][]string) {
	if pool == nil || task == nil || len(rows) == 0 {
		return
	}
	fieldList := strings.Split(fields, ",")
	for i := range fieldList {
		fieldList[i] = strings.TrimSpace(fieldList[i])
	}
	assets := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		item := make(map[string]string, len(fieldList))
		for i, name := range fieldList {
			if i < len(row) {
				item[name] = strings.TrimSpace(row[i])
			}
		}
		assets = append(assets, item)
	}
	payload, err := json.Marshal(map[string]any{
		"engine": engineName, "query": query,
		"count": len(assets), "fields": fieldList, "assets": assets,
	})
	if err != nil {
		return
	}
	truncated := false
	if len(payload) > collectorPayloadMax {
		// 诚实降级：按行数等比截断并明示，不悄悄丢。
		keep := len(assets) * collectorPayloadMax / len(payload)
		if keep < 1 {
			keep = 1
		}
		assets = assets[:keep]
		payload, _ = json.Marshal(map[string]any{
			"engine": engineName, "query": query,
			"count": len(assets), "fields": fieldList, "assets": assets,
			"truncated": true, "total": len(rows),
		})
		truncated = true
	}

	brief := &TaskBrief{
		ID: task.ID, Name: task.Name, SrcType: task.SrcType,
		VulnTypes: task.VulnTypes, SrcRules: task.SrcRules,
		TargetSource: task.TargetSource, Engine: engineName, FofaQuery: query,
		CandidatesJSON: string(payload),
	}
	req := llm.Request{
		Messages: []llm.Message{
			{Role: "system", Content: CollectorSystemPrompt},
			{Role: "user", Content: BuildCollectorUserPrompt(brief)},
		},
		MaxTokens: 8192,
	}
	chatCtx, cancel := context.WithTimeout(ctx, collectorAnalyzeTimeout)
	defer cancel()
	chatResult, err := chatAndRecord(chatCtx, pool, req, "")
	if err != nil {
		EmitWarn(task.ID, "collector", "collector_analysis",
			"测绘结果大模型分析失败："+utils.SanitizeSecretText(err.Error()),
			map[string]any{"engine": engineName, "assets": len(assets), "error": err.Error()})
		return
	}
	text := strings.TrimSpace(chatResult.Response.Content)
	items, ok := parseCollectorAnalysis(text)
	if !ok {
		EmitWarn(task.ID, "collector", "collector_analysis",
			"测绘结果大模型分析：返回无法解析为资产 JSON",
			map[string]any{"engine": engineName, "assets": len(assets), "raw": utils.Truncate(text, 800)})
		return
	}
	merged := mergeCollectorScores(task, items)
	EmitInfo(task.ID, "collector", "collector_analysis",
		fmt.Sprintf("测绘结果大模型分析完成：%d 条资产，调优优先级 %d 条", len(assets), merged),
		map[string]any{
			"engine": engineName, "query": query, "assets": len(assets),
			"total_rows": len(rows), "truncated": truncated,
			"analysis": items, "merged": merged,
			"model": chatResult.Endpoint.Model,
		})
}

// parseCollectorAnalysis 宽容解析 LLM 返回（{"targets":[...]} 或裸数组两种形态）。
func parseCollectorAnalysis(text string) ([]collectorTargetItem, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, false
	}
	// 剥 ```json 包裹。
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	var wrapped struct {
		Targets []collectorTargetItem `json:"targets"`
	}
	if err := json.Unmarshal([]byte(text), &wrapped); err == nil && len(wrapped.Targets) > 0 {
		return wrapped.Targets, true
	}
	var bare []collectorTargetItem
	if err := json.Unmarshal([]byte(text), &bare); err == nil && len(bare) > 0 {
		return bare, true
	}
	// 找首个 { 兜底截取。
	if idx := strings.Index(text, "{"); idx >= 0 {
		if err := json.Unmarshal([]byte(text[idx:]), &wrapped); err == nil && len(wrapped.Targets) > 0 {
			return wrapped.Targets, true
		}
	}
	return nil, false
}

// clampScore 夹取 0-100。
func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// mergeCollectorScores 把 LLM 评分合并到已入队目标：只调高不调低（规则分保底）。
// 返回调优条数。
func mergeCollectorScores(task *model.Task, items []collectorTargetItem) int {
	if len(items) == 0 {
		return 0
	}
	byHost := map[string]collectorTargetItem{}
	for _, item := range items {
		host := strings.ToLower(strings.TrimSpace(item.Host))
		if host == "" && item.URL != "" {
			host = strings.ToLower(utils.NormalizeHost(item.URL))
		}
		if host != "" {
			byHost[host] = item
		}
	}
	var targets []model.Target
	core.Db.Where("task_id = ?", task.ID).Find(&targets)
	merged := 0
	for _, t := range targets {
		host := strings.ToLower(strings.TrimSpace(t.Host))
		if host == "" {
			continue
		}
		item, ok := byHost[host]
		if !ok {
			continue
		}
		if item.PriorityScore <= int(t.PriorityScore) && strings.TrimSpace(t.PriorityReason) != "" {
			continue
		}
		reason := strings.TrimSpace(item.PriorityReason)
		if reason != "" {
			reason = "LLM分析：" + utils.Truncate(reason, 160)
		}
		updates := map[string]any{}
		if item.PriorityScore > int(t.PriorityScore) {
			updates["priority_score"] = float64(clampScore(item.PriorityScore))
		}
		if reason != "" {
			updates["priority_reason"] = reason
		}
		if len(updates) == 0 {
			continue
		}
		if err := core.Db.Model(&model.Target{}).Where("id = ?", t.ID).Updates(updates).Error; err == nil {
			merged++
		}
	}
	return merged
}
