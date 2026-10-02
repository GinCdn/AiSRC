package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/utils"
)

// FindingFilter 漏洞列表查询条件。
type FindingFilter struct {
	TaskID     string
	Status     string
	Confidence string
	Verdicts   []string
	UserStatus string
	Submitted  *bool
	// Severity 按复审生效等级（EffectiveSeverity，中文词表）精确过滤。
	Severity string
	OnlyTop  bool
	// ExcludeSuperseded 排除「回炉重挖中」的 deepen 前身（对齐原版 /archived
	// 的 Finding.status != "superseded"：避免和新一轮深挖的发现重复展示）。
	ExcludeSuperseded bool
	Query             string
	Limit             int
	Offset            int
	Compact           bool
	OrderBy           string
}

// BuildFindingView 组装漏洞视图（含审核结论与目标信息）。
func BuildFindingView(f *model.Finding, r *model.Review, target *model.Target, compact bool) map[string]any {
	if f == nil {
		return nil
	}
	view := map[string]any{
		"id":               f.ID,
		"task_id":          f.TaskID,
		"target_id":        f.TargetID,
		"worker_id":        f.WorkerID,
		"vuln_type":        f.VulnType,
		"title":            f.Title,
		"severity_claimed": f.SeverityClaimed,
		"target_url":       f.TargetURL,
		"owner":            f.Owner,
		"status":           f.Status,
		"dedup_key":        f.DedupKey,
		"is_top":           f.IsTop,
		"llm_model":        f.LLMModel,
		"llm_base_url":     f.LLMBaseURL,
		"created_at":       utils.ToCSTISO(f.CreatedAt),
		"severity":         f.SeverityClaimed,
	}
	if target != nil {
		view["target_host"] = target.Host
		view["target_title"] = target.Title
		view["school"] = target.School
		view["is_edu"] = target.IsEdu
		view["org"] = target.Org
		view["owner_proof"] = target.Org
		view["edu_school"] = target.School
		view["deepen_count"] = target.DeepenCount
	}
	if r != nil {
		view["review"] = map[string]any{
			"id":                r.ID,
			"verdict":           r.Verdict,
			"confidence":        r.Confidence,
			"severity_final":    r.SeverityFinal,
			"score":             r.Score,
			"in_scope":          r.InScope,
			"is_duplicate":      r.IsDuplicate,
			"ignore_reasons":    nonNilStrings(r.IgnoreReasons),
			"downgrade_reasons": nonNilStrings(r.DowngradeReasons),
			"reproduced":        r.Reproduced,
			"reviewer_notes":    r.ReviewerNotes,
			"deepen_directive":  r.DeepenDirective,
			"reviewed_at":       utils.ToCSTNullable(r.ReviewedAt),
			// 用户复审字段：报告抽屉与列表行都从 review 子对象读这些键，
			// 曾漏下发导致「标记为已提交」后详情/列表永远显示「未提交」、
			// 角标状态值读不到（顶层字段虽有，但读取端不在顶层）。
			"user_status":      r.UserStatus,
			"user_severity":    r.UserSeverity,
			"user_notes":       r.UserNotes,
			"user_edits":       r.UserEdits,
			"submitted":        r.Submitted,
			"user_reviewed_at": utils.ToCSTNullable(r.UserReviewedAt),
		}
		view["verdict"] = r.Verdict
		view["confidence"] = r.Confidence
		view["severity_final"] = r.SeverityFinal
		view["score"] = r.Score
		view["in_scope"] = r.InScope
		view["is_duplicate"] = r.IsDuplicate
		view["ignore_reasons"] = nonNilStrings(r.IgnoreReasons)
		view["downgrade_reasons"] = nonNilStrings(r.DowngradeReasons)
		view["reproduced"] = r.Reproduced
		view["reviewer_notes"] = r.ReviewerNotes
		view["deepen_directive"] = r.DeepenDirective
		view["user_status"] = r.UserStatus
		view["user_severity"] = r.UserSeverity
		view["user_notes"] = r.UserNotes
		view["user_edits"] = r.UserEdits
		view["submitted"] = r.Submitted
		view["user_reviewed_at"] = utils.ToCSTNullable(r.UserReviewedAt)
		view["effective_severity"] = r.EffectiveSeverity()
	}
	if !compact {
		view["description"] = f.Description
		view["steps"] = nonNilStrings(f.Steps)
		view["poc"] = f.Poc
		view["raw_request"] = f.RawRequest
		view["raw_response"] = f.RawResponse
		view["evidence"] = mapOrEmpty(f.Evidence)
		view["affected_scope"] = f.AffectedScope
		view["kill_chain"] = nonNilMapSlice(f.KillChain)
		view["self_check"] = mapOrEmpty(f.SelfCheck)
		view["assistant_messages"] = nonNilMapSlice(f.AssistantMsgs)
	}
	return view
}

// QueryFindings 通用漏洞列表查询。
// 采用「先按审核条件筛 finding_id，再批量装配视图」的两段式实现，避免复杂 JOIN 映射。
func QueryFindings(filter FindingFilter) ([]map[string]any, int64, error) {
	reviewPredicate := len(filter.Verdicts) > 0 || filter.Confidence != "" ||
		filter.UserStatus != "" || filter.Submitted != nil

	var allowedFindings map[string]bool
	if reviewPredicate {
		var reviews []model.Review
		db := core.Db.Model(&model.Review{})
		if len(filter.Verdicts) > 0 {
			db = db.Where("verdict IN ?", filter.Verdicts)
		}
		if filter.Confidence != "" {
			db = db.Where("confidence = ?", filter.Confidence)
		}
		if filter.UserStatus != "" {
			db = db.Where("user_status = ?", filter.UserStatus)
		}
		if filter.Submitted != nil {
			db = db.Where("submitted = ?", *filter.Submitted)
		}
		if err := db.Find(&reviews).Error; err != nil {
			return nil, 0, err
		}
		allowedFindings = make(map[string]bool, len(reviews))
		for _, r := range reviews {
			allowedFindings[r.FindingID] = true
		}
	}

	db := core.Db.Model(&model.Finding{})
	if filter.TaskID != "" {
		db = db.Where("task_id = ?", filter.TaskID)
	}
	if filter.Status != "" {
		db = db.Where("status = ?", filter.Status)
	}
	if filter.OnlyTop {
		db = db.Where("is_top = ?", true)
	}
	if filter.ExcludeSuperseded {
		db = db.Where("status != ?", constant.FindingSuperseded)
	}
	var findings []model.Finding
	if err := db.Find(&findings).Error; err != nil {
		return nil, 0, err
	}

	// 收窄到审核条件命中的集合。
	if allowedFindings != nil {
		kept := make([]model.Finding, 0, len(findings))
		for _, f := range findings {
			if allowedFindings[f.ID] {
				kept = append(kept, f)
			}
		}
		findings = kept
	}

	// 批量装配审核与目标。
	findingIDs := make([]string, 0, len(findings))
	targetIDs := make([]string, 0, len(findings))
	for _, f := range findings {
		findingIDs = append(findingIDs, f.ID)
		if f.TargetID != "" {
			targetIDs = append(targetIDs, f.TargetID)
		}
	}
	reviewMap := map[string]*model.Review{}
	if len(findingIDs) > 0 {
		var reviews []model.Review
		core.Db.Where("finding_id IN ?", findingIDs).Find(&reviews)
		for i := range reviews {
			reviewMap[reviews[i].FindingID] = &reviews[i]
		}
	}
	targetMap := map[string]*model.Target{}
	if len(targetIDs) > 0 {
		var targets []model.Target
		core.Db.Where("id IN ?", targetIDs).Find(&targets)
		for i := range targets {
			targetMap[targets[i].ID] = &targets[i]
		}
	}

	out := make([]map[string]any, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		out = append(out, BuildFindingView(f, reviewMap[f.ID], targetMap[f.TargetID], filter.Compact))
	}

	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		filtered := make([]map[string]any, 0, len(out))
		for _, item := range out {
			if jsonContains(item, query) {
				filtered = append(filtered, item)
			}
		}
		out = filtered
	}

	// 生效等级精确过滤（全局漏洞库的「全部等级」下拉；分页前执行保证 total 正确）。
	if sev := strings.ToLower(strings.TrimSpace(filter.Severity)); sev != "" {
		filtered := make([]map[string]any, 0, len(out))
		for _, item := range out {
			if strings.ToLower(fmt.Sprintf("%v", item["effective_severity"])) == sev {
				filtered = append(filtered, item)
			}
		}
		out = filtered
	}

	// 排序：默认按评分 / 创建时间；调用方可通过 OrderBy 指定。
	sortFindingViews(out, filter.OrderBy)

	total := int64(len(out))
	if filter.Limit > 0 {
		if filter.Offset >= len(out) {
			return nil, total, nil
		}
		end := filter.Offset + filter.Limit
		if end > len(out) {
			end = len(out)
		}
		out = out[filter.Offset:end]
	}
	return out, total, nil
}

// sortFindingViews 对漏洞视图排序。
func sortFindingViews(items []map[string]any, orderBy string) {
	scoreOf := func(item map[string]any) float64 {
		if v, ok := item["score"].(float64); ok {
			return v
		}
		return 0
	}
	topOf := func(item map[string]any) int {
		if v, ok := item["is_top"].(bool); ok && v {
			return 1
		}
		return 0
	}
	submittedOf := func(item map[string]any) int {
		if v, ok := item["submitted"].(bool); ok && v {
			return 1
		}
		return 0
	}
	timeOf := func(item map[string]any) string {
		if v, ok := item["created_at"].(string); ok {
			return v
		}
		return ""
	}
	writeOpOf := func(item map[string]any) int {
		text := fmt.Sprintf("%v %v", item["title"], item["target_url"])
		for _, keyword := range []string{"删除", "修改", "更新", "delete", "update", "/save", "remove"} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(keyword)) {
				return 0
			}
		}
		return 1
	}

	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if topOf(a) != topOf(b) {
			return topOf(a) > topOf(b)
		}
		switch orderBy {
		case "score":
			if scoreOf(a) != scoreOf(b) {
				return scoreOf(a) > scoreOf(b)
			}
			return timeOf(a) > timeOf(b)
		case "submit":
			// 待提交列表（对齐原版 submit_list 排序）：未提交在前，其次评分。
			if submittedOf(a) != submittedOf(b) {
				return submittedOf(a) < submittedOf(b)
			}
			if scoreOf(a) != scoreOf(b) {
				return scoreOf(a) > scoreOf(b)
			}
			return timeOf(a) > timeOf(b)
		case "archived":
			if writeOpOf(a) != writeOpOf(b) {
				return writeOpOf(a) < writeOpOf(b)
			}
			if scoreOf(a) != scoreOf(b) {
				return scoreOf(a) > scoreOf(b)
			}
			return timeOf(a) > timeOf(b)
		default:
			return timeOf(a) > timeOf(b)
		}
	})
}

// GetFindingView 漏洞详情。
func GetFindingView(findingID string) (map[string]any, error) {
	var finding model.Finding
	if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
		return nil, err
	}
	var review model.Review
	reviewPtr := (*model.Review)(nil)
	if err := core.Db.Where("finding_id = ?", findingID).First(&review).Error; err == nil {
		reviewPtr = &review
	}
	var target model.Target
	targetPtr := (*model.Target)(nil)
	if err := core.Db.First(&target, "id = ?", finding.TargetID).Error; err == nil {
		targetPtr = &target
	}
	return BuildFindingView(&finding, reviewPtr, targetPtr, false), nil
}

// UpdateResult 用户复审更新（结论 / 等级 / 备注 / 报告字段）。
func UpdateResult(findingID string, patch map[string]any) (map[string]any, error) {
	var review model.Review
	if err := core.Db.Where("finding_id = ?", findingID).First(&review).Error; err != nil {
		// 无审核记录时补一条，保证用户仍可裁决。
		review = model.Review{
			ID:         utils.UUID(),
			FindingID:  findingID,
			Verdict:    constant.VerdictAccepted,
			UserStatus: constant.UserPending,
		}
		var finding model.Finding
		if err := core.Db.First(&finding, "id = ?", findingID).Error; err == nil {
			review.TaskID = finding.TaskID
		}
		if err := core.Db.Create(&review).Error; err != nil {
			return nil, err
		}
	}

	updates := map[string]any{}
	if value, ok := patch["user_status"]; ok {
		status := fmt.Sprintf("%v", value)
		switch status {
		case constant.UserPassed, constant.UserRejected, constant.UserPending, constant.UserDeepening:
			updates["user_status"] = status
		}
	}
	if value, ok := patch["user_severity"]; ok {
		severity := engine.NormalizeSeverity(fmt.Sprintf("%v", value))
		updates["user_severity"] = severity
	}
	if value, ok := patch["user_notes"]; ok {
		updates["user_notes"] = fmt.Sprintf("%v", value)
	}
	if value, ok := patch["submitted"]; ok {
		if b, ok := value.(bool); ok {
			updates["submitted"] = b
		}
	}
	if edits, ok := patch["user_edits"]; ok {
		raw, err := json.Marshal(edits)
		if err == nil {
			updates["user_edits"] = string(raw)
		}
	}
	updates["user_reviewed_at"] = time.Now()
	if _, ok := updates["user_status"]; !ok && review.UserStatus == "" {
		updates["user_status"] = constant.UserPending
	}

	if err := core.Db.Model(&model.Review{}).Where("id = ?", review.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	return GetFindingView(findingID)
}

// RestoreArchived 把 AI 未采纳（ignored/deepen）的归档漏洞救回复审队列。
func RestoreArchived(findingID string) error {
	var review model.Review
	if err := core.Db.Where("finding_id = ?", findingID).First(&review).Error; err != nil {
		return err
	}
	if review.Verdict != constant.VerdictIgnored && review.Verdict != constant.VerdictDeepen {
		return fmt.Errorf("该漏洞不在 AI 未采纳归档中，无需恢复")
	}
	notes := strings.TrimRight(review.ReviewerNotes, " \n")
	notes = strings.TrimSpace(notes + "\n[人工恢复] 由 AI 未采纳归档手动救回复审队列。")
	if err := core.Db.Model(&model.Review{}).Where("id = ?", review.ID).Updates(map[string]any{
		"verdict":        constant.VerdictAccepted,
		"user_status":    constant.UserPending,
		"reviewer_notes": notes,
	}).Error; err != nil {
		return err
	}
	core.Db.Model(&model.Finding{}).
		Where("id = ? AND status <> ?", findingID, constant.FindingSuperseded).
		Update("status", constant.FindingReviewed)
	return nil
}

// DeepenFinding 用户手动打回深挖。
func DeepenFinding(findingID, directive string) (bool, string) {
	var finding model.Finding
	if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
		return false, "漏洞不存在"
	}
	var task model.Task
	cap := constant.DeepenCapDefault
	if err := core.Db.First(&task, "id = ?", finding.TaskID).Error; err == nil {
		cap = task.DeepenCap
	}
	return engine.ApplyDeepenByIDs(finding.TargetID, findingID, directive, "user", cap)
}

// ToggleResultTop 结果置顶。
func ToggleResultTop(findingID string, isTop bool) error {
	return core.Db.Model(&model.Finding{}).Where("id = ?", findingID).Update("is_top", isTop).Error
}

// KillsweepFilter 通杀列表条件。
type KillsweepFilter struct {
	TaskID         string
	OnlyHits       bool
	IncludeInvalid bool
	Limit          int
	Offset         int
}

// ListKillsweeps 通杀列表。
func ListKillsweeps(filter KillsweepFilter) ([]map[string]any, int64, error) {
	var records []model.Killsweep
	db := core.Db.Model(&model.Killsweep{})
	if filter.TaskID != "" {
		db = db.Where("task_id = ?", filter.TaskID)
	}
	if filter.OnlyHits {
		db = db.Where("is_killsweep = ?", true)
	}
	if !filter.IncludeInvalid {
		db = db.Where("status <> ?", constant.KillsweepInvalid)
	}
	if err := db.Order("is_killsweep DESC, created_at DESC").Find(&records).Error; err != nil {
		return nil, 0, err
	}
	total := int64(len(records))
	if filter.Limit > 0 {
		if filter.Offset >= len(records) {
			return nil, total, nil
		}
		end := filter.Offset + filter.Limit
		if end > len(records) {
			end = len(records)
		}
		records = records[filter.Offset:end]
	}
	out := make([]map[string]any, 0, len(records))
	for i := range records {
		out = append(out, BuildKillsweepView(&records[i]))
	}
	return out, total, nil
}

// BuildKillsweepView 通杀视图。
func BuildKillsweepView(k *model.Killsweep) map[string]any {
	if k == nil {
		return nil
	}
	return map[string]any{
		"id":                k.ID,
		"task_id":           k.TaskID,
		"origin_finding_id": k.OriginFindingID,
		"product_key":       k.ProductKey,
		"product_name":      k.ProductName,
		"vuln_type":         k.VulnType,
		"vuln_summary":      k.VulnSummary,
		"fofa_query":        k.FofaQuery,
		"fingerprint":       k.Fingerprint,
		"asset_count":       k.AssetCount,
		"edu_count":         k.EduCount,
		"is_killsweep":      k.IsKillsweep,
		"confidence":        k.Confidence,
		"verified_url":      k.VerifiedURL,
		"verified":          k.Verified,
		"affected_table":    nonNilMapSlice(k.AffectedTable),
		"notes":             k.Notes,
		"status":            k.Status,
		"retryable":         model.KillsweepRetryable(k.Status, k.IsKillsweep),
		"created_at":        utils.ToCSTISO(k.CreatedAt),
		"updated_at":        utils.ToCSTISO(k.UpdatedAt),
	}
}

// InvalidateKillsweep 标记通杀结论无效。
func InvalidateKillsweep(taskID, killsweepID, reason string) error {
	if reason == "" {
		reason = "用户标记为无效"
	}
	res := core.Db.Model(&model.Killsweep{}).
		Where("id = ? AND task_id = ?", killsweepID, taskID).
		Updates(map[string]any{"status": constant.KillsweepInvalid, "is_killsweep": false, "notes": reason})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("通杀记录不存在")
	}
	engine.EmitInfo(taskID, "killsweep", "killsweep_invalid", "标记通杀结论无效："+reason,
		map[string]any{"killsweep_id": killsweepID})
	return nil
}

// RetryKillsweep 重跑通杀分析。
func RetryKillsweep(taskID, killsweepID string) error {
	var record model.Killsweep
	if err := core.Db.First(&record, "id = ? AND task_id = ?", killsweepID, taskID).Error; err != nil {
		return fmt.Errorf("通杀记录不存在")
	}
	if !model.KillsweepRetryable(record.Status, record.IsKillsweep) {
		return fmt.Errorf("该通杀记录已定论，无需重试")
	}
	core.Db.Model(&model.Killsweep{}).Where("id = ?", killsweepID).
		Update("status", constant.KillsweepAnalyzing)
	engine.EmitInfo(taskID, "killsweep", "killsweep_retry", "重新触发通杀分析",
		map[string]any{"killsweep_id": killsweepID})
	engine.ManagerInstance().TriggerKillsweep(taskID, record.OriginFindingID)
	return nil
}

// ===== 报告助手 =====

// AssistantReply 报告助手回复。
type AssistantReply struct {
	Reply    string         `json:"reply"`
	Edits    map[string]any `json:"edits,omitempty"`
	ToolLogs []map[string]any `json:"tool_logs,omitempty"`
	Model    string         `json:"model,omitempty"`
	BaseURL  string         `json:"base_url,omitempty"`
	Usage    any            `json:"usage,omitempty"`
	ErrorMsg string         `json:"error,omitempty"`
}

// RunReportAssistant 调用 LLM 生成报告完善建议（非流式：走同一工具循环，无实时回调）。
func RunReportAssistant(ctx context.Context, findingID, message string) *AssistantReply {
	return RunReportAssistantLoop(ctx, findingID, message, nil)
}

// appendAssistantMessage 记录助手对话历史。
func appendAssistantMessage(finding *model.Finding, question, answer string) {
	history := finding.AssistantMsgs
	if len(history) >= constant.IntelMsgCap {
		history = history[len(history)-constant.IntelMsgCap+2:]
	}
	history = append(history,
		map[string]any{"role": "user", "content": utils.Truncate(question, 4000), "ts": utils.ToCSTISO(time.Now())},
		map[string]any{"role": "assistant", "content": utils.Truncate(answer, 8000), "ts": utils.ToCSTISO(time.Now())},
	)
	// 列名是 assistant_msgs（GORM 对 AssistantMsgs 的默认 snake_case），写 assistant_messages 会报
	// Error 1054 Unknown column（实测踩过，日志 03:26:24）。json tag 的 assistant_messages 只是 API 输出名。
	if err := core.Db.Model(&model.Finding{}).Where("id = ?", finding.ID).
		Update("assistant_msgs", history).Error; err != nil {
		global.Log.Warnf("保存助手对话失败: %v", err)
	}
}

// ===== 跨任务漏洞视图（vulns 页）=====

// VulnStats 全局漏洞统计。
func VulnStats() map[string]any {
	stats := map[string]any{
		"total": 0, "accepted": 0, "ignored": 0, "deepen": 0,
		"review_pending": 0, "submit_ready": 0, "rejected": 0, "archived": 0,
		"killsweep": 0, "by_severity": map[string]int{}, "by_type": map[string]int{},
	}
	var findings []model.Finding
	core.Db.Find(&findings)
	findingStatus := make(map[string]string, len(findings))
	bySeverity := map[string]int{}
	byType := map[string]int{}
	for _, f := range findings {
		findingStatus[f.ID] = f.Status
		byType[f.VulnType]++
	}

	var reviews []model.Review
	core.Db.Find(&reviews)
	// total/submitted/ready/by_severity 对齐原版 vulns.py::_base_conds：
	// 全局漏洞库只统计「人工审核通过且非 superseded」，前端「过审漏洞」卡用 total。
	passedTotal, passedSubmitted := 0, 0
	for _, r := range reviews {
		switch r.Verdict {
		case constant.VerdictAccepted:
			stats["accepted"] = toInt(stats["accepted"]) + 1
		case constant.VerdictIgnored:
			stats["ignored"] = toInt(stats["ignored"]) + 1
		case constant.VerdictDeepen:
			stats["deepen"] = toInt(stats["deepen"]) + 1
		}
		inScope := r.UserStatus == constant.UserPassed && findingStatus[r.FindingID] != constant.FindingSuperseded
		switch r.UserStatus {
		case constant.UserPending:
			stats["review_pending"] = toInt(stats["review_pending"]) + 1
		case constant.UserPassed:
			if r.Submitted {
				passedSubmitted++
			} else {
				stats["submit_ready"] = toInt(stats["submit_ready"]) + 1
			}
		case constant.UserRejected:
			stats["rejected"] = toInt(stats["rejected"]) + 1
		}
		if r.Submitted {
			stats["archived"] = toInt(stats["archived"]) + 1
		}
		if inScope {
			passedTotal++
			severity := r.EffectiveSeverity()
			if severity != "" {
				bySeverity[severity]++
			}
		}
	}
	var killsweepCount int64
	core.Db.Model(&model.Killsweep{}).Count(&killsweepCount)
	stats["killsweep"] = int(killsweepCount)
	stats["total"] = passedTotal
	stats["submitted"] = passedSubmitted
	stats["ready"] = passedTotal - passedSubmitted
	stats["by_severity"] = bySeverity
	stats["by_type"] = byType
	return stats
}

// ===== 小工具 =====

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func derefBool(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

func derefFloat(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func decodeStringSlice(raw *string) []string {
	if raw == nil || *raw == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(*raw), &out); err != nil {
		return []string{}
	}
	return out
}

func decodeMap(raw *string) map[string]any {
	if raw == nil || *raw == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(*raw), &out); err != nil {
		return map[string]any{}
	}
	return out
}

func mapOrEmpty(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func nonNilMapSlice(items []map[string]any) []map[string]any {
	if items == nil {
		return []map[string]any{}
	}
	return items
}

// jsonContains 在视图的 JSON 序列化结果里做全文匹配。
func jsonContains(view map[string]any, query string) bool {
	raw, err := json.Marshal(view)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), query)
}
