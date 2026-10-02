package service

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/utils"

	"gorm.io/gorm"
)

// BuildTaskView 组装任务视图（含可选的统计信息与脱敏配置）。
func BuildTaskView(task *model.Task, withStats bool) map[string]any {
	if task == nil {
		return nil
	}
	view := map[string]any{
		"id":                task.ID,
		"name":              task.Name,
		"status":            task.Status,
		"src_type":          task.SrcType,
		"vuln_types":        nonNilStrings(task.VulnTypes),
		"target_source":     task.TargetSource,
		"engine":            engine.NormalizeEngine(firstNotEmpty(task.Engine, engine.LoadSystemSettings().Defaults.Engine)),
		"fofa_query":        task.FofaQuery,
		"concurrency":       task.Concurrency,
		"deepen_cap":        task.DeepenCap,
		"auto_killsweep":    task.AutoKillsweep,
		"src_rules":         task.SrcRules,
		"manual_targets":    nonNilStrings(task.ManualTargets),
		"auth_bindings":     maskAuthBindings(task.AuthBindings),
		"model_config_data": buildModelConfigView(task),
		"fofa_config":       buildFofaConfigView(task),
		"engine_config":     buildEngineConfigView(task),
		"llm_usage":         task.RuntimeStats.LLM,
		"engine_usage":      task.RuntimeStats.Engine,
		"created_at":        utils.ToCSTISO(task.CreatedAt),
		"updated_at":        utils.ToCSTISO(task.UpdatedAt),
		"is_top":            task.IsTop,
	}
	if withStats {
		stats := TaskStatsOf(task.ID)
		view["stats"] = stats
		view["pending_user_review"] = stats["review_pending"]
		view["target_stats"] = TargetStatusStats(task.ID)
	} else {
		view["stats"] = nil
		view["pending_user_review"] = 0
		view["target_stats"] = map[string]int64{}
	}
	return view
}

// TargetStatusStats 目标状态计数（任务列表「目标」列，按状态分组）。
func TargetStatusStats(taskID string) map[string]int64 {
	rows := make([]struct {
		Status string
		N      int64
	}, 0, 6)
	if err := core.Db.Model(&model.Target{}).Select("status, COUNT(*) AS n").
		Where("task_id = ?", taskID).Group("status").Scan(&rows).Error; err != nil {
		global.Log.Warnf("目标状态统计失败 task=%s: %v", taskID, err)
		return map[string]int64{}
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Status] = r.N
	}
	return out
}

// buildModelConfigView 组装任务级模型配置（密钥脱敏）。
func buildModelConfigView(task *model.Task) map[string]any {
	cfg := task.ModelConfig
	singleKeyRef := strings.TrimSpace(cfg.KeyRef)
	if singleKeyRef == "" {
		singleKeyRef = utils.IdentityRef(cfg.BaseURL)
	}
	view := map[string]any{
		"inherit_global": cfg.IsInherit(),
		"base_url":       cfg.BaseURL,
		"model":          cfg.Model,
		"protocol":       cfg.Protocol,
		"api_key":        utils.MaskSecret(cfg.APIKey),
		"api_key_set":    strings.TrimSpace(cfg.APIKey) != "",
		"key_ref":        singleKeyRef,
		"prompt_version": cfg.PromptVersion,
	}
	providers := make([]map[string]any, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		keyRef := strings.TrimSpace(p.KeyRef)
		if keyRef == "" {
			keyRef = utils.IdentityRef(p.BaseURL, p.Name)
		}
		providers = append(providers, map[string]any{
			"name":        p.Name,
			"base_url":    p.BaseURL,
			"model":       p.Model,
			"protocol":    p.Protocol,
			"api_key":     utils.MaskSecret(p.APIKey),
			"api_key_set": strings.TrimSpace(p.APIKey) != "",
			"key_ref":     keyRef,
			"weight":      p.Weight,
			"enabled":     p.Enabled,
			"temperature": p.Temperature,
		})
	}
	view["providers"] = providers
	// 端点池模式没有单一 model 字段，列表/看板「模型」列会显示成「未配置模型」。
	// 下发 model_display：启用端点的去重模型名（逗号连接）；都没有则报端点数。
	if strings.TrimSpace(cfg.Model) == "" && len(cfg.Providers) > 0 {
		seen := map[string]bool{}
		names := make([]string, 0, len(cfg.Providers))
		enabledCount := 0
		for _, p := range cfg.Providers {
			if !p.Enabled {
				continue
			}
			enabledCount++
			name := strings.TrimSpace(p.Model)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
		if len(names) > 0 {
			view["model_display"] = strings.Join(names, " / ")
		} else {
			view["model_display"] = fmt.Sprintf("端点池 · %d 个端点", enabledCount)
		}
	}
	return view
}

// buildFofaConfigView 组装测绘配置视图。
func buildFofaConfigView(task *model.Task) map[string]any {
	cfg := task.FofaConfig
	phaseText := cfg.CollectorPhaseText
	if phaseText == "" {
		phaseText = phaseLabel(cfg.CollectorPhase)
	}
	return map[string]any{
		"key":                  utils.MaskSecret(cfg.Key),
		"key_set":              strings.TrimSpace(cfg.Key) != "",
		"base_url":             cfg.BaseURL,
		"max_pages":            cfg.MaxPages,
		"page_size":            cfg.PageSize,
		"intent_mode":          cfg.IntentMode,
		"skip_site_recon":      cfg.SkipSiteRecon,
		"cursor":               cfg.Cursor,
		"current_query":        cfg.CurrentQuery,
		"empty_streak":         cfg.EmptyStreak,
		"empty_query_streak":   cfg.EmptyQueryStreak,
		"fofa_exhausted":       cfg.FofaExhausted,
		"last_fofa_error":      cfg.LastFofaError,
		"fofa_auth_fail_count": cfg.FofaAuthFailCount,
		"daily_limit_count":    cfg.DailyLimitCount,
		"engine_fail_count":    cfg.EngineFailCount,
		"next_retry_at":        cfg.NextRetryAt,
		"collector_phase":      cfg.CollectorPhase,
		"collector_phase_text": phaseText,
	}
}

// buildEngineConfigView 组装引擎配置视图。
func buildEngineConfigView(task *model.Task) map[string]any {
	engineName := engine.NormalizeEngine(firstNotEmpty(task.Engine, engine.LoadSystemSettings().Defaults.Engine))
	key, baseURL := ResolveEngineConfig(engineName)
	return map[string]any{
		"engine":   engineName,
		"display":  engine.EngineDisplayName(engineName),
		"key_set":  strings.TrimSpace(key) != "",
		"key":      utils.MaskSecret(key),
		"base_url": baseURL,
	}
}

// phaseLabel 把搜集阶段标识转为可读文案。
func phaseLabel(phase string) string {
	switch phase {
	case "search":
		return "正在检索资产…"
	case "enrich":
		return "正在补全资产信息…"
	case "dispatch":
		return "正在入队…"
	case "scoring":
		return "正在评分排序…"
	case "idle":
		return "搜集待命"
	default:
		return ""
	}
}

// maskAuthBindings 凭据绑定脱敏（保留结构，屏蔽明文）。
func maskAuthBindings(bindings []model.AuthBinding) []map[string]any {
	out := make([]map[string]any, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, map[string]any{
			"target":        b.Target,
			"username":      b.Username,
			"password":      utils.MaskSecret(b.Password),
			"password_set":  b.Password != "",
			"cookie":        utils.MaskSecret(b.Cookie),
			"cookie_set":    b.Cookie != "",
			"authorization": utils.MaskSecret(b.Authorization),
			"auth_set":      b.Authorization != "",
			"login_url":     b.LoginURL,
			"raw":           utils.MaskSecret(b.Raw),
			"raw_set":       b.Raw != "",
			"note":          b.Note,
		})
	}
	return out
}

// TaskStatsOf 汇总任务的看板统计。
func TaskStatsOf(taskID string) map[string]any {
	stats := map[string]any{
		"queued": 0, "scanning": 0, "done": 0, "dead": 0, "skipped": 0,
		"findings_total": 0, "pending_review": 0, "accepted": 0, "ignored": 0,
		"deepen": 0, "killsweep": 0, "review_pending": 0, "submit_ready": 0,
		"review_queue": 0,
		"rejected": 0, "archived": 0, "archived_write": 0,
		"hosts_total": 0, "hosts_checked": 0, "checked": 0,
	}
	if core.Db == nil {
		return stats
	}

	type statusCount struct {
		Status string
		Total  int64
	}
	var targetCounts []statusCount
	core.Db.Model(&model.Target{}).Select("status, count(*) as total").
		Where("task_id = ?", taskID).Group("status").Scan(&targetCounts)
	hostsTotal := 0
	for _, row := range targetCounts {
		hostsTotal += int(row.Total)
		switch row.Status {
		case constant.TargetQueued:
			stats["queued"] = int(row.Total)
		case constant.TargetAssigned, constant.TargetScanning:
			stats["scanning"] = toInt(stats["scanning"]) + int(row.Total)
		case constant.TargetDone:
			stats["done"] = int(row.Total)
		case constant.TargetDead:
			stats["dead"] = int(row.Total)
		case constant.TargetSkipped:
			stats["skipped"] = int(row.Total)
		}
	}
	stats["hosts_total"] = hostsTotal
	stats["hosts_checked"] = toInt(stats["done"]) + toInt(stats["dead"])
	stats["checked"] = stats["hosts_checked"]
	stats["scanning"] = toInt(stats["scanning"])

	var findings []model.Finding
	core.Db.Where("task_id = ?", taskID).Find(&findings)
	stats["findings_total"] = len(findings)

	findingIDs := make([]string, 0, len(findings))
	findingStatus := make(map[string]string, len(findings))
	findingTitle := make(map[string]string, len(findings))
	findingURL := make(map[string]string, len(findings))
	for _, f := range findings {
		findingIDs = append(findingIDs, f.ID)
		findingStatus[f.ID] = f.Status
		findingTitle[f.ID] = f.Title
		findingURL[f.ID] = f.TargetURL
		if f.Status == constant.FindingPendingReview {
			stats["pending_review"] = toInt(stats["pending_review"]) + 1
		}
	}

	if len(findingIDs) > 0 {
		var reviews []model.Review
		core.Db.Where("finding_id IN ?", findingIDs).Find(&reviews)
		for _, review := range reviews {
			switch review.Verdict {
			case constant.VerdictAccepted:
				stats["accepted"] = toInt(stats["accepted"]) + 1
				// 复审队列口径 = AI 采纳且用户待处理（与 ListReviewQueue 的过滤
				// 完全同源）。review_pending 用原版同名字段语义（app/api/tasks.py
				// 362-363：verdict==accepted && user_status==pending），与
				// review_queue 恒同值；review_pending 曾是「所有用户待处理」的
				// 旧口径（含 AI 未采纳），会导致 REVIEW 卡与队列数量对不上。
				if review.UserStatus == constant.UserPending {
					stats["review_queue"] = toInt(stats["review_queue"]) + 1
					stats["review_pending"] = toInt(stats["review_pending"]) + 1
				}
			case constant.VerdictIgnored:
				stats["ignored"] = toInt(stats["ignored"]) + 1
			case constant.VerdictDeepen:
				stats["deepen"] = toInt(stats["deepen"]) + 1
			}
			switch {
			case review.UserStatus == constant.UserPassed && !review.Submitted:
				// 对齐原版 tasks.py 364 行：passed 且未提交才算待提交。
				stats["submit_ready"] = toInt(stats["submit_ready"]) + 1
			case review.UserStatus == constant.UserRejected:
				stats["rejected"] = toInt(stats["rejected"]) + 1
			}
			// AI 未采纳归档：与 ListArchived 过滤完全一致（原版 tasks.py 372-382
			// 的注释明确要求「徽标数字 == 列表条数」）。曾误用 submitted 数量，
			// 前端拿它当「AI 未采纳」徽标时数字与列表永远对不上。
			if (review.Verdict == constant.VerdictIgnored || review.Verdict == constant.VerdictDeepen) &&
				review.UserStatus == constant.UserPending &&
				findingStatus[review.FindingID] != constant.FindingSuperseded {
				stats["archived"] = toInt(stats["archived"]) + 1
				// 写/删类置顶统计（对齐原版 tasks.py 383-403 的 ilike 条件）。
				if isWriteOpText(findingTitle[review.FindingID], findingURL[review.FindingID]) {
					stats["archived_write"] = toInt(stats["archived_write"]) + 1
				}
			}
		}
	}

	var killsweepCount int64
	core.Db.Model(&model.Killsweep{}).Where("task_id = ?", taskID).Count(&killsweepCount)
	stats["killsweep"] = int(killsweepCount)

	return stats
}

// isWriteOpText 判断写/删类漏洞（对齐原版 archived_write 的 ilike 条件：
// title 命中 删除/修改/更新/delete/update，或 url 命中 delete/update/save/remove）。
func isWriteOpText(title, url string) bool {
	t := strings.ToLower(title)
	u := strings.ToLower(url)
	for _, kw := range []string{"删除", "修改", "更新", "delete", "update"} {
		if strings.Contains(t, strings.ToLower(kw)) {
			return true
		}
	}
	for _, kw := range []string{"delete", "update", "/save", "remove"} {
		if strings.Contains(u, kw) {
			return true
		}
	}
	return false
}

// ListTasks 任务列表：先按置顶、再按创建时间倒序；支持全量 JSON 文本搜索。
func ListTasks(query string, limit, offset int) ([]map[string]any, int64, error) {
	var tasks []model.Task
	if err := core.Db.Order("is_top DESC, created_at DESC").Find(&tasks).Error; err != nil {
		return nil, 0, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query != "" {
		filtered := make([]model.Task, 0, len(tasks))
		for _, task := range tasks {
			haystack := strings.ToLower(strings.Join([]string{
				task.ID, task.Name, task.SrcType, task.Status,
				task.FofaQuery, strings.Join(task.VulnTypes, " "),
			}, " "))
			if strings.Contains(haystack, query) {
				filtered = append(filtered, task)
			}
		}
		tasks = filtered
	}
	total := int64(len(tasks))
	tasks = sliceTasks(tasks, limit, offset)
	out := make([]map[string]any, 0, len(tasks))
	for i := range tasks {
		out = append(out, BuildTaskView(&tasks[i], true))
	}
	return out, total, nil
}

// sliceTasks 按 limit/offset 切片（limit<=0 表示全量）。
func sliceTasks(tasks []model.Task, limit, offset int) []model.Task {
	if limit <= 0 {
		if offset > 0 {
			if offset >= len(tasks) {
				return nil
			}
			return tasks[offset:]
		}
		return tasks
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(tasks) {
		return nil
	}
	end := offset + limit
	if end > len(tasks) {
		end = len(tasks)
	}
	return tasks[offset:end]
}

// QueryTargets 目标查询（跨任务通用，按置顶/优先级排序）。
//
// 曾名为 HardTargets 并对外暴露为「全局硬骨头库」端点（/api/tasks/hard-targets），
// 该功能对标主流扫描平台均无对应物、且信息完全被任务目标列表覆盖，已整体移除；
// 本函数保留是因为任务目标列表（TaskTargets）与看板（BoardView）共用此查询。
type QueryTargetsFilter struct {
	TaskID   string
	Status   string
	MinScore float64
	Query    string
	Limit    int
	Offset   int
}

// QueryTargets 返回过滤排序后的目标视图。
func QueryTargets(filter QueryTargetsFilter) ([]map[string]any, int64, error) {
	var targets []model.Target
	db := core.Db.Model(&model.Target{})
	if filter.TaskID != "" {
		db = db.Where("task_id = ?", filter.TaskID)
	}
	if filter.Status != "" {
		db = db.Where("status = ?", filter.Status)
	}
	if filter.MinScore > 0 {
		db = db.Where("priority_score >= ?", filter.MinScore)
	}
	if err := db.Order("is_top DESC, priority_score DESC, created_at DESC").Find(&targets).Error; err != nil {
		return nil, 0, err
	}
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	if query != "" {
		filtered := make([]model.Target, 0, len(targets))
		for _, t := range targets {
			haystack := strings.ToLower(strings.Join([]string{t.Host, t.URL, t.Title, t.Org, t.School, t.IP}, " "))
			if strings.Contains(haystack, query) {
				filtered = append(filtered, t)
			}
		}
		targets = filtered
	}
	total := int64(len(targets))
	targets = sliceTargets(targets, filter.Limit, filter.Offset)
	out := make([]map[string]any, 0, len(targets))
	// task_name 派生字段：前端目标列表「任务」列优先读 row.task_name（缺失时只能显示哈希 ID）。
	taskNames := taskNameMap(targets)
	for i := range targets {
		view := BuildTargetView(&targets[i])
		view["task_name"] = taskNames[targets[i].TaskID]
		out = append(out, view)
	}
	return out, total, nil
}

// taskNameMap 批量取任务名（空 ID 去重后一次查询）。
func taskNameMap(targets []model.Target) map[string]string {
	ids := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for i := range targets {
		if targets[i].TaskID != "" && !seen[targets[i].TaskID] {
			seen[targets[i].TaskID] = true
			ids = append(ids, targets[i].TaskID)
		}
	}
	names := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return names
	}
	var rows []model.Task
	if err := core.Db.Select("id, name").Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return names
	}
	for _, t := range rows {
		names[t.ID] = t.Name
	}
	return names
}

func sliceTargets(items []model.Target, limit, offset int) []model.Target {
	if limit <= 0 {
		if offset > 0 {
			if offset >= len(items) {
				return nil
			}
			return items[offset:]
		}
		return items
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

// BuildTargetView 目标视图。
func BuildTargetView(t *model.Target) map[string]any {
	if t == nil {
		return nil
	}
	view := map[string]any{
		"id":              t.ID,
		"task_id":         t.TaskID,
		"url":             t.URL,
		"host":            t.Host,
		"ip":              t.IP,
		"org":             t.Org,
		"title":           t.Title,
		"source":          t.Source,
		"is_edu":          t.IsEdu,
		"school":          t.School,
		"priority_score":  t.PriorityScore,
		"priority_reason": t.PriorityReason,
		"status":          t.Status,
		"verdict":         t.Verdict,
		"retry_count":     t.RetryCount,
		"dead_reason":     t.DeadReason,
		"last_error":      t.LastError,
		"deepen_count":    t.DeepenCount,
		"deepen_context":  t.DeepenContext,
		"leaked_creds":    t.LeakedCreds,
		"auth_status":     t.AuthStatus,
		"assigned_worker": t.AssignedWorker,
		"is_top":          t.IsTop,
		"created_at":      utils.ToCSTISO(t.CreatedAt),
		"updated_at":      utils.ToCSTISO(t.UpdatedAt),
		"heartbeat_at":    utils.ToCSTNullable(t.HeartbeatAt),
	}
	return view
}

// TaskHosts 按 host 聚合的目标视图（含漏洞计数）。
func TaskHosts(taskID string, limit, offset int) ([]map[string]any, int64, error) {
	var targets []model.Target
	if err := core.Db.Where("task_id = ?", taskID).
		Order("priority_score DESC, created_at ASC").Find(&targets).Error; err != nil {
		return nil, 0, err
	}
	total := int64(len(targets))
	targets = sliceTargets(targets, limit, offset)

	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		ids = append(ids, t.ID)
	}
	findingCount := map[string]int{}
	acceptedCount := map[string]int{}
	if len(ids) > 0 {
		type row struct {
			TargetID string
			Total    int64
		}
		var rows []row
		core.Db.Model(&model.Finding{}).Select("target_id, count(*) as total").
			Where("target_id IN ?", ids).Group("target_id").Scan(&rows)
		for _, r := range rows {
			findingCount[r.TargetID] = int(r.Total)
		}
		var accepted []row
		core.Db.Model(&model.Finding{}).Select("target_id, count(*) as total").
			Where("target_id IN ? AND status = ?", ids, constant.FindingReviewed).
			Group("target_id").Scan(&accepted)
		for _, r := range accepted {
			acceptedCount[r.TargetID] = int(r.Total)
		}
	}

	out := make([]map[string]any, 0, len(targets))
	for i := range targets {
		view := BuildTargetView(&targets[i])
		view["findings"] = findingCount[targets[i].ID]
		view["reviewed"] = acceptedCount[targets[i].ID]
		out = append(out, view)
	}
	return out, total, nil
}

// BoardView 任务看板：目标 + 实时事件 + 当前 worker。
func BoardView(taskID string) (map[string]any, error) {
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		return nil, err
	}
	targets, _, err := QueryTargets(QueryTargetsFilter{TaskID: taskID, Limit: 100})
	if err != nil {
		return nil, err
	}
	var events []model.TaskEvent
	core.Db.Where("task_id = ?", taskID).Order("id DESC").Limit(300).Find(&events)
	eventList := make([]map[string]any, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		row := events[i]
		payload := map[string]any{}
		for k, v := range row.Payload {
			payload[k] = v
		}
		payload["id"] = row.ID
		payload["agent"] = row.Agent
		payload["kind"] = row.Kind
		payload["level"] = row.Level
		payload["message"] = row.Message
		payload["ts"] = utils.ToCSTISO(row.Ts)
		eventList = append(eventList, payload)
	}

	runner := engine.ManagerInstance().GetRunner(taskID)
	live := map[string]any{"workers": []map[string]any{}, "escalations": []string{}}
	if runner != nil {
		live["workers"] = runner.LiveWorkers()
		live["escalations"] = runner.LiveEscalations()
	}

	// 单站协作态势：site 路线按三阶段聚合（非 site 任务为 nil，前端面板隐藏）。
	siteCollab := engine.BuildCollabOverview(collabOverviewRows(taskID))

	return map[string]any{
		"task":         BuildTaskView(&task, true),
		"targets":      targets,
		"events":       eventList,
		"live":         live,
		"stats":        TaskStatsOf(taskID),
		"site_collab":  siteCollab,
		"server_time":  utils.ToCSTISO(time.Now()),
	}, nil
}

// collabOverviewRows 汇总单站协作聚合所需的目标行（含未 superseded 的战果计数）。
func collabOverviewRows(taskID string) []map[string]any {
	var targets []model.Target
	core.Db.Select("id, source, status, verdict, priority_reason, deepen_count").
		Where("task_id = ?", taskID).Find(&targets)
	findingCounts := map[string]int{}
	var fcRows []struct {
		TargetID string
		N        int64
	}
	core.Db.Model(&model.Finding{}).Select("target_id, count(*) as n").
		Where("task_id = ? AND status != ?", taskID, constant.FindingSuperseded).
		Group("target_id").Scan(&fcRows)
	for _, row := range fcRows {
		findingCounts[row.TargetID] = int(row.N)
	}
	rows := make([]map[string]any, 0, len(targets))
	for i := range targets {
		t := &targets[i]
		rows = append(rows, map[string]any{
			"source":          t.Source,
			"status":          t.Status,
			"verdict":         t.Verdict,
			"priority_reason": t.PriorityReason,
			"deepen_count":    t.DeepenCount,
			"findings":        findingCounts[t.ID],
		})
	}
	return rows
}

// TargetTrace 目标事件轨迹。
func TargetTrace(taskID, targetID string, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 200
	}
	var events []model.TaskEvent
	if err := core.Db.Where("task_id = ?", taskID).Order("id DESC").Limit(limit * 3).Find(&events).Error; err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, limit)
	for i := len(events) - 1; i >= 0; i-- {
		row := events[i]
		if tid, ok := row.Payload["target_id"].(string); !ok || tid != targetID {
			continue
		}
		item := map[string]any{
			"id":      row.ID,
			"agent":   row.Agent,
			"kind":    row.Kind,
			"level":   row.Level,
			"message": row.Message,
			"ts":      utils.ToCSTISO(row.Ts),
		}
		for k, v := range row.Payload {
			item[k] = v
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// ToggleTaskTop 切换任务置顶。
func ToggleTaskTop(taskID string, isTop bool) error {
	return core.Db.Model(&model.Task{}).Where("id = ?", taskID).Update("is_top", isTop).Error
}

// ToggleBatchTop 批量置顶：tasks / vulns 共用。
func ToggleBatchTop(table string, ids []string, isTop bool) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var modelRef any
	switch table {
	case "vuln":
		modelRef = &model.Finding{}
	default:
		modelRef = &model.Task{}
	}
	res := core.Db.Model(modelRef).Where("id IN ?", ids).Update("is_top", isTop)
	return res.RowsAffected, res.Error
}

// DeleteTask 删除任务及其全部关联数据。
func DeleteTask(taskID string) error {
	engine.ManagerInstance().Remove(taskID)
	return core.Db.Transaction(func(tx *gorm.DB) error {
		var findingIDs []string
		tx.Model(&model.Finding{}).Where("task_id = ?", taskID).Pluck("id", &findingIDs)
		if len(findingIDs) > 0 {
			if err := tx.Where("finding_id IN ?", findingIDs).Delete(&model.Review{}).Error; err != nil {
				return err
			}
		}
		for _, step := range []func() error{
			func() error { return tx.Where("task_id = ?", taskID).Delete(&model.Finding{}).Error },
			func() error { return tx.Where("task_id = ?", taskID).Delete(&model.Killsweep{}).Error },
			func() error { return tx.Where("task_id = ?", taskID).Delete(&model.Target{}).Error },
			func() error { return tx.Where("task_id = ?", taskID).Delete(&model.TaskEvent{}).Error },
			func() error { return tx.Where("id = ?", taskID).Delete(&model.Task{}).Error },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		global.Log.Infof("已删除任务 %s（含 %d 条漏洞）", taskID, len(findingIDs))
		return nil
	})
}

// TaskWorkDir 返回任务工作目录。
func TaskWorkDir(taskID string) string {
	return fmt.Sprintf("%s/%s", config.WorkRootDir(), taskID)
}

// nonNilStrings 保证 JSON 输出为数组而非 null。
func nonNilStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

// sortStringsDesc 倒序排序（辅助）。
func sortStringsDesc(items []string) {
	sort.Sort(sort.Reverse(sort.StringSlice(items)))
}

// toInt 把 map 中的任意数值转为 int。
func toInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}
