package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// 调度参数（与 AutoHunter orchestrator 对齐）。
const (
	LoopIntervalSeconds     = 5   // 主循环周期
	LowWatermark            = 6   // 队列低水位，低于该值触发搜集
	WorkerMaxConcurrency    = 32  // 全局 worker 并发硬上限
	WorkerMaxRounds         = 12  // 单目标最多 LLM 轮次
	WorkerWallLimitMinute   = 15  // 单目标墙钟上限（分钟）
	HeartbeatIntervalSecond = 30  // 目标心跳写入间隔
	StaleHeartbeatSeconds   = 300 // 心跳超时判定为幽灵目标
	ReviewBatchPerTick      = 4   // 每轮最多派发的审核任务数
	RetryMaxPerTarget       = 2   // 同一目标最大重试次数
	NoVulnRetryCap          = 1   // 无洞目标允许的重复回队次数
)

// workerSem 全局 worker 并发信号量，保证跨任务总量可控。
var workerSem = make(chan struct{}, WorkerMaxConcurrency)

// workerHandle 一个在跑的 worker 句柄。
type workerHandle struct {
	targetID string
	workerID string
	session  *WorkerSession
	cancel   context.CancelFunc
	started  time.Time
}

// TaskRunner 单个任务的调度器：派发目标、回收幽灵、派发审核、触发通杀。
type TaskRunner struct {
	TaskID string

	mu          sync.Mutex
	workerPool  *llm.Pool
	workers     map[string]*workerHandle
	reviews     map[string]context.CancelFunc
	killsweeps  map[string]context.CancelFunc
	escalations map[string]context.CancelFunc
	directives  map[string]string

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// NewTaskRunner 创建任务运行器。
func NewTaskRunner(taskID string) *TaskRunner {
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskRunner{
		TaskID:      taskID,
		workers:     map[string]*workerHandle{},
		reviews:     map[string]context.CancelFunc{},
		killsweeps:  map[string]context.CancelFunc{},
		escalations: map[string]context.CancelFunc{},
		directives:  map[string]string{},
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
}

// LiveWorkers 返回当前在跑 worker 的只读快照。
func (r *TaskRunner) LiveWorkers() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]map[string]any, 0, len(r.workers))
	for _, h := range r.workers {
		out = append(out, map[string]any{
			"target_id": h.targetID,
			"worker_id": h.workerID,
			"round":     h.session.Round,
			"model":     h.session.ModelName,
			"elapsed":   int(time.Since(h.started).Seconds()),
		})
	}
	return out
}

// LiveEscalations 返回正在进行的扩大危害分析。
func (r *TaskRunner) LiveEscalations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.escalations))
	for id := range r.escalations {
		out = append(out, id)
	}
	return out
}

// InjectDirective 向某个运行中目标注入人工实时指令。
func (r *TaskRunner) InjectDirective(targetID, directive string) map[string]any {
	directive = strings.TrimSpace(directive)
	if directive == "" {
		return map[string]any{"ok": false, "reason": "指令不能为空"}
	}
	r.mu.Lock()
	h, ok := r.workers[targetID]
	if ok && h.session != nil {
		h.session.SetDirective(directive)
	}
	r.mu.Unlock()
	if ok {
		EmitInfo(r.TaskID, "orchestrator", "worker_directive_queued",
			"已向运行中的目标注入人工指令", map[string]any{"target_id": targetID})
		return map[string]any{"ok": true, "delivered": true}
	}
	// 目标不在跑：暂存，等下次派发时注入。
	r.mu.Lock()
	r.directives[targetID] = directive
	r.mu.Unlock()
	EmitInfo(r.TaskID, "orchestrator", "worker_directive_queued",
		"目标暂未运行，指令已排队等待下次派发", map[string]any{"target_id": targetID})
	return map[string]any{"ok": true, "delivered": false}
}

func (r *TaskRunner) popDirective(targetID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	value := r.directives[targetID]
	delete(r.directives, targetID)
	return value
}

// CancelEscalation 取消正在进行的扩大危害分析。
func (r *TaskRunner) CancelEscalation(findingID, reason string) map[string]any {
	if reason == "" {
		reason = "用户取消扩大危害"
	}
	r.mu.Lock()
	cancel, ok := r.escalations[findingID]
	delete(r.escalations, findingID)
	r.mu.Unlock()
	if !ok {
		return map[string]any{"ok": false, "reason": "该漏洞没有正在进行的扩大危害任务"}
	}
	cancel()
	EmitWarn(r.TaskID, "escalation", "escalate_cancelled", reason, map[string]any{"finding_id": findingID})
	return map[string]any{"ok": true}
}

// Run 启动任务主循环，直到任务被暂停 / 停止。
func (r *TaskRunner) Run() {
	defer close(r.done)
	if core.Db != nil {
		r.recoverOnStart()
	}
	ticker := time.NewTicker(time.Duration(LoopIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if err := r.tick(); err != nil {
				global.Log.Errorf("TaskRunner[%s] tick error: %v", r.TaskID, err)
				EmitError(r.TaskID, "orchestrator", "error", "主循环异常: "+err.Error(), nil)
			}
		}
	}
}

// Stop 请求停止主循环并取消全部子任务。
func (r *TaskRunner) Stop() {
	r.once.Do(func() { r.cancel() })
}

// Done 返回主循环结束信号。
func (r *TaskRunner) Done() <-chan struct{} { return r.done }

// recoverOnStart 进程重启恢复：把上次遗留的在途目标回退为排队。
// 同时清掉测绘失败退避与停机计数：重启任务=用户主动重试，应放开引擎查询。
func (r *TaskRunner) recoverOnStart() {
	res := core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status IN ?", r.TaskID, []string{constant.TargetAssigned, constant.TargetScanning}).
		Updates(map[string]any{"status": constant.TargetQueued, "assigned_worker": ""})
	if res.Error == nil && res.RowsAffected > 0 {
		EmitInfo(r.TaskID, "orchestrator", "recover",
			fmt.Sprintf("启动恢复：%d 个在途目标已回退为排队", res.RowsAffected), nil)
	}
	if core.Db != nil {
		var task model.Task
		if err := core.Db.First(&task, "id = ?", r.TaskID).Error; err == nil &&
			(task.FofaConfig.NextRetryAt != time.Time{} || task.FofaConfig.EngineFailCount > 0) {
			task.FofaConfig.NextRetryAt = time.Time{}
			task.FofaConfig.EngineFailCount = 0
			if raw, err := json.Marshal(task.FofaConfig); err == nil {
				core.Db.Model(&model.Task{}).Where("id = ?", r.TaskID).
					Update("fofa_config", string(raw))
			}
		}
	}
}

// tick 单轮调度：派发 → 补队列 → 再审派发 → 审核派发 → idle 判定。
func (r *TaskRunner) tick() error {
	var task model.Task
	if err := core.Db.First(&task, "id = ?", r.TaskID).Error; err != nil {
		// 任务被删除：结束主循环。
		r.Stop()
		return nil
	}
	if task.Status == constant.TaskPaused || task.Status == constant.TaskStopped {
		return nil
	}

	r.workerPool = BuildPoolForTask(&task)

	// 1. 先派发已有队列。
	r.reapWorkers()
	r.reclaimStale()
	r.dispatch(&task)

	// 2. 队列水位低 → 补目标。
	queued := r.count(constant.TargetQueued)
	if queued < LowWatermark {
		added, err := Refill(r.ctx, &task, r.workerPool)
		if err != nil {
			global.Log.Warnf("TaskRunner[%s] refill error: %v", r.TaskID, err)
		}
		if added > 0 {
			EmitInfo(r.TaskID, "collector", "refill",
				fmt.Sprintf("新增 %d 个目标入队", added), map[string]any{"added": added})
		}
	}

	// 3. 新入队目标再派发一轮。
	r.reapWorkers()
	r.reclaimStale()
	r.dispatch(&task)

	// 4. 派发审核。
	r.dispatchReviews(&task)

	// 5. idle 标记。
	queued = r.count(constant.TargetQueued)
	inflight := r.countIn(
		constant.TargetAssigned, constant.TargetScanning,
	)
	r.mu.Lock()
	active := len(r.workers) > 0
	r.mu.Unlock()

	busy := active || inflight > 0
	switch {
	case queued == 0 && !busy && task.Status == constant.TaskRunning:
		core.Db.Model(&model.Task{}).Where("id = ?", r.TaskID).
			Update("status", constant.TaskIdle)
	case task.Status == constant.TaskIdle && (queued > 0 || busy):
		core.Db.Model(&model.Task{}).Where("id = ?", r.TaskID).
			Update("status", constant.TaskRunning)
	}
	return nil
}

// count 统计某状态目标数。
func (r *TaskRunner) count(status string) int {
	var n int64
	core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status = ?", r.TaskID, status).Count(&n)
	return int(n)
}

// countIn 统计多个状态的目标数。
func (r *TaskRunner) countIn(statuses ...string) int {
	var n int64
	core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status IN ?", r.TaskID, statuses).Count(&n)
	return int(n)
}

// dispatch 按并发上限派发排队目标。
func (r *TaskRunner) dispatch(task *model.Task) {
	r.mu.Lock()
	active := len(r.workers)
	r.mu.Unlock()

	capValue := task.Concurrency
	if capValue <= 0 {
		capValue = 3
	}
	if capValue > WorkerMaxConcurrency {
		capValue = WorkerMaxConcurrency
	}
	free := capValue - active
	for i := 0; i < free; i++ {
		target := r.popQueued()
		if target == nil {
			return
		}
		r.spawnWorker(task, target)
	}
}

// popQueued 取一个优先级最高的排队目标并置为 assigned。
func (r *TaskRunner) popQueued() *model.Target {
	var target model.Target
	err := core.Db.Where("task_id = ? AND status = ?", r.TaskID, constant.TargetQueued).
		Order("priority_score DESC, created_at ASC").First(&target).Error
	if err != nil {
		return nil
	}
	workerID := utils.ShortUUID(8)
	res := core.Db.Model(&model.Target{}).
		Where("id = ? AND status = ?", target.ID, constant.TargetQueued).
		Updates(map[string]any{
			"status":          constant.TargetAssigned,
			"assigned_worker": workerID,
			"heartbeat_at":    time.Now(),
		})
	if res.Error != nil || res.RowsAffected == 0 {
		// 竞争失败：本轮跳过，下轮再取。
		return nil
	}
	target.Status = constant.TargetAssigned
	target.AssignedWorker = workerID
	return &target
}

// spawnWorker 启动一个目标挖掘协程。
func (r *TaskRunner) spawnWorker(task *model.Task, target *model.Target) {
	ctx, cancel := context.WithCancel(r.ctx)
	session := &WorkerSession{
		TaskID:        r.TaskID,
		TargetID:      target.ID,
		WorkerID:      target.AssignedWorker,
		MaxRounds:     WorkerMaxRounds,
		MaxWall:       WorkerWallLimitMinute * time.Minute,
		WorkDir:       workDirForTask(r.TaskID),
		DeclaredTypes: task.VulnTypes,
	}

	handle := &workerHandle{
		targetID: target.ID,
		workerID: target.AssignedWorker,
		session:  session,
		cancel:   cancel,
		started:  time.Now(),
	}
	r.mu.Lock()
	r.workers[target.ID] = handle
	r.mu.Unlock()

	if directive := r.popDirective(target.ID); directive != "" {
		session.SetDirective(directive)
	}

	go func() {
		defer cancel()
		defer func() {
			r.mu.Lock()
			delete(r.workers, target.ID)
			r.mu.Unlock()
		}()
		workerSem <- struct{}{}
		defer func() { <-workerSem }()
		r.runWorker(ctx, task, target, handle)
	}()
}

// runWorker 执行一次目标挖掘并回写状态。
func (r *TaskRunner) runWorker(ctx context.Context, task *model.Task, target *model.Target, handle *workerHandle) {
	heartbeatDone := make(chan struct{})
	go r.heartbeatLoop(target.ID, heartbeatDone)
	defer close(heartbeatDone)

	core.Db.Model(&model.Target{}).Where("id = ?", target.ID).
		Update("status", constant.TargetScanning)
	EmitInfo(r.TaskID, "worker", "worker_start",
		fmt.Sprintf("开始挖掘 %s", displayTarget(target)),
		map[string]any{"target_id": target.ID, "url": target.URL, "host": target.Host})

	wctx := r.buildWorkerContext(task, target)
	result := RunWorker(ctx, r.workerPool, wctx, WorkerMaxRounds, handle.session.WorkDir)

	if ctx.Err() != nil {
		EmitWarn(r.TaskID, "worker", "worker_cancelled", "目标挖掘被取消",
			map[string]any{"target_id": target.ID})
		return
	}
	r.persistWorkerResult(task, target, result)
	// LLM 用量按目标粒度落库，界面不必等整轮任务结束就能看到累计值。
	PersistUsage(r.TaskID)
}

// buildWorkerContext 组装 Worker 启动上下文（含情报 / 泄露凭据 / 深化指令）。
func (r *TaskRunner) buildWorkerContext(task *model.Task, target *model.Target) *WorkerContext {
	wctx := &WorkerContext{
		TaskID:    r.TaskID,
		TargetID:  target.ID,
		URL:       target.URL,
		Host:      target.Host,
		Title:     target.Title,
		Org:       target.Org,
		SrcType:   task.SrcType,
		VulnTypes: task.VulnTypes,
		SrcRules:  task.SrcRules,
	}
	if len(target.LeakedCreds) > 0 {
		lines := make([]string, 0, len(target.LeakedCreds))
		for _, cred := range target.LeakedCreds {
			username := fmt.Sprintf("%v", cred["username"])
			password := fmt.Sprintf("%v", cred["password"])
			if username == "" && password == "" {
				continue
			}
			lines = append(lines, username+" / "+password)
		}
		wctx.LeakedCreds = strings.Join(lines, "\n")
	}
	if target.AuthContext != nil {
		wctx.AuthContext = target.AuthContext
	}
	if target.DeepenContext != nil {
		if directive, ok := target.DeepenContext["directive"].(string); ok {
			wctx.DeepenDirective = directive
		}
	}
	wctx.IntelHint = buildIntelHint(target)
	// 单站协作：site_* 路线目标注入分工上下文（路线+同站覆盖摘要+用户凭据引导）。
	if IsSiteSource(target.Source) {
		if route := RouteForSource(target.Source); route != nil {
			wctx.SiteRouteSource = route.Source
			coverageBlock := r.buildCoverageContext(siteHostKey(target.URL, target.Host))
			wctx.SiteCollabBlock = RenderContext(route, task.FofaQuery, coverageBlock,
				target.PriorityReason, SkipReconEnabled(task))
			EmitInfo(r.TaskID, "worker", "site_route_start",
				fmt.Sprintf("协作路线：%s", route.Label),
				map[string]any{"target_id": target.ID, "route": route.Source, "label": route.Label})
		}
	}
	return wctx
}

// buildCoverageContext 同站协作覆盖摘要：后续 worker 启动时避免重复测同一批 API。
func (r *TaskRunner) buildCoverageContext(hostKey string) string {
	hostKey = strings.TrimSpace(hostKey)
	if hostKey == "" {
		return ""
	}
	var events []model.TaskEvent
	core.Db.Where("task_id = ? AND kind = ?", r.TaskID, "coverage_reported").
		Order("id DESC").Limit(80).Find(&events)
	lines := make([]string, 0, 12)
	seen := map[string]bool{}
	for _, event := range events {
		if strOf(event.Payload["host"]) != hostKey {
			continue
		}
		route := firstNonEmptyString(strOf(event.Payload["route"]), "unknown")
		summary := truncateStr(strOf(event.Payload["summary"]), 180)
		sample := coverageEndpointSample(event.Payload["endpoints"], 6)
		key := route + ":" + summary + ":" + strings.Join(sample, "|")
		if seen[key] {
			continue
		}
		seen[key] = true
		line := fmt.Sprintf("- %s: %s", route, summary)
		if len(sample) > 0 {
			line += fmt.Sprintf("（%s）", truncateStr(strings.Join(sample, "；"), 260))
		}
		lines = append(lines, line)
		if len(lines) >= 12 {
			break
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "# 同站协作覆盖摘要（前序 worker 上报）\n" + strings.Join(lines, "\n") + "\n"
}

// coverageEndpointSample 从覆盖事件端点列表取前 n 条「METHOD path => status result」样例。
// 兼容 DB 反序列化后的 []any 与进程内直接传的 []map[string]any 两种形态。
func coverageEndpointSample(raw any, n int) []string {
	var items []map[string]any
	switch list := raw.(type) {
	case []any:
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				items = append(items, m)
			}
		}
	case []map[string]any:
		items = list
	}
	sample := make([]string, 0, n)
	for i, item := range items {
		if i >= n {
			break
		}
		method := strings.ToUpper(strOf(item["method"]))
		if method == "" {
			method = "GET"
		}
		path := firstNonEmptyString(strOf(item["path"]), strOf(item["url"]))
		status := firstNonEmptyString(strOf(item["status"]), "-")
		result := firstNonEmptyString(strOf(item["result"]), strOf(item["note"]))
		line := strings.TrimSpace(fmt.Sprintf("%s %s => %s %s", method, path, status, result))
		if line != "" {
			sample = append(sample, line)
		}
	}
	return sample
}

// spawnSiteFollowups 从覆盖上报提炼定向追打目标（对齐原版 _spawn_site_followups）。
func (r *TaskRunner) spawnSiteFollowups(target *model.Target, coverage []map[string]any) {
	// 追打 worker 自己上报的 coverage 不再派生，避免无限接力。
	if strings.HasPrefix(target.Source, "site_f") {
		return
	}
	baseURL := firstNonEmptyString(target.URL, "http://"+target.Host)
	specs := FollowupSpecsFromCoverage(coverage, baseURL, 8)
	if len(specs) == 0 {
		return
	}
	var usedRows []model.Target
	core.Db.Select("source").Where("task_id = ? AND source LIKE ?", r.TaskID, "site_f%").Find(&usedRows)
	used := make(map[string]bool, len(usedRows))
	for _, row := range usedRows {
		used[row.Source] = true
	}
	now := time.Now()
	spawned := 0
	for _, spec := range specs {
		source := nextSiteFollowupSource(used)
		if source == "" {
			break
		}
		record := model.Target{
			ID:             utils.UUID(),
			TaskID:         r.TaskID,
			URL:            target.URL,
			Host:           target.Host,
			Source:         source,
			PriorityScore:  float64(asInt(spec["priority"])),
			PriorityReason: strOf(spec["reason"]),
			AuthContext:    target.AuthContext,
			LeakedCreds:    target.LeakedCreds,
			Status:         constant.TargetQueued,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		// 并发派生撞同一 site_f 编号时唯一索引拦下，跳过即可。
		if err := core.Db.Create(&record).Error; err != nil {
			continue
		}
		spawned++
	}
	if spawned > 0 {
		EmitInfo(r.TaskID, "orchestrator", "site_followups_spawned",
			fmt.Sprintf("单站协作追打：从覆盖上报派生 %d 条定向追打路线", spawned),
			map[string]any{"target_id": target.ID, "spawned": spawned})
	}
}

// nextSiteFollowupSource 取下一个未用的 site_fXX 编号。
func nextSiteFollowupSource(used map[string]bool) string {
	for idx := 1; idx < 100; idx++ {
		source := fmt.Sprintf("site_f%02d", idx)
		if !used[source] {
			used[source] = true
			return source
		}
	}
	return ""
}

// persistWorkerResult 按 Worker 产出更新目标状态与漏洞落库。
func (r *TaskRunner) persistWorkerResult(task *model.Task, target *model.Target, result *WorkerResult) {
	if result == nil {
		result = &WorkerResult{Verdict: "error", Errors: []string{"worker 无返回"}}
	}
	saved := 0
	for _, item := range result.Submitted {
		finding, err := PersistFinding(r.TaskID, target, item, result.ModelName, result.BaseURL, target.AssignedWorker)
		if err != nil {
			global.Log.Warnf("TaskRunner[%s] 保存漏洞失败: %v", r.TaskID, err)
			continue
		}
		saved++
		EmitInfo(r.TaskID, "worker", "finding_submitted",
			fmt.Sprintf("提交漏洞：%s", finding.Title),
			map[string]any{
				"target_id":  target.ID,
				"finding_id": finding.ID,
				"vuln_type":  finding.VulnType,
				"severity":   finding.SeverityClaimed,
				"target_url": finding.TargetURL,
				"title":      finding.Title,
			})
	}

	updates := map[string]any{
		"assigned_worker": "",
		"heartbeat_at":    nil,
		"last_error":      strings.Join(result.Errors, "; "),
	}
	switch {
	case result.Verdict == "found" || saved > 0:
		updates["status"] = constant.TargetDone
		updates["verdict"] = "found"
	case result.Verdict == "error":
		if target.RetryCount < RetryMaxPerTarget && isTransientWorkerError(strings.Join(result.Errors, "; ")) {
			updates["status"] = constant.TargetQueued
			updates["retry_count"] = target.RetryCount + 1
		} else {
			updates["status"] = constant.TargetDead
			updates["verdict"] = "error"
			updates["dead_reason"] = firstLine(strings.Join(result.Errors, "; "))
		}
	default: // no_vuln
		if target.RetryCount < NoVulnRetryCap && shouldRetryNoVuln(target) {
			updates["status"] = constant.TargetQueued
			updates["retry_count"] = target.RetryCount + 1
		} else {
			updates["status"] = constant.TargetDone
			updates["verdict"] = "no_vuln"
		}
	}
	core.Db.Model(&model.Target{}).Where("id = ?", target.ID).Updates(updates)

	// 单站协作：覆盖上报事件已在工具调用时落库，此处据其派生定向追打目标。
	if len(result.ReportedCoverage) > 0 {
		r.spawnSiteFollowups(target, result.ReportedCoverage)
	}

	// 全局情报库：worker 上报沉淀 + 出洞自动提炼（对齐原版 _distill_intel）。
	DistillWorkerIntel(task, target, saved, result)

	switch updates["status"] {
	case constant.TargetDone:
		EmitInfo(r.TaskID, "worker", "worker_finish",
			fmt.Sprintf("目标完成：%s", displayTarget(target)),
			map[string]any{"target_id": target.ID, "verdict": updates["verdict"], "findings": saved})
	case constant.TargetDead:
		EmitWarn(r.TaskID, "worker", "worker_finish",
			fmt.Sprintf("目标失败：%s（%s）", displayTarget(target), updates["dead_reason"]),
			map[string]any{"target_id": target.ID})
	default:
		EmitInfo(r.TaskID, "worker", "target_requeued",
			fmt.Sprintf("目标回队重试：%s", displayTarget(target)),
			map[string]any{"target_id": target.ID})
	}
}

// reapWorkers 回收已结束的 worker（goroutine 自身已清理，此处仅做记录）。
func (r *TaskRunner) reapWorkers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, h := range r.workers {
		if h.session != nil && h.session.finished {
			h.cancel()
			delete(r.workers, id)
		}
	}
}

// reclaimStale 回收心跳超时的幽灵目标。
func (r *TaskRunner) reclaimStale() {
	deadline := time.Now().Add(-StaleHeartbeatSeconds * time.Second)
	var stale []model.Target
	core.Db.Where("task_id = ? AND status IN ? AND (heartbeat_at IS NULL OR heartbeat_at < ?)",
		r.TaskID, []string{constant.TargetAssigned, constant.TargetScanning}, deadline).
		Find(&stale)
	for _, t := range stale {
		r.mu.Lock()
		_, running := r.workers[t.ID]
		r.mu.Unlock()
		if running {
			continue
		}
		core.Db.Model(&model.Target{}).Where("id = ?", t.ID).
			Updates(map[string]any{
				"status":          constant.TargetQueued,
				"assigned_worker": "",
				"heartbeat_at":    nil,
			})
		EmitWarn(r.TaskID, "orchestrator", "reclaim",
			fmt.Sprintf("回收幽灵目标：%s", displayTarget(&t)),
			map[string]any{"target_id": t.ID})
	}
}

// heartbeatLoop 周期性刷新目标心跳。
func (r *TaskRunner) heartbeatLoop(targetID string, done <-chan struct{}) {
	ticker := time.NewTicker(HeartbeatIntervalSecond * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			core.Db.Model(&model.Target{}).Where("id = ?", targetID).
				Update("heartbeat_at", time.Now())
		}
	}
}

// dispatchReviews 把待审核漏洞派发给 Reviewer Agent。
func (r *TaskRunner) dispatchReviews(task *model.Task) {
	var pending []model.Finding
	core.Db.Where("task_id = ? AND status = ?", r.TaskID, constant.FindingPendingReview).
		Order("created_at ASC").Limit(ReviewBatchPerTick).Find(&pending)
	for i := range pending {
		finding := pending[i]
		r.mu.Lock()
		if _, exists := r.reviews[finding.ID]; exists {
			r.mu.Unlock()
			continue
		}
		_, cancel := context.WithCancel(r.ctx)
		r.reviews[finding.ID] = cancel
		r.mu.Unlock()

		go func(f model.Finding) {
			defer cancel()
			defer func() {
				r.mu.Lock()
				delete(r.reviews, f.ID)
				r.mu.Unlock()
			}()
			r.runReview(&f)
		}(finding)
	}
}

// runReview 执行一次漏洞审核。
func (r *TaskRunner) runReview(finding *model.Finding) {
	var task model.Task
	if err := core.Db.First(&task, "id = ?", r.TaskID).Error; err != nil {
		return
	}
	EmitInfo(r.TaskID, "reviewer", "review_start", "开始审核漏洞："+finding.Title,
		map[string]any{"finding_id": finding.ID})

	brief := findingBriefOf(finding)
	existing := existingFingerprints(r.TaskID, finding)
	review, err := ReviewFinding(context.Background(), r.workerPool, brief, existing)
	if err != nil {
		EmitError(r.TaskID, "reviewer", "review_error", "审核异常："+err.Error(),
			map[string]any{"finding_id": finding.ID})
		// 审核失败降级放行，交由用户复审。
		review = &model.Review{
			ID:            utils.UUID(),
			FindingID:     finding.ID,
			TaskID:        r.TaskID,
			Verdict:       constant.VerdictAccepted,
			Confidence:    "uncertain",
			InScope:       true,
			ReviewerNotes: "自动审核失败，已降级放行待人工确认：" + err.Error(),
			UserStatus:    constant.UserPending,
		}
	}
	// 挽救链（对齐原版 _maybe_deepen_ignored）：少数「入口真实、下一步明确」的
	// ignored 半成品改判 deepen 定向补链；反射 XSS/需管理员登录/图形验证码等仍保持 ignored。
	if maybeDeepenIgnored(brief, review, task.SrcType) {
		EmitInfo(r.TaskID, "reviewer", "review_rescued_deepen",
			"系统改判：ignored→deepen（入口真实、下一步明确）："+finding.Title,
			map[string]any{"finding_id": finding.ID})
	}
	if err := SaveReview(review); err != nil {
		global.Log.Warnf("保存审核结果失败: %v", err)
		return
	}
	findingStatus := constant.FindingReviewed
	core.Db.Model(&model.Finding{}).Where("id = ?", finding.ID).
		Update("status", findingStatus)

	switch review.Verdict {
	case constant.VerdictDeepen:
		if ok, reason := applyDeepenForFinding(finding, review.DeepenDirective, "ai", task.DeepenCap); ok {
			EmitInfo(r.TaskID, "reviewer", "auto_deepen", "AI 判定需深化："+finding.Title,
				map[string]any{"finding_id": finding.ID})
		} else {
			EmitInfo(r.TaskID, "reviewer", "review_deferred", "深化未执行："+reason,
				map[string]any{"finding_id": finding.ID})
		}
	case constant.VerdictIgnored:
		EmitInfo(r.TaskID, "reviewer", "review_done", "审核判定忽略："+finding.Title,
			map[string]any{"finding_id": finding.ID, "verdict": review.Verdict})
	default:
		EmitInfo(r.TaskID, "reviewer", "review_done", "审核通过："+finding.Title,
			map[string]any{"finding_id": finding.ID, "verdict": review.Verdict})
		if task.AutoKillsweep {
			r.TriggerKillsweep(finding.ID)
		}
	}
}

// TriggerKillsweep 触发通杀分析（幂等：同漏洞已有任务则忽略）。
func (r *TaskRunner) TriggerKillsweep(findingID string) bool {
	r.mu.Lock()
	if _, exists := r.killsweeps[findingID]; exists {
		r.mu.Unlock()
		return false
	}
	_, cancel := context.WithCancel(r.ctx)
	r.killsweeps[findingID] = cancel
	r.mu.Unlock()

	go func() {
		defer cancel()
		defer func() {
			r.mu.Lock()
			delete(r.killsweeps, findingID)
			r.mu.Unlock()
		}()
		r.runKillsweep(findingID)
	}()
	return true
}

func (r *TaskRunner) runKillsweep(findingID string) {
	var finding model.Finding
	if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
		return
	}
	EmitInfo(r.TaskID, "killsweep", "killsweep_start", "开始通杀分析："+finding.Title,
		map[string]any{"finding_id": findingID})
	record, err := RunKillsweep(context.Background(), r.workerPool, r.TaskID, findingID, findingBriefOf(&finding))
	if err != nil {
		EmitError(r.TaskID, "killsweep", "killsweep_error", "通杀分析异常："+err.Error(),
			map[string]any{"finding_id": findingID})
		return
	}
	if err := SaveKillsweep(record); err != nil {
		global.Log.Warnf("保存通杀记录失败: %v", err)
		return
	}
	if record.IsKillsweep {
		EmitInfo(r.TaskID, "killsweep", "killsweep_done",
			fmt.Sprintf("判定为通杀：%s（影响 %d 个资产）", record.ProductName, record.AssetCount),
			map[string]any{"finding_id": findingID, "killsweep_id": record.ID})
	} else {
		EmitInfo(r.TaskID, "killsweep", "killsweep_done", "非通杀漏洞",
			map[string]any{"finding_id": findingID, "killsweep_id": record.ID})
	}
}

// TriggerEscalation 触发「扩大危害」分析。
func (r *TaskRunner) TriggerEscalation(findingID, origSeverity string) bool {
	r.mu.Lock()
	if _, exists := r.escalations[findingID]; exists {
		r.mu.Unlock()
		return false
	}
	_, cancel := context.WithCancel(r.ctx)
	r.escalations[findingID] = cancel
	r.mu.Unlock()

	go func() {
		defer cancel()
		defer func() {
			r.mu.Lock()
			delete(r.escalations, findingID)
			r.mu.Unlock()
		}()
		RunEscalation(r.ctx, r.workerPool, r.TaskID, findingID, origSeverity)
	}()
	return true
}

// Pause 暂停任务：取消全部在途工作并把未完成目标回退为排队。
func (r *TaskRunner) Pause(reason string) {
	if reason == "" {
		reason = "任务暂停"
	}
	r.cancelChildren(reason)
	core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status IN ?", r.TaskID, []string{constant.TargetAssigned, constant.TargetScanning}).
		Updates(map[string]any{"status": constant.TargetQueued, "assigned_worker": "", "heartbeat_at": nil})
	core.Db.Model(&model.Task{}).Where("id = ?", r.TaskID).Update("status", constant.TaskPaused)
	EmitWarn(r.TaskID, "orchestrator", "workers_cancelled", reason, nil)
}

// StopTask 停止任务并结束主循环。
func (r *TaskRunner) StopTask(reason string) {
	if reason == "" {
		reason = "任务停止"
	}
	r.cancelChildren(reason)
	core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status IN ?", r.TaskID, []string{constant.TargetAssigned, constant.TargetScanning}).
		Updates(map[string]any{"status": constant.TargetQueued, "assigned_worker": "", "heartbeat_at": nil})
	core.Db.Model(&model.Task{}).Where("id = ?", r.TaskID).Update("status", constant.TaskStopped)
	r.Stop()
}

// cancelChildren 取消全部派生协程。
func (r *TaskRunner) cancelChildren(reason string) {
	r.mu.Lock()
	workers := make([]*workerHandle, 0, len(r.workers))
	for _, h := range r.workers {
		workers = append(workers, h)
	}
	reviews := make([]context.CancelFunc, 0, len(r.reviews))
	for _, c := range r.reviews {
		reviews = append(reviews, c)
	}
	killsweeps := make([]context.CancelFunc, 0, len(r.killsweeps))
	for _, c := range r.killsweeps {
		killsweeps = append(killsweeps, c)
	}
	escalations := make([]context.CancelFunc, 0, len(r.escalations))
	for _, c := range r.escalations {
		escalations = append(escalations, c)
	}
	r.workers = map[string]*workerHandle{}
	r.reviews = map[string]context.CancelFunc{}
	r.killsweeps = map[string]context.CancelFunc{}
	r.escalations = map[string]context.CancelFunc{}
	r.mu.Unlock()

	for _, h := range workers {
		h.cancel()
	}
	for _, c := range reviews {
		c()
	}
	for _, c := range killsweeps {
		c()
	}
	for _, c := range escalations {
		c()
	}
	EmitWarn(r.TaskID, "orchestrator", "workers_cancelled",
		fmt.Sprintf("%s：已取消 %d 个在途 worker", reason, len(workers)), nil)
}

// SkipTarget 手动跳过目标。
func (r *TaskRunner) SkipTarget(targetID, reason string) map[string]any {
	if reason == "" {
		reason = "用户手动删除该目标"
	}
	var target model.Target
	if err := core.Db.First(&target, "id = ? AND task_id = ?", targetID, r.TaskID).Error; err != nil {
		return map[string]any{"ok": false, "reason": "目标不存在"}
	}
	r.mu.Lock()
	h, running := r.workers[targetID]
	r.mu.Unlock()
	if running {
		h.cancel()
	}
	core.Db.Model(&model.Target{}).Where("id = ?", targetID).
		Updates(map[string]any{
			"status":          constant.TargetSkipped,
			"dead_reason":     reason,
			"assigned_worker": "",
			"heartbeat_at":    nil,
		})
	EmitInfo(r.TaskID, "orchestrator", "skip",
		fmt.Sprintf("跳过目标：%s（%s）", displayTarget(&target), reason),
		map[string]any{"target_id": targetID})
	return map[string]any{"ok": true}
}

// Snapshot 返回运行器诊断快照。
func (r *TaskRunner) Snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"task_id":     r.TaskID,
		"workers":     len(r.workers),
		"reviews":     len(r.reviews),
		"killsweeps":  len(r.killsweeps),
		"escalations": len(r.escalations),
	}
}

// ===== 包级辅助 =====

// ApplyDeepenByIDs 按 ID 加载目标与漏洞，执行深挖并持久化（供 API 层直接调用）。
func ApplyDeepenByIDs(targetID, findingID, directive, source string, cap int) (bool, string) {
	var finding model.Finding
	if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
		return false, "漏洞不存在"
	}
	if targetID != "" && finding.TargetID != targetID {
		return false, "漏洞不属于该目标"
	}
	return applyDeepenForFinding(&finding, directive, source, cap)
}

// applyDeepenForFinding 在已加载实体上执行深挖并落库。
func applyDeepenForFinding(finding *model.Finding, directive, source string, cap int) (bool, string) {
	var target model.Target
	if err := core.Db.First(&target, "id = ?", finding.TargetID).Error; err != nil {
		return false, "目标不存在"
	}
	ok, reason := ApplyDeepen(&target, finding, directive, source, cap)
	if !ok {
		return false, reason
	}
	if err := core.Db.Save(&target).Error; err != nil {
		return false, "目标回队失败：" + err.Error()
	}
	core.Db.Model(&model.Finding{}).Where("id = ?", finding.ID).
		Updates(map[string]any{"status": finding.Status, "dedup_key": finding.DedupKey})

	// 深挖回队后必须确保有 runner 在消费队列。
	// 任务跑完会进入 idle，服务重启后 idle 任务也不会被 RestoreOnStartup 恢复
	// （只恢复 running）——这两种情况下 runner 都已消失，回队目标会永远停在
	// queued 无人派发，用户表现为「点深挖没反应」（实测踩过：深挖 200 后静默
	// 2.5 分钟，直到手动点启动才恢复）。任务已暂停/停止时不复活。
	ensureRunnerForQueued(finding.TaskID)
	return true, ""
}

// ensureRunnerForQueued 任务未暂停/停止时确保 runner 在跑（幂等）。
func ensureRunnerForQueued(taskID string) {
	if taskID == "" || core.Db == nil {
		return
	}
	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		return
	}
	if task.Status == constant.TaskPaused || task.Status == constant.TaskStopped {
		return
	}
	ManagerInstance().EnsureRunning(taskID)
}

// workDirForTask 返回任务工作目录。
func workDirForTask(taskID string) string {
	return filepath.Join(config.WorkRootDir(), taskID)
}

// buildIntelHint 从情报库为该目标组装提示（触发式检索：root 域 / 系统指纹 / 同 host
// 命中才给，不主动全量注入；每类限 4 条、总量限 1800 字符，防 prompt 膨胀）。
func buildIntelHint(target *model.Target) string {
	if core.Db == nil || target == nil {
		return ""
	}
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return ""
	}
	keys := []string{host}
	if root := utils.RootDomain(host); root != "" && root != host {
		keys = append(keys, root)
	}
	keys = append(keys, DetectFingerprints(host, target.Title, target.Org)...)
	var items []model.Intel
	core.Db.Where("match_key IN ? OR source_host = ?", keys, host).
		Order("hit_count DESC").Limit(24).Find(&items)
	if len(items) == 0 {
		return ""
	}
	perKind := map[string]int{}
	totalChars := 0
	lines := make([]string, 0, 8)
	for _, it := range items {
		if it.Summary == "" || perKind[it.Kind] >= 4 {
			continue
		}
		line := "- [" + it.Kind + "] " + it.Summary
		if totalChars+len(line) > 1800 {
			break
		}
		perKind[it.Kind]++
		totalChars += len(line)
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// existingFingerprints 收集同任务已存在漏洞指纹，供 Reviewer 判重。
func existingFingerprints(taskID string, exclude *model.Finding) []string {
	var items []model.Finding
	core.Db.Where("task_id = ? AND id <> ?", taskID, exclude.ID).
		Order("created_at DESC").Limit(50).Find(&items)
	out := make([]string, 0, len(items))
	for _, f := range items {
		out = append(out, f.VulnType+" | "+f.Title+" | "+f.TargetURL)
	}
	return out
}

// findingBriefOf 把 Finding 实体转为提示词视图。
func findingBriefOf(f *model.Finding) *FindingBrief {
	return &FindingBrief{
		ID:              f.ID,
		TaskID:          f.TaskID,
		TargetID:        f.TargetID,
		VulnType:        f.VulnType,
		Title:           f.Title,
		SeverityClaimed: f.SeverityClaimed,
		TargetURL:       f.TargetURL,
		Owner:           f.Owner,
		Description:     f.Description,
		Steps:           f.Steps,
		Poc:             f.Poc,
		RawRequest:      f.RawRequest,
		RawResponse:     f.RawResponse,
		AffectedScope:   f.AffectedScope,
		Evidence:        f.Evidence,
		KillChain:       f.KillChain,
		SelfCheck:       f.SelfCheck,
	}
}

// displayTarget 目标可读展示。
func displayTarget(t *model.Target) string {
	if t == nil {
		return ""
	}
	if t.Host != "" {
		return t.Host
	}
	return t.URL
}

// shouldRetryNoVuln 判断无洞目标是否值得重试（有深化上下文 / 有高危指纹）。
func shouldRetryNoVuln(t *model.Target) bool {
	if t.DeepenCount > 0 || len(t.DeepenContext) > 0 {
		return true
	}
	return t.PriorityScore >= 60
}

// isTransientWorkerError 判定是否为可重试的瞬时错误。
func isTransientWorkerError(message string) bool {
	lower := strings.ToLower(message)
	for _, key := range []string{"timeout", "temporarily", "connection reset", "eof", "429", "502", "503", "504", "rate limit", "超时", "连接"} {
		if strings.Contains(lower, key) {
			return true
		}
	}
	return false
}

// ===== 管理器 =====

// Manager 全局任务运行器管理。
type Manager struct {
	mu      sync.Mutex
	runners map[string]*TaskRunner
}

var managerInstance = &Manager{runners: map[string]*TaskRunner{}}

// ManagerInstance 返回全局管理器。
func ManagerInstance() *Manager { return managerInstance }

// GetRunner 取任务运行器。
func (m *Manager) GetRunner(taskID string) *TaskRunner {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runners[taskID]
}

// EnsureRunning 确保任务运行器在跑（幂等）。
// runner 已存在且任务处于 paused/stopped 时，视为用户点「启动」要求恢复：
// 把状态复位为 running，存活的主循环下一轮 tick 自然恢复调度——
// （修复：暂停后点启动，此前在此早退且不改状态，tick 见 paused 永远跳过，
// 任务表现为「启动了但没进行」）。
func (m *Manager) EnsureRunning(taskID string) {
	m.mu.Lock()
	runner, exists := m.runners[taskID]
	if exists {
		// 僵尸条目：主循环已退出但还没来得及注销 → 清掉走重建路径。
		select {
		case <-runner.done:
			delete(m.runners, taskID)
			exists = false
		default:
		}
	}
	if exists {
		m.mu.Unlock()
		// idle 也一并复位：目标可能全部处理完+测绘取尽后停在空闲，点「启动」
		// 应让主循环立刻再跑一轮（测绘有新页就继续；真没活干 tick 会自动
		// 收敛回 idle），而不是按钮点了毫无反应。
		core.Db.Model(&model.Task{}).
			Where("id = ? AND status IN ?", taskID, []string{constant.TaskPaused, constant.TaskStopped, constant.TaskIdle}).
			Update("status", constant.TaskRunning)
		return
	}
	runner = NewTaskRunner(taskID)
	m.runners[taskID] = runner
	m.mu.Unlock()

	core.Db.Model(&model.Task{}).Where("id = ?", taskID).Update("status", constant.TaskRunning)
	go func() {
		runner.Run()
		m.mu.Lock()
		// 指针比对：防止旧 runner 退出时误删同 taskID 的新 runner
		// （停止后快速点启动的竞态窗口）。
		if m.runners[taskID] == runner {
			delete(m.runners, taskID)
		}
		m.mu.Unlock()
	}()
}

// PauseTask 暂停任务。
func (m *Manager) PauseTask(taskID, reason string) {
	if runner := m.GetRunner(taskID); runner != nil {
		runner.Pause(reason)
		return
	}
	core.Db.Model(&model.Task{}).Where("id = ?", taskID).Update("status", constant.TaskPaused)
	core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status IN ?", taskID, []string{constant.TargetAssigned, constant.TargetScanning}).
		Updates(map[string]any{"status": constant.TargetQueued, "assigned_worker": "", "heartbeat_at": nil})
}

// StopTask 停止任务。
func (m *Manager) StopTask(taskID, reason string) {
	if runner := m.GetRunner(taskID); runner != nil {
		// 先注销再停：缩小「停止后立刻点启动撞到旧 runner 早退」的竞态窗口。
		m.mu.Lock()
		if m.runners[taskID] == runner {
			delete(m.runners, taskID)
		}
		m.mu.Unlock()
		runner.StopTask(reason)
		return
	}
	core.Db.Model(&model.Task{}).Where("id = ?", taskID).Update("status", constant.TaskStopped)
}

// Remove 从管理器移除任务运行器（任务删除时调用）。
func (m *Manager) Remove(taskID string) {
	m.mu.Lock()
	runner, exists := m.runners[taskID]
	delete(m.runners, taskID)
	m.mu.Unlock()
	if exists {
		runner.StopTask("任务已删除")
	}
}

// SkipTarget 跨任务跳过目标。
func (m *Manager) SkipTarget(taskID, targetID, reason string) map[string]any {
	runner := m.GetRunner(taskID)
	if runner == nil {
		core.Db.Model(&model.Target{}).Where("id = ? AND task_id = ?", targetID, taskID).
			Updates(map[string]any{"status": constant.TargetSkipped, "dead_reason": reason})
		return map[string]any{"ok": true}
	}
	return runner.SkipTarget(targetID, reason)
}

// InjectDirective 跨任务注入指令。
func (m *Manager) InjectDirective(taskID, targetID, directive string) map[string]any {
	runner := m.GetRunner(taskID)
	if runner == nil {
		return map[string]any{"ok": false, "reason": "任务未在运行"}
	}
	return runner.InjectDirective(targetID, directive)
}

// CancelEscalation 跨任务取消扩大危害。
func (m *Manager) CancelEscalation(taskID, findingID, reason string) map[string]any {
	runner := m.GetRunner(taskID)
	if runner == nil {
		return map[string]any{"ok": false, "reason": "任务未在运行"}
	}
	return runner.CancelEscalation(findingID, reason)
}

// TriggerKillsweep 跨任务触发通杀。
func (m *Manager) TriggerKillsweep(taskID, findingID string) bool {
	runner := m.GetRunner(taskID)
	if runner == nil {
		// 任务未在运行：直接后台跑一次。
		go func() {
			var finding model.Finding
			if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
				return
			}
			pool := BuildGlobalPool()
			record, err := RunKillsweep(context.Background(), pool, taskID, findingID, findingBriefOf(&finding))
			if err == nil {
				_ = SaveKillsweep(record)
			}
		}()
		return true
	}
	return runner.TriggerKillsweep(findingID)
}

// DiagnosticSnapshot 全部任务运行器诊断。
func (m *Manager) DiagnosticSnapshot() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.runners))
	for id := range m.runners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, m.runners[id].Snapshot())
	}
	return out
}

// Shutdown 停止全部任务。
func (m *Manager) Shutdown() {
	m.mu.Lock()
	runners := make([]*TaskRunner, 0, len(m.runners))
	for _, r := range m.runners {
		runners = append(runners, r)
	}
	m.runners = map[string]*TaskRunner{}
	m.mu.Unlock()
	for _, r := range runners {
		r.Stop()
	}
}

// RestoreOnStartup 启动时恢复 running 状态的任务。
func (m *Manager) RestoreOnStartup() {
	if core.Db == nil {
		return
	}
	var tasks []model.Task
	core.Db.Where("status = ?", constant.TaskRunning).Find(&tasks)
	for _, t := range tasks {
		EmitInfo(t.ID, "orchestrator", "recover", "服务重启，自动恢复运行中的任务", nil)
		m.EnsureRunning(t.ID)
	}
}
