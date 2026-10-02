package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/result"
	"AiSRC/service"
	"AiSRC/service/engine"

	"github.com/gin-gonic/gin"
)

// ListFindings 全部原始漏洞。
// GET /api/tasks/:task_id/findings
func ListFindings(c *gin.Context) {
	listFindingsBy(c, service.FindingFilter{
		Status: queryString(c, "status"),
	})
}

// ListResults 最终结果列表（仅 accepted）。
// GET /api/tasks/:task_id/results
func ListResults(c *gin.Context) {
	listFindingsBy(c, service.FindingFilter{
		Verdicts:   []string{constant.VerdictAccepted},
		Confidence: queryString(c, "confidence"),
		OrderBy:    "score",
	})
}

// ListDeepen 打回深挖列表。
// GET /api/tasks/:task_id/deepen-list
func ListDeepen(c *gin.Context) {
	listFindingsBy(c, service.FindingFilter{
		Verdicts: []string{constant.VerdictDeepen},
		OrderBy:  "score",
	})
}

// ListReviewQueue 用户复审队列（AI accepted 且用户待处理）。
// GET /api/tasks/:task_id/review-queue
func ListReviewQueue(c *gin.Context) {
	listFindingsBy(c, service.FindingFilter{
		Verdicts:   []string{constant.VerdictAccepted},
		UserStatus: constant.UserPending,
		OrderBy:    "score",
	})
}

// ListSubmitList 待提交列表（用户复审通过）。
// GET /api/tasks/:task_id/submit-list
func ListSubmitList(c *gin.Context) {
	filter := service.FindingFilter{UserStatus: constant.UserPassed, OrderBy: "submit"}
	if c.Query("submitted") != "" {
		value := queryBool(c, "submitted", false)
		filter.Submitted = &value
	}
	listFindingsBy(c, filter)
}

// ListRejected 已驳回列表。
// GET /api/tasks/:task_id/rejected
func ListRejected(c *gin.Context) {
	listFindingsBy(c, service.FindingFilter{UserStatus: constant.UserRejected, OrderBy: "score"})
}

// ListArchived AI 未采纳归档。
// GET /api/tasks/:task_id/archived
func ListArchived(c *gin.Context) {
	listFindingsBy(c, service.FindingFilter{
		Verdicts:   []string{constant.VerdictIgnored, constant.VerdictDeepen},
		UserStatus: constant.UserPending,
		// 对齐原版：正在回炉重挖的 deepen 前身不显示（避免和新一轮重复），
		// 也让 stats.archived 徽标口径与列表条数完全一致。
		ExcludeSuperseded: true,
		OrderBy:           "archived",
	})
}

// listFindingsBy 漏洞列表通用处理。
func listFindingsBy(c *gin.Context, filter service.FindingFilter) {
	filter.TaskID = pathParam(c, "task_id")
	filter.Query = queryString(c, "q")
	filter.Compact = queryBool(c, "compact", false)
	filter.Limit = queryInt(c, "limit", 0)
	filter.Offset = queryInt(c, "offset", 0)

	items, total, err := service.QueryFindings(filter)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, filter.Limit, filter.Offset)
}

// GetFinding 漏洞详情。
// GET /api/findings/:finding_id
func GetFinding(c *gin.Context) {
	findingID := pathParam(c, "finding_id")
	view, err := service.GetFindingView(findingID)
	if err != nil {
		result.Failed(c, result.NotFound, result.SubFindingNotFound)
		return
	}
	result.Success(c, view)
}

// UpdateResult 更新结果（用户复审裁决 / 报告字段）。
// PATCH /api/results/:finding_id
func UpdateResult(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	findingID := pathParam(c, "finding_id")
	var dto UpdateResultRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	patch := map[string]any{}
	if dto.UserStatus != nil {
		patch["user_status"] = *dto.UserStatus
	}
	if dto.UserSeverity != nil {
		patch["user_severity"] = *dto.UserSeverity
	}
	if dto.UserNotes != nil {
		patch["user_notes"] = *dto.UserNotes
	}
	if dto.UserEdits != nil {
		patch["user_edits"] = dto.UserEdits
	}
	if dto.Submitted != nil {
		patch["submitted"] = *dto.Submitted
	}
	if len(patch) == 0 && dto.IsTop == nil {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	if len(patch) > 0 {
		if _, err := service.UpdateResult(findingID, patch); err != nil {
			result.Failed(c, result.InternalError, result.SubWriteError)
			return
		}
	}
	if dto.IsTop != nil {
		if err := service.ToggleResultTop(findingID, *dto.IsTop); err != nil {
			result.Failed(c, result.InternalError, result.SubWriteError)
			return
		}
	}
	view, err := service.GetFindingView(findingID)
	if err != nil {
		result.Failed(c, result.NotFound, result.SubFindingNotFound)
		return
	}
	result.Success(c, view)
}

// RestoreResult 把 AI 未采纳归档漏洞救回复审队列。
// POST /api/results/:finding_id/restore
func RestoreResult(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	findingID := pathParam(c, "finding_id")
	if err := service.RestoreArchived(findingID); err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, gin.H{"ok": true, "id": findingID})
}

// DeepenResult 用户手动打回深挖。
// POST /api/results/:finding_id/deepen
func DeepenResult(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	findingID := pathParam(c, "finding_id")
	var dto DeepenRequest
	if err := c.ShouldBindJSON(&dto); err != nil || strings.TrimSpace(dto.Directive) == "" {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	ok, reason := service.DeepenFinding(findingID, dto.Directive)
	if !ok {
		result.FailedWithMsg(c, result.BadRequest, reason)
		return
	}
	result.Success(c, gin.H{"ok": true, "id": findingID})
}

// ListKillsweeps 通杀列表。
// GET /api/tasks/:task_id/killsweeps
func ListKillsweeps(c *gin.Context) {
	filter := service.KillsweepFilter{
		TaskID:         pathParam(c, "task_id"),
		OnlyHits:       queryBool(c, "only_hits", false),
		IncludeInvalid: queryBool(c, "include_invalid", false),
		Limit:          queryInt(c, "limit", 0),
		Offset:         queryInt(c, "offset", 0),
	}
	items, total, err := service.ListKillsweeps(filter)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, filter.Limit, filter.Offset)
}

// InvalidateKillsweep 标记通杀结论无效。
// POST /api/tasks/:task_id/killsweeps/:killsweep_id/invalidate
func InvalidateKillsweep(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	killsweepID := pathParam(c, "killsweep_id")
	reason := ""
	if body, err := c.GetRawData(); err == nil && len(body) > 0 {
		reason = strings.TrimSpace(string(body))
		reason = strings.Trim(strings.TrimPrefix(reason, "{"), "}")
	}
	if err := service.InvalidateKillsweep(taskID, killsweepID, reason); err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, gin.H{"ok": true, "id": killsweepID})
}

// RetryKillsweep 重跑通杀分析。
// POST /api/tasks/:task_id/killsweeps/:killsweep_id/retry
func RetryKillsweep(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	taskID := pathParam(c, "task_id")
	killsweepID := pathParam(c, "killsweep_id")
	if err := service.RetryKillsweep(taskID, killsweepID); err != nil {
		result.FailedWithMsg(c, result.BadRequest, err.Error())
		return
	}
	result.Success(c, gin.H{"ok": true, "id": killsweepID})
}

// FindingAssistant 报告助手（一次问答）。
// POST /api/findings/:finding_id/assistant
func FindingAssistant(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	findingID := pathParam(c, "finding_id")
	var dto AssistantRequest
	if err := c.ShouldBindJSON(&dto); err != nil {
		result.Failed(c, result.BadRequest, result.SubInvalidFormat)
		return
	}
	// 与原版一致：空提问 400、漏洞不存在 404，而不是统一 500。
	if strings.TrimSpace(dto.Message) == "" {
		result.FailedWithMsg(c, result.BadRequest, "请输入问题或操作指令")
		return
	}
	if _, err := service.GetFindingView(findingID); err != nil {
		result.FailedWithMsg(c, result.NotFound, "漏洞不存在")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	reply := service.RunReportAssistant(ctx, findingID, dto.Message)
	if reply.ErrorMsg != "" {
		result.FailedWithMsg(c, result.InternalError, reply.ErrorMsg)
		return
	}
	result.Success(c, reply)
}

// sseJSON 按原版 AutoHunter 的 _sse 语义写一行事件：`data: {json}\n\n`。
// 前端 streamSSE 只解析 data 行并 JSON.parse，纯文本事件会被静默丢弃（回复空白的根因）。
func sseJSON(c *gin.Context, ev map[string]any) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(c.Writer, "data: %s\n\n", b)
	c.Writer.Flush()
}

// FindingAssistantStream 报告助手（SSE 流）。
// POST /api/findings/:finding_id/assistant/stream
// 事件协议对齐原版 findings.py::_sse：thinking / assistant_partial / tool_call / tool_result /
// suggested_edits / final{text,suggested_edits} / done{answer,suggested_edits}。
func FindingAssistantStream(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	findingID := pathParam(c, "finding_id")
	var dto AssistStreamRequest
	_ = c.ShouldBindJSON(&dto)

	// 在写出 SSE 头之前完成校验，保证错误仍是标准的 {"detail": ...} + 真实状态码
	// （与原版 AutoHunter 一致：空提问 400、漏洞不存在 404）。
	if strings.TrimSpace(dto.Message) == "" {
		result.FailedWithMsg(c, result.BadRequest, "请输入问题或操作指令")
		return
	}
	if _, err := service.GetFindingView(findingID); err != nil {
		result.FailedWithMsg(c, result.NotFound, "漏洞不存在")
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	sseJSON(c, map[string]any{"type": "thinking", "text": "正在分析漏洞报告…"})

	// 挂在请求上下文上：客户端断开（前端「停止生成」）时取消循环，对齐原版 cancel_event。
	// 上限放宽到 10 分钟：工具循环（至多 10 轮 × LLM + 受控验证）可能远超 2 分钟。
	ctx, cancel := context.WithTimeout(c.Request.Context(), 600*time.Second)
	defer cancel()
	reply := service.RunReportAssistantLoop(ctx, findingID, dto.Message, func(ev map[string]any) {
		sseJSON(c, ev)
	})

	var edits any
	if len(reply.Edits) > 0 {
		edits = reply.Edits
	}
	if reply.ErrorMsg != "" {
		// 原版语义：错误收敛为 final 文案下发，不伪装成「已完成」（findings.py 947-950）。
		sseJSON(c, map[string]any{"type": "final", "text": reply.ErrorMsg})
		sseJSON(c, map[string]any{"type": "done", "answer": reply.ErrorMsg})
		return
	}
	// final 事件已由循环内部发出（含 suggested_edits），此处只补 done 收口帧。
	sseJSON(c, map[string]any{"type": "done", "answer": reply.Reply, "suggested_edits": edits, "tool_logs": reply.ToolLogs})
}

// ===== 跨任务漏洞（vulns 页）=====

// VulnStatsHandler 全局漏洞统计。
// GET /api/vulns/stats
func VulnStatsHandler(c *gin.Context) {
	result.Success(c, service.VulnStats())
}

// ListVulns 全局漏洞列表。
// GET /api/vulns
func ListVulns(c *gin.Context) {
	filter := service.FindingFilter{
		TaskID:     queryString(c, "task_id"),
		Status:     queryString(c, "status"),
		Confidence: queryString(c, "confidence"),
		Query:      queryString(c, "q"),
		Compact:    queryBool(c, "compact", false),
		Limit:      queryInt(c, "limit", 0),
		Offset:     queryInt(c, "offset", 0),
		OrderBy:    "score",
		// 全局漏洞库口径对齐 /api/vulns/stats：人工审核通过且非 superseded。
		// 曾漏挂该口径导致列表 24 条 vs 统计 3 条（未过审/已废弃全混进来）。
		UserStatus:        constant.UserPassed,
		ExcludeSuperseded: true,
	}
	if verdict := queryString(c, "verdict"); verdict != "" {
		filter.Verdicts = []string{verdict}
	}
	if userStatus := queryString(c, "user_status"); userStatus != "" {
		filter.UserStatus = userStatus
	}
	// submitted=yes/no 提交状态筛选（此前从未解析，前端切「已提交/待提交」无效）。
	switch strings.ToLower(queryString(c, "submitted")) {
	case "yes", "true", "1":
		v := true
		filter.Submitted = &v
	case "no", "false", "0":
		v := false
		filter.Submitted = &v
	}
	// severity 独立过滤（按复审生效等级精确匹配），不再拼进全文搜索词。
	if severity := queryString(c, "severity"); severity != "" {
		filter.Severity = severity
	}
	items, total, err := service.QueryFindings(filter)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubQueryError)
		return
	}
	respondList(c, ensureSlice(items), total, filter.Limit, filter.Offset)
}

// BatchToggleVulnTop 批量置顶漏洞。
// PATCH /api/vulns/batch/top
func BatchToggleVulnTop(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	var dto BatchTopRequest
	if err := c.ShouldBindJSON(&dto); err != nil || len(dto.IDs) == 0 {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	isTop := true
	if dto.IsTop != nil {
		isTop = *dto.IsTop
	}
	affected, err := service.ToggleBatchTop("vuln", dto.IDs, isTop)
	if err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true, "affected": affected, "is_top": isTop})
}

// ToggleVulnTop 单条漏洞置顶。
// PATCH /api/vulns/:vuln_id/top
func ToggleVulnTop(c *gin.Context) {
	if requireWrite(c) {
		return
	}
	vulnID := pathParam(c, "vuln_id")
	var dto ToggleTopRequest
	if err := c.ShouldBindJSON(&dto); err != nil || dto.IsTop == nil {
		result.Failed(c, result.BadRequest, result.SubMissingParam)
		return
	}
	if err := service.ToggleResultTop(vulnID, *dto.IsTop); err != nil {
		result.Failed(c, result.InternalError, result.SubWriteError)
		return
	}
	result.Success(c, gin.H{"ok": true, "id": vulnID, "is_top": *dto.IsTop})
}

var _ = engine.EmitInfo
