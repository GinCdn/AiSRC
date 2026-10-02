package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// WorkerSession 一次目标挖掘的会话状态。工具回调通过它回写进度与结论。
type WorkerSession struct {
	TaskID    string
	TargetID  string
	WorkerID  string
	WorkDir   string
	TargetURL string
	Round     int
	MaxRounds int
	MaxWall   time.Duration
	ModelName string
	BaseURL   string
	HealthRef string

	finished      bool
	finishSummary string
	directive     string
	budgetReason  string
	budgetGranted int      // 已成功追加的次数
	budgetWarned  bool     // 是否已就"进入收尾阶段"提醒过（追加后重新武装）
	gateWarned    bool     // finish 时是否已就「未收割 gate」提醒过（第二次放行）
	coverageWarned bool    // finish 时是否已就「漏洞类型覆盖不足」提醒过（第二次放行）
	hostKey           string              // 单站协作覆盖事件的 host 键（归一化）
	routeSource       string              // 单站协作路线来源（非空 = site worker）
	reportedCoverage  []map[string]any    // 本轮 report_coverage 上报（收尾时交 orchestrator 派生追打）
	reportedIntel     []map[string]any    // 本轮 report_intel 上报（收尾时交 orchestrator 沉淀全局情报库）
	DeclaredTypes []string // 任务声明的漏洞类型清单（finish 覆盖检查用）
	submitted     []*SubmittedFinding
	pool          *llm.Pool
	toolCalls     int
	session       *sessionState
	gates         map[string]*GateRecord // 3-gate 通过记录：token -> record
	gateCache     map[string]string      // 验证指纹 -> token（避免重复重放）
}

// budgetMaxGrant 单目标最多允许追加几次预算。软预算模型必须有硬上限，
// 否则模型可以无限自我续命，任务永远不收敛、用量无法预估。
const budgetMaxGrant = 3

// Session 返回本 Worker 的会话态（Cookie + 鉴权头），首次访问时按目标地址初始化。
func (s *WorkerSession) Session() *sessionState {
	if s.session == nil {
		s.session = newSessionState(s.TargetURL)
	}
	return s.session
}

// SubmitFinding 由 submit_finding 工具回调，暂存后统一落库。
func (s *WorkerSession) SubmitFinding(finding *SubmittedFinding) error {
	if finding == nil {
		return fmt.Errorf("空漏洞内容")
	}
	s.submitted = append(s.submitted, finding)
	return nil
}

// Finish 由 finish 工具回调。
func (s *WorkerSession) Finish(summary string) {
	s.finished = true
	s.finishSummary = summary
}

// SubmittedTypes 返回本轮已提交漏洞的去重类型清单（保持提交顺序）。
func (s *WorkerSession) SubmittedTypes() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range s.submitted {
		if item != nil && item.VulnType != "" && !seen[item.VulnType] {
			seen[item.VulnType] = true
			out = append(out, item.VulnType)
		}
	}
	return out
}

// UntouchedDeclaredTypes 返回任务声明了但本轮从未提交过的类型（覆盖检查用）。
func (s *WorkerSession) UntouchedDeclaredTypes() []string {
	if len(s.DeclaredTypes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, t := range s.SubmittedTypes() {
		seen[t] = true
	}
	out := []string{}
	for _, t := range s.DeclaredTypes {
		if !seen[t] {
			out = append(out, t)
		}
	}
	return out
}

// RequestMoreBudget 由 need_more_budget 工具回调。返回是否真的追加了预算。
//
// 旧实现只在「剩余不足 2 轮」时才真正追加，却无条件回一句"已追加 4 轮"——
// 模型在轮次充裕时调用会被假消息误导；追加后也不重新武装收尾提醒。
// 现在改为：始终尝试追加（受 budgetMaxGrant 硬上限约束），并把真实剩余轮数回给模型。
func (s *WorkerSession) RequestMoreBudget(reason string) (granted bool, remaining int) {
	s.budgetReason = reason
	if s.budgetGranted < budgetMaxGrant {
		s.budgetGranted++
		s.MaxRounds += budgetExtendRounds
		s.budgetWarned = false // 预算变宽，重新武装收尾提醒
		granted = true
	}
	return granted, s.MaxRounds - s.Round
}

// budgetExtendRounds 单次追加的轮数。
const budgetExtendRounds = 4

// BudgetNotice 返回"预算即将用尽"的提示文本；无需提醒时返回空串。
//
// 系统提示词一直在教模型"接近结束时调用 need_more_budget"，却从不告诉它
// 还剩几轮——模型无从判断"接近结束"，于是该工具从未被触发，
// 漏洞已复现却因轮次耗尽没能走到 submit_finding（实测 DVWA 即如此）。
// 进入最后 3 轮时明确告知剩余轮数，并给出"先提交再续命"的优先级。
func (s *WorkerSession) BudgetNotice() string {
	if s == nil || s.budgetWarned {
		return ""
	}
	remaining := s.MaxRounds - s.Round
	if remaining > 3 || remaining <= 0 {
		return ""
	}
	s.budgetWarned = true
	notice := fmt.Sprintf("## 预算提醒（还剩 %d 轮）\n"+
		"已进入收尾阶段，请优先保证产出：\n"+
		"1. 若已掌握可用证据，立即调用 submit_finding 提交（未提交等于没有发现）；\n"+
		"2. 确有未完成的关键验证步骤，调用 need_more_budget 说明原因后再继续；\n"+
		"3. 两者都已处理，则调用 finish 结束本目标。", remaining)
	// 收尾阶段叠加「未收割 gate」提示：验证通过却没提交的发现即将随目标结束而丢失。
	if pending := s.UnharvestedGates(); len(pending) > 0 {
		notice += fmt.Sprintf("\n\n⚠️ 注意：以下漏洞已通过 3-gate 验证但尚未提交：%s。"+
			"请在收尾前用对应 gate_token 调用 submit_finding，否则 finish 会被拒绝。", strings.Join(pending, "、"))
	}
	return notice
}

// SetDirective 注入人工实时指令。
func (s *WorkerSession) SetDirective(directive string) {
	s.directive = directive
}

// TakeDirective 取出并清空待注入指令。
func (s *WorkerSession) TakeDirective() string {
	d := s.directive
	s.directive = ""
	return d
}

// Submitted 返回本次会话提交的漏洞。
func (s *WorkerSession) Submitted() []*SubmittedFinding { return s.submitted }

// UnharvestedGates 返回「已通过 3-gate 验证但尚未携带其 token 提交」的漏洞类型列表。
// 验证通过 = 服务端已确认差异可归因，此时不提交就等于把已确认的漏洞白白丢掉
// （实测 DVWA：RCE 验证通过后模型去验证下一个，轮次耗尽，RCE 从未落库）。
func (s *WorkerSession) UnharvestedGates() []string {
	if s == nil || len(s.gates) == 0 {
		return nil
	}
	used := map[string]bool{}
	for _, f := range s.submitted {
		if f != nil && strings.TrimSpace(f.GateToken) != "" {
			used[strings.TrimSpace(f.GateToken)] = true
		}
	}
	seen := map[string]bool{}
	pending := make([]string, 0)
	for _, rec := range s.gates {
		if rec == nil || used[rec.Token] || seen[rec.VulnType] {
			continue
		}
		seen[rec.VulnType] = true
		pending = append(pending, rec.VulnType)
	}
	return pending
}

// PutGate 保存一条 3-gate 通过记录（Worker 工具调用为串行，无需加锁）。
func (s *WorkerSession) PutGate(rec *GateRecord) {
	if s == nil || rec == nil {
		return
	}
	if s.gates == nil {
		s.gates = map[string]*GateRecord{}
	}
	if s.gateCache == nil {
		s.gateCache = map[string]string{}
	}
	s.gates[rec.Token] = rec
	if rec.Fingerprint != "" {
		s.gateCache[rec.Fingerprint] = rec.Token
	}
}

// GetGate 按令牌取回 3-gate 记录。
func (s *WorkerSession) GetGate(token string) *GateRecord {
	if s == nil || s.gates == nil {
		return nil
	}
	return s.gates[strings.TrimSpace(token)]
}

// CachedGate 按验证指纹取已签发的令牌；无记录返回空串。
func (s *WorkerSession) CachedGate(fingerprint string) string {
	if s == nil || s.gateCache == nil {
		return ""
	}
	return s.gateCache[fingerprint]
}

// WorkerResult 一次 Worker 执行的产出。
type WorkerResult struct {
	Verdict      string // found / no_vuln / error
	Summary      string
	Submitted    []*SubmittedFinding
	Errors       []string
	Rounds       int
	ToolCalls    int
	ModelName    string
	BaseURL      string
	HealthRef    string
	BudgetReason string
	// 单站协作：本轮覆盖上报记录（orchestrator 据此派生 site_fXX 追打目标）。
	ReportedCoverage []map[string]any
	// 全局情报库：本轮 worker 主动上报的可复用经验（cred/endpoint/profile）。
	ReportedIntel []map[string]any
}

// buildWorkerRegistry 构造 Worker 可用工具集。
func buildWorkerRegistry() *ToolRegistry {
	registry := NewToolRegistry()
	registry.Register(httpRequestToolDef(), handleHTTPRequest)
	registry.Register(sessionSetToolDef(), handleSessionSet)
	registry.Register(dnsLookupToolDef(), handleDNSLookup)
	registry.Register(verifyFindingToolDef(), handleVerifyFinding)
	registry.Register(submitFindingToolDef(), handleSubmitFinding)
	registry.Register(finishToolDef(), handleFinish)
	registry.Register(needMoreBudgetToolDef(), handleNeedMoreBudget)
	registry.Register(runShellToolDef(), handleRunShell)
	return registry
}

// RunWorker 执行一个目标的完整挖掘循环。
func RunWorker(ctx context.Context, pool *llm.Pool, wctx *WorkerContext, maxRounds int, workDir string) *WorkerResult {
	result := &WorkerResult{Verdict: "no_vuln", ModelName: poolName(pool)}

	if pool == nil || pool.Size() == 0 {
		result.Verdict = "error"
		result.Errors = append(result.Errors, "未配置可用的 LLM 端点")
		return result
	}

	session := &WorkerSession{
		TaskID:        wctx.TaskID,
		TargetID:      wctx.TargetID,
		WorkerID:      "w-" + utils.ShortUUID(8),
		WorkDir:       workDir,
		TargetURL:     wctx.URL,
		MaxRounds:     maxRounds,
		MaxWall:       15 * time.Minute,
		DeclaredTypes: wctx.VulnTypes,
		pool:          pool,
	}
	// 单站协作：覆盖事件的 host 键与路线来源（report_coverage 工具用）。
	session.hostKey = siteHostKey(wctx.URL, wctx.Host)
	session.routeSource = wctx.SiteRouteSource

	if workDir != "" {
		_ = os.MkdirAll(filepath.Join(workDir, session.WorkerID), 0o755)
		session.WorkDir = filepath.Join(workDir, session.WorkerID)
	}

	// 启动必试：用户凭据由服务端注入或直接登录，密码不出本机、不进模型上下文。
	attempt := BootstrapAuth(ctx, session, wctx.AuthContext)
	if attempt != nil {
		payload := attempt.AsEvent()
		payload["target_id"] = wctx.TargetID
		if attempt.Status == "login_fail" {
			EmitWarn(wctx.TaskID, "worker", "auth_status", FormatAuthStatusMessage(*attempt), payload)
		} else {
			EmitInfo(wctx.TaskID, "worker", "auth_status", FormatAuthStatusMessage(*attempt), payload)
		}
	}

	registry := buildWorkerRegistry()
	// 全局情报上报：所有 worker 都可沉淀可复用经验（原版语义）。
	registry.Register(reportIntelToolDef(), handleReportIntel)
	// Kali SSH 协调执行（系统设置启用后注册）。
	if KaliEnabled() {
		registry.Register(runKaliToolDef(LoadSystemSettings()), handleRunKali)
	}
	// ima 知识库检索（系统设置启用后注册）。
	{
		ima := LoadSystemSettings().Ima
		if ima.Enabled && strings.TrimSpace(ima.BaseURL) != "" {
			registry.Register(imaSearchToolDef(), handleImaSearch)
		}
	}
	// 单站协作路线 worker 追加覆盖上报工具（非 site 路线不注册）。
	if wctx.SiteRouteSource != "" {
		registry.Register(reportCoverageToolDef(), handleReportCoverage)
	}
	tools := registry.Defs()

	kickoff := BuildWorkerKickoffPrompt(wctx)
	if block := UserAuthPromptBlock(wctx.AuthContext, attempt); block != "" {
		kickoff += "\n" + block
	}

	messages := []llm.Message{
		{Role: "system", Content: WorkerSystemPrompt + AgentPersonaSuffix()},
		{Role: "user", Content: kickoff},
	}
	// kickoff 里已经写明启动尝试结果，清掉启动阶段产生的「会话态变化」标记，
	// 避免第一轮重复注入同一份信息。
	session.Session().takeDirty()

	deadline := time.Now().Add(session.MaxWall)
	preferRef := ""

	for session.Round < session.MaxRounds {
		if ctx.Err() != nil {
			result.Errors = append(result.Errors, "任务已停止")
			break
		}
		if time.Now().After(deadline) {
			EmitWarn(wctx.TaskID, "worker", "worker_timeout",
				fmt.Sprintf("Worker 墙钟超时，提前收敛（%s）", wctx.Host), map[string]any{"target_id": wctx.TargetID})
			break
		}

		// 会话态发生变化（登录成功 / session_set / 吸收到新 Set-Cookie）时，
		// 把最新会话态注入本轮——模型才能"看见"自己现在持有哪些登录态，
		// 不会反复无效登录，也不会在会话过期后仍按已登录假设行动。
		if session.Session().takeDirty() {
			messages = append(messages, llm.Message{
				Role:    "user",
				Content: session.Session().statusBlock(),
			})
		}

		// 注入人工实时指令（若有）
		if directive := session.TakeDirective(); directive != "" {
			messages = append(messages, llm.Message{
				Role:    "user",
				Content: "## 人工实时指令（最高优先级，本轮必须执行）\n" + directive,
			})
			EmitInfo(wctx.TaskID, "worker", "directive_applied",
				"已注入人工指令："+utils.Truncate(directive, 120),
				map[string]any{"target_id": wctx.TargetID, "directive": directive})
		}

		// 收尾阶段明确告知剩余轮次（否则模型无从判断"接近结束"，见 BudgetNotice 注释）
		if notice := session.BudgetNotice(); notice != "" {
			remaining := session.MaxRounds - session.Round
			messages = append(messages, llm.Message{Role: "user", Content: notice})
			EmitInfo(wctx.TaskID, "worker", "budget_notice",
				fmt.Sprintf("已进入收尾阶段（剩余 %d 轮）", remaining),
				map[string]any{"target_id": wctx.TargetID, "remaining": remaining})
		}

		session.Round++
		EmitInfo(wctx.TaskID, "worker", "llm_round_start",
			fmt.Sprintf("第 %d 轮推理", session.Round),
			map[string]any{
				"target_id": wctx.TargetID,
				"round":     session.Round,
				"remaining": session.MaxRounds - session.Round,
			})

		// 端点池全部冷却（限流/网关超时）时等待恢复重试，而不是一轮失败就把目标打死。
		chatResult, err := chatAndRecordWait(wctx.TaskID, ctx, pool, llm.Request{
			Messages:  messages,
			Tools:     tools,
			MaxTokens: 8192,
		}, preferRef)
		if err != nil {
			detail := utils.SanitizeSecretText(err.Error())
			result.Errors = append(result.Errors, detail)
			EmitError(wctx.TaskID, "worker", "llm_error", "模型调用失败："+detail,
				map[string]any{"target_id": wctx.TargetID, "error": detail})
			result.Verdict = "error"
			break
		}
		preferRef = chatResult.HealthRef
		session.ModelName = chatResult.Endpoint.Model
		session.BaseURL = chatResult.Endpoint.BaseURL
		session.HealthRef = chatResult.HealthRef

		response := chatResult.Response
		if strings.TrimSpace(response.Content) != "" {
			EmitInfo(wctx.TaskID, "worker", "worker_thought",
				utils.Truncate(response.Content, 600),
				map[string]any{"target_id": wctx.TargetID, "round": session.Round})
		}

		// 记录 assistant 消息
		assistant := llm.Message{Role: "assistant", Content: response.Content}
		if len(response.ToolCalls) > 0 {
			assistant.ToolCalls = response.ToolCalls
		}
		messages = append(messages, assistant)

		if len(response.ToolCalls) == 0 {
			// 没有工具调用：模型直接给出结论，视为收敛
			EmitInfo(wctx.TaskID, "worker", "worker_auto_finish",
				"模型未请求工具，自动收敛本轮目标",
				map[string]any{"target_id": wctx.TargetID})
			break
		}

		for _, call := range response.ToolCalls {
			session.toolCalls++
			args := decodeArguments(call.Function.Arguments)

			toolResult := registry.Execute(ctx, call.Function.Name, args, session)

			EmitInfo(wctx.TaskID, "worker", "tool_call",
				fmt.Sprintf("调用工具 %s", call.Function.Name),
				map[string]any{
					"target_id": wctx.TargetID,
					"tool":      call.Function.Name,
					"args":      args,
				})

			level := "info"
			if toolResult.IsErr {
				level = "warn"
			}
			Emit(wctx.TaskID, "worker", "tool_result", level,
				fmt.Sprintf("%s 返回：%s", call.Function.Name, utils.Truncate(firstLine(toolResult.Output), 200)),
				map[string]any{
					"target_id": wctx.TargetID,
					"tool":      call.Function.Name,
					"text":      utils.Truncate(toolResult.Output, 4000),
				})

			messages = append(messages, llm.Message{
				Role:       "tool",
				ToolCallID: call.ID,
				Name:       call.Function.Name,
				Content:    utils.Truncate(toolResult.Output, 12000),
			})

			if session.finished {
				break
			}
		}

		if session.finished {
			break
		}

		// 上下文瘦身：保留 system + kickoff + 最近 12 条消息。
		// 切点必须对齐到消息边界，否则会切出孤立的 tool 消息导致模型 400。
		if trimmed, ok := trimKeepingRecent(messages, 2, 12); ok {
			messages = append(trimmed, llm.Message{
				Role:    "user",
				Content: "（为节省上下文，早期中间步骤已被折叠。请基于当前信息继续，必要时重新获取关键数据。）",
			})
		}
	}

	result.Rounds = session.Round
	result.ToolCalls = session.toolCalls
	result.Submitted = session.submitted
	result.Summary = session.finishSummary
	result.BudgetReason = session.budgetReason
	result.ModelName = session.ModelName
	result.BaseURL = session.BaseURL
	result.HealthRef = session.HealthRef
	result.ReportedCoverage = session.reportedCoverage
	result.ReportedIntel = session.reportedIntel
	if len(session.submitted) > 0 {
		result.Verdict = "found"
	}
	return result
}

// PersistFinding 把 Worker 提交的漏洞落库，并生成去重键。
func PersistFinding(taskID string, target *model.Target, finding *SubmittedFinding, modelName, baseURL, workerID string) (*model.Finding, error) {
	if core.Db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	now := time.Now().UTC()

	record := model.Finding{
		ID:              utils.UUID(),
		TaskID:          taskID,
		TargetID:        target.ID,
		WorkerID:        workerID,
		VulnType:        utils.Truncate(finding.VulnType, 80),
		Title:           utils.Truncate(finding.Title, 500),
		SeverityClaimed: finding.SeverityClaimed,
		TargetURL:       utils.Truncate(firstNonEmptyString(finding.TargetURL, target.URL), 500),
		Owner:           utils.Truncate(firstNonEmptyString(finding.Owner, target.School, target.Org), 300),
		Description:     finding.Description,
		Steps:           finding.Steps,
		Poc:             finding.Poc,
		RawRequest:      finding.RawRequest,
		RawResponse:     finding.RawResponse,
		Evidence:        finding.Evidence,
		AffectedScope:   finding.AffectedScope,
		KillChain:       finding.KillChain,
		SelfCheck:       finding.SelfCheck,
		AssistantMsgs:   []map[string]any{},
		LLMModel:        utils.Truncate(modelName, 200),
		LLMBaseURL:      utils.Truncate(baseURL, 300),
		Status:          constant.FindingPendingReview,
		CreatedAt:       now,
	}
	record.DedupKey = BuildDedupKey(record.VulnType, record.TargetURL, target.Host)

	// 去重键冲突时改写为带后缀的键，保证不阻塞新漏洞入库
	var existing model.Finding
	err := core.Db.Where("dedup_key = ?", record.DedupKey).First(&existing).Error
	if err == nil && existing.ID != "" {
		record.DedupKey = record.DedupKey + ":dup:" + utils.ShortUUID(8)
	}

	if err := core.Db.Create(&record).Error; err != nil {
		return nil, err
	}
	global.Log.Infof("落库漏洞 task=%s id=%s title=%s", taskID, record.ID, record.Title)
	return &record, nil
}

// BuildDedupKey 生成漏洞级去重键（类型 + 主机 + 路径特征）。
func BuildDedupKey(vulnType, targetURL, host string) string {
	normalizedType := normalizeVulnType(vulnType)
	path := pathSignature(targetURL)
	key := fmt.Sprintf("%s|%s|%s", normalizedType, utils.NormalizeHost(firstNonEmptyString(host, targetURL)), path)
	ref := utils.IdentityRef(key)
	return normalizedType + ":" + ref
}

func normalizeVulnType(vulnType string) string {
	trimmed := strings.ToLower(strings.TrimSpace(vulnType))
	aliases := map[string]string{
		"sql注入": "sqli", "sqli": "sqli", "sqlinjection": "sqli",
		"任意文件上传": "upload", "文件上传": "upload", "upload": "upload",
		"任意文件读取": "fileread", "文件读取": "fileread", "lfi": "fileread",
		"命令执行": "rce", "rce": "rce",
		"ssrf": "ssrf", "服务端请求伪造": "ssrf",
		"越权访问": "idor", "越权": "idor", "idor": "idor",
		"未授权访问": "unauth", "未授权": "unauth",
		"逻辑缺陷": "logic", "逻辑漏洞": "logic",
		"信息泄露": "infoleak", "xss": "xss",
		"弱口令": "weakpwd",
	}
	if alias, ok := aliases[trimmed]; ok {
		return alias
	}
	if trimmed == "" {
		return "unknown"
	}
	return refOf(trimmed)
}

func refOf(value string) string {
	return utils.IdentityRef(value)
}

// pathSignature 提取 URL 的路径签名（数字段归一化为 {n}）。
func pathSignature(rawURL string) string {
	value := strings.TrimSpace(rawURL)
	if value == "" {
		return "/"
	}
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[idx:]
	} else {
		return "/"
	}
	if idx := strings.IndexAny(value, "?#"); idx >= 0 {
		value = value[:idx]
	}
	segments := strings.Split(value, "/")
	for i, segment := range segments {
		if isNumeric(segment) {
			segments[i] = "{n}"
		}
	}
	joined := strings.Join(segments, "/")
	if joined == "" {
		return "/"
	}
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func decodeArguments(raw string) map[string]any {
	args := map[string]any{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return args
	}
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		args["_raw"] = raw
		args["_parse_error"] = err.Error()
	}
	return args
}

func firstLine(text string) string {
	if idx := strings.IndexAny(text, "\r\n"); idx >= 0 {
		return text[:idx]
	}
	return text
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func poolName(pool *llm.Pool) string {
	if pool == nil {
		return ""
	}
	endpoints := pool.Endpoints()
	if len(endpoints) == 0 {
		return ""
	}
	return endpoints[0].Model
}
