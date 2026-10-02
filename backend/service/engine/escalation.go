package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// 扩大危害最大轮次。
const EscalationMaxRounds = 10

// EscalationOutcome 扩大危害结论。
type EscalationOutcome struct {
	Escalated     bool             `json:"escalated"`
	Reason        string           `json:"reason,omitempty"`
	VulnType      string           `json:"vuln_type,omitempty"`
	Title         string           `json:"title,omitempty"`
	Severity      string           `json:"severity,omitempty"`
	Description   string           `json:"description,omitempty"`
	KillChain     []map[string]any `json:"kill_chain,omitempty"`
	Poc           string           `json:"poc,omitempty"`
	RawRequest    string           `json:"raw_request,omitempty"`
	RawResponse   string           `json:"raw_response,omitempty"`
	AffectedScope string           `json:"affected_scope,omitempty"`
	ImpactCount   int              `json:"impact_count,omitempty"`
}

// submitEscalationToolDef 提交升级结论工具定义。
func submitEscalationToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "submit_escalation",
		Description: "仅在实现【显著危害升级】时提交：等级提升 / 影响面数量级变化 / 实际拿到敏感数据、写操作、账号接管等新实质危害。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"vuln_type":      map[string]any{"type": "string", "description": "漏洞类型"},
				"title":          map[string]any{"type": "string", "description": "标题"},
				"severity":       map[string]any{"type": "string", "description": "升级后等级：严重/高危/中危/低危/信息"},
				"description":    map[string]any{"type": "string", "description": "升级后的危害描述"},
				"poc":            map[string]any{"type": "string", "description": "POC"},
				"raw_request":    map[string]any{"type": "string", "description": "原始请求"},
				"raw_response":   map[string]any{"type": "string", "description": "原始响应"},
				"affected_scope": map[string]any{"type": "string", "description": "影响范围"},
				"impact_count":   map[string]any{"type": "integer", "description": "受影响对象数量"},
				"kill_chain": map[string]any{
					"type": "array", "description": "攻击链步骤",
					"items": map[string]any{"type": "object"},
				},
			},
			"required": []string{"title", "severity", "description"},
		},
	}
}

// abandonEscalationToolDef 放弃升级工具定义。
func abandonEscalationToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "abandon_escalation",
		Description: "当无法在原洞基础上实现任何显著危害升级时调用，放弃本次扩大危害。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"reason": map[string]any{"type": "string", "description": "放弃原因"},
			},
			"required": []string{"reason"},
		},
	}
}

// RunEscalation 在已确认漏洞基础上执行一次「扩大危害」深挖。
// 显著升级时生成一条全新 Finding（走 pending_review 审核流程）。
func RunEscalation(ctx context.Context, pool *llm.Pool, taskID, findingID, origSeverity string) *EscalationOutcome {
	var finding model.Finding
	if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
		return &EscalationOutcome{Reason: "漏洞不存在"}
	}
	if pool == nil || pool.Size() == 0 {
		EmitError(taskID, "escalation", "escalate_error", "未配置可用的 LLM 端点", map[string]any{"finding_id": findingID})
		return &EscalationOutcome{Reason: "未配置可用的 LLM 端点"}
	}

	var task model.Task
	srcType := "edusrc"
	if err := core.Db.First(&task, "id = ?", taskID).Error; err == nil {
		srcType = firstNonEmptyString(task.SrcType, "edusrc")
	}

	EmitInfo(taskID, "escalation", "escalate_start", "开始扩大危害："+finding.Title,
		map[string]any{"finding_id": findingID})

	var outcome *EscalationOutcome

	session := &WorkerSession{
		TaskID:    taskID,
		TargetID:  finding.TargetID,
		WorkerID:  "escalation",
		MaxRounds: EscalationMaxRounds,
		WorkDir:   workDirForTask(taskID),
	}

	registry := NewToolRegistry()
	registry.Register(httpRequestToolDef(), handleHTTPRequest)
	registry.Register(runShellToolDef(), handleRunShell)
	registry.Register(submitEscalationToolDef(), func(_ context.Context, args map[string]any, _ *WorkerSession) ToolResult {
		outcome = parseEscalationOutcome(args)
		return ResultOK("已记录升级结论。")
	})
	registry.Register(abandonEscalationToolDef(), func(_ context.Context, args map[string]any, _ *WorkerSession) ToolResult {
		outcome = &EscalationOutcome{Escalated: false, Reason: stringArg(args, "reason")}
		return ResultOK("已放弃本次升级。")
	})

	messages := []llm.Message{
		{Role: "system", Content: EscalationSystemPrompt},
		{Role: "user", Content: buildEscalationBrief(&finding, origSeverity, srcType)},
	}

	for round := 1; round <= EscalationMaxRounds; round++ {
		if ctx.Err() != nil {
			return &EscalationOutcome{Reason: "扩大危害深挖已被取消"}
		}
		session.Round = round
		response, err := chatAndRecord(ctx, pool, llm.Request{
			Messages:    compactMessages(messages),
			Tools:       registry.Defs(),
			Temperature: 0.25,
			ToolChoice:  "auto",
		}, session.HealthRef)
		if err != nil {
			EmitError(taskID, "escalation", "escalate_error", "LLM 调用失败："+err.Error(),
				map[string]any{"finding_id": findingID})
			return &EscalationOutcome{Reason: "LLM 调用失败: " + err.Error()}
		}
		session.HealthRef = response.HealthRef
		session.ModelName = response.Endpoint.Model
		session.BaseURL = response.Endpoint.BaseURL

		assistant := llm.Message{Role: "assistant", Content: response.Response.Content, ToolCalls: response.Response.ToolCalls}
		messages = append(messages, assistant)

		if len(response.Response.ToolCalls) == 0 {
			messages = append(messages, llm.Message{
				Role:    "user",
				Content: "请继续深挖，或调用 submit_escalation / abandon_escalation 收尾。",
			})
			continue
		}

		for _, call := range response.Response.ToolCalls {
			if ctx.Err() != nil {
				return &EscalationOutcome{Reason: "扩大危害深挖已被取消"}
			}
			args := decodeArguments(call.Function.Arguments)
			var result ToolResult
			func() {
				defer func() {
					if r := recover(); r != nil {
						result = ResultErr(fmt.Sprintf("工具执行异常: %v", r))
					}
				}()
				result = registry.Execute(ctx, call.Function.Name, args, session)
			}()
			payload, _ := json.Marshal(map[string]any{"ok": !result.IsErr, "output": utils.SanitizeSecretText(result.Output)})
			messages = append(messages, llm.Message{
				Role:       "tool",
				ToolCallID: call.ID,
				Content:    string(payload),
			})
		}
		if outcome != nil {
			break
		}
	}

	if outcome == nil {
		outcome = &EscalationOutcome{Escalated: false, Reason: fmt.Sprintf("未在 %d 轮内实现显著升级", EscalationMaxRounds)}
	}

	if !outcome.Escalated {
		EmitInfo(taskID, "escalation", "escalate_abandon", "未实现显著升级："+utils.Truncate(outcome.Reason, 200),
			map[string]any{"finding_id": findingID})
		return outcome
	}

	if err := persistEscalationFinding(taskID, &finding, origSeverity, outcome); err != nil {
		EmitError(taskID, "escalation", "escalate_error", "保存升级漏洞失败："+err.Error(),
			map[string]any{"finding_id": findingID})
		return outcome
	}
	EmitInfo(taskID, "escalation", "escalate_done",
		fmt.Sprintf("扩大危害成功「%s」→「%s」(%s→%s)，已生成新洞进审核",
			finding.Title, outcome.Title, origSeverity, outcome.Severity),
		map[string]any{"finding_id": findingID, "new_severity": outcome.Severity})
	return outcome
}

// persistEscalationFinding 生成一条新的 pending_review 漏洞。
func persistEscalationFinding(taskID string, origin *model.Finding, origSeverity string, outcome *EscalationOutcome) error {
	baseKey := BuildDedupKey(outcome.VulnType, origin.TargetURL, origin.TargetURL)
	newKey := baseKey + ":esc:" + utils.ShortUUID(8)
	record := model.Finding{
		ID:              utils.UUID(),
		TaskID:          taskID,
		TargetID:        origin.TargetID,
		WorkerID:        "escalation",
		VulnType:        outcome.VulnType,
		Title:           utils.Truncate(outcome.Title, 480),
		SeverityClaimed: NormalizeSeverity(outcome.Severity),
		TargetURL:       origin.TargetURL,
		Owner:           origin.Owner,
		Description:     outcome.Description,
		Steps:           []string{},
		Poc:             outcome.Poc,
		RawRequest:      outcome.RawRequest,
		RawResponse:     outcome.RawResponse,
		Evidence: map[string]any{
			"escalated_from": origin.ID,
			"orig_severity":  origSeverity,
			"impact_count":   outcome.ImpactCount,
		},
		AffectedScope: outcome.AffectedScope,
		KillChain:     outcome.KillChain,
		SelfCheck:     map[string]any{},
		DedupKey:      newKey,
		Status:        constant.FindingPendingReview,
		LLMModel:      origin.LLMModel,
		LLMBaseURL:    origin.LLMBaseURL,
	}
	return core.Db.Create(&record).Error
}

// buildEscalationBrief 组装扩大危害起点说明。
func buildEscalationBrief(f *model.Finding, severity, srcType string) string {
	unitLabel := "归属"
	if srcType == "enterprise" || srcType == "src" {
		unitLabel = "企业/系统归属"
	}
	killChain, _ := json.Marshal(f.KillChain)
	var sb strings.Builder
	sb.WriteString("# 已确认存在的漏洞（你的深挖起点）\n")
	sb.WriteString("- 标题：" + f.Title + "\n")
	sb.WriteString("- 漏洞类型：" + f.VulnType + "\n")
	sb.WriteString("- 当前等级：" + severity + "\n")
	sb.WriteString("- 目标 URL：" + f.TargetURL + "\n")
	sb.WriteString("- " + unitLabel + "：" + f.Owner + "\n")
	sb.WriteString("- 描述：" + truncateForPrompt(f.Description, 800) + "\n")
	sb.WriteString("- 攻击链：" + truncateForPrompt(string(killChain), 600) + "\n")
	sb.WriteString("- PoC：" + truncateForPrompt(f.Poc, 600) + "\n")
	sb.WriteString("- 原始请求(片段)：" + truncateForPrompt(f.RawRequest, 600) + "\n")
	sb.WriteString("- 原始响应(片段)：" + truncateForPrompt(f.RawResponse, 900) + "\n\n")
	sb.WriteString("请在这个已确认据点上继续往下打，把危害做大。打出任何原洞没证明、而你新证明出来的实锤危害" +
		"（等级提升 / 影响面数量级 / 实际拿到敏感数据·写操作·账号接管等新实质危害）就 submit_escalation；" +
		"只有纯原地打转、和原洞完全等价时才 abandon_escalation。")
	return sb.String()
}

// parseEscalationOutcome 解析 submit_escalation 入参。
func parseEscalationOutcome(args map[string]any) *EscalationOutcome {
	return &EscalationOutcome{
		Escalated:     true,
		VulnType:      stringArg(args, "vuln_type"),
		Title:         stringArg(args, "title"),
		Severity:      stringArg(args, "severity"),
		Description:   stringArg(args, "description"),
		KillChain:     mapSliceArg(args, "kill_chain"),
		Poc:           stringArg(args, "poc"),
		RawRequest:    stringArg(args, "raw_request"),
		RawResponse:   stringArg(args, "raw_response"),
		AffectedScope: stringArg(args, "affected_scope"),
		ImpactCount:   intArg(args, "impact_count", 0),
	}
}

// compactMessages 上下文瘦身：保留 system + 最近 N 条消息。
func compactMessages(messages []llm.Message) []llm.Message {
	const keepRecent = 12
	if trimmed, ok := trimKeepingRecent(messages, 1, keepRecent); ok {
		return trimmed
	}
	return messages
}

// trimKeepingRecent 保留前 headCount 条锚点消息与最近 keepRecent 条消息。
//
// 切点会向后对齐到「非 tool」消息边界：一旦窗口以孤立的 tool 消息开头，
// OpenAI / DeepSeek 会直接返回
//
//	400 Messages with role 'tool' must be a response to a preceding message with 'tool_calls'
//
// 因为模型返回 assistant(tool_calls) 后，紧随其后的 tool 结果必须与之一同出现。
// 返回裁剪后的切片以及是否真的发生了裁剪。
func trimKeepingRecent(messages []llm.Message, headCount, keepRecent int) ([]llm.Message, bool) {
	if headCount < 0 || keepRecent <= 0 || len(messages) <= headCount+keepRecent {
		return messages, false
	}
	start := len(messages) - keepRecent
	for start < len(messages) && messages[start].Role == "tool" {
		start++
	}
	if start >= len(messages) {
		return messages, false
	}
	out := make([]llm.Message, 0, headCount+len(messages)-start)
	out = append(out, messages[:headCount]...)
	out = append(out, messages[start:]...)
	return out, true
}
