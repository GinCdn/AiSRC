package service

// 报告助手工具循环（对齐原版 findings.py REPORT_ASSISTANT_TOOLS + _run_report_assistant_loop）。
//
// 助手可执行受控验证（http_request / run_shell）并提出报告改稿（propose_report_edits），
// 每一步通过 emit 回调实时推给 SSE；最后收口轮强制不给工具，逼模型基于已执行结果作答。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// assistantMaxRounds 助手最大循环轮数（原版 REPORT_ASSISTANT_MAX_ROUNDS 默认 10）。
const assistantMaxRounds = 10

var assistantSeverities = []string{"严重", "高危", "中危", "低危"}

// assistantToolDefs 报告助手工具集（对齐原版 REPORT_ASSISTANT_TOOLS）。
func assistantToolDefs() []llm.ToolDef {
	return []llm.ToolDef{
		{
			Name:        "http_request",
			Description: "对该漏洞相关目标发一个 HTTP 请求，用于补充验证或查看响应。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url":               map[string]any{"type": "string"},
					"method":            map[string]any{"type": "string"},
					"headers":           map[string]any{"type": "object"},
					"data":              map[string]any{"type": "string"},
					"json_body":         map[string]any{"type": "object"},
					"follow_redirects":  map[string]any{"type": "boolean"},
					"confirm_destructive": map[string]any{"type": "boolean", "description": "非 GET/HEAD/OPTIONS 方法必须 true"},
					"confirm_reason":    map[string]any{"type": "string"},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "run_shell",
			Description: "执行简短验证命令（如 curl）。用于用户明确要求再操作/验证时。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command":             map[string]any{"type": "string"},
					"timeout":             map[string]any{"type": "integer"},
					"confirm_destructive": map[string]any{"type": "boolean"},
					"confirm_reason":      map[string]any{"type": "string"},
				},
				"required": []string{"command"},
			},
		},
		{
			Name: "propose_report_edits",
			Description: "提出对当前报告字段的改稿，不会直接写入数据库。润色标题/描述/复现/PoC/影响范围/建议等级时必须调用。" +
				"前端可一键应用到编辑器。只填需要改的字段。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":          map[string]any{"type": "string"},
					"description":    map[string]any{"type": "string"},
					"affected_scope": map[string]any{"type": "string"},
					"steps":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"poc":            map[string]any{"type": "string"},
					"severity":       map[string]any{"type": "string", "enum": assistantSeverities},
					"rationale":      map[string]any{"type": "string", "description": "改了什么、为什么这样改（给审核员看的短说明）"},
				},
			},
		},
	}
}

var unexecutedToolTextRe = regexp.MustCompile(`(?i)(^|\n)\s*(#.*\n)?\s*curl\s+-`)

// looksLikeUnexecutedToolText 检测模型是否用文字伪造了工具调用。
func looksLikeUnexecutedToolText(text string) bool {
	low := strings.ToLower(text)
	for _, marker := range []string{"tool_calls", "invoke name=", "run_shell", "http_request"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return unexecutedToolTextRe.MatchString(text)
}

// assistantToolCallSummary 把一次工具调用浓缩成一句人话（前端实时展示）。
func assistantToolCallSummary(name string, args map[string]any) string {
	switch name {
	case "http_request":
		method := strings.ToUpper(strMap(args, "method"))
		if method == "" {
			method = "GET"
		}
		return strings.TrimSpace(method + " " + strMap(args, "url"))
	case "run_shell":
		return utils.Truncate(strings.TrimSpace(strMap(args, "command")), 200)
	case "propose_report_edits":
		var keys []string
		for _, k := range []string{"title", "description", "affected_scope", "steps", "poc", "severity"} {
			if v, ok := args[k]; ok && fmt.Sprintf("%v", v) != "" && fmt.Sprintf("%v", v) != "[]" {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			return "改稿：字段草案"
		}
		return "改稿：" + strings.Join(keys, "、")
	}
	return name
}

// assistantToolResultSummary 把工具结果浓缩成一句关键信息（前端实时展示）。
func assistantToolResultSummary(name string, result map[string]any) string {
	if result["blocked"] == true {
		return utils.Truncate("已拦截："+strMap(result, "error"), 200)
	}
	if result["ok"] == false {
		return utils.Truncate("失败："+strMap(result, "error"), 200)
	}
	switch name {
	case "http_request":
		bodyLen := 0
		if n, ok := result["body_len"].(int); ok {
			bodyLen = n
		} else if body, ok := result["body"].(string); ok {
			bodyLen = len(body)
		}
		return fmt.Sprintf("HTTP %s · 响应 %d 字节", orDash(result["status_code"]), bodyLen)
	case "run_shell":
		out, _ := result["output"].(string)
		extra := ""
		if result["timed_out"] == true {
			extra = " · 超时"
		}
		return fmt.Sprintf("退出码 %s · 输出 %d 字节%s", orDash(result["return_code"]), len(out), extra)
	case "propose_report_edits":
		edits, _ := result["edits"].(map[string]any)
		keys := make([]string, 0, len(edits))
		for k := range edits {
			if k != "rationale" {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			return "可一键应用：草案"
		}
		return "可一键应用：" + strings.Join(keys, "、")
	}
	return "完成"
}

func strMap(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func orDash(v any) string {
	switch n := v.(type) {
	case int:
		if n == 0 {
			return "?"
		}
		return fmt.Sprintf("%d", n)
	case float64:
		return fmt.Sprintf("%d", int(n))
	case string:
		if n == "" {
			return "?"
		}
		return n
	}
	return "?"
}

// normalizeProposedEdits 校验助手改稿；空草案视为失败（原版 _normalize_proposed_edits）。
func normalizeProposedEdits(args map[string]any) map[string]any {
	if args == nil {
		return map[string]any{"ok": false, "error": "改稿参数无效"}
	}
	edits := map[string]any{}
	if v := strings.TrimSpace(strMap(args, "title")); v != "" {
		edits["title"] = utils.Truncate(v, 200)
	}
	if v := strings.TrimSpace(strMap(args, "description")); v != "" {
		edits["description"] = utils.Truncate(v, 8000)
	}
	if v := strings.TrimSpace(strMap(args, "affected_scope")); v != "" {
		edits["affected_scope"] = utils.Truncate(v, 4000)
	}
	if v := strings.TrimSpace(strMap(args, "poc")); v != "" {
		edits["poc"] = utils.Truncate(v, 8000)
	}
	switch raw := args["steps"].(type) {
	case string:
		var steps []string
		for _, line := range strings.Split(raw, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				steps = append(steps, line)
			}
		}
		if len(steps) > 0 {
			if len(steps) > 40 {
				steps = steps[:40]
			}
			edits["steps"] = steps
		}
	case []any:
		var steps []string
		for _, item := range raw {
			if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
				steps = append(steps, s)
			}
		}
		if len(steps) > 0 {
			if len(steps) > 40 {
				steps = steps[:40]
			}
			edits["steps"] = steps
		}
	}
	if v := strings.TrimSpace(strMap(args, "severity")); v != "" {
		for _, allowed := range assistantSeverities {
			if v == allowed {
				edits["severity"] = v
				break
			}
		}
	}
	if v := strings.TrimSpace(strMap(args, "rationale")); v != "" {
		edits["rationale"] = utils.Truncate(v, 500)
	}
	payload := map[string]any{}
	for k, v := range edits {
		if k != "rationale" {
			payload[k] = v
		}
	}
	if len(payload) == 0 {
		return map[string]any{"ok": false, "error": "没有可应用的改稿字段"}
	}
	return map[string]any{"ok": true, "edits": edits}
}

// fallbackAnswer 模型最终没给文字时，基于已执行的工具动作兜底生成摘要。
func fallbackAnswer(toolLogs []map[string]any) string {
	if len(toolLogs) == 0 {
		return "我没有需要补充验证的动作。请把问题说得更具体些，例如让我判断某条证据是否成立、或要求我重新 curl 某个接口看状态码。"
	}
	lines := []string{"我执行了以下验证动作，但模型未给出文字总结，先把关键结果列给你："}
	for i, log := range toolLogs {
		args, _ := log["args"].(map[string]any)
		result, _ := log["result"].(map[string]any)
		lines = append(lines, fmt.Sprintf("%d. `%s` → %s",
			i+1, assistantToolCallSummary(strMap(log, "tool"), args), assistantToolResultSummary(strMap(log, "tool"), result)))
	}
	lines = append(lines, "\n如需进一步解读，请追问。")
	return strings.Join(lines, "\n")
}

// RunReportAssistantLoop 报告助手主循环；emit 非空时实时推送 SSE 事件。
func RunReportAssistantLoop(ctx context.Context, findingID, message string, emit func(map[string]any)) *AssistantReply {
	emitSafe := func(ev map[string]any) {
		if emit != nil {
			emit(ev)
		}
	}
	var finding model.Finding
	if err := core.Db.First(&finding, "id = ?", findingID).Error; err != nil {
		return &AssistantReply{ErrorMsg: "漏洞不存在"}
	}
	var review model.Review
	edits := map[string]any{}
	if err := core.Db.Where("finding_id = ?", findingID).First(&review).Error; err == nil {
		edits = review.UserEdits
	}

	var task model.Task
	pool := engine.BuildGlobalPool()
	if err := core.Db.First(&task, "id = ?", finding.TaskID).Error; err == nil {
		pool = engine.BuildPoolForTask(&task)
	}
	if pool.Size() == 0 {
		return &AssistantReply{ErrorMsg: "未配置可用的 LLM 端点，请先在设置中配置模型"}
	}

	brief := &engine.FindingBrief{
		ID: finding.ID, TaskID: finding.TaskID, TargetID: finding.TargetID,
		VulnType: finding.VulnType, Title: finding.Title, SeverityClaimed: finding.SeverityClaimed,
		TargetURL: finding.TargetURL, Owner: finding.Owner, Description: finding.Description,
		Steps: finding.Steps, Poc: finding.Poc, RawRequest: finding.RawRequest,
		RawResponse: finding.RawResponse, AffectedScope: finding.AffectedScope,
		Evidence: finding.Evidence, KillChain: finding.KillChain,
	}
	contextText := engine.BuildReportAssistantContext(brief, edits)
	messages := []llm.Message{
		{Role: "system", Content: engine.ReportAssistantSystemPrompt},
		{Role: "user", Content: contextText},
	}
	if strings.TrimSpace(message) != "" {
		messages = append(messages, llm.Message{Role: "user", Content: message})
	}
	tools := assistantToolDefs()
	toolLogs := make([]map[string]any, 0, 4)
	var suggestedEdits map[string]any

	for round := 0; round < assistantMaxRounds; round++ {
		if ctx.Err() != nil {
			return &AssistantReply{Reply: "已停止。", ToolLogs: toolLogs, Edits: suggestedEdits}
		}
		lastRound := round == assistantMaxRounds-1
		callMessages := messages
		req := llm.Request{Messages: callMessages, Tools: tools, Temperature: 0.2, ToolChoice: "auto"}
		if lastRound {
			emitSafe(map[string]any{"type": "thinking", "text": "正在汇总结论…"})
			callMessages = append(append([]llm.Message{}, messages...), llm.Message{
				Role: "user",
				Content: "这是最后收口轮。不要再提出新的 curl/工具调用，也不要用文字伪造 tool_calls。" +
					"只能基于已执行结果给出结论；如证据还不够，明确说明还差什么。",
			})
			req.ToolChoice = "none"
		} else {
			emitSafe(map[string]any{"type": "thinking", "text": "正在分析…"})
		}
		chatResult, err := pool.Chat(ctx, req, "")
		if err != nil {
			return &AssistantReply{ErrorMsg: "LLM 调用失败: " + err.Error(), ToolLogs: toolLogs}
		}
		response := chatResult.Response
		if text := strings.TrimSpace(response.Content); text != "" {
			emitSafe(map[string]any{"type": "assistant_partial", "text": text})
		}
		assistantMsg := llm.Message{Role: "assistant", Content: response.Content}
		hasCalls := len(response.ToolCalls) > 0
		if hasCalls && !lastRound {
			assistantMsg.ToolCalls = response.ToolCalls
		}
		messages = append(messages, assistantMsg)

		if !hasCalls || lastRound {
			answer := strings.TrimSpace(response.Content)
			if looksLikeUnexecutedToolText(answer) {
				if !lastRound {
					messages = append(messages, llm.Message{
						Role: "user",
						Content: "你刚才用文字写了一个待执行的命令/工具调用，但后端没有真正执行它。" +
							"如果还需要验证，请下一轮使用 function calling 调用 http_request 或 run_shell；" +
							"如果不需要，就直接给出结论。",
					})
					continue
				}
				answer = "助手达到本次辅助验证轮数上限，最后一轮仍提出了新的未执行验证动作。" +
					"我没有把这段伪工具调用当作结论；请基于上方已执行的工具结果判断，或再次发起助手请求继续验证。"
			}
			if answer == "" {
				answer = fallbackAnswer(toolLogs)
			}
			// 持久化对话历史（问答各一条，回答带改稿 JSON 的旧通道保留给非流式端点）。
			recorded := answer
			if suggestedEdits != nil {
				if b, err := json.Marshal(map[string]any{"edits": suggestedEdits}); err == nil {
					recorded = answer + "\n\n```json\n" + string(b) + "\n```"
				}
			}
			appendAssistantMessage(&finding, message, recorded)
			emitSafe(map[string]any{"type": "final", "text": answer, "suggested_edits": suggestedEdits})
			return &AssistantReply{
				Reply: answer, Edits: suggestedEdits, ToolLogs: toolLogs,
				Model: chatResult.Endpoint.Model, BaseURL: chatResult.Endpoint.BaseURL,
				Usage: response.Usage,
			}
		}

		for _, call := range response.ToolCalls {
			if ctx.Err() != nil {
				return &AssistantReply{Reply: "已停止。", ToolLogs: toolLogs, Edits: suggestedEdits}
			}
			args := map[string]any{}
			if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
				args = map[string]any{}
			}
			name := call.Function.Name
			emitSafe(map[string]any{"type": "tool_call", "tool": name, "summary": assistantToolCallSummary(name, args)})
			var result map[string]any
			switch name {
			case "http_request":
				result = engine.AssistantHTTPRequest(ctx, args)
			case "run_shell":
				result = engine.AssistantRunShell(ctx, args)
			case "propose_report_edits":
				result = normalizeProposedEdits(args)
				if result["ok"] == true {
					if ed, ok := result["edits"].(map[string]any); ok && len(ed) > 0 {
						suggestedEdits = ed
						emitSafe(map[string]any{"type": "suggested_edits", "edits": suggestedEdits})
					}
				}
			default:
				result = map[string]any{"ok": false, "error": "未知工具: " + name}
			}
			toolLogs = append(toolLogs, map[string]any{"tool": name, "args": args, "result": result})
			emitSafe(map[string]any{"type": "tool_result", "tool": name, "summary": assistantToolResultSummary(name, result)})
			payload, _ := json.Marshal(result)
			messages = append(messages, llm.Message{
				Role:       "tool",
				ToolCallID: call.ID,
				Name:       name,
				Content:    utils.Truncate(string(payload), 3500),
			})
		}
	}

	answer := fallbackAnswer(toolLogs)
	emitSafe(map[string]any{"type": "final", "text": answer, "suggested_edits": suggestedEdits})
	return &AssistantReply{Reply: answer, Edits: suggestedEdits, ToolLogs: toolLogs}
}
