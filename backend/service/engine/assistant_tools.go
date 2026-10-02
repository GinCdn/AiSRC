package engine

// 报告助手受控执行器（对齐原版 findings.py 的 ToolExecutor：受控 http_request / run_shell，
// 破坏性动作需 confirm_destructive，输出清洗脱敏、限长）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"AiSRC/utils"
)

var (
	assistantMDURLRe = regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)\s]+)\)`)
	assistantURLRe   = regexp.MustCompile(`https?://[^\s<>()'"]+`)
)

// CleanAssistantURL 清洗模型给出的 URL：剥 markdown/反引号/尖括号，取首个 http(s) 链接。
func CleanAssistantURL(value string) string {
	text := strings.TrimSpace(value)
	text = strings.Trim(text, "`'\"<>")
	if m := assistantMDURLRe.FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(m[2])
	}
	if m := assistantURLRe.FindString(text); m != "" {
		return strings.TrimSpace(m)
	}
	return strings.TrimSpace(text)
}

// CleanAssistantShellCommand 清洗 shell 命令：剥续行错位（"\ -H" → " -H"）、markdown 链接。
func CleanAssistantShellCommand(command string) string {
	text := strings.ReplaceAll(command, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = assistantMDURLRe.ReplaceAllString(text, "$2")
	text = regexp.MustCompile(`\\[ \t]+(?=-{1,2}[A-Za-z])`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

// AssistantSafeTimeout 帮助函数：timeout 夹在 [1, upper]。
func AssistantSafeTimeout(value any, def, upper int) int {
	parsed := intOf(value)
	if parsed <= 0 {
		return def
	}
	if parsed > upper {
		return upper
	}
	return parsed
}

// AssistantHTTPRequest 报告助手受控 HTTP 请求（timeout 20s；非只读方法需显式确认）。
// 返回结构对齐原版 executor.http_request：ok/status/url/body。
func AssistantHTTPRequest(ctx context.Context, args map[string]any) map[string]any {
	url := CleanAssistantURL(stringArg(args, "url"))
	if url == "" {
		return map[string]any{"ok": false, "error": "http_request 缺少 url"}
	}
	method := strings.ToUpper(strings.TrimSpace(stringArg(args, "method")))
	if method == "" {
		method = "GET"
	}
	switch method {
	case "GET", "HEAD", "OPTIONS":
	default:
		if !boolArg(args, "confirm_destructive") {
			return map[string]any{
				"ok": false, "blocked": true,
				"error": fmt.Sprintf("%s 属写操作/主动探测：需 confirm_destructive=true 并在 confirm_reason 说明理由", method),
			}
		}
	}
	body := stringArg(args, "data")
	if body == "" {
		if raw, ok := args["json_body"]; ok && raw != nil {
			if b, err := json.Marshal(raw); err == nil {
				body = string(b)
			}
		}
	}
	state := newSessionState(url)
	exchange := doHTTP(ctx, state, httpCall{
		Method:          method,
		URL:             url,
		Headers:         anyMapToStringMap(args["headers"]),
		Body:            body,
		FollowRedirects: boolArg(args, "follow_redirects"),
		Timeout:         20 * time.Second,
	})
	if exchange.Error != "" {
		return map[string]any{"ok": false, "error": "请求失败：" + exchange.Error, "url": url}
	}
	respBody := utils.Truncate(utils.SanitizeSecretText(exchange.Body), 6000)
	return map[string]any{
		"ok":           true,
		"url":          url,
		"status_code":  exchange.StatusCode,
		"status_text":  http.StatusText(exchange.StatusCode),
		"content_type": exchange.Header.Get("Content-Type"),
		"body":         respBody,
		"body_len":     len(exchange.Body),
	}
}

// AssistantRunShell 报告助手受控命令执行（default 30s / 上限 90s；沿用 worker 安全守卫）。
func AssistantRunShell(ctx context.Context, args map[string]any) map[string]any {
	if !ShellEnabled() {
		return map[string]any{"ok": false, "error": "当前部署未开启命令执行工具（shell.enabled=false）"}
	}
	command := CleanAssistantShellCommand(stringArg(args, "command"))
	if command == "" {
		return map[string]any{"ok": false, "error": "run_shell 缺少 command"}
	}
	for _, pattern := range selfDestructPatterns {
		if pattern.MatchString(command) {
			return map[string]any{"ok": false, "blocked": true, "error": "命令被安全守卫拦截：疑似破坏性/自毁操作"}
		}
	}
	if strings.Contains(command, "rm -rf") && !strings.Contains(command, "./work") {
		return map[string]any{"ok": false, "blocked": true, "error": "命令被安全守卫拦截：禁止递归删除非工作目录"}
	}
	timeout := AssistantSafeTimeout(args["timeout"], 30, 90)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, shellBinary(), shellFlag(), command)
	output, err := cmd.CombinedOutput()
	text := utils.Truncate(utils.SanitizeSecretText(string(output)), 6000)
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return map[string]any{"ok": false, "timed_out": true, "return_code": nil, "output": text,
				"error": fmt.Sprintf("命令超时（%ds）", timeout)}
		}
		return map[string]any{"ok": false, "return_code": nil, "output": text,
			"error": fmt.Sprintf("命令退出异常：%v", err)}
	}
	return map[string]any{"ok": true, "return_code": 0, "output": text}
}
