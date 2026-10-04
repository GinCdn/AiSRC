package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// ToolHandler 工具执行函数签名。
type ToolHandler func(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult

// Tool 一个可被 LLM 调用的工具。
type Tool struct {
	Def     llm.ToolDef
	Handler ToolHandler
}

// ToolRegistry 工具注册表。
type ToolRegistry struct {
	ordered []string
	tools   map[string]*Tool
}

// NewToolRegistry 创建空注册表。
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{tools: make(map[string]*Tool)}
}

// Register 注册一个工具。
func (r *ToolRegistry) Register(def llm.ToolDef, handler ToolHandler) {
	if _, exists := r.tools[def.Name]; !exists {
		r.ordered = append(r.ordered, def.Name)
	}
	r.tools[def.Name] = &Tool{Def: def, Handler: handler}
}

// Defs 返回全部工具定义（保持注册顺序）。
func (r *ToolRegistry) Defs() []llm.ToolDef {
	defs := make([]llm.ToolDef, 0, len(r.ordered))
	for _, name := range r.ordered {
		if tool, ok := r.tools[name]; ok {
			defs = append(defs, tool.Def)
		}
	}
	return defs
}

// DefsOf 只返回指定名字的工具定义。
func (r *ToolRegistry) DefsOf(names ...string) []llm.ToolDef {
	defs := make([]llm.ToolDef, 0, len(names))
	for _, name := range names {
		if tool, ok := r.tools[name]; ok {
			defs = append(defs, tool.Def)
		}
	}
	return defs
}

// Execute 执行工具。任何 panic 都被收敛为工具级错误，不影响 Worker 主循环。
func (r *ToolRegistry) Execute(ctx context.Context, name string, args map[string]any, session *WorkerSession) (result ToolResult) {
	tool, ok := r.tools[name]
	if !ok {
		return ResultErr(fmt.Sprintf("未知工具：%s", name))
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			detail := utils.SanitizeSecretText(fmt.Sprintf("%v", recovered))
			result = ResultErr("工具执行异常：" + detail)
		}
	}()
	return tool.Handler(ctx, args, session)
}

// ==================== 工具定义 ====================

// httpRequestTool HTTP 请求工具 schema。
func httpRequestToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "http_request",
		Description: "发起一次 HTTP 请求并返回状态码、响应头与响应体片段。用于资产探测与漏洞验证。已登记的会话态（Cookie/鉴权头）会自动携带，响应 Set-Cookie 会自动吸收。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"method": map[string]any{
					"type":        "string",
					"enum":        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
					"description": "HTTP 方法，默认 GET",
				},
				"url": map[string]any{"type": "string", "description": "完整请求 URL"},
				"headers": map[string]any{
					"type":        "object",
					"description": "请求头键值对",
				},
				"body": map[string]any{"type": "string", "description": "请求体（字符串）"},
				"follow_redirects": map[string]any{
					"type":        "boolean",
					"description": "是否跟随 302 跳转，默认 false",
				},
			},
			"required": []string{"url"},
		},
	}
}

// dnsLookupToolDef DNS 解析工具 schema。
func dnsLookupToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "dns_lookup",
		Description: "解析域名，返回 A/AAAA/CNAME 记录与归属信息线索。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host": map[string]any{"type": "string", "description": "待解析的主机名"},
			},
			"required": []string{"host"},
		},
	}
}

// submitFindingToolDef 提交漏洞工具 schema。
func submitFindingToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "submit_finding",
		Description: "提交一个已复现验证的漏洞。提交前必须先用真实工具取得证据（原始请求/响应包），" +
			"并如实填写 self_check 自检（对照当前 SRC 模式忽略清单）。" +
			"sql_injection / rce / unauthorized_access / idor / file_upload / captcha_bypass 六类" +
			"必须先调 verify_finding 通过三步确认，携带返回的 gate_token。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"vuln_type": map[string]any{"type": "string", "description": "漏洞类型，可选值：" +
					"sql_injection/rce/code_exec/file_inclusion/directory_traversal/file_read/" +
					"unauthorized_access/idor/privilege_escalation/file_upload/captcha_bypass/" +
					"backdoor_compromised/weak_password/info_leak/xss/csrf/ssrf/xxe/" +
					"deserialization/component_vuln/business_logic"},
				"title":            map[string]any{"type": "string", "description": "漏洞标题"},
				"severity_claimed": map[string]any{"type": "string", "enum": []string{"严重", "高危", "中危", "低危", "信息"}},
				"target_url":       map[string]any{"type": "string", "description": "可直接复现的完整 URL"},
				"owner":            map[string]any{"type": "string", "description": "归属单位及确认依据"},
				"description":      map[string]any{"type": "string", "description": "漏洞描述与成因"},
				"steps": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "可逐步复现的操作步骤",
				},
				"poc":            map[string]any{"type": "string", "description": "PoC 命令或请求报文"},
				"raw_request":    map[string]any{"type": "string", "description": "原始请求报文"},
				"raw_response":   map[string]any{"type": "string", "description": "原始响应片段"},
				"affected_scope": map[string]any{"type": "string", "description": "影响范围"},
				"gate_token": map[string]any{
					"type":        "string",
					"description": "verify_finding 三步确认通过后签发的凭证（六类请求对漏洞必填）",
				},
				"kill_chain": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"method": map[string]any{"type": "string"},
							"detail": map[string]any{"type": "string"},
						},
					},
					"description": "攻击链路步骤",
				},
				"evidence": map[string]any{"type": "object", "description": "结构化证据（命令/参数/响应差异等）"},
				// self_check：对齐原版 submit_finding schema（app/tools/schemas.py 183-196）。
				// worker 提交前的垃圾洞自检，reviewer 与前端报告页都消费这份数据。
				"self_check": map[string]any{
					"type":        "object",
					"description": "对照当前 SRC 模式忽略清单的自检，提交前如实填写",
					"properties": map[string]any{
						"is_reflected_xss":            map[string]any{"type": "boolean", "description": "是否为反射型 XSS（按当前 SRC 规则判断是否忽略/降级）"},
						"needs_admin_login":           map[string]any{"type": "boolean", "description": "是否需要登录管理员后台才能触发（会被忽略）"},
						"needs_mitm":                  map[string]any{"type": "boolean", "description": "是否需要中间人攻击（会被忽略）"},
						"is_pure_info_leak":           map[string]any{"type": "boolean", "description": "是否为无实际利用的信息泄露，如 phpinfo/内网IP/源码（会被忽略）"},
						"scanner_only_no_poc":         map[string]any{"type": "boolean", "description": "是否仅扫描器出结果但无法给出利用方法（会被忽略）"},
						"is_public_interface":         map[string]any{"type": "boolean", "description": "该接口是否本就是面向公众的公开接口（若是，访问它通常不构成漏洞）"},
						"info_leak_hits_strict_list":  map[string]any{"type": "boolean", "description": "若属信息泄露类：泄露数据是否命中当前 SRC 模式的高价值敏感数据口径"},
					},
					"required": []string{"is_reflected_xss", "needs_admin_login", "needs_mitm", "is_pure_info_leak", "scanner_only_no_poc"},
				},
			},
			"required": []string{"vuln_type", "title", "severity_claimed", "target_url", "description", "steps", "self_check"},
		},
	}
}

// finishToolDef 结束目标工具 schema。
func finishToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "finish",
		Description: "本目标已完成分析且无更多可挖点，结束该目标。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"summary": map[string]any{"type": "string", "description": "本轮检索过的路径与结论摘要"},
			},
			"required": []string{"summary"},
		},
	}
}

// needMoreBudgetToolDef 申请更多预算工具 schema。
func needMoreBudgetToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name:        "need_more_budget",
		Description: "预算即将用尽但仍有明确未完成的验证步骤时，请求追加轮次。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"reason": map[string]any{"type": "string", "description": "还需要做什么，为什么必需"},
			},
			"required": []string{"reason"},
		},
	}
}

// sessionSetToolDef 会话态登记工具 schema。
func sessionSetToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name: "session_set",
		Description: "登记/更新当前目标的会话态：注入 Cookie 或鉴权头（如手工登录后拿到的 session、" +
			"Authorization: Bearer）。登记后所有 http_request 自动携带，响应里的 Set-Cookie 也会自动吸收。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"cookies": map[string]any{
					"type":        "object",
					"description": "Cookie 键值对，如 {\"PHPSESSID\":\"abc\"}；也可直接给 Cookie 字符串",
				},
				"cookie": map[string]any{
					"type":        "string",
					"description": "Cookie 字符串形式（如 \"a=1; b=2\"），与 cookies 二选一",
				},
				"headers": map[string]any{
					"type":        "object",
					"description": "需要长期携带的请求头，如 {\"Authorization\":\"Bearer xxx\"}",
				},
				"url": map[string]any{
					"type":        "string",
					"description": "Cookie 作用域 URL，默认当前目标地址",
				},
				"clear": map[string]any{
					"type":        "boolean",
					"description": "是否先清空既有会话态，默认 false",
				},
			},
		},
	}
}

// runShellToolDef 受限命令执行工具 schema。
func runShellToolDef() llm.ToolDef {
	envText := "bash 语法与常见 Unix 工具（curl/grep/sed/awk 等）"
	if runtime.GOOS == "windows" && windowsBashPath() == "" {
		envText = "Windows cmd 语法（没有 grep/curl 等 Unix 工具，优先改用 http_request）"
	}
	return llm.ToolDef{
		Name:        "run_shell",
		Description: "在受控工作目录执行只读性质的安全工具命令（如 curl 探活、目录枚举）。执行环境：" + envText + "。禁止破坏性操作。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string", "description": "要执行的命令"},
				"timeout": map[string]any{"type": "integer", "description": "超时秒数，默认 30，最大 120"},
			},
			"required": []string{"command"},
		},
	}
}

// ==================== 工具实现 ====================

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 安全测试场景需接受自签证书
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	},
}

// handleHTTPRequest 执行 HTTP 请求（自动携带会话态、自动吸收 Set-Cookie）。
func handleHTTPRequest(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	state := session.Session()
	parsed := parseAuthURL(stringArg(args, "url"))
	before := state.cookieNames(parsed)

	exchange := doHTTP(ctx, state, httpCall{
		Method:          stringArg(args, "method"),
		URL:             stringArg(args, "url"),
		Headers:         anyMapToStringMap(args["headers"]),
		Body:            stringArg(args, "body"),
		FollowRedirects: boolArg(args, "follow_redirects"),
		Timeout:         35 * time.Second,
	})
	if exchange.Error != "" {
		return ResultErr("请求失败：" + exchange.Error)
	}

	// 响应若改写了会话 Cookie（如登录成功后下发 session），标记会话态已变化，
	// 让 Worker 下一轮把最新会话态注入提示词。
	if after := state.cookieNames(parsed); !equalStringSlices(before, after) {
		state.markDirty()
	}

	bodyText := utils.Truncate(exchange.Body, 8000)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d %s\n", exchange.StatusCode, http.StatusText(exchange.StatusCode)))
	sb.WriteString(fmt.Sprintf("Content-Type: %s\n", exchange.Header.Get("Content-Type")))
	if server := exchange.Header.Get("Server"); server != "" {
		sb.WriteString(fmt.Sprintf("Server: %s\n", server))
	}
	if location := exchange.Header.Get("Location"); location != "" {
		sb.WriteString(fmt.Sprintf("Location: %s\n", location))
	}
	if len(exchange.Applied) > 0 {
		sb.WriteString(fmt.Sprintf("会话态：已自动携带 %s\n", strings.Join(exchange.Applied, ", ")))
	}
	if names := setCookieNames(exchange.Header.Values("Set-Cookie")); len(names) > 0 {
		sb.WriteString(fmt.Sprintf("已吸收 Set-Cookie：%s（后续请求自动携带）\n", strings.Join(names, ", ")))
	}
	if exchange.FinalURL != "" && exchange.FinalURL != strings.TrimSpace(stringArg(args, "url")) {
		sb.WriteString(fmt.Sprintf("跳转终点：%s\n", exchange.FinalURL))
	}
	sb.WriteString("\n--- body ---\n")
	sb.WriteString(bodyText)

	title := extractHTMLTitle(bodyText)
	return ToolResult{
		Output: sb.String(),
		Meta: map[string]any{
			"status_code": exchange.StatusCode,
			"title":       title,
			"length":      len(exchange.Body),
			"final_url":   exchange.FinalURL,
		},
	}
}

// handleSessionSet 登记会话态（Cookie / 鉴权头），后续请求自动携带。
func handleSessionSet(_ context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if session == nil {
		return ResultErr("会话不存在")
	}
	state := session.Session()

	cookies := anyMapToStringMap(args["cookies"])
	if raw := strings.TrimSpace(stringArg(args, "cookie")); raw != "" {
		for name, value := range parseCookieString(raw) {
			if cookies == nil {
				cookies = map[string]string{}
			}
			cookies[name] = value
		}
	}
	headers := anyMapToStringMap(args["headers"])
	scope := parseAuthURL(stringArg(args, "url"))

	if boolArg(args, "clear") {
		state.clear()
	}
	state.apply(scope, cookies, headers)

	activeCookies := state.cookieNames(scope)
	activeHeaders := state.headerNames()
	if len(activeCookies) == 0 && len(activeHeaders) == 0 {
		return ResultErr("未提供任何有效 Cookie/Header，或作用域 URL 非法")
	}

	EmitInfo(session.TaskID, "worker", "tool_session_set",
		fmt.Sprintf("登记会话态：Cookie(%s) Header(%s)", strings.Join(activeCookies, ","), strings.Join(activeHeaders, ",")),
		map[string]any{
			"target_id":    session.TargetID,
			"cookie_names": activeCookies,
			"header_names": activeHeaders,
		})

	return ResultOK(fmt.Sprintf("会话态已更新：Cookie[%s] Header[%s]。后续 http_request 自动携带；请以该据点继续深挖受限接口。",
		strings.Join(activeCookies, ", "), strings.Join(activeHeaders, ", ")))
}

// handleDNSLookup 执行 DNS 解析。
func handleDNSLookup(ctx context.Context, args map[string]any, _ *WorkerSession) ToolResult {
	host := strings.TrimSpace(stringArg(args, "host"))
	if host == "" {
		return ResultErr("host 不能为空")
	}
	host = utils.NormalizeHost(host)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resolver := net.Resolver{}
	addrs, err := resolver.LookupHost(reqCtx, host)
	if err != nil {
		return ResultErr("解析失败：" + err.Error())
	}
	cname, _ := resolver.LookupCNAME(reqCtx, host)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("host: %s\n", host))
	if cname != "" && cname != host+"." {
		sb.WriteString(fmt.Sprintf("cname: %s\n", strings.TrimSuffix(cname, ".")))
	}
	sb.WriteString("addresses:\n")
	for _, addr := range addrs {
		sb.WriteString("  - " + addr + "\n")
	}
	root := utils.RootDomain(host)
	sb.WriteString(fmt.Sprintf("root_domain: %s\n", root))

	return ToolResult{
		Output: sb.String(),
		Meta:   map[string]any{"addresses": addrs, "root_domain": root},
	}
}

// handleSubmitFinding 接收 Worker 提交的漏洞。
func handleSubmitFinding(_ context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if session == nil {
		return ResultErr("会话不存在")
	}
	finding := parseSubmittedFinding(args)
	if finding.Title == "" || finding.VulnType == "" {
		return ResultErr("vuln_type 与 title 为必填项")
	}
	if len(finding.Steps) == 0 {
		return ResultErr("steps 不能为空，必须提供可复现步骤")
	}
	// 3-gate：请求对类漏洞必须持有有效验证凭证，证据由服务端重放产生。
	if reason := applyGateEvidence(session, finding); reason != "" {
		return ResultErr(reason)
	}
	// self_check 兜底为空对象（对齐原版 default=dict）：避免落库 NULL，
	// 前端报告页与 reviewer 读不到结构。模型漏填不拦——自检是辅助信号不是硬门槛。
	if finding.SelfCheck == nil {
		finding.SelfCheck = map[string]any{}
	}
	if err := session.SubmitFinding(finding); err != nil {
		return ResultErr("提交失败：" + err.Error())
	}
	return ResultOK(fmt.Sprintf("已受理漏洞「%s」（%s，%s）。请继续检查该目标是否还有其他漏洞，或调用 finish 结束。",
		finding.Title, finding.VulnType, finding.SeverityClaimed))
}

// handleFinish 结束当前目标。
//
// 守卫：存在「已通过 3-gate 验证但未提交」的发现时，第一次 finish 被拒绝并
// 列出待收割项（验证过却不提交 = 把已确认的漏洞白白丢掉）；模型若仍坚持
// 结束，第二次放行，避免死循环卡轮次。
func handleFinish(_ context.Context, args map[string]any, session *WorkerSession) ToolResult {
	summary := strings.TrimSpace(stringArg(args, "summary"))
	if session != nil {
		if pending := session.UnharvestedGates(); len(pending) > 0 && !session.gateWarned {
			session.gateWarned = true
			return ResultErr(fmt.Sprintf(
				"还有 %d 个已通过 3-gate 验证但尚未提交的发现（%s）。请先用对应 gate_token 调用 submit_finding 提交，"+
					"再调用 finish；确认放弃才可再次 finish。", len(pending), strings.Join(pending, "、")))
		}
		// 覆盖守卫（对齐原版 _premature_finish_reason 的精神，warned-once 不硬锁）：
		// 任务声明了多种漏洞类型但只提交过其中一部分时，提醒继续覆盖其余类型，
		// 避免「挖到一个 SQL 就收工」；模型确认收尾（第二次 finish）即放行。
		if untouched := session.UntouchedDeclaredTypes(); len(untouched) > 0 && !session.coverageWarned {
			session.coverageWarned = true
			return ResultErr(fmt.Sprintf(
				"当前只提交了 %s。任务还声明了这些类型尚未系统排查：%s。"+
					"请继续检查登录/越权/文件上传/验证码/命令执行等对应入口，发现线索就验证提交；"+
					"确认该目标确实只剩这些类型无攻击面时，再次调用 finish 即可结束。",
				strings.Join(session.SubmittedTypes(), "、"), strings.Join(untouched, "、")))
		}
		// 无发现且探索量不足时提醒（对齐原版：仅 N 轮、N 次工具动作不足以确认无洞）。
		if len(session.submitted) == 0 && session.Round < session.MaxRounds-2 && session.toolCalls < 6 {
			session.coverageWarned = true
			return ResultErr(fmt.Sprintf(
				"过早结束：仅 %d 轮、%d 次工具动作，不足以确认该目标无洞。"+
					"除非已明确证明目标不可达，或纯静态且无登录/表单/API/JS/可控参数，"+
					"否则继续覆盖首页、登录、API、JS 线索与高价值端点后再判断；确认无攻击面可再次 finish。",
				session.Round, session.toolCalls))
		}
		session.Finish(summary)
	}
	return ResultOK("已结束该目标。")
}

// handleNeedMoreBudget 记录追加预算请求，并如实回报剩余轮数。
//
// 旧实现只在「剩余不足 2 轮」时才真正追加，却对其他情况也回"已追加 4 轮"，
// 模型据此以为预算已放宽而继续探索，实际会在下一轮撞上硬上限。
func handleNeedMoreBudget(_ context.Context, args map[string]any, session *WorkerSession) ToolResult {
	reason := strings.TrimSpace(stringArg(args, "reason"))
	if session == nil {
		return ResultErr("当前无会话上下文，无法追加预算")
	}
	granted, remaining := session.RequestMoreBudget(reason)
	if !granted {
		return ResultOK(fmt.Sprintf("预算追加已达上限（%d 次）。当前剩余 %d 轮，"+
			"请立即调用 submit_finding 提交已有证据，或调用 finish 收尾。", budgetMaxGrant, remaining))
	}
	return ResultOK(fmt.Sprintf("已追加 %d 轮预算，当前剩余 %d 轮。"+
		"请优先完成未结的验证并调用 submit_finding 提交。", budgetExtendRounds, remaining))
}

// 自毁类命令拦截规则：只拦「会破坏运行环境或自身」的操作，不拦安全测试动作。
var selfDestructPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-rf\s+/(\s|$)`),
	regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\b`),
	regexp.MustCompile(`(?i)\bdd\s+if=.*of=/dev/`),
	regexp.MustCompile(`(?i):\(\)\s*\{\s*:\|:&\s*\};:`),
	regexp.MustCompile(`(?i)\bshutdown\b|\breboot\b|\bhalt\b`),
	regexp.MustCompile(`(?i)\bchmod\s+-R\s+777\s+/(\s|$)`),
	regexp.MustCompile(`(?i)\bkillall\b|\bpkill\s+-9\b`),
	regexp.MustCompile(`(?i)\buserdel\b|\bgroupdel\b`),
}

// handleRunShell 执行受限命令。
func handleRunShell(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if !ShellEnabled() {
		return ResultErr("当前部署未开启命令执行工具（shell.enabled=false）")
	}
	command := strings.TrimSpace(stringArg(args, "command"))
	if command == "" {
		return ResultErr("command 不能为空")
	}
	for _, pattern := range selfDestructPatterns {
		if pattern.MatchString(command) {
			return ResultErr("命令被安全守卫拦截：疑似破坏性/自毁操作")
		}
	}
	if strings.Contains(command, "rm -rf") && !strings.Contains(command, "./work") {
		return ResultErr("命令被安全守卫拦截：禁止递归删除非工作目录")
	}

	timeout := intArg(args, "timeout", 30)
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 120 {
		timeout = 120
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, shellBinary(), shellFlag(), command)
	if session != nil && session.WorkDir != "" {
		cmd.Dir = session.WorkDir
	}
	// 代理池：粘性出口注入 shell 环境（对齐原版 _shell_proxy_env；未启用时不注入）。
	if session != nil {
		ensureSessionProxy(session.Session())
		if proxyConn := session.Session().proxyURL; proxyConn != "" {
			cmd.Env = append(os.Environ(),
				"HTTP_PROXY="+proxyConn,
				"HTTPS_PROXY="+proxyConn,
				"ALL_PROXY="+proxyConn,
				"NO_PROXY=127.0.0.1,localhost",
			)
		}
	}
	output, err := cmd.CombinedOutput()
	text := utils.Truncate(utils.SanitizeSecretText(string(output)), 8000)
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return ToolResult{
				Output: fmt.Sprintf("命令超时（%ds）\n%s", timeout, text),
				Meta:   map[string]any{"timeout": true},
				IsErr:  true,
			}
		}
		return ToolResult{
			Output: fmt.Sprintf("命令退出异常：%v\n%s", err, text),
			Meta:   map[string]any{"exit_error": true},
			IsErr:  true,
		}
	}
	if text == "" {
		text = "(无输出)"
	}
	return ResultOK(text)
}

// 运行时开关（进程内 atomic 缓存）：由启动与 SaveSettings 调 ApplyRuntimeFlags 同步。
// 不直接读 LoadSystemSettings——那会每次查库，而 ShellEnabled 在 Emit/工具路径高频调用。
var (
	shellEnabledRuntime  atomic.Bool // 允许 Shell 执行（默认关）
	verboseEventsRuntime atomic.Bool // 记录噪音事件（默认关）
)

// ShellEnabled 是否启用命令执行工具。设置页「允许 Shell 执行」是唯一权威开关
//（默认关）。旧实现的 `Env=="debug" &&` 死门让生产模式下开关永远无效，已移除。
func ShellEnabled() bool {
	return shellEnabledRuntime.Load()
}

// VerboseEvents 是否把噪音事件（refill/skip 等）落库。设置页「记录噪音事件」开关。
func VerboseEvents() bool {
	return verboseEventsRuntime.Load()
}

// SetShellEnabled 动态开关（兼容旧调用，语义同 ApplyRuntimeFlags 的单字段版）。
func SetShellEnabled(enabled bool) { shellEnabledRuntime.Store(enabled) }

// SetVerboseEvents 动态开关「记录噪音事件」。
func SetVerboseEvents(enabled bool) { verboseEventsRuntime.Store(enabled) }

// ApplyRuntimeFlags 用系统设置同步进程内运行时开关。启动与设置保存后各调一次。
func ApplyRuntimeFlags(settings *model.SystemSettings) {
	SetShellEnabled(settings.Defaults.EffectiveShellEnabled())
	verboseEventsRuntime.Store(settings.Defaults.EffectiveVerboseEvents())
	applyProxySnapshot(settings)
}

// windowsBashPath 探测 bash（含 grep/sed/awk 等 Unix 工具，与提示词教给
// LLM 的命令语法一致）。覆盖：Git for Windows 固定路径、WorkBuddy 便携版
// Git、PATH 里的非 WSL bash。显式排除 System32 的 WSL bash（未装发行版时
// 直接报错）。探测结果进程内缓存。
var windowsBashPath = sync.OnceValue(func() string {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Git", "bin", "bash.exe"),
	}
	// WorkBuddy 便携版 Git：~/.workbuddy/binaries/PortableGit/versions/*/bin/bash.exe
	if home, err := os.UserHomeDir(); err == nil {
		if hits, _ := filepath.Glob(filepath.Join(home, ".workbuddy", "binaries", "PortableGit", "versions", "*", "bin", "bash.exe")); len(hits) > 0 {
			candidates = append(candidates, hits...)
		}
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if path, err := exec.LookPath("bash"); err == nil &&
		!strings.Contains(strings.ToLower(path), "system32") { // 排除 WSL bash
		return path
	}
	return ""
})

func shellBinary() string {
	if runtime.GOOS == "windows" {
		if bash := windowsBashPath(); bash != "" {
			return bash
		}
		return "cmd"
	}
	return "/bin/sh"
}

func shellFlag() string {
	if runtime.GOOS == "windows" {
		if windowsBashPath() != "" {
			return "-c"
		}
		return "/C"
	}
	return "-c"
}

// ==================== 参数与文本辅助 ====================

func stringArg(args map[string]any, key string) string {
	if value, ok := args[key]; ok {
		switch typed := value.(type) {
		case string:
			return typed
		case json.Number:
			return typed.String()
		case float64:
			return fmt.Sprintf("%v", typed)
		case bool:
			return fmt.Sprintf("%v", typed)
		}
	}
	return ""
}

func boolArg(args map[string]any, key string) bool {
	if value, ok := args[key]; ok {
		if flag, ok := value.(bool); ok {
			return flag
		}
	}
	return false
}

func intArg(args map[string]any, key string, fallback int) int {
	if value, ok := args[key]; ok {
		switch typed := value.(type) {
		case float64:
			return int(typed)
		case int:
			return typed
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return int(parsed)
			}
		case string:
			var parsed int
			if _, err := fmt.Sscanf(typed, "%d", &parsed); err == nil {
				return parsed
			}
		}
	}
	return fallback
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func mapSliceArg(args map[string]any, key string) []map[string]any {
	raw, ok := args[key]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if object, ok := item.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func mapArg(args map[string]any, key string) map[string]any {
	if object, ok := args[key].(map[string]any); ok {
		return object
	}
	return nil
}

func parseSubmittedFinding(args map[string]any) *SubmittedFinding {
	return &SubmittedFinding{
		VulnType:        strings.TrimSpace(stringArg(args, "vuln_type")),
		Title:           strings.TrimSpace(stringArg(args, "title")),
		SeverityClaimed: strings.TrimSpace(stringArg(args, "severity_claimed")),
		TargetURL:       strings.TrimSpace(stringArg(args, "target_url")),
		Owner:           strings.TrimSpace(stringArg(args, "owner")),
		Description:     strings.TrimSpace(stringArg(args, "description")),
		Steps:           stringSliceArg(args, "steps"),
		Poc:             stringArg(args, "poc"),
		RawRequest:      stringArg(args, "raw_request"),
		RawResponse:     stringArg(args, "raw_response"),
		AffectedScope:   stringArg(args, "affected_scope"),
		KillChain:       mapSliceArg(args, "kill_chain"),
		Evidence:        mapArg(args, "evidence"),
		SelfCheck:       mapArg(args, "self_check"),
		GateToken:       stringArg(args, "gate_token"),
	}
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractHTMLTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(match[1], " "))
}

// reportCoverageToolDef 单站协作覆盖上报工具 schema（仅 site 路线 worker 注册）。
func reportCoverageToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name: "report_coverage",
		Description: "单站协作覆盖记录：把本轮已验证的 API/入口与结论上报给同站其它路线 worker 复用，" +
			"系统会从高价值端点自动派生定向追打任务。没出洞也必须记录覆盖面；每个阶段至少上报一次。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"route": map[string]any{
					"type":        "string",
					"description": "路线来源，缺省取当前目标的协作路线",
				},
				"summary": map[string]any{
					"type":        "string",
					"description": "已覆盖的 API/入口与结论概括（必填，不能为空）",
				},
				"endpoints": map[string]any{
					"type":        "array",
					"description": "端点清单，每项 {method, path, status, checks, result}",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"method": map[string]any{"type": "string", "description": "HTTP 方法，默认 GET"},
							"path":   map[string]any{"type": "string", "description": "路径（相对或绝对 URL）"},
							"status": map[string]any{"type": "string", "description": "状态码或现象"},
							"checks": map[string]any{"type": "string", "description": "做了什么验证"},
							"result": map[string]any{"type": "string", "description": "结论/证据要点"},
						},
					},
				},
				"remaining": map[string]any{
					"type":        "string",
					"description": "剩余盲区/最值得分配给其它路线或追打的线索",
				},
			},
			"required": []string{"summary"},
		},
	}
}

// handleReportCoverage 单站协作覆盖记录：记入本轮会话，收尾时由 orchestrator
// 持久化为 coverage_reported 事件并派生 site_fXX 追打目标。
func handleReportCoverage(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if len(session.reportedCoverage) >= 12 {
		return ResultOK("本轮覆盖记录已足够，收尾时汇总即可。")
	}

	route := strings.TrimSpace(stringArg(args, "route"))
	if route == "" {
		route = session.routeSource
	}
	summary := truncateStr(strings.TrimSpace(stringArg(args, "summary")), 400)
	if summary == "" {
		return ResultErr("summary 不能为空：请概括已覆盖的 API/入口和结论。")
	}
	endpoints := make([]map[string]any, 0, 8)
	if rawList, ok := args["endpoints"].([]any); ok {
		for i, raw := range rawList {
			if i >= 20 {
				break
			}
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			method := strings.ToUpper(truncateStr(stringArg(item, "method"), 12))
			if method == "" {
				method = "GET"
			}
			path := truncateStr(firstNonEmptyString(stringArg(item, "path"), stringArg(item, "url")), 220)
			endpoints = append(endpoints, map[string]any{
				"method": method,
				"path":   path,
				"status": truncateStr(stringArg(item, "status"), 40),
				"checks": truncateStr(stringArg(item, "checks"), 120),
				"result": truncateStr(firstNonEmptyString(stringArg(item, "result"), stringArg(item, "note")), 180),
			})
		}
	}
	record := map[string]any{
		"route":     firstNonEmptyString(route, "site"),
		"summary":   summary,
		"endpoints": endpoints,
		"remaining": truncateStr(strings.TrimSpace(stringArg(args, "remaining")), 400),
	}
	session.reportedCoverage = append(session.reportedCoverage, record)
	// 即时落事件（活动流可见 + buildCoverageContext 复用同一份 kind）。
	EmitInfo(session.TaskID, "worker", "coverage_reported",
		fmt.Sprintf("覆盖上报[%s]：%s（端点 %d 个）", record["route"], utils.Truncate(summary, 180), len(endpoints)),
		map[string]any{
			"target_id": session.TargetID,
			"host":      session.hostKey,
			"route":     record["route"],
			"summary":   summary,
			"endpoints": endpoints,
			"remaining": record["remaining"],
		})
	return ResultOK("覆盖记录已记下，后续同站 worker 会看到摘要。继续补盲区或 finish。")
}

// reportIntelToolDef 全局情报上报工具 schema（所有 worker 注册，对齐原版 report_intel）。
func reportIntelToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name: "report_intel",
		Description: "全局情报上报：把本目标【已验证】的可复用经验沉淀到全局情报库，供后续同类系统目标的 worker 复用。" +
			"kind=cred（验证过能登录的凭据）/ endpoint（验证有效的未授权或敏感端点）/ profile（技术栈、WAF、突破口等画像）。" +
			"系统另会在出洞后按指纹自动提炼，无需重复上报指纹；只报已验证的信息，宁缺毋滥。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind": map[string]any{
					"type":        "string",
					"enum":        []string{"cred", "endpoint", "profile"},
					"description": "情报类型：cred=登录凭据 / endpoint=敏感端点 / profile=资产画像",
				},
				"payload": map[string]any{
					"type":        "object",
					"description": "按 kind 提供字段：cred={username,password}；endpoint={path,vuln_type}；profile={key,value}",
				},
				"summary": map[string]any{
					"type":        "string",
					"description": "一句话概括这条经验的用法（如「nacos 默认口令可进控制台」）",
				},
				"verified": map[string]any{
					"type":        "boolean",
					"description": "是否已经实际验证有效（true=verified，false=likely）",
				},
			},
			"required": []string{"kind", "payload"},
		},
	}
}

// handleReportIntel 全局情报记录：记入本轮会话（≤20 条防滥用），收尾时由
// orchestrator 沉淀到全局情报库（cred 按 root 域 / endpoint 按系统指纹 / profile 按 root 域）。
func handleReportIntel(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if len(session.reportedIntel) >= intelMaxReported {
		return ResultOK("本轮情报已上报足够，无需再报。")
	}
	kind := strings.ToLower(strings.TrimSpace(stringArg(args, "kind")))
	switch kind {
	case "cred", "endpoint", "profile":
	default:
		return ResultErr("kind 必须是 cred/endpoint/profile 之一。")
	}
	payload := mapArg(args, "payload")
	if len(payload) == 0 {
		return ResultErr("payload 必须是非空对象，按 kind 提供对应字段（cred={username,password} / endpoint={path,vuln_type} / profile={key,value}）。")
	}
	// 收敛 payload 字段（键 ≤50 字符、值 ≤300 字符、剔空），与收尾沉淀共用一套清洗。
	cleaned := map[string]any{}
	for k, v := range payload {
		key := truncateStr(strings.TrimSpace(k), 50)
		if key == "" {
			continue
		}
		text := truncateStr(strings.TrimSpace(fmt.Sprintf("%v", v)), intelMaxField)
		if text == "" || text == "<nil>" {
			continue
		}
		cleaned[key] = text
	}
	if len(cleaned) == 0 {
		return ResultErr("payload 内容为空。")
	}
	summary := truncateStr(strings.TrimSpace(stringArg(args, "summary")), 300)
	item := map[string]any{
		"kind":       kind,
		"payload":    cleaned,
		"summary":    summary,
		"confidence": "likely",
	}
	if boolArg(args, "verified") {
		item["confidence"] = "verified"
	}
	session.reportedIntel = append(session.reportedIntel, item)
	EmitInfo(session.TaskID, "worker", "intel_reported",
		fmt.Sprintf("情报上报[%s]：%s", kind, utils.Truncate(summary, 160)),
		map[string]any{
			"target_id":  session.TargetID,
			"host":       session.hostKey,
			"intel_kind": kind,
			"confidence": item["confidence"],
		})
	return ResultOK("情报已记录，将沉淀到全局情报库供后续 worker 复用。继续挖洞或 finish。")
}

// kaliToolDescription 动态生成 run_kali 工具描述（含用户启用的分类）。
func kaliToolDescription(settings *model.SystemSettings) string {
	enabled := map[string]bool{}
	for _, key := range settings.Kali.Categories {
		enabled[key] = true
	}
	var lines []string
	for _, c := range model.KaliCategories {
		if len(settings.Kali.Categories) == 0 || enabled[c.Key] {
			lines = append(lines, "- "+c.Label+"（"+c.Key+"）："+c.Desc)
		}
	}
	return "Kali 渗透机协调执行：把工具分类与执行目的交给系统与大模型协调出具体命令，" +
		"经安全过滤后通过 SSH 在 Kali 上执行并返回输出。可用分类：\n" +
		strings.Join(lines, "\n") +
		"\n仅限授权测试范围；禁止 DoS/破坏性命令（服务端硬拦截）。"
}

// runKaliToolDef Kali SSH 协调执行工具 schema（设置启用后注册）。
func runKaliToolDef(settings *model.SystemSettings) llm.ToolDef {
	return llm.ToolDef{
		Name:        "run_kali",
		Description: kaliToolDescription(settings),
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"category": map[string]any{
					"type":        "string",
					"description": "工具分类 key（如 info_gathering / web_analysis / password_attacks，见工具描述）",
				},
				"purpose": map[string]any{
					"type":        "string",
					"description": "本次执行目的（想达成什么，如「枚举目标子域」「验证弱口令」）",
				},
				"commands": map[string]any{
					"type":        "array",
					"description": "命令草案清单（系统会与大模型协调校正后执行）",
					"items":       map[string]any{"type": "string"},
				},
				"target": map[string]any{
					"type":        "string",
					"description": "目标 host/URL（命令针对的对象）",
				},
				"timeout_seconds": map[string]any{
					"type":        "integer",
					"description": "单条命令超时秒数，缺省 90，上限 300",
				},
			},
			"required": []string{"category", "purpose"},
		},
	}
}

// handleRunKali Kali 协调执行：先与大模型协调产出最终命令清单，再 SSH 执行。
func handleRunKali(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if !KaliEnabled() {
		return ResultErr("Kali SSH 未启用或未配置完整（系统设置 → Kali 集成）。")
	}
	settings := LoadSystemSettings()
	category := strings.ToLower(strings.TrimSpace(stringArg(args, "category")))
	enabled := len(settings.Kali.Categories) == 0
	for _, key := range settings.Kali.Categories {
		if key == category {
			enabled = true
			break
		}
	}
	if !enabled {
		return ResultErr("分类 " + category + " 未在 Kali 设置中启用。")
	}
	purpose := strings.TrimSpace(stringArg(args, "purpose"))
	if purpose == "" {
		return ResultErr("purpose 不能为空：说明本次执行目的。")
	}
	commands := stringSliceArg(args, "commands")
	target := strings.TrimSpace(stringArg(args, "target"))

	// ===== 大模型协调：校正/补全命令清单 =====
	finalCommands := commands
	advice := ""
	if session.pool != nil {
		coordReq := llm.Request{
			Messages: []llm.Message{
				{Role: "system", Content: "你是 Kali 渗透机命令协调器。根据工具分类、执行目的与命令草案，" +
					"产出最终要执行的命令清单（Kali Linux bash 可直接运行，每条一行，不带行号，" +
					"输出干净 JSON：{\"commands\":[\"...\"],\"advice\":\"一句话要点\"}，最多 8 条）。" +
					"草案合理就照用/微调，缺失就补全；禁止任何破坏性或拒绝服务命令。"},
				{Role: "user", Content: fmt.Sprintf(
					"分类：%s\n目的：%s\n目标：%s\n命令草案：%s",
					category, purpose, target, strings.Join(commands, "\n"))},
			},
			MaxTokens: 2048,
		}
		chatCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		if chatResult, err := chatAndRecord(chatCtx, session.pool, coordReq, ""); err == nil {
			if parsed, ok := parseKaliCoordination(chatResult.Response.Content); ok {
				if len(parsed.Commands) > 0 {
					finalCommands = parsed.Commands
				}
				advice = parsed.Advice
			}
		}
		cancel()
	}
	if len(finalCommands) == 0 {
		return ResultErr("命令清单为空：请给出 commands 草案。")
	}

	// ===== 安全硬拦截 =====
	allowed, rejected := FilterKaliCommands(finalCommands)
	if len(allowed) == 0 {
		return ResultErr("全部命令被安全拦截（破坏性/拒绝服务类）：" + strings.Join(rejected, "；"))
	}
	timeoutSeconds := intOf(args["timeout_seconds"])
	if timeoutSeconds <= 0 {
		timeoutSeconds = 90
	}
	if timeoutSeconds > 300 {
		timeoutSeconds = 300
	}

	// ===== SSH 执行 =====
	results, err := KaliExecute(ctx, allowed, time.Duration(timeoutSeconds)*time.Second)
	if err != nil {
		EmitWarn(session.TaskID, "worker", "kali_exec",
			"Kali 执行失败："+err.Error(),
			map[string]any{"target_id": session.TargetID, "category": category, "error": err.Error()})
		return ResultErr("Kali 执行失败：" + err.Error())
	}
	EmitInfo(session.TaskID, "worker", "kali_exec",
		fmt.Sprintf("Kali[%s] 执行 %d 条命令（协调建议：%s）", KaliCategoryLabel(category), len(results), utils.Truncate(advice, 100)),
		map[string]any{"target_id": session.TargetID, "category": category, "purpose": purpose,
			"commands": allowed, "rejected": rejected, "advice": advice, "results": results})

	var sb strings.Builder
	if advice != "" {
		sb.WriteString("协调建议：" + advice + "\n\n")
	}
	if len(rejected) > 0 {
		sb.WriteString("已拦截命令：" + strings.Join(rejected, "；") + "\n\n")
	}
	for _, item := range results {
		sb.WriteString("$ " + strOf(item["command"]) + "\n" + strOf(item["output"]) + "\n")
		if errText := strOf(item["error"]); errText != "" {
			sb.WriteString("[error] " + errText + "\n")
		}
		sb.WriteString("\n")
	}
	return ResultOK(utils.Truncate(strings.TrimSpace(sb.String()), 8000))
}

// parseKaliCoordination 解析协调器返回 JSON。
func parseKaliCoordination(text string) (struct {
	Commands []string `json:"commands"`
	Advice   string   `json:"advice"`
}, bool) {
	var out struct {
		Commands []string `json:"commands"`
		Advice   string   `json:"advice"`
	}
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &out); err == nil && len(out.Commands) > 0 {
		return out, true
	}
	if idx := strings.Index(text, "{"); idx >= 0 {
		if err := json.Unmarshal([]byte(text[idx:]), &out); err == nil && len(out.Commands) > 0 {
			return out, true
		}
	}
	return out, false
}

// imaSearchToolDef ima 知识库检索工具 schema（设置启用后注册）。
func imaSearchToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name: "ima_search",
		Description: "ima 知识库检索：按查询词检索用户配置的 ima/企业知识库，返回相关知识片段。" +
			"遇到需要企业内部知识、历史报告、资产背景、单位情报等场景时调用；普通技术问题不必调用。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "检索查询词（关键词或问题）",
				},
				"top_k": map[string]any{
					"type":        "integer",
					"description": "返回条数上限，缺省取系统配置",
				},
			},
			"required": []string{"query"},
		},
	}
}

// handleImaSearch ima 知识库检索工具回调。
func handleImaSearch(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	query := strings.TrimSpace(stringArg(args, "query"))
	if query == "" {
		return ResultErr("query 不能为空。")
	}
	result, err := ImaSearch(ctx, query, intOf(args["top_k"]))
	if err != nil {
		EmitWarn(session.TaskID, "worker", "ima_search",
			"ima 知识库检索失败："+err.Error(),
			map[string]any{"target_id": session.TargetID, "query": query, "error": err.Error()})
		return ResultErr("ima 知识库检索失败：" + err.Error())
	}
	EmitInfo(session.TaskID, "worker", "ima_search",
		fmt.Sprintf("ima 知识库检索：%s（命中 %d 字符）", utils.Truncate(query, 80), len(result)),
		map[string]any{"target_id": session.TargetID, "query": query})
	if strings.TrimSpace(result) == "" {
		return ResultOK("知识库无相关内容。")
	}
	return ResultOK(utils.Truncate(result, 6000))
}
