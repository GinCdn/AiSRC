package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"AiSRC/service/llm"
	"AiSRC/utils"
)

// ==================== CyberStrike 3-gate 确认协议 ====================
//
// 任何「请求对类」漏洞（注入/越权/上传/验证码绕过等）在提交前必须经过
// 三个 gate，且由服务端强制执行，不信任模型的自我声明：
//
//	Gate 1（基线）：向目标发送无 payload 的正常请求，记录响应指纹；
//	Gate 2（攻击）：发送带 payload 的攻击请求，记录同样指纹；
//	Gate 3（对比）：由服务端重放两者并对比响应差异，差异可归因于 payload
//	                （状态码变化 / 标记回显 / 显著长度差 / 错误文案消失）
//	                才判定通过并签发 gate_token。
//
// submit_finding 对强制集合内的漏洞类型校验 gate_token，没有 token 直接拒绝。
// 这样堵住两类高发误报：①「看到可疑参数就报」（从未对比过基线）；
// ②「编造响应差异」（服务端重放结果不会说谎）。

// gateRequiredTypes 必须持有 gate_token 才能提交的漏洞类型集合。
var gateRequiredTypes = map[string]bool{
	"sql_injection":       true,
	"rce":                 true,
	"unauthorized_access": true,
	"idor":                true,
	"file_upload":         true,
	"captcha_bypass":      true,
}

// GateRecord 一次通过的 3-gate 验证记录。
type GateRecord struct {
	Token     string         `json:"token"`
	VulnType  string         `json:"vuln_type"`
	Fingerprint string       `json:"fingerprint"`
	VerifiedAt  string       `json:"verified_at"`
	Baseline  *gateObservation `json:"baseline"`
	Attack    *gateObservation `json:"attack"`
	Diff      *GateDiff        `json:"diff"`
}

// gateObservation 单次请求的响应观测摘要。
type gateObservation struct {
	Method      string `json:"method,omitempty"`
	URL         string `json:"url,omitempty"`
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	ContentType string `json:"content_type"`
	FinalURL    string `json:"final_url,omitempty"`
	BodyHead    string `json:"body_head"`
}

// statusLine 返回「METHOD URL -> HTTP 状态」单行摘要。
func (o *gateObservation) statusLine() string {
	if o == nil {
		return "(无观测)"
	}
	return fmt.Sprintf("%s %s -> HTTP %d", o.Method, o.URL, o.Status)
}

// GateDiff Gate 3 的对比结论。
type GateDiff struct {
	Pass           bool     `json:"pass"`
	StatusDiff     bool     `json:"status_diff"`
	LengthDiff     int      `json:"length_diff"`
	ContainsHit    bool     `json:"contains_hit"`
	NotContainsHit bool     `json:"not_contains_hit"`
	Signals        []string `json:"signals"`
	Reasons        []string `json:"reasons"`
}

// verifyFindingToolDef verify_finding 工具 schema（3-gate 执行器）。
func verifyFindingToolDef() llm.ToolDef {
	return llm.ToolDef{
		Name: "verify_finding",
		Description: "三步确认协议（3-gate）执行器：提交「基线请求 + 攻击请求」，由服务端依次重放并对比响应差异。" +
			"差异可归因于 payload 时签发 gate_token；sql_injection / rce / unauthorized_access / idor / " +
			"file_upload / captcha_bypass 六类漏洞提交 submit_finding 时必须携带该 token。" +
			"基线 = 去掉 payload 的正常请求；攻击 = 带 payload 的请求；expect 声明你预期出现的差异信号。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"vuln_type": map[string]any{
					"type":        "string",
					"description": "漏洞类型（与 submit_finding 的 vuln_type 一致）",
				},
				"baseline": map[string]any{
					"type":          "object",
					"description":   "Gate 1 基线请求：{method,url,headers,body}，不带 payload",
					"properties":    map[string]any{
						"method":  map[string]any{"type": "string", "description": "默认 GET"},
						"url":     map[string]any{"type": "string"},
						"headers": map[string]any{"type": "object"},
						"body":    map[string]any{"type": "string"},
					},
					"required": []string{"url"},
				},
				"attack": map[string]any{
					"type":          "object",
					"description":   "Gate 2 攻击请求：{method,url,headers,body}，带 payload",
					"properties":    map[string]any{
						"method":  map[string]any{"type": "string", "description": "默认 GET"},
						"url":     map[string]any{"type": "string"},
						"headers": map[string]any{"type": "object"},
						"body":    map[string]any{"type": "string"},
					},
					"required": []string{"url"},
				},
				"expect": map[string]any{
					"type": "object",
					"description": "Gate 3 预期差异声明（至少声明一项；全部缺省时走通用启发式：状态码变化或响应长度显著差异）",
					"properties": map[string]any{
						"status": map[string]any{
							"type":        "integer",
							"description": "攻击响应预期状态码",
						},
						"body_contains": map[string]any{
							"type":        "string",
							"description": "攻击响应体应包含的标记（推荐在 payload 中放唯一回显标记，如 x7q2m9）",
						},
						"body_not_contains": map[string]any{
							"type":        "string",
							"description": "攻击响应体不应包含的文案（如「验证码错误」「无权限」）",
						},
						"min_length_diff": map[string]any{
							"type":        "integer",
							"description": "攻击与基线响应的最小长度差（字节）",
						},
					},
				},
			},
			"required": []string{"vuln_type", "baseline", "attack"},
		},
	}
}

// handleVerifyFinding 执行 3-gate：重放基线与攻击请求，对比差异并签发/复用 gate_token。
func handleVerifyFinding(ctx context.Context, args map[string]any, session *WorkerSession) ToolResult {
	if session == nil {
		return ResultErr("会话不存在")
	}
	vulnType := strings.TrimSpace(stringArg(args, "vuln_type"))
	if vulnType == "" {
		return ResultErr("vuln_type 不能为空")
	}
	baselineCall := gateCallFromArgs(mapArg(args, "baseline"))
	attackCall := gateCallFromArgs(mapArg(args, "attack"))
	if baselineCall == nil || attackCall == nil {
		return ResultErr("baseline 与 attack 都必须提供（至少含 url）")
	}
	expect := mapArg(args, "expect")

	// 同一验证（类型+基线+攻击指纹）已通过时直接复用 token，避免重复消耗请求预算。
	fingerprint := gateFingerprint(vulnType, baselineCall, attackCall)
	if token := session.CachedGate(fingerprint); token != "" {
		if rec := session.GetGate(token); rec != nil {
			EmitInfo(session.TaskID, "worker", "gate_pass",
				fmt.Sprintf("3-gate 复用既有结论：%s @ %s", vulnType, displayGateURL(attackCall.URL)),
				map[string]any{"target_id": session.TargetID, "token": token, "reused": true})
			return ResultOK(fmt.Sprintf("该验证此前已通过（token 不变）。\ngate_token: %s\n%s", token, renderGateSummary(rec)))
		}
	}

	state := session.Session()
	// Gate 1：基线。
	baselineEx := doHTTP(ctx, state, *baselineCall)
	if baselineEx.Error != "" {
		return ResultErr("Gate 1 基线请求失败：" + baselineEx.Error)
	}
	// Gate 2：攻击。
	attackEx := doHTTP(ctx, state, *attackCall)
	if attackEx.Error != "" {
		return ResultErr("Gate 2 攻击请求失败：" + attackEx.Error)
	}
	// Gate 3：对比。
	baselineObs := newGateObservation(baselineCall, baselineEx)
	attackObs := newGateObservation(attackCall, attackEx)
	diff := compareGateResponse(baselineObs, attackObs, vulnType, expect)

	if !diff.Pass {
		EmitWarn(session.TaskID, "worker", "gate_fail",
			fmt.Sprintf("3-gate 未通过：%s @ %s（%s）", vulnType, displayGateURL(attackCall.URL), firstNonEmpty(diff.Reasons...)),
			map[string]any{"target_id": session.TargetID, "vuln_type": vulnType})
		return ResultErr("3-gate 未通过，不可提交该漏洞。\n" + renderGateFailure(baselineObs, attackObs, diff))
	}

	rec := &GateRecord{
		Token:       "gate-" + utils.ShortUUID(16),
		VulnType:    vulnType,
		Fingerprint: fingerprint,
		VerifiedAt:  utils.ToCSTISO(time.Now()),
		Baseline:    baselineObs,
		Attack:      attackObs,
		Diff:        diff,
	}
	session.PutGate(rec)

	EmitInfo(session.TaskID, "worker", "gate_pass",
		fmt.Sprintf("3-gate 通过：%s @ %s", vulnType, displayGateURL(attackCall.URL)),
		map[string]any{"target_id": session.TargetID, "vuln_type": vulnType, "token": rec.Token})

	return ResultOK(fmt.Sprintf("3-gate 通过（基线 %d/%dB → 攻击 %d/%dB）。\ngate_token: %s\n%s",
		baselineObs.Status, baselineObs.Length, attackObs.Status, attackObs.Length, rec.Token, renderGateSummary(rec)))
}

// gateCallFromArgs 把工具入参里的请求对象转成 httpCall。
func gateCallFromArgs(spec map[string]any) *httpCall {
	if spec == nil {
		return nil
	}
	rawURL := strings.TrimSpace(stringArg(spec, "url"))
	if rawURL == "" {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(stringArg(spec, "method")))
	if method == "" {
		method = "GET"
	}
	return &httpCall{
		Method:          method,
		URL:             rawURL,
		Headers:         anyMapToStringMap(spec["headers"]),
		Body:            stringArg(spec, "body"),
		FollowRedirects: false,
		Timeout:         30 * time.Second,
	}
}

// newGateObservation 从请求定义与响应构造观测摘要。
func newGateObservation(call *httpCall, exchange httpExchange) *gateObservation {
	body := exchange.Body
	head := utils.Truncate(body, 600)
	finalURL := exchange.FinalURL
	if finalURL == "" {
		finalURL = call.URL
	}
	return &gateObservation{
		Method:      call.Method,
		URL:         finalURL,
		Status:      exchange.StatusCode,
		Length:      len(body),
		ContentType: exchange.Header.Get("Content-Type"),
		FinalURL:    finalURL,
		BodyHead:    head,
	}
}

// compareGateResponse Gate 3：按 expect 声明 + 通用启发式判定差异是否可归因于 payload。
//
// 优先级：显式声明的信号任一命中即 PASS；无任何声明时退回启发式
// （状态码变化，或长度差 ≥ max(32, 基线长度 15%)）。所有信号都会写入
// diff.Signals 供 Reviewer 与人工复核。
func compareGateResponse(baseline, attack *gateObservation, vulnType string, expect map[string]any) *GateDiff {
	diff := &GateDiff{Signals: []string{}, Reasons: []string{}}
	if baseline == nil || attack == nil {
		diff.Reasons = append(diff.Reasons, "观测缺失，无法对比")
		return diff
	}
	diff.StatusDiff = baseline.Status != attack.Status
	diff.LengthDiff = attack.Length - baseline.Length

	expectStatus := intArg(expect, "status", 0)
	contains := strings.TrimSpace(stringArg(expect, "body_contains"))
	notContains := strings.TrimSpace(stringArg(expect, "body_not_contains"))
	minLengthDiff := intArg(expect, "min_length_diff", 0)

	declared := expectStatus > 0 || contains != "" || notContains != "" || minLengthDiff > 0

	if expectStatus > 0 {
		if attack.Status == expectStatus {
			diff.Signals = append(diff.Signals, fmt.Sprintf("攻击响应状态码 %d 符合预期", attack.Status))
		} else {
			diff.Reasons = append(diff.Reasons, fmt.Sprintf("预期攻击响应状态码 %d，实际 %d", expectStatus, attack.Status))
		}
	}
	if contains != "" {
		if strings.Contains(attack.BodyHead, contains) {
			diff.ContainsHit = true
			diff.Signals = append(diff.Signals, "payload 回显标记命中（body_contains）")
		} else {
			diff.Reasons = append(diff.Reasons, "攻击响应中未找到预期的回显标记（body_contains 未命中）")
		}
	}
	if notContains != "" {
		if !strings.Contains(attack.BodyHead, notContains) {
			diff.NotContainsHit = true
			diff.Signals = append(diff.Signals, "预期应消失的文案未出现（body_not_contains）")
		} else {
			diff.Reasons = append(diff.Reasons, fmt.Sprintf("攻击响应仍包含「%s」——防护未绕过或凭据未生效", notContains))
		}
	}
	if minLengthDiff > 0 {
		if absInt(diff.LengthDiff) >= minLengthDiff {
			diff.Signals = append(diff.Signals, fmt.Sprintf("响应长度差 %dB 达到预期阈值", absInt(diff.LengthDiff)))
		} else {
			diff.Reasons = append(diff.Reasons, fmt.Sprintf("响应长度差 %dB 未达到预期阈值 %dB", absInt(diff.LengthDiff), minLengthDiff))
		}
	}

	// 无任何显式声明：走通用启发式（防止模型偷懒不写 expect 就永远过不了）。
	if !declared {
		threshold := baseline.Length * 15 / 100
		if threshold < 32 {
			threshold = 32
		}
		if diff.StatusDiff {
			diff.Signals = append(diff.Signals, fmt.Sprintf("状态码变化：%d → %d", baseline.Status, attack.Status))
		}
		if absInt(diff.LengthDiff) >= threshold {
			diff.Signals = append(diff.Signals, fmt.Sprintf("响应长度差 %dB 超过启发式阈值 %dB", absInt(diff.LengthDiff), threshold))
		}
		if len(diff.Signals) == 0 {
			diff.Reasons = append(diff.Reasons,
				fmt.Sprintf("攻击响应与基线无显著差异（状态 %d→%d，长度 %d→%d）——payload 未生效或该参数不可注入",
					baseline.Status, attack.Status, baseline.Length, attack.Length))
		}
	}

	// 基线本身异常：验证设计有缺陷，即便信号命中也保守判 FAIL。
	if baseline.Status >= 500 {
		diff.Reasons = append(diff.Reasons, fmt.Sprintf("基线请求本身返回 %d——先修复基线（正常访问都失败说明打点或会话有问题）", baseline.Status))
	}

	diff.Pass = len(diff.Reasons) == 0 && (len(diff.Signals) > 0)
	if !diff.Pass && len(diff.Reasons) == 0 {
		diff.Reasons = append(diff.Reasons, "未观测到可归因于 payload 的响应差异")
	}
	return diff
}

// ==================== submit_finding 的 gate 校验与证据注入 ====================

// applyGateEvidence 校验 submit_finding 携带的 gate_token：
// 强制类型必须持有效 token；通过则把三步证据写入 finding.Evidence["gate"]，
// 并在模型偷懒时用攻击请求的原始报文补齐 raw_request / raw_response。
// 返回空串表示通过；非空为拒绝原因。
func applyGateEvidence(session *WorkerSession, finding *SubmittedFinding) string {
	if finding == nil || session == nil {
		return ""
	}
	if !gateRequiredTypes[strings.ToLower(strings.TrimSpace(finding.VulnType))] {
		return ""
	}
	token := strings.TrimSpace(finding.GateToken)
	if token == "" {
		return fmt.Sprintf(
			"%s 属于请求对类漏洞，必须先完成三步确认协议：调用 verify_finding 提交基线请求与攻击请求"+
				"（expect 里声明预期差异，推荐用唯一回显标记），通过后携带返回的 gate_token 重新提交。", finding.VulnType)
	}
	rec := session.GetGate(token)
	if rec == nil {
		return "gate_token 无效（不存在或已失效）。请重新调用 verify_finding 获取。"
	}
	if !strings.EqualFold(rec.VulnType, finding.VulnType) {
		return fmt.Sprintf("gate_token 与漏洞类型不匹配（token 是 %s，提交的是 %s）。请用正确类型重新验证。",
			rec.VulnType, finding.VulnType)
	}

	if finding.Evidence == nil {
		finding.Evidence = map[string]any{}
	}
	finding.Evidence["gate"] = map[string]any{
		"protocol":    "3-gate",
		"verdict":     "pass",
		"token":       rec.Token,
		"verified_at": rec.VerifiedAt,
		"baseline":    rec.Baseline,
		"attack":      rec.Attack,
		"diff":        rec.Diff,
	}
	if strings.TrimSpace(finding.RawRequest) == "" && rec.Attack != nil {
		finding.RawRequest = "（3-gate 攻击请求）" + rec.Attack.statusLine()
	}
	if strings.TrimSpace(finding.RawResponse) == "" && rec.Attack != nil {
		finding.RawResponse = utils.Truncate(rec.Attack.BodyHead, 2000)
	}
	return ""
}

// ==================== 辅助 ====================

func gateFingerprint(vulnType string, baseline, attack *httpCall) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(vulnType))))
	for _, call := range []*httpCall{baseline, attack} {
		h.Write([]byte{0})
		h.Write([]byte(call.Method))
		h.Write([]byte{0})
		h.Write([]byte(call.URL))
		h.Write([]byte{0})
		h.Write([]byte(call.Body))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func renderGateSummary(rec *GateRecord) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("基线：HTTP %d，%dB\n攻击：HTTP %d，%dB\n差异信号：",
		rec.Baseline.Status, rec.Baseline.Length, rec.Attack.Status, rec.Attack.Length))
	if len(rec.Diff.Signals) == 0 {
		sb.WriteString("(无)")
	} else {
		sb.WriteString(strings.Join(rec.Diff.Signals, "；"))
	}
	sb.WriteString("\n已写入验证证据，submit_finding 时携带上面的 gate_token 即可。")
	return sb.String()
}

func renderGateFailure(baseline, attack *gateObservation, diff *GateDiff) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("基线：HTTP %d，%dB\n攻击：HTTP %d，%dB\n",
		baseline.Status, baseline.Length, attack.Status, attack.Length))
	if len(diff.Reasons) > 0 {
		sb.WriteString("原因：" + strings.Join(diff.Reasons, "；") + "\n")
	}
	sb.WriteString("建议：确认 payload 确实生效（可先用 http_request 手工试探），" +
		"或在 expect 里给出更准确的预期（回显标记 / 目标状态码 / 长度差）。")
	return sb.String()
}

func displayGateURL(rawURL string) string {
	return utils.Truncate(rawURL, 120)
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return item
		}
	}
	return ""
}
