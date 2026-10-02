package engine

import (
	"fmt"
	"strings"
)

// 各阶段 System Prompt。与 AutoHunter 的提示词工程保持同构：
// Collector 负责资产搜集与预筛，Worker 负责挖洞，Reviewer 负责初审，
// Killsweep 负责通杀可行性分析，Escalation 负责扩大危害。

const CollectorSystemPrompt = `你是资产搜集与预筛规划器（Collector）。职责：

1. 依据任务给出的 SRC 口径（EduSRC / 企业SRC）、漏洞类型与规则，规划测绘引擎查询语法；
2. 对检索结果做探活、归属判定（是否属于目标行业）、优先级评分（0-100）；
3. 只排序不过滤：低分目标排在后面，但不得擅自丢弃；
4. 输出必须是严格 JSON，不要输出任何解释性文字。

评分维度（加权）：
- 归属置信度（单位名称/域名后缀/备案主体） 40 分
- 系统类型价值（后台/教务/OA/统一认证/文件服务） 30 分
- 组件指纹命中已知弱点（框架版本、默认页、中间件） 20 分
- 可达性（HTTP 状态、标题非默认页、非 CDN 静态页） 10 分

输出 JSON Schema：
{"targets":[{"url":"","host":"","title":"","org":"","school":"","is_edu":true,"priority_score":0,"priority_reason":""}]}`

const IntentParsePrompt = `你是测绘引擎查询语法生成器。把用户的自然语言意图翻译为目标引擎的查询语法。

要求：
1. 只输出一行查询字符串，不要输出解释、不要用 Markdown 代码块包裹；
2. 使用目标引擎支持的字段（如 title=、body=、host=、domain=、cert=、ip=、port=、status_code=），
   逻辑运算符使用 && 与 ||；
3. 不要臆造字段；不确定时优先使用 title= 与 body= 组合；
4. 若输入本身已是合法查询语法，原样返回。`

const WorkerSystemPrompt = `你是渗透测试执行 Agent（Worker），在获得明确授权的测试范围内工作。

工作方式：
1. 每轮先做信息收集（入口盘点、指纹识别、目录/接口探测），再选择最可能突破的路径；
2. 只使用已提供的工具；不要臆造执行结果，所有结论必须来自工具返回的真实数据；
3. 发现可疑点后必须走「三步确认协议」（3-gate）：调 verify_finding 提交
   baseline（去掉 payload 的正常请求）与 attack（带 payload 的请求），
   服务端会重放两者并对比响应差异，差异可归因于 payload 才签发 gate_token；
   sql_injection / rce / unauthorized_access / idor / file_upload / captcha_bypass
   六类漏洞提交 submit_finding 时必须携带 gate_token，没有会被拒绝。
   推荐 payload 中放唯一回显标记（如 x7q2m9）并在 expect.body_contains 断言它；
4. 严格不触碰破坏性操作：不得删除、篡改、批量写入业务数据，不得造成拒绝服务；
5. 越权类漏洞必须拿到他人数据的实际证据（脱敏后引用少量字段即可），不能仅凭接口返回 200 判定。

会话与凭据：
- 用户提供的 Cookie/账密已由系统在启动时注入或完成登录，http_request 会自动携带登录态，
  响应里的 Set-Cookie 也会自动吸收；不要反复无效登录，也不要每条请求手工贴 Cookie。
- 若你自行拿到新的 Cookie/Token/会话，用 session_set 登记一次，后续请求自动生效。
- 登录成功、拿到 session 本身不是漏洞，必须继续实证越权、敏感数据、敏感写操作。

产出要求：
- 确认漏洞时调用 submit_finding 工具提交，字段必须完整；六类请求对漏洞须携带 gate_token；
- submit_finding 时必须如实填写 self_check 自检（对照忽略清单：is_reflected_xss /
  needs_admin_login / needs_mitm / is_pure_info_leak / scanner_only_no_poc /
  is_public_interface / info_leak_hits_strict_list），有真实证据支撑才填 true，不许瞎猜；
- 覆盖义务：任务声明的每种漏洞类型都要有对应的尝试动作（看登录→越权/认证绕过，
  看上传→文件上传，看输入点→SQL 注入，看命令拼接→RCE，看验证码→captcha_bypass）；
  提交一个漏洞后必须继续排查其余类型与入口，直到把任务清单过完或确认无对应攻击面，
  不要「挖到一个就收工」；
- 本目标确无漏洞（或剩余类型确无攻击面）时调用 finish 工具，并给出检索过的路径摘要；
- 需要更多预算但已接近结束时，调用 need_more_budget 说明剩余验证步骤；
- 验证过的高价值经验（可用登录凭据/未授权端点/技术栈画像）随手调 report_intel
  沉淀到全局情报库，供同类系统目标复用；纯猜测不要报。

严禁：伪造证据、夸大影响、编造请求响应、在未验证情况下声称复现成功。`

const ReviewerSystemPrompt = `你是漏洞初审 Agent（Reviewer）。对 Worker 提交的漏洞做严格质检。

判定维度：
1. 在范围内（in_scope）：目标是否属于任务声明的资产范围与行业口径；
2. 可复现（reproduced）：请求/响应证据是否自洽、是否构成可判定的验证；
3. 危害成立（severity）：等级是否与证据匹配，是否夸大；
4. 重复（is_duplicate）：是否与既有漏洞同源（同 host 同类型同参数）。

输出严格 JSON：
{
  "verdict": "accepted|ignored|deepen",
  "confidence": "confirmed|likely|uncertain",
  "severity_final": "严重|高危|中危|低危|信息",
  "score": 0-100,
  "in_scope": true,
  "is_duplicate": false,
  "reproduced": true,
  "ignore_reasons": [],
  "downgrade_reasons": [],
  "reviewer_notes": "",
  "deepen_directive": ""
}

规则：
- evidence.gate 存在且 verdict=="pass" 表示服务端已按三步确认协议重放基线/攻击并确认差异，
  此时 reproduced 判 true 且置信度可上调；没有该证据时 reproduced 只能依据文本证据自行判定；
- verdict=deepen 时必须给出具体、可执行的 deepen_directive（要打什么接口、验证什么信号）；
- 证据不足但方向有价值 → deepen；方向本身无价值 → ignored；
- 不要因为「等级低」而 ignore，等级低但成立就 accepted 并降级。`

const KillsweepSystemPrompt = `你是通杀可行性分析 Agent（Killsweep）。

输入：一条已确认漏洞 + 该系统的指纹信息。
任务：判断这是否是「同一套通用产品/框架」的漏洞，从而可以一打一片。

输出严格 JSON：
{
  "is_killsweep": true,
  "product_name": "",
  "product_key": "",
  "confidence": "confirmed|likely|uncertain",
  "fofa_query": "",
  "fingerprint": "",
  "asset_count": 0,
  "edu_count": 0,
  "vuln_summary": "",
  "notes": ""
}

要求：
- product_key 必须归一化（小写、去版本号、去空格），同款系统必须得到同一个 key；
- fofa_query 必须是可直接执行的圈定同款系统的查询语法；
- 无法确认是通用产品时 is_killsweep=false 并说明原因；
- 严禁猜测资产规模，asset_count 仅填工具实际返回的数量。`

const EscalationSystemPrompt = `你是危害扩大 Agent（Escalation）。在已确认漏洞的基础上，评估并验证实际影响边界。

原则：
1. 只做「证明影响范围」所必需的最小操作；
2. 读取到他人数据时，仅在证据中记载脱敏样例（如姓名首字+星号、手机号中间四位掩码）；
3. 禁止批量导出、禁止修改/删除任何数据、禁止横向扩散到非授权范围；
4. 明确记录升级路径与边界，输出结构化结论。`

const ReportAssistantSystemPrompt = `你是漏洞报告助手。基于当前漏洞的真实数据，帮助用户完善报告、核对证据、校准等级。

规则：
1. 只依据给定上下文中的事实作答，不得编造请求、响应或影响；
2. 需要补充验证时，可调用 http_request 工具（仅限该目标域名）；需要跑简短验证命令（如 curl 对比）时用 run_shell；
3. 修改报告内容时，必须调用 propose_report_edits 返回结构化改稿，不要直接断言已修改；
4. 工具执行完要基于真实结果给结论，禁止用文字伪造工具调用；
5. 语气专业、简洁，面向 SRC 平台提交场景。`

// VulnTypeOptions 内置漏洞类型取值。
//
// 这些是接口契约里的原始取值（与原版 AutoHunter 前端 VULN_OPTIONS 完全一致），
// 前端负责映射为中文展示名。后端只做清洗与去重，不改变取值本身。
var VulnTypeOptions = []string{
	"sql_injection",
	"rce",
	"code_exec",
	"file_inclusion",
	"directory_traversal",
	"file_read",
	"unauthorized_access",
	"idor",
	"privilege_escalation",
	"file_upload",
	"captcha_bypass",
	"backdoor_compromised",
	"weak_password",
	"info_leak",
	"xss",
	"csrf",
	"ssrf",
	"xxe",
	"deserialization",
	"component_vuln",
	"business_logic",
}

// VulnTypeOption 带展示名的漏洞类型选项（供 /api/about 等只读接口使用）。
type VulnTypeOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// vulnTypeLabels 取值 → 中文展示名。
var vulnTypeLabels = map[string]string{
	"sql_injection":        "SQL 注入",
	"rce":                  "命令执行",
	"code_exec":            "代码执行",
	"file_inclusion":       "文件包含",
	"directory_traversal":  "目录遍历",
	"file_read":            "任意文件读取",
	"unauthorized_access":  "未授权",
	"idor":                 "水平越权",
	"privilege_escalation": "垂直越权",
	"file_upload":          "文件上传",
	"captcha_bypass":       "验证码绕过",
	"backdoor_compromised": "已控后门",
	"weak_password":        "弱口令",
	"info_leak":            "敏感信息泄露",
	"xss":                  "XSS",
	"csrf":                 "CSRF",
	"ssrf":                 "SSRF",
	"xxe":                  "XXE",
	"deserialization":      "反序列化",
	"component_vuln":       "组件漏洞",
	"business_logic":       "业务逻辑漏洞",
}

// VulnTypeLabel 返回漏洞类型的中文展示名；未知取值原样返回。
func VulnTypeLabel(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	if label, ok := vulnTypeLabels[key]; ok {
		return label
	}
	return value
}

// VulnTypeOptionsWithLabel 返回带中文展示名的完整选项列表。
func VulnTypeOptionsWithLabel() []VulnTypeOption {
	out := make([]VulnTypeOption, 0, len(VulnTypeOptions))
	for _, value := range VulnTypeOptions {
		out = append(out, VulnTypeOption{Value: value, Label: VulnTypeLabel(value)})
	}
	return out
}

// JoinVulnTypeLabels 把取值列表渲染为中文提示词片段；空列表回落为「通用」
// （与原版 collector_llm 的 '通用' 兜底一致）。
func JoinVulnTypeLabels(values []string) string {
	labels := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			labels = append(labels, VulnTypeLabel(value))
		}
	}
	if len(labels) == 0 {
		return "通用"
	}
	return strings.Join(labels, "、")
}

// DefaultVulnTypes 新建任务的默认漏洞类型（与原版前端「默认全开」一致）。
//
// 仅供前端表单初值参考；创建任务时后端不会强制注入该默认值，
// 与原版一致：缺省即空列表。
func DefaultVulnTypes() []string {
	return append([]string(nil), VulnTypeOptions...)
}

// SrcTypeLabel 返回口径中文名。
func SrcTypeLabel(srcType string) string {
	if srcType == "enterprise" {
		return "企业SRC"
	}
	return "EduSRC"
}

// NormalizeSrcType 归一化口径取值。
func NormalizeSrcType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "enterprise", "corp", "business":
		return "enterprise"
	default:
		return "edusrc"
	}
}

// BuildCollectorUserPrompt 组装 Collector 的用户消息。
func BuildCollectorUserPrompt(task *TaskBrief) string {
	var sb strings.Builder
	sb.WriteString("任务信息：\n")
	sb.WriteString(fmt.Sprintf("- 名称：%s\n", task.Name))
	sb.WriteString(fmt.Sprintf("- 口径：%s\n", SrcTypeLabel(task.SrcType)))
	sb.WriteString(fmt.Sprintf("- 漏洞类型：%s\n", JoinVulnTypeLabels(task.VulnTypes)))
	sb.WriteString(fmt.Sprintf("- 目标来源：%s\n", task.TargetSource))
	if task.Engine != "" {
		sb.WriteString(fmt.Sprintf("- 搜索引擎：%s\n", task.Engine))
	}
	if task.FofaQuery != "" {
		sb.WriteString(fmt.Sprintf("- 查询语法/协作重点：%s\n", task.FofaQuery))
	}
	if task.SrcRules != "" {
		sb.WriteString(fmt.Sprintf("- 附加规则：%s\n", task.SrcRules))
	}
	if len(task.ManualTargets) > 0 {
		sb.WriteString(fmt.Sprintf("- 手动目标数：%d\n", len(task.ManualTargets)))
	}
	sb.WriteString("\n请对下列候选资产做归属判定与优先级评分，输出 JSON：\n")
	sb.WriteString(task.CandidatesJSON)
	return sb.String()
}

// BuildWorkerKickoffPrompt 组装 Worker 的首轮用户消息。
func BuildWorkerKickoffPrompt(ctx *WorkerContext) string {
	var sb strings.Builder
	sb.WriteString("## 授权测试目标\n")
	sb.WriteString(fmt.Sprintf("- URL：%s\n", ctx.URL))
	sb.WriteString(fmt.Sprintf("- Host：%s\n", ctx.Host))
	if ctx.Title != "" {
		sb.WriteString(fmt.Sprintf("- 标题：%s\n", ctx.Title))
	}
	if ctx.Org != "" {
		sb.WriteString(fmt.Sprintf("- 归属：%s\n", ctx.Org))
	}
	sb.WriteString(fmt.Sprintf("\n## 任务口径\n- %s\n- 关注漏洞类型：%s\n", SrcTypeLabel(ctx.SrcType), JoinVulnTypeLabels(ctx.VulnTypes)))
	if ctx.SrcRules != "" {
		sb.WriteString(fmt.Sprintf("\n## 附加规则\n%s\n", ctx.SrcRules))
	}
	if ctx.LeakedCreds != "" {
		sb.WriteString(fmt.Sprintf("\n## 搜集阶段发现的泄露凭据线索\n%s\n", ctx.LeakedCreds))
	}
	if ctx.IntelHint != "" {
		sb.WriteString(fmt.Sprintf("\n## 历史情报（同类目标复用经验）\n%s\n", ctx.IntelHint))
	}
	if ctx.DeepenDirective != "" {
		sb.WriteString(fmt.Sprintf("\n## 人工打回深挖指令（本次必须优先完成）\n%s\n", ctx.DeepenDirective))
	}
	// 单站协作分工块：路线目标/检查清单/覆盖摘要/用户凭据引导已整体渲染好。
	if ctx.SiteCollabBlock != "" {
		sb.WriteString("\n")
		sb.WriteString(ctx.SiteCollabBlock)
	}
	sb.WriteString("\n请开始信息收集与漏洞挖掘。每轮先说明思路，再调用工具。\n")
	return sb.String()
}

// BuildReviewUserPrompt 组装 Reviewer 的用户消息。
func BuildReviewUserPrompt(finding *FindingBrief, existing []string) string {
	var sb strings.Builder
	sb.WriteString("## 待审核漏洞\n")
	sb.WriteString(fmt.Sprintf("- 标题：%s\n", finding.Title))
	sb.WriteString(fmt.Sprintf("- 类型：%s\n", finding.VulnType))
	sb.WriteString(fmt.Sprintf("- 声称等级：%s\n", finding.SeverityClaimed))
	sb.WriteString(fmt.Sprintf("- 目标：%s\n", finding.TargetURL))
	sb.WriteString(fmt.Sprintf("- 归属：%s\n", finding.Owner))
	sb.WriteString(fmt.Sprintf("\n### 描述\n%s\n", finding.Description))
	if len(finding.Steps) > 0 {
		sb.WriteString("\n### 复现步骤\n")
		for i, step := range finding.Steps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
	}
	if finding.Poc != "" {
		sb.WriteString(fmt.Sprintf("\n### PoC\n```\n%s\n```\n", truncateForPrompt(finding.Poc, 3000)))
	}
	if finding.RawRequest != "" {
		sb.WriteString(fmt.Sprintf("\n### 原始请求\n```\n%s\n```\n", truncateForPrompt(finding.RawRequest, 2000)))
	}
	if finding.RawResponse != "" {
		sb.WriteString(fmt.Sprintf("\n### 原始响应\n```\n%s\n```\n", truncateForPrompt(finding.RawResponse, 3000)))
	}
	if finding.AffectedScope != "" {
		sb.WriteString(fmt.Sprintf("\n### 影响范围\n%s\n", finding.AffectedScope))
	}
	if len(existing) > 0 {
		sb.WriteString("\n## 已有漏洞（用于查重）\n")
		for _, item := range existing {
			sb.WriteString("- " + item + "\n")
		}
	}
	sb.WriteString("\n请输出审核 JSON。\n")
	return sb.String()
}

// BuildKillsweepUserPrompt 组装通杀分析的用户消息。
func BuildKillsweepUserPrompt(finding *FindingBrief) string {
	var sb strings.Builder
	sb.WriteString("## 已确认漏洞\n")
	sb.WriteString(fmt.Sprintf("- 标题：%s\n", finding.Title))
	sb.WriteString(fmt.Sprintf("- 类型：%s\n", finding.VulnType))
	sb.WriteString(fmt.Sprintf("- 目标：%s\n", finding.TargetURL))
	sb.WriteString(fmt.Sprintf("- 归属：%s\n", finding.Owner))
	sb.WriteString(fmt.Sprintf("\n### 描述\n%s\n", truncateForPrompt(finding.Description, 2000)))
	if finding.Poc != "" {
		sb.WriteString(fmt.Sprintf("\n### PoC\n```\n%s\n```\n", truncateForPrompt(finding.Poc, 2000)))
	}
	if finding.RawResponse != "" {
		sb.WriteString(fmt.Sprintf("\n### 响应特征（用于提取指纹）\n```\n%s\n```\n", truncateForPrompt(finding.RawResponse, 2000)))
	}
	sb.WriteString("\n请判断该系统是否为通用产品，并输出通杀分析 JSON。\n")
	return sb.String()
}

// BuildReportAssistantContext 组装报告助手上下文。
func BuildReportAssistantContext(finding *FindingBrief, edits map[string]any) string {
	title := pickEditString(edits, "title", finding.Title)
	description := pickEditString(edits, "description", finding.Description)
	scope := pickEditString(edits, "affected_scope", finding.AffectedScope)
	poc := pickEditString(edits, "poc", finding.Poc)

	var sb strings.Builder
	sb.WriteString("## 当前报告数据\n")
	sb.WriteString(fmt.Sprintf("- 标题：%s\n", title))
	sb.WriteString(fmt.Sprintf("- 漏洞类型：%s\n", finding.VulnType))
	sb.WriteString(fmt.Sprintf("- 目标：%s\n", finding.TargetURL))
	sb.WriteString(fmt.Sprintf("- 归属：%s\n", finding.Owner))
	sb.WriteString(fmt.Sprintf("- 等级：%s\n", finding.SeverityClaimed))
	sb.WriteString(fmt.Sprintf("\n### 描述\n%s\n", description))
	if scope != "" {
		sb.WriteString(fmt.Sprintf("\n### 影响范围\n%s\n", scope))
	}
	if poc != "" {
		sb.WriteString(fmt.Sprintf("\n### PoC\n```\n%s\n```\n", truncateForPrompt(poc, 3000)))
	}
	if finding.RawRequest != "" {
		sb.WriteString(fmt.Sprintf("\n### 原始请求\n```\n%s\n```\n", truncateForPrompt(finding.RawRequest, 2000)))
	}
	if finding.RawResponse != "" {
		sb.WriteString(fmt.Sprintf("\n### 原始响应\n```\n%s\n```\n", truncateForPrompt(finding.RawResponse, 3000)))
	}
	return sb.String()
}

func pickEditString(edits map[string]any, key, fallback string) string {
	if edits == nil {
		return fallback
	}
	if value, ok := edits[key]; ok {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return text
		}
	}
	return fallback
}

func truncateForPrompt(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit]) + "\n...[已截断]"
}
