package engine

// 单站协作（site_collab）路线定义与聚合，对齐原版 app/agents/site_collab.py。
//
// FOFA 任务是广度优先；单站任务不同：同一个真实 host 由多个聚焦 worker 并发
// 进攻，每人负责一条路线，并把覆盖面回报给全队复用。

import (
	"fmt"
	"regexp"
	"strings"

	"AiSRC/model"
	"AiSRC/utils"
)

// SiteRoute 单站协作路线定义。
type SiteRoute struct {
	Source     string
	Label      string
	Priority   float64
	Focus      string
	Checklist  []string
	FinishRule string
	Phase      int // 0=侦察盘点 1=主题深挖 2=定向追打
}

// siteRoutes 七条固定路线（phase0 侦察两条 + phase1 主题五条）。
var siteRoutes = []*SiteRoute{
	{
		Source: "site_map", Label: "入口/API 盘点", Priority: 180.0, Phase: 0,
		Focus: "建立全站入口与 API 清单，优先覆盖 robots/sitemap/API 文档/前端路由/隐藏后台/非标路径。",
		Checklist: []string{
			"抓首页、robots.txt、sitemap.xml、常见 API 文档、登录页和跳转链，整理入口地图。",
			"提取 JS/HTML 中的 API base、路由、接口前缀、权限入口和上传/导入/导出路径。",
			"对每组 API 做最小 GET/OPTIONS/HEAD 或安全只读请求，标记公开/需登录/403/404/异常。",
			"用 report_coverage 记录已覆盖的路径簇和剩余最值得分配给其它路线的入口。",
		},
		FinishRule: "没有洞也必须说明 API/入口覆盖面和剩余盲区；发现强线索写 deepen_lead。",
	},
	{
		Source: "site_js", Label: "前端 JS/API/密钥", Priority: 170.0, Phase: 0,
		Focus: "围绕前端资源做 JS 审计，挖接口、token、对象存储、隐藏管理路由和未授权 API。",
		Checklist: []string{
			"抓取关联 JS，提取 API、路由、硬编码 key/token、OSS/STS/MinIO 线索。",
			"对提取出的每个高价值 API 做最小实证请求，区分公开接口、未授权、需登录和假阳性。",
			"遇到 token/key 先看结构再验证是否可用；不可用不要提交。",
			"用 report_coverage 记录已测试 API 前缀、接口样例和结论。",
		},
		FinishRule: "不能只停在接口清单；每个高价值接口至少做一次实证验证。",
	},
	{
		Source: "site_auth", Label: "认证/越权/会话", Priority: 160.0, Phase: 1,
		Focus: "测试登录、SSO/CAS、会话维持、IDOR、水平/垂直越权、默认口令和弱验证码。",
		Checklist: []string{
			"识别登录/认证流程、回调地址、票据、验证码、找回/注册/绑定等账号相关接口。",
			"对用户 ID、订单/文件/消息/部门/班级等对象参数做只读越权验证，必须有 before/after 或差异证据。",
			"如果拿到 session/token，先固定会话再测试受限 API；只登录成功本身不是洞。",
			"用 report_coverage 记录认证接口、对象参数、已尝试的越权维度和结论。",
		},
		FinishRule: "没有真实对象 ID 或状态差异就不交半成品；写清下一轮如何找 ID。",
	},
	{
		Source: "site_unauth", Label: "未授权/配置暴露", Priority: 150.0, Phase: 1,
		Focus: "测试 Swagger/Actuator/Nacos/Druid/.git/.env/备份/配置/日志/调试端点等暴露面。",
		Checklist: []string{
			"围绕 API 文档、actuator/env、nacos、druid、.git、.env、备份包、日志路径做小范围验证。",
			"401/403/跳登录只记鉴权存在，不当漏洞；200 也必须拿到配置、凭据、敏感数据或可操作能力。",
			"对配置/凭据必须继续验证可用性，无法验证就不要提交。",
			"用 report_coverage 记录已测试暴露面路径和状态码/证据。",
		},
		FinishRule: "只看到页面/文档不算洞；要落到可用配置、数据或操作能力。",
	},
	{
		Source: "site_file", Label: "文件/导入导出", Priority: 140.0, Phase: 1,
		Focus: "测试上传、附件、导入导出、模板下载、任意文件读取/覆盖、路径穿越和解析执行。",
		Checklist: []string{
			"枚举上传/附件/导入/导出/下载/预览/模板接口，先做只读或安全小样本验证。",
			"上传必须证明解析执行、越权读取、敏感覆盖或可控文件落点；txt 可访问不算洞。",
			"下载/预览要验证路径、ID、权限边界，不用破坏性写入。",
			"用 report_coverage 记录文件相关接口、参数和验证结论。",
		},
		FinishRule: "文件类要有真实影响；不能只报能上传普通文件。",
	},
	{
		Source: "site_inject", Label: "注入/RCE/模板表达式", Priority: 130.0, Phase: 1,
		Focus: "测试 SQL/NoSQL/命令/模板/表达式/反序列化/RCE 类入口，优先参数明确的 API。",
		Checklist: []string{
			"从 API 清单中挑有参数的查询、搜索、统计、导出、回调接口做 baseline vs payload 差异验证。",
			"优先布尔/时间/错误三类最小 PoC；遇 WAF 绕过后必须回测。",
			"RCE/命令/模板只做安全无害回显或延时验证，不做破坏性动作。",
			"用 report_coverage 记录已测参数、payload 类型和差异结论。",
		},
		FinishRule: "扫描器输出不等于洞；必须有可复现差异或原始请求响应。",
	},
	{
		Source: "site_logic", Label: "业务逻辑/状态流", Priority: 120.0, Phase: 1,
		Focus: "测试注册、审批、支付、报名、验证码、重放、状态流绕过和敏感写操作。",
		Checklist: []string{
			"找状态变化接口：register/save/update/delete/approve/pay/export/import/bind/reset 等。",
			"用安全对象验证重放、越权、缺验证码、顺序绕过、价格/数量/状态篡改等逻辑问题。",
			"写操作必须证明真实状态变化和影响，不对生产数据做破坏性改动。",
			"用 report_coverage 记录已测业务流程、状态接口和结论。",
		},
		FinishRule: "业务逻辑洞必须有前后状态差异；没有就写 no_vuln 或 deepen_lead。",
	},
}

var siteRouteBySource = func() map[string]*SiteRoute {
	m := make(map[string]*SiteRoute, len(siteRoutes))
	for _, r := range siteRoutes {
		m[r.Source] = r
	}
	return m
}()

// focusedRoute 定向 API 追打（site_fXX 虚拟路线，phase2）。
var focusedRoute = &SiteRoute{
	Source: "site_focus", Label: "定向 API 追打", Priority: 155.0, Phase: 2,
	Focus: "围绕前序 worker 发现的具体 API/路径做逐项验证，不重新泛泛侦察。",
	Checklist: []string{
		"先复现前序记录的基线请求，确认路径/方法/状态码真实存在。",
		"按指令逐项验证未授权、越权、注入、文件、逻辑或配置暴露，不跳到无关路径。",
		"每个参数/对象边界都要有 baseline vs payload/不同对象/不同状态的差异证据。",
		"最后用 report_coverage 写清这个路径簇测过什么、什么有价值、什么打不穿。",
	},
	FinishRule: "只围绕定向入口收敛；打穿就 submit_finding，差一步写 deepen_lead。",
}

// userPageRoute 指定页面直打（site_uXX 虚拟路线，phase2）。
// 用户在目标清单里逐行填写的具体页面（同一 host 下几十个不同 URL 很常见），
// 每个去重 URL 一条目标，worker 直接对该页面做漏洞挖掘，不做泛泛侦察。
var userPageRoute = &SiteRoute{
	Source: "site_page", Label: "指定页面直打", Priority: 165.0, Phase: 2,
	Focus: "用户逐条指定的具体页面，直接围绕该页面及其参数做漏洞实证，不从零泛扫全站。",
	Checklist: []string{
		"先请求该页面确认可达（记录状态码/跳转/登录墙），作为后续验证的基线。",
		"枚举页面的每个参数与功能点（输入框/上传/下载/跳转/ID），逐项做 baseline vs payload 差异验证。",
		"按页面功能对号入座：查询点测注入、上传点测文件、跳转点测开放重定向、ID 类测越权、回显点测 XSS。",
		"该页面打穿就 submit_finding；打不穿也要用 report_coverage 记录测过的参数与结论。",
	},
	FinishRule: "只围绕指定页面收敛；有实锤就 submit_finding，差一步写 deepen_lead，无货写清测了什么。",
}

// UserPageSource 指定页面目标的来源序号：site_u01…site_u99、site_u100…site_u999。
// 超出上限返回空串（调用方跳过）。序号进 source 是为了配合唯一索引
// ux_target_task_host(task_id, host, source)——同一 host 的多个页面各占一行。
func UserPageSource(seq int) string {
	if seq <= 0 || seq > 999 {
		return ""
	}
	if seq < 100 {
		return fmt.Sprintf("site_u%02d", seq)
	}
	return fmt.Sprintf("site_u%03d", seq)
}

// userPageReason 指定页面目标的优先级理由（含页面 URL，worker 渲染为定向指令）。
func userPageReason(pageURL string) string {
	reason := fmt.Sprintf("[单站协作] 指定页面直打 · 用户清单指定页面 %s，直接围绕该页面做漏洞实证", pageURL)
	if len(reason) > 300 {
		reason = reason[:300]
	}
	return reason
}

// 开局并发入队的全部固定路线（侦察 + 主题深挖一起抢 worker，不串行苦等）。
var initialRoutes = append(append([]*SiteRoute{}, discoveryRoutes()...), followupRoutes()...)

func discoveryRoutes() []*SiteRoute {
	out := make([]*SiteRoute, 0, 2)
	for _, r := range siteRoutes {
		if r.Phase == 0 {
			out = append(out, r)
		}
	}
	return out
}

func followupRoutes() []*SiteRoute {
	out := make([]*SiteRoute, 0, 5)
	for _, r := range siteRoutes {
		if r.Phase > 0 {
			out = append(out, r)
		}
	}
	return out
}

// skippableReconSources 开启「跳过入口盘点」时被跳过的侦察路线。
var skippableReconSources = map[string]bool{"site_map": true}

var siteFocusSourceRe = regexp.MustCompile(`^site_f\d{2}$`)

var siteUserPageSourceRe = regexp.MustCompile(`^site_u\d{2,3}$`)

// IsSiteSource 是否单站协作路线来源（site_*）。
func IsSiteSource(source string) bool {
	return strings.HasPrefix(source, "site_")
}

// RouteForSource 把任意 site source（含 site_fXX 追打、site_uXX 指定页面）映射到路线定义。
func RouteForSource(source string) *SiteRoute {
	source = strings.TrimSpace(source)
	if siteFocusSourceRe.MatchString(source) {
		return focusedRoute
	}
	if siteUserPageSourceRe.MatchString(source) {
		return userPageRoute
	}
	return siteRouteBySource[source]
}

// RouteReason 路线入队的优先级理由（入目标表 priority_reason）。
func RouteReason(route *SiteRoute) string {
	focus := route.Focus
	if len(focus) > 120 {
		focus = focus[:120]
	}
	return fmt.Sprintf("[单站协作] %s · %s", route.Label, focus)
}

// SkipReconEnabled 任务是否开启「跳过入口盘点侦察」（fofa_config.skip_site_recon）。
func SkipReconEnabled(task *model.Task) bool {
	return task != nil && task.FofaConfig.SkipSiteRecon
}

// InitialRoutesFor 按任务配置返回开局入队的路线。
func InitialRoutesFor(task *model.Task) []*SiteRoute {
	if SkipReconEnabled(task) {
		out := make([]*SiteRoute, 0, len(initialRoutes))
		for _, r := range initialRoutes {
			if !skippableReconSources[r.Source] {
				out = append(out, r)
			}
		}
		return out
	}
	return initialRoutes
}

// 用户在自由文本里给出的登录凭据/登录态识别特征（宁可宽松命中）。
var credSignals = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(账号|帐号|账户|用户名|登录名|user(?:name)?|account|login)\s*[:：=]\s*\S+`),
	regexp.MustCompile(`(?i)(密码|口令|passwd|password|pwd|pass)\s*[:：=]\s*\S+`),
	regexp.MustCompile(`(?i)\bcookie\s*[:：]\s*\S+`),
	regexp.MustCompile(`(?i)\bauthorization\s*[:：]\s*\S+`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{10,}`),
	regexp.MustCompile(`(?i)\b(JSESSIONID|PHPSESSID|SESSION|SESSID|sid|token|access_token|CASTGC)\s*=\s*\S+`),
	regexp.MustCompile(`(?i)(已有|提供|给你|附上|如下).{0,6}(账号|帐号|账户|登录|凭据|凭证|cookie|token|session)`),
}

// DetectUserCredentials 判断用户文本里是否明确给出可登录的账号密码/登录态。
// 误判成本只是多一段引导文字；漏判成本是 agent 忽略用户凭据不去登录。
func DetectUserCredentials(siteInfo string) bool {
	text := strings.TrimSpace(siteInfo)
	if text == "" {
		return false
	}
	for _, re := range credSignals {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

const userCredDirective = "# ⚠ 用户已提供登录凭据 —— 必须登录并进系统深入\n" +
	"上方「用户提供的目标相关信息」里含用户主动给出的账号密码 / Cookie / Token / 登录态。" +
	"这是用户明确授权你使用的入场券，必须执行以下动作，不得跳过：\n" +
	"1. 【先登录】用给出的账号密码走登录接口，或直接把给出的 Cookie/Authorization 用 session_set 登记；" +
	"拿到登录态后 session_set 会让后续 http_request 自动携带，不要每次手动拼 Cookie 也不要忘带。\n" +
	"   ⚠ 登录若是表单/CAS/SSO：先 GET 登录页取隐藏字段（CAS 的 lt/execution、表单的 csrf token），" +
	"再带账号密码+隐藏字段 POST 登录接口，且 http_request 必须设 follow_redirects=true——" +
	"一次即可自动走完 302 连环跳、每跳 Cookie 自动入会话；看返回 redirect_chain/final_url 判成败。\n" +
	"2. 【判成败】登录成功的判据：拿到 Set-Cookie/有效 session、能访问到需登录才可见的页面/接口（非跳登录、非 401/403）。" +
	"确认登录成功后，登录本身不是洞、绝不能就此 finish。\n" +
	"3. 【进系统深入】带着登录态进入系统内部逐项深挖：翻后台/个人中心/管理菜单，测越权(IDOR/水平垂直)、" +
	"遍历他人对象、敏感数据读取、上传/导入、敏感写操作、配置与凭据泄露、受限 API。至少实证一项够格危害才 submit_finding。\n" +
	"4. 【登不进/无货】若凭据登录失败，明确记录失败现象；若登进去但确无可深挖危害，用 finish 的 deepening 摘要写清" +
	"「已用此登录态到达哪里、下一轮该拿它打哪个系统/接口、取什么数据」，不要空手收摊。\n" +
	"纪律：只登录成功 / 只进个人中心 / 只写「可能可以访问 X」都不算洞；必须有登录态下的实锤危害。严禁改密。\n"

// RenderContext 渲染单站协作分工上下文块（注入 worker 提示词）。
func RenderContext(route *SiteRoute, siteInfo, coverageBlock, focusNote string, skipRecon bool) string {
	lines := []string{
		"# 单站协作分工",
		fmt.Sprintf("- 当前路线：%s", route.Label),
		fmt.Sprintf("- 路线目标：%s", route.Focus),
		"- 协作规则：只围绕当前站点行动；你负责把本路线测扎实，不要重复其它路线已经覆盖的点。",
		"- 覆盖要求：发现 API/入口后要逐项做最小安全验证；没出洞也要用 report_coverage 记录覆盖面。",
		"- 收敛规则：能打穿就 submit_finding；有明确据点但差一步就写覆盖摘要里的追打线索；无实证不要交半成品。",
	}
	if route.Phase > 0 {
		lines = append(lines,
			"- 深挖纪律：你是【深挖路线】不是浅扫。围绕本路线 focus 把每个候选入口都测到有结论——"+
				"打穿就 submit_finding；差一步（有据点但缺 ID/凭据/回显）就在覆盖摘要里写追打线索，"+
				"系统会自动接力深挖；确认无洞也要说清测了哪些入口、为何不通。不要首页加几个常见路径扫一遍就 finish。")
		if skipRecon {
			lines = append(lines,
				"- 侦察说明：本次已关闭「入口盘点」泛侦察（通常因为你已拿到登录凭据或目标明确）。"+
					"site_js 前端资源侦察仍在并发跑、成果会陆续上报；除此之外别再从零泛扒全站，"+
					"直接按本路线 focus 定位相关入口（如认证路线直奔登录/越权接口）就开打，边测边深挖。")
		} else {
			lines = append(lines,
				"- 复用侦察：site_map/site_js 侦察路线与你并发在跑，成果会陆续上报。"+
					"下方【若已有覆盖摘要】就优先在这些已知入口上做本路线的定向验证，别从零重复侦察；"+
					"【若暂无覆盖摘要】说明侦察还在跑，你直接按本路线 focus 自己快速摸一遍相关入口就开打，"+
					"不要空等侦察——先扒首页/JS 找本路线相关接口（如认证路线找登录/越权接口），边测边深挖。")
		}
	}
	if info := strings.TrimSpace(siteInfo); info != "" {
		if len(info) > 2000 {
			info = info[:2000]
		}
		lines = append(lines, "", "# 用户提供的目标相关信息", info)
		if DetectUserCredentials(info) {
			lines = append(lines, "", strings.TrimRight(userCredDirective, "\n"))
		}
	}
	if block := strings.TrimSpace(coverageBlock); block != "" {
		lines = append(lines, "", block)
	}
	if note := strings.TrimSpace(focusNote); note != "" {
		if len(note) > 1800 {
			note = note[:1800]
		}
		lines = append(lines, "", "# 本轮定向追打指令", note, "不要把这条指令当作已验证结论；必须重新做最小实证请求。")
	}
	lines = append(lines, "", "# 本路线检查清单")
	for _, item := range route.Checklist {
		lines = append(lines, "- "+item)
	}
	lines = append(lines, "", fmt.Sprintf("# 本路线结束标准\n%s", route.FinishRule))
	return strings.Join(lines, "\n") + "\n\n"
}

// ---------------- 协作态势聚合（看板面板） ----------------

// collabPhases 三阶段元数据（前端「协作态势」面板渲染用）。
var collabPhases = []map[string]any{
	{"phase": 0, "key": "recon", "label": "侦察盘点",
		"desc": "site_map / site_js 摸清全站入口、API 与前端密钥"},
	{"phase": 1, "key": "theme", "label": "主题深挖",
		"desc": "认证越权 / 未授权配置 / 文件 / 注入RCE / 业务逻辑 五路分头深挖"},
	{"phase": 2, "key": "focus", "label": "定向追打",
		"desc": "围绕侦察发现的具体 API 逐项验证打穿"},
}

// collapseCards 同名路线合并成一张卡，避免侦察/主题深挖把页面撑爆。
func collapseCards(cards []map[string]any) []map[string]any {
	grouped := map[string]map[string]any{}
	var order []string
	var leftover []map[string]any
	for _, card := range cards {
		if card["is_aggregate"] == true {
			leftover = append(leftover, card)
			continue
		}
		key, _ := card["label"].(string)
		if key == "" {
			key, _ = card["source"].(string)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			key = "路线"
		}
		status, _ := card["status"].(string)
		if status == "" {
			status = "done"
		}
		findings := asInt(card["findings"])
		deepen := asInt(card["deepen_count"])
		item, ok := grouped[key]
		if !ok {
			order = append(order, key)
			grouped[key] = map[string]any{
				"source": card["source"], "label": card["label"], "focus": card["focus"],
				"status": status, "verdict": card["verdict"],
				"findings": findings, "deepen_count": deepen,
				"count": 1,
				"running": boolToInt(status == "running"), "queued": boolToInt(status == "queued"),
				"done": boolToInt(status == "done"),
			}
			continue
		}
		item["count"] = asInt(item["count"]) + 1
		item["findings"] = asInt(item["findings"]) + findings
		item["deepen_count"] = asInt(item["deepen_count"]) + deepen
		item[status] = asInt(item[status]) + 1
		if status == "running" || (status == "queued" && item["status"] != "running") {
			item["status"] = status
		}
	}
	out := make([]map[string]any, 0, len(order)+len(leftover))
	for _, key := range order {
		out = append(out, grouped[key])
	}
	return append(out, leftover...)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// BuildCollabOverview 把该任务的 site 路线聚合成前端可直接渲染的「协作态势」结构。
//
// rows 每条字段：source, status, verdict, priority_reason, findings(int), deepen_count(int)。
// 非 site 任务（无 site 来源行）返回 nil，前端面板隐藏。
func BuildCollabOverview(rows []map[string]any) map[string]any {
	siteRows := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		src, _ := r["source"].(string)
		if IsSiteSource(src) {
			siteRows = append(siteRows, r)
		}
	}
	if len(siteRows) == 0 {
		return nil
	}

	runningSet := map[string]bool{"assigned": true, "scanning": true}
	statusOf := func(r map[string]any) string {
		s := strings.ToLower(strOf(r["status"]))
		switch {
		case runningSet[s]:
			return "running"
		case s == "queued":
			return "queued"
		default:
			return "done"
		}
	}

	buckets := map[int][]map[string]any{0: {}, 1: {}, 2: {}}
	focusAgg := map[string]int{"total": 0, "running": 0, "queued": 0, "done": 0, "findings": 0}

	for _, r := range siteRows {
		src := strOf(r["source"])
		route := RouteForSource(src)
		if route == nil {
			continue
		}
		st := statusOf(r)
		fcount := asInt(r["findings"])
		if route.Phase == 2 { // 追打路线聚合
			focusAgg["total"]++
			focusAgg[st]++
			focusAgg["findings"] += fcount
			continue
		}
		buckets[route.Phase] = append(buckets[route.Phase], map[string]any{
			"source": src, "label": route.Label, "focus": route.Focus,
			"status": st, "verdict": strOf(r["verdict"]),
			"findings": fcount, "deepen_count": asInt(r["deepen_count"]),
		})
	}

	// 追打聚合成单张卡塞进 phase2（有才显示）。
	if focusAgg["total"] > 0 {
		aggStatus := "done"
		if focusAgg["running"] > 0 {
			aggStatus = "running"
		} else if focusAgg["queued"] > 0 {
			aggStatus = "queued"
		}
		buckets[2] = append(buckets[2], map[string]any{
			"source": "site_focus", "label": focusedRoute.Label, "focus": focusedRoute.Focus,
			"status": aggStatus, "verdict": "",
			"findings": focusAgg["findings"], "deepen_count": 0,
			"is_aggregate": true, "count": focusAgg["total"],
			"running": focusAgg["running"], "queued": focusAgg["queued"], "done": focusAgg["done"],
			"aggregate": map[string]any{"total": focusAgg["total"], "running": focusAgg["running"],
				"queued": focusAgg["queued"], "done": focusAgg["done"], "findings": focusAgg["findings"]},
		})
	}

	phasesOut := make([]map[string]any, 0, len(collabPhases))
	for _, meta := range collabPhases {
		phase := asInt(meta["phase"])
		cards := collapseCards(buckets[phase])
		running, queued, done, findings := 0, 0, 0, 0
		for _, c := range cards {
			running += asInt(c["running"])
			queued += asInt(c["queued"])
			done += asInt(c["done"])
			findings += asInt(c["findings"])
			if st, _ := c["status"].(string); st == "running" && asInt(c["running"]) == 0 {
				running++
			} else if st == "queued" && asInt(c["queued"]) == 0 {
				queued++
			} else if st == "done" && asInt(c["done"]) == 0 {
				done++
			}
		}
		state := "idle"
		switch {
		case len(cards) == 0:
			state = "idle"
		case running > 0:
			state = "active"
		case queued > 0:
			state = "pending"
		default:
			state = "done"
		}
		entry := map[string]any{
			"phase": meta["phase"], "key": meta["key"], "label": meta["label"], "desc": meta["desc"],
			"state":  state,
			"routes": cards,
			"counts": map[string]any{"total": running + queued + done, "running": running,
				"queued": queued, "done": done, "findings": findings},
		}
		phasesOut = append(phasesOut, entry)
	}

	// 推断整体当前阶段：取最后一个有活动的阶段；都 done/idle 则取最高有卡的阶段。
	current := 0
	for _, p := range phasesOut {
		if s, _ := p["state"].(string); s == "active" || s == "pending" {
			current = asInt(p["phase"])
		}
	}
	allSettled := true
	for _, p := range phasesOut {
		if s, _ := p["state"].(string); s != "idle" && s != "done" {
			allSettled = false
			break
		}
	}
	if allSettled {
		for _, p := range phasesOut {
			if s, _ := p["state"].(string); s == "done" {
				current = asInt(p["phase"])
			}
		}
	}

	totalRoutes := len(siteRows)
	totalFindings := 0
	totalRunning := 0
	for _, r := range siteRows {
		totalFindings += asInt(r["findings"])
		if statusOf(r) == "running" {
			totalRunning++
		}
	}

	return map[string]any{
		"current_phase": current,
		"phases":        phasesOut,
		"totals": map[string]any{"routes": totalRoutes, "findings": totalFindings,
			"running": totalRunning},
	}
}

// siteHostKey 归一化覆盖事件的 host 键（对齐原版 dedup.normalize_host(url or host)）。
func siteHostKey(url, host string) string {
	key := strings.TrimSpace(host)
	if key == "" {
		key = strings.TrimSpace(url)
	}
	return utils.NormalizeHost(key)
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// ---------------- 覆盖上报 → 定向追打提炼 ----------------

var highValueRe = regexp.MustCompile(`(?i)(api|admin|login|auth|token|session|user|account|member|student|teacher|` +
	`order|file|upload|download|export|import|swagger|api-docs|actuator|nacos|` +
	`druid|env|config|search|query|list|page|save|update|delete|approve|reset|bind|pay)`)

var staticAssetRe = regexp.MustCompile(`(?i)\.(?:css|png|jpe?g|gif|svg|ico|woff2?|map)(?:$|\?)`)

// normalizeCollabPath 把端点路径归一化（绝对 URL/协议相对/相对路径统一为 path?query）。
func normalizeCollabPath(path, baseURL string) string {
	raw := strings.TrimSpace(path)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		idx := strings.Index(raw[8:], "/")
		if idx < 0 {
			return "/"
		}
		return raw[8+idx:]
	}
	if strings.HasPrefix(raw, "//") {
		if idx := strings.Index(raw[2:], "/"); idx >= 0 {
			return raw[2+idx:]
		}
		return "/"
	}
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	// 相对路径：拼在 baseURL 后取路径部分。
	base := strings.TrimSuffix(baseURL, "/")
	if idx := strings.Index(base, "://"); idx >= 0 {
		base = base[idx+3:]
		if slash := strings.Index(base, "/"); slash >= 0 {
			base = base[slash:]
		} else {
			base = ""
		}
	}
	return "/" + raw
}

// classifyCollabEndpoint 按路径/方法/结论给端点归类，输出追打方向。
func classifyCollabEndpoint(path, method, checks, result string) (category, tactic string) {
	low := strings.ToLower(strings.Join([]string{path, method, checks, result}, " "))
	switch {
	case containsAny(low, "swagger", "api-docs", "actuator", "nacos", "druid", ".env", "config", "heapdump"):
		return "未授权/配置暴露", "验证是否能读到受限配置、凭据、接口文档后的敏感操作能力。"
	case containsAny(low, "upload", "download", "file", "attach", "import", "export", "preview", "template"):
		return "文件/导入导出", "验证上传解析、任意文件读、越权下载、导出敏感数据或路径穿越。"
	case containsAny(low, "login", "auth", "token", "session", "sso", "cas", "user", "account", "member", "student", "teacher"):
		return "认证/越权", "验证登录态、对象 ID、角色边界、用户资料/学生/教师数据是否可越权读取。"
	case containsAny(low, "search", "query", "list", "page", "report", "stat", "sql", "where", "filter"):
		return "注入/查询参数", "做 baseline vs 布尔/错误/延时/排序字段差异验证，禁止拖库。"
	case containsAny(low, "save", "update", "delete", "approve", "reset", "bind", "pay", "register", "submit"):
		return "业务逻辑/状态流", "验证缺鉴权、越权写、重放、状态绕过或关键业务参数篡改。"
	}
	return "综合 API 验证", "先判断公开/需登录，再按未授权、越权、参数注入、数据泄露逐项验证。"
}

func containsAny(s string, keys ...string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// FollowupSpecsFromCoverage 从覆盖上报中提炼定向追打任务。
// 返回的 spec 不含 DB 细节，只表达「对哪个入口、按什么方向继续打」。
func FollowupSpecsFromCoverage(coverage []map[string]any, baseURL string, maxSpecs int) []map[string]any {
	if maxSpecs <= 0 {
		maxSpecs = 8
	}
	specs := make([]map[string]any, 0, maxSpecs)
	seen := map[string]bool{}
	for _, record := range coverage {
		route := strOf(record["route"])
		if route == "" {
			route = "site"
		}
		remaining := strings.TrimSpace(strOf(record["remaining"]))
		endpoints, _ := record["endpoints"].([]map[string]any)
		if endpoints == nil {
			if rawList, ok := record["endpoints"].([]any); ok {
				for _, raw := range rawList {
					if m, ok := raw.(map[string]any); ok {
						endpoints = append(endpoints, m)
					}
				}
			}
		}
		limit := len(endpoints)
		if limit > 30 {
			limit = 30
		}
		for _, item := range endpoints[:limit] {
			path := normalizeCollabPath(strOf(item["path"]), baseURL)
			if path == "" || staticAssetRe.MatchString(path) {
				continue
			}
			status := strOf(item["status"])
			checks := strOf(item["checks"])
			result := strOf(item["result"])
			if result == "" {
				result = strOf(item["note"])
			}
			method := strings.ToUpper(strOf(item["method"]))
			if method == "" {
				method = "GET"
			}
			if len(method) > 12 {
				method = method[:12]
			}
			if !highValueRe.MatchString(strings.Join([]string{path, checks, result, remaining}, " ")) {
				continue
			}
			key := method + ":" + strings.Split(path, "?")[0]
			if seen[key] {
				continue
			}
			seen[key] = true
			category, tactic := classifyCollabEndpoint(path, method, checks, result)
			reason := fmt.Sprintf("[单站协作追打] 来源 %s 发现 %s %s；方向：%s。前序状态/结论：%s %s。任务：%s",
				route, method, truncateStr(path, 160), category, firstNonEmptyString(status, "-"), truncateStr(result, 140), tactic)
			if remaining != "" {
				reason += " 剩余线索：" + truncateStr(remaining, 180)
			}
			specs = append(specs, map[string]any{
				"method":       method,
				"path":         truncateStr(path, 220),
				"category":     category,
				"source_route": route,
				"priority":     focusedRoute.Priority + float64(maxOf(0, 20-len(specs))),
				"reason":       truncateStr(reason, 300),
			})
			if len(specs) >= maxSpecs {
				return specs
			}
		}
	}
	return specs
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func maxOf(a, b int) int {
	if a > b {
		return a
	}
	return b
}
