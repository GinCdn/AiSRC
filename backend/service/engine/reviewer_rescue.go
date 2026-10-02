package engine

// reviewer 挽救链（对齐原版 reviewer.py _ignored_deepen_directive / _maybe_deepen_ignored）：
// 把少数「真实入口但未打穿」的 ignored 兜底转成 deepen，避免 reviewer 把已有价值线索
// 直接归档；真正垃圾/公开展示/图形验证码/反射 XSS 仍保持 ignored。这不是放宽 accepted 口径。

import (
	"encoding/json"
	"strings"

	"AiSRC/constant"
	"AiSRC/model"
)

// reviewNeverDeepenMarkers 命中即不救（真垃圾/超范围）。
var reviewNeverDeepenMarkers = []string{
	"反射型xss", "反射 xss", "self-xss", "self xss", "用户名枚举",
	"phpinfo", "拒绝服务", "dos",
	"短信轰炸", "邮箱轰炸", "邮件轰炸", "验证码轰炸", "sms bomb", "email bomb",
	"非教育", "不在范围", "钓鱼", "中间人", "mitm", "本就公开", "公开展示", "公开接口",
}

// reviewCaptchaOnlyIgnoreMarkers 仅图形/算术验证码类：除非注册场景，不救。
var reviewCaptchaOnlyIgnoreMarkers = []string{"图形验证码", "算术验证码"}

// rceRescueTypes 盲打 RCE 类漏洞类型（scanner_only_no_poc 不挡救）。
var rceRescueTypes = map[string]bool{
	"rce": true, "command_injection": true, "command_exec": true,
	"code_injection": true, "ssti": true, "deserialization": true,
}

const harmlessProtocol = "不要删改真实/他人数据。按无害证法补证据：" +
	"① 自建带唯一标识的哨兵（如 SRC_TEST_<rand>），增→改→删只碰自己这条，旁路 GET/列表回读 before→after；" +
	"② 未登录/无 token 对照：写接口应 401/403，带低权登录态应变 200/授权通过；" +
	"③ 只能碰已有对象时幂等回写原值，看 affectedRows≥1 或授权通过且值未变。" +
	"做不到就 finish(deepen_lead) 写清缺哪一步，禁止硬删真数据凑证据。"

// selfCheckFlag 读 self_check 布尔键（JSON 反序列化后可能是 bool）。
func selfCheckFlag(sc map[string]any, key string) bool {
	v, ok := sc[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// reviewRescueText 拼接待匹配文本（finding 全文 + review 理由，转小写）。
func reviewRescueText(brief *FindingBrief, review *model.Review) string {
	evidenceJSON, _ := json.Marshal(brief.Evidence)
	chainJSON, _ := json.Marshal(brief.KillChain)
	parts := []string{
		brief.VulnType, brief.Title, brief.TargetURL, brief.Description,
		brief.Poc, brief.RawRequest, brief.RawResponse, brief.AffectedScope,
		string(evidenceJSON), string(chainJSON),
		strings.Join(review.IgnoreReasons, " "),
		strings.Join(review.DowngradeReasons, " "),
		review.ReviewerNotes,
	}
	return strings.ToLower(strings.Join(parts, "\n"))
}

func hasAnyMarker(text string, markers []string) bool {
	lower := strings.ToLower(text)
	for _, m := range markers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// ignoredDeepenDirective 判定该 ignored 是否值得改判 deepen，返回定向深挖指令（空=不改判）。
func ignoredDeepenDirective(brief *FindingBrief, review *model.Review, srcType string) string {
	if review.Verdict != constant.VerdictIgnored || review.IsDuplicate || !review.InScope {
		return ""
	}
	sc := brief.SelfCheck
	rceType := rceRescueTypes[strings.ToLower(strings.TrimSpace(brief.VulnType))]
	if selfCheckFlag(sc, "is_reflected_xss") || selfCheckFlag(sc, "needs_admin_login") || selfCheckFlag(sc, "needs_mitm") {
		return ""
	}
	// 盲打/无回显 RCE 常由扫描器时间盲模板发现、worker 给不出回显 PoC 时会置 scanner_only_no_poc，
	// 正是值得定向深挖坐实的线索，不因这个标记就完全不救（对应问题：无回显 RCE 被丢）。
	if selfCheckFlag(sc, "scanner_only_no_poc") && !rceType {
		return ""
	}

	text := reviewRescueText(brief, review)
	registerLike := hasAnyMarker(text, []string{"注册", "register", "signup"})
	neverMarkers := reviewNeverDeepenMarkers
	if registerLike {
		filtered := make([]string, 0, len(neverMarkers))
		for _, m := range neverMarkers {
			if m != "本就公开" && m != "公开接口" {
				filtered = append(filtered, m)
			}
		}
		neverMarkers = filtered
	}
	if hasAnyMarker(text, neverMarkers) ||
		(hasAnyMarker(text, reviewCaptchaOnlyIgnoreMarkers) && !registerLike) {
		return ""
	}

	authSignal := hasAnyMarker(text, []string{
		"未授权", "无需登录", "无鉴权", "未鉴权", "unauthorized", "without auth", "no auth",
	})
	configSignal := hasAnyMarker(text, []string{
		"系统配置", "配置项", "系统参数", "configkey", "initpassword", "init password",
		"sys.user.initpassword", "/config", "appconfig", "setting",
	})
	registerSignal := registerLike && hasAnyMarker(text, []string{
		"注册", "批量注册", "无验证码", "免验证码", "register", "signup", "captcha",
	})
	secretContext := hasAnyMarker(text, []string{"泄露", "硬编码", "暴露", "明文", "返回", "前端", "js", "配置", "config"})
	strongSecretSignal := hasAnyMarker(text, []string{
		"secret", "appsecret", "clientsecret", "api key", "apikey", "accesskey",
		"私钥", "密钥", "签名密钥",
	})
	bearerSecretSignal := hasAnyMarker(text, []string{"token", "jwt", "session"}) && secretContext
	secretSignal := strongSecretSignal || bearerSecretSignal
	uploadSignal := hasAnyMarker(text, []string{
		"上传", "upload", "savefile", "fileupload", "multipart/form-data",
	})
	writeSignal := hasAnyMarker(text, []string{
		"修改", "删除", "新增", "保存", "重置", "update", "delete", "remove", "save", "reset",
	})
	rceSignal := rceType || hasAnyMarker(text, []string{
		"rce", "命令执行", "命令注入", "command inject", "远程代码", "代码执行", "code execution",
		"ssti", "模板注入", "反序列化", "deserial",
	})
	sideChannel := hasAnyMarker(text, []string{
		"时间盲", "time-based", "time based", "sleep(", "延时", "响应时间", "响应延迟", "延迟",
		"dnslog", "oast", "带外", "ceye", "interactsh", "burpcollaborator", "回连", "外连",
		"落地文件", "写入文件", "结果写入", "outfile", "tee ", "touch ",
	})

	// 无回显/盲打 RCE：有稳定侧信道证据但缺直接回显，不当垃圾丢，回炉坐实。
	if rceSignal && sideChannel {
		return ("这是疑似盲打/无回显 RCE/命令执行/SSTI/反序列化：已有侧信道线索但缺直接回显。" +
			"沿同一注入点把命令结果坐实——用稳定 time-based(sleep 递增验证时间差线性)、" +
			"DNS/HTTP 带外回连(dnslog/interactsh/ceye)、或把命令输出写入可回读的业务字段/落地文件后访问，" +
			"拿到明确执行结果证据。确认时间差不稳定或无任何侧信道差异才 finish no_vuln。")
	}
	if configSignal && (authSignal || secretSignal) {
		return ("不要再把「配置项泄露」当最终成果提交；沿已证实的配置接口继续深挖：" +
			"枚举更多配置 key/接口地址，提取 token、secret、默认口令或后台路径，并实证能否登录后台、" +
			"调用受限 API、读取敏感数据或执行敏感写操作。只拿到默认值/普通配置则 finish no_vuln。")
	}
	if registerSignal {
		return ("基于已证实的注册入口继续深挖，不要把「可批量注册」单独当洞：" +
			"注册低影响测试账号后登录拿 token/session，枚举表单/用户/导出/后台 API，" +
			"验证是否能读取或修改他人数据、批量导出、越权访问管理接口，或链到短信/改密/账号接管。" +
			"若只能注册空账号且无下游危害，finish no_vuln。")
	}
	if secretSignal {
		return ("沿已发现的 key/secret/token 继续深挖：确认它是否可用，尝试伪造签名或携带凭证调用受限 API，" +
			"必须打出读取敏感数据、后台权限、配额盗刷或敏感写操作的实证；仅证明字符串存在不要再提交。")
	}
	if uploadSignal && authSignal {
		return ("沿未授权上传入口继续深挖：验证可上传的扩展名、落点路径和访问方式，" +
			"优先证明脚本可解析执行/可覆盖敏感文件/可读取敏感数据；只能上传并访问 txt 则 finish no_vuln。")
	}
	if writeSignal && authSignal {
		return "沿未授权写接口继续深挖，但禁止删改真实/他人数据。" + harmlessProtocol
	}
	if strings.EqualFold(strings.TrimSpace(srcType), "enterprise") && authSignal {
		return ("该未授权线索尚未打出企业可收影响；继续验证是否能读取客户/员工/订单/审批/财务等受限数据，" +
			"或执行权限、配置、业务状态类敏感写操作。无实际影响则 finish no_vuln。")
	}
	return ""
}

// maybeDeepenIgnored 满足条件时把 ignored 改判 deepen（返回是否改判）。
func maybeDeepenIgnored(brief *FindingBrief, review *model.Review, srcType string) bool {
	directive := ignoredDeepenDirective(brief, review, srcType)
	if directive == "" {
		return false
	}
	review.Verdict = constant.VerdictDeepen
	review.Confidence = "uncertain"
	review.SeverityFinal = nil
	if review.Score < 2.5 {
		review.Score = 2.5
	} else if review.Score > 3.9 {
		review.Score = 3.9
	}
	if strings.TrimSpace(review.DeepenDirective) == "" {
		review.DeepenDirective = directive
	}
	review.ReviewerNotes = strings.TrimSpace(review.ReviewerNotes) +
		"\n[系统改判] 该 Finding 不够 accepted，但属于「入口真实、下一步明确」的半成品；已从 ignored 改为 deepen，要求 worker 定向补链。"
	return true
}
