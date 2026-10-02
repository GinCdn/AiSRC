package engine

// 全局情报库写入链（对齐原版 agents/intel.py + orchestrator._distill_intel）：
//   1. worker 主动上报（report_intel 工具）：cred / endpoint / profile，无论出洞与否都收；
//   2. 自动提炼：仅在确认出洞时（verdict=found 或有落库漏洞），按识别到的系统指纹
//      沉淀 fingerprint / endpoint / profile 三类，质量门槛防冗余垃圾。
// 指纹识别纯字符串 in 匹配（无正则、无回溯、无网络、纯内存）；写入失败仅记日志，
// 绝不阻断 worker 主流程。

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/utils"
)

// intelMaxReported 单目标 worker 主动上报上限（防滥用，对齐原版 20 条）。
const intelMaxReported = 20

// intelMaxField 情报内容字段硬截断（防异常超长）。
const intelMaxField = 300

// fingerprintKeywords 轻量指纹关键词表：命中即把 value 作为
// fingerprint/endpoint 类情报的 match_key（同款系统跨域复用）。宁缺毋滥。
var fingerprintKeywords = []struct {
	keywords []string
	fp       string
}{
	// 统一身份认证 / SSO
	{[]string{"统一身份认证", "统一认证", "cas/login", "/cas/", "single sign"}, "sso_cas"},
	// 邮件系统
	{[]string{"coremail", "/coremail/"}, "mail_coremail"},
	{[]string{"exchange", "owa/auth", "/owa/"}, "mail_exchange"},
	// 常见国产框架/CMS
	{[]string{"若依", "ruoyi", "ry-", "若依管理"}, "framework_ruoyi"},
	{[]string{"thinkphp", "think_template", "x-powered-by: thinkphp"}, "framework_thinkphp"},
	{[]string{"fastadmin"}, "framework_fastadmin"},
	{[]string{"springboot", "whitelabel error page", "/actuator"}, "framework_springboot"},
	{[]string{"jeecg", "jeecg-boot", "jeecgboot"}, "framework_jeecg"},
	{[]string{"seeyon", "致远", "/seeyon/"}, "oa_seeyon"},
	{[]string{"泛微", "weaver", "/weaver/", "ecology"}, "oa_weaver"},
	{[]string{"通达", "tongda", "/ispirit/"}, "oa_tongda"},
	// 教务/校园业务系统
	{[]string{"强智", "jwgl", "教务系统", "academic"}, "edu_jwgl"},
	{[]string{"正方", "zfsoft", "/jwglxt/"}, "edu_zhengfang"},
	{[]string{"迎新", "yxxt", "新生报到"}, "edu_freshman"},
	// VPN / 网关
	{[]string{"sslvpn", "anyconnect"}, "vpn_cisco"},
	{[]string{"sangfor", "深信服", "/por/login"}, "vpn_sangfor"},
	{[]string{"webvpn"}, "vpn_webvpn"},
	// 数据库/中间件管理
	{[]string{"phpmyadmin"}, "db_phpmyadmin"},
	{[]string{"druid", "/druid/index"}, "mw_druid"},
	{[]string{"swagger-ui", "swagger-ui.html", "/v2/api-docs"}, "api_swagger"},
	{[]string{"nacos", "/nacos/"}, "mw_nacos"},
	{[]string{"grafana"}, "mw_grafana"},
	{[]string{"kibana"}, "mw_kibana"},
}

// DetectFingerprints 从 title/server/body/host 等文本片段识别系统指纹。
// 返回去重后的指纹标识列表；无匹配返回空。
func DetectFingerprints(parts ...string) []string {
	blob := strings.ToLower(strings.Join(parts, " "))
	if blob == "" {
		return nil
	}
	// 限制扫描长度，防异常超长 body（纯 in 匹配本就线性，再加一道保险）。
	if len(blob) > 20000 {
		blob = blob[:20000]
	}
	hits := make([]string, 0, 4)
	for _, item := range fingerprintKeywords {
		for _, kw := range item.keywords {
			if strings.Contains(blob, kw) {
				hits = append(hits, item.fp)
				break
			}
		}
	}
	// 去重保序
	seen := make(map[string]bool, len(hits))
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// intelClip 情报文本字段截断。
func intelClip(text string) string {
	return strings.TrimSpace(utils.Truncate(text, intelMaxField))
}

// intelPayloadClean 清洗 payload：键 ≤50 字符、值截断、剔除空值；清洗后为空返回 nil。
func intelPayloadClean(raw map[string]any) map[string]any {
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		key := intelClip(k)
		if key == "" || len(key) > 50 {
			continue
		}
		text := ""
		switch value := v.(type) {
		case string:
			text = value
		case nil:
			continue
		default:
			text = fmt.Sprintf("%v", value)
		}
		text = intelClip(text)
		if text == "" {
			continue
		}
		out[key] = text
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recordIntel 写入一条情报（ UpsertIntel 的安全包装：绝不 panic、绝不阻断主流程）。
func recordIntel(kind, matchKey string, payload map[string]any, summary, sourceHost, sourceTaskID, confidence string) {
	if core.Db == nil {
		return
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	matchKey = strings.ToLower(strings.TrimSpace(matchKey))
	if matchKey == "" || len(matchKey) > 255 {
		return
	}
	switch kind {
	case constant.IntelCred, constant.IntelFingerprint, constant.IntelEndpoint, constant.IntelProfile:
	default:
		return
	}
	payload = intelPayloadClean(payload)
	if payload == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			global.Log.Warnf("TaskRunner[%s] 情报写入降级: %v", sourceTaskID, r)
		}
	}()
	upsert := model.Intel{
		Kind:         kind,
		MatchKey:     matchKey,
		Payload:      payload,
		Summary:      utils.Truncate(strings.TrimSpace(summary), 500),
		SourceHost:   utils.Truncate(sourceHost, 255),
		SourceTaskID: utils.Truncate(sourceTaskID, 32),
		Confidence:   firstNonEmptyString(confidence, "likely"),
	}
	UpsertIntel(upsert)
}

// UpsertIntel 写入一条情报（按 kind + match_key + dedup_hash 去重累计命中）。
// service 层情报视图与 engine 写入链共用同一入口。
func UpsertIntel(item model.Intel) {
	if core.Db == nil {
		return
	}
	if item.ID == "" {
		item.ID = utils.UUID()
	}
	if item.DedupHash == "" {
		item.DedupHash = utils.IdentityRef(item.Kind, item.MatchKey, item.Summary)
	}
	if item.Confidence == "" {
		item.Confidence = "likely"
	}
	now := time.Now()
	var existing model.Intel
	err := core.Db.Where("kind = ? AND match_key = ? AND dedup_hash = ?",
		item.Kind, item.MatchKey, item.DedupHash).First(&existing).Error
	if err == nil {
		updates := map[string]any{
			"hit_count": existing.HitCount + 1,
			"last_seen": now,
			"summary":   firstNonEmptyString(item.Summary, existing.Summary),
			"payload":   item.Payload,
		}
		// verified 优先级高于 likely：一旦验证过就升级，不回退（对齐原版）。
		if item.Confidence == "verified" && existing.Confidence != "verified" {
			updates["confidence"] = "verified"
		}
		core.Db.Model(&model.Intel{}).Where("id = ?", existing.ID).Updates(updates)
		return
	}
	item.FirstSeen = now
	item.LastSeen = now
	if item.HitCount <= 0 {
		item.HitCount = 1
	}
	core.Db.Create(&item)
}

// DistillWorkerIntel 情报沉淀（persistWorkerResult 收尾调用，对齐原版 _distill_intel）：
//   - worker 主动上报：cred 按 root 域、endpoint 按系统指纹（无指纹退 root 域）、profile 按 root 域；
//   - 自动提炼：只在确认出洞时——fingerprint（同款系统打法）、endpoint（有效端点）、profile（本域画像）。
func DistillWorkerIntel(task *model.Task, target *model.Target, saved int, result *WorkerResult) {
	if target == nil || result == nil {
		return
	}
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return
	}
	root := utils.RootDomain(host)
	fps := DetectFingerprints(host, target.Title, target.Org)

	// ===== worker 主动上报的情报 =====
	for _, item := range result.ReportedIntel {
		kind, _ := item["kind"].(string)
		payload, _ := item["payload"].(map[string]any)
		summary, _ := item["summary"].(string)
		confidence, _ := item["confidence"].(string)
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case constant.IntelCred:
			if root != "" {
				recordIntel(constant.IntelCred, root, payload, summary, host, task.ID, confidence)
			}
		case constant.IntelEndpoint:
			// 有系统指纹按指纹存（可跨域复用）；否则退而按 root 域存。
			keys := fps
			if len(keys) == 0 && root != "" {
				keys = []string{root}
			}
			for _, key := range keys {
				recordIntel(constant.IntelEndpoint, key, payload, summary, host, task.ID, confidence)
			}
		case constant.IntelProfile:
			if root != "" {
				recordIntel(constant.IntelProfile, root, payload, summary, host, task.ID, confidence)
			}
		}
	}

	// ===== 自动提炼：只在确认出洞时（质量门槛，防冗余垃圾）=====
	if result.Verdict != "found" && saved == 0 {
		return
	}
	for _, finding := range result.Submitted {
		if finding == nil || finding.VulnType == "" {
			continue
		}
		path := ""
		if parsed, err := url.Parse(finding.TargetURL); err == nil {
			path = parsed.Path
		}
		tactic := fmt.Sprintf("%s：%s", finding.VulnType, finding.Title)
		for _, fp := range fps {
			recordIntel(constant.IntelFingerprint, fp,
				map[string]any{"tactic": tactic, "vuln_type": finding.VulnType},
				fmt.Sprintf("%s（来自 %s）", finding.VulnType, host),
				host, task.ID, "verified")
			// endpoint：同款系统有效端点
			if path != "" && path != "/" {
				recordIntel(constant.IntelEndpoint, fp,
					map[string]any{"path": path, "vuln_type": finding.VulnType},
					fmt.Sprintf("（来自 %s 出洞）", host),
					host, task.ID, "verified")
			}
		}
	}

	// profile：本域技术栈画像（仅当识别出指纹时，记一条系统类型）
	if root != "" && len(fps) > 0 {
		recordIntel(constant.IntelProfile, root,
			map[string]any{"key": "系统类型", "value": strings.Join(fps, ", ")},
			"", host, task.ID, "likely")
	}
}
