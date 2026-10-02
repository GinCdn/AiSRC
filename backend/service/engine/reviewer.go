package engine

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"
)

// jsonFencePattern 匹配被 Markdown 代码块包裹的 JSON。
var jsonFencePattern = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// ExtractJSON 从模型输出中提取第一个 JSON 对象。
func ExtractJSON(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", false
	}
	if match := jsonFencePattern.FindStringSubmatch(trimmed); len(match) > 1 {
		return match[1], true
	}
	// 退化为括号配对扫描，避免多余文字干扰
	start := strings.Index(trimmed, "{")
	if start < 0 {
		return "", false
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(trimmed); i++ {
		ch := trimmed[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return trimmed[start : i+1], true
			}
		}
	}
	return "", false
}

// ReviewFinding 调用 Reviewer 对漏洞做 AI 初审并落库。
func ReviewFinding(ctx context.Context, pool *llm.Pool, brief *FindingBrief, existingSummaries []string) (*model.Review, error) {
	review := &model.Review{
		ID:               utils.UUID(),
		FindingID:        brief.ID,
		TaskID:           brief.TaskID,
		Verdict:          constant.VerdictAccepted,
		Confidence:       "likely",
		InScope:          true,
		Score:            0,
		UserStatus:       constant.UserPending,
		IgnoreReasons:    []string{},
		DowngradeReasons: []string{},
		UserEdits:        map[string]any{},
		ReviewedAt:       timePtr(time.Now().UTC()),
	}

	if pool == nil || pool.Size() == 0 {
		review.ReviewerNotes = "[系统] 未配置可用 LLM 端点，跳过 AI 初审，直接进入人工复审。"
		return review, nil
	}

	result, err := chatAndRecord(ctx, pool, llm.Request{
		Messages: []llm.Message{
			{Role: "system", Content: ReviewerSystemPrompt + AgentPersonaSuffix()},
			{Role: "user", Content: BuildReviewUserPrompt(brief, existingSummaries)},
		},
		MaxTokens: 4096,
	}, "")
	if err != nil {
		review.ReviewerNotes = "[系统] AI 初审调用失败：" + utils.SanitizeSecretText(err.Error())
		return review, nil
	}

	payload, ok := ExtractJSON(result.Response.Content)
	if !ok {
		review.ReviewerNotes = "[系统] AI 初审未返回可解析 JSON，已按原样进入人工复审。原始输出：" +
			utils.Truncate(result.Response.Content, 500)
		return review, nil
	}

	var verdict ReviewVerdict
	if err := json.Unmarshal([]byte(payload), &verdict); err != nil {
		review.ReviewerNotes = "[系统] AI 初审输出解析失败：" + err.Error()
		return review, nil
	}

	review.Verdict = normalizeVerdict(verdict.Verdict)
	review.Confidence = normalizeConfidence(verdict.Confidence)
	review.Score = verdict.Score
	review.InScope = verdict.InScope
	review.IsDuplicate = verdict.IsDuplicate
	review.Reproduced = verdict.Reproduced
	review.IgnoreReasons = nonNilStrings(verdict.IgnoreReasons)
	review.DowngradeReasons = nonNilStrings(verdict.DowngradeReasons)
	review.ReviewerNotes = verdict.ReviewerNotes
	review.DeepenDirective = verdict.DeepenDirective
	if verdict.SeverityFinal != "" {
		severity := verdict.SeverityFinal
		review.SeverityFinal = &severity
	}
	if review.Verdict == constant.VerdictDeepen && strings.TrimSpace(review.DeepenDirective) == "" {
		review.DeepenDirective = "针对该漏洞继续扩大验证范围，确认实际影响边界。"
	}

	// ===== 展示兜底（不改判定逻辑，只补弱模型经常漏输出的字段）=====

	// 1) 3-gate 服务端重放已确认差异 → reproduced 强制 true。
	//    提示词向模型承诺过该语义，但弱模型经常漏输出 reproduced 字段，导致恒显示「未复现」。
	if gateEvidenceVerdict(brief.Evidence) == "pass" && !review.Reproduced {
		review.Reproduced = true
	}
	// 2) AI 未输出 score（解析后恒 0）时，按最终等级 + 置信度推导展示分，避免前端「评分一直为 0」。
	if review.Score <= 0 {
		sev := review.EffectiveSeverity()
		if sev == "" {
			sev = brief.SeverityClaimed
		}
		review.Score = fallbackScore(sev, review.Confidence)
	}
	return review, nil
}

// gateEvidenceVerdict 读取 evidence.gate.verdict（3-gate 服务端重放结论）。
func gateEvidenceVerdict(evidence map[string]any) string {
	if evidence == nil {
		return ""
	}
	gate, ok := evidence["gate"].(map[string]any)
	if !ok {
		return ""
	}
	verdict, _ := gate["verdict"].(string)
	return verdict
}

// fallbackScore AI 未给分时的展示兜底：等级基线分 + 置信度修正，夹取 5-95。
func fallbackScore(severity, confidence string) float64 {
	base := 40.0
	switch severity {
	case "严重":
		base = 90
	case "高危":
		base = 75
	case "中危":
		base = 55
	case "低危":
		base = 35
	case "信息":
		base = 15
	}
	switch confidence {
	case "confirmed":
		base += 5
	case "uncertain":
		base -= 15
	}
	if base < 5 {
		base = 5
	}
	if base > 95 {
		base = 95
	}
	return base
}

// SaveReview 落库审核结论。
func SaveReview(review *model.Review) error {
	if core.Db == nil {
		return nil
	}
	return core.Db.Create(review).Error
}

// ApplyDeepen 人工 / AI 打回深挖：把深挖上下文写回 target 并入队重扫。
func ApplyDeepen(target *model.Target, finding *model.Finding, directive string, source string, cap int) (bool, string) {
	if target == nil {
		return false, "目标不存在"
	}
	if strings.TrimSpace(directive) == "" {
		return false, "深挖指令不能为空"
	}
	limit := utils.ClampDeepenCap(cap)
	if target.DeepenCount >= limit {
		return false, "该目标深挖次数已达上限（" + itoa(limit) + " 次）"
	}

	target.DeepenContext = map[string]any{
		"directive":        directive,
		"vuln_type":        finding.VulnType,
		"original_title":   finding.Title,
		"original_summary": utils.Truncate(finding.Description, 1000),
		"from_finding_id":  finding.ID,
		"source":           source,
	}
	target.DeepenCount++
	target.Status = constant.TargetQueued
	target.AssignedWorker = ""
	target.RetryCount = 0
	target.Verdict = ""
	target.HeartbeatAt = nil
	target.DeadReason = ""
	target.PriorityScore += 100
	target.PriorityReason = "[深挖#" + itoa(target.DeepenCount) + "] " + utils.Truncate(directive, 80)

	finding.Status = constant.FindingSuperseded
	if !strings.Contains(finding.DedupKey, ":sup:") {
		finding.DedupKey = finding.DedupKey + ":sup:" + utils.ShortUUID(8)
	}
	return true, ""
}

// 漏洞等级排序权重。
var severityRank = map[string]int{
	"严重": 5, "高危": 4, "中危": 3, "低危": 2, "信息": 1,
}

// SeverityRank 返回等级权重。
func SeverityRank(severity string) int {
	if rank, ok := severityRank[severity]; ok {
		return rank
	}
	return 0
}

// NormalizeSeverity 归一化等级名称。
func NormalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "严重", "致命":
		return "严重"
	case "high", "高危":
		return "高危"
	case "medium", "中危", "medium risk":
		return "中危"
	case "low", "低危":
		return "低危"
	case "info", "信息", "informational":
		return "信息"
	default:
		return strings.TrimSpace(value)
	}
}

func normalizeVerdict(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "accepted", "accept", "pass":
		return constant.VerdictAccepted
	case "deepen", "reinvestigate", "continue":
		return constant.VerdictDeepen
	default:
		return constant.VerdictIgnored
	}
}

func normalizeConfidence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "confirmed":
		return "confirmed"
	case "uncertain":
		return "uncertain"
	default:
		return "likely"
	}
}

func nonNilStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

func timePtr(t time.Time) *time.Time { return &t }

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
