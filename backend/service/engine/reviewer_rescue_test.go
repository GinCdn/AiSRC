package engine

import (
	"strings"
	"testing"

	"AiSRC/constant"
	"AiSRC/model"
)

func rescueReview() *model.Review {
	return &model.Review{
		Verdict:    constant.VerdictIgnored,
		InScope:    true,
		Score:      1.0,
		ReviewerNotes: "扫描器结果，无 PoC",
	}
}

func rescueBrief() *FindingBrief {
	return &FindingBrief{
		VulnType:    "unauthorized_access",
		Title:       "某系统存在接口未授权访问",
		TargetURL:   "http://example.com/api/user/list",
		Description: "未授权访问接口可返回用户数据",
		SelfCheck:   map[string]any{},
	}
}

func TestIgnoredDeepenDirectiveGuards(t *testing.T) {
	review := rescueReview()
	brief := rescueBrief()

	// 非 ignored 不救
	review.Verdict = constant.VerdictAccepted
	if ignoredDeepenDirective(brief, review, "") != "" {
		t.Fatal("accepted 不应改判")
	}
	// 重复/超范围不救
	review.Verdict = constant.VerdictIgnored
	review.IsDuplicate = true
	if ignoredDeepenDirective(brief, review, "") != "" {
		t.Fatal("duplicate 不应改判")
	}
	review.IsDuplicate = false
	review.InScope = false
	if ignoredDeepenDirective(brief, review, "") != "" {
		t.Fatal("out of scope 不应改判")
	}
	review.InScope = true

	// self_check 三条硬挡：反射 XSS / 需管理员登录 / 需中间人
	for _, key := range []string{"is_reflected_xss", "needs_admin_login", "needs_mitm"} {
		brief.SelfCheck = map[string]any{key: true}
		if ignoredDeepenDirective(brief, review, "") != "" {
			t.Fatalf("self_check.%s=true 不应改判", key)
		}
	}
	brief.SelfCheck = map[string]any{}

	// 永不救词表：反射 XSS 文案
	brief.Description = "这是一个反射型xss问题"
	if ignoredDeepenDirective(brief, review, "") != "" {
		t.Fatal("never-deepen 词表命中不应改判")
	}
}

func TestMaybeDeepenIgnoredRCEBlind(t *testing.T) {
	review := rescueReview()
	brief := rescueBrief()
	brief.VulnType = "rce"
	brief.Description = "扫描器报命令执行，时间盲注延时明显，但无回显"
	brief.SelfCheck = map[string]any{"scanner_only_no_poc": true}

	if !maybeDeepenIgnored(brief, review, "") {
		t.Fatal("盲打 RCE + 侧信道应被救成 deepen")
	}
	if review.Verdict != constant.VerdictDeepen {
		t.Fatalf("verdict 应为 deepen，got %s", review.Verdict)
	}
	if review.Confidence != "uncertain" {
		t.Fatalf("confidence 应为 uncertain，got %s", review.Confidence)
	}
	if review.Score < 2.5 || review.Score > 3.9 {
		t.Fatalf("score 应夹在 [2.5,3.9]，got %v", review.Score)
	}
	if !strings.Contains(review.ReviewerNotes, "[系统改判]") {
		t.Fatal("notes 应带系统改判标记")
	}
	if review.DeepenDirective == "" {
		t.Fatal("应生成定向深挖指令")
	}
	// 非 RCE 的 scanner_only_no_poc 不救
	review2 := rescueReview()
	brief2 := rescueBrief()
	brief2.SelfCheck = map[string]any{"scanner_only_no_poc": true}
	if maybeDeepenIgnored(brief2, review2, "") {
		t.Fatal("非 RCE 的 scanner_only_no_poc 不应改判")
	}
}

func TestMaybeDeepenIgnoredSecretAndConfig(t *testing.T) {
	review := rescueReview()
	brief := rescueBrief()
	brief.Title = "接口泄露 appsecret 密钥"
	brief.Description = "响应中包含硬编码 appsecret"
	if !maybeDeepenIgnored(brief, review, "") {
		t.Fatal("secret 泄露线索应改判 deepen")
	}

	review2 := rescueReview()
	brief2 := rescueBrief()
	brief2.Title = "系统配置接口未授权访问"
	brief2.Description = "未授权读取 /config 系统配置项"
	if ignoredDeepenDirective(brief2, review2, "") == "" {
		t.Fatal("config+auth 线索应给出改判指令")
	}
}
