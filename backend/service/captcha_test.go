package service

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// flipDigit 返回一个与原验证码必然不同的四位数（用于断言错误答案被拒绝）。
func flipDigit(code string) string {
	b := []byte(code)
	if b[0] == '9' {
		b[0] = '0'
	} else {
		b[0]++
	}
	return string(b)
}

// decodeCaptchaSVG 解出 data URL 里的 SVG 原文。
func decodeCaptchaSVG(t *testing.T, image string) string {
	t.Helper()
	const prefix = "data:image/svg+xml;base64,"
	if !strings.HasPrefix(image, prefix) {
		t.Fatalf("验证码图片应为 SVG data URL，实际以 %q 开头", truncate(image, 48))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(image, prefix))
	if err != nil {
		t.Fatalf("验证码 data URL 的 base64 无法解码: %v", err)
	}
	return string(raw)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// 验证码必须是后端随机生成的 4 位数字。
func TestCaptchaIsFourDigitsAndRandom(t *testing.T) {
	ResetLoginGuard()
	seen := map[string]int{}
	for i := 0; i < 50; i++ {
		id, code, ttl := NewCaptcha()
		if id == "" {
			t.Fatalf("第 %d 次生成的验证码 ID 为空", i)
		}
		if len(code) != CaptchaDigits {
			t.Fatalf("验证码应为 %d 位，实际 %q（%d 位）", CaptchaDigits, code, len(code))
		}
		for _, ch := range code {
			if ch < '0' || ch > '9' {
				t.Fatalf("验证码必须全为数字，实际 %q", code)
			}
		}
		if ttl <= 0 {
			t.Fatalf("验证码有效期应为正数，实际 %v", ttl)
		}
		seen[code]++
	}
	if len(seen) == 1 {
		t.Fatalf("50 次生成的验证码完全相同（%v），随机源未生效", seen)
	}
}

// 校验通过后必须立刻作废：同一张图不能重复使用。
func TestVerifyCaptchaConsumesOnce(t *testing.T) {
	ResetLoginGuard()
	id, code, _ := NewCaptcha()

	if !VerifyCaptcha(id, code) {
		t.Fatalf("首次校验应通过")
	}
	if VerifyCaptcha(id, code) {
		t.Fatalf("同一验证码被重复使用，未做到一次性消费")
	}
}

// 错误答案同样消费验证码，杜绝同一张图被反复试探。
func TestVerifyCaptchaWrongCodeConsumed(t *testing.T) {
	ResetLoginGuard()
	id, code, _ := NewCaptcha()
	wrong := flipDigit(code)

	if VerifyCaptcha(id, wrong) {
		t.Fatalf("错误答案不应通过校验")
	}
	if VerifyCaptcha(id, code) {
		t.Fatalf("错误答案试探后验证码未作废，存在暴力破解窗口")
	}
}

// 未登记的 ID 与空输入必须拒绝。
func TestVerifyCaptchaRejectsUnknownAndEmpty(t *testing.T) {
	ResetLoginGuard()
	if VerifyCaptcha("", "1234") {
		t.Fatalf("空 ID 应拒绝")
	}
	if VerifyCaptcha("not-exist", "1234") {
		t.Fatalf("未登记 ID 应拒绝")
	}
	id, _, _ := NewCaptcha()
	if VerifyCaptcha(id, "") {
		t.Fatalf("空验证码应拒绝")
	}
}

// 失败计数：达阈值才要求验证码，成功后清零，且按来源隔离。
func TestLoginFailureThresholdAndReset(t *testing.T) {
	ResetLoginGuard()
	const ip = "10.0.0.9"

	if CaptchaRequired(ip) {
		t.Fatalf("初始状态不应要求验证码")
	}
	for i := 1; i < CaptchaThreshold; i++ {
		if got := RecordLoginFailure(ip); got != i {
			t.Fatalf("第 %d 次失败计数应为 %d，实际 %d", i, i, got)
		}
		if CaptchaRequired(ip) {
			t.Fatalf("失败 %d 次（阈值 %d）时不应要求验证码", i, CaptchaThreshold)
		}
	}
	if got := RecordLoginFailure(ip); got != CaptchaThreshold {
		t.Fatalf("第 %d 次失败计数应为 %d，实际 %d", CaptchaThreshold, CaptchaThreshold, got)
	}
	if !CaptchaRequired(ip) {
		t.Fatalf("失败满 %d 次后必须要求验证码", CaptchaThreshold)
	}

	if CaptchaRequired("10.0.0.10") {
		t.Fatalf("失败计数必须按来源隔离，其它 IP 不应被牵连")
	}

	ClearLoginFailures(ip)
	if CaptchaRequired(ip) || LoginFailures(ip) != 0 {
		t.Fatalf("登录成功后失败计数应清零")
	}
}

// 渲染出的图片必须是 SVG data URL，且 4 个数字各自出现在文本节点里。
func TestCaptchaImageIsSvgDataURL(t *testing.T) {
	const code = "7042"
	svg := decodeCaptchaSVG(t, CaptchaImage(code))

	if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Fatalf("解码后缺少 svg 根节点: %s", truncate(svg, 120))
	}
	if !strings.Contains(svg, `width="132"`) {
		t.Fatalf("验证码图片尺寸异常: %s", truncate(svg, 120))
	}
	for _, ch := range code {
		if !strings.Contains(svg, ">"+string(ch)+"</text>") {
			t.Fatalf("SVG 文本节点中缺少数字 %c", ch)
		}
	}
}

// 过期验证码必须失效。
func TestCaptchaExpires(t *testing.T) {
	ResetLoginGuard()
	id, code, _ := NewCaptcha()

	// 直接把过期时间改到过去，模拟超时。
	guardMu.Lock()
	captchaSet[id] = captchaEntry{code: code, expiresAt: time.Now().Add(-time.Second)}
	guardMu.Unlock()

	if VerifyCaptcha(id, code) {
		t.Fatalf("过期验证码必须失效")
	}
}
