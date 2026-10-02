package engine

import "testing"

// TestBuildManualCandidatesKeepsScheme 锁定一个真实缺陷：
// 旧实现无条件剥掉 "//" 之前的部分再硬编码补 "http://"，
// 导致用户显式填写的 https:// 目标被静默降级成 http://。
// 原版 _normalize_url 用 `parsed.scheme or "http"` 保留用户 scheme。
func TestBuildManualCandidatesKeepsScheme(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"显式 https 必须保留", "https://dvwa.gincdn.cc", "https://dvwa.gincdn.cc"},
		{"显式 http 保留", "http://dvwa.gincdn.cc", "http://dvwa.gincdn.cc"},
		{"裸域补 http", "dvwa.gincdn.cc", "http://dvwa.gincdn.cc"},
		{"大写 scheme 归一", "HTTPS://dvwa.gincdn.cc", "https://dvwa.gincdn.cc"},
		{"保留路径与查询", "https://dvwa.gincdn.cc/vulnerabilities/sqli/?id=1", "https://dvwa.gincdn.cc/vulnerabilities/sqli/?id=1"},
		{"根路径斜杠省略", "https://dvwa.gincdn.cc/", "https://dvwa.gincdn.cc"},
		{"协议相对写法", "//dvwa.gincdn.cc", "http://dvwa.gincdn.cc"},
		{"剥离尾部说明文字", "https://dvwa.gincdn.cc 这个是靶场", "https://dvwa.gincdn.cc"},
		{"剥离尾部标点", "dvwa.gincdn.cc,", "http://dvwa.gincdn.cc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildManualCandidates([]string{tc.input})
			if len(got) != 1 {
				t.Fatalf("输入 %q 期望产出 1 个候选，实际 %d", tc.input, len(got))
			}
			if got[0].URL != tc.want {
				t.Fatalf("输入 %q 期望 %q，实际 %q", tc.input, tc.want, got[0].URL)
			}
		})
	}
}

// TestBuildManualCandidatesSkipsComments 空行与注释行应被忽略。
func TestBuildManualCandidatesSkipsComments(t *testing.T) {
	got := buildManualCandidates([]string{"", "   ", "# 这是注释", "https://ok.example.com"})
	if len(got) != 1 || got[0].URL != "https://ok.example.com" {
		t.Fatalf("注释未被正确过滤：%+v", got)
	}
}
