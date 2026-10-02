package engine

import "testing"

// prefilterCandidates 必须按标签边界整词匹配，不能子串匹配——
// gincdn.cc 含 "cdn" 字样曾被整域误杀（返回 10 条入队 0 个）。
func TestPrefilterCandidates(t *testing.T) {
	cases := []struct {
		host string
		skip bool
	}{
		{"gincdn.cc", false},                    // 恰好含 cdn 字样的正常域名，不能误杀
		{"http://pikachu.gincdn.cc", false},     // 带 scheme 的完整 URL host
		{"www.gincdn.cc", false},                // www 前缀
		{"cdn.example.com", true},               // 真正的 CDN 子域
		{"static.example.com", true},            // 静态资源子域
		{"img-cdn.example.com", true},           // - 连接的 CDN 标签
		{"cdnjs.cloudflare.com", true},          // cdnjs 独立标签
		{"cdnjs.example.com", true},             // cdnjs 标签
		{"example.com", false},                  // 普通域名
		{"waf.example.com", true},               // WAF 子域
		{"tower.example.com", false},            // 含 waf 字样但非独立标签
	}
	for _, tc := range cases {
		out := prefilterCandidates([]Candidate{{URL: "http://" + tc.host, Host: tc.host}})
		got := len(out) == 0
		if got != tc.skip {
			t.Errorf("prefilterCandidates(%q) skip = %v, want %v", tc.host, got, tc.skip)
		}
	}
}
