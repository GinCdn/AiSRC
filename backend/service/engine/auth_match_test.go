package engine

import (
	"testing"

	"AiSRC/model"
)

// TestMatchAuthBindingExactURLWins 精确 URL 优先级最高。
func TestMatchAuthBindingExactURLWins(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "*", Username: "star", Password: "p"},
		{Target: "dvwa.gincdn.cc", Username: "byhost", Password: "p"},
		{Target: "https://dvwa.gincdn.cc/login.php", Username: "byurl", Password: "p"},
	}
	got := MatchAuthBinding("https://dvwa.gincdn.cc/login.php", bindings, []string{"https://dvwa.gincdn.cc"})
	if got == nil || got.Username != "byurl" {
		t.Fatalf("精确 URL 应优先命中，实际 %+v", got)
	}
	if got.MatchedBy != "url" {
		t.Fatalf("命中方式应为 url，实际 %q", got.MatchedBy)
	}
}

// TestMatchAuthBindingBeatsWildcard 通配只在没有更具体的绑定时兜底。
func TestMatchAuthBindingBeatsWildcard(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "*", Username: "star", Password: "p"},
		{Target: "dvwa.gincdn.cc", Username: "byhost", Password: "p"},
	}
	got := MatchAuthBinding("https://dvwa.gincdn.cc/", bindings, nil)
	if got == nil || got.Username != "byhost" {
		t.Fatalf("同主机绑定应压过通配，实际 %+v", got)
	}

	got = MatchAuthBinding("https://other.example.com/", bindings, nil)
	if got == nil || got.Username != "star" {
		t.Fatalf("无更具体绑定时应回落到通配，实际 %+v", got)
	}
	if got.MatchedBy != "default" {
		t.Fatalf("通配命中方式应为 default，实际 %q", got.MatchedBy)
	}
}

// TestMatchAuthBindingSameHostMerges 与原版一致：缺端口的绑定都落进 host:port 桶，
// 同主机多条绑定按声明顺序合并，后出现者覆盖先出现者。
func TestMatchAuthBindingSameHostMerges(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "dvwa.gincdn.cc", Username: "byhost", Password: "p"},
		{Target: "https://dvwa.gincdn.cc/login.php", Username: "byurl", Password: "p"},
	}
	got := MatchAuthBinding("https://dvwa.gincdn.cc/vulnerabilities/sqli/", bindings, nil)
	if got == nil {
		t.Fatal("同主机绑定应命中")
	}
	if got.Username != "byurl" {
		t.Fatalf("同主机绑定应按顺序合并（后者覆盖），实际 %+v", got)
	}
}

// TestMatchAuthBindingHostportBeatsHost host:port 比裸 host 更具体。
func TestMatchAuthBindingHostportBeatsHost(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "dvwa.gincdn.cc", Username: "host", Password: "p"},
		{Target: "dvwa.gincdn.cc:8443", Username: "hostport", Password: "p"},
	}
	got := MatchAuthBinding("https://dvwa.gincdn.cc:8443/", bindings, nil)
	if got == nil || got.Username != "hostport" {
		t.Fatalf("host:port 应优先，实际 %+v", got)
	}
}

// TestMatchAuthBindingLineMatch 绑定的 target 命中清单行时归属 line 桶。
func TestMatchAuthBindingLineMatch(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "dvwa.gincdn.cc", Username: "byline", Password: "p"},
		{Target: "*", Username: "star", Password: "p"},
	}
	got := MatchAuthBinding("https://dvwa.gincdn.cc/x", bindings, []string{"dvwa.gincdn.cc"})
	if got == nil || got.Username != "byline" {
		t.Fatalf("清单行命中应压过通配，实际 %+v", got)
	}
}

// TestMatchAuthBindingNoBinding 无绑定或目标为空时返回 nil。
func TestMatchAuthBindingNoBinding(t *testing.T) {
	if got := MatchAuthBinding("https://a.example.com/", nil, nil); got != nil {
		t.Fatalf("无绑定应返回 nil，实际 %+v", got)
	}
	if got := MatchAuthBinding("", []model.AuthBinding{{Target: "*", Username: "u", Password: "p"}}, nil); got != nil {
		t.Fatalf("空目标应返回 nil，实际 %+v", got)
	}
	got := MatchAuthBinding("https://a.example.com/", []model.AuthBinding{{Target: "a.example.com", Cookie: "SID=1"}}, nil)
	if got == nil || got.Cookie != "SID=1" {
		t.Fatalf("Cookie 型绑定应被匹配，实际 %+v", got)
	}
}

// TestMatchAuthBindingDropsEmptyCredential 无任何可用凭据的绑定不参与匹配
// （对齐原版 normalize_bindings：kinds 为空即丢弃，避免"只有备注"的绑定占位）。
func TestMatchAuthBindingDropsEmptyCredential(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "a.example.com", Username: "only-user-no-password"},
		{Target: "a.example.com", Note: "只有备注"},
	}
	if got := MatchAuthBinding("https://a.example.com/", bindings, nil); got != nil {
		t.Fatalf("无用凭据不应命中，实际 %+v", got)
	}
}

// TestMatchAuthBindingParsesRawBlob 用户直接粘贴原文时也能取出凭据（对齐 normalize_binding）。
func TestMatchAuthBindingParsesRawBlob(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "a.example.com", Raw: "用户名: admin 密码: secret123"},
	}
	got := MatchAuthBinding("https://a.example.com/", bindings, nil)
	if got == nil || got.Username != "admin" || got.Password != "secret123" {
		t.Fatalf("raw 用户名密码行应被解析，实际 %+v", got)
	}

	bindings = []model.AuthBinding{
		{Target: "a.example.com", Raw: "Cookie: PHPSESSID=xyz; theme=dark"},
	}
	got = MatchAuthBinding("https://a.example.com/", bindings, nil)
	if got == nil || len(parseCookieString(got.Cookie)) != 2 {
		t.Fatalf("raw Cookie 头应被解析，实际 %+v", got)
	}
}

// TestMatchAuthBindingMerges 命中多条同优先级绑定时合并。
func TestMatchAuthBindingMerges(t *testing.T) {
	bindings := []model.AuthBinding{
		{Target: "dvwa.gincdn.cc", Username: "admin", LoginURL: "https://dvwa.gincdn.cc/login.php", Cookie: "SID=1"},
		{Target: "dvwa.gincdn.cc", Password: "password", Cookie: "PHPSESSID=abc"},
	}
	got := MatchAuthBinding("https://dvwa.gincdn.cc/", bindings, nil)
	if got == nil {
		t.Fatal("应命中 host 桶")
	}
	if got.Username != "admin" || got.Password != "password" || got.Cookie != "PHPSESSID=abc" {
		t.Fatalf("合并结果不正确：%+v", got)
	}
}
