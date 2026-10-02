package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseCookieString 容忍 "Cookie:" 前缀、空格与空段。
func TestParseCookieString(t *testing.T) {
	cases := []struct {
		raw   string
		count int
	}{
		{"", 0},
		{"abc", 0},
		{"a=1", 1},
		{"a=1; b=2", 2},
		{"Cookie: a=1; b=2", 2},
		{"a=1;;b=2;   ", 2},
		{"PHPSESSID=abc123; theme=dark", 2},
	}
	for _, item := range cases {
		if got := parseCookieString(item.raw); len(got) != item.count {
			t.Fatalf("parseCookieString(%q) 期望 %d 项，实际 %d（%v）", item.raw, item.count, len(got), got)
		}
	}
	if got := parseCookieString("Cookie: PHPSESSID=xyz")["PHPSESSID"]; got != "xyz" {
		t.Fatalf("前缀解析错误，实际 %q", got)
	}
}

// TestSetCookieNames 从 Set-Cookie 头里取名字。
func TestSetCookieNames(t *testing.T) {
	names := setCookieNames([]string{"PHPSESSID=1; Path=/", "token=x; HttpOnly", "bad"})
	if len(names) != 2 || names[0] != "PHPSESSID" || names[1] != "token" {
		t.Fatalf("解析结果错误：%v", names)
	}
}

// TestRequestSetupCarriesSession 会话头与会话 Cookie 被自动携带。
func TestRequestSetupCarriesSession(t *testing.T) {
	state := newSessionState("http://target.example.com/")
	state.applyHeaders(map[string]string{"Authorization": "Bearer t"})
	state.applyCookies(nil, map[string]string{"SID": "abc"})

	headers, applied := state.requestSetup(parseAuthURL("http://target.example.com/a"), nil)
	if headers["Authorization"] != "Bearer t" {
		t.Fatalf("鉴权头未携带：%v", headers)
	}
	if headers["User-Agent"] == "" {
		t.Fatal("默认 UA 缺失")
	}
	// Cookie 交给 http.Client 从 jar 补，手工再写会重复发送。
	if headers["Cookie"] != "" {
		t.Fatalf("jar 命中时不应手工设置 Cookie 头，实际 %q", headers["Cookie"])
	}
	if !containsString(applied, "Cookie(1)") || !containsString(applied, "headers(1)") {
		t.Fatalf("applied 摘要不正确：%v", applied)
	}
}

// TestRequestSetupFallsBackToManualCookie jar 无法登记时走兜底池。
func TestRequestSetupFallsBackToManualCookie(t *testing.T) {
	state := newSessionState("")
	state.applyCookies(nil, map[string]string{"SID": "abc"})
	headers, applied := state.requestSetup(parseAuthURL("http://x.example.com/"), nil)
	if headers["Cookie"] != "SID=abc" {
		t.Fatalf("兜底 Cookie 未生效：%q", headers["Cookie"])
	}
	if !containsString(applied, "Cookie(1)") {
		t.Fatalf("applied 摘要不正确：%v", applied)
	}
}

// TestRequestSetupCallerCookieWhenSessionEmpty 会话为空时尊重调用方给的 Cookie。
func TestRequestSetupCallerCookieWhenSessionEmpty(t *testing.T) {
	state := newSessionState("http://h.example.com/")
	headers, _ := state.requestSetup(parseAuthURL("http://h.example.com/"), map[string]string{"Cookie": "B=2"})
	if headers["Cookie"] != "B=2" {
		t.Fatalf("会话为空时应保留调用方 Cookie，实际 %q", headers["Cookie"])
	}

	// 一旦有会话态，调用方临时 Cookie 让位（对齐原版行为）。
	state.applyCookies(nil, map[string]string{"A": "1"})
	headers, _ = state.requestSetup(parseAuthURL("http://h.example.com/"), map[string]string{"Cookie": "B=2"})
	if headers["Cookie"] != "" {
		t.Fatalf("会话就绪后不应再写调用方 Cookie，实际 %q", headers["Cookie"])
	}
}

// TestSessionAbsorbsSetCookie httptest 验证：响应 Set-Cookie 被吸收，后续请求自动带上。
func TestSessionAbsorbsSetCookie(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "sess123", Path: "/"})
			_, _ = w.Write([]byte("set"))
			return
		}
		seen = append(seen, r.Header.Get("Cookie"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	state := newSessionState(server.URL)
	exchange := doHTTP(context.Background(), state, httpCall{URL: server.URL + "/set"})
	if !exchange.OK {
		t.Fatalf("请求失败：%s", exchange.Error)
	}
	names := state.cookieNames(nil)
	if len(names) != 1 || names[0] != "PHPSESSID" {
		t.Fatalf("Set-Cookie 未被吸收：%v", names)
	}

	if exchange := doHTTP(context.Background(), state, httpCall{URL: server.URL + "/check"}); !exchange.OK {
		t.Fatalf("第二次请求失败：%s", exchange.Error)
	}
	if len(seen) != 1 || seen[0] != "PHPSESSID=sess123" {
		t.Fatalf("后续请求未自动携带会话 Cookie：%v", seen)
	}
}

// TestDoHTTPTracksRedirectTarget 跟随跳转时记录终点，不跟随时保留原地址。
func TestDoHTTPTracksRedirectTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/from" {
			http.Redirect(w, r, "/to", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("landed"))
	}))
	defer server.Close()

	state := newSessionState(server.URL)
	followed := doHTTP(context.Background(), state, httpCall{URL: server.URL + "/from", FollowRedirects: true})
	if !strings.HasSuffix(followed.FinalURL, "/to") {
		t.Fatalf("跳转终点应为 /to，实际 %q", followed.FinalURL)
	}
	if followed.StatusCode != http.StatusOK {
		t.Fatalf("应落到 200，实际 %d", followed.StatusCode)
	}

	notFollowed := doHTTP(context.Background(), state, httpCall{URL: server.URL + "/from"})
	if notFollowed.StatusCode != http.StatusFound || !strings.HasSuffix(notFollowed.FinalURL, "/from") {
		t.Fatalf("不跟随时应停在 302/from，实际 %d %q", notFollowed.StatusCode, notFollowed.FinalURL)
	}
}

// TestSessionStatusBlockHidesValues 状态块只出 Cookie 名，不出值。
func TestSessionStatusBlockHidesValues(t *testing.T) {
	state := newSessionState("http://h.example.com/")
	state.applyCookies(nil, map[string]string{"SID": "super-secret-value"})
	state.applyHeaders(map[string]string{"Authorization": "Bearer top-secret"})

	block := state.statusBlock()
	if strings.Contains(block, "super-secret-value") || strings.Contains(block, "top-secret") {
		t.Fatalf("状态块泄漏了凭据值：\n%s", block)
	}
	if !strings.Contains(block, "SID") || !strings.Contains(block, "Authorization") {
		t.Fatalf("状态块缺少字段名：\n%s", block)
	}
}

// TestSessionClear 清空后不再持有任何会话态。
func TestSessionClear(t *testing.T) {
	state := newSessionState("http://h.example.com/")
	state.applyCookies(nil, map[string]string{"SID": "abc"})
	state.applyHeaders(map[string]string{"Authorization": "Bearer t"})
	state.clear()
	if len(state.cookieNames(nil)) != 0 || len(state.headerNames()) != 0 {
		t.Fatalf("clear 后仍持有会话态：%v / %v", state.cookieNames(nil), state.headerNames())
	}
	if !strings.Contains(state.statusBlock(), "暂无登录态") {
		t.Fatalf("clear 后状态块应提示无登录态：%s", state.statusBlock())
	}
}

// TestHandleSessionSetRegistersState session_set 工具登记 Cookie/头，且回执不回显凭据值。
func TestHandleSessionSetRegistersState(t *testing.T) {
	session := &WorkerSession{TaskID: "t1", TargetID: "tg1", TargetURL: "http://a.example.com/"}
	result := handleSessionSet(context.Background(), map[string]any{
		"cookies": map[string]any{"SID": "secret-cookie"},
		"headers": map[string]any{"Authorization": "Bearer secret-token"},
	}, session)
	if result.IsErr {
		t.Fatalf("登记会话态失败：%s", result.Output)
	}
	if names := session.Session().cookieNames(nil); len(names) != 1 || names[0] != "SID" {
		t.Fatalf("Cookie 未登记：%v", names)
	}
	if names := session.Session().headerNames(); len(names) != 1 || names[0] != "Authorization" {
		t.Fatalf("会话头未登记：%v", names)
	}
	if strings.Contains(result.Output, "secret-cookie") || strings.Contains(result.Output, "secret-token") {
		t.Fatalf("工具回执泄漏了凭据：%s", result.Output)
	}

	// 全新会话下空参数无效，应明确报错而不是假装登记成功。
	fresh := &WorkerSession{TaskID: "t1", TargetURL: "http://a.example.com/"}
	empty := handleSessionSet(context.Background(), map[string]any{}, fresh)
	if !empty.IsErr {
		t.Fatalf("空参数应报错，实际 %s", empty.Output)
	}
}

// TestHandleSessionSetAcceptsCookieString 支持直接给 Cookie 字符串。
func TestHandleSessionSetAcceptsCookieString(t *testing.T) {
	session := &WorkerSession{TaskID: "t1", TargetURL: "http://a.example.com/"}
	result := handleSessionSet(context.Background(), map[string]any{
		"cookie": "Cookie: PHPSESSID=x; theme=dark",
	}, session)
	if result.IsErr {
		t.Fatalf("登记失败：%s", result.Output)
	}
	if names := session.Session().cookieNames(nil); len(names) != 2 {
		t.Fatalf("Cookie 串未解析为 2 项：%v", names)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
