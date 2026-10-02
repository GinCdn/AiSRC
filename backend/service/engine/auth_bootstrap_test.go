package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"AiSRC/model"
)

// TestNormalizeAuthBindingParsesRaw 用户粘贴的原文能被解析成结构化凭据。
func TestNormalizeAuthBindingParsesRaw(t *testing.T) {
	cases := []struct {
		name          string
		raw           string
		wantUser      string
		wantPass      string
		wantCookie    string
		wantAuthz     string
		wantKindCount int
	}{
		{name: "authorization 头", raw: "Authorization: Bearer abc.def", wantAuthz: "Bearer abc.def", wantKindCount: 1},
		{name: "裸 bearer", raw: "Bearer xyz", wantAuthz: "Bearer xyz", wantKindCount: 1},
		{name: "纯 token 前缀补 Bearer", raw: "Authorization: abc123", wantAuthz: "Bearer abc123", wantKindCount: 1},
		{name: "cookie 头", raw: "Cookie: PHPSESSID=xyz; theme=dark", wantCookie: "PHPSESSID=xyz; theme=dark", wantKindCount: 1},
		{name: "中文用户名密码行", raw: "用户名: root 密码: toor", wantUser: "root", wantPass: "toor", wantKindCount: 1},
		{name: "英文 user pass 行", raw: "username=admin password=p@ss", wantUser: "admin", wantPass: "p@ss", wantKindCount: 1},
		{name: "user/pass 简写", raw: "admin / passw0rd", wantUser: "admin", wantPass: "passw0rd", wantKindCount: 1},
	}
	for _, item := range cases {
		got := NormalizeAuthBinding(model.AuthBinding{Target: "a.example.com", Raw: item.raw})
		if got.Username != item.wantUser || got.Password != item.wantPass {
			t.Fatalf("[%s] 账密解析错误：%q / %q", item.name, got.Username, got.Password)
		}
		if got.Cookie != item.wantCookie {
			t.Fatalf("[%s] Cookie 解析错误：%q", item.name, got.Cookie)
		}
		if got.Authorization != item.wantAuthz {
			t.Fatalf("[%s] Authorization 解析错误：%q", item.name, got.Authorization)
		}
		if kinds := AuthKindsOf(got); len(kinds) != item.wantKindCount {
			t.Fatalf("[%s] kinds 数量错误：%v", item.name, kinds)
		}
	}
}

// TestNormalizeAuthBindingKeepsExplicitFields 显式字段优先于 raw 推断。
func TestNormalizeAuthBindingKeepsExplicitFields(t *testing.T) {
	got := NormalizeAuthBinding(model.AuthBinding{
		Username: "explicit", Password: "explicit-pw",
		Raw: "用户名: raw 密码: raw-pw",
	})
	if got.Username != "explicit" || got.Password != "explicit-pw" {
		t.Fatalf("显式字段应优先，实际 %+v", got)
	}
}

// TestExtractLoginForm 从 HTML 中抽出含密码框的表单。
func TestExtractLoginForm(t *testing.T) {
	html := `<html><body>
	<form action="/signin" method="post">
		<input type="hidden" name="csrf_token" value="tok-1">
		<input type="text" name="username" value="">
		<input type="password" name="password">
		<input type="submit" name="commit" value="登录">
	</form></body></html>`

	form := extractLoginForm(html, "http://a.example.com/login")
	if form == nil {
		t.Fatal("应抽取到登录表单")
	}
	if form.Action != "http://a.example.com/signin" {
		t.Fatalf("action 解析错误：%q", form.Action)
	}
	if len(form.Fields) != 4 {
		t.Fatalf("字段数量错误：%v", form.Fields)
	}
	if form.Fields[0].Name != "csrf_token" || form.Fields[0].Value != "tok-1" {
		t.Fatalf("隐藏域未保留：%v", form.Fields[0])
	}

	if got := extractLoginForm("<html>no form</html>", "http://a/"); got != nil {
		t.Fatalf("无表单应返回 nil，实际 %+v", got)
	}
}

// TestFillLoginFields 账号密码字段选择要跳过 CSRF 隐藏域。
func TestFillLoginFields(t *testing.T) {
	form := &loginForm{Action: "http://a/", Fields: []formField{
		{Name: "csrf_token", Value: "tok-1"},
		{Name: "user_token", Value: "tok-2"},
		{Name: "username", Value: ""},
		{Name: "password", Value: ""},
	}}
	filled := fillLoginFields(form, "admin", "pw")
	values := map[string]string{}
	for _, field := range filled {
		values[field.Name] = field.Value
	}
	if values["user_token"] != "tok-2" || values["csrf_token"] != "tok-1" {
		t.Fatalf("CSRF 隐藏域被错误改写：%v", values)
	}
	if values["username"] != "admin" || values["password"] != "pw" {
		t.Fatalf("账密未正确填入：%v", values)
	}
}

// TestFillLoginFieldsFallback 无标准名字时按正则兜底。
func TestFillLoginFieldsFallback(t *testing.T) {
	form := &loginForm{Action: "http://a/", Fields: []formField{
		{Name: "account_name", Value: ""},
		{Name: "passwd", Value: ""},
	}}
	filled := fillLoginFields(form, "admin", "pw")
	values := map[string]string{}
	for _, field := range filled {
		values[field.Name] = field.Value
	}
	if values["account_name"] != "admin" || values["passwd"] != "pw" {
		t.Fatalf("兜底字段选择错误：%v", values)
	}
}

// TestLoginOrigin 登录只打站点根。
func TestLoginOrigin(t *testing.T) {
	cases := map[string]string{
		"https://dvwa.gincdn.cc/druid/index.html": "https://dvwa.gincdn.cc",
		"http://a.example.com:8080/x/y?a=1":       "http://a.example.com:8080",
		"a.example.com":                           "http://a.example.com",
		"":                                        "",
	}
	for raw, want := range cases {
		if got := loginOrigin(raw); got != want {
			t.Fatalf("loginOrigin(%q) = %q，期望 %q", raw, got, want)
		}
	}
}

// startLoginServer 起一个"首页跳登录页 + 表单登录"的模拟靶站。
func startLoginServer() (*httptest.Server, *url.Values) {
	lastPost := &url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/login.php", http.StatusFound)
		case "/login.php":
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				*lastPost = r.PostForm
				if r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "password" {
					http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "fresh-session", Path: "/"})
					http.Redirect(w, r, "/index.php", http.StatusFound)
					return
				}
				_, _ = w.Write([]byte("<html><body>Login failed</body></html>"))
				return
			}
			_, _ = w.Write([]byte(`<html><body>
			<form action="login.php" method="post">
				<input type="text" name="username">
				<input type="password" name="password">
				<input type="submit" name="Login" value="Login">
			</form></body></html>`))
		case "/index.php":
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	return server, lastPost
}

// TestTryUserLoginSuccess 完整表单登录：拿到会话 Cookie 并跳离登录页。
func TestTryUserLoginSuccess(t *testing.T) {
	server, lastPost := startLoginServer()
	defer server.Close()

	state := newSessionState(server.URL)
	ok, reason := tryUserLogin(context.Background(), state, server.URL, "admin", "password", "")
	if !ok {
		t.Fatalf("登录应成功，实际失败：%s", reason)
	}
	if lastPost.Get("username") != "admin" || lastPost.Get("password") != "password" {
		t.Fatalf("提交的表单字段不正确：%v", *lastPost)
	}
	if names := state.cookieNames(nil); len(names) != 1 || names[0] != "PHPSESSID" {
		t.Fatalf("登录后未持有会话 Cookie：%v", names)
	}
}

// TestTryUserLoginBadPassword 明确的口令错误要被识别为失败而不是"静默成功"。
func TestTryUserLoginBadPassword(t *testing.T) {
	server, _ := startLoginServer()
	defer server.Close()

	state := newSessionState(server.URL)
	ok, reason := tryUserLogin(context.Background(), state, server.URL, "admin", "wrong-password", "")
	if ok {
		t.Fatal("错误口令不应判定为登录成功")
	}
	if !strings.Contains(reason, "用户名或密码错误") {
		t.Fatalf("失败原因应指出口令错误，实际 %q", reason)
	}
}

// TestBootstrapAuthCookieOnly 只有 Cookie 时直接注入，不发起登录。
func TestBootstrapAuthCookieOnly(t *testing.T) {
	session := &WorkerSession{TaskID: "t1", TargetID: "tg1", TargetURL: "http://a.example.com/"}
	attempt := BootstrapAuth(context.Background(), session, &model.AuthBinding{
		Target: "a.example.com", Cookie: "PHPSESSID=abc",
	})
	if attempt == nil {
		t.Fatal("应返回尝试结果")
	}
	if attempt.Status != "injected" {
		t.Fatalf("状态应为 injected，实际 %q（%s）", attempt.Status, attempt.Reason)
	}
	if len(session.Session().cookieNames(nil)) != 1 {
		t.Fatalf("会话态未注入：%v", session.Session().cookieNames(nil))
	}
}

// TestBootstrapAuthNoBinding 无凭据时不产生任何事件与提示。
func TestBootstrapAuthNoBinding(t *testing.T) {
	session := &WorkerSession{TaskID: "t1", TargetURL: "http://a.example.com/"}
	if attempt := BootstrapAuth(context.Background(), session, nil); attempt != nil {
		t.Fatalf("无凭据应返回 nil，实际 %+v", attempt)
	}
	empty := &model.AuthBinding{Target: "a.example.com", Note: "只有备注"}
	attempt := BootstrapAuth(context.Background(), session, empty)
	if attempt == nil || attempt.Status != "unused" || attempt.Used {
		t.Fatalf("空凭据应判 unused，实际 %+v", attempt)
	}
}

// TestBootstrapAuthLoginFlow 账密由服务端完成登录，且密码不出本机、不进上下文。
func TestBootstrapAuthLoginFlow(t *testing.T) {
	server, _ := startLoginServer()
	defer server.Close()

	session := &WorkerSession{TaskID: "t1", TargetID: "tg1", TargetURL: server.URL + "/"}
	attempt := BootstrapAuth(context.Background(), session, &model.AuthBinding{
		Target: "a.example.com", Username: "admin", Password: "password",
	})
	if attempt == nil || attempt.Status != "login_ok" {
		t.Fatalf("应登录成功，实际 %+v", attempt)
	}
	if !containsString(attempt.Kinds, "password") {
		t.Fatalf("kinds 应含 password，实际 %v", attempt.Kinds)
	}
	if len(session.Session().cookieNames(nil)) == 0 {
		t.Fatal("登录后会话态为空")
	}

	// 提示词只描述结果，绝不回显口令。
	block := UserAuthPromptBlock(&model.AuthBinding{Username: "admin", Password: "password"}, attempt)
	if strings.Contains(block, "password") && strings.Contains(block, "密码已由系统持有") == false {
		t.Fatalf("提示词可能泄漏口令：\n%s", block)
	}
	if !strings.Contains(block, "密码已由系统持有") || !strings.Contains(block, "登录成功") {
		t.Fatalf("提示词缺少凭据说明或尝试结果：\n%s", block)
	}
}

// TestBootstrapAuthLoginFailure 登录失败要如实反映，不能假装已就绪。
func TestBootstrapAuthLoginFailure(t *testing.T) {
	server, _ := startLoginServer()
	defer server.Close()

	session := &WorkerSession{TaskID: "t1", TargetURL: server.URL + "/"}
	attempt := BootstrapAuth(context.Background(), session, &model.AuthBinding{
		Username: "admin", Password: "nope",
	})
	if attempt == nil || attempt.Status != "login_fail" {
		t.Fatalf("应判定登录失败，实际 %+v", attempt)
	}
	message := FormatAuthStatusMessage(*attempt)
	if !strings.Contains(message, "登录失败") {
		t.Fatalf("事件文案错误：%q", message)
	}
}

// TestUserAuthPromptBlockNoPasswordLeak 任何情况下都不把口令写进提示词。
func TestUserAuthPromptBlockNoPasswordLeak(t *testing.T) {
	binding := &model.AuthBinding{
		Target: "a.example.com", Username: "admin", Password: "s3cret-pw",
		Raw: "用户名: admin 密码: s3cret-pw",
	}
	block := UserAuthPromptBlock(binding, nil)
	if strings.Contains(block, "s3cret-pw") {
		t.Fatalf("提示词泄漏了口令：\n%s", block)
	}
	if !strings.Contains(block, "admin") {
		t.Fatalf("提示词应保留账号名：\n%s", block)
	}
}

// TestSessionCarryAfterBootstrapLogin 端到端：登录一次后，后续对受限页面的请求
// 自动带登录态——这正是「服务端登录自动化」要解决的问题。用 DVWA 式的
// 首页跳登录页 + 会话校验流程模拟。
func TestSessionCarryAfterBootstrapLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := false
		if cookie, err := r.Cookie("PHPSESSID"); err == nil && cookie.Value == "good" {
			authorized = true
		}
		switch r.URL.Path {
		case "/login.php":
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				if r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "password" {
					http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "good", Path: "/"})
					http.Redirect(w, r, "/index.php", http.StatusFound)
					return
				}
				_, _ = w.Write([]byte("<html>Login failed</html>"))
				return
			}
			_, _ = w.Write([]byte(`<form action="login.php" method="post">
			<input type="text" name="username"><input type="password" name="password"></form>`))
		case "/", "/index.php":
			if !authorized {
				http.Redirect(w, r, "/login.php", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("<html>Welcome admin</html>"))
		case "/vulnerabilities/sqli/":
			if !authorized {
				http.Redirect(w, r, "/login.php", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("<html>SQL Injection</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := &WorkerSession{TaskID: "t1", TargetID: "tg1", TargetURL: server.URL + "/"}
	attempt := BootstrapAuth(context.Background(), session, &model.AuthBinding{
		Target: "*", Username: "admin", Password: "password",
	})
	if attempt == nil || attempt.Status != "login_ok" {
		t.Fatalf("启动登录应成功，实际 %+v", attempt)
	}

	// 登录后访问受限页面：不跟随时应直接 200，而不是被 302 打回登录页。
	exchange := doHTTP(context.Background(), session.Session(), httpCall{
		URL: server.URL + "/vulnerabilities/sqli/",
	})
	if exchange.StatusCode != http.StatusOK {
		t.Fatalf("受限页面应带登录态返回 200，实际 %d（final=%s）", exchange.StatusCode, exchange.FinalURL)
	}
	if !strings.Contains(exchange.Body, "SQL Injection") {
		t.Fatalf("未拿到受限页面正文：%s", exchange.Body)
	}
	if !containsString(exchange.Applied, "Cookie(1)") {
		t.Fatalf("请求应自动携带会话 Cookie，实际 %v", exchange.Applied)
	}
}

// TestFormatAuthStatusMessage 事件文案对齐原版的四种状态。
func TestFormatAuthStatusMessage(t *testing.T) {
	cases := []struct {
		attempt AuthAttempt
		want    string
	}{
		{AuthAttempt{Status: "unused", BindingTarget: "*", Reason: "未匹配本目标"}, "凭据未使用：未匹配本目标"},
		{AuthAttempt{Status: "injected", Kinds: []string{"cookie"}, BindingTarget: "a.example.com", CookieNames: []string{"SID"}}, "凭据[cookie] → 绑定 a.example.com → 已注入 SID"},
		{AuthAttempt{Status: "login_ok", Kinds: []string{"password"}, BindingTarget: "a.example.com", Reason: "登录成功（cookies=1）"}, "凭据[password] → 绑定 a.example.com → 登录成功：登录成功（cookies=1）"},
		{AuthAttempt{Status: "login_fail", Kinds: []string{"password"}, BindingTarget: "a.example.com", Reason: "登录失败：HTTP 403"}, "凭据[password] → 绑定 a.example.com → 登录失败：登录失败：HTTP 403"},
	}
	for _, item := range cases {
		if got := FormatAuthStatusMessage(item.attempt); got != item.want {
			t.Fatalf("文案不匹配：\n实际 %q\n期望 %q", got, item.want)
		}
	}
}
