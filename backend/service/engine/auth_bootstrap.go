package engine

// 用户提供的登录凭据：解析类型、按目标匹配、启动必试注入/登录。
//
// 这是对原版 app/agents/auth_bootstrap.py 的完整移植。原版之所以必须有这一层，
// 是因为「把账号密码写进提示词让模型自己登录」既泄漏凭据又不可靠：
// 密码会随上下文发往第三方模型，且模型经常把 token 抄错。
// 因此登录由服务端完成——密码不出本机、不进上下文，模型只拿到「已就绪」的回执。
//
// 不提供凭据时整条链路无操作（兼容现状）。事件/状态只暴露 kinds 与字段名，不出明文。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"AiSRC/model"
)

// ---- Raw 串解析 ----

var (
	bearerRe       = regexp.MustCompile(`(?i)\bBearer\s+(\S+)`)
	authHeaderRe   = regexp.MustCompile(`(?im)^\s*Authorization\s*:\s*(.+)$`)
	cookieHeaderRe = regexp.MustCompile(`(?im)^\s*Cookie\s*:\s*(.+)$`)
	userPassRe     = regexp.MustCompile(`(?i)(?:用户名|账号|帐号|账户|username|user)\s*[:=：]\s*(\S+).{0,40}?` +
		`(?:密码|password|passwd|pwd)\s*[:=：]\s*(\S+)`)
	slashPairRe   = regexp.MustCompile(`(?i)^\s*([^\s/]{1,64})\s*/\s*([^\s]{1,128})\s*$`)
	kvCookieRe    = regexp.MustCompile(`^[A-Za-z0-9_.\-]+=\S+`)
	bearerPreRe   = regexp.MustCompile(`(?i)^Bearer\s+`)
	schemeWordRe  = regexp.MustCompile(`(?i)^\w+\s+`)
	userFieldRe   = regexp.MustCompile(`(?i)user|account|login|email|name`)
	passFieldRe   = regexp.MustCompile(`(?i)pass|pwd`)
	formRe        = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
	passwordType  = regexp.MustCompile(`(?i)type=["']?password`)
	formActionRe  = regexp.MustCompile(`(?is)<form\b[^>]*\baction=["']([^"']*)["']`)
	inputRe       = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	inputNameRe   = regexp.MustCompile(`(?i)\bname=["']([^"']+)["']`)
	inputValueRe  = regexp.MustCompile(`(?i)\bvalue=["']([^"']*)["']`)
	captchaRe     = regexp.MustCompile(`(?i)(验证码|captcha|太多次|锁定|locked|too many)`)
	badPasswordRe = regexp.MustCompile(`(?i)(密码错误|用户名或密码|login failed|invalid (user|password)|认证失败)`)
	jsonOKRe      = regexp.MustCompile(`(?i)"(code|status|success)"\s*:\s*(200|0|true|"ok")`)
	sessionNameRe = regexp.MustCompile(`(?i)session|token|castgc|jwt|auth`)
	nonLoginPath  = regexp.MustCompile(`(?i)/(?:druid|actuator|nacos|\.env|\.git|swagger|api-docs|heapdump|metrics|webjars)(?:/|$|\.)`)
)

// loginPaths 常见登录入口（对齐原版 _LOGIN_PATHS）。
var loginPaths = []string{
	"/login", "/user/login", "/admin/login", "/account/login", "/signin",
	"/cas/login", "/auth/login",
}

// jsonLoginPaths 无表单站点的 JSON 登录接口候选（对齐原版 try_user_login）。
var jsonLoginPaths = []string{"/api/login", "/api/user/login", "/api/auth/login", "/login"}

// loginUserNames / loginPassNames 账号密码字段的优先名（按精确匹配优先挑选）。
var (
	loginUserNames = []string{"username", "user_name", "user", "uname", "account", "loginname", "login", "email", "j_username"}
	loginPassNames = []string{"password", "passwd", "pwd", "pass", "userpass", "j_password"}
	// loginTokenRe 命中即跳过：这些字段是 CSRF/验证码等，不能被账号密码覆盖。
	loginTokenRe = regexp.MustCompile(`(?i)token|csrf|nonce|captcha|verify|captcha|code|submit|button`)
)

// NormalizeAuthBinding 规范化一条绑定的凭据内容。
//
// 用户往往直接粘贴一段原文（Burp 里复制的请求头、`用户名: xxx 密码: yyy` 一行、
// 或 `user/pass` 简写），这里按原版 normalize_binding 的优先级把能认出来的都认出来：
// Authorization 头 → Cookie 头 → Bearer token → 用户名密码行 → user/pass 简写 → 裸 Cookie 串。
func NormalizeAuthBinding(src model.AuthBinding) model.AuthBinding {
	out := src
	out.Target = strings.TrimSpace(out.Target)
	if out.Target == "" {
		out.Target = "*"
	}
	out.Username = strings.TrimSpace(out.Username)
	out.Password = strings.TrimSpace(out.Password)
	out.Cookie = strings.TrimSpace(out.Cookie)
	out.Authorization = strings.TrimSpace(out.Authorization)
	out.LoginURL = strings.TrimSpace(out.LoginURL)
	out.Note = strings.TrimSpace(out.Note)
	out.MatchedBy = strings.TrimSpace(out.MatchedBy)
	blob := strings.TrimSpace(out.Raw)

	if blob != "" {
		if m := authHeaderRe.FindStringSubmatch(blob); m != nil && out.Authorization == "" {
			out.Authorization = strings.TrimSpace(m[1])
		}
		if m := cookieHeaderRe.FindStringSubmatch(blob); m != nil && out.Cookie == "" {
			out.Cookie = strings.TrimSpace(m[1])
		}
		if m := bearerRe.FindStringSubmatch(blob); m != nil && out.Authorization == "" {
			out.Authorization = "Bearer " + m[1]
		}
		if m := userPassRe.FindStringSubmatch(blob); m != nil {
			if out.Username == "" || out.Password == "" {
				out.Username, out.Password = m[1], m[2]
			}
		}
		if out.Username == "" || out.Password == "" {
			// 仅当首行整行像 user/pass 且不像 Cookie 串时才认，避免把 "PHPSESSID=a" 当凭据。
			first := strings.TrimSpace(strings.SplitN(blob, "\n", 2)[0])
			if m := slashPairRe.FindStringSubmatch(first); m != nil {
				head := blob
				if len(head) > 80 {
					head = head[:80]
				}
				if strings.Contains(first, "/") && !strings.Contains(head, "Cookie") && !strings.Contains(first, "=") {
					out.Username, out.Password = m[1], m[2]
				}
			}
		}
		// 只有没解析出账密时，才把整段当成裸 Cookie 串。
		// 否则 `username=admin password=p@ss` 这种一行账密会被 kvCookieRe 误判成 Cookie，
		// 往会话里塞一个名为 username 的垃圾 Cookie。
		if out.Cookie == "" && out.Username == "" && out.Password == "" {
			firstSegment := strings.TrimSpace(strings.SplitN(blob, ";", 2)[0])
			if kvCookieRe.MatchString(firstSegment) {
				out.Cookie = blob
			}
		}
	}

	if out.Authorization != "" && !bearerPreRe.MatchString(out.Authorization) && !schemeWordRe.MatchString(out.Authorization) {
		out.Authorization = "Bearer " + out.Authorization
	}
	return out
}

// AuthKindsOf 返回凭据形态（cookie / bearer / password），对齐原版 normalize_binding 的 kinds。
func AuthKindsOf(binding model.AuthBinding) []string {
	kinds := make([]string, 0, 3)
	if len(parseCookieString(binding.Cookie)) > 0 {
		kinds = append(kinds, "cookie")
	}
	if strings.TrimSpace(binding.Authorization) != "" {
		kinds = append(kinds, "bearer")
	}
	if binding.Username != "" && binding.Password != "" {
		kinds = append(kinds, "password")
	}
	return kinds
}

// authHeadersOf 返回需要长期携带的凭据头。
func authHeadersOf(binding model.AuthBinding) map[string]string {
	headers := map[string]string{}
	if strings.TrimSpace(binding.Authorization) != "" {
		headers["Authorization"] = strings.TrimSpace(binding.Authorization)
	}
	return headers
}

// ---- 启动必试 ----

// AuthAttempt 一次启动凭据尝试的结果（对齐原版 AuthAttemptResult）。
type AuthAttempt struct {
	Used          bool     `json:"used"`
	Matched       bool     `json:"matched"`
	Status        string   `json:"status"` // injected | login_ok | login_fail | unused
	Kinds         []string `json:"kinds"`
	MatchedBy     string   `json:"matched_by"`
	BindingTarget string   `json:"binding_target"`
	Reason        string   `json:"reason"`
	CookieNames   []string `json:"cookie_names"`
	HeaderNames   []string `json:"header_names"`
}

// AsEvent 事件载荷（只出字段名，不出凭据值）。
func (a AuthAttempt) AsEvent() map[string]any {
	reason := a.Reason
	if len([]rune(reason)) > 300 {
		reason = string([]rune(reason)[:300])
	}
	return map[string]any{
		"used":           a.Used,
		"matched":        a.Matched,
		"status":         a.Status,
		"kinds":          a.Kinds,
		"matched_by":     a.MatchedBy,
		"binding_target": a.BindingTarget,
		"reason":         reason,
		"cookie_names":   a.CookieNames,
		"header_names":   a.HeaderNames,
	}
}

// BootstrapAuth Worker 启动时调用：有 Cookie/Bearer 则注入；有账密则服务端尝试登录。
//
// 返回 nil 表示本目标根本没有匹配到凭据（原版此时不产生任何事件与提示）。
func BootstrapAuth(ctx context.Context, session *WorkerSession, binding *model.AuthBinding) *AuthAttempt {
	if session == nil || binding == nil {
		return nil
	}
	normalized := NormalizeAuthBinding(*binding)
	kinds := AuthKindsOf(normalized)
	bindingTarget := normalized.Target
	if bindingTarget == "" {
		bindingTarget = "*"
	}

	attempt := &AuthAttempt{
		Used:          true,
		Matched:       true,
		Kinds:         kinds,
		MatchedBy:     normalized.MatchedBy,
		BindingTarget: bindingTarget,
	}

	if len(kinds) == 0 {
		attempt.Used = false
		attempt.Status = "unused"
		attempt.Reason = "凭据为空"
		return attempt
	}

	state := session.Session()

	// 1) Cookie / Bearer 注入
	cookies := parseCookieString(normalized.Cookie)
	headers := authHeadersOf(normalized)
	if len(cookies) > 0 || len(headers) > 0 {
		scope := parseAuthURL(session.TargetURL)
		state.apply(scope, cookies, headers)
		if len(state.cookieNames(scope)) == 0 && len(state.headerNames()) == 0 {
			attempt.Status = "login_fail"
			attempt.Reason = "session_set 失败：会话态为空"
			return attempt
		}
	}

	// 2) 仅会话注入、无账密
	if normalized.Username == "" || normalized.Password == "" {
		attempt.Status = "injected"
		attempt.Reason = "已注入用户提供的 Cookie/Authorization，后续请求自动携带"
		attempt.CookieNames = state.cookieNames(nil)
		attempt.HeaderNames = state.headerNames()
		return attempt
	}

	// 3) 账密登录：始终打站点根，避免把 /druid、/actuator 这类路径当登录页
	loginBase := loginOrigin(session.TargetURL)
	if loginBase == "" {
		loginBase = session.TargetURL
	}
	ok, reason := tryUserLogin(ctx, state, loginBase, normalized.Username, normalized.Password, normalized.LoginURL)
	if ok {
		attempt.Status = "login_ok"
	} else {
		attempt.Status = "login_fail"
	}
	attempt.Reason = reason
	attempt.CookieNames = state.cookieNames(nil)
	attempt.HeaderNames = state.headerNames()
	return attempt
}

// loginOrigin 取站点根（登录只打根，不把 /druid /actuator 当登录页）。
func loginOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed := parseAuthURL(raw)
	if parsed == nil {
		return raw
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + parsed.Host
}

// tryUserLogin Best-effort 表单登录；成功则会话池已吸收 Set-Cookie。
func tryUserLogin(ctx context.Context, state *sessionState, baseURL, username, password, loginURL string) (bool, string) {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		return false, "无目标 URL"
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	origin := loginOrigin(base)
	if origin == "" {
		origin = base
	}
	path := "/"
	if parsed := parseAuthURL(base); parsed != nil && parsed.Path != "" {
		path = parsed.Path
	}

	candidates := make([]string, 0, len(loginPaths)+3)
	if loginURL != "" {
		if strings.Contains(loginURL, "://") {
			candidates = append(candidates, loginURL)
		} else {
			candidates = append(candidates, resolveURL(origin+"/", strings.TrimLeft(loginURL, "/")))
		}
	}
	if !nonLoginPath.MatchString(path) {
		if path == "" || path == "/" {
			candidates = append(candidates, origin)
		} else {
			candidates = append(candidates, base)
		}
	}
	candidates = append(candidates, origin)
	for _, p := range loginPaths {
		candidates = append(candidates, resolveURL(origin+"/", strings.TrimLeft(p, "/")))
	}

	seen := map[string]bool{}
	// navReason 记"页面不可用/没有登录表单"这类导航信息，authReason 记凭据被明确拒绝的原因。
	// 分开记的原因：原版用同一个变量，后面的候选页会把"用户名或密码错误"这种
	// 关键结论覆盖成"页面无登录表单"，模型最终只看到没用的噪声。
	navReason := "未找到可用登录表单"
	authReason := ""
	for _, pageURL := range candidates {
		if pageURL == "" || seen[pageURL] {
			continue
		}
		seen[pageURL] = true
		if parsed := parseAuthURL(pageURL); parsed != nil && nonLoginPath.MatchString(parsed.Path) {
			continue
		}

		getExchange := doHTTP(ctx, state, httpCall{
			Method:          "GET",
			URL:             pageURL,
			FollowRedirects: true,
			Timeout:         15 * time.Second,
		})
		if !getExchange.OK {
			navReason = "打开登录页失败: " + exchangeFailureText(getExchange)
			continue
		}

		form := extractLoginForm(getExchange.Body, pageURL)
		if form == nil {
			// JSON 风格站点：直接 POST 常见字段（同时带 username / userName / account）
			for _, apiPath := range jsonLoginPaths {
				apiURL := resolveURL(origin+"/", strings.TrimLeft(apiPath, "/"))
				if seen[apiURL] {
					continue
				}
				seen[apiURL] = true
				payload, _ := json.Marshal(map[string]string{
					"username": username, "password": password,
					"userName": username, "account": username,
				})
				postExchange := doHTTP(ctx, state, httpCall{
					Method:          "POST",
					URL:             apiURL,
					Headers:         map[string]string{"Content-Type": "application/json"},
					Body:            string(payload),
					FollowRedirects: true,
					Timeout:         15 * time.Second,
				})
				ok, reason := judgeLoginSuccess(state, postExchange, origin, "")
				if ok {
					return true, reason
				}
				if reason != "" && authReason == "" {
					authReason = reason
				}
			}
			navReason = "页面无登录表单: " + pageURL
			continue
		}

		fields := fillLoginFields(form, username, password)
		postExchange := doHTTP(ctx, state, httpCall{
			Method:          "POST",
			URL:             form.Action,
			Headers:         map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:            encodeForm(fields),
			FollowRedirects: true,
			Timeout:         20 * time.Second,
		})
		ok, reason := judgeLoginSuccess(state, postExchange, origin, pageURL)
		if ok {
			return true, reason
		}
		if reason != "" && authReason == "" {
			authReason = reason
		}
	}
	if authReason != "" {
		return false, authReason
	}
	return false, navReason
}

// exchangeFailureText 把请求失败原因渲染成一行文本。
func exchangeFailureText(exchange httpExchange) string {
	if exchange.Error != "" {
		return exchange.Error
	}
	return fmt.Sprintf("HTTP %d", exchange.StatusCode)
}

// loginForm 从 HTML 里抽出的登录表单。
type loginForm struct {
	Action string
	Fields []formField
}

// formField 表单字段（保持出现顺序，同名后者覆盖值但保序，对齐 Python dict 语义）。
type formField struct {
	Name  string
	Value string
}

// extractLoginForm 抽取第一个含 password 输入框的表单。
func extractLoginForm(html, pageURL string) *loginForm {
	if html == "" {
		return nil
	}
	for _, formHTML := range formRe.FindAllString(html, -1) {
		if !passwordType.MatchString(formHTML) {
			continue
		}
		action := pageURL
		if m := formActionRe.FindStringSubmatch(formHTML); m != nil && strings.TrimSpace(m[1]) != "" {
			action = m[1]
		}
		action = resolveURL(pageURL, action)

		fields := make([]formField, 0, 8)
		index := map[string]int{}
		for _, tag := range inputRe.FindAllString(formHTML, -1) {
			nameMatch := inputNameRe.FindStringSubmatch(tag)
			if nameMatch == nil {
				continue
			}
			name := nameMatch[1]
			value := ""
			if valueMatch := inputValueRe.FindStringSubmatch(tag); valueMatch != nil {
				value = valueMatch[1]
			}
			if pos, exists := index[name]; exists {
				fields[pos].Value = value
				continue
			}
			index[name] = len(fields)
			fields = append(fields, formField{Name: name, Value: value})
		}
		return &loginForm{Action: action, Fields: fields}
	}
	return nil
}

// fillLoginFields 按字段名启发式填入用户名与密码。
//
// 比原版更进一步：原版取「第一个匹配 user/account/login 的字段」，遇到
// `<input name="user_token">` 这种 CSRF 隐藏域就会把用户名填进 token 字段，
// 导致表单带上了错误的 CSRF 值而登录失败。这里改为
// ① 优先精确命中常用字段名；② 跳过 token/csrf/captcha 等非凭据字段。
func fillLoginFields(form *loginForm, username, password string) []formField {
	fields := make([]formField, len(form.Fields))
	copy(fields, form.Fields)

	userKey := pickLoginField(fields, loginUserNames, userFieldRe)
	passKey := pickLoginField(fields, loginPassNames, passFieldRe)
	if userKey == "" {
		userKey = "username"
	}
	if passKey == "" {
		passKey = "password"
	}
	fields = setField(fields, userKey, username)
	fields = setField(fields, passKey, password)
	return fields
}

// pickLoginField 先按常用名精确匹配，再按正则兜底；始终跳过 CSRF/验证码字段。
func pickLoginField(fields []formField, exactNames []string, pattern *regexp.Regexp) string {
	for _, want := range exactNames {
		for _, field := range fields {
			if strings.EqualFold(field.Name, want) && !loginTokenRe.MatchString(field.Name) {
				return field.Name
			}
		}
	}
	for _, field := range fields {
		if loginTokenRe.MatchString(field.Name) {
			continue
		}
		if pattern.MatchString(field.Name) {
			return field.Name
		}
	}
	return ""
}

// setField 就地更新字段值，不存在则追加（保持既有顺序）。
func setField(fields []formField, name, value string) []formField {
	for i := range fields {
		if fields[i].Name == name {
			fields[i].Value = value
			return fields
		}
	}
	return append(fields, formField{Name: name, Value: value})
}

// encodeForm 按 application/x-www-form-urlencoded 编码。
func encodeForm(fields []formField) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, url.QueryEscape(field.Name)+"="+url.QueryEscape(field.Value))
	}
	return strings.Join(parts, "&")
}

// judgeLoginSuccess 判定登录是否成功（对齐原版 _judge_login_success）。
func judgeLoginSuccess(state *sessionState, exchange httpExchange, origin, formURL string) (bool, string) {
	if !exchange.OK {
		return false, "登录请求失败: " + exchangeFailureText(exchange)
	}
	status := exchange.StatusCode
	bodyLower := strings.ToLower(exchange.Body)
	finalURL := strings.TrimSpace(exchange.FinalURL)
	if finalURL == "" {
		finalURL = origin
	}

	if captchaRe.MatchString(bodyLower) {
		return false, "登录失败：可能需要验证码或账号被锁定"
	}
	if status == 401 || status == 403 {
		return false, fmt.Sprintf("登录失败：HTTP %d", status)
	}
	if badPasswordRe.MatchString(bodyLower) {
		return false, "登录失败：用户名或密码错误"
	}

	cookies := state.cookieNames(parseAuthURL(origin))
	sessionish := false
	for _, name := range cookies {
		if sessionNameRe.MatchString(name) {
			sessionish = true
			break
		}
	}
	leftLogin := finalURL != "" && !strings.Contains(strings.ToLower(finalURL), "login") &&
		(formURL == "" || strings.TrimRight(finalURL, "/") != strings.TrimRight(formURL, "/"))
	jsonOK := jsonOKRe.MatchString(bodyLower)

	if sessionish || leftLogin || jsonOK || ((status == 200 || status == 302) && len(cookies) > 0) {
		return true, fmt.Sprintf("登录成功（cookies=%d, final=%s）", len(cookies), truncateRunes(finalURL, 80))
	}
	return false, "登录后未观察到有效会话 Cookie 或跳转，判定失败"
}

// ---- 提示词与事件文案 ----

// FormatAuthStatusMessage 事件文案（对齐原版 format_auth_status_message）。
func FormatAuthStatusMessage(attempt AuthAttempt) string {
	kinds := strings.Join(attempt.Kinds, ",")
	if kinds == "" {
		kinds = "-"
	}
	bind := attempt.BindingTarget
	if bind == "" {
		bind = "-"
	}
	via := "绑定 " + bind
	if attempt.MatchedBy == "shared" {
		via = "全局会话"
	}
	switch attempt.Status {
	case "unused":
		reason := attempt.Reason
		if reason == "" {
			reason = "未匹配本目标"
		}
		return "凭据未使用：" + reason
	case "injected":
		names := attempt.CookieNames
		if len(names) == 0 {
			names = attempt.HeaderNames
		}
		if len(names) == 0 {
			return fmt.Sprintf("凭据[%s] → %s → 已注入 %s", kinds, via, kinds)
		}
		return fmt.Sprintf("凭据[%s] → %s → 已注入 %s", kinds, via, strings.Join(names, ","))
	case "login_ok":
		return fmt.Sprintf("凭据[%s] → %s → 登录成功：%s", kinds, via, attempt.Reason)
	case "login_fail":
		return fmt.Sprintf("凭据[%s] → %s → 登录失败：%s", kinds, via, attempt.Reason)
	}
	return fmt.Sprintf("凭据[%s] → %s：%s", kinds, attempt.Status, attempt.Reason)
}

// UserAuthPromptBlock 组装 Worker 提示词里的「用户凭据说明 + 系统尝试结果」。
//
// 只描述形态与结果，绝不回显密码——凭据已在服务端就位，模型只需要知道能不能用。
func UserAuthPromptBlock(binding *model.AuthBinding, attempt *AuthAttempt) string {
	if binding == nil && attempt == nil {
		return ""
	}
	lines := []string{"# 用户提供的登录凭据（入场券，登录成功本身不是洞）"}

	if binding != nil {
		normalized := NormalizeAuthBinding(*binding)
		if kinds := AuthKindsOf(normalized); len(kinds) > 0 {
			lines = append(lines, "- 类型："+strings.Join(kinds, ", "))
		}
		target := normalized.Target
		if target == "" {
			target = "*"
		}
		matchedBy := normalized.MatchedBy
		if matchedBy == "" {
			matchedBy = "-"
		}
		lines = append(lines, fmt.Sprintf("- 绑定：%s（匹配方式 %s）", target, matchedBy))
		if names := sortedCookieNames(parseCookieString(normalized.Cookie)); len(names) > 0 {
			lines = append(lines, "- Cookie 名："+strings.Join(names, ", "))
		}
		if normalized.Authorization != "" {
			lines = append(lines, "- Header 名：Authorization")
		}
		if normalized.Username != "" {
			lines = append(lines, fmt.Sprintf("- 账号：%s（密码已由系统持有，勿回显）", normalized.Username))
		}
		if normalized.LoginURL != "" {
			lines = append(lines, "- 登录 URL："+normalized.LoginURL)
		}
	}

	if attempt != nil {
		lines = append(lines, fmt.Sprintf("- 系统启动尝试：%s — %s", attempt.Status, attempt.Reason))
		switch attempt.Status {
		case "injected", "login_ok":
			lines = append(lines, "纪律：会话已就绪，直接带登录态深挖；禁止重复无效登录；只登录成功不算洞。")
		case "login_fail":
			lines = append(lines, "纪律：系统登录未成功，可换登录入口/记录失败后继续测未授权面；勿反复空撞同一接口。")
		case "unused":
			lines = append(lines, "纪律：本目标未匹配到凭据，按无登录态挖掘。")
		}
	} else {
		lines = append(lines, "纪律：必须先使用上述凭据登录或 session_set；登录成功后深挖越权/敏感数据/写操作。")
	}
	return strings.Join(lines, "\n") + "\n\n"
}

// ---- 小工具 ----

// resolveURL 按 URL 语义解析相对地址。
func resolveURL(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return base
	}
	baseParsed, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refParsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseParsed.ResolveReference(refParsed).String()
}

// sortedCookieNames 返回排序后的 Cookie 名。
func sortedCookieNames(cookies map[string]string) []string {
	names := make([]string, 0, len(cookies))
	for name := range cookies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// truncateRunes 按字符数截断。
func truncateRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}
