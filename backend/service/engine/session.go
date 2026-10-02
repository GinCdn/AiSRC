package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"AiSRC/utils"
)

// browserUA 默认浏览器 UA，对齐原版 app/http_defaults.py::BROWSER_UA。
//
// 站点与 WAF 常按 UA 指纹放行/拦截：DVWA 靶场上非常规 UA 会被拦，
// 而安全测试需要与真实浏览器一致的指纹，因此这里与浏览器保持一致。
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// maxSessionHeaders 会话头数量上限（对齐原版 _SESSION_MAX_HEADERS）。
const maxSessionHeaders = 16

// sessionState 单个 Worker 的会话态：Cookie 池 + 鉴权头。
//
// 对齐原版 app/tools/executor.py 的 _session_cookies / _session_headers：
// bootstrap 注入或 session_set 登记的凭据，后续 http_request 自动携带，
// 响应 Set-Cookie 自动吸收——这是「登录一次、之后一直带登录态」的实现基础。
//
// Cookie 用 net/http/cookiejar 托管：它天然处理跨域、Path、以及 302 跳转链上的
// Set-Cookie 吸收；手工维护 flat map 会在跟随跳转时丢掉中间响应设置的会话 Cookie。
type sessionState struct {
	targetURL *url.URL
	jar       http.CookieJar
	fallback  map[string]string
	headers   map[string]string
	dirty     bool
}

// newSessionState 创建会话态；targetURL 是该 Worker 的目标地址，作为 Cookie 默认作用域。
func newSessionState(targetURL string) *sessionState {
	state := &sessionState{
		fallback: map[string]string{},
		headers:  map[string]string{},
	}
	if jar, err := cookiejar.New(nil); err == nil {
		state.jar = jar
	}
	if parsed := parseAuthURL(targetURL); parsed != nil {
		state.targetURL = parsed
	}
	return state
}

// baseURL 返回会话归属的目标地址。
func (s *sessionState) baseURL() *url.URL {
	if s == nil {
		return nil
	}
	return s.targetURL
}

// markDirty 标记会话态已变化，供 Worker 下一轮注入状态块。
func (s *sessionState) markDirty() {
	if s != nil {
		s.dirty = true
	}
}

// takeDirty 取出并清空变化标记。
func (s *sessionState) takeDirty() bool {
	if s == nil {
		return false
	}
	changed := s.dirty
	s.dirty = false
	return changed
}

// clear 清空全部会话态。
func (s *sessionState) clear() {
	if s == nil {
		return
	}
	if jar, err := cookiejar.New(nil); err == nil {
		s.jar = jar
	}
	s.fallback = map[string]string{}
	s.headers = map[string]string{}
	s.dirty = true
}

// applyCookies 注入 Cookie。scope 为空时用目标地址；jar 无法登记时落 fallback。
func (s *sessionState) applyCookies(scope *url.URL, cookies map[string]string) {
	if s == nil || len(cookies) == 0 {
		return
	}
	if scope == nil {
		scope = s.baseURL()
	}
	if scope == nil || s.jar == nil {
		for name, value := range cookies {
			if strings.TrimSpace(name) == "" {
				continue
			}
			s.fallback[name] = value
		}
		s.dirty = true
		return
	}

	list := make([]*http.Cookie, 0, len(cookies))
	for name, value := range cookies {
		if strings.TrimSpace(name) == "" {
			continue
		}
		list = append(list, &http.Cookie{Name: name, Value: value, Path: "/"})
	}
	s.jar.SetCookies(scope, list)
	// jar 会因域名/安全策略静默丢弃部分 Cookie，兜底再存一份保证不会丢凭据。
	if len(s.jar.Cookies(scope)) == 0 {
		for name, value := range cookies {
			s.fallback[name] = value
		}
	}
	s.dirty = true
}

// applyHeaders 注入会话头；Cookie 头并入 Cookie 池统一管理。
func (s *sessionState) applyHeaders(headers map[string]string) {
	if s == nil || len(headers) == 0 {
		return
	}
	for key, value := range headers {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "cookie") {
			// Cookie 走 jar 统一管理，避免与会话头各自维护后互相覆盖。
			s.applyCookies(nil, parseCookieString(value))
			continue
		}
		if _, exists := s.headers[name]; !exists && len(s.headers) >= maxSessionHeaders {
			continue
		}
		s.headers[name] = value
	}
	s.dirty = true
}

// apply 供 bootstrap 使用：一次性注入 Cookie 与鉴权头。
func (s *sessionState) apply(scope *url.URL, cookies, headers map[string]string) {
	s.applyCookies(scope, cookies)
	s.applyHeaders(headers)
}

// jarCookies 返回 jar 中对指定 URL 生效的 Cookie。
func (s *sessionState) jarCookies(target *url.URL) []*http.Cookie {
	if s == nil || s.jar == nil {
		return nil
	}
	if target == nil {
		target = s.baseURL()
	}
	if target == nil {
		return nil
	}
	return s.jar.Cookies(target)
}

// fallbackCookies 返回 jar 不可用时的兜底 Cookie。
func (s *sessionState) fallbackCookies() []*http.Cookie {
	if s == nil || len(s.fallback) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.fallback))
	for name := range s.fallback {
		names = append(names, name)
	}
	sort.Strings(names)
	list := make([]*http.Cookie, 0, len(names))
	for _, name := range names {
		list = append(list, &http.Cookie{Name: name, Value: s.fallback[name]})
	}
	return list
}

// cookieList 返回对指定 URL 生效的 Cookie（jar 优先，空则回退手工池）。
func (s *sessionState) cookieList(target *url.URL) []*http.Cookie {
	list := s.jarCookies(target)
	if len(list) == 0 {
		list = s.fallbackCookies()
	}
	return list
}

// cookieNames 返回当前持有的 Cookie 名（不含值，避免凭据回显）。
func (s *sessionState) cookieNames(target *url.URL) []string {
	list := s.cookieList(target)
	seen := map[string]bool{}
	names := make([]string, 0, len(list))
	for _, cookie := range list {
		if cookie.Name == "" || seen[cookie.Name] {
			continue
		}
		seen[cookie.Name] = true
		names = append(names, cookie.Name)
	}
	sort.Strings(names)
	return names
}

// headerNames 返回当前持有的会话头名。
func (s *sessionState) headerNames() []string {
	if s == nil || len(s.headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.headers))
	for name := range s.headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// requestSetup 组装本次请求的最终请求头，返回合并结果与「已自动携带」的摘要标签。
//
// 调用方显式给出的 Cookie 头在会话池为空时才生效——有会话态时以会话池为准，
// 避免模型的临时 Cookie 覆盖掉刚登录成功的会话（原版同样丢弃调用方 Cookie 头）。
func (s *sessionState) requestSetup(target *url.URL, caller map[string]string) (map[string]string, []string) {
	merged := map[string]string{}
	applied := []string{}
	callerCookie := ""

	if s != nil {
		for name, value := range s.headers {
			merged[name] = value
		}
	}
	hasUserAgent := false
	for name, value := range caller {
		if strings.EqualFold(name, "cookie") {
			callerCookie = value
			continue
		}
		if strings.EqualFold(name, "user-agent") {
			hasUserAgent = true
		}
		merged[name] = value
	}

	// jar 有命中时不能手工设置 Cookie 头：http.Client 会把 jar 里的 Cookie 追加到
	// 已有 Cookie 头上，手工再写一遍会变成 `NAME=v; NAME=v` 重复发送。
	if jarHits := s.jarCookies(target); len(jarHits) > 0 {
		applied = append(applied, fmt.Sprintf("Cookie(%d)", len(jarHits)))
	} else if fallback := s.fallbackCookies(); len(fallback) > 0 {
		parts := make([]string, 0, len(fallback))
		for _, cookie := range fallback {
			parts = append(parts, cookie.Name+"="+cookie.Value)
		}
		merged["Cookie"] = strings.Join(parts, "; ")
		applied = append(applied, fmt.Sprintf("Cookie(%d)", len(fallback)))
	} else if callerCookie != "" {
		merged["Cookie"] = callerCookie
	}
	if s != nil && len(s.headers) > 0 {
		applied = append(applied, fmt.Sprintf("headers(%d)", len(s.headers)))
	}
	if !hasUserAgent && merged["User-Agent"] == "" {
		merged["User-Agent"] = browserUA
	}
	return merged, applied
}

// statusBlock 生成会话态摘要块，供 Worker 每轮注入（不含 Cookie 值）。
func (s *sessionState) statusBlock() string {
	cookies := s.cookieNames(nil)
	headers := s.headerNames()

	var sb strings.Builder
	sb.WriteString("# 当前会话态（系统自动携带，无需重复注入）\n")
	if len(cookies) == 0 && len(headers) == 0 {
		sb.WriteString("- 暂无登录态。拿到凭据后用 session_set 登记（或直接提供账密由系统登录）。\n")
		return sb.String()
	}
	if len(cookies) > 0 {
		sb.WriteString(fmt.Sprintf("- 已持有 Cookie：%s\n", strings.Join(cookies, ", ")))
	}
	if len(headers) > 0 {
		sb.WriteString(fmt.Sprintf("- 已注入鉴权头：%s\n", strings.Join(headers, ", ")))
	}
	sb.WriteString("纪律：会话已就绪，直接带登录态深挖受限接口；登录成功本身不是漏洞。\n")
	return sb.String()
}

// ==================== 统一 HTTP 请求封装 ====================

// httpCall 一次 HTTP 调用的入参。
type httpCall struct {
	Method          string
	URL             string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	Timeout         time.Duration
}

// httpExchange 一次 HTTP 调用的结果。
type httpExchange struct {
	OK         bool
	StatusCode int
	Header     http.Header
	Body       string
	FinalURL   string
	Error      string
	Applied    []string
}

// doHTTP 执行 HTTP 请求：自动携带会话态、吸收 Set-Cookie、记录跳转终点。
func doHTTP(ctx context.Context, session *sessionState, call httpCall) httpExchange {
	rawURL := strings.TrimSpace(call.URL)
	if rawURL == "" {
		return httpExchange{Error: "url 不能为空"}
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return httpExchange{Error: "URL 非法：" + rawURL}
	}

	method := strings.ToUpper(strings.TrimSpace(call.Method))
	if method == "" {
		method = http.MethodGet
	}
	timeout := call.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	var bodyReader io.Reader
	if call.Body != "" {
		bodyReader = strings.NewReader(call.Body)
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, bodyReader)
	if err != nil {
		return httpExchange{Error: "构造请求失败：" + err.Error()}
	}

	headers, applied := session.requestSetup(parsed, call.Headers)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", browserUA)
	}

	client := httpClient
	if session != nil && session.jar != nil {
		clone := *httpClient
		clone.Jar = session.jar
		client = &clone
	}
	if !call.FollowRedirects {
		clone := *client
		clone.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = &clone
	}

	resp, err := client.Do(req)
	if err != nil {
		return httpExchange{Error: utils.SanitizeSecretText(err.Error()), Applied: applied}
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return httpExchange{
		OK:         true,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       string(raw),
		FinalURL:   finalURL,
		Applied:    applied,
	}
}

// setCookieNames 从 Set-Cookie 响应头里提取 Cookie 名。
func setCookieNames(values []string) []string {
	seen := map[string]bool{}
	names := make([]string, 0, len(values))
	for _, value := range values {
		part := strings.TrimSpace(value)
		if idx := strings.Index(part, "="); idx > 0 {
			name := strings.TrimSpace(part[:idx])
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// parseCookieString 解析 Cookie 串（容忍带 "Cookie:" 前缀与多余空格）。
func parseCookieString(raw string) map[string]string {
	out := map[string]string{}
	text := strings.TrimSpace(raw)
	if text == "" {
		return out
	}
	if len(text) >= 7 && strings.EqualFold(text[:7], "cookie:") {
		text = strings.TrimSpace(text[7:])
	}
	for _, part := range strings.Split(text, ";") {
		part = strings.TrimSpace(part)
		if part == "" || !strings.Contains(part, "=") {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name != "" {
			out[name] = value
		}
	}
	return out
}

// anyMapToStringMap 把工具参数里的对象转成 string→string。
func anyMapToStringMap(raw any) map[string]string {
	object, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(object))
	for key, value := range object {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case float64:
			out[key] = fmt.Sprintf("%v", typed)
		case bool:
			out[key] = fmt.Sprintf("%v", typed)
		}
	}
	return out
}

// equalStringSlices 判断两个字符串切片是否等价（用于会话态变化检测）。
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
