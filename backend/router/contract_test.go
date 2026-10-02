package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/service"
	"AiSRC/service/llm"

	"github.com/gin-gonic/gin"
)

// 本文件是「响应契约」的回归护栏：确保后端始终输出与原版 AutoHunter
// 一致的响应格式——成功为裸 JSON，失败为 {"detail": ...} + 真实 HTTP 状态码。
//
// 测试全程不触碰数据库与日志：配置直接注入内存，因此可在任何环境运行。

const (
	testSecret        = "contract-test-secret-key-at-least-32-bytes"
	testFullToken     = "full-token-for-contract-test"
	testReadToken     = "readonly-token-for-contract-test"
	testObserverToken = "observer-token-for-contract-test"
)

// newContractRouter 构造一个不依赖外部资源的路由实例。
func newContractRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	config.AppConfig = config.Config{
		System: config.SystemConfig{
			Host:   "127.0.0.1",
			Port:   "8080",
			Env:    "test",
			WebDir: "./__no_such_web_dir__", // 保证静态托管分支走空实现
		},
		Token: config.TokenConfig{
			Header:        "Bearer",
			Secret:        testSecret,
			Issuer:        "aisrc",
			Password:      "contract-test-password",
			FullToken:     testFullToken,
			ReadToken:     testReadToken,
			ObserverToken: testObserverToken,
		},
	}
	return InitRouter()
}

// do 发起一次请求并返回响应。
func do(engine *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// doJSON 发起一次带 JSON 请求体的请求并返回响应。
func doJSON(engine *gin.Engine, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// decodeBody 把响应体解析为 map，便于断言字段。
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应体不是合法 JSON 对象: %v, body=%q", err, rec.Body.String())
	}
	return out
}

// detailOf 读取错误响应中的 detail 字段。
func detailOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body := decodeBody(t, rec)
	detail, ok := body["detail"].(string)
	if !ok {
		t.Fatalf("错误响应缺少 detail 字段: %q", rec.Body.String())
	}
	return detail
}

// TestSuccessResponseIsBareJSON 成功响应必须是裸 JSON，不能有 code/msg/data 外层包装。
func TestSuccessResponseIsBareJSON(t *testing.T) {
	engine := newContractRouter()
	rec := do(engine, http.MethodGet, "/health", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health 状态码应为 200，实际 %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["ok"] != true {
		t.Errorf("GET /health 应包含 ok=true，实际 %q", rec.Body.String())
	}
	for _, key := range []string{"code", "msg", "data"} {
		if _, exists := body[key]; exists {
			t.Errorf("成功响应不应出现包装字段 %q：%q", key, rec.Body.String())
		}
	}
}

// TestUnauthorizedReturns401WithDetail 未携带令牌必须返回 401 + {"detail": ...}。
func TestUnauthorizedReturns401WithDetail(t *testing.T) {
	engine := newContractRouter()
	for _, path := range []string{"/api/tasks", "/api/settings", "/api/intel", "/api/vulns"} {
		rec := do(engine, http.MethodGet, path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s 未带令牌应返回 401，实际 %d", path, rec.Code)
			continue
		}
		if got := detailOf(t, rec); got != "需要 AiSRC 访问令牌" {
			t.Errorf("GET %s 的 detail 应为「需要 AiSRC 访问令牌」，实际 %q", path, got)
		}
	}
}

// TestReadonlyTokenForbiddenOnWrite 只读令牌的写操作必须返回 403 且文案与原版一致。
func TestReadonlyTokenForbiddenOnWrite(t *testing.T) {
	engine := newContractRouter()
	headers := map[string]string{"X-Aisrc-Token": testReadToken}

	rec := do(engine, http.MethodPost, "/api/tasks", headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("只读令牌写操作应返回 403，实际 %d", rec.Code)
	}
	if got := detailOf(t, rec); got != "只读令牌不允许此操作" {
		t.Errorf("只读令牌 403 文案不符，实际 %q", got)
	}
}

// TestObserverTokenForbiddenOnWrite 观摩令牌的写操作文案与只读令牌区分。
func TestObserverTokenForbiddenOnWrite(t *testing.T) {
	engine := newContractRouter()
	headers := map[string]string{"X-Aisrc-Token": testObserverToken}

	rec := do(engine, http.MethodDelete, "/api/tasks/whatever", headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("观摩令牌写操作应返回 403，实际 %d", rec.Code)
	}
	if got := detailOf(t, rec); got != "观摩令牌不允许访问敏感信息或执行写操作" {
		t.Errorf("观摩令牌 403 文案不符，实际 %q", got)
	}
}

// TestNotFoundReturns404WithDetail 未匹配的 API 路径返回 404 + {"detail": ...}。
func TestNotFoundReturns404WithDetail(t *testing.T) {
	engine := newContractRouter()
	rec := do(engine, http.MethodGet, "/api/not-a-real-endpoint", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知 API 路径应返回 404，实际 %d", rec.Code)
	}
	if got := detailOf(t, rec); got != "资源不存在" {
		t.Errorf("404 detail 应为「资源不存在」，实际 %q", got)
	}
}

// TestMethodNotAllowedReturns405 路径存在但方法不支持时返回 405。
func TestMethodNotAllowedReturns405(t *testing.T) {
	engine := newContractRouter()
	headers := map[string]string{"X-Aisrc-Token": testReadToken}
	rec := do(engine, http.MethodPut, "/api/tasks", headers)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /api/tasks 应返回 405，实际 %d", rec.Code)
	}
	if got := detailOf(t, rec); got != "请求方法不被允许" {
		t.Errorf("405 detail 应为「请求方法不被允许」，实际 %q", got)
	}
}

// TestFaviconServedInline 两个图标路径返回同一份内联 SVG。
func TestFaviconServedInline(t *testing.T) {
	engine := newContractRouter()
	for _, path := range []string{"/favicon.svg", "/favicon.ico"} {
		rec := do(engine, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s 应返回 200，实际 %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<svg") {
			t.Errorf("GET %s 应返回内联 SVG", path)
		}
	}
}

// TestHealthWithoutDatabaseStillOK 未连接数据库时健康探针仍返回 200 且 ok=true。
// 原版行为一致：探针只表示进程存活。
func TestHealthWithoutDatabaseStillOK(t *testing.T) {
	engine := newContractRouter()
	for _, path := range []string{"/health", "/api/health"} {
		rec := do(engine, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s 应返回 200，实际 %d", path, rec.Code)
		}
		if decodeBody(t, rec)["ok"] != true {
			t.Errorf("GET %s 应返回 ok=true", path)
		}
	}
}

// TestTokenChannelsAccepted 四种令牌承载方式都必须被识别。
//
// 覆盖原版 AutoHunter 的取令牌顺序（token_from_headers）：
//
//	x-autohunter-token → authorization: Bearer → cookie ah_api_token
//
// 外加本项目扩展的 X-Aisrc-Token 头与 query 参数（SSE/WebSocket 握手用）。
// 其中 ah_api_token 是原版前端的 Cookie 名，必须支持，否则原版前端无法接入。
func TestTokenChannelsAccepted(t *testing.T) {
	engine := newContractRouter()
	cases := []struct {
		name    string
		headers map[string]string
		path    string
	}{
		{"原版头 X-Autohunter-Token", map[string]string{"X-Autohunter-Token": testFullToken}, "/api/tasks"},
		{"扩展头 X-Aisrc-Token", map[string]string{"X-Aisrc-Token": testFullToken}, "/api/tasks"},
		{"标准 Authorization Bearer", map[string]string{"Authorization": "Bearer " + testFullToken}, "/api/tasks"},
		{"原版 Cookie ah_api_token", map[string]string{"Cookie": "ah_api_token=" + testFullToken}, "/api/tasks"},
		{"兼容 Cookie aisrc_token", map[string]string{"Cookie": "aisrc_token=" + testFullToken}, "/api/tasks"},
		{"query 参数 token", nil, "/api/tasks?token=" + testFullToken},
	}
	for _, tc := range cases {
		rec := do(engine, http.MethodGet, tc.path, tc.headers)
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s：令牌未被识别，返回了 401", tc.name)
		}
	}
}

// TestStaticFullTokenGrantsFullRole 静态全权限令牌（对应原版 AUTOHUNTER_API_TOKEN）
// 可直接执行写操作，无需先登录换取 JWT。
func TestStaticFullTokenGrantsFullRole(t *testing.T) {
	engine := newContractRouter()
	headers := map[string]string{"X-Autohunter-Token": testFullToken}

	// 写操作若被鉴权拦截会返回 401/403；这里放行后才会走到业务校验，
	// 无论是 400（参数缺失）还是 200，都足以证明「未被鉴权拦截」。
	rec := do(engine, http.MethodPost, "/api/tasks", headers)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("静态全权限令牌应可写，实际被拦截：%d %s", rec.Code, rec.Body.String())
	}
}

// TestForgedTokenRejected 伪造令牌不得通过鉴权。
func TestForgedTokenRejected(t *testing.T) {
	engine := newContractRouter()
	rec := do(engine, http.MethodGet, "/api/tasks", map[string]string{
		"Authorization": "Bearer forged.token.value",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("伪造令牌应返回 401，实际 %d", rec.Code)
	}
}

// TestAuthStatusShape 鉴权状态接口必须包含原版字段 auth_required 与 role。
func TestAuthStatusShape(t *testing.T) {
	engine := newContractRouter()
	rec := do(engine, http.MethodGet, "/api/auth/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/status 应返回 200，实际 %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if _, ok := body["auth_required"]; !ok {
		t.Errorf("缺少原版字段 auth_required：%q", rec.Body.String())
	}
	if _, ok := body["role"]; !ok {
		t.Errorf("缺少原版字段 role：%q", rec.Body.String())
	}
	if body["auth_required"] != true {
		t.Errorf("已配置口令时 auth_required 应为 true：%q", rec.Body.String())
	}
}

// TestAuthStatusResolvesIssuedToken 回归护栏：/api/auth/status 必须能把
// 请求里携带的令牌解析成真实角色。
//
// ⚠️ 这条是补漏的：`OptionalAuthMiddleware` 曾「定义了但没挂到路由上」，
// 导致 status 恒返回 role=none —— 令牌完全有效，前端却在每次刷新时
// 都判定「未登录」并弹出登录框。它不属于任何既有断言能覆盖的范围，
// 故单独锁定：签发 → 携带 → 必须换回 full。
func TestAuthStatusResolvesIssuedToken(t *testing.T) {
	engine := newContractRouter()
	if err := core.InitJWT(); err != nil {
		t.Fatalf("初始化 JWT 失败: %v", err)
	}
	token, err := core.GenerateToken("admin", constant.RoleFull, 0)
	if err != nil {
		t.Fatalf("签发令牌失败: %v", err)
	}

	for name, headers := range map[string]map[string]string{
		"header":     {"X-Aisrc-Token": token},
		"bearer":     {"Authorization": "Bearer " + token},
		"cookie":     {"Cookie": "ah_api_token=" + token},
		"legacyCookie": {"Cookie": "aisrc_token=" + token},
	} {
		rec := do(engine, http.MethodGet, "/api/auth/status", headers)
		if rec.Code != http.StatusOK {
			t.Fatalf("[%s] GET /api/auth/status 应返回 200，实际 %d", name, rec.Code)
		}
		body := decodeBody(t, rec)
		if body["role"] != constant.RoleFull {
			t.Errorf("[%s] 有效令牌必须解析为 full，实际 role=%v（%q）", name, body["role"], rec.Body.String())
		}
		if body["username"] != "admin" {
			t.Errorf("[%s] 应从令牌回填 username=admin，实际 %v", name, body["username"])
		}
	}
}

// TestAuthStatusCarriesLoginGuard 登录守卫状态随 status 一起下发，
// 刷新后前端才能正确决定是否直接展示验证码。
func TestAuthStatusCarriesLoginGuard(t *testing.T) {
	engine := newContractRouter()
	service.ResetLoginGuard()
	t.Cleanup(service.ResetLoginGuard)

	rec := do(engine, http.MethodGet, "/api/auth/status", nil)
	body := decodeBody(t, rec)
	if body["captcha_required"] != false {
		t.Errorf("初始状态 captcha_required 应为 false：%q", rec.Body.String())
	}
	if body["login_failures"] != float64(0) {
		t.Errorf("初始状态 login_failures 应为 0：%q", rec.Body.String())
	}
	if body["captcha_digits"] != float64(service.CaptchaDigits) {
		t.Errorf("captcha_digits 应为 %d：%q", service.CaptchaDigits, rec.Body.String())
	}
}

// TestCaptchaEndpointIssuesFourDigitImage 验证码接口必须下发 4 位图的 data URL。
func TestCaptchaEndpointIssuesFourDigitImage(t *testing.T) {
	engine := newContractRouter()
	service.ResetLoginGuard()
	t.Cleanup(service.ResetLoginGuard)

	rec := do(engine, http.MethodGet, "/api/auth/captcha", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/captcha 应返回 200，实际 %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if id, _ := body["captcha_id"].(string); id == "" {
		t.Errorf("缺少 captcha_id：%q", rec.Body.String())
	}
	image, _ := body["captcha_image"].(string)
	if !strings.HasPrefix(image, "data:image/svg+xml;base64,") {
		t.Errorf("captcha_image 应为 SVG data URL：%q", rec.Body.String())
	}
	if body["digits"] != float64(service.CaptchaDigits) {
		t.Errorf("digits 应为 %d：%q", service.CaptchaDigits, rec.Body.String())
	}
	// 明文绝不能出现在响应里。
	if strings.Contains(rec.Body.String(), `"code"`) {
		t.Errorf("响应中不得出现验证码明文：%q", rec.Body.String())
	}
}

// TestLoginRequiresCaptchaAfterThreeFailures 登录失败满 3 次后必须要求验证码，
// 且错误响应要带上 captcha_required 供前端切换表单。
func TestLoginRequiresCaptchaAfterThreeFailures(t *testing.T) {
	engine := newContractRouter()
	service.ResetLoginGuard()
	t.Cleanup(service.ResetLoginGuard)

	const ip = "192.0.2.77"
	headers := map[string]string{"X-Real-IP": ip}

	for i := 1; i <= service.CaptchaThreshold; i++ {
		rec := doJSON(engine, http.MethodPost, "/api/auth/login",
			`{"username":"admin","password":"wrong-password"}`, headers)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次密码错误应返回 401，实际 %d（%q）", i, rec.Code, rec.Body.String())
		}
		body := decodeBody(t, rec)
		if body["detail"] != service.ErrPasswordMismatch.Error() {
			t.Errorf("第 %d 次应返回统一文案，实际 %v", i, body["detail"])
		}
		want := i >= service.CaptchaThreshold
		if body["captcha_required"] != want {
			t.Errorf("第 %d 次失败后 captcha_required 应为 %v，实际 %v", i, want, body["captcha_required"])
		}
	}

	// 已触发验证码：再提交正确密码但无验证码，必须被拦下。
	rec := doJSON(engine, http.MethodPost, "/api/auth/login",
		`{"username":"admin","password":"contract-test-password"}`, headers)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺验证码时应返回 400，实际 %d（%q）", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["captcha_required"] != true {
		t.Errorf("缺验证码时 captcha_required 应为 true：%q", rec.Body.String())
	}
}

// TestLoginRejectsWrongUsername 用户名必须与 token.username 一致（未配置时回落 admin）。
//
// 回归背景：Login 早期**只校验密码**，用户名填什么都能过——而且还会按该用户名
// 自动建号。结果是「用户名」形同虚设、任意名字 + 正确密码即可登录。
// 这里用「用户名不符 + 密码正确」断言 401：若用户名未参与校验，请求会越过密码
// 比对继续走到 ensureAdmin（测试环境无 DB），绝不会安静地返回 401。
func TestLoginRejectsWrongUsername(t *testing.T) {
	engine := newContractRouter()
	service.ResetLoginGuard()
	t.Cleanup(service.ResetLoginGuard)

	rec := doJSON(engine, http.MethodPost, "/api/auth/login",
		`{"username":"not-the-admin","password":"contract-test-password"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("用户名不符时应返回 401，实际 %d（%q）", rec.Code, rec.Body.String())
	}
	// 文案与密码错误完全一致：不暴露「是用户名错还是密码错」，避免枚举账号。
	if got := decodeBody(t, rec)["detail"]; got != service.ErrPasswordMismatch.Error() {
		t.Errorf("应返回统一文案 %q，实际 %v", service.ErrPasswordMismatch.Error(), got)
	}
}

// TestLoginAcceptsValidCaptcha 验证码正确时必须放行到后续校验，
// 而不是继续以「验证码错误」拦下。
//
// 这里故意用错误密码收口：请求越过验证码闸门后会走到密码比对并返回 401，
// 断言点就从「错误文案」变成「账号或密码错误」，无需数据库即可证明放行。
func TestLoginAcceptsValidCaptcha(t *testing.T) {
	engine := newContractRouter()
	service.ResetLoginGuard()
	t.Cleanup(service.ResetLoginGuard)

	const ip = "192.0.2.88"
	headers := map[string]string{"X-Real-IP": ip}

	// 先把该来源打到验证码门槛。
	for i := 1; i <= service.CaptchaThreshold; i++ {
		doJSON(engine, http.MethodPost, "/api/auth/login",
			`{"username":"admin","password":"wrong-password"}`, headers)
	}
	if !service.CaptchaRequired(ip) {
		t.Fatalf("前置条件不成立：应已触发验证码")
	}

	// 取一个真实验证码（守卫与路由同进程，共享同一份存储）。
	id, code, _ := service.NewCaptcha()
	rec := doJSON(engine, http.MethodPost, "/api/auth/login",
		fmt.Sprintf(`{"username":"admin","password":"wrong-password","captcha_id":%q,"captcha_code":%q}`, id, code),
		headers)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("验证码正确时应越过闸门并在密码校验处返回 401，实际 %d（%q）", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, rec)["detail"]; got != service.ErrPasswordMismatch.Error() {
		t.Fatalf("应返回密码错误，实际 %v（说明请求被验证码闸门拦下了）", got)
	}

	// 同一个验证码不能复用。
	rec = doJSON(engine, http.MethodPost, "/api/auth/login",
		fmt.Sprintf(`{"username":"admin","password":"wrong-password","captcha_id":%q,"captcha_code":%q}`, id, code),
		headers)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("复用验证码应被拒绝（400），实际 %d（%q）", rec.Code, rec.Body.String())
	}
}

// TestSettingsEnginesViewContract 设置视图必须下发引擎清单与全量引擎条目。
//
// 前端「各引擎 API Key」区块与默认引擎下拉都依赖 available_engines；
// 曾因后端漏下发该字段、engines 段又只包含 DB 中已保存的引擎（空表时为 {}），
// 设置页一个引擎输入框都渲染不出来。原版行为（settings_service.py）：
// available_engines = [{name, display_name}...]（按注册顺序），engines 段为
// 每个已注册引擎都出条目，fofa 条目合并 fofa 段的 key/base_url。
func TestSettingsEnginesViewContract(t *testing.T) {
	engine := newContractRouter()

	rec := doJSON(engine, http.MethodGet, "/api/settings", `{}`,
		map[string]string{"X-Autohunter-Token": testFullToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/settings 应返回 200，实际 %d", rec.Code)
	}
	body := decodeBody(t, rec)

	wantOrder := []string{"fofa", "quake", "hunter", "zoomeye", "shodan", "censys"}
	available, ok := body["available_engines"].([]any)
	if !ok || len(available) != len(wantOrder) {
		t.Fatalf("available_engines 应为 %d 个引擎的数组：%s", len(wantOrder), rec.Body.String())
	}
	for i, want := range wantOrder {
		meta, _ := available[i].(map[string]any)
		if meta["name"] != want {
			t.Errorf("available_engines[%d].name = %v，应为 %s", i, meta["name"], want)
		}
		if dn, _ := meta["display_name"].(string); dn == "" {
			t.Errorf("available_engines[%d] 缺 display_name", i)
		}
	}

	engines, _ := body["engines"].(map[string]any)
	for _, want := range wantOrder {
		item, exists := engines[want]
		if !exists {
			t.Errorf("engines 段缺少引擎 %s（DB 未配置也必须出条目）", want)
			continue
		}
		entry := item.(map[string]any)
		if entry["display_name"] == "" {
			t.Errorf("engines.%s 缺 display_name", want)
		}
		if _, isBool := entry["key_set"].(bool); !isBool {
			t.Errorf("engines.%s 的 key_set 必须是布尔值，实际 %T", want, entry["key_set"])
		}
	}

	// fofa 条目 base_url 固定为官方默认端点（引擎端点不再可配置）。
	fofaEntry := engines["fofa"].(map[string]any)
	if fofaEntry["base_url"] != "https://fofa.info" {
		t.Errorf("engines.fofa.base_url 应固定为官方默认端点，实际 %v", fofaEntry["base_url"])
	}

	// 保存→读回的落库链路需要真实数据库（契约测试环境 core.Db 为 nil），
	// 由真机端到端验证覆盖；此处确认无 DB 时保存路径返回明确错误而非 panic。
	save := doJSON(engine, http.MethodPut, "/api/settings",
		`{"engines":{"hunter":{"key":"test-hunter-key-123456"}}}`,
		map[string]string{"X-Autohunter-Token": testFullToken})
	if save.Code == http.StatusInternalServerError {
		detail := save.Body.String()
		if !strings.Contains(detail, "数据库未初始化") {
			t.Errorf("无 DB 时保存应返回明确错误，实际：%s", detail)
		}
	}
}

// TestTestLLMResponseContract 连通性测试接口必须返回原版契约字段。
//
// 原版 /api/settings/test-llm 返回 {ok, results, error_copy}，其中顶层 ok 是
// 前端判定「LLM 可用 / LLM 不可用」的唯一依据。曾因漏返回 ok，导致探测明明
// 通过（results[].ok=true）却显示「LLM 不可用」，故加此回归护栏。
func TestTestLLMResponseContract(t *testing.T) {

	engine := newContractRouter()
	rec := doJSON(engine, http.MethodPost, "/api/settings/test-llm", `{}`,
		map[string]string{"X-Autohunter-Token": testFullToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/settings/test-llm 应返回 200，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	okValue, exists := body["ok"]
	if !exists {
		t.Fatalf("缺少顶层 ok 字段（前端据此判定 LLM 可用性）：%s", rec.Body.String())
	}
	if _, isBool := okValue.(bool); !isBool {
		t.Errorf("ok 必须是布尔值，实际 %T", okValue)
	}
	if _, exists := body["results"]; !exists {
		t.Errorf("缺少 results 字段：%s", rec.Body.String())
	}
	if _, exists := body["error_copy"]; !exists {
		t.Errorf("缺少 error_copy 字段：%s", rec.Body.String())
	}
}

// TestTestLLMProvidersShape 传 providers 时必须按入参端点测试，
// 而不是回落到全局配置（对应原版 _test_configs 的 providers 分支）。
func TestTestLLMProvidersShape(t *testing.T) {
	engine := newContractRouter()
	payload := `{"providers":[{"name":"probe","base_url":"http://127.0.0.1:1/v1",` +
		`"api_key":"sk-test-not-real","model":"demo-model","protocol":"openai_chat","enabled":true}]}`
	rec := doJSON(engine, http.MethodPost, "/api/settings/test-llm", payload,
		map[string]string{"X-Autohunter-Token": testFullToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回 200，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	results, _ := body["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("应只测试入参里的 1 个端点，实际 %d 个：%s", len(results), rec.Body.String())
	}
	item, _ := results[0].(map[string]any)
	if item["name"] != "probe" {
		t.Errorf("端点名应沿用入参 name=probe，实际 %v", item["name"])
	}
	if item["model"] != "demo-model" {
		t.Errorf("model 应沿用入参，实际 %v", item["model"])
	}
	if item["ok"] != false {
		t.Errorf("指向不可达地址的端点应为 ok=false，实际 %v", item["ok"])
	}
}

// TestTestLLMProbeDoesNotPoisonHealth 手动「测试连接」不得写入生产熔断器。
//
// 原版注释明确此语义：手动探测若 Mark 健康状态，会污染正在运行的 worker 的
// 端点冷却判断（成功时还会误清真实 cooldown）。生产健康标记只应发生在真实调用路径。
func TestTestLLMProbeDoesNotPoisonHealth(t *testing.T) {
	engine := newContractRouter()
	payload := `{"providers":[{"name":"poison-check","base_url":"http://127.0.0.1:1/v1",` +
		`"api_key":"sk-test-not-real","model":"poison-model-should-not-appear","protocol":"openai_chat","enabled":true}]}`
	doJSON(engine, http.MethodPost, "/api/settings/test-llm", payload,
		map[string]string{"X-Autohunter-Token": testFullToken})

	for _, snap := range llm.Health().All() {
		if snap.Model == "poison-model-should-not-appear" {
			t.Fatalf("手动测试污染了生产健康快照：model=%s status=%s", snap.Model, snap.Status)
		}
	}
}
