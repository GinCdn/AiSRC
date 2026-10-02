package engine

import (
	"strings"
	"testing"

	"AiSRC/model"
)

func TestIsSiteSource(t *testing.T) {
	for _, s := range []string{"site_map", "site_js", "site_f01", "site_focus", "site_u01", "site_u45", "site_u100"} {
		if !IsSiteSource(s) {
			t.Fatalf("IsSiteSource(%q) = false, want true", s)
		}
	}
	if IsSiteSource("fofa") || IsSiteSource("manual") || IsSiteSource("") {
		t.Fatal("非 site 来源不应命中")
	}
}

func TestRouteForSource(t *testing.T) {
	if r := RouteForSource("site_auth"); r == nil || r.Label != "认证/越权/会话" {
		t.Fatalf("site_auth 路线映射错误: %+v", r)
	}
	if r := RouteForSource("site_f07"); r == nil || r.Phase != 2 {
		t.Fatalf("site_f07 应映射定向追打(phase2): %+v", r)
	}
	if r := RouteForSource("site_u12"); r == nil || r.Label != "指定页面直打" {
		t.Fatalf("site_u12 应映射指定页面直打: %+v", r)
	}
	if RouteForSource("site_unknown") != nil {
		t.Fatal("未知 site 来源应返回 nil")
	}
}

func TestUserPageSource(t *testing.T) {
	if got := UserPageSource(1); got != "site_u01" {
		t.Fatalf("UserPageSource(1) = %q, want site_u01", got)
	}
	if got := UserPageSource(45); got != "site_u45" {
		t.Fatalf("UserPageSource(45) = %q, want site_u45", got)
	}
	if got := UserPageSource(100); got != "site_u100" {
		t.Fatalf("UserPageSource(100) = %q, want site_u100", got)
	}
	if UserPageSource(0) != "" || UserPageSource(1000) != "" {
		t.Fatal("越界序号应返回空串")
	}
}

func TestInitialRoutesForSkipRecon(t *testing.T) {
	task := &model.Task{}
	if got := len(InitialRoutesFor(task)); got != 7 {
		t.Fatalf("默认开局路线应 7 条，got %d", got)
	}
	task.FofaConfig.SkipSiteRecon = true
	got := InitialRoutesFor(task)
	if len(got) != 6 {
		t.Fatalf("跳过盘点后应 6 条，got %d", len(got))
	}
	for _, r := range got {
		if r.Source == "site_map" {
			t.Fatal("skip_site_recon 不应包含 site_map")
		}
	}
}

func TestRenderContextCredentialDirective(t *testing.T) {
	route := RouteForSource("site_auth")
	plain := RenderContext(route, "目标是一个管理系统", "", "", false)
	if strings.Contains(plain, "用户已提供登录凭据") {
		t.Fatal("无凭据文本不应注入登录引导")
	}
	withCred := RenderContext(route, "账号: admin 密码: admin123，请登录测试", "", "", false)
	if !strings.Contains(withCred, "用户已提供登录凭据") {
		t.Fatal("给出账号密码应注入强制登录引导")
	}
	if !strings.Contains(withCred, "认证/越权/会话") {
		t.Fatal("渲染块应包含路线名")
	}
}

func TestBuildCollabOverview(t *testing.T) {
	// 非 site 任务 → nil
	if BuildCollabOverview([]map[string]any{{"source": "fofa", "status": "done"}}) != nil {
		t.Fatal("非 site 任务应返回 nil")
	}
	rows := []map[string]any{
		{"source": "site_map", "status": "done", "verdict": "found", "findings": 1, "deepen_count": 0},
		{"source": "site_auth", "status": "scanning", "findings": 0, "deepen_count": 1},
		{"source": "site_f01", "status": "done", "findings": 0},
		{"source": "site_f02", "status": "done", "findings": 2},
	}
	overview := BuildCollabOverview(rows)
	if overview == nil {
		t.Fatal("site 任务应返回聚合结构")
	}
	if overview["current_phase"] != 1 { // theme 阶段在跑
		t.Fatalf("current_phase 应为 1，got %v", overview["current_phase"])
	}
	phases, _ := overview["phases"].([]map[string]any)
	if len(phases) != 3 {
		t.Fatalf("应有 3 个阶段，got %d", len(phases))
	}
	// phase2 应聚合为单张 is_aggregate 卡
	var focusCard map[string]any
	for _, p := range phases {
		if p["phase"] == 2 {
			routes, _ := p["routes"].([]map[string]any)
			if len(routes) != 1 {
				t.Fatalf("追打阶段应聚合 1 张卡，got %d", len(routes))
			}
			focusCard = routes[0]
		}
	}
	if focusCard == nil || focusCard["is_aggregate"] != true || asInt(focusCard["findings"]) != 2 {
		t.Fatalf("追打聚合卡错误: %+v", focusCard)
	}
	totals, _ := overview["totals"].(map[string]any)
	if asInt(totals["routes"]) != 4 || asInt(totals["findings"]) != 3 {
		t.Fatalf("totals 错误: %+v", totals)
	}
}

func TestFollowupSpecsFromCoverage(t *testing.T) {
	coverage := []map[string]any{
		{
			"route": "site_map",
			"summary": "发现后台",
			"endpoints": []map[string]any{
				{"method": "GET", "path": "/admin/api/user/list", "status": "200", "result": "未授权读取用户列表"},
				{"method": "GET", "path": "/static/logo.png", "status": "200"},
			},
			"remaining": "存在 /admin/api/export 入口",
		},
	}
	specs := FollowupSpecsFromCoverage(coverage, "http://example.com", 8)
	if len(specs) != 1 {
		t.Fatalf("应提炼 1 条追打（静态资源被滤），got %d", len(specs))
	}
	spec := specs[0]
	if spec["path"] != "/admin/api/user/list" || spec["category"] != "认证/越权" {
		t.Fatalf("追打 spec 错误: %+v", spec)
	}
	if !strings.Contains(spec["reason"].(string), "单站协作追打") {
		t.Fatalf("reason 应带追打标记: %v", spec["reason"])
	}
}

func TestNextSiteFollowupSource(t *testing.T) {
	used := map[string]bool{"site_f01": true}
	if got := nextSiteFollowupSource(used); got != "site_f02" {
		t.Fatalf("应取 site_f02，got %s", got)
	}
}
