package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newGateFakeTarget 构造一个假目标站点：
// - /item?id=1            正常页面（基线）
// - /item?id=1'           payload 触发 SQL 报错（差异页）
// - /api/order?uid=2      登录可见；无登录（带 bypass=1）返回越权数据
// 通过 attackHits 统计攻击路径被真实打到的次数，用于验证缓存不重复重放。
func newGateFakeTarget(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	attackHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "'") {
			attackHits++
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "you have an error in your SQL syntax near '1''")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><title>Item</title>normal item page body</html>")
	})
	mux.HandleFunc("/api/order", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("uid") == "2" && r.Header.Get("X-Role") != "admin" {
			attackHits++
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"order":"other-user-order-9931","phone":"138****0002"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"order":"self-order-1001"}`)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &attackHits
}

func gateArgs(baseURL string) map[string]any {
	return map[string]any{
		"vuln_type": "sql_injection",
		"baseline": map[string]any{
			"method": "GET",
			"url":    baseURL + "/item?id=1",
		},
		"attack": map[string]any{
			"method": "GET",
			"url":    baseURL + "/item?id=1'",
		},
		"expect": map[string]any{
			"body_contains": "SQL syntax",
		},
	}
}

func TestGatePassSignsToken(t *testing.T) {
	server, _ := newGateFakeTarget(t)
	session := &WorkerSession{TargetURL: server.URL}

	res := handleVerifyFinding(context.Background(), gateArgs(server.URL), session)
	if res.IsErr {
		t.Fatalf("marker 命中应通过 3-gate，实际失败：%s", res.Output)
	}
	token := extractGateToken(res.Output)
	if token == "" {
		t.Fatalf("通过结果应包含 gate_token，实际输出：\n%s", res.Output)
	}
	rec := session.GetGate(token)
	if rec == nil {
		t.Fatalf("签发的 token 应可在会话中取回，token=%s", token)
	}
	if !strings.EqualFold(rec.VulnType, "sql_injection") {
		t.Fatalf("记录的漏洞类型应为 sql_injection，实际 %s", rec.VulnType)
	}
	if rec.Baseline.Status != 200 || rec.Attack.Status != 500 {
		t.Fatalf("基线/攻击状态码应为 200/500，实际 %d/%d", rec.Baseline.Status, rec.Attack.Status)
	}
	if !rec.Diff.StatusDiff || !rec.Diff.ContainsHit {
		t.Fatalf("diff 应记录状态差异与回显命中，实际 %+v", rec.Diff)
	}
}

// 从工具输出中提取 gate_token（形如 "gate-xxxxxxxx"）。
func extractGateToken(output string) string {
	marker := "gate_token: "
	idx := strings.Index(output, marker)
	if idx < 0 {
		return ""
	}
	rest := output[idx+len(marker):]
	if end := strings.IndexAny(rest, "\n\r"); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

func TestGateFailOnNoDifference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "same response for every request")
	}))
	defer server.Close()
	session := &WorkerSession{TargetURL: server.URL}

	args := gateArgs(server.URL)
	args["expect"] = map[string]any{} // 无显式声明，走启发式：两者完全一致必须 FAIL
	res := handleVerifyFinding(context.Background(), args, session)
	if !res.IsErr {
		t.Fatalf("攻击响应与基线一致时必须 FAIL，实际输出：\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "无显著差异") {
		t.Fatalf("失败原因应说明无差异，实际输出：\n%s", res.Output)
	}
}

func TestGateCacheReusesToken(t *testing.T) {
	server, attackHits := newGateFakeTarget(t)
	session := &WorkerSession{TargetURL: server.URL}

	first := handleVerifyFinding(context.Background(), gateArgs(server.URL), session)
	if first.IsErr {
		t.Fatalf("首次验证应通过：%s", first.Output)
	}
	token1 := extractGateToken(first.Output)

	// 完全相同的验证再次调用：直接复用 token，不再重放攻击请求。
	second := handleVerifyFinding(context.Background(), gateArgs(server.URL), session)
	if second.IsErr {
		t.Fatalf("缓存命中应直接通过：%s", second.Output)
	}
	token2 := extractGateToken(second.Output)
	if token1 == "" || token1 != token2 {
		t.Fatalf("同指纹验证应复用同一 token，实际 %q vs %q", token1, token2)
	}
	if *attackHits != 1 {
		t.Fatalf("攻击路径应只被真实打到 1 次（缓存复用），实际 %d 次", *attackHits)
	}
}

func TestSubmitFindingGateEnforcement(t *testing.T) {
	server, _ := newGateFakeTarget(t)
	session := &WorkerSession{TargetURL: server.URL}

	submitArgs := func(extra map[string]any) map[string]any {
		args := map[string]any{
			"vuln_type":        "sql_injection",
			"title":            "商品查询参数 SQL 注入",
			"severity_claimed": "高危",
			"target_url":       server.URL + "/item?id=1",
			"description":      "id 参数未过滤，单引号触发 SQL 报错",
			"steps":            []any{"访问 /item?id=1'", "观察 SQL 报错"},
		}
		for key, value := range extra {
			args[key] = value
		}
		return args
	}

	// 1) 无 token：直接拒绝，并给出 verify_finding 指引。
	res := handleSubmitFinding(nil, submitArgs(nil), session)
	if !res.IsErr {
		t.Fatal("sql_injection 无 gate_token 必须被拒绝")
	}
	if !strings.Contains(res.Output, "verify_finding") {
		t.Fatalf("拒绝信息应指引调用 verify_finding，实际：%s", res.Output)
	}

	// 2) 伪造 token：拒绝。
	res = handleSubmitFinding(nil, submitArgs(map[string]any{"gate_token": "gate-forged"}), session)
	if !res.IsErr {
		t.Fatal("伪造 gate_token 必须被拒绝")
	}

	// 3) 正确流程：先 verify 拿 token，再提交，证据自动注入。
	gateRes := handleVerifyFinding(context.Background(), gateArgs(server.URL), session)
	if gateRes.IsErr {
		t.Fatalf("verify 应通过：%s", gateRes.Output)
	}
	token := extractGateToken(gateRes.Output)
	res = handleSubmitFinding(nil, submitArgs(map[string]any{"gate_token": token}), session)
	if res.IsErr {
		t.Fatalf("持有效 token 应受理：%s", res.Output)
	}
	submitted := session.Submitted()
	if len(submitted) != 1 {
		t.Fatalf("应落一条提交，实际 %d 条", len(submitted))
	}
	gate, ok := submitted[0].Evidence["gate"].(map[string]any)
	if !ok {
		t.Fatalf("Evidence 应包含 gate 段，实际：%v", submitted[0].Evidence)
	}
	if gate["verdict"] != "pass" || gate["token"] != token {
		t.Fatalf("gate 段应记录 pass 与 token，实际：%v", gate)
	}

	// 4) 类型不匹配：sql_injection 的 token 提交 idor，拒绝。
	res = handleSubmitFinding(nil, map[string]any{
		"vuln_type":        "idor",
		"title":            "订单接口水平越权",
		"severity_claimed": "高危",
		"target_url":       server.URL + "/api/order?uid=2",
		"description":      "改 uid 可看他人订单",
		"steps":            []any{"GET /api/order?uid=2"},
		"gate_token":       token,
	}, session)
	if !res.IsErr {
		t.Fatal("gate_token 与漏洞类型不匹配必须被拒绝")
	}

	// 5) 非强制类型（backdoor_compromised）无 token 也应受理。
	res = handleSubmitFinding(nil, map[string]any{
		"vuln_type":        "backdoor_compromised",
		"title":            "发现预留后门账号",
		"severity_claimed": "严重",
		"target_url":       server.URL + "/admin",
		"description":      "登录页存在后门账号提示",
		"steps":            []any{"访问 /admin"},
	}, session)
	if res.IsErr {
		t.Fatalf("非请求对类漏洞不应强制 gate_token：%s", res.Output)
	}
}

func TestGateBaseLineServerErrorFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "baseline is broken")
	}))
	defer server.Close()
	session := &WorkerSession{TargetURL: server.URL}

	args := gateArgs(server.URL)
	args["expect"] = map[string]any{"body_contains": "baseline is broken"}
	res := handleVerifyFinding(context.Background(), args, session)
	if !res.IsErr {
		t.Fatal("基线本身 500 时必须 FAIL（验证设计有缺陷）")
	}
	if !strings.Contains(res.Output, "基线请求本身返回 500") {
		t.Fatalf("失败原因应指出基线异常，实际输出：\n%s", res.Output)
	}
}
