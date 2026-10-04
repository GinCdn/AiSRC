package engine

// 代理池接线验证：
//   - 轮转分配与冷却排除；
//   - doHTTP 走代理成功（转发代理真实转发）并上报成功；
//   - 坏代理连续 3 次连接失败进冷却，之后自动直连兜底成功。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"AiSRC/model"
)

// testProxyPort 从 httptest 地址取端口（portOf 已被 collector.go 占用）。
func testProxyPort(raw string) int {
	u, _ := url.Parse(raw)
	p, _ := strconv.Atoi(u.Port())
	return p
}

func resetProxyRuntime(t *testing.T) {
	t.Helper()
	applyProxySnapshot(&model.SystemSettings{})
	proxyPoolMu.Lock()
	proxyHealth = map[string]*proxyHealthState{}
	proxyPoolMu.Unlock()
}

// TestAcquireProxyRoundRobin 启用池时轮转分配；排除后取下一个；全部排除返回空。
func TestAcquireProxyRoundRobin(t *testing.T) {
	resetProxyRuntime(t)
	defer resetProxyRuntime(t)
	applyProxySnapshot(&model.SystemSettings{Proxy: model.ProxySettings{
		Enabled: true,
		Proxies: []model.ProxyItem{
			{ID: "p1", Host: "10.0.0.1", Port: 1080, Enabled: true},
			{ID: "p2", Host: "10.0.0.2", Port: 1080, Enabled: true},
			{ID: "p3", Host: "10.0.0.3", Port: 1080, Enabled: false},
		},
	}})
	first, url1 := acquireProxy(nil)
	if first == "" || url1 == "" {
		t.Fatal("启用池时 acquire 不应返回空")
	}
	if first != "p1" && first != "p2" {
		t.Fatalf("应分配启用中的代理，实际 %s", first)
	}
	second, _ := acquireProxy(map[string]bool{first: true})
	if second == "" || second == first {
		t.Fatalf("排除 %s 后应分配另一个，实际 %q", first, second)
	}
	id, _ := acquireProxy(map[string]bool{"p1": true, "p2": true})
	if id != "" {
		t.Fatalf("全部排除时应返回空（直连兜底），实际 %q", id)
	}
}

// TestProxyCooldown 连续 3 次失败进冷却，冷却期内 acquire 跳过；成功清零不冷却。
func TestProxyCooldown(t *testing.T) {
	resetProxyRuntime(t)
	defer resetProxyRuntime(t)
	applyProxySnapshot(&model.SystemSettings{Proxy: model.ProxySettings{
		Enabled: true,
		Proxies: []model.ProxyItem{{ID: "p1", Host: "10.0.0.1", Port: 1080, Enabled: true}},
	}})
	for i := 0; i < proxyFailThreshold; i++ {
		reportProxyResult("p1", false)
	}
	if id, _ := acquireProxy(nil); id != "" {
		t.Fatal("冷却中的代理不应被分配")
	}
	reportProxyResult("p1", true)
	if id, _ := acquireProxy(nil); id != "p1" {
		t.Fatal("成功上报应清零并恢复分配")
	}
}

// newForwardProxy 起一个 http 转发代理（absolute-form GET），返回代理与命中计数。
func newForwardProxy(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.Host == "" || r.URL.Host == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(proxy.Close)
	return proxy, &hits
}

// TestDoHTTPViaProxy 会话粘性代理生效：请求经代理转发，成功后健康清零。
func TestDoHTTPViaProxy(t *testing.T) {
	resetProxyRuntime(t)
	defer resetProxyRuntime(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer origin.Close()
	proxy, hits := newForwardProxy(t)

	applyProxySnapshot(&model.SystemSettings{Proxy: model.ProxySettings{
		Enabled: true,
		Proxies: []model.ProxyItem{{
			ID: "tp1", Host: "127.0.0.1", Port: testProxyPort(proxy.URL), Protocol: "http", Enabled: true,
		}},
	}})

	state := newSessionState(origin.URL)
	exchange := doHTTP(context.Background(), state, httpCall{URL: origin.URL})
	if !exchange.OK || exchange.Body != "origin-ok" {
		t.Fatalf("经代理请求失败：%q", exchange.Error)
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("请求未经代理转发，命中 %d", *hits)
	}
	if state.proxyID != "tp1" {
		t.Fatalf("粘性代理未记录：%q", state.proxyID)
	}
	proxyPoolMu.Lock()
	h := proxyHealth["tp1"]
	proxyPoolMu.Unlock()
	if h == nil || h.fails != 0 {
		t.Fatal("成功后健康应清零")
	}
}

// TestDoHTTPFallbackDirect 坏代理连续失败进冷却后，请求自动直连兜底成功。
func TestDoHTTPFallbackDirect(t *testing.T) {
	resetProxyRuntime(t)
	defer resetProxyRuntime(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct-ok"))
	}))
	defer origin.Close()

	applyProxySnapshot(&model.SystemSettings{Proxy: model.ProxySettings{
		Enabled: true,
		Proxies: []model.ProxyItem{{ID: "bad1", Host: "127.0.0.1", Port: 1, Protocol: "http", Enabled: true}},
	}})

	state := newSessionState(origin.URL)
	// 第 1 次：走坏代理，proxyconnect 失败。
	first := doHTTP(context.Background(), state, httpCall{URL: origin.URL})
	if first.OK || first.Error == "" {
		t.Fatal("坏代理首次请求应失败并记录错误")
	}
	if state.proxyURL != "" {
		t.Fatal("代理连接失败后应放弃该出口")
	}
	proxyPoolMu.Lock()
	h := proxyHealth["bad1"]
	proxyPoolMu.Unlock()
	if h == nil || h.fails != 1 {
		t.Fatal("应上报一次代理连接失败")
	}
	// 第 2 次：池内无其他可用出口 → 直连兜底成功。
	second := doHTTP(context.Background(), state, httpCall{URL: origin.URL})
	if !second.OK || second.Body != "direct-ok" {
		t.Fatalf("应直连兜底成功：%q", second.Error)
	}
}
