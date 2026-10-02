package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// newFakeNewAPI 起一个模拟 NewAPI billing 兼容接口的假网关。
// 行为可开关：关闭 billing 接口以模拟 Sub2API（返回 404）。
func newFakeNewAPI(t *testing.T, disableBilling bool, hardLimit, totalUsage float64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/billing/subscription", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if disableBilling {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"billing_subscription","hard_limit_usd":` +
			jsonFloat(hardLimit) + `,"system_hard_limit_usd":0}`))
	})
	mux.HandleFunc("/dashboard/billing/usage", func(w http.ResponseWriter, r *http.Request) {
		if disableBilling {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("start_date") == "" || r.URL.Query().Get("end_date") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","total_usage":` + jsonFloat(totalUsage) + `}`))
	})
	return httptest.NewServer(mux)
}

func jsonFloat(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return fmt.Sprintf("%v", v)
}

func TestBillingNewAPICompatible(t *testing.T) {
	srv := newFakeNewAPI(t, false, 20, 4.5)
	defer srv.Close()

	info, err := NewClient().Billing(context.Background(), srv.URL, "sk-test")
	if err != nil {
		t.Fatalf("Billing 不应报错: %v", err)
	}
	if !info.Supported {
		t.Fatalf("NewAPI 兼容网关应 Supported=true，detail=%s", info.Detail)
	}
	if info.Gateway != "newapi" {
		t.Errorf("gateway 应为 newapi，实际 %q", info.Gateway)
	}
	if info.HardLimitUSD != 20 {
		t.Errorf("HardLimitUSD 应为 20，实际 %v", info.HardLimitUSD)
	}
	if info.UsedUSD != 4.5 {
		t.Errorf("UsedUSD 应为 4.5，实际 %v", info.UsedUSD)
	}
	if info.RemainingUSD != 15.5 {
		t.Errorf("RemainingUSD 应为 15.5，实际 %v", info.RemainingUSD)
	}
}

// TestBillingBaseURLWithV1 用户按对话地址习惯填 /v1 结尾时，billing 必须剥掉
// /v1 再拼 dashboard 路径。
func TestBillingBaseURLWithV1(t *testing.T) {
	srv := newFakeNewAPI(t, false, 10, 0)
	defer srv.Close()

	info, err := NewClient().Billing(context.Background(), srv.URL+"/v1", "sk-test")
	if err != nil {
		t.Fatalf("Billing 不应报错: %v", err)
	}
	if !info.Supported {
		t.Fatalf("带 /v1 后缀的 base_url 也应命中 billing 接口，detail=%s", info.Detail)
	}
	if info.HardLimitUSD != 10 {
		t.Errorf("HardLimitUSD 应为 10，实际 %v", info.HardLimitUSD)
	}
}

// TestBillingUnsupportedGateway Sub2API 等无 billing 接口的网关：
// Supported=false + 说明文案，且 Billing 本身不返回错误。
func TestBillingUnsupportedGateway(t *testing.T) {
	srv := newFakeNewAPI(t, true, 0, 0)
	defer srv.Close()

	info, err := NewClient().Billing(context.Background(), srv.URL, "sk-test")
	if err != nil {
		t.Fatalf("无 billing 接口不应报错（应返回 Supported=false）: %v", err)
	}
	if info.Supported {
		t.Fatalf("404 网关不应标记为支持: %+v", info)
	}
	if info.Detail == "" {
		t.Fatalf("Supported=false 时必须给出原因说明")
	}
}

// TestBillingMissingInputs 缺 base_url / key 必须明确报错。
func TestBillingMissingInputs(t *testing.T) {
	c := NewClient()
	if _, err := c.Billing(context.Background(), "", "sk-x"); err == nil {
		t.Errorf("缺 base_url 应报错")
	}
	if _, err := c.Billing(context.Background(), "http://x", "  "); err == nil {
		t.Errorf("缺 API Key 应报错")
	}
}
