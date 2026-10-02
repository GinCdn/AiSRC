package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"AiSRC/utils"
)

// BillingInfo 中转站余额/配额查询结果。
//
// NewAPI（QuantumNous/new-api）与 One API 系网关提供 OpenAI 风格的 billing
// 兼容接口；Sub2API 等订阅转 API 网关可能没有该接口——此时 Supported=false，
// 调用方应视为「该网关不提供余额查询」而不是错误。
type BillingInfo struct {
	Supported    bool    `json:"supported"`
	Gateway      string  `json:"gateway"`       // newapi / unknown
	HardLimitUSD float64 `json:"hard_limit_usd"` // 总额度（美元）
	UsedUSD      float64 `json:"used_usd"`       // 已用（美元）
	RemainingUSD float64 `json:"remaining_usd"`  // 剩余（美元）
	Detail       string  `json:"detail"`         // Supported=false 时的原因说明
}

// billingBaseURL 规范化计费接口根地址：billing 路径不带 /v1 前缀，
// 而用户填的 base_url 可能以 /v1 结尾（对话地址写法），需要剥掉。
func billingBaseURL(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	base = strings.TrimSuffix(base, "/v1")
	return strings.TrimRight(base, "/")
}

// billingGet 请求 billing 兼容接口并解析 JSON。
func (c *Client) billingGet(ctx context.Context, url, apiKey string, out any) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	for key, value := range openAIHeaders(apiKey) {
		req.Header.Set(key, value)
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("接口返回 %d: %s", resp.StatusCode, utils.Truncate(strings.TrimSpace(string(body)), 160))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, fmt.Errorf("解析响应失败: %w", err)
	}
	return resp.StatusCode, nil
}

// Billing 查询中转站余额/配额。
//
// 两步：subscription 拿总额度（hard_limit_usd），usage 拿已用金额
// （total_usage，美元）。查询窗口取过去 90 天（One API 系对区间长度有
// 上限约束，90 天在安全范围内；窗口内累计即令牌全部消费）。
func (c *Client) Billing(ctx context.Context, baseURL, apiKey string) (*BillingInfo, error) {
	baseURL = strings.TrimSpace(baseURL)
	apiKey = strings.TrimSpace(apiKey)
	if baseURL == "" {
		return nil, fmt.Errorf("未配置 base_url")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("未配置 API Key")
	}
	base := billingBaseURL(baseURL)

	info := &BillingInfo{Gateway: "unknown"}

	// ① 总额度。
	var sub struct {
		HardLimitUSD       float64 `json:"hard_limit_usd"`
		SystemHardLimitUSD float64 `json:"system_hard_limit_usd"`
	}
	subStatus, subErr := c.billingGet(ctx, base+"/dashboard/billing/subscription", apiKey, &sub)
	if subErr != nil || (sub.HardLimitUSD <= 0 && sub.SystemHardLimitUSD <= 0) {
		info.Detail = fmt.Sprintf("该端点未提供余额查询（subscription %s）", billingReason(subStatus, subErr))
		return info, nil
	}
	limit := sub.HardLimitUSD
	if limit <= 0 {
		limit = sub.SystemHardLimitUSD
	}
	info.Supported = true
	info.Gateway = "newapi"
	info.HardLimitUSD = limit

	// ② 已用金额。失败不影响「支持」判定——只显示总额度。
	now := time.Now()
	start := now.AddDate(0, 0, -90).Format("2006-01-02")
	end := now.AddDate(0, 0, 1).Format("2006-01-02")
	var usage struct {
		TotalUsage float64 `json:"total_usage"`
	}
	if _, usageErr := c.billingGet(ctx,
		fmt.Sprintf("%s/dashboard/billing/usage?start_date=%s&end_date=%s", base, start, end),
		apiKey, &usage); usageErr == nil && usage.TotalUsage > 0 {
		info.UsedUSD = usage.TotalUsage
	}
	info.RemainingUSD = info.HardLimitUSD - info.UsedUSD
	if info.RemainingUSD < 0 {
		info.RemainingUSD = 0
	}
	return info, nil
}

// billingReason 把一次 billing 请求的失败归因为简短说明。
func billingReason(status int, err error) string {
	switch {
	case err != nil && status == 0:
		return "连接失败"
	case status == http.StatusNotFound:
		return "接口不存在(404)"
	case status == http.StatusUnauthorized:
		return "令牌无权限(401)"
	case status != 0:
		return fmt.Sprintf("HTTP %d", status)
	default:
		return "响应无额度字段"
	}
}
