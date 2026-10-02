package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/utils"
)

// ProxyList 返回代理池视图。
func ProxyList() map[string]any {
	settings := engine.LoadSystemSettings()
	items := make([]map[string]any, 0, len(settings.Proxy.Proxies))
	for i := range settings.Proxy.Proxies {
		items = append(items, buildProxyView(settings.Proxy.Proxies[i]))
	}
	return map[string]any{
		"enabled": settings.Proxy.Enabled,
		"total":   len(items),
		"items":   items,
	}
}

func buildProxyView(item model.ProxyItem) map[string]any {
	return map[string]any{
		"id":           item.ID,
		"name":         item.Name,
		"protocol":     item.Protocol,
		"host":         item.Host,
		"port":         item.Port,
		"username":     item.Username,
		"password":     utils.MaskSecret(item.Password),
		"password_set": strings.TrimSpace(item.Password) != "",
		"enabled":      item.Enabled,
		"display":      item.Display(),
	}
}

// AddProxy 新增单条代理。
func AddProxy(item model.ProxyItem) (map[string]any, error) {
	settings := engine.LoadSystemSettings()
	if len(settings.Proxy.Proxies) >= constant.ProxyMaxItems {
		return nil, fmt.Errorf("代理数量已达上限 %d", constant.ProxyMaxItems)
	}
	if strings.TrimSpace(item.Host) == "" {
		return nil, fmt.Errorf("代理主机不能为空")
	}
	if item.ID == "" {
		item.ID = utils.UUID()
	}
	item.Protocol = normalizeProxyProtocol(item.Protocol)
	settings.Proxy.Proxies = append(settings.Proxy.Proxies, item)
	if err := engine.SaveSystemSettings(settings); err != nil {
		return nil, err
	}
	return buildProxyView(item), nil
}

// UpdateProxy 更新单条代理。
func UpdateProxy(proxyID string, patch map[string]any) (map[string]any, error) {
	settings := engine.LoadSystemSettings()
	for i := range settings.Proxy.Proxies {
		if settings.Proxy.Proxies[i].ID != proxyID {
			continue
		}
		item := settings.Proxy.Proxies[i]
		if value, ok := patch["name"]; ok {
			item.Name = strings.TrimSpace(fmt.Sprintf("%v", value))
		}
		if value, ok := patch["protocol"]; ok {
			item.Protocol = normalizeProxyProtocol(fmt.Sprintf("%v", value))
		}
		if value, ok := patch["host"]; ok {
			item.Host = strings.TrimSpace(fmt.Sprintf("%v", value))
		}
		if value, ok := patch["port"]; ok {
			item.Port = toInt(value)
		}
		if value, ok := patch["username"]; ok {
			item.Username = strings.TrimSpace(fmt.Sprintf("%v", value))
		}
		if value, ok := patch["password"]; ok {
			text := strings.TrimSpace(fmt.Sprintf("%v", value))
			if text != "" && !utils.IsMaskedSecret(text) {
				item.Password = text
			}
		}
		if value, ok := patch["enabled"]; ok {
			if b, ok := value.(bool); ok {
				item.Enabled = b
			}
		}
		settings.Proxy.Proxies[i] = item
		if err := engine.SaveSystemSettings(settings); err != nil {
			return nil, err
		}
		return buildProxyView(item), nil
	}
	return nil, fmt.Errorf("代理不存在")
}

// DeleteProxy 删除单条代理。
func DeleteProxy(proxyID string) error {
	settings := engine.LoadSystemSettings()
	kept := make([]model.ProxyItem, 0, len(settings.Proxy.Proxies))
	found := false
	for _, item := range settings.Proxy.Proxies {
		if item.ID == proxyID {
			found = true
			continue
		}
		kept = append(kept, item)
	}
	if !found {
		return fmt.Errorf("代理不存在")
	}
	settings.Proxy.Proxies = kept
	return engine.SaveSystemSettings(settings)
}

// ToggleProxyPool 启用 / 停用代理池。
func ToggleProxyPool(enabled bool) (map[string]any, error) {
	settings := engine.LoadSystemSettings()
	settings.Proxy.Enabled = enabled
	if err := engine.SaveSystemSettings(settings); err != nil {
		return nil, err
	}
	return ProxyList(), nil
}

// ImportProxies 批量导入代理（每行 host:port 或 protocol://user:pass@host:port）。
func ImportProxies(raw string, replace bool) (map[string]any, error) {
	settings := engine.LoadSystemSettings()
	existing := settings.Proxy.Proxies
	if replace {
		existing = nil
	}
	seen := map[string]bool{}
	for _, item := range existing {
		seen[strings.ToLower(item.Host)+":"+itoa(item.Port)] = true
	}
	added := 0
	skipped := 0
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item, err := parseProxyLine(line)
		if err != nil {
			skipped++
			continue
		}
		key := strings.ToLower(item.Host) + ":" + itoa(item.Port)
		if seen[key] {
			skipped++
			continue
		}
		if len(existing) >= constant.ProxyMaxItems {
			skipped++
			continue
		}
		seen[key] = true
		existing = append(existing, item)
		added++
	}
	settings.Proxy.Proxies = existing
	if err := engine.SaveSystemSettings(settings); err != nil {
		return nil, err
	}
	view := ProxyList()
	view["added"] = added
	view["skipped"] = skipped
	return view, nil
}

// parseProxyLine 解析单行代理配置。
func parseProxyLine(line string) (model.ProxyItem, error) {
	item := model.ProxyItem{ID: utils.UUID(), Protocol: "http", Enabled: true}
	target := line
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil {
			return item, err
		}
		item.Protocol = normalizeProxyProtocol(parsed.Scheme)
		if parsed.User != nil {
			item.Username = parsed.User.Username()
			if password, ok := parsed.User.Password(); ok {
				item.Password = password
			}
		}
		target = parsed.Host
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Count(target, ":") == 1 {
			parts := strings.SplitN(target, ":", 2)
			host = parts[0]
			portText = parts[1]
		} else {
			return item, fmt.Errorf("格式不正确: %s", line)
		}
	}
	port := 0
	if portText != "" {
		port = atoi(portText)
	}
	if strings.TrimSpace(host) == "" || port <= 0 {
		return item, fmt.Errorf("缺少主机或端口: %s", line)
	}
	item.Host = host
	item.Port = port
	if item.Name == "" {
		item.Name = host + ":" + portText
	}
	return item, nil
}

// TestProxies 测试代理连通性（未指定 id 时测试全部启用的代理）。
func TestProxies(proxyIDs []string) map[string]any {
	settings := engine.LoadSystemSettings()
	targets := make([]model.ProxyItem, 0, len(settings.Proxy.Proxies))
	for _, item := range settings.Proxy.Proxies {
		if len(proxyIDs) == 0 {
			if item.Enabled {
				targets = append(targets, item)
			}
			continue
		}
		for _, id := range proxyIDs {
			if id == item.ID {
				targets = append(targets, item)
				break
			}
		}
	}

	results := make([]map[string]any, 0, len(targets))
	for _, item := range targets {
		results = append(results, testSingleProxy(item))
	}
	return map[string]any{"total": len(results), "results": results}
}

// testSingleProxy 通过代理访问一个轻量探测端点。
func testSingleProxy(item model.ProxyItem) map[string]any {
	result := map[string]any{
		"id":      item.ID,
		"name":    item.Name,
		"display": item.Display(),
		"ok":      false,
		"latency": 0,
		"error":   "",
	}
	proxyURL, err := url.Parse(buildProxyURL(item))
	if err != nil {
		result["error"] = "代理地址无效：" + err.Error()
		return result
	}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
		TLSHandshakeTimeout: 8 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	probeURL := "http://httpbin.org/ip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		result["error"] = err.Error()
		result["latency"] = latency
		return result
	}
	defer resp.Body.Close()
	result["ok"] = resp.StatusCode < 500
	result["latency"] = latency
	result["status_code"] = resp.StatusCode
	return result
}

// buildProxyURL 组装代理连接串（含认证）。
func buildProxyURL(item model.ProxyItem) string {
	scheme := normalizeProxyProtocol(item.Protocol)
	host := fmt.Sprintf("%s:%d", item.Host, item.Port)
	if item.Username != "" {
		if item.Password != "" {
			return fmt.Sprintf("%s://%s:%s@%s", scheme, url.QueryEscape(item.Username), url.QueryEscape(item.Password), host)
		}
		return fmt.Sprintf("%s://%s@%s", scheme, url.QueryEscape(item.Username), host)
	}
	return scheme + "://" + host
}

// ActiveProxyURL 返回当前启用的第一个代理（供 Worker 工具使用）。
func ActiveProxyURL() string {
	settings := engine.LoadSystemSettings()
	if !settings.Proxy.Enabled {
		return ""
	}
	for _, item := range settings.Proxy.Proxies {
		if item.Enabled {
			return buildProxyURL(item)
		}
	}
	return ""
}

func normalizeProxyProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "socks5", "socks":
		return "socks5"
	case "https":
		return "https"
	default:
		return "http"
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	digits := make([]byte, 0, 12)
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

func atoi(text string) int {
	value := 0
	for _, ch := range strings.TrimSpace(text) {
		if ch < '0' || ch > '9' {
			return 0
		}
		value = value*10 + int(ch-'0')
	}
	return value
}

// EnsureProxyTableMigrated 占位：代理数据存于 settings 单行，无需独立表。
func EnsureProxyTableMigrated() {}

var _ = core.Db
