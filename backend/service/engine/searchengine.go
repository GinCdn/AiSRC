package engine

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"AiSRC/utils"
)

// EngineResult 统一测绘结果（行按 Fields 顺序排列）。
type EngineResult struct {
	Fields     []string
	Results    [][]string
	Size       int
	Page       int
	Engine     string
	NextCursor string
	// Trace MCP 工作流轨迹（prepare/request/response/normalize 各步结构化记录），
	// 统一入口 SearchEngine 自动填充，collector 落为 mcp_workflow 事件。
	Trace []map[string]any
}

// EngineError 测绘引擎错误。AccountError=true 表示账号级致命错误（重试无意义）。
type EngineError struct {
	Message      string
	AccountError bool
	RateLimited  bool
	// DataCap 数据查看上限（如 Hunter 单次查询最多查看 1 万条资产）。
	// 属于正常取尽而非失败，collector 应标记 exhausted 停止翻页。
	DataCap bool
}

func (e *EngineError) Error() string { return e.Message }

// engineFields 统一输出字段顺序。
var engineFields = []string{"host", "ip", "port", "title", "domain", "org"}

// engineDefaults 各引擎默认 API 端点。
var engineDefaults = map[string]string{
	"fofa":    "https://fofa.info",
	"quake":   "https://quake.360.net",
	"hunter":  "https://hunter.qianxin.com",
	"shodan":  "https://api.shodan.io",
	"zoomeye": "https://api.zoomeye.ai",
	"censys":  "https://api.platform.censys.io",
}

// EngineDisplayName 引擎展示名。
func EngineDisplayName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "fofa":
		return "FOFA"
	case "quake":
		return "360 Quake"
	case "hunter":
		return "奇安信 Hunter"
	case "shodan":
		return "Shodan"
	case "zoomeye":
		return "ZoomEye"
	case "censys":
		return "Censys"
	default:
		if name == "" {
			return "FOFA"
		}
		return name
	}
}

// engineOrder 引擎清单顺序，对齐原版 app/engines/__init__.py 的注册顺序
// （import fofa → quake → hunter → zoomeye → shodan → censys）。
var engineOrder = []string{"fofa", "quake", "hunter", "zoomeye", "shodan", "censys"}

// EngineInfo 引擎元信息（供设置页渲染「各引擎 API Key」区块）。
type EngineInfo struct {
	Name        string
	DisplayName string
}

// ListEngines 列出全部已注册引擎，顺序与原版注册顺序一致。
// 对齐原版 app/engines/base.py::list_engines()。
func ListEngines() []EngineInfo {
	out := make([]EngineInfo, 0, len(engineOrder))
	for _, name := range engineOrder {
		out = append(out, EngineInfo{Name: name, DisplayName: EngineDisplayName(name)})
	}
	return out
}

// NormalizeEngine 归一化引擎名。
func NormalizeEngine(name string) string {
	value := strings.ToLower(strings.TrimSpace(name))
	if _, ok := engineDefaults[value]; ok {
		return value
	}
	return "fofa"
}

// DefaultEngineBaseURL 引擎默认端点。
func DefaultEngineBaseURL(name string) string {
	return engineDefaults[NormalizeEngine(name)]
}

// SearchEngine 统一查询入口。外层自动采集 MCP 工作流轨迹
// （对齐 hunter-mcp 等测绘 MCP 服务器的工具调用形态：prepare → request →
// response → normalize），所有引擎一致生效，collector 落为 mcp_workflow 事件。
func SearchEngine(ctx context.Context, engineName, apiKey, query string, page, pageSize int, baseURL string) (*EngineResult, error) {
	name := NormalizeEngine(engineName)
	if strings.TrimSpace(apiKey) == "" {
		return nil, &EngineError{Message: "缺少 " + EngineDisplayName(name) + " API Key", AccountError: true}
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = DefaultEngineBaseURL(name)
	}

	// MCP 工作流 step1: prepare（参数准备，key 脱敏）。
	trace := []map[string]any{{
		"step": "prepare", "tool": name + "_search", "engine": name,
		"base_url": base, "query": query, "page": page, "page_size": pageSize,
		"api_key": utils.MaskSecret(apiKey),
	}}
	ctx, callLog := withEngineCallLog(ctx)
	started := time.Now()
	result, err := searchEngineDispatch(ctx, name, base, apiKey, query, page, pageSize)
	elapsed := time.Since(started).Milliseconds()

	// step2: request（实际发出的请求，URL 中密钥参数脱敏）。
	if callLog.url != "" {
		trace = append(trace, map[string]any{
			"step": "request", "method": callLog.method, "url": maskEngineURL(callLog.url),
		})
	}
	// step3: response（HTTP 状态/行数/耗时/错误）。
	responseStep := map[string]any{"step": "response", "elapsed_ms": elapsed}
	if callLog.status > 0 {
		responseStep["http_status"] = callLog.status
	}
	if err != nil {
		responseStep["error"] = err.Error()
	}
	trace = append(trace, responseStep)
	// step4: normalize（归一化结果）。
	if err == nil && result != nil {
		trace = append(trace, map[string]any{
			"step": "normalize", "fields": result.Fields, "rows": len(result.Results), "size": result.Size,
		})
		result.Trace = trace
	}
	return result, err
}

// engineTraceURL 从轨迹取 request 步的脱敏 URL（事件摘要用）。
func engineTraceURL(trace []map[string]any) string {
	for _, step := range trace {
		if strOf(step["step"]) == "request" {
			return strOf(step["url"])
		}
	}
	return ""
}

// engineTraceElapsed 从轨迹取 response 步耗时（事件摘要用）。
func engineTraceElapsed(trace []map[string]any) int64 {
	for _, step := range trace {
		if strOf(step["step"]) == "response" {
			return int64(intOf(step["elapsed_ms"]))
		}
	}
	return 0
}

// searchEngineDispatch 按引擎分发（原 SearchEngine 的 switch 主体）。
func searchEngineDispatch(ctx context.Context, name, base, apiKey, query string, page, pageSize int) (*EngineResult, error) {
	switch name {
	case "quake":
		return searchQuake(ctx, base, apiKey, query, page, pageSize)
	case "hunter":
		return searchHunter(ctx, base, apiKey, query, page, pageSize)
	case "shodan":
		return searchShodan(ctx, base, apiKey, query, page)
	case "zoomeye":
		return searchZoomEye(ctx, base, apiKey, query, page, pageSize)
	case "censys":
		return searchCensys(ctx, base, apiKey, query, page, pageSize)
	default:
		return searchFofa(ctx, base, apiKey, query, page, pageSize)
	}
}

// engineCallLog 单次测绘 HTTP 调用记录（经 context 传递，并发安全）。
type engineCallLog struct {
	method    string
	url       string
	status    int
	err       string
	elapsedMS int64
}

type engineCallLogKey struct{}

// withEngineCallLog 在 context 上挂一块本次测绘调用的记录板。
func withEngineCallLog(ctx context.Context) (context.Context, *engineCallLog) {
	log := &engineCallLog{}
	return context.WithValue(ctx, engineCallLogKey{}, log), log
}

// engineCallLogFrom 从 context 取记录板（无则 nil，doSearchJSON 容忍）。
func engineCallLogFrom(ctx context.Context) *engineCallLog {
	log, _ := ctx.Value(engineCallLogKey{}).(*engineCallLog)
	return log
}

// maskEngineURL 把 URL 查询参数中的密钥类键值打码（key/api-key/token/password/sign）。
func maskEngineURL(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	query := parsed.Query()
	changed := false
	for key, values := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "key") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "password") || strings.Contains(lower, "sign") {
			for i := range values {
				values[i] = "••••••••"
			}
			query[key] = values
			changed = true
		}
	}
	if !changed {
		return target
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// searchHTTPClient 测绘请求使用的 HTTP 客户端（容忍自建镜像证书）。
var searchHTTPClient = &http.Client{
	Timeout: 45 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// doSearchJSON 发起请求并解析 JSON 响应。
// 调用细节同步写回 ctx 上的 engineCallLog（SearchEngine 据此生成 MCP 工作流轨迹）。
func doSearchJSON(ctx context.Context, method, target string, headers map[string]string, body io.Reader) (map[string]any, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, 0, &EngineError{Message: "构造请求失败：" + err.Error()}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if log := engineCallLogFrom(ctx); log != nil {
		log.method = method
		log.url = target
	}
	started := time.Now()
	resp, err := searchHTTPClient.Do(req)
	if log := engineCallLogFrom(ctx); log != nil {
		log.elapsedMS = time.Since(started).Milliseconds()
	}
	if err != nil {
		if log := engineCallLogFrom(ctx); log != nil {
			log.err = err.Error()
		}
		return nil, 0, &EngineError{Message: "请求失败：" + err.Error()}
	}
	defer resp.Body.Close()
	if log := engineCallLogFrom(ctx); log != nil {
		log.status = resp.StatusCode
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, resp.StatusCode, &EngineError{Message: "读取响应失败：" + err.Error()}
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		snippet := utils.Truncate(strings.ReplaceAll(string(raw), "\n", " "), 240)
		return nil, resp.StatusCode, &EngineError{
			Message: fmt.Sprintf("返回非 JSON (HTTP %d): %s", resp.StatusCode, snippet),
		}
	}
	return data, resp.StatusCode, nil
}

// ===== FOFA =====

var fofaAccountErrorMarkers = []string{
	"820000", "820001", "-700", "账号无效", "账号已过期", "账号过期",
	"无效的fofa", "无效的 fofa", "f点不足", "f币不足", "余额不足", "配额",
	"权限不足", "没有权限", "会员", "account invalid", "invalid key",
	"expired", "insufficient", "quota", "permission", "unauthorized", "forbidden",
}

func searchFofa(ctx context.Context, base, apiKey, query string, page, pageSize int) (*EngineResult, error) {
	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	params.Set("fields", strings.Join(engineFields, ","))
	params.Set("page", strconv.Itoa(page))
	params.Set("size", strconv.Itoa(pageSize))
	params.Set("full", "false")

	data, _, err := doSearchJSON(ctx, http.MethodGet, base+"/api/v1/search/all?"+params.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if truthy(data["error"]) {
		message := fmt.Sprintf("%v", data["errmsg"])
		return nil, &EngineError{
			Message:      "FOFA 错误: " + message,
			AccountError: containsAnyFold(message, fofaAccountErrorMarkers),
		}
	}
	rows := toRows(data["results"])
	return &EngineResult{
		Fields:  engineFields,
		Results: rows,
		Size:    intOf(data["size"]),
		Page:    page,
		Engine:  "fofa",
	}, nil
}

// ===== Quake =====

func searchQuake(ctx context.Context, base, apiKey, query string, page, pageSize int) (*EngineResult, error) {
	size := pageSize
	if size > 100 {
		size = 100
	}
	if size < 1 {
		size = 10
	}
	payload := map[string]any{
		"query": query,
		"start": maxInt(0, (page-1)*pageSize),
		"size":  size,
		"include": []string{
			"ip", "port", "hostname", "domain", "title", "service.http.title",
			"org", "location.country_cn", "service.http.host",
		},
	}
	body, _ := json.Marshal(payload)
	headers := map[string]string{
		"X-QuakeToken": apiKey,
		"Content-Type": "application/json; charset=utf-8",
	}
	data, status, err := doSearchJSON(ctx, http.MethodPost, base+"/api/v3/search/quake_service", headers, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	code := fmt.Sprintf("%v", data["code"])
	if code != "" && code != "0" && strings.ToLower(code) != "q0" && !strings.Contains(code, "成功") {
		message := firstNonEmptyString(fmt.Sprintf("%v", data["message"]), fmt.Sprintf("%v", data["data"]))
		if containsAnyFold(message, []string{"q3005", "q3015", "频率", "rate", "too many"}) {
			return nil, &EngineError{Message: "Quake 频率限制: " + message, RateLimited: true}
		}
		if containsAnyFold(message, []string{"权限", "无效", "认证", "token", "unauthorized", "forbidden", "invalid"}) {
			return nil, &EngineError{Message: "Quake 错误[" + code + "]: " + message, AccountError: true}
		}
		return nil, &EngineError{Message: "Quake 错误[" + code + "]: " + message}
	}
	if status >= 400 {
		return nil, &EngineError{Message: fmt.Sprintf("Quake HTTP %d: %v", status, data["message"])}
	}
	items := toMapSlice(data["data"])
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, quakeRow(item))
	}
	total := 0
	if meta, ok := data["meta"].(map[string]any); ok {
		if pagination, ok := meta["pagination"].(map[string]any); ok {
			total = intOf(pagination["total"])
		}
	}
	if total == 0 {
		total = len(rows)
	}
	return &EngineResult{Fields: engineFields, Results: rows, Size: total, Page: page, Engine: "quake"}, nil
}

func quakeRow(item map[string]any) []string {
	ip := str(item["ip"])
	port := str(item["port"])
	host := firstNonEmptyString(str(item["hostname"]), str(item["domain"]), str(item["service.http.host"]))
	title := firstNonEmptyString(
		nestedStr(item, "service", "http", "title"),
		str(item["title"]),
	)
	org := firstNonEmptyString(str(item["org"]), nestedStr(item, "location", "country_cn"))
	if host == "" {
		host = ip
	}
	if host == "" {
		host = ip
	}
	if !strings.Contains(host, "://") && host != "" {
		scheme := "http"
		if port == "443" || port == "8443" {
			scheme = "https"
		}
		host = scheme + "://" + host
		if port != "" && port != "80" && port != "443" {
			host += ":" + port
		}
	}
	return []string{host, ip, port, title, str(item["domain"]), org}
}

// ===== Hunter =====

func searchHunter(ctx context.Context, base, apiKey, query string, page, pageSize int) (*EngineResult, error) {
	size := pageSize
	if size > 100 {
		size = 100
	}
	params := url.Values{}
	params.Set("api-key", apiKey)
	params.Set("search", base64.URLEncoding.EncodeToString([]byte(query)))
	params.Set("page", strconv.Itoa(page))
	params.Set("page_size", strconv.Itoa(size))
	params.Set("is_web", "3")

	data, _, err := doSearchJSON(ctx, http.MethodGet, base+"/openApi/search?"+params.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if intOf(data["code"]) != 200 {
		message := firstNonEmptyString(fmt.Sprintf("%v", data["message"]), fmt.Sprintf("%v", data["data"]))
		account := containsAnyFold(message, []string{"key", "认证", "无效", "余额", "积分", "权限", "unauthorized", "forbidden"})
		// 「支持最大查看10000条资产」= 翻页越过引擎查看上限，重试永远不会成功。
		dataCap := strings.Contains(message, "支持最大查看") || strings.Contains(message, "10000")
		// 「请求太多啦」= QPS 限频，等待后重试即可恢复（与 Quake 频率限制同语义）。
		rateLimited := containsAnyFold(message, []string{"请求太多", "频率", "too many", "rate limit"})
		return nil, &EngineError{Message: "Hunter 错误: " + message, AccountError: account, DataCap: dataCap, RateLimited: rateLimited}
	}
	payload, _ := data["data"].(map[string]any)
	items := toMapSlice(payload["arr"])
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		host := hunterHost(item)
		port := str(item["port"])
		if host != "" && !strings.Contains(host, "://") {
			scheme := "http"
			if port == "443" {
				scheme = "https"
			}
			host = scheme + "://" + host
		}
		rows = append(rows, []string{
			host,
			str(item["ip"]),
			port,
			firstNonEmptyString(str(item["web_title"]), str(item["title"])),
			str(item["domain"]),
			firstNonEmptyString(str(item["company"]), str(item["company_name"])),
		})
	}
	return &EngineResult{
		Fields:  engineFields,
		Results: rows,
		Size:    intOf(payload["total"]),
		Page:    page,
		Engine:  "hunter",
	}, nil
}

func hunterHost(item map[string]any) string {
	rawURL := strings.TrimSpace(str(item["url"]))
	if rawURL != "" {
		target := rawURL
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}
	return firstNonEmptyString(str(item["domain"]), str(item["ip"]))
}

// ===== Shodan =====

func searchShodan(ctx context.Context, base, apiKey, query string, page int) (*EngineResult, error) {
	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("query", query)
	params.Set("page", strconv.Itoa(page))

	data, _, err := doSearchJSON(ctx, http.MethodGet, base+"/shodan/host/search?"+params.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if message := str(data["error"]); message != "" {
		account := containsAnyFold(message, []string{"invalid", "unauthorized", "forbidden", "api key", "plan"})
		return nil, &EngineError{Message: "Shodan 错误: " + message, AccountError: account}
	}
	matches := toMapSlice(data["matches"])
	rows := make([][]string, 0, len(matches))
	for _, item := range matches {
		httpData, _ := item["http"].(map[string]any)
		title := ""
		if httpData != nil {
			title = str(httpData["title"])
		}
		hostnames := toStringSlice(item["hostnames"])
		host := ""
		if len(hostnames) > 0 {
			host = hostnames[0]
		}
		port := str(item["port"])
		if host == "" {
			host = str(item["ip_str"])
		}
		if host != "" && !strings.Contains(host, "://") {
			scheme := "http"
			if port == "443" {
				scheme = "https"
			}
			host = scheme + "://" + host
			if port != "" && port != "80" && port != "443" {
				host += ":" + port
			}
		}
		rows = append(rows, []string{host, str(item["ip_str"]), port, title, "", str(item["org"])})
	}
	return &EngineResult{
		Fields:  engineFields,
		Results: rows,
		Size:    intOf(data["total"]),
		Page:    page,
		Engine:  "shodan",
	}, nil
}

// ===== ZoomEye =====

func searchZoomEye(ctx context.Context, base, apiKey, query string, page, pageSize int) (*EngineResult, error) {
	size := pageSize
	if size > 1000 {
		size = 1000
	}
	payload := map[string]any{
		"qbase64":  base64.StdEncoding.EncodeToString([]byte(query)),
		"page":     page,
		"pagesize": size,
		"fields":   "ip,port,domain,hostname,title,url,organization.name",
	}
	lower := strings.ToLower(query)
	for _, token := range []string{"title=", "title:", "body=", "body:", "http.title", "web."} {
		if strings.Contains(lower, token) {
			payload["sub_type"] = "web"
			break
		}
	}
	body, _ := json.Marshal(payload)
	headers := map[string]string{"API-KEY": apiKey, "Content-Type": "application/json"}
	data, _, err := doSearchJSON(ctx, http.MethodPost, base+"/v2/search", headers, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	code := intOf(data["code"])
	if code != 0 && code != 200 && code != 60000 && data["data"] == nil {
		message := firstNonEmptyString(str(data["message"]), str(data["error"]))
		account := containsAnyFold(message, []string{"key", "认证", "无效", "权限", "unauthorized", "forbidden", "quota"})
		return nil, &EngineError{Message: "ZoomEye 错误: " + message, AccountError: account}
	}
	items := toMapSlice(data["data"])
	if len(items) == 0 {
		items = toMapSlice(data["matches"])
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		title := str(item["title"])
		if list, ok := item["title"].([]any); ok {
			parts := make([]string, 0, len(list))
			for _, v := range list {
				if s := str(v); s != "" {
					parts = append(parts, s)
				}
			}
			title = utils.Truncate(strings.Join(parts, " | "), 200)
		}
		org := nestedStr(item, "organization", "name")
		if org == "" {
			org = firstNonEmptyString(str(item["org"]), str(item["organization"]))
		}
		host := firstNonEmptyString(str(item["hostname"]), str(item["domain"]), str(item["url"]), str(item["ip"]))
		port := str(item["port"])
		if host != "" && !strings.Contains(host, "://") {
			scheme := "http"
			if port == "443" {
				scheme = "https"
			}
			host = scheme + "://" + host
			if port != "" && port != "80" && port != "443" {
				host += ":" + port
			}
		}
		rows = append(rows, []string{host, str(item["ip"]), port, title, str(item["domain"]), org})
	}
	return &EngineResult{
		Fields:  engineFields,
		Results: rows,
		Size:    intOf(data["total"]),
		Page:    page,
		Engine:  "zoomeye",
	}, nil
}

// ===== Censys（平台 v3 简化实现）=====

func searchCensys(ctx context.Context, base, apiKey, query string, page, pageSize int) (*EngineResult, error) {
	size := pageSize
	if size > 100 {
		size = 100
	}
	payload := map[string]any{
		"query":     query,
		"page_size": size,
		"fields":    []string{"host.ip", "host.services.port", "host.services.service_name", "host.names", "host.autonomous_system.name"},
	}
	body, _ := json.Marshal(payload)
	headers := map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Content-Type":  "application/json",
	}
	data, status, err := doSearchJSON(ctx, http.MethodPost, base+"/v3/global/search/query", headers, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, &EngineError{Message: "Censys 认证失败，请检查 API Key", AccountError: true}
	}
	hits := toMapSlice(data["result"])
	if len(hits) == 0 {
		hits = toMapSlice(data["results"])
	}
	rows := make([][]string, 0, len(hits))
	for _, hit := range hits {
		hostObj, _ := hit["host"].(map[string]any)
		if hostObj == nil {
			hostObj = hit
		}
		ip := str(hostObj["ip"])
		names := toStringSlice(hostObj["names"])
		host := ip
		if len(names) > 0 {
			host = names[0]
		}
		port := ""
		services := toMapSlice(hostObj["services"])
		if len(services) > 0 {
			port = str(services[0]["port"])
		}
		org := nestedStr(hostObj, "autonomous_system", "name")
		if host != "" && !strings.Contains(host, "://") {
			scheme := "http"
			if port == "443" {
				scheme = "https"
			}
			host = scheme + "://" + host
			if port != "" && port != "80" && port != "443" {
				host += ":" + port
			}
		}
		rows = append(rows, []string{host, ip, port, "", "", org})
	}
	return &EngineResult{
		Fields:  engineFields,
		Results: rows,
		Size:    len(rows),
		Page:    page,
		Engine:  "censys",
	}, nil
}

// ===== 通用小工具 =====

func toRows(value any) [][]string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, row := range list {
		switch item := row.(type) {
		case []any:
			cells := make([]string, 0, len(item))
			for _, cell := range item {
				cells = append(cells, str(cell))
			}
			rows = append(rows, cells)
		case map[string]any:
			rows = append(rows, []string{
				str(item["host"]), str(item["ip"]), str(item["port"]),
				str(item["title"]), str(item["domain"]), str(item["org"]),
			})
		}
	}
	return rows
}

func toMapSlice(value any) []map[string]any {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toStringSlice(value any) []string {
	list, ok := value.([]any)
	if !ok {
		if s, ok := value.(string); ok && s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s := str(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func nestedStr(item map[string]any, path ...string) string {
	var current any = item
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			// 兼容 "a.b" 形式的扁键。
			joined := strings.Join(path, ".")
			if flat, ok := item[joined]; ok {
				return str(flat)
			}
			return ""
		}
	}
	return str(current)
}

func str(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func intOf(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func truthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "true" || v == "1"
	case float64:
		return v != 0
	default:
		return false
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func containsAnyFold(text string, markers []string) bool {
	lower := strings.ToLower(text)
	for _, m := range markers {
		if m != "" && strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}
