package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"AiSRC/utils"
)

// 协议类型。
const (
	ProtocolAuto       = "auto"
	ProtocolOpenAI     = "openai_chat"
	ProtocolAnthropic  = "anthropic_messages"
	DefaultTemperature = 0.3
)

// 工具调用能力探测的三态结论（对齐原版 _probe_tool_calling）。
const (
	ToolCallingYes     = "yes"
	ToolCallingNo      = "no"
	ToolCallingUnknown = "unknown"
)

// StatusError 携带 HTTP 状态码的端点错误。
//
// Error() 文案与改造前完全一致（保持既有调用方与日志格式不变），
// 额外暴露 StatusCode，让「测试连接」能像原版那样下发真实 status_code。
type StatusError struct {
	StatusCode int
	Body       string
}

// Error 实现 error 接口。
func (e *StatusError) Error() string {
	return fmt.Sprintf("模型端点返回 %d: %s", e.StatusCode, utils.Truncate(strings.TrimSpace(e.Body), 300))
}

// Message 统一消息结构（OpenAI 语义）。
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall LLM 请求的工具调用。
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction 工具调用内容。
type ToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolDef 工具定义（函数式工具调用 schema）。
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// Request 统一请求。
type Request struct {
	Model       string
	Messages    []Message
	Tools       []ToolDef
	Temperature float64
	MaxTokens   int
	ToolChoice  string // "" / auto / none
}

// Usage token 用量。
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	CachedTokens     int64 `json:"cached_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// Response 统一响应。
type Response struct {
	Content      string
	ToolCalls    []ToolCall
	Usage        Usage
	Model        string
	FinishReason string
}

// Endpoint 一个可调用的 LLM 端点。
type Endpoint struct {
	Name        string
	BaseURL     string
	APIKey      string
	Model       string
	Protocol    string
	Temperature float64
	Weight      int
}

// ResolveProtocol 依据 base_url 与显式配置推断协议。
func ResolveProtocol(protocol, baseURL string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	switch p {
	case ProtocolOpenAI, ProtocolAnthropic:
		return p
	}
	lower := strings.ToLower(baseURL)
	if strings.Contains(lower, "anthropic") || strings.Contains(lower, "/messages") {
		return ProtocolAnthropic
	}
	return ProtocolOpenAI
}

// ChatURL 拼接对话补全地址。
func ChatURL(baseURL, protocol string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if protocol == ProtocolAnthropic {
		if strings.HasSuffix(base, "/v1") {
			return base + "/messages"
		}
		return base + "/v1/messages"
	}
	if strings.HasSuffix(base, "/v1") {
		return base + "/chat/completions"
	}
	return base + "/v1/chat/completions"
}

// ModelsURL 拼接模型列表地址。
func ModelsURL(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(base, "/v1") {
		return base + "/models"
	}
	return base + "/v1/models"
}

// Client 协议无关的 LLM 客户端。
type Client struct {
	http *http.Client
}

// NewClient 创建客户端。
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 180 * time.Second}}
}

// Chat 调用一次对话补全，自动适配 OpenAI / Anthropic 协议。
func (c *Client) Chat(ctx context.Context, ep Endpoint, req Request) (*Response, error) {
	protocol := ResolveProtocol(ep.Protocol, ep.BaseURL)
	if protocol == ProtocolAnthropic {
		return c.chatAnthropic(ctx, ep, req)
	}
	return c.chatOpenAI(ctx, ep, req)
}

func (c *Client) chatOpenAI(ctx context.Context, ep Endpoint, req Request) (*Response, error) {
	body := map[string]any{
		"model":    firstNonEmpty(req.Model, ep.Model),
		"messages": req.Messages,
	}
	temp := req.Temperature
	if temp <= 0 {
		temp = ep.Temperature
	}
	if temp <= 0 {
		temp = DefaultTemperature
	}
	body["temperature"] = temp
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}
	if len(req.Tools) > 0 {
		body["tools"] = toOpenAITools(req.Tools)
		if req.ToolChoice != "" {
			body["tool_choice"] = req.ToolChoice
		}
	}

	raw, err := c.doJSON(ctx, ChatURL(ep.BaseURL, ProtocolOpenAI), openAIHeaders(ep.APIKey), body, req.MaxTokens > 0)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content   string     `json:"content"`
				ToolCalls []ToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens        int64 `json:"prompt_tokens"`
			CompletionTokens    int64 `json:"completion_tokens"`
			TotalTokens         int64 `json:"total_tokens"`
			PromptTokensDetails struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("解析模型响应失败: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("模型未返回任何候选结果")
	}
	choice := parsed.Choices[0]
	return &Response{
		Content:      choice.Message.Content,
		ToolCalls:    choice.Message.ToolCalls,
		FinishReason: choice.FinishReason,
		Model:        firstNonEmpty(parsed.Model, ep.Model),
		Usage: Usage{
			PromptTokens:     parsed.Usage.PromptTokens,
			CompletionTokens: parsed.Usage.CompletionTokens,
			CachedTokens:     parsed.Usage.PromptTokensDetails.CachedTokens,
			TotalTokens:      parsed.Usage.TotalTokens,
		},
	}, nil
}

func (c *Client) chatAnthropic(ctx context.Context, ep Endpoint, req Request) (*Response, error) {
	system, messages := splitSystem(req.Messages)

	body := map[string]any{
		"model":      firstNonEmpty(req.Model, ep.Model),
		"messages":   toAnthropicMessages(messages),
		"max_tokens": pickInt(req.MaxTokens, 4096),
	}
	if system != "" {
		body["system"] = system
	}
	temp := req.Temperature
	if temp <= 0 {
		temp = ep.Temperature
	}
	if temp > 0 {
		body["temperature"] = temp
	}
	if len(req.Tools) > 0 {
		body["tools"] = toAnthropicTools(req.Tools)
		if req.ToolChoice != "" {
			body["tool_choice"] = map[string]any{"type": mapToolChoice(req.ToolChoice)}
		}
	}

	raw, err := c.doJSON(ctx, ChatURL(ep.BaseURL, ProtocolAnthropic), anthropicHeaders(ep.APIKey), body, false)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens          int64 `json:"input_tokens"`
			OutputTokens         int64 `json:"output_tokens"`
			CacheReadInputTokens int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("解析模型响应失败: %w", err)
	}

	resp := &Response{
		Model:        firstNonEmpty(parsed.Model, ep.Model),
		FinishReason: parsed.StopReason,
		Usage: Usage{
			PromptTokens:     parsed.Usage.InputTokens,
			CompletionTokens: parsed.Usage.OutputTokens,
			CachedTokens:     parsed.Usage.CacheReadInputTokens,
		},
	}
	var texts []string
	for _, block := range parsed.Content {
		switch block.Type {
		case "text":
			texts = append(texts, block.Text)
		case "tool_use":
			args := "{}"
			if len(block.Input) > 0 {
				args = string(block.Input)
			}
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:   block.ID,
				Type: "function",
				Function: ToolFunction{
					Name:      block.Name,
					Arguments: args,
				},
			})
		}
	}
	resp.Content = strings.Join(texts, "\n")
	return resp, nil
}

// ListModels 拉取端点可用模型列表。
func (c *Client) ListModels(ctx context.Context, baseURL, apiKey, protocol string) ([]string, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("未配置 base_url")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("未配置 API Key")
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	headers := openAIHeaders(apiKey)
	if ResolveProtocol(protocol, baseURL) == ProtocolAnthropic {
		headers = anthropicHeaders(apiKey)
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ModelsURL(baseURL), nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求模型列表失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("模型商返回 %d: %s", resp.StatusCode, utils.Truncate(strings.TrimSpace(string(body)), 200))
	}

	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("解析模型列表失败: %w", err)
	}
	seen := map[string]bool{}
	models := make([]string, 0)
	for _, item := range parsed.Data {
		if item.ID == "" || seen[item.ID] {
			continue
		}
		seen[item.ID] = true
		models = append(models, item.ID)
	}
	for _, item := range parsed.Models {
		if item.ID == "" || seen[item.ID] {
			continue
		}
		seen[item.ID] = true
		models = append(models, item.ID)
	}
	return models, nil
}

// Ping 轻量连通性测试，返回延迟与模型回显。
// PingResult 端点连通性探测结果。
// 字段口径对齐原版 AutoHunter `_test_llm_one` 的返回项，供「测试连接」直接下发前端。
type PingResult struct {
	LatencyMS  int64
	Reply      string
	Model      string
	StatusCode int
}

func (c *Client) Ping(ctx context.Context, ep Endpoint) (PingResult, error) {
	start := time.Now()
	// StatusCode 初值必须是 0（对齐原版）：只有真正拿到 HTTP 响应才填状态码，
	// 连接超时/DNS 失败这类错误没有状态码，填 200 会变成误导性的「成功」。
	out := PingResult{}
	resp, err := c.Chat(ctx, ep, Request{
		Messages:  []Message{{Role: "user", Content: "Reply with exactly: ok"}},
		MaxTokens: 8,
	})
	out.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) {
			out.StatusCode = statusErr.StatusCode
		}
		return out, err
	}
	out.StatusCode = http.StatusOK
	out.Reply = strings.TrimSpace(resp.Content)
	out.Model = resp.Model
	return out, nil
}

// ProbeToolCalling 探测端点是否支持 function/tool calling，返回 yes/no/unknown。
//
// 仅由「测试连接」按钮触发，绝不进入挖洞主循环，不影响 worker/collector 的预算与行为。
// 判定从严（对齐原版）：真正拿到 tool_call 才判 yes；HTTP 错误文本里明确提到
// tool/function 才判 no；其余一律 unknown —— 不下死结论，避免把正常模型误判成不支持。
func (c *Client) ProbeToolCalling(ctx context.Context, ep Endpoint) string {
	resp, err := c.Chat(ctx, ep, Request{
		Messages: []Message{
			{Role: "system", Content: "You must use the provided tool to answer."},
			{Role: "user", Content: "Call the report_ready tool with status=ok."},
		},
		Tools: []ToolDef{{
			Name:        "report_ready",
			Description: "Report readiness. You must call this function.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status": map[string]any{"type": "string"},
				},
				"required": []string{"status"},
			},
		}},
		ToolChoice: "auto",
		MaxTokens:  64,
	})
	if err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) {
			low := strings.ToLower(statusErr.Body)
			if strings.Contains(low, "tool") || strings.Contains(low, "function") {
				return ToolCallingNo
			}
		}
		return ToolCallingUnknown
	}
	if len(resp.ToolCalls) > 0 {
		return ToolCallingYes
	}
	return ToolCallingUnknown
}

func (c *Client) doJSON(ctx context.Context, url string, headers map[string]string, body map[string]any, retryWithoutMaxTokens bool) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	do := func(data []byte) (*http.Response, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("请求模型端点失败: %w", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return resp, raw, nil
	}

	resp, raw, err := do(payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return raw, nil
	}
	// 部分端点不认 max_tokens，降级重试一次
	if retryWithoutMaxTokens && resp.StatusCode == http.StatusBadRequest && bytes.Contains(raw, []byte("max_tokens")) {
		delete(body, "max_tokens")
		if degraded, err := json.Marshal(body); err == nil {
			if resp2, raw2, err2 := do(degraded); err2 == nil && resp2.StatusCode == http.StatusOK {
				return raw2, nil
			}
		}
	}
	return nil, &StatusError{StatusCode: resp.StatusCode, Body: string(raw)}
}

func openAIHeaders(apiKey string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + apiKey,
		"User-Agent":    "AiSRC/1.0",
	}
}

func anthropicHeaders(apiKey string) map[string]string {
	return map[string]string{
		"x-api-key":         apiKey,
		"anthropic-version": "2023-06-01",
		"User-Agent":        "AiSRC/1.0",
	}
}

func splitSystem(messages []Message) (string, []Message) {
	var system []string
	rest := make([]Message, 0, len(messages))
	for _, message := range messages {
		if message.Role == "system" {
			system = append(system, message.Content)
			continue
		}
		rest = append(rest, message)
	}
	return strings.Join(system, "\n\n"), rest
}

func toAnthropicMessages(messages []Message) []map[string]any {
	result := make([]map[string]any, 0, len(messages))
	for _, message := range messages {
		switch message.Role {
		case "tool":
			result = append(result, map[string]any{
				"role": "user",
				"content": []map[string]any{{
					"type":        "tool_result",
					"tool_use_id": message.ToolCallID,
					"content":     message.Content,
				}},
			})
		case "assistant":
			blocks := make([]map[string]any, 0, len(message.ToolCalls)+1)
			if message.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": message.Content})
			}
			for _, call := range message.ToolCalls {
				var input any = map[string]any{}
				if strings.TrimSpace(call.Function.Arguments) != "" {
					_ = json.Unmarshal([]byte(call.Function.Arguments), &input)
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    call.ID,
					"name":  call.Function.Name,
					"input": input,
				})
			}
			if len(blocks) == 0 {
				blocks = append(blocks, map[string]any{"type": "text", "text": ""})
			}
			result = append(result, map[string]any{"role": "assistant", "content": blocks})
		default:
			result = append(result, map[string]any{
				"role":    "user",
				"content": []map[string]any{{"type": "text", "text": message.Content}},
			})
		}
	}
	return result
}

func toOpenAITools(tools []ToolDef) []map[string]any {
	result := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		result = append(result, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        tool.Name,
				"description": tool.Description,
				"parameters":  tool.Parameters,
			},
		})
	}
	return result
}

func toAnthropicTools(tools []ToolDef) []map[string]any {
	result := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		result = append(result, map[string]any{
			"name":         tool.Name,
			"description":  tool.Description,
			"input_schema": tool.Parameters,
		})
	}
	return result
}

func mapToolChoice(choice string) string {
	switch choice {
	case "none":
		return "none"
	case "required":
		return "any"
	default:
		return "auto"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func pickInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
