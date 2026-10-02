package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"AiSRC/service/llm"
)

// TestChatAndRecordCountsUsage 用假的模型端点验证用量确实被累计。
//
// 这条链路此前是断的：RecordLLMUsage 定义了却无人调用，
// 界面上「LLM 用量」恒为 0。
func TestChatAndRecordCountsUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model": "fake-model",
			"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
			"usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18,
			          "prompt_tokens_details": {"cached_tokens": 3}}
		}`))
	}))
	defer server.Close()

	pool := BuildPoolFromRaw(server.URL, "sk-test", "fake-model", "openai_chat")
	if pool.Size() == 0 {
		t.Fatal("端点池为空，无法验证")
	}

	before := RuntimeUsageSnapshot()
	_, err := chatAndRecord(context.Background(), pool, llm.Request{
		Messages: []llm.Message{{Role: "user", Content: "hi"}},
	}, "")
	if err != nil {
		t.Fatalf("调用失败：%v", err)
	}
	after := RuntimeUsageSnapshot()

	if after.Requests != before.Requests+1 {
		t.Fatalf("requests 未累加：%d -> %d", before.Requests, after.Requests)
	}
	if after.PromptTokens != before.PromptTokens+11 {
		t.Fatalf("prompt_tokens 未累加：%d -> %d", before.PromptTokens, after.PromptTokens)
	}
	if after.CompletionTokens != before.CompletionTokens+7 {
		t.Fatalf("completion_tokens 未累加：%d -> %d", before.CompletionTokens, after.CompletionTokens)
	}
	if after.CachedTokens != before.CachedTokens+3 {
		t.Fatalf("cached_tokens 未累加：%d -> %d", before.CachedTokens, after.CachedTokens)
	}
}

// TestChatAndRecordCountsFailure 调用失败时也要计入 errors。
func TestChatAndRecordCountsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
	}))
	defer server.Close()

	pool := BuildPoolFromRaw(server.URL, "sk-test", "fake-model", "openai_chat")
	if pool.Size() == 0 {
		t.Fatal("端点池为空，无法验证")
	}

	before := RuntimeUsageSnapshot()
	if _, err := chatAndRecord(context.Background(), pool, llm.Request{
		Messages: []llm.Message{{Role: "user", Content: "hi"}},
	}, ""); err == nil {
		t.Fatal("预期调用失败")
	}
	after := RuntimeUsageSnapshot()

	if after.Errors != before.Errors+1 {
		t.Fatalf("errors 未累加：%d -> %d", before.Errors, after.Errors)
	}
	if after.Requests <= before.Requests {
		t.Fatalf("失败的调用也应计入 requests：%d -> %d", before.Requests, after.Requests)
	}
}
