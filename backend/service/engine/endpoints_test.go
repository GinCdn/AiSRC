package engine

import (
	"testing"

	"AiSRC/model"
	"AiSRC/utils"
)

// testMaskedKey 与 MaskSecret 占位一致。
const testMaskedKey = "••••••••"

// TestResolveProviderKey 验证任务端点密钥的回落解析：
// 明文直用；空/脱敏按 key_ref 或 IdentityRef 命中系统池；兜底系统单端点 key。
func TestResolveProviderKey(t *testing.T) {
	settings := &model.SystemSettings{
		LLM: model.LLMSettings{
			BaseURL: "https://single.example.com",
			APIKey:  "sk-single",
			Providers: []model.LLMProvider{
				{Name: "llm-1", BaseURL: "https://pool.example.com", APIKey: "sk-pool-1"},
				{Name: "llm-2", BaseURL: "https://pool2.example.com", APIKey: "sk-pool-2"},
			},
		},
	}

	cases := []struct {
		name string
		in   model.LLMProvider
		want string
	}{
		{
			name: "明文 key 直接使用",
			in:   model.LLMProvider{Name: "t", BaseURL: "https://x.example.com", APIKey: "sk-plain"},
			want: "sk-plain",
		},
		{
			name: "空 key 按 IdentityRef 命中系统池",
			in:   model.LLMProvider{Name: "llm-1", BaseURL: "https://pool.example.com", APIKey: ""},
			want: "sk-pool-1",
		},
		{
			name: "脱敏 key 按显式 key_ref 命中系统池",
			in: model.LLMProvider{
				Name:    "task-endpoint",
				BaseURL: "https://pool2.example.com",
				APIKey:  testMaskedKey,
				KeyRef:  utils.IdentityRef("https://pool2.example.com", "llm-2"),
			},
			want: "sk-pool-2",
		},
		{
			name: "无命中回落系统单端点 key",
			in:   model.LLMProvider{Name: "other", BaseURL: "https://unknown.example.com", APIKey: ""},
			want: "sk-single",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveProviderKey(tc.in, settings)
			if got != tc.want {
				t.Fatalf("resolveProviderKey(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEndpointsFromProvidersFillsMaskedKey 验证任务端点池组装时空/脱敏 key
// 被替换为系统配置里的明文（任务路径与探针路径解析一致）。
func TestEndpointsFromProvidersFillsMaskedKey(t *testing.T) {
	settings := &model.SystemSettings{
		LLM: model.LLMSettings{
			BaseURL: "https://single.example.com",
			APIKey:  "sk-single",
			Providers: []model.LLMProvider{
				{Name: "llm-1", BaseURL: "https://pool.example.com", APIKey: "sk-pool-1"},
			},
		},
	}
	providers := []model.LLMProvider{
		{Name: "llm-1", BaseURL: "https://pool.example.com", APIKey: testMaskedKey, Model: "m1", Enabled: true},
		{Name: "fresh", BaseURL: "https://fresh.example.com", APIKey: "", KeyRef: utils.IdentityRef("https://pool.example.com", "llm-1"), Model: "m2", Enabled: true},
	}
	endpoints := endpointsFromProviders(providers, settings)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
	if endpoints[0].APIKey != "sk-pool-1" {
		t.Fatalf("endpoint[0] key = %q, want sk-pool-1", endpoints[0].APIKey)
	}
	if endpoints[1].APIKey != "sk-pool-1" {
		t.Fatalf("endpoint[1] key (via key_ref) = %q, want sk-pool-1", endpoints[1].APIKey)
	}
}
