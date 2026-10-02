package engine

import (
	"fmt"
	"testing"

	"AiSRC/service/llm"
)

// buildToolHistory 构造若干轮「assistant 携带 tool_calls + 对应 tool 结果」的历史。
func buildToolHistory(rounds, callsPerRound int) []llm.Message {
	messages := []llm.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "kickoff"},
	}
	for i := 0; i < rounds; i++ {
		calls := make([]llm.ToolCall, 0, callsPerRound)
		tools := make([]llm.Message, 0, callsPerRound)
		for j := 0; j < callsPerRound; j++ {
			id := fmt.Sprintf("call-%d-%d", i, j)
			calls = append(calls, llm.ToolCall{ID: id, Type: "function"})
			tools = append(tools, llm.Message{Role: "tool", ToolCallID: id})
		}
		messages = append(messages, llm.Message{Role: "assistant", Content: "", ToolCalls: calls})
		messages = append(messages, tools...)
	}
	return messages
}

// assertNoOrphanTool 断言窗口内不存在孤立的 tool 消息。
//
// OpenAI / DeepSeek 要求 role=tool 的消息必须紧跟在携带 tool_calls 的
// assistant 消息之后，否则直接返回 400：
//
//	Messages with role 'tool' must be a response to a preceding message with 'tool_calls'
func assertNoOrphanTool(t *testing.T, label string, out []llm.Message) {
	t.Helper()
	for i, message := range out {
		if message.Role != "tool" {
			continue
		}
		j := i - 1
		for j >= 0 && out[j].Role == "tool" {
			j--
		}
		if j < 0 || len(out[j].ToolCalls) == 0 {
			t.Fatalf("%s：下标 %d 出现孤立 tool 消息（前一条非 tool 消息缺少 tool_calls）", label, i)
		}
	}
}

// TestTrimKeepingRecentNeverSplitsToolGroup 逐个 keepRecent 取值验证切点对齐。
// 这正是一次真实跑靶场时暴露的崩溃：第 10 轮推理被模型端点 400 拒绝。
func TestTrimKeepingRecentNeverSplitsToolGroup(t *testing.T) {
	messages := buildToolHistory(8, 2)
	if len(messages) < 26 {
		t.Fatalf("用例需要足够长的历史，当前 %d 条", len(messages))
	}

	for keep := 1; keep <= len(messages); keep++ {
		out, trimmed := trimKeepingRecent(messages, 2, keep)
		label := fmt.Sprintf("keepRecent=%d", keep)

		if len(out) > len(messages) {
			t.Fatalf("%s：裁剪后反而变长", label)
		}
		if !trimmed {
			continue
		}
		if out[0].Role != "system" || out[1].Role != "user" {
			t.Fatalf("%s：锚点消息未被保留：%q / %q", label, out[0].Role, out[1].Role)
		}
		if out[2].Role == "tool" {
			t.Fatalf("%s：窗口以孤立 tool 消息开头", label)
		}
		assertNoOrphanTool(t, label, out)
	}
}

// TestCompactMessagesNeverSplitsToolGroup 覆盖 escalation 使用的 1 条锚点版本。
func TestCompactMessagesNeverSplitsToolGroup(t *testing.T) {
	messages := buildToolHistory(10, 1)
	out := compactMessages(messages)

	if len(out) >= len(messages) {
		t.Fatalf("预期发生裁剪，实际 %d -> %d", len(messages), len(out))
	}
	if out[0].Role != "system" {
		t.Fatalf("system 锚点未保留，首条为 %q", out[0].Role)
	}
	assertNoOrphanTool(t, "compactMessages", out)
}

// TestTrimKeepingRecentSkipsShortHistory 历史未超阈值时应原样返回，避免无谓拷贝。
func TestTrimKeepingRecentSkipsShortHistory(t *testing.T) {
	messages := []llm.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "kickoff"},
		{Role: "assistant", Content: "hi"},
	}
	out, trimmed := trimKeepingRecent(messages, 2, 12)
	if trimmed {
		t.Fatalf("短历史不应被裁剪")
	}
	if len(out) != len(messages) {
		t.Fatalf("短历史应原样返回，实际 %d 条", len(out))
	}
}
