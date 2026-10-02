package engine

import (
	"context"
	"sync"
	"time"

	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/llm"
)

// 运行期用量统计（进程内累计 + 落库快照）。
var (
	usageMu          sync.Mutex
	llmUsageTotal    model.LLMRuntime
	engineUsageTotal model.EngineRuntime
)

// LLMCooldownWaitBudget worker 对「端点全部冷却」的最长等待时间。
// 冷却档位 60s~600s；中转站抖动（504/502/429）通常几十秒即恢复，
// 等待重试远好于把目标直接打死（pikachu 52 目标全灭实测教训）。
const LLMCooldownWaitBudget = 5 * time.Minute

// chatAndRecord 统一发起 LLM 调用并累计用量。
//
// llm 包不能反向依赖 engine（会形成导入环），所以统计挂在这一层。
// 早先的实现里 RecordLLMUsage 从未被调用，导致「LLM 用量」在界面上恒为 0。
func chatAndRecord(ctx context.Context, pool *llm.Pool, req llm.Request, preferRef string) (*llm.ChatResult, error) {
	result, err := pool.Chat(ctx, req, preferRef)
	if result != nil && result.Response != nil {
		usage := result.Response.Usage
		RecordLLMUsage(usage.PromptTokens, usage.CompletionTokens, usage.CachedTokens, err != nil)
	} else {
		RecordLLMUsage(0, 0, 0, err != nil)
	}
	return result, err
}

// chatAndRecordWait 带瞬时错误等待的 LLM 调用：端点全部冷却（哨兵）或
// 限流/网关超时/网络抖动（真实 429/5xx/超时错误）时，按 5s→30s 退避重试，
// 直到 LLMCooldownWaitBudget 耗尽或 ctx 取消，而不是立刻报错把目标打死
//（冷却通常 60~120s，中转站抖动几十秒即恢复，等待后重试即可继续）。
// 仅 worker 主循环使用；collector tick 等同步路径仍用 chatAndRecord，
// 避免长等待阻塞主循环。
//
// 注意：全冷却时 pool.Chat 内部 Pick 直接返回哨兵，不会触发真实请求与
// Health().Mark，因此等待期的轮询不会把冷却越滚越长；只有半开探测真失败
// 才会记一次失败。
func chatAndRecordWait(taskID string, ctx context.Context, pool *llm.Pool, req llm.Request, preferRef string) (*llm.ChatResult, error) {
	deadline := time.Now().Add(LLMCooldownWaitBudget)
	backoff := 5 * time.Second
	notified := false
	for {
		result, err := chatAndRecord(ctx, pool, req, preferRef)
		if err == nil || ctx.Err() != nil {
			return result, err
		}
		if !llm.IsTransientError(err) {
			return result, err
		}
		if time.Now().Add(backoff).After(deadline) {
			return result, err
		}
		if !notified {
			notified = true
			EmitWarn(taskID, "worker", "llm_wait",
				"模型端点暂不可用（限流/网关超时/冷却中），等待恢复后自动重试（最多等 5 分钟）",
				nil)
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

// RecordLLMUsage 累计一次 LLM 调用用量。
func RecordLLMUsage(promptTokens, completionTokens, cachedTokens int64, failed bool) {
	usageMu.Lock()
	defer usageMu.Unlock()
	llmUsageTotal.PromptTokens += promptTokens
	llmUsageTotal.CompletionTokens += completionTokens
	llmUsageTotal.CachedTokens += cachedTokens
	llmUsageTotal.Requests++
	if failed {
		llmUsageTotal.Errors++
	}
}

// RecordEngineUsage 累计一次测绘引擎调用。
func RecordEngineUsage(pages int, quota int) {
	usageMu.Lock()
	defer usageMu.Unlock()
	engineUsageTotal.Calls++
	engineUsageTotal.Pages += int64(pages)
	if quota > 0 {
		engineUsageTotal.Quota = int64(quota)
	}
}

// RuntimeUsageSnapshot 返回 LLM 用量快照。
func RuntimeUsageSnapshot() model.LLMRuntime {
	usageMu.Lock()
	defer usageMu.Unlock()
	return llmUsageTotal
}

// EngineUsageSnapshot 返回测绘用量快照。
func EngineUsageSnapshot() model.EngineRuntime {
	usageMu.Lock()
	defer usageMu.Unlock()
	return engineUsageTotal
}

// PersistUsage 把进程累计用量写入任务运行统计。
func PersistUsage(taskID string) {
	if core.Db == nil || taskID == "" {
		return
	}
	usageMu.Lock()
	llm := llmUsageTotal
	engineUsage := engineUsageTotal
	usageMu.Unlock()

	var task model.Task
	if err := core.Db.First(&task, "id = ?", taskID).Error; err != nil {
		return
	}
	task.RuntimeStats.LLM = llm
	task.RuntimeStats.Engine = engineUsage

	// 必须走 Updates(&task) 让 gorm 应用 runtime_stats 上的 serializer:json。
	// 直接 Update("runtime_stats", stats) 会把 struct 原样交给驱动，报
	//   sql: converting argument $1 type: unsupported type model.RuntimeStats, a struct
	// 并且这个错误此前被忽略，导致用量「看着像 0」。
	err := core.Db.Model(&model.Task{}).Where("id = ?", taskID).
		Select("runtime_stats").Updates(&task).Error
	if err != nil {
		global.Log.Warnf("[usage] 用量落库失败：%v", err)
		return
	}
	global.Log.Infof("[usage] 任务 %s 用量落库：requests=%d prompt=%d completion=%d cached=%d errors=%d",
		taskID, llm.Requests, llm.PromptTokens, llm.CompletionTokens, llm.CachedTokens, llm.Errors)
}
