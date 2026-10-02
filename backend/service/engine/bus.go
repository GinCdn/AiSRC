package engine

import (
	"encoding/json"
	"sync"
	"time"

	"AiSRC/utils"
)

// Event 实时事件。落库为 TaskEvent，同时经 WebSocket 推送给前端看板。
type Event struct {
	Agent   string         `json:"agent"`
	Kind    string         `json:"kind"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Ts      string         `json:"ts"`
	Extra   map[string]any `json:"-"`
}

// MarshalJSON 把 Extra 的字段平铺到顶层，便于前端直接读取 payload；
// 同时保留 payload 包装对象（前端 toTraceRow/toActivity 读 rec.payload，
// 缺这个键会让看板事件详情的 payload 区块恒空——实测踩过）。
func (e Event) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(e.Extra)+6)
	for key, value := range e.Extra {
		out[key] = value
	}
	out["payload"] = e.Extra
	out["agent"] = e.Agent
	out["kind"] = e.Kind
	out["level"] = e.Level
	out["message"] = e.Message
	out["ts"] = e.Ts
	return json.Marshal(out)
}

// NewEvent 构造事件。
func NewEvent(agent, kind, level, message string) Event {
	return Event{
		Agent:   agent,
		Kind:    kind,
		Level:   level,
		Message: message,
		Ts:      utils.Now().Format(time.RFC3339),
		Extra:   map[string]any{},
	}
}

// With 追加一个附加字段。
func (e Event) With(key string, value any) Event {
	if e.Extra == nil {
		e.Extra = map[string]any{}
	}
	e.Extra[key] = value
	return e
}

// 事件噪音与重要级别集合（用于看板回放过滤）。
var noiseKinds = map[string]bool{
	"refill": true, "cluster_cooldown_skip": true, "skip": true, "ping": true,
}

var importantKinds = map[string]bool{
	"worker_start": true, "worker_finish": true, "worker_channels": true,
	"finding_submitted": true, "review_start": true, "review_done": true,
	"target_done": true, "target_requeued": true, "target_skip": true,
	"killsweep_start": true, "killsweep_done": true, "killsweep_invalid": true, "killsweep_retry": true,
	"escalate_start": true, "escalate_done": true, "escalate_cancelled": true,
	"collector_phase": true, "collector_done": true, "collector_empty": true,
	"task_started": true, "task_paused": true, "task_stopped": true, "task_idle": true,
	"llm_error": true, "worker_error": true, "review_error": true,
	"submit_ready": true, "user_rejected": true, "archived_restore": true,
	"deepen_queued": true, "worker_directive_queued": true, "quota_stop": true,
	"site_collect": true, "coverage_reported": true, "site_followups_spawned": true,
	"intel_reported": true, "mcp_workflow": true, "collector_analysis": true,
}

var traceKinds = map[string]bool{
	"tool_call": true, "tool_result": true, "llm_round_start": true, "worker_thought": true,
}

// EventVisible 判断事件是否应该出现在看板活动流中。
func EventVisible(kind, level string, verbose bool) bool {
	if noiseKinds[kind] {
		return false
	}
	if level == "warn" || level == "error" {
		return true
	}
	if importantKinds[kind] {
		return true
	}
	if verbose && traceKinds[kind] {
		return true
	}
	return false
}

// IsImportant 判断是否重要事件（触发前端增量刷新）。
func IsImportant(kind string) bool {
	return importantKinds[kind]
}

// IsNoise 判断是否噪音事件。
func IsNoise(kind string) bool {
	return noiseKinds[kind]
}

// subscriber 单个 WebSocket 订阅者。
type subscriber struct {
	ch     chan Event
	closed bool
}

// Bus 按任务维度的事件总线。
type Bus struct {
	mu   sync.RWMutex
	subs map[string]map[*subscriber]bool
}

var globalBus = &Bus{subs: make(map[string]map[*subscriber]bool)}

// BusInstance 返回全局事件总线。
func BusInstance() *Bus { return globalBus }

// Subscribe 订阅某个任务的事件流。
func (b *Bus) Subscribe(taskID string) *subscriber {
	sub := &subscriber{ch: make(chan Event, 1000)}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[taskID] == nil {
		b.subs[taskID] = make(map[*subscriber]bool)
	}
	b.subs[taskID][sub] = true
	return sub
}

// Unsubscribe 取消订阅。
func (b *Bus) Unsubscribe(taskID string, sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if group, ok := b.subs[taskID]; ok {
		delete(group, sub)
		if len(group) == 0 {
			delete(b.subs, taskID)
		}
	}
	b.closeSub(sub)
}

func (b *Bus) closeSub(sub *subscriber) {
	if sub.closed {
		return
	}
	sub.closed = true
	close(sub.ch)
}

// Publish 广播事件（慢消费者丢弃最旧事件，不阻塞生产者）。
func (b *Bus) Publish(taskID string, event Event) {
	b.mu.RLock()
	group := b.subs[taskID]
	subs := make([]*subscriber, 0, len(group))
	for sub := range group {
		subs = append(subs, sub)
	}
	b.mu.RUnlock()

	for _, sub := range subs {
		if sub.closed {
			continue
		}
		select {
		case sub.ch <- event:
		default:
			// 队列满：丢弃最旧一条再入队最新，避免慢消费者静默失联
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- event:
			default:
			}
		}
	}
}

// Events 返回订阅通道。
func (s *subscriber) Events() <-chan Event { return s.ch }

// SubscribeCount 返回某任务的订阅者数量。
func (b *Bus) SubscribeCount(taskID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[taskID])
}
