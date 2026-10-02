package engine

import (
	"time"

	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/utils"
)

// Emit 落库一条任务事件并广播给订阅者。
// 所有 Agent 的日志都走这里，保证「落库 + 实时推送」永不脱节。
func Emit(taskID, agent, kind, level, message string, extra map[string]any) {
	if taskID == "" {
		return
	}
	// 「记录噪音事件」关闭（默认）时，调度类噪声（refill/skip 等）不落库不广播。
	// 这些事件只有进度展示价值，无任何下游消费（已核对 orchestrator/intel 均不查它们）。
	if !VerboseEvents() && IsNoise(kind) {
		return
	}
	event := NewEvent(agent, kind, level, message)
	for key, value := range extra {
		event = event.With(key, value)
	}

	record := model.TaskEvent{
		TaskID:  taskID,
		Agent:   agent,
		Level:   level,
		Kind:    kind,
		Message: utils.Truncate(message, 4000),
		Payload: extra,
		Ts:      time.Now().UTC(),
	}
	if core.Db != nil {
		if err := core.Db.Create(&record).Error; err != nil {
			global.Log.Warnf("写入任务事件失败 task=%s kind=%s: %v", taskID, kind, err)
		}
	}
	BusInstance().Publish(taskID, event)
}

// EmitInfo 记录 info 级事件。
func EmitInfo(taskID, agent, kind, message string, extra map[string]any) {
	Emit(taskID, agent, kind, "info", message, extra)
}

// EmitWarn 记录 warn 级事件。
func EmitWarn(taskID, agent, kind, message string, extra map[string]any) {
	Emit(taskID, agent, kind, "warn", message, extra)
}

// EmitError 记录 error 级事件。
func EmitError(taskID, agent, kind, message string, extra map[string]any) {
	Emit(taskID, agent, kind, "error", message, extra)
}
