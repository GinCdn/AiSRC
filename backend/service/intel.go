package service

import (
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/utils"
)

// IntelFilter 情报查询条件。
type IntelFilter struct {
	Kind       string
	Query      string
	SourceHost string
	Limit      int
	Offset     int
	OnlyTop    bool
}

// BuildIntelView 情报视图。
func BuildIntelView(item *model.Intel) map[string]any {
	if item == nil {
		return nil
	}
	return map[string]any{
		"id":             item.ID,
		"kind":           item.Kind,
		"kind_label":     intelKindLabel(item.Kind),
		"match_key":      item.MatchKey,
		"payload":        mapOrEmpty(item.Payload),
		"summary":        item.Summary,
		"source_host":    item.SourceHost,
		"source_task_id": item.SourceTaskID,
		"confidence":     item.Confidence,
		"hit_count":      item.HitCount,
		"first_seen":     utils.ToCSTISO(item.FirstSeen),
		"last_seen":      utils.ToCSTISO(item.LastSeen),
	}
}

// intelKindLabel 情报类型中文名。
func intelKindLabel(kind string) string {
	switch kind {
	case constant.IntelCred:
		return "登录凭据"
	case constant.IntelFingerprint:
		return "系统指纹"
	case constant.IntelEndpoint:
		return "敏感端点"
	case constant.IntelProfile:
		return "资产画像"
	default:
		return kind
	}
}

// QueryIntel 情报列表。
func QueryIntel(filter IntelFilter) ([]map[string]any, int64, error) {
	var items []model.Intel
	db := core.Db.Model(&model.Intel{})
	if filter.Kind != "" {
		db = db.Where("kind = ?", filter.Kind)
	}
	if filter.SourceHost != "" {
		db = db.Where("source_host = ?", filter.SourceHost)
	}
	if err := db.Order("hit_count DESC, last_seen DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		filtered := make([]model.Intel, 0, len(items))
		for _, item := range items {
			haystack := strings.ToLower(strings.Join([]string{
				item.Kind, item.MatchKey, item.Summary, item.SourceHost, item.Confidence,
			}, " "))
			if strings.Contains(haystack, query) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	total := int64(len(items))
	if filter.Limit > 0 {
		if filter.Offset >= len(items) {
			return nil, total, nil
		}
		end := filter.Offset + filter.Limit
		if end > len(items) {
			end = len(items)
		}
		items = items[filter.Offset:end]
	}
	out := make([]map[string]any, 0, len(items))
	for i := range items {
		out = append(out, BuildIntelView(&items[i]))
	}
	return out, total, nil
}

// IntelStats 情报统计。
func IntelStats() map[string]any {
	stats := map[string]any{
		"total": 0, "cred": 0, "fingerprint": 0, "endpoint": 0, "profile": 0,
		"by_kind": map[string]int{}, "last_updated": "",
	}
	var items []model.Intel
	core.Db.Find(&items)
	stats["total"] = len(items)
	byKind := map[string]int{}
	var latest time.Time
	for _, item := range items {
		byKind[item.Kind]++
		if item.LastSeen.After(latest) {
			latest = item.LastSeen
		}
	}
	stats["by_kind"] = byKind
	stats["cred"] = byKind[constant.IntelCred]
	stats["fingerprint"] = byKind[constant.IntelFingerprint]
	stats["endpoint"] = byKind[constant.IntelEndpoint]
	stats["profile"] = byKind[constant.IntelProfile]
	if !latest.IsZero() {
		stats["last_updated"] = utils.ToCSTISO(latest)
	}
	return stats
}

// CurateIntelPreview 返回情报整理预览（去重 / 合并建议）。
func CurateIntelPreview() map[string]any {
	var items []model.Intel
	core.Db.Order("kind ASC, match_key ASC").Find(&items)

	groups := map[string][]string{}
	for _, item := range items {
		key := item.Kind + "|" + item.MatchKey
		groups[key] = append(groups[key], item.ID)
	}
	duplicates := make([]map[string]any, 0)
	for key, ids := range groups {
		if len(ids) <= 1 {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		duplicates = append(duplicates, map[string]any{
			"kind":      parts[0],
			"match_key": parts[1],
			"count":     len(ids),
			"ids":       ids,
		})
	}
	return map[string]any{
		"total":      len(items),
		"duplicates": duplicates,
		"dup_groups": len(duplicates),
	}
}

// CurateIntel 执行情报整理：合并重复项、清理低信息量条目。
func CurateIntel() map[string]any {
	var items []model.Intel
	core.Db.Order("kind ASC, match_key ASC, hit_count DESC").Find(&items)

	keep := map[string]*model.Intel{}
	removed := make([]string, 0)
	merged := 0
	for i := range items {
		item := items[i]
		key := item.Kind + "|" + item.MatchKey
		existing, ok := keep[key]
		if !ok {
			copyItem := item
			keep[key] = &copyItem
			continue
		}
		existing.HitCount += item.HitCount
		if item.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = item.LastSeen
		}
		if existing.Summary == "" {
			existing.Summary = item.Summary
		}
		merged++
		removed = append(removed, item.ID)
	}
	for _, id := range removed {
		core.Db.Delete(&model.Intel{}, "id = ?", id)
	}
	for _, item := range keep {
		core.Db.Model(&model.Intel{}).Where("id = ?", item.ID).
			Updates(map[string]any{"hit_count": item.HitCount, "last_seen": item.LastSeen, "summary": item.Summary})
	}
	return map[string]any{
		"before":      len(items),
		"after":       len(keep),
		"merged":      merged,
		"removed_ids": removed,
	}
}

// DeleteIntel 删除单条情报。
func DeleteIntel(intelID string) error {
	return core.Db.Delete(&model.Intel{}, "id = ?", intelID).Error
}

// ClearIntel 清空情报库。
func ClearIntel() (int64, error) {
	res := core.Db.Where("1 = 1").Delete(&model.Intel{})
	return res.RowsAffected, res.Error
}

// ===== 运行日志 =====

// LogFilter 运行日志查询条件。
type LogFilter struct {
	TaskID string
	Agent  string
	Level  string
	Kind   string
	Query  string
	Limit  int
	Offset int
}

// QueryRuntimeLogs 查询运行日志。
func QueryRuntimeLogs(filter LogFilter) ([]map[string]any, int64, error) {
	var events []model.TaskEvent
	db := core.Db.Model(&model.TaskEvent{})
	if filter.TaskID != "" {
		db = db.Where("task_id = ?", filter.TaskID)
	}
	if filter.Agent != "" {
		db = db.Where("agent = ?", filter.Agent)
	}
	if filter.Level != "" {
		db = db.Where("level = ?", filter.Level)
	}
	if filter.Kind != "" {
		db = db.Where("kind = ?", filter.Kind)
	}
	if err := db.Order("id DESC").Find(&events).Error; err != nil {
		return nil, 0, err
	}
	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		filtered := make([]model.TaskEvent, 0, len(events))
		for _, event := range events {
			haystack := strings.ToLower(event.Message + " " + event.Kind + " " + event.Agent)
			if strings.Contains(haystack, query) {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}
	total := int64(len(events))
	if filter.Limit > 0 {
		if filter.Offset >= len(events) {
			return nil, total, nil
		}
		end := filter.Offset + filter.Limit
		if end > len(events) {
			end = len(events)
		}
		events = events[filter.Offset:end]
	}
	out := make([]map[string]any, 0, len(events))
	// task_name/task_status 派生字段：前端运行异常页「任务」列优先读 task_name、
	// 状态列读 task_status（缺失时恒显哈希 ID 与 unknown，实测踩过）。
	taskMeta := runtimeTaskMetaMap(events)
	for i := range events {
		event := events[i]
		item := map[string]any{
			"id":      event.ID,
			"task_id": event.TaskID,
			"agent":   event.Agent,
			"kind":    event.Kind,
			"level":   event.Level,
			"message": event.Message,
			"ts":      utils.ToCSTISO(event.Ts),
		}
		if meta, ok := taskMeta[event.TaskID]; ok {
			item["task_name"] = meta.name
			item["task_status"] = meta.status
		}
		for k, v := range event.Payload {
			item[k] = v
		}
		// 保留 payload 包装对象：前端运行日志页按 record.payload 渲染展开行，
		// 只平铺不给键会让「payload」列永远显示不出（实测踩过）。
		item["payload"] = event.Payload
		out = append(out, item)
	}
	return out, total, nil
}

type runtimeTaskMeta struct{ name, status string }

// runtimeTaskMetaMap 批量取事件关联任务的名称与状态（task_id 去重后一次查询）。
func runtimeTaskMetaMap(events []model.TaskEvent) map[string]runtimeTaskMeta {
	ids := make([]string, 0, len(events))
	seen := make(map[string]bool, len(events))
	for i := range events {
		if events[i].TaskID != "" && !seen[events[i].TaskID] {
			seen[events[i].TaskID] = true
			ids = append(ids, events[i].TaskID)
		}
	}
	meta := make(map[string]runtimeTaskMeta, len(ids))
	if len(ids) == 0 {
		return meta
	}
	var rows []model.Task
	if err := core.Db.Select("id, name, status").Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return meta
	}
	for _, t := range rows {
		meta[t.ID] = runtimeTaskMeta{name: t.Name, status: t.Status}
	}
	return meta
}

// RuntimeLogStats 运行日志统计。
func RuntimeLogStats(taskID string) map[string]any {
	stats := map[string]any{
		"total": 0, "info": 0, "warn": 0, "error": 0,
		"by_agent": map[string]int{}, "by_kind": map[string]int{},
	}
	var events []model.TaskEvent
	db := core.Db.Model(&model.TaskEvent{})
	if taskID != "" {
		db = db.Where("task_id = ?", taskID)
	}
	db.Find(&events)
	stats["total"] = len(events)
	byAgent := map[string]int{}
	byKind := map[string]int{}
	for _, event := range events {
		switch event.Level {
		case "warn":
			stats["warn"] = toInt(stats["warn"]) + 1
		case "error":
			stats["error"] = toInt(stats["error"]) + 1
		default:
			stats["info"] = toInt(stats["info"]) + 1
		}
		byAgent[event.Agent]++
		byKind[event.Kind]++
	}
	stats["by_agent"] = byAgent
	stats["by_kind"] = byKind

	// 运行期用量快照（LLM token / 引擎调用）。
	stats["llm"] = engine.RuntimeUsageSnapshot()
	stats["engine"] = engine.EngineUsageSnapshot()
	stats["bus_subscribers"] = engine.BusInstance().SubscribeCount(taskID)
	return stats
}
