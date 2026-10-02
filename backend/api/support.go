package api

import (
	"encoding/json"

	"AiSRC/middleware"
	"AiSRC/result"
	"AiSRC/service"
	"AiSRC/utils"

	"github.com/gin-gonic/gin"
)

// requireWrite 校验写权限：非只读方法要求 full 角色，否则直接中止请求。
// 返回 true 表示已中止（调用方应 return）。
//
// 注意：响应由 middleware 内部统一写出（{"detail": ...}），这里不再重复写，
// 否则会出现两份 JSON 拼接到同一个响应体里的问题。
func requireWrite(c *gin.Context) bool {
	return !middleware.RequireFull(c)
}

// requireFull 显式要求全权限角色（用于启停 / 删除等敏感操作）。
func requireFull(c *gin.Context) bool {
	return requireWrite(c)
}

// forbidObserver 观摩角色禁止访问敏感信息。返回 true 表示已拦截。
func forbidObserver(c *gin.Context) bool {
	return !middleware.ForbidObserver(c)
}

// currentRole 返回当前请求角色。
func currentRole(c *gin.Context) string {
	return middleware.CurrentRole(c)
}

// isObserver 是否观摩角色。
func isObserver(c *gin.Context) bool {
	return middleware.IsObserver(c)
}

// respondList 按 AutoHunter 的「双形态列表协议」输出：
// limit<=0 → 裸数组全量；limit>0 → {items,has_more,total,limit,offset}。
func respondList(c *gin.Context, items any, total int64, limit, offset int) {
	if limit > 0 {
		hasMore := int64(offset+limit) < total
		result.Success(c, gin.H{
			"items":    items,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
			"has_more": hasMore,
		})
		return
	}
	result.Success(c, items)
}

// ensureSlice 保证空集合序列化为 []，避免前端拿到 null。
func ensureSlice[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

// maskIfObserver 观摩角色下对文本做密钥脱敏。
func maskIfObserver(c *gin.Context, text string) string {
	if !isObserver(c) {
		return text
	}
	return utils.SanitizeSecretText(text)
}

// settingsUpdateFromPayload 把原始 JSON 载荷转换为设置更新结构。
// 借助 JSON 往返复用 service.SettingsUpdate 上的指针字段语义（缺省字段=不修改）。
// 另需额外识别 llm.providers 是否显式出现，用于区分「清空提供方」与「未提交该字段」。
func settingsUpdateFromPayload(payload map[string]any) *service.SettingsUpdate {
	update := &service.SettingsUpdate{}
	if len(payload) == 0 {
		return update
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return update
	}
	_ = json.Unmarshal(raw, update)
	if llmRaw, ok := payload["llm"].(map[string]any); ok && update.LLM != nil {
		if _, exists := llmRaw["providers"]; exists {
			update.LLM.ProvidersSet = true
		}
	}
	return update
}
