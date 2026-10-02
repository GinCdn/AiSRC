package llm

import (
	"regexp"
	"strconv"
	"strings"

	"AiSRC/utils"
)

// secretLikeRE 匹配错误文本里可能混入的密钥形态（对齐原版 _TEST_SECRET_RE）。
var secretLikeRE = regexp.MustCompile(`(?i)(?:\bsk-[A-Za-z0-9_-]{8,}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,})`)

// SafeErrorText 把错误文本压成单行、抹掉可能混入的密钥，再按 limit 截断。
// limit <= 0 表示不截断。
//
// 端点的错误响应体常常把 Authorization 头回显出来，直接下发前端会泄露密钥。
func SafeErrorText(value, secret string, limit int) string {
	text := strings.Join(strings.Fields(value), " ")
	if secret = strings.TrimSpace(secret); secret != "" {
		text = strings.ReplaceAll(text, secret, "<masked>")
	}
	text = secretLikeRE.ReplaceAllString(text, "<masked>")
	if limit > 0 {
		return utils.Truncate(text, limit)
	}
	return text
}

// TestErrorCopy 生成「复制」按钮使用的多行诊断文本。
//
// 行序与字段口径对齐原版 _llm_test_error_copy，便于两边输出直接比对；
// 布尔值刻意保持 Python 风格的 True/False。
func TestErrorCopy(item map[string]any) string {
	lines := []string{
		"ok=" + boolText(item["ok"]),
		"name=" + dashIfBlank(stringField(item, "name")),
		"model=" + dashIfBlank(stringField(item, "model")),
		"base_url=" + dashIfBlank(stringField(item, "base_url")),
		"protocol=" + dashIfBlank(stringField(item, "protocol")),
		"status_code=" + intText(item["status_code"]),
		"latency_ms=" + intText(item["latency_ms"]),
		"tool_calling=" + dashIfBlank(stringField(item, "tool_calling")),
	}
	if errText := stringField(item, "error"); errText != "" {
		lines = append(lines, "error="+errText)
	}
	if reply := stringField(item, "reply"); reply != "" {
		lines = append(lines, "reply="+reply)
	}
	return strings.Join(lines, "\n")
}

// stringField 取字符串字段并去除首尾空白。
func stringField(item map[string]any, key string) string {
	value, _ := item[key].(string)
	return strings.TrimSpace(value)
}

// boolText 按原版风格输出布尔字面量。
func boolText(value any) string {
	if flag, ok := value.(bool); ok && flag {
		return "True"
	}
	return "False"
}

// intText 把数值字段渲染为十进制整数，无法识别时回退 0（对齐原版 `or 0`）。
func intText(value any) string {
	switch typed := value.(type) {
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	}
	return "0"
}

// dashIfBlank 空值统一渲染为短横线（对齐原版 `or '-'`）。
func dashIfBlank(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
