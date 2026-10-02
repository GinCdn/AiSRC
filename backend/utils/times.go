package utils

import (
	"time"
)

// CST 东八区（北京时间）。全项目时间统一以此为准。
var CST = time.FixedZone("CST", 8*3600)

// Now 返回当前北京时间。
func Now() time.Time {
	return time.Now().In(CST)
}

// NowUTC 返回 UTC 时间（落库用，与 AutoHunter 的 UTC naive 语义对齐）。
func NowUTC() time.Time {
	return time.Now().UTC()
}

// ToCSTISO 把数据库中的 UTC 时间输出为东八区 ISO8601 字符串。
// 前端 slice(0,19) 即可得到「2026-10-01 12:00:00」形态的本地时间值。
func ToCSTISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(CST).Format("2006-01-02T15:04:05.000-07:00")
}

// ToCSTISOShort 返回不带毫秒的东八区 ISO8601 字符串。
func ToCSTISOShort(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(CST).Format("2006-01-02T15:04:05+08:00")
}

// ToCSTNullable 空时间返回 nil，便于 JSON 序列化为 null。
func ToCSTNullable(t *time.Time) interface{} {
	if t == nil || t.IsZero() {
		return nil
	}
	return ToCSTISO(*t)
}

// ParseTime 容错解析前端传入的时间字符串。
func ParseTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000-07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
