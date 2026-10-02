package utils

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// ClientIP 获取真实客户端 IP（兼容反代）。
func ClientIP(c *gin.Context) string {
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if real := strings.TrimSpace(c.GetHeader("X-Real-IP")); real != "" {
		return real
	}
	return c.ClientIP()
}

// NormalizeHost 从 URL 或 host 提取归一化的主机名（含端口剥离与大小写统一）。
func NormalizeHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if idx := strings.IndexAny(value, "/?#"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, "@"); idx >= 0 {
		value = value[idx+1:]
	}
	if idx := strings.LastIndex(value, ":"); idx > 0 && !strings.Contains(value[idx+1:], "]") {
		port := value[idx+1:]
		if isAllDigits(port) {
			value = value[:idx]
		}
	}
	return strings.ToLower(value)
}

// RootDomain 提取根域名（用于情报 match_key）。
func RootDomain(host string) string {
	host = NormalizeHost(host)
	if host == "" {
		return ""
	}
	if isAllDigits(strings.ReplaceAll(host, ".", "")) {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// 处理 .com.cn / .edu.cn / .co.uk 等二级后缀
	twoLevel := map[string]bool{"com": true, "net": true, "org": true, "gov": true, "edu": true, "co": true}
	if len(parts) >= 3 && twoLevel[parts[len(parts)-2]] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// CleanTargetList 保序去重并规范化目标 URL 列表。
func CleanTargetList(items []string) []string {
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			value = "http://" + value
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

func isAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
