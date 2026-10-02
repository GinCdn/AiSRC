package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// maskCharset 脱敏占位字符集合，用于识别「前端回传的脱敏串」。
const maskCharset = "*•·●…○◦."

// MaskSecret 对非空密钥统一返回固定占位符；空值返回空串。
func MaskSecret(secret string) string {
	if strings.TrimSpace(secret) == "" {
		return ""
	}
	return "••••••••"
}

// IsMaskedSecret 判断传入值是否为脱敏占位（视为「未修改」，不可回写数据库）。
func IsMaskedSecret(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		if !strings.ContainsRune(maskCharset, r) {
			return false
		}
	}
	return true
}

// SecretRef 计算密钥指纹，用于前端判断「密钥是否换过」而不暴露明文。
func SecretRef(secret string) string {
	if strings.TrimSpace(secret) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])[:16]
}

// IdentityRef 计算端点身份指纹（base_url + model + key + protocol）。
func IdentityRef(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{8,}`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{8,}`),
	regexp.MustCompile(`(?i)(api[_-]?key|token|password|secret)\s*[=:]\s*[^\s,;"']+`),
}

// SanitizeSecretText 从日志文本中抹去疑似密钥片段。
func SanitizeSecretText(text string, extraSecrets ...string) string {
	result := text
	for _, secret := range extraSecrets {
		secret = strings.TrimSpace(secret)
		if len(secret) >= 6 {
			result = strings.ReplaceAll(result, secret, "••••••••")
		}
	}
	for _, pattern := range secretPatterns {
		result = pattern.ReplaceAllString(result, "••••••••")
	}
	return result
}

// Truncate 按字符（rune）截断字符串。
func Truncate(text string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}
