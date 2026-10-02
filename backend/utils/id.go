package utils

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
)

// UUID 生成 32 位十六进制 ID（与 AutoHunter 的 uuid4().hex 语义一致）。
func UUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// 极端情况下退化为时间戳，保证不返回空 ID
		return hex.EncodeToString([]byte(Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(buf)
}

// ShortUUID 生成 n 个十六进制字符的短 ID。
func ShortUUID(n int) string {
	if n <= 0 || n > 32 {
		n = 12
	}
	full := UUID()
	if n > len(full) {
		n = len(full)
	}
	return full[:n]
}

// RandomToken 生成指定字节数的随机十六进制令牌。
func RandomToken(bytesLen int) string {
	if bytesLen <= 0 {
		bytesLen = 24
	}
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return UUID()
	}
	return hex.EncodeToString(buf)
}

// RandomDigits 生成 n 位数字串。
func RandomDigits(n int) string {
	if n <= 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			sb.WriteByte('0')
			continue
		}
		sb.WriteByte(byte('0' + v.Int64()))
	}
	return sb.String()
}

// Clamp 把 v 夹到 [min, max]；非法（如 0 且不允许 0）时返回 def。
func Clamp(v int, min, max, def int) int {
	if v <= 0 && def > 0 && min > 0 {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// ClampDeepenCap 深挖次数上限夹取（0..10，默认 2）。
func ClampDeepenCap(v int) int {
	if v < 0 {
		return 0
	}
	if v > 10 {
		return 10
	}
	return v
}
