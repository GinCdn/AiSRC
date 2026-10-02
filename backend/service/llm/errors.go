package llm

import (
	"context"
	"errors"
	"net"
	"strings"
)

// IsTransientError 判断是否为「等待后可能自愈」的瞬时错误：
// 池全冷却、限流(429)、网关/上游 5xx、网络超时/连接抖动。
// 账号级错误（401/403/400/404）与请求级取消不算瞬时，调用方应立即失败。
//
// 背景：Pool.Chat 在端点尚未进冷却时返回的是真实错误（StatusError/网络错误），
// 只有「Pick 不到任何可用端点」才返回 ErrPoolCoolingDown 哨兵。
// 若重试包装只认哨兵，单端点 + 中转站抖动的场景仍会把目标打死
//（pikachu 00:51~00:53 实测：llm_wait 已生效，6 个目标仍死于首轮 504）。
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrPoolCoolingDown) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == 429 || statusErr.StatusCode >= 500
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"connection refused", "connection reset", "connection aborted",
		"no such host", "i/o timeout", "server misbehaving", "unexpected eof",
		"rate limit", "too many requests", "429",
		" 500", " 502", " 503", " 504",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}
