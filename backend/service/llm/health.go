package llm

import (
	"sync"
	"time"
)

// 端点健康状态。
const (
	HealthOK       = "ok"
	HealthCooldown = "cooldown"
	HealthHalfOpen = "half_open"
	HealthFailed   = "failed"
	// HealthUntested 运行时从未调用过该端点（可能只有手动测试探测记录）。
	HealthUntested = "untested"
)

// HealthSnapshot 端点健康快照（下发给前端展示）。
type HealthSnapshot struct {
	Ref                 string `json:"ref"`
	BaseURL             string `json:"base_url"`
	Model               string `json:"model"`
	Protocol            string `json:"protocol"`
	Status              string `json:"status"`
	TransportStatus     string `json:"transport_status"`
	BehaviorStatus      string `json:"behavior_status"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	CooldownSeconds     int    `json:"cooldown_seconds"`
	CooldownUntilTS     int64  `json:"cooldown_until_ts"`
	LastError           string `json:"last_error"`
	ErrorKind           string `json:"error_kind"`
	LastSeen            string `json:"last_seen"`
	SuccessCount        int64  `json:"success_count"`
	FailureCount        int64  `json:"failure_count"`
}

type healthState struct {
	ref                 string
	baseURL             string
	model               string
	protocol            string
	status              string
	transportStatus     string
	behaviorStatus      string
	consecutiveFailures int
	cooldownUntil       time.Time
	cooldownSeconds     int
	lastError           string
	errorKind           string
	lastSeen            time.Time
	successCount        int64
	failureCount        int64
	// runtimeMarked 运行时是否真实调用过（区分「健康」与「只是没报过错」）。
	runtimeMarked bool
}

// HealthRegistry 端点健康注册表（进程内单例）。
type HealthRegistry struct {
	mu     sync.RWMutex
	states map[string]*healthState
}

var healthRegistry = &HealthRegistry{states: make(map[string]*healthState)}

// Health 返回全局健康注册表。
func Health() *HealthRegistry { return healthRegistry }

// Key 计算端点健康键：base_url + model + protocol（不含明文密钥）。
func healthKey(baseURL, model, protocol string) string {
	return baseURL + "|" + model + "|" + ResolveProtocol(protocol, baseURL)
}

// Ref 返回端点健康指纹。
func endpoinRef(baseURL, model, protocol, apiKey string) string {
	return healthRef(baseURL, model, protocol, apiKey)
}

func (h *HealthRegistry) state(baseURL, model, protocol, apiKey string) *healthState {
	key := healthKey(baseURL, model, protocol)
	h.mu.RLock()
	st, ok := h.states[key]
	h.mu.RUnlock()
	if ok {
		return st
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if st, ok := h.states[key]; ok {
		return st
	}
	st = &healthState{
		ref:             endpoinRef(baseURL, model, protocol, apiKey),
		baseURL:         baseURL,
		model:           model,
		protocol:        ResolveProtocol(protocol, baseURL),
		status:          HealthOK,
		transportStatus: HealthOK,
		behaviorStatus:  HealthOK,
	}
	h.states[key] = st
	return st
}

// Snapshot 返回单个端点健康快照。
func (h *HealthRegistry) Snapshot(baseURL, model, protocol, apiKey string) HealthSnapshot {
	st := h.state(baseURL, model, protocol, apiKey)
	h.mu.RLock()
	defer h.mu.RUnlock()
	return snapshotOf(st)
}

// Mark 记录一次调用结果。失败达到阈值即进入冷却。
func (h *HealthRegistry) Mark(baseURL, model, protocol, apiKey string, err error) {
	st := h.state(baseURL, model, protocol, apiKey)
	h.mu.Lock()
	defer h.mu.Unlock()

	st.lastSeen = time.Now()
	st.runtimeMarked = true
	if err == nil {
		st.successCount++
		st.consecutiveFailures = 0
		st.status = HealthOK
		st.transportStatus = HealthOK
		st.behaviorStatus = HealthOK
		st.cooldownUntil = time.Time{}
		st.cooldownSeconds = 0
		st.lastError = ""
		st.errorKind = ""
		return
	}

	st.failureCount++
	st.consecutiveFailures++
	st.lastError = err.Error()
	st.errorKind = classifyError(err)

	threshold := 3
	if st.consecutiveFailures >= threshold {
		cooldown := cooldownFor(st.consecutiveFailures)
		st.status = HealthCooldown
		st.transportStatus = HealthCooldown
		st.cooldownSeconds = cooldown
		st.cooldownUntil = time.Now().Add(time.Duration(cooldown) * time.Second)
	} else {
		st.status = HealthHalfOpen
	}
}

// Available 判断端点当前是否可参与调度。
func (h *HealthRegistry) Available(baseURL, model, protocol, apiKey string) bool {
	st := h.state(baseURL, model, protocol, apiKey)
	h.mu.Lock()
	defer h.mu.Unlock()
	if st.status == HealthCooldown || st.status == HealthFailed {
		if time.Now().Before(st.cooldownUntil) {
			return false
		}
		// 冷却结束进入半开，允许探测
		st.status = HealthHalfOpen
		st.cooldownSeconds = 0
	}
	return true
}

// Reset 手动清除冷却（用于「测试连接」成功后立即恢复）。
func (h *HealthRegistry) Reset(baseURL, model, protocol, apiKey string) {
	st := h.state(baseURL, model, protocol, apiKey)
	h.mu.Lock()
	defer h.mu.Unlock()
	st.status = HealthOK
	st.transportStatus = HealthOK
	st.consecutiveFailures = 0
	st.cooldownUntil = time.Time{}
	st.cooldownSeconds = 0
	st.lastError = ""
}

// All 返回全部端点健康快照。
func (h *HealthRegistry) All() []HealthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]HealthSnapshot, 0, len(h.states))
	for _, st := range h.states {
		result = append(result, snapshotOf(st))
	}
	return result
}

func snapshotOf(st *healthState) HealthSnapshot {
	status := st.status
	if !st.runtimeMarked {
		// 运行时从未调用过：不能谎报「健康」，报「未检测」，
		// 手动测试结果由 probe_status 单独表达。
		status = HealthUntested
	}
	if status == HealthCooldown && !time.Now().Before(st.cooldownUntil) {
		status = HealthHalfOpen
	}
	remaining := 0
	if status == HealthCooldown && time.Now().Before(st.cooldownUntil) {
		remaining = int(time.Until(st.cooldownUntil).Seconds()) + 1
	}
	lastSeen := ""
	if !st.lastSeen.IsZero() {
		lastSeen = st.lastSeen.Format(time.RFC3339)
	}
	until := int64(0)
	if !st.cooldownUntil.IsZero() {
		until = st.cooldownUntil.Unix()
	}
	return HealthSnapshot{
		Ref:                 st.ref,
		BaseURL:             st.baseURL,
		Model:               st.model,
		Protocol:            st.protocol,
		Status:              status,
		TransportStatus:     st.transportStatus,
		BehaviorStatus:      st.behaviorStatus,
		ConsecutiveFailures: st.consecutiveFailures,
		CooldownSeconds:     remaining,
		CooldownUntilTS:     until,
		LastError:           st.lastError,
		ErrorKind:           st.errorKind,
		LastSeen:            lastSeen,
		SuccessCount:        st.successCount,
		FailureCount:        st.failureCount,
	}
}

func cooldownFor(failures int) int {
	switch {
	case failures >= 8:
		return 600
	case failures >= 6:
		return 300
	case failures >= 4:
		return 120
	default:
		return 60
	}
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "401", "403", "unauthorized", "invalid api key", "令牌"):
		return "auth"
	case containsAny(msg, "429", "rate limit", "too many requests", "限流"):
		return "rate_limit"
	case containsAny(msg, "timeout", "超时", "deadline"):
		return "timeout"
	case containsAny(msg, "connection", "连接", "refused", "no such host"):
		return "network"
	case containsAny(msg, "500", "502", "503", "504"):
		return "upstream"
	default:
		return "unknown"
	}
}

func containsAny(text string, needles ...string) bool {
	lower := ""
	for _, r := range text {
		if r >= 'A' && r <= 'Z' {
			lower += string(r + 32)
		} else {
			lower += string(r)
		}
	}
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if indexOf(lower, needle) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(haystack, needle string) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
