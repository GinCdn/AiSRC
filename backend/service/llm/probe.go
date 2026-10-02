package llm

import (
	"sync"
	"time"
)

// ProbeSnapshot 手动「测试端点」的探测记录快照。
//
// 与 HealthRegistry 完全隔离：生产熔断器（Health().Mark / Available）只认
// 真实调用路径，手动探测绝不写入生产健康状态——这是原版明确注释过的契约
// （手动探测若污染熔断器，会干扰运行中 worker 的冷却判断，成功时还会误清
// 真实 cooldown）。探测记录只在 ProviderHealth 展示层合并下发。
type ProbeSnapshot struct {
	Ref       string `json:"ref"`
	BaseURL   string `json:"base_url"`
	Model     string `json:"model"`
	Protocol  string `json:"protocol"`
	Status    string `json:"status"` // "ok" / "fail"
	Error     string `json:"error"`
	LatencyMS int64  `json:"latency_ms"`
	ProbedAt  string `json:"probed_at"`
}

type probeState struct {
	ref       string
	baseURL   string
	model     string
	protocol  string
	status    string
	errText   string
	latencyMS int64
	probedAt  time.Time
}

// ProbeRegistry 手动测试探测注册表（进程内单例，与生产健康注册表分离）。
type ProbeRegistry struct {
	mu     sync.RWMutex
	states map[string]*probeState
}

var probeRegistry = &ProbeRegistry{states: make(map[string]*probeState)}

// Probes 返回全局探测注册表。
func Probes() *ProbeRegistry { return probeRegistry }

// Record 记录一次手动测试结果（后测覆盖前测）。
func (p *ProbeRegistry) Record(baseURL, model, protocol, errText string, latencyMS int64) {
	if baseURL == "" && model == "" {
		return
	}
	key := healthKey(baseURL, model, protocol)
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.states[key]
	if !ok {
		st = &probeState{
			ref:      healthRef(baseURL, model, protocol, ""),
			baseURL:  baseURL,
			model:    model,
			protocol: ResolveProtocol(protocol, baseURL),
		}
		p.states[key] = st
	}
	st.status = "ok"
	st.errText = ""
	st.latencyMS = latencyMS
	st.probedAt = time.Now()
	if errText != "" {
		st.status = "fail"
		st.errText = errText
	}
}

// All 返回全部探测记录。
func (p *ProbeRegistry) All() []ProbeSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]ProbeSnapshot, 0, len(p.states))
	for _, st := range p.states {
		probedAt := ""
		if !st.probedAt.IsZero() {
			probedAt = st.probedAt.Format(time.RFC3339)
		}
		result = append(result, ProbeSnapshot{
			Ref:       st.ref,
			BaseURL:   st.baseURL,
			Model:     st.model,
			Protocol:  st.protocol,
			Status:    st.status,
			Error:     st.errText,
			LatencyMS: st.latencyMS,
			ProbedAt:  probedAt,
		})
	}
	return result
}
