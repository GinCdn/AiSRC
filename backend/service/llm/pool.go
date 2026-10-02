package llm

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"AiSRC/utils"
)

// ErrPoolCoolingDown 池内端点全部处于熔断冷却，暂时无法调度。
// 调用方可用 errors.Is 识别：长驻 worker 应等待冷却恢复后重试，
// 同步短路径（看板查询等）可直接失败。
var ErrPoolCoolingDown = errors.New("端点池中没有可用端点（全部处于冷却状态）")

// healthRef 端点身份指纹（不含明文密钥，仅用密钥指纹参与）。
func healthRef(baseURL, model, protocol, apiKey string) string {
	return utils.IdentityRef(baseURL, model, ResolveProtocol(protocol, baseURL), utils.SecretRef(apiKey))
}

// Pool 端点池：平滑加权轮询 + 任务粘性 + 故障转移 + 健康冷却。
type Pool struct {
	mu        sync.Mutex
	endpoints []Endpoint
	weights   map[string]int // 平滑轮询当前权重
	client    *Client
}

// NewPool 创建端点池（自动过滤未启用 / 配置不完整的端点）。
func NewPool(endpoints []Endpoint) *Pool {
	valid := make([]Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if strings.TrimSpace(ep.BaseURL) == "" || strings.TrimSpace(ep.Model) == "" || strings.TrimSpace(ep.APIKey) == "" {
			continue
		}
		if ep.Weight <= 0 {
			ep.Weight = 1
		}
		if ep.Protocol == "" {
			ep.Protocol = ProtocolAuto
		}
		valid = append(valid, ep)
	}
	return &Pool{endpoints: valid, weights: make(map[string]int), client: NewClient()}
}

// Size 返回池内端点数。
func (p *Pool) Size() int { return len(p.endpoints) }

// Endpoints 返回池内全部端点。
func (p *Pool) Endpoints() []Endpoint {
	result := make([]Endpoint, len(p.endpoints))
	copy(result, p.endpoints)
	return result
}

// Pick 依平滑加权轮询选出一个可用端点；preferRef 非空时优先命中该端点（任务粘性）。
func (p *Pool) Pick(preferRef string) *Endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.endpoints) == 0 {
		return nil
	}

	if preferRef != "" {
		for i := range p.endpoints {
			ep := p.endpoints[i]
			if healthRef(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey) == preferRef &&
				Health().Available(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey) {
				return &ep
			}
		}
	}

	available := make([]int, 0, len(p.endpoints))
	total := 0
	for i, ep := range p.endpoints {
		if !Health().Available(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey) {
			continue
		}
		available = append(available, i)
		total += ep.Weight
	}
	if len(available) == 0 {
		return nil
	}

	// 平滑加权轮询
	best := available[0]
	bestWeight := 0
	for _, idx := range available {
		ep := p.endpoints[idx]
		key := healthRef(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey)
		p.weights[key] += ep.Weight
		if p.weights[key] > bestWeight {
			bestWeight = p.weights[key]
			best = idx
		}
	}
	chosen := p.endpoints[best]
	key := healthRef(chosen.BaseURL, chosen.Model, chosen.Protocol, chosen.APIKey)
	p.weights[key] -= total
	if p.weights[key] < 0 {
		p.weights[key] = 0
	}
	return &chosen
}

// ChatResult 一次成功调用的结果（含实际命中的端点信息）。
type ChatResult struct {
	Response    *Response
	Endpoint    Endpoint
	HealthRef   string
	TriedCount  int
	LastFailure string
}

// Chat 在池内做故障转移调用：最多尝试 min(3, 端点数) 个端点。
func (p *Pool) Chat(ctx context.Context, req Request, preferRef string) (*ChatResult, error) {
	if len(p.endpoints) == 0 {
		return nil, fmt.Errorf("端点池为空，请先在设置中配置模型端点")
	}

	maxTries := 3
	if len(p.endpoints) < maxTries {
		maxTries = len(p.endpoints)
	}

	tried := map[string]bool{}
	var lastErr error
	triedCount := 0

	for attempt := 0; attempt < maxTries; attempt++ {
		var ep *Endpoint
		if attempt == 0 {
			ep = p.Pick(preferRef)
		} else {
			ep = p.pickExcluding(tried)
		}
		if ep == nil {
			break
		}
		key := healthRef(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey)
		tried[key] = true
		triedCount++

		response, err := p.client.Chat(ctx, *ep, req)
		Health().Mark(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey, err)
		if err == nil {
			return &ChatResult{
				Response:  response,
				Endpoint:  *ep,
				HealthRef: key,
			}, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = ErrPoolCoolingDown
	}
	return &ChatResult{TriedCount: triedCount, LastFailure: lastErr.Error()}, lastErr
}

// pickExcluding 选一个尚未尝试过的可用端点。
func (p *Pool) pickExcluding(excluded map[string]bool) *Endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()

	available := make([]int, 0, len(p.endpoints))
	total := 0
	for i, ep := range p.endpoints {
		key := healthRef(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey)
		if excluded[key] || !Health().Available(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey) {
			continue
		}
		available = append(available, i)
		total += ep.Weight
	}
	if len(available) == 0 {
		return nil
	}
	best := available[0]
	bestWeight := 0
	for _, idx := range available {
		ep := p.endpoints[idx]
		key := healthRef(ep.BaseURL, ep.Model, ep.Protocol, ep.APIKey)
		p.weights[key] += ep.Weight
		if p.weights[key] > bestWeight {
			bestWeight = p.weights[key]
			best = idx
		}
	}
	chosen := p.endpoints[best]
	key := healthRef(chosen.BaseURL, chosen.Model, chosen.Protocol, chosen.APIKey)
	p.weights[key] -= total
	return &chosen
}

// ListModels 用池中第一个配置完整的端点拉取模型列表。
func (p *Pool) ListModels(ctx context.Context, preferBaseURL, preferAPIKey, protocol string) ([]string, error) {
	baseURL := strings.TrimSpace(preferBaseURL)
	apiKey := strings.TrimSpace(preferAPIKey)
	if baseURL == "" || apiKey == "" {
		for _, ep := range p.endpoints {
			if strings.TrimSpace(ep.BaseURL) != "" && strings.TrimSpace(ep.APIKey) != "" {
				baseURL = ep.BaseURL
				apiKey = ep.APIKey
				break
			}
		}
	}
	return p.client.ListModels(ctx, baseURL, apiKey, protocol)
}

// TestAll 逐一测试池内端点连通性，返回结构对齐原版 `_test_llm_one`。
//
// ⚠️ 这是「管理员手动测试」专用路径：只返回结果，**不写生产熔断器**。
// 原版注释明确此语义——若这里 Mark 健康状态，一次手动点击就会污染正在运行的
// worker/collector 的端点冷却判断（成功还会误清真实 cooldown，让 worker 立刻
// 冲击刚被限流的端点）。生产健康标记只应发生在真实调用路径上。
func (p *Pool) TestAll(ctx context.Context) []map[string]any {
	endpoints := p.Endpoints()
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].Name < endpoints[j].Name
	})
	results := make([]map[string]any, 0, len(endpoints))
	for _, ep := range endpoints {
		res, err := p.client.Ping(ctx, ep)
		item := map[string]any{
			"name":     ep.Name,
			"ok":       err == nil,
			"base_url": ep.BaseURL,
			// model 取「配置值」而非 API 回包的模型名——原版 _test_llm_one 的
			// result["model"] 始终是 provider.model，不随后端路由改写。
			"model":        ep.Model,
			"protocol":     ResolveProtocol(ep.Protocol, ep.BaseURL),
			"status_code":  res.StatusCode,
			"latency_ms":   res.LatencyMS,
			"error":        "",
			"reply":        "",
			"tool_calling": ToolCallingUnknown,
		}
		if err != nil {
			item["error"] = SafeErrorText(err.Error(), ep.APIKey, 500)
		} else {
			item["reply"] = utils.Truncate(res.Reply, 80)
			// 端点实际服务的模型名。部分网关会把请求静默路由到别的模型，
			// 与配置不一致时单独附上，便于排查「配了 A 却跑了 B」。
			if res.Model != "" && res.Model != ep.Model {
				item["served_model"] = res.Model
			}
			// 连通性 OK 后再探一次工具调用能力（额外一次小请求，仅测试按钮触发）。
			item["tool_calling"] = p.client.ProbeToolCalling(ctx, ep)
		}
		item["error_copy"] = TestErrorCopy(item)
		results = append(results, item)
	}
	return results
}
