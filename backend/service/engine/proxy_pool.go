package engine

// 代理池运行时（对齐原版 proxy_service v2 设计）：
//   - 配置快照由 ApplyRuntimeFlags 在启动与设置保存时同步进进程内 atomic（不查库）。
//   - acquire：round-robin 轮转分配，跳过停用/冷却中/排除项；全部不可用返回空 = 直连兜底，绝不阻断挖洞。
//   - report：连续 3 次连接类失败 → 冷却 60s；成功即清零。
//
// 线程安全：健康状态与轮转计数共用一把锁。

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"AiSRC/model"
)

// proxyFailThreshold 连续这么多次连接失败 → 冷却。
const proxyFailThreshold = 3

// proxyCooldown 代理冷却时长。
const proxyCooldown = 60 * time.Second

// proxySnapshot 代理池配置快照（原子替换）。
type proxySnapshot struct {
	Enabled bool
	Items   []model.ProxyItem
}

var proxySnapshotRuntime atomic.Value // 存 proxySnapshot

var proxyPoolMu sync.Mutex
var proxyHealth = map[string]*proxyHealthState{} // 按代理 ID
var proxyRR int

type proxyHealthState struct {
	fails         int
	cooldownUntil time.Time
}

// applyProxySnapshot 同步代理池快照（启动与设置保存后经 ApplyRuntimeFlags 调用）。
func applyProxySnapshot(settings *model.SystemSettings) {
	snap := proxySnapshot{Enabled: settings.Proxy.Enabled, Items: settings.Proxy.Proxies}
	if snap.Items == nil {
		snap.Items = []model.ProxyItem{}
	}
	proxySnapshotRuntime.Store(snap)
}

// acquireProxy 轮转取一个可用代理（排除 exclude），返回 (id, 连接串)；无可用返回空 = 直连兜底。
func acquireProxy(exclude map[string]bool) (string, string) {
	snap, ok := proxySnapshotRuntime.Load().(proxySnapshot)
	if !ok || !snap.Enabled || len(snap.Items) == 0 {
		return "", ""
	}
	proxyPoolMu.Lock()
	defer proxyPoolMu.Unlock()
	n := len(snap.Items)
	for i := 0; i < n; i++ {
		proxyRR++
		item := snap.Items[proxyRR%n]
		if !item.Enabled || exclude[item.ID] {
			continue
		}
		if h := proxyHealth[item.ID]; h != nil && time.Now().Before(h.cooldownUntil) {
			continue
		}
		return item.ID, proxyConnURL(item)
	}
	return "", ""
}

// reportProxyResult 上报一次代理使用结果：成功清零；连续连接类失败达阈值进入冷却
//（冷却到期后重新计数，冷却本身就是惩罚，不叠加）。
func reportProxyResult(id string, ok bool) {
	if id == "" {
		return
	}
	proxyPoolMu.Lock()
	defer proxyPoolMu.Unlock()
	h := proxyHealth[id]
	if h == nil {
		h = &proxyHealthState{}
		proxyHealth[id] = h
	}
	if ok {
		h.fails = 0
		h.cooldownUntil = time.Time{}
		return
	}
	h.fails++
	if h.fails >= proxyFailThreshold {
		h.cooldownUntil = time.Now().Add(proxyCooldown)
		h.fails = 0
	}
}

// proxyConnURL 组装代理连接串（含认证；与 service 包 buildProxyURL 同构，engine 不能反向导入 service）。
func proxyConnURL(item model.ProxyItem) string {
	scheme := item.Protocol
	switch scheme {
	case "socks", "socks5h":
		scheme = "socks5"
	}
	if scheme != "http" && scheme != "https" && scheme != "socks5" {
		scheme = "http"
	}
	host := fmt.Sprintf("%s:%d", item.Host, item.Port)
	if item.Username != "" {
		if item.Password != "" {
			return fmt.Sprintf("%s://%s:%s@%s", scheme, url.QueryEscape(item.Username), url.QueryEscape(item.Password), host)
		}
		return fmt.Sprintf("%s://%s@%s", scheme, url.QueryEscape(item.Username), host)
	}
	return scheme + "://" + host
}

// proxyTransportCache 按连接串缓存挂了代理的传输层（保持连接池复用，避免每请求重建）。
var proxyTransportCache sync.Map // 连接串 -> http.RoundTripper

// proxyTransport 返回走指定代理的传输层；解析失败返回 nil。
func proxyTransport(connURL string) http.RoundTripper {
	if connURL == "" {
		return nil
	}
	if cached, hit := proxyTransportCache.Load(connURL); hit {
		return cached.(http.RoundTripper)
	}
	pu, err := url.Parse(connURL)
	if err != nil {
		return nil
	}
	base, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil
	}
	tr := base.Clone()
	tr.Proxy = http.ProxyURL(pu)
	proxyTransportCache.Store(connURL, tr)
	return tr
}

// isProxyTransportError 只有连不上代理才算代理故障；目标读超时、证书错误不算，避免误杀好出口。
func isProxyTransportError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "proxyconnect") || strings.Contains(text, "socks")
}

// ensureSessionProxy 保证会话持有粘性代理出口：池关 → 清空直连；
// 池开且未持有 → 轮转取一个。全部不可用（用尽/冷却）时保持空 = 直连兜底。
func ensureSessionProxy(session *sessionState) {
	if session == nil {
		return
	}
	snap, ok := proxySnapshotRuntime.Load().(proxySnapshot)
	if !ok || !snap.Enabled {
		session.proxyID, session.proxyURL = "", ""
		return
	}
	if session.proxyID != "" || session.proxyURL != "" {
		return
	}
	session.proxyID, session.proxyURL = acquireProxy(session.usedProxies)
}

// dropSessionProxy 会话放弃当前代理（连接类失败后调用），下次请求轮转换出口。
func dropSessionProxy(session *sessionState) {
	if session == nil || session.proxyID == "" {
		return
	}
	if session.usedProxies == nil {
		session.usedProxies = map[string]bool{}
	}
	session.usedProxies[session.proxyID] = true
	session.proxyID, session.proxyURL = "", ""
}
