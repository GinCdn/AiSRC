package engine

import (
	"net/url"
	"strings"

	"AiSRC/model"
)

// MatchAuthBinding 为某个目标 URL 挑选生效的凭据绑定。
//
// 对齐原版 app/agents/auth_bootstrap.py::match_auth_to_target 的优先级：
// 精确 URL > 命中清单行 > host:port > host > 通配 "*"。
// 命中多条时合并（用户名/密码/登录入口取最后一条非空）。
//
// 早先的实现从未给 target.AuthContext 赋值，导致用户在任务里配置的凭据
// 被静默忽略——agent 完全不知道存在凭据。
func MatchAuthBinding(targetURL string, bindings []model.AuthBinding, manualLines []string) *model.AuthBinding {
	if len(bindings) == 0 || strings.TrimSpace(targetURL) == "" {
		return nil
	}

	// 先规范化：把用户在 raw 里粘贴的整段原文（Authorization 头 / Cookie 头 /
	// 用户名密码行 / user/pass 简写）解析成结构化字段，无有效凭据的绑定直接丢弃。
	usable := make([]model.AuthBinding, 0, len(bindings))
	for _, binding := range bindings {
		normalized := NormalizeAuthBinding(binding)
		if len(AuthKindsOf(normalized)) == 0 {
			continue
		}
		usable = append(usable, normalized)
	}
	if len(usable) == 0 {
		return nil
	}
	bindings = usable

	urlNorm := normalizeAuthURL(targetURL)
	host := authHost(targetURL)
	hostPort := authHostPort(targetURL)

	lines := make([]string, 0, len(manualLines))
	for _, line := range manualLines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	var byURL, byLine, byHostPort, byHost, byStar []model.AuthBinding
	for _, binding := range bindings {
		key := strings.TrimSpace(binding.Target)
		if key == "" || key == "*" {
			byStar = append(byStar, binding)
			continue
		}
		if keyNorm := normalizeAuthURL(key); keyNorm != "" && keyNorm == urlNorm {
			byURL = append(byURL, binding)
			continue
		}
		if matchedLine(binding, key, lines, targetURL, host, urlNorm) {
			byLine = append(byLine, binding)
			continue
		}
		if keyPort := authHostPort(key); keyPort != "" && keyPort == hostPort {
			byHostPort = append(byHostPort, binding)
			continue
		}
		if keyHost := authHost(key); keyHost != "" && keyHost == host {
			byHost = append(byHost, binding)
		}
	}

	buckets := [][]model.AuthBinding{byURL, byLine, byHostPort, byHost, byStar}
	labels := []string{"url", "line", "hostport", "host", "default"}
	for i, bucket := range buckets {
		if len(bucket) == 0 {
			continue
		}
		merged := mergeAuthContext(bucket)
		merged.MatchedBy = labels[i]
		return &merged
	}
	return nil
}

// matchedLine 判断绑定的 target 是否命中了清单里确实指向本目标的某一行。
func matchedLine(binding model.AuthBinding, key string, lines []string, targetURL, host, urlNorm string) bool {
	for _, line := range lines {
		if key != line && normalizeAuthURL(key) != normalizeAuthURL(line) {
			continue
		}
		if authHost(line) == host || normalizeAuthURL(line) == urlNorm {
			return true
		}
	}
	return false
}

// mergeAuthContext 合并同一目标的多个绑定，后出现的非空值覆盖先出现的。
func mergeAuthContext(items []model.AuthBinding) model.AuthBinding {
	merged := model.AuthBinding{}
	for _, item := range items {
		if item.Target != "" {
			merged.Target = item.Target
		}
		if item.Username != "" {
			merged.Username = item.Username
		}
		if item.Password != "" {
			merged.Password = item.Password
		}
		if item.Cookie != "" {
			merged.Cookie = item.Cookie
		}
		if item.Authorization != "" {
			merged.Authorization = item.Authorization
		}
		if item.LoginURL != "" {
			merged.LoginURL = item.LoginURL
		}
		if item.Raw != "" {
			merged.Raw = item.Raw
		}
		if item.Note != "" {
			merged.Note = item.Note
		}
	}
	return merged
}

// parseAuthURL 宽松解析 URL：缺少 scheme 时按 http 处理。
func parseAuthURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return nil
	}
	return parsed
}

// normalizeAuthURL 归一化为 scheme://host[:port][/path]，用于精确比对。
func normalizeAuthURL(raw string) string {
	parsed := parseAuthURL(raw)
	if parsed == nil {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	path := strings.TrimRight(parsed.Path, "/")
	return scheme + "://" + host + authPortSuffix(scheme, parsed.Port()) + path
}

// authHost 取主机名。
func authHost(raw string) string {
	parsed := parseAuthURL(raw)
	if parsed == nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// authHostPort 取 host[:port]，未显式带端口时只返回 host。
func authHostPort(raw string) string {
	parsed := parseAuthURL(raw)
	if parsed == nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" {
		return host
	}
	return host + ":" + port
}

// authPortSuffix 省略协议默认端口，避免 http://h:80 与 http://h 被当成两个目标。
func authPortSuffix(scheme, port string) string {
	if port == "" {
		return ""
	}
	if scheme == "http" && port == "80" {
		return ""
	}
	if scheme == "https" && port == "443" {
		return ""
	}
	return ":" + port
}
