package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/utils"
)

// updateHTTPClient 在线更新使用的 HTTP 客户端。
var updateHTTPClient = &http.Client{Timeout: 20 * time.Second}

// UpdateCheckResult 更新检查结果。
type UpdateCheckResult struct {
	Enabled      bool   `json:"enabled"`
	Current      string `json:"current"`
	Latest       string `json:"latest"`
	HasUpdate    bool   `json:"has_update"`
	ReleaseName  string `json:"release_name"`
	ReleaseNotes string `json:"release_notes"`
	ReleaseURL   string `json:"release_url"`
	PublishedAt  string `json:"published_at"`
	Repo         string `json:"repo"`
	Branch       string `json:"branch"`
	CheckedAt    string `json:"checked_at"`
	ErrorMsg     string `json:"error,omitempty"`
}

// CheckUpdate 查询远端发布信息并比对版本。
func CheckUpdate(ctx context.Context) *UpdateCheckResult {
	result := &UpdateCheckResult{
		Enabled:   config.AppConfig.Update.Enabled,
		Current:   constant.Version,
		Repo:      config.AppConfig.Update.ReleasesURL,
		Branch:    config.AppConfig.Update.Branch,
		CheckedAt: utils.ToCSTISO(time.Now()),
	}
	if !result.Enabled {
		result.ErrorMsg = "在线更新未启用"
		return result
	}

	repo := strings.TrimRight(config.AppConfig.Update.ReleasesURL, "/")
	apiURL := repo
	if !strings.Contains(apiURL, "api.github.com") {
		// https://github.com/owner/repo → https://api.github.com/repos/owner/repo/releases/latest
		parts := strings.Split(repo, "/")
		if len(parts) >= 2 {
			owner := parts[len(parts)-2]
			name := parts[len(parts)-1]
			apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, name)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		result.ErrorMsg = err.Error()
		return result
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AiSRC/"+constant.Version)

	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		result.ErrorMsg = "请求发布信息失败：" + err.Error()
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result.ErrorMsg = fmt.Sprintf("发布信息获取失败（HTTP %d）", resp.StatusCode)
		return result
	}

	var payload struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		Body        string `json:"body"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		result.ErrorMsg = "解析发布信息失败：" + err.Error()
		return result
	}

	result.Latest = strings.TrimPrefix(payload.TagName, "v")
	result.ReleaseName = payload.Name
	result.ReleaseNotes = utils.Truncate(payload.Body, 4000)
	result.ReleaseURL = payload.HTMLURL
	if payload.PublishedAt != "" {
		if ts, ok := utils.ParseTime(payload.PublishedAt); ok {
			result.PublishedAt = utils.ToCSTISO(ts)
		} else {
			result.PublishedAt = payload.PublishedAt
		}
	}
	result.HasUpdate = compareVersion(result.Latest, result.Current) > 0
	return result
}

// RunUpdate 触发在线更新（本项目以「拉取源码 + 重新构建」方式实现）。
func RunUpdate() map[string]any {
	if !config.AppConfig.Update.Enabled {
		return map[string]any{"ok": false, "reason": "在线更新未启用"}
	}
	repo := config.AppConfig.Update.RepoRoot
	if strings.TrimSpace(repo) == "" {
		return map[string]any{
			"ok":     false,
			"reason": "未配置源码目录 repo_root，无法执行在线更新",
			"hint":   "请在 config.yaml 的 update.repo_root 指向代码仓库目录，或用 git pull 后重新构建",
		}
	}
	return map[string]any{
		"ok":     false,
		"reason": "为避免在生产环境自动执行外部命令，请手动在源码目录执行 git pull 与重新构建",
		"repo":   repo,
		"branch": config.AppConfig.Update.Branch,
	}
}

// compareVersion 语义化版本比较：a > b 返回 1，a < b 返回 -1，相等返回 0。
func compareVersion(a, b string) int {
	partA := splitVersion(a)
	partB := splitVersion(b)
	length := len(partA)
	if len(partB) > length {
		length = len(partB)
	}
	for i := 0; i < length; i++ {
		var va, vb int
		if i < len(partA) {
			va = partA[i]
		}
		if i < len(partB) {
			vb = partB[i]
		}
		if va > vb {
			return 1
		}
		if va < vb {
			return -1
		}
	}
	return 0
}

func splitVersion(value string) []int {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if idx := strings.IndexAny(value, "-+"); idx >= 0 {
		value = value[:idx]
	}
	parts := strings.Split(value, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		out = append(out, atoi(part))
	}
	return out
}
