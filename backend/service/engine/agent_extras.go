package engine

// Agent 增强能力：AI 人格/技能注入、ima 知识库检索、Kali SSH 协调执行。
// 三者均由系统设置驱动，未启用时零影响（不注册工具、不注入提示词）。

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"AiSRC/model"
	"AiSRC/utils"
)

// ============================================================ 人格 / 技能

// AgentPersonaSuffix 组装人格 + 技能提示词后缀（追加到各 Agent 系统提示词尾部）。
// 未启用人格与技能时返回空串，零影响。
func AgentPersonaSuffix() string {
	settings := LoadSystemSettings()
	var sb strings.Builder
	if p := settings.Persona; p.Enabled {
		var lines []string
		if name := strings.TrimSpace(p.Name); name != "" {
			lines = append(lines, "人格名："+name)
		}
		if style := strings.TrimSpace(p.Style); style != "" {
			lines = append(lines, "口吻风格："+style)
		}
		if principles := strings.TrimSpace(p.Principles); principles != "" {
			lines = append(lines, "行为准则：\n"+principles)
		}
		if len(lines) > 0 {
			sb.WriteString("\n\n## AI 人格（用户配置，须遵守）\n" + strings.Join(lines, "\n"))
		}
	}
	if s := settings.Skills; s.Enabled {
		active := make([]string, 0, len(s.Items))
		for _, item := range s.Items {
			if item.Enabled && strings.TrimSpace(item.Content) != "" {
				active = append(active, "### 技能："+strings.TrimSpace(item.Name)+"\n"+strings.TrimSpace(item.Content))
			}
		}
		if len(active) > 0 {
			sb.WriteString("\n\n## 已装配技能（用户配置，按需运用）\n" + strings.Join(active, "\n\n"))
		}
	}
	return sb.String()
}

// ============================================================ ima 知识库

// ImaSearch 调用 ima 知识库检索端点（POST query，兼容任意返回 JSON 的检索服务）。
// 返回拼接好的知识片段文本；失败返回 error。
func ImaSearch(ctx context.Context, query string, topK int) (string, error) {
	settings := LoadSystemSettings()
	ima := settings.Ima
	if !ima.Enabled || strings.TrimSpace(ima.BaseURL) == "" {
		return "", fmt.Errorf("ima 知识库未启用或未配置端点")
	}
	if topK <= 0 {
		topK = ima.TopK
	}
	if topK <= 0 {
		topK = 5
	}
	payload := fmt.Sprintf(`{"query":%q,"top_k":%d,"repo_id":%q}`, query, topK, ima.RepoID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ima.BaseURL, strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(ima.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+ima.APIKey)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ima 检索 HTTP %d: %s", resp.StatusCode, utils.Truncate(string(raw), 200))
	}
	return utils.Truncate(strings.TrimSpace(string(raw)), 6000), nil
}

// ============================================================ Kali SSH

// KaliEnabled Kali 集成是否启用（开关 + 主机 + 认证齐备）。
func KaliEnabled() bool {
	settings := LoadSystemSettings()
	k := settings.Kali
	if !k.Enabled || strings.TrimSpace(k.Host) == "" || strings.TrimSpace(k.Username) == "" {
		return false
	}
	if (k.AuthType == "key" || k.AuthType == "") && strings.TrimSpace(k.PrivateKey) != "" {
		return true
	}
	return k.AuthType == "password" && strings.TrimSpace(k.Password) != ""
}

// KaliCategoryLabel 分类 key → 中文名。
func KaliCategoryLabel(key string) string {
	for _, c := range model.KaliCategories {
		if c.Key == key {
			return c.Label
		}
	}
	return key
}

// KaliExecute 通过 SSH 在 Kali 上执行命令（超时与输出截断保护）。
func KaliExecute(ctx context.Context, commands []string, timeout time.Duration) ([]map[string]any, error) {
	settings := LoadSystemSettings()
	k := settings.Kali
	if !KaliEnabled() {
		return nil, fmt.Errorf("Kali SSH 未启用或未配置完整")
	}
	if len(commands) == 0 {
		return nil, fmt.Errorf("命令清单为空")
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	cfg, err := kaliSSHConfig(k)
	if err != nil {
		return nil, err
	}
	port := k.Port
	if port <= 0 {
		port = 22
	}
	results := make([]map[string]any, 0, len(commands))
	client, err := kaliDial(ctx, cfg, k.Host, port)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		item := map[string]any{"command": command}
		output, execErr := kaliRun(ctx, client, command, timeout)
		item["output"] = utils.Truncate(output, 8000)
		if execErr != nil {
			item["error"] = execErr.Error()
		}
		results = append(results, item)
	}
	return results, nil
}

// kaliDangerousMarkers 硬拦截的破坏性命令片段（Kali 机也要防误毁）。
var kaliDangerousMarkers = []string{
	"rm -rf /", "mkfs", "dd if=/dev/zero", ":(){", "shutdown", "reboot",
	"wget -o-", "curl | sh", "curl | bash",
}

// FilterKaliCommands 硬拦截破坏性命令，返回被拒清单。
func FilterKaliCommands(commands []string) (allowed, rejected []string) {
	for _, command := range commands {
		lower := strings.ToLower(strings.TrimSpace(command))
		danger := false
		for _, marker := range kaliDangerousMarkers {
			if strings.Contains(lower, marker) {
				danger = true
				break
			}
		}
		if danger {
			rejected = append(rejected, command)
		} else {
			allowed = append(allowed, command)
		}
	}
	return
}
