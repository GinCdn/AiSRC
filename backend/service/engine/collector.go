package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/llm"
	"AiSRC/utils"

	"gorm.io/gorm/clause"
)

// 搜集参数。
const (
	RefillMaxPagesDefault = 20
	RefillPageSizeDefault = 100
	FofaAuthFailPauseAt   = 5 // 测绘账号连续无效次数达到该值 → 自动暂停任务

	// 引擎查询失败退避：1min 起步指数翻倍，15min 封顶；
	// 连续失败达 EngineFailStopAt 次后停止自动重试（不再是每 5 秒盲重试同页）。
	EngineFailBackoffBase = time.Minute
	EngineFailBackoffMax  = 15 * time.Minute
	EngineFailStopAt      = 5

	// 翻页节流：Hunter 等 openAPI 有 QPS 限制（「请求太多啦，稍后再试试」），
	// 上一版 0.5s 连发 3 页即触发限频；每页之间强制最小间隔。
	EnginePageInterval = 2 * time.Second

	// 限频错误的专属退避：QPS 限制通常几秒~几十秒即恢复，
	// 不走普通失败的 1min 起步指数退避。
	RateLimitBackoff = 30 * time.Second
)

// 评分规则：正向加权。
type scoreRule struct {
	Name     string
	Weight   float64
	Keywords []string
}

var scorePositive = []scoreRule{
	{"admin_backend", 3, []string{"管理后台", "后台管理", "管理系统", "管理中心", "控制台", "console", "manager"}},
	{"data_interactive", 3, []string{"支付", "缴费", "考试", "成绩", "充值", "转账", "订单", "申报", "报名", "审批"}},
	{"wechat_platform", 2, []string{"微信管理", "企业微信", "公众号", "小程序管理"}},
	{"api_gateway", 2, []string{"开放平台", "应用管理", "api网关", "swagger"}},
	{"spa_with_api", 2, []string{"vue", "react", "nuxt", "angular", "/api/"}},
	{"cloud_storage", 2, []string{"x-oss-", "oss-cn-", ".aliyuncs.com", "sts", "minio", "bucket"}},
	{"edu_industry", 1, []string{"大学", "学院", "学校", "职业技术", "教育局", "教育厅", "科学院", "研究所"}},
}

// 评分规则：负向降权。
var scoreNegative = []scoreRule{
	{"auth_gateway", -4, []string{"统一身份认证", "统一认证", "认证平台", "cas", "sso", "authserver", "登录中心"}},
	{"pure_frontend", -4, []string{"官网", "新闻网", "门户", "首页", "宣传", "概况", "简介"}},
	{"sensitive_gov", -3, []string{"党员", "党建", "党委", "纪检", "组织部", "统战", "信访"}},
	{"data_display", -2, []string{"数据平台", "数据中心", "大数据", "统计平台", "数据可视化大屏"}},
	{"public_generic_service", -3, []string{"grafana", "kibana", "redis", "zabbix", "prometheus", "jenkins", "phpmyadmin"}},
	{"known_opensource", -1, []string{"wordpress", "wp-content", "discuz", "dedecms", "phpcms"}},
}

// 低价值资产预筛：命中即跳过（不浪费 worker 预算）。
var prefilterSkipKeywords = []string{
	"cdn", "static.", "assets.", "img.", "image.", "font.", "jsdelivr", "cdnjs",
	"waf", "safedog", "安全狗", "云锁", "网站防火墙",
}

// eduPortAllow 允许的常见 Web 端口；非常规端口会被降权但保留。
var eduPortAllow = map[string]bool{
	"": true, "80": true, "443": true, "8080": true, "8443": true,
	"8000": true, "8888": true, "9000": true, "81": true, "8081": true,
}

// Refill 补充目标队列，返回新入队数量。
func Refill(ctx context.Context, task *model.Task, pool *llm.Pool) (int, error) {
	if task == nil {
		return 0, nil
	}
	queued := countQueued(task.ID)
	if queued >= LowWatermark {
		clearStalePhase(task)
		return 0, nil
	}

	settings := LoadSystemSettings()
	engineName := NormalizeEngine(firstNonEmptyString(task.Engine, settings.Defaults.Engine))
	apiKey, baseURL := resolveEngineCredential(task, settings, engineName)
	maxPages := task.FofaConfig.MaxPages
	if maxPages <= 0 {
		maxPages = settings.Fofa.MaxPages
	}
	if maxPages <= 0 {
		maxPages = RefillMaxPagesDefault
	}
	if maxPages > constant.MaxPagesMax {
		maxPages = constant.MaxPagesMax
	}
	pageSize := task.FofaConfig.PageSize
	if pageSize <= 0 {
		pageSize = settings.Fofa.PageSize
	}
	if pageSize <= 0 {
		pageSize = RefillPageSizeDefault
	}
	if pageSize > constant.PageSizeMax {
		pageSize = constant.PageSizeMax
	}

	seen := existingHosts(task.ID)
	added := 0

	// 1) 手动清单优先入队。
	if (task.TargetSource == "manual" || task.TargetSource == "both") && len(task.ManualTargets) > 0 {
		manual := buildManualCandidates(task.ManualTargets)
		added += enqueueCandidates(task, manual, seen, "manual")
	}

	// 1.5) 单站协作：同一 host 按固定路线拆成多个 worker 并发进攻（不走测绘翻页）。
	if task.TargetSource == "site" && len(task.ManualTargets) > 0 {
		added += siteCollect(task)
	}

	// 2) 测绘引擎检索。
	if task.TargetSource != "manual" && task.TargetSource != "site" && strings.TrimSpace(task.FofaQuery) != "" {
		if strings.TrimSpace(apiKey) == "" {
			if added == 0 {
				return 0, fmt.Errorf("未配置 %s API Key，无法检索目标", EngineDisplayName(engineName))
			}
			return added, nil
		}
		// 已取尽则不再发查询：此前「无结果→标记取尽」后下一个 tick 仍会从
		// cursor+1 继续，游标一页页空爬、还能爬到 Hunter 的 1 万条上限进入
		// 死循环报错。取尽后只有查询词/引擎变更（intent 缓存键失配或用户
		// 编辑重置游标）才会重新开始翻页。
		if task.FofaConfig.FofaExhausted {
			clearStalePhase(task)
			return added, nil
		}
		// 失败退避：上一轮引擎查询失败后未到退避截止时间，直接跳过本轮。
		// （没有这道闸，主循环每 5 秒 tick 一次就从同一页重打一次。）
		if !task.FofaConfig.NextRetryAt.IsZero() && time.Now().Before(task.FofaConfig.NextRetryAt) {
			return added, nil
		}
		// 连续失败停机：退避重试若干轮仍失败（限频/配额/网络故障），
		// 停止自动重试，等用户改查询词/引擎或重启任务再放开。
		if task.FofaConfig.EngineFailCount >= EngineFailStopAt {
			clearStalePhase(task)
			return added, nil
		}
		// 意图模式：自然语言查询必须先经 LLM 翻译成引擎查询语法
		// （IntentParsePrompt 此前定义但从未接线，自然语言直发引擎必 0 结果）。
		queryText := strings.TrimSpace(task.FofaQuery)
		queryText = resolveIntentQuery(ctx, task, pool, engineName, queryText)
		startPage := task.FofaConfig.Cursor + 1
		if startPage <= 0 {
			startPage = 1
		}
		// Hunter 单次查询最多查看 1 万条资产（page*page_size ≤ 10000），
		// 越界直接报错且永不成功，必须提前夹住并把任务标记取尽。
		if engineName == "hunter" {
			hunterCap := 10000 / pageSize
			if hunterCap < 1 {
				hunterCap = 1
			}
			if startPage > hunterCap {
				EmitWarn(task.ID, "collector", "engine_query",
					fmt.Sprintf("%s 已达单次查看 1 万条上限（第 %d 页超出 %d 页上限），标记取尽不再翻页",
						EngineDisplayName(engineName), startPage, hunterCap),
					map[string]any{"engine": engineName, "start_page": startPage, "page_cap": hunterCap})
				updateFofaConfig(task, map[string]any{
					"fofa_exhausted":       true,
					"collector_phase":      "idle",
					"collector_phase_text": "已取尽（引擎查看上限）",
				})
				return added, nil
			}
			if startPage+maxPages-1 > hunterCap {
				maxPages = hunterCap - startPage + 1
			}
		}
		collected := 0
		allRows := make([][]string, 0, maxPages*pageSize)
		resultFields := ""
		// 检索开始事件：看板/轨迹此前对测绘阶段零可见（成功路径无任何
		// Emit），用户看不到「资产测绘」到底发没发请求、翻了哪些页。
		EmitInfo(task.ID, "collector", "engine_query",
			fmt.Sprintf("开始 %s 检索：%s（第 %d~%d 页，每页 %d 条）",
				EngineDisplayName(engineName), queryText, startPage, startPage+maxPages-1, pageSize),
			map[string]any{"engine": engineName, "query": queryText, "base_url": baseURL,
				"start_page": startPage, "max_pages": maxPages, "page_size": pageSize})
		for page := startPage; page < startPage+maxPages; page++ {
			if ctx.Err() != nil {
				break
			}
			if page > startPage {
				// 翻页节流：Hunter 等 openAPI 有 QPS 限制，0.5s 连发即触发限频。
				select {
				case <-ctx.Done():
				case <-time.After(EnginePageInterval):
				}
				if ctx.Err() != nil {
					break
				}
			}
			result, err := SearchEngine(ctx, engineName, apiKey, queryText, page, pageSize, baseURL)
			if err != nil {
				// MCP 工作流轨迹照发（带 error 步），失败也要留下完整链路。
				if result != nil && len(result.Trace) > 0 {
					EmitInfo(task.ID, "collector", "mcp_workflow",
						fmt.Sprintf("MCP 工作流[%s 第 %d 页]失败", EngineDisplayName(engineName), page),
						map[string]any{"engine": engineName, "page": page, "steps": result.Trace})
				}
				EmitWarn(task.ID, "collector", "engine_query",
					fmt.Sprintf("%s 检索失败（第 %d 页）：%s", EngineDisplayName(engineName), page, err.Error()),
					map[string]any{"engine": engineName, "query": queryText, "page": page, "error": err.Error()})
				// 引擎查看上限（如 Hunter 1 万条）：属于正常取尽，不是失败，
				// 标记取尽停止翻页；走 handleEngineError 会让 tick 每 5 秒无限重试。
				var engErr *EngineError
				if errors.As(err, &engErr) && engErr.DataCap {
					EmitWarn(task.ID, "collector", "engine_query",
						fmt.Sprintf("%s 已达单次查看上限，标记取尽（累计入队 %d 个目标）",
							EngineDisplayName(engineName), added+collected),
						map[string]any{"engine": engineName, "page": page, "data_cap": true})
			updateFofaConfig(task, map[string]any{
				"fofa_exhausted":       true,
				"cursor":               page - 1,
				"collector_phase":      "idle",
				"collector_phase_text": "已取尽（引擎查看上限）",
				"engine_fail_count":    0,
				"next_retry_at":        time.Time{},
			})
					break
				}
				return added, handleEngineError(task, engineName, err)
			}
			// MCP 工作流轨迹：prepare/request/response/normalize 全步落事件
			// （对齐 hunter-mcp 等测绘 MCP 服务器的工具调用日志形态）。
			EmitInfo(task.ID, "collector", "mcp_workflow",
				fmt.Sprintf("MCP 工作流[%s 第 %d 页]：%s → %d 行（%d ms）",
					EngineDisplayName(engineName), page, engineTraceURL(result.Trace), len(result.Results), engineTraceElapsed(result.Trace)),
				map[string]any{"engine": engineName, "page": page, "steps": result.Trace, "rows": len(result.Results)})
			rows := normalizeEngineRows(result)
			if len(rows) == 0 {
				// 该页无结果：视为已翻完。
				EmitInfo(task.ID, "collector", "engine_query",
					fmt.Sprintf("%s 检索第 %d 页无结果，检索结束（累计入队 %d 个目标）",
						EngineDisplayName(engineName), page, added+collected),
					map[string]any{"engine": engineName, "page": page, "rows": 0, "enqueued": collected})
			updateFofaConfig(task, map[string]any{
				"fofa_exhausted":    true,
				"cursor":            page,
				"current_query":     queryText,
				"engine_fail_count": 0,
				"next_retry_at":     time.Time{},
			})
				break
			}
			allRows = append(allRows, result.Results...)
			if resultFields == "" {
				resultFields = strings.Join(result.Fields, ",")
			}
			candidates := prefilterCandidates(rows)
			pageEnqueued := enqueueCandidates(task, candidates, seen, engineName)
			collected += pageEnqueued
			EmitInfo(task.ID, "collector", "engine_query",
				fmt.Sprintf("%s 检索第 %d 页：返回 %d 条，过滤后入队 %d 个目标",
					EngineDisplayName(engineName), page, len(rows), pageEnqueued),
				map[string]any{"engine": engineName, "query": queryText, "page": page,
					"rows": len(rows), "enqueued": pageEnqueued})
		updateFofaConfig(task, map[string]any{
			"cursor":               page,
			"current_query":        queryText,
			"fofa_exhausted":       false,
			"last_fofa_error":      "",
			"fofa_auth_fail_count": 0,
			"engine_fail_count":    0,
			"next_retry_at":        time.Time{},
		})
			if collected >= LowWatermark*4 {
				break
			}
		}
		added += collected
		EmitInfo(task.ID, "collector", "engine_query",
			fmt.Sprintf("%s 检索完成：本次入队 %d 个目标", EngineDisplayName(engineName), collected),
			map[string]any{"engine": engineName, "enqueued": collected})
		// 测绘结果完整传递给大模型分析（全部行、全字段；失败仅警告不阻断）。
		// 异步执行：分析内含冷却等待重试，不能阻塞补位循环。
		if len(allRows) > 0 {
			go AnalyzeEngineResults(ctx, task, pool, engineName, task.FofaQuery, resultFields, allRows)
		}
	}

	if added > 0 {
		updateFofaConfig(task, map[string]any{
			"collector_phase":      "idle",
			"collector_phase_text": fmt.Sprintf("已入队 %d 个目标", added),
		})
	}
	return added, nil
}

// resolveIntentQuery 意图模式查询解析：自然语言 → 引擎查询语法。
// IntentParsePrompt 此前定义但从未接线，自然语言直发引擎必然 0 结果，
// 触发「取尽标记不粘滞 + 游标空爬」连锁缺陷（gincdn.cc 实测踩坑）。
// 结果按「原始意图|引擎」缓存进 fofa_config，任务不改查询就不重复调 LLM；
// 解析失败回退原文（保持旧行为）并告警。
func resolveIntentQuery(ctx context.Context, task *model.Task, pool *llm.Pool, engineName, raw string) string {
	forKey := raw + "|" + engineName
	if task.FofaConfig.IntentQuery != "" && task.FofaConfig.IntentQueryFor == forKey {
		return task.FofaConfig.IntentQuery
	}
	needsParse := task.FofaConfig.IntentMode == "intent" || containsHan(raw)
	if !needsParse || pool == nil {
		return raw
	}
	parsed := ""
	if chatResult, err := chatAndRecord(ctx, pool, llm.Request{
		Messages: []llm.Message{
			{Role: "system", Content: IntentParsePrompt +
				"\n当前目标引擎：" + EngineDisplayName(engineName) +
				"（只使用该引擎支持的查询字段；不确定时优先用 domain=、title=、body= 等通用字段）。"},
			{Role: "user", Content: raw},
		},
		MaxTokens: 256,
	}, ""); err == nil {
		parsed = sanitizeEngineQuery(chatResult.Response.Content)
	}
	if parsed == "" || parsed == raw {
		if parsed == "" {
			EmitWarn(task.ID, "collector", "engine_query",
				"意图解析失败，按原文查询（建议改写为引擎查询语法）",
				map[string]any{"engine": engineName, "query": raw})
		}
		updateFofaConfig(task, map[string]any{"intent_query": raw, "intent_query_for": forKey})
		return raw
	}
	EmitInfo(task.ID, "collector", "engine_query",
		fmt.Sprintf("意图解析：%s → %s", utils.Truncate(raw, 120), utils.Truncate(parsed, 160)),
		map[string]any{"engine": engineName, "raw": raw, "parsed": parsed})
	updateFofaConfig(task, map[string]any{"intent_query": parsed, "intent_query_for": forKey})
	return parsed
}

// sanitizeEngineQuery 清洗 LLM 返回的查询：剥代码围栏/引号/换行，只留首行。
func sanitizeEngineQuery(text string) string {
	text = strings.ReplaceAll(text, "`", "")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.Trim(line, `"'`)
		return utils.Truncate(line, 300)
	}
	return ""
}

// containsHan 判断字符串是否含汉字（视为自然语言意图）。
func containsHan(text string) bool {
	return hanRe.MatchString(text)
}

var hanRe = regexp.MustCompile(`[\p{Han}]`)

// resolveEngineCredential 解析当前引擎的 Key 与 BaseURL。
// 各测绘引擎的凭据固定取系统设置「各引擎 API Key」区块（engines 段）；
// 端点**固定为该引擎官方默认端点**（DefaultEngineBaseURL），不再读用户
// 配置——测绘 API 都是官方固定入口，自定义端点没有真实场景，反而让
// 「API 端点（可选）」输入框变成困惑源（用户反馈：应该固定好）。
// 曾把非 FOFA 引擎静默回退到 FOFA 凭据——拿 FOFA 的 key/base 调 Hunter
// API 必然失败且难排查；未配置就返回空，由调用方报「未配置 X API Key」。
func resolveEngineCredential(task *model.Task, settings *model.SystemSettings, engineName string) (string, string) {
	base := DefaultEngineBaseURL(engineName)
	if engineName == "fofa" {
		key := firstNonEmptyString(task.FofaConfig.Key, settings.Fofa.Key)
		if key != "" {
			return key, base
		}
	}
	if item, ok := settings.Engines[engineName]; ok {
		if strings.TrimSpace(item.Key) != "" {
			return item.Key, base
		}
	}
	if engineName == "fofa" {
		// FOFA 引擎最后回退 fofa 段（段内 key 为空也返回，让上层报缺 Key）。
		return firstNonEmptyString(task.FofaConfig.Key, settings.Fofa.Key), base
	}
	// 非 FOFA 引擎：未在 engines 段配置即视为未配置，不借用其它引擎凭据。
	return "", ""
}

// handleEngineError 记录引擎错误并更新失败计数。
// 失败退避：同一页每 5 秒盲重试是主循环 tick 的副作用，必须掐断——
// 每次失败按 1/2/4/8…分钟指数退避设置 next_retry_at，连续失败达
// EngineFailStopAt 次后停止自动重试（改查询词/引擎或重启任务才放开）。
func handleEngineError(task *model.Task, engineName string, err error) error {
	engineErr, ok := err.(*EngineError)
	updates := map[string]any{"last_fofa_error": utils.Truncate(err.Error(), 300)}
	if ok && engineErr.AccountError {
		updates["fofa_auth_fail_count"] = task.FofaConfig.FofaAuthFailCount + 1
	}

	// DataCap（引擎查看上限）与账号级自动暂停之外的普通失败才计退避；
	// 账号级错误走既有自动暂停链，退避无意义。
	accountFatal := ok && engineErr.AccountError &&
		task.FofaConfig.FofaAuthFailCount+1 >= FofaAuthFailPauseAt
	failCount := task.FofaConfig.EngineFailCount + 1
	switch {
	case accountFatal:
		// 账号级错误不计退避，走下方自动暂停链。
	case ok && engineErr.RateLimited:
		// QPS 限频：等待后同页重试即可恢复，不烧普通失败计数
		//（否则长扫描中偶发限频会把任务推到「连续失败停机」）。
		nextAt := time.Now().Add(RateLimitBackoff)
		updates["next_retry_at"] = nextAt
		updates["collector_phase"] = "idle"
		updates["collector_phase_text"] = fmt.Sprintf(
			"%s 触发频率限制，%s 后自动重试当前页",
			EngineDisplayName(engineName), nextAt.Format("15:04:05"))
	case failCount >= EngineFailStopAt:
		updates["engine_fail_count"] = failCount
		updates["next_retry_at"] = time.Time{}
		updates["collector_phase"] = "idle"
		updates["collector_phase_text"] = fmt.Sprintf(
			"%s 连续失败 %d 次，已停止自动重试（修改查询词或重启任务后重试）",
			EngineDisplayName(engineName), failCount)
	default:
		updates["engine_fail_count"] = failCount
		backoff := EngineFailBackoffBase << (failCount - 1)
		if backoff > EngineFailBackoffMax {
			backoff = EngineFailBackoffMax
		}
		nextAt := time.Now().Add(backoff)
		updates["next_retry_at"] = nextAt
		updates["collector_phase"] = "idle"
		updates["collector_phase_text"] = fmt.Sprintf(
			"%s 查询失败，%s 后自动重试（第 %d/%d 次失败）",
			EngineDisplayName(engineName), nextAt.Format("15:04:05"), failCount, EngineFailStopAt)
	}
	updateFofaConfig(task, updates)

	if accountFatal {
		managerInstance.PauseTask(task.ID, EngineDisplayName(engineName)+" 账号连续无效，任务已自动暂停")
		EmitError(task.ID, "collector", "auto_paused",
			EngineDisplayName(engineName)+" 账号连续无效，已自动暂停任务",
			map[string]any{"engine": engineName, "error": err.Error()})
	}
	return err
}

// normalizeEngineRows 把引擎结果行转成候选资产。
func normalizeEngineRows(result *EngineResult) []Candidate {
	if result == nil {
		return nil
	}
	out := make([]Candidate, 0, len(result.Results))
	for _, row := range result.Results {
		item := map[string]string{}
		for i, name := range result.Fields {
			if i < len(row) {
				item[name] = strings.TrimSpace(row[i])
			}
		}
		host := utils.NormalizeHost(item["host"])
		if host == "" {
			host = utils.NormalizeHost(item["domain"])
		}
		if host == "" {
			continue
		}
		out = append(out, Candidate{
			URL:    item["host"],
			Host:   host,
			IP:     item["ip"],
			Title:  item["title"],
			Org:    item["org"],
			Source: result.Engine,
		})
	}
	return out
}

// prefilterCandidates 低价值资产预筛：过滤纯静态 / CDN 类主机。
//
// 关键词按「标签边界」整词匹配（host 按 . 与 - 切分后逐标签比较），
// 不做子串匹配——否则 gincdn.cc 这类恰好包含 cdn 字样的正常域名会被整域
// 误杀（实测：Hunter 返回 10 条全部被丢，「过滤后入队 0 个目标」）。
func prefilterCandidates(candidates []Candidate) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		lowerHost := strings.ToLower(c.Host)
		labels := strings.FieldsFunc(lowerHost, func(r rune) bool { return r == '.' || r == '-' })
		skip := false
		for _, keyword := range prefilterSkipKeywords {
			kw := strings.ToLower(strings.TrimSuffix(keyword, "."))
			for _, label := range labels {
				if label == kw {
					skip = true
					break
				}
			}
			if skip {
				break
			}
		}
		if skip {
			continue
		}
		out = append(out, c)
	}
	return out
}

// buildManualCandidates 解析手动目标清单。
//
// 与原版 app/agents/manual_targets.py::_normalize_url 一致：保留用户显式填写的
// scheme 与路径/查询，仅在缺 scheme 时补 http://。
// 早先的实现无条件剥掉 "//" 之前的部分再硬编码补 "http://"，会把用户写的
// https:// 目标静默降级成 http://（多一次跳转，HTTPS-only 站点甚至打到不同入口）。
func buildManualCandidates(items []string) []Candidate {
	out := make([]Candidate, 0, len(items))
	for _, raw := range items {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 先拆 scheme，缺省 http。
		scheme := "http"
		if idx := strings.Index(line, "://"); idx > 0 {
			if parsed := strings.ToLower(line[:idx]); parsed == "http" || parsed == "https" {
				scheme = parsed
			}
			line = line[idx+3:]
		} else if strings.HasPrefix(line, "//") {
			line = line[2:]
		}

		// 去掉误粘的说明文字与尾部标点。
		if idx := strings.IndexAny(line, " \t（("); idx > 0 {
			line = line[:idx]
		}
		line = strings.TrimRight(line, ",;，；")
		// 根路径 `/` 省略，避免与裸域产生无意义差异。
		if line == "/" {
			line = ""
		} else if strings.HasSuffix(line, "/") && !strings.Contains(strings.TrimSuffix(line, "/"), "/") {
			line = strings.TrimSuffix(line, "/")
		}

		host := utils.NormalizeHost(line)
		if host == "" {
			continue
		}
		out = append(out, Candidate{URL: scheme + "://" + line, Host: host, Source: "manual"})
	}
	return out
}

// enqueueCandidates 去重、评分并写入目标表，返回新入队数量。
func enqueueCandidates(task *model.Task, candidates []Candidate, seen map[string]bool, source string) int {
	if len(candidates) == 0 {
		return 0
	}
	batch := make([]model.Target, 0, len(candidates))
	now := time.Now()
	for _, c := range candidates {
		if c.Host == "" || seen[c.Host] {
			continue
		}
		seen[c.Host] = true
		score, reason, isEdu := ScoreCandidate(c, task.SrcType)
		batch = append(batch, model.Target{
			ID:             utils.UUID(),
			TaskID:         task.ID,
			URL:            c.URL,
			Host:           c.Host,
			IP:             c.IP,
			Org:            c.Org,
			Title:          utils.Truncate(c.Title, 480),
			Source:         source,
			IsEdu:          &isEdu,
			School:         extractSchool(firstNonEmptyString(c.Org, c.Title)),
			PriorityScore:  score,
			PriorityReason: reason,
			AuthContext:    MatchAuthBinding(c.URL, task.AuthBindings, task.ManualTargets),
			Status:         constant.TargetQueued,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	if len(batch) == 0 {
		return 0
	}
	// 批量插入，主键冲突（并发重复入队）直接忽略。
	result := core.Db.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(batch, 200)
	if result.Error != nil {
		global.Log.Warnf("入队目标失败: %v", result.Error)
		return 0
	}
	return int(result.RowsAffected)
}

// ScoreCandidate 目标优先级评分：只决定先打谁，不代表放弃。
func ScoreCandidate(c Candidate, srcType string) (float64, string, bool) {
	text := strings.ToLower(c.Title + " " + c.Org + " " + c.Host)
	score := 50.0
	reasons := make([]string, 0, 6)

	for _, rule := range scorePositive {
		for _, keyword := range rule.Keywords {
			if strings.Contains(text, strings.ToLower(keyword)) {
				score += rule.Weight * 3
				reasons = append(reasons, "+"+rule.Name)
				break
			}
		}
	}
	for _, rule := range scoreNegative {
		for _, keyword := range rule.Keywords {
			if strings.Contains(text, strings.ToLower(keyword)) {
				score += rule.Weight * 3
				reasons = append(reasons, "-"+rule.Name)
				break
			}
		}
	}

	port := portOf(c.Host)
	if port != "" && !eduPortAllow[port] {
		score += 3
		reasons = append(reasons, "+非标端口")
	}

	isEdu := isEduHost(c.Host, c.Org)
	if isEdu {
		score += 6
		reasons = append(reasons, "+教育资产")
	} else if srcType == "edusrc" {
		score -= 8
		reasons = append(reasons, "-非教育资产")
	}

	if score < 1 {
		score = 1
	}
	if score > 100 {
		score = 100
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "基线分")
	}
	return score, strings.Join(reasons, " "), isEdu
}

// portOf 从 host 串里取端口。
func portOf(host string) string {
	idx := strings.LastIndex(host, ":")
	if idx < 0 || idx == len(host)-1 {
		return ""
	}
	port := host[idx+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return port
}

// isEduHost 判断是否为教育资产。
func isEduHost(host, org string) bool {
	lowerHost := strings.ToLower(host)
	if strings.HasSuffix(lowerHost, ".edu.cn") || strings.HasSuffix(lowerHost, ".edu") {
		return true
	}
	combined := org + host
	for _, keyword := range []string{"大学", "学院", "学校", "教育厅", "教育局", "职业技术", "科学院", "研究院"} {
		if strings.Contains(combined, keyword) {
			return true
		}
	}
	return false
}

var schoolPattern = regexp.MustCompile(`([\p{Han}A-Za-z]{2,20}(?:大学|学院|学校|职业技术学院|中学|小学))`)

// extractSchool 从组织名 / 标题中提取学校名。
func extractSchool(text string) string {
	if match := schoolPattern.FindString(text); match != "" {
		return match
	}
	return ""
}

// countQueued 统计任务排队目标数。
func countQueued(taskID string) int {
	var n int64
	core.Db.Model(&model.Target{}).
		Where("task_id = ? AND status = ?", taskID, constant.TargetQueued).Count(&n)
	return int(n)
}

// existingHosts 返回任务内已有 host 集合。
func existingHosts(taskID string) map[string]bool {
	var hosts []string
	core.Db.Model(&model.Target{}).Where("task_id = ?", taskID).Pluck("host", &hosts)
	seen := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		seen[h] = true
	}
	return seen
}

// updateFofaConfig 更新任务的测绘进度配置并落库。
func updateFofaConfig(task *model.Task, updates map[string]any) {
	if task == nil {
		return
	}
	cfg := task.FofaConfig
	for key, value := range updates {
		switch key {
		case "cursor":
			cfg.Cursor = intOf(value)
		case "current_query":
			cfg.CurrentQuery = fmt.Sprintf("%v", value)
		case "fofa_exhausted":
			cfg.FofaExhausted = truthy(value)
		case "intent_query":
			cfg.IntentQuery = fmt.Sprintf("%v", value)
		case "intent_query_for":
			cfg.IntentQueryFor = fmt.Sprintf("%v", value)
		case "last_fofa_error":
			cfg.LastFofaError = fmt.Sprintf("%v", value)
		case "fofa_auth_fail_count":
			cfg.FofaAuthFailCount = intOf(value)
		case "daily_limit_count":
			cfg.DailyLimitCount = intOf(value)
		case "collector_phase":
			cfg.CollectorPhase = fmt.Sprintf("%v", value)
		case "collector_phase_text":
			cfg.CollectorPhaseText = fmt.Sprintf("%v", value)
		case "engine_fail_count":
			cfg.EngineFailCount = intOf(value)
		case "next_retry_at":
			if t, isTime := value.(time.Time); isTime {
				cfg.NextRetryAt = t
			}
		}
	}
	task.FofaConfig = cfg
	raw, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	core.Db.Model(&model.Task{}).Where("id = ?", task.ID).Update("fofa_config", string(raw))
}

// clearStalePhase 清理被中断留下的「正在入队」中间态。
func clearStalePhase(task *model.Task) {
	phase := task.FofaConfig.CollectorPhase
	text := task.FofaConfig.CollectorPhaseText
	if (phase == "enrich" || phase == "dispatch") && strings.Contains(text, "正在入队") {
		updateFofaConfig(task, map[string]any{
			"collector_phase":      "idle",
			"collector_phase_text": "队列充足，搜集待命",
		})
	}
}

// SortTargetsByPriority 按优先级降序排序（供 API 复用）。
func SortTargetsByPriority(targets []model.Target) {
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].IsTop != targets[j].IsTop {
			return targets[i].IsTop
		}
		return targets[i].PriorityScore > targets[j].PriorityScore
	})
}

// siteCollect 把用户给的单站目标拆成多条协作路线入队（对齐原版 collector._site_collect）。
//
// 先走手动清单清理（复用 buildManualCandidates：去备注/括号说明/补协议），
// 每个 host 按「缺失的开局路线」各建一条目标（侦察两条 + 主题五条开局并发），
// 靠唯一索引 ux_target_task_host(task_id, host, source) 与预载 have 防重复。
// 不入 seen：单站模式下同一 host 允许（也必须）存在多条来源不同的目标。
//
// 指定页面直打：用户逐行填写的往往是同一 host 下的不同页面（如 pikachu 的
// 45 个漏洞页）。固定路线只挂首个 URL，其余 URL 若不单独入队会被唯一索引
// 全部吞掉——「填了 45 个站点只扫第一个」实测踩坑。故按 host 分组后，每个
// 去重 URL 追加一条 site_uXX 目标，直打该页面。
func siteCollect(task *model.Task) int {
	candidates := buildManualCandidates(task.ManualTargets)
	if len(candidates) == 0 {
		return 0
	}
	routes := InitialRoutesFor(task)

	// 按 host 分组（保持首现顺序）。
	hostOrder := make([]string, 0, len(candidates))
	byHost := make(map[string][]Candidate)
	for _, c := range candidates {
		if _, ok := byHost[c.Host]; !ok {
			hostOrder = append(hostOrder, c.Host)
		}
		byHost[c.Host] = append(byHost[c.Host], c)
	}

	var rows []model.Target
	core.Db.Select("host", "source").Where("task_id = ?", task.ID).Find(&rows)
	have := make(map[string]map[string]bool, len(candidates))
	for _, row := range rows {
		if have[row.Host] == nil {
			have[row.Host] = map[string]bool{}
		}
		have[row.Host][row.Source] = true
	}

	added := 0
	pageTotal := 0
	now := time.Now()
	var newTargets []model.Target
	for _, host := range hostOrder {
		list := byHost[host]
		existing := have[host]

		// 1) 固定协作路线（挂在该 host 的首个 URL 上）。
		batch := make([]model.Target, 0, len(routes))
		for _, route := range routes {
			if existing[route.Source] {
				continue
			}
			batch = append(batch, model.Target{
				ID:             utils.UUID(),
				TaskID:         task.ID,
				URL:            list[0].URL,
				Host:           host,
				Source:         route.Source,
				PriorityScore:  route.Priority,
				PriorityReason: RouteReason(route),
				AuthContext:    MatchAuthBinding(list[0].URL, task.AuthBindings, task.ManualTargets),
				Status:         constant.TargetQueued,
				CreatedAt:      now,
				UpdatedAt:      now,
			})
		}
		if len(batch) > 0 {
			result := core.Db.Clauses(clause.OnConflict{DoNothing: true}).Create(&batch)
			if result.Error != nil {
				global.Log.Warnf("单站协作路线入队失败: %v", result.Error)
			} else {
				added += int(result.RowsAffected)
				newTargets = append(newTargets, batch...)
			}
			if existing == nil {
				existing = map[string]bool{}
				have[host] = existing
			}
			for _, route := range routes {
				existing[route.Source] = true
			}
		}

		// 2) 指定页面直打：同 host 下每个去重 URL 一条 site_uXX。
		urlSeen := make(map[string]bool, len(list))
		for _, c := range list {
			key := strings.ToLower(c.URL)
			if urlSeen[key] {
				continue
			}
			urlSeen[key] = true
			pageTotal++
			source := UserPageSource(pageTotal)
			if source == "" || existing[source] {
				continue // 超出上限或同序号目标已存在（防重复入队）
			}
			page := model.Target{
				ID:             utils.UUID(),
				TaskID:         task.ID,
				URL:            c.URL,
				Host:           host,
				Source:         source,
				PriorityScore:  userPageRoute.Priority,
				PriorityReason: userPageReason(c.URL),
				AuthContext:    MatchAuthBinding(c.URL, task.AuthBindings, task.ManualTargets),
				Status:         constant.TargetQueued,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			result := core.Db.Clauses(clause.OnConflict{DoNothing: true}).Create(&page)
			if result.Error != nil {
				global.Log.Warnf("指定页面目标入队失败: %v", result.Error)
				continue
			}
			added += int(result.RowsAffected)
			newTargets = append(newTargets, page)
			existing[source] = true
		}
	}
	if added > 0 {
		EmitInfo(task.ID, "collector", "site_collect",
			fmt.Sprintf("单站协作：%d 个站点按 %d 条路线开局，另拆 %d 个指定页面对象（共入队 %d 条目标）",
				len(hostOrder), len(routes), pageTotal, added),
			map[string]any{"hosts": len(hostOrder), "routes": len(routes),
				"pages": pageTotal, "enqueued": added})
		// 异步补抓页面标题（手动/指定页面目标 title 恒空，看板卡片只会显示「无标题」）。
		go enrichTargetTitles(task.ID, newTargets)
	}
	return added
}

// enrichTargetTitles 并发抓取目标页面的 <title> 填充 target.title（仅空标题）。
// 异步执行：入队路径在主循环 tick 里同步跑，绝不能做慢 HTTP。
func enrichTargetTitles(taskID string, targets []model.Target) {
	client := &http.Client{Timeout: 8 * time.Second}
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var filled int32
	for _, t := range targets {
		if strings.TrimSpace(t.URL) == "" {
			continue
		}
		wg.Add(1)
		go func(t model.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			title := extractHTMLTitle(fetchPageBody(client, t.URL))
			if title == "" {
				return
			}
			res := core.Db.Model(&model.Target{}).
				Where("id = ? AND (title IS NULL OR title = '')", t.ID).
				Update("title", utils.Truncate(title, 480))
			if res.Error == nil && res.RowsAffected > 0 {
				atomic.AddInt32(&filled, 1)
			}
		}(t)
	}
	wg.Wait()
	if n := atomic.LoadInt32(&filled); n > 0 {
		EmitInfo(taskID, "collector", "site_titles",
			fmt.Sprintf("已抓取 %d 个目标的页面标题", n),
			map[string]any{"filled": n})
	}
}

// fetchPageBody 只读抓取页面内容（限 256KB，够提取 <title> 即可）。
func fetchPageBody(client *http.Client, pageURL string) string {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return ""
	}
	return string(body)
}
