package model

import (
	"time"
)

// LLMSettings 系统级模型设置。任务级配置可覆盖此处。
type LLMSettings struct {
	Mode        string        `json:"mode"` // single / pool
	BaseURL     string        `json:"base_url"`
	APIKey      string        `json:"api_key"`
	Model       string        `json:"model"`
	Protocol    string        `json:"protocol"`
	Temperature float64       `json:"temperature"`
	Providers   []LLMProvider `json:"providers"`
}

// FofaSettings 系统级测绘设置。
type FofaSettings struct {
	Key               string `json:"key"`
	BaseURL           string `json:"base_url"`
	MaxPages          int    `json:"max_pages"`
	PageSize          int    `json:"page_size"`
	DefaultIntentMode string `json:"default_intent_mode"`
}

// EngineItem 单个搜索引擎的设置。
type EngineItem struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	BaseURL string `json:"base_url"`
	Enabled bool   `json:"enabled"`
}

// DefaultsSettings 系统默认调度参数。
type DefaultsSettings struct {
	Concurrency         int     `json:"concurrency"`
	DeepenCap           int     `json:"deepen_cap"`
	SkipScoreThreshold  float64 `json:"skip_score_threshold"`
	WorkerPromptVersion string  `json:"worker_prompt_version"`
	Engine              string  `json:"engine"`
	// 三个开关用 *bool：nil = 存量配置里没有该键（GORM serializer:json 整段存储，
	// bool 无法区分「未配置」与「显式关」，*bool 才能保住缺省语义）。
	// AutoKillsweep nil 视为 true（原版缺省开）；Shell / Verbose nil 视为 false（安全缺省）。
	AutoKillsweep *bool `json:"auto_killsweep"`
	ShellEnabled  *bool `json:"shell_enabled"`
	VerboseEvents *bool `json:"verbose_events"`
}

// EffectiveAutoKillsweep 复审通过后自动通杀（缺省开，对齐原版 auto_killsweep=True）。
func (d DefaultsSettings) EffectiveAutoKillsweep() bool {
	return d.AutoKillsweep == nil || *d.AutoKillsweep
}

// EffectiveShellEnabled 是否允许 run_shell 执行（缺省关，安全敏感开关）。
func (d DefaultsSettings) EffectiveShellEnabled() bool {
	return d.ShellEnabled != nil && *d.ShellEnabled
}

// EffectiveVerboseEvents 是否把噪音事件（refill/skip 等）落库（缺省关）。
func (d DefaultsSettings) EffectiveVerboseEvents() bool {
	return d.VerboseEvents != nil && *d.VerboseEvents
}

// UISettings 界面偏好（服务端为准，前端只做本地缓存）。
type UISettings struct {
	Theme         string  `json:"theme"` // light / dark
	AccentHue     int     `json:"accentHue"`
	WallpaperKind string  `json:"wallpaperKind"` // none / url / file
	WallpaperURL  string  `json:"wallpaperUrl"`
	WallpaperFit  string  `json:"wallpaperFit"` // cover / contain
	WallpaperDim  float64 `json:"wallpaperDim"`
	Saved         bool    `json:"saved"`
}

// ProxyItem 单条代理配置。
type ProxyItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // http / https / socks5
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
}

// Display 返回可读的代理地址（密码不下发）。
func (p ProxyItem) Display() string {
	scheme := p.Protocol
	if scheme == "" {
		scheme = "http"
	}
	if p.Username != "" {
		return scheme + "://" + p.Username + "@" + p.Host + ":" + itoa(p.Port)
	}
	return scheme + "://" + p.Host + ":" + itoa(p.Port)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ProxySettings 代理池配置。
type ProxySettings struct {
	Enabled bool        `json:"enabled"`
	Proxies []ProxyItem `json:"proxies"`
}

// PersonaSettings AI 人格配置：追加到各 Agent 系统提示词尾部（worker/reviewer）。
type PersonaSettings struct {
	Enabled    bool   `json:"enabled"`
	Name       string `json:"name"`      // 人格名（如「严谨的渗透老手」）
	Style      string `json:"style"`     // 口吻/称谓（如「直接、冷静、以证据说话」）
	Principles string `json:"principles"` // 行为准则（多行文本）
}

// SkillItem 单条技能：可复用的领域知识包，启用后注入系统提示词
// （参考 deepseek-harness 的技能化设计：技能=名字+正文，按开关选择性生效）。
type SkillItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Enabled bool   `json:"enabled"`
}

// SkillsSettings 技能配置。
type SkillsSettings struct {
	Enabled bool        `json:"enabled"`
	Items   []SkillItem `json:"items"`
}

// ImaSettings ima 知识库检索配置（兼容任意返回 JSON 的检索端点）。
type ImaSettings struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"` // 检索 API 端点（POST query）
	APIKey  string `json:"api_key"`
	RepoID  string `json:"repo_id"` // 知识库/知识引擎标识
	TopK    int    `json:"top_k"`
}

// KaliSettings Kali 渗透机 SSH 集成配置。
type KaliSettings struct {
	Enabled    bool     `json:"enabled"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Username   string   `json:"username"`
	AuthType   string   `json:"auth_type"` // password / key
	Password   string   `json:"password"`
	PrivateKey string   `json:"private_key"`
	Categories []string `json:"categories"` // 启用的工具分类 key
}

// KaliCategory Kali 工具分类（key/中文名/说明，供提示词与设置页共用）。
type KaliCategory struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}

// KaliCategories 14 类 Kali 工具分类（用户口径）。
var KaliCategories = []KaliCategory{
	{"info_gathering", "信息收集", "whois/dig/nmap 主机发现与端口扫描、子域枚举、指纹识别"},
	{"vuln_analysis", "脆弱性分析", "nikto/nucleus/nmap --script vuln 等漏洞扫描与评估"},
	{"web_analysis", "Web 应用分析", "burpsuite 类代理分析、dirb/gobuster 目录爆破、CMS 识别"},
	{"database_assessment", "数据库评估", "sqlmap 数据库注入评估、默认凭据探测"},
	{"password_attacks", "密码攻击", "hydra/medusa/john/hashcat 在线离线口令审计"},
	{"wireless_attacks", "无线攻击", "aircrack-ng 套件等无线安全评估"},
	{"reverse_engineering", "逆向工程", "gdb/radare2/strings 二进制分析与反汇编"},
	{"exploitation", "漏洞利用", "searchsploit/metasploit 漏洞利用框架"},
	{"sniffing_spoofing", "嗅探与欺骗", "tcpdump/wireshark/tcpdump 流量分析、arpspoof"},
	{"post_exploitation", "后渗透", "权限维持、横向移动、信息收集深化（仅授权范围内）"},
	{"forensics", "取证", "binwalk/foremost/autopsy 取证分析"},
	{"reporting_tools", "报告工具", "pipal/faraday 等结果记录与报告辅助"},
	{"stress_testing", "压力测试", "授权范围内的压测（注意：仍禁止 DoS 业务系统）"},
	{"hardware_hacking", "硬件黑客", "硬件接口与固件分析工具"},
}

// SystemSettings 全局系统配置（单行 id=global）。
type SystemSettings struct {
	ID        string                `gorm:"primaryKey;size:32" json:"id"`
	LLM       LLMSettings           `gorm:"serializer:json" json:"llm"`
	Fofa      FofaSettings          `gorm:"serializer:json" json:"fofa"`
	Engines   map[string]EngineItem `gorm:"serializer:json" json:"engines"`
	Defaults  DefaultsSettings      `gorm:"serializer:json" json:"defaults"`
	UI        UISettings            `gorm:"serializer:json" json:"ui"`
	Proxy     ProxySettings         `gorm:"serializer:json" json:"proxy"`
	Persona   PersonaSettings       `gorm:"serializer:json" json:"persona"`
	Skills    SkillsSettings        `gorm:"serializer:json" json:"skills"`
	Ima       ImaSettings           `gorm:"serializer:json" json:"ima"`
	Kali      KaliSettings          `gorm:"serializer:json" json:"kali"`
	UpdatedAt time.Time             `json:"-"`
}

// TableName 指定表名。
func (SystemSettings) TableName() string { return "aisrc_system_settings" }

// Admin 平台账号（单账号模型，与 GinBlog 的双角色体系保持同构）。
type Admin struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Password     string    `gorm:"size:128;not null" json:"-"`
	NickName     string    `gorm:"size:64" json:"nick_name"`
	TokenVersion int       `gorm:"default:0" json:"-"`
	CreatedAt    time.Time `json:"-"`
	UpdatedAt    time.Time `json:"-"`
}

// TableName 指定表名。
func (Admin) TableName() string { return "aisrc_admin" }

// AdminVo 令牌载荷中的身份信息。
type AdminVo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}
