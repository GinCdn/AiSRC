package constant

// 上下文与通用常量。
const (
	// ContextKeyUserObj 鉴权后写入 gin.Context 的身份对象。
	ContextKeyUserObj = "authedUserObj"

	// Version 全局系统版本号。
	Version = "1.0.1"

	// AppName 应用名。
	AppName = "AiSRC"

	// AppDescription 应用描述。
	AppDescription = "多 Agent 协同的自动化漏洞挖掘平台"

	// AppAuthor 项目作者（沿用原版 AutoHunter 元信息）。
	AppAuthor = "StanleyNull"

	// AppLicense 开源协议。
	AppLicense = "Apache-2.0"

	// Credit 页脚署名。
	Credit = "Powered By StanleyNull"

	// FaviconSVG 极简品牌图标：瞄准镜 reticle，与原版一致。
	FaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none" ` +
		`stroke="#3b9eff" stroke-width="2.2" stroke-linecap="round">` +
		`<circle cx="16" cy="16" r="9"/>` +
		`<path d="M16 2.5v6M16 23.5v6M2.5 16h6M23.5 16h6"/>` +
		`<circle cx="16" cy="16" r="2" fill="#3b9eff" stroke="none"/>` +
		`</svg>`
)

// 角色定义。
const (
	RoleFull     = "full"     // 全权限
	RoleReadonly = "readonly" // 只读
	RoleObserver = "observer" // 观摩（敏感信息打码）
	RoleNone     = "none"     // 未认证
)

// 任务状态。
const (
	TaskCreated = "created"
	TaskRunning = "running"
	TaskIdle    = "idle"
	TaskPaused  = "paused"
	TaskStopped = "stopped"
)

// 目标状态。
const (
	TargetQueued   = "queued"
	TargetAssigned = "assigned"
	TargetScanning = "scanning"
	TargetDone     = "done"
	TargetSkipped  = "skipped"
	TargetDead     = "dead"
)

// 目标终态判定。
var TargetFinishedStatuses = []string{TargetDone, TargetDead}
var TargetOpenStatuses = []string{TargetQueued, TargetAssigned, TargetScanning}

// Finder 审核结论。
const (
	VerdictAccepted = "accepted"
	VerdictIgnored  = "ignored"
	VerdictDeepen   = "deepen"
)

// 用户复审状态。
const (
	UserPending   = "pending"
	UserPassed    = "passed"
	UserRejected  = "rejected"
	UserDeepening = "deepening"
)

// 漏洞状态。
const (
	FindingPendingReview = "pending_review"
	FindingReviewed      = "reviewed"
	FindingSuperseded    = "superseded"
)

// 通杀状态。
const (
	KillsweepAnalyzing = "analyzing"
	KillsweepDone      = "done"
	KillsweepFailed    = "failed"
	KillsweepCancelled = "cancelled"
	KillsweepInvalid   = "invalid"
)

// 情报类型。
const (
	IntelCred        = "cred"
	IntelFingerprint = "fingerprint"
	IntelEndpoint    = "endpoint"
	IntelProfile     = "profile"
)

// 数值上限。
const (
	TaskConcurrencyMax = 32
	DeepenCapDefault   = 2
	DeepenCapMax       = 10
	MaxPagesMax        = 200
	PageSizeMax        = 1000
	ProxyMaxItems      = 200
	IntelMsgCap        = 100
)

// SecretMask 密钥脱敏占位符。
const SecretMask = "••••••••"
