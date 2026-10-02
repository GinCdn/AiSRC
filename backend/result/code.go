package result

// 主状态码（与标准 HTTP 状态码语义对齐）。
const (
	StatusSuccess    = 200 // 成功
	BadRequest       = 400 // 参数错误
	Unauthorized     = 401 // 未授权
	Forbidden        = 403 // 权限不足
	NotFound         = 404 // 资源不存在
	MethodNotAllowed = 405 // 方法不允许
	Conflict         = 409 // 资源冲突
	TooManyRequests  = 429 // 请求过于频繁
	InternalError    = 500 // 服务器错误
	Insufficient     = 507 // 存储空间不足
)

// SubCode 子码：同一主状态码下的细分场景。
type SubCode string

const (
	SubDefault SubCode = "" // 默认

	// 400 子场景
	SubMissingParam  SubCode = "missing_param"
	SubInvalidFormat SubCode = "invalid_format"
	SubInvalidState  SubCode = "invalid_state"

	// 401 子场景
	SubNoAuthInfo   SubCode = "no_auth"
	SubInvalidToken SubCode = "invalid_token"
	SubTokenExpired SubCode = "expired_token"
	SubPwdError     SubCode = "pwd_error"

	// 403 子场景
	NoPermission SubCode = "no_permission"

	// 404 子场景
	SubTaskNotFound     SubCode = "task_not_found"
	SubTargetNotFound   SubCode = "target_not_found"
	SubFindingNotFound  SubCode = "finding_not_found"
	SubReviewNotFound   SubCode = "review_not_found"
	SubRecordNotFound   SubCode = "record_not_found"
	SubResourceNotFound SubCode = "resource_not_found"

	// 405 子场景
	SubMethodNotAllowed SubCode = "method_not_allowed"

	// 409 子场景
	SubAlreadyExists SubCode = "already_exists"
	SubBusy          SubCode = "busy"

	// 500 子场景
	SubDbError    SubCode = "db_error"
	SubQueryError SubCode = "query_error"
	SubWriteError SubCode = "write_error"
	SubLLMError   SubCode = "llm_error"

	// 507 子场景
	SubDiskFull SubCode = "disk_full"
)

// msgMap 消息映射表。
var msgMap = map[int]map[SubCode]string{
	StatusSuccess: {
		SubDefault: "成功",
	},
	BadRequest: {
		SubDefault:       "参数错误",
		SubMissingParam:  "缺少必填参数",
		SubInvalidFormat: "参数格式无效",
		SubInvalidState:  "当前状态不允许该操作",
	},
	Unauthorized: {
		SubDefault:      "未授权访问",
		SubNoAuthInfo:   "请求头 Authorization 格式错误",
		SubInvalidToken: "令牌无效",
		SubTokenExpired: "令牌已过期",
		SubPwdError:     "口令错误",
	},
	Forbidden: {
		SubDefault:   "权限不足",
		NoPermission: "当前角色不允许执行该操作",
	},
	NotFound: {
		SubDefault:          "资源不存在",
		SubTaskNotFound:     "任务不存在",
		SubTargetNotFound:   "目标不存在",
		SubFindingNotFound:  "漏洞不存在",
		SubReviewNotFound:   "审核记录不存在",
		SubRecordNotFound:   "记录不存在",
		SubResourceNotFound: "资源不存在",
	},
	MethodNotAllowed: {
		SubDefault:          "请求方法不被允许",
		SubMethodNotAllowed: "请求方法不被允许",
	},
	Conflict: {
		SubDefault:       "资源冲突",
		SubAlreadyExists: "记录已存在",
		SubBusy:          "操作正在进行中",
	},
	InternalError: {
		SubDefault:    "服务器内部错误",
		SubDbError:    "数据库操作失败",
		SubQueryError: "查询失败",
		SubWriteError: "数据写入失败",
		SubLLMError:   "模型调用失败",
	},
	Insufficient: {
		SubDefault:  "存储空间不足",
		SubDiskFull: "磁盘剩余空间不足",
	},
}

// GetMsg 获取消息（主码 + 子码）。
func GetMsg(code int, subCode SubCode) string {
	if subMap, ok := msgMap[code]; ok {
		if msg, ok := subMap[subCode]; ok {
			return msg
		}
		return subMap[SubDefault]
	}
	return "未知错误"
}
