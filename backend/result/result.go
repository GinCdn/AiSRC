package result

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 本包负责响应输出，格式与原版 AutoHunter（FastAPI）保持逐字节兼容：
//
//	成功：直接输出业务数据本体（裸 JSON 对象 / 数组），HTTP 200，无外层包装；
//	失败：{"detail": "..."}，HTTP 状态码为真实错误码（400/401/403/404/409/500/507）。
//
// 这样做的好处是前端契约与原版完全一致：原版 Vue 前端、任何按 AutoHunter
// 接口文档编写的调用方都可以零改动接入。

// Detail 错误响应体。字段名 detail 与原版 FastAPI 的 HTTPException 对齐。
type Detail struct {
	Detail string `json:"detail"`
}

// Success 成功响应：输出业务数据本体。
func Success(c *gin.Context, data interface{}) {
	if data == nil {
		data = gin.H{}
	}
	c.JSON(http.StatusOK, data)
}

// Failed 失败响应：{"detail": msg} + 真实 HTTP 状态码。
func Failed(c *gin.Context, code int, subCode SubCode) {
	FailedWithMsg(c, code, GetMsg(code, subCode))
}

// FailedWithMsg 支持自定义消息的失败响应。
func FailedWithMsg(c *gin.Context, code int, msg string) {
	if msg == "" {
		msg = GetMsg(code, SubDefault)
	}
	c.JSON(httpStatus(code), Detail{Detail: msg})
}

// FailedWithPayload 在 {"detail": msg} 基础上附加额外字段。
//
// 原版契约只要求 detail + 真实状态码；这里按「响应字段为超集」的既有做法附加
// 结构化的引导信息（如验证码要求），`detail` 始终存在且不可被覆盖，
// 因此按原版字段编写的调用方不受影响。
func FailedWithPayload(c *gin.Context, code int, msg string, extra gin.H) {
	if msg == "" {
		msg = GetMsg(code, SubDefault)
	}
	body := gin.H{"detail": msg}
	for key, value := range extra {
		if key == "detail" {
			continue
		}
		body[key] = value
	}
	c.JSON(httpStatus(code), body)
}

// Abort 输出失败响应并终止后续处理。
func Abort(c *gin.Context, code int, subCode SubCode) {
	Failed(c, code, subCode)
	c.Abort()
}

// AbortWithMsg 输出自定义消息的失败响应并终止后续处理。
func AbortWithMsg(c *gin.Context, code int, msg string) {
	FailedWithMsg(c, code, msg)
	c.Abort()
}

// httpStatus 把业务主码映射为真实 HTTP 状态码。
// 主码常量本身就是按 HTTP 语义定义的，这里只做越界兜底。
func httpStatus(code int) int {
	switch code {
	case http.StatusOK,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusConflict,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusInsufficientStorage:
		return code
	default:
		return http.StatusInternalServerError
	}
}

// PageData 分页响应体（与原版一致：items/total/limit/offset/has_more）。
type PageData struct {
	Items   interface{} `json:"items"`
	Total   int64       `json:"total"`
	Limit   int         `json:"limit"`
	Offset  int         `json:"offset"`
	HasMore bool        `json:"has_more"`
}

// Page 构造分页响应。
func Page(items interface{}, total int64, limit, offset int) PageData {
	count := 0
	if list, ok := items.([]interface{}); ok {
		count = len(list)
	}
	return PageData{
		Items:   items,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: int64(offset+count) < total,
	}
}

// PageWithLen 已知本次返回条数时构造分页响应。
func PageWithLen(items interface{}, total int64, limit, offset, length int) PageData {
	return PageData{
		Items:   items,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: int64(offset+length) < total,
	}
}
