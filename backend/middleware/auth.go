package middleware

import (
	"crypto/subtle"
	"strings"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/result"
	"AiSRC/utils"

	"github.com/gin-gonic/gin"
)

// Identity 鉴权后的请求身份。
type Identity struct {
	Role        string
	Username    string
	TokenSource string
}

var readMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// authDisabled 判断是否关闭了鉴权（未配置口令与任何令牌）。
func authDisabled() bool {
	t := config.AppConfig.Token
	return strings.TrimSpace(t.Password) == "" &&
		strings.TrimSpace(t.FullToken) == "" &&
		strings.TrimSpace(t.ReadToken) == "" &&
		strings.TrimSpace(t.ObserverToken) == ""
}

// AuthDisabled 对外暴露的「是否关闭鉴权」判定（WebSocket 等非标准 HTTP 入口复用）。
func AuthDisabled() bool { return authDisabled() }

// ResolveRoleOf 按请求上下文解析身份角色（WebSocket 握手复用）。
func ResolveRoleOf(c *gin.Context) string {
	return ResolveRole(ExtractToken(c))
}

// ExtractToken 按优先级提取令牌，与原版 AutoHunter 的 token_from_headers 保持一致：
// X-Autohunter-Token（兼容别名 X-Aisrc-Token）→ Authorization: Bearer → query token → Cookie。
func ExtractToken(c *gin.Context) string {
	for _, header := range []string{"X-Aisrc-Token", "X-Autohunter-Token"} {
		if value := strings.TrimSpace(c.GetHeader(header)); value != "" {
			return value
		}
	}
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], config.AppConfig.Token.Header) {
			return strings.TrimSpace(parts[1])
		}
		if len(parts) == 1 {
			return authHeader
		}
	}
	if value := strings.TrimSpace(c.Query("token")); value != "" {
		return value
	}
	// Cookie 名与原版一致（ah_api_token）；aisrc_token 作为本项目自定义名的兼容别名。
	for _, name := range []string{"ah_api_token", "aisrc_token"} {
		if cookie, err := c.Cookie(name); err == nil {
			if value := strings.TrimSpace(cookie); value != "" {
				return value
			}
		}
	}
	return ""
}

// ResolveIdentity 解析令牌对应的角色与用户名。
//
// 判定顺序与原版 AutoHunter 的 resolve_role 一致：全权限 → 只读 → 观摩 → JWT。
// 静态令牌使用常量时间比较，避免通过响应耗时逐字节猜解令牌。
//
// ⚠️ 令牌携带的用户名必须一并返回：`Identity.Username` 曾长期无人赋值，
// 导致 /api/auth/status 的 username 恒为空（前端顶栏永远显示「未登录」）、
// 注销也永远只作用于兜底的 admin。role 与 username 必须同源解析。
func ResolveIdentity(token string) (role string, username string) {
	t := config.AppConfig.Token
	if authDisabled() {
		return constant.RoleFull, ""
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return constant.RoleNone, ""
	}
	if ft := strings.TrimSpace(t.FullToken); ft != "" && secureEqual(token, ft) {
		return constant.RoleFull, ""
	}
	if rt := strings.TrimSpace(t.ReadToken); rt != "" && secureEqual(token, rt) {
		return constant.RoleReadonly, ""
	}
	if ot := strings.TrimSpace(t.ObserverToken); ot != "" && secureEqual(token, ot) {
		return constant.RoleObserver, ""
	}
	claims, err := core.ValidateToken(token)
	if err != nil {
		return constant.RoleNone, ""
	}
	role = claims.Role
	if role == "" {
		role = constant.RoleFull
	}
	return role, claims.Username
}

// ResolveRole 解析令牌对应的角色。返回 constant.RoleNone 表示未认证。
//
// 保留原签名（WebSocket 握手等既有调用方复用），内部委托给 ResolveIdentity。
func ResolveRole(token string) string {
	role, _ := ResolveIdentity(token)
	return role
}

// secureEqual 常量时间字符串比较（长度不同直接返回 false，长度本身不是秘密）。
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// AuthMiddleware 统一鉴权与角色判定。
// 规则：未认证 → 401；非只读方法要求 full 角色，否则 403。
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c)
		role, username := ResolveIdentity(token)

		if role == constant.RoleNone {
			// 文案与原版 AutoHunter 一致：{"detail": "需要 AiSRC 访问令牌"} + 401
			LogAuthFailure(c, "missing_or_invalid_token")
			result.AbortWithMsg(c, result.Unauthorized, "需要 AiSRC 访问令牌")
			return
		}

		if role != constant.RoleFull && !readMethods[c.Request.Method] {
			result.AbortWithMsg(c, result.Forbidden, WriteDeniedMsg(role))
			return
		}

		identity := &Identity{Role: role, Username: username, TokenSource: tokenSource(c)}
		c.Set(constant.ContextKeyUserObj, identity)
		c.Next()
	}
}

// OptionalAuthMiddleware 解析身份但不拦截（用于 /api/auth/status 等）。
//
// ⚠️ 这个中间件必须真正挂到路由上才有意义：漏挂时 status 拿不到身份，
// 会恒返回 role=none，前端每次刷新都判定「未登录」。
func OptionalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, username := ResolveIdentity(ExtractToken(c))
		c.Set(constant.ContextKeyUserObj, &Identity{Role: role, Username: username, TokenSource: tokenSource(c)})
		c.Next()
	}
}

// CurrentIdentity 读取当前请求身份。
func CurrentIdentity(c *gin.Context) *Identity {
	if value, exists := c.Get(constant.ContextKeyUserObj); exists {
		if identity, ok := value.(*Identity); ok {
			return identity
		}
	}
	return &Identity{Role: constant.RoleNone}
}

// CurrentRole 读取当前角色。
func CurrentRole(c *gin.Context) string {
	return CurrentIdentity(c).Role
}

// IsObserver 是否观摩角色。
func IsObserver(c *gin.Context) bool {
	return CurrentRole(c) == constant.RoleObserver
}

// IsFull 是否全权限。
func IsFull(c *gin.Context) bool {
	return CurrentRole(c) == constant.RoleFull
}

// RequireFull 写操作守卫：非全权限直接 403。
func RequireFull(c *gin.Context) bool {
	if IsFull(c) {
		return true
	}
	result.AbortWithMsg(c, result.Forbidden, WriteDeniedMsg(CurrentRole(c)))
	return false
}

// ForbidObserver 观摩角色守卫：用于禁止查看敏感轨迹等。
func ForbidObserver(c *gin.Context) bool {
	if IsObserver(c) {
		result.AbortWithMsg(c, result.Forbidden, "观摩令牌不允许查看该内容")
		return false
	}
	return true
}

// WriteDeniedMsg 写操作被拒时的提示文案（与原版 AutoHunter 的措辞一致）。
func WriteDeniedMsg(role string) string {
	if role == constant.RoleObserver {
		return "观摩令牌不允许访问敏感信息或执行写操作"
	}
	return "只读令牌不允许此操作"
}

func tokenSource(c *gin.Context) string {
	if c.GetHeader("X-Aisrc-Token") != "" || c.GetHeader("X-Autohunter-Token") != "" {
		return "header"
	}
	if c.GetHeader("Authorization") != "" {
		return "authorization"
	}
	if c.Query("token") != "" {
		return "query"
	}
	for _, name := range []string{"ah_api_token", "aisrc_token"} {
		if value, err := c.Cookie(name); err == nil && value != "" {
			return "cookie"
		}
	}
	return "none"
}

// LogAuthFailure 记录鉴权失败（不打印令牌明文）。
// 日志器可能尚未初始化（如单元测试或极早期启动阶段），此处必须容忍 nil。
func LogAuthFailure(c *gin.Context, reason string) {
	if global.Log == nil {
		return
	}
	global.Log.Warnf("鉴权失败 path=%s reason=%s ip=%s", c.Request.URL.Path, reason, utils.ClientIP(c))
}
