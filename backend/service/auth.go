package service

import (
	"errors"
	"fmt"
	"strings"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/middleware"
	"AiSRC/model"
	"AiSRC/utils"
)

// AuthStatus 当前鉴权状态（前端用于判断是否需要登录）。
//
// auth_required 与原版 AutoHunter 同名同义（原版前端读取该字段）；
// auth_enabled 为等价别名，便于其它调用方沿用。
type AuthStatus struct {
	AuthRequired bool   `json:"auth_required"`
	AuthEnabled  bool   `json:"auth_enabled"`
	PasswordSet  bool   `json:"password_set"`
	FullTokenSet bool   `json:"full_token_set"`
	ReadTokenSet bool   `json:"read_token_set"`
	ObsTokenSet  bool   `json:"observer_token_set"`
	Role         string `json:"role"`
	RoleLabel    string `json:"role_label"`
	Username     string `json:"username"`
	ExpiresIn    int64  `json:"expires_in"`
	Version      string `json:"version"`
	// LoginFailures / CaptchaRequired 为超集字段：前端据此在打开登录框时
	// 就决定是否直接展示验证码（刷新后不会把「已触发验证码」的状态丢掉）。
	LoginFailures   int  `json:"login_failures"`
	CaptchaRequired bool `json:"captcha_required"`
	CaptchaDigits   int  `json:"captcha_digits"`
}

// BuildAuthStatus 组装鉴权状态。
func BuildAuthStatus(role string, username string) *AuthStatus {
	token := config.AppConfig.Token
	required := !middleware.AuthDisabled()
	return &AuthStatus{
		AuthRequired: required,
		AuthEnabled:  required,
		PasswordSet:  strings.TrimSpace(token.Password) != "",
		FullTokenSet: strings.TrimSpace(token.FullToken) != "",
		ReadTokenSet: strings.TrimSpace(token.ReadToken) != "",
		ObsTokenSet:  strings.TrimSpace(token.ObserverToken) != "",
		Role:         role,
		RoleLabel:    RoleLabel(role),
		Username:     username,
		ExpiresIn:    core.TokenExpireSeconds(),
		Version:      constant.Version,
	}
}

// RoleLabel 角色中文名。
func RoleLabel(role string) string {
	switch role {
	case constant.RoleFull:
		return "全权限"
	case constant.RoleReadonly:
		return "只读"
	case constant.RoleObserver:
		return "观摩"
	default:
		return "未认证"
	}
}

// LoginResult 登录结果。
type LoginResult struct {
	Token     string `json:"token"`
	Role      string `json:"role"`
	RoleLabel string `json:"role_label"`
	Username  string `json:"username"`
	ExpiresIn int64  `json:"expires_in"`
}

// ErrPasswordMismatch 账号或密码错误。
//
// 用哨兵错误而非字符串匹配，避免上层依赖提示文案（文案可改，语义不可改）。
var ErrPasswordMismatch = errors.New("账号或密码错误")

// Login 校验账号密码并签发令牌。
//
// 用户名与密码同为**必校验凭据**：用户名取自 `token.username`（未配置时回落
// `admin`），密码取自 `token.password`。两者任一不符都返回同一个哨兵错误，
// 不区分「用户名错」还是「密码错」，避免被用来枚举账号。
// 校验通过后按用户名落地 Admin 记录（首次登录自动建号）。
func Login(password, username string) (*LoginResult, error) {
	// 输入先做统一净化，阻止日志注入与奇怪载荷。
	password = utils.SanitizeSecretText(strings.TrimSpace(password))
	username = strings.TrimSpace(username)

	if middleware.AuthDisabled() {
		return nil, fmt.Errorf("当前未启用鉴权（未配置登录口令与令牌），无需登录")
	}
	if strings.TrimSpace(config.AppConfig.Token.Password) == "" {
		return nil, fmt.Errorf("未配置登录密码，无法登录")
	}
	expectedUser := strings.TrimSpace(config.AppConfig.Token.Username)
	if expectedUser == "" {
		expectedUser = "admin"
	}
	if username != expectedUser || password != config.AppConfig.Token.Password {
		return nil, ErrPasswordMismatch
	}

	admin, err := ensureAdmin(username)
	if err != nil {
		return nil, err
	}
	token, err := core.GenerateToken(admin.Username, constant.RoleFull, admin.TokenVersion)
	if err != nil {
		return nil, fmt.Errorf("签发令牌失败: %v", err)
	}
	global.Log.Infof("用户 %s 登录成功", admin.Username)
	return &LoginResult{
		Token:     token,
		Role:      constant.RoleFull,
		RoleLabel: RoleLabel(constant.RoleFull),
		Username:  admin.Username,
		ExpiresIn: core.TokenExpireSeconds(),
	}, nil
}

// Logout 注销：递增令牌版本，使已签发令牌全部失效。
func Logout(username string) error {
	var admin model.Admin
	if err := core.Db.First(&admin, "username = ?", username).Error; err != nil {
		return fmt.Errorf("账号不存在")
	}
	if err := core.Db.Model(&model.Admin{}).Where("id = ?", admin.ID).
		Update("token_version", admin.TokenVersion+1).Error; err != nil {
		return err
	}
	global.Log.Infof("用户 %s 已注销，令牌版本号 +1", username)
	return nil
}

// ensureAdmin 确保账号存在（首次登录自动建号，与 GinBlog 的初始化逻辑同构）。
func ensureAdmin(username string) (*model.Admin, error) {
	var admin model.Admin
	err := core.Db.First(&admin, "username = ?", username).Error
	if err == nil {
		return &admin, nil
	}
	admin = model.Admin{
		Username: username,
		Password: utils.SecretRef(config.AppConfig.Token.Password),
		NickName: "管理员",
	}
	if err := core.Db.Create(&admin).Error; err != nil {
		return nil, fmt.Errorf("创建账号失败: %v", err)
	}
	return &admin, nil
}

// ValidateTokenRole 校验令牌并返回角色与用户名。
func ValidateTokenRole(token string) (string, string) {
	claims, err := core.ValidateToken(token)
	if err != nil {
		return constant.RoleNone, ""
	}
	role := claims.Role
	if role == "" {
		role = constant.RoleFull
	}
	return role, claims.Username
}
