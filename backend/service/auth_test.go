package service

import (
	"errors"
	"testing"

	"AiSRC/config"
)

// TestLoginChecksUsernameAndPassword 用户名与密码都是必校验凭据。
//
// 回归背景：Login 早期**只比对密码**，用户名填任何值都能通过，并且会按该名字
// 自动建号 —— 「用户名」实际上是摆设，任意名字 + 正确密码即可登录。
//
// 用例选取的都是在「凭据比对」阶段就会拒绝的组合，因此不需要数据库即可断言；
// 而比对恰好发生在 ensureAdmin 之前，正好覆盖本次改动的位置。
func TestLoginChecksUsernameAndPassword(t *testing.T) {
	old := config.AppConfig
	t.Cleanup(func() { config.AppConfig = old })

	config.AppConfig.Token.Password = "secret-password"
	config.AppConfig.Token.Username = "aisrc-admin"

	cases := []struct {
		name     string
		username string
		password string
	}{
		{name: "用户名不符", username: "someone-else", password: "secret-password"},
		{name: "密码不符", username: "aisrc-admin", password: "wrong-password"},
		{name: "两者都不符", username: "someone-else", password: "wrong-password"},
		{name: "用户名为空", username: "", password: "secret-password"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Login(tc.password, tc.username)
			if !errors.Is(err, ErrPasswordMismatch) {
				t.Fatalf("应返回统一错误 ErrPasswordMismatch（不区分用户名错/密码错），实际 %v", err)
			}
		})
	}
}

// TestLoginUsernameFallsBackToAdmin 未配置 token.username 时按 admin 处理。
//
// 这是旧配置（没有 username 字段）的兼容路径：老部署升级后无需改配置即可继续登录。
func TestLoginUsernameFallsBackToAdmin(t *testing.T) {
	old := config.AppConfig
	t.Cleanup(func() { config.AppConfig = old })

	config.AppConfig.Token.Password = "secret-password"
	config.AppConfig.Token.Username = ""

	// 用户名不是 admin → 拒绝（证明回落值就是 admin，而不是「任意用户名都放行」）。
	if _, err := Login("secret-password", "root"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("未配置 username 时应回落 admin，root 必须被拒，实际 %v", err)
	}
}
