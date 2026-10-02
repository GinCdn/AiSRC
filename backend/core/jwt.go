package core

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"AiSRC/config"
	"AiSRC/model"
	"AiSRC/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims 自定义 JWT 声明。
type Claims struct {
	model.AdminVo
	Role         string `json:"role"`
	TokenVersion int    `json:"token_version"`
	jwt.RegisteredClaims
}

var (
	tokenExpiredDuration time.Duration
	tokenSecret          []byte
	tokenIssuer          string
)

// InitJWT 初始化 JWT 配置。
func InitJWT() error {
	secret := strings.TrimSpace(config.AppConfig.Token.Secret)
	if len(secret) < 32 {
		return errors.New("JWT 密钥长度必须 ≥32 字节")
	}
	expireHours := config.AppConfig.Token.ExpireTime
	if expireHours <= 0 {
		expireHours = 24
	}
	tokenExpiredDuration = time.Duration(expireHours) * time.Hour
	tokenSecret = []byte(secret)
	tokenIssuer = config.AppConfig.Token.Issuer
	return nil
}

// GenerateToken 签发平台访问令牌。
func GenerateToken(username string, role string, tokenVersion int) (string, error) {
	now := utils.Now()
	claims := Claims{
		AdminVo:      model.AdminVo{ID: 1, Username: username},
		Role:         role,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiredDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tokenIssuer,
			ID:        uuid.NewString(),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(tokenSecret)
}

// ValidateToken 校验令牌并返回声明。
func ValidateToken(tokenString string) (*Claims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, errors.New("令牌不能为空")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的签名算法: %v", t.Header["alg"])
		}
		return tokenSecret, nil
	}, jwt.WithIssuer(tokenIssuer), jwt.WithLeeway(5*time.Second))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("令牌已过期")
		}
		if strings.Contains(err.Error(), "signature is invalid") {
			return nil, errors.New("令牌签名无效")
		}
		return nil, errors.New("令牌无效")
	}
	if !token.Valid {
		return nil, errors.New("令牌无效")
	}
	return claims, nil
}

// TokenExpireSeconds 返回令牌有效期（秒）。
func TokenExpireSeconds() int64 {
	return int64(tokenExpiredDuration.Seconds())
}
