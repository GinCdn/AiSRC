package middleware

import (
	"AiSRC/config"

	"github.com/gin-gonic/gin"
)

// Cors 跨域中间件。默认仅允许同源；配置了 token.allowOrigins 时按白名单放行。
func Cors() gin.HandlerFunc {
	allowed := make(map[string]bool)
	for _, origin := range config.AppConfig.Token.AllowOrigins {
		if origin = trimSpace(origin); origin != "" {
			allowed[origin] = true
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			c.Next()
			return
		}

		if allowed["*"] || allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Aisrc-Token, X-Autohunter-Token, X-Requested-With")
			c.Header("Access-Control-Expose-Headers", "Content-Disposition, Content-Length")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func trimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t' || value[start] == '\n' || value[start] == '\r') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '\n' || value[end-1] == '\r') {
		end--
	}
	return value[start:end]
}
