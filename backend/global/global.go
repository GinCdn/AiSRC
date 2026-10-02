package global

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
)

// 全局共享配置，与 GinBlog 保持一致的极简风格。
var (
	Log *logrus.Logger
	Ctx = context.Background()
)

// DirtyWrite 标记「配置有写入」，供前端做轻量变更感知。
var (
	dirtyMu  sync.RWMutex
	dirtyVer int64
)

// BumpConfigVersion 递增配置版本号。
func BumpConfigVersion() int64 {
	dirtyMu.Lock()
	defer dirtyMu.Unlock()
	dirtyVer++
	return dirtyVer
}

// ConfigVersion 返回当前配置版本号。
func ConfigVersion() int64 {
	dirtyMu.RLock()
	defer dirtyMu.RUnlock()
	return dirtyVer
}
