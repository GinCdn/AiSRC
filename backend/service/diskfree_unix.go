//go:build !windows

package service

import (
	"os"
	"path/filepath"
	"syscall"
)

// DiskFree 返回路径所在磁盘的剩余与总容量（字节）。类 Unix 实现。
// 路径不存在时逐级向上回退（statfs 要求路径已存在）。
func DiskFree(path string) (freeBytes, totalBytes int64, err error) {
	probe := path
	for {
		if _, statErr := os.Stat(probe); statErr == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	var st syscall.Statfs_t
	if err = syscall.Statfs(probe, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}
