//go:build windows

package service

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DiskFree 返回路径所在磁盘的剩余与总容量（字节）。Windows 实现。
// 路径不存在时逐级向上回退（GetDiskFreeSpaceEx 要求路径已存在）。
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
	var free, total, avail uint64
	if err = windows.GetDiskFreeSpaceEx(windows.StringToUTF16Ptr(probe), &free, &total, &avail); err != nil {
		return 0, 0, err
	}
	return int64(free), int64(total), nil
}
