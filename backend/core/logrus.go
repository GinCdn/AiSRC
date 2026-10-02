package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"AiSRC/config"
	"AiSRC/global"

	"github.com/lestrrat-go/file-rotatelogs"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
)

// canCreateSymlink 探测当前进程能否在 dir 下创建符号链接。
//
// Windows 上创建符号链接需要管理员权限、或已启用「开发者模式」与
// SeCreateSymbolicLinkPrivilege，普通用户直接调用会返回
// ERROR_PRIVILEGE_NOT_HELD(1314)。非 Windows 平台一律返回 true。
func canCreateSymlink(dir string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	// 探测文件名带 pid，避免同目录多实例互相干扰。
	probe := filepath.Join(dir, fmt.Sprintf(".symlink-probe-%d", os.Getpid()))
	_ = os.Remove(probe)
	if err := os.Symlink(filepath.Join(dir, ".symlink-probe-target"), probe); err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}

// InitLogger 初始化日志系统：控制台 + 按天切割的日志文件。
func InitLogger(cfg config.LoggerConfig) *logrus.Logger {
	logger := logrus.New()
	logger.SetReportCaller(cfg.ShowLine)

	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	formatter := &logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
		ForceColors:     cfg.Color,
		CallerPrettyfier: func(frame *runtime.Frame) (string, string) {
			return fmt.Sprintf("%s:%d", filepath.Base(frame.File), frame.Line), ""
		},
	}
	logger.SetFormatter(formatter)

	if !cfg.Console {
		logger.SetOutput(io.Discard)
	}

	if cfg.Path != "" {
		opts := []rotatelogs.Option{
			rotatelogs.WithMaxAge(time.Duration(cfg.MaxAge) * 24 * time.Hour),
			rotatelogs.WithRotationTime(24 * time.Hour),
		}

		// WithLinkName 会在每次轮转后创建「指向当日文件」的符号链接（即 cfg.Path
		// 这个固定入口）。但 Windows 下创建符号链接需要特权，普通权限运行时会失败，
		// rotatelogs 会持续往标准输出打：
		//   failed to rotate: failed to create new symlink: ... A required privilege is not held by the client.
		// 这里先探测一次能力，不具备条件就退化为纯按天切割——日志内容不受影响，
		// 仅少了 logs/log 这个稳定入口，改按 logs/log.YYYYMMDD 查阅。
		if canCreateSymlink(filepath.Dir(cfg.Path)) {
			opts = append(opts, rotatelogs.WithLinkName(cfg.Path))
		} else {
			logger.Infof("当前环境无法创建符号链接（需管理员权限或开发者模式），日志跳过固定入口 %s，按天文件为 %s.YYYYMMDD", cfg.Path, cfg.Path)
		}

		writer, err := rotatelogs.New(cfg.Path+".%Y%m%d", opts...)
		if err != nil {
			logger.Warnf("日志切割初始化失败，仅输出控制台：%v", err)
		} else {
			logger.AddHook(lfshook.NewHook(
				lfshook.WriterMap{
					logrus.DebugLevel: writer,
					logrus.InfoLevel:  writer,
					logrus.WarnLevel:  writer,
					logrus.ErrorLevel: writer,
					logrus.FatalLevel: writer,
					logrus.PanicLevel: writer,
				},
				formatter,
			))
		}
	}

	global.Log = logger
	return logger
}
