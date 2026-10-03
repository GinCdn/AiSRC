package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 总配置。与 GinBlog 保持一致的「单文件 YAML + 结构体映射」风格。
type Config struct {
	System SystemConfig `yaml:"system"`
	Logger LoggerConfig `yaml:"logger"`
	Mysql  MysqlConfig  `yaml:"mysql"`
	Token  TokenConfig  `yaml:"token"`
	LLM    LLMConfig    `yaml:"llm"`
	Engine EngineConfig `yaml:"engine"`
	Data   DataConfig   `yaml:"data"`
	Update UpdateConfig `yaml:"update"`
}

// SystemConfig 系统配置
type SystemConfig struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	Env  string `yaml:"env"`
	// WebDir 前端构建产物目录（Vite dist）。为空时默认 ./web/dist，
	// 与原版 AutoHunter 的 WEB_DIR 约定一致。
	WebDir string `yaml:"web_dir"`
}

// LoggerConfig 日志配置
type LoggerConfig struct {
	Level       string `yaml:"level"`
	Path        string `yaml:"path"`
	ShowLine    bool   `yaml:"show_line"`
	Color       bool   `yaml:"color"`
	MaxSize     int    `yaml:"max_size"`
	MaxAge      int    `yaml:"max_age"`
	MaxBackups  int    `yaml:"max_backups"`
	Compress    bool   `yaml:"compress"`
	ServiceName string `yaml:"service_name"`
	Console     bool   `yaml:"console"`
}

// MysqlConfig 数据库配置
type MysqlConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	Charset  string `yaml:"charset"`
	MaxIdle  int    `yaml:"maxIdle"`
	MaxOpen  int    `yaml:"maxOpen"`
}

// TokenConfig 令牌配置
type TokenConfig struct {
	Header        string   `yaml:"header"`
	Secret        string   `yaml:"secret"`
	ExpireTime    int      `yaml:"expireTime"`
	Issuer        string   `yaml:"issuer"`
	Username      string   `yaml:"username"`      // 登录账号（未配置时回落 admin）
	Password      string   `yaml:"password"`      // 登录密码（至少 8 位）
	FullToken     string   `yaml:"fullToken"`     // 全权限静态令牌（对应原版 AUTOHUNTER_API_TOKEN）
	ReadToken     string   `yaml:"readToken"`     // 只读令牌
	ObserverToken string   `yaml:"observerToken"` // 观摩令牌
	AllowOrigins  []string `yaml:"allowOrigins"`  // CORS 白名单
}

// LLMConfig 全局默认模型配置（任务级可覆盖）
type LLMConfig struct {
	Mode        string  `yaml:"mode"` // single / pool
	BaseURL     string  `yaml:"base_url"`
	APIKey      string  `yaml:"api_key"`
	Model       string  `yaml:"model"`
	Protocol    string  `yaml:"protocol"` // auto / openai_chat / anthropic_messages
	Temperature float64 `yaml:"temperature"`
}

// EngineConfig 默认搜索引擎（FOFA）配置
type EngineConfig struct {
	Default    string `yaml:"default"`
	BaseURL    string `yaml:"base_url"`
	Key        string `yaml:"key"`
	MaxPages   int    `yaml:"max_pages"`
	PageSize   int    `yaml:"page_size"`
	IntentMode string `yaml:"intent_mode"`
}

// DataConfig 数据目录与工作目录
type DataConfig struct {
	WorkRoot      string `yaml:"work_root"`
	BackupDir     string `yaml:"backup_dir"`
	WallpaperDir  string `yaml:"wallpaper_dir"`
	RetentionDays int    `yaml:"retention_days"`
	AutoBackup    bool   `yaml:"auto_backup"`
	BackupHours   int    `yaml:"backup_interval_hours"`
	BackupKeep    int    `yaml:"backup_keep"`
	WorkMaxBytes  int64  `yaml:"work_max_bytes"`
}

// UpdateConfig 在线更新配置
type UpdateConfig struct {
	Enabled     bool   `yaml:"enabled"`
	RepoRoot    string `yaml:"repo_root"`
	Branch      string `yaml:"branch"`
	ReleasesURL string `yaml:"releases_url"`
	Token       string `yaml:"token"` // 私有仓库查询 Releases 需要令牌
}

var AppConfig Config

// Init 读取项目配置文件。
func Init() {
	path := "./config.yaml"
	if custom := strings.TrimSpace(os.Getenv("AISRC_CONFIG")); custom != "" {
		path = custom
	}
	data, err := os.ReadFile(path)
	if err != nil {
		panic("读取配置文件失败：" + err.Error())
	}
	if err := yaml.Unmarshal(data, &AppConfig); err != nil {
		panic("读取配置文件失败：" + err.Error())
	}
	applyDefaults()
}

// applyDefaults 为缺省项补上安全默认值，避免配置漏填导致运行时异常。
func applyDefaults() {
	if AppConfig.System.Host == "" {
		AppConfig.System.Host = "0.0.0.0"
	}
	if AppConfig.System.Port == "" {
		AppConfig.System.Port = "8080"
	}
	if AppConfig.System.Env == "" {
		AppConfig.System.Env = "release"
	}
	if strings.TrimSpace(AppConfig.System.WebDir) == "" {
		AppConfig.System.WebDir = "./web/dist"
	}
	if AppConfig.Mysql.Charset == "" {
		AppConfig.Mysql.Charset = "utf8mb4"
	}
	if AppConfig.Mysql.MaxIdle <= 0 {
		AppConfig.Mysql.MaxIdle = 20
	}
	if AppConfig.Mysql.MaxOpen <= 0 {
		AppConfig.Mysql.MaxOpen = 100
	}
	if AppConfig.Token.Header == "" {
		AppConfig.Token.Header = "Bearer"
	}
	if strings.TrimSpace(AppConfig.Token.Username) == "" {
		AppConfig.Token.Username = "admin"
	}
	if AppConfig.Token.ExpireTime <= 0 {
		AppConfig.Token.ExpireTime = 24
	}
	if AppConfig.Token.Issuer == "" {
		AppConfig.Token.Issuer = "aisrc"
	}
	if AppConfig.LLM.BaseURL == "" {
		AppConfig.LLM.BaseURL = "https://api.deepseek.com/v1"
	}
	if AppConfig.LLM.Model == "" {
		AppConfig.LLM.Model = "deepseek-chat"
	}
	if AppConfig.LLM.Protocol == "" {
		AppConfig.LLM.Protocol = "auto"
	}
	if AppConfig.LLM.Mode == "" {
		AppConfig.LLM.Mode = "single"
	}
	if AppConfig.Engine.Default == "" {
		AppConfig.Engine.Default = "fofa"
	}
	if AppConfig.Engine.MaxPages <= 0 {
		AppConfig.Engine.MaxPages = 20
	}
	if AppConfig.Engine.PageSize <= 0 {
		AppConfig.Engine.PageSize = 100
	}
	if AppConfig.Data.WorkRoot == "" {
		AppConfig.Data.WorkRoot = "./work"
	}
	if AppConfig.Data.BackupDir == "" {
		AppConfig.Data.BackupDir = "./backups"
	}
	if AppConfig.Data.RetentionDays <= 0 {
		AppConfig.Data.RetentionDays = 7
	}
	if AppConfig.Data.BackupHours <= 0 {
		AppConfig.Data.BackupHours = 24
	}
	if AppConfig.Data.BackupKeep <= 0 {
		AppConfig.Data.BackupKeep = 7
	}
	if AppConfig.Data.WorkMaxBytes <= 0 {
		AppConfig.Data.WorkMaxBytes = 512 << 20
	}
	if AppConfig.Update.Branch == "" {
		AppConfig.Update.Branch = "main"
	}
	if AppConfig.Update.ReleasesURL == "" {
		AppConfig.Update.ReleasesURL = "https://github.com/GinCdn/AutoAiSRC"
	}
}

// WebDir 返回绝对化后的前端构建产物目录。
func WebDir() string {
	dir := strings.TrimSpace(AppConfig.System.WebDir)
	if dir == "" {
		dir = "./web/dist"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Clean(dir)
	}
	return abs
}

// WorkRootDir 返回绝对化后的工作目录。
func WorkRootDir() string {
	dir := strings.TrimSpace(AppConfig.Data.WorkRoot)
	if dir == "" {
		dir = "./work"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Clean(dir)
	}
	return abs
}

// BackupDir 返回绝对化后的备份目录。
func BackupDir() string {
	dir := strings.TrimSpace(AppConfig.Data.BackupDir)
	if dir == "" {
		dir = "./backups"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Clean(dir)
	}
	return abs
}
