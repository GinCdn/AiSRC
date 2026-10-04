package service

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/utils"
)

// updateHTTPClient 在线更新使用的 HTTP 客户端（检查版本）。
var updateHTTPClient = &http.Client{Timeout: 20 * time.Second}

// downloadHTTPClient 下载安装包用的 HTTP 客户端（大文件，放宽超时）。
var downloadHTTPClient = &http.Client{Timeout: 5 * time.Minute}

// UpdateCheckResult 更新检查结果。
type UpdateCheckResult struct {
	Enabled      bool   `json:"enabled"`
	Current      string `json:"current"`
	Latest       string `json:"latest"`
	HasUpdate    bool   `json:"has_update"`
	ReleaseName  string `json:"release_name"`
	ReleaseNotes string `json:"release_notes"`
	ReleaseURL   string `json:"release_url"`
	PublishedAt  string `json:"published_at"`
	Repo         string `json:"repo"`
	Branch       string `json:"branch"`
	CheckedAt    string `json:"checked_at"`
	ErrorMsg     string `json:"error,omitempty"`
	// 以下别名键对齐前端 SettingsView 的读取链（current_version/latest_version/changelog）。
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Changelog      string `json:"changelog"`
	// HotUpdateable 表示当前运行形态支持「一键更新并重启」：
	// 裸二进制部署（Windows/Linux amd64）恒可；Docker 容器内部署不可（应拉新镜像）。
	HotUpdateable bool `json:"hot_updateable"`
}

// UpdateStatusResult 更新执行状态（前端轮询）。
type UpdateStatusResult struct {
	State         string `json:"state"` // idle / downloading / swapping / restarting / failed
	Message       string `json:"message,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	Error         string `json:"error,omitempty"`
}

// 更新任务状态。
var (
	updateStateMu   sync.Mutex
	updateState     atomic.Value // string
	updateMessage   atomic.Value // string
	updateTarget    atomic.Value // string
	updateErrorText atomic.Value // string
	updateRunning   atomic.Bool
)

func init() {
	updateState.Store("idle")
	updateMessage.Store("")
	updateTarget.Store("")
	updateErrorText.Store("")
}

// setUpdateJob 写状态快照。
func setUpdateJob(state, message, target, errText string) {
	updateState.Store(state)
	updateMessage.Store(message)
	if target != "" {
		updateTarget.Store(target)
	}
	if errText != "" {
		updateErrorText.Store(errText)
	}
}

// GetUpdateStatus 供状态接口读取。
func GetUpdateStatus() *UpdateStatusResult {
	return &UpdateStatusResult{
		State:         updateState.Load().(string),
		Message:       updateMessage.Load().(string),
		TargetVersion: updateTarget.Load().(string),
		Error:         updateErrorText.Load().(string),
	}
}

// shutdownHook 由 main 在启动时注册：优雅停调度器与 HTTP 服务。
var (
	shutdownHook     func()
	shutdownHookOnce sync.Once
)

// RegisterShutdownHook 注册更新重启前的优雅停机回调（幂等，取最后注册者）。
func RegisterShutdownHook(fn func()) { shutdownHook = fn }

func runShutdownHook() {
	if shutdownHook != nil {
		shutdownHookOnce.Do(shutdownHook)
	}
}

// latestRelease GitHub Release 元信息。
type latestRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// releasesAPIURL 从 releases_url 推导 releases/latest API 地址。
func releasesAPIURL() string {
	repo := strings.TrimRight(config.AppConfig.Update.ReleasesURL, "/")
	if strings.Contains(repo, "api.github.com") {
		return repo
	}
	parts := strings.Split(repo, "/")
	if len(parts) < 2 {
		return repo
	}
	owner := parts[len(parts)-2]
	name := parts[len(parts)-1]
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, name)
}

// fetchLatestRelease 拉取远端最新发布信息。
func fetchLatestRelease(ctx context.Context) (*latestRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPIURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AiSRC/"+constant.Version)
	if token := strings.TrimSpace(config.AppConfig.Update.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求发布信息失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("发布信息获取失败（HTTP %d）", resp.StatusCode)
	}
	var payload latestRelease
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析发布信息失败：%w", err)
	}
	return &payload, nil
}

// assetSuffix 当前平台对应的发行包资产后缀。
func assetSuffix() string {
	if runtime.GOOS == "windows" {
		return "windows-amd64.zip"
	}
	return "linux-amd64.tar.gz"
}

// pickAsset 在发布资产里挑当前平台的安装包。
func pickAsset(rel *latestRelease) (string, string) {
	suffix := assetSuffix()
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, suffix) {
			return a.Name, a.BrowserDownloadURL
		}
	}
	return "", ""
}

// inDocker 判断是否运行在容器内（容器内自更新无意义，应拉新镜像）。
func inDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/.dockerinit"); err == nil {
		return true
	}
	return false
}

// CheckUpdate 查询远端发布信息并比对版本。
func CheckUpdate(ctx context.Context) *UpdateCheckResult {
	result := &UpdateCheckResult{
		Enabled:   config.AppConfig.Update.Enabled,
		Current:   constant.Version,
		Repo:      config.AppConfig.Update.ReleasesURL,
		Branch:    config.AppConfig.Update.Branch,
		CheckedAt: utils.ToCSTISO(time.Now()),
	}
	result.CurrentVersion = constant.Version
	if !result.Enabled {
		result.ErrorMsg = "在线更新未启用"
		return result
	}

	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		result.ErrorMsg = err.Error()
		return result
	}

	result.Latest = strings.TrimPrefix(rel.TagName, "v")
	result.LatestVersion = result.Latest
	result.ReleaseName = rel.Name
	result.ReleaseNotes = utils.Truncate(rel.Body, 4000)
	result.Changelog = result.ReleaseNotes
	result.ReleaseURL = rel.HTMLURL
	if rel.PublishedAt != "" {
		if ts, ok := utils.ParseTime(rel.PublishedAt); ok {
			result.PublishedAt = utils.ToCSTISO(ts)
		} else {
			result.PublishedAt = rel.PublishedAt
		}
	}
	result.HasUpdate = compareVersion(result.Latest, result.Current) > 0
	_, assetURL := pickAsset(rel)
	result.HotUpdateable = assetURL != "" && runtime.GOARCH == "amd64" && !inDocker()
	return result
}

// RunUpdate 触发在线更新：后台下载对应平台安装包 → 原子替换二进制与前端 → 自动重启。
// 立即返回 ok，前端通过 GET /api/update/status 轮询进度。
func RunUpdate() map[string]any {
	if !config.AppConfig.Update.Enabled {
		return map[string]any{"ok": false, "error": "在线更新未启用"}
	}
	if inDocker() {
		return map[string]any{
			"ok":    false,
			"error": "检测到 Docker 容器部署，请使用 docker compose pull 拉取新镜像更新",
		}
	}
	if runtime.GOARCH != "amd64" {
		return map[string]any{"ok": false, "error": "在线更新仅支持 amd64 平台安装包"}
	}
	if !updateRunning.CompareAndSwap(false, true) {
		return map[string]any{"ok": false, "error": "已有更新任务进行中，请稍候"}
	}

	// 独立上下文：请求返回后下载仍继续。
	ctx, cancel := context.WithCancel(context.Background())
	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		cancel()
		updateRunning.Store(false)
		return map[string]any{"ok": false, "error": err.Error()}
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	if compareVersion(latest, constant.Version) <= 0 {
		cancel()
		updateRunning.Store(false)
		return map[string]any{"ok": false, "error": fmt.Sprintf("当前已是最新版本 v%s", constant.Version)}
	}
	assetName, assetURL := pickAsset(rel)
	if assetURL == "" {
		cancel()
		updateRunning.Store(false)
		return map[string]any{"ok": false, "error": "发布页未找到当前平台（" + assetSuffix() + "）安装包，请手动下载更新"}
	}

	setUpdateJob("downloading", "正在下载更新包 "+assetName, latest, "")
	go func() {
		defer func() {
			cancel()
			// 失败路径释放运行位；成功路径进程即将退出，无影响。
			if updateState.Load().(string) == "failed" {
				updateRunning.Store(false)
			}
		}()
		performUpdate(ctx, assetURL, latest)
	}()
	return map[string]any{"ok": true, "message": "正在下载并应用更新，服务将自动重启", "target_version": latest}
}

// performUpdate 下载 → 解压 → 替换 → 重启 的完整流程（后台 goroutine）。
func performUpdate(ctx context.Context, assetURL, target string) {
	exePath, err := os.Executable()
	if err != nil {
		setUpdateJob("failed", "", target, "定位安装目录失败："+err.Error())
		return
	}
	installDir := filepath.Dir(exePath)
	if abs, aerr := filepath.Abs(installDir); aerr == nil {
		installDir = abs
	}
	tmpDir := filepath.Join(installDir, "update_tmp")
	_ = os.RemoveAll(tmpDir) // 清理上次残留
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		setUpdateJob("failed", "", target, "创建临时目录失败："+err.Error())
		return
	}

	// 1. 下载
	setUpdateJob("downloading", "正在下载更新包（"+target+"）…", target, "")
	archivePath := filepath.Join(tmpDir, "update.asset")
	if err := downloadFile(ctx, downloadHTTPClient, assetURL, archivePath); err != nil {
		setUpdateJob("failed", "", target, "下载更新包失败："+err.Error())
		return
	}

	// 2. 解压到暂存区（staging/）
	setUpdateJob("swapping", "下载完成，正在解包…", target, "")
	staging := filepath.Join(tmpDir, "staging")
	if err := extractUpdateAsset(archivePath, staging); err != nil {
		setUpdateJob("failed", "", target, "解包失败："+err.Error())
		return
	}
	stagingBin := filepath.Join(staging, binName())
	if _, err := os.Stat(stagingBin); err != nil {
		setUpdateJob("failed", "", target, "安装包中未找到服务端二进制")
		return
	}

	// 3. 替换 web/（保留用户 config.yaml 与 data/logs/work）
	webDir := config.WebDir()
	stagingWeb := filepath.Join(staging, "web")
	if _, err := os.Stat(stagingWeb); err == nil {
		if err := swapWebDir(stagingWeb, webDir, tmpDir); err != nil {
			setUpdateJob("failed", "", target, "替换前端资源失败："+err.Error())
			return
		}
	}

	// 4. 覆盖其余发行文件（启动脚本/README 等，不碰 config.yaml）
	if err := copyRootFiles(staging, installDir); err != nil {
		setUpdateJob("failed", "", target, "更新发行文件失败："+err.Error())
		return
	}

	// 5. 替换二进制
	setUpdateJob("swapping", "正在替换服务端程序…", target, "")
	curBin, err := os.Executable()
	if err == nil {
		curBin, err = filepath.Abs(curBin)
	}
	if err != nil {
		setUpdateJob("failed", "", target, "定位当前程序失败："+err.Error())
		return
	}
	if err := swapBinary(curBin, stagingBin); err != nil {
		setUpdateJob("failed", "", target, "替换程序失败："+err.Error())
		return
	}

	// 6. 重启：优雅停机（钩子）→ 拉起新进程 → 老进程退出
	setUpdateJob("restarting", "更新完成，正在重启服务…", target, "")
	go restartProcess(curBin)
}

// binName 当前平台的服务端二进制名。
func binName() string {
	if runtime.GOOS == "windows" {
		return "aisrc.exe"
	}
	return "aisrc"
}

// swapWebDir 把 stagingWeb 换到 webDir：老目录改名留档，新目录顶上，最后清理留档。
func swapWebDir(stagingWeb, webDir, tmpDir string) error {
	old := filepath.Join(tmpDir, "web.old")
	_ = os.RemoveAll(old)
	if _, err := os.Stat(webDir); err == nil {
		// Windows 下静态服务可能短暂持有句柄，重试数次。
		var rerr error
		for i := 0; i < 5; i++ {
			if rerr = os.Rename(webDir, old); rerr == nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if rerr != nil {
			return fmt.Errorf("旧前端目录改名失败：%w", rerr)
		}
	}
	if err := os.Rename(stagingWeb, webDir); err != nil {
		// 回滚：把老目录换回去，保持服务可用。
		_ = os.Rename(old, webDir)
		return fmt.Errorf("新前端目录就位失败：%w", err)
	}
	_ = os.RemoveAll(old)
	return nil
}

// swapBinary 替换服务端二进制。Windows 运行中文件不可覆盖但可改名：先改名留档再顶上。
func swapBinary(curBin, stagingBin string) error {
	if runtime.GOOS != "windows" {
		if err := os.Rename(stagingBin, curBin); err != nil {
			return err
		}
		return os.Chmod(curBin, 0o755)
	}
	oldBin := curBin + ".old"
	_ = os.RemoveAll(oldBin) // 上一轮更新留档，可删
	if err := os.Rename(curBin, oldBin); err != nil {
		return fmt.Errorf("当前程序改名失败：%w", err)
	}
	if err := os.Rename(stagingBin, curBin); err != nil {
		// 回滚改名，保持老版本可继续运行。
		_ = os.Rename(oldBin, curBin)
		return fmt.Errorf("新程序就位失败：%w", err)
	}
	return nil
}

// copyRootFiles 把暂存区根目录的发行文件（不含二进制/web/config.yaml）覆盖到安装目录。
func copyRootFiles(staging, installDir string) error {
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	skip := map[string]bool{binName(): true, "web": true, "config.yaml": true,
		"data": true, "logs": true, "work": true, "update_tmp": true}
	for _, e := range entries {
		if skip[e.Name()] {
			continue
		}
		src := filepath.Join(staging, e.Name())
		dst := filepath.Join(installDir, e.Name())
		if e.IsDir() {
			if err := copyDir(src, dst); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(src, dst, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// restartProcess 优雅停机 → 拉起新进程 → 老进程退出。
func restartProcess(newBin string) {
	time.Sleep(500 * time.Millisecond) // 让更新接口的响应先送达前端
	runShutdownHook()                  // 停调度器 + 关 HTTP（端口释放）
	time.Sleep(200 * time.Millisecond)

	cwd, _ := os.Getwd()
	args := append([]string{newBin}, os.Args[1:]...)
	attr := &os.ProcAttr{
		Dir: cwd,
		Env: os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	proc, err := os.StartProcess(newBin, args, attr)
	if err != nil {
		// 标准句柄不可继承时退化为分离进程。
		attr.Files = nil
		proc, err = os.StartProcess(newBin, args, attr)
	}
	if err != nil {
		// 新进程起不来：老进程已停，只能留日志。此时新二进制已就位，用户可手动启动。
		if global := os.Getenv("AISRC_LOG_PATH"); global != "" {
			_ = os.WriteFile(global+"_update_error.txt", []byte(err.Error()), 0o644)
		}
		fmt.Fprintf(os.Stderr, "[update] 重启失败：%v（新版本已就位，请手动启动）\n", err)
		os.Exit(1)
	}
	_ = proc.Release()
	os.Exit(0)
}

// downloadFile 流式下载到目标路径。
func downloadFile(ctx context.Context, client *http.Client, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "AiSRC/"+constant.Version)
	if token := strings.TrimSpace(config.AppConfig.Update.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// extractUpdateAsset 解 zip / tar.gz 到 dst，剥离顶层目录，得到扁平结构：
// staging/aisrc(.exe)、staging/web/**、staging/其余发行文件。config.yaml 一律丢弃。
func extractUpdateAsset(archivePath, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	lower := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZip(archivePath, dst)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractTarGz(archivePath, dst)
	default:
		return fmt.Errorf("不支持的安装包格式：%s", filepath.Base(archivePath))
	}
}

// stripTop 剥离归档内路径的顶层目录（AutoAiSRC-v1.0.2-windows-amd64/... → ...）。
func stripTop(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if idx := strings.Index(name, "/"); idx >= 0 {
		return name[idx+1:], true
	}
	return name, false
}

func extractZip(archivePath, dst string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		rel, ok := stripTop(f.Name)
		if !ok || rel == "" || f.FileInfo().IsDir() {
			continue
		}
		if rel == "config.yaml" || strings.HasPrefix(rel, "data/") ||
			strings.HasPrefix(rel, "logs/") || strings.HasPrefix(rel, "work/") {
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		if err := writeZipEntry(f, target); err != nil {
			return err
		}
	}
	return nil
}

func writeZipEntry(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	mode := os.FileMode(0o644)
	if f.Mode()&0o111 != 0 {
		mode = 0o755
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

func extractTarGz(archivePath, dst string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel, ok := stripTop(hdr.Name)
		if !ok || rel == "" || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if rel == "config.yaml" || strings.HasPrefix(rel, "data/") ||
			strings.HasPrefix(rel, "logs/") || strings.HasPrefix(rel, "work/") {
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if hdr.Mode&0o111 != 0 {
			mode = 0o755
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
}

// copyDir 递归复制目录。
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target, 0o755)
	})
}

// copyFile 复制单文件并保留可执行位。
func copyFile(src, dst string, execMode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info.Mode()&0o111 != 0 {
		mode = execMode
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// compareVersion 语义化版本比较：a > b 返回 1，a < b 返回 -1，相等返回 0。
func compareVersion(a, b string) int {
	partA := splitVersion(a)
	partB := splitVersion(b)
	length := len(partA)
	if len(partB) > length {
		length = len(partB)
	}
	for i := 0; i < length; i++ {
		var va, vb int
		if i < len(partA) {
			va = partA[i]
		}
		if i < len(partB) {
			vb = partB[i]
		}
		if va > vb {
			return 1
		}
		if va < vb {
			return -1
		}
	}
	return 0
}

func splitVersion(value string) []int {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if idx := strings.IndexAny(value, "-+"); idx >= 0 {
		value = value[:idx]
	}
	parts := strings.Split(value, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		out = append(out, atoi(part))
	}
	return out
}
