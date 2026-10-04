package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"AiSRC/config"
	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/global"
	"AiSRC/model"
	"AiSRC/service/engine"
	"AiSRC/utils"

	"gorm.io/gorm"
)

// BackupStatus 备份状态。
func BackupStatus() map[string]any {
	dir := config.BackupDir()
	snapshots := listSnapshots(dir)
	var totalBytes int64
	for _, item := range snapshots {
		totalBytes += item.Size
	}
	view := map[string]any{
		"dir":            dir,
		"count":          len(snapshots),
		"total_bytes":    totalBytes,
		"auto_backup":    config.AppConfig.Data.AutoBackup,
		"interval_hours": config.AppConfig.Data.BackupHours,
		"keep":           config.AppConfig.Data.BackupKeep,
		"latest":         latestSnapshotName(snapshots),
		"snapshots":      snapshots,
	}
	if len(snapshots) > 0 {
		view["last_backup_at"] = snapshots[0].ModTime
	} else {
		view["last_backup_at"] = ""
	}
	view["snapshots_human"] = utils.HumanBytes(totalBytes)
	view["db_human"] = databaseSizeHuman()
	if free, total, err := DiskFree(dir); err == nil {
		view["disk"] = map[string]any{
			"free_bytes":  free,
			"total_bytes": total,
			"free_human":  utils.HumanBytes(free),
			"total_human": utils.HumanBytes(total),
		}
	}
	workStats := WorkdirStats()
	workLimit := config.AppConfig.Data.WorkMaxBytes
	view["work"] = map[string]any{
		"human":     workStats["total_size_human"],
		"bytes":     workStats["total_bytes"],
		"max_human": utils.HumanBytes(workLimit),
	}
	return view
}

// databaseSizeHuman 当前数据库所有表的总大小（MySQL information_schema）。
func databaseSizeHuman() string {
	if core.Db == nil {
		return ""
	}
	var total int64
	if err := core.Db.Raw(
		"SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE()",
	).Scan(&total).Error; err != nil || total <= 0 {
		return ""
	}
	return utils.HumanBytes(total)
}

// SnapshotInfo 备份文件信息。
type SnapshotInfo struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ModTime   string `json:"mod_time"`
	Bytes     int64  `json:"bytes"`      // Size 别名（前端读 bytes）
	Human     string `json:"human"`      // 可读大小
	CreatedAt string `json:"created_at"` // ModTime 别名（前端读 created_at）
}

func listSnapshots(dir string) []SnapshotInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []SnapshotInfo{}
	}
	out := make([]SnapshotInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		modTime := utils.ToCSTISO(info.ModTime())
		size := info.Size()
		out = append(out, SnapshotInfo{
			Name:      entry.Name(),
			Size:      size,
			ModTime:   modTime,
			Bytes:     size,
			Human:     utils.HumanBytes(size),
			CreatedAt: modTime,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime > out[j].ModTime })
	return out
}

func latestSnapshotName(items []SnapshotInfo) string {
	if len(items) == 0 {
		return ""
	}
	return items[0].Name
}

// BackupDump 备份数据载荷。
type BackupDump struct {
	Version    string                `json:"version"`
	ExportedAt string                `json:"exported_at"`
	Tasks      []model.Task          `json:"tasks"`
	Targets    []model.Target        `json:"targets"`
	Findings   []model.Finding       `json:"findings"`
	Reviews    []model.Review        `json:"reviews"`
	Killsweeps []model.Killsweep     `json:"killsweeps"`
	Events     []model.TaskEvent     `json:"events"`
	Intel      []model.Intel         `json:"intel"`
	Settings   *model.SystemSettings `json:"settings"`
}

// CreateSnapshot 生成一份完整快照并落盘，返回文件名。
func CreateSnapshot() (string, error) {
	dump, err := collectDump()
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		return "", err
	}
	dir := config.BackupDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("snapshot-%s.json", time.Now().Format("20060102-150405"))
	target := filepath.Join(dir, name)
	if err := os.WriteFile(target, raw, 0o644); err != nil {
		return "", err
	}
	pruneSnapshots(dir, config.AppConfig.Data.BackupKeep)
	global.Log.Infof("已生成数据快照 %s（%d 字节）", target, len(raw))
	return name, nil
}

// ExportDump 导出数据为 JSON 字节（直接下载）。
func ExportDump() ([]byte, string, error) {
	dump, err := collectDump()
	if err != nil {
		return nil, "", err
	}
	raw, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		return nil, "", err
	}
	name := fmt.Sprintf("aisrc-export-%s.json", time.Now().Format("20060102-150405"))
	return raw, name, nil
}

// collectDump 汇总全量数据。
func collectDump() (*BackupDump, error) {
	dump := &BackupDump{
		Version:    constant.Version,
		ExportedAt: utils.ToCSTISO(time.Now()),
	}
	steps := []struct {
		dest any
	}{
		{&dump.Tasks}, {&dump.Targets}, {&dump.Findings}, {&dump.Reviews},
		{&dump.Killsweeps}, {&dump.Events}, {&dump.Intel},
	}
	for _, step := range steps {
		if err := core.Db.Find(step.dest).Error; err != nil {
			return nil, err
		}
	}
	settings := engine.LoadSystemSettings()
	dump.Settings = settings
	return dump, nil
}

// ReadSnapshot 读取指定快照内容。
func ReadSnapshot(name string) ([]byte, error) {
	if strings.ContainsAny(name, `/\`) || !strings.HasSuffix(name, ".json") {
		return nil, fmt.Errorf("非法的快照名称")
	}
	return os.ReadFile(filepath.Join(config.BackupDir(), name))
}

// RestoreSnapshot 从 JSON 载荷恢复数据（覆盖式导入）。
func RestoreSnapshot(raw []byte) (map[string]any, error) {
	var dump BackupDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, fmt.Errorf("快照格式不正确: %v", err)
	}
	counts := map[string]any{}

	err := core.Db.Transaction(func(tx *gorm.DB) error {
		// 清空现有数据（保留系统设置与账号）。
		for _, step := range []func() error{
			func() error { return tx.Where("1 = 1").Delete(&model.Review{}).Error },
			func() error { return tx.Where("1 = 1").Delete(&model.Finding{}).Error },
			func() error { return tx.Where("1 = 1").Delete(&model.Killsweep{}).Error },
			func() error { return tx.Where("1 = 1").Delete(&model.Target{}).Error },
			func() error { return tx.Where("1 = 1").Delete(&model.TaskEvent{}).Error },
			func() error { return tx.Where("1 = 1").Delete(&model.Task{}).Error },
			func() error { return tx.Where("1 = 1").Delete(&model.Intel{}).Error },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		// 分批写入，避免超大数据集一次性 SQL 过长。
		for _, batch := range []struct {
			items any
			label string
		}{
			{dump.Tasks, "tasks"},
			{dump.Targets, "targets"},
			{dump.Findings, "findings"},
			{dump.Reviews, "reviews"},
			{dump.Killsweeps, "killsweeps"},
			{dump.Events, "events"},
			{dump.Intel, "intel"},
		} {
			if err := insertInBatches(tx, batch.items); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if dump.Settings != nil {
		dump.Settings.ID = "global"
		if err := engine.SaveSystemSettings(dump.Settings); err != nil {
			global.Log.Warnf("恢复系统设置失败: %v", err)
		}
	}
	counts["tasks"] = len(dump.Tasks)
	counts["targets"] = len(dump.Targets)
	counts["findings"] = len(dump.Findings)
	counts["reviews"] = len(dump.Reviews)
	counts["killsweeps"] = len(dump.Killsweeps)
	counts["events"] = len(dump.Events)
	counts["intel"] = len(dump.Intel)
	counts["restored_at"] = utils.ToCSTISO(time.Now())
	return counts, nil
}

// insertInBatches 按类型分批插入。
func insertInBatches(tx *gorm.DB, items any) error {
	switch list := items.(type) {
	case []model.Task:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 200).Error
	case []model.Target:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 200).Error
	case []model.Finding:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 200).Error
	case []model.Review:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 200).Error
	case []model.Killsweep:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 200).Error
	case []model.TaskEvent:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 500).Error
	case []model.Intel:
		if len(list) == 0 {
			return nil
		}
		return tx.CreateInBatches(list, 200).Error
	default:
		return nil
	}
}

// pruneSnapshots 保留最近 N 份快照。
func pruneSnapshots(dir string, keep int) {
	if keep <= 0 {
		return
	}
	items := listSnapshots(dir)
	if len(items) <= keep {
		return
	}
	for _, item := range items[keep:] {
		_ = os.Remove(filepath.Join(dir, item.Name))
	}
}

// StartAutoBackup 启动自动备份定时任务。
func StartAutoBackup(stop <-chan struct{}) {
	if !config.AppConfig.Data.AutoBackup {
		return
	}
	interval := time.Duration(config.AppConfig.Data.BackupHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if name, err := CreateSnapshot(); err != nil {
					global.Log.Warnf("自动备份失败: %v", err)
				} else {
					global.Log.Infof("自动备份完成: %s", name)
				}
			}
		}
	}()
}
