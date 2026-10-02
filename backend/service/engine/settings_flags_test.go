package engine

import (
	"testing"

	"AiSRC/model"
)

// TestDefaultsSwitchSemantics 三个设置开关的 nil/显式值语义。
// nil = 存量配置里没有该键：auto_killsweep 视为开（原版缺省），shell/verbose 视为关（安全缺省）。
func TestDefaultsSwitchSemantics(t *testing.T) {
	var d model.DefaultsSettings
	if !d.EffectiveAutoKillsweep() {
		t.Error("nil auto_killsweep 应视为开（原版缺省 True）")
	}
	if d.EffectiveShellEnabled() {
		t.Error("nil shell_enabled 应视为关（安全缺省）")
	}
	if d.EffectiveVerboseEvents() {
		t.Error("nil verbose_events 应视为关（安全缺省）")
	}

	on, off := true, false
	d.AutoKillsweep, d.ShellEnabled, d.VerboseEvents = &off, &on, &on
	if d.EffectiveAutoKillsweep() {
		t.Error("显式 false 的 auto_killsweep 不应被缺省覆盖")
	}
	if !d.EffectiveShellEnabled() || !d.EffectiveVerboseEvents() {
		t.Error("显式 true 的开关应生效")
	}
}

// TestApplyRuntimeFlags 验证设置 → 运行时开关的同步。
func TestApplyRuntimeFlags(t *testing.T) {
	defer func() {
		ApplyRuntimeFlags(&model.SystemSettings{}) // 恢复默认（全关）
	}()

	settings := &model.SystemSettings{}
	on, off := true, false
	settings.Defaults.ShellEnabled = &on
	settings.Defaults.VerboseEvents = &off
	ApplyRuntimeFlags(settings)
	if !ShellEnabled() {
		t.Error("ApplyRuntimeFlags 后 Shell 应开")
	}
	if VerboseEvents() {
		t.Error("ApplyRuntimeFlags 后 verbose 应关")
	}

	settings.Defaults.ShellEnabled = &off
	settings.Defaults.VerboseEvents = &on
	ApplyRuntimeFlags(settings)
	if ShellEnabled() || !VerboseEvents() {
		t.Error("二次同步应覆盖旧值")
	}
}

// TestEmitNoiseFiltered 「记录噪音事件」关闭时噪音事件不落库不广播，开启后恢复。
func TestEmitNoiseFiltered(t *testing.T) {
	defer ApplyRuntimeFlags(&model.SystemSettings{})
	SetVerboseEvents(false)

	sub := BusInstance().Subscribe("t-noise")
	defer BusInstance().Unsubscribe("t-noise", sub)

	Emit("t-noise", "orchestrator", "skip", "info", "跳过", nil)
	select {
	case ev := <-sub.Events():
		t.Fatalf("verbose 关闭时噪音事件不应广播，实得 kind=%s", ev.Kind)
	default:
	}

	SetVerboseEvents(true)
	Emit("t-noise", "orchestrator", "skip", "info", "跳过", nil)
	select {
	case ev := <-sub.Events():
		if ev.Kind != "skip" {
			t.Fatalf("期望 kind=skip，实得 %s", ev.Kind)
		}
	default:
		t.Fatal("verbose 开启后噪音事件应正常广播")
	}

	// 非噪音事件不受开关影响
	SetVerboseEvents(false)
	Emit("t-noise", "worker", "worker_start", "info", "开始", nil)
	select {
	case ev := <-sub.Events():
		if ev.Kind != "worker_start" {
			t.Fatalf("期望 kind=worker_start，实得 %s", ev.Kind)
		}
	default:
		t.Fatal("非噪音事件不应被噪音开关拦截")
	}
}
