package engine

import (
	"strings"
	"testing"
)

// TestRequestMoreBudgetHonest 追加预算必须"如实回报"：
// 这是把 DVWA 那次跑成 findings_total=0 的直接诱因——
// 工具无条件回"已追加 4 轮"，模型以为预算放宽而继续探索，下一轮却撞上硬上限。
func TestRequestMoreBudgetHonest(t *testing.T) {
	s := &WorkerSession{MaxRounds: 12, Round: 3}

	// 前 budgetMaxGrant 次都应真正追加，剩余轮数逐次 +4
	for i := 1; i <= budgetMaxGrant; i++ {
		granted, remaining := s.RequestMoreBudget("仍需验证 SQL 注入回显")
		if !granted {
			t.Fatalf("第 %d 次追加应成功", i)
		}
		want := 12 + i*budgetExtendRounds - 3
		if remaining != want {
			t.Fatalf("第 %d 次追加后剩余轮数应为 %d，实际 %d", i, want, remaining)
		}
	}

	// 超过上限后必须明确拒绝，而不是继续谎报
	granted, remaining := s.RequestMoreBudget("还要再看一眼")
	if granted {
		t.Fatalf("超过上限（%d 次）后不应再追加", budgetMaxGrant)
	}
	if remaining != s.MaxRounds-s.Round {
		t.Fatalf("拒绝时也应回报真实剩余：want %d got %d", s.MaxRounds-s.Round, remaining)
	}
}

// TestBudgetNoticeFiresOnceAndRearms 收尾提醒只在"进入最后 3 轮"时出现一次，
// 且追加预算后重新武装——既不能刷屏，也不能在续命后失声。
func TestBudgetNoticeFiresOnceAndRearms(t *testing.T) {
	s := &WorkerSession{MaxRounds: 12, Round: 0}

	// 轮次充裕时不打扰
	s.Round = 5 // 剩余 7
	if got := s.BudgetNotice(); got != "" {
		t.Fatalf("剩余 7 轮不应提醒，实际 %q", got)
	}

	// 进入最后 3 轮：提醒一次，且带上真实剩余轮数
	s.Round = 9 // 剩余 3
	notice := s.BudgetNotice()
	if notice == "" {
		t.Fatal("剩余 3 轮应发出收尾提醒")
	}
	if !strings.Contains(notice, "还剩 3 轮") {
		t.Fatalf("提醒应写明剩余轮数，实际 %q", notice)
	}
	if !strings.Contains(notice, "submit_finding") {
		t.Fatalf("提醒应引导先提交再续命，实际 %q", notice)
	}

	// 同一阶段不重复提醒
	s.Round = 10 // 剩余 2
	if got := s.BudgetNotice(); got != "" {
		t.Fatalf("同一收尾阶段不应重复提醒，实际 %q", got)
	}

	// 追加预算后重新武装：剩余回到 6，再进入最后 3 轮应再次提醒
	if granted, _ := s.RequestMoreBudget("确有未完成验证"); !granted {
		t.Fatal("本次追加应成功")
	}
	if got := s.BudgetNotice(); got != "" {
		t.Fatalf("剩余 6 轮不应提醒，实际 %q", got)
	}
	s.Round = s.MaxRounds - 3
	if got := s.BudgetNotice(); got == "" {
		t.Fatal("续命后再次进入收尾阶段应重新提醒")
	}
}

// TestNeedMoreBudgetToolReply 工具回复必须与真实剩余一致，不得出现"已追加"却未追加。
func TestNeedMoreBudgetToolReply(t *testing.T) {
	s := &WorkerSession{MaxRounds: 12, Round: 5}
	res := handleNeedMoreBudget(nil, map[string]any{"reason": "还需要验证文件上传"}, s)
	if res.IsErr {
		t.Fatalf("正常调用不应报错：%s", res.Output)
	}
	if !strings.Contains(res.Output, "已追加") {
		t.Fatalf("首次调用应如实告知已追加，实际 %q", res.Output)
	}
	if !strings.Contains(res.Output, "剩余 11 轮") {
		t.Fatalf("应回报真实剩余轮数（12+4-5=11），实际 %q", res.Output)
	}

	// 打满上限后必须改为引导收尾
	for i := 0; i < budgetMaxGrant; i++ {
		s.RequestMoreBudget("继续")
	}
	res = handleNeedMoreBudget(nil, map[string]any{"reason": "再看一眼"}, s)
	if strings.Contains(res.Output, "已追加") {
		t.Fatalf("超限后不得再回'已追加'，实际 %q", res.Output)
	}
	if !strings.Contains(res.Output, "上限") || !strings.Contains(res.Output, "submit_finding") {
		t.Fatalf("超限后应提示上限并引导提交，实际 %q", res.Output)
	}

	// 无会话上下文应报错而非静默
	if res := handleNeedMoreBudget(nil, map[string]any{"reason": "x"}, nil); !res.IsErr {
		t.Fatal("无会话上下文应报错")
	}
}
