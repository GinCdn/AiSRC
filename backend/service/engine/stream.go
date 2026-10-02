package engine

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"AiSRC/constant"
	"AiSRC/core"
	"AiSRC/middleware"
	"AiSRC/model"
	"AiSRC/result"
	"AiSRC/utils"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// 活动流参数。
const (
	StreamHistoryLimit = 200
	StreamPingInterval = 25 * time.Second
	StreamWriteTimeout = 10 * time.Second
	StreamReadTimeout  = 70 * time.Second
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// StreamHandler WebSocket 实时活动流：GET /api/tasks/:task_id/stream
// 令牌来源优先级：query ?token= → Authorization → Cookie（浏览器 WS 无法自定义头）。
func StreamHandler(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		result.AbortWithMsg(c, result.BadRequest, "缺少任务 ID")
		return
	}

	// 鉴权：沿用与 REST 相同的令牌解析逻辑。
	if token := strings.TrimSpace(c.Query("token")); token != "" {
		c.Request.Header.Set("Authorization", "Bearer "+token)
	}
	role := middleware.ResolveRoleOf(c)
	if !middleware.AuthDisabled() && role == constant.RoleNone {
		result.AbortWithMsg(c, result.Unauthorized, "需要 AiSRC 访问令牌")
		return
	}
	observer := role == constant.RoleObserver

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// 对齐原版 stream.py：WebSocket 全量投递（原版仅在历史回放 REST 用
	// verbose 过滤）。此前这里恒为 false，worker 的 tool_call/tool_result/
	// worker_thought/llm_round_start 细节事件全被过滤，前端展开「挖掘过程」
	// 永远是「暂无工具/思考细节」。observer 仍走 writeEvent 脱敏。
	verbose := true

	sub := BusInstance().Subscribe(taskID)
	defer BusInstance().Unsubscribe(taskID, sub)

	// 1) 历史回放：刷新页面后仍能看到关键事件。
	for _, event := range HistoryEvents(taskID, StreamHistoryLimit, verbose) {
		if err := writeEvent(conn, event, observer); err != nil {
			return
		}
	}

	// 2) 客户端读协程：只用于感知断连。
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.SetReadLimit(1024)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// 3) 实时推送 + 心跳。
	ping := time.NewTicker(StreamPingInterval)
	defer ping.Stop()
	for {
		select {
		case <-done:
			return
		case event, ok := <-sub.Events():
			if !ok {
				return
			}
			if !EventVisible(event.Kind, event.Level, verbose) {
				continue
			}
			if err := writeEvent(conn, event, observer); err != nil {
				return
			}
		case <-ping.C:
			conn.SetWriteDeadline(time.Now().Add(StreamWriteTimeout))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"kind":"ping"}`)); err != nil {
				return
			}
		}
	}
}

// writeEvent 向连接写入一条事件（observer 角色下对敏感字段脱敏）。
func writeEvent(conn *websocket.Conn, event Event, observer bool) error {
	if observer {
		event = sanitizeEventForObserver(event)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil
	}
	conn.SetWriteDeadline(time.Now().Add(StreamWriteTimeout))
	return conn.WriteMessage(websocket.TextMessage, payload)
}

// HistoryEvents 从事件表回放历史事件（按可见性过滤）。
func HistoryEvents(taskID string, limit int, verbose bool) []Event {
	if core.Db == nil || limit <= 0 {
		return nil
	}
	var rows []model.TaskEvent
	core.Db.Where("task_id = ?", taskID).Order("id DESC").Limit(limit * 3).Find(&rows)

	events := make([]Event, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		row := rows[i]
		kind := row.Kind
		level := row.Level
		if !EventVisible(kind, level, verbose) {
			continue
		}
		event := NewEvent(row.Agent, kind, level, row.Message)
		event.Ts = utils.ToCSTISO(row.Ts)
		for k, v := range row.Payload {
			event = event.With(k, v)
		}
		events = append(events, event)
		if len(events) >= limit {
			break
		}
	}
	return events
}

// sanitizeEventForObserver 观摩模式下对事件附加字段脱敏。
func sanitizeEventForObserver(event Event) Event {
	if len(event.Extra) == 0 {
		return event
	}
	cleaned := make(map[string]any, len(event.Extra))
	for k, v := range event.Extra {
		if text, ok := v.(string); ok {
			cleaned[k] = utils.SanitizeSecretText(text)
			continue
		}
		cleaned[k] = v
	}
	event.Extra = cleaned
	return event
}
