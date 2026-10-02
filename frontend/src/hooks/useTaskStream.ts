/**
 * 任务实时事件流（WebSocket）。
 *
 * 对应后端 GET /api/tasks/{task_id}/stream：
 *   - 握手鉴权通过 ?token= 传递，后端 30s 无事件时下发 { kind: 'ping' } 保活；
 *   - 断线后 5s 自动重连（组件卸载或任务切换时停止）。
 */
import { useEffect, useRef, useState } from 'react'
import { wsUrl } from '@/api'
import type { TaskEvent } from '@/types'

interface Options {
  /** 内存中最多保留的事件条数。 */
  capacity?: number
  /** 是否启用连接。 */
  enabled?: boolean
  /** 忽略噪音事件（心跳 / 轮询类）。 */
  filterNoise?: boolean
  /** 每条事件到达时的回调（用于外部做增量处理）。 */
  onEvent?: (event: TaskEvent) => void
}

/** 视为噪音、默认不展示的事件种类。 */
const NOISE_KINDS = new Set(['ping', 'heartbeat', 'tick', 'poll', 'keepalive'])

/** 连接状态。 */
export type StreamStatus = 'idle' | 'connecting' | 'open' | 'closed'

export function useTaskStream(taskId: string | undefined, options: Options = {}) {
  const { capacity = 400, enabled = true, filterNoise = true, onEvent } = options
  const [events, setEvents] = useState<TaskEvent[]>([])
  const [status, setStatus] = useState<StreamStatus>('idle')
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  useEffect(() => {
    if (!taskId || !enabled) {
      setStatus('idle')
      return
    }
    let socket: WebSocket | null = null
    let timer: number | null = null
    let closed = false

    setEvents([])

    function connect() {
      if (closed || !taskId) return
      setStatus('connecting')
      socket = new WebSocket(wsUrl(taskId))

      socket.onopen = () => setStatus('open')

      socket.onmessage = (evt) => {
        let parsed: TaskEvent
        try {
          parsed = JSON.parse(evt.data as string) as TaskEvent
        } catch {
          return
        }
        const kind = String(parsed.kind || '')
        if (filterNoise && NOISE_KINDS.has(kind)) return
        // 无 id 的帧（如 ping）只做保活，不入列表。
        if (parsed.id === undefined || parsed.id === null) {
          onEventRef.current?.(parsed)
          return
        }
        setEvents((prev) => {
          const next = [...prev, parsed]
          return next.length > capacity ? next.slice(next.length - capacity) : next
        })
        onEventRef.current?.(parsed)
      }

      socket.onclose = () => {
        setStatus('closed')
        if (!closed) {
          timer = window.setTimeout(connect, 5000)
        }
      }

      socket.onerror = () => {
        socket?.close()
      }
    }

    connect()

    return () => {
      closed = true
      if (timer !== null) window.clearTimeout(timer)
      socket?.close()
      socket = null
    }
  }, [taskId, enabled, capacity, filterNoise])

  return { events, status }
}
