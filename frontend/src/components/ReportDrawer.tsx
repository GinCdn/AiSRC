import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  App,
  Button,
  Checkbox,
  Descriptions,
  Divider,
  Drawer,
  Empty,
  Input,
  List,
  Modal,
  Select,
  Space,
  Spin,
  Tabs,
  Tag,
  Timeline,
  Typography
} from 'antd'
import {
  CheckOutlined,
  CloseOutlined,
  CopyOutlined,
  RobotOutlined,
  SaveOutlined,
  SendOutlined,
  StopOutlined,
  ThunderboltOutlined,
  UndoOutlined,
  UserOutlined
} from '@ant-design/icons'
import { systemApi, userApi } from '@/api'
import { useAuthStore } from '@/store'
import {
  SEVERITY_COLOR,
  SEVERITY_LABEL,
  USER_STATUS_LABEL,
  VERDICT_LABEL,
  VULN_TYPE_LABEL,
  fmtLocalTime,
  prettyJSON
} from '@/utils/format'
import type { FindingStep, FindingView, Review } from '@/types'
import { copyText } from '@/utils/clipboard'
import { buildEdusrcToolReport, buildReportMd, effectiveSeverity, stripStepIndex } from '@/utils/report'

/* ============================================================================
 * 内部工具
 * 报告构建与剪贴板已抽出为 @/utils/report 与 @/utils/clipboard（对标原版
 * report.js / clipboard.js），本文件只保留抽屉自身的视图辅助函数。
 * ========================================================================== */

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

function str(v: unknown, fallback = ''): string {
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return fallback
}

/** 观摩角色脱敏：屏蔽链接 / IP / 凭证类文本。 */
const URL_RE = /https?:\/\/[^\s<>"'`]+/gi
const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g
const CRED_RE = /\b(api[_-]?key|token|secret|password|passwd|pwd|cookie|authorization|bearer)\b\s*[:=]\s*\S+/gi
function redact(text: unknown): string {
  return str(text)
    .replace(URL_RE, '[已脱敏链接]')
    .replace(IP_RE, '[已脱敏IP]')
    .replace(CRED_RE, (m) => `${m.split(/[:=]/)[0].trim()}=[已脱敏]`)
}

/** 取生效值：用户编辑覆盖优先，其次原始字段。 */
function effField(f: FindingView, key: string): unknown {
  const e = asRecord(f.review?.user_edits)
  const v = e[key]
  if (v !== undefined && v !== null && v !== '') return v
  return asRecord(f)[key]
}

/** 信度中文名。 */
const CONF_LABEL: Record<string, string> = { confirmed: '确认', likely: '疑似', uncertain: '不确定' }

/** 严重级候选。 */
const SEVERITY_OPTIONS = ['严重', '高危', '中危', '低危']

/** 复审状态候选。 */
const USER_STATUS_OPTIONS = ['pending', 'passed', 'rejected', 'deepening']

/** 助手工具中文名。 */
const TOOL_LABEL: Record<string, string> = {
  http_request: 'HTTP 请求',
  run_shell: '执行命令',
  propose_report_edits: '提出改稿'
}

/** 助手欢迎语。 */
const ASSISTANT_WELCOME =
  '我是这份漏洞的报告助手。点下面的快捷指令，或直接问证据、等级、复现怎么写。润色结果可以一键写进编辑器。'

/** 助手快捷指令。 */
const ASSISTANT_PRESETS: Array<{ label: string; text: string }> = [
  { label: '审证据', text: '判断这份报告证据链是否足够提交 SRC：缺什么、有没有像误报的地方、过审概率怎么看。' },
  { label: '润色成SRC口径', text: '按当前 SRC 类型把标题、描述、影响范围、复现步骤和 PoC 改成可直接提交的口径，并给出改稿建议。' },
  { label: '补复现步骤', text: '把复现步骤写成审核员能跟着点的逐步操作，补齐请求要点和判定成功的标志。' },
  { label: '校准等级', text: '根据实际危害校准严重/高危/中危/低危，说明为什么现在这个等级站得住或应该下调。' },
  { label: '现场再验证', text: '对 PoC 或关键接口再发一次定向请求，看漏洞是否仍在，并解读状态码和关键响应。' }
]


/* ---------------------------------------------------------------- 对话类型 */

interface ChatStep {
  type: string
  label: string
  result?: string
  tool?: string
}

interface ChatMsg {
  id: string
  role: 'user' | 'assistant'
  content: string
  partial: string
  steps: ChatStep[]
  streaming: boolean
  suggestedEdits: Record<string, unknown> | null
}

let seq = 0
function nextId(): string {
  seq += 1
  return `m${seq}`
}

/** 工具/思考步骤文案。 */
function stepLabel(type: string, raw: Record<string, unknown>): string {
  if (type === 'thinking') return str(raw.text) || '分析中…'
  if (type === 'tool_call') return `${TOOL_LABEL[str(raw.tool)] || str(raw.tool) || '工具'}：${str(raw.summary)}`
  if (type === 'tool_result') return `↳ ${str(raw.summary) || '完成'}`
  return str(raw.text)
}

/** 推荐改稿里可应用的字段。 */
function editFields(edits: Record<string, unknown> | null): string[] {
  if (!edits) return []
  return ['title', 'description', 'affected_scope', 'steps', 'poc', 'severity'].filter((k) => edits[k])
}

/**
 * 容错解析助手流式事件：
 * 兼容 { type: thinking/tool_call/tool_result/assistant_partial/suggested_edits/final/done }
 * 与 { delta / content / done / message } 两类协议。
 */
function applyAssistantEvent(m: ChatMsg, raw: Record<string, unknown>): ChatMsg {
  const type = str(raw.type)
  const delta = str(raw.delta)
  const text = str(raw.text)
  const content = str(raw.content)
  const answer = str(raw.answer)
  const notice = str(raw.message) || str(raw.error)
  const next: ChatMsg = { ...m }

  // 步骤类
  if (type === 'thinking' || type === 'tool_call' || type === 'tool_result') {
    const label = stepLabel(type, raw)
    const steps = [...next.steps]
    if (type === 'tool_result' && steps.length && steps[steps.length - 1].type === 'tool_call') {
      steps[steps.length - 1] = { ...steps[steps.length - 1], result: label }
    } else {
      steps.push({ type, label, tool: str(raw.tool) })
    }
    next.steps = steps
    return next
  }
  if (type === 'assistant_partial') {
    next.partial = text
    return next
  }
  if (type === 'suggested_edits') {
    next.suggestedEdits = asRecord(raw.edits)
    return next
  }
  if (type === 'final') {
    next.content = text || next.content
    next.partial = ''
    const sug = asRecord(raw.suggested_edits)
    if (Object.keys(sug).length) next.suggestedEdits = sug
    return next
  }
  if (type === 'done') {
    next.content = answer || content || next.content || next.partial || '已完成。'
    next.partial = ''
    next.streaming = false
    const sug = asRecord(raw.suggested_edits)
    if (Object.keys(sug).length) next.suggestedEdits = sug
    return next
  }

  // 通用流式协议
  if (delta) {
    next.partial += delta
    if (raw.done) {
      next.content = next.partial
      next.partial = ''
      next.streaming = false
    }
    return next
  }
  if (content) {
    if (raw.done) {
      next.content = content
      next.partial = ''
      next.streaming = false
    } else {
      next.partial += content
    }
    return next
  }
  if (raw.done) {
    next.content = next.content || next.partial || answer || '已完成。'
    next.partial = ''
    next.streaming = false
    return next
  }
  // 未知事件但带提示文案：作为步骤展示，避免静默丢信息
  if (notice) {
    next.steps = [...next.steps, { type: 'notice', label: notice }]
    return next
  }
  return next
}

/* ============================================================================
 * 组件
 * ========================================================================== */

interface Props {
  open: boolean
  findingId: string | null
  taskId?: string
  /** 任务 SRC 类型；企业 SRC 不生成 EduSRC 报告，隐藏对应按钮（对齐原版 isEnterprise）。 */
  srcType?: string
  onClose: () => void
  /** 复审/深化等写操作完成后通知外层刷新看板 */
  onChanged?: () => void
}

/**
 * 漏洞报告抽屉 + AI 报告助手对话。
 *
 * 覆盖：漏洞详情（标题/类型/等级/目标/复现步骤/证据/攻击链路/自检/LLM 模型与端点）、
 * 用户复审表单（user_status / user_severity / user_notes / submitted）、一键深化、
 * 恢复归档，以及报告助手流式对话（支持 AbortController 停止生成）。
 */
export default function ReportDrawer({ open, findingId, taskId, srcType, onClose, onChanged }: Props) {
  const { message } = App.useApp()
  const role = useAuthStore((s) => s.role)
  const writable = role === 'full'
  const isObserver = role === 'observer'
  /** 企业 SRC 不产出 EduSRC 报告（对齐原版 ReportDrawer 的 isEnterprise 判定）。 */
  const isEnterprise = srcType === 'enterprise'

  const [finding, setFinding] = useState<FindingView | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  // 复审表单
  const [userStatus, setUserStatus] = useState('pending')
  const [userSeverity, setUserSeverity] = useState('')
  const [userNotes, setUserNotes] = useState('')
  const [submitted, setSubmitted] = useState(false)

  // 内容编辑
  const [editing, setEditing] = useState(false)
  const [editTitle, setEditTitle] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editScope, setEditScope] = useState('')
  const [editSteps, setEditSteps] = useState('')
  const [editPoc, setEditPoc] = useState('')

  // 深化
  const [deepenOpen, setDeepenOpen] = useState(false)
  const [deepenText, setDeepenText] = useState('')
  const [deepening, setDeepening] = useState(false)

  // 助手
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatBusy, setChatBusy] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const chatRef = useRef<HTMLDivElement | null>(null)

  const [activeTab, setActiveTab] = useState('report')

  const mask = useCallback((text: unknown): string => (isObserver ? redact(text) : str(text)), [isObserver])

  const review: Review | undefined = finding?.review

  /** 生效严重级（展示用）。 */
  const effSev = finding ? effectiveSeverity(finding) : '-'

  /** 加载详情并重置表单 / 对话。 */
  useEffect(() => {
    if (!open || !findingId) {
      setFinding(null)
      return
    }
    let cancelled = false
    setLoading(true)
    setEditing(false)
    setDeepenOpen(false)
    setDeepenText('')
    setChatInput('')
    setChatBusy(false)
    setActiveTab('report')
    // 切换 finding 时中断上一轮生成
    abortRef.current?.abort()
    abortRef.current = null
    void (async () => {
      try {
        const f = await userApi.getFinding(findingId)
        if (cancelled) return
        setFinding(f)
        const rv: Partial<Review> = f.review ?? {}
        setUserStatus(str(rv.user_status, 'pending') || 'pending')
        setUserSeverity(str(rv.user_severity) || str(f.severity_final) || str(f.severity))
        setUserNotes(str(rv.user_notes))
        setSubmitted(!!rv.submitted)
        const e = asRecord(rv.user_edits)
        setEditTitle(str(e.title) || str(f.title))
        setEditDesc(str(e.description) || str(asRecord(f).description))
        setEditScope(str(e.affected_scope) || str(asRecord(f).affected_scope))
        const stepsRaw = e.steps ?? asRecord(f).steps
        setEditSteps(
          Array.isArray(stepsRaw)
            ? stepsRaw
                .map((s) => (typeof s === 'string' ? s : str(asRecord(s).title) || str(asRecord(s).detail)))
                .filter(Boolean)
                .join('\n')
            : str(stepsRaw)
        )
        setEditPoc(str(e.poc) || str(asRecord(f).poc))
        // 恢复历史助手对话
        const savedRaw = Array.isArray(f.assistant_msgs)
          ? f.assistant_msgs
          : Array.isArray(asRecord(f).assistant_messages)
            ? (asRecord(f).assistant_messages as unknown[])
            : []
        const history: ChatMsg[] = savedRaw.map((raw) => {
          const r = asRecord(raw)
          return {
            id: nextId(),
            role: str(r.role) === 'user' ? 'user' : 'assistant',
            content: str(r.content),
            partial: '',
            steps: [],
            streaming: false,
            suggestedEdits: null
          }
        })
        setMessages(
          history.length ? history : [{ id: nextId(), role: 'assistant', content: ASSISTANT_WELCOME, partial: '', steps: [], streaming: false, suggestedEdits: null }]
        )
      } catch (e) {
        if (!cancelled) message.error(`加载漏洞失败：${e instanceof Error ? e.message : String(e)}`)
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [open, findingId, message])

  // 关闭 / 卸载时中断生成
  useEffect(
    () => () => {
      abortRef.current?.abort()
    },
    []
  )

  // 助手对话自动滚动到底部
  useEffect(() => {
    const el = chatRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages])

  /** 写操作后回读详情并通知外层。 */
  const reload = useCallback(async () => {
    if (!findingId) return
    try {
      const f = await userApi.getFinding(findingId)
      setFinding(f)
    } catch {
      /* 忽略回读失败 */
    }
  }, [findingId])

  /** 保存复审（表单 + 内容编辑）。 */
  async function saveReview() {
    if (!finding || saving) return
    setSaving(true)
    try {
      await userApi.updateResult(finding.id, {
        user_status: userStatus,
        user_severity: userSeverity,
        user_notes: userNotes,
        submitted,
        user_edits: {
          title: editTitle,
          description: editDesc,
          affected_scope: editScope,
          steps: editSteps
            .split('\n')
            .map((s) => s.trim())
            .filter(Boolean),
          poc: editPoc
        }
      })
      message.success('已保存复审')
      setEditing(false)
      await reload()
      onChanged?.()
    } catch (e) {
      message.error(`保存失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setSaving(false)
    }
  }

  /** 裁决：通过 / 驳回。 */
  async function decide(status: 'passed' | 'rejected') {
    if (!finding || saving) return
    setSaving(true)
    try {
      const res = await userApi.updateResult(finding.id, {
        user_status: status,
        user_severity: userSeverity,
        user_notes: userNotes
      })
      const rec = asRecord(res)
      if (status === 'passed') {
        const trigger = rec.killsweep_triggered ? '，通杀 Hunter 已启动' : ''
        const skip = str(rec.killsweep_skipped_reason)
        message.success(`已通过 → 进入待提交${trigger}${skip ? `，${skip}` : ''}`)
      } else {
        message.success('已驳回')
      }
      onChanged?.()
      onClose()
    } catch (e) {
      message.error(`操作失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setSaving(false)
    }
  }

  /** 标记已提交。 */
  async function markSubmitted() {
    if (!finding || saving) return
    setSaving(true)
    try {
      await userApi.updateResult(finding.id, { submitted: true })
      setSubmitted(true)
      message.success('已标记为已提交')
      onChanged?.()
      onClose()
    } catch (e) {
      message.error(`操作失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setSaving(false)
    }
  }

  /** 恢复归档：专用接口把 verdict 改回 accepted，才能真正进复审队列。 */
  async function restore() {
    if (!finding || saving) return
    setSaving(true)
    try {
      await userApi.restoreResult(finding.id)
      message.success('已恢复到复审队列')
      onChanged?.()
      onClose()
    } catch (e) {
      message.error(`恢复失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setSaving(false)
    }
  }

  /** 一键深化。 */
  async function submitDeepen() {
    if (!finding || deepening) return
    const directive = deepenText.trim()
    if (!directive) {
      message.warning('请先写一句深挖指令')
      return
    }
    setDeepening(true)
    try {
      const r = await userApi.deepenResult(finding.id, directive)
      message.success(str(asRecord(r).message) || '已打回深挖，目标重新入队')
      setDeepenOpen(false)
      setDeepenText('')
      onChanged?.()
      onClose()
    } catch (e) {
      message.error(`深化失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setDeepening(false)
    }
  }

  /** 复制 Markdown 报告。 */
  async function copyReport() {
    if (!finding) return
    const ok = await copyText(buildReportMd(finding))
    if (ok) message.success('报告已复制（Markdown）')
    else message.error('复制失败，请手动选中')
  }

  /** 复制 EduSRC 油猴脚本可用的单条 JSON（企业 SRC 不产出，按钮也不显示）。 */
  async function copyEdusrcJson() {
    if (!finding) return
    const text = JSON.stringify(buildEdusrcToolReport(finding), null, 2)
    const ok = await copyText(text)
    if (ok) message.success('已复制 EduSRC 工具 JSON')
    else message.error('复制失败，请使用导出按钮')
  }

  /** 复制助手回复。 */
  async function copyAssistant(m: ChatMsg) {
    const text = (m.content || m.partial || '').trim()
    if (!text) {
      message.warning('还没有可复制的内容')
      return
    }
    const ok = await copyText(text)
    if (ok) message.success('已复制助手回复')
    else message.error('复制失败')
  }

  /** 停止生成。 */
  function stopAssistant() {
    abortRef.current?.abort()
  }

  /** 发起助手对话。 */
  async function askAssistant(preset?: string) {
    const text = (preset ?? chatInput).trim()
    if (!text || chatBusy || !finding) return
    setChatInput('')
    const userMsg: ChatMsg = {
      id: nextId(),
      role: 'user',
      content: text,
      partial: '',
      steps: [],
      streaming: false,
      suggestedEdits: null
    }
    const liveId = nextId()
    const liveMsg: ChatMsg = {
      id: liveId,
      role: 'assistant',
      content: '',
      partial: '',
      steps: [],
      streaming: true,
      suggestedEdits: null
    }
    setMessages((prev) => [...prev, userMsg, liveMsg])
    setChatBusy(true)
    const controller = new AbortController()
    abortRef.current = controller

    const patch = (fn: (m: ChatMsg) => ChatMsg) =>
      setMessages((prev) => prev.map((m) => (m.id === liveId ? fn(m) : m)))

    try {
      await systemApi.reportAssistantStream(
        finding.id,
        text,
        (raw) => patch((m) => applyAssistantEvent(m, asRecord(raw))),
        controller.signal
      )
      patch((m) => (m.streaming ? { ...m, streaming: false, partial: '' } : m))
    } catch (e) {
      const aborted = e instanceof DOMException ? e.name === 'AbortError' : str(asRecord(e).name) === 'AbortError'
      patch((m) => {
        if (aborted) {
          return { ...m, content: m.content || m.partial || '已停止。', partial: '', streaming: false }
        }
        return { ...m, content: `报告助手异常：${e instanceof Error ? e.message : String(e)}`, streaming: false }
      })
    } finally {
      setChatBusy(false)
      abortRef.current = null
    }
  }

  /** 把推荐改稿写入编辑器。 */
  function applySuggestedEdits(edits: Record<string, unknown> | null) {
    if (!edits) return
    if (edits.title) setEditTitle(str(edits.title))
    if (edits.description) setEditDesc(str(edits.description))
    if (edits.affected_scope) setEditScope(str(edits.affected_scope))
    if (Array.isArray(edits.steps)) setEditSteps(edits.steps.map((s) => str(s)).join('\n'))
    if (edits.poc) setEditPoc(str(edits.poc))
    if (edits.severity) setUserSeverity(str(edits.severity))
    setEditing(true)
    setActiveTab('report')
    message.success('已填入编辑器，确认后点保存复审')
  }

  /** 复现步骤归一化。 */
  const steps: FindingStep[] = useMemo(() => (Array.isArray(finding?.steps) ? finding.steps : []), [finding])

  /** 攻击链路（数组 / 对象两种形态）。 */
  const killChain = useMemo(() => {
    const raw: unknown = finding?.kill_chain
    if (Array.isArray(raw)) {
      return raw.map((c) => {
        const r = asRecord(c)
        return { method: str(r.method), detail: str(r.detail) }
      })
    }
    return []
  }, [finding])

  /** 证据。 */
  const evidence = useMemo(() => asRecord(finding?.evidence), [finding])
  const selfCheck = useMemo(() => asRecord(finding?.self_check), [finding])

  /** 是否已在队列之外（用于决定显示「恢复到复审」）。 */
  const canRestore = userStatus === 'rejected'

  const tabItems = [
    {
      key: 'report',
      label: '报告详情',
      children: (
        <Spin spinning={loading}>
          {!finding ? (
            <Empty description="暂无数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Descriptions
                size="small"
                column={2}
                bordered
                items={[
                  { key: 'type', label: '漏洞类型', children: VULN_TYPE_LABEL[finding.vuln_type] || finding.vuln_type || '-' },
                  { key: 'sev', label: '严重级', children: <Tag color={SEVERITY_COLOR[effSev] || 'default'}>{effSev}</Tag> },
                  { key: 'target', label: '目标', span: 2, children: <span className="mono">{mask(finding.target_url)}</span> },
                  {
                    key: 'status',
                    label: '复审状态',
                    children: USER_STATUS_LABEL[str(review?.user_status)] || str(review?.user_status) || '待复审'
                  },
                  {
                    key: 'verdict',
                    label: 'AI 结论',
                    children: VERDICT_LABEL[str(review?.verdict)] || str(review?.verdict) || '-'
                  },
                  {
                    key: 'score',
                    label: '评分 / 信度',
                    children: `${review?.score ?? '-'} · ${CONF_LABEL[str(review?.confidence)] || str(review?.confidence) || '-'}`
                  },
                  {
                    key: 'submitted',
                    label: '提交状态',
                    children: submitted ? <Tag color="green">已提交</Tag> : <Tag>未提交</Tag>
                  },
                  {
                    key: 'owner',
                    label: '归属单位',
                    children: mask(str(asRecord(finding).edu_school) || str(asRecord(finding).owner) || '待确认')
                  },
                  { key: 'created', label: '发现时间', children: fmtLocalTime(finding.created_at) },
                  { key: 'model', label: '产出模型', children: finding.llm_model || '-' },
                  { key: 'base', label: 'LLM 端点', span: 2, children: <span className="mono">{mask(finding.llm_base_url) || '-'}</span> }
                ]}
              />

              <div>
                <Typography.Text strong>漏洞描述</Typography.Text>
                <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 4 }}>
                  {mask(str(effField(finding, 'description'))) || '-'}
                </Typography.Paragraph>
                <Typography.Text strong>影响范围</Typography.Text>
                <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 4 }}>
                  {mask(str(effField(finding, 'affected_scope'))) || '-'}
                </Typography.Paragraph>
              </div>

              <div>
                <Typography.Text strong>复现步骤（{steps.length}）</Typography.Text>
                {steps.length ? (
                  <Space direction="vertical" size={8} style={{ width: '100%', marginTop: 6 }}>
                    {steps.map((s, i) => {
                      // 原版契约：steps 是 string[]（每步一句话）。对象形态 {title,detail,request,response}
                      // 是编辑器/改稿兼容形态——纯 string 时标题行直接显示整句，否则只显示「步骤」二字（实测踩过）。
                      const isPlain = typeof s === 'string'
                      // AI 步骤文本常自带「1. 」序号，渲染层统一编号前先剥掉，避免双重编号。
                      const title = isPlain ? stripStepIndex(s as string) : str((s as Record<string, unknown>).title)
                      const detail = isPlain ? '' : str((s as Record<string, unknown>).detail)
                      const req = isPlain ? '' : str((s as Record<string, unknown>).request)
                      const resp = isPlain ? '' : str((s as Record<string, unknown>).response)
                      return (
                        <div key={i} style={{ borderLeft: '2px solid var(--aisrc-border)', paddingLeft: 10 }}>
                          <Typography.Text strong style={isPlain ? { fontWeight: 400, whiteSpace: 'pre-wrap' } : undefined}>
                            {i + 1}. {mask(title) || '步骤'}
                          </Typography.Text>
                          {detail ? (
                            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', margin: '2px 0' }}>
                              {mask(detail)}
                            </Typography.Paragraph>
                          ) : null}
                          {req ? (
                            <>
                              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                请求
                              </Typography.Text>
                              <pre className="code-block">{mask(req)}</pre>
                            </>
                          ) : null}
                          {resp ? (
                            <>
                              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                响应
                              </Typography.Text>
                              <pre className="code-block">{mask(resp)}</pre>
                            </>
                          ) : null}
                        </div>
                      )
                    })}
                  </Space>
                ) : (
                  <Typography.Paragraph type="secondary" style={{ marginTop: 4 }}>
                    -
                  </Typography.Paragraph>
                )}
              </div>

              <div>
                <Typography.Text strong>证据链</Typography.Text>
                {evidence.extracted_data_sample ? (
                  <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', margin: '4px 0' }}>
                    {mask(str(evidence.extracted_data_sample))}
                  </Typography.Paragraph>
                ) : null}
                {evidence.tool_output ? <pre className="code-block">{mask(str(evidence.tool_output))}</pre> : null}
                {evidence.notes ? (
                  <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>{mask(str(evidence.notes))}</Typography.Paragraph>
                ) : null}
                <pre className="code-block">{mask(prettyJSON(evidence))}</pre>
              </div>

              {/* PoC / Payload：仅补充呈现（用户编辑优先），三条全空时不占位 */}
              {str(effField(finding, 'poc')) || str(asRecord(finding).raw_request) || str(asRecord(finding).raw_response) ? (
                <div>
                  <Typography.Text strong>PoC / Payload</Typography.Text>
                  {str(effField(finding, 'poc')) ? (
                    <>
                      <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 4 }}>
                        PoC
                      </Typography.Text>
                      <pre className="code-block">{mask(str(effField(finding, 'poc')))}</pre>
                    </>
                  ) : null}
                  {str(asRecord(finding).raw_request) ? (
                    <>
                      <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 4 }}>
                        原始请求
                      </Typography.Text>
                      <pre className="code-block">{mask(str(asRecord(finding).raw_request))}</pre>
                    </>
                  ) : null}
                  {str(asRecord(finding).raw_response) ? (
                    <>
                      <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 4 }}>
                        原始响应
                      </Typography.Text>
                      <pre className="code-block">{mask(str(asRecord(finding).raw_response))}</pre>
                    </>
                  ) : null}
                </div>
              ) : null}

              <div>
                <Typography.Text strong>攻击链路（{killChain.length}）</Typography.Text>
                {killChain.length ? (
                  <Timeline
                    style={{ marginTop: 8 }}
                    items={killChain.map((c, i) => ({
                      key: i,
                      color: 'blue',
                      children: (
                        <Space direction="vertical" size={0}>
                          <Typography.Text strong>{mask(c.method)}</Typography.Text>
                          {c.detail ? <Typography.Text type="secondary">{mask(c.detail)}</Typography.Text> : null}
                        </Space>
                      )
                    }))}
                  />
                ) : (
                  <pre className="code-block">{mask(prettyJSON(asRecord(finding.kill_chain)))}</pre>
                )}
              </div>

              <div>
                <Typography.Text strong>自检（self_check）</Typography.Text>
                {/* 对齐原版：无自检数据显示「（无）」，不渲染空 JSON 块 */}
                <pre className="code-block">
                  {mask(Object.keys(selfCheck).length ? prettyJSON(selfCheck) : '（无）')}
                </pre>
              </div>

              <Divider style={{ margin: '8px 0' }} />

              {/* 内容编辑 */}
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                  <Typography.Text strong>报告内容编辑</Typography.Text>
                  <Button size="small" onClick={() => setEditing((v) => !v)} disabled={!writable}>
                    {editing ? '取消编辑' : '编辑内容'}
                  </Button>
                </Space>
                {editing ? (
                  <Space direction="vertical" size={6} style={{ width: '100%' }}>
                    <Input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} addonBefore="标题" />
                    <Input.TextArea rows={3} value={editDesc} onChange={(e) => setEditDesc(e.target.value)} placeholder="描述" />
                    <Input.TextArea
                      rows={2}
                      value={editScope}
                      onChange={(e) => setEditScope(e.target.value)}
                      placeholder="影响范围"
                    />
                    <Input.TextArea
                      rows={4}
                      value={editSteps}
                      onChange={(e) => setEditSteps(e.target.value)}
                      placeholder="复现步骤（每行一步）"
                    />
                    <Input.TextArea rows={3} value={editPoc} onChange={(e) => setEditPoc(e.target.value)} placeholder="PoC" />
                  </Space>
                ) : null}
              </Space>

              <Divider style={{ margin: '8px 0' }} />

              {/* 用户复审表单 */}
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Typography.Text strong>人工复审</Typography.Text>
                <Space size={8} wrap>
                  <Select
                    value={userStatus}
                    onChange={setUserStatus}
                    disabled={!writable}
                    style={{ width: 140 }}
                    options={USER_STATUS_OPTIONS.map((s) => ({ value: s, label: USER_STATUS_LABEL[s] || s }))}
                  />
                  <Select
                    value={userSeverity || undefined}
                    onChange={setUserSeverity}
                    disabled={!writable}
                    placeholder="复审等级"
                    style={{ width: 140 }}
                    options={SEVERITY_OPTIONS.map((s) => ({ value: s, label: `${s}（${SEVERITY_LABEL[s === '严重' ? 'critical' : s === '高危' ? 'high' : s === '中危' ? 'medium' : 'low'] || ''}）` }))}
                  />
                  <Checkbox checked={submitted} disabled={!writable} onChange={(e) => setSubmitted(e.target.checked)}>
                    已提交
                  </Checkbox>
                </Space>
                <Input.TextArea
                  rows={3}
                  value={userNotes}
                  disabled={!writable}
                  onChange={(e) => setUserNotes(e.target.value)}
                  placeholder="人工复审意见…"
                />
                {writable ? (
                  <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={saveReview}>
                    保存复审
                  </Button>
                ) : (
                  <Typography.Text type="secondary">
                    {role === 'readonly' ? '只读权限不可写' : '未认证，无法复审'}
                  </Typography.Text>
                )}
              </Space>
            </Space>
          )}
        </Spin>
      )
    },
    {
      key: 'assistant',
      label: (
        <Space size={6}>
          <RobotOutlined />
          AI 报告助手
        </Space>
      ),
      children: (
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Space style={{ width: '100%', justifyContent: 'space-between' }} wrap>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {writable ? '问证据、等级、复现；可写稿进编辑器，也可做少量定向验证' : '只读模式不可发送'}
            </Typography.Text>
            {chatBusy ? (
              <Button size="small" danger icon={<StopOutlined />} onClick={stopAssistant}>
                停止
              </Button>
            ) : null}
          </Space>
          {writable ? (
            <Space size={6} wrap>
              {ASSISTANT_PRESETS.map((p) => (
                <Button key={p.label} size="small" disabled={chatBusy} onClick={() => askAssistant(p.text)}>
                  {p.label}
                </Button>
              ))}
            </Space>
          ) : null}

          <div
            ref={chatRef}
            className="chat-scroll"
            style={{ height: 380, border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 10 }}
          >
            {messages.map((m) => (
              <div key={m.id} className={`chat-msg ${m.role}`}>
                <span className="chat-avatar">{m.role === 'user' ? <UserOutlined /> : <RobotOutlined />}</span>
                <div className="chat-bubble">
                  {m.steps.length ? (
                    <Space direction="vertical" size={2} style={{ width: '100%', marginBottom: 6 }}>
                      {m.steps.map((s, si) => (
                        <Typography.Text key={si} type="secondary" style={{ fontSize: 12 }}>
                          {s.type === 'tool_call' ? '⚙' : s.type === 'thinking' ? '…' : s.type === 'notice' ? '!' : '•'} {s.label}
                          {s.result ? ` ${s.result}` : ''}
                        </Typography.Text>
                      ))}
                    </Space>
                  ) : null}
                  {m.content ? <div style={{ whiteSpace: 'pre-wrap' }}>{mask(m.content)}</div> : null}
                  {m.streaming && m.partial && !m.content ? (
                    <div style={{ whiteSpace: 'pre-wrap' }}>{mask(m.partial)}</div>
                  ) : null}
                  {m.streaming && !m.content && !m.partial && !m.steps.length ? (
                    <Typography.Text type="secondary">正在分析…</Typography.Text>
                  ) : null}
                  {m.streaming ? <span>▍</span> : null}
                  {editFields(m.suggestedEdits).length ? (
                    <Space style={{ marginTop: 6 }} size={6} wrap>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        可应用改稿：{editFields(m.suggestedEdits).join('、')}
                      </Typography.Text>
                      <Button size="small" type="primary" disabled={!writable} onClick={() => applySuggestedEdits(m.suggestedEdits)}>
                        写入编辑器
                      </Button>
                    </Space>
                  ) : null}
                  {m.role === 'assistant' && (m.content || m.partial) && !m.streaming ? (
                    <div style={{ marginTop: 6 }}>
                      <Button size="small" type="text" icon={<CopyOutlined />} onClick={() => copyAssistant(m)}>
                        复制
                      </Button>
                    </div>
                  ) : null}
                </div>
              </div>
            ))}
          </div>

          {writable ? (
            <Space.Compact style={{ width: '100%' }}>
              <Input.TextArea
                rows={2}
                value={chatInput}
                disabled={chatBusy}
                placeholder="例：这个洞为什么不是普通信息泄露？再 curl 一下 PoC 看状态码。"
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => {
                  // 跳过 IME 组合期，Enter 发送、Shift+Enter 换行、Esc 停止
                  if (e.key === 'Escape') {
                    stopAssistant()
                    return
                  }
                  if (e.key === 'Enter' && !e.shiftKey) {
                    if (e.nativeEvent.isComposing) return
                    e.preventDefault()
                    void askAssistant()
                  }
                }}
              />
              {chatBusy ? (
                <Button danger icon={<StopOutlined />} onClick={stopAssistant}>
                  停止
                </Button>
              ) : (
                <Button
                  type="primary"
                  icon={<SendOutlined />}
                  disabled={!chatInput.trim()}
                  onClick={() => askAssistant()}
                >
                  发送
                </Button>
              )}
            </Space.Compact>
          ) : null}
          {writable ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              Enter 发送 · Shift+Enter 换行 · Esc 停止
            </Typography.Text>
          ) : null}
        </Space>
      )
    }
  ]

  return (
    <Drawer
      open={open}
      placement="right"
      width={780}
      onClose={onClose}
      destroyOnClose={false}
      title={
        <Space size={8} wrap>
          <Tag color={SEVERITY_COLOR[effSev] || 'default'} style={{ marginInlineEnd: 0 }}>
            {effSev}
          </Tag>
          <Typography.Text strong ellipsis style={{ maxWidth: 420 }}>
            {mask(str(review?.user_edits?.title) || finding?.title || '漏洞报告')}
          </Typography.Text>
          {finding ? <Typography.Text type="secondary">{taskId ? '' : ''}</Typography.Text> : null}
        </Space>
      }
      extra={
        <Space size={8}>
          <Button size="small" icon={<CopyOutlined />} onClick={copyReport} disabled={!finding}>
            复制 Markdown
          </Button>
          {!isEnterprise ? (
            <Button size="small" icon={<CopyOutlined />} onClick={() => void copyEdusrcJson()} disabled={!finding}>
              复制 EduSRC JSON
            </Button>
          ) : null}
        </Space>
      }
      footer={
        writable && finding ? (
          <Space wrap>
            {/* 已提交后裁决动作失去意义（已在待提交池走完流程），收起避免误点 */}
            {!submitted ? (
              <>
                <Button type="primary" icon={<CheckOutlined />} loading={saving} onClick={() => decide('passed')}>
                  通过（进待提交）
                </Button>
                <Button danger icon={<CloseOutlined />} loading={saving} onClick={() => decide('rejected')}>
                  不通过
                </Button>
              </>
            ) : (
              <Tag color="green" style={{ marginInlineEnd: 0 }}>已提交 · 已移出待提交池</Tag>
            )}
            <Button icon={<ThunderboltOutlined />} onClick={() => setDeepenOpen(true)}>
              继续深挖
            </Button>
            {!submitted ? (
              <Button icon={<SaveOutlined />} loading={saving} onClick={markSubmitted}>
                标记为已提交
              </Button>
            ) : null}
            {canRestore ? (
              <Button icon={<UndoOutlined />} loading={saving} onClick={restore}>
                恢复到复审队列
              </Button>
            ) : null}
          </Space>
        ) : null
      }
    >
      <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />

      {/* 继续深挖 */}
      <Modal
        open={deepenOpen}
        title="继续深挖"
        okText={deepening ? '提交中…' : '打回深挖并重新入队'}
        okButtonProps={{ loading: deepening, disabled: !deepenText.trim() }}
        cancelText="取消"
        onOk={submitDeepen}
        onCancel={() => {
          if (deepening) return
          setDeepenOpen(false)
        }}
      >
        <Space direction="vertical" size={6} style={{ width: '100%' }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            告诉 worker 这一轮去把什么打穿，越具体越好。
          </Typography.Text>
          <Input.TextArea
            rows={3}
            value={deepenText}
            onChange={(e) => setDeepenText(e.target.value)}
            placeholder="例：用泄露的初始密码 123456 实际登录某个真实账号，证明能进系统拿到数据"
          />
        </Space>
      </Modal>
    </Drawer>
  )
}
