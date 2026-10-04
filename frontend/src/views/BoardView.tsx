import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  App,
  Badge,
  Button,
  Card,
  Checkbox,
  Col,
  Descriptions,
  Drawer,
  Empty,
  Input,
  List,
  Modal,
  Progress,
  Row,
  Space,
  Spin,
  Table,
  Tabs,
  Tag,
  Timeline,
  Tooltip,
  Typography
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  DownloadOutlined,
  EditOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  PushpinFilled,
  ReloadOutlined,
  StopOutlined
} from '@ant-design/icons'
import { toListResult, userApi } from '@/api'
import { useAuthStore } from '@/store'
import { useTaskStream } from '@/hooks/useTaskStream'
import {
  SEVERITY_COLOR,
  TARGET_STATUS_LABEL,
  TASK_STATUS_BADGE,
  TASK_STATUS_LABEL,
  VULN_TYPE_LABEL,
  fmtLocalTime,
  truncate
} from '@/utils/format'
import type { BoardData, FindingView, Killsweep, Target, Task, TaskEvent, TaskStatus } from '@/types'
import ReportDrawer from '@/components/ReportDrawer'
import { copyText, downloadNamedFile, formatLlmErrorCopy, isLlmErrorEvent } from '@/utils/clipboard'
import { buildEdusrcToolReport, buildReportMd } from '@/utils/report'

/** 批量导出每页拉取的条数（对齐原版 EXPORT_PAGE_SIZE）。 */
const EXPORT_PAGE_SIZE = 80

/* ============================================================================
 * 内部工具函数（避免依赖尚未迁移的 report.js / clipboard.js）
 * ========================================================================== */

/** 收敛为对象。 */
function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

/** 收敛为字符串。 */
function str(v: unknown, fallback = ''): string {
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return fallback
}

/** 收敛为数字。 */
function num(v: unknown, fallback = 0): number {
  const n = Number(v)
  return Number.isFinite(n) ? n : fallback
}

/** 收敛为数字字典。 */
function asNumberRecord(v: unknown): Record<string, number> {
  const rec = asRecord(v)
  const out: Record<string, number> = {}
  Object.entries(rec).forEach(([k, val]) => {
    const n = Number(val)
    if (Number.isFinite(n)) out[k] = n
  })
  return out
}

/** 收敛为字符串数组。 */
function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return []
  return v.map((x) => str(x)).filter(Boolean)
}

/** token 数缩写。 */
function formatTokenCount(v: unknown): string {
  const n = num(v)
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`
  if (n >= 10_000) return `${Math.round(n / 1000)}K`
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`
  return String(n)
}

/** 单行压缩。 */
function shortText(text: unknown, max = 80): string {
  const s = str(text).replace(/\s+/g, ' ').trim()
  return s.length > max ? `${s.slice(0, max)}…` : s
}

/** 运行时长。 */
function elapsed(iso?: string | null): string {
  if (!iso) return ''
  const t = new Date(str(iso)).getTime()
  if (Number.isNaN(t)) return ''
  const s = Math.floor((Date.now() - t) / 1000)
  if (s < 0) return ''
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m${s % 60}s`
}

/** 引擎中文名。 */
const ENGINE_LABEL: Record<string, string> = {
  fofa: 'FOFA',
  quake: '360 Quake',
  hunter: 'Hunter',
  zoomeye: 'ZoomEye',
  shodan: 'Shodan',
  censys: 'Censys'
}
function engineLabelOf(engine?: string): string {
  if (!engine) return 'FOFA'
  return ENGINE_LABEL[engine] || engine
}

/** Agent 图标 / 中文名。 */
const AGENT_ICON: Record<string, string> = {
  orchestrator: '◆',
  collector: '🛰',
  worker: '⚔',
  reviewer: '⚖',
  killsweep: '◇',
  escalation: '⬆'
}
const AGENT_LABEL: Record<string, string> = {
  orchestrator: '主控',
  collector: '搜集',
  worker: '挖掘',
  reviewer: '审核',
  killsweep: '通杀',
  escalation: '扩大危害'
}

/** 目标终态集合：进入这些状态才算「已结束」。 */
const TARGET_CLOSED_STATUS = new Set(['done', 'skipped', 'dead'])

/** 里程碑事件（进入活动流）。 */
const IMPORTANT_KINDS = new Set([
  'collector_phase',
  'engine_query',
  'finding_submitted',
  'finding_duplicate',
  'finding_invalid',
  'worker_start',
  'worker_finish',
  'worker_cancelled',
  'worker_auto_finish',
  'target_done',
  'target_requeued',
  'timeout',
  'auto_deepen',
  'salvage',
  'review_start',
  'review_done',
  'review_error',
  'review_deferred',
  'review_cancelled',
  'reproduce_start',
  'reproduce_done',
  'killsweep_start',
  'killsweep_done',
  'killsweep_error',
  'killsweep_dedup',
  'killsweep_invalid',
  'killsweep_cancelled',
  'killsweep_retry',
  'llm_error',
  'llm_soft_retry',
  'llm_interrupt',
  'worker_resume',
  'llm_provider_failed',
  'quota_stop',
  'reclaim',
  'recover',
  'workers_cancelled',
  'tool_exception',
  'auth_status',
  'gate_pass',
  'gate_fail',
  'escalate_start',
  'escalate_done',
  'escalate_skip',
  'escalate_cancelled',
  'escalate_error',
  'escalate_abandon',
  'worker_directive',
  'worker_directive_queued'
])

/** 噪音事件。 */
const NOISE_KINDS = new Set([
  'ping',
  'tool_call',
  'tool_result',
  'tool_http',
  'tool_shell',
  'tool_shell_blocked',
  'tool_arg_error',
  'tool_js_analyze',
  'tool_decode',
  'tool_waf_advice',
  'tool_fofa_lookup',
  'tool_session_set',
  'worker_thought',
  'intel_reported',
  'js_analyzer_enabled',
  'killsweep_fofa',
  'killsweep_http',
  'killsweep_shell',
  'escalate_http',
  'escalate_shell',
  'escalate_session',
  'llm_round_start',
  'refill',
  'cluster_cooldown_skip',
  'skip'
])

/** 展开活动流时展示的细节事件。 */
const DETAIL_KINDS = new Set([
  'tool_call',
  'tool_result',
  'tool_http',
  'tool_shell',
  'tool_shell_blocked',
  'tool_arg_error',
  'tool_js_analyze',
  'tool_decode',
  'tool_waf_advice',
  'tool_fofa_lookup',
  'tool_session_set',
  'worker_thought',
  'worker_directive',
  'llm_round_start',
  'llm_error',
  'llm_soft_retry',
  'tool_exception',
  'finish_blocked',
  'auth_status'
])

/** 需要聚合进目标轨迹的事件。 */
const TRACE_KINDS = new Set<string>([...NOISE_KINDS, ...IMPORTANT_KINDS, 'finish_blocked'])

/** 目标状态列顺序。 */
const TARGET_STATUS_ORDER = ['queued', 'assigned', 'scanning', 'done', 'skipped', 'dead']

/** 目标来源中文名。 */
const TARGET_SOURCE_LABEL: Record<string, string> = {
  fofa: '测绘',
  manual: '手动',
  site: '单站',
  both: '测绘+手动'
}

/** 目标来源中文标签（site_* 协作路线动态匹配，site_uXX=指定页面直打）。 */
function targetSourceLabel(source: string): string {
  const raw = (source || '').trim()
  if (TARGET_SOURCE_LABEL[raw]) return TARGET_SOURCE_LABEL[raw]
  if (/^site_u\d+$/.test(raw)) return '指定页面'
  if (/^site_f\d+$/.test(raw)) return '定向追打'
  const SITE_ROUTE_LABELS: Record<string, string> = {
    site_map: '入口盘点',
    site_js: 'JS侦察',
    site_auth: '认证越权',
    site_unauth: '未授权暴露',
    site_file: '文件',
    site_inject: '注入RCE',
    site_logic: '业务逻辑',
    site_focus: '定向追打'
  }
  return SITE_ROUTE_LABELS[raw] || raw || '未知来源'
}

/** 目标卡片主标题：URL 带路径时显示 host+路径（完整形态），纯 host 目标仍显示 host。 */
function targetDisplayURL(t: { host?: string; url?: string; id?: string }): string {
  const url = (t.url || '').trim()
  if (url) {
    try {
      const u = new URL(url)
      const path = u.pathname + u.search
      if (path && path !== '/') return u.host + path
    } catch {
      /* 非 URL 形态回落 host */
    }
  }
  return t.host || url || t.id || ''
}

/** 搜集阶段中文名。 */
const PHASE_LABEL: Record<string, string> = {
  prefilter: '探活预筛',
  scoring: '评分归属',
  target_filter: '正在跑过滤器阶段',
  enrich: '补充情报',
  dispatch: '入队完成'
}

/** 观摩角色脱敏。 */
const URL_RE = /https?:\/\/[^\s<>"'`]+/gi
const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g
const CRED_RE = /\b(api[_-]?key|token|secret|password|passwd|pwd|cookie|authorization|bearer)\b\s*[:=]\s*\S+/gi
function redact(text: unknown): string {
  return str(text)
    .replace(URL_RE, '[已脱敏链接]')
    .replace(IP_RE, '[已脱敏IP]')
    .replace(CRED_RE, (m) => `${m.split(/[:=]/)[0].trim()}=[已脱敏]`)
}

/* ---------------------------------------------------------------- 内部类型 */

/** 活态 worker。 */
interface WorkerLive {
  target_id: string
  host: string
  action: string
  round: number
  started_at: string
  findings: number
  score: number
  score_reason: string
  auth: string
  auth_label: string
  model: string
  model_role: string
  model_base_url: string
}

/** 活态扩大危害。 */
interface EscalationLive {
  finding_id: string
  title: string
  severity: string
  started_at: string
  action: string
}

/** 单站协作路线。 */
interface CollabRoute {
  label: string
  source: string
  status: string
  count: number
  findings: number
  running: number
  queued: number
  done: number
  focus: string
  isAggregate: boolean
}

/** 单站协作阶段。 */
interface CollabPhase {
  key: string
  phase: number
  label: string
  desc: string
  state: string
  total: number
  routes: CollabRoute[]
}

/** 单站协作态势。 */
interface SiteCollab {
  routes: number
  running: number
  findings: number
  currentPhase: number
  phases: CollabPhase[]
}

/** 活动流条目。 */
interface ActivityItem {
  uid: number
  kind: string
  level: string
  agent: string
  text: string
  ts: string
  targetId: string
  round: number
  payload: Record<string, unknown>
  raw: Record<string, unknown>
}

/** 轨迹行。 */
interface TraceRow {
  uid: number
  ts: string
  agent: string
  kind: string
  level: string
  text: string
  round: number
  targetId: string
  payload: Record<string, unknown>
}

/** 通杀资产行。 */
interface AssetRow {
  school: string
  url: string
  host: string
  vulnTitle: string
  status: string
  evidence: string
}

/** 列表状态。 */
interface ListState {
  items: FindingView[]
  total: number
  hasMore: boolean
  loading: boolean
}
function emptyList(): ListState {
  return { items: [], total: 0, hasMore: false, loading: false }
}

let traceUid = 0
function nextUid(): number {
  traceUid += 1
  return traceUid
}

/* ---------------------------------------------------------------- 解析器 */

function parseWorkers(v: unknown): WorkerLive[] {
  if (!Array.isArray(v)) return []
  return v
    .map((raw) => {
      const r = asRecord(raw)
      return {
        target_id: str(r.target_id),
        host: str(r.host),
        action: str(r.action),
        round: num(r.round),
        started_at: str(r.started_at),
        findings: num(r.findings),
        score: num(r.score),
        score_reason: str(r.score_reason),
        auth: str(r.auth),
        auth_label: str(r.auth_label),
        model: str(r.model),
        model_role: str(r.model_role),
        model_base_url: str(r.model_base_url)
      }
    })
    .filter((w) => w.target_id)
}

function parseEscalations(v: unknown): EscalationLive[] {
  if (!Array.isArray(v)) return []
  return v
    .map((raw) => {
      const r = asRecord(raw)
      return {
        finding_id: str(r.finding_id),
        title: str(r.title) || str(r.finding_id),
        severity: str(r.severity),
        started_at: str(r.started_at),
        action: str(r.action)
      }
    })
    .filter((e) => e.finding_id)
}

function parseCollab(v: unknown): SiteCollab | null {
  const r = asRecord(v)
  if (!Object.keys(r).length) return null
  const totals = asRecord(r.totals)
  const phasesRaw = Array.isArray(r.phases) ? r.phases : []
  const phases: CollabPhase[] = phasesRaw.map((p) => {
    const pr = asRecord(p)
    const routesRaw = Array.isArray(pr.routes) ? pr.routes : []
    const routes: CollabRoute[] = routesRaw.map((rt) => {
      const rr = asRecord(rt)
      return {
        label: str(rr.label) || '路线',
        source: str(rr.source),
        status: str(rr.status, 'done'),
        count: Math.max(1, num(rr.count, 1)),
        findings: num(rr.findings),
        running: num(rr.running),
        queued: num(rr.queued),
        done: num(rr.done),
        focus: str(rr.focus),
        isAggregate: !!rr.is_aggregate
      }
    })
    return {
      key: str(pr.key) || `phase-${num(pr.phase)}`,
      phase: num(pr.phase),
      label: str(pr.label),
      desc: str(pr.desc),
      state: str(pr.state, 'idle'),
      total: num(asRecord(pr.counts).total),
      routes
    }
  })
  return {
    routes: num(totals.routes),
    running: num(totals.running),
    findings: num(totals.findings),
    currentPhase: num(r.current_phase),
    phases
  }
}

/** 合并同名单站路线。 */
function groupRoutes(routes: CollabRoute[]): CollabRoute[] {
  const map = new Map<string, CollabRoute>()
  const leftover: CollabRoute[] = []
  for (const r of routes) {
    const label = r.label.replace(/\s*[×xX]\s*\d+\s*$/, '').trim() || r.label
    if (r.isAggregate) {
      leftover.push({ ...r, label })
      continue
    }
    const existing = map.get(label)
    if (!existing) {
      map.set(label, { ...r, label })
      continue
    }
    existing.count += r.count
    existing.findings += r.findings
    existing.running += r.running
    existing.queued += r.queued
    existing.done += r.done
    if (r.status === 'running' || (r.status === 'queued' && existing.status !== 'running')) {
      existing.status = r.status
    }
  }
  return [...map.values(), ...leftover]
}

function phaseStateText(state: string): string {
  return ({ active: '进行中', pending: '排队中', done: '已完成', idle: '未开始' } as Record<string, string>)[state] || ''
}

function assetRows(k: Killsweep): AssetRow[] {
  const rec = asRecord(k)
  const table = Array.isArray(rec.affected_table) ? rec.affected_table : []
  if (table.length) {
    return table.map((raw) => {
      const r = asRecord(raw)
      return {
        school: str(r.school) || '待确认',
        url: str(r.url),
        host: str(r.host),
        vulnTitle: str(r.vuln_title),
        status: str(r.status),
        evidence: str(r.evidence)
      }
    })
  }
  const verifiedUrl = str(rec.verified_url)
  if (verifiedUrl) {
    return [
      {
        school: '待确认',
        url: verifiedUrl,
        host: '',
        vulnTitle: str(rec.vuln_summary) || str(rec.origin_title) || '通杀验证目标',
        status: rec.verified ? 'verified' : 'candidate',
        evidence: rec.verified ? '通杀 Hunter 已验证' : '通杀 Hunter 圈定候选'
      }
    ]
  }
  return []
}

function ksText(k: Killsweep, key: string, fallback = ''): string {
  return str(asRecord(k)[key], fallback)
}
function ksNum(k: Killsweep, key: string): number {
  return num(asRecord(k)[key])
}
function ksBool(k: Killsweep, key: string): boolean {
  return !!asRecord(k)[key]
}

/* ---------------------------------------------------------------- 事件格式化 */

/** 把事件格式化成一句人话。 */
function formatEventText(kind: string, d: Record<string, unknown>, engine: string): string {
  const msg = str(d.message)
  if (msg) return msg
  const slice = (v: unknown, n: number) => str(v).slice(0, n)
  switch (kind) {
    case 'worker_start':
      return `开始挖掘 ${str(d.target)}${d.mode === 'deepen' ? '（定向深挖）' : ''}`
    case 'collector_phase':
      return msg || PHASE_LABEL[str(d.phase)] || '正在跑过滤器阶段'
    case 'finding_submitted':
      return `🎯 发现漏洞 [${str(d.severity)}] ${str(d.title)}`
    case 'duplicate_checked':
      return d.duplicate ? `查重重复：${str(d.title)}` : ''
    case 'finding_duplicate':
      return `重复漏洞已拦截：${str(d.title)}`
    case 'finding_invalid':
      return '漏洞格式校验失败，重试中'
    case 'worker_finish':
      return `收尾: ${str(d.verdict)}`
    case 'worker_auto_finish':
      return `自动收敛: ${slice(d.summary || d.verdict, 120)}`
    case 'worker_cancelled':
      return `挖掘被取消: ${str(d.target)}`
    case 'review_start':
      return `开始审核: ${str(d.title)}`
    case 'review_done':
      return `审核完成: ${str(d.verdict)} · ${str(d.confidence)} · ${str(d.score)}`
    case 'review_error':
      return `审核异常: ${slice(d.error, 120)}`
    case 'review_deferred':
      return '审核暂缓，稍后重试'
    case 'review_cancelled':
      return '审核已取消'
    case 'reproduce_start':
      return `复现验证: ${str(d.title)}`
    case 'reproduce_done':
      return `复现${d.reproduced ? '成功' : '未证实'}: ${str(d.title)}`
    case 'killsweep_start':
      return `通杀 Hunter 启动：${str(d.title)}`
    case 'killsweep_done':
      return `通杀分析完成：${str(d.product)} · ${d.is_killsweep ? '可通杀' : '不可通杀'}`
    case 'killsweep_error':
      return `通杀分析异常: ${slice(d.error, 120)}`
    case 'killsweep_dedup':
      return `通杀分析去重：${str(d.product)}`
    case 'killsweep_invalid':
      return `通杀记录已标记无效：${str(d.product)}`
    case 'killsweep_retry':
      return `手动重启通杀分析：${str(d.product) || str(d.title)}`
    case 'llm_error':
      return `⚠ LLM 调用失败: ${str(d.error)}`
    case 'llm_soft_retry':
      return `LLM 软重试 ${str(d.attempt, '?')}/${str(d.max_attempts, '?')}（${str(d.kind) || str(d.failure_kind) || 'retry'}，等 ${num(d.wait_seconds)}s）: ${slice(d.error, 180)}`
    case 'llm_interrupt':
      return `LLM 中断收尾${d.has_resume ? '（已保存进度）' : ''}: ${slice(d.error, 180)}`
    case 'worker_resume':
      return `断点续挖：恢复笔记 ${num(d.notes_len)} 字 / cookie ${asStringArray(d.cookies).length} / 头 ${asStringArray(d.headers).length}`
    case 'llm_provider_failed':
      return `LLM 端点失败: ${str(d.model)} @ ${str(d.base_url)} (${str(d.error_kind) || 'failed'})${d.error ? ` · ${str(d.error)}` : ''}`
    case 'tool_exception':
      return `工具异常: ${str(d.tool)} ${slice(d.error, 80)}`
    case 'tool_http':
      return `HTTP ${str(d.method, 'GET')} ${str(d.url)}`
    case 'tool_shell':
      return `$ ${slice(d.command, 160)}`
    case 'tool_shell_blocked':
      return `拦截命令: ${slice(d.reason || d.command, 120)}`
    case 'tool_arg_error':
      return `工具参数错误: ${str(d.tool)} ${slice(d.error, 80)}`
    case 'tool_js_analyze':
      return `JS 分析: ${slice(d.url, 120)}`
    case 'tool_decode':
      return `解码: ${str(d.mode, 'auto')}`
    case 'tool_waf_advice':
      return `WAF 建议: ${str(d.context, 'generic')}`
    case 'tool_fofa_lookup':
      return `${engineLabelOf(engine)}: ${slice(d.query, 100)}`
    case 'tool_session_set':
      return '会话态更新'
    case 'gate_pass':
      return msg || `✅ 3-gate 验证通过: ${str(d.vuln_type, '?')}${d.reused ? '（复用既有结论）' : ''}`
    case 'gate_fail':
      return msg || `⛔ 3-gate 验证未通过: ${str(d.vuln_type, '?')}`
    case 'worker_thought':
      return `💭 ${slice(d.text, 200)}`
    case 'worker_directive':
      return `🎛 执行人工指令: ${slice(d.text, 160)}`
    case 'worker_directive_queued':
      return msg || `已排队人工指令: ${slice(d.text, 120)}`
    case 'llm_round_start':
      return `第 ${str(d.round, '?')} 轮 LLM`
    case 'escalate_start':
      return `扩大危害启动: ${str(d.title)}`
    case 'escalate_done':
      return `扩大危害完成: ${str(d.title)} · ${str(d.severity)}`
    case 'escalate_skip':
      return msg || '扩大危害未显著，已放弃'
    case 'escalate_cancelled':
      return msg || '扩大危害已取消'
    case 'escalate_error':
      return `扩大危害异常: ${slice(d.error, 120)}`
    case 'escalate_abandon':
      return `扩大危害放弃: ${slice(d.reason, 120)}`
    case 'escalate_http':
      return `扩大危害 HTTP ${slice(d.url, 120)}`
    case 'escalate_shell':
      return `扩大危害 $ ${slice(d.command, 120)}`
    case 'auth_status': {
      const kinds = asStringArray(d.kinds).join(',') || '-'
      const st = str(d.status, '?')
      if (msg) return msg
      if (st === 'injected') return `凭据[${kinds}] 已注入`
      if (st === 'login_ok') return `凭据[${kinds}] 登录成功`
      if (st === 'login_fail') return `凭据[${kinds}] 登录失败：${slice(d.reason, 100)}`
      return `凭据未使用：${slice(d.reason, 100)}`
    }
    case 'ping':
      return ''
    default:
      return msg || kind
  }
}

function isImportantEvent(rec: Record<string, unknown>): boolean {
  const kind = str(rec.kind)
  if (kind === 'ping') return false
  const level = str(rec.level)
  if (level === 'error' || level === 'warn') return true
  if (NOISE_KINDS.has(kind)) return false
  if (IMPORTANT_KINDS.has(kind)) return true
  if (kind === 'duplicate_checked') return !!rec.duplicate
  if (rec.message && kind === 'error') return true
  return false
}

function eventData(rec: Record<string, unknown>): Record<string, unknown> {
  return { ...asRecord(rec.payload), ...rec }
}

function traceDedupKey(rec: Record<string, unknown>): string {
  const ts = str(rec.ts)
  const parsed = ts ? new Date(ts).getTime() : 0
  const sec = Number.isNaN(parsed) ? 0 : Math.floor(parsed / 1000)
  return `${str(rec.kind)}|${str(rec.round)}|${str(rec.message) || str(rec.kind)}|${sec}`
}

function toTraceRow(ev: TaskEvent | Record<string, unknown>, engine: string): TraceRow | null {
  const rec = asRecord(ev)
  const kind = str(rec.kind)
  if (!kind || kind === 'ping') return null
  const d = eventData(rec)
  const text = str(rec.message) || formatEventText(kind, d, engine) || kind
  const ts = str(rec.ts) || new Date().toISOString()
  return {
    uid: nextUid(),
    ts,
    agent: str(rec.agent),
    kind,
    level: str(rec.level, 'info'),
    text,
    round: num(rec.round),
    targetId: str(rec.target_id),
    payload: asRecord(rec.payload)
  }
}

function toActivity(ev: TaskEvent | Record<string, unknown>, engine: string): ActivityItem | null {
  const rec = asRecord(ev)
  const kind = str(rec.kind)
  if (kind === 'ping') return null
  const d = eventData(rec)
  const text = formatEventText(kind, d, engine)
  if (!text) return null
  return {
    uid: nextUid(),
    kind,
    level: str(rec.level, 'info'),
    agent: str(rec.agent),
    text,
    ts: str(rec.ts) || new Date().toISOString(),
    targetId: str(rec.target_id),
    round: num(rec.round),
    payload: asRecord(rec.payload),
    raw: d
  }
}

function traceColor(kind: string, level: string): string {
  if (level === 'error') return 'red'
  if (level === 'warn') return 'orange'
  if (kind === 'finding_submitted' || kind === 'escalate_done' || kind === 'killsweep_done' || kind === 'gate_pass') return 'green'
  if (kind === 'worker_start' || kind === 'review_start' || kind === 'reproduce_start') return 'blue'
  if (DETAIL_KINDS.has(kind)) return 'gray'
  return 'blue'
}

/* ============================================================================
 * 视图组件
 * ========================================================================== */

/**
 * 任务指挥台看板。
 *
 * 数据来源：userApi.getTask / userApi.board 拉快照，useTaskStream 增量消费 WebSocket；
 * 运行中 5s、空闲 15s 定时刷新看板，列表页签按需加载、事件驱动后台刷新。
 */
export default function BoardView() {
  const { taskId = '' } = useParams<{ taskId: string }>()
  const navigate = useNavigate()
  const { message, modal } = App.useApp()

  const role = useAuthStore((s) => s.role)
  const writable = role === 'full'
  const isObserver = role === 'observer'

  // ---------------------------------------------------------- 基础状态
  const [task, setTask] = useState<Task | null>(null)
  const [board, setBoard] = useState<BoardData | null>(null)
  const [stats, setStats] = useState<Record<string, number>>({})
  const [llmUsage, setLlmUsage] = useState<Record<string, unknown>>({})
  const [engineUsage, setEngineUsage] = useState<Record<string, unknown>>({})
  const [modelConfig, setModelConfig] = useState<Record<string, unknown>>({})
  const [fofaConfig, setFofaConfig] = useState<Record<string, unknown>>({})
  const [liveWorkers, setLiveWorkers] = useState<WorkerLive[]>([])
  const [liveEscalations, setLiveEscalations] = useState<EscalationLive[]>([])
  const [collab, setCollab] = useState<SiteCollab | null>(null)
  const [activity, setActivity] = useState<ActivityItem[]>([])
  const [traceMap, setTraceMap] = useState<Record<string, TraceRow[]>>({})
  const [expandedActivity, setExpandedActivity] = useState<number[]>([])

  const [initialLoading, setInitialLoading] = useState(true)
  const [boardReady, setBoardReady] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  // ---------------------------------------------------------- 页签与搜索
  const [activeTab, setActiveTab] = useState('board')
  const [searchDraft, setSearchDraft] = useState('')
  const [searchText, setSearchText] = useState('')
  const [submittedFilter, setSubmittedFilter] = useState(false)

  // ---------------------------------------------------------- 列表
  const [queue, setQueue] = useState<ListState>(emptyList)
  const [submitItems, setSubmitItems] = useState<ListState>(emptyList)
  const [killsweeps, setKillsweeps] = useState<{ items: Killsweep[]; loading: boolean }>({ items: [], loading: false })
  const [rejected, setRejected] = useState<ListState>(emptyList)
  const [archived, setArchived] = useState<ListState>(emptyList)
  const [deepen, setDeepen] = useState<ListState>(emptyList)
  const [autoKillsweep, setAutoKillsweep] = useState(true)
  const [autoSaving, setAutoSaving] = useState(false)

  // ---------------------------------------------------------- 抽屉 / 弹窗
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerId, setDrawerId] = useState<string | null>(null)
  const [directiveOpen, setDirectiveOpen] = useState(false)
  const [directiveTarget, setDirectiveTarget] = useState<{ id: string; host: string } | null>(null)
  const [directiveText, setDirectiveText] = useState('')
  const [directiveSending, setDirectiveSending] = useState(false)
  const [traceOpen, setTraceOpen] = useState(false)
  const [traceTarget, setTraceTarget] = useState<{ id: string; host: string } | null>(null)
  const [traceRows, setTraceRows] = useState<TraceRow[]>([])
  const [traceLoading, setTraceLoading] = useState(false)
  const [traceDirective, setTraceDirective] = useState('')
  const [traceDirectiveSending, setTraceDirectiveSending] = useState(false)
  const [cancellingEscalate, setCancellingEscalate] = useState<string | null>(null)
  const [invalidatingId, setInvalidatingId] = useState<string | null>(null)
  const [retryingId, setRetryingId] = useState<string | null>(null)
  const [expandedKs, setExpandedKs] = useState<string[]>([])

  // ---------------------------------------------------------- refs
  const taskIdRef = useRef(taskId)
  taskIdRef.current = taskId
  const engineRef = useRef('')
  engineRef.current = task?.engine || ''
  const loadedTabsRef = useRef<Set<string>>(new Set())
  const searchRef = useRef('')
  searchRef.current = searchText
  const submittedRef = useRef(false)
  submittedRef.current = submittedFilter
  const queueLenRef = useRef(0)
  queueLenRef.current = queue.items.length
  const submitLenRef = useRef(0)
  submitLenRef.current = submitItems.items.length
  const archivedLenRef = useRef(0)
  archivedLenRef.current = archived.items.length
  const deepenLenRef = useRef(0)
  deepenLenRef.current = deepen.items.length
  const traceTargetIdRef = useRef('')
  traceTargetIdRef.current = traceTarget?.id || ''

  const boardPollRef = useRef<number | null>(null)
  const refreshTimerRef = useRef<number | null>(null)
  const searchTimerRef = useRef<number | null>(null)

  /** 观摩角色脱敏包装。 */
  const mask = useCallback((text: unknown): string => (isObserver ? redact(text) : str(text)), [isObserver])

  // ============================================================ 数据加载

  const loadTask = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return
    try {
      const t = await userApi.getTask(id)
      if (id !== taskIdRef.current) return
      setTask(t)
      setAutoKillsweep(t.auto_killsweep !== false)
    } catch {
      /* 错误提示由 request 层统一处理 */
    }
  }, [])

  const loadBoard = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return
    try {
      const b = await userApi.board(id)
      if (id !== taskIdRef.current) return
      setBoard(b)
      setStats(asNumberRecord(b.stats))
      setLlmUsage(asRecord(b.llm_usage))
      setEngineUsage(asRecord(b.engine_usage))
      setModelConfig(asRecord(b.model_config_data))
      setFofaConfig(asRecord(b.fofa_config))
      const bRecord = asRecord(b)
      const liveShape = asRecord(bRecord.live)
      const taskShape = asRecord(bRecord.task)
      // 后端契约：live = {workers, escalations}；llm_usage / engine_usage /
      // model_config_data / fofa_config 都挂在 task 视图内。
      // 曾按顶层 b.live_workers 等扁平键读取，全部恒 undefined —— Worker Matrix
      // 恒空、目标抽屉恒显「已结束」。读取时兼容旧扁平键做兜底。
      setLiveWorkers(parseWorkers(liveShape.workers ?? bRecord.live_workers))
      setLiveEscalations(parseEscalations(liveShape.escalations ?? bRecord.live_escalations))
      setLlmUsage(asRecord(taskShape.llm_usage ?? bRecord.llm_usage))
      setEngineUsage(asRecord(taskShape.engine_usage ?? bRecord.engine_usage))
      setModelConfig(asRecord(taskShape.model_config_data ?? bRecord.model_config_data))
      setFofaConfig(asRecord(taskShape.fofa_config ?? bRecord.fofa_config))
      setCollab(parseCollab(b.site_collab))
      const status = str(taskShape.status || bRecord.task_status)
      if (status) setTask((prev) => (prev ? { ...prev, status: status as TaskStatus } : prev))
      const seeded = Array.isArray(b.events) ? b.events : []
      if (seeded.length) {
        setActivity((prev) => {
          if (prev.length) return prev
          return seeded
            .map((e) => toActivity(e, engineRef.current))
            .filter((x): x is ActivityItem => !!x)
            .slice(0, 200)
        })
      }
    } catch {
      /* 看板失败不阻断 WebSocket */
    } finally {
      if (id === taskIdRef.current) setBoardReady(true)
    }
  }, [])

  const loadReview = useCallback(async (reset = true) => {
    const id = taskIdRef.current
    if (!id) return
    setQueue((s) => ({ ...s, loading: true }))
    try {
      const offset = reset ? 0 : queueLenRef.current
      const res = await userApi.reviewQueue(id, {
        q: searchRef.current || undefined,
        compact: 1,
        limit: 200,
        offset
      })
      const lr = toListResult<FindingView>(res)
      if (id !== taskIdRef.current) return
      setQueue((s) => ({
        items: reset ? lr.items : [...s.items, ...lr.items],
        total: lr.total,
        hasMore: lr.hasMore,
        loading: false
      }))
    } catch {
      setQueue((s) => ({ ...s, loading: false }))
    }
  }, [])

  const loadSubmit = useCallback(async (reset = true) => {
    const id = taskIdRef.current
    if (!id) return
    setSubmitItems((s) => ({ ...s, loading: true }))
    try {
      const offset = reset ? 0 : submitLenRef.current
      const res = await userApi.submitList(id, {
        // 显式传 0/1：默认只看真待提交（与角标 submit_ready 口径一致），
        // 已提交的记录移出本列表；勾「只看已提交」才传 1。
        submitted: submittedRef.current ? 1 : 0,
        compact: 1,
        limit: 120,
        offset
      })
      const lr = toListResult<FindingView>(res)
      if (id !== taskIdRef.current) return
      setSubmitItems((s) => ({
        items: reset ? lr.items : [...s.items, ...lr.items],
        total: lr.total,
        hasMore: lr.hasMore,
        loading: false
      }))
    } catch {
      setSubmitItems((s) => ({ ...s, loading: false }))
    }
  }, [])

  /* ---------------- 批量导出 / 复制（对齐原版 BoardView 的 8 个动作） ----------------
   * 列表接口默认带 compact=1（给看板省流量），导出必须显式关掉才能拿到
   * raw_request / raw_response / evidence / kill_chain 等报告所需的全字段。
   */

  const [bulkWorking, setBulkWorking] = useState(false)

  const fetchPagedFindingList = useCallback(
    async (loader: (offset: number) => Promise<unknown>): Promise<FindingView[]> => {
      const reports: FindingView[] = []
      let offset = 0
      for (;;) {
        const res = await loader(offset)
        const lr = toListResult<FindingView>(res)
        reports.push(...lr.items)
        if (!lr.items.length || !lr.hasMore) break
        offset += lr.items.length
        await new Promise((resolve) => requestAnimationFrame(resolve))
      }
      return reports
    },
    []
  )

  const fetchAllSubmitReports = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return []
    return fetchPagedFindingList((offset) =>
      userApi.submitList(id, {
        submitted: submittedRef.current ? 1 : 0,
        compact: 0,
        limit: EXPORT_PAGE_SIZE,
        offset
      })
    )
  }, [fetchPagedFindingList])

  const fetchAllReviewReports = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return []
    return fetchPagedFindingList((offset) =>
      userApi.reviewQueue(id, { compact: 0, limit: EXPORT_PAGE_SIZE, offset })
    )
  }, [fetchPagedFindingList])

  /** 导出测绘/清单产出的全部目标（CSV，aisrc- 前缀）。 */
  const exportTargetsCsv = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return
    const res = await userApi.targets(id, { compact: 0, limit: 0 })
    const lr = toListResult<Target>(res)
    const rows: Target[] = lr.items
    if (!rows.length) {
      message.info('暂无目标可导出')
      return
    }
    const header = ['url', 'host', 'ip', 'port', 'title', 'org_source', 'status', 'verdict', 'priority_score', 'priority_reason', 'source']
    const esc = (v: unknown) => {
      const text = v === null || v === undefined ? '' : String(v)
      return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
    }
    const lines = [header.join(',')]
    for (const t of rows) {
      lines.push(
        [
          t.url, t.host, t.ip, t.port, t.title, (t as unknown as Record<string, unknown>).org ?? '',
          t.status, t.verdict, t.priority_score, (t as unknown as Record<string, unknown>).priority_reason ?? '',
          t.source
        ]
          .map(esc)
          .join(',')
      )
    }
    downloadNamedFile(`aisrc-${fileStem()}-targets.csv`, '\ufeff' + lines.join('\n'), 'text/csv;charset=utf-8')
    message.success(`已导出 ${rows.length} 个目标`)
  }, [message])

  /** 跑一次批量动作，统一处理"生成中 → 完成/失败"的提示与忙碌态。 */
  const runBulk = useCallback(
    async (label: string, job: () => Promise<void>) => {
      if (bulkWorking) return
      setBulkWorking(true)
      message.info(label)
      try {
        await job()
      } finally {
        setBulkWorking(false)
      }
    },
    [bulkWorking, message]
  )

  /** 复制某条 LLM 异常事件的真实错误（含 model / base_url / status，便于贴给运维）。 */
  const copyLlmEvent = useCallback(
    async (ev: Record<string, unknown>) => {
      const ok = await copyText(formatLlmErrorCopy(ev))
      if (ok) message.success('已复制 LLM 错误信息')
      else message.error('复制失败，请手动选中')
    },
    [message]
  )

  const joinReportMarkdown = (reports: FindingView[]) => reports.map((f) => buildReportMd(f)).join('\n\n---\n\n')
  const edusrcReports = (reports: FindingView[]) => reports.map((f) => buildEdusrcToolReport(f))
  const fileStem = () => (taskIdRef.current || '').slice(0, 8)

  /** 复审队列 / 待提交共用的四个动作；空结果时的文案按来源区分。 */
  const bulkCopyMd = (kind: 'review' | 'submit') =>
    runBulk('正在生成全部 Markdown...', async () => {
      const reports = kind === 'review' ? await fetchAllReviewReports() : await fetchAllSubmitReports()
      if (kind === 'review' && !reports.length) {
        message.warning('没有待复审报告')
        return
      }
      const ok = await copyText(joinReportMarkdown(reports))
      if (ok) message.success(`已复制 ${reports.length} 份${kind === 'review' ? '待复审' : ''}报告`)
      else message.error('复制失败，请使用导出按钮')
    })

  const bulkExportMd = (kind: 'review' | 'submit') =>
    runBulk('正在生成 Markdown 文件...', async () => {
      const reports = kind === 'review' ? await fetchAllReviewReports() : await fetchAllSubmitReports()
      if (kind === 'review' && !reports.length) {
        message.warning('没有待复审报告')
        return
      }
      downloadNamedFile(
        `aisrc-${fileStem()}-${kind === 'review' ? 'review' : 'submit'}.md`,
        joinReportMarkdown(reports),
        'text/markdown'
      )
      message.success(`已导出 ${reports.length} 份${kind === 'review' ? '待复审' : ''}报告`)
    })

  const bulkCopyEdusrc = (kind: 'review' | 'submit') =>
    runBulk('正在生成全部 EduSRC JSON...', async () => {
      const reports = kind === 'review' ? await fetchAllReviewReports() : await fetchAllSubmitReports()
      if (kind === 'review' && !reports.length) {
        message.warning('没有待复审报告')
        return
      }
      const ok = await copyText(JSON.stringify(edusrcReports(reports), null, 2))
      if (ok) message.success(`已复制 ${reports.length} 份${kind === 'review' ? '待复审 ' : ''}EduSRC JSON`)
      else message.error('复制失败，请使用导出 reports.json')
    })

  const bulkExportEdusrc = (kind: 'review' | 'submit') =>
    runBulk('正在生成 reports.json...', async () => {
      const reports = kind === 'review' ? await fetchAllReviewReports() : await fetchAllSubmitReports()
      if (kind === 'review' && !reports.length) {
        message.warning('没有待复审报告')
        return
      }
      downloadNamedFile(
        kind === 'review'
          ? `aisrc-${fileStem()}-review-edusrc.json`
          : `aisrc-${fileStem()}-edusrc-reports.json`,
        JSON.stringify(edusrcReports(reports), null, 2),
        'application/json'
      )
      message.success(`已导出 ${reports.length} 份${kind === 'review' ? '待复审 ' : ''}EduSRC JSON`)
    })

  const loadRejected = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return
    setRejected((s) => ({ ...s, loading: true }))
    try {
      const res = await userApi.rejectedList(id, { q: searchRef.current || undefined })
      const lr = toListResult<FindingView>(res)
      if (id !== taskIdRef.current) return
      setRejected({ items: lr.items, total: lr.total, hasMore: false, loading: false })
    } catch {
      setRejected((s) => ({ ...s, loading: false }))
    }
  }, [])

  const loadArchived = useCallback(async (reset = true) => {
    const id = taskIdRef.current
    if (!id) return
    setArchived((s) => ({ ...s, loading: true }))
    try {
      const offset = reset ? 0 : archivedLenRef.current
      const res = await userApi.archivedList(id, { q: searchRef.current || undefined, limit: 50, offset })
      const lr = toListResult<FindingView>(res)
      if (id !== taskIdRef.current) return
      setArchived((s) => ({
        items: reset ? lr.items : [...s.items, ...lr.items],
        total: lr.total,
        hasMore: lr.hasMore,
        loading: false
      }))
    } catch {
      setArchived((s) => ({ ...s, loading: false }))
    }
  }, [])

  const loadDeepen = useCallback(async (reset = true) => {
    const id = taskIdRef.current
    if (!id) return
    setDeepen((s) => ({ ...s, loading: true }))
    try {
      const offset = reset ? 0 : deepenLenRef.current
      const res = await userApi.deepenList(id, { limit: 120, offset })
      const lr = toListResult<FindingView>(res)
      if (id !== taskIdRef.current) return
      setDeepen((s) => ({
        items: reset ? lr.items : [...s.items, ...lr.items],
        total: lr.total,
        hasMore: lr.hasMore,
        loading: false
      }))
    } catch {
      setDeepen((s) => ({ ...s, loading: false }))
    }
  }, [])

  const loadKillsweeps = useCallback(async () => {
    const id = taskIdRef.current
    if (!id) return
    setKillsweeps((s) => ({ ...s, loading: true }))
    try {
      const res = await userApi.killsweeps(id, { q: searchRef.current || undefined })
      const lr = toListResult<Killsweep>(res)
      if (id !== taskIdRef.current) return
      setKillsweeps({ items: lr.items, loading: false })
    } catch {
      setKillsweeps((s) => ({ ...s, loading: false }))
    }
  }, [])

  const loadTab = useCallback(
    async (tab: string) => {
      if (tab === 'review') await loadReview(true)
      else if (tab === 'submit') await loadSubmit(true)
      else if (tab === 'killsweep') await loadKillsweeps()
      else if (tab === 'rejected') await loadRejected()
      else if (tab === 'archived') await loadArchived(true)
      else if (tab === 'deepen') await loadDeepen(true)
      else return
      loadedTabsRef.current.add(tab)
    },
    [loadReview, loadSubmit, loadKillsweeps, loadRejected, loadArchived, loadDeepen]
  )

  const refreshFromEvent = useCallback(
    async (kind: string) => {
      const loaded = loadedTabsRef.current
      const jobs: Promise<void>[] = [loadBoard()]
      const isFinding = kind.includes('finding') || kind.includes('review')
      if (isFinding && loaded.has('review')) jobs.push(loadReview(true))
      if (isFinding && loaded.has('rejected')) jobs.push(loadRejected())
      if (isFinding && loaded.has('archived')) jobs.push(loadArchived(true))
      if ((kind.includes('submit') || kind.includes('review') || kind.includes('deepen')) && loaded.has('deepen')) {
        jobs.push(loadDeepen(true))
      }
      if ((kind.includes('submit') || kind.includes('review')) && loaded.has('submit')) jobs.push(loadSubmit(true))
      if (kind.includes('killsweep') && loaded.has('killsweep')) jobs.push(loadKillsweeps())
      await Promise.all(jobs)
    },
    [loadBoard, loadReview, loadRejected, loadArchived, loadSubmit, loadDeepen, loadKillsweeps]
  )

  const scheduleRefresh = useCallback(
    (kind: string) => {
      if (refreshTimerRef.current !== null) window.clearTimeout(refreshTimerRef.current)
      refreshTimerRef.current = window.setTimeout(() => {
        refreshTimerRef.current = null
        void refreshFromEvent(kind)
      }, 300)
    },
    [refreshFromEvent]
  )

  // ============================================================ WebSocket

  const handleEvent = useCallback(
    (ev: TaskEvent) => {
      const rec = asRecord(ev)
      const kind = str(rec.kind)
      // 先聚合进目标轨迹（轨迹需要工具/思考等细节）。
      const row = toTraceRow(rec, engineRef.current)
      if (row && row.targetId && TRACE_KINDS.has(kind)) {
        setTraceMap((prev) => {
          const list = [...(prev[row.targetId] || [])]
          const key = traceDedupKey({ kind: row.kind, round: row.round, message: row.text, ts: row.ts })
          for (let i = list.length - 1, floor = Math.max(0, list.length - 60); i >= floor; i -= 1) {
            if (traceDedupKey({ kind: list[i].kind, round: list[i].round, message: list[i].text, ts: list[i].ts }) === key) {
              return prev
            }
          }
          list.push(row)
          const capped = list.length > 300 ? list.slice(list.length - 300) : list
          return { ...prev, [row.targetId]: capped }
        })
        if (traceTargetIdRef.current === row.targetId) {
          setTraceRows((prev) => [row, ...prev].slice(0, 400))
        }
      }
      if (!isImportantEvent(rec)) return
      if (kind === 'collector_phase') {
        setFofaConfig((prev) => ({
          ...prev,
          collector_phase: str(rec.phase),
          collector_phase_text: str(rec.message),
          last_target_filter_total: num(rec.survivors),
          last_target_filter_evaluated: num(rec.filter_evaluated)
        }))
      }
      const item = toActivity(rec, engineRef.current)
      if (!item) return
      if (isObserver) item.text = redact(item.text)
      setActivity((prev) => [item, ...prev].slice(0, 200))
      if (
        kind.includes('finding') ||
        kind.includes('review') ||
        kind.includes('target_done') ||
        kind.includes('submit') ||
        kind.includes('killsweep') ||
        kind.includes('worker') ||
        kind.includes('escalate') ||
        kind.includes('deepen')
      ) {
        scheduleRefresh(kind)
      }
    },
    [isObserver, scheduleRefresh]
  )

  const { status: streamStatus } = useTaskStream(taskId, {
    enabled: !!taskId,
    capacity: 400,
    onEvent: handleEvent
  })

  // ============================================================ 生命周期

  useEffect(() => {
    if (!taskId) return
    loadedTabsRef.current = new Set()
    setTask(null)
    setBoard(null)
    setStats({})
    setLlmUsage({})
    setEngineUsage({})
    setModelConfig({})
    setFofaConfig({})
    setLiveWorkers([])
    setLiveEscalations([])
    setCollab(null)
    setActivity([])
    setTraceMap({})
    setExpandedActivity([])
    setQueue(emptyList())
    setSubmitItems(emptyList())
    setRejected(emptyList())
    setArchived(emptyList())
    setDeepen(emptyList())
    setKillsweeps({ items: [], loading: false })
    setActiveTab('board')
    setSearchDraft('')
    setSearchText('')
    setSubmittedFilter(false)
    setDrawerId(null)
    setDrawerOpen(false)
    setBoardReady(false)
    setInitialLoading(true)
    setRefreshing(true)
    void (async () => {
      try {
        await loadTask()
        setInitialLoading(false)
        await loadBoard()
      } catch {
        /* 忽略 */
      } finally {
        setInitialLoading(false)
        setRefreshing(false)
      }
    })()
  }, [taskId, loadTask, loadBoard])

  const running = task?.status === 'running' || num(stats.scanning) > 0
  useEffect(() => {
    if (!taskId) return
    if (boardPollRef.current !== null) window.clearInterval(boardPollRef.current)
    const ms = running ? 5000 : 15000
    boardPollRef.current = window.setInterval(() => {
      void loadBoard()
      if (loadedTabsRef.current.has(activeTab)) void loadTab(activeTab)
    }, ms)
    return () => {
      if (boardPollRef.current !== null) window.clearInterval(boardPollRef.current)
      boardPollRef.current = null
    }
  }, [taskId, running, activeTab, loadBoard, loadTab])

  useEffect(() => {
    if (!taskId || activeTab === 'board') return
    if (loadedTabsRef.current.has(activeTab)) return
    void loadTab(activeTab)
  }, [activeTab, taskId, loadTab])

  useEffect(() => {
    if (searchTimerRef.current !== null) window.clearTimeout(searchTimerRef.current)
    searchTimerRef.current = window.setTimeout(() => {
      const next = searchDraft.trim()
      // 先落到 ref，保证后续加载器读到的是最新关键词，避免首帧用旧值请求。
      searchRef.current = next
      setSearchText(next)
      if (activeTab === 'review') void loadReview(true)
      else if (activeTab === 'rejected') void loadRejected()
      else if (activeTab === 'archived') void loadArchived(true)
      else if (activeTab === 'killsweep') void loadKillsweeps()
    }, 180)
    return () => {
      if (searchTimerRef.current !== null) window.clearTimeout(searchTimerRef.current)
    }
  }, [searchDraft, activeTab, loadReview, loadRejected, loadArchived, loadKillsweeps])

  useEffect(
    () => () => {
      if (refreshTimerRef.current !== null) window.clearTimeout(refreshTimerRef.current)
      if (searchTimerRef.current !== null) window.clearTimeout(searchTimerRef.current)
    },
    []
  )

  // ============================================================ 操作

  async function ctl(action: 'start' | 'pause' | 'stop') {
    if (!taskId) return
    try {
      if (action === 'start') {
        const res = (await userApi.startTask(taskId)) as { status?: string; target_stats?: Record<string, number> }
        const stats = res?.target_stats || {}
        const queued = num(stats.queued) + num(stats.assigned) + num(stats.scanning)
        const done = num(stats.done)
        message.success('已启动')
        // 启动复位后若无任何待办/在途目标，主循环 5 秒内会收敛回空闲——提前说明，避免「点了没反应」的困惑。
        // 手动清单/site 任务没有测绘环节，「测绘已取尽」只对含测绘来源的任务说。
        if (queued === 0) {
          const hasCollect = task.target_source !== 'manual' && task.target_source !== 'site'
          message.info(
            done > 0
              ? hasCollect
                ? `当前无待办目标（${done} 个已全部处理完成）；若测绘已取尽，任务将保持空闲`
                : `当前无待办目标（${done} 个已全部处理完成），任务将保持空闲`
              : hasCollect
                ? '当前无待办目标；若测绘已取尽，任务将保持空闲'
                : '当前无待办目标，任务将保持空闲',
            5
          )
        }
      } else if (action === 'pause') {
        await userApi.pauseTask(taskId)
        message.success('已暂停')
      } else {
        await userApi.stopTask(taskId)
        message.success('已停止')
      }
      await Promise.all([loadTask(), loadBoard()])
    } catch (e) {
      message.error(`操作失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  async function refreshAll() {
    setRefreshing(true)
    try {
      const jobs: Promise<void>[] = [loadTask(), loadBoard()]
      if (activeTab !== 'board' && loadedTabsRef.current.has(activeTab)) jobs.push(loadTab(activeTab))
      await Promise.all(jobs)
    } finally {
      setRefreshing(false)
    }
  }

  function openFinding(id: string) {
    setDrawerId(id)
    setDrawerOpen(true)
  }

  function skipTarget(t: Target) {
    if (!writable) return
    modal.confirm({
      title: `删除目标「${mask(t.host || t.id)}」？`,
      content:
        '将立即取消它正在进行的挖掘并跳过该目标（之后不再重新派发、回队，也不会被自动搜集回来）。仅对当前任务生效，不影响其它任务与已挖到的漏洞。',
      okText: '确认删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          await userApi.skipTarget(taskId, t.id, '人工在看板跳过')
          setLiveWorkers((prev) => prev.filter((w) => w.target_id !== t.id))
          message.success(`已跳过目标 ${mask(t.host)}`)
          await loadBoard()
        } catch (e) {
          message.error(`删除失败：${e instanceof Error ? e.message : String(e)}`)
        }
      }
    })
  }

  function rescanTarget(t: Target) {
    if (!writable) return
    const needsConfirm = t.status === 'skipped' || t.status === 'dead'
    const run = async () => {
      try {
        await userApi.rescanTarget(taskId, t.id)
        message.success(`已重新排队 ${mask(t.host)}`)
        await loadBoard()
      } catch (e) {
        message.error(`重扫失败：${e instanceof Error ? e.message : String(e)}`)
      }
    }
    if (!needsConfirm) {
      void run()
      return
    }
    modal.confirm({
      title: `重新扫描「${mask(t.host || t.id)}」？`,
      content: '该目标此前已停止挖掘（已跳过或失败）。重扫将清除失败原因并重新排队，按当前任务参数重新挖掘。已挖到的漏洞不受影响。',
      okText: '重新扫描',
      cancelText: '取消',
      onOk: run
    })
  }

  function openDirective(id: string, host: string) {
    if (!writable) return
    setDirectiveTarget({ id, host })
    setDirectiveText('')
    setDirectiveOpen(true)
  }

  async function submitDirective() {
    const text = directiveText.trim()
    if (!text || !directiveTarget) return
    setDirectiveSending(true)
    try {
      await userApi.injectDirective(taskId, directiveTarget.id, text)
      message.success('指令已排队，下一轮 LLM 前生效')
      setDirectiveOpen(false)
      setDirectiveTarget(null)
      setDirectiveText('')
    } catch (e) {
      message.error(`注入失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setDirectiveSending(false)
    }
  }

  async function openTrace(targetId: string, host: string) {
    if (!targetId) return
    setTraceTarget({ id: targetId, host })
    setTraceOpen(true)
    setTraceDirective('')
    const live = traceMap[targetId] || []
    setTraceRows([...live].reverse())
    setTraceLoading(true)
    try {
      const res = await userApi.targetTrace(taskId, targetId, 200)
      const raw: unknown[] = Array.isArray(res)
        ? res
        : Array.isArray(asRecord(res).events)
          ? (asRecord(res).events as unknown[])
          : []
      const rows: TraceRow[] = raw
        .map((e) => toTraceRow(asRecord(e), engineRef.current))
        .filter((x): x is TraceRow => !!x)
      const seen = new Set<string>()
      const merged: TraceRow[] = []
      for (const r of [...rows, ...live]) {
        const key = traceDedupKey({ kind: r.kind, round: r.round, message: r.text, ts: r.ts })
        if (seen.has(key)) continue
        seen.add(key)
        merged.push(r)
      }
      merged.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime())
      setTraceRows([...merged].reverse())
    } catch (e) {
      message.error(`加载轨迹失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setTraceLoading(false)
    }
  }

  async function sendTraceDirective() {
    const text = traceDirective.trim()
    if (!writable || !traceTarget || !text || traceDirectiveSending) return
    setTraceDirectiveSending(true)
    try {
      await userApi.injectDirective(taskId, traceTarget.id, text)
      message.success('指令已排队，下一轮 LLM 前生效')
      setTraceDirective('')
    } catch (e) {
      message.error(`注入失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setTraceDirectiveSending(false)
    }
  }

  function cancelEscalation(e: EscalationLive) {
    if (!writable || cancellingEscalate) return
    modal.confirm({
      title: `取消「${shortText(mask(e.title), 60)}」的扩大危害？`,
      okText: '确认取消',
      cancelText: '返回',
      onOk: async () => {
        setCancellingEscalate(e.finding_id)
        try {
          await userApi.cancelEscalation(taskId, e.finding_id)
          setLiveEscalations((prev) => prev.filter((x) => x.finding_id !== e.finding_id))
          message.success('已取消扩大危害')
        } catch (err) {
          message.error(`取消失败：${err instanceof Error ? err.message : String(err)}`)
        } finally {
          setCancellingEscalate(null)
        }
      }
    })
  }

  async function restoreArchivedItem(id: string) {
    try {
      await userApi.restoreResult(id)
      message.success('已恢复到复审队列')
      setArchived((s) => ({ ...s, items: s.items.filter((f) => f.id !== id) }))
      const jobs: Promise<void>[] = [loadBoard()]
      if (loadedTabsRef.current.has('review')) jobs.push(loadReview(true))
      await Promise.all(jobs)
    } catch (e) {
      message.error(`恢复失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  function invalidateKillsweep(k: Killsweep) {
    if (!writable || invalidatingId) return
    const name = shortText(k.product_name || ksText(k, 'vuln_summary') || '这条通杀记录', 60)
    modal.confirm({
      title: `把「${name}」标记为无效？`,
      content: '标记后会从默认通杀列隐藏，原始记录仍保留用于审计。',
      okText: '标记无效',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        setInvalidatingId(k.id)
        try {
          await userApi.invalidateKillsweep(taskId, k.id, '人工复审判定该通杀候选无效')
          setExpandedKs((prev) => prev.filter((x) => x !== k.id))
          message.success('已标记为无效')
          await Promise.all([loadKillsweeps(), loadBoard()])
        } catch (e) {
          message.error(`标记失败：${e instanceof Error ? e.message : String(e)}`)
        } finally {
          setInvalidatingId(null)
        }
      }
    })
  }

  async function retryKillsweep(k: Killsweep) {
    if (!writable || retryingId) return
    setRetryingId(k.id)
    try {
      await userApi.retryKillsweep(taskId, k.id)
      message.success('已重新启动通杀分析')
      await Promise.all([loadKillsweeps(), loadBoard()])
    } catch (e) {
      message.error(`重启失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setRetryingId(null)
    }
  }

  async function toggleAutoKillsweep(next: boolean) {
    if (!writable || autoSaving) return
    setAutoSaving(true)
    try {
      await userApi.updateTask(taskId, { auto_killsweep: next })
      setAutoKillsweep(next)
      setTask((prev) => (prev ? { ...prev, auto_killsweep: next } : prev))
      message.success(next ? '已开启：复审通过后自动通杀' : '已关闭自动通杀')
    } catch (e) {
      message.error(`保存失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setAutoSaving(false)
    }
  }

  // ============================================================ 派生数据

  const targetColumns = useMemo(() => {
    const cols = board?.columns
    if (cols && typeof cols === 'object' && Object.keys(cols).length) {
      const keys = [
        ...TARGET_STATUS_ORDER.filter((k) => cols[k]),
        ...Object.keys(cols).filter((k) => !TARGET_STATUS_ORDER.includes(k))
      ]
      return keys.map((k) => ({ key: k, title: TARGET_STATUS_LABEL[k] || k, items: cols[k] || [] }))
    }
    const grouped: Record<string, Target[]> = {}
    for (const t of board?.targets || []) {
      const key = t.status || 'queued'
      if (!grouped[key]) grouped[key] = []
      grouped[key].push(t)
    }
    const keys = [
      ...TARGET_STATUS_ORDER.filter((k) => grouped[k]),
      ...Object.keys(grouped).filter((k) => !TARGET_STATUS_ORDER.includes(k))
    ]
    return keys.map((k) => ({ key: k, title: TARGET_STATUS_LABEL[k] || k, items: grouped[k] }))
  }, [board])

  const totalTargets =
    num(stats.queued) + num(stats.scanning) + num(stats.done) + num(stats.dead) + num(stats.skipped)
  const resolvedTargets = num(stats.done) + num(stats.dead) + num(stats.skipped)
  const totalHosts = num(stats.hosts_total)
  const checkedHosts = num(stats.hosts_checked)

  const collectDonePhases = useMemo(() => new Set(['dispatch', 'idle', 'exhausted', 'fofa_error']), [])
  const collectorPhase = str(fofaConfig.collector_phase)
  const isCollecting = useMemo(() => {
    if (task?.status !== 'running') return false
    if (collectorPhase) return !collectDonePhases.has(collectorPhase)
    return totalTargets === 0
  }, [task?.status, collectorPhase, totalTargets, collectDonePhases])
  const collectorPct = useMemo(() => {
    const total = num(fofaConfig.last_target_filter_total)
    const done = num(fofaConfig.last_target_filter_evaluated)
    if (collectorPhase === 'prefilter') return 18
    if (collectorPhase === 'scoring') return 38
    if (collectorPhase === 'target_filter') return 62
    if (collectorPhase === 'enrich') return total > 0 ? Math.max(72, Math.min(88, Math.round((done / total) * 100))) : 78
    if (collectorPhase === 'dispatch') return 100
    return 25
  }, [collectorPhase, fofaConfig])
  const progressPct = isCollecting
    ? collectorPct || 8
    : totalTargets
      ? Math.round((resolvedTargets / totalTargets) * 100)
      : 0
  const collectorVisible =
    !collectDonePhases.has(collectorPhase) && (isCollecting || !!collectorPhase || !!str(fofaConfig.collector_phase_text))
  const collectorText =
    str(fofaConfig.collector_phase_text) ||
    PHASE_LABEL[collectorPhase] ||
    (isCollecting ? '正在初始化搜集引擎…' : '正在跑过滤器阶段')
  const collectorMeta = (() => {
    const total = num(fofaConfig.last_target_filter_total)
    const done = num(fofaConfig.last_target_filter_evaluated)
    if (total > 0) return `过滤器 ${done}/${total}`
    return PHASE_LABEL[collectorPhase] || (isCollecting ? '初始化中' : '')
  })()

  // 端点池模式没有单一 model 字段：后端补发 model_display（启用端点模型名汇总）。
  const modelName =
    str(modelConfig.model_display) || str(modelConfig.model) || str(llmUsage.model) || '未配置模型'
  const cacheHitRate = useMemo(() => {
    const hit = num(llmUsage.cache_hit_tokens)
    const miss = num(llmUsage.cache_miss_tokens)
    const base = hit + miss || num(llmUsage.prompt_tokens)
    if (!base) return null
    return Math.round((hit / base) * 100)
  }, [llmUsage])
  const engineSourceHint = useMemo(() => {
    const by = asRecord(engineUsage.by_source)
    const label: Record<string, string> = { collector: '搜集', worker: 'Worker', killsweep: '通杀' }
    return Object.entries(by)
      .filter(([, n]) => num(n) > 0)
      .map(([k, n]) => `${label[k] || k} ${num(n)}`)
      .join(' · ')
  }, [engineUsage])

  // REVIEW 卡只读 review_queue（与 ListReviewQueue / TaskStatsOf 完全同源：
  // accepted + 用户待处理）。review_pending 已在 TaskStatsOf 里改为同口径，
  // 不再用 max 兜底——旧兜底会把 AI 未采纳的 pending 也算进来，导致
  // 「REVIEW 卡 4、复审队列 1」的口径矛盾。
  const reviewCount = num(stats.review_queue)
  const submitCount = submitItems.items.length
  const sweepCount = Math.max(num(stats.killsweep), killsweeps.items.length)
  const rejectedCount = Math.max(num(stats.rejected), rejected.items.length)
  const archivedCount = Math.max(num(stats.archived), archived.items.length)
  const deepenCount = Math.max(num(stats.deepen), deepen.items.length)
  const archivedWriteCount = num(stats.archived_write)

  const searchTokens = useMemo(() => searchText.trim().toLowerCase().split(/\s+/).filter(Boolean), [searchText])
  const filterList = useCallback(
    (items: FindingView[]): FindingView[] => {
      if (!searchTokens.length) return items
      return items.filter((f) => {
        let text = ''
        try {
          text = JSON.stringify(f).toLowerCase()
        } catch {
          text = String(f).toLowerCase()
        }
        return searchTokens.every((t) => text.includes(t))
      })
    },
    [searchTokens]
  )
  const filteredQueue = useMemo(() => filterList(queue.items), [filterList, queue.items])
  const filteredSubmit = useMemo(() => filterList(submitItems.items), [filterList, submitItems.items])
  const filteredRejected = useMemo(() => filterList(rejected.items), [filterList, rejected.items])
  const filteredArchived = useMemo(() => filterList(archived.items), [filterList, archived.items])
  const filteredDeepen = useMemo(() => filterList(deepen.items), [filterList, deepen.items])

  function detailsForTarget(targetId: string): TraceRow[] {
    const list = traceMap[targetId] || []
    return list
      .filter((r) => DETAIL_KINDS.has(r.kind))
      .slice()
      .reverse()
      .slice(0, 40)
  }
  function targetIsLive(targetId: string): boolean {
    return liveWorkers.some((w) => w.target_id === targetId)
  }
  /** 目标是否已终态（done/skipped/dead）。 */
  function targetIsClosed(targetId: string): boolean {
    return TARGET_CLOSED_STATUS.has(targetStatusOf(targetId))
  }
  /** 从看板快照读目标状态；快照未就绪时返回空串。 */
  function targetStatusOf(targetId: string): string {
    const list = Array.isArray(board?.targets) ? board.targets : []
    const row = list.map((x) => asRecord(x)).find((x) => str(x.id) === targetId)
    return str(row?.status)
  }
  /** 轨迹抽屉标签：worker 在跑 → 实时；目标未终态但 worker 暂缺 → 调度中；终态 → 已结束。 */
  function traceTagColor(targetId: string): string {
    if (targetIsLive(targetId)) return 'processing'
    if (targetIsClosed(targetId)) return 'default'
    return 'gold'
  }
  function traceTagText(targetId: string): string {
    if (targetIsLive(targetId)) return '实时'
    if (targetIsClosed(targetId)) return '已结束'
    return '调度中'
  }
  function evTime(ts: string): string {
    const d = new Date(str(ts))
    if (Number.isNaN(d.getTime())) return '-'
    return d.toLocaleTimeString('zh-CN', { hour12: false })
  }

  // ============================================================ 渲染片段

  function sevTag(sev: string) {
    return (
      <Tag color={SEVERITY_COLOR[sev] || 'default'} style={{ marginInlineEnd: 0 }}>
        {sev || '-'}
      </Tag>
    )
  }

  /** 漏洞行（复审 / 待提交 / 已驳回 / 已归档 / 深化中 复用）。 */
  function renderFindingRow(f: FindingView, extra?: ReactNode) {
    const sev = str(f.review?.user_severity) || str(f.severity_final) || str(f.user_severity) || str(f.severity)
    return (
      <List.Item
        style={{ cursor: 'pointer', paddingInline: 12 }}
        onClick={() => openFinding(f.id)}
        actions={
          extra
            ? [extra]
            : [
                <Typography.Text type="secondary" key="score">
                  {f.review?.score ?? '-'}
                </Typography.Text>
              ]
        }
      >
        <List.Item.Meta
          avatar={sevTag(sev)}
          title={
            <Space size={6} wrap>
              <Typography.Text strong>{mask(f.title)}</Typography.Text>
              {f.is_top ? <PushpinFilled style={{ color: '#faad14' }} /> : null}
              {/* 已提交标识：让「标记为已提交」在列表里立刻可见（否则用户感知不到变化） */}
              {f.review?.submitted ? <Tag color="green">已提交</Tag> : null}
            </Space>
          }
          description={
            <Space direction="vertical" size={0} style={{ width: '100%' }}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {VULN_TYPE_LABEL[f.vuln_type] || f.vuln_type || '-'} · {mask(f.target_url)}
              </Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                发现 {fmtLocalTime(f.created_at)}
                {f.llm_model ? ` · 模型 ${f.llm_model}` : ''}
              </Typography.Text>
              {f.review?.user_notes ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  复审备注：{mask(f.review.user_notes)}
                </Typography.Text>
              ) : null}
              {str(f.archive_reason_text) ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {str(f.archive_reason_text)}
                </Typography.Text>
              ) : null}
            </Space>
          }
        />
      </List.Item>
    )
  }

  const tabItems = [
    { key: 'board', label: '实时看板' },
    {
      key: 'review',
      label: (
        <Space size={4}>
          复审队列
          {reviewCount ? <Badge count={reviewCount} color="#7c5cff" size="small" /> : null}
        </Space>
      )
    },
    {
      key: 'submit',
      label: (
        <Space size={4}>
          待提交
          {submitCount ? <Badge count={submitCount} color="#16a34a" size="small" /> : null}
        </Space>
      )
    },
    {
      key: 'deepen',
      label: (
        <Space size={4}>
          深化中
          {deepenCount ? <Badge count={deepenCount} color="#4f8cff" size="small" /> : null}
        </Space>
      )
    },
    {
      key: 'killsweep',
      label: (
        <Space size={4}>
          通杀列
          {sweepCount ? <Badge count={sweepCount} color="#d97706" size="small" /> : null}
        </Space>
      )
    },
    {
      key: 'rejected',
      label: (
        <Space size={4}>
          已驳回
          {rejectedCount ? <Badge count={rejectedCount} color="#dc2626" size="small" /> : null}
        </Space>
      )
    },
    {
      key: 'archived',
      label: (
        <Space size={4}>
          AI 未采纳
          {archivedCount ? <Badge count={archivedCount} color="#8c8c8c" size="small" /> : null}
          {archivedWriteCount ? <Tag color="red">写删 {archivedWriteCount}</Tag> : null}
        </Space>
      )
    }
  ]

  const assetColumns: ColumnsType<AssetRow> = [
    { title: '单位', dataIndex: 'school', key: 'school', width: 140, render: (v: string) => mask(v) },
    {
      title: '目标',
      key: 'target',
      render: (_, r) => <span className="mono">{mask(r.url || r.host || '-')}</span>
    },
    { title: '通杀洞', key: 'vuln', render: (_, r) => mask(r.vulnTitle || '-') },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => (
        <Tag color={v === 'verified' ? 'green' : 'default'}>{v === 'verified' ? '已验证' : '候选'}</Tag>
      )
    },
    { title: '依据', key: 'evidence', render: (_, r) => mask(r.evidence || '-') }
  ]

  /** 通杀卡片。 */
  function renderKillsweep(k: Killsweep) {
    const rows = assetRows(k)
    const verifiedCount = rows.filter((r) => r.status === 'verified').length
    const status = k.status
    const confidence = ksText(k, 'confidence')
    const isSweep = ksBool(k, 'is_killsweep') || ksBool(k, 'has_sites')
    const verified = ksBool(k, 'verified')
    const retryable = ksBool(k, 'retryable')
    const open = expandedKs.includes(k.id)
    return (
      <Card
        key={k.id}
        size="small"
        style={{ marginBottom: 10 }}
        title={
          <Space size={6} wrap>
            <Typography.Text strong>
              {mask(k.product_name || ksText(k, 'origin_title') || ksText(k, 'vuln_summary') || '通杀分析')}
            </Typography.Text>
            {status === 'analyzing' ? <Tag color="processing">分析中</Tag> : null}
            {status === 'failed' ? <Tag color="red">启动失败</Tag> : null}
            {status === 'cancelled' ? <Tag>已取消</Tag> : null}
            {status !== 'analyzing' && status !== 'failed' && status !== 'cancelled' ? (
              <Tag color={isSweep ? 'green' : 'default'}>
                {isSweep ? `有通杀站${verifiedCount > 1 ? ` ${verifiedCount} 个` : ''}` : '无通杀站'}
              </Tag>
            ) : null}
            {verified ? <Tag color="green">已验证{verifiedCount > 1 ? ` ${verifiedCount} 个` : ''}</Tag> : null}
            {confidence ? <Tag color="blue">{confidence}</Tag> : null}
          </Space>
        }
        extra={
          <Button
            size="small"
            type="text"
            onClick={() =>
              setExpandedKs((prev) => (open ? prev.filter((x) => x !== k.id) : [...prev, k.id]))
            }
          >
            {open ? '收起' : '展开'}
          </Button>
        }
      >
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {ksText(k, 'vuln_type') ? `${ksText(k, 'vuln_type')} · ` : ''}
            {mask(ksText(k, 'origin_title') || ksText(k, 'vuln_summary') || '源漏洞')} · 发现 {fmtLocalTime(k.created_at)}
          </Typography.Text>
          <Space size={12} wrap>
            <Typography.Text style={{ fontSize: 12 }}>
              <b>{rows.length}</b> 资产
            </Typography.Text>
            <Typography.Text style={{ fontSize: 12 }}>
              <b>{task?.src_type === 'enterprise' ? ksNum(k, 'asset_count') : ksNum(k, 'edu_count')}</b>
              {task?.src_type === 'enterprise' ? '范围' : '教育'}
            </Typography.Text>
            <Typography.Text style={{ fontSize: 12 }}>
              <b>{ksNum(k, 'asset_count')}</b> 全网
            </Typography.Text>
            <Typography.Text style={{ fontSize: 12 }}>
              <b>{k.hits}</b> 命中 / <b>{k.scanned}</b> 扫描
            </Typography.Text>
          </Space>
          {open ? (
            <>
              <Descriptions
                size="small"
                column={1}
                bordered
                items={[
                  { key: 'created', label: '发现时间', children: fmtLocalTime(k.created_at) || '未知' },
                  {
                    key: 'query',
                    label: '测绘语法',
                    children: <code className="mono">{mask(ksText(k, 'fofa_query') || '无测绘语法')}</code>
                  },
                  {
                    key: 'fingerprint',
                    label: '指纹依据',
                    children: mask(
                      ksText(k, 'fingerprint') ||
                        (status === 'failed' || status === 'cancelled' ? k.notes : '') ||
                        k.notes ||
                        '无补充依据'
                    )
                  }
                ]}
              />
              <div style={{ marginTop: 8 }}>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  统一资产列表 · {rows.length} 条（强制字段：单位/系统 · 目标 · 漏洞 · 状态 · 依据）
                </Typography.Text>
                <Table<AssetRow>
                  rowKey={(r, i) => `${r.url || r.host || 'row'}-${i}`}
                  size="small"
                  columns={assetColumns}
                  dataSource={rows}
                  pagination={false}
                  locale={{ emptyText: '暂无资产明细，仅保留通杀摘要。' }}
                  style={{ marginTop: 6 }}
                />
              </div>
              {writable ? (
                <Space style={{ marginTop: 8 }} wrap>
                  {retryable ? (
                    <Button size="small" loading={retryingId === k.id} onClick={() => retryKillsweep(k)}>
                      重新启动通杀
                    </Button>
                  ) : null}
                  <Button
                    size="small"
                    danger
                    disabled={invalidatingId === k.id || status === 'analyzing'}
                    loading={invalidatingId === k.id}
                    onClick={() => invalidateKillsweep(k)}
                  >
                    标记为无效
                  </Button>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {status === 'failed'
                      ? 'LLM/中转站失败后可直接重启，不用改复审状态。'
                      : !isSweep
                        ? '分析完成但没有圈到通杀站；也可再跑一轮。'
                        : '误判、资产不稳定、未实际验证或通杀条件不成立时使用。'}
                  </Typography.Text>
                </Space>
              ) : null}
            </>
          ) : null}
        </Space>
      </Card>
    )
  }

  // ============================================================ 主渲染

  if (initialLoading && !task) {
    return (
      <section className="board-view">
        <Card>
          <div style={{ textAlign: 'center', padding: '48px 0' }}>
            <Spin tip="正在加载任务看板…" size="large" />
          </div>
        </Card>
      </section>
    )
  }

  if (!task) {
    return (
      <section className="board-view">
        <Card>
          <Empty description="任务不存在或加载失败，请返回任务列表重试">
            <Button type="primary" onClick={() => navigate('/')}>
              返回任务列表
            </Button>
          </Empty>
        </Card>
      </section>
    )
  }

  const runLabel = TASK_STATUS_LABEL[task.status] || task.status
  const runHint =
    task.status === 'running' ? '24×7 自动补队列' : task.status === 'idle' ? '等待新目标或人工动作' : '调度已收敛'
  const isEnterprise = task.src_type === 'enterprise'

  return (
    <section className="board-view">
      {refreshing && !initialLoading ? <Progress percent={100} showInfo={false} size="small" status="active" /> : null}

      {/* 顶部任务信息与操作 */}
      <Card style={{ marginBottom: 12 }} size="small">
        <Row gutter={16} align="middle">
          <Col flex="auto">
            <Space size={10} align="center" wrap style={{ marginTop: 6 }}>
              <Typography.Title level={4} style={{ margin: 0 }}>
                {task.name}
              </Typography.Title>
              <Badge status={TASK_STATUS_BADGE[task.status] || 'default'} text={runLabel} />
            </Space>
            <div className="board-meta-strip">
              <div className="board-meta-cell">
                <span className="board-meta-k">口径</span>
                <span className="board-meta-v">{isEnterprise ? '企业SRC' : 'EduSRC'}</span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">来源</span>
                <span className="board-meta-v">
                  {({ fofa: '测绘搜集', manual: '手动清单', both: '测绘+手动', site: '单站协作' } as Record<string, string>)[
                    task.target_source
                  ] || task.target_source}
                  {task.target_source !== 'manual' && task.target_source !== 'site' ? (
                    <Tag color="blue" style={{ marginInlineStart: 6, marginInlineEnd: 0 }}>
                      {engineLabelOf(task.engine)}
                    </Tag>
                  ) : null}
                </span>
              </div>
              <div className="board-meta-cell board-meta-cell-wide">
                <span className="board-meta-k">目标</span>
                <span
                  className="board-meta-v"
                  title={str(task.fofa_query || (task.target_source === 'site' ? task.manual_targets?.[0] : '') || '')}
                >
                  {task.target_source === 'site'
                    ? truncate(task.fofa_query || task.manual_targets?.[0] || '单站协作', 60)
                    : truncate(task.fofa_query || '手动清单', 60)}
                </span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">并发</span>
                <span className="board-meta-v">{task.concurrency}</span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">深挖</span>
                <span className="board-meta-v">×{task.deepen_cap ?? 2}</span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">队列</span>
                <span className="board-meta-v">{runHint}</span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">模型</span>
                <span className="board-meta-v">{modelName}</span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">Token</span>
                <span className="board-meta-v">
                  {formatTokenCount(llmUsage.total_tokens)}（入 {formatTokenCount(llmUsage.prompt_tokens)} / 出{' '}
                  {formatTokenCount(llmUsage.completion_tokens)}）
                </span>
              </div>
              <div className="board-meta-cell">
                <span className="board-meta-k">请求</span>
                <span className="board-meta-v">{num(llmUsage.requests)}</span>
              </div>
              <Tooltip title={mask(str(engineUsage.last_query))}>
                <div className="board-meta-cell">
                  <span className="board-meta-k">测绘</span>
                  <span className="board-meta-v">
                    {num(engineUsage.count)} · {str(engineUsage.last_engine) || engineLabelOf(task.engine)}
                    {engineSourceHint ? ` · ${engineSourceHint}` : ''}
                  </span>
                </div>
              </Tooltip>
              {cacheHitRate !== null ? (
                <div className="board-meta-cell">
                  <span className="board-meta-k">缓存命中</span>
                  <span className="board-meta-v">{cacheHitRate}%</span>
                </div>
              ) : null}
              <div className="board-meta-cell">
                <span className="board-meta-k">事件流</span>
                <span className={`board-meta-v${streamStatus === 'open' ? ' is-ok' : ''}`}>{streamStatus}</span>
              </div>
            </div>
          </Col>
          <Col>
            <Space direction="vertical" align="center" size={8}>
              <Progress
                type="circle"
                size={92}
                percent={progressPct}
                status={isCollecting ? 'active' : 'normal'}
                format={() => (
                  <span style={{ fontSize: 12 }}>
                    {isCollecting && !collectorPhase ? '…' : `${progressPct}%`}
                    <br />
                    {isCollecting ? '搜集进度' : '处置进度'}
                  </span>
                )}
              />
              {writable ? (
                <Space wrap>
                  <Button icon={<EditOutlined />} onClick={() => navigate(`/create/${taskId}`)}>
                    编辑参数
                  </Button>
                  <Button
                    icon={<DownloadOutlined />}
                    onClick={() => runBulk('正在导出测绘结果…', exportTargetsCsv)}
                  >
                    导出目标
                  </Button>
                  <Button
                    type="primary"
                    icon={<PlayCircleOutlined />}
                    disabled={task.status === 'running'}
                    onClick={() => ctl('start')}
                  >
                    启动
                  </Button>
                  <Button
                    icon={<PauseCircleOutlined />}
                    disabled={task.status !== 'running'}
                    onClick={() => ctl('pause')}
                  >
                    暂停
                  </Button>
                  <Button danger icon={<StopOutlined />} onClick={() => ctl('stop')}>
                    停止
                  </Button>
                  <Button icon={<ReloadOutlined />} loading={refreshing} onClick={() => refreshAll()}>
                    刷新
                  </Button>
                </Space>
              ) : (
                <Space>
                  <Tag>{role === 'readonly' ? '只读模式' : '未认证'}</Tag>
                  <Button icon={<ReloadOutlined />} loading={refreshing} onClick={() => refreshAll()}>
                    刷新
                  </Button>
                </Space>
              )}
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 单站协作态势 */}
      {collab ? (
        <Card
          size="small"
          style={{ marginBottom: 12 }}
          title={
            <Space size={8}>
              <Tag color="purple">单站协作</Tag>
              <Typography.Text strong>协作态势</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                同一目标拆成多条路线协同攻击，共享覆盖上下文、逐阶段深入
              </Typography.Text>
            </Space>
          }
          extra={
            <Space size={12}>
              <Typography.Text style={{ fontSize: 12 }}>
                <b>{collab.routes}</b> 路线
              </Typography.Text>
              {collab.running ? (
                <Typography.Text style={{ fontSize: 12, color: '#7c5cff' }}>
                  <b>{collab.running}</b> 进行中
                </Typography.Text>
              ) : null}
              {collab.findings ? (
                <Typography.Text style={{ fontSize: 12, color: '#16a34a' }}>
                  <b>{collab.findings}</b> 已出洞
                </Typography.Text>
              ) : null}
            </Space>
          }
        >
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            {collab.phases.map((p) => {
              const routes = groupRoutes(p.routes)
              return (
                <div key={p.key} style={{ borderLeft: '2px solid var(--aisrc-border)', paddingLeft: 10 }}>
                  <Space size={8} wrap>
                    <Tag>阶段 {p.phase + 1}</Tag>
                    <Typography.Text strong>{p.label}</Typography.Text>
                    <Tag color={p.state === 'active' ? 'processing' : p.state === 'done' ? 'green' : 'default'}>
                      {phaseStateText(p.state)}
                    </Tag>
                    {p.phase === collab.currentPhase ? <Tag color="purple">当前</Tag> : null}
                    {p.total ? (
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {p.total} 条
                      </Typography.Text>
                    ) : null}
                  </Space>
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: '4px 0' }}>
                    {p.desc}
                  </Typography.Paragraph>
                  {routes.length ? (
                    <Space size={6} wrap>
                      {routes.map((r) => (
                        <Tooltip
                          key={`${r.source}:${r.label}`}
                          title={
                            r.count > 1
                              ? `共 ${r.count} 条${r.running ? ` · ${r.running} 进行中` : ''}${r.queued ? ` · ${r.queued} 排队` : ''}${r.done ? ` · ${r.done} 完成` : ''}`
                              : r.focus || r.label
                          }
                        >
                          <Tag color={r.status === 'running' ? 'processing' : r.status === 'queued' ? 'blue' : 'default'}>
                            {r.label}
                            {r.count > 1 ? ` ×${r.count}` : ''}
                            {r.findings ? ` · ${r.findings}` : ''}
                          </Tag>
                        </Tooltip>
                      ))}
                    </Space>
                  ) : (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {p.phase === 0 ? '待启动' : p.phase === 1 ? '等侦察完成后自动派发' : '等待侦察发现具体入口'}
                    </Typography.Text>
                  )}
                </div>
              )
            })}
          </Space>
        </Card>
      ) : null}

      {/* 搜集阶段进度条 */}
      {collectorVisible ? (
        <Card size="small" style={{ marginBottom: 12 }}>
          <Space size={12} style={{ width: '100%' }} align="center">
            <Typography.Text strong>{collectorText}</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {collectorMeta}
            </Typography.Text>
          </Space>
          <Progress percent={collectorPct} status="active" size="small" style={{ marginTop: 6 }} />
        </Card>
      ) : null}

      {/* 指标卡 */}
      <div className="stat-grid">
        <div className="stat-card">
          <span className="stat-k">SITES</span>
          <b className="stat-v">{totalHosts || totalTargets}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            独立网站 · {totalTargets} 条目标
          </span>
        </div>
        <div className="stat-card">
          <span className="stat-k">ACTIVE</span>
          <b className="stat-v">{num(stats.scanning)}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            扫描中
          </span>
        </div>
        <div className="stat-card">
          <span className="stat-k">CHECKED</span>
          <b className="stat-v">{checkedHosts}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            已检查
          </span>
        </div>
        <div className="stat-card warn">
          <span className="stat-k">FINDINGS</span>
          <b className="stat-v">{num(stats.findings_total)}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            原始发现
          </span>
        </div>
        <div className="stat-card danger">
          <span className="stat-k">REVIEW</span>
          <b className="stat-v">{reviewCount}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            待复审
          </span>
        </div>
        <div className="stat-card ok">
          <span className="stat-k">READY</span>
          <b className="stat-v">{submitCount}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            待提交
          </span>
        </div>
        <div className="stat-card">
          <span className="stat-k">SWEEP</span>
          <b className="stat-v">{sweepCount}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            通杀列
          </span>
        </div>
      </div>

      <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />

      {/* 搜索条（非看板页签） */}
      {activeTab !== 'board' ? (
        <Card size="small" style={{ marginBottom: 12 }}>
          <Space wrap>
            <Input.Search
              allowClear
              placeholder={
                isEnterprise
                  ? '搜索漏洞：标题 / URL / 类型 / 单位 / 系统 / 报告正文 / 审核备注'
                  : '搜索漏洞：标题 / URL / 类型 / 学校 / 报告正文 / 审核备注'
              }
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              style={{ width: 420 }}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              命中{' '}
              {activeTab === 'review'
                ? filteredQueue.length
                : activeTab === 'submit'
                  ? filteredSubmit.length
                  : activeTab === 'rejected'
                    ? filteredRejected.length
                    : activeTab === 'archived'
                      ? filteredArchived.length
                      : activeTab === 'deepen'
                        ? filteredDeepen.length
                        : killsweeps.items.length}
            </Typography.Text>
          </Space>
        </Card>
      ) : null}

      {/* ---------------- 实时看板 ---------------- */}
      {activeTab === 'board' ? (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          {/* 目标看板列 */}
          <Card
            size="small"
            title={
              <Space size={8}>
                <Typography.Text strong>目标看板</Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  按状态分组 · 可跳过 / 注入指令 / 查看轨迹
                </Typography.Text>
              </Space>
            }
          >
            {!boardReady ? (
              <Spin>
                <div style={{ height: 80 }} />
              </Spin>
            ) : !targetColumns.length ? (
              <Empty description="暂无目标（等待搜集器入队）" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              <div style={{ display: 'flex', gap: 12, overflowX: 'auto', paddingBottom: 4, alignItems: 'flex-start' }}>
                {targetColumns.map((col) => (
                  <div key={col.key} style={{ minWidth: 320, maxWidth: 560, flex: '1 1 340px' }}>
                    <Space size={6} style={{ marginBottom: 8 }}>
                      <Typography.Text strong>{col.title}</Typography.Text>
                      <Badge count={col.items.length} color="#7c5cff" size="small" />
                    </Space>
                    <Space direction="vertical" size={8} style={{ width: '100%' }}>
                      {col.items.map((t) => (
                        <Card key={t.id} size="small" styles={{ body: { padding: 10 } }}>
                          <Space direction="vertical" size={4} style={{ width: '100%' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, maxWidth: '100%' }}>
                              {t.is_top ? <PushpinFilled style={{ color: '#faad14', flexShrink: 0 }} /> : null}
                              <Typography.Text strong ellipsis={{ tooltip: true }} style={{ flex: 1, minWidth: 0 }}>
                                {mask(targetDisplayURL(t))}
                              </Typography.Text>
                              <Tag color={SEVERITY_COLOR[t.verdict] || 'default'} style={{ marginInlineEnd: 0, flexShrink: 0 }}>
                                {num(t.priority_score).toFixed(0)}
                              </Tag>
                            </div>
                            <Typography.Text type="secondary" style={{ fontSize: 12, maxWidth: '100%', display: 'block' }} className="nowrap-ellipsis" ellipsis={{ tooltip: true }}>
                              {mask(t.title) || '（无标题）'}
                            </Typography.Text>
                            <Space size={6} wrap style={{ fontSize: 12 }}>
                              <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                                {TARGET_STATUS_LABEL[t.status] || t.status}
                              </Tag>
                              <Tag style={{ marginInlineEnd: 0 }}>{targetSourceLabel(t.source)}</Tag>
                              {t.deepen_count ? <Tag color="purple">深化 ×{t.deepen_count}</Tag> : null}
                              {t.category ? <Tag>{t.category}</Tag> : null}
                            </Space>
                            {writable ? (
                              <Space size={4} wrap>
                                <Button size="small" onClick={() => openTrace(t.id, t.host)}>
                                  轨迹
                                </Button>
                                <Button size="small" onClick={() => openDirective(t.id, t.host)}>
                                  注入指令
                                </Button>
                                {TARGET_CLOSED_STATUS.has(t.status) ? (
                                  <Button
                                    size="small"
                                    type="primary"
                                    ghost
                                    onClick={() => rescanTarget(t)}
                                  >
                                    重扫
                                  </Button>
                                ) : null}
                                <Button size="small" danger onClick={() => skipTarget(t)}>
                                  跳过
                                </Button>
                              </Space>
                            ) : null}
                          </Space>
                        </Card>
                      ))}
                    </Space>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Row gutter={12}>
            {/* Worker 矩阵 */}
            <Col xs={24} lg={12}>
              <Card
                size="small"
                title={
                  <Space size={8}>
                    <Typography.Text strong>Worker Matrix</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      点击卡片查看轨迹
                    </Typography.Text>
                    <Badge count={liveWorkers.length} color="#7c5cff" size="small" />
                  </Space>
                }
              >
                {!boardReady ? (
                  <Spin>
                    <div style={{ height: 60 }} />
                  </Spin>
                ) : !liveWorkers.length ? (
                  <Empty description="暂无运行中的 worker" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : (
                  <Space direction="vertical" size={8} style={{ width: '100%' }}>
                    {liveWorkers.map((w) => (
                      <Card
                        key={w.target_id}
                        size="small"
                        hoverable
                        styles={{ body: { padding: 10 } }}
                        onClick={() => openTrace(w.target_id, w.host)}
                      >
                        <Space direction="vertical" size={4} style={{ width: '100%' }}>
                          <Space size={6} wrap>
                            <Typography.Text strong>{mask(w.host)}</Typography.Text>
                            {w.auth ? (
                              <Tag
                                color={w.auth === 'login_fail' ? 'red' : w.auth === 'unused' ? 'default' : 'green'}
                                style={{ marginInlineEnd: 0 }}
                              >
                                {({ injected: '凭据·已注入', login_ok: '凭据·登录成功', login_fail: '凭据·登录失败', unused: '凭据·未匹配' } as Record<
                                  string,
                                  string
                                >)[w.auth] || `凭据·${w.auth}`}
                              </Tag>
                            ) : null}
                            {w.score > 0 ? <Tag color="gold">★{Math.round(w.score * 10) / 10}</Tag> : null}
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              第 {w.round} 轮 · {elapsed(w.started_at)}
                            </Typography.Text>
                          </Space>
                          <Typography.Text style={{ fontSize: 12 }}>{mask(w.action)}</Typography.Text>
                          {w.model || w.model_base_url ? (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }} className="nowrap-ellipsis">
                              {w.model_role || '挖掘模型'} · {w.model || '未知模型'}
                              {w.model_base_url ? ` @ ${mask(w.model_base_url)}` : ''}
                            </Typography.Text>
                          ) : null}
                          <Space size={8}>
                            <Typography.Text style={{ fontSize: 12 }} type={w.findings > 0 ? 'success' : 'secondary'}>
                              {w.findings > 0 ? `🎯 ${w.findings} 个漏洞` : '侦察中…'}
                            </Typography.Text>
                            <Progress
                              percent={Math.min(100, Math.round((w.round / 60) * 100))}
                              showInfo={false}
                              size="small"
                              style={{ width: 120 }}
                            />
                          </Space>
                          {writable ? (
                            <Space size={4}>
                              <Button
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  openDirective(w.target_id, w.host)
                                }}
                              >
                                注入指令
                              </Button>
                              <Button
                                size="small"
                                danger
                                onClick={(e) => {
                                  e.stopPropagation()
                                  skipTarget({
                                    ...(board?.targets?.find((t) => t.id === w.target_id) || ({} as Target)),
                                    id: w.target_id,
                                    host: w.host
                                  } as Target)
                                }}
                              >
                                跳过
                              </Button>
                            </Space>
                          ) : null}
                        </Space>
                      </Card>
                    ))}

                    {liveEscalations.length ? (
                      <>
                        <Typography.Text strong style={{ fontSize: 12 }}>
                          扩大危害（进行中 {liveEscalations.length}）
                        </Typography.Text>
                        {liveEscalations.map((e) => (
                          <Card key={e.finding_id} size="small" styles={{ body: { padding: 10 } }}>
                            <Space direction="vertical" size={4} style={{ width: '100%' }}>
                              <Space size={6} wrap>
                                <Typography.Text strong>{mask(e.title)}</Typography.Text>
                                {e.severity ? <Tag color={SEVERITY_COLOR[e.severity] || 'default'}>{e.severity}</Tag> : null}
                                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                  {elapsed(e.started_at)}
                                </Typography.Text>
                              </Space>
                              <Typography.Text style={{ fontSize: 12 }}>
                                {mask(e.action) || '扩大危害进行中…'}
                              </Typography.Text>
                              {writable ? (
                                <Button
                                  size="small"
                                  danger
                                  loading={cancellingEscalate === e.finding_id}
                                  onClick={() => cancelEscalation(e)}
                                >
                                  取消扩大危害
                                </Button>
                              ) : null}
                            </Space>
                          </Card>
                        ))}
                      </>
                    ) : null}
                  </Space>
                )}
              </Card>
            </Col>

            {/* 活动流 */}
            <Col xs={24} lg={12}>
              <Card
                size="small"
                title={
                  <Space size={8}>
                    <Typography.Text strong>Activity Stream</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      点击带目标的行展开细节
                    </Typography.Text>
                  </Space>
                }
                extra={
                  <Button size="small" type="text" onClick={() => setActivity([])}>
                    清空
                  </Button>
                }
                styles={{ body: { maxHeight: 520, overflow: 'auto', padding: 8 } }}
              >
                {!boardReady && !activity.length ? (
                  <Spin>
                    <div style={{ height: 80 }} />
                  </Spin>
                ) : !activity.length ? (
                  <Empty description="等待事件…" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : (
                  <Space direction="vertical" size={2} style={{ width: '100%' }}>
                    {activity.map((ev) => {
                      const expandable = !!ev.targetId
                      const open = expandedActivity.includes(ev.uid)
                      const details = expandable ? detailsForTarget(ev.targetId) : []
                      return (
                        <div key={ev.uid} style={{ borderBottom: '1px solid var(--aisrc-border)', padding: '4px 2px' }}>
                          <div
                            style={{ display: 'flex', gap: 6, alignItems: 'flex-start', cursor: expandable ? 'pointer' : 'default' }}
                            onClick={() =>
                              expandable &&
                              setExpandedActivity((prev) =>
                                open ? prev.filter((x) => x !== ev.uid) : [...prev, ev.uid]
                              )
                            }
                          >
                            <Typography.Text type="secondary" style={{ fontSize: 11, width: 12 }}>
                              {expandable ? (open ? '▼' : '▶') : ''}
                            </Typography.Text>
                            <span style={{ fontSize: 13 }}>{AGENT_ICON[ev.agent] || '•'}</span>
                            <Tag
                              color={ev.level === 'error' ? 'red' : ev.level === 'warn' ? 'orange' : 'default'}
                              style={{ marginInlineEnd: 0, fontSize: 11 }}
                            >
                              {AGENT_LABEL[ev.agent] || ev.agent || '事件'}
                            </Tag>
                            <Typography.Text style={{ fontSize: 12, flex: 1, wordBreak: 'break-word' }}>{ev.text}</Typography.Text>
                            {isLlmErrorEvent(ev.raw) ? (
                              <Tooltip title="复制 LLM 真实错误">
                                <Button
                                  size="small"
                                  type="link"
                                  style={{ padding: 0, height: 18, fontSize: 11 }}
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    void copyLlmEvent(ev.raw)
                                  }}
                                >
                                  复制
                                </Button>
                              </Tooltip>
                            ) : null}
                            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                              {evTime(ev.ts)}
                            </Typography.Text>
                          </div>
                          {expandable && open ? (
                            <div style={{ marginTop: 4, paddingLeft: 26 }}>
                              {!details.length ? (
                                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                  {targetIsLive(ev.targetId)
                                    ? '暂无工具/思考细节（worker 运行中，稍等产出）'
                                    : targetIsClosed(ev.targetId)
                                      ? '该 worker 已结束，工具/思考明细已归档清理（仅保留关键节点）'
                                      : '暂无工具/思考细节（目标调度中，等待 worker 派发）'}
                                </Typography.Text>
                              ) : (
                                <Timeline
                                  items={details.map((d) => ({
                                    key: d.uid,
                                    color: traceColor(d.kind, d.level),
                                    children: (
                                      <Space direction="vertical" size={0}>
                                        <Space size={6}>
                                          <Typography.Text style={{ fontSize: 12 }}>{mask(d.text)}</Typography.Text>
                                          {isLlmErrorEvent({ ...d.payload, kind: d.kind, ts: d.ts }) ? (
                                            <Tooltip title="复制 LLM 真实错误">
                                              <Button
                                                size="small"
                                                type="link"
                                                style={{ padding: 0, height: 18, fontSize: 11 }}
                                                onClick={() =>
                                                  void copyLlmEvent({ ...d.payload, kind: d.kind, ts: d.ts })
                                                }
                                              >
                                                复制
                                              </Button>
                                            </Tooltip>
                                          ) : null}
                                        </Space>
                                        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                                          {d.kind}
                                          {d.round ? ` · R${d.round}` : ''} · {evTime(d.ts)}
                                        </Typography.Text>
                                      </Space>
                                    )
                                  }))}
                                />
                              )}
                            </div>
                          ) : null}
                        </div>
                      )
                    })}
                  </Space>
                )}
              </Card>
            </Col>
          </Row>
        </Space>
      ) : null}

      {/* ---------------- 复审队列 ---------------- */}
      {activeTab === 'review' ? (
        <Card
          size="small"
          title={
            <Space size={8} wrap>
              <Typography.Text strong>复审队列</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                AI 采纳后等待人工裁决
              </Typography.Text>
              {queue.total ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  待复审 {queue.total} 条 · 导出全部，不受搜索框影响
                </Typography.Text>
              ) : null}
              <Button
                size="small"
                disabled={!queue.total || bulkWorking}
                onClick={() => void bulkCopyMd('review')}
              >
                复制全部 Markdown
              </Button>
              <Button
                size="small"
                disabled={!queue.total || bulkWorking}
                onClick={() => void bulkExportMd('review')}
              >
                导出 .md
              </Button>
              {!isEnterprise ? (
                <>
                  <Button
                    size="small"
                    disabled={!queue.total || bulkWorking}
                    onClick={() => void bulkCopyEdusrc('review')}
                  >
                    复制 EduSRC JSON
                  </Button>
                  <Button
                    size="small"
                    disabled={!queue.total || bulkWorking}
                    onClick={() => void bulkExportEdusrc('review')}
                  >
                    导出 reports.json
                  </Button>
                </>
              ) : null}
            </Space>
          }
        >
          {queue.loading && !queue.items.length ? (
            <Spin>
              <div style={{ height: 80 }} />
            </Spin>
          ) : !queue.items.length ? (
            <Empty description="没有待复审的漏洞（AI 采纳后会进这里）" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : !filteredQueue.length ? (
            <Empty description="没有匹配当前关键词的复审漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <>
              <List dataSource={filteredQueue} renderItem={(f) => renderFindingRow(f)} />
              {queue.hasMore ? (
                <Button block loading={queue.loading} onClick={() => loadReview(false)}>
                  加载更多复审漏洞
                </Button>
              ) : null}
            </>
          )}
        </Card>
      ) : null}

      {/* ---------------- 待提交 ---------------- */}
      {activeTab === 'submit' ? (
        <Card
          size="small"
          title={
            <Space size={8} wrap>
              <Typography.Text strong>待提交</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                人工通过后的 SRC 报告池
              </Typography.Text>
              <Checkbox
                checked={submittedFilter}
                onChange={(e) => {
                  setSubmittedFilter(e.target.checked)
                  submittedRef.current = e.target.checked
                  void loadSubmit(true)
                }}
              >
                只看已提交
              </Checkbox>
              {submitItems.items.length ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  已加载 {submitItems.items.length} 条{submitItems.hasMore ? '，还有更多' : ''}
                </Typography.Text>
              ) : null}
              <Button
                size="small"
                disabled={!submitItems.items.length || bulkWorking}
                onClick={() => void bulkCopyMd('submit')}
              >
                复制全部 Markdown
              </Button>
              <Button
                size="small"
                disabled={!submitItems.items.length || bulkWorking}
                onClick={() => void bulkExportMd('submit')}
              >
                导出 .md
              </Button>
              {!isEnterprise ? (
                <>
                  <Button
                    size="small"
                    disabled={!submitItems.items.length || bulkWorking}
                    onClick={() => void bulkCopyEdusrc('submit')}
                  >
                    复制 EduSRC JSON
                  </Button>
                  <Button
                    size="small"
                    disabled={!submitItems.items.length || bulkWorking}
                    onClick={() => void bulkExportEdusrc('submit')}
                  >
                    导出 reports.json
                  </Button>
                </>
              ) : null}
            </Space>
          }
        >
          {submitItems.loading && !submitItems.items.length ? (
            <Spin>
              <div style={{ height: 80 }} />
            </Spin>
          ) : !submitItems.items.length ? (
            <Empty description="还没有通过复审的漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : !filteredSubmit.length ? (
            <Empty description="没有匹配当前关键词的待提交漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <>
              <List
                dataSource={filteredSubmit}
                renderItem={(f) =>
                  renderFindingRow(
                    f,
                    f.review?.submitted ? <Tag color="green">已提交</Tag> : <Tag>待提交</Tag>
                  )
                }
              />
              {submitItems.hasMore ? (
                <Button block loading={submitItems.loading} onClick={() => loadSubmit(false)}>
                  加载更多待提交漏洞
                </Button>
              ) : null}
            </>
          )}
        </Card>
      ) : null}

      {/* ---------------- 深化中 ---------------- */}
      {activeTab === 'deepen' ? (
        <Card
          size="small"
          title={
            <Space size={8}>
              <Typography.Text strong>深化中</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                已打回 worker 重新入队深挖的漏洞
              </Typography.Text>
            </Space>
          }
        >
          {deepen.loading && !deepen.items.length ? (
            <Spin>
              <div style={{ height: 80 }} />
            </Spin>
          ) : !deepen.items.length ? (
            <Empty description="暂无深化中的漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : !filteredDeepen.length ? (
            <Empty description="没有匹配当前关键词的深化漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <>
              <List dataSource={filteredDeepen} renderItem={(f) => renderFindingRow(f)} />
              {deepen.hasMore ? (
                <Button block loading={deepen.loading} onClick={() => loadDeepen(false)}>
                  加载更多深化漏洞
                </Button>
              ) : null}
            </>
          )}
        </Card>
      ) : null}

      {/* ---------------- 通杀列 ---------------- */}
      {activeTab === 'killsweep' ? (
        <Card
          size="small"
          title={
            <Space size={8}>
              <Typography.Text strong>通杀列</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {autoKillsweep ? '复审通过后自动分析同款系统' : '已关闭自动通杀'}；失败可直接重启
              </Typography.Text>
            </Space>
          }
          extra={
            <Tooltip title={writable ? '关闭后，新的复审通过不再自动开通杀' : '只读不能改'}>
              <Checkbox
                checked={autoKillsweep}
                disabled={!writable || autoSaving}
                onChange={(e) => toggleAutoKillsweep(e.target.checked)}
              >
                复审通过后自动通杀
              </Checkbox>
            </Tooltip>
          }
        >
          {killsweeps.loading && !killsweeps.items.length ? (
            <Spin>
              <div style={{ height: 80 }} />
            </Spin>
          ) : !killsweeps.items.length ? (
            <Empty
              description={
                autoKillsweep
                  ? '还没有通杀记录。人工复审通过后会自动分析同款系统，失败也会留在这里。'
                  : '还没有通杀记录。本任务已关闭自动通杀，复审通过只进待提交。'
              }
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          ) : (
            <>{killsweeps.items.map((k) => renderKillsweep(k))}</>
          )}
        </Card>
      ) : null}

      {/* ---------------- 已驳回 ---------------- */}
      {activeTab === 'rejected' ? (
        <Card
          size="small"
          title={
            <Space size={8}>
              <Typography.Text strong>已驳回</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                沉淀不收口径，可恢复或继续深挖
              </Typography.Text>
            </Space>
          }
        >
          {rejected.loading && !rejected.items.length ? (
            <Spin>
              <div style={{ height: 80 }} />
            </Spin>
          ) : !rejected.items.length ? (
            <Empty
              description="还没有被驳回的漏洞（复审点「不通过」会进这里，可回看与恢复）"
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          ) : !filteredRejected.length ? (
            <Empty description="没有匹配当前关键词的驳回漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <List dataSource={filteredRejected} renderItem={(f) => renderFindingRow(f)} />
          )}
        </Card>
      ) : null}

      {/* ---------------- AI 未采纳 ---------------- */}
      {activeTab === 'archived' ? (
        <Card
          size="small"
          title={
            <Space direction="vertical" size={0}>
              <Typography.Text strong>AI 未采纳</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                AI 判为非漏洞或深挖未升级的洞，保留在此防误杀，可点开查看、必要时「恢复到复审」
              </Typography.Text>
              {archivedWriteCount ? (
                <Typography.Text style={{ fontSize: 12 }} type="danger">
                  有 {archivedWriteCount} 条写/删类已置顶，优先人工看，别让真洞埋在这里
                </Typography.Text>
              ) : null}
            </Space>
          }
        >
          {archived.loading && !archived.items.length ? (
            <Spin>
              <div style={{ height: 80 }} />
            </Spin>
          ) : !archived.items.length ? (
            <Empty
              description="暂无 AI 未采纳的漏洞（AI 审核判「非漏洞」或「深挖未升级」的洞会沉淀到这里，防止误杀）"
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          ) : !filteredArchived.length ? (
            <Empty description="没有匹配当前关键词的未采纳漏洞" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <>
              <List
                dataSource={filteredArchived}
                renderItem={(f) =>
                  renderFindingRow(
                    f,
                    writable ? (
                      <Button
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation()
                          void restoreArchivedItem(f.id)
                        }}
                      >
                        恢复到复审
                      </Button>
                    ) : (
                      <Typography.Text type="secondary">{f.review?.score ?? '-'}</Typography.Text>
                    )
                  )
                }
              />
              {archived.hasMore ? (
                <Button block loading={archived.loading} onClick={() => loadArchived(false)}>
                  加载更多未采纳漏洞
                </Button>
              ) : null}
            </>
          )}
        </Card>
      ) : null}

      {/* 报告抽屉 */}
      <ReportDrawer
        open={drawerOpen}
        findingId={drawerId}
        taskId={taskId}
        srcType={task.src_type}
        onClose={() => setDrawerOpen(false)}
        onChanged={() => {
          void refreshFromEvent('review_updated')
        }}
      />

      {/* 注入实时指令弹窗 */}
      <Modal
        open={directiveOpen}
        title={`注入实时指令${directiveTarget ? ` · ${mask(directiveTarget.host)}` : ''}`}
        okText={directiveSending ? '发送中…' : '注入指令'}
        okButtonProps={{ loading: directiveSending, disabled: !directiveText.trim() }}
        cancelText="取消"
        onOk={submitDirective}
        onCancel={() => {
          if (directiveSending) return
          setDirectiveOpen(false)
          setDirectiveTarget(null)
          setDirectiveText('')
        }}
      >
        <Space direction="vertical" size={6} style={{ width: '100%' }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            指令会在下一轮 LLM 调用前注入给该目标的 worker，越具体越有效。
          </Typography.Text>
          <Input.TextArea
            rows={4}
            value={directiveText}
            onChange={(e) => setDirectiveText(e.target.value)}
            placeholder="例如：优先验证 /api/user/list 的越权；不要再扫目录，直接打 IDOR"
          />
        </Space>
      </Modal>

      {/* Worker 执行轨迹抽屉 */}
      <Drawer
        open={traceOpen}
        placement="right"
        width={620}
        onClose={() => {
          setTraceOpen(false)
          setTraceTarget(null)
          setTraceRows([])
        }}
        title={
          <Space size={8} wrap>
            <Typography.Text strong>{mask(traceTarget?.host || '执行轨迹')}</Typography.Text>
            <Tag color={traceTagColor(traceTarget?.id || '')}>
              {traceTagText(traceTarget?.id || '')}
            </Tag>
          </Space>
        }
      >
        {writable ? (
          <Card size="small" style={{ marginBottom: 12 }}>
            <Space direction="vertical" size={6} style={{ width: '100%' }}>
              <Typography.Text style={{ fontSize: 12 }}>人工实时指令（下一轮 LLM 前注入）</Typography.Text>
              <Input.TextArea
                rows={3}
                value={traceDirective}
                onChange={(e) => setTraceDirective(e.target.value)}
                placeholder="例如：优先验证 /api/user/list 的越权；不要再扫目录，直接打 IDOR"
              />
              <Button
                type="primary"
                loading={traceDirectiveSending}
                disabled={!traceDirective.trim()}
                onClick={sendTraceDirective}
              >
                注入指令
              </Button>
            </Space>
          </Card>
        ) : null}

        {traceLoading && !traceRows.length ? (
          <Spin>
            <div style={{ height: 120 }} />
          </Spin>
        ) : !traceRows.length ? (
          <Empty
            description={
              targetIsLive(traceTarget?.id || '')
                ? '暂无轨迹（worker 运行中，产生工具调用后自动刷新）'
                : targetIsClosed(traceTarget?.id || '')
                  ? '该 worker 已结束，工具/思考明细已归档清理（仅保留关键节点）'
                  : '暂无轨迹（目标调度中，等待 worker 派发后自动出现）'
            }
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          />
        ) : (
          <Timeline
            items={traceRows.map((r) => ({
              key: r.uid,
              color: traceColor(r.kind, r.level),
              children: (
                <Space direction="vertical" size={0} style={{ width: '100%' }}>
                  <Typography.Text style={{ fontSize: 12 }}>{mask(r.text)}</Typography.Text>
                  <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                    {r.kind}
                    {r.round ? ` · R${r.round}` : ''} · {evTime(r.ts)}
                  </Typography.Text>
                </Space>
              )
            }))}
          />
        )}
      </Drawer>
    </section>
  )
}
