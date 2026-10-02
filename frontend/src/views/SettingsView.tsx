/**
 * 系统设置页（对标 AutoHunter Vue 版 src/views/SettingsView.vue）。
 *
 * 分区（Ant Design Tabs，左侧纵向）：
 *   界面     —— 主题 / 壁纸（上传、链接、删除、查询）
 *   模型     —— LLM 单端点 / 端点池、模型探测、连通性测试、端点健康
 *   资产测绘 —— 默认引擎、分页、搜集方式、各引擎 API Key
 *   默认参数 —— 并发 / 深挖 / 分页 / 跳过阈值 / 各种开关
 *   代理池   —— ProxyPoolEditor（自包含）
 *   数据     —— 工作目录统计与清理、备份导出 / 快照 / 恢复
 *   更新     —— 检查更新与一键热更
 *
 * 与后端约定：
 *   响应体统一 { code, msg, data }，request 层已解包，业务代码直接拿到 data。
 *   字段一律 snake_case；密钥回显为脱敏串（8 个圆点），PUT 时未改动的密钥会
 *   被省略（不对后端提交占位符 / 空串），后端按「未修改」处理。
 *   保存统一走 userApi.updateSettings(payload)，payload 只提交被改动的段；
 *   模型 / 测绘 / 默认参数约 1 秒防抖自动保存，外观与其余分区即时落库。
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Alert,
  App,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Input,
  InputNumber,
  Segmented,
  Select,
  Slider,
  Space,
  Switch,
  Tabs,
  Tag,
  Tooltip,
  Typography
} from 'antd'
import {
  DeleteOutlined,
  DownloadOutlined,
  ExperimentOutlined,
  ReloadOutlined,
  SaveOutlined,
  ThunderboltOutlined,
  UndoOutlined,
  UploadOutlined,
  WalletOutlined
} from '@ant-design/icons'
import { systemApi, userApi } from '@/api'
import { useAuthStore, useUIStore } from '@/store'
import {
  ACCENT_PRESETS,
  UI_DEFAULTS,
  clampDim,
  clampHue,
  hexToHue,
  hueToHex,
  prefsFromApi,
  prefsToApi
} from '@/utils/uiTheme'
import { fmtBytes, fmtLocalTime, fmtRelativeTime } from '@/utils/format'
import LlmModelPicker from '@/components/LlmModelPicker'
import LlmPoolEditor, { MASKED_KEY, type LlmProviderRow } from '@/components/LlmPoolEditor'
import ProxyPoolEditor from '@/components/ProxyPoolEditor'
import { SecretPassword } from '@/components/PasswordEye'
import type { BackupStatus, HealthSnapshot, LlmBalanceInfo, WorkdirStats } from '@/types'

// ---------------------------------------------------------------- 常量与类型

/** 密钥脱敏占位符（8 个圆点）。 */
const MASKED_PLACEHOLDER = MASKED_KEY

/** 协议选项。 */
const PROTOCOL_OPTIONS = [
  { value: 'auto', label: '自动判断' },
  { value: 'openai_chat', label: 'OpenAI Chat' },
  { value: 'anthropic_messages', label: 'Anthropic Messages' }
]

/** 搜集方式选项。 */
const INTENT_OPTIONS = [
  { value: '', label: '自动判断' },
  { value: 'syntax', label: '查询语法（当前引擎官网语法）' },
  { value: 'intent', label: '自然语言意图' }
]

/** 页签定义。 */
const TABS = [
  { id: 'appearance', label: '外观', hint: '颜色与背景' },
  { id: 'llm', label: '模型', hint: 'LLM 通道' },
  { id: 'recon', label: '资产测绘', hint: '引擎与 Key' },
  { id: 'runtime', label: '默认参数', hint: '并发与深挖' },
  { id: 'ai', label: 'AI 增强', hint: '人格·Skill·知识库·Kali' },
  { id: 'proxy', label: '代理池', hint: '出网换 IP' },
  { id: 'data', label: '数据与备份', hint: '磁盘与快照' },
  { id: 'update', label: '更新', hint: '版本检查' }
]

/** LLM 调用模式。 */
type LlmMode = 'single' | 'pool'

/** 自动保存状态。 */
type AutoStatus = 'idle' | 'pending' | 'saving' | 'saved' | 'error' | 'incomplete'

/** 引擎元信息。 */
interface EngineMeta {
  name: string
  display_name?: string
}

/** 引擎编辑行（端点已固定为官方默认，不再可编辑）。 */
interface EngineRow {
  display_name: string
  key: string
  key_set: boolean
}

/** 设置表单。 */
interface SettingsForm {
  base_url: string
  api_key: string
  key_ref: string
  api_key_set: boolean
  model: string
  protocol: string
  temperature: number
  providers: LlmProviderRow[]
  max_pages: number
  page_size: number
  default_intent_mode: string
  default_engine: string
  engines: Record<string, EngineRow>
  available_engines: EngineMeta[]
  concurrency: number
  deepen_cap: number
  skip_score_threshold: number
  worker_prompt_version: string
  auto_killsweep: boolean
  shell_enabled: boolean
  verbose_events: boolean
  ui_theme: string
  ui_accent_hue: number
  ui_wallpaper_kind: string
  ui_wallpaper_url: string
  ui_wallpaper_fit: string
  ui_wallpaper_dim: number
  persona_enabled: boolean
  persona_name: string
  persona_style: string
  persona_principles: string
  skills_enabled: boolean
  skill_items: SkillRow[]
  ima_enabled: boolean
  ima_base_url: string
  ima_api_key: string
  ima_api_key_set: boolean
  ima_repo_id: string
  ima_top_k: number
  kali_enabled: boolean
  kali_host: string
  kali_port: number
  kali_username: string
  kali_auth_type: string
  kali_password: string
  kali_password_set: boolean
  kali_private_key: string
  kali_private_key_set: boolean
  kali_categories: string[]
  all_kali_categories: KaliCategoryMeta[]
}

/** 单条技能（可复用的领域知识包）。 */
interface SkillRow {
  id: string
  name: string
  content: string
  enabled: boolean
}

/** Kali 工具分类元信息。 */
interface KaliCategoryMeta {
  key: string
  label: string
  desc: string
}

/** 后端设置视图的原始形状（@/types 的视图类型为简化版，这里对齐真实契约）。 */
interface RawLlmView {
  mode?: string
  base_url?: string
  api_key?: string
  api_key_set?: boolean
  api_key_masked?: string
  key_ref?: string
  model?: string
  protocol?: string
  temperature?: number
  providers?: LlmProviderRow[]
}
interface RawFofaView {
  key?: string
  key_set?: boolean
  max_pages?: number
  page_size?: number
  default_intent_mode?: string
}
interface RawEngineView {
  display_name?: string
  key?: string
  key_set?: boolean
  enabled?: boolean
}
interface RawDefaultsView {
  concurrency?: number
  deepen_cap?: number
  skip_score_threshold?: number
  worker_prompt_version?: string
  engine?: string
  // 后端为 *bool：null/缺省 = 未配置（auto_killsweep 语义开，shell/verbose 语义关）
  auto_killsweep?: boolean | null
  shell_enabled?: boolean | null
  verbose_events?: boolean | null
}
/**
 * 服务端返回的 ui 偏好。
 * ⚠️ 后端 `model.UISettings` 的 json tag 是 **camelCase**，不是 snake_case——
 * 早前这里按 snake_case 读，导致读回永远是 undefined（壁纸一刷新就丢）、
 * 提交时也被 encoding/json 静默丢弃（PUT 返回 200 且 saved:true，但一个字段都没存）。
 */
interface RawUiView {
  theme?: string
  accentHue?: number
  wallpaperKind?: string
  wallpaperUrl?: string
  wallpaperFit?: string
  wallpaperDim?: number
}
interface RawSettingsView {
  updated_at?: string
  llm?: RawLlmView
  fofa?: RawFofaView
  engines?: Record<string, RawEngineView>
  defaults?: RawDefaultsView
  ui?: RawUiView
  persona?: RawPersonaView
  skills?: RawSkillsView
  ima?: RawImaView
  kali?: RawKaliView
  available_engines?: EngineMeta[]
}

interface RawPersonaView {
  enabled?: boolean
  name?: string
  style?: string
  principles?: string
}
interface RawSkillsView {
  enabled?: boolean
  items?: SkillRow[]
}
interface RawImaView {
  enabled?: boolean
  base_url?: string
  api_key?: string
  api_key_set?: boolean
  repo_id?: string
  top_k?: number
}
interface RawKaliView {
  enabled?: boolean
  host?: string
  port?: number
  username?: string
  auth_type?: string
  password?: string
  password_set?: boolean
  private_key?: string
  private_key_set?: boolean
  categories?: string[]
  all_categories?: KaliCategoryMeta[]
}

/** 连通性测试单条结果。 */
interface LlmTestItem {
  name?: string
  base_url?: string
  model?: string
  protocol?: string
  ok?: boolean
  latency_ms?: number
  status_code?: number
  reply?: string
  error?: string
  error_copy?: string
  tool_calling?: string
}
/** 连通性测试结果。 */
interface LlmTestResult {
  ok?: boolean
  results?: LlmTestItem[]
  error?: string
  error_copy?: string
}

/** 工作目录统计（补齐后端 human 可读字段）。 */
interface WorkdirStatsExt {
  root?: string
  work_root?: string
  total_bytes?: number
  total_size_human?: string
  total_dirs?: number
  total_files?: number
  auto_cleanup_enabled?: boolean
  retention_days?: number
  oldest_dir?: { name?: string; age_days?: number } | null
}
/** 工作目录清理结果。 */
interface WorkdirCleanupResult {
  scanned_dirs?: number
  deleted_dirs?: number
  failed_dirs?: number
  freed_human?: string
  deleted?: Array<{ name?: string; age_days?: number; size_human?: string }>
  failed?: Array<{ name?: string; error?: string }>
}
/** 备份状态（补齐后端 human 可读字段）。 */
interface BackupStatusExt {
  backup_dir?: string
  db_human?: string
  disk?: { free_human?: string; total_human?: string }
  snapshots_human?: string
  snapshots?: Array<{ name: string; human?: string; bytes?: number; created_at?: string }>
  auto_backup?: { enabled?: boolean; interval_hours?: number } | boolean
  work?: { human?: string; max_human?: string }
  last_backup_at?: string | null
}
/** 更新检查结果（补齐 commit 维度字段）。 */
interface UpdateInfoExt {
  enabled?: boolean
  current_version?: string
  latest_version?: string
  has_update?: boolean
  update_available?: boolean
  branch?: string
  release_url?: string
  releases_url?: string
  changelog?: string
  current_commit?: string
  latest_commit?: string
  commits_behind?: number
  latest_message?: string
  changed_files?: string[]
  hot_updateable?: boolean
  rebuild_command?: string
  error?: string
  hint?: string
}

// ---------------------------------------------------------------- 纯函数工具

/** 错误文案（去掉后端拼接的状态码前缀）。 */
function errText(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e)
  return msg.replace(/^\d+\s*/, '')
}

/** 协议收敛到合法值。 */
function normalizeProtocol(protocol?: string): string {
  return protocol === 'openai_chat' || protocol === 'anthropic_messages' || protocol === 'auto'
    ? protocol
    : 'auto'
}

/** 是否是一个「新的真实密钥」（脱敏占位符 / 空串都不算）。 */
function isNewSecret(value?: string): boolean {
  const v = String(value || '').trim()
  return v.length >= 8 && v !== MASKED_PLACEHOLDER
}

/** 新密钥或 undefined（用于探测 / 测试请求体）。 */
function newSecretOrUndefined(value?: string): string | undefined {
  const v = String(value || '').trim()
  return isNewSecret(v) ? v : undefined
}

let providerUidSeq = 1
function nextProviderUid(): string {
  return `srv-uid-${providerUidSeq++}`
}

/** 规范化一条端点行。 */
function normalizeProvider(raw: Partial<LlmProviderRow>, index: number, temperature = 0.3): LlmProviderRow {
  const apiKeySet = !!raw.api_key_set
  return {
    uid: raw.uid || nextProviderUid(),
    name: raw.name || `llm-${index + 1}`,
    base_url: raw.base_url || '',
    api_key: raw.api_key || (apiKeySet ? MASKED_PLACEHOLDER : ''),
    api_key_set: apiKeySet,
    api_key_masked: raw.api_key_masked || '',
    key_ref: raw.key_ref || '',
    health_ref: raw.health_ref || '',
    model: raw.model || '',
    protocol: normalizeProtocol(raw.protocol),
    temperature: raw.temperature ?? temperature,
    weight: raw.weight ?? 1,
    enabled: raw.enabled !== false,
    models: Array.isArray(raw.models) ? raw.models : [],
    modelsLoading: !!raw.modelsLoading,
    modelsError: raw.modelsError || ''
  }
}

/** 端点提交体（未改动的新密钥省略，交给后端按 key_ref 保留原值）。 */
function buildProviderPayload(row: LlmProviderRow): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    name: String(row.name || '').trim(),
    base_url: String(row.base_url || '').trim(),
    model: String(row.model || '').trim(),
    protocol: normalizeProtocol(row.protocol),
    temperature: Number(row.temperature ?? 0.3),
    weight: Math.max(1, Math.min(100, Number(row.weight || 1))),
    enabled: row.enabled !== false,
    key_ref: row.key_ref || ''
  }
  if (isNewSecret(row.api_key)) payload.api_key = row.api_key.trim()
  return payload
}

/** 单端点是否已具备可用密钥。 */
function hasSingleKey(form: SettingsForm): boolean {
  return (
    isNewSecret(form.api_key) ||
    form.api_key === MASKED_PLACEHOLDER ||
    form.api_key_set ||
    !!form.key_ref
  )
}

/** 端点行是否已具备可用密钥。 */
function hasProviderKey(row: LlmProviderRow): boolean {
  return (
    isNewSecret(row.api_key) ||
    row.api_key === MASKED_PLACEHOLDER ||
    !!row.api_key_set ||
    !!row.key_ref
  )
}

const SEG_KEYS = ['llm', 'fofa', 'engines', 'defaults', 'ui', 'persona', 'skills', 'ima', 'kali'] as const
type SegKey = (typeof SEG_KEYS)[number]

/** 组装分段提交体（每个段的键顺序固定，便于与基线做 JSON 比较）。 */
function buildSegments(form: SettingsForm, mode: LlmMode): Record<SegKey, Record<string, unknown>> {
  const llm: Record<string, unknown> = {
    mode,
    base_url: form.base_url,
    model: form.model,
    protocol: form.protocol,
    temperature: Number(form.temperature)
  }
  if (isNewSecret(form.api_key)) llm.api_key = form.api_key.trim()
  if (form.key_ref) llm.key_ref = form.key_ref
  if (mode === 'pool') llm.providers = form.providers.map(buildProviderPayload)

  const fofaEngine = form.engines.fofa
  const fofa: Record<string, unknown> = {
    max_pages: Number(form.max_pages),
    page_size: Number(form.page_size),
    default_intent_mode: form.default_intent_mode
  }
  if (fofaEngine && isNewSecret(fofaEngine.key)) fofa.key = fofaEngine.key.trim()

  const engines: Record<string, unknown> = {}
  for (const [name, engine] of Object.entries(form.engines)) {
    const patch: Record<string, unknown> = {}
    if (isNewSecret(engine.key)) patch.key = engine.key.trim()
    engines[name] = patch
  }

  const defaults: Record<string, unknown> = {
    concurrency: Number(form.concurrency),
    deepen_cap: Number(form.deepen_cap),
    // max_pages/page_size 属 fofa 段（原版语义），不在此处发送
    skip_score_threshold: Number(form.skip_score_threshold),
    worker_prompt_version: form.worker_prompt_version,
    engine: form.default_engine || 'fofa',
    auto_killsweep: form.auto_killsweep,
    shell_enabled: form.shell_enabled,
    verbose_events: form.verbose_events
  }

  // 走 prefsToApi 统一夹取并转成 camelCase（后端 model.UISettings 的 json tag）
  const ui = prefsToApi({
    theme: form.ui_theme,
    accentHue: form.ui_accent_hue,
    wallpaperKind: form.ui_wallpaper_kind,
    wallpaperUrl: form.ui_wallpaper_url,
    wallpaperFit: form.ui_wallpaper_fit,
    wallpaperDim: form.ui_wallpaper_dim
  })

  const persona: Record<string, unknown> = {
    enabled: form.persona_enabled,
    name: form.persona_name,
    style: form.persona_style,
    principles: form.persona_principles
  }

  const skills: Record<string, unknown> = {
    enabled: form.skills_enabled,
    items: form.skill_items.map((row) => ({
      id: row.id || undefined,
      name: row.name,
      content: row.content,
      enabled: row.enabled
    }))
  }

  const ima: Record<string, unknown> = {
    enabled: form.ima_enabled,
    base_url: form.ima_base_url,
    repo_id: form.ima_repo_id,
    top_k: Number(form.ima_top_k)
  }
  if (isNewSecret(form.ima_api_key)) ima.api_key = form.ima_api_key.trim()

  const kali: Record<string, unknown> = {
    enabled: form.kali_enabled,
    host: form.kali_host,
    port: Number(form.kali_port),
    username: form.kali_username,
    auth_type: form.kali_auth_type,
    categories: form.kali_categories
  }
  if (isNewSecret(form.kali_password)) kali.password = form.kali_password
  if (isNewSecret(form.kali_private_key)) kali.private_key = form.kali_private_key

  return { llm, fofa, engines, defaults, ui, persona, skills, ima, kali }
}

/** 每段转成字符串，作为「未改动」比较基线。 */
function stringifySegments(seg: Record<SegKey, Record<string, unknown>>): Record<SegKey, string> {
  const out: Record<string, string> = {}
  for (const key of SEG_KEYS) out[key] = JSON.stringify(seg[key])
  return out as Record<SegKey, string>
}

const EMPTY_BASELINE: Record<SegKey, string> = {
  llm: '', fofa: '', engines: '', defaults: '', ui: '',
  persona: '', skills: '', ima: '', kali: ''
}

/** 校验 LLM 配置是否完整。 */
function validateLlm(form: SettingsForm, mode: LlmMode): string | null {
  if (mode === 'single') {
    if (!form.base_url.trim() || !form.model.trim() || !hasSingleKey(form)) {
      return '单端点配置缺少 base_url、api_key 或模型'
    }
    return null
  }
  if (!form.providers.length) return '端点池至少需要一个端点'
  for (let i = 0; i < form.providers.length; i++) {
    const p = form.providers[i]
    if (!String(p.name || '').trim() || !String(p.base_url || '').trim() || !String(p.model || '').trim() || !hasProviderKey(p)) {
      return `LLM 端点 #${i + 1} 缺少名称、base_url、api_key 或模型`
    }
  }
  if (!form.providers.some((p) => p.enabled !== false)) {
    return '端点池至少需要启用一个端点'
  }
  return null
}

/** 把设置接口返回的 UI 片段读出来。 */
function readUiView(res: Record<string, unknown>): RawUiView | null {
  const ui = res?.ui
  if (ui && typeof ui === 'object') return ui as RawUiView
  if ('wallpaperKind' in res || 'theme' in res) return res as RawUiView
  return null
}

/** 健康列表归一（兼容数组、{ items: [...] }、{ providers: [...] } 三种形态——后端 ProviderHealth 返回 items）。 */
function normalizeHealthList(res: unknown): HealthSnapshot[] {
  if (Array.isArray(res)) return res as HealthSnapshot[]
  if (res && typeof res === 'object') {
    const obj = res as { items?: unknown; providers?: unknown }
    if (Array.isArray(obj.items)) return obj.items as HealthSnapshot[]
    if (Array.isArray(obj.providers)) return obj.providers as HealthSnapshot[]
  }
  return []
}

/** 测试单条结果的可读描述。 */
/**
 * 归一化连通性测试结果。
 *
 * 契约上后端会返回顶层 ok（原版 AutoHunter 亦然），但一旦缺失，
 * 所有读取 `llmTest.ok` 的位置都会把「测试通过」显示成「LLM 不可用」。
 * 这里在入口做一次兜底推导，保证标题、提示、错误块三者口径一致。
 */
function normalizeLlmTestResult(res: LlmTestResult): LlmTestResult {
  if (typeof res.ok === 'boolean') return res
  const results = res.results || []
  return { ...res, ok: results.length > 0 && results.every((item) => item.ok === true) }
}

function resultText(item: LlmTestItem): string {
  const parts: string[] = []
  if (item.protocol) parts.push(item.protocol)
  if (item.model) parts.push(item.model)
  if (item.latency_ms) parts.push(`${item.latency_ms}ms`)
  if (item.status_code) parts.push(`HTTP ${item.status_code}`)
  if (item.ok && item.reply) parts.push(`reply: ${item.reply}`)
  if (item.ok && item.tool_calling) {
    const map: Record<string, string> = {
      yes: '工具调用 ✓',
      no: '工具调用 ✗（不支持原生 function calling，系统会提示词模拟兜底）',
      unknown: '工具调用 ? 未检测到'
    }
    parts.push(map[item.tool_calling] || '')
  }
  if (!item.ok && item.error) parts.push(item.error)
  return parts.filter(Boolean).join(' · ')
}

/** 健康状态 → Tag 颜色。 */
function healthColor(status?: string): string {
  if (status === 'ok') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'cooldown') return 'warning'
  if (status === 'half_open') return 'processing'
  return 'default'
}

/** 健康状态 → 文案。 */
function healthText(status?: string): string {
  if (status === 'ok') return '健康'
  if (status === 'failed') return '失效'
  if (status === 'cooldown') return '冷却中'
  if (status === 'half_open') return '探测中'
  return '未检测'
}

/** 备份自动开关文案。 */
function autoBackupText(value: BackupStatusExt['auto_backup']): { on: boolean; text: string } {
  if (value && typeof value === 'object') {
    return { on: !!value.enabled, text: value.enabled ? `每 ${value.interval_hours ?? '?'} 小时` : '已关闭' }
  }
  if (typeof value === 'boolean') return { on: value, text: value ? '已开启' : '已关闭' }
  return { on: false, text: '未知' }
}

// ---------------------------------------------------------------- 组件

/** 系统设置页。 */
export default function SettingsView() {
  const { message, modal } = App.useApp()
  const role = useAuthStore((s) => s.role)
  const canWrite = role === 'full'
  const setAppearance = useUIStore((s) => s.setAppearance)

  const [searchParams, setSearchParams] = useSearchParams()
  const [tab, setTab] = useState<string>(() => {
    const t = searchParams.get('tab')
    return t && TABS.some((x) => x.id === t) ? t : 'appearance'
  })

  // ---- 基础状态
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [llmMode, setLlmMode] = useState<LlmMode>('single')
  const [form, setForm] = useState<SettingsForm>(() => emptyForm())
  const [metaUpdatedAt, setMetaUpdatedAt] = useState('')
  const [autoStatus, setAutoStatus] = useState<AutoStatus>('idle')
  const [autoError, setAutoError] = useState('')

  // ---- 模型
  const [singleModels, setSingleModels] = useState<string[]>([])
  const [singleModelsLoading, setSingleModelsLoading] = useState(false)
  const [singleModelsError, setSingleModelsError] = useState('')
  const [testingLlm, setTestingLlm] = useState(false)
  const [balanceLoading, setBalanceLoading] = useState(false)
  const [balanceInfo, setBalanceInfo] = useState<LlmBalanceInfo | null>(null)
  const [testingProvider, setTestingProvider] = useState(-1)
  const [kaliTesting, setKaliTesting] = useState(false)
  const [kaliTestResult, setKaliTestResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [llmTest, setLlmTest] = useState<LlmTestResult | null>(null)
  const [health, setHealth] = useState<HealthSnapshot[]>([])
  const [healthLoading, setHealthLoading] = useState(false)

  // ---- 数据与备份
  const [workdir, setWorkdir] = useState<WorkdirStatsExt | null>(null)
  const [workdirLoading, setWorkdirLoading] = useState(false)
  const [cleanupDays, setCleanupDays] = useState(7)
  const [cleaning, setCleaning] = useState(false)
  const [cleanupResult, setCleanupResult] = useState<WorkdirCleanupResult | null>(null)
  const [backup, setBackup] = useState<BackupStatusExt | null>(null)
  const [backupLoading, setBackupLoading] = useState(false)
  const [backupBusy, setBackupBusy] = useState('')
  const [backupIncludeWork, setBackupIncludeWork] = useState(false)
  const [restoreIncludeWork, setRestoreIncludeWork] = useState(false)
  const [restoreFile, setRestoreFile] = useState<File | null>(null)
  const [restarting, setRestarting] = useState<'' | 'update' | 'backup'>('')

  // ---- 更新
  const [updateChecking, setUpdateChecking] = useState(false)
  const [updateInfo, setUpdateInfo] = useState<UpdateInfoExt | null>(null)
  const [updateError, setUpdateError] = useState('')
  const [updateRunning, setUpdateRunning] = useState(false)
  const [updateSupported, setUpdateSupported] = useState(true)

  // ---- 外观
  const [wallpaperBusy, setWallpaperBusy] = useState(false)
  const [wallpaperError, setWallpaperError] = useState('')
  const [wallpaperInfo, setWallpaperInfo] = useState<{ kind?: string; url?: string; exists?: boolean } | null>(null)

  // ---- refs
  const suppress = useRef(false)
  const savingRef = useRef(false)
  const pendingRef = useRef(false)
  const baselineRef = useRef<Record<SegKey, string>>({ ...EMPTY_BASELINE })
  const pollRef = useRef<number | null>(null)
  const restoreFileRef = useRef<HTMLInputElement | null>(null)
  const wallpaperInputRef = useRef<HTMLInputElement | null>(null)

  /** 局部补丁。 */
  function patch(p: Partial<SettingsForm>) {
    setForm((prev) => ({ ...prev, ...p }))
  }

  /**
   * 改外观：立即生效 + 写回表单（再由自动保存落库）。
   *
   * 主题色 / 铺满方式 / 背景明暗都是"所见即所得"的偏好，等 1.2 秒防抖再变会显得迟钝，
   * 所以这里先经 setAppearance 打到 <html> 的 CSS 变量上，再交给自动保存持久化。
   */
  function applyUi(next: Partial<SettingsForm>) {
    const merged = { ...form, ...next }
    patch(next)
    setAppearance(
      prefsFromApi({
        theme: merged.ui_theme,
        accentHue: merged.ui_accent_hue,
        wallpaperKind: merged.ui_wallpaper_kind,
        wallpaperUrl: merged.ui_wallpaper_url,
        wallpaperFit: merged.ui_wallpaper_fit,
        wallpaperDim: merged.ui_wallpaper_dim
      })
    )
  }

  /** 恢复默认外观：删掉服务端壁纸 + 色相/铺满/明暗回默认（对齐原版 resetAppearance）。 */
  async function resetAppearance() {
    setWallpaperError('')
    try {
      await userApi.deleteWallpaper()
    } catch {
      /* 没有壁纸时删除会报错，忽略即可 */
    }
    applyUi({
      ui_theme: UI_DEFAULTS.theme,
      ui_accent_hue: UI_DEFAULTS.accentHue,
      ui_wallpaper_kind: UI_DEFAULTS.wallpaperKind,
      ui_wallpaper_url: UI_DEFAULTS.wallpaperUrl,
      ui_wallpaper_fit: UI_DEFAULTS.wallpaperFit,
      ui_wallpaper_dim: UI_DEFAULTS.wallpaperDim
    })
    message.success('已恢复默认外观')
  }

  /** 引擎行补丁。 */
  function patchEngine(name: string, p: Partial<EngineRow>) {
    setForm((prev) => ({
      ...prev,
      engines: { ...prev.engines, [name]: { ...prev.engines[name], ...p } }
    }))
  }

  // ------------------------------------------------------------ 载入

  async function load() {
    setLoading(true)
    suppress.current = true
    try {
      const s = (await userApi.getSettings()) as unknown as RawSettingsView
      const llm = s.llm || {}
      const fofa = s.fofa || {}
      const def = s.defaults || {}
      const ui = s.ui || {}
      const engView = s.engines || {}
      const available = Array.isArray(s.available_engines) ? s.available_engines : []
      const personaView = s.persona || {}
      const skillsView = s.skills || {}
      const imaView = s.ima || {}
      const kaliView = s.kali || {}

      const engines: Record<string, EngineRow> = {}
      if (available.length) {
        for (const meta of available) {
          if (!meta?.name) continue
          const cur = engView[meta.name] || {}
          engines[meta.name] = {
            display_name: meta.display_name || cur.display_name || meta.name,
            key: '',
            key_set: !!cur.key_set
          }
        }
      } else {
        for (const [name, cur] of Object.entries(engView)) {
          engines[name] = {
            display_name: cur.display_name || name,
            key: '',
            key_set: !!cur.key_set
          }
        }
      }
      if (engines.fofa) {
        if (!engines.fofa.key_set && fofa.key_set) engines.fofa.key_set = true
      }

      const mode: LlmMode = llm.mode === 'pool' ? 'pool' : 'single'
      const providers: LlmProviderRow[] = (llm.providers || []).map((p, idx) =>
        normalizeProvider(p, idx, Number(llm.temperature ?? 0.3))
      )

      const nextForm: SettingsForm = {
        base_url: llm.base_url || '',
        api_key: '',
        key_ref: llm.key_ref || '',
        api_key_set: !!llm.api_key_set,
        model: llm.model || '',
        protocol: normalizeProtocol(llm.protocol),
        temperature: Number(llm.temperature ?? 0.3),
        providers,
        max_pages: Number(fofa.max_pages ?? 20),
        page_size: Number(fofa.page_size ?? 100),
        default_intent_mode: fofa.default_intent_mode || '',
        default_engine: def.engine || 'fofa',
        engines,
        available_engines: available,
        concurrency: Number(def.concurrency ?? 3),
        deepen_cap: Number(def.deepen_cap ?? 2),
        // 「默认最大页数/每页条数」与 FOFA 页签同源（原版就在 fofa 段，defaults 段没有这对键）
        skip_score_threshold: Number(def.skip_score_threshold ?? -10),
        worker_prompt_version: def.worker_prompt_version || 'legacy',
        auto_killsweep: def.auto_killsweep !== false,
        shell_enabled: def.shell_enabled === true,
        verbose_events: def.verbose_events === true,
        ui_theme: ui.theme || UI_DEFAULTS.theme,
        ui_accent_hue: clampHue(ui.accentHue ?? UI_DEFAULTS.accentHue),
        ui_wallpaper_kind: ui.wallpaperKind || UI_DEFAULTS.wallpaperKind,
        ui_wallpaper_url: ui.wallpaperUrl || '',
        ui_wallpaper_fit: ui.wallpaperFit === 'contain' ? 'contain' : UI_DEFAULTS.wallpaperFit,
        ui_wallpaper_dim: clampDim(ui.wallpaperDim ?? UI_DEFAULTS.wallpaperDim),
        persona_enabled: personaView.enabled === true,
        persona_name: personaView.name || '',
        persona_style: personaView.style || '',
        persona_principles: personaView.principles || '',
        skills_enabled: skillsView.enabled === true,
        skill_items: (skillsView.items || []).map((row) => ({
          id: row.id || '',
          name: row.name || '',
          content: row.content || '',
          enabled: row.enabled !== false
        })),
        ima_enabled: imaView.enabled === true,
        ima_base_url: imaView.base_url || '',
        ima_api_key: '',
        ima_api_key_set: !!imaView.api_key_set,
        ima_repo_id: imaView.repo_id || '',
        ima_top_k: Number(imaView.top_k ?? 5),
        kali_enabled: kaliView.enabled === true,
        kali_host: kaliView.host || '',
        kali_port: Number(kaliView.port ?? 22),
        kali_username: kaliView.username || 'root',
        kali_auth_type: kaliView.auth_type || 'password',
        kali_password: '',
        kali_password_set: !!kaliView.password_set,
        kali_private_key: '',
        kali_private_key_set: !!kaliView.private_key_set,
        kali_categories: Array.isArray(kaliView.categories) ? kaliView.categories : [],
        all_kali_categories: Array.isArray(kaliView.all_categories) ? kaliView.all_categories : []
      }

      setForm(nextForm)
      setLlmMode(mode)
      setMetaUpdatedAt(s.updated_at || '')
      baselineRef.current = stringifySegments(buildSegments(nextForm, mode))
      setAutoStatus('idle')
      setAutoError('')
      // 同步全局外观（主题色 / 铺满方式 / 明暗 / 壁纸）
      setAppearance(
        prefsFromApi({
          theme: nextForm.ui_theme,
          accentHue: nextForm.ui_accent_hue,
          wallpaperKind: nextForm.ui_wallpaper_kind,
          wallpaperUrl: nextForm.ui_wallpaper_url,
          wallpaperFit: nextForm.ui_wallpaper_fit,
          wallpaperDim: nextForm.ui_wallpaper_dim
        })
      )
    } catch (e) {
      message.error(errText(e))
    } finally {
      setLoading(false)
    }
  }

  /** 壁纸预览地址。 */
  function wallpaperSrc(kind: string, url: string): string {
    if (kind === 'file') return '/api/settings/ui/wallpaper'
    if (kind === 'url') return url
    return ''
  }

  // ------------------------------------------------------------ 保存

  function scheduleStatusLabel(): string {
    if (autoStatus === 'pending') return '将自动保存…'
    if (autoStatus === 'saving') return '自动保存中…'
    if (autoStatus === 'saved') {
      const t = metaUpdatedAt ? fmtLocalTime(metaUpdatedAt).slice(11) : ''
      return t ? `已自动保存 ${t}` : '已自动保存'
    }
    if (autoStatus === 'incomplete') return autoError || '完善配置后将自动保存'
    if (autoStatus === 'error') return autoError || '自动保存失败'
    return '改动后约 1 秒自动保存'
  }

  async function doSave(silent: boolean) {
    if (savingRef.current) {
      pendingRef.current = true
      return
    }
    const invalid = validateLlm(form, llmMode)
    if (invalid) {
      setAutoStatus('incomplete')
      setAutoError(invalid)
      if (!silent) message.error(invalid)
      return
    }
    const seg = buildSegments(form, llmMode)
    const changed: Record<string, unknown> = {}
    for (const key of SEG_KEYS) {
      if (JSON.stringify(seg[key]) !== baselineRef.current[key]) changed[key] = seg[key]
    }
    if (!Object.keys(changed).length) {
      setAutoStatus('saved')
      return
    }

    savingRef.current = true
    setSaving(true)
    setAutoStatus('saving')
    setAutoError('')
    try {
      const res = (await userApi.updateSettings(changed)) as unknown as RawSettingsView
      const updated = mergeServer(form, res, llmMode)
      suppress.current = true
      setForm(updated)
      if (res.updated_at) setMetaUpdatedAt(res.updated_at)
      baselineRef.current = stringifySegments(buildSegments(updated, llmMode))
      setAutoStatus('saved')
      if (!silent) message.success('系统配置已保存')
    } catch (e) {
      const msg = errText(e)
      setAutoStatus('error')
      setAutoError(msg)
      message.error(msg)
    } finally {
      setSaving(false)
      savingRef.current = false
      if (pendingRef.current) {
        pendingRef.current = false
        window.setTimeout(() => void doSave(true), 0)
      }
    }
  }

  /** 保存成功后就地合并服务端回写（禁止整表替换，避免选中端点跳回第 1 个）。 */
  function mergeServer(current: SettingsForm, s: RawSettingsView, mode: LlmMode): SettingsForm {
    const llm = s.llm || {}
    const updated: SettingsForm = { ...current }
    updated.api_key = ''
    updated.api_key_set = !!llm.api_key_set
    updated.key_ref = llm.key_ref || current.key_ref
    if (llm.protocol) updated.protocol = normalizeProtocol(llm.protocol)

    const engView = s.engines || {}
    const engines: Record<string, EngineRow> = { ...current.engines }
    for (const name of Object.keys(engines)) {
      const cur = engView[name] || {}
      engines[name] = {
        ...engines[name],
        key: '',
        key_set: !!cur.key_set || (name === 'fofa' && !!s.fofa?.key_set)
      }
      if (cur.display_name) engines[name].display_name = cur.display_name
    }
    updated.engines = engines
    if (s.defaults?.engine) updated.default_engine = s.defaults.engine

    // persona/skills/ima/kali：明文字段就地取服务端回写；密钥字段回占位符语义。
    const persona = s.persona || {}
    updated.persona_enabled = persona.enabled === true
    updated.persona_name = persona.name ?? current.persona_name
    updated.persona_style = persona.style ?? current.persona_style
    updated.persona_principles = persona.principles ?? current.persona_principles
    const skills = s.skills || {}
    updated.skills_enabled = skills.enabled === true
    updated.skill_items = Array.isArray(skills.items) ? skills.items : current.skill_items
    const ima = s.ima || {}
    updated.ima_enabled = ima.enabled === true
    updated.ima_base_url = ima.base_url ?? current.ima_base_url
    updated.ima_api_key = ''
    updated.ima_api_key_set = !!ima.api_key_set
    updated.ima_repo_id = ima.repo_id ?? current.ima_repo_id
    updated.ima_top_k = Number(ima.top_k ?? current.ima_top_k)
    const kali = s.kali || {}
    updated.kali_enabled = kali.enabled === true
    updated.kali_host = kali.host ?? current.kali_host
    updated.kali_port = Number(kali.port ?? current.kali_port)
    updated.kali_username = kali.username ?? current.kali_username
    updated.kali_auth_type = kali.auth_type ?? current.kali_auth_type
    updated.kali_password = ''
    updated.kali_password_set = !!kali.password_set
    updated.kali_private_key = ''
    updated.kali_private_key_set = !!kali.private_key_set
    updated.kali_categories = Array.isArray(kali.categories) ? kali.categories : current.kali_categories

    if (mode === 'pool') {
      const saved = Array.isArray(llm.providers) ? llm.providers : []
      updated.providers = current.providers.map((row, i) => {
        const remote = saved[i]
        const base: LlmProviderRow = {
          ...row,
          // 已提交的新密钥落库后改回脱敏占位符，保持「未改动」语义。
          api_key: row.api_key_set || isNewSecret(row.api_key) ? MASKED_PLACEHOLDER : '',
          api_key_set: true
        }
        if (!remote) {
          base.api_key_set = !!row.api_key_set || isNewSecret(row.api_key)
          return base
        }
        return {
          ...base,
          api_key_set: !!remote.api_key_set,
          api_key: remote.api_key_set ? MASKED_PLACEHOLDER : base.api_key,
          api_key_masked: remote.api_key_masked || row.api_key_masked,
          key_ref: remote.key_ref || row.key_ref,
          health_ref: remote.health_ref || row.health_ref
        }
      })
    }
    return updated
  }

  // ---- 自动保存：form / 模式变化后约 1 秒防抖落库（仅提交被改动的段）
  useEffect(() => {
    if (loading) return
    if (suppress.current) return
    setAutoStatus('pending')
    setAutoError('')
    const timer = window.setTimeout(() => void doSave(true), 1200)
    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form, llmMode, loading])

  // ---- 载入 / 保存回写引起的 form 变更：只跳过这一轮自动保存（须声明在自动保存 effect 之后）
  useEffect(() => {
    suppress.current = false
  }, [form, llmMode])

  // ------------------------------------------------------------ 模型相关

  async function refreshProviderHealth() {
    setHealthLoading(true)
    try {
      setHealth(normalizeHealthList(await userApi.providerHealth()))
    } catch {
      /* 健康探针失败不阻断 */
    } finally {
      setHealthLoading(false)
    }
  }

  async function loadSingleModels() {
    setSingleModelsLoading(true)
    setSingleModelsError('')
    try {
      const payload: Record<string, unknown> = {
        base_url: form.base_url,
        protocol: form.protocol,
        model: form.model
      }
      const key = newSecretOrUndefined(form.api_key)
      if (key) payload.api_key = key
      if (form.key_ref) payload.key_ref = form.key_ref
      const res = await userApi.settingsModels(payload)
      const list = Array.isArray(res?.models) ? res.models.filter(Boolean) : []
      if (list.length) {
        setSingleModels(list)
        if (!form.model || !list.includes(form.model)) patch({ model: list[0] })
        message.success(`已获取 ${list.length} 个模型`)
      } else {
        setSingleModels([])
        setSingleModelsError(res?.error || '未获取到模型列表')
        message.warning('获取模型失败')
      }
    } catch (e) {
      setSingleModels([])
      setSingleModelsError(errText(e))
      message.warning('获取模型失败')
    } finally {
      setSingleModelsLoading(false)
    }
  }

  async function testSingleLlm() {
    setTestingLlm(true)
    setLlmTest(null)
    try {
      const payload: Record<string, unknown> = {
        base_url: form.base_url,
        model: form.model,
        protocol: form.protocol,
        temperature: Number(form.temperature)
      }
      const key = newSecretOrUndefined(form.api_key)
      if (key) payload.api_key = key
      if (form.key_ref) payload.key_ref = form.key_ref
      const res = normalizeLlmTestResult((await userApi.testLLM(payload)) as unknown as LlmTestResult)
      setLlmTest(res)
      message[res.ok ? 'success' : 'warning'](res.ok ? 'LLM 测试通过' : 'LLM 测试失败')
    } catch (e) {
      setLlmTest({ ok: false, results: [], error: errText(e) })
      message.warning('LLM 测试失败')
    } finally {
      setTestingLlm(false)
    }
  }

  /** 查询中转站余额（NewAPI / One API 系 billing 兼容接口；Sub2API 等返回不支持）。 */
  async function loadBalance() {
    setBalanceLoading(true)
    setBalanceInfo(null)
    try {
      const payload: Record<string, unknown> = { base_url: form.base_url }
      const key = newSecretOrUndefined(form.api_key)
      if (key) payload.api_key = key
      if (form.key_ref) payload.key_ref = form.key_ref
      const info = await userApi.llmBalance(payload)
      setBalanceInfo(info)
      if (info.supported) {
        message.success('余额查询成功')
      } else {
        message.info(info.detail || '该端点不提供余额查询')
      }
    } catch (e) {
      const text = errText(e)
      setBalanceInfo({ supported: false, gateway: '', hard_limit_usd: 0, used_usd: 0, remaining_usd: 0, detail: text })
      message.warning(text || '余额查询失败')
    } finally {
      setBalanceLoading(false)
    }
  }

  async function testProvider(index: number) {
    const provider = form.providers[index]
    if (!provider) return
    setTestingProvider(index)
    setLlmTest(null)
    try {
      const payload = buildProviderPayload(provider)
      if (
        !String(payload.base_url || '').trim() ||
        !String(payload.model || '').trim() ||
        (!payload.api_key && !provider.key_ref && !provider.api_key_set && provider.api_key !== MASKED_PLACEHOLDER)
      ) {
        throw new Error(`LLM 端点 #${index + 1} 配置不完整`)
      }
      const res = normalizeLlmTestResult((await userApi.testLLM({ providers: [payload] })) as unknown as LlmTestResult)
      setLlmTest(res)
      void refreshProviderHealth()
      message[res.ok ? 'success' : 'warning'](`端点 #${index + 1} 测试${res.ok ? '通过' : '失败'}`)
    } catch (e) {
      setLlmTest({ ok: false, results: [], error: errText(e) })
      message.warning(`端点 #${index + 1} 测试失败`)
    } finally {
      setTestingProvider(-1)
    }
  }

  /** 测试 Kali SSH 连接（用当前表单值，允许保存前试连；密钥留空自动复用已存配置）。 */
  async function testKali() {
    setKaliTesting(true)
    setKaliTestResult(null)
    try {
      const payload: Record<string, unknown> = {
        host: form.kali_host.trim(),
        port: Number(form.kali_port) || 22,
        username: form.kali_username.trim(),
        auth_type: form.kali_auth_type
      }
      if (form.kali_password.trim()) payload.password = form.kali_password
      if (form.kali_private_key.trim()) payload.private_key = form.kali_private_key
      const res = (await userApi.kaliTest(payload)) as { ok?: boolean; latency_ms?: number; output?: string; error?: string; detail?: string }
      if (res?.ok) {
        setKaliTestResult({ ok: true, text: `连接成功（${res.latency_ms ?? '?'}ms）${res.output ? ` · ${res.output.split('\n')[0]}` : ''}` })
        message.success('Kali SSH 连接成功')
      } else {
        const reason = res?.error || res?.detail || '连接失败'
        setKaliTestResult({ ok: false, text: reason })
        message.warning('Kali SSH 连接失败')
      }
    } catch (e) {
      setKaliTestResult({ ok: false, text: errText(e) })
      message.warning('Kali SSH 连接失败')
    } finally {
      setKaliTesting(false)
    }
  }

  function healthFor(provider: LlmProviderRow): HealthSnapshot | undefined {
    if (provider.health_ref) {
      const hit = health.find((h) => h.ref === provider.health_ref)
      if (hit) return hit
    }
    return health.find((h) => h.base_url === provider.base_url && h.model === provider.model)
  }

  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      message.success('已复制')
    } catch {
      message.warning('复制失败，请手动选中')
    }
  }

  // ------------------------------------------------------------ 工作目录 / 备份

  async function loadWorkdirStats() {
    setWorkdirLoading(true)
    try {
      const raw: WorkdirStats = await userApi.workdirStats()
      const ext = raw as unknown as WorkdirStatsExt
      setWorkdir(ext)
      setCleanupDays(ext.retention_days || 7)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setWorkdirLoading(false)
    }
  }

  function runCleanup() {
    const days = Number(cleanupDays)
    if (!Number.isFinite(days) || days <= 0) {
      message.warning('保留天数要大于 0，才会删除过期目录')
      return
    }
    modal.confirm({
      title: '清理过期工作目录',
      content: `将删除超过 ${days} 天没再写入的工作目录。正在挖掘的目标不会动。确定清理？`,
      okText: '清理',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        setCleaning(true)
        setCleanupResult(null)
        try {
          const res = (await userApi.workdirCleanup(days)) as unknown as WorkdirCleanupResult
          setCleanupResult(res)
          message.success(`已清理 ${res.deleted_dirs ?? 0} 个目录，释放 ${res.freed_human || '0 B'}`)
          await loadWorkdirStats()
        } catch (e) {
          message.error(errText(e))
        } finally {
          setCleaning(false)
        }
      }
    })
  }

  async function loadBackupStats() {
    setBackupLoading(true)
    try {
      const raw: BackupStatus = await userApi.backupStatus()
      setBackup(raw as unknown as BackupStatusExt)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setBackupLoading(false)
    }
  }

  async function exportBackup() {
    setBackupBusy('export')
    try {
      await systemApi.downloadBackupExport(backupIncludeWork)
      message.success(backupIncludeWork ? '已开始下载（含工作目录）' : '已开始下载数据库备份')
    } catch (e) {
      message.error(errText(e))
    } finally {
      setBackupBusy('')
    }
  }

  async function snapshotNow() {
    setBackupBusy('snapshot')
    try {
      const res = (await userApi.backupSnapshot()) as unknown as { name?: string; human?: string }
      message.success(`已在服务器覆盖保存 ${res?.name || '快照'}${res?.human ? `（${res.human}）` : ''}`)
      await loadBackupStats()
    } catch (e) {
      message.error(errText(e))
    } finally {
      setBackupBusy('')
    }
  }

  async function downloadSnapshot(name: string) {
    setBackupBusy(name)
    try {
      await systemApi.downloadBackupSnapshot(name)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setBackupBusy('')
    }
  }

  function restoreBackup() {
    if (!restoreFile) {
      message.warning('请先选择备份文件（.tar.gz）')
      return
    }
    modal.confirm({
      title: '从备份恢复',
      content: '将覆盖当前数据库并重启服务。进行中的任务会中断。确定恢复？',
      okText: '恢复并重启',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        setBackupBusy('restore')
        try {
          const res = await systemApi.restoreBackup(restoreFile, restoreIncludeWork)
          const r = res as { message?: string; restarted?: boolean }
          message.success(r?.message || '已恢复')
          setRestoreFile(null)
          if (restoreFileRef.current) restoreFileRef.current.value = ''
          if (r?.restarted) startRestart('backup')
        } catch (e) {
          message.error(errText(e))
        } finally {
          setBackupBusy('')
        }
      }
    })
  }

  /** 重启轮询：服务恢复后刷新整页数据。 */
  function startRestart(kind: 'update' | 'backup') {
    setRestarting(kind)
    let attempts = 0
    if (pollRef.current) window.clearInterval(pollRef.current)
    pollRef.current = window.setInterval(async () => {
      attempts += 1
      try {
        await userApi.getSettings()
        if (pollRef.current) window.clearInterval(pollRef.current)
        pollRef.current = null
        setRestarting('')
        message.success(kind === 'backup' ? '备份恢复完成，服务已重启' : '更新完成，服务已重启 🎉')
        setUpdateInfo(null)
        await load()
      } catch {
        /* 服务未就绪，继续轮询 */
      }
      if (attempts > 60) {
        if (pollRef.current) window.clearInterval(pollRef.current)
        pollRef.current = null
        setRestarting('')
        message.warning('重启超时，请手动刷新页面')
      }
    }, 3000)
  }

  // ------------------------------------------------------------ 更新

  async function checkUpdate() {
    setUpdateChecking(true)
    setUpdateError('')
    setUpdateInfo(null)
    try {
      const res = (await userApi.checkUpdate()) as unknown as UpdateInfoExt
      setUpdateInfo(res)
    } catch (e) {
      const msg = errText(e)
      // 原版未注册 update 路由时隐藏相关提示；其余情况展示原因。
      if (/^\s*404\b|not found/i.test(msg)) setUpdateSupported(false)
      else setUpdateError(msg)
    } finally {
      setUpdateChecking(false)
    }
  }

  function runUpdate() {
    modal.confirm({
      title: '确认更新？',
      content: '服务会自动重启，进行中的任务会优雅暂停。',
      okText: '更新',
      cancelText: '取消',
      onOk: async () => {
        setUpdateRunning(true)
        setUpdateError('')
        try {
          const r = (await userApi.runUpdate()) as unknown as { ok?: boolean; error?: string; command?: string }
          if (r?.ok) {
            startRestart('update')
          } else {
            setUpdateError(r?.error || '更新失败')
            if (r?.command) {
              setUpdateInfo((prev) => (prev ? { ...prev, rebuild_command: r.command } : prev))
            }
          }
        } catch (e) {
          setUpdateError(errText(e))
        } finally {
          setUpdateRunning(false)
        }
      }
    })
  }

  // ------------------------------------------------------------ 外观

  async function onWallpaperFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setWallpaperBusy(true)
    setWallpaperError('')
    try {
      const res = await systemApi.uploadWallpaper(file)
      // 上传接口返回 { ok, path, url }；url 是图片原文件端点，直接采用。
      const rawUrl = typeof res?.url === 'string' ? res.url : ''
      applyUi({ ui_wallpaper_kind: 'file', ui_wallpaper_url: rawUrl })
      message.success('壁纸已更新')
    } catch (err) {
      setWallpaperError(errText(err))
    } finally {
      setWallpaperBusy(false)
    }
  }

  function applyWallpaperUrl() {
    const url = (form.ui_wallpaper_url || '').trim()
    if (!url) {
      void onClearWallpaper()
      return
    }
    if (!/^https?:\/\//i.test(url)) {
      setWallpaperError('请填写 http(s) 图片地址')
      return
    }
    setWallpaperError('')
    applyUi({ ui_wallpaper_kind: 'url', ui_wallpaper_url: url })
  }

  async function onClearWallpaper() {
    setWallpaperBusy(true)
    setWallpaperError('')
    try {
      await userApi.deleteWallpaper()
    } catch (e) {
      setWallpaperError(errText(e))
    } finally {
      applyUi({ ui_wallpaper_kind: 'none', ui_wallpaper_url: '' })
      setWallpaperBusy(false)
    }
  }

  async function loadWallpaperInfo() {
    try {
      const res = await userApi.wallpaperInfo()
      setWallpaperInfo(res)
    } catch {
      setWallpaperInfo(null)
    }
  }

  // ------------------------------------------------------------ 挂载

  useEffect(() => {
    void load()
    void refreshProviderHealth()
    void checkUpdate()
    void loadWorkdirStats()
    void loadBackupStats()
    void loadWallpaperInfo()
    const timer = window.setInterval(() => void refreshProviderHealth(), 10000)
    return () => {
      window.clearInterval(timer)
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ---- 外部（如顶部菜单）切换 ?tab= 时联动
  useEffect(() => {
    const t = searchParams.get('tab')
    if (t && TABS.some((x) => x.id === t) && t !== tab) setTab(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams])

  function onTabChange(key: string) {
    setTab(key)
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set('tab', key)
        return next
      },
      { replace: true }
    )
  }

  // ------------------------------------------------------------ 渲染

  const engineList: EngineMeta[] = form.available_engines.length
    ? form.available_engines
    : Object.entries(form.engines).map(([name, e]) => ({ name, display_name: e.display_name }))

  const updateAvailable = !!(updateInfo?.update_available ?? updateInfo?.has_update)
  const updateUpToDate =
    !!updateInfo && !updateAvailable && !updateInfo.error && updateInfo.enabled !== false
  const backupAuto = autoBackupText(backup?.auto_backup)
  const ro = !canWrite

  /** 界面页。 */
function renderAppearance(): ReactNode {
    return (
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small" title="主题与背景">
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <div>
              <Typography.Text>明暗主题</Typography.Text>
              <div style={{ marginTop: 6 }}>
                <Segmented
                  value={form.ui_theme}
                  options={[
                    { value: 'light', label: '亮色' },
                    { value: 'dark', label: '暗色' }
                  ]}
                  onChange={(v) => applyUi({ ui_theme: String(v) })}
                  disabled={ro}
                />
              </div>
            </div>

            {/* 主题色：预设色板 + 自定义取色器 + 色相滑块，三者都写同一个 accentHue */}
            <div>
              <Typography.Text>主题色</Typography.Text>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginTop: 6 }}>
                {ACCENT_PRESETS.map((sw) => (
                  <Tooltip key={sw.h} title={sw.name}>
                    <button
                      type="button"
                      aria-label={sw.name}
                      disabled={ro}
                      onClick={() => applyUi({ ui_accent_hue: sw.h })}
                      style={{
                        width: 24,
                        height: 24,
                        padding: 0,
                        borderRadius: '50%',
                        cursor: ro ? 'not-allowed' : 'pointer',
                        background: `oklch(58% 0.16 ${sw.h})`,
                        border:
                          clampHue(form.ui_accent_hue) === sw.h
                            ? '2px solid var(--aisrc-text)'
                            : '1px solid var(--aisrc-border)'
                      }}
                    />
                  </Tooltip>
                ))}
                <input
                  type="color"
                  aria-label="自定义主题色"
                  title="自定义"
                  disabled={ro}
                  value={hueToHex(form.ui_accent_hue)}
                  onChange={(e) => applyUi({ ui_accent_hue: hexToHue(e.target.value, form.ui_accent_hue) })}
                  style={{
                    width: 34,
                    height: 26,
                    padding: 0,
                    borderRadius: 4,
                    cursor: ro ? 'not-allowed' : 'pointer',
                    border: '1px solid var(--aisrc-border)',
                    background: 'transparent'
                  }}
                />
              </div>
              <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 6 }}>
                色相 {form.ui_accent_hue} · 按钮、选中态、焦点会跟着变
              </Typography.Text>
            </div>

            <div>
              <Typography.Text>色相</Typography.Text>
              <Slider
                min={0}
                max={360}
                value={form.ui_accent_hue}
                disabled={ro}
                onChange={(v) => applyUi({ ui_accent_hue: Number(v) })}
                style={{ marginTop: 6 }}
              />
            </div>

            <div>
              <Typography.Text>铺满方式</Typography.Text>
              <div style={{ marginTop: 6 }}>
                <Segmented
                  value={form.ui_wallpaper_fit}
                  options={[
                    { value: 'cover', label: '铺满裁切' },
                    { value: 'contain', label: '完整显示' }
                  ]}
                  onChange={(v) => applyUi({ ui_wallpaper_fit: String(v) })}
                  disabled={ro}
                />
              </div>
            </div>

            <div>
              <Typography.Text>背景压暗 {Math.round(form.ui_wallpaper_dim * 100)}%</Typography.Text>
              <Slider
                min={0.08}
                max={0.62}
                step={0.01}
                value={form.ui_wallpaper_dim}
                disabled={ro}
                onChange={(v) => applyUi({ ui_wallpaper_dim: Number(v) })}
                style={{ marginTop: 6 }}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                往左拖图更清楚，往右拖字更好读
              </Typography.Text>
            </div>

            <div>
              <Typography.Text>背景图链接</Typography.Text>
              <Space.Compact style={{ width: '100%', marginTop: 6 }}>
                <Input
                  value={form.ui_wallpaper_url}
                  disabled={form.ui_wallpaper_kind === 'file'}
                  placeholder="https://example.com/wallpaper.jpg"
                  onChange={(e) => patch({ ui_wallpaper_url: e.target.value })}
                  onPressEnter={applyWallpaperUrl}
                />
                <Button onClick={applyWallpaperUrl} disabled={ro}>
                  使用链接
                </Button>
              </Space.Compact>
            </div>

            <Space wrap>
              <Button
                icon={<UploadOutlined />}
                loading={wallpaperBusy}
                disabled={ro}
                onClick={() => wallpaperInputRef.current?.click()}
              >
                上传图片
              </Button>
              <input
                ref={wallpaperInputRef}
                type="file"
                accept="image/*"
                hidden
                disabled={wallpaperBusy || ro}
                onChange={(e) => void onWallpaperFile(e)}
              />
              <Button
                icon={<DeleteOutlined />}
                disabled={ro || form.ui_wallpaper_kind === 'none'}
                onClick={() => void onClearWallpaper()}
              >
                去掉背景
              </Button>
              <Button icon={<UndoOutlined />} disabled={ro} onClick={() => void resetAppearance()}>
                恢复默认外观
              </Button>
              <Button icon={<ReloadOutlined />} onClick={() => void loadWallpaperInfo()}>
                查询壁纸信息
              </Button>
            </Space>

            {wallpaperBusy ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                正在压缩并保存图片…
              </Typography.Text>
            ) : null}

            {wallpaperError ? (
              <Typography.Text type="danger" style={{ fontSize: 12 }}>
                {wallpaperError}
              </Typography.Text>
            ) : null}

            {wallpaperInfo ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                当前壁纸：{wallpaperInfo.kind || 'none'}
                {wallpaperInfo.exists ? ' · 服务器已保存' : ' · 服务器无文件'}
                {wallpaperInfo.url ? ` · ${wallpaperInfo.url}` : ''}
              </Typography.Text>
            ) : null}

            <div
              style={{
                height: 120,
                borderRadius: 8,
                border: '1px solid var(--aisrc-border)',
                backgroundImage:
                  form.ui_wallpaper_kind === 'none'
                    ? undefined
                    : `url(${JSON.stringify(wallpaperSrc(form.ui_wallpaper_kind, form.ui_wallpaper_url))})`,
                // 预览跟随铺满方式，选了"完整显示"就不该在预览里被裁切
                backgroundSize: form.ui_wallpaper_fit === 'contain' ? 'contain' : 'cover',
                backgroundPosition: 'center',
                backgroundRepeat: 'no-repeat',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--aisrc-text-sub)',
                fontSize: 13
              }}
            >
              {form.ui_wallpaper_kind === 'none'
                ? '当前没有自定义背景'
                : form.ui_wallpaper_kind === 'file'
                  ? '已使用服务器保存的图片'
                  : '使用网络图片'}
            </div>

            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              主题色与背景保存在本实例服务器，换电脑也能带上
            </Typography.Text>
          </Space>
        </Card>
      </Space>
    )
  }

  
  /** 模型页。 */
  function renderLlm(): ReactNode {
    return (
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small" title="AI / LLM 默认通道">
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Segmented
              value={llmMode}
              onChange={(v) => {
                setLlmMode(v as LlmMode)
                setLlmTest(null)
              }}
              options={[
                { value: 'single', label: '单端点' },
                { value: 'pool', label: '端点池' }
              ]}
            />

            {llmMode === 'single' ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12 }}>
                <div style={{ gridColumn: '1 / -1' }}>
                  <Typography.Text>base_url</Typography.Text>
                  <Input
                    disabled={ro}
                    value={form.base_url}
                    placeholder="https://api.deepseek.com/v1"
                    onChange={(e) => {
                      setSingleModels([])
                      setSingleModelsError('')
                      setBalanceInfo(null)
                      patch({ base_url: e.target.value, key_ref: '' })
                    }}
                  />
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    支持官方 API 与 NewAPI / One API / Sub2API 等中转站：中转填站址根地址或 …/v1 均可（自动补全）。
                    Coding Plan 填官方根地址（智谱 …/api/coding/paas/v4、方舟 …/api/coding/v3），不要再加 /v1。
                  </Typography.Text>
                </div>

                <div>
                  <Typography.Text>api_key</Typography.Text>
                  <SecretPassword
                    disabled={ro}
                    value={form.api_key}
                    placeholder={form.api_key_set ? '已配置，留空不修改' : 'sk-...'}
                    onChange={(e) => patch({ api_key: e.target.value })}
                  />
                </div>

                <div>
                  <Typography.Text>协议</Typography.Text>
                  <Select
                    style={{ width: '100%' }}
                    disabled={ro}
                    value={form.protocol}
                    options={PROTOCOL_OPTIONS}
                    onChange={(v: string) => {
                      setSingleModels([])
                      setSingleModelsError('')
                      patch({ protocol: v, key_ref: '' })
                    }}
                  />
                </div>

                <div>
                  <Typography.Text>temperature</Typography.Text>
                  <InputNumber
                    style={{ width: '100%' }}
                    disabled={ro}
                    min={0}
                    max={2}
                    step={0.1}
                    value={form.temperature}
                    onChange={(v) => patch({ temperature: v ?? 0.3 })}
                  />
                </div>

                <div>
                  <Typography.Text>模型名</Typography.Text>
                  <LlmModelPicker
                    value={form.model}
                    models={singleModels}
                    loading={singleModelsLoading}
                    disabled={ro}
                    error={singleModelsError}
                    required
                    onChange={(v) => patch({ model: v })}
                    onRefresh={() => void loadSingleModels()}
                  />
                </div>

                <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                  <Button
                    icon={<ExperimentOutlined />}
                    loading={testingLlm}
                    disabled={ro}
                    onClick={() => void testSingleLlm()}
                  >
                    {testingLlm ? '测试中…' : '测试连接'}
                  </Button>
                  <Button
                    icon={<WalletOutlined />}
                    loading={balanceLoading}
                    disabled={ro}
                    onClick={() => void loadBalance()}
                  >
                    查余额
                  </Button>
                </div>
                {balanceInfo ? (
                  <div style={{ gridColumn: '1 / -1' }}>
                    {balanceInfo.supported ? (
                      <Typography.Text style={{ fontSize: 13 }}>
                        {`余额（${balanceInfo.gateway === 'newapi' ? 'NewAPI 兼容网关' : balanceInfo.gateway}）：总额度 $${balanceInfo.hard_limit_usd.toFixed(2)}`}
                        {balanceInfo.used_usd > 0 ? ` · 已用 $${balanceInfo.used_usd.toFixed(2)}` : ''}
                        {` · 剩余 $${balanceInfo.remaining_usd.toFixed(2)}`}
                      </Typography.Text>
                    ) : (
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {balanceInfo.detail || '该端点不提供余额查询'}
                      </Typography.Text>
                    )}
                  </div>
                ) : null}
              </div>
            ) : (
              <LlmPoolEditor
                value={form.providers}
                disabled={ro}
                onChange={(rows) => patch({ providers: rows })}
                onModelsFetched={() => void refreshProviderHealth()}
              />
            )}
          </Space>
        </Card>

        {llmMode === 'pool' ? (
          <Card
            size="small"
            title="端点健康状态"
            extra={
              <Button size="small" icon={<ReloadOutlined />} loading={healthLoading} onClick={() => void refreshProviderHealth()}>
                刷新
              </Button>
            }
          >
            {!form.providers.length ? (
              <Typography.Text type="secondary">暂无端点</Typography.Text>
            ) : (
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                {form.providers.map((provider, index) => {
                  const h = healthFor(provider)
                  // 运行时从未调用过但手动测试过：用探测结果说话。
                  const probed = h?.status === 'untested' && !!h.probe_status
                  const probeOK = h?.probe_status === 'ok'
                  const statusTip = h?.probe_error || h?.last_error || (probed ? (probeOK ? '手动测试通过' : '手动测试失败') : '暂无健康记录')
                  return (
                    <div key={provider.uid || index} style={{ border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 10 }}>
                      <Space wrap size={10}>
                        <strong>{provider.name || `llm-${index + 1}`}</strong>
                        <Typography.Text type="secondary">{provider.model || '未设置模型'}</Typography.Text>
                        <Tooltip title={statusTip}>
                          <Tag color={probed ? (probeOK ? 'success' : 'error') : healthColor(h?.status)}>
                            {probed ? (probeOK ? '测试通过' : '测试失败') : healthText(h?.status)}
                          </Tag>
                        </Tooltip>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          连续失败 {h?.consecutive_failures ?? 0} 次
                        </Typography.Text>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          冷却 {h?.cooldown_seconds ?? 0}s
                        </Typography.Text>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          成功 {h?.success_count ?? 0} / 失败 {h?.failure_count ?? 0}
                        </Typography.Text>
                        {h?.error_kind ? <Tag>{h.error_kind}</Tag> : null}
                        {h?.last_seen ? (
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            {fmtRelativeTime(h.last_seen)}
                          </Typography.Text>
                        ) : h?.probe_at ? (
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            测试于 {fmtRelativeTime(h.probe_at)}
                            {h.probe_latency_ms ? ` · ${h.probe_latency_ms}ms` : ''}
                          </Typography.Text>
                        ) : null}
                        <Button
                          size="small"
                          loading={testingProvider === index}
                          disabled={ro}
                          onClick={() => void testProvider(index)}
                        >
                          测试端点
                        </Button>
                      </Space>
                      {h?.last_error || h?.probe_error ? (
                        <Typography.Paragraph type="danger" style={{ fontSize: 12, margin: '6px 0 0' }}>
                          {h?.last_error || h?.probe_error}
                        </Typography.Paragraph>
                      ) : null}
                    </div>
                  )
                })}
              </Space>
            )}
          </Card>
        ) : null}

        {llmTest ? (
          <Card size="small" title={llmTest.ok ? 'LLM 可用' : 'LLM 不可用'}>
            {llmTest.error ? (
              <Typography.Paragraph type="danger" style={{ marginBottom: 8 }}>
                {llmTest.error}
              </Typography.Paragraph>
            ) : null}
            {!llmTest.ok && (llmTest.error_copy || llmTest.error) ? (
              <pre className="code-block" style={{ marginBottom: 8 }}>
                {llmTest.error_copy || llmTest.error}
              </pre>
            ) : null}
            {llmTest.results?.length ? (
              <Space direction="vertical" size={6} style={{ width: '100%' }}>
                {llmTest.results.map((item, i) => (
                  <div key={`${item.name || 'single'}-${i}`} style={{ borderTop: i ? '1px solid var(--aisrc-border)' : 'none', paddingTop: i ? 6 : 0 }}>
                    <Space style={{ justifyContent: 'space-between', width: '100%' }}>
                      <strong>{item.ok ? '通过' : '失败'} · {item.name || 'single'}</strong>
                      <Button
                        size="small"
                        type="link"
                        onClick={() => void copyText(item.error_copy || item.error || resultText(item))}
                      >
                        复制
                      </Button>
                    </Space>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {resultText(item)}
                    </Typography.Text>
                    {!item.ok && (item.error_copy || item.error) ? (
                      <pre className="code-block" style={{ marginTop: 6 }}>
                        {item.error_copy || item.error}
                      </pre>
                    ) : null}
                  </div>
                ))}
              </Space>
            ) : null}
          </Card>
        ) : null}
      </Space>
    )
  }

  /** 资产测绘页。 */
  function renderRecon(): ReactNode {
    return (
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small" title="测绘默认">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12 }}>
            <div style={{ gridColumn: '1 / -1' }}>
              <Typography.Text>默认搜索引擎</Typography.Text>
              <Select
                style={{ width: '100%' }}
                disabled={ro}
                value={form.default_engine}
                options={engineList.map((e) => ({ value: e.name, label: e.display_name || e.name }))}
                onChange={(v: string) => patch({ default_engine: v })}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                新建任务「搜索引擎」留空时使用此项，任务里仍可临时换引擎。
              </Typography.Text>
            </div>

            <div>
              <Typography.Text>默认最大页数</Typography.Text>
              <InputNumber
                style={{ width: '100%' }}
                disabled={ro}
                min={1}
                value={form.max_pages}
                onChange={(v) => patch({ max_pages: v ?? 20 })}
              />
            </div>

            <div>
              <Typography.Text>每页条数</Typography.Text>
              <InputNumber
                style={{ width: '100%' }}
                disabled={ro}
                min={1}
                value={form.page_size}
                onChange={(v) => patch({ page_size: v ?? 100 })}
              />
            </div>

            <div style={{ gridColumn: '1 / -1' }}>
              <Typography.Text>默认搜集方式</Typography.Text>
              <Select
                style={{ width: '100%' }}
                disabled={ro}
                value={form.default_intent_mode}
                options={INTENT_OPTIONS}
                onChange={(v: string) => patch({ default_intent_mode: v })}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                分页与搜集方式对当前选用的测绘引擎生效。
              </Typography.Text>
            </div>
          </div>
        </Card>

        <Card size="small" title="各引擎 API Key">
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            按需配置；未配 Key 的引擎在任务里选中时无法搜资产。密钥留空表示不修改。
          </Typography.Paragraph>
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            {engineList.map((eng) => {
              const row = form.engines[eng.name]
              if (!row) return null
              const placeholder =
                eng.name === 'censys'
                  ? 'Platform Personal Access Token，或旧版 API_ID:SECRET'
                  : eng.name === 'quake'
                    ? 'X-QuakeToken（个人中心 API Token）'
                    : `${eng.display_name || eng.name} API Key`
              return (
                <div key={eng.name} style={{ border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 12 }}>
                  <Space style={{ justifyContent: 'space-between', width: '100%' }}>
                    <strong>{row.display_name || eng.display_name || eng.name}</strong>
                    <Tag color={row.key_set ? 'success' : 'default'}>{row.key_set ? '已配置' : '未配置'}</Tag>
                  </Space>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12, marginTop: 10 }}>
                    <div style={{ gridColumn: '1 / -1' }}>
                      <Typography.Text>API Key</Typography.Text>
                      <SecretPassword
                        disabled={ro}
                        value={row.key}
                        placeholder={row.key_set ? '已配置，留空不修改' : placeholder}
                        onChange={(e) => patchEngine(eng.name, { key: e.target.value })}
                      />
                      {eng.name === 'censys' ? (
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          新账号用 Censys Platform 的 Personal Access Token；仅旧 Legacy Search 才填 API_ID:SECRET。
                        </Typography.Text>
                      ) : null}
                    </div>
                  </div>
                </div>
              )
            })}
          </Space>
        </Card>
      </Space>
    )
  }

  /** 默认参数页。 */
  function renderRuntime(): ReactNode {
    return (
      <Card size="small" title="调度默认">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12 }}>
          <div>
            <Typography.Text>新建任务默认并发</Typography.Text>
            <InputNumber
              style={{ width: '100%' }}
              disabled={ro}
              min={1}
              max={32}
              value={form.concurrency}
              onChange={(v) => patch({ concurrency: v ?? 3 })}
            />
          </div>
          <div>
            <Typography.Text>新建任务默认深挖次数</Typography.Text>
            <InputNumber
              style={{ width: '100%' }}
              disabled={ro}
              min={0}
              max={10}
              value={form.deepen_cap}
              onChange={(v) => patch({ deepen_cap: v ?? 2 })}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              同一目标被打回深挖的最大次数（默认 2，范围 0–10；0 表示关闭回炉）。
            </Typography.Text>
          </div>
          <div>
            <Typography.Text>默认最大页数</Typography.Text>
            <InputNumber
              style={{ width: '100%' }}
              disabled={ro}
              min={1}
              value={form.max_pages}
              onChange={(v) => patch({ max_pages: v ?? 20 })}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              与「测绘渠道」页签共用（存储于 FOFA 设置）。
            </Typography.Text>
          </div>
          <div>
            <Typography.Text>默认每页条数</Typography.Text>
            <InputNumber
              style={{ width: '100%' }}
              disabled={ro}
              min={1}
              value={form.page_size}
              onChange={(v) => patch({ page_size: v ?? 100 })}
            />
          </div>
          <div>
            <Typography.Text>低分跳过阈值</Typography.Text>
            <InputNumber
              style={{ width: '100%' }}
              disabled={ro}
              step={1}
              value={form.skip_score_threshold}
              onChange={(v) => patch({ skip_score_threshold: v ?? -10 })}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              Collector 评分低于此值的目标直接跳过。
            </Typography.Text>
          </div>
          <div>
            <Typography.Text>worker 提示词版本</Typography.Text>
            <Input
              disabled={ro}
              value={form.worker_prompt_version}
              placeholder="legacy"
              onChange={(e) => patch({ worker_prompt_version: e.target.value })}
            />
          </div>
          <div>
            <Typography.Text>复审通过后自动通杀</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Switch disabled={ro} checked={form.auto_killsweep} onChange={(v) => patch({ auto_killsweep: v })} />
            </div>
          </div>
          <div>
            <Typography.Text>允许 Shell 执行</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Switch disabled={ro} checked={form.shell_enabled} onChange={(v) => patch({ shell_enabled: v })} />
            </div>
          </div>
          <div>
            <Typography.Text>记录噪音事件</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Switch disabled={ro} checked={form.verbose_events} onChange={(v) => patch({ verbose_events: v })} />
            </div>
          </div>
        </div>
      </Card>
    )
  }

  /** AI 增强页：人格 / 技能 / ima 知识库 / Kali 集成。 */
  function renderAi(): ReactNode {
    const ro = !canWrite
    const toggleKaliCategory = (key: string, on: boolean) => {
      const next = on
        ? [...form.kali_categories, key]
        : form.kali_categories.filter((k) => k !== key)
      patch({ kali_categories: next })
    }
    const patchSkill = (idx: number, p: Partial<SkillRow>) => {
      const next = form.skill_items.map((row, i) => (i === idx ? { ...row, ...p } : row))
      patch({ skill_items: next })
    }
    return (
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        {/* ---------------- AI 人格 ---------------- */}
        <Card
          size="small"
          title="AI 人格"
          extra={
            <Button
              size="small"
              onClick={() =>
                patch({
                  persona_enabled: true,
                  persona_name: '严谨的渗透测试专家',
                  persona_style: '直接、冷静、以证据说话；先确认授权与范围，再谈技术。',
                  persona_principles:
                    '1. 所有结论必须基于真实工具输出，禁止臆测；\n2. 优先选择对目标影响最小的验证方式；\n3. 发现高危问题先完整取证再继续；\n4. 严格遵守授权范围，越界目标一律跳过。'
                })
              }
              disabled={ro}
            >
              填入示例
            </Button>
          }
        >
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Typography.Text>启用人格</Typography.Text>
              <Switch disabled={ro} checked={form.persona_enabled} onChange={(v) => patch({ persona_enabled: v })} />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                启用后追加到 Worker / Reviewer 系统提示词尾部
              </Typography.Text>
            </div>
            <Input
              disabled={ro || !form.persona_enabled}
              placeholder="人格名（如：严谨的渗透测试专家）"
              value={form.persona_name}
              onChange={(e) => patch({ persona_name: e.target.value })}
            />
            <Input
              disabled={ro || !form.persona_enabled}
              placeholder="口吻风格（如：直接、冷静、以证据说话）"
              value={form.persona_style}
              onChange={(e) => patch({ persona_style: e.target.value })}
            />
            <Input.TextArea
              disabled={ro || !form.persona_enabled}
              placeholder={'行为准则（支持 Markdown：# 标题、列表、代码块，原样注入系统提示词）'}
              rows={10}
              value={form.persona_principles}
              onChange={(e) => patch({ persona_principles: e.target.value })}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              三个字段均支持 Markdown，原样追加到 Worker / Reviewer 系统提示词尾部，准则最多 5000 字
            </Typography.Text>
          </Space>
        </Card>

        {/* ---------------- Skill 技能 ---------------- */}
        <Card
          size="small"
          title="Skill 技能"
          extra={
            <Space>
              <Button
                size="small"
                disabled={ro}
                onClick={() =>
                  patch({
                    skill_items: [
                      ...form.skill_items,
                      {
                        id: `skill-${Date.now()}`,
                        name: '新 Skill',
                        content: '# 新 Skill\n\n## 一、定位\n\n描述这项 Skill 给 Agent 的领域知识与操作要点…',
                        enabled: true
                      }
                    ]
                  })
                }
              >
                新增技能
              </Button>
              <Button
                size="small"
                disabled={ro}
                onClick={() =>
                  patch({
                    skills_enabled: true,
                    skill_items: [
                      ...form.skill_items,
                      {
                        id: `skill-demo-${Date.now()}`,
                        name: '内网横向方法论',
                        content:
                          '# 内网横向方法论\n\n## 一、定位\n\n拿到边界主机后按以下顺序评估横向可能，全程只读优先。\n\n## 二、操作要点\n\n1. 抓取本机凭据（mimikatz 类）确认是否有域内复用口令；\n2. 列举可达网段与开放端口，优先定位域控与文件服务器；\n3. 用确定的凭据先做只读验证（`dir` 域共享），确认有效再深入；\n4. 每一步记录主机、凭据来源、验证结果，形成可复现链路。\n\n## 三、停止规则\n\n1. 目标不在授权范围，立即停；\n2. 需要写入或破坏性动作才能继续，标注「未验证」并停。',
                        enabled: true
                      }
                    ]
                  })
                }
              >
                填入示例
              </Button>
            </Space>
          }
        >
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Typography.Text>启用技能</Typography.Text>
              <Switch disabled={ro} checked={form.skills_enabled} onChange={(v) => patch({ skills_enabled: v })} />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                启用的 Skill 会装配进 Agent 系统提示词，按需运用
              </Typography.Text>
            </div>
            {form.skill_items.length === 0 ? (
              <Typography.Text type="secondary">暂无 Skill，点「新增技能」或「填入示例」。</Typography.Text>
            ) : (
              form.skill_items.map((row, idx) => (
                <div
                  key={row.id || idx}
                  style={{ border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 10 }}
                >
                  <Space style={{ width: '100%', marginBottom: 6 }} wrap>
                    <Input
                      disabled={ro}
                      style={{ width: 220 }}
                      placeholder="技能名"
                      value={row.name}
                      onChange={(e) => patchSkill(idx, { name: e.target.value })}
                    />
                    <Switch
                      disabled={ro}
                      checked={row.enabled}
                      checkedChildren="启用"
                      unCheckedChildren="停用"
                      onChange={(v) => patchSkill(idx, { enabled: v })}
                    />
                    <Button
                      size="small"
                      danger
                      disabled={ro}
                      onClick={() => patch({ skill_items: form.skill_items.filter((_, i) => i !== idx) })}
                    >
                      删除
                    </Button>
                  </Space>
                  <Input.TextArea
                    disabled={ro}
                    rows={10}
                    placeholder={'Skill 正文（支持 Markdown：# 标题、列表、代码块，原样注入系统提示词）'}
                    value={row.content}
                    onChange={(e) => patchSkill(idx, { content: e.target.value })}
                  />
                  <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 4 }}>
                    正文支持 Markdown，不限制字数，保存时自动补全
                  </Typography.Text>
                </div>
              ))
            )}
          </Space>
        </Card>

        {/* ---------------- ima 知识库 ---------------- */}
        <Card size="small" title="ima 知识库">
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Typography.Text>启用检索</Typography.Text>
              <Switch disabled={ro} checked={form.ima_enabled} onChange={(v) => patch({ ima_enabled: v })} />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                启用后 Worker 获得 ima_search 工具，按需检索知识库（企业情报/历史报告/资产背景）
              </Typography.Text>
            </div>
            <Input
              disabled={ro || !form.ima_enabled}
              placeholder="检索 API 端点（POST，如 https://ima.example.com/api/kb/search）"
              value={form.ima_base_url}
              onChange={(e) => patch({ ima_base_url: e.target.value })}
            />
            <Space wrap>
              <Input.Password
                disabled={ro || !form.ima_enabled}
                placeholder={form.ima_api_key_set ? '已配置，留空复用' : 'API Key'}
                value={form.ima_api_key}
                onChange={(e) => patch({ ima_api_key: e.target.value })}
                style={{ width: 260 }}
              />
              <Input
                disabled={ro || !form.ima_enabled}
                placeholder="知识库标识 repo_id"
                value={form.ima_repo_id}
                onChange={(e) => patch({ ima_repo_id: e.target.value })}
                style={{ width: 200 }}
              />
              <InputNumber
                disabled={ro || !form.ima_enabled}
                min={1}
                max={20}
                value={form.ima_top_k}
                onChange={(v) => patch({ ima_top_k: Number(v ?? 5) })}
                addonBefore="TopK"
                style={{ width: 140 }}
              />
            </Space>
          </Space>
        </Card>

        {/* ---------------- Kali 集成 ---------------- */}
        <Card
          size="small"
          title="Kali 渗透机（SSH）"
          extra={
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              启用后 Worker 获得 run_kali 工具：选分类 + 说明目的，系统与大模型协调出命令并经 SSH 执行
            </Typography.Text>
          }
        >
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Typography.Text>启用 Kali</Typography.Text>
              <Switch disabled={ro} checked={form.kali_enabled} onChange={(v) => patch({ kali_enabled: v })} />
            </div>
            <Space wrap>
              <Input
                disabled={ro || !form.kali_enabled}
                placeholder="主机（如 192.168.56.101）"
                value={form.kali_host}
                onChange={(e) => patch({ kali_host: e.target.value })}
                style={{ width: 220 }}
              />
              <InputNumber
                disabled={ro || !form.kali_enabled}
                min={1}
                max={65535}
                value={form.kali_port}
                onChange={(v) => patch({ kali_port: Number(v ?? 22) })}
                addonBefore="SSH"
                style={{ width: 130 }}
              />
              <Input
                disabled={ro || !form.kali_enabled}
                placeholder="用户名"
                value={form.kali_username}
                onChange={(e) => patch({ kali_username: e.target.value })}
                style={{ width: 160 }}
              />
              <Select
                disabled={ro || !form.kali_enabled}
                value={form.kali_auth_type}
                onChange={(v) => patch({ kali_auth_type: v })}
                style={{ width: 130 }}
                options={[
                  { value: 'password', label: '密码认证' },
                  { value: 'key', label: '私钥认证' }
                ]}
              />
            </Space>
            {form.kali_auth_type === 'key' ? (
              <Input.TextArea
                disabled={ro || !form.kali_enabled}
                rows={4}
                placeholder={form.kali_private_key_set ? '已配置私钥，留空复用（粘贴新私钥覆盖）' : '私钥（PEM，-----BEGIN OPENSSH PRIVATE KEY-----）'}
                value={form.kali_private_key}
                onChange={(e) => patch({ kali_private_key: e.target.value })}
              />
            ) : (
              <Input.Password
                disabled={ro || !form.kali_enabled}
                placeholder={form.kali_password_set ? '已配置密码，留空复用' : 'SSH 密码'}
                value={form.kali_password}
                onChange={(e) => patch({ kali_password: e.target.value })}
                style={{ width: 320 }}
              />
            )}
            <Space wrap size={10}>
              <Button
                size="small"
                loading={kaliTesting}
                disabled={ro || !form.kali_enabled || !form.kali_host.trim()}
                onClick={() => void testKali()}
              >
                测试连接
              </Button>
              {kaliTestResult ? (
                <Typography.Text type={kaliTestResult.ok ? 'success' : 'danger'} style={{ fontSize: 12 }}>
                  {kaliTestResult.ok ? '✓ ' : '✗ '}
                  {kaliTestResult.text}
                </Typography.Text>
              ) : (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  用当前表单值试连（密钥留空复用已存配置），执行 uname -a 验证
                </Typography.Text>
              )}
            </Space>
            <div>
              <Typography.Text strong>启用的工具分类</Typography.Text>
              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 6 }}>
                被选中的分类才允许 Worker 调用（命令仍会经安全过滤；破坏性/拒绝服务类硬拦截）
              </Typography.Paragraph>
              <Checkbox.Group
                disabled={ro || !form.kali_enabled}
                value={form.kali_categories}
                onChange={(vals) => patch({ kali_categories: vals as string[] })}
                options={(form.all_kali_categories.length
                  ? form.all_kali_categories
                  : []
                ).map((c) => ({ value: c.key, label: `${c.label}（${c.desc}）` }))}
                style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 6 }}
              />
            </div>
          </Space>
        </Card>
      </Space>
    )
  }

  /** 数据与备份页。 */
  function renderData(): ReactNode {
    const deleted = cleanupResult?.deleted || []
    const failed = cleanupResult?.failed || []
    return (
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Card
          size="small"
          title="数据备份"
          extra={
            <Button size="small" icon={<ReloadOutlined />} loading={backupLoading} onClick={() => void loadBackupStats()}>
              刷新
            </Button>
          }
        >
          {restarting === 'backup' ? (
            <Alert type="info" showIcon message="备份已写入，服务正在重启…" />
          ) : backupLoading && !backup ? (
            <Typography.Text type="secondary">加载中…</Typography.Text>
          ) : backup ? (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Descriptions
                size="small"
                column={3}
                items={[
                  { key: 'db', label: '数据库', children: backup.db_human || '-' },
                  { key: 'disk', label: '库盘剩余', children: backup.disk?.free_human || '未知' },
                  { key: 'snap', label: '本地快照', children: backup.snapshots_human || '0 B' },
                  {
                    key: 'auto',
                    label: '自动备份',
                    children: <Tag color={backupAuto.on ? 'success' : 'default'}>{backupAuto.text}</Tag>
                  },
                  { key: 'work', label: '工作目录', children: backup.work?.human || '0 B' },
                  {
                    key: 'last',
                    label: '上次备份',
                    children: backup.last_backup_at ? fmtRelativeTime(backup.last_backup_at) : '-'
                  }
                ]}
              />

              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }}>
                日常请点「下载备份」把文件带走。服务器只覆盖留 1 份 gzip 快照（再打会覆盖），不自动堆多份。
                工作目录可选打包，上限 {backup.work?.max_human || '未知'}。
              </Typography.Paragraph>

              <Space wrap>
                <Space size={6}>
                  <Switch size="small" checked={backupIncludeWork} onChange={setBackupIncludeWork} />
                  <Typography.Text>下载时同时打包工作目录</Typography.Text>
                </Space>
                <Button icon={<DownloadOutlined />} loading={backupBusy === 'export'} disabled={ro} onClick={() => void exportBackup()}>
                  {backupBusy === 'export' ? '打包中…' : '下载备份'}
                </Button>
                <Button disabled={ro || !!backupBusy} onClick={() => void snapshotNow()}>
                  {backupBusy === 'snapshot' ? '覆盖中…' : '在服务器覆盖留一份'}
                </Button>
              </Space>

              {backup.snapshots?.length ? (
                <div>
                  <Typography.Text strong>服务器快照（{backup.snapshots.length}）</Typography.Text>
                  <Space direction="vertical" size={4} style={{ width: '100%', marginTop: 6 }}>
                    {backup.snapshots.map((s) => (
                      <Space key={s.name} style={{ justifyContent: 'space-between', width: '100%' }}>
                        <span className="mono">{s.name}</span>
                        <Space size={10}>
                          <Typography.Text type="secondary">
                            {s.human || (s.bytes != null ? fmtBytes(s.bytes) : '-')}
                          </Typography.Text>
                          {s.created_at ? (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              {fmtLocalTime(s.created_at)}
                            </Typography.Text>
                          ) : null}
                          <Button size="small" type="link" disabled={!!backupBusy} onClick={() => void downloadSnapshot(s.name)}>
                            下载
                          </Button>
                        </Space>
                      </Space>
                    ))}
                  </Space>
                </div>
              ) : null}

              <div>
                <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                  从备份恢复会覆盖当前数据库并重启。请先下载一份当前备份。
                </Typography.Paragraph>
                <Space wrap>
                  <input
                    ref={restoreFileRef}
                    type="file"
                    accept=".gz,.tgz,.tar.gz,application/gzip"
                    disabled={ro}
                    onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
                  />
                  <Space size={6}>
                    <Switch size="small" checked={restoreIncludeWork} onChange={setRestoreIncludeWork} />
                    <Typography.Text>同时恢复工作目录</Typography.Text>
                  </Space>
                  <Button danger disabled={ro || !!backupBusy || !restoreFile} loading={backupBusy === 'restore'} onClick={restoreBackup}>
                    {backupBusy === 'restore' ? '恢复中…' : '恢复并重启'}
                  </Button>
                </Space>
              </div>
            </Space>
          ) : (
            <Typography.Text type="secondary">暂无备份状态</Typography.Text>
          )}
        </Card>

        <Card
          size="small"
          title="工作目录管理"
          extra={
            <Button size="small" icon={<ReloadOutlined />} loading={workdirLoading} onClick={() => void loadWorkdirStats()}>
              刷新统计
            </Button>
          }
        >
          {workdirLoading && !workdir ? (
            <Typography.Text type="secondary">加载中…</Typography.Text>
          ) : workdir ? (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Descriptions
                size="small"
                column={3}
                items={[
                  {
                    key: 'size',
                    label: '磁盘占用',
                    children: workdir.total_size_human || fmtBytes(workdir.total_bytes)
                  },
                  {
                    key: 'dirs',
                    label: '目标目录数',
                    children: String(workdir.total_dirs ?? workdir.total_files ?? 0)
                  },
                  {
                    key: 'auto',
                    label: '自动清理',
                    children: workdir.auto_cleanup_enabled ? `已开启（${workdir.retention_days ?? 0} 天）` : '已关闭'
                  },
                  {
                    key: 'oldest',
                    label: '最旧目录',
                    children: workdir.oldest_dir?.age_days != null ? `${workdir.oldest_dir.age_days} 天前` : '-'
                  }
                ]}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                工作路径：<code>{workdir.work_root || workdir.root || '-'}</code>
              </Typography.Text>

              <Space wrap>
                <Space size={6}>
                  <Typography.Text>清理保留天数</Typography.Text>
                  <InputNumber
                    min={0}
                    max={365}
                    disabled={ro}
                    value={cleanupDays}
                    onChange={(v) => setCleanupDays(v ?? 0)}
                  />
                </Space>
                <Button loading={cleaning} disabled={ro} onClick={runCleanup}>
                  {cleaning ? '清理中…' : '清理过期目录'}
                </Button>
              </Space>

              {cleanupResult ? (
                <div>
                  <Typography.Text>
                    清理完成 · 扫描 {cleanupResult.scanned_dirs ?? 0} 个目录 · 删除 {cleanupResult.deleted_dirs ?? 0} 个
                    {cleanupResult.failed_dirs ? ` · 失败 ${cleanupResult.failed_dirs} 个` : ''} · 释放{' '}
                    {cleanupResult.freed_human || '0 B'}
                  </Typography.Text>
                  {deleted.length ? (
                    <details style={{ marginTop: 8 }}>
                      <summary style={{ cursor: 'pointer', color: 'var(--aisrc-text-sub)' }}>
                        已清理目录（{deleted.length}）
                      </summary>
                      <Space direction="vertical" size={2} style={{ width: '100%', marginTop: 6 }}>
                        {deleted.slice(0, 100).map((d, i) => (
                          <Space key={`${d.name}-${i}`} style={{ justifyContent: 'space-between', width: '100%' }}>
                            <span className="mono">{d.name}</span>
                            <Typography.Text type="secondary">
                              {d.age_days ?? '-'} 天 · {d.size_human || '-'}
                            </Typography.Text>
                          </Space>
                        ))}
                        {deleted.length > 100 ? (
                          <Typography.Text type="secondary">仅显示前 100 条，共 {deleted.length} 条</Typography.Text>
                        ) : null}
                      </Space>
                    </details>
                  ) : null}
                  {failed.length ? (
                    <details style={{ marginTop: 8 }}>
                      <summary style={{ cursor: 'pointer', color: 'var(--aisrc-text-sub)' }}>
                        失败目录（{failed.length}）
                      </summary>
                      <Space direction="vertical" size={2} style={{ width: '100%', marginTop: 6 }}>
                        {failed.map((d, i) => (
                          <Space key={`${d.name}-${i}`} style={{ justifyContent: 'space-between', width: '100%' }}>
                            <span className="mono">{d.name}</span>
                            <Typography.Text type="danger">{d.error}</Typography.Text>
                          </Space>
                        ))}
                      </Space>
                    </details>
                  ) : null}
                </div>
              ) : null}
            </Space>
          ) : (
            <Typography.Text type="secondary">暂无工作目录统计</Typography.Text>
          )}
        </Card>
      </Space>
    )
  }

  /** 更新页。 */
  function renderUpdate(): ReactNode {
    if (!updateSupported) {
      return <Alert type="warning" showIcon message="当前后端未注册更新接口" description="请使用部署环境的 git / 镜像方式手动更新。" />
    }
    return (
      <Card size="small" title="版本更新">
        {restarting === 'update' ? (
          <Alert type="info" showIcon message="服务正在重启，自动重连中…" />
        ) : (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Button icon={<ThunderboltOutlined />} loading={updateChecking} disabled={ro} onClick={() => void checkUpdate()}>
              {updateChecking ? '检测中…' : '检查更新'}
            </Button>

            {updateError ? <Alert type="error" showIcon message={updateError} /> : null}

            {updateInfo?.error ? (
              <Alert
                type="warning"
                showIcon
                message={updateInfo.error}
                description={
                  <Space direction="vertical" size={4}>
                    {updateInfo.hint ? <span>{updateInfo.hint}</span> : null}
                    <a
                      href={updateInfo.releases_url || updateInfo.release_url || 'https://github.com/StanleyNull/AutoHunter'}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      打开 GitHub 仓库 / Releases
                    </a>
                  </Space>
                }
              />
            ) : null}

            {updateAvailable ? (
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                <Space wrap>
                  <span className="mono">{updateInfo?.current_commit || updateInfo?.current_version || '-'}</span>
                  <span>→</span>
                  <span className="mono">{updateInfo?.latest_commit || updateInfo?.latest_version || '-'}</span>
                  {typeof updateInfo?.commits_behind === 'number' ? (
                    <Tag color="processing">落后 {updateInfo.commits_behind} 个提交</Tag>
                  ) : null}
                </Space>
                {updateInfo?.latest_message || updateInfo?.changelog ? (
                  <Typography.Paragraph style={{ marginBottom: 0 }}>
                    {updateInfo.latest_message || updateInfo.changelog}
                  </Typography.Paragraph>
                ) : null}
                {updateInfo?.changed_files?.length ? (
                  <details>
                    <summary style={{ cursor: 'pointer', color: 'var(--aisrc-text-sub)' }}>
                      变更文件（{updateInfo.changed_files.length}）
                    </summary>
                    <ul>
                      {updateInfo.changed_files.map((f) => (
                        <li key={f} className="mono">
                          {f}
                        </li>
                      ))}
                    </ul>
                  </details>
                ) : null}

                {updateInfo?.hot_updateable ? (
                  <Space wrap>
                    <Button type="primary" loading={updateRunning} disabled={ro} onClick={runUpdate}>
                      {updateRunning ? '更新中…' : '一键更新并重启'}
                    </Button>
                    <Typography.Text type="secondary">仅后端代码变更，可热更新（git pull + 自动重启）</Typography.Text>
                  </Space>
                ) : (
                  <div>
                    <Typography.Paragraph type="warning">
                      ⚠ 本次更新包含前端 / Dockerfile 变更，需在服务器执行完整重建：
                    </Typography.Paragraph>
                    <pre className="code-block">
                      {updateInfo?.rebuild_command || 'git pull && docker compose up -d --build'}
                    </pre>
                  </div>
                )}
              </Space>
            ) : updateUpToDate ? (
              <Alert
                type="success"
                showIcon
                message={`已是最新版本（${updateInfo?.current_commit || updateInfo?.current_version || '-'}）`}
              />
            ) : null}
          </Space>
        )}
      </Card>
    )
  }

  const tabItems = useMemo(
    () =>
      [
        { key: 'appearance', label: '外观', hint: '颜色与背景', children: renderAppearance() },
        { key: 'llm', label: '模型', hint: 'LLM 通道', children: renderLlm() },
        { key: 'recon', label: '资产测绘', hint: '引擎与 Key', children: renderRecon() },
        { key: 'runtime', label: '默认参数', hint: '并发与深挖', children: renderRuntime() },
        { key: 'ai', label: 'AI 增强', hint: '人格·Skill·知识库·Kali', children: renderAi() },
        {
          key: 'proxy',
          label: '代理池',
          hint: '出网换 IP',
          children: <ProxyPoolEditor disabled={!canWrite} />
        },
        { key: 'data', label: '数据与备份', hint: '磁盘与快照', children: renderData() },
        { key: 'update', label: '更新', hint: '版本检查', children: renderUpdate() }
      ].map((item) => ({
        key: item.key,
        label: (
          <span
            style={{
              display: 'inline-flex',
              flexDirection: 'column',
              lineHeight: 1.3,
              // antd v6 页签按钮是 text-align:center，双行标签短标题会被居中出缩进；
              // 显式左对齐让标题与副标题左缘一致。
              textAlign: 'left'
            }}
          >
            <span>{item.label}</span>
            <span style={{ fontSize: 12, opacity: 0.55 }}>{item.hint}</span>
          </span>
        ),
        children: item.children
      })),
    // 每次渲染都基于最新 state 重建面板内容
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [form, llmMode, singleModels, singleModelsLoading, singleModelsError, llmTest, testingLlm, balanceLoading, balanceInfo, testingProvider, health, healthLoading, workdir, workdirLoading, cleaning, cleanupDays, cleanupResult, backup, backupLoading, backupBusy, backupIncludeWork, restoreIncludeWork, restoreFile, restarting, updateChecking, updateInfo, updateError, updateRunning, updateSupported, wallpaperBusy, wallpaperError, wallpaperInfo, tab, canWrite, loading, saving, autoStatus, autoError, metaUpdatedAt]
  )

  const showSaveBar = tab === 'llm' || tab === 'recon' || tab === 'runtime'

  return (
    <section className="settings-view">
      <header className="page-head">
        <div>
          <h2>系统配置</h2>
          <p className="page-sub">
            模型 / 测绘 / 默认参数约 1 秒自动保存；界面与其余分区即时落库。
            {metaUpdatedAt ? ` 上次保存 ${fmtLocalTime(metaUpdatedAt)}。` : ''}
          </p>
        </div>
      </header>

      {!canWrite ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="当前角色无写入权限"
          description="只读 / 观摩角色仅可查看设置。所有保存、测试、上传、备份、恢复与更新操作均已禁用。"
        />
      ) : null}

      {loading ? (
        <Card loading style={{ minHeight: 320 }} />
      ) : (
        <>
          <Tabs tabPosition="left" activeKey={tab} onChange={onTabChange} items={tabItems} />

          {showSaveBar ? (
            <Card size="small" style={{ marginTop: 12 }}>
              <Space wrap>
                <Button type="primary" icon={<SaveOutlined />} loading={saving} disabled={!canWrite} onClick={() => void doSave(false)}>
                  {saving ? '保存中…' : '立即保存'}
                </Button>
                <Tag color={autoStatus === 'error' || autoStatus === 'incomplete' ? 'error' : autoStatus === 'saved' ? 'success' : 'default'}>
                  {scheduleStatusLabel()}
                </Tag>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  密钥留空不覆盖；输入完成后会随自动保存写入。
                </Typography.Text>
              </Space>
            </Card>
          ) : null}
        </>
      )}
    </section>
  )
}

/** 空表单。 */
function emptyForm(): SettingsForm {
  return {
    base_url: '',
    api_key: '',
    key_ref: '',
    api_key_set: false,
    model: '',
    protocol: 'auto',
    temperature: 0.3,
    providers: [],
    max_pages: 20,
    page_size: 100,
    default_intent_mode: '',
    default_engine: 'fofa',
    engines: {},
    available_engines: [],
    concurrency: 3,
    deepen_cap: 2,
    skip_score_threshold: -10,
    worker_prompt_version: 'legacy',
    auto_killsweep: true,
    shell_enabled: false,
    verbose_events: false,
    ui_theme: UI_DEFAULTS.theme,
    ui_accent_hue: UI_DEFAULTS.accentHue,
    ui_wallpaper_kind: UI_DEFAULTS.wallpaperKind,
    ui_wallpaper_url: UI_DEFAULTS.wallpaperUrl,
    ui_wallpaper_fit: UI_DEFAULTS.wallpaperFit,
    ui_wallpaper_dim: UI_DEFAULTS.wallpaperDim,
    persona_enabled: false,
    persona_name: '',
    persona_style: '',
    persona_principles: '',
    skills_enabled: false,
    skill_items: [],
    ima_enabled: false,
    ima_base_url: '',
    ima_api_key: '',
    ima_api_key_set: false,
    ima_repo_id: '',
    ima_top_k: 5,
    kali_enabled: false,
    kali_host: '',
    kali_port: 22,
    kali_username: 'root',
    kali_auth_type: 'password',
    kali_password: '',
    kali_password_set: false,
    kali_private_key: '',
    kali_private_key_set: false,
    kali_categories: [],
    all_kali_categories: []
  }
}
