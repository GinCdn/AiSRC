/**
 * 全局类型定义。
 *
 * 与后端约定（与原版 AutoHunter 逐字段一致）：
 *  - 成功：HTTP 200 + 数据本体（裸 JSON），这里定义的就是该数据本体的形状；
 *  - 失败：真实 HTTP 状态码 + { detail: string }，由 request 层统一转成 ApiError。
 *
 * 列表接口双形态：limit=0 返回裸数组，limit>0 返回 PageResult，用 ListResult 表达。
 */

/** 后端错误响应体（仅在出错时出现，由 request 层消费）。 */
export interface ErrorDetail {
  detail: string
}

/**
 * 历史遗留的 { code, msg, data } 包装类型。
 * 当前后端已不再使用，仅保留供极少数外部调用方参考。
 */
export interface Result<T = unknown> {
  code: number
  msg: string
  data: T
}

/** 分页形态：limit>0 时后端返回该结构，limit=0 时直接返回裸数组。 */
export interface PageResult<T> {
  items: T[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

/** 列表接口的双形态返回。 */
export type ListResult<T> = T[] | PageResult<T>

/** 角色：full 全权限 / readonly 只读 / observer 观摩 / none 未认证。 */
export type Role = 'full' | 'readonly' | 'observer' | 'none'

/** 鉴权状态。 */
export interface AuthStatus {
  auth_enabled: boolean
  auth_required: boolean
  password_set: boolean
  read_token_set: boolean
  observer_token_set: boolean
  role: Role
  role_label: string
  username: string
  expires_in: number
  version: string
  /** 连续登录失败次数（登录守卫，超集字段）。 */
  login_failures: number
  /** 是否必须输入验证码（失败满 3 次后为 true）。 */
  captcha_required: boolean
  /** 验证码位数（后端固定 4）。 */
  captcha_digits: number
}

/** 图形验证码。明文只存在于服务端，这里只有渲染好的图片。 */
export interface CaptchaInfo {
  captcha_id: string
  /** SVG 图片的 data URL，可直接塞进 <img src>。 */
  captcha_image: string
  expires_in: number
  digits: number
  threshold: number
}

/** 登录结果。 */
export interface LoginResult {
  token: string
  role: Role
  role_label: string
  username: string
  expires_in: number
}

/** 系统健康信息（ok 为原版契约字段）。 */
export interface HealthInfo {
  ok: boolean
  status: string
  db: boolean
  version: string
  time: string
  [key: string]: unknown
}

/** 关于信息。 */
export interface AboutInfo {
  name: string
  version: string
  description: string
  engine: string[]
  [key: string]: unknown
}

// ---------------------------------------------------------------- 任务

/** 目标来源类型。 */
export type TargetSource = 'fofa' | 'manual' | 'site' | 'both'

/** 任务状态。 */
export type TaskStatus = 'created' | 'running' | 'idle' | 'paused' | 'stopped'

/** 表单认证绑定。 */
export interface AuthBinding {
  target: string
  username: string
  password: string
  cookie: string
  authorization: string
  login_url: string
  raw: string
  note: string
}

/** 单个 LLM 提供方。 */
export interface LlmProvider {
  name: string
  base_url: string
  api_key: string
  api_key_set?: boolean
  key_ref?: string
  model: string
  protocol: string
  temperature: number
  weight: number
  enabled: boolean
}

/** 模型配置（任务级可覆盖全局）。 */
export interface LlmModelConfig {
  inherit_global: boolean
  base_url: string
  api_key: string
  model: string
  protocol: string
  prompt_version: string
  providers: LlmProvider[]
}

/** 测绘（FOFA 等）配置与进度。 */
export interface FofaConfig {
  key: string
  base_url: string
  max_pages: number
  page_size: number
  intent_mode: string
  skip_site_recon: boolean
  cursor: number
  current_query: string
  history: string[]
  empty_streak: number
  empty_query_streak: number
  fofa_exhausted: boolean
  last_fofa_error: string
  fofa_auth_fail_count: number
  daily_limit_count: number
  collector_phase: string
  collector_phase_text: string
}

/** 运行期用量统计。 */
export interface RuntimeStats {
  llm_tokens_in: number
  llm_tokens_out: number
  llm_calls: number
  engine_queries: number
  [key: string]: unknown
}

/** 任务。 */
export interface Task {
  id: string
  name: string
  src_type: string
  vuln_types: string[]
  src_rules: string
  target_source: TargetSource
  fofa_query: string
  manual_targets: string[]
  auth_bindings: AuthBinding[]
  model_config: LlmModelConfig
  fofa_config: FofaConfig
  engine: string
  concurrency: number
  deepen_cap: number
  auto_killsweep: boolean
  status: TaskStatus
  is_top: boolean
  runtime_stats: RuntimeStats
  created_at: string
  updated_at: string
  // 视图派生字段
  pending_user_review?: number
  target_stats?: Record<string, number>
  workers?: unknown[]
}

/** 目标（资产）。 */
export interface Target {
  id: string
  task_id: string
  host: string
  url: string
  source: string
  title: string
  ip: string
  port: number
  priority_score: number
  priority_reason?: string
  status: string
  verdict: string
  deepen_context: string
  deepen_count: number
  leaked_creds: string[]
  auth_status: string
  auth_context: string
  assigned_worker: string
  heartbeat_at: string | null
  dead_reason: string
  is_top: boolean
  category: string
  tech: string[]
  created_at: string
  updated_at: string
}

/** 看板快照。 */
export interface BoardData {
  task: Task
  columns?: Record<string, Target[]>
  targets?: Target[]
  stats?: Record<string, number>
  events?: TaskEvent[]
  workers?: unknown[]
  escalations?: string[]
  [key: string]: unknown
}

// ---------------------------------------------------------------- 漏洞

/** 漏洞步骤。原版契约是 string[]（每步一句话）；对象形态兼容编辑器/改稿。 */
export type FindingStep = string | {
  title?: string
  detail?: string
  request?: string
  response?: string
  [key: string]: unknown
}

/** 漏洞。 */
export interface Finding {
  id: string
  task_id: string
  target_id: string
  target_url: string
  host: string
  vuln_type: string
  title: string
  severity: string
  status: string
  steps: FindingStep[]
  evidence: Record<string, unknown>
  kill_chain: Record<string, unknown>
  assistant_msgs: Array<{ role: string; content: string; [key: string]: unknown }>
  self_check: Record<string, unknown>
  dedup_key: string
  llm_model: string
  llm_base_url: string
  is_top: boolean
  created_at: string
  updated_at: string
}

/** AI 审核记录 + 用户复审记录。 */
export interface Review {
  id: string
  finding_id: string
  task_id: string
  verdict: string
  confidence: string
  severity_final: string
  score: number
  in_scope: boolean
  is_duplicate: boolean
  ignore_reasons: string[]
  downgrade_reasons: string[]
  reproduced: boolean
  reviewer_notes: string
  deepen_directive: string
  user_status: string
  user_severity: string
  user_notes: string
  user_edits: Record<string, unknown>
  submitted: boolean
  user_reviewed_at: string | null
  created_at: string
  updated_at: string
}

/** 漏洞视图（列表/详情统一结构）。 */
export interface FindingView extends Finding {
  review?: Review
  review_verdict?: string
  confidence?: string
  severity_final?: string
  score?: number
  user_status?: string
  user_severity?: string
  submitted?: boolean
  in_scope?: boolean
  is_duplicate?: boolean
  target?: Target
  [key: string]: unknown
}

/** 通杀（批量验证）记录。 */
export interface Killsweep {
  id: string
  task_id: string
  finding_id: string
  product_key: string
  product_name: string
  status: string
  hits: number
  scanned: number
  notes: string
  created_at: string
  updated_at: string
}

/** 任务事件（运行时日志）。 */
export interface TaskEvent {
  id: number
  task_id: string
  agent: string
  kind: string
  level: string
  message: string
  ts: string
  payload?: Record<string, unknown>
}

/** 运行异常日志行。 */
export interface RuntimeLog {
  id: number
  task_id: string
  task_name?: string
  task_status?: string
  agent: string
  kind: string
  level: string
  message: string
  ts: string
  payload?: Record<string, unknown>
}

/** 目标执行轨迹条目。 */
export interface TraceEntry {
  ts: string
  agent: string
  kind: string
  level: string
  message: string
  payload?: Record<string, unknown>
}

// ---------------------------------------------------------------- 情报

/** 情报条目。 */
export interface Intel {
  id: string
  kind: string
  title: string
  summary: string
  severity: string
  confidence: string
  match_key: string
  tags: string[]
  source_task_id: string
  created_at: string
  updated_at: string
  [key: string]: unknown
}

// ---------------------------------------------------------------- 设置

/** 全局模型设置视图。 */
export interface LlmSettingsView {
  mode: string
  base_url: string
  api_key: string
  api_key_set: boolean
  model: string
  protocol: string
  temperature: number
  providers: LlmProvider[]
}

/** 测绘设置视图。 */
export interface FofaSettingsView {
  key: string
  key_set: boolean
  base_url: string
  max_pages: number
  page_size: number
  default_intent_mode: string
}

/** 引擎设置项。 */
export interface EngineSettingsView {
  key: string
  key_set: boolean
  base_url: string
  enabled: boolean
}

/** 默认参数。 */
export interface DefaultsSettings {
  concurrency: number
  deepen_cap: number
  max_pages: number
  page_size: number
  auto_killsweep: boolean
  shell_enabled: boolean
  verbose_events: boolean
  [key: string]: unknown
}

/** 界面设置。 */
export interface UISettings {
  wallpaper_kind: string
  wallpaper_url: string
  theme: string
  saved: boolean
  [key: string]: unknown
}

/** 代理项。 */
export interface ProxyItem {
  id: string
  url: string
  display?: string
  protocol: string
  host: string
  port: number
  username: string
  password: string
  enabled: boolean
  note: string
  latency_ms: number
  last_checked: string | null
  ok: boolean
  [key: string]: unknown
}

/** 代理池设置。 */
export interface ProxySettingsView {
  enabled: boolean
  proxies: ProxyItem[]
}

/** 全局设置视图。 */
export interface SettingsView {
  llm: LlmSettingsView
  fofa: FofaSettingsView
  engines: Record<string, EngineSettingsView>
  defaults: DefaultsSettings
  ui: UISettings
  proxy: ProxySettingsView
  [key: string]: unknown
}

/** 提供方健康状态。 */
export interface HealthSnapshot {
  ref: string
  base_url: string
  model: string
  protocol: string
  status: string
  transport_status: string
  behavior_status: string
  consecutive_failures: number
  cooldown_seconds: number
  cooldown_until_ts: number
  last_error: string
  error_kind: string
  last_seen: string
  success_count: number
  failure_count: number
  /** 手动「测试端点」探测记录（仅展示，不参与运行时熔断）。 */
  probe_status?: string
  probe_at?: string
  probe_error?: string
  probe_latency_ms?: number
}

/** 工作目录统计。 */
export interface WorkdirStats {
  root: string
  total_bytes: number
  total_files: number
  max_bytes: number
  usage_ratio: number
  tasks: Array<{
    task_id: string
    task_name?: string
    bytes: number
    files: number
    updated_at?: string
  }>
}

/** 备份状态。 */
export interface BackupStatus {
  backup_dir: string
  snapshots: Array<{ name: string; bytes: number; created_at: string }>
  last_backup_at: string | null
  auto_backup: boolean
  interval_hours: number
  keep: number
  total_bytes: number
}

/** 更新检查结果。 */
export interface UpdateCheck {
  enabled: boolean
  current_version: string
  latest_version: string
  has_update: boolean
  branch: string
  release_url: string
  changelog: string
  [key: string]: unknown
}

/** 通用批量置顶返回。 */
export interface BatchTopResult {
  success_count: number
  failed_ids: string[]
}

/** 模型列表返回。 */
export interface ModelListResult {
  models: string[]
  error?: string
  ok?: boolean
  [key: string]: unknown
}

/** 中转站（NewAPI / One API 系）余额查询结果。 */
export interface LlmBalanceInfo {
  /** 网关是否提供 billing 兼容接口（Sub2API 等为 false，不是错误）。 */
  supported: boolean
  gateway: string
  hard_limit_usd: number
  used_usd: number
  remaining_usd: number
  /** supported=false 时的原因说明。 */
  detail: string
}

/** 通用操作返回。 */
export interface OkResult {
  ok: boolean
  message?: string
  reason?: string
  [key: string]: unknown
}
