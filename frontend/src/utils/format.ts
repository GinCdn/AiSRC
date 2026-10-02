/**
 * 格式化工具。
 *
 * 后端时间统一为带时区的 ISO8601 字符串（东八区 +08:00 或 UTC 的 Z），
 * 这里统一按【浏览器本地时区】渲染，保证不同时区的使用者看到自己的时间。
 */

/** 补零。 */
function pad(n: number): string {
  return String(n).padStart(2, '0')
}

/** 把 ISO 时间字符串格式化为本地 `YYYY-MM-DD HH:mm:ss`。 */
export function fmtLocalTime(iso?: string | null): string {
  if (!iso) return '-'
  const s = String(iso).trim()
  const hasTz = /[zZ]|[+-]\d{2}:\d{2}$/.test(s)
  const d = new Date(hasTz ? s : `${s}Z`)
  if (Number.isNaN(d.getTime())) return s.slice(0, 19).replace('T', ' ')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes()
  )}:${pad(d.getSeconds())}`
}

/** 相对时间（如「3 分钟前」）。 */
export function fmtRelativeTime(iso?: string | null): string {
  if (!iso) return '-'
  const s = String(iso).trim()
  const hasTz = /[zZ]|[+-]\d{2}:\d{2}$/.test(s)
  const d = new Date(hasTz ? s : `${s}Z`)
  if (Number.isNaN(d.getTime())) return '-'
  const diff = Date.now() - d.getTime()
  if (diff < 0) return fmtLocalTime(iso)
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return `${sec} 秒前`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min} 分钟前`
  const hour = Math.floor(min / 60)
  if (hour < 24) return `${hour} 小时前`
  const day = Math.floor(hour / 24)
  if (day < 30) return `${day} 天前`
  return fmtLocalTime(iso)
}

/** 字节数格式化。 */
export function fmtBytes(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let idx = 0
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024
    idx += 1
  }
  return `${value >= 100 || idx === 0 ? Math.round(value) : value.toFixed(1)} ${units[idx]}`
}

/** 千分位数字。 */
export function fmtNumber(value?: number | null): string {
  if (value === null || value === undefined) return '0'
  return value.toLocaleString('zh-CN')
}

/** 截断长文本。 */
export function truncate(text?: string | null, limit = 120): string {
  if (!text) return ''
  const s = String(text)
  return s.length > limit ? `${s.slice(0, limit)}…` : s
}

/** 安全 JSON 序列化（用于展示 payload）。 */
export function prettyJSON(value: unknown): string {
  try {
    return JSON.stringify(value ?? {}, null, 2)
  } catch {
    return String(value ?? '')
  }
}

/** 严重级别 → Ant Design 颜色。 */
export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'orange',
  low: 'blue',
  info: 'default',
  严重: 'red',
  高危: 'volcano',
  中危: 'orange',
  低危: 'blue',
  信息: 'default',
}

/** 严重级别中文名。 */
export const SEVERITY_LABEL: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

/** 任务状态中文名。 */
export const TASK_STATUS_LABEL: Record<string, string> = {
  running: '运行中',
  idle: '空闲',
  paused: '已暂停',
  stopped: '已停止',
  created: '未启动',
}

/** 任务状态 → Ant Design Badge 状态。 */
export const TASK_STATUS_BADGE: Record<string, 'success' | 'processing' | 'warning' | 'default' | 'error'> = {
  running: 'processing',
  idle: 'success',
  paused: 'warning',
  stopped: 'error',
  created: 'default',
}

/** 目标状态中文名。 */
export const TARGET_STATUS_LABEL: Record<string, string> = {
  queued: '待扫描',
  assigned: '已派发',
  scanning: '扫描中',
  done: '已完成',
  skipped: '已跳过',
  dead: '已放弃',
}

/** 引擎中文名。 */
export const ENGINE_LABEL: Record<string, string> = {
  fofa: 'FOFA',
  quake: '360 Quake',
  hunter: 'Hunter',
  zoomeye: 'ZoomEye',
  shodan: 'Shodan',
  censys: 'Censys',
}

/** 审核结论中文名。 */
export const VERDICT_LABEL: Record<string, string> = {
  accepted: '通过',
  ignored: '忽略',
  deepen: '需深化',
  superseded: '已被取代',
}

/** 用户复审状态中文名。 */
export const USER_STATUS_LABEL: Record<string, string> = {
  pending: '待复审',
  passed: '已通过',
  rejected: '已驳回',
  deepening: '深化中',
}

/** 漏洞类型中文名。 */
/**
 * 漏洞类型取值 → 中文展示名。
 * 取值与原版 AutoHunter 的 VULN_OPTIONS 完全一致，同时兼容历史短码别名。
 */
export const VULN_TYPE_LABEL: Record<string, string> = {
  sql_injection: 'SQL 注入',
  rce: '命令执行',
  code_exec: '代码执行',
  file_inclusion: '文件包含',
  directory_traversal: '目录遍历',
  file_read: '任意文件读取',
  unauthorized_access: '未授权',
  idor: '水平越权',
  privilege_escalation: '垂直越权',
  file_upload: '文件上传',
  captcha_bypass: '验证码绕过',
  backdoor_compromised: '已控后门',
  weak_password: '弱口令',
  info_leak: '敏感信息泄露',
  xss: 'XSS',
  csrf: 'CSRF',
  ssrf: 'SSRF',
  xxe: 'XXE',
  deserialization: '反序列化',
  component_vuln: '组件漏洞',
  business_logic: '业务逻辑漏洞',
  // 历史别名（后端早期版本或 LLM 自由输出时可能出现的取值）
  sqli: 'SQL 注入',
  upload: '文件上传',
  unauth: '未授权访问',
  跨站脚本: 'XSS',
  info: '信息泄露',
  weakpass: '弱口令',
  logic: '业务逻辑',
  other: '其他',
}

/** 漏洞类型取值列表的展示名（用于表格单元格）。 */
export const VULN_OPTIONS_WITH_LABEL = [
  { value: 'sql_injection', label: 'SQL 注入' },
  { value: 'rce', label: '命令执行' },
  { value: 'code_exec', label: '代码执行' },
  { value: 'file_inclusion', label: '文件包含' },
  { value: 'directory_traversal', label: '目录遍历' },
  { value: 'file_read', label: '任意文件读取' },
  { value: 'unauthorized_access', label: '未授权' },
  { value: 'idor', label: '水平越权' },
  { value: 'privilege_escalation', label: '垂直越权' },
  { value: 'file_upload', label: '文件上传' },
  { value: 'captcha_bypass', label: '验证码绕过' },
  { value: 'backdoor_compromised', label: '已控后门' },
  { value: 'weak_password', label: '弱口令' },
  { value: 'info_leak', label: '敏感信息泄露' },
  { value: 'xss', label: 'XSS' },
  { value: 'csrf', label: 'CSRF' },
  { value: 'ssrf', label: 'SSRF' },
  { value: 'xxe', label: 'XXE' },
  { value: 'deserialization', label: '反序列化' },
  { value: 'component_vuln', label: '组件漏洞' },
  { value: 'business_logic', label: '业务逻辑漏洞' }
]

/** 引擎名兜底。 */
export function engineLabel(engine?: string): string {
  if (!engine) return ''
  return ENGINE_LABEL[engine] || engine
}

/** 任务来源文案。 */
export function targetSourceLabel(task?: { target_source?: string; engine?: string } | null): string {
  if (!task) return '-'
  const source = task.target_source
  const eng = engineLabel(task.engine)
  if (source === 'manual') return '手动清单'
  if (source === 'site') return '单站协作'
  if (source === 'both') return eng ? `${eng}+手动` : '测绘+手动'
  if (source === 'fofa') return eng || '测绘搜集'
  return source || '-'
}

/** 任务范围文案。 */
export function taskScopeText(task?: {
  target_source?: string
  fofa_query?: string
  manual_targets?: string[]
} | null): string {
  if (!task) return '-'
  if (task.target_source === 'site') {
    return task.fofa_query || task.manual_targets?.[0] || '单站协作'
  }
  return task.fofa_query || '手动清单'
}
