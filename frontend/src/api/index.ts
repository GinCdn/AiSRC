/**
 * 接口封装。按 GinBlog 的三段式风格组织：
 *   publicApi  —— 无需鉴权（健康检查、关于、登录、鉴权状态）
 *   userApi    —— 需要鉴权（任务、漏洞、情报、代理、设置、日志、备份、更新）
 *   systemApi  —— 流式与二进制等特殊通道（SSE / 下载 / 表单上传）
 *
 * 说明：后端与原版 AutoHunter 接口契约一致 —— 成功返回数据本体（裸 JSON），
 * 失败返回真实 HTTP 状态码 + { detail }；request 层负责错误提示与归一化，
 * 因此这里直接声明返回数据的类型。
 */
import request, { extractDetail, type RequestConfig } from '@/utils/request'
import { getToken } from '@/utils/auth'
import type {
  AboutInfo,
  AuthStatus,
  BackupStatus,
  BatchTopResult,
  BoardData,
  CaptchaInfo,
  EngineSettingsView,
  FofaSettingsView,
  Finding,
  FindingView,
  HealthInfo,
  HealthSnapshot,
  Intel,
  Killsweep,
  ListResult,
  LlmSettingsView,
  LoginResult,
  LlmBalanceInfo,
  ModelListResult,
  OkResult,
  PageResult,
  ProxyItem,
  ProxySettingsView,
  Result,
  Review,
  RuntimeLog,
  SettingsView,
  Target,
  Task,
  TaskEvent,
  TraceEntry,
  UpdateCheck,
  WorkdirStats
} from '@/types'

/** 过滤空值并拼装查询串。 */
export function qs(params: Record<string, unknown> = {}): string {
  const s = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') s.set(k, String(v))
  })
  const out = s.toString()
  return out ? `?${out}` : ''
}

/** 把双形态列表统一收敛成 { items, total, hasMore }。 */
export function toListResult<T>(res: ListResult<T>): { items: T[]; total: number; hasMore: boolean } {
  if (Array.isArray(res)) {
    return { items: res, total: res.length, hasMore: false }
  }
  const page = res as PageResult<T>
  return { items: page.items || [], total: page.total || 0, hasMore: !!page.has_more }
}

// ------------------------------------------------------------ publicApi

export const publicApi = {
  /** 健康探针。 */
  health: (config?: RequestConfig) => request<HealthInfo>({ url: '/api/health', method: 'GET', ...config }),
  /** 关于信息。 */
  about: () => request<AboutInfo>({ url: '/api/about', method: 'GET' }),
  /** 鉴权状态（未登录也可访问）。 */
  authStatus: (config?: RequestConfig) =>
    request<AuthStatus>({ url: '/api/auth/status', method: 'GET', silent: true, ...config }),
  /** 图形验证码（后端随机生成 4 位；明文不下发，只回图片）。 */
  captcha: () => request<CaptchaInfo>({ url: '/api/auth/captcha', method: 'GET', silent: true }),
  /**
   * 账号密码登录。
   *
   * captcha 仅在连续失败达阈值（默认 3 次）后必传；其余时候传了也会被忽略。
   */
  login: (password: string, username: string, captcha?: { id: string; code: string }) =>
    request<LoginResult>({
      url: '/api/auth/login',
      method: 'POST',
      // 登录失败由弹窗自行展示（含验证码切换），这里关掉全局 toast 避免重复提示。
      silent: true,
      data: {
        password,
        username,
        captcha_id: captcha?.id || '',
        captcha_code: captcha?.code || ''
      }
    }),
  /** 退出登录。 */
  logout: () => request<OkResult>({ url: '/api/auth/logout', method: 'POST' })
}

// ------------------------------------------------------------ userApi

export const userApi = {
  // ---------------- 任务
  listTasks: () => request<Task[]>({ url: '/api/tasks', method: 'GET' }),
  createTask: (data: Partial<Task>) => request<Task>({ url: '/api/tasks', method: 'POST', data }),
  getTask: (id: string) => request<Task>({ url: `/api/tasks/${id}`, method: 'GET' }),
  updateTask: (id: string, data: Partial<Task>) =>
    request<Task>({ url: `/api/tasks/${id}`, method: 'PATCH', data }),
  /** 删除任务：按当前登录身份提交，后端 `requireWrite` 校验写权限。 */
  deleteTask: (id: string) => request<OkResult>({ url: `/api/tasks/${id}`, method: 'DELETE' }),
  startTask: (id: string) => request<Task>({ url: `/api/tasks/${id}/start`, method: 'POST' }),
  pauseTask: (id: string) => request<Task>({ url: `/api/tasks/${id}/pause`, method: 'POST' }),
  stopTask: (id: string) => request<Task>({ url: `/api/tasks/${id}/stop`, method: 'POST' }),
  taskModels: (id: string, data: Record<string, unknown> = {}) =>
    request<ModelListResult>({ url: `/api/tasks/${id}/models`, method: 'POST', data, silent: true }),
  taskTop: (id: string, isTop: boolean) =>
    request<OkResult>({ url: `/api/tasks/${id}/top`, method: 'PATCH', data: { is_top: isTop } }),
  taskBatchTop: (ids: string[], isTop: boolean) =>
    request<BatchTopResult>({ url: '/api/tasks/batch/top', method: 'PATCH', data: { ids, is_top: isTop } }),

  // ---------------- 看板与目标
  board: (id: string, opts: Record<string, unknown> = {}) =>
    request<BoardData>({ url: `/api/tasks/${id}/board${qs(opts)}`, method: 'GET' }),
  targets: (id: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<Target>>({ url: `/api/tasks/${id}/targets${qs(opts)}`, method: 'GET' }),
  hosts: (id: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<Target>>({ url: `/api/tasks/${id}/hosts${qs(opts)}`, method: 'GET' }),
  skipTarget: (taskId: string, targetId: string, reason = '') =>
    request<OkResult>({
      url: `/api/tasks/${taskId}/targets/${targetId}/skip`,
      method: 'POST',
      data: { reason }
    }),
  rescanTarget: (taskId: string, targetId: string) =>
    request<OkResult>({
      url: `/api/tasks/${taskId}/targets/${targetId}/rescan`,
      method: 'POST'
    }),
  injectDirective: (taskId: string, targetId: string, directive: string) =>
    request<OkResult>({
      url: `/api/tasks/${taskId}/targets/${targetId}/directive`,
      method: 'POST',
      data: { directive }
    }),
  targetTrace: (taskId: string, targetId: string, limit = 200) =>
    request<TraceEntry[]>({
      url: `/api/tasks/${taskId}/targets/${targetId}/trace${qs({ limit })}`,
      method: 'GET'
    }),
  cancelEscalation: (taskId: string, findingId: string, reason = '') =>
    request<OkResult>({
      url: `/api/tasks/${taskId}/escalations/${findingId}/cancel`,
      method: 'POST',
      data: { reason }
    }),

  // ---------------- 漏洞 / 复审
  findings: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/findings${qs(opts)}`, method: 'GET' }),
  results: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/results${qs(opts)}`, method: 'GET' }),
  deepenList: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/deepen-list${qs(opts)}`, method: 'GET' }),
  reviewQueue: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/review-queue${qs(opts)}`, method: 'GET' }),
  submitList: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/submit-list${qs(opts)}`, method: 'GET' }),
  rejectedList: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/rejected${qs(opts)}`, method: 'GET' }),
  archivedList: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/tasks/${taskId}/archived${qs(opts)}`, method: 'GET' }),
  getFinding: (id: string) =>
    request<FindingView & { review?: Review }>({ url: `/api/findings/${id}`, method: 'GET' }),
  updateResult: (findingId: string, data: Record<string, unknown>) =>
    request<FindingView>({ url: `/api/results/${findingId}`, method: 'PATCH', data }),
  restoreResult: (findingId: string) =>
    request<OkResult>({ url: `/api/results/${findingId}/restore`, method: 'POST' }),
  deepenResult: (findingId: string, directive: string) =>
    request<OkResult>({ url: `/api/results/${findingId}/deepen`, method: 'POST', data: { directive } }),
  killsweeps: (taskId: string, opts: Record<string, unknown> = {}) =>
    request<ListResult<Killsweep>>({ url: `/api/tasks/${taskId}/killsweeps${qs(opts)}`, method: 'GET' }),
  invalidateKillsweep: (taskId: string, killsweepId: string, reason: string) =>
    request<OkResult>({
      url: `/api/tasks/${taskId}/killsweeps/${killsweepId}/invalidate`,
      method: 'POST',
      data: { reason }
    }),
  retryKillsweep: (taskId: string, killsweepId: string) =>
    request<OkResult>({
      url: `/api/tasks/${taskId}/killsweeps/${killsweepId}/retry`,
      method: 'POST'
    }),

  // ---------------- 全局漏洞库
  vulnStats: () => request<Record<string, unknown>>({ url: '/api/vulns/stats', method: 'GET' }),
  vulns: (opts: Record<string, unknown> = {}) =>
    request<ListResult<FindingView>>({ url: `/api/vulns${qs(opts)}`, method: 'GET' }),
  vulnTop: (id: string, isTop: boolean) =>
    request<OkResult>({ url: `/api/vulns/${id}/top`, method: 'PATCH', data: { is_top: isTop } }),
  vulnBatchTop: (ids: string[], isTop: boolean) =>
    request<BatchTopResult>({ url: '/api/vulns/batch/top', method: 'PATCH', data: { ids, is_top: isTop } }),

  // ---------------- 全局情报库
  intelStats: () => request<Record<string, unknown>>({ url: '/api/intel/stats', method: 'GET' }),
  intelList: (opts: Record<string, unknown> = {}) =>
    request<ListResult<Intel>>({ url: `/api/intel${qs(opts)}`, method: 'GET' }),
  previewIntelCurate: (limit?: number) =>
    request<Record<string, unknown>>({ url: `/api/intel/curate${qs({ limit })}`, method: 'GET' }),
  applyIntelCurate: (limit?: number) =>
    request<OkResult>({ url: `/api/intel/curate${qs({ limit })}`, method: 'POST' }),
  deleteIntel: (id: string) => request<OkResult>({ url: `/api/intel/${id}`, method: 'DELETE' }),
  clearIntel: (kind?: string) => request<OkResult>({ url: `/api/intel${qs({ kind })}`, method: 'DELETE' }),

  // ---------------- 运行异常日志
  runtimeLogStats: () => request<Record<string, unknown>>({ url: '/api/runtime-logs/stats', method: 'GET' }),
  runtimeLogs: (opts: Record<string, unknown> = {}) =>
    request<ListResult<RuntimeLog>>({ url: `/api/runtime-logs${qs(opts)}`, method: 'GET' }),

  // ---------------- 代理池
  proxyList: () => request<ProxyItem[]>({ url: '/api/proxy', method: 'GET' }),
  proxyAdd: (data: Partial<ProxyItem>) => request<ProxyItem>({ url: '/api/proxy', method: 'POST', data }),
  proxyUpdate: (id: string, data: Partial<ProxyItem>) =>
    request<ProxyItem>({ url: `/api/proxy/${encodeURIComponent(id)}`, method: 'PUT', data }),
  proxyDelete: (id: string) =>
    request<OkResult>({ url: `/api/proxy/${encodeURIComponent(id)}`, method: 'DELETE' }),
  proxyToggle: (enabled: boolean) =>
    request<OkResult>({ url: '/api/proxy/toggle', method: 'PUT', data: { enabled } }),
  proxyTest: (data: Record<string, unknown> = {}) =>
    request<OkResult>({ url: '/api/proxy/test', method: 'POST', data, silent: true }),

  // ---------------- 全局设置
  getSettings: () => request<SettingsView>({ url: '/api/settings', method: 'GET' }),
  updateSettings: (data: Record<string, unknown>) =>
    request<SettingsView>({ url: '/api/settings', method: 'PUT', data }),
  settingsModels: (data: Record<string, unknown> = {}) =>
    request<ModelListResult>({ url: '/api/settings/models', method: 'POST', data, silent: true }),
  providerHealth: () => request<HealthSnapshot[]>({ url: '/api/settings/provider-health', method: 'GET' }),
  testLLM: (data: Record<string, unknown> = {}) =>
    request<OkResult>({ url: '/api/settings/test-llm', method: 'POST', data, silent: true }),
  kaliTest: (data: Record<string, unknown> = {}) =>
    request<OkResult & { output?: string; latency_ms?: number; error?: string }>({ url: '/api/settings/kali/test', method: 'POST', data, silent: true }),
  llmBalance: (data: Record<string, unknown> = {}) =>
    request<LlmBalanceInfo>({ url: '/api/settings/llm/balance', method: 'POST', data, silent: true }),
  workdirStats: () => request<WorkdirStats>({ url: '/api/settings/workdir/stats', method: 'GET' }),
  workdirCleanup: (retentionDays?: number) =>
    request<OkResult>({
      url: `/api/settings/workdir/cleanup${qs({ retention_days: retentionDays, dry_run: false })}`,
      method: 'POST'
    }),
  wallpaperInfo: () =>
    request<{ kind: string; url: string; exists: boolean }>({
      url: '/api/settings/ui/wallpaper',
      method: 'GET'
    }),
  deleteWallpaper: () => request<OkResult>({ url: '/api/settings/ui/wallpaper', method: 'DELETE' }),

  // ---------------- 备份
  backupStatus: () => request<BackupStatus>({ url: '/api/backup/status', method: 'GET' }),
  backupSnapshot: () => request<OkResult>({ url: '/api/backup/snapshot', method: 'POST' }),

  // ---------------- 在线更新
  checkUpdate: () => request<UpdateCheck>({ url: '/api/update/check', method: 'GET', silent: true }),
  runUpdate: () => request<OkResult>({ url: '/api/update/run', method: 'POST' })
}

/** 供设置页使用的类型别名，避免上层重复 import。 */
export type {
  EngineSettingsView,
  FofaSettingsView,
  LlmSettingsView,
  ProxySettingsView,
  SettingsView,
  TaskEvent,
  Finding,
  Result
}

// ------------------------------------------------------------ systemApi

/** SSE 事件回调。 */
export type SSEHandler = (event: Record<string, unknown>) => void

/**
 * 消费一个 SSE 流式接口（报告助手）。
 * 返回 Promise，在流结束时 resolve；可通过 AbortSignal 主动中断。
 */
async function streamSSE(
  url: string,
  body: Record<string, unknown>,
  onEvent: SSEHandler,
  signal?: AbortSignal
): Promise<void> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (token) {
    headers['X-Aisrc-Token'] = token
    headers['X-Autohunter-Token'] = token
  }
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let parsed: unknown = null
    try {
      parsed = JSON.parse(text)
    } catch {
      /* 非 JSON 错误体，按裸文本处理 */
    }
    throw new Error(extractDetail(parsed) || text || `请求失败(${res.status})`)
  }
  if (!res.body) throw new Error('浏览器不支持流式响应')

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let idx = buffer.indexOf('\n\n')
    while (idx !== -1) {
      const chunk = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)
      chunk.split('\n').forEach((line) => {
        const trimmed = line.startsWith('data:') ? line.slice(5).trim() : ''
        if (!trimmed) return
        try {
          onEvent(JSON.parse(trimmed))
        } catch {
          /* 心跳等非 JSON 行直接忽略 */
        }
      })
      idx = buffer.indexOf('\n\n')
    }
  }
}

/** 触发浏览器下载（用于备份导出）。 */
async function downloadFile(url: string, method = 'POST', fallbackName = 'aisrc-backup.tar.gz'): Promise<void> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) {
    headers['X-Aisrc-Token'] = token
    headers['X-Autohunter-Token'] = token
  }
  const res = await fetch(url, { method, headers })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let parsed: unknown = null
    try {
      parsed = JSON.parse(text)
    } catch {
      /* 非 JSON 错误体，按裸文本处理 */
    }
    throw new Error(extractDetail(parsed) || text || `请求失败(${res.status})`)
  }
  const blob = await res.blob()
  let filename = fallbackName
  const cd = res.headers.get('content-disposition') || ''
  const star = cd.match(/filename\*=UTF-8''([^;]+)/i)
  const plain = cd.match(/filename="?([^";]+)"?/i)
  if (star) filename = decodeURIComponent(star[1])
  else if (plain) filename = plain[1]
  const href = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = href
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(href), 2000)
}

/** 表单上传公共实现。 */
async function uploadForm(url: string, form: FormData): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) {
    headers['X-Aisrc-Token'] = token
    headers['X-Autohunter-Token'] = token
  }
  const res = await fetch(url, { method: 'POST', headers, body: form })
  const text = await res.text()
  if (!res.ok) {
    // 后端错误体固定为 { detail: "..." }（403 时会区分只读 / 观摩令牌）。
    let parsed: unknown = null
    try {
      parsed = JSON.parse(text)
    } catch {
      /* 非 JSON 错误体，下面按裸文本处理 */
    }
    throw new Error(extractDetail(parsed) || text || `请求失败(${res.status})`)
  }
  if (!text) return {}
  try {
    return JSON.parse(text) as Record<string, unknown>
  } catch {
    throw new Error('响应不是合法的 JSON')
  }
}

export const systemApi = {
  /** 报告助手流式对话。 */
  reportAssistantStream: (
    findingId: string,
    message: string,
    onEvent: SSEHandler,
    signal?: AbortSignal
  ) => streamSSE(`/api/findings/${findingId}/assistant/stream`, { message }, onEvent, signal),

  /** 代理批量导入（文本或文件）。 */
  proxyImport: (text: string, file?: File | null) => {
    const form = new FormData()
    if (text) form.append('text', text)
    if (file) form.append('file', file, file.name || 'proxies.txt')
    return uploadForm('/api/proxy/import', form)
  },

  /** 上传界面壁纸。 */
  uploadWallpaper: (file: File) => {
    const form = new FormData()
    form.append('file', file, file.name || 'wallpaper.jpg')
    return uploadForm('/api/settings/ui/wallpaper', form)
  },

  /** 导入（恢复）备份。 */
  restoreBackup: (file: File, includeWork = false) => {
    const form = new FormData()
    form.append('file', file)
    return uploadForm(`/api/backup/restore${qs({ include_work: includeWork })}`, form)
  },

  /** 导出备份并触发下载。 */
  downloadBackupExport: (includeWork = false) =>
    downloadFile(`/api/backup/export${qs({ include_work: includeWork })}`, 'POST'),

  /** 下载指定快照。 */
  downloadBackupSnapshot: (name: string) =>
    downloadFile(`/api/backup/snapshots/${encodeURIComponent(name)}`, 'GET', `${name}.tar.gz`)
}

/** 拼接任务实时事件流的 WebSocket 地址。 */
export function wsUrl(taskId: string): string {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const suffix = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${proto}://${location.host}/api/tasks/${taskId}/stream${suffix}`
}

export default { publicApi, userApi, systemApi }
