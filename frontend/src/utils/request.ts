/**
 * Axios 请求封装。
 *
 * 与后端约定（与原版 AutoHunter 逐字段一致）：
 *  - 成功：HTTP 200 + 数据本体（裸 JSON 对象或数组），没有外层包装；
 *  - 失败：真实 HTTP 状态码（400/401/403/404/409/500/507）+ { "detail": "错误说明" }。
 *
 * 因此响应拦截器只负责把错误转成统一的 ApiError 并弹出提示，
 * 业务数据由 request() 原样透传。
 */
import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios'
import { message } from 'antd'
import { getToken, removeToken } from './auth'

/** 业务侧抛出的错误，携带 HTTP 状态码便于上层分支处理。 */
export class ApiError extends Error {
  code: number
  /**
   * 后端返回的原始错误负载。
   *
   * 契约主体是 `{ detail }`，但部分是超集（如登录失败附带
   * `captcha_required` / `login_failures`）。调用方需要读这些引导字段时
   * 就从这里取，不必再单独发一次请求。
   */
  payload?: unknown

  constructor(code: number, msg: string, payload?: unknown) {
    super(msg)
    this.name = 'ApiError'
    this.code = code
    this.payload = payload
  }
}

/** 读取错误负载里的一个字段（安全取值，类型不符时返回 undefined）。 */
export function payloadField<T = unknown>(error: unknown, key: string): T | undefined {
  if (error instanceof ApiError && error.payload && typeof error.payload === 'object') {
    return (error.payload as Record<string, unknown>)[key] as T
  }
  return undefined
}

const instance: AxiosInstance = axios.create({
  baseURL: '',
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// 401 处理回调由 store 注入，避免 request 层直接依赖路由。
let unauthorizedHandler: (() => void) | null = null

/** 注册 401 处理器（登录弹窗 / 跳转登录页）。 */
export function setUnauthorizedHandler(handler: () => void): void {
  unauthorizedHandler = handler
}

instance.interceptors.request.use(
  (config) => {
    const token = getToken()
    if (token) {
      // 后端优先识别 X-Aisrc-Token；同时带 Bearer 以兼容标准网关。
      config.headers['X-Aisrc-Token'] = token
      config.headers['X-Autohunter-Token'] = token
      config.headers.Authorization = `Bearer ${token}`
    }
    // FormData / URLSearchParams 由 axios 自动设置 Content-Type
    if (config.data instanceof FormData || config.data instanceof URLSearchParams) {
      delete config.headers['Content-Type']
    }
    return config
  },
  (error) => Promise.reject(error)
)

instance.interceptors.response.use(
  (response) => {
    // 二进制响应（下载备份）直接透传，不做业务码校验。
    if (response.config.responseType === 'blob') {
      return response
    }
    // 兜底兼容可能存在的 { code, msg, data } 包装（当前后端已不使用）。
    const res = response.data as unknown
    if (res && typeof res === 'object' && !Array.isArray(res)) {
      const record = res as Record<string, unknown>
      if (typeof record.code === 'number' && record.code !== 200) {
        const msg = typeof record.msg === 'string' && record.msg ? record.msg : '请求失败'
        // 同 401 分支：未登录态下的提示由登录弹窗表达。
        const muted = record.code === 401 && !getToken()
        if (!(response.config as RequestConfig).silent && !muted) {
          message.error(msg)
        }
        if (record.code === 401) {
          removeToken()
          unauthorizedHandler?.()
        }
        return Promise.reject(new ApiError(record.code, msg, res))
      }
    }
    return response
  },
  (error) => {
    const silent = (error.config as RequestConfig | undefined)?.silent
    const status: number | undefined = error.response?.status
    const detail = extractDetail(error.response?.data)
    // 登录接口的 401 是「账号密码错误」，不是会话过期：
    // 不能清令牌、也不能触发跳转登录页，否则弹窗会被自己的失败请求顶掉。
    const isLoginCall = String(error.config?.url || '').includes('/api/auth/login')

    let msg = '网络异常，请检查网络连接'
    // 是否跳过 toast：未登录态下的 401 无需再提示（登录弹窗已表达），
    // 登录失败的具体原因也已在弹窗内展示。
    let muted = false
    if (status) {
      switch (status) {
        case 401:
          if (!isLoginCall) {
            // 先看请求是否带了会话：没带说明本就没登录，只是弹窗在等输入。
            const hadToken = !!getToken()
            removeToken()
            unauthorizedHandler?.()
            msg = detail || '未登录或登录已过期'
            muted = !hadToken
          } else {
            msg = detail || '账号或密码错误'
            muted = true
          }
          break
        case 403:
          msg = detail || '无权限执行该操作'
          break
        case 404:
          msg = detail || '请求的资源不存在'
          break
        case 405:
          msg = detail || '请求方法不被允许'
          break
        case 409:
          msg = detail || '资源状态冲突'
          break
        case 429:
          msg = detail || '请求过于频繁，请稍后再试'
          break
        case 507:
          msg = detail || '服务器磁盘空间不足'
          break
        default:
          msg = detail || (status >= 500 ? '服务器内部错误' : `请求失败(${status})`)
      }
    } else if (error.message?.includes('timeout')) {
      msg = '请求超时，请稍后重试'
    }
    if (!silent && !muted) {
      message.error(msg)
    }
    return Promise.reject(new ApiError(status ?? 0, msg, error.response?.data))
  }
)

/** 从后端错误体中提取可读信息：优先 detail，其次 msg，最后裸文本。 */
export function extractDetail(payload: unknown): string {
  if (typeof payload === 'string') {
    return payload.trim()
  }
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>
    if (typeof record.detail === 'string') return record.detail
    if (typeof record.msg === 'string') return record.msg
    if (typeof record.error === 'string') return record.error
  }
  return ''
}

/** 扩展 axios 配置：silent 用于关闭默认错误提示。 */
export interface RequestConfig extends AxiosRequestConfig {
  silent?: boolean
}

/** 统一请求入口，返回后端返回的数据本体。 */
export function request<T = unknown>(config: RequestConfig): Promise<T> {
  return instance(config).then((res) => {
    // 二进制下载由调用方自行处理（返回原始响应以便读取响应头文件名）。
    if (config.responseType === 'blob') {
      return res as unknown as T
    }
    return res.data as T
  })
}

export default request
