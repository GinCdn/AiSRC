/**
 * 令牌本地存储工具。
 *
 * 与 GinBlog 的差异：AiSRC 只有单一身份体系（full / readonly / observer 三角色），
 * 因此只维护一份令牌，不再区分 admin / user 两套。
 */

const TOKEN_KEY = 'aisrc-token'
/** 主 Cookie 名与原版 AutoHunter 一致（ah_api_token），便于两套前端共用令牌。 */
const COOKIE_KEY = 'ah_api_token'
/** 兼容别名：本项目早期版本写入的 Cookie 名。 */
const LEGACY_COOKIE_KEY = 'aisrc_token'

/**
 * 规范化令牌：兼容历史误存的 Bearer 前缀、首尾引号与零宽字符。
 */
export function normalizeToken(token: string | null | undefined): string {
  if (!token) return ''
  let normalized = String(token)
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .trim()
  if (
    (normalized.startsWith('"') && normalized.endsWith('"')) ||
    (normalized.startsWith("'") && normalized.endsWith("'"))
  ) {
    normalized = normalized.slice(1, -1).trim()
  }
  if (/^Bearer\s+/i.test(normalized)) {
    normalized = normalized.replace(/^Bearer\s+/i, '').trim()
  }
  return normalized.replace(/[\r\n\t\s]/g, '')
}

/** 读取令牌（并把旧数据就地修正）。 */
export function getToken(): string {
  const stored = localStorage.getItem(TOKEN_KEY)
  const normalized = normalizeToken(stored)
  if (normalized && normalized !== stored) {
    localStorage.setItem(TOKEN_KEY, normalized)
  }
  return normalized
}

/** 写入令牌，同时同步一份 Cookie（供 <img> 等无法带自定义头的场景使用）。 */
export function setToken(token: string): void {
  const normalized = normalizeToken(token)
  if (!normalized) {
    removeToken()
    return
  }
  localStorage.setItem(TOKEN_KEY, normalized)
  const secure = location.protocol === 'https:' ? '; Secure' : ''
  document.cookie = `${COOKIE_KEY}=${encodeURIComponent(normalized)}; Path=/; SameSite=Strict${secure}`
  document.cookie = `${LEGACY_COOKIE_KEY}=${encodeURIComponent(normalized)}; Path=/; SameSite=Strict${secure}`
}

/** 清除令牌与 Cookie。 */
export function removeToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  document.cookie = `${COOKIE_KEY}=; Path=/; Max-Age=0; SameSite=Strict`
  document.cookie = `${LEGACY_COOKIE_KEY}=; Path=/; Max-Age=0; SameSite=Strict`
}

/** 首次加载时把 Cookie 里的令牌回填到 localStorage（兼容分享链接）。 */
export function bootstrapTokenFromCookie(): void {
  if (localStorage.getItem(TOKEN_KEY)) return
  const matched =
    document.cookie.match(/(?:^|;\s*)ah_api_token=([^;]+)/) ||
    document.cookie.match(/(?:^|;\s*)aisrc_token=([^;]+)/)
  if (matched) {
    localStorage.setItem(TOKEN_KEY, normalizeToken(decodeURIComponent(matched[1])))
  }
}
