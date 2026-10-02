/**
 * 全局状态（Zustand）。
 *
 * 按 GinBlog 的拆法分成若干独立 store：
 *   useAuthStore —— 鉴权态（令牌、角色、是否开启鉴权）
 *   useUIStore   —— 界面偏好（侧边栏折叠、事件噪音开关、壁纸）
 *
 * 只有需要跨页面共享的状态才放这里；页面内部数据一律用组件局部 state，
 * 避免把列表数据塞进全局 store 造成无谓的全局重渲染。
 */
import { create } from 'zustand'
import { publicApi, userApi } from '@/api'
import { bootstrapTokenFromCookie, getToken, removeToken, setToken } from '@/utils/auth'
import { UI_DEFAULTS, applyChrome, prefsFromApi, prefsToApi } from '@/utils/uiTheme'
import type { UiPrefs } from '@/utils/uiTheme'
import type { Role } from '@/types'

// ------------------------------------------------------------ 鉴权

interface AuthState {
  /** 本地令牌。 */
  token: string
  /** 当前角色。 */
  role: Role
  /** 用户名（登录时后端回填）。 */
  username: string
  /** 服务端是否开启了鉴权。 */
  authEnabled: boolean
  /** 是否已从服务端取回鉴权状态（用于避免首屏误判）。 */
  ready: boolean
  /** 连续登录失败次数（服务端按来源 IP 统计，本地不自行计数）。 */
  loginFailures: number
  /** 是否必须输入验证码（失败满 3 次后由服务端置位）。 */
  captchaRequired: boolean
  /** 拉取鉴权状态。 */
  load: () => Promise<Role>
  /** 账号密码登录；仅在服务端要求验证码时传 captcha。 */
  login: (password: string, username: string, captcha?: CaptchaAnswer) => Promise<Role>
  /** 退出登录。 */
  logout: () => Promise<void>
  /** 是否具备写权限。 */
  canWrite: () => boolean
  /** 是否为观摩角色（敏感信息需脱敏）。 */
  isObserver: () => boolean
}

/** 验证码答案（id 与用户输入的 4 位数字）。 */
export interface CaptchaAnswer {
  id: string
  code: string
}

/** 从登录失败负载中同步登录守卫状态（服务端为准）。 */
function syncLoginGuard(error: unknown, set: (partial: Partial<AuthState>) => void): void {
  const payload = (error as { payload?: unknown })?.payload
  if (!payload || typeof payload !== 'object') return
  const record = payload as Record<string, unknown>
  if (record.login_failures === undefined && record.captcha_required === undefined) return
  set({
    loginFailures: Number(record.login_failures ?? 0),
    captchaRequired: !!record.captcha_required
  })
}

/** 把任意值收敛为合法角色。 */
function normalizeRole(role: unknown): Role {
  if (role === 'full' || role === 'readonly' || role === 'observer') return role
  return 'none'
}

bootstrapTokenFromCookie()

export const useAuthStore = create<AuthState>((set, get) => ({
  token: getToken(),
  role: 'none',
  username: '',
  authEnabled: true,
  ready: false,
  loginFailures: 0,
  captchaRequired: false,

  load: async () => {
    try {
      const status = await publicApi.authStatus()
      // 未开启鉴权时，服务端直接视为 full。
      const role = status.auth_enabled ? normalizeRole(status.role) : 'full'
      set({
        role,
        username: status.username || '',
        authEnabled: !!status.auth_enabled,
        ready: true,
        loginFailures: status.login_failures ?? 0,
        captchaRequired: !!status.captcha_required
      })
      return role
    } catch {
      set({ ready: true })
      return get().role
    }
  },

  login: async (password, username, captcha) => {
    try {
      const res = await publicApi.login(password, username, captcha)
      setToken(res.token)
      const role = normalizeRole(res.role)
      // 登录成功即清零守卫状态，与后端的 ClearLoginFailures 对齐。
      set({
        token: getToken(),
        role,
        username: res.username || username,
        ready: true,
        loginFailures: 0,
        captchaRequired: false
      })
      return role
    } catch (error) {
      // 失败次数与「是否需要验证码」都由服务端裁决，这里只做同步。
      syncLoginGuard(error, (partial) => set(partial))
      throw error
    }
  },

  logout: async () => {
    try {
      await publicApi.logout()
    } catch {
      /* 忽略登出接口失败，本地状态仍然清理 */
    }
    removeToken()
    set({ token: '', role: 'none', username: '' })
  },

  canWrite: () => get().role === 'full',
  isObserver: () => get().role === 'observer'
}))

// ------------------------------------------------------------ 界面偏好

interface UIState {
  /** 侧边栏是否折叠。 */
  collapsed: boolean
  /** 看板是否显示噪音事件（心跳、轮询类）。 */
  verboseEvents: boolean
  /** 当前壁纸地址（为空使用默认渐变）。 */
  wallpaper: string
  /** 壁纸类型：none / file / url。 */
  wallpaperKind: string
  /** 明暗主题：light / dark（由设置页写入，直接驱动 <html data-theme>）。 */
  theme: string
  /** 主题色色相 0–360。 */
  accentHue: number
  /** 壁纸铺满方式：cover / contain。 */
  wallpaperFit: string
  /** 背景明暗 0.08–0.62。 */
  wallpaperDim: number
  /** 背景图原始地址（url 类型时使用）。 */
  wallpaperUrl: string
  /** 是否已向服务端取过一次外观（避免首屏用默认值做判断）。 */
  appearanceLoaded: boolean
  toggleCollapsed: () => void
  setVerboseEvents: (value: boolean) => void
  setWallpaper: (kind: string, url: string) => void
  /** 更新外观（局部字段即可），立即生效。 */
  setAppearance: (next: Partial<UiPrefs>) => void
  /**
   * 把当前外观整段提交给服务端。
   *
   * ⚠️ 后端 `SaveSettings` 对 UI 段是**整段替换**（`settings.UI = *update.UI`），
   * 所以这里必须发全 6 个字段；只发 `{theme}` 会把色相/壁纸/明暗一次性清零。
   */
  persistAppearance: () => Promise<void>
  /** 启动时从服务端拉一次外观偏好。 */
  loadAppearance: () => Promise<void>
}

/** 壁纸类型 → 可用的图片地址。 */
function resolveWallpaperSrc(kind: string, url: string): string {
  // kind=file 必须指向图片原文件端点；/api/settings/ui/wallpaper 是 JSON 信息接口，
  // 指向它 background-image 拿到的是 JSON → 壁纸「永远没反应」。
  if (kind === 'file') return '/api/settings/ui/wallpaper/raw'
  if (kind === 'url') return url
  return ''
}

const UI_PREF_KEY = 'aisrc-ui-pref'

/** 从本地恢复界面偏好。 */
function loadUIPref(): { collapsed: boolean; verboseEvents: boolean } {
  try {
    const raw = localStorage.getItem(UI_PREF_KEY)
    if (!raw) return { collapsed: false, verboseEvents: false }
    const parsed = JSON.parse(raw) as { collapsed?: boolean; verboseEvents?: boolean }
    return { collapsed: !!parsed.collapsed, verboseEvents: !!parsed.verboseEvents }
  } catch {
    return { collapsed: false, verboseEvents: false }
  }
}

/** 持久化界面偏好。 */
function saveUIPref(state: { collapsed: boolean; verboseEvents: boolean }): void {
  try {
    localStorage.setItem(UI_PREF_KEY, JSON.stringify(state))
  } catch {
    /* 忽略隐私模式下的写入失败 */
  }
}

const initialPref = loadUIPref()

/** 外观的本地缓存键：仅作启动首帧用，服务端始终为准。 */
const APPEARANCE_KEY = 'aisrc-ui-appearance'

/** 读取本地缓存的外观，避免首屏闪一下默认配色。 */
function loadAppearanceCache(): UiPrefs {
  try {
    const raw = localStorage.getItem(APPEARANCE_KEY)
    if (!raw) return { ...UI_DEFAULTS }
    return prefsFromApi(JSON.parse(raw) as Record<string, unknown>)
  } catch {
    return { ...UI_DEFAULTS }
  }
}

/** 写本地缓存（服务端保存成功后调用）。 */
function saveAppearanceCache(prefs: UiPrefs): void {
  try {
    localStorage.setItem(APPEARANCE_KEY, JSON.stringify(prefs))
  } catch {
    /* 忽略隐私模式下的写入失败 */
  }
}

const cachedAppearance = loadAppearanceCache()

export const useUIStore = create<UIState>((set, get) => ({
  collapsed: initialPref.collapsed,
  verboseEvents: initialPref.verboseEvents,
  wallpaper: resolveWallpaperSrc(cachedAppearance.wallpaperKind, cachedAppearance.wallpaperUrl),
  wallpaperKind: cachedAppearance.wallpaperKind,
  theme: cachedAppearance.theme,
  accentHue: cachedAppearance.accentHue,
  wallpaperFit: cachedAppearance.wallpaperFit,
  wallpaperDim: cachedAppearance.wallpaperDim,
  wallpaperUrl: cachedAppearance.wallpaperUrl,
  appearanceLoaded: false,

  toggleCollapsed: () => {
    const collapsed = !get().collapsed
    set({ collapsed })
    saveUIPref({ collapsed, verboseEvents: get().verboseEvents })
  },

  setVerboseEvents: (value) => {
    set({ verboseEvents: value })
    saveUIPref({ collapsed: get().collapsed, verboseEvents: value })
  },

  setWallpaper: (kind, url) =>
    set({ wallpaperKind: kind, wallpaperUrl: url, wallpaper: resolveWallpaperSrc(kind, url) }),

  setAppearance: (next) => {
    const s = get()
    const merged: UiPrefs = {
      theme: next.theme ?? s.theme,
      accentHue: next.accentHue ?? s.accentHue,
      wallpaperKind: next.wallpaperKind ?? s.wallpaperKind,
      wallpaperUrl: next.wallpaperUrl ?? s.wallpaperUrl,
      wallpaperFit: next.wallpaperFit ?? s.wallpaperFit,
      wallpaperDim: next.wallpaperDim ?? s.wallpaperDim
    }
    applyChrome(merged)
    set({
      theme: merged.theme,
      accentHue: merged.accentHue,
      wallpaperFit: merged.wallpaperFit,
      wallpaperDim: merged.wallpaperDim,
      wallpaperKind: merged.wallpaperKind,
      wallpaperUrl: merged.wallpaperUrl,
      wallpaper: resolveWallpaperSrc(merged.wallpaperKind, merged.wallpaperUrl)
    })
    saveAppearanceCache(merged)
  },

  persistAppearance: async () => {
    const s = get()
    const prefs: UiPrefs = {
      theme: s.theme,
      accentHue: s.accentHue,
      wallpaperKind: s.wallpaperKind,
      wallpaperUrl: s.wallpaperUrl,
      wallpaperFit: s.wallpaperFit,
      wallpaperDim: s.wallpaperDim
    }
    await userApi.updateSettings({ ui: prefsToApi(prefs) })
  },

  loadAppearance: async () => {
    try {
      const res = await userApi.getSettings()
      const ui = (res as unknown as { ui?: Record<string, unknown> }).ui || {}
      // setAppearance 内部会 applyChrome + 写缓存
      get().setAppearance(prefsFromApi(ui))
    } catch {
      /* 服务端不可达时沿用本地缓存 */
    } finally {
      set({ appearanceLoaded: true })
    }
  }
}))
