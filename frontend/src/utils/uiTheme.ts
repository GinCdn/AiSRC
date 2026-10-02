/**
 * 外观偏好（对标原版 frontend/src/uiTheme.js）。
 *
 * ⚠️ 字段名一律用后端契约的 camelCase：`accentHue / wallpaperKind / wallpaperUrl /
 * wallpaperFit / wallpaperDim`。后端 `model.UISettings` 的 json tag 就是 camelCase，
 * 早期还原版这里写成了 snake_case，导致 PUT 出去的值被 encoding/json 静默丢弃
 * （连 `saved:true` 都照回，但一个字段都没存进去）。
 */

/** 主题色预设（色相 h）。 */
export const ACCENT_PRESETS: Array<{ h: number; name: string }> = [
  { h: 235, name: '青蓝' },
  { h: 175, name: '青绿' },
  { h: 85, name: '琥珀' },
  { h: 25, name: '珊瑚' },
  { h: 310, name: '紫' },
  { h: 255, name: '靛' }
]

/** 外观默认值。 */
export const UI_DEFAULTS = {
  theme: 'light',
  accentHue: 235,
  wallpaperKind: 'none',
  wallpaperUrl: '',
  wallpaperFit: 'cover',
  wallpaperDim: 0.28
}

/** 外观偏好。 */
export interface UiPrefs {
  theme: string
  accentHue: number
  wallpaperKind: string
  wallpaperUrl: string
  wallpaperFit: string
  wallpaperDim: number
}

/** 色相夹取到 0–360。 */
export function clampHue(h: unknown): number {
  const n = Number(h)
  if (!Number.isFinite(n)) return UI_DEFAULTS.accentHue
  return Math.max(0, Math.min(360, Math.round(n)))
}

/** 背景明暗夹取：>=0.65 视为脏数据回默认，其余落 0.08–0.62。 */
export function clampDim(d: unknown): number {
  const n = Number(d)
  if (!Number.isFinite(n)) return UI_DEFAULTS.wallpaperDim
  if (n >= 0.65) return UI_DEFAULTS.wallpaperDim
  return Math.max(0.08, Math.min(0.62, n))
}

/** 服务端返回 → 本地偏好（含夹取与白名单）。 */
export function prefsFromApi(ui: Record<string, unknown> = {}): UiPrefs {
  return {
    theme: ui.theme === 'dark' ? 'dark' : 'light',
    accentHue: clampHue(ui.accentHue),
    wallpaperKind: ['none', 'url', 'file'].includes(String(ui.wallpaperKind))
      ? String(ui.wallpaperKind)
      : 'none',
    wallpaperUrl: typeof ui.wallpaperUrl === 'string' ? ui.wallpaperUrl.trim() : '',
    wallpaperFit: ui.wallpaperFit === 'contain' ? 'contain' : 'cover',
    wallpaperDim: clampDim(ui.wallpaperDim)
  }
}

/** 本地偏好 → 提交给服务端的载荷（camelCase，与服务端 json tag 对齐）。 */
export function prefsToApi(prefs: UiPrefs): Record<string, unknown> {
  return {
    theme: prefs.theme,
    accentHue: clampHue(prefs.accentHue),
    wallpaperKind: prefs.wallpaperKind,
    wallpaperUrl: prefs.wallpaperUrl || '',
    wallpaperFit: prefs.wallpaperFit,
    wallpaperDim: clampDim(prefs.wallpaperDim),
    saved: true
  }
}

/** 十六进制颜色 → 色相（自定义取色器用）。 */
export function hexToHue(hex: string, fallback = UI_DEFAULTS.accentHue): number {
  const m = String(hex || '')
    .trim()
    .match(/^#?([0-9a-f]{6})$/i)
  if (!m) return fallback
  const n = parseInt(m[1], 16)
  const r = ((n >> 16) & 255) / 255
  const g = ((n >> 8) & 255) / 255
  const b = (n & 255) / 255
  const max = Math.max(r, g, b)
  const min = Math.min(r, g, b)
  if (max - min < 0.08) return fallback
  const d = max - min
  let h = 0
  if (max === r) h = (g - b) / d + (g < b ? 6 : 0)
  else if (max === g) h = (b - r) / d + 2
  else h = (r - g) / d + 4
  return Math.round(h * 60) % 360
}

/** 色相 → 十六进制颜色（取色器回显用，与原版同一套 HSL→RGB 参数）。 */
export function hueToHex(h: number): string {
  const hue = clampHue(h) / 360
  const a = (p: number, q: number, t: number) => {
    let tt = t
    if (tt < 0) tt += 1
    if (tt > 1) tt -= 1
    if (tt < 1 / 6) return p + (q - p) * 6 * tt
    if (tt < 1 / 2) return q
    if (tt < 2 / 3) return p + (q - p) * (2 / 3 - tt) * 6
    return p
  }
  const q = 0.62
  const p = 0.28
  const r = Math.round(a(p, q, hue + 1 / 3) * 255)
  const g = Math.round(a(p, q, hue) * 255)
  const b = Math.round(a(p, q, hue - 1 / 3) * 255)
  return `#${[r, g, b].map((x) => x.toString(16).padStart(2, '0')).join('')}`
}

/** 把外观偏好写进 <html> 的 CSS 变量与 data 属性（全局主题色的唯一落点）。 */
export function applyChrome(prefs: Pick<UiPrefs, 'theme' | 'accentHue' | 'wallpaperFit' | 'wallpaperDim'>): void {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  root.setAttribute('data-theme', prefs.theme === 'dark' ? 'dark' : 'light')
  root.style.setProperty('--accent-h', String(clampHue(prefs.accentHue)))
  root.style.setProperty('--wallpaper-dim', String(clampDim(prefs.wallpaperDim)))
  root.style.setProperty('--wallpaper-fit', prefs.wallpaperFit === 'contain' ? 'contain' : 'cover')
}
