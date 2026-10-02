/**
 * 目标凭据绑定（auth bindings）共享逻辑。
 *
 * 新建任务（CreateView）与编辑任务（TaskEditModal）需要完全一致的
 * 「默认 * 绑定 + 按手动目标清单生成下拉选项 + 增删 + 导出时过滤空行」行为，
 * 这里抽成单一实现，避免两处漂移。
 */
import { useCallback, useMemo, useState } from 'react'
import type { AuthBinding } from '@/types'

/** 生成一条空绑定。 */
export function emptyBinding(): AuthBinding {
  return {
    target: '*',
    raw: '',
    username: '',
    password: '',
    cookie: '',
    authorization: '',
    login_url: '',
    note: ''
  }
}

/** 手动目标多行文本 → 去空行后的清单。 */
export function manualTargetLines(manualTargets: string): string[] {
  return String(manualTargets || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
}

export interface AuthBindingsApi {
  authBindings: AuthBinding[]
  setAuthBindings: (list: AuthBinding[]) => void
  addBinding: () => void
  removeBinding: (index: number) => void
  updateBinding: (index: number, patch: Partial<AuthBinding>) => void
  /** 绑定目标下拉选项：* 与手动目标清单。 */
  bindingOptions: Array<{ value: string; label: string }>
  /** 导出为提交给后端的紧凑结构（过滤全空行）。 */
  exportAuthBindings: () => AuthBinding[]
}

/**
 * @param manualTargets 当前「手动目标清单」的多行文本
 */
export function useAuthBindings(manualTargets: string): AuthBindingsApi {
  const [authBindings, setAuthBindings] = useState<AuthBinding[]>([emptyBinding()])

  const bindingOptions = useMemo(() => {
    const opts = [{ value: '*', label: '*（全部目标默认）' }]
    manualTargetLines(manualTargets).forEach((line) => opts.push({ value: line, label: line }))
    return opts
  }, [manualTargets])

  const addBinding = useCallback(() => {
    setAuthBindings((prev) => [...prev, emptyBinding()])
  }, [])

  const removeBinding = useCallback((index: number) => {
    setAuthBindings((prev) => {
      const next = prev.filter((_, i) => i !== index)
      return next.length ? next : [emptyBinding()]
    })
  }, [])

  const updateBinding = useCallback((index: number, patch: Partial<AuthBinding>) => {
    setAuthBindings((prev) => prev.map((item, i) => (i === index ? { ...item, ...patch } : item)))
  }, [])

  const exportAuthBindings = useCallback(
    () =>
      authBindings
        .map((b) => ({
          target: (b.target || '*').trim() || '*',
          username: (b.username || '').trim(),
          password: (b.password || '').trim(),
          cookie: (b.cookie || '').trim(),
          authorization: (b.authorization || '').trim(),
          login_url: (b.login_url || '').trim(),
          raw: (b.raw || '').trim(),
          note: (b.note || '').trim()
        }))
        .filter((b) => b.username || b.password || b.cookie || b.authorization || b.raw),
    [authBindings]
  )

  return {
    authBindings,
    setAuthBindings,
    addBinding,
    removeBinding,
    updateBinding,
    bindingOptions,
    exportAuthBindings
  }
}
