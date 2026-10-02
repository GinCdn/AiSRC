/**
 * 剪贴板与文件导出工具（对标原版 frontend/src/clipboard.js）。
 *
 * 之所以单独抽出来：原版这份是 BoardView / SettingsView 共用的，
 * 还原版此前各页各写一份（且 SettingsView 那份缺少非安全上下文降级），
 * 导致「复制 LLM 真实错误」「导出 .md」等能力整体缺失。
 */

/** 复制文本到剪贴板，带非安全上下文 / 权限被拒的降级路径。 */
export async function copyText(text: string): Promise<boolean> {
  const value = String(text ?? '')
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch {
      /* 走下面的降级分支：HTTP、权限被拒、内嵌上下文都会落到这里 */
    }
  }

  try {
    const ta = document.createElement('textarea')
    ta.value = value
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.left = '-9999px'
    ta.style.top = '0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    ta.setSelectionRange(0, ta.value.length)
    try {
      const ok = document.execCommand('copy')
      if (!ok) throw new Error('execCommand copy returned false')
      return true
    } finally {
      document.body.removeChild(ta)
    }
  } catch {
    return false
  }
}

/** 下载指定文件名与内容的文本文件。 */
export function downloadNamedFile(filename: string, text: string, mime: string): void {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

/** 该事件是否属于「LLM 调用异常」，需要给用户一个复制入口。 */
export function isLlmErrorEvent(ev: Record<string, unknown> = {}): boolean {
  const k = String(ev.kind || '')
  if (k.startsWith('llm_') || k === 'worker_auto_finish' || k === 'quota_stop') return true
  const text = `${ev.message || ''} ${ev._text || ''} ${ev.error || ''}`
  return k === 'target_requeued' && /LLM|额度|配额|不可用/.test(text)
}

/** 把 LLM 错误事件格式化成可直接粘贴给运维/模型的诊断文本。 */
export function formatLlmErrorCopy(ev: Record<string, unknown> = {}): string {
  const s = (v: unknown) => (v === undefined || v === null ? '' : String(v))
  if (ev.error_copy) {
    const head = [
      ev.kind ? `event=${s(ev.kind)}` : '',
      ev.model ? `model=${s(ev.model)}` : '',
      ev.base_url ? `base_url=${s(ev.base_url)}` : '',
      ev.ts ? `time=${s(ev.ts)}` : ''
    ].filter(Boolean)
    return [...head, String(ev.error_copy)].join('\n')
  }
  const lines: string[] = []
  if (ev.kind) lines.push(`kind=${s(ev.kind)}`)
  if (ev.ts) lines.push(`time=${s(ev.ts)}`)
  if (ev.model) lines.push(`model=${s(ev.model)}`)
  if (ev.base_url) lines.push(`base_url=${s(ev.base_url)}`)
  if (ev.error_kind) lines.push(`error_kind=${s(ev.error_kind)}`)
  if (ev.status !== undefined && ev.status !== null && ev.status !== '') lines.push(`status=${s(ev.status)}`)
  if (ev.code) lines.push(`code=${s(ev.code)}`)
  const summary = s(ev._text || ev.message)
  if (summary) lines.push(`message=${summary}`)
  if (ev.error && ev.error !== summary) lines.push(`error=${s(ev.error)}`)
  if (ev.detail) lines.push(`detail=${s(ev.detail)}`)
  if (ev.diagnostic) lines.push(`diagnostic=${s(ev.diagnostic)}`)
  if (ev.summary && ev.summary !== summary) lines.push(`summary=${s(ev.summary)}`)
  return lines.join('\n') || summary || s(ev.kind)
}

/** 把 LLM 端点测试结果格式化成可复制文本。 */
export function formatLlmTestCopy(test: Record<string, unknown> = {}): string {
  if (test.error_copy) return String(test.error_copy)
  const parts: string[] = [`LLM ${test.ok ? '可用' : '不可用'}`]
  if (test.error) parts.push(String(test.error))
  for (const item of (test.results as Record<string, unknown>[]) || []) {
    parts.push(
      String(
        item.error_copy ||
          [
            `ok=${item.ok}`,
            `name=${item.name || '-'}`,
            `model=${item.model || '-'}`,
            `base_url=${item.base_url || '-'}`,
            `status_code=${item.status_code || 0}`,
            item.error ? `error=${item.error}` : '',
            item.tool_calling ? `tool_calling=${item.tool_calling}` : ''
          ]
            .filter(Boolean)
            .join('\n')
      )
    )
  }
  return parts.filter(Boolean).join('\n\n')
}
