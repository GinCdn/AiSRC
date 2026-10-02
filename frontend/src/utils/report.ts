/**
 * 报告构建（对标原版 frontend/src/report.js）。
 *
 * 此前还原版没有这个模块，只有 ReportDrawer 内部一个简化的 buildReportMd，
 * 因此「复制 EduSRC JSON」「导出 reports.json」「导出全部 .md」整块能力缺失。
 * 这里按原版逐字对齐，并把 ReportDrawer 也切过来，避免"报告写疑似 / 抽屉写较可信"两处措辞打架。
 */
import type { FindingView } from '@/types'

/** 信度标签单一真相。 */
export const CONF: Record<string, string> = { confirmed: '确认', likely: '疑似', uncertain: '不确定' }

const LEVEL_MAP: Record<string, string> = { 严重: 'grave', 高危: 'high', 中危: 'medium', 低危: 'low' }

const CATEGORY_MAP: Record<string, number> = {
  SQL注入漏洞: 1,
  文件上传漏洞: 2,
  代码执行漏洞: 3,
  命令执行漏洞: 4,
  XSS漏洞: 5,
  CSRF漏洞: 6,
  SSRF漏洞: 7,
  点击劫持漏洞: 8,
  弱口令: 9,
  敏感信息泄露: 10,
  其他漏洞: 13,
  任意文件读取: 14,
  任意文件下载: 15,
  未授权访问: 16,
  逻辑缺陷: 17,
  '疑似被黑/存在后门': 18,
  AI漏洞: 19
}

/** 宽泛取值：任意对象转 Record。 */
function rec(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

/** 宽泛转字符串。 */
function s(v: unknown, fallback = ''): string {
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return fallback
}

/** 取生效值：用户编辑 > 原始。 */
function eff(f: FindingView, key: string): unknown {
  const e = rec(f.review?.user_edits)
  const v = e[key]
  if (v !== undefined && v !== null && v !== '') return v
  return rec(f)[key]
}

/**
 * 生效严重级（报告与抽屉共用的单一真相）。
 *
 * 原版 report.js 只认 `review.user_severity / review.severity_final`，
 * 遇到「审核已给出 severity_final、但用户尚未复审」的漏洞会渲染成 "-"；
 * 这里补齐 user_severity / severity / severity_final 的回退链，
 * 让报告与抽屉不会出现「抽屉有等级、报告却是 -」的打架。
 */
export function effectiveSeverity(f: FindingView): string {
  const rv = rec(f.review)
  return (
    s(rv.user_severity) ||
    s(rv.severity_final) ||
    s(rec(f).user_severity) ||
    s(rec(f).severity_final) ||
    s(rec(f).severity) ||
    '-'
  )
}

function slugPart(value: unknown): string {
  const text = String(value ?? '')
    .trim()
    .toLowerCase()
  const slug = text.replace(/[^a-z0-9\u4e00-\u9fff]+/g, '-').replace(/^-+|-+$/g, '')
  return slug || 'target'
}

/** FNV-1a 32bit，与原版一致（保证同一漏洞生成的 id 稳定）。 */
function shortHash(value: unknown): string {
  const text = String(value ?? '')
  let h = 2166136261
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

function firstNumber(values: unknown[], fallback: number): number {
  for (const value of values) {
    const n = Number(value)
    if (Number.isFinite(n) && n > 0) return n
  }
  return fallback
}

function inferCategoryName(f: FindingView): string {
  const text = `${s(f.vuln_type)} ${s(eff(f, 'title'))}`.toLowerCase()
  if (/sql|sqli|注入/.test(text)) return 'SQL注入漏洞'
  if (/upload|file_upload|文件上传/.test(text)) return '文件上传漏洞'
  if (/command|cmd|命令执行/.test(text)) return '命令执行漏洞'
  if (/rce|code|ssti|deserialize|反序列化|代码执行/.test(text)) return '代码执行漏洞'
  if (/xss|跨站/.test(text)) return 'XSS漏洞'
  if (/csrf/.test(text)) return 'CSRF漏洞'
  if (/ssrf/.test(text)) return 'SSRF漏洞'
  if (/clickjacking|点击劫持/.test(text)) return '点击劫持漏洞'
  if (/weak|password|弱口令|默认口令/.test(text)) return '弱口令'
  if (/download|任意文件下载/.test(text)) return '任意文件下载'
  if (/read|lfi|path|traversal|任意文件读取|路径穿越/.test(text)) return '任意文件读取'
  if (/info|leak|disclosure|sensitive|data|数据|泄露/.test(text)) return '敏感信息泄露'
  if (/logic|payment|captcha|业务|逻辑|验证码/.test(text)) return '逻辑缺陷'
  if (/ai|prompt|llm/.test(text)) return 'AI漏洞'
  return '未授权访问'
}

/** 去掉 AI 步骤文本自带的序号前缀（"1. " / "2、" / "3)" 等），渲染层统一编号，避免「1. 1.」双重编号。 */
export function stripStepIndex(text: string): string {
  return text
    .replace(/^\s*步骤\s*\d{1,2}\s*[.、．)）:：]?\s*/, '')
    .replace(/^\s*\d{1,2}\s*[.、．)）:：]\s*/, '')
}

/** 复现步骤兼容两种形态：字符串，或 {title, detail} 对象（FindingStep）。 */
function stepLines(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  return raw.map((item) => {
    if (typeof item === 'string') return stripStepIndex(item)
    const r = rec(item)
    return stripStepIndex(s(r.title) || s(r.detail))
  })
}

/** 报告正文（Markdown）。 */
export function buildReportCoreMd(f: FindingView): string {
  const raw = rec(f)
  const rv = rec(f.review)
  const sev = effectiveSeverity(f)
  const conf = CONF[s(rv.confidence)] || s(rv.confidence) || '-'
  const title = s(eff(f, 'title'))
  const desc = s(eff(f, 'description'))
  const scope = s(eff(f, 'affected_scope'))
  const steps = stepLines(raw.steps)
  const poc = s(eff(f, 'poc'))
  // 归属单位：优先 ip138 标记（高校/单位）> worker 判定的 owner
  const owner = s(raw.edu_school).trim() || s(raw.owner) || '-'
  const proof = s(raw.owner_proof).trim()

  // 证据数据样本（worker 取样的小表格 / 工具输出 / 备注），有才渲染
  const ev = rec(raw.evidence)
  const evParts: string[] = []
  if (ev.extracted_data_sample) evParts.push(`**数据样本**\n\n${s(ev.extracted_data_sample)}`)
  if (ev.tool_output) evParts.push(`**工具输出**\n\n\`\`\`\n${s(ev.tool_output)}\n\`\`\``)
  if (ev.notes) evParts.push(`**说明**\n\n${s(ev.notes)}`)
  const evBlock = evParts.length ? `\n## 证据数据\n\n${evParts.join('\n\n')}\n` : ''

  // 攻击链路：怎么一步步打下来的（侦察→定位→利用→取证）
  const chainRaw = Array.isArray(raw.kill_chain) ? raw.kill_chain : []
  const chain = chainRaw
    .map((item) => rec(item))
    .filter((item) => s(item.method))
  let chainBlock = ''
  if (chain.length) {
    const flow = chain.map((item) => s(item.method)).join(' → ')
    const detail = chain
      .map((item, i) => `${i + 1}. **${s(item.method)}**${item.detail ? ` — ${s(item.detail)}` : ''}`)
      .join('\n')
    chainBlock = `\n## 攻击链路\n\n\`${flow}\`\n\n${detail}\n`
  }

  return `# ${title}

| 项目 | 内容 |
| --- | --- |
| **漏洞等级** | ${sev}（${rv.score ?? '-'} / 10） |
| **信度** | ${conf} |
| **漏洞类型** | \`${s(f.vuln_type)}\` |
| **归属单位** | ${owner} |
${proof ? `| **归属证明** | ${proof} |\n` : ''}| **目标 URL** | ${s(f.target_url)} |

## 漏洞描述

${desc || '-'}

## 影响范围

${scope || '-'}

## 复现步骤

${steps.map((item, i) => `${i + 1}. ${item}`).join('\n') || '-'}

## 验证 PoC

\`\`\`bash
${poc || '-'}
\`\`\`

## 证据链

**原始请求**

\`\`\`http
${s(raw.raw_request) || '-'}
\`\`\`

**原始响应**

\`\`\`http
${s(raw.raw_response) || '-'}
\`\`\`
${evBlock}## AI 审核结论

> ${s(rv.reviewer_notes, '-').replace(/\n/g, '\n> ')}
${rv.user_notes ? `\n## 人工复审备注\n\n${s(rv.user_notes)}` : ''}
${chainBlock}`
}

/** 生成 EduSRC 结构化 JSON（油猴脚本可用）。 */
export function buildEdusrcReportJson(f: FindingView, content: string): Record<string, unknown> {
  const raw = rec(f)
  const rv = rec(f.review)
  const categoryName = inferCategoryName(f)
  // 归属单位：优先 ip138 标记 > worker 判定的 owner
  const eduSchool = s(raw.edu_school).trim()
  const owner = (eduSchool || s(raw.owner) || s(rec(rv.user_edits).owner)).trim()
  const firmName = owner && owner !== '-' ? owner : '待填写单位'
  // EduSRC JSON 标题只写学校名（查不到才退回漏洞标题）
  const title =
    firmName !== '待填写单位'
      ? firmName
      : s(eff(f, 'title')) || s(raw.title) || 'AiSRC 漏洞报告'
  const edits = rec(rv.user_edits)
  const edusrcMeta = rec(rec(raw.evidence).edusrc)
  const firmId = firstNumber([edits.firm_id, edusrcMeta.firm_id, raw.firm_id], 0)
  const companyId = firstNumber([edits.company_id, edusrcMeta.company_id, raw.company_id], 3)
  const level = LEVEL_MAP[effectiveSeverity(f)] || 'medium'
  return {
    id: `aisrc-${slugPart(raw.vuln_type)}-${shortHash(`${s(raw.id)}|${s(raw.target_url)}|${title}`)}`,
    vuln_type: s(raw.vuln_type) || 'custom',
    title,
    category: CATEGORY_MAP[categoryName] || CATEGORY_MAP['未授权访问'],
    level,
    firm_id: firmId,
    firm_name: firmName,
    company_id: companyId,
    credentials: 'False',
    url: s(raw.target_url),
    content
  }
}

/** 油猴脚本用的单条 reports.json 条目。 */
export function buildEdusrcToolReport(f: FindingView): Record<string, unknown> {
  return buildEdusrcReportJson(f, buildReportCoreMd(f))
}

/** 完整报告：正文 + EDUSRC 自动填充 JSON。 */
export function buildReportMd(f: FindingView): string {
  const core = buildReportCoreMd(f)
  const edusrcJson = buildEdusrcToolReport(f)
  return `${core}

## EDUSRC 自动填充 JSON

> 可粘贴到 \`edusrc-tool\` 油猴脚本"导入报告"里；\`firm_id\` 默认为 0，提交前按 EDUSRC 单位搜索结果补全；\`company_id\` 未识别时默认为 3（其他厂商），不要写死具体开发商。

\`\`\`\`json
${JSON.stringify(edusrcJson, null, 2)}
\`\`\`\``
}
