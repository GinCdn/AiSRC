/**
 * 新建 / 编辑任务整页（对标 Vue 版 src/views/CreateView.vue，并补上编辑能力）。
 *
 *   /create            → 新建：默认值取自系统设置，提交走 createTask 后跳指挥台
 *   /create/:taskId    → 编辑：回填任务详情，提交走 updateTask
 *
 * 字段组与 TaskEditModal 完全一致，只是改成整页卡片分区呈现：
 *   任务基本信息 / 目标从哪来 / 目标清单与登录凭据 / 额外规则 / 高级（模型·分页·并发）。
 *
 * 与后端约定（同 TaskEditModal）：
 *   - 模型配置在请求/响应体里的键名是 `model_config_data`（React 的 Task 类型里写作 model_config，已兼容读取）；
 *   - 密钥脱敏占位符为 8 个圆点，未改动则省略该字段；
 *   - 模型列表：编辑态 POST /api/tasks/:id/models，新建态 POST /api/settings/models，成功只回 `{ models }`。
 */
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Alert,
  App,
  Button,
  Card,
  Checkbox,
  Col,
  Collapse,
  Input,
  InputNumber,
  Row,
  Segmented,
  Select,
  Skeleton,
  Space,
  Typography
} from 'antd'
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  PlusOutlined,
  ReloadOutlined,
  SaveOutlined
} from '@ant-design/icons'
import { userApi } from '@/api'
import { useAuthStore } from '@/store'
import { emptyBinding, manualTargetLines, useAuthBindings } from '@/hooks/useAuthBindings'
import type { AuthBinding, FofaConfig, TargetSource, Task } from '@/types'
import { SecretPassword } from '@/components/PasswordEye'

// ---------------------------------------------------------------- 常量

/** 密钥脱敏占位符（8 个圆点）。 */
const MASKED_KEY = '••••••••'

/** 漏洞类型选项。 */
const VULN_OPTIONS = [
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

/** 默认全开的漏洞类型。 */
const DEFAULT_VULN_IDS = VULN_OPTIONS.map((o) => o.value)

/** 目标来源选项（标题 + 说明）。 */
const SOURCE_OPTIONS = [
  { value: 'fofa', title: '资产测绘', desc: '用引擎按语法或意图拉一批站' },
  { value: 'manual', title: '手动清单', desc: '自己贴域名 / URL，清理后入队' },
  { value: 'both', title: '测绘 + 手动', desc: '搜到的和你贴的一起打' },
  { value: 'site', title: '单站深挖', desc: '少数 URL 协作，可带登录凭据' }
]

/** 搜索引擎选项。 */
const ENGINE_OPTIONS = [
  { value: '', label: '系统默认' },
  { value: 'fofa', label: 'FOFA' },
  { value: 'quake', label: 'Quake' },
  { value: 'hunter', label: 'Hunter' },
  { value: 'zoomeye', label: 'ZoomEye' },
  { value: 'shodan', label: 'Shodan' },
  { value: 'censys', label: 'Censys' }
]

/** 引擎显示名。 */
const ENGINE_LABEL_MAP: Record<string, string> = {
  fofa: 'FOFA',
  quake: '360 Quake',
  hunter: 'Hunter',
  zoomeye: 'ZoomEye',
  shodan: 'Shodan',
  censys: 'Censys'
}

/** 模型协议选项。 */
const PROTOCOL_OPTIONS = [
  { value: 'auto', label: '自动识别' },
  { value: 'openai_chat', label: 'OpenAI Chat Completions' },
  { value: 'anthropic_messages', label: 'Anthropic Messages' }
]

/** 语法样例（不同用途各一套，与 Vue 蓝本一致）。 */
const QUERY_PLACEHOLDERS: Record<string, string> = {
  fofa: 'title="统一身份认证" && domain=".edu.cn"',
  quake: 'title:"统一身份认证" AND domain:"edu.cn"',
  hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
  zoomeye: 'title="统一身份认证" && country="CN"',
  shodan: 'http.title:"login" hostname:edu.cn',
  censys: 'host.services.http.response.html_title:"Login" and host.dns.names: edu.cn'
}
const QUERY_HINTS: Record<string, string> = {
  fofa: 'title="统一身份认证" && domain=".edu.cn"',
  quake: 'title:"登录" AND domain:"edu.cn"',
  hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
  zoomeye: 'title="login" && country="CN"',
  shodan: 'http.title:"nginx" port:443',
  censys: 'host.dns.names: edu.cn'
}

/** 协作备注里疑似凭据的特征词。 */
const CRED_PATTERN =
  /(账号|帐号|账户|用户名|user(name)?|密码|pass(word|wd)?|cookie|token|authorization|bearer|jsessionid|session|登录态|凭据|凭证)/i

// ---------------------------------------------------------------- 类型

type ModelMode = 'inherit' | 'single' | 'pool'

/** 后端下发的任务级模型配置（键名 model_config_data）。 */
interface RawModelConfig {
  inherit_global?: boolean
  mode?: string
  base_url?: string
  api_key?: string
  api_key_set?: boolean
  key_ref?: string
  model?: string
  protocol?: string
  prompt_version?: string
  providers?: RawProvider[]
}

/** 后端下发的端点池条目。 */
interface RawProvider {
  name?: string
  base_url?: string
  api_key?: string
  api_key_set?: boolean
  api_key_masked?: string
  key_ref?: string
  model?: string
  protocol?: string
  temperature?: number
  weight?: number
  enabled?: boolean
}

/** 端点池编辑行。 */
interface ProviderRow {
  uid: string
  name: string
  base_url: string
  api_key: string
  api_key_set: boolean
  api_key_masked: string
  key_ref: string
  model: string
  protocol: string
  temperature: number
  weight: number
  enabled: boolean
  models: string[]
  modelsLoading: boolean
  modelsError: string
}

/** 表单状态。 */
interface FormState {
  name: string
  src_type: string
  vuln_types: string[]
  src_rules: string
  target_source: TargetSource
  engine: string
  fofa_query: string
  intent_mode: string
  manual_targets: string
  base_url: string
  api_key: string
  api_key_set: boolean
  key_ref: string
  model: string
  protocol: string
  prompt_version: string
  fofa_key: string
  fofa_base_url: string
  max_pages: number
  page_size: number
  concurrency: number
  deepen_cap: number
  auto_killsweep: boolean
  skip_site_recon: boolean
  /** 用户是否手动调过「跳过入口盘点」，调过就不再自动跟随凭据。 */
  skip_recon_touched: boolean
}

/** 系统默认值（「跟随系统」的展示与差异基准）。 */
interface Inherited {
  base_url: string
  model: string
  protocol: string
  prompt_version: string
  fofa_base_url: string
  max_pages: number
  page_size: number
  intent_mode: string
  concurrency: number
  deepen_cap: number
  llm_provider_count: number
  llm_mode: string
  /** 系统端点池原样下发（api_key 为脱敏串，带 key_ref 供任务端点引用）。 */
  llm_providers: RawProvider[]
}

// ---------------------------------------------------------------- 纯函数工具

/** 清洗密钥：脱敏占位与空串统一视为「未修改」。 */
function cleanKey(value: string): string {
  const v = (value || '').trim()
  return v === MASKED_KEY ? '' : v
}

/** 协议收敛到合法值。 */
function normalizeProtocol(protocol?: string): string {
  return protocol === 'openai_chat' || protocol === 'anthropic_messages' || protocol === 'auto'
    ? protocol
    : 'auto'
}

/** 生成端点行的稳定 uid。 */
let uidSeq = 1
function nextUid(): string {
  return `pool-uid-${uidSeq++}`
}

/** 规范化一条端点行。 */
function normalizeProvider(raw: Partial<ProviderRow> = {}, index = 0, temperature = 0.3): ProviderRow {
  return {
    uid: raw.uid || nextUid(),
    name: raw.name || `llm-${index + 1}`,
    base_url: raw.base_url || '',
    api_key: raw.api_key || '',
    api_key_set: !!raw.api_key_set,
    api_key_masked: raw.api_key_masked || '',
    key_ref: raw.key_ref || '',
    model: raw.model || '',
    protocol: normalizeProtocol(raw.protocol),
    temperature: raw.temperature ?? temperature,
    weight: raw.weight ?? 1,
    enabled: raw.enabled !== false,
    models: Array.isArray(raw.models) ? raw.models : [],
    modelsLoading: !!raw.modelsLoading,
    modelsError: raw.modelsError || ''
  }
}

/** 导出端点池提交体。 */
function exportProviders(rows: ProviderRow[]) {
  return rows.map((p, idx) => ({
    name: String(p.name || `llm-${idx + 1}`).trim(),
    base_url: String(p.base_url || '').trim(),
    api_key: cleanKey(p.api_key),
    key_ref: p.key_ref || '',
    model: String(p.model || '').trim(),
    protocol: normalizeProtocol(p.protocol),
    temperature: Number(p.temperature ?? 0.3),
    weight: Math.max(1, Math.min(100, Number(p.weight || 1))),
    enabled: p.enabled !== false
  }))
}

/** 读取后端下发的模型配置（兼容 React 类型里的 model_config 命名）。 */
function readModelConfig(task: Task | null): RawModelConfig {
  if (!task) return {}
  const raw = (task as Task & { model_config_data?: RawModelConfig }).model_config_data
  if (raw && typeof raw === 'object') return raw
  const fallback = task.model_config as unknown as RawModelConfig | undefined
  return fallback && typeof fallback === 'object' ? fallback : {}
}

/** 从 unknown 容器里安全取字符串。 */
function pickString(source: unknown, key: string): string {
  if (!source || typeof source !== 'object') return ''
  const value = (source as Record<string, unknown>)[key]
  return typeof value === 'string' ? value : ''
}

/** 从 unknown 容器里安全取数字。 */
function pickNumber(source: unknown, key: string, fallback: number): number {
  if (!source || typeof source !== 'object') return fallback
  const value = (source as Record<string, unknown>)[key]
  const num = Number(value)
  return Number.isFinite(num) ? num : fallback
}

/** 引擎显示名（空 → 系统默认引擎）。 */
function engineText(engine: string): string {
  return ENGINE_LABEL_MAP[engine] || engine || '系统默认引擎'
}

/** 空表单（新建态默认全选漏洞类型）。 */
function emptyForm(): FormState {
  return {
    name: '',
    src_type: 'edusrc',
    vuln_types: [...DEFAULT_VULN_IDS],
    src_rules: '',
    target_source: 'fofa',
    engine: '',
    fofa_query: '',
    intent_mode: '',
    manual_targets: '',
    base_url: '',
    api_key: '',
    api_key_set: false,
    key_ref: '',
    model: '',
    protocol: 'auto',
    prompt_version: 'legacy',
    fofa_key: '',
    fofa_base_url: '',
    max_pages: 20,
    page_size: 100,
    concurrency: 3,
    deepen_cap: 2,
    auto_killsweep: true,
    skip_site_recon: false,
    skip_recon_touched: false
  }
}

/** 空继承基线。 */
function emptyInherited(): Inherited {
  return {
    base_url: '',
    model: '',
    protocol: 'auto',
    prompt_version: 'legacy',
    fofa_base_url: '',
    max_pages: 20,
    page_size: 100,
    intent_mode: '',
    concurrency: 3,
    deepen_cap: 2,
    llm_provider_count: 0,
    llm_mode: 'single',
    llm_providers: []
  }
}
// ---------------------------------------------------------------- 局部通用组件

/** 带标题与提示的字段壳。 */
function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <Typography.Text>{label}</Typography.Text>
      {children}
      {hint ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {hint}
        </Typography.Text>
      ) : null}
    </div>
  )
}

/** 两列网格。 */
function Grid({ children }: { children: ReactNode }) {
  return <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12 }}>{children}</div>
}

/** 卡片分区标题。 */
function BlockHead({ title, desc }: { title: string; desc?: string }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <Typography.Text strong>{title}</Typography.Text>
      {desc ? (
        <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
          {desc}
        </Typography.Text>
      ) : null}
    </div>
  )
}

interface ModelPickerProps {
  value: string
  models: string[]
  loading?: boolean
  error?: string
  disabled?: boolean
  placeholder?: string
  refreshLabel?: string
  onChange: (value: string) => void
  onRefresh: () => void
}

/** 模型名选择器（等价 Vue 的 LlmModelPicker）。 */
function ModelPicker({
  value,
  models,
  loading,
  error,
  disabled,
  placeholder = 'deepseek-chat',
  refreshLabel = '查询模型',
  onChange,
  onRefresh
}: ModelPickerProps) {
  const list = models.filter(Boolean)
  const [useCustom, setUseCustom] = useState(list.length === 0)

  useEffect(() => {
    if (!list.length) {
      setUseCustom(true)
      return
    }
    setUseCustom(!!value && !list.includes(value))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.join('\u0000'), value])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {list.length && !useCustom ? (
          <Select
            style={{ flex: 1, minWidth: 0 }}
            value={value || undefined}
            disabled={disabled}
            placeholder="请选择模型"
            options={list.map((m) => ({ value: m, label: m }))}
            onChange={(v: string) => onChange(v)}
          />
        ) : (
          <Input
            style={{ flex: 1, minWidth: 0 }}
            value={value}
            disabled={disabled}
            placeholder={placeholder}
            onChange={(e) => onChange(e.target.value)}
          />
        )}
        <Button icon={<ReloadOutlined />} loading={loading} disabled={disabled} onClick={onRefresh}>
          {loading ? '查询中…' : refreshLabel}
        </Button>
        {list.length ? (
          <Button disabled={disabled} onClick={() => setUseCustom((v) => !v)}>
            {useCustom ? '选列表' : '手动输入'}
          </Button>
        ) : null}
      </div>
      {error ? (
        <Typography.Text type="danger" style={{ fontSize: 12 }}>
          {error}
        </Typography.Text>
      ) : list.length ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          已获取 {list.length} 个可用模型，可下拉选择
        </Typography.Text>
      ) : null}
    </div>
  )
}

interface PoolEditorProps {
  taskId: string
  value: ProviderRow[]
  defaults: { base_url: string; model: string; protocol: string }
  onChange: (rows: ProviderRow[]) => void
}

/** 端点池编辑器（等价 Vue 的 LlmPoolEditor）。 */
function ProviderPoolEditor({ taskId, value, defaults, onChange }: PoolEditorProps) {
  const { modal, message } = App.useApp()
  const [selected, setSelected] = useState(0)

  useEffect(() => {
    if (!value.length) setSelected(-1)
    else if (selected < 0 || selected >= value.length) setSelected(0)
  }, [value.length, selected])

  const current = selected >= 0 ? value[selected] : undefined

  function replaceAll(mutator: (rows: ProviderRow[]) => void) {
    const next = value.map((row, idx) => normalizeProvider(row, idx))
    mutator(next)
    onChange(next)
  }

  function patchAt(index: number, patch: Partial<ProviderRow>) {
    if (index < 0 || index >= value.length) return
    onChange(value.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  function patchCurrent(patch: Partial<ProviderRow>) {
    if (selected < 0) return
    patchAt(selected, patch)
  }

  function addProvider() {
    replaceAll((rows) => {
      rows.push(
        normalizeProvider(
          {
            name: `llm-${rows.length + 1}`,
            base_url: defaults.base_url || 'https://api.deepseek.com/v1',
            model: defaults.model || 'deepseek-chat',
            protocol: defaults.protocol || 'auto',
            temperature: 0.3,
            weight: 1,
            enabled: true
          },
          rows.length
        )
      )
      setSelected(rows.length - 1)
    })
  }

  function removeProvider(index: number) {
    const provider = value[index]
    if (!provider) return
    const label = provider.name || provider.model || `端点 #${index + 1}`
    modal.confirm({
      title: '删除模型端点',
      content: `确认删除模型端点「${label}」？`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => {
        replaceAll((rows) => {
          rows.splice(index, 1)
          if (!rows.length) setSelected(-1)
          else if (selected > index) setSelected(selected - 1)
          else if (selected === index) setSelected(Math.min(index, rows.length - 1))
        })
      }
    })
  }

  function moveProvider(index: number, delta: number) {
    const next = index + delta
    if (next < 0 || next >= value.length) return
    replaceAll((rows) => {
      const [row] = rows.splice(index, 1)
      rows.splice(next, 0, row)
      setSelected(next)
    })
  }

  function invalidateKey(patch: Partial<ProviderRow> = {}) {
    patchCurrent({ key_ref: '', api_key_set: false, api_key_masked: '', models: [], modelsError: '', ...patch })
  }

  async function loadModels(index: number) {
    const provider = value[index]
    if (!provider) return
    patchAt(index, { modelsLoading: true, modelsError: '' })
    const payload = {
      base_url: provider.base_url,
      api_key: cleanKey(provider.api_key) || undefined,
      protocol: provider.protocol,
      key_ref: provider.key_ref || undefined,
      model: provider.model
    }
    try {
      const res = taskId ? await userApi.taskModels(taskId, payload) : await userApi.settingsModels(payload)
      const list = Array.isArray(res?.models) ? res.models.filter(Boolean) : []
      if (list.length) {
        const model = !provider.model || !list.includes(provider.model) ? list[0] : provider.model
        patchAt(index, { models: list, modelsLoading: false, modelsError: '', model })
        message.success(`已获取 ${list.length} 个模型`)
      } else {
        patchAt(index, { models: [], modelsLoading: false, modelsError: '未获取到模型列表' })
        message.warning(`端点 #${index + 1} 获取模型失败`)
      }
    } catch (e) {
      const detail = e instanceof Error ? e.message.replace(/^\d+\s*/, '') : ''
      patchAt(index, { models: [], modelsLoading: false, modelsError: detail || '模型列表获取失败' })
      message.warning(`端点 #${index + 1} 获取模型失败`)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <Typography.Text>
          <strong>端点列表</strong>
          <Typography.Text type="secondary"> · {value.length} 个</Typography.Text>
        </Typography.Text>
        <Button size="small" icon={<PlusOutlined />} onClick={addProvider}>
          添加端点
        </Button>
      </Space>

      {!value.length ? (
        <Typography.Text type="secondary">端点池为空，至少添加一个端点。</Typography.Text>
      ) : (
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          {value.map((provider, idx) => (
            <Button
              key={provider.uid}
              block
              size="small"
              type={selected === idx ? 'primary' : 'default'}
              style={{ textAlign: 'left', height: 'auto', padding: '6px 10px' }}
              onClick={() => setSelected(idx)}
            >
              <Space size={8} style={{ width: '100%' }}>
                <span>{provider.name || `llm-${idx + 1}`}</span>
                <Typography.Text style={{ fontSize: 12, opacity: 0.8 }}>
                  {provider.model || '未设置模型'}
                </Typography.Text>
                <Typography.Text style={{ fontSize: 12, opacity: 0.8 }}>
                  {provider.protocol === 'auto'
                    ? 'Auto'
                    : provider.protocol === 'anthropic_messages'
                      ? 'Anthropic'
                      : 'OpenAI'}
                </Typography.Text>
                <Typography.Text style={{ fontSize: 12, opacity: 0.8 }}>
                  权重 {provider.weight || 1}
                </Typography.Text>
                {provider.enabled === false ? (
                  <Typography.Text style={{ fontSize: 12, opacity: 0.8 }}>已停用</Typography.Text>
                ) : null}
              </Space>
            </Button>
          ))}
        </Space>
      )}

      {current ? (
        <div style={{ border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 12 }}>
          <Space style={{ justifyContent: 'space-between', width: '100%', marginBottom: 10 }}>
            <Typography.Text strong>端点 {selected + 1}</Typography.Text>
            <Space size={4}>
              <Button
                size="small"
                icon={<ArrowUpOutlined />}
                title="上移"
                disabled={selected === 0}
                onClick={() => moveProvider(selected, -1)}
              />
              <Button
                size="small"
                icon={<ArrowDownOutlined />}
                title="下移"
                disabled={selected === value.length - 1}
                onClick={() => moveProvider(selected, 1)}
              />
              <Checkbox
                checked={current.enabled !== false}
                onChange={(e) => patchCurrent({ enabled: e.target.checked })}
              >
                启用
              </Checkbox>
              <Button size="small" danger icon={<DeleteOutlined />} onClick={() => removeProvider(selected)} />
            </Space>
          </Space>

          <Grid>
            <Field label="名称">
              <Input
                value={current.name}
                placeholder="primary"
                onChange={(e) => patchCurrent({ name: e.target.value })}
              />
            </Field>
            <Field label="协议">
              <Select
                style={{ width: '100%' }}
                value={current.protocol}
                options={PROTOCOL_OPTIONS}
                onChange={(v: string) => invalidateKey({ protocol: v })}
              />
            </Field>
            <Field label="base_url">
              <Input
                value={current.base_url}
                placeholder="https://api.deepseek.com/v1"
                onChange={(e) => patchCurrent({ base_url: e.target.value })}
              />
            </Field>
            <Field label="api_key">
              <SecretPassword
                value={current.api_key}
                placeholder={current.api_key_set ? '已配置，留空不修改' : 'sk-...'}
                onChange={(e) => patchCurrent({ api_key: e.target.value })}
              />
            </Field>
            <Field label="temperature">
              <InputNumber
                style={{ width: '100%' }}
                min={0}
                max={2}
                step={0.1}
                value={current.temperature}
                onChange={(v) => patchCurrent({ temperature: v ?? 0.3 })}
              />
            </Field>
            <Field label="权重">
              <InputNumber
                style={{ width: '100%' }}
                min={1}
                max={100}
                value={current.weight}
                onChange={(v) => patchCurrent({ weight: v ?? 1 })}
              />
            </Field>
            <Field label="模型名">
              <ModelPicker
                value={current.model}
                models={current.models}
                loading={current.modelsLoading}
                error={current.modelsError}
                onChange={(v) => patchCurrent({ model: v })}
                onRefresh={() => void loadModels(selected)}
              />
            </Field>
          </Grid>
        </div>
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------- 主体

/** 新建 / 编辑任务页。 */
export default function CreateView() {
  const navigate = useNavigate()
  const { taskId } = useParams()
  const { message } = App.useApp()

  const role = useAuthStore((s) => s.role)
  const writable = role === 'full'
  const editMode = !!taskId

  const [form, setForm] = useState<FormState>(emptyForm)
  const [modelMode, setModelMode] = useState<ModelMode>('inherit')
  const [providers, setProviders] = useState<ProviderRow[]>([])
  const [inherited, setInherited] = useState<Inherited>(emptyInherited)
  const [loading, setLoading] = useState(editMode)
  const [submitting, setSubmitting] = useState(false)

  // 单端点模型探测
  const [singleModels, setSingleModels] = useState<string[]>([])
  const [singleModelsLoading, setSingleModelsLoading] = useState(false)
  const [singleModelsError, setSingleModelsError] = useState('')

  // 差异基准：新建态取系统默认值，编辑态取任务原值，用于「只提交改动过的字段」。
  const baselineRef = useRef({
    prompt_version: 'legacy',
    intent_mode: '',
    fofa_base_url: '',
    max_pages: 20,
    page_size: 100
  })

  const {
    authBindings,
    setAuthBindings,
    addBinding,
    removeBinding,
    updateBinding,
    bindingOptions,
    exportAuthBindings
  } = useAuthBindings(form.manual_targets)

  const isSiteMode = form.target_source === 'site'
  const isFofaMode = form.target_source === 'fofa'
  // 测绘条件区（引擎/意图/查询语法）只有资产测绘与测绘+手动需要；
  // 手动清单/单站深挖不搜资产，不该出现这块。
  const showEngineBlock = form.target_source === 'fofa' || form.target_source === 'both'
  const engineIsFofa = !form.engine || form.engine === 'fofa'
  const showAuthBindings = !isFofaMode

  const manualCount = manualTargetLines(form.manual_targets).length
  const vulnCount = form.vuln_types.length
  const recapSource = SOURCE_OPTIONS.find((s) => s.value === form.target_source)?.title || '未选'

  const queryPlaceholder =
    form.intent_mode === 'intent'
      ? form.src_type === 'enterprise'
        ? '例：找某集团 OA/CRM/ERP/API/运维后台资产'
        : '例：找全国高校的统一身份认证登录系统'
      : QUERY_PLACEHOLDERS[form.engine || 'fofa'] || QUERY_PLACEHOLDERS.fofa
  const queryHintSample = QUERY_HINTS[form.engine || 'fofa'] || QUERY_HINTS.fofa

  const singleKeyReady = !!form.key_ref || form.api_key_set || !!cleanKey(form.api_key)

  const recapModel =
    modelMode === 'pool'
      ? '任务端点池'
      : modelMode === 'single'
        ? form.model || '单端点'
        : inherited.llm_mode === 'pool'
          ? `跟随系统 · ${inherited.llm_provider_count} 端点`
          : '跟随系统'

  const recapLine = (() => {
    const bits = [
      form.src_type === 'enterprise' ? '企业 SRC' : 'EduSRC',
      recapSource,
      isSiteMode ? '' : engineText(form.engine),
      `${vulnCount} 类漏洞`
    ]
    if (!isFofaMode && manualCount) bits.push(`${manualCount} 条手动目标`)
    return bits.filter(Boolean).join(' · ')
  })()

  const missingHint = (() => {
    if (!form.name.trim()) return '还差任务名称'
    if (modelMode === 'single' && !singleKeyReady) return '单端点还缺 API Key'
    if ((form.target_source === 'manual' || form.target_source === 'site') && !manualCount) return '还没贴目标清单'
    if ((form.target_source === 'fofa' || form.target_source === 'both') && !form.fofa_query.trim()) return '还没写搜集条件'
    if (!vulnCount) return '至少选一类漏洞'
    return ''
  })()

  function patch(p: Partial<FormState>) {
    setForm((prev) => ({ ...prev, ...p }))
  }

  /** 协作备注 / 凭据区里是否像带了登录凭据。 */
  function looksHasCreds(): boolean {
    if (CRED_PATTERN.test(form.fofa_query || '')) return true
    return exportAuthBindings().length > 0
  }

  // 拉取系统默认值：始终用于「跟随系统」展示；新建态同时作为表单默认值。
  useEffect(() => {
    let alive = true
    void (async () => {
      try {
        const s = await userApi.getSettings()
        if (!alive) return
        const llm = s.llm
        const fofa = s.fofa
        const defaults = s.defaults

        const promptVersion = pickString(defaults, 'worker_prompt_version') || 'legacy'
        const providerCount =
          pickNumber(llm, 'provider_count', 0) ||
          (Array.isArray(llm?.providers) ? llm.providers.length : 0)
        const baseURL = llm?.base_url || ''
        const model = llm?.model || ''
        const protocol = llm?.protocol || 'auto'
        const fofaBaseURL = fofa?.base_url || ''
        const maxPages = fofa?.max_pages ?? 20
        const pageSize = fofa?.page_size ?? 100
        const intentMode = fofa?.default_intent_mode || ''
        const concurrency = defaults?.concurrency ?? 3
        const deepenCap = defaults?.deepen_cap ?? 2

        setInherited({
          base_url: baseURL,
          model,
          protocol,
          prompt_version: promptVersion,
          fofa_base_url: fofaBaseURL,
          max_pages: maxPages,
          page_size: pageSize,
          intent_mode: intentMode,
          concurrency,
          deepen_cap: deepenCap,
          llm_provider_count: providerCount,
          llm_mode: llm?.mode || 'single',
          llm_providers: Array.isArray(llm?.providers) ? llm.providers : []
        })

        if (!editMode) {
          patch({
            base_url: baseURL,
            model,
            protocol,
            key_ref: pickString(llm, 'key_ref'),
            prompt_version: promptVersion,
            fofa_base_url: fofaBaseURL,
            max_pages: maxPages,
            page_size: pageSize,
            intent_mode: intentMode,
            concurrency,
            deepen_cap: deepenCap
          })
          baselineRef.current = {
            prompt_version: promptVersion,
            intent_mode: intentMode,
            fofa_base_url: fofaBaseURL,
            max_pages: Number(maxPages),
            page_size: Number(pageSize)
          }
        }
      } catch {
        /* 设置读取失败时沿用内置默认值 */
      }
    })()
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editMode])

  // 编辑态：拉任务详情回填。
  useEffect(() => {
    if (!editMode || !taskId) return
    let alive = true
    setLoading(true)
    void (async () => {
      try {
        const t = await userApi.getTask(taskId)
        if (!alive) return
        const cfg = readModelConfig(t)
        const fofa: Partial<FofaConfig> = t.fofa_config || {}

        setForm({
          name: t.name || '',
          src_type: t.src_type || 'edusrc',
          vuln_types: Array.isArray(t.vuln_types) ? t.vuln_types.filter(Boolean) : [],
          src_rules: t.src_rules || '',
          target_source: (t.target_source || 'fofa') as TargetSource,
          engine: t.engine || '',
          fofa_query: t.fofa_query || '',
          intent_mode: fofa.intent_mode || '',
          manual_targets: (Array.isArray(t.manual_targets) ? t.manual_targets : []).join('\n'),
          base_url: cfg.base_url || '',
          api_key: cfg.api_key_set ? MASKED_KEY : cfg.api_key || '',
          api_key_set: !!cfg.api_key_set,
          key_ref: cfg.key_ref || '',
          model: cfg.model || '',
          protocol: normalizeProtocol(cfg.protocol),
          prompt_version: cfg.prompt_version || 'legacy',
          fofa_key: fofa.key ? MASKED_KEY : '',
          fofa_base_url: fofa.base_url || '',
          max_pages: fofa.max_pages ?? 20,
          page_size: fofa.page_size ?? 100,
          concurrency: t.concurrency || 3,
          deepen_cap: t.deepen_cap ?? 2,
          auto_killsweep: t.auto_killsweep !== false,
          skip_site_recon: !!fofa.skip_site_recon,
          skip_recon_touched: true
        })

        const rows = Array.isArray(cfg.providers) ? cfg.providers : []
        setProviders(
          rows.map((p, idx) =>
            normalizeProvider(
              {
                name: p.name || `llm-${idx + 1}`,
                base_url: p.base_url || '',
                api_key: p.api_key_set ? MASKED_KEY : p.api_key || '',
                api_key_set: !!p.api_key_set,
                api_key_masked: p.api_key_masked || '',
                key_ref: p.key_ref || '',
                model: p.model || '',
                protocol: p.protocol || 'auto',
                temperature: p.temperature ?? 0.3,
                weight: p.weight ?? 1,
                enabled: p.enabled !== false
              },
              idx
            )
          )
        )
        if (cfg.inherit_global !== false && !rows.length) setModelMode('inherit')
        else if (rows.length > 0 || cfg.mode === 'pool') setModelMode('pool')
        else setModelMode('single')

        const bindings: AuthBinding[] = Array.isArray(t.auth_bindings) ? t.auth_bindings : []
        setAuthBindings(
          bindings.length
            ? bindings.map((b) => ({
                target: b.target || '*',
                raw: b.raw || '',
                username: b.username || '',
                password: b.password || '',
                cookie: b.cookie || '',
                authorization: b.authorization || '',
                login_url: b.login_url || '',
                note: b.note || ''
              }))
            : [emptyBinding()]
        )

        baselineRef.current = {
          prompt_version: cfg.prompt_version || 'legacy',
          intent_mode: fofa.intent_mode || '',
          fofa_base_url: fofa.base_url || '',
          max_pages: Number(fofa.max_pages ?? 20),
          page_size: Number(fofa.page_size ?? 100)
        }
      } catch {
        /* 错误提示已由 request 层统一处理 */
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editMode, taskId])

  // 单站模式：没手动调过开关时，按「是否像带了凭据」自动跟随。
  useEffect(() => {
    if (!isSiteMode || form.skip_recon_touched) return
    patch({ skip_site_recon: looksHasCreds() })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.fofa_query, isSiteMode, authBindings])

  // 切到端点池且池为空时补种子：系统配置是端点池时整池带入（含 key_ref，
  // 运行时按引用取系统已存密钥，无需重新输入）；否则按单端点信息补一条。
  useEffect(() => {
    if (modelMode !== 'pool') return
    setProviders((prev) => {
      if (prev.length) return prev
      const sysPool = (inherited.llm_providers || []).filter((p) => (p.base_url || '').trim() !== '')
      if (inherited.llm_mode === 'pool' && sysPool.length) {
        return sysPool.map((p, idx) =>
          normalizeProvider(
            {
              name: p.name || `llm-${idx + 1}`,
              base_url: p.base_url || '',
              model: p.model || '',
              protocol: p.protocol || 'auto',
              temperature: typeof p.temperature === 'number' ? p.temperature : 0.3,
              weight: typeof p.weight === 'number' ? p.weight : 1,
              enabled: p.enabled !== false,
              // 系统池密钥不落表单：api_key 留空 + api_key_set=true，
              // 提交带 key_ref，后端运行时按引用解析明文。
              api_key: '',
              api_key_set: p.api_key_set === true || (p.key_ref || '') !== '',
              key_ref: p.key_ref || ''
            },
            idx
          )
        )
      }
      return [
        normalizeProvider({
          name: 'llm-1',
          base_url: form.base_url || inherited.base_url || 'https://api.deepseek.com/v1',
          model: form.model || inherited.model || 'deepseek-chat',
          protocol: form.protocol || inherited.protocol || 'auto',
          temperature: 0.3,
          weight: 1,
          enabled: true,
          // 单端点种子引用系统已存密钥（key_ref 由系统设置带入），免重输。
          api_key: '',
          api_key_set: !!form.key_ref,
          key_ref: form.key_ref || ''
        })
      ]
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modelMode, inherited.llm_mode, inherited.llm_providers.length])

  /** 探测单端点可用模型：编辑态走任务级探针，新建态走全局探针。 */
  async function loadSingleModels() {
    setSingleModelsLoading(true)
    setSingleModelsError('')
    const payload = {
      base_url: form.base_url || undefined,
      api_key: cleanKey(form.api_key) || undefined,
      key_ref: form.key_ref || undefined,
      model: form.model || undefined,
      protocol: form.protocol
    }
    try {
      const res = taskId ? await userApi.taskModels(taskId, payload) : await userApi.settingsModels(payload)
      const list = Array.isArray(res?.models) ? res.models.filter(Boolean) : []
      if (list.length) {
        setSingleModels(list)
        setForm((prev) => (!prev.model || !list.includes(prev.model) ? { ...prev, model: list[0] } : prev))
      } else {
        setSingleModels([])
        setSingleModelsError('未获取到模型列表')
      }
    } catch (e) {
      setSingleModels([])
      setSingleModelsError(e instanceof Error && e.message ? e.message.replace(/^\d+\s*/, '') : '模型列表获取失败')
    } finally {
      setSingleModelsLoading(false)
    }
  }

  /** 提交：新建走 createTask，编辑走 updateTask。 */
  async function submit() {
    if (submitting) return
    if (!writable) {
      message.error('当前为只读权限，无法创建或修改任务')
      return
    }
    if (modelMode === 'single' && !singleKeyReady) {
      message.error('单端点模式需要填写模型 api_key（或已有 key_ref）')
      return
    }
    if (modelMode === 'pool') {
      const rows = exportProviders(providers)
      if (!rows.length || rows.some((p) => !p.base_url || !p.model || (!p.api_key && !p.key_ref))) {
        message.error('端点池每个端点都需要名称 / base_url / 模型 / api_key')
        return
      }
    }
    if (!vulnCount) {
      message.error('至少选一类漏洞')
      return
    }

    setSubmitting(true)
    try {
      const baseline = baselineRef.current

      let modelConfig: Record<string, unknown>
      if (modelMode === 'inherit') {
        modelConfig = { inherit_global: true }
      } else if (modelMode === 'pool') {
        modelConfig = { inherit_global: false, providers: exportProviders(providers) }
      } else {
        modelConfig = {
          inherit_global: false,
          base_url: form.base_url,
          model: form.model,
          protocol: form.protocol
        }
        const key = cleanKey(form.api_key)
        if (key) modelConfig.api_key = key
        // 无明文 key 时带 key_ref 引用系统已存密钥（运行时按引用解析）。
        else if (form.key_ref) modelConfig.key_ref = form.key_ref
      }
      if (form.prompt_version !== baseline.prompt_version) modelConfig.prompt_version = form.prompt_version

      const maxPages = Number(form.max_pages) || 20
      const pageSize = Number(form.page_size) || 100
      // max_pages 始终写入，避免任务配置缺省时掉回硬编码默认值。
      const fofaConfig: Partial<FofaConfig> = { max_pages: maxPages }
      if (pageSize !== baseline.page_size) fofaConfig.page_size = pageSize
      if (form.intent_mode !== baseline.intent_mode) fofaConfig.intent_mode = form.intent_mode
      const fofaKey = cleanKey(form.fofa_key)
      if (fofaKey) fofaConfig.key = fofaKey
      if (form.fofa_base_url && form.fofa_base_url !== baseline.fofa_base_url) {
        fofaConfig.base_url = form.fofa_base_url
      }
      if (isSiteMode && form.skip_site_recon) fofaConfig.skip_site_recon = true

      const payload = {
        name: form.name,
        src_type: form.src_type,
        vuln_types: form.vuln_types,
        target_source: form.target_source,
        engine: form.engine,
        fofa_query: form.fofa_query,
        manual_targets: manualTargetLines(form.manual_targets),
        auth_bindings: showAuthBindings ? exportAuthBindings() : [],
        src_rules: form.src_rules,
        concurrency: Number(form.concurrency) || 3,
        deepen_cap: Math.max(0, Math.min(Number(form.deepen_cap) || 0, 10)),
        auto_killsweep: form.auto_killsweep !== false,
        model_config_data: modelConfig,
        // 增量补丁：只带改动过的字段，避免把未动的值覆盖回默认。
        fofa_config: fofaConfig as FofaConfig
      }

      if (editMode && taskId) {
        await userApi.updateTask(taskId, payload)
        message.success('任务参数已保存')
        navigate(`/task/${taskId}`)
      } else {
        const created = await userApi.createTask(payload)
        message.success('任务已创建')
        navigate(`/task/${created.id}`)
      }
    } catch {
      /* 错误提示已由 request 层统一处理 */
    } finally {
      setSubmitting(false)
    }
  }

  const submitLabel = editMode ? '保存修改' : '创建任务'

  return (
    <section className="create-view">
      <header className="page-head">
        <div>
          <h2>{editMode ? '编辑任务' : '新建任务'}</h2>
          <p className="page-sub">
            {editMode
              ? '改完保存即可；运行中的任务会在下一轮调度读取新参数'
              : '先选口径和目标从哪来，填完创建，直接进看板开打'}
          </p>
        </div>
        <Space>
          <Button onClick={() => navigate(-1)}>返回</Button>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            loading={submitting}
            disabled={loading || !writable}
            onClick={() => void submit()}
          >
            {submitting ? '提交中…' : submitLabel}
          </Button>
        </Space>
      </header>

      {!writable ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="当前为只读权限，无法创建或修改任务"
        />
      ) : null}

      {loading ? (
        <Card>
          <Skeleton active paragraph={{ rows: 10 }} />
        </Card>
      ) : (
        <Row gutter={16}>
          <Col xs={24} lg={16}>
            {/* ---------- 任务 ---------- */}
            <Card size="small" style={{ marginBottom: 12 }}>
              <BlockHead title="任务" desc="名称给自己看；口径决定审核红线" />
              <Grid>
                <Field label="任务名称">
                  <Input
                    value={form.name}
                    placeholder={form.src_type === 'enterprise' ? '企业 SRC 批量挖掘' : 'EduSRC 批量挖掘'}
                    onChange={(e) => patch({ name: e.target.value })}
                  />
                </Field>
                <Field label="SRC 口径">
                  <Segmented
                    block
                    value={form.src_type}
                    onChange={(v) => patch({ src_type: String(v) })}
                    options={[
                      { label: 'EduSRC', value: 'edusrc' },
                      { label: '企业 SRC', value: 'enterprise' }
                    ]}
                  />
                </Field>
              </Grid>

              <div style={{ marginTop: 12 }}>
                <Field label="要挖的漏洞" hint="点一下开关。默认全开，收窄范围能更快对准。">
                  <Select
                    mode="tags"
                    style={{ width: '100%' }}
                    value={form.vuln_types}
                    options={VULN_OPTIONS}
                    placeholder="选择或直接输入自定义漏洞类型"
                    onChange={(v: string[]) => patch({ vuln_types: v })}
                  />
                </Field>
              </div>
            </Card>

            {/* ---------- 目标从哪来 ---------- */}
            <Card size="small" style={{ marginBottom: 12 }}>
              <BlockHead title="目标从哪来" desc="这一步决定下面要填什么" />
              <Segmented
                block
                value={form.target_source}
                onChange={(v) => patch({ target_source: String(v) as TargetSource })}
                options={SOURCE_OPTIONS.map((s) => ({ label: s.title, value: s.value }))}
              />
              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 8 }}>
                {SOURCE_OPTIONS.find((s) => s.value === form.target_source)?.desc}
              </Typography.Paragraph>

              {showEngineBlock ? (
                <>
                  <Field label="搜索引擎" hint="Key 在「设置 → 资产测绘」。没配 Key 的引擎搜不到资产。">
                    <Select
                      style={{ width: '100%' }}
                      value={form.engine}
                      options={ENGINE_OPTIONS}
                      onChange={(v: string) => patch({ engine: v })}
                    />
                  </Field>

                  <div style={{ marginTop: 12 }}>
                    <Field label="怎么写条件">
                      <Segmented
                        block
                        value={form.intent_mode}
                        onChange={(v) => patch({ intent_mode: String(v) })}
                        options={[
                          { label: '自动判断', value: '' },
                          { label: '查询语法', value: 'syntax' },
                          { label: '大白话意图', value: 'intent' }
                        ]}
                      />
                    </Field>
                  </div>

                  <div style={{ marginTop: 12 }}>
                    <Field
                      label={form.intent_mode === 'intent' ? '要找什么（大白话）' : '查询语法'}
                      hint={
                        form.intent_mode === 'intent'
                          ? '搜集 Agent 会把意图翻成语法，并按结果逐轮演化。'
                          : `按当前引擎官网语法原样请求，不会改写成别的引擎。示例 ${queryHintSample}`
                      }
                    >
                      <Input.TextArea
                        rows={3}
                        value={form.fofa_query}
                        placeholder={queryPlaceholder}
                        onChange={(e) => patch({ fofa_query: e.target.value })}
                      />
                    </Field>
                  </div>
                </>
              ) : (
                <Field label="协作重点">
                  <Input.TextArea
                    rows={4}
                    value={form.fofa_query}
                    placeholder={'后台位置、重点方向。登录凭据请填下面「登录凭据」。\n例：后台在 /admin，重点测 API、越权、上传。'}
                    onChange={(e) => patch({ fofa_query: e.target.value })}
                  />
                </Field>
              )}
            </Card>

            {/* ---------- 目标清单 + 登录凭据 ---------- */}
            {!isFofaMode ? (
              <Card size="small" style={{ marginBottom: 12 }}>
                <BlockHead
                  title={isSiteMode ? '主目标 URL' : '手动目标清单'}
                  desc={isSiteMode ? '每行一个，会拆成多条协作路线' : '每行一个，可直接粘贴杂乱资产表'}
                />
                <Input.TextArea
                  rows={8}
                  value={form.manual_targets}
                  placeholder={
                    isSiteMode
                      ? 'https://target.example.com/\nhttps://target.example.com/admin 后台'
                      : 'www.example.edu.cn\nhttps://a.example.edu.cn/path?x=1\nhttps://b.example.edu.cn/ 港澳台\n(203.0.113.10)'
                  }
                  onChange={(e) => patch({ manual_targets: e.target.value })}
                />
                <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 6 }}>
                  自动去掉行尾中文备注、括号 IP 入队、裸域名补协议、去重。入队时按根域挂泄露凭据。
                  {manualCount ? ` 已识别 ${manualCount} 条。` : ''}
                </Typography.Paragraph>

                {showAuthBindings ? (
                  <>
                    <div style={{ marginTop: 8, marginBottom: 8 }}>
                      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
                        <Typography.Text strong>登录凭据（可选）</Typography.Text>
                        <Button type="link" size="small" onClick={addBinding}>
                          + 添加一条
                        </Button>
                      </Space>
                      <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 4, marginBottom: 0 }}>
                        不填不影响挖掘。填了会强制尝试：Cookie / Token 注入会话，账密走登录。绑定{' '}
                        <code>*</code> 表示本任务都用。
                      </Typography.Paragraph>
                    </div>

                    <Space direction="vertical" size={8} style={{ width: '100%' }}>
                      {authBindings.map((b, i) => (
                        <div
                          key={i}
                          style={{ border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 12 }}
                        >
                          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', marginBottom: 10 }}>
                            <div style={{ flex: 1 }}>
                              <Field label="绑定目标">
                                <Select
                                  style={{ width: '100%' }}
                                  value={b.target}
                                  options={bindingOptions}
                                  onChange={(v: string) => updateBinding(i, { target: v })}
                                />
                              </Field>
                            </div>
                            <Button danger icon={<DeleteOutlined />} title="删除" onClick={() => removeBinding(i)} />
                          </div>

                          <Field label="快捷粘贴（自动分辨 Cookie / Bearer / 账密）">
                            <Input.TextArea
                              rows={2}
                              value={b.raw}
                              placeholder={'Cookie: JSESSIONID=xxx\nAuthorization: Bearer eyJ...\n账号: test  密码: Test@123'}
                              onChange={(e) => updateBinding(i, { raw: e.target.value })}
                            />
                          </Field>

                          <details style={{ marginTop: 10 }}>
                            <summary style={{ cursor: 'pointer', color: 'var(--aisrc-text-sub)' }}>
                              展开填结构化字段
                            </summary>
                            <div style={{ marginTop: 10 }}>
                              <Grid>
                                <Field label="账号">
                                  <Input
                                    autoComplete="off"
                                    value={b.username}
                                    onChange={(e) => updateBinding(i, { username: e.target.value })}
                                  />
                                </Field>
                                <Field label="密码">
                                  <SecretPassword
                                    autoComplete="new-password"
                                    value={b.password}
                                    onChange={(e) => updateBinding(i, { password: e.target.value })}
                                  />
                                </Field>
                                <Field label="Cookie 串">
                                  <Input
                                    value={b.cookie}
                                    placeholder="JSESSIONID=...; other=..."
                                    onChange={(e) => updateBinding(i, { cookie: e.target.value })}
                                  />
                                </Field>
                                <Field label="Authorization">
                                  <Input
                                    value={b.authorization}
                                    placeholder="Bearer eyJ..."
                                    onChange={(e) => updateBinding(i, { authorization: e.target.value })}
                                  />
                                </Field>
                                <Field label="登录 URL（可选）">
                                  <Input
                                    value={b.login_url}
                                    placeholder="https://host/login"
                                    onChange={(e) => updateBinding(i, { login_url: e.target.value })}
                                  />
                                </Field>
                              </Grid>
                            </div>
                          </details>
                        </div>
                      ))}
                    </Space>
                  </>
                ) : null}

                {isSiteMode ? (
                  <>
                    <div style={{ marginTop: 12 }}>
                      <Checkbox
                        checked={form.skip_site_recon}
                        onChange={(e) => patch({ skip_site_recon: e.target.checked, skip_recon_touched: true })}
                      >
                        跳过入口盘点侦察（省 token）
                      </Checkbox>
                    </div>
                    <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 6 }}>
                      默认先泛扒首页 / robots / API 文档。已给登录凭据时可跳过——Agent 能从内部功能发现入口。
                      填了账密或 Cookie 会自动勾上。
                    </Typography.Paragraph>
                    {looksHasCreds() && !exportAuthBindings().length ? (
                      <Typography.Paragraph type="warning" style={{ fontSize: 12, marginBottom: 0 }}>
                        协作备注里像有凭据，但凭据区是空的。挪到凭据区才能强制尝试并在看板反馈。
                      </Typography.Paragraph>
                    ) : null}
                  </>
                ) : null}
              </Card>
            ) : null}

            {/* ---------- 额外规则 ---------- */}
            <Card size="small" style={{ marginBottom: 12 }}>
              <BlockHead
                title="本任务额外规则"
                desc={`叠在内置 ${form.src_type === 'enterprise' ? '企业 SRC' : 'EduSRC'} 标准上，不能放宽红线`}
              />
              <Input.TextArea
                rows={3}
                value={form.src_rules}
                placeholder="例：本校不收弱口令；重点收越权与未授权。"
                onChange={(e) => patch({ src_rules: e.target.value })}
              />
            </Card>

            {/* ---------- 高级 ---------- */}
            <Collapse
              style={{ marginBottom: 12 }}
              items={[
                {
                  key: 'advanced',
                  label: '高级：模型、测绘分页、并发',
                  children: (
                    <>
                      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                        当前系统是
                        {inherited.llm_mode === 'pool'
                          ? `${inherited.llm_provider_count} 个模型端点`
                          : '单模型'}
                        。「跟随系统」时，设置页改完下一轮生效。
                      </Typography.Paragraph>

                      <Segmented
                        block
                        value={modelMode}
                        onChange={(v) => setModelMode(String(v) as ModelMode)}
                        options={[
                          { label: '跟随系统', value: 'inherit' },
                          { label: '单端点', value: 'single' },
                          { label: '端点池', value: 'pool' }
                        ]}
                      />

                      {modelMode === 'single' ? (
                        <div style={{ marginTop: 12 }}>
                          <Grid>
                            <Field label="模型 base_url">
                              <Input
                                value={form.base_url}
                                placeholder="https://api.deepseek.com/v1"
                                onChange={(e) => {
                                  setSingleModels([])
                                  setSingleModelsError('')
                                  patch({ base_url: e.target.value, key_ref: '' })
                                }}
                              />
                            </Field>
                            <Field label="模型 api_key">
                              <SecretPassword
                                value={form.api_key}
                                placeholder={form.key_ref || form.api_key_set ? '已配置，留空复用' : 'sk-...'}
                                onChange={(e) => patch({ api_key: e.target.value })}
                              />
                            </Field>
                            <Field label="模型名">
                              <ModelPicker
                                value={form.model}
                                models={singleModels}
                                loading={singleModelsLoading}
                                error={singleModelsError}
                                onChange={(v) => patch({ model: v })}
                                onRefresh={() => void loadSingleModels()}
                              />
                            </Field>
                            <Field label="模型协议">
                              <Select
                                style={{ width: '100%' }}
                                value={form.protocol}
                                options={PROTOCOL_OPTIONS}
                                onChange={(v: string) => {
                                  setSingleModels([])
                                  setSingleModelsError('')
                                  patch({ protocol: v, key_ref: '' })
                                }}
                              />
                            </Field>
                          </Grid>
                        </div>
                      ) : null}

                      {modelMode === 'pool' ? (
                        <div style={{ marginTop: 12 }}>
                          <ProviderPoolEditor
                            taskId={taskId || ''}
                            value={providers}
                            defaults={{
                              base_url: form.base_url || inherited.base_url,
                              model: form.model || inherited.model,
                              protocol: form.protocol || inherited.protocol
                            }}
                            onChange={setProviders}
                          />
                        </div>
                      ) : null}

                      <div style={{ marginTop: 12 }}>
                        <Grid>
                          {showEngineBlock ? (
                            <Field label="搜集最大页数">
                              <InputNumber
                                style={{ width: '100%' }}
                                min={1}
                                max={200}
                                value={form.max_pages}
                                onChange={(v) => patch({ max_pages: v ?? 20 })}
                              />
                            </Field>
                          ) : null}
                          <Field label="worker 并发">
                            <InputNumber
                              style={{ width: '100%' }}
                              min={1}
                              max={32}
                              value={form.concurrency}
                              onChange={(v) => patch({ concurrency: v ?? 3 })}
                            />
                          </Field>
                          <Field label="深挖次数">
                            <InputNumber
                              style={{ width: '100%' }}
                              min={0}
                              max={10}
                              value={form.deepen_cap}
                              onChange={(v) => patch({ deepen_cap: v ?? 0 })}
                            />
                          </Field>
                          {showEngineBlock ? (
                            <Field label="每页条数">
                              <InputNumber
                                style={{ width: '100%' }}
                                min={1}
                                max={1000}
                                value={form.page_size}
                                onChange={(v) => patch({ page_size: v ?? 100 })}
                              />
                            </Field>
                          ) : null}
                        </Grid>

                        <div style={{ marginTop: 10 }}>
                          <Checkbox
                            checked={form.auto_killsweep}
                            onChange={(e) => patch({ auto_killsweep: e.target.checked })}
                          >
                            复审通过后自动通杀
                          </Checkbox>
                          <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 6 }}>
                            关掉后，通过复审只进待提交，不会自动分析同款系统。通杀列里已有记录仍可手动重启。
                          </Typography.Paragraph>
                        </div>

                        {showEngineBlock ? (
                          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                            页数对当前测绘引擎生效。
                          </Typography.Paragraph>
                        ) : null}

                        {showEngineBlock && engineIsFofa ? (
                          <Grid>
                            <Field label="FOFA Key（本任务覆盖，可选）">
                              <SecretPassword
                                value={form.fofa_key}
                                placeholder="留空用系统设置"
                                onChange={(e) => patch({ fofa_key: e.target.value })}
                              />
                            </Field>
                            <Field label="FOFA API 端点（可选）">
                              <Input
                                value={form.fofa_base_url}
                                placeholder="https://fofa.info"
                                onChange={(e) => patch({ fofa_base_url: e.target.value })}
                              />
                            </Field>
                          </Grid>
                        ) : showEngineBlock ? (
                          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                            当前不是 FOFA：Key 用设置页「各引擎 API Key」。
                          </Typography.Paragraph>
                        ) : null}

                        <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }}>
                          深挖次数是同一目标被打回的上限（人工 + AI 审核 + 自动），0 表示关闭回炉。
                        </Typography.Paragraph>
                      </div>
                    </>
                  )
                }
              ]}
            />
          </Col>

          {/* ---------- 摘要侧栏 ---------- */}
          <Col xs={24} lg={8}>
            <Card size="small" style={{ position: 'sticky', top: 0 }}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {editMode ? '当前任务' : '即将创建'}
              </Typography.Text>
              <Typography.Title level={4} style={{ margin: '4px 0 12px' }}>
                {form.name.trim() || '未命名任务'}
              </Typography.Title>

              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                <SummaryRow k="口径" v={form.src_type === 'enterprise' ? '企业 SRC' : 'EduSRC'} />
                <SummaryRow k="通杀" v={form.auto_killsweep === false ? '手动' : '自动'} />
                <SummaryRow k="来源" v={recapSource} />
                {!isSiteMode ? <SummaryRow k="引擎" v={engineText(form.engine)} /> : null}
                <SummaryRow k="漏洞" v={`${vulnCount} 类`} />
                {!isFofaMode ? <SummaryRow k="清单" v={`${manualCount} 条`} /> : null}
                <SummaryRow k="模型" v={recapModel} />
                <SummaryRow k="并发" v={String(form.concurrency)} />
              </Space>

              {missingHint ? (
                <Typography.Paragraph type="warning" style={{ fontSize: 12, marginTop: 12 }}>
                  {missingHint}
                </Typography.Paragraph>
              ) : null}

              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 4 }}>
                {recapLine}
              </Typography.Paragraph>

              <Button
                type="primary"
                block
                icon={<SaveOutlined />}
                loading={submitting}
                disabled={loading || !writable}
                onClick={() => void submit()}
              >
                {submitting ? '提交中…' : submitLabel}
              </Button>
            </Card>
          </Col>
        </Row>
      )}
    </section>
  )
}

/** 摘要行。 */
function SummaryRow({ k, v }: { k: string; v: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {k}
      </Typography.Text>
      <Typography.Text style={{ fontSize: 12 }}>{v}</Typography.Text>
    </div>
  )
}
