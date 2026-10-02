/**
 * 任务编辑弹窗（对标 Vue 版 src/components/TaskEditModal.vue）。
 *
 * 覆盖字段：名称 / src_type / vuln_types / src_rules / target_source / engine /
 * fofa_query / manual_targets / concurrency / deepen_cap / auto_killsweep /
 * auth_bindings（走 useAuthBindings）/ 模型方案（跟随系统 · 单端点 · 端点池）/
 * 测绘分页与 FOFA 任务级覆盖。
 *
 * 与后端的关键约定：
 *   - 密钥脱敏占位符恒为 8 个圆点 `••••••••`；回填时原样展示，提交时若「未被改过」
 *     则直接省略该字段，后端按「未修改」处理（避免把脱敏串写回库、也避免清空密钥）。
 *   - 模型配置在请求/响应体里的键名是 `model_config_data`
 *     （React 的 Task 类型里写成了 model_config，这里做了兼容读取）。
 *   - `/api/tasks/:id/models` 成功时只回 `{ models }`，没有 ok 字段，失败走业务码 reject。
 *
 * Vue 的 LlmModelPicker / LlmPoolEditor 两个子组件在本文件内以 ModelPicker /
 * ProviderPoolEditor 等价实现，避免新增文件。
 */
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import {
  App,
  Button,
  Checkbox,
  Collapse,
  Input,
  InputNumber,
  Modal,
  Segmented,
  Select,
  Space,
  Typography
} from 'antd'
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  PlusOutlined,
  ReloadOutlined
} from '@ant-design/icons'
import { userApi } from '@/api'
import { emptyBinding, manualTargetLines, useAuthBindings } from '@/hooks/useAuthBindings'
import type { AuthBinding, FofaConfig, TargetSource, Task } from '@/types'
import { SecretPassword } from '@/components/PasswordEye'

// ---------------------------------------------------------------- 常量

/** 密钥脱敏占位符（8 个圆点）。 */
const MASKED_KEY = '••••••••'

/** 漏洞类型选项（与创建任务默认种子一致）。 */
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

/** 搜索引擎选项。 */
const ENGINE_OPTIONS = [
  { value: '', label: '系统默认引擎' },
  { value: 'fofa', label: 'FOFA' },
  { value: 'quake', label: '360 Quake' },
  { value: 'hunter', label: 'Hunter (鹰图)' },
  { value: 'zoomeye', label: 'ZoomEye' },
  { value: 'shodan', label: 'Shodan' },
  { value: 'censys', label: 'Censys' }
]

/** 搜集方式选项。 */
const INTENT_OPTIONS = [
  { value: '', label: '自动判断' },
  { value: 'syntax', label: '查询语法（当前引擎官网语法）' },
  { value: 'intent', label: '自然语言意图' }
]

/** 模型协议选项。 */
const PROTOCOL_OPTIONS = [
  { value: 'auto', label: '自动识别' },
  { value: 'openai_chat', label: 'OpenAI Chat Completions' },
  { value: 'anthropic_messages', label: 'Anthropic Messages' }
]

/** 各引擎的查询语法示例（占位提示用）。 */
const QUERY_SAMPLES: Record<string, string> = {
  fofa: 'title="统一身份认证" && domain=".edu.cn"',
  quake: 'title:"统一身份认证" AND domain:"edu.cn"',
  hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
  zoomeye: 'title="统一身份认证" && country="CN"',
  shodan: 'http.title:"login" hostname:edu.cn',
  censys: 'host.dns.names: edu.cn'
}

// ---------------------------------------------------------------- 类型

/** 模型方案。 */
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

/** 端点池编辑行（含前端专用字段）。 */
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

/** 生成端点行的稳定 uid，避免列表 key 抖动。 */
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

/** 导出端点池提交体（脱敏密钥交给后端按「未修改」处理）。 */
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

/** 空表单。 */
function emptyForm(): FormState {
  return {
    name: '',
    src_type: 'edusrc',
    vuln_types: [],
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
    skip_site_recon: false
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

/** 区块小标题。 */
function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <Typography.Title level={5} style={{ margin: '18px 0 10px' }}>
      {children}
    </Typography.Title>
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

/**
 * 模型名选择器（等价 Vue 的 LlmModelPicker）：
 * 有候选列表且当前值命中 → 下拉；否则退化为手输，避免误选。
 */
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
    // 只在候选集合或当前值变化时重算，list 每次渲染都是新数组故用字符串化做依赖
  }, [list.join('\u0000'), value]) // eslint-disable-line react-hooks/exhaustive-deps

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

/**
 * 端点池编辑器（等价 Vue 的 LlmPoolEditor）。
 * 列表态由父组件持有，导出用纯函数 exportProviders 完成，不再暴露命令式 ref。
 */
function ProviderPoolEditor({ taskId, value, defaults, onChange }: PoolEditorProps) {
  const { modal, message } = App.useApp()
  const [selected, setSelected] = useState(0)

  // 选中项随列表长度收敛。
  useEffect(() => {
    if (!value.length) setSelected(-1)
    else if (selected < 0 || selected >= value.length) setSelected(0)
  }, [value.length, selected])

  const current = selected >= 0 ? value[selected] : undefined

  /** 结构变更（增删移）时整表规范化。 */
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

  /** 改动 base_url / protocol 时旧密钥引用作废。 */
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
      // 编辑已有任务时走任务级探针，才能解析端点池里已有的密钥；新建走全局设置探针。
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

interface Props {
  open: boolean
  /** null 表示未选中任务。 */
  task: Task | null
  onClose: () => void
  onSaved: () => void
}

/** 任务编辑弹窗。 */
export default function TaskEditModal({ open, task, onClose, onSaved }: Props) {
  const { message } = App.useApp()

  const [form, setForm] = useState<FormState>(emptyForm)
  const [modelMode, setModelMode] = useState<ModelMode>('inherit')
  const [providers, setProviders] = useState<ProviderRow[]>([])
  const [saving, setSaving] = useState(false)

  // 单端点模型探测
  const [models, setModels] = useState<string[]>([])
  const [modelsLoading, setModelsLoading] = useState(false)
  const [modelsError, setModelsError] = useState('')

  // 编辑前快照：用于「只提交改动过的字段」，避免误清后端已有值。
  const originalRef = useRef({
    base_url: '',
    model: '',
    protocol: 'auto',
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
  const engineIsFofa = !form.engine || form.engine === 'fofa'
  // 凭据区只对「用户自己指定目标」有意义：纯 FOFA 自动搜不展示。
  const showAuthBindings = !isFofaMode
  const queryPlaceholder = QUERY_SAMPLES[form.engine || 'fofa'] || QUERY_SAMPLES.fofa

  function patch(p: Partial<FormState>) {
    setForm((prev) => ({ ...prev, ...p }))
  }

  /** 用任务详情回填表单。 */
  function fill(t: Task | null) {
    if (!t) return
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
      // 密钥只回填脱敏串：用户不改就原样提交（后端识别为未修改）。
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
      skip_site_recon: !!fofa.skip_site_recon
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

    // 方案判定：显式继承且无端点池 → 跟随系统；有端点池或声明 pool → 端点池；否则单端点。
    const inheritGlobal = cfg.inherit_global !== false
    if (inheritGlobal && !rows.length) setModelMode('inherit')
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

    originalRef.current = {
      base_url: cfg.base_url || '',
      model: cfg.model || '',
      protocol: normalizeProtocol(cfg.protocol),
      prompt_version: cfg.prompt_version || 'legacy',
      intent_mode: fofa.intent_mode || '',
      fofa_base_url: fofa.base_url || '',
      max_pages: Number(fofa.max_pages ?? 20),
      page_size: Number(fofa.page_size ?? 100)
    }

    setModels([])
    setModelsError('')
  }

  // 打开 / 切换任务时回填。
  useEffect(() => {
    if (!open) return
    fill(task)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, task])

  // 模型方案切换：单端点自动探测模型；端点池为空时补一条种子。
  useEffect(() => {
    if (!open) return
    if (modelMode === 'single') {
      void loadSingleModels()
    } else if (modelMode === 'pool') {
      setProviders((prev) =>
        prev.length
          ? prev
          : [
              normalizeProvider({
                name: 'llm-1',
                base_url: form.base_url || 'https://api.deepseek.com/v1',
                model: form.model || 'deepseek-chat',
                protocol: form.protocol || 'auto',
                temperature: 0.3,
                weight: 1,
                enabled: true
              })
            ]
      )
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, modelMode])

  /** 探测当前任务单端点可用模型。 */
  async function loadSingleModels() {
    const taskId = task?.id
    if (!taskId) return
    setModelsLoading(true)
    setModelsError('')
    try {
      const res = await userApi.taskModels(taskId, {
        base_url: form.base_url || undefined,
        api_key: cleanKey(form.api_key) || undefined,
        key_ref: form.key_ref || undefined,
        protocol: form.protocol
      })
      const list = Array.isArray(res?.models) ? res.models.filter(Boolean) : []
      if (list.length) {
        setModels(list)
        setForm((prev) => (!prev.model || !list.includes(prev.model) ? { ...prev, model: list[0] } : prev))
      } else {
        setModels([])
        setModelsError('未获取到模型列表')
      }
    } catch {
      setModels([])
      setModelsError('拉取失败，可手动输入模型名')
    } finally {
      setModelsLoading(false)
    }
  }

  /** 保存：拼装增量 payload 后走 updateTask。 */
  async function save() {
    if (!task || saving) return

    const singleKeyReady = !!form.key_ref || form.api_key_set || !!cleanKey(form.api_key)
    if (modelMode === 'single' && !singleKeyReady) {
      message.error('单端点模式需要填写模型 api_key（或已有 key_ref）')
      return
    }
    if (modelMode === 'pool') {
      const rows = exportProviders(providers)
      // 已保存的密钥以脱敏串回显（api_key_set 或 MASKED_KEY），cleanKey 后 api_key 为空，
      // 但后端 mergeProviders 会按 base_url+name 保留旧值——这类行不算「缺 key」（实测踩过：
      // 用户什么都不改点保存也被拦「端点池每个端点都需要 api_key」）。
      const missing = providers.some((p, idx) => {
        const row = rows[idx]
        if (!row || !row.base_url || !row.model) return true
        const savedKey = p.api_key_set === true || (p.api_key || '').trim() === MASKED_KEY
        return !row.api_key && !row.key_ref && !savedKey
      })
      if (!rows.length || missing) {
        message.error('端点池每个端点都需要 base_url / 模型 / api_key（已保存的可留空保留）')
        return
      }
    }

    setSaving(true)
    try {
      const original = originalRef.current

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
        // 无明文 key（编辑回显脱敏串）时带 key_ref 引用系统已存密钥。
        else if (form.key_ref) modelConfig.key_ref = form.key_ref
      }
      if (form.prompt_version !== original.prompt_version) modelConfig.prompt_version = form.prompt_version

      const maxPages = Number(form.max_pages) || 20
      const pageSize = Number(form.page_size) || 100
      const fofaConfig: Partial<FofaConfig> = {}
      if (maxPages !== original.max_pages) fofaConfig.max_pages = maxPages
      if (pageSize !== original.page_size) fofaConfig.page_size = pageSize
      if (form.intent_mode !== original.intent_mode) fofaConfig.intent_mode = form.intent_mode
      const fofaKey = cleanKey(form.fofa_key)
      if (fofaKey) fofaConfig.key = fofaKey
      if (form.fofa_base_url !== original.fofa_base_url) fofaConfig.base_url = form.fofa_base_url
      if (isSiteMode) fofaConfig.skip_site_recon = form.skip_site_recon

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

      await userApi.updateTask(task.id, payload)
      message.success('任务参数已保存')
      onSaved()
    } catch {
      /* 错误提示已由 request 层统一处理 */
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={open}
      width={820}
      title="编辑任务参数"
      maskClosable={false}
      onCancel={() => {
        if (!saving) onClose()
      }}
      footer={
        <Space>
          <Button disabled={saving} onClick={onClose}>
            取消
          </Button>
          <Button type="primary" loading={saving} onClick={() => void save()}>
            {saving ? '保存中…' : '保存参数'}
          </Button>
        </Space>
      }
    >
      <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>
        运行中的任务会在下一轮调度读取新参数；密钥留空或保持脱敏占位则保留原值。
      </Typography.Paragraph>

      <div style={{ maxHeight: '62vh', overflowY: 'auto', paddingRight: 8 }}>
        <Grid>
          <Field label="任务名称">
            <Input value={form.name} onChange={(e) => patch({ name: e.target.value })} />
          </Field>
          <Field label="任务模式">
            <Select
              style={{ width: '100%' }}
              value={form.src_type}
              options={[
                { value: 'edusrc', label: 'EduSRC（教育行业）' },
                { value: 'enterprise', label: '企业SRC' }
              ]}
              onChange={(v: string) => patch({ src_type: v })}
            />
          </Field>
          <Field label="目标来源">
            <Select
              style={{ width: '100%' }}
              value={form.target_source}
              options={[
                { value: 'fofa', label: '测绘引擎自动搜' },
                { value: 'manual', label: '手动清单' },
                { value: 'both', label: '测绘 + 手动' },
                { value: 'site', label: '单站协作' }
              ]}
              onChange={(v: string) => patch({ target_source: v as TargetSource })}
            />
          </Field>
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
          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <Checkbox
              checked={form.auto_killsweep}
              onChange={(e) => patch({ auto_killsweep: e.target.checked })}
            >
              复审通过后自动通杀
            </Checkbox>
          </div>
        </Grid>

        {!isSiteMode ? (
          <>
            <Grid>
              <Field label="搜索引擎" hint="各引擎 API Key 在「设置 → 资产测绘」配置。">
                <Select
                  style={{ width: '100%' }}
                  value={form.engine}
                  options={ENGINE_OPTIONS}
                  onChange={(v: string) => patch({ engine: v })}
                />
              </Field>
              <Field label="搜集方式">
                <Select
                  style={{ width: '100%' }}
                  value={form.intent_mode}
                  options={INTENT_OPTIONS}
                  onChange={(v: string) => patch({ intent_mode: v })}
                />
              </Field>
            </Grid>
          </>
        ) : null}

        <SectionTitle>挖掘范围</SectionTitle>

        <Field label="漏洞类型">
          <Select
            mode="tags"
            style={{ width: '100%' }}
            value={form.vuln_types}
            options={VULN_OPTIONS}
            placeholder="选择或直接输入自定义漏洞类型"
            onChange={(v: string[]) => patch({ vuln_types: v })}
          />
        </Field>

        {!isSiteMode ? (
          <div style={{ marginTop: 12 }}>
            <Field
              label="查询语法 / 搜集意图"
              hint={
                form.intent_mode === 'intent'
                  ? '搜集 Agent 会把意图翻成语法，并按结果逐轮演化。'
                  : `选了哪个引擎就写哪个引擎的官网语法，原样请求，不会改写成别的引擎语法。示例：${queryPlaceholder}`
              }
            >
              <Input
                value={form.fofa_query}
                placeholder={queryPlaceholder}
                onChange={(e) => patch({ fofa_query: e.target.value })}
              />
            </Field>
          </div>
        ) : (
          <div style={{ marginTop: 12 }}>
            <Field label="目标相关信息 / 协作重点">
              <Input.TextArea
                rows={4}
                value={form.fofa_query}
                placeholder="可写重点方向、后台位置等协作备注。登录凭据请填下方「登录凭据」区。"
                onChange={(e) => patch({ fofa_query: e.target.value })}
              />
            </Field>
          </div>
        )}

        <div style={{ marginTop: 12 }}>
          <Field
            label={isSiteMode ? '主目标 URL（每行一个，会自动拆成多条协作路线）' : '手动目标清单（每行一个，可粘贴杂乱资产表）'}
            hint="保存时自动清理备注 / 补协议 / 去重；搜集入队时会按根域补充泄露凭据。"
          >
            <Input.TextArea
              rows={8}
              value={form.manual_targets}
              placeholder="支持行尾备注、括号 IP、裸域名；保存时自动清理，入队时查泄露凭据"
              onChange={(e) => patch({ manual_targets: e.target.value })}
            />
          </Field>
        </div>

        {showAuthBindings ? (
          <>
            <SectionTitle>
              <Space style={{ justifyContent: 'space-between', width: '100%' }}>
                <span>登录凭据（按目标绑定，可选）</span>
                <Button type="link" size="small" onClick={addBinding}>
                  + 添加一条
                </Button>
              </Space>
            </SectionTitle>
            <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: -4 }}>
              不填不影响挖掘。填了会强制尝试并在看板反馈成败。绑定 <code>*</code> 表示本任务都用。
            </Typography.Paragraph>

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

                  <Field label="快捷粘贴">
                    <Input.TextArea
                      rows={2}
                      value={b.raw}
                      placeholder={'Cookie: JSESSIONID=xxx\nAuthorization: Bearer eyJ...\n账号: test  密码: Test@123'}
                      onChange={(e) => updateBinding(i, { raw: e.target.value })}
                    />
                  </Field>

                  <details style={{ marginTop: 10 }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--aisrc-text-sub)' }}>结构化字段</summary>
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
                        <Field label="Cookie">
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
          <div style={{ marginTop: 14 }}>
            <Checkbox
              checked={form.skip_site_recon}
              onChange={(e) => patch({ skip_site_recon: e.target.checked })}
            >
              跳过入口盘点侦察（省 token）
            </Checkbox>
            <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 6, marginBottom: 0 }}>
              跳过泛扒首页 / API 文档的「入口盘点」路线。已给登录凭据时推荐开启：Agent 直接登录进系统挖，
              不浪费 token 泛侦察（前端 JS / 密钥侦察仍保留）。
            </Typography.Paragraph>
          </div>
        ) : null}

        <Collapse
          style={{ marginTop: 16 }}
          defaultActiveKey={['advanced']}
          items={[
            {
              key: 'advanced',
              label: '高级：模型 / 测绘分页',
              children: (
                <>
                  <Segmented
                    block
                    value={modelMode}
                    onChange={(v) => setModelMode(v as ModelMode)}
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
                              setModels([])
                              setModelsError('')
                              patch({ base_url: e.target.value, key_ref: '' })
                            }}
                          />
                        </Field>
                        <Field label="模型协议">
                          <Select
                            style={{ width: '100%' }}
                            value={form.protocol}
                            options={PROTOCOL_OPTIONS}
                            onChange={(v: string) => {
                              setModels([])
                              setModelsError('')
                              patch({ protocol: v, key_ref: '' })
                            }}
                          />
                        </Field>
                        <Field label="模型 api_key">
                          <SecretPassword
                            value={form.api_key}
                            placeholder={form.api_key_set || form.key_ref ? '已配置，留空保留原值' : 'sk-...'}
                            onChange={(e) => patch({ api_key: e.target.value })}
                          />
                        </Field>
                        <Field label="模型名">
                          <ModelPicker
                            value={form.model}
                            models={models}
                            loading={modelsLoading}
                            error={modelsError}
                            refreshLabel="刷新"
                            onChange={(v) => patch({ model: v })}
                            onRefresh={() => void loadSingleModels()}
                          />
                        </Field>
                      </Grid>
                    </div>
                  ) : null}

                  {modelMode === 'pool' ? (
                    <div style={{ marginTop: 12 }}>
                      <ProviderPoolEditor
                        taskId={task?.id || ''}
                        value={providers}
                        defaults={{ base_url: form.base_url, model: form.model, protocol: form.protocol }}
                        onChange={setProviders}
                      />
                    </div>
                  ) : null}

                  <div style={{ marginTop: 12 }}>
                    <Grid>
                      {!isSiteMode ? (
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
                      {!isSiteMode ? (
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
                    {!isSiteMode ? (
                      <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 6 }}>
                        分页对当前选用的测绘引擎生效。
                      </Typography.Paragraph>
                    ) : null}

                    {!isSiteMode && engineIsFofa ? (
                      <div style={{ marginTop: 8 }}>
                        <Grid>
                          <Field label="FOFA Key（任务级覆盖）">
                            <SecretPassword
                              value={form.fofa_key}
                              placeholder="留空保留原值"
                              onChange={(e) => patch({ fofa_key: e.target.value })}
                            />
                          </Field>
                          <Field label="FOFA API 端点">
                            <Input
                              value={form.fofa_base_url}
                              placeholder="https://fofa.info"
                              onChange={(e) => patch({ fofa_base_url: e.target.value })}
                            />
                          </Field>
                        </Grid>
                        <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 6, marginBottom: 0 }}>
                          仅 FOFA 支持任务级 Key / 端点覆盖；其它引擎请改系统设置。
                        </Typography.Paragraph>
                      </div>
                    ) : null}
                  </div>
                </>
              )
            }
          ]}
        />

        <div style={{ marginTop: 16 }}>
          <Field
            label="SRC 规则（可选，叠加在内置标准上，不替换）"
            hint={`已内置${form.src_type === 'enterprise' ? '企业SRC' : 'EduSRC'}标准。这里只追加本任务额外要求；留空则只用内置标准。与内置冲突时按更严的执行，不能放宽红线。`}
          >
            <Input.TextArea
              rows={3}
              value={form.src_rules}
              placeholder="例：本校不收弱口令；重点收越权与未授权。"
              onChange={(e) => patch({ src_rules: e.target.value })}
            />
          </Field>
        </div>
      </div>
    </Modal>
  )
}
