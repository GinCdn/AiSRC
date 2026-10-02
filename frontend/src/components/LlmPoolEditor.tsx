/**
 * LLM 端点池编辑器（对标 AutoHunter Vue 版 LlmPoolEditor.vue）。
 *
 * 受控组件：列表数据由父组件持有，结构变更（增 / 删 / 移）会整表规范化后回吐，
 * 字段编辑也只浅拷贝触发一次更新，避免每键重建对象导致输入框丢光标。
 *
 * 密钥语义：视图里返回的密钥是脱敏占位符（8 个圆点 `••••••••`）。
 * 若用户未改动，onChange 出来的数据里该字段仍保持占位符原值；
 * 是否提交给后端由上层决定（上层可按「仍是占位符 / 空串」判定为未修改而省略）。
 */
import { useEffect, useMemo, useState } from 'react'
import { App, Button, Checkbox, Input, InputNumber, Select, Space, Tag, Typography } from 'antd'
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  PlusOutlined
} from '@ant-design/icons'
import { userApi } from '@/api'
import LlmModelPicker from '@/components/LlmModelPicker'
import { SecretPassword } from '@/components/PasswordEye'
import type { LlmProvider } from '@/types'

/** 密钥脱敏占位符（8 个圆点）。 */
export const MASKED_KEY = '••••••••'

/** 协议选项。 */
const PROTOCOL_OPTIONS = [
  { value: 'auto', label: '自动判断' },
  { value: 'openai_chat', label: 'OpenAI Chat' },
  { value: 'anthropic_messages', label: 'Anthropic Messages' }
]

/** 端点池编辑行（在 LlmProvider 基础上补前端工作字段）。 */
export interface LlmProviderRow extends LlmProvider {
  /** 稳定 uid，避免列表 key 抖动。 */
  uid?: string
  /** 后端是否已配置密钥。 */
  api_key_set?: boolean
  /** 后端回显的脱敏密钥。 */
  api_key_masked?: string
  /** 后端密钥引用（用于保留原密钥）。 */
  key_ref?: string
  /** 后端健康引用。 */
  health_ref?: string
  /** 该端点已拉到的候选模型。 */
  models?: string[]
  /** 正在拉取模型。 */
  modelsLoading?: boolean
  /** 拉取模型的错误提示。 */
  modelsError?: string
}

interface Props {
  /** 端点列表（来自父组件）。 */
  value: LlmProvider[]
  /** 列表变化（含前端工作字段）。 */
  onChange: (rows: LlmProviderRow[]) => void
  /** 编辑已有任务时传入，拉模型走任务级密钥解析。 */
  taskId?: string
  /** 拉取模型成功后的回调。 */
  onModelsFetched?: (index: number, models: string[]) => void
  /** 禁用交互（非 full 角色）。 */
  disabled?: boolean
  /** 新增端点的默认值。 */
  defaults?: {
    base_url?: string
    model?: string
    protocol?: string
    temperature?: number
  }
}

let uidSeq = 1
function nextUid(): string {
  return `llm-uid-${uidSeq++}`
}

/** 协议收敛到合法值。 */
function normalizeProtocol(protocol?: string): string {
  return protocol === 'openai_chat' || protocol === 'anthropic_messages' || protocol === 'auto'
    ? protocol
    : 'auto'
}

/** 清洗密钥：脱敏占位 / 空串视为「未提供新密钥」。 */
export function cleanSecret(value?: string): string {
  const v = String(value || '').trim()
  return v === MASKED_KEY ? '' : v
}

/** 规范化一条端点行。 */
function normalizeRow(
  raw: Partial<LlmProviderRow>,
  index: number,
  defaults?: Props['defaults']
): LlmProviderRow {
  const apiKeySet = !!raw.api_key_set
  return {
    uid: raw.uid || nextUid(),
    name: raw.name || `llm-${index + 1}`,
    base_url: raw.base_url || '',
    // 已配置但未回传明文时，统一以脱敏占位符呈现，保证「未改动即保持原值」。
    api_key: raw.api_key || (apiKeySet ? MASKED_KEY : ''),
    api_key_set: apiKeySet,
    api_key_masked: raw.api_key_masked || '',
    key_ref: raw.key_ref || '',
    health_ref: raw.health_ref || '',
    model: raw.model || '',
    protocol: normalizeProtocol(raw.protocol),
    temperature: raw.temperature ?? defaults?.temperature ?? 0.3,
    weight: raw.weight ?? 1,
    enabled: raw.enabled !== false,
    models: Array.isArray(raw.models) ? raw.models : [],
    modelsLoading: !!raw.modelsLoading,
    modelsError: raw.modelsError || ''
  }
}

/** 端点池编辑器。 */
export default function LlmPoolEditor({ value, onChange, taskId, onModelsFetched, disabled, defaults }: Props) {
  const { message, modal } = App.useApp()
  const [selected, setSelected] = useState(0)

  const rows = useMemo<LlmProviderRow[]>(
    () => (Array.isArray(value) ? (value as LlmProviderRow[]) : []),
    [value]
  )

  // 选中项随列表长度收敛。
  useEffect(() => {
    if (!rows.length) setSelected(-1)
    else if (selected < 0 || selected >= rows.length) setSelected(0)
  }, [rows.length, selected])

  const current = selected >= 0 ? rows[selected] : undefined

  /** 结构变更（增删移）时整表规范化。 */
  function replaceAll(mutator: (next: LlmProviderRow[]) => void) {
    const next = rows.map((row, idx) => normalizeRow(row, idx, defaults))
    mutator(next)
    onChange(next)
  }

  /** 原位补丁：只浅拷贝数组，避免每键新建对象导致输入框丢焦点。 */
  function patchAt(index: number, patch: Partial<LlmProviderRow>) {
    if (index < 0 || index >= rows.length) return
    onChange(
      rows.map((row, i) => (i === index ? { ...normalizeRow(row, i, defaults), ...patch } : row))
    )
  }

  function patchCurrent(patch: Partial<LlmProviderRow>) {
    if (selected < 0) return
    patchAt(selected, patch)
  }

  function addProvider() {
    replaceAll((next) => {
      next.push(
        normalizeRow(
          {
            name: `llm-${next.length + 1}`,
            base_url: defaults?.base_url || 'https://api.deepseek.com/v1',
            model: defaults?.model || 'deepseek-chat',
            protocol: defaults?.protocol || 'auto',
            temperature: defaults?.temperature ?? 0.3,
            weight: 1,
            enabled: true
          },
          next.length,
          defaults
        )
      )
      setSelected(next.length - 1)
    })
  }

  function removeProvider(index: number) {
    const provider = rows[index]
    if (!provider) return
    const label = provider.name || provider.model || `端点 #${index + 1}`
    modal.confirm({
      title: '删除模型端点',
      content: `确认删除模型端点「${label}」？`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => {
        replaceAll((next) => {
          next.splice(index, 1)
          if (!next.length) setSelected(-1)
          else if (selected > index) setSelected(selected - 1)
          else if (selected === index) setSelected(Math.min(index, next.length - 1))
        })
      }
    })
  }

  function moveProvider(index: number, delta: number) {
    const next = index + delta
    if (next < 0 || next >= rows.length) return
    replaceAll((list) => {
      const [row] = list.splice(index, 1)
      list.splice(next, 0, row)
      setSelected(next)
    })
  }

  /** base_url / 协议变化时旧的密钥引用与模型缓存作废。 */
  function invalidateKey(patch: Partial<LlmProviderRow>) {
    patchCurrent({
      key_ref: '',
      api_key_set: false,
      api_key_masked: '',
      models: [],
      modelsError: '',
      ...patch
    })
  }

  /** 拉取该端点的可用模型（任务编辑走 /tasks/:id/models，否则走 /settings/models）。 */
  async function loadModels(index: number) {
    const provider = rows[index]
    if (!provider || disabled) return
    patchAt(index, { modelsLoading: true, modelsError: '' })
    const payload = {
      base_url: provider.base_url,
      api_key: cleanSecret(provider.api_key) || undefined,
      protocol: provider.protocol,
      key_ref: provider.key_ref || undefined,
      model: provider.model
    }
    try {
      const res = taskId
        ? await userApi.taskModels(taskId, payload)
        : await userApi.settingsModels(payload)
      const list = Array.isArray(res?.models) ? res.models.filter(Boolean) : []
      if (list.length) {
        const model = !provider.model || !list.includes(provider.model) ? list[0] : provider.model
        patchAt(index, { models: list, modelsLoading: false, modelsError: '', model })
        onModelsFetched?.(index, list)
        message.success(`已获取 ${list.length} 个模型`)
      } else {
        patchAt(index, { models: [], modelsLoading: false, modelsError: res?.error || '未获取到模型列表' })
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <Typography.Text>
          <strong>端点列表</strong>
          <Typography.Text type="secondary"> · {rows.length} 个</Typography.Text>
        </Typography.Text>
        <Button size="small" icon={<PlusOutlined />} disabled={disabled} onClick={addProvider}>
          添加端点
        </Button>
      </div>

      {!rows.length ? (
        <div
          style={{
            border: '1px dashed var(--aisrc-border)',
            borderRadius: 8,
            padding: 16,
            textAlign: 'center',
            color: 'var(--aisrc-text-sub)'
          }}
        >
          <Typography.Text type="secondary">端点池为空，至少添加一个端点。</Typography.Text>
          <div style={{ marginTop: 10 }}>
            <Button size="small" icon={<PlusOutlined />} disabled={disabled} onClick={addProvider}>
              添加端点
            </Button>
          </div>
        </div>
      ) : (
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          {rows.map((provider, idx) => {
            const active = selected === idx
            return (
              <button
                key={provider.uid || idx}
                type="button"
                disabled={disabled}
                onClick={() => setSelected(idx)}
                style={{
                  width: '100%',
                  textAlign: 'left',
                  cursor: disabled ? 'not-allowed' : 'pointer',
                  border: `1px solid ${active ? 'var(--aisrc-accent)' : 'var(--aisrc-border)'}`,
                  background: active ? 'var(--aisrc-accent-soft)' : 'transparent',
                  borderRadius: 8,
                  padding: '8px 10px',
                  color: 'inherit',
                  opacity: provider.enabled === false ? 0.55 : 1
                }}
              >
                <Space size={10} wrap>
                  <span
                    style={{
                      display: 'inline-block',
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: 'var(--aisrc-text-sub)'
                    }}
                  />
                  <strong>{provider.name || `llm-${idx + 1}`}</strong>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {provider.model || '未设置模型'}
                  </Typography.Text>
                  <Tag style={{ marginInlineEnd: 0 }}>
                    {provider.protocol === 'auto'
                      ? 'Auto'
                      : provider.protocol === 'anthropic_messages'
                        ? 'Anthropic'
                        : 'OpenAI'}
                  </Tag>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    权重 {provider.weight || 1}
                  </Typography.Text>
                  {provider.enabled === false ? (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      已停用
                    </Typography.Text>
                  ) : null}
                </Space>
              </button>
            )
          })}
        </Space>
      )}

      {current ? (
        <div style={{ border: '1px solid var(--aisrc-border)', borderRadius: 8, padding: 12 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
              marginBottom: 12
            }}
          >
            <Typography.Text strong>端点 {selected + 1}</Typography.Text>
            <Space size={6}>
              <Button
                size="small"
                icon={<ArrowUpOutlined />}
                title="上移"
                disabled={disabled || selected === 0}
                onClick={() => moveProvider(selected, -1)}
              />
              <Button
                size="small"
                icon={<ArrowDownOutlined />}
                title="下移"
                disabled={disabled || selected === rows.length - 1}
                onClick={() => moveProvider(selected, 1)}
              />
              <Checkbox
                checked={current.enabled !== false}
                disabled={disabled}
                onChange={(e) => patchCurrent({ enabled: e.target.checked })}
              >
                启用
              </Checkbox>
              <Button
                size="small"
                danger
                icon={<DeleteOutlined />}
                title="删除端点"
                disabled={disabled}
                onClick={() => removeProvider(selected)}
              />
            </Space>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <Typography.Text>名称</Typography.Text>
              <Input
                value={current.name}
                disabled={disabled}
                placeholder="primary"
                onChange={(e) => patchCurrent({ name: e.target.value })}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <Typography.Text>协议</Typography.Text>
              <Select
                style={{ width: '100%' }}
                value={current.protocol}
                disabled={disabled}
                options={PROTOCOL_OPTIONS}
                onChange={(v: string) => invalidateKey({ protocol: v })}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, gridColumn: '1 / -1' }}>
              <Typography.Text>base_url</Typography.Text>
              <Input
                value={current.base_url}
                disabled={disabled}
                placeholder="https://api.deepseek.com/v1"
                onChange={(e) => invalidateKey({ base_url: e.target.value })}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                Coding Plan 填官方根地址即可，不要再加 /v1；无版本号的根会自动补 /v1。
              </Typography.Text>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <Typography.Text>api_key</Typography.Text>
              <SecretPassword
                value={current.api_key}
                disabled={disabled}
                placeholder={
                  current.api_key_set
                    ? `${current.api_key_masked || '已配置'}，留空不修改`
                    : 'sk-...'
                }
                onChange={(e) => patchCurrent({ api_key: e.target.value })}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <Typography.Text>temperature</Typography.Text>
              <InputNumber
                style={{ width: '100%' }}
                min={0}
                max={2}
                step={0.1}
                value={current.temperature}
                disabled={disabled}
                onChange={(v) => patchCurrent({ temperature: v ?? 0.3 })}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <Typography.Text>权重</Typography.Text>
              <InputNumber
                style={{ width: '100%' }}
                min={1}
                max={100}
                value={current.weight}
                disabled={disabled}
                onChange={(v) => patchCurrent({ weight: v ?? 1 })}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, gridColumn: '1 / -1' }}>
              <Typography.Text>模型名</Typography.Text>
              <LlmModelPicker
                value={current.model}
                models={current.models || []}
                loading={current.modelsLoading}
                disabled={disabled}
                error={current.modelsError}
                required
                onChange={(v) => patchCurrent({ model: v })}
                onRefresh={() => void loadModels(selected)}
              />
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
