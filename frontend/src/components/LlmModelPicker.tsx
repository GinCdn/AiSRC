/**
 * 模型名选择 / 手输组合控件（对标 AutoHunter Vue 版 LlmModelPicker.vue）。
 *
 * 行为对齐：
 *   - 有候选列表且当前值命中列表 → 下拉选择；
 *   - 无候选列表，或当前值不在列表里 → 退化为手动输入（避免误选把已配置的模型冲掉）；
 *   - 提供「查询模型」按钮与「选列表 / 手动输入」切换。
 */
import { useEffect, useState } from 'react'
import { Button, Input, Select, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'

interface Props {
  /** 当前模型名。 */
  value: string
  /** 候选模型列表。 */
  models: string[]
  /** 是否正在拉取模型。 */
  loading?: boolean
  /** 禁用交互。 */
  disabled?: boolean
  /** 必填标记（透传给原生输入框）。 */
  required?: boolean
  /** 手输占位符。 */
  placeholder?: string
  /** 查询按钮文案。 */
  refreshLabel?: string
  /** 默认提示（无错误时展示，优先于「已获取 N 个」）。 */
  hint?: string
  /** 错误提示（优先级最高）。 */
  error?: string
  /** 值变化。 */
  onChange: (value: string) => void
  /** 点击「查询模型」。 */
  onRefresh?: () => void
}

/** 模型名选择器。 */
export default function LlmModelPicker({
  value,
  models,
  loading = false,
  disabled = false,
  required = false,
  placeholder = 'deepseek-chat',
  refreshLabel = '查询模型',
  hint = '',
  error = '',
  onChange,
  onRefresh
}: Props) {
  const list = (models || []).filter(Boolean)
  const inList = !!value && list.includes(value)
  const [useCustom, setUseCustom] = useState(list.length === 0)

  // 候选集合或当前值变化时重算展示形态；数组每次渲染都是新引用，用字符串化做依赖。
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
            aria-required={required}
            options={list.map((m) => ({ value: m, label: m }))}
            onChange={(v: string) => onChange(v)}
          />
        ) : (
          <Input
            style={{ flex: 1, minWidth: 0 }}
            value={value}
            disabled={disabled}
            required={required}
            placeholder={placeholder}
            onChange={(e) => onChange(e.target.value)}
          />
        )}
        <Button
          icon={<ReloadOutlined />}
          loading={loading}
          disabled={loading || disabled}
          onClick={() => onRefresh?.()}
        >
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
      ) : hint ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {hint}
        </Typography.Text>
      ) : list.length && !inList && !useCustom ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          已获取 {list.length} 个可用模型，可下拉选择
        </Typography.Text>
      ) : list.length ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          已获取 {list.length} 个可用模型，可下拉选择
        </Typography.Text>
      ) : null}
    </div>
  )
}
