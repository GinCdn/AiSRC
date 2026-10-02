import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { App, Button, Card, Empty, Input, Segmented, Space, Table, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { toListResult, userApi } from '@/api'
import { useAuthStore } from '@/store'
import { fmtLocalTime } from '@/utils/format'
import type { Intel } from '@/types'

/** 情报单次拉取上限（该接口不分页）。 */
const LIST_LIMIT = 800

/** 情报类别。 */
type KindKey = 'all' | 'cred' | 'fingerprint' | 'endpoint' | 'profile'

/** 情报库统计概览。 */
interface IntelStats {
  total: number
  verified: number
  reused: number
  by_kind: Record<string, number>
}

/** Curator 预览条目。 */
interface CuratorItem {
  kind: string
  match_key: string
  reasons: string[]
}

/** Curator 预览结果。 */
interface CuratorPreview {
  flagged: number
  examined: number
  items: CuratorItem[]
}

const KIND_META: Record<string, { label: string; icon: string; color: string; hex: string }> = {
  cred: { label: '凭证', icon: '🔑', color: 'red', hex: '#f5222d' },
  fingerprint: { label: '打法', icon: '🎯', color: 'blue', hex: '#1677ff' },
  endpoint: { label: '端点', icon: '🧭', color: 'orange', hex: '#fa8c16' },
  profile: { label: '画像', icon: '🪪', color: 'green', hex: '#16a34a' }
}

const KIND_KEYS = ['cred', 'fingerprint', 'endpoint', 'profile'] as const

const KIND_TABS: Array<{ key: KindKey; label: string }> = [
  { key: 'all', label: '全部' },
  { key: 'cred', label: '凭证' },
  { key: 'fingerprint', label: '打法' },
  { key: 'endpoint', label: '端点' },
  { key: 'profile', label: '画像' }
]

const CONFIDENCE_TABS = [
  { value: 'all', label: '全部可信度' },
  { value: 'verified', label: '仅已验证' },
  { value: 'likely', label: '仅疑似' }
]

const URL_RE = /https?:\/\/[^\s<>"'`]+/gi
const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g
const CRED_RE =
  /\b(api[_-]?key|token|secret|password|passwd|pwd|cookie|authorization|bearer)\b\s*[:=]\s*\S+/gi

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

function str(v: unknown, fallback = ''): string {
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return fallback
}

function num(v: unknown): number {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

/** 观摩角色脱敏：屏蔽链接、IP 与凭证字段。 */
function redact(text: string): string {
  return text
    .replace(URL_RE, '[已脱敏链接]')
    .replace(IP_RE, '[已脱敏IP]')
    .replace(CRED_RE, (m) => `${m.split(/[:=]/)[0].trim()}=[已脱敏]`)
}

function kindMeta(kind: string): { label: string; icon: string; color: string; hex: string } {
  return KIND_META[kind] || { label: kind || '其他', icon: '•', color: 'default', hex: '#8c8c8c' }
}

function payloadOf(row: Intel): Record<string, unknown> {
  return asRecord(row.payload)
}

function hitCount(row: Intel): number {
  return num(row.hit_count)
}

function sourceHostOf(row: Intel): string {
  return str(row.source_host)
}

function lastSeenOf(row: Intel): string {
  return str(row.last_seen) || row.created_at
}

/** 主文案：按类别从 payload 里提炼最关键的一条信息。 */
function primaryText(row: Intel): string {
  const p = payloadOf(row)
  if (row.kind === 'cred') return `${str(p.username) || '?'} : ${str(p.password) || '?'}`
  if (row.kind === 'endpoint') return str(p.path) || row.summary || '-'
  if (row.kind === 'fingerprint') return str(p.tactic) || row.summary || '-'
  if (row.kind === 'profile') return `${str(p.key)}：${str(p.value)}`
  return row.summary || '-'
}

/** 次文案：端点 / 打法类的漏洞类型优先，其余回落摘要。 */
function secondaryText(row: Intel): string {
  const p = payloadOf(row)
  if ((row.kind === 'endpoint' || row.kind === 'fingerprint') && p.vuln_type) return str(p.vuln_type)
  return row.summary || ''
}

/** 解析 Curator 预览返回值。 */
function parseCurator(res: Record<string, unknown> | null): CuratorPreview | null {
  if (!res) return null
  const rawItems = Array.isArray(res.items) ? res.items : []
  return {
    flagged: num(res.flagged),
    examined: num(res.examined),
    items: rawItems.map((item) => {
      const r = asRecord(item)
      return {
        kind: str(r.kind),
        match_key: str(r.match_key),
        reasons: Array.isArray(r.reasons) ? r.reasons.map((x) => str(x)) : []
      }
    })
  }
}

/**
 * 全局情报库。
 *
 * 跨任务沉淀的可复用作战情报（凭证 / 打法 / 端点 / 画像）。
 * 支持类别与可信度标签页筛选、关键词搜索、单条删除、按类别清空，
 * 以及 Intel Curator 的预览（GET）与执行（POST）。
 */
export default function IntelView() {
  const { message, modal } = App.useApp()

  const role = useAuthStore((s) => s.role)
  const writable = role === 'full'
  const isObserver = role === 'observer'

  const [stats, setStats] = useState<IntelStats>({ total: 0, verified: 0, reused: 0, by_kind: {} })
  const [rows, setRows] = useState<Intel[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [kind, setKind] = useState<KindKey>('all')
  const [confidence, setConfidence] = useState('all')
  const [searchDraft, setSearchDraft] = useState('')
  const [searchText, setSearchText] = useState('')

  const [curator, setCurator] = useState<CuratorPreview | null>(null)
  const [curatorLoading, setCuratorLoading] = useState(false)
  const [curatorApplying, setCuratorApplying] = useState(false)

  /** 概览统计。 */
  const loadStats = useCallback(async () => {
    try {
      const res = await userApi.intelStats()
      setStats({
        total: num(res?.total),
        verified: num(res?.verified),
        reused: num(res?.reused),
        by_kind: (res?.by_kind as Record<string, number>) || {}
      })
    } catch {
      /* 统计失败不阻断列表 */
    }
  }, [])

  /** 列表：双形态统一收敛（该接口单次返回，不做分页）。 */
  const loadList = useCallback(async () => {
    setRefreshing(true)
    try {
      const res = await userApi.intelList({
        kind: kind === 'all' ? undefined : kind,
        confidence: confidence === 'all' ? undefined : confidence,
        q: searchText || undefined,
        limit: LIST_LIMIT
      })
      const list = toListResult<Intel>(res)
      setRows(list.items)
    } catch {
      setRows([])
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [kind, confidence, searchText])

  /** 预览本轮可提炼的情报（GET）。 */
  const previewCurator = useCallback(async () => {
    setCuratorLoading(true)
    try {
      const res = await userApi.previewIntelCurate(1000)
      setCurator(parseCurator(res))
    } catch {
      setCurator(null)
    } finally {
      setCuratorLoading(false)
    }
  }, [])

  /** 全量刷新：统计 + 列表 + Curator 预览。 */
  const reload = useCallback(async () => {
    await Promise.all([loadStats(), loadList(), previewCurator()])
  }, [loadStats, loadList, previewCurator])

  // 首屏：统计与 Curator 预览（列表由筛选维度副作用触发）。
  useEffect(() => {
    void loadStats()
    void previewCurator()
  }, [loadStats, previewCurator])

  // 类别 / 可信度 / 关键词变化都会重新拉取列表（含首屏）。
  useEffect(() => {
    void loadList()
  }, [loadList])

  // 搜索防抖：180ms 后落稿，由上面的列表副作用触发拉取。
  useEffect(() => {
    const timer = window.setTimeout(() => setSearchText(searchDraft.trim()), 180)
    return () => window.clearTimeout(timer)
  }, [searchDraft])

  /** 主文案展示：观摩角色下凭证类整体脱敏。 */
  function maskPrimary(row: Intel): string {
    if (!isObserver) return primaryText(row)
    if (row.kind === 'cred') return '[已脱敏凭证]'
    return redact(primaryText(row))
  }

  function maskSecondary(row: Intel): string {
    const text = secondaryText(row)
    return isObserver ? redact(text) : text
  }

  function maskScope(row: Intel): string {
    return isObserver ? '[已脱敏]' : row.match_key || '-'
  }

  /** 单条删除。 */
  function removeOne(row: Intel) {
    if (!writable) return
    modal.confirm({
      title: '确认删除这条情报？',
      content: `${row.match_key} · ${primaryText(row)}`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          await userApi.deleteIntel(row.id)
          message.success('已删除')
          await reload()
        } catch {
          /* 错误提示已由 request 层统一处理 */
        }
      }
    })
  }

  /** 按当前类别清空（危险操作，二次确认）。 */
  function clearKind() {
    if (!writable) return
    const label = kind === 'all' ? '全部' : kindMeta(kind).label
    modal.confirm({
      title: `确认清空【${label}】情报？`,
      content: '此操作不可恢复，请确认后继续。',
      okText: '确认清空',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          await userApi.clearIntel(kind)
          message.success(`已清空【${label}】情报`)
          await reload()
        } catch {
          /* 错误提示已由 request 层统一处理 */
        }
      }
    })
  }

  /** 执行 Curator 清理（POST），成功后刷新。 */
  function applyCurator() {
    if (!writable || curatorApplying) return
    const flagged = curator?.flagged ?? 0
    if (!flagged) return
    modal.confirm({
      title: `Intel Curator 发现 ${flagged} 条低价值候选`,
      content: '将只清理未验证且未复用的明显垃圾，确认执行？',
      okText: '执行清理',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        setCuratorApplying(true)
        try {
          const res = await userApi.applyIntelCurate(1000)
          const deleted = num(res?.deleted)
          const kept = num(res?.kept_hot)
          message.success(
            `已清理 ${deleted} 条垃圾情报` +
              (kept ? `，保留 ${kept} 条高频复用项（hit≥3）需人工确认` : '')
          )
          await reload()
        } catch {
          /* 错误提示已由 request 层统一处理 */
        } finally {
          setCuratorApplying(false)
        }
      }
    })
  }

  const columns: ColumnsType<Intel> = [
    {
      title: '类别',
      key: 'kind',
      width: 120,
      render: (_, row) => {
        const meta = kindMeta(row.kind)
        return (
          <Tag color={meta.color}>
            {meta.icon} {meta.label}
          </Tag>
        )
      }
    },
    {
      title: '情报',
      key: 'intel',
      render: (_, row) => (
        <Space direction="vertical" size={2} style={{ width: '100%' }}>
          <Typography.Text strong>{maskPrimary(row)}</Typography.Text>
          {maskSecondary(row) ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {maskSecondary(row)}
            </Typography.Text>
          ) : null}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            作用域：<span className="mono">{maskScope(row)}</span>
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '复用',
      key: 'hit',
      width: 110,
      render: (_, row) =>
        hitCount(row) > 1 ? (
          <Tag color="purple">×{hitCount(row)} 复用</Tag>
        ) : (
          <Typography.Text type="secondary">-</Typography.Text>
        )
    },
    {
      title: '来源 / 时间',
      key: 'source',
      width: 200,
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <span className="mono text-sub">
            {isObserver ? '[已脱敏]' : sourceHostOf(row) || '未知来源'}
          </span>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {fmtLocalTime(lastSeenOf(row))}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '操作',
      key: 'action',
      width: 90,
      hidden: !writable,
      render: (_, row) => (
        <Button size="small" type="text" danger icon={<DeleteOutlined />} onClick={() => removeOne(row)}>
          删除
        </Button>
      )
    }
  ]

  return (
    <section className="intel-view">
      <header className="page-head">
        <div>
          <h2>全局情报库</h2>
          <p className="page-sub">
            跨任务沉淀的可复用作战情报——凭证 / 打法 / 端点 / 画像，由 worker 自动回写并复用。
          </p>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} loading={refreshing && !loading} onClick={() => void reload()}>
            刷新
          </Button>
          <Link to="/">
            <Button>返回任务</Button>
          </Link>
        </Space>
      </header>

      <div className="stat-grid">
        <div className="stat-card">
          <span className="stat-k">情报总量</span>
          <b className="stat-v">{stats.total}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            已验证 {stats.verified} · 被复用 {stats.reused}
          </span>
        </div>
        {KIND_KEYS.map((k) => (
          <div
            key={k}
            className="stat-card"
            onClick={() => setKind(kind === k ? 'all' : k)}
            style={{
              cursor: 'pointer',
              outline: kind === k ? '1px solid var(--aisrc-accent)' : 'none'
            }}
          >
            <span className="stat-k">
              {kindMeta(k).icon} {kindMeta(k).label}
            </span>
            <b className="stat-v" style={{ color: kindMeta(k).hex }}>
              {num(stats.by_kind[k])}
            </b>
          </div>
        ))}
      </div>

      <Card size="small" style={{ marginBottom: 12 }}>
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Tabs
            activeKey={kind}
            onChange={(key) => setKind(key as KindKey)}
            items={KIND_TABS.map((t) => ({ key: t.key, label: t.label }))}
            tabBarStyle={{ marginBottom: 0 }}
          />
          <Space wrap>
            <Input
              allowClear
              prefix={<SearchOutlined />}
              placeholder="搜索 域名 / 账号 / 路径 / 来源 / 内容"
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              style={{ width: 320 }}
            />
            <Segmented
              value={confidence}
              onChange={(v) => setConfidence(String(v))}
              options={CONFIDENCE_TABS.map((t) => ({ value: t.value, label: t.label }))}
            />
            {writable ? (
              <Button danger onClick={clearKind}>
                清空当前类
              </Button>
            ) : null}
          </Space>
        </Space>
      </Card>

      <Card size="small" style={{ marginBottom: 12 }}>
        <Space style={{ width: '100%', justifyContent: 'space-between' }} wrap>
          <Space direction="vertical" size={0}>
            <Typography.Text strong>Intel Curator</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {curatorLoading
                ? '维护检查中…'
                : `候选垃圾 ${curator?.flagged ?? 0} 条，已检查 ${curator?.examined ?? 0} 条`}
            </Typography.Text>
            {curator?.items.length ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }} className="nowrap-ellipsis">
                示例：{curator.items[0].kind} · {curator.items[0].match_key} ·{' '}
                {curator.items[0].reasons.join('、')}
              </Typography.Text>
            ) : null}
          </Space>
          <Space>
            <Button size="small" loading={curatorLoading} onClick={() => void previewCurator()}>
              重新检查
            </Button>
            {writable ? (
              <Button
                size="small"
                danger
                loading={curatorApplying}
                disabled={!curator?.flagged}
                onClick={applyCurator}
              >
                维护清理
              </Button>
            ) : null}
          </Space>
        </Space>
      </Card>

      {loading ? (
        <Card loading />
      ) : rows.length === 0 ? (
        <Card>
          <Empty description="情报库暂无记录，worker 出洞 / 撞库成功后会自动沉淀" />
        </Card>
      ) : (
        <Table<Intel>
          rowKey="id"
          columns={columns}
          dataSource={rows}
          pagination={false}
          size="small"
          loading={refreshing}
          scroll={{ x: 900 }}
        />
      )}
    </section>
  )
}
