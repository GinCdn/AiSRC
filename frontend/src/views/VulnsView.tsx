import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  App,
  Button,
  Card,
  Col,
  Empty,
  Input,
  Pagination,
  Row,
  Segmented,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Typography
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type { TableProps } from 'antd'
import { PushpinFilled, PushpinOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { toListResult, userApi } from '@/api'
import { useAuthStore } from '@/store'
import { SEVERITY_COLOR, SEVERITY_LABEL, VULN_TYPE_LABEL, fmtLocalTime } from '@/utils/format'
import type { FindingView } from '@/types'
import ReportDrawer from '@/components/ReportDrawer'

const PAGE_SIZE = 100

/** 漏洞库统计概览。 */
interface VulnStats {
  total: number
  submitted: number
  ready: number
  by_severity: Record<string, number>
}

/** 提交状态筛选页签。 */
const SUBMIT_TABS = [
  { value: 'all', label: '全部' },
  { value: 'yes', label: '已提交' },
  { value: 'no', label: '待提交' }
]

/** 严重级 → echarts 用的十六进制色（同时兼容中英文标识）。 */
const SEV_HEX: Record<string, string> = {
  critical: '#f5222d',
  high: '#fa541c',
  medium: '#fa8c16',
  low: '#1677ff',
  info: '#8c8c8c',
  严重: '#f5222d',
  高危: '#fa541c',
  中危: '#fa8c16',
  低危: '#1677ff',
  信息: '#8c8c8c'
}

/** 图表统一文字色（浅色主题）。 */
const CHART_TEXT = '#475569'

const URL_RE = /https?:\/\/[^\s<>"'`]+/gi
const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g

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
const CRED_RE = /\b(api[_-]?key|token|secret|password|passwd|pwd|cookie|authorization|bearer)\b\s*[:=]\s*\S+/gi

function redact(text: string): string {
  return text
    .replace(URL_RE, '[已脱敏链接]')
    .replace(IP_RE, '[已脱敏IP]')
    .replace(CRED_RE, (m) => `${m.split(/[:=]/)[0].trim()}=[已脱敏]`)
}

/** 严重级元信息：中文名 + antd 标签色 + 图表色。 */
function sevMeta(severity: string): { label: string; color: string; hex: string } {
  const raw = String(severity || '')
  const key = raw.toLowerCase()
  return {
    label: SEVERITY_LABEL[key] || raw || '未定级',
    color: SEVERITY_COLOR[raw] || SEVERITY_COLOR[key] || 'default',
    hex: SEV_HEX[key] || SEV_HEX[raw] || '#8c8c8c'
  }
}

/** 生效严重级：用户复审等级优先，其次最终判定，再次 AI 原始等级。 */
function effSev(row: FindingView): string {
  return (
    str(row.effective_severity) || str(row.severity_final) || str(row.user_severity) || str(row.severity)
  )
}

/** 归属单位。 */
function ownerOf(row: FindingView): string {
  return str(row.owner) || str(row.edu_school)
}

/** 攻击链路步骤名（数组 / 对象两种形态都兜住）。 */
function chainMethods(row: FindingView): string[] {
  const raw: unknown = row.kill_chain
  if (!Array.isArray(raw)) return []
  return raw.map((item) => str(asRecord(item).method)).filter(Boolean)
}

/**
 * 全局漏洞库。
 *
 * 跨任务汇总通过人工审核的漏洞（已提交 / 待提交两类）；顶部用 Statistic 展示
 * 概览与严重级分布，并用 ECharts（暗色）画分布图。点击任意漏洞行复用
 * ReportDrawer 打开详情抽屉，写入完成后回读列表。
 */
export default function VulnsView() {
  const { message, modal } = App.useApp()

  const role = useAuthStore((s) => s.role)
  const writable = role === 'full'
  const isObserver = role === 'observer'

  const [stats, setStats] = useState<VulnStats>({ total: 0, submitted: 0, ready: 0, by_severity: {} })
  const [rows, setRows] = useState<FindingView[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [submitted, setSubmitted] = useState('all')
  const [severity, setSeverity] = useState('')
  const [searchDraft, setSearchDraft] = useState('')
  const [searchText, setSearchText] = useState('')
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)

  // 置顶：selected 为本页已勾选漏洞 id，toggling 为单条进行中的 id。
  const [selected, setSelected] = useState<string[]>([])
  const [toggling, setToggling] = useState<string[]>([])
  const [batchBusy, setBatchBusy] = useState(false)

  // 漏洞详情抽屉（复用 ReportDrawer）。
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerId, setDrawerId] = useState<string | null>(null)
  const [drawerTaskId, setDrawerTaskId] = useState('')

  /** 概览统计。 */
  const loadStats = useCallback(async () => {
    try {
      const res = await userApi.vulnStats()
      setStats({
        total: num(res?.total),
        submitted: num(res?.submitted),
        ready: num(res?.ready),
        by_severity: (res?.by_severity as Record<string, number>) || {}
      })
    } catch {
      /* 统计失败不阻断列表 */
    }
  }, [])

  /** 列表：双形态返回统一收敛。 */
  const loadList = useCallback(
    async (overrides: { page?: number; search?: string } = {}) => {
      const nextPage = overrides.page ?? page
      const nextSearch = overrides.search ?? searchText
      setRefreshing(true)
      try {
        const res = await userApi.vulns({
          submitted,
          severity: severity || undefined,
          q: nextSearch || undefined,
          limit: PAGE_SIZE,
          offset: (nextPage - 1) * PAGE_SIZE
        })
        const list = toListResult<FindingView>(res)
        setRows(list.items)
        setTotal(list.total)
        // 翻页 / 重载后清空勾选。
        setSelected([])
      } catch {
        setRows([])
        setTotal(0)
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    [submitted, severity, page, searchText]
  )

  // 筛选维度变化（含首屏）：回到第一页并同步刷新统计。
  useEffect(() => {
    setPage(1)
    setSelected([])
    void loadStats()
    void loadList({ page: 1 })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [submitted, severity])

  // 搜索防抖：180ms。
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const q = searchDraft.trim()
      setSearchText(q)
      setPage(1)
      void loadList({ page: 1, search: q })
    }, 180)
    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchDraft])

  const severityOptions = useMemo(() => Object.keys(stats.by_severity || {}), [stats.by_severity])
  const sevEntries = useMemo(
    () => Object.entries(stats.by_severity || {}).sort((a, b) => num(b[1]) - num(a[1])),
    [stats.by_severity]
  )
  /** 高危及以上（严重/高危）合计——统计卡第 4 格。 */
  const severeCount = useMemo(
    () =>
      sevEntries
        .filter(([k]) => ['严重', 'critical'].includes(String(k).toLowerCase()))
        .reduce((acc, [, v]) => acc + num(v), 0),
    [sevEntries]
  )
  const highCount = useMemo(
    () =>
      sevEntries
        .filter(([k]) => ['严重', '高危', 'critical', 'high'].includes(String(k).toLowerCase()))
        .reduce((acc, [, v]) => acc + num(v), 0),
    [sevEntries]
  )
  /** 统计卡副文案占比（与「过审漏洞」卡等高同构）。 */
  const pctOf = (n: number) => (stats.total > 0 ? `占过审 ${Math.round((n / stats.total) * 100)}%` : '占过审 0%')

  /** 严重级分布（饼图，数据来自 stats，全量且权威）。 */
  const severityOption = useMemo(() => {
    const data = sevEntries.map(([key, value]) => ({
      name: sevMeta(key).label,
      value: num(value),
      itemStyle: { color: sevMeta(key).hex }
    }))
    return {
      backgroundColor: 'transparent',
      textStyle: { color: CHART_TEXT },
      tooltip: { trigger: 'item' },
      legend: { bottom: 0, type: 'scroll', textStyle: { color: CHART_TEXT } },
      series: [
        {
          name: '严重级',
          type: 'pie',
          radius: ['42%', '66%'],
          center: ['50%', '44%'],
          avoidLabelOverlap: true,
          label: { color: CHART_TEXT, formatter: '{b} {c}' },
          labelLine: { lineStyle: { color: 'rgba(15,23,42,0.25)' } },
          itemStyle: { borderColor: '#ffffff', borderWidth: 2 },
          data
        }
      ]
    }
  }, [sevEntries])

  /** 漏洞类型分布（当前页条目的类型计数，条形图）。 */
  const vulnTypeOption = useMemo(() => {
    const counter = new Map<string, number>()
    rows.forEach((r) => {
      const key = str(r.vuln_type) || 'other'
      counter.set(key, (counter.get(key) || 0) + 1)
    })
    const keys = Array.from(counter.keys()).sort((a, b) => (counter.get(b) || 0) - (counter.get(a) || 0))
    return {
      backgroundColor: 'transparent',
      textStyle: { color: CHART_TEXT },
      grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      xAxis: {
        type: 'value',
        minInterval: 1,
        axisLabel: { color: CHART_TEXT },
        splitLine: { lineStyle: { color: 'rgba(15,23,42,0.08)' } }
      },
      yAxis: {
        type: 'category',
        data: keys.map((k) => VULN_TYPE_LABEL[k] || k),
        axisLabel: { color: CHART_TEXT }
      },
      series: [
        {
          name: '漏洞数',
          type: 'bar',
          barMaxWidth: 18,
          itemStyle: { color: '#7c5cff', borderRadius: [0, 4, 4, 0] },
          data: keys.map((k) => counter.get(k) || 0)
        }
      ]
    }
  }, [rows])

  /** 目标 / 归属展示：观摩角色脱敏。 */
  function targetText(row: FindingView): string {
    return isObserver ? '[已脱敏目标]' : str(row.target_url) || '-'
  }

  function ownerText(row: FindingView): string {
    return isObserver ? '[已脱敏]' : ownerOf(row) || '待确认'
  }

  function maskText(v: unknown): string {
    const text = str(v)
    return isObserver ? redact(text) : text
  }

  /** 打开漏洞详情抽屉。 */
  function openVuln(row: FindingView) {
    setDrawerId(row.id)
    setDrawerTaskId(row.task_id)
    setDrawerOpen(true)
  }

  /** 单条置顶。 */
  async function toggleTop(row: FindingView) {
    if (!writable || toggling.includes(row.id)) return
    const next = !row.is_top
    setToggling((prev) => [...prev, row.id])
    try {
      await userApi.vulnTop(row.id, next)
      setRows((prev) => prev.map((r) => (r.id === row.id ? { ...r, is_top: next } : r)))
      message.success(next ? '已置顶' : '已取消置顶')
    } catch {
      /* 错误提示已由 request 层统一处理 */
    } finally {
      setToggling((prev) => prev.filter((id) => id !== row.id))
    }
  }

  /** 批量置顶。 */
  function batchTop(isTop: boolean) {
    if (!writable || batchBusy || !selected.length) return
    const verb = isTop ? '置顶' : '取消置顶'
    const ids = [...selected]
    modal.confirm({
      title: `确认${verb}选中的 ${ids.length} 条漏洞？`,
      okText: `确认${verb}`,
      cancelText: '取消',
      onOk: async () => {
        setBatchBusy(true)
        try {
          const res = await userApi.vulnBatchTop(ids, isTop)
          const ok = res?.success_count ?? 0
          const failed = res?.failed_ids ?? []
          const idSet = new Set(ids)
          setRows((prev) => prev.map((r) => (idSet.has(r.id) ? { ...r, is_top: isTop } : r)))
          if (failed.length) {
            message.warning(`成功${verb} ${ok} 条，失败 ${failed.length} 条（记录可能已不存在）`)
          } else {
            message.success(`成功${verb} ${ok} 条`)
          }
          setSelected([])
        } catch {
          /* 错误提示已由 request 层统一处理 */
        } finally {
          setBatchBusy(false)
        }
      }
    })
  }

  const rowSelection: TableProps<FindingView>['rowSelection'] = writable
    ? {
        selectedRowKeys: selected,
        onChange: (keys) => setSelected(keys.map((k) => String(k)))
      }
    : undefined

  const columns: ColumnsType<FindingView> = [
    {
      title: '等级',
      key: 'severity',
      width: 100,
      render: (_, row) => {
        const meta = sevMeta(effSev(row))
        return <Tag color={meta.color}>{meta.label}</Tag>
      }
    },
    {
      title: '漏洞',
      key: 'vuln',
      render: (_, row) => {
        const chain = chainMethods(row)
        return (
          <Space direction="vertical" size={2} style={{ width: '100%' }}>
            <Space size={6}>
              {row.is_top ? <PushpinFilled style={{ color: '#faad14' }} /> : null}
              <Typography.Text strong>{maskText(row.title)}</Typography.Text>
            </Space>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {VULN_TYPE_LABEL[row.vuln_type] || row.vuln_type || '-'} ·{' '}
              <span className="mono">{targetText(row)}</span>
              {row.llm_model ? ` · ${row.llm_model}` : ''}
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              归属：{ownerText(row)} · 任务：
              <Link to={`/task/${row.task_id}`} onClick={(e) => e.stopPropagation()}>
                {str(row.task_name) || row.task_id}
              </Link>
            </Typography.Text>
            {chain.length ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }} className="nowrap-ellipsis">
                攻击链路：{chain.join(' → ')}
              </Typography.Text>
            ) : null}
          </Space>
        )
      }
    },
    {
      title: '提交状态',
      key: 'submitted',
      width: 130,
      render: (_, row) => (
        <Space direction="vertical" size={2}>
          {row.submitted ? <Tag color="green">✓ 已提交</Tag> : <Tag>◷ 待提交</Tag>}
          {row.confidence ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {String(row.confidence)}
            </Typography.Text>
          ) : null}
        </Space>
      )
    },
    {
      title: '时间',
      key: 'time',
      width: 170,
      render: (_, row) => (
        <span className="mono text-sub">
          {fmtLocalTime(str(row.user_reviewed_at) || row.created_at)}
        </span>
      )
    },
    {
      title: '操作',
      key: 'action',
      width: 130,
      hidden: !writable,
      render: (_, row) => (
        <Button
          size="small"
          type="text"
          icon={row.is_top ? <PushpinFilled /> : <PushpinOutlined />}
          loading={toggling.includes(row.id)}
          onClick={(e) => {
            e.stopPropagation()
            void toggleTop(row)
          }}
        >
          {row.is_top ? '取消置顶' : '置顶'}
        </Button>
      )
    }
  ]

  return (
    <section className="vulns-view">
      <header className="page-head">
        <div>
          <h2>全局漏洞库</h2>
          <p className="page-sub">
            跨任务汇总通过人工审核的漏洞——含已提交 SRC 与待提交两类，用于统一归档与复盘。
          </p>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            loading={refreshing && !loading}
            onClick={() => {
              void loadStats()
              void loadList()
            }}
          >
            刷新
          </Button>
          <Link to="/">
            <Button>返回任务</Button>
          </Link>
        </Space>
      </header>

      <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="过审漏洞" value={stats.total} />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              已提交 {stats.submitted} · 待提交 {stats.ready}
            </Typography.Text>
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="已提交" value={stats.submitted} valueStyle={{ color: '#16a34a' }} />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {pctOf(stats.submitted)}
            </Typography.Text>
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="待提交" value={stats.ready} valueStyle={{ color: '#d97706' }} />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {pctOf(stats.ready)}
            </Typography.Text>
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="高危及以上" value={highCount} valueStyle={{ color: '#fa541c' }} />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              严重 {severeCount} · 高危 {highCount - severeCount}
            </Typography.Text>
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
        <Col xs={24} lg={12}>
          <Card size="small" title="严重级分布" styles={{ body: { paddingTop: 4 } }}>
            {sevEntries.length ? (
              <ReactECharts option={severityOption} notMerge style={{ height: 240 }} />
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            size="small"
            title={`漏洞类型分布${rows.length ? `（当前页 ${rows.length} 条）` : ''}`}
            styles={{ body: { paddingTop: 4 } }}
          >
            {rows.length ? (
              <ReactECharts option={vulnTypeOption} notMerge style={{ height: 240 }} />
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
            )}
          </Card>
        </Col>
      </Row>

      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Segmented
            value={submitted}
            onChange={(v) => setSubmitted(String(v))}
            options={SUBMIT_TABS.map((t) => ({ value: t.value, label: t.label }))}
          />
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="搜索 标题 / 类型 / URL / 归属 / 任务"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
            style={{ width: 320 }}
          />
          <Select
            value={severity}
            onChange={(v) => setSeverity(v)}
            style={{ width: 150 }}
            options={[
              { value: '', label: '全部等级' },
              ...severityOptions.map((s) => ({ value: s, label: sevMeta(s).label }))
            ]}
          />
          {writable && selected.length > 0 ? (
            <>
              <Button size="small" icon={<PushpinFilled />} loading={batchBusy} onClick={() => batchTop(true)}>
                批量置顶
              </Button>
              <Button size="small" icon={<PushpinOutlined />} loading={batchBusy} onClick={() => batchTop(false)}>
                批量取消置顶
              </Button>
              <Button size="small" type="text" onClick={() => setSelected([])}>
                清空选择（{selected.length}）
              </Button>
            </>
          ) : null}
        </Space>

        <Table<FindingView>
          rowKey="id"
          columns={columns}
          dataSource={rows}
          pagination={false}
          size="small"
          loading={loading || refreshing}
          rowSelection={rowSelection}
          scroll={{ x: 980 }}
          locale={{ emptyText: '漏洞库暂无记录，人工审核通过的漏洞会自动汇总到这里' }}
          onRow={(row) => ({
            style: { cursor: 'pointer' },
            onClick: () => openVuln(row)
          })}
        />
        {total > PAGE_SIZE ? (
          <div style={{ marginTop: 12, textAlign: 'right' }}>
            <Pagination
              current={page}
              pageSize={PAGE_SIZE}
              total={total}
              showSizeChanger={false}
              showTotal={(t, range) => `${range[0]}-${range[1]} / ${t}`}
              onChange={(p) => {
                setPage(p)
                setSelected([])
                void loadList({ page: p })
              }}
            />
          </div>
        ) : null}
      </Card>

      <ReportDrawer
        open={drawerOpen}
        findingId={drawerId}
        taskId={drawerTaskId}
        onClose={() => setDrawerOpen(false)}
        onChanged={() => {
          void loadStats()
          void loadList()
        }}
      />
    </section>
  )
}
