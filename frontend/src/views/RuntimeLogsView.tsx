import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Button, Card, Empty, Input, Pagination, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { toListResult, userApi } from '@/api'
import { fmtLocalTime, prettyJSON } from '@/utils/format'
import type { RuntimeLog } from '@/types'

const PAGE_SIZE = 100

const LEVEL_COLOR: Record<string, string> = {
  error: 'red',
  warn: 'orange',
  info: 'blue'
}

/**
 * 全局运行异常日志。
 *
 * 视图对应 GET /api/runtime-logs（跨任务的 error/warn 事件），
 * 顶部统计来自 GET /api/runtime-logs/stats。
 */
export default function RuntimeLogsView() {
  const [stats, setStats] = useState<{ total: number; errors: number; warns: number; by_agent: Record<string, number> }>(
    { total: 0, errors: 0, warns: 0, by_agent: {} }
  )
  const [rows, setRows] = useState<RuntimeLog[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [level, setLevel] = useState('all')
  const [agent, setAgent] = useState('all')
  const [searchDraft, setSearchDraft] = useState('')
  const [searchText, setSearchText] = useState('')
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)

  /** 统计。 */
  const loadStats = useCallback(async () => {
    try {
      const res = await userApi.runtimeLogStats()
      setStats({
        total: Number(res?.total ?? 0),
        errors: Number(res?.errors ?? 0),
        warns: Number(res?.warns ?? 0),
        by_agent: (res?.by_agent as Record<string, number>) || {}
      })
    } catch {
      /* 统计失败不阻断列表 */
    }
  }, [])

  /** 列表。 */
  const loadList = useCallback(
    async (overrides: { page?: number; search?: string } = {}) => {
      setRefreshing(true)
      const nextPage = overrides.page ?? page
      const nextSearch = overrides.search ?? searchText
      try {
        const res = await userApi.runtimeLogs({
          level: level === 'all' ? undefined : level,
          agent: agent === 'all' ? undefined : agent,
          q: nextSearch || undefined,
          limit: PAGE_SIZE,
          offset: (nextPage - 1) * PAGE_SIZE
        })
        const list = toListResult<RuntimeLog>(res)
        setRows(list.items)
        setTotal(list.total)
      } catch {
        setRows([])
        setTotal(0)
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    [level, agent, page, searchText]
  )

  useEffect(() => {
    loadStats()
  }, [loadStats])

  useEffect(() => {
    loadList()
    // 仅依赖筛选维度，页码变化由 handlers 显式触发
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [level, agent])

  // 搜索防抖：180ms。
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearchText(searchDraft.trim())
      setPage(1)
      loadList({ page: 1, search: searchDraft.trim() })
    }, 180)
    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchDraft])

  const agentOptions = useMemo(() => {
    const names = Object.keys(stats.by_agent || {}).sort()
    return [
      { value: 'all', label: '全部 agent' },
      ...names.map((n) => ({ value: n, label: n || 'unknown' }))
    ]
  }, [stats.by_agent])

  const columns: ColumnsType<RuntimeLog> = [
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      width: 90,
      render: (v: string) => <Tag color={LEVEL_COLOR[v] || 'default'}>{(v || 'info').toUpperCase()}</Tag>
    },
    {
      title: '事件',
      key: 'kind',
      width: 190,
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{record.kind || 'event'}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.agent || 'unknown'}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '详情',
      dataIndex: 'message',
      key: 'message',
      render: (v: string, record) => (
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          <Typography.Text>{v}</Typography.Text>
          {record.payload && Object.keys(record.payload).length ? (
            <details>
              <summary style={{ cursor: 'pointer', color: 'var(--aisrc-text-sub)', fontSize: 12 }}>
                payload
              </summary>
              <pre className="code-block">{prettyJSON(record.payload)}</pre>
            </details>
          ) : null}
        </Space>
      )
    },
    {
      title: '任务',
      key: 'task',
      width: 200,
      render: (_, record) => (
        <Space direction="vertical" size={0} style={{ width: '100%' }}>
          <Link to={`/task/${record.task_id}`}>{record.task_name || record.task_id}</Link>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.task_status || 'unknown'}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '时间',
      dataIndex: 'ts',
      key: 'ts',
      width: 170,
      render: (v: string) => <span className="mono text-sub">{fmtLocalTime(v)}</span>
    }
  ]

  return (
    <section className="runtime-logs-view">
      <header className="page-head">
        <div>
          <h2>全局运行异常</h2>
          <p className="page-sub">
            集中查看跨任务 LLM / reviewer / worker / orchestrator 异常与安全收敛事件。
          </p>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} loading={refreshing} onClick={() => Promise.all([loadStats(), loadList()])}>
            刷新
          </Button>
          <Link to="/">
            <Button>返回任务</Button>
          </Link>
        </Space>
      </header>

      <div className="stat-grid">
        <div className="stat-card">
          <span className="stat-k">异常事件</span>
          <b className="stat-v">{stats.total}</b>
          <span className="text-sub" style={{ fontSize: 12 }}>
            Error {stats.errors} · Warn {stats.warns}
          </span>
        </div>
        <div className="stat-card danger">
          <span className="stat-k">错误</span>
          <b className="stat-v">{stats.errors}</b>
        </div>
        <div className="stat-card warn">
          <span className="stat-k">警告</span>
          <b className="stat-v">{stats.warns}</b>
        </div>
        <div className="stat-card">
          <span className="stat-k">Agent 来源</span>
          <b className="stat-v">{Object.keys(stats.by_agent || {}).length}</b>
        </div>
      </div>

      <Card size="small" style={{ marginBottom: 12 }}>
        <Space wrap>
          <Select
            value={level}
            onChange={(v) => {
              setLevel(v)
              setPage(1)
            }}
            style={{ width: 130 }}
            options={[
              { value: 'all', label: '全部级别' },
              { value: 'error', label: 'ERROR' },
              { value: 'warn', label: 'WARN' },
              { value: 'info', label: 'INFO' }
            ]}
          />
          <Select value={agent} onChange={(v) => setAgent(v)} style={{ width: 170 }} options={agentOptions} />
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="搜索 任务 / agent / kind / 错误详情"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
            style={{ width: 320 }}
          />
        </Space>
      </Card>

      {loading ? (
        <Card loading />
      ) : rows.length === 0 ? (
        <Card>
          <Empty description="当前筛选条件下没有运行异常事件" />
        </Card>
      ) : (
        <>
          <Table<RuntimeLog>
            rowKey="id"
            columns={columns}
            dataSource={rows}
            pagination={false}
            size="small"
            loading={refreshing}
            expandable={{
              expandedRowRender: (record) => (
                <pre className="code-block">{prettyJSON(record.payload || {})}</pre>
              ),
              rowExpandable: (record) => !!record.payload && Object.keys(record.payload).length > 0
            }}
          />
          {total > PAGE_SIZE ? (
            <div style={{ marginTop: 12, textAlign: 'right' }}>
              <Pagination
                current={page}
                pageSize={PAGE_SIZE}
                total={total}
                showSizeChanger={false}
                onChange={(p) => {
                  setPage(p)
                  loadList({ page: p })
                }}
              />
            </div>
          ) : null}
        </>
      )}
    </section>
  )
}
