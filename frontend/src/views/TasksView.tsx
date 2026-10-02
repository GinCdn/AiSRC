import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  App,
  Badge,
  Button,
  Card,
  Checkbox,
  Empty,
  Modal,
  Skeleton,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  BugOutlined,
  DeleteOutlined,
  EditOutlined,
  InfoCircleOutlined,
  PlusOutlined,
  PushpinFilled,
  PushpinOutlined,
  ReloadOutlined,
  ThunderboltOutlined,
  WarningOutlined
} from '@ant-design/icons'
import { userApi } from '@/api'
import { useAuthStore } from '@/store'
import {
  TASK_STATUS_BADGE,
  TASK_STATUS_LABEL,
  TARGET_STATUS_LABEL,
  engineLabel,
  fmtLocalTime,
  targetSourceLabel,
  taskScopeText
} from '@/utils/format'
import type { Task } from '@/types'
import TaskEditModal from '@/components/TaskEditModal'

/**
 * 任务列表页。
 *
 * 关键行为：
 *   1. 有运行中任务时 5s 轮询，否则 15s 慢轮询（保持远端状态可见）；
 *   2. 置顶支持单条与批量（勾选后出现批量操作栏），仅 full 角色可见；
 *   3. 删除需二次确认，按当前登录身份提交（后端校验写权限）。
 */
export default function TasksView() {
  const navigate = useNavigate()
  const { message } = App.useApp()

  const role = useAuthStore((s) => s.role)
  const writable = role === 'full'
  const isObserver = role === 'observer'

  const [tasks, setTasks] = useState<Task[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // 置顶相关
  const [selected, setSelected] = useState<string[]>([])
  const [toggling, setToggling] = useState<string[]>([])

  // 编辑弹窗
  const [editOpen, setEditOpen] = useState(false)
  const [editingTask, setEditingTask] = useState<Task | null>(null)

  // 删除确认
  const [delTarget, setDelTarget] = useState<Task | null>(null)
  const [delError, setDelError] = useState('')
  const [deleting, setDeleting] = useState(false)

  const pollTimer = useRef<number | null>(null)
  const hasRunning = useMemo(() => tasks.some((t) => t.status === 'running'), [tasks])

  /** 拉取列表；background=true 时不显示骨架屏与刷新态。 */
  const load = useCallback(
    async (opts: { background?: boolean } = {}) => {
      if (!opts.background) setRefreshing(true)
      try {
        const list = await userApi.listTasks()
        setTasks(Array.isArray(list) ? list : [])
      } catch {
        /* 错误提示已由 request 层统一处理 */
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    []
  )

  // 轮询：有运行中任务时加快刷新。
  useEffect(() => {
    if (pollTimer.current !== null) window.clearInterval(pollTimer.current)
    const ms = hasRunning ? 5000 : 15000
    pollTimer.current = window.setInterval(() => load({ background: true }), ms)
    return () => {
      if (pollTimer.current !== null) window.clearInterval(pollTimer.current)
      pollTimer.current = null
    }
  }, [hasRunning, load])

  useEffect(() => {
    load()
  }, [load])

  /** 单条切换置顶：就地更新，避免整表刷新。 */
  async function toggleTop(task: Task) {
    if (toggling.includes(task.id)) return
    const next = !task.is_top
    setToggling((prev) => [...prev, task.id])
    try {
      await userApi.taskTop(task.id, next)
      setTasks((prev) => prev.map((t) => (t.id === task.id ? { ...t, is_top: next } : t)))
      message.success(next ? '已置顶' : '已取消置顶')
    } catch (e) {
      message.error(`置顶失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setToggling((prev) => prev.filter((id) => id !== task.id))
    }
  }

  /** 批量置顶。 */
  async function batchTop(isTop: boolean) {
    if (!selected.length) return
    try {
      const res = await userApi.taskBatchTop(selected, isTop)
      const ok = res?.success_count ?? 0
      const failed = res?.failed_ids ?? []
      const idSet = new Set(selected)
      setTasks((prev) => prev.map((t) => (idSet.has(t.id) ? { ...t, is_top: isTop } : t)))
      message.success(
        `成功${isTop ? '置顶' : '取消置顶'} ${ok} 个任务${failed.length ? `，${failed.length} 个失败` : ''}`
      )
      setSelected([])
    } catch (e) {
      message.error(`批量操作失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  /** 打开编辑弹窗（先拉最新详情，避免用到列表里的旧字段）。 */
  async function openEdit(task: Task) {
    try {
      const detail = await userApi.getTask(task.id)
      setEditingTask(detail)
      setEditOpen(true)
    } catch (e) {
      message.error(`加载任务失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  /** 确认删除：二次确认后按当前登录身份提交（后端 `requireWrite` 校验权限）。 */
  async function confirmDelete() {
    if (!delTarget || deleting) return
    const task = delTarget
    setDeleting(true)
    setDelError('')
    try {
      await userApi.deleteTask(task.id)
      setTasks((prev) => prev.filter((t) => t.id !== task.id))
      setDelTarget(null)
      message.success('任务已删除')
    } catch (e) {
      setDelError(`删除失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setDeleting(false)
    }
  }

  /** 本页（当前列表）是否已全选。 */
  const allChecked = tasks.length > 0 && tasks.every((t) => selected.includes(t.id))
  /** 是否有部分选中（驱动表头复选框的半选态）。 */
  const someChecked = selected.length > 0

  const columns: ColumnsType<Task> = [
    {
      // 表头全选：勾选=本页全选，取消=清空选择（对齐原版 toggleAllChecked）
      title: (
        <Space size={4}>
          <Checkbox
            checked={allChecked}
            indeterminate={someChecked && !allChecked}
            disabled={!tasks.length}
            onChange={(e) => setSelected(e.target.checked ? tasks.map((t) => t.id) : [])}
          />
          <span style={{ fontSize: 12, whiteSpace: 'nowrap' }}>全选本页</span>
        </Space>
      ),
      key: 'select',
      width: 96,
      hidden: !writable,
      render: (_, record) => (
        <Checkbox
          checked={selected.includes(record.id)}
          onChange={(e) =>
            setSelected((prev) =>
              e.target.checked ? [...prev, record.id] : prev.filter((id) => id !== record.id)
            )
          }
          onClick={(e) => e.stopPropagation()}
        />
      )
    },
    {
      title: '任务',
      key: 'name',
      render: (_, record) => (
        <Space direction="vertical" size={2} style={{ width: '100%' }}>
          <Space size={6}>
            {record.is_top ? <PushpinFilled style={{ color: '#faad14' }} /> : null}
            {record.status === 'running' ? <Badge status="processing" /> : null}
            <Typography.Text strong>{record.name}</Typography.Text>
            {record.pending_user_review && record.pending_user_review > 0 ? (
              <Tooltip title={`${record.pending_user_review} 个漏洞待复审`}>
                <Tag color="red">{record.pending_user_review} 待复审</Tag>
              </Tooltip>
            ) : null}
          </Space>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.src_type === 'enterprise' ? '企业SRC' : 'EduSRC'} · {targetSourceLabel(record)} ·
            并发 {record.concurrency} · 深挖 ×{record.deepen_cap ?? 2} · {engineLabel(record.engine)}
          </Typography.Text>
          <Typography.Text type="secondary" className="nowrap-ellipsis" style={{ fontSize: 12 }}>
            {taskScopeText(record)}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 110,
      render: (status: string) => (
        <Badge status={TASK_STATUS_BADGE[status] || 'default'} text={TASK_STATUS_LABEL[status] || status} />
      )
    },
    {
      title: '目标',
      key: 'targets',
      width: 150,
      render: (_, record) => {
        const stats = record.target_stats || {}
        const total = Object.values(stats).reduce((acc, n) => acc + (Number(n) || 0), 0)
        if (!total) return <Typography.Text type="secondary">-</Typography.Text>
        return (
          <Space size={4} wrap>
            {Object.entries(stats).map(([k, v]) => (
              <Tag key={k} style={{ marginInlineEnd: 0 }}>
                {TARGET_STATUS_LABEL[k] || k} {v}
              </Tag>
            ))}
          </Space>
        )
      }
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 170,
      render: (v: string) => <span className="mono text-sub">{fmtLocalTime(v)}</span>
    },
    {
      title: '操作',
      key: 'action',
      width: 190,
      render: (_, record) => (
        <Space size={4} onClick={(e) => e.stopPropagation()}>
          {writable ? (
            <>
              <Button
                size="small"
                type="text"
                icon={record.is_top ? <PushpinFilled /> : <PushpinOutlined />}
                loading={toggling.includes(record.id)}
                onClick={() => toggleTop(record)}
              >
                {record.is_top ? '取消置顶' : '置顶'}
              </Button>
              <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openEdit(record)}>
                编辑
              </Button>
              <Button
                size="small"
                type="text"
                danger
                icon={<DeleteOutlined />}
                onClick={() => {
                  setDelTarget(record)
                  setDelToken('')
                  setDelError('')
                }}
              >
                删除
              </Button>
            </>
          ) : (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              只读
            </Typography.Text>
          )}
        </Space>
      )
    }
  ]

  return (
    <section className="tasks-view">
      <header className="page-head">
        <div>
          <h2>任务列表</h2>
          <p className="page-sub">点击任务行进入任务看板，查看实时进展与复审队列</p>
        </div>
        <Space wrap>
          <Button icon={<ReloadOutlined />} loading={refreshing && !loading} onClick={() => load()}>
            刷新
          </Button>
          {writable ? (
            <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/create')}>
              新建任务
            </Button>
          ) : null}
          {!isObserver ? (
            <>
              <Link to="/vulns">
                <Button icon={<BugOutlined />}>全局漏洞库</Button>
              </Link>
              <Link to="/intel">
                <Button icon={<ThunderboltOutlined />}>全局情报库</Button>
              </Link>
            </>
          ) : null}
          <Link to="/runtime-logs">
            <Button icon={<WarningOutlined />}>运行异常</Button>
          </Link>
        </Space>
      </header>

      {writable && selected.length > 0 ? (
        <Card size="small" style={{ marginBottom: 12 }}>
          <Space>
            <Typography.Text>已选 {selected.length} 个任务</Typography.Text>
            <Button size="small" icon={<PushpinFilled />} onClick={() => batchTop(true)}>
              批量置顶
            </Button>
            <Button size="small" icon={<PushpinOutlined />} onClick={() => batchTop(false)}>
              批量取消置顶
            </Button>
            <Button size="small" type="text" onClick={() => setSelected([])}>
              清空选择
            </Button>
          </Space>
        </Card>
      ) : null}

      {loading ? (
        <Card>
          <Skeleton active paragraph={{ rows: 6 }} />
        </Card>
      ) : tasks.length === 0 ? (
        <Card>
          <Empty description="还没有任务，点右上角「新建任务」创建第一个挖掘任务">
            {writable ? (
              <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/create')}>
                新建任务
              </Button>
            ) : null}
          </Empty>
        </Card>
      ) : (
        <Table<Task>
          rowKey="id"
          columns={columns}
          dataSource={tasks}
          pagination={false}
          size="middle"
          scroll={{ x: 1080 }}
          onRow={(record) => ({
            style: { cursor: 'pointer' },
            onClick: () => navigate(`/task/${record.id}`)
          })}
        />
      )}

      <TaskEditModal
        open={editOpen}
        task={editingTask}
        onClose={() => {
          setEditOpen(false)
          setEditingTask(null)
        }}
        onSaved={() => {
          setEditOpen(false)
          setEditingTask(null)
          load()
        }}
      />

      <Modal
        open={!!delTarget}
        title="删除任务"
        okText={deleting ? '删除中…' : '确认删除'}
        okButtonProps={{ danger: true, loading: deleting }}
        cancelText="取消"
        onOk={confirmDelete}
        onCancel={() => {
          if (deleting) return
          setDelTarget(null)
          setDelError('')
        }}
      >
        {delTarget ? (
          <Space direction="vertical" style={{ width: '100%' }}>
            <Typography.Paragraph style={{ marginBottom: 0 }}>
              即将删除任务 <Typography.Text strong>「{delTarget.name}」</Typography.Text>。
            </Typography.Paragraph>
            <Typography.Paragraph type="warning" style={{ marginBottom: 0 }}>
              <InfoCircleOutlined /> 此操作会一并删除该任务的
              <Typography.Text strong>全部目标、漏洞、审核与通杀记录</Typography.Text>，且
              <Typography.Text strong>不可恢复</Typography.Text>。（全局情报库不受影响）
            </Typography.Paragraph>
            {delError ? <Typography.Text type="danger">{delError}</Typography.Text> : null}
          </Space>
        ) : null}
      </Modal>
    </section>
  )
}
