/**
 * 代理池编辑器（对标 AutoHunter Vue 版 ProxyPoolEditor.vue）。
 *
 * 设计：默认自包含（自己拉列表、自己调增删改测接口与批量导入），
 * 与 Vue 版一致，父组件直接 `<ProxyPoolEditor />` 即可。
 * 同时保留 value / onChange / enabled / onToggleEnabled / onImport 受控入口，
 * 供需要「父组件持有列表」的场景使用；`value` 传入时进入受控模式，不再自行拉取。
 */
import { useEffect, useRef, useState } from 'react'
import {
  App,
  Button,
  Card,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { systemApi, userApi } from '@/api'
import type { ProxyItem } from '@/types'
import { SecretPassword } from '@/components/PasswordEye'

/** 代理行（在 ProxyItem 基础上补运行期状态字段）。 */
interface ProxyRow extends ProxyItem {
  /** 展示名（后端可选下发）。 */
  name?: string
  /** 运行期健康状态：正常 / cooldown。 */
  status?: string
  /** 冷却剩余秒数。 */
  cooldown_remaining_sec?: number
}

/** 导入结果。 */
interface ImportResult {
  added: number
  skipped: number
  invalid: number
}

interface Props {
  /** 受控列表；传入即受控（不再自行拉取）。 */
  value?: ProxyItem[]
  /** 列表变化回调（受控模式下由父组件持有）。 */
  onChange?: (items: ProxyItem[]) => void
  /** 受控的「启用代理池」开关。 */
  enabled?: boolean
  /** 开关切换回调。 */
  onToggleEnabled?: (enabled: boolean) => void | Promise<void>
  /** 自定义批量导入实现；缺省走 systemApi.proxyImport。 */
  onImport?: (text: string, file?: File | null) => Promise<Record<string, unknown>>
  /** 禁用所有写操作（非 full 角色）。 */
  disabled?: boolean
}

/** 协议选项。 */
const PROTOCOL_OPTIONS = [
  { value: 'http', label: 'HTTP' },
  { value: 'https', label: 'HTTPS' },
  { value: 'socks5', label: 'SOCKS5' }
]

/** 编辑草稿。 */
interface EditDraft {
  name: string
  protocol: string
  host: string
  port: number | null
  username: string
  password: string
  note: string
}

const EMPTY_DRAFT: EditDraft = {
  name: '',
  protocol: 'http',
  host: '',
  port: null,
  username: '',
  password: '',
  note: ''
}

/** 从接口返回里读出列表与开关（兼容裸数组与 { enabled, proxies } 两种形态）。 */
function readList(res: unknown): { enabled: boolean | null; items: ProxyItem[] } {
  if (Array.isArray(res)) return { enabled: null, items: res as ProxyItem[] }
  if (res && typeof res === 'object') {
    const obj = res as { enabled?: unknown; proxies?: unknown }
    const items = Array.isArray(obj.proxies) ? (obj.proxies as ProxyItem[]) : []
    return { enabled: typeof obj.enabled === 'boolean' ? obj.enabled : null, items }
  }
  return { enabled: null, items: [] }
}

/** 从接口返回里读出 enabled 布尔。 */
function readEnabled(res: unknown): boolean | null {
  if (res && typeof res === 'object' && typeof (res as { enabled?: unknown }).enabled === 'boolean') {
    return (res as { enabled: boolean }).enabled
  }
  return null
}

/** 错误文案。 */
function errText(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e)
  return msg.replace(/^\d+\s*/, '')
}

/** 代理池编辑器。 */
export default function ProxyPoolEditor({
  value,
  onChange,
  enabled: enabledProp,
  onToggleEnabled,
  onImport,
  disabled = false
}: Props) {
  const { message, modal } = App.useApp()
  const controlled = useRef(value !== undefined).current

  const [items, setItems] = useState<ProxyRow[]>(controlled ? (value as ProxyRow[]) : [])
  const [enabledFlag, setEnabledFlag] = useState(!!enabledProp)
  const [loading, setLoading] = useState(!controlled)

  // 添加代理
  const [showAdd, setShowAdd] = useState(false)
  const [addBusy, setAddBusy] = useState(false)
  const [addForm, setAddForm] = useState({
    name: '',
    protocol: 'http',
    host: '',
    port: null as number | null,
    username: '',
    password: ''
  })

  // 批量导入
  const [showImport, setShowImport] = useState(false)
  const [importText, setImportText] = useState('')
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<ImportResult | null>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  // 行内编辑
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editDraft, setEditDraft] = useState<EditDraft>(EMPTY_DRAFT)
  const [editBusy, setEditBusy] = useState(false)

  // 测试
  const [testing, setTesting] = useState<Record<string, boolean>>({})
  const [testResult, setTestResult] = useState<Record<string, string>>({})
  const [testingAll, setTestingAll] = useState(false)

  /** 更新列表（受控时回吐给父组件）。 */
  function setList(next: ProxyRow[]) {
    setItems(next)
    onChange?.(next)
  }

  /** 拉取列表。 */
  async function load() {
    if (controlled) return
    setLoading(true)
    try {
      const parsed = readList(await userApi.proxyList())
      setItems(parsed.items)
      if (parsed.enabled !== null) setEnabledFlag(parsed.enabled)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    // 仅挂载时拉一次
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // 受控开关同步。
  useEffect(() => {
    if (typeof enabledProp === 'boolean') setEnabledFlag(enabledProp)
  }, [enabledProp])

  // 受控列表同步。
  useEffect(() => {
    if (controlled && Array.isArray(value)) setItems(value as ProxyRow[])
  }, [controlled, value])

  /** 全局启用 / 关闭。 */
  async function onToggleGlobal(next: boolean) {
    if (disabled) return
    try {
      const on = readEnabled(await userApi.proxyToggle(next)) ?? next
      setEnabledFlag(on)
      await onToggleEnabled?.(on)
      message.success(on ? '代理池已启用：被封后自动/手动换 IP' : '代理池已关闭：全部直连')
    } catch (e) {
      message.error(errText(e))
    }
  }

  /** 新增代理。 */
  async function submitAdd() {
    const port = Number(addForm.port)
    if (!addForm.host.trim() || !Number.isInteger(port) || port < 1 || port > 65535) {
      message.warning('host 与端口（1-65535）必填')
      return
    }
    setAddBusy(true)
    try {
      await userApi.proxyAdd({
        name: addForm.name.trim(),
        protocol: addForm.protocol,
        host: addForm.host.trim(),
        port,
        username: addForm.username.trim(),
        password: addForm.password,
        enabled: true
      })
      message.success('已添加代理')
      setShowAdd(false)
      setAddForm({ name: '', protocol: 'http', host: '', port: null, username: '', password: '' })
      await load()
    } catch (e) {
      const msg = errText(e)
      message.error(msg.includes('409') ? '该代理已存在' : msg)
    } finally {
      setAddBusy(false)
    }
  }

  /** 行启用开关。 */
  async function toggleRow(row: ProxyRow) {
    if (disabled) return
    const next = row.enabled === false
    try {
      await userApi.proxyUpdate(row.id, { enabled: next })
      setList(items.map((r) => (r.id === row.id ? { ...r, enabled: next } : r)))
    } catch (e) {
      message.error(errText(e))
    }
  }

  /** 删除行。 */
  function removeRow(row: ProxyRow) {
    if (disabled) return
    modal.confirm({
      title: '删除代理',
      content: `确认删除代理「${row.name || row.display || row.host}」？`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          await userApi.proxyDelete(row.id)
          setList(items.filter((r) => r.id !== row.id))
          message.success('已删除')
        } catch (e) {
          message.error(errText(e))
        }
      }
    })
  }

  /** 单条测试（后端契约：POST /api/proxy/test {ids:[...]} → {total, results:[{ok,latency,error}]}）。 */
  async function testRow(row: ProxyRow) {
    setTesting((p) => ({ ...p, [row.id]: true }))
    setTestResult((p) => {
      const n = { ...p }
      delete n[row.id]
      return n
    })
    try {
      const res = (await userApi.proxyTest({ ids: [row.id] })) as {
        total?: number
        results?: Array<{ id?: string; ok?: boolean; latency?: number; error?: string }>
      }
      const item = res?.results?.[0]
      setTestResult((p) => ({
        ...p,
        [row.id]: item?.ok ? `连通 ${item.latency ?? '?'}ms` : item?.error || '测试失败'
      }))
      await load()
    } catch (e) {
      setTestResult((p) => ({ ...p, [row.id]: errText(e) }))
    } finally {
      setTesting((p) => ({ ...p, [row.id]: false }))
    }
  }

  /** 批量测试全部启用代理（后端一次探测完，逐条串行打点，避免瞬间打满出口）。 */
  async function testAll() {
    if (!items.length) return
    setTestingAll(true)
    try {
      const res = (await userApi.proxyTest({})) as {
        total?: number
        results?: Array<{ id?: string; ok?: boolean; latency?: number; error?: string }>
      }
      const next: Record<string, string> = {}
      for (const item of res?.results || []) {
        if (!item.id) continue
        next[item.id] = item.ok ? `连通 ${item.latency ?? '?'}ms` : item.error || '测试失败'
      }
      setTestResult(next)
      const okCount = Object.values(next).filter((v) => v.startsWith('连通')).length
      message.success(`测试完成：${okCount}/${Object.keys(next).length} 条连通`)
      await load()
    } catch (e) {
      message.error(errText(e))
    } finally {
      setTestingAll(false)
    }
  }

  /** 选择导入文件。 */
  function onImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    setImportFile(e.target.files?.[0] || null)
  }

  /** 提交导入。 */
  async function submitImport() {
    if (!importText.trim() && !importFile) {
      message.warning('粘贴代理文本或选择 txt 文件')
      return
    }
    setImporting(true)
    setImportResult(null)
    try {
      const res = onImport
        ? await onImport(importText, importFile)
        : await systemApi.proxyImport(importText, importFile)
      const obj = res as { added?: number; skipped?: number; invalid?: number }
      setImportResult({
        added: Number(obj?.added ?? 0),
        skipped: Number(obj?.skipped ?? 0),
        invalid: Number(obj?.invalid ?? 0)
      })
      setImportText('')
      setImportFile(null)
      // 清空原生文件框：否则文件名仍显示但状态已清，同文件二次选择不触发 change。
      if (fileRef.current) fileRef.current.value = ''
      await load()
      message.success('导入完成')
    } catch (e) {
      message.error(errText(e))
    } finally {
      setImporting(false)
    }
  }

  /** 进入行内编辑。 */
  function beginEdit(row: ProxyRow) {
    if (disabled) return
    setEditingId(row.id)
    setEditDraft({
      name: row.name || '',
      protocol: row.protocol || 'http',
      host: row.host || '',
      port: row.port ?? null,
      username: row.username || '',
      password: '',
      note: row.note || ''
    })
  }

  function cancelEdit() {
    setEditingId(null)
    setEditDraft(EMPTY_DRAFT)
  }

  /** 保存行内编辑（密码留空表示不修改）。 */
  async function saveEdit() {
    const id = editingId
    if (!id) return
    const port = Number(editDraft.port)
    if (!editDraft.host.trim() || !Number.isInteger(port) || port < 1 || port > 65535) {
      message.warning('host 与端口（1-65535）必填')
      return
    }
    setEditBusy(true)
    try {
      const patch: Partial<ProxyItem> = {
        name: editDraft.name.trim(),
        protocol: editDraft.protocol,
        host: editDraft.host.trim(),
        port,
        username: editDraft.username.trim(),
        note: editDraft.note.trim()
      }
      if (editDraft.password) patch.password = editDraft.password
      await userApi.proxyUpdate(id, patch)
      setList(
        items.map((r) =>
          r.id === id
            ? {
                ...r,
                name: patch.name as string,
                protocol: patch.protocol as string,
                host: patch.host as string,
                port,
                username: patch.username as string,
                note: patch.note as string
              }
            : r
        )
      )
      message.success('已保存')
      cancelEdit()
      await load()
    } catch (e) {
      message.error(errText(e))
    } finally {
      setEditBusy(false)
    }
  }

  const columns: ColumnsType<ProxyRow> = [
    { title: '名称', dataIndex: 'name', key: 'name', width: 150, render: (v: string) => v || '-' },
    {
      title: '协议',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 90,
      render: (v: string) => <Tag>{v || 'http'}</Tag>
    },
    {
      title: '地址',
      key: 'addr',
      render: (_, row) => <code>{row.display || `${row.host}:${row.port}`}</code>
    },
    {
      title: '状态',
      key: 'status',
      width: 120,
      render: (_, row) => {
        const cooling = row.status === 'cooldown'
        return (
          <Space size={6}>
            <span
              style={{
                display: 'inline-block',
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: cooling ? 'var(--aisrc-warn)' : 'var(--aisrc-success)'
              }}
            />
            {cooling ? (
              <Tooltip title="连续连接失败，冷却中">
                <span>冷却 {row.cooldown_remaining_sec ?? '?'}s</span>
              </Tooltip>
            ) : (
              <span>正常</span>
            )}
          </Space>
        )
      }
    },
    {
      title: '启用',
      key: 'enabled',
      width: 80,
      render: (_, row) => (
        <Switch checked={row.enabled !== false} disabled={disabled} size="small" onChange={() => void toggleRow(row)} />
      )
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      render: (_, row) => (
        <Space size={4} wrap>
          <Button size="small" type="text" icon={<EditOutlined />} disabled={disabled} onClick={() => beginEdit(row)}>
            编辑
          </Button>
          <Button
            size="small"
            type="text"
            disabled={testing[row.id]}
            onClick={() => void testRow(row)}
          >
            {testing[row.id] ? '测试中…' : '测试'}
          </Button>
          <Button
            size="small"
            type="text"
            danger
            icon={<DeleteOutlined />}
            disabled={disabled}
            onClick={() => removeRow(row)}
          />
          {testResult[row.id] ? (
            <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block' }}>
              {testResult[row.id]}
            </Typography.Text>
          ) : null}
        </Space>
      )
    }
  ]

  return (
    <div className="proxy-pool" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <Space align="start">
          <Switch checked={enabledFlag} disabled={disabled} onChange={(v) => void onToggleGlobal(v)} />
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <Typography.Text strong>启用代理池</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {enabledFlag ? '挖洞流量走代理，被封自动/手动换 IP' : '关闭中：全部直连'}
            </Typography.Text>
          </div>
        </Space>
        <Space>
          <Button icon={<ReloadOutlined />} disabled={showImport} onClick={() => setShowImport((v) => !v)}>
            导入 txt / 粘贴
          </Button>
          <Button icon={<ThunderboltOutlined />} loading={testingAll} disabled={!items.length} onClick={() => void testAll()}>
            测试全部
          </Button>
          <Button type="primary" icon={<PlusOutlined />} disabled={disabled} onClick={() => setShowAdd((v) => !v)}>
            添加代理
          </Button>
        </Space>
      </div>

      {showAdd ? (
        <Card size="small">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
            <div>
              <Typography.Text>名称</Typography.Text>
              <Input
                value={addForm.name}
                placeholder="可留空自动命名"
                onChange={(e) => setAddForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div>
              <Typography.Text>协议</Typography.Text>
              <Select
                style={{ width: '100%' }}
                value={addForm.protocol}
                options={PROTOCOL_OPTIONS}
                onChange={(v: string) => setAddForm((f) => ({ ...f, protocol: v }))}
              />
            </div>
            <div>
              <Typography.Text>host</Typography.Text>
              <Input
                value={addForm.host}
                placeholder="1.2.3.4"
                onChange={(e) => setAddForm((f) => ({ ...f, host: e.target.value }))}
              />
            </div>
            <div>
              <Typography.Text>端口</Typography.Text>
              <InputNumber
                style={{ width: '100%' }}
                min={1}
                max={65535}
                value={addForm.port}
                placeholder="8080"
                onChange={(v) => setAddForm((f) => ({ ...f, port: v ?? null }))}
              />
            </div>
            <div>
              <Typography.Text>用户名</Typography.Text>
              <Input
                value={addForm.username}
                placeholder="可空"
                onChange={(e) => setAddForm((f) => ({ ...f, username: e.target.value }))}
              />
            </div>
            <div>
              <Typography.Text>密码</Typography.Text>
              <SecretPassword
                value={addForm.password}
                placeholder="可空"
                onChange={(e) => setAddForm((f) => ({ ...f, password: e.target.value }))}
              />
            </div>
          </div>
          <Space style={{ marginTop: 12 }}>
            <Button type="primary" loading={addBusy} onClick={() => void submitAdd()}>
              保存
            </Button>
            <Button onClick={() => setShowAdd(false)}>取消</Button>
          </Space>
        </Card>
      ) : null}

      {showImport ? (
        <Card size="small">
          <Typography.Text>
            粘贴代理（每行一条，支持 <code>scheme://user:pass@host:port</code>、<code>协议|host|port|用户|密码</code>、
            <code>host:port</code>）
          </Typography.Text>
          <Input.TextArea
            style={{ marginTop: 8 }}
            rows={6}
            value={importText}
            placeholder={'http://1.2.3.4:8080\nsocks5://user:pass@5.6.7.8:1080\n9.9.9.9:3128'}
            onChange={(e) => setImportText(e.target.value)}
          />
          <div style={{ marginTop: 8 }}>
            <Typography.Text>或从 txt 文件导入</Typography.Text>
            <input ref={fileRef} type="file" accept=".txt,.text,.list,.log,*/*" onChange={onImportFile} />
          </div>
          <Space style={{ marginTop: 12 }}>
            <Button type="primary" loading={importing} onClick={() => void submitImport()}>
              导入
            </Button>
            <Button
              onClick={() => {
                setShowImport(false)
                setImportResult(null)
              }}
            >
              关闭
            </Button>
          </Space>
          {importResult ? (
            <Typography.Paragraph style={{ marginTop: 10, marginBottom: 0 }}>
              新增 <b>{importResult.added}</b> 条，重复跳过 <b>{importResult.skipped}</b> 条，非法/无效{' '}
              <b>{importResult.invalid}</b> 行
            </Typography.Paragraph>
          ) : null}
        </Card>
      ) : null}

      {loading ? (
        <Card loading />
      ) : !items.length ? (
        <div style={{ padding: '12px 0', color: 'var(--aisrc-text-sub)', fontSize: 13 }}>
          代理池为空。被封 IP 前提前把代理倒进来；不启用也不影响正常挖掘（直连）。
        </div>
      ) : (
        <Table<ProxyRow>
          rowKey="id"
          size="small"
          columns={columns}
          dataSource={items}
          pagination={false}
          expandable={{
            expandedRowKeys: editingId ? [editingId] : [],
            showExpandColumn: false,
            expandedRowRender: () => (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
                <div>
                  <Typography.Text>名称</Typography.Text>
                  <Input
                    value={editDraft.name}
                    onChange={(e) => setEditDraft((d) => ({ ...d, name: e.target.value }))}
                  />
                </div>
                <div>
                  <Typography.Text>协议</Typography.Text>
                  <Select
                    style={{ width: '100%' }}
                    value={editDraft.protocol}
                    options={PROTOCOL_OPTIONS}
                    onChange={(v: string) => setEditDraft((d) => ({ ...d, protocol: v }))}
                  />
                </div>
                <div>
                  <Typography.Text>host</Typography.Text>
                  <Input
                    value={editDraft.host}
                    onChange={(e) => setEditDraft((d) => ({ ...d, host: e.target.value }))}
                  />
                </div>
                <div>
                  <Typography.Text>端口</Typography.Text>
                  <InputNumber
                    style={{ width: '100%' }}
                    min={1}
                    max={65535}
                    value={editDraft.port}
                    onChange={(v) => setEditDraft((d) => ({ ...d, port: v ?? null }))}
                  />
                </div>
                <div>
                  <Typography.Text>用户名</Typography.Text>
                  <Input
                    value={editDraft.username}
                    onChange={(e) => setEditDraft((d) => ({ ...d, username: e.target.value }))}
                  />
                </div>
                <div>
                  <Typography.Text>密码</Typography.Text>
                  <SecretPassword
                    value={editDraft.password}
                    placeholder="留空不修改"
                    onChange={(e) => setEditDraft((d) => ({ ...d, password: e.target.value }))}
                  />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <Typography.Text>备注</Typography.Text>
                  <Input
                    value={editDraft.note}
                    onChange={(e) => setEditDraft((d) => ({ ...d, note: e.target.value }))}
                  />
                </div>
                <Space style={{ gridColumn: '1 / -1' }}>
                  <Button type="primary" loading={editBusy} onClick={() => void saveEdit()}>
                    保存
                  </Button>
                  <Button onClick={cancelEdit}>取消</Button>
                </Space>
              </div>
            )
          }}
        />
      )}

      <Typography.Paragraph type="secondary" style={{ marginBottom: 0, fontSize: 12, lineHeight: 1.6 }}>
        覆盖 Worker 的 http_request 和 run_shell。连不上代理才换下一个；读超时和证书错误不换。
        明确的 WAF 拦截页：GET/HEAD 自动换出口并重试一次，POST 等写请求只换出口、不自动重放。
        也可由 Worker 调用 rotate_proxy，登录态会保留。不启用或没有可用代理时继续直连。
      </Typography.Paragraph>
    </div>
  )
}
