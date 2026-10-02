import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { App, Badge, Button, Dropdown, Layout, Menu, Tag, Tooltip } from 'antd'
import {
  AppstoreOutlined,
  BugOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SettingOutlined,
  SunOutlined,
  MoonOutlined,
  ThunderboltOutlined,
  WarningOutlined,
  LogoutOutlined,
  UserOutlined
} from '@ant-design/icons'
import { useAuthStore, useUIStore } from '@/store'
import { publicApi } from '@/api'
import type { HealthInfo } from '@/types'

const { Header, Sider, Content } = Layout

interface Props {
  children: ReactNode
}

/**
 * 主框架：左侧导航 + 顶部状态栏 + 内容区。
 *
 * 导航按 AutoHunter 的模块划分：任务、全局漏洞库、全局情报库、
 * 运行异常、系统设置。观摩角色隐藏漏洞库与情报库入口（后端同样会拦）。
 *
 * 「全局硬骨头库」（/hard-targets，跨任务死目标聚合页）已整体移除：
 * 对标主流扫描平台无对应功能，信息完全被任务目标列表覆盖。
 */
export default function BasicLayout({ children }: Props) {
  const location = useLocation()
  const navigate = useNavigate()
  const { message } = App.useApp()
  const collapsed = useUIStore((s) => s.collapsed)
  const toggleCollapsed = useUIStore((s) => s.toggleCollapsed)
  const themeName = useUIStore((s) => s.theme)
  const setAppearance = useUIStore((s) => s.setAppearance)
  const persistAppearance = useUIStore((s) => s.persistAppearance)

  const role = useAuthStore((s) => s.role)
  const username = useAuthStore((s) => s.username)
  const authEnabled = useAuthStore((s) => s.authEnabled)
  const logout = useAuthStore((s) => s.logout)

  const dark = themeName === 'dark'

  /** 一键切换明暗主题：先本地生效，再把整段 ui 偏好落库。 */
  async function toggleTheme() {
    const next = dark ? 'light' : 'dark'
    setAppearance({ theme: next })
    try {
      await persistAppearance()
    } catch {
      // 落库失败不回滚本地：本次会话仍按用户选择显示，下次启动以服务端为准
      message.warning('主题已切换，但保存到服务器失败')
    }
  }

  const [health, setHealth] = useState<HealthInfo | null>(null)

  // 顶部健康探针：30s 一次，仅用于状态指示。
  useEffect(() => {
    let alive = true
    async function tick() {
      try {
        const res = await publicApi.health({ silent: true })
        if (alive) setHealth(res)
      } catch {
        if (alive) setHealth(null)
      }
    }
    tick()
    const timer = setInterval(tick, 30000)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [])

  /** 当前选中的菜单项（按路径前缀匹配）。 */
  const selectedKey = useMemo(() => {
    const p = location.pathname
    if (p.startsWith('/vulns')) return '/vulns'
    if (p.startsWith('/intel')) return '/intel'
    if (p.startsWith('/runtime-logs')) return '/runtime-logs'
    if (p.startsWith('/settings')) return '/settings'
    if (p.startsWith('/create')) return '/create'
    return '/'
  }, [location.pathname])

  const isObserver = role === 'observer'

  const menuItems = useMemo(() => {
    const items = [
      { key: '/', icon: <AppstoreOutlined />, label: <Link to="/">任务列表</Link> },
      { key: '/intel', icon: <ThunderboltOutlined />, label: <Link to="/intel">全局情报库</Link> },
      { key: '/runtime-logs', icon: <WarningOutlined />, label: <Link to="/runtime-logs">运行异常</Link> },
      { key: '/settings', icon: <SettingOutlined />, label: <Link to="/settings">系统设置</Link> }
    ]
    // 观摩角色不显示漏洞库（敏感）；情报库与设置保留只读进入。
    if (!isObserver) {
      items.splice(3, 0, {
        key: '/vulns',
        icon: <BugOutlined />,
        label: <Link to="/vulns">全局漏洞库</Link>
      })
    }
    return items
  }, [isObserver])

  /** 角色标签配色。 */
  const roleTag = useMemo(() => {
    if (!authEnabled) return <Tag color="default">未启用鉴权</Tag>
    if (role === 'full') return <Tag color="green">全权限</Tag>
    if (role === 'readonly') return <Tag color="blue">只读</Tag>
    if (role === 'observer') return <Tag color="orange">观摩</Tag>
    return <Tag color="red">未认证</Tag>
  }, [authEnabled, role])

  const online = !!health

  return (
    <Layout className="aisrc-layout">
      <Sider
        className="aisrc-sidebar"
        theme="light"
        collapsible
        collapsed={collapsed}
        trigger={null}
        width={208}
        collapsedWidth={64}
      >
        <div className="aisrc-brand">
          <span className="aisrc-brand-mark">Ai</span>
          {!collapsed ? (
            <span className="aisrc-brand-text">
              <b>AiSRC</b>
              <small>自动挖掘系统</small>
            </span>
          ) : null}
        </div>
        <Menu
          mode="inline"
          selectedKeys={[selectedKey]}
          items={menuItems}
          style={{ flex: 1, borderInlineEnd: 'none', paddingTop: 8 }}
        />
      </Sider>

      <Layout>
        <Header className="aisrc-header">
          <div className="aisrc-header-left">
            <Button
              type="text"
              icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={toggleCollapsed}
              aria-label="折叠侧边栏"
            />
            <Tooltip title={health ? `版本 ${health.version} · 运行任务 ${health.tasks_running}` : '后端不可达'}>
              <Badge
                status={online ? 'success' : 'error'}
                text={online ? `服务在线 · v${health?.version ?? '-'}` : '服务离线'}
              />
            </Tooltip>
            {health && typeof health.tasks_running === 'number' && health.tasks_running > 0 ? (
              <Tag color="processing" icon={<DashboardOutlined />}>
                {health.tasks_running} 个任务运行中
              </Tag>
            ) : null}
          </div>

          <div className="aisrc-header-right">
            {roleTag}
            <Tooltip title={dark ? '切换到亮色' : '切换到暗色'}>
              <Button
                type="text"
                icon={dark ? <SunOutlined /> : <MoonOutlined />}
                onClick={() => void toggleTheme()}
                aria-label={dark ? '切换到亮色主题' : '切换到暗色主题'}
              />
            </Tooltip>
            <Dropdown
              menu={{
                items: [
                  {
                    key: 'settings',
                    icon: <SettingOutlined />,
                    label: '系统设置',
                    onClick: () => navigate('/settings')
                  },
                  {
                    key: 'update',
                    icon: <FileSearchOutlined />,
                    label: '检查更新',
                    onClick: () => navigate('/settings?tab=update')
                  },
                  { type: 'divider' as const },
                  {
                    key: 'logout',
                    icon: <LogoutOutlined />,
                    label: '退出登录',
                    disabled: !authEnabled,
                    onClick: async () => {
                      await logout()
                      navigate('/', { replace: true })
                    }
                  }
                ]
              }}
            >
              <Button type="text" icon={<UserOutlined />}>
                {username || (authEnabled ? '未登录' : '本机管理员')}
              </Button>
            </Dropdown>
          </div>
        </Header>

        <Content className="aisrc-content">{children}</Content>
      </Layout>
    </Layout>
  )
}
