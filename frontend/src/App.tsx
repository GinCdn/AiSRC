import { useEffect } from 'react'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import BasicLayout from '@/layouts/BasicLayout'
import LoginModal from '@/components/LoginModal'
import TasksView from '@/views/TasksView'
import CreateView from '@/views/CreateView'
import BoardView from '@/views/BoardView'
import VulnsView from '@/views/VulnsView'
import IntelView from '@/views/IntelView'
import RuntimeLogsView from '@/views/RuntimeLogsView'
import SettingsView from '@/views/SettingsView'
import { useAuthStore } from '@/store'
import { setUnauthorizedHandler } from '@/utils/request'

/** 404 兜底。 */
function NotFound() {
  return (
    <div className="aisrc-empty">
      <h2>页面不存在</h2>
      <p>请检查地址，或从左侧菜单进入对应模块。</p>
    </div>
  )
}

export default function App() {
  const ready = useAuthStore((s) => s.ready)
  const authEnabled = useAuthStore((s) => s.authEnabled)
  const role = useAuthStore((s) => s.role)
  const load = useAuthStore((s) => s.load)
  const navigate = useNavigate()

  // 首屏拉取鉴权状态；会话失效时由 request 层回调跳回任务页。
  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setUnauthorizedHandler(() => {
      useAuthStore.setState({ role: 'none' })
      navigate('/', { replace: true })
    })
  }, [navigate])

  // 服务端开启了鉴权但当前未认证 → 用登录弹窗遮住整个界面。
  const needLogin = ready && authEnabled && role === 'none'

  return (
    <>
      <BasicLayout>
        <Routes>
          <Route path="/" element={<TasksView />} />
          <Route path="/create" element={<CreateView />} />
          <Route path="/create/:taskId" element={<CreateView />} />
          <Route path="/task/:taskId" element={<BoardView />} />
          <Route path="/vulns" element={<VulnsView />} />
          <Route path="/intel" element={<IntelView />} />
          <Route path="/runtime-logs" element={<RuntimeLogsView />} />
          <Route path="/settings" element={<SettingsView />} />
          <Route path="/tasks" element={<Navigate to="/" replace />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BasicLayout>
      <LoginModal open={needLogin} />
    </>
  )
}
