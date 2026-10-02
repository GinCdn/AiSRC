import { StrictMode, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App as AntdApp, ConfigProvider, theme } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import App from './App'
import { useUIStore } from './store'
import { hueToHex } from './utils/uiTheme'
import { passwordEyeIcon } from './components/PasswordEye'
import './styles/global.scss'

dayjs.locale('zh-cn')

/**
 * 主题容器：把服务端下发的外观偏好同步到 Ant Design 令牌与 <html> 上的 CSS 变量。
 *
 * `theme / accentHue / wallpaperFit / wallpaperDim` 都由设置页的「界面」分区驱动，
 * 这里只负责读：写入口在 useUIStore.setAppearance。
 */
function Root() {
  const themeName = useUIStore((s) => s.theme)
  const accentHue = useUIStore((s) => s.accentHue)
  const wallpaper = useUIStore((s) => s.wallpaper)
  const loadAppearance = useUIStore((s) => s.loadAppearance)

  const dark = themeName === 'dark'

  // data-theme 与 CSS 变量由 applyChrome 统一维护；这里只兜住首帧。
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light'
  }

  // 启动即拉一次服务端外观偏好（失败则沿用本地缓存）。
  useEffect(() => {
    void loadAppearance()
  }, [loadAppearance])

  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          // 主题色跟随色相滑块（与 global.scss 的 --aisrc-accent 同源）
          colorPrimary: hueToHex(accentHue),
          borderRadius: 8,
          fontSize: 14,
          fontFamily:
            "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif"
        },
        components: {
          Layout: { bodyBg: 'transparent', headerBg: 'transparent', siderBg: 'transparent' },
          Menu: { itemBg: 'transparent', subMenuItemBg: 'transparent' },
          // 全站密码框眼睛语义：睁眼=明文可见，闭眼=密文遮蔽（覆盖 antd 默认的反义图标）。
          inputPassword: { iconRender: passwordEyeIcon }
        }
      }}
    >
      <AntdApp>
        {/* 壁纸层 + 明暗蒙版（铺满方式/明暗由设置页的界面分区驱动） */}
        <div
          className="aisrc-wallpaper"
          aria-hidden="true"
          style={wallpaper ? { backgroundImage: `url(${JSON.stringify(wallpaper)})` } : undefined}
        />
        <div className="aisrc-layout">
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </div>
      </AntdApp>
    </ConfigProvider>
  )
}

const container = document.getElementById('root')
if (!container) {
  throw new Error('未找到 #root 挂载点')
}

createRoot(container).render(
  <StrictMode>
    <Root />
  </StrictMode>
)
