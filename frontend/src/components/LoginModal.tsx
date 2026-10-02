import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Form, Input, Modal, Typography } from 'antd'
import { LockOutlined, ReloadOutlined, UserOutlined } from '@ant-design/icons'
import { publicApi } from '@/api'
import { useAuthStore } from '@/store'
import type { CaptchaInfo } from '@/types'
import { SecretPassword } from '@/components/PasswordEye'

interface Props {
  /** 是否强制登录（服务端开启鉴权且当前未认证）。 */
  open: boolean
}

/**
 * 登录弹窗：账号密码登录。
 *
 * 用户名与密码都是**用户自己输入的凭据**（服务端按 `token.username` / `token.password`
 * 校验），因此这里不做任何预填——预填会让固定账号看起来像写死的默认值。
 * 连续失败达阈值（后端默认 3 次）后，服务端会把 `captcha_required` 置位，
 * 此时弹窗自动展开验证码一栏——验证码是后端随机生成的 4 位数字，
 * 明文只留在服务端，前端只拿到渲染好的图片，且每张图只能用一次。
 */
export default function LoginModal({ open }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [captcha, setCaptcha] = useState<CaptchaInfo | null>(null)
  const [captchaLoading, setCaptchaLoading] = useState(false)
  const [form] = Form.useForm()

  const login = useAuthStore((s) => s.login)
  const captchaRequired = useAuthStore((s) => s.captchaRequired)
  const loginFailures = useAuthStore((s) => s.loginFailures)

  const digits = captcha?.digits ?? 4

  /** 取一张新验证码（服务端每次都发新的随机 4 位）。 */
  const refreshCaptcha = useCallback(async () => {
    setCaptchaLoading(true)
    try {
      setCaptcha(await publicApi.captcha())
    } catch {
      setCaptcha(null)
    } finally {
      setCaptchaLoading(false)
    }
  }, [])

  // 打开弹窗时若服务端已判定需要验证码（例如刷新前就已失败 3 次），直接取一张。
  useEffect(() => {
    if (open && captchaRequired) void refreshCaptcha()
    // refreshCaptcha 恒定，无需进依赖
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, captchaRequired])

  // 关闭后清空，避免下次打开残留上一次的报错与验证码。
  useEffect(() => {
    if (!open) {
      form.resetFields()
      setError('')
      setCaptcha(null)
    }
  }, [open, form])

  async function handleSubmit() {
    setError('')
    let values: Record<string, unknown>
    try {
      values = await form.validateFields()
    } catch {
      return
    }

    const code = String(values.captcha_code || '').trim()
    if (captchaRequired && code.length !== digits) {
      setError(`请输入 ${digits} 位验证码`)
      return
    }

    try {
      setLoading(true)
      await login(
        String(values.password || ''),
        String(values.username || '').trim(),
        captchaRequired && captcha ? { id: captcha.captcha_id, code } : undefined
      )
      // 成功后 App 会根据 role 自动关闭弹窗。
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : '登录失败，请重试')
      // 无论成功与否，服务端都已消费掉这张图，必须换一张新的；
      // 同时把用户输错的验证码清掉，避免误提交。
      form.setFieldValue('captcha_code', '')
      // 失败前就已经要求验证码 → 上面的 effect 不会再次触发，这里手动换一张；
      // 失败后才刚升级到「需要验证码」→ 交给 effect 去取，避免重复请求。
      if (captchaRequired) {
        await refreshCaptcha()
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal
      open={open}
      closable={false}
      maskClosable={false}
      keyboard={false}
      footer={null}
      width={420}
      title="AiSRC 自动挖掘系统 · 登录"
    >
      <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
        服务端已开启访问鉴权，请使用账号与密码登录。连续多次密码错误后需要输入验证码。
      </Typography.Paragraph>

      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="username"
          label="用户名"
          rules={[{ required: true, message: '请输入用户名' }]}
        >
          <Input
            prefix={<UserOutlined style={{ opacity: 0.55 }} />}
            placeholder="请输入用户名"
            autoComplete="username"
          />
        </Form.Item>

        <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}>
          <SecretPassword
            prefix={<LockOutlined style={{ opacity: 0.55 }} />}
            placeholder="请输入密码"
            autoComplete="current-password"
          />
        </Form.Item>

        {captchaRequired ? (
          <>
            <Form.Item label={`验证码（${digits} 位数字）`} style={{ marginBottom: 4 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {captcha ? (
                  <img
                    src={captcha.captcha_image}
                    alt="验证码"
                    title="点击换一张"
                    onClick={() => void refreshCaptcha()}
                    style={{
                      height: 40,
                      borderRadius: 6,
                      border: '1px solid var(--aisrc-border, rgba(0,0,0,0.12))',
                      cursor: 'pointer',
                      flex: '0 0 auto'
                    }}
                  />
                ) : (
                  <Button
                    onClick={() => void refreshCaptcha()}
                    loading={captchaLoading}
                    icon={<ReloadOutlined />}
                    style={{ flex: '0 0 auto' }}
                  >
                    获取验证码
                  </Button>
                )}
                <Form.Item
                  name="captcha_code"
                  noStyle
                  rules={[{ required: true, message: '请输入验证码' }]}
                >
                  <Input
                    placeholder={`${digits} 位数字`}
                    maxLength={digits}
                    inputMode="numeric"
                    autoComplete="off"
                  />
                </Form.Item>
              </div>
            </Form.Item>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 12
              }}
            >
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                已连续失败 {loginFailures} 次，需通过验证码继续
              </Typography.Text>
              {captcha ? (
                <Typography.Link
                  style={{ fontSize: 12 }}
                  onClick={() => void refreshCaptcha()}
                >
                  看不清？换一张
                </Typography.Link>
              ) : null}
            </div>
          </>
        ) : null}

        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} /> : null}

        <Button type="primary" htmlType="submit" block loading={loading}>
          登录
        </Button>
      </Form>
    </Modal>
  )
}
