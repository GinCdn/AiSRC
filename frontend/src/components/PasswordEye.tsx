import { EyeInvisibleOutlined, EyeOutlined } from '@ant-design/icons'
import { Input, Tooltip } from 'antd'
import type { ComponentProps, ReactNode } from 'react'

/**
 * 密码框眼睛图标（覆盖 antd 默认的反义图标）。
 * 约定：睁眼 = 当前明文可见，闭眼 = 当前密文遮蔽。
 */
export function passwordEyeIcon(visible: boolean): ReactNode {
  return visible ? <EyeOutlined /> : <EyeInvisibleOutlined />
}

/** 后端脱敏掩码恒为 8 个圆点（utils.MaskSecret）。 */
export const MASKED_SECRET = '••••••••'

/** 值是否是后端下发的脱敏串（已保存凭据，明文不出后端）。 */
export function isMaskedSecretValue(value: unknown): boolean {
  return typeof value === 'string' && value.trim() === MASKED_SECRET
}

type SecretPasswordProps = ComponentProps<typeof Input.Password>

/**
 * 密码/密钥输入框（全站统一）：
 * - 值是后端下发的脱敏串（已保存凭据）→ 隐藏眼睛：明文不出后端，点了也只会
 *   「显示」8 个圆点字符，与打点无异（实测让用户误以为眼睛坏了）；悬停提示说明，
 *   输入新值即覆盖、回填串原样提交走后端「未修改」合并。
 * - 值是用户本轮输入的真实值 → 正常眼睛：睁眼 = 明文，闭眼 = 打点。
 */
export function SecretPassword({ value, placeholder, className, ...rest }: SecretPasswordProps) {
  if (isMaskedSecretValue(value)) {
    return (
      <Tooltip title="已保存的密码/密钥出于安全不回传明文，眼睛无法查看；直接输入新值即可覆盖，不填则保持不变">
        <Input.Password
          {...rest}
          value={value}
          placeholder={placeholder}
          visibilityToggle={false}
          className={className ? `${className} aisrc-secret-masked` : 'aisrc-secret-masked'}
        />
      </Tooltip>
    )
  }
  return (
    <Input.Password
      {...rest}
      value={value}
      placeholder={placeholder}
      className={className}
      iconRender={passwordEyeIcon}
    />
  )
}
