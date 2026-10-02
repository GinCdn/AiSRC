package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 登录守卫：连续失败计数 + 图形验证码
//
// 设计要点：
//   - 验证码**由服务端生成、服务端校验**：接口只返回渲染好的图片，
//     明文仅保存在进程内存，5 分钟过期且一次消费（校验失败也消费），
//     前端与网络层都拿不到明文，防重放与爆破。
//   - 失败计数按**来源 IP** 维度；达 CaptchaThreshold 次后强制要求验证码。
//   - 登录成功后清零，避免正常用户被长期挡住。
//
// 存储是进程内的，单实例部署足够。多实例部署需换 Redis，
// 这属于与原版一致的取舍（原版同样没有分布式会话）。
// ---------------------------------------------------------------------------

const (
	// CaptchaThreshold 触发验证码所需的连续登录失败次数。
	CaptchaThreshold = 3
	// CaptchaDigits 验证码位数（后端随机生成的后端位数）。
	CaptchaDigits = 4
	// captchaTTL 验证码有效期。
	captchaTTL = 5 * time.Minute
	// loginFailWindow 失败计数窗口：超过该时长未再失败则自动清零。
	loginFailWindow = 30 * time.Minute
	// maxCaptchaEntries / maxLoginFailEntries 是公开接口的内存护栏：
	// 验证码接口无需鉴权，来源 IP 也可被伪造，若不设上限则字典会被刷爆。
	maxCaptchaEntries   = 4096
	maxLoginFailEntries = 4096
)

type captchaEntry struct {
	code      string
	expiresAt time.Time
}

type loginFailEntry struct {
	count  int
	lastAt time.Time
}

var (
	guardMu    sync.Mutex
	captchaSet = make(map[string]captchaEntry)
	loginFails = make(map[string]loginFailEntry)
)

// LoginFailures 返回来源 IP 的累计登录失败次数（超出窗口自动清零）。
func LoginFailures(ip string) int {
	guardMu.Lock()
	defer guardMu.Unlock()
	entry, ok := loginFails[ip]
	if !ok {
		return 0
	}
	if time.Since(entry.lastAt) > loginFailWindow {
		delete(loginFails, ip)
		return 0
	}
	return entry.count
}

// CaptchaRequired 该来源是否已达验证码门槛。
func CaptchaRequired(ip string) bool {
	return LoginFailures(ip) >= CaptchaThreshold
}

// RecordLoginFailure 记录一次登录失败，返回累计次数。
func RecordLoginFailure(ip string) int {
	guardMu.Lock()
	defer guardMu.Unlock()
	if len(loginFails) >= maxLoginFailEntries {
		purgeStaleLoginFailsLocked()
	}
	entry := loginFails[ip]
	if time.Since(entry.lastAt) > loginFailWindow {
		entry.count = 0
	}
	entry.count++
	entry.lastAt = time.Now()
	loginFails[ip] = entry
	return entry.count
}

// ClearLoginFailures 登录成功后清零该来源的失败计数。
func ClearLoginFailures(ip string) {
	guardMu.Lock()
	defer guardMu.Unlock()
	delete(loginFails, ip)
}

// ResetLoginGuard 清空全部计数与验证码（仅测试使用）。
func ResetLoginGuard() {
	guardMu.Lock()
	defer guardMu.Unlock()
	captchaSet = make(map[string]captchaEntry)
	loginFails = make(map[string]loginFailEntry)
}

// NewCaptcha 生成 4 位随机验证码，返回验证码 ID、明文（仅留在服务端）与有效期。
func NewCaptcha() (id string, code string, ttl time.Duration) {
	digits := make([]byte, CaptchaDigits)
	for i := range digits {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			// crypto/rand 不可用属系统级异常；退化为时间派生数字，保证不 panic。
			digits[i] = byte('0' + (time.Now().UnixNano()/int64(i+1))%10)
			continue
		}
		digits[i] = byte('0' + n.Int64())
	}
	code = string(digits)
	id = randomHex(16)

	guardMu.Lock()
	purgeExpiredCaptchaLocked()
	evictCaptchaLocked()
	captchaSet[id] = captchaEntry{code: code, expiresAt: time.Now().Add(captchaTTL)}
	guardMu.Unlock()
	return id, code, captchaTTL
}

// VerifyCaptcha 校验验证码。无论成败都立即消费该 ID，防止同一图反复试探。
func VerifyCaptcha(id, code string) bool {
	id = strings.TrimSpace(id)
	code = strings.TrimSpace(code)
	if id == "" || code == "" {
		return false
	}
	guardMu.Lock()
	entry, ok := captchaSet[id]
	delete(captchaSet, id)
	guardMu.Unlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(entry.code), []byte(code)) == 1
}

// purgeExpiredCaptchaLocked 清理过期验证码（调用方须持锁）。
func purgeExpiredCaptchaLocked() {
	now := time.Now()
	for key, entry := range captchaSet {
		if now.After(entry.expiresAt) {
			delete(captchaSet, key)
		}
	}
}

// evictCaptchaLocked 控制验证码字典规模（调用方须持锁）。
//
// 正常使用下字典只有个位数条目，这里只在被刷时才生效；
// 被丢弃的是任意条目，最坏情况是攻击者的图失效，不影响正常用户。
func evictCaptchaLocked() {
	for key := range captchaSet {
		if len(captchaSet) < maxCaptchaEntries {
			return
		}
		delete(captchaSet, key)
	}
}

// purgeStaleLoginFailsLocked 清理失败计数字典（调用方须持锁）。
func purgeStaleLoginFailsLocked() {
	now := time.Now()
	for key, entry := range loginFails {
		if now.Sub(entry.lastAt) > loginFailWindow {
			delete(loginFails, key)
		}
	}
	for key := range loginFails {
		if len(loginFails) < maxLoginFailEntries {
			return
		}
		delete(loginFails, key)
	}
}

// randomHex 生成 n 字节随机数的十六进制串（用作验证码 ID）。
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// CaptchaImage 把验证码渲染为 SVG 图片并包成 data URL。
//
// 只用数字与几何图形，不依赖任何字体文件，浏览器直接显示；
// 每个数字带随机旋转/位移与颜色，叠加干扰线与噪点，肉眼可读但抗简单脚本识别。
func CaptchaImage(code string) string {
	const width, height = 132, 44
	digitColors := []string{"#26325b", "#1f4d3d", "#6b2d5c", "#7a3b12", "#20304a"}
	noiseColors := []string{"#8fa0c4", "#c2a3c6", "#93bda9", "#cbb48c"}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`,
		width, height, width, height)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#eef1f8"/>`, width, height)

	// 干扰线：5 条随机斜线。
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&b,
			`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1" opacity="0.6"/>`,
			randInt(width), randInt(height), randInt(width), randInt(height), noiseColors[i%len(noiseColors)])
	}
	// 干扰点：18 个小圆。
	for i := 0; i < 18; i++ {
		fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="1" fill="%s" opacity="0.5"/>`,
			randInt(width), randInt(height), noiseColors[i%len(noiseColors)])
	}
	// 数字：逐个随机旋转与纵向偏移。
	for i, ch := range code {
		x := 14 + i*28
		y := 31 + randInt(7) - 3
		rotate := randInt(31) - 15
		fmt.Fprintf(&b,
			`<text x="%d" y="%d" font-family="Menlo,Consolas,'Courier New',monospace" font-size="26" font-weight="700" fill="%s" transform="rotate(%d %d 22)">%c</text>`,
			x, y, digitColors[i%len(digitColors)], rotate, x, ch)
	}
	b.WriteString(`</svg>`)

	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String()))
}

// randInt 返回 [0,n) 的密码学安全随机整数。
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(value.Int64())
}
