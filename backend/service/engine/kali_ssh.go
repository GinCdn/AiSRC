package engine

// Kali SSH 连接执行层（golang.org/x/crypto/ssh）。
// 密码/私钥不出本机；单条命令超时保护；输出截断保护。

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"AiSRC/model"
	"AiSRC/utils"
)

// kaliSSHConfig 组装 SSH 客户端配置（密码或私钥二选一）。
func kaliSSHConfig(k model.KaliSettings) (*ssh.ClientConfig, error) {
	auth := make([]ssh.AuthMethod, 0, 1)
	if k.AuthType == "key" || (k.AuthType == "" && strings.TrimSpace(k.PrivateKey) != "") {
		signer, err := ssh.ParsePrivateKey([]byte(k.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败：%v", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else {
		if strings.TrimSpace(k.Password) == "" {
			return nil, fmt.Errorf("缺少 SSH 密码或私钥")
		}
		auth = append(auth, ssh.Password(k.Password))
	}
	return &ssh.ClientConfig{
		User:            k.Username,
		Auth:            auth,
		Timeout:         15 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 内网渗透机，跳过主机指纹校验
	}, nil
}

// kaliDial 建立 SSH 连接（支持 ctx 取消）。
func kaliDial(ctx context.Context, cfg *ssh.ClientConfig, host string, port int) (*ssh.Client, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SSH 连接 %s 失败：%v", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH 握手 %s 失败：%v", addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// KaliProbe 用给定配置探测 Kali SSH 连通性（设置页「测试连接」用）。
// 纯探测：不写任何运行时状态。返回 {ok,host,port,latency_ms,output,error}。
func KaliProbe(k model.KaliSettings) map[string]any {
	port := k.Port
	if port <= 0 {
		port = 22
	}
	res := map[string]any{"ok": false, "host": k.Host, "port": port}
	if strings.TrimSpace(k.Host) == "" {
		res["error"] = "请先填写主机地址"
		return res
	}
	if strings.TrimSpace(k.Username) == "" {
		res["error"] = "请先填写用户名"
		return res
	}
	start := time.Now()
	cfg, err := kaliSSHConfig(k)
	if err != nil {
		res["error"] = err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	client, err := kaliDial(ctx, cfg, k.Host, port)
	if err != nil {
		res["latency_ms"] = time.Since(start).Milliseconds()
		res["error"] = err.Error()
		return res
	}
	defer client.Close()
	output, runErr := kaliRun(ctx, client, "uname -a", 10*time.Second)
	res["latency_ms"] = time.Since(start).Milliseconds()
	if runErr != nil {
		res["error"] = runErr.Error()
		return res
	}
	res["ok"] = true
	res["output"] = utils.Truncate(output, 200)
	return res
}

// kaliRun 在已建立的 SSH 连接上执行单条命令，返回合并输出。
func kaliRun(ctx context.Context, client *ssh.Client, command string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建 SSH 会话失败：%v", err)
	}
	defer session.Close()

	done := make(chan error, 1)
	var outBuf, errBuf strings.Builder
	session.Stdout = &outBuf
	session.Stderr = &errBuf

	if err := session.Start(command); err != nil {
		return "", fmt.Errorf("启动命令失败：%v", err)
	}
	go func() { done <- session.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		output := strings.TrimSpace(outBuf.String())
		if errText := strings.TrimSpace(errBuf.String()); errText != "" {
			output += "\n[stderr]\n" + errText
		}
		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				return output, fmt.Errorf("命令退出码 %d", exitErr.ExitStatus())
			}
			return output, err
		}
		return output, nil
	case <-timer.C:
		_ = session.Signal(ssh.SIGKILL)
		return outBuf.String() + "\n[stderr]\n" + errBuf.String(), fmt.Errorf("命令超时（%s）", timeout)
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("任务已取消")
	}
}
