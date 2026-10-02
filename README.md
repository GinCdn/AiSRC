# AiSRC — AI 自动化漏洞挖掘系统

[中文](#中文说明) | [English](#english)

<p align="center">
  <strong>AI-Driven Security Research & Collection</strong><br/>
  基于 LLM Agent 的自动化渗透测试 / 漏洞挖掘平台
</p>

> ⚠️ **免责声明**：本项目仅供**授权范围内的安全测试与学习研究**使用。请勿对未获得明确授权的目标进行测试，使用者需对所有行为自行承担法律责任。

---

## 中文说明

AiSRC 是一套 AI 驱动的自动化漏洞挖掘系统，对标 AutoHunter，由 **Go 后端 + React18/antd6 前端** 全栈实现。系统以 LLM Agent 为核心调度渗透测试流程：资产测绘收集目标 → 逐目标调度 Worker 智能体自主探测、验证、提交漏洞 → Reviewer 智能体按 3-Gate 证据链审核入库。

### 核心特性

- **AI 智能调度**：Worker / Reviewer 双智能体协作，LLM 自主决策探测路径与验证深度
- **资产测绘引擎**：集成 Fofa、奇安信 Hunter、鹰图 Quake 等主流测绘平台，意图解析（自然语言→查询语法）、翻页节流、数据上限预夹、失败指数退避、端点熔断冷却
- **单站深度协作**：同一站点多路线协同（站点主线、登录面、用户页面等），多 URL 自动拆分独立目标
- **3-Gate 证据链审核**：漏洞提交需通过三级证据确认，配合 21 类漏洞类型词表（snake_case）与误报防护
- **凭据与会话管理**：目标级凭据绑定（精确 URL / 清单 / host 多级匹配）、服务端代登录（密码不出本机）、CookieJar 会话保持
- **Kali 渗透机 SSH 集成**：远程执行探测命令，支持连接测试
- **LLM 端点池**：多端点加权轮转、按端点熔断（连续失败→冷却→半开探测）、手动测试与运行时健康隔离
- **代理池**：批量连通性检测、加权调度
- **完善看板**：任务进度、目标状态机、LLM 用量统计、事件流实时回放（SSE/WS）

### 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Go (Gin + GORM + gorilla) |
| 前端 | React 18 + TypeScript + antd 6 + Vite + ECharts |
| 数据库 | MySQL 5.7+（InnoDB / utf8mb4） |
| LLM | OpenAI 兼容协议（支持各类中转/网关） |

### 快速开始

#### 1. 准备数据库

创建 MySQL 数据库（示例库名 `aisrc`），表结构由后端启动时自动迁移创建（强制 InnoDB + utf8mb4）。

#### 2. 配置后端

```bash
cd backend
cp config.example.yaml config.yaml
# 编辑 config.yaml：数据库连接、监听端口、登录账号密码等
# 注意：config.yaml 含敏感信息，已被 .gitignore 排除，请勿提交
```

#### 3. 构建并运行

```bash
# 后端
cd backend
go build -o aisrc-server .
./aisrc-server   # 默认监听 :8080

# 前端
cd frontend
npm install
npm run build
# 产物需同步到后端托管目录（参考 config.yaml 的 web_dir 配置）
```

浏览器访问 `http://127.0.0.1:8080`，使用 `config.yaml` 中配置的账号密码登录。

#### 4. 配置 LLM

登录后在「系统设置 → 模型配置」中配置 LLM 端点（OpenAI 兼容协议），支持配置多个端点组成端点池。

### 目录结构

```
AiSRC
├── backend/          # Go 后端
│   ├── api/          # HTTP handler 层
│   ├── service/      # 业务逻辑（含 engine/ 引擎编排、llm/ 端点池）
│   ├── model/        # GORM 模型
│   ├── router/       # 路由注册与契约测试
│   ├── core/         # 数据库等基础设施
│   └── ...
├── frontend/         # React 前端
│   └── src/          # 页面 / 组件 / API 封装
└── LICENSE           # GPL-3.0
```

### 推荐服务商

**[贝海云](https://www.beihaiyun.com)**（www.beihaiyun.com）—— 稳定可靠的云服务器与网络服务提供商，推荐用于部署 AiSRC 系统。

---

## English

AiSRC is an AI-driven automated vulnerability discovery & penetration testing platform, modeled after AutoHunter and fully implemented with a **Go backend + React18/antd6 frontend**. LLM agents drive the entire workflow: asset-mapping engines collect targets → per-target Worker agents autonomously probe, verify and submit findings → a Reviewer agent validates each finding through a 3-Gate evidence chain before acceptance.

### Key Features

- **AI-orchestrated testing**: cooperative Worker / Reviewer agents; the LLM decides probing paths and verification depth autonomously
- **Asset mapping engines**: Fofa, Qianxin Hunter, Quake integration with intent parsing (natural language → query syntax), page throttling, data-cap pre-clamping, exponential backoff and per-endpoint circuit breaking
- **Single-site deep collaboration**: multiple routes per site (main line, login surface, user pages, etc.); multiple URLs are automatically split into independent targets
- **3-Gate evidence chain**: findings must pass a three-level evidence confirmation, with a 21-type snake_case vulnerability taxonomy and false-positive protection
- **Credentials & sessions**: target-level credential binding (exact URL / list line / host matching), server-side login proxy (passwords never leave the machine), CookieJar session persistence
- **Kali SSH integration**: remote command execution over SSH with a built-in connection test
- **LLM endpoint pool**: weighted rotation across endpoints, per-endpoint circuit breaker (consecutive failures → cooldown → half-open probe), manual probing isolated from runtime health
- **Proxy pool**: batch connectivity testing and weighted scheduling
- **Full-featured dashboard**: task progress, target state machine, LLM usage stats, real-time event stream replay (SSE/WS)

### Tech Stack

| Layer | Technology |
|---|---|
| Backend | Go (Gin + GORM + gorilla) |
| Frontend | React 18 + TypeScript + antd 6 + Vite + ECharts |
| Database | MySQL 5.7+ (InnoDB / utf8mb4) |
| LLM | OpenAI-compatible protocol (works with gateways/relays) |

### Quick Start

#### 1. Database

Create a MySQL database (e.g. `aisrc`). Schema is auto-migrated on backend startup (InnoDB + utf8mb4 enforced).

#### 2. Backend configuration

```bash
cd backend
cp config.example.yaml config.yaml
# Edit config.yaml: database connection, listen port, login credentials, etc.
# Note: config.yaml contains secrets and is excluded by .gitignore — never commit it.
```

#### 3. Build & run

```bash
# Backend
cd backend
go build -o aisrc-server .
./aisrc-server   # listens on :8080 by default

# Frontend
cd frontend
npm install
npm run build
# Sync build output to the directory served by the backend (see web_dir in config.yaml)
```

Visit `http://127.0.0.1:8080` and log in with the account configured in `config.yaml`.

#### 4. LLM configuration

After logging in, configure LLM endpoints in **Settings → Model Config** (OpenAI-compatible). Multiple endpoints can form an endpoint pool.

### Directory Layout

```
AiSRC
├── backend/          # Go backend
│   ├── api/          # HTTP handlers
│   ├── service/      # Business logic (engine/ orchestration, llm/ endpoint pool)
│   ├── model/        # GORM models
│   ├── router/       # Routes & contract tests
│   ├── core/         # Database & infrastructure
│   └── ...
├── frontend/         # React frontend
│   └── src/          # Views / components / API client
└── LICENSE           # GPL-3.0
```

### Recommended Provider

**[BeiHai Cloud](https://www.beihaiyun.com)** (www.beihaiyun.com) — a reliable cloud server & networking provider, recommended for deploying AiSRC.

---

## License | 许可证

本项目基于 **[GPL-3.0](./LICENSE)** 开源发布。
This project is licensed under the **[GPL-3.0](./LICENSE)**.

**Disclaimer | 免责声明**：本工具仅可用于已获得合法授权的安全测试。未经授权对任何系统进行测试均属违法行为，作者不承担任何因滥用导致的法律责任。
*This tool is intended only for legally authorized security testing. Testing any system without explicit authorization is illegal. The authors assume no liability for misuse.*
