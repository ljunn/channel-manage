# 渠道管家（Channel Manage）

> 面向 Sub2API 的上游市场、渠道质量与生产调度控制面。

渠道管家从多套 Sub2API / New API 采集分组倍率、余额和模型能力，对获得生产授权的 API Key 持续探测，并在独立控制面中生成可解释、可审批的调度动作。它不参与模型请求转发；控制面故障不会影响生产 Sub2API 的现有流量。

## 核心能力

- **数据源管理**：账号密码登录 Sub2API / New API，按周期采集分组、倍率、余额和能力快照，并按数据源配置余额/倍率换算比例（如 `1:10`）。
- **市场大盘**：统一展示各平台倍率、最低价、平均值和 30 日历史样本。
- **渠道雷达**：生产 Key 与远端分组组成渠道，分别记录主动探测与目标节点真实业务质量。
- **目标节点**：同步 Sub2API 版本和目标分组；不拉取其他账号，只记录本系统创建的托管账号。
- **托管账号**：用获得明确授权的上游 Key 创建 `[托管]` 账号，创建时始终停止调度。
- **策略调度**：版本化策略、影子模拟、动作意图、人工审批、幂等执行和失败事件。
- **安全审计**：AES-256-GCM 凭据加密、紧急冻结、目标写权限、所有权标记与追加式审计。
- **事件通知**：P0 / P1 事件可通过 Resend 邮件发送，并保留每次投递结果。

## 最直接的三个用途

### 1. 看清上游价格和质量

把多个 Sub2API / New API 数据源放进同一个市场大盘，统一比较分组倍率、余额、模型能力、首 Token 速度和近期成功率，不再反复切换后台或依赖手工表格。

### 2. 自动维护中转站渠道

将选定的源分组绑定到自己的 Sub2API 目标分组后，系统会创建独立托管账号，持续探测真实可用性，并按价格或速度策略自动调整启停状态和优先级。

### 3. 提前发现生产风险

余额消耗、接口异常、慢首响、渠道隔离和目标同步失败都会留下事件与审计记录；关键故障可通过邮件通知，便于在用户请求受影响前处理。

## 用它有什么好处

- **少盯后台**：价格、余额、质量和调度集中维护，异常渠道自动退出，恢复后自动重新加入。
- **降低中转成本**：按目标倍率筛选更便宜的上游，并用真实业务速度或探测结果安排优先级。
- **故障影响更小**：慢首响和连续失败渠道会被隔离，控制面自身故障不会中断 Sub2API 已有流量。
- **操作可追溯**：托管账号、策略版本、执行动作、失败原因和远端同步结果都有记录。
- **边界更清楚**：只维护本系统创建并带所有权标记的账号，不读取或修改目标节点上的其他账号。

## 适合谁

- 同时采购多个上游，需要统一比较价格、余额和稳定性的 API 中转站运营者。
- 使用 Sub2API 管理多个 GPT、Claude、Gemini 或 Grok 分组，希望自动调度渠道的个人或团队。
- 需要把上游故障、余额不足和慢响应从人工巡检改为持续监控的运维人员。
- 希望自部署并掌握上游凭据、调度策略和审计数据的开发者。

## 安全模型

远程写入必须同时满足：

1. 目标节点显式开启托管写入。
2. 系统未开启紧急冻结。
3. 系统已关闭影子模式。
4. 动作已由运营者批准，或已显式开启自动批准。
5. 远端账号存在本系统生成的所有权标记。

渠道管家不会读取或修改目标节点上的其他账号。托管账号优先级最低为 `101`，创建后 `schedulable=false`；只有策略判定生成的动作通过上述闸门后才能恢复调度。

## 一键部署

服务器已安装 Docker、Docker Compose、OpenSSL 和 curl 时执行：

```bash
curl -fsSL https://raw.githubusercontent.com/ljunn/channel-manage/main/deploy/install.sh | sudo sh
```

默认访问 `http://服务器IP:4473`。安装脚本会生成数据库密码、JWT 密钥和初始管理员密码，并将 `.env` 权限设为 `600`。

## 源码启动

```bash
cp .env.example .env
# 修改 JWT_SECRET、POSTGRES_PASSWORD 和 ADMIN_PASSWORD
docker compose up -d --build
```

首次未设置 `ADMIN_PASSWORD` 时，随机密码只写入容器日志：

```bash
docker compose logs app | grep 初始管理员
```

登录后可点击页面右上角的账号邮箱，修改登录邮箱或密码。修改时需要验证当前密码；保存成功后，除当前浏览器外的其他登录会话会自动退出。

本地开发：

```bash
make test
make build
```

Go 服务默认监听 `8080`，Vite 开发服务会将 `/api` 代理到该端口。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_PORT` | `4473` | Docker 对外端口 |
| `ADMIN_EMAIL` | `admin@channel.local` | 初始管理员邮箱 |
| `ADMIN_PASSWORD` | 随机 | 首次管理员密码 |
| `JWT_SECRET` | 无 | 至少 32 字符，生产必填 |
| `CREDENTIAL_ENCRYPTION_KEY` | `JWT_SECRET` | 凭据加密密钥 |
| `POSTGRES_USER` | `channel_manage` | PostgreSQL 用户 |
| `POSTGRES_PASSWORD` | 无 | PostgreSQL 密码 |
| `POSTGRES_DB` | `channel_manage` | PostgreSQL 数据库 |
| `ALLOW_INSECURE_UPSTREAMS` | `false` | 是否允许 HTTP 上游 |
| `ALLOW_PRIVATE_UPSTREAMS` | `false` | 是否允许内网或本机上游 |

默认拒绝 HTTP、环回、私网、链路本地和未指定地址，降低 SSRF 风险。仅在封闭网络部署且已确认边界时开启对应选项。

## 业务流程

```text
数据源登录 -> 分组/倍率采集 -> Key 生产授权 -> 渠道探测
     -> 策略评估 -> 动作意图 -> 审批 -> 安全闸门 -> 托管账号写入
```

渠道生命周期：

```text
DISCOVERED -> VALIDATING -> HEALTHY -> SUSPECT -> QUARANTINED
                    |          |             |
                    +----------+-------------+-> MANUAL_HOLD
```

单次普通失败进入 `SUSPECT`。默认在最近 5 分钟真实业务至少 5 个样本且异常率达到 20% 时，与主动探测失败联合确认隔离；真实日志不可用时降级为连续三次主动探测失败规则。人工暂停不会被后台任务自动覆盖。

## 升级

部署目录中执行：

```bash
sudo ./update.sh
```

升级脚本会先通过 `pg_dump` 写入 `backups/`，再拉取新镜像并滚动重建服务。

## 发布

- 推送 `main` 会运行 Go 测试、Vue 构建和 Compose 校验。
- 推送 `v主版本.次版本.修订号` 标签会创建 GitHub Release。
- Release 包含 Linux / macOS 的 amd64 / arm64 单二进制和 `checksums.txt`。
- 同一标签会发布 `ghcr.io/ljunn/channel-manage` 多架构镜像并更新 `latest`。
- 标签对应版本必须先写入 `CHANGELOG.md`，否则 Release 任务失败。

## 项目周边服务与交流

- API 中转服务：[openapi.junliai.org](https://openapi.junliai.org/)
- 图片生成服务：[img.junliai.org](https://img.junliai.org/)
- 泡泡马池：[poolmarket.cc](https://poolmarket.cc/)
- 配套小店：[pay.ldxp.cn/shop/48RBVZXA](https://pay.ldxp.cn/shop/48RBVZXA)
- QQ 交流群：`1030276111`
- 联系邮箱：[pengljun@qq.com](mailto:pengljun@qq.com)

## 许可证

本项目使用 GNU Affero General Public License v3.0。
