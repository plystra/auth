# Invoice SaaS 后端示例

这个独立的业务 API 使用 Plystra Auth 的公开 HTTP 接口保护发票读取与批准。业务数据保存在另一套 PostgreSQL 数据库；它不读取 Auth 的表，也不调用 Auth 的领域服务。

先按 [SaaS 接入手册](../../../auth-docs/mvp-onboarding.md)完成运营引导、业务权限登记、公开应用审批、客户安装和服务端密钥创建。`invoice:approve` 必须保持 `agent_approval=required`。第 6–7 节提供 OAuth Agent 授权与人工审批步骤；第 14 节提供原生父子 Agent 的资源组委托和撤销步骤。这个示例接受受众为本应用的用户或 Agent 访问令牌，不把 Agent 密钥直接当作业务访问令牌。

## 配置与启动

从 `auth` 仓库根目录运行，使用仓库锁定的 Go 工具链和 PostgreSQL 17+。通过部署环境或秘密管理设施设置：

| 环境变量 | 值 |
| --- | --- |
| `INVOICE_SAAS_DATABASE_URL` | 独立业务数据库连接串；不能指向 Auth 数据库 |
| `INVOICE_SAAS_AUTH_ISSUER` | Auth 签发令牌时使用的精确发行方 URL |
| `INVOICE_SAAS_AUTH_SERVER_URL` | Auth 服务端面的根 URL，例如本地 `http://127.0.0.1:8081` |
| `INVOICE_SAAS_CLIENT_ID` | 已审批并安装的 Invoice SaaS 应用 `client_id` |
| `INVOICE_SAAS_API_KEY` | 该应用的服务端密钥；授予 `auth.authz:check` 与 `auth.audit:write`，显式启用 `allow_subject_assertion` 并限制在目标客户范围内。应用清单、有效安装和 Agent 当前权威须覆盖业务动作 |
| `INVOICE_SAAS_AUTH_JWKS_URL` | 可选；默认发行方 URL 加 `/.well-known/jwks.json`。本地测试或内部反向代理可显式指定实际 JWKS 地址 |
| `INVOICE_SAAS_HTTP_ADDR` | 可选；默认 `127.0.0.1:8090` |

Auth URL 必须使用 HTTPS；本机演示允许显式回环 IP 上的 HTTP。HTTP 重定向一律拒绝，不把服务端密钥、主体令牌或 JWKS 请求转发至新地址。配置缺项时启动失败并指出缺失的变量；错误不输出连接串或密钥。

使用独立空库，先以具备建表权限的业务迁移账户运行：

```text
go run ./examples/invoice-saas/cmd/invoice-saas migrate
```

该命令使用示例自己的迁移表 `invoice_saas_migrations`，可重复执行。升级已有示例数据库时也须先执行：新增的 `0002`、`0003` 创建该业务数据库自己的 River 队列和审计投递记录，不改变 Auth 数据库。服务进程使用受限业务账户，需有发票及投递表的读写权限、River 表的运行权限及其序列的使用权限。不要让业务账户访问 Auth 数据库。

按手册第 14 节创建资源项目组后，在部署主机导入演示发票。替换以下 Space 与组 ID 为实际响应中的值；资源归属由业务数据库维护，业务 HTTP 请求不能指定或覆盖它们。

```text
go run ./examples/invoice-saas/cmd/invoice-saas seed --id inv_demo --space-id <customer_space_id> --group-id <invoice_project_group_id> --amount-cents 12345 --currency USD
go run ./examples/invoice-saas/cmd/invoice-saas serve
```

`seed` 仅是主机上的演示数据导入命令；重复 ID 会被拒绝。生产业务的发票创建、计费与业务管理不属于这个示例。金额为正整数最小货币单位；发票具有版本号、状态及批准成员记录。

## 业务请求

取得 `aud=<INVOICE_SAAS_CLIENT_ID>` 的访问令牌后调用：

```text
curl -i http://127.0.0.1:8090/invoices/inv_demo -H "Authorization: Bearer <access_token>" -H "X-Request-Id: req_invoice_read"
curl -i -X POST http://127.0.0.1:8090/invoices/inv_demo/approve -H "Authorization: Bearer <access_token>" -H "Content-Type: application/json" -H "X-Request-Id: req_invoice_approve" -d '{"expected_version":1}'
```

令牌和密钥均是占位符，不要把真实凭据写入源码、日志或共享命令记录。接口定义由 Go 类型生成到 [openapi.json](openapi.json)。

每次请求先固定 ES256、`typ=at+jwt` 验证 JWT，再校验发行方、应用受众、有效期、签发时间、主体与成员。按固定 JWKS 地址及 `kid` 取钥，缓存公钥 5 分钟，未知 `kid` 触发有速率上限的刷新。不会根据令牌内的 URL 选择公钥来源。然后从业务数据库读实际发票及其 Space/组，在线调用 `POST /server/v1/authz/check`。本地验签与公钥缓存不缓存授权结果。

| 结果 | 业务行为 |
| --- | --- |
| `200` | 返回持久化发票；`X-Auth-Decision-Id` 给出本次判断 ID |
| `401 INVALID_TOKEN` | 不调用授权 API，不执行业务变更；重新取得正确受众的有效令牌 |
| `403`，普通 deny | 不执行；保留 `error.details.decision_id`，用解释与审计排查当前权限、作用域和所有者包络 |
| `403 APPROVAL_REQUIRED` | 不执行；针对实际发票 ID、版本、金额、币种和动作计算 SHA-256 请求摘要并发起审批。响应含 `approval_id`、`request_digest` 与 `decision_id` |
| `403 APPROVAL_PENDING` / `APPROVAL_REJECTED` | 不执行；等待或处理人工决定，不重复创建审批 |
| `409 CONFLICT` | 发票已被批准或版本已变化；重新读取当前状态，不重复执行变更 |
| `503 UNAVAILABLE` | Auth 不可用、响应不合法或存储失败；不执行变更，不降级为离线放行 |

人工审批走 Auth 主体面的公开收件箱、step-up 和批准接口，参照接入手册第 7 节。审批人可看到实际金额、币种、版本、请求摘要和完整委托链。批准后用原业务请求重试；Auth 重新计算当前权威并原子消费一次批准，示例通过 `draft` 和 `expected_version` 的条件更新保证发票至多批准一次，保存已验签成员的 ID 与批准时间。

Auth 判断与 SaaS 数据库变更是两个独立事务。网络中断、版本冲突或业务写入失败可能已经消费批准；不能宣称它们具有分布式原子性，也不能重放批准来补偿。先读取业务状态，确有需要时重新申请人工批准。业务请求摘要供人工核对；按现有业务审批契约，Auth 按 Agent、动作和资源匹配批准，摘要不作为额外授权事实。

## 撤销、解释和审计

按接入手册第 14 节收窄父 Agent 授予后，子 Agent 的旧 JWT 即便仍可本地验签，其下一次发票读取也返回 `403 OWNER_ENVELOPE_EXCLUDED`。停止父 Agent 后，整棵委托树的凭据和令牌均失效。其他独立 Agent 分支保持原有权威。

保留业务响应的 `X-Request-Id` 与判断 ID。服务端以同一主体令牌、动作及数据库读取的真实资源事实调用 `authz.explain`；解释不会消费批准，也不能用作执行凭据。授权用户可调用 `GET /v1/spaces/{id}/audit-logs?decision_id=...` 或按 `request_id`、`member_id`、`action` 查询，关联判断、审批与委托链；不要把主体令牌写进日志。

`serve` 同时启动 River 审计消费者。读取、拒绝及失败记录使用 `invoice.read` / `invoice.approve` 事件名；批准成功的发票变更、投递记录和 River 任务在业务数据库的同一事务中提交。入队失败返回 `503`，不提交批准；中央审计暂时不可用时，已提交的业务事件仍留在本地队列，重启后继续投递。后台以已验签的成员和用户 ID 作应用断言，调用公开 `audit.write`，不保存访问令牌；Auth 按投递时的成员、绑定、安装与写入权限重新验证，不放宽撤销规则。

用主机命令查看 JSON 状态，传入末条事件 ID 可继续分页：

```text
go run ./examples/invoice-saas/cmd/invoice-saas audit-status --limit 50
go run ./examples/invoice-saas/cmd/invoice-saas audit-status --after <evt_id> --limit 50
```

`delivered` 带 Auth 审计 ID；`pending` 等待或重试；`failed` 表示 River 自动重试已耗尽；`blocked` 需要核对不确定结果。响应丢失或结果不明时使用原幂等 key；只有收到明确重放的失败响应才推进持久化投递代次。Auth 的去重窗口为 24 小时，示例在首次尝试 23 小时后停止不确定重试；已尝试事件的服务端 URL、应用或密钥变化也会停止发送。失败、阻塞及其事件记录保留，不自动清除或伪造回执。

投递使用当前有效的 ID 断言，主体删除、绑定撤销或安装失权可阻止历史待投递事件继续提交。运维人员须按 `request_id`、资源及所有者链查询 Auth，核对是否已有记录，再处理保留的失败任务；不能直接换 key、修改主体或删除记录来掩盖未知结果。本示例不提供跳过核对的自动重发，也不宣称无限期恰好一次投递。完整投递边界和验证步骤见[接入手册第 16–17 节](../../../auth-docs/mvp-onboarding.md)。

## 自动化验证

从仓库根目录运行，Docker 必须可用：

```text
go test -race ./examples/invoice-saas/... -count=1
go test -race ./cmd/plystra-auth -run '^TestEmptyDeploymentCreatesBusinessPermissionsThroughPublicEntrypoints$' -count=1
make check
```

示例测试验证独立数据库、重复迁移、SQL 查询准备、公开 CLI、JWT 与 JWKS 安全边界、真实 HTTP、失败关闭和并发业务变更。`TestInvoiceSaaSAuditOutbox` 覆盖业务与入队回滚、River 重启恢复、响应丢失、缓存失败恢复、凭据变化、幂等窗口及秘密扫描。空库接入测试通过公开 Auth API/CLI 建立应用、安装、用户、父子 Agent 与授予，再通过独立 SaaS API 验证资源组隔离、审批后的实际业务落库、单次消费、Auth 故障、中央业务审计故障恢复后的唯一成功记录及撤销审计。专项失败测试使用可控 HTTP 响应；空库场景使用真正的 Auth 授权与审批服务。

当前原生 Agent 分支已有独立业务示例；M3 的 OAuth Agent 治理受众契约及 M5/M6 完整终验仍以 [roadmap](../../../auth-docs/roadmap.md) 为准。完整托管界面、SDK 与其余平台能力继续按长期路线图实施。
