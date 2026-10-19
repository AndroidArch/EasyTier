# EasyTier Web 原生 HTTP MCP

MCP 直接运行在 `easytier-web` Rust 后端内，与 REST API 使用同一个监听端口，路径为 **`/mcp`**。不需要 Python、单独的 MCP 进程或 HTTP 回环代理。

## 启用

默认关闭，不改变现有 Web 管理端行为。先通过原有 Web 界面创建一个管理账号，再用该账号绑定 MCP：

```powershell
$env:ET_MCP_ENABLED = 'true'
$env:ET_MCP_USERNAME = '已有的管理账号'
$env:ET_MCP_TOKEN = '<自行设置的随机访问令牌>'
cargo run -p easytier-web -- --api-server-port 11211
```

客户端连接 `http://127.0.0.1:11211/mcp`，每次请求携带：

```http
Authorization: Bearer <自行设置的随机访问令牌>
```

MCP 使用独立访问令牌，不接收 Web 登录密码。每次请求将令牌映射到配置的现有账号，再经过现有管理处理器执行。不会绕过用户归属、配置权限或集中网络的所有权约束；不接受任意 `user_id` 参数。修改/删除绑定账号或轮换令牌后需要相应更新服务配置。所有持有同一个令牌的客户端共享该账号权限，当前不是每用户多令牌/OAuth 实现。

CLI 参数与对应环境变量：

| 参数 | 环境变量 | 默认值/说明 |
| --- | --- | --- |
| `--mcp-enabled` | ET_MCP_ENABLED | false |
| `--mcp-token` | ET_MCP_TOKEN | 启用时必填，Debug 输出脱敏 |
| `--mcp-username` | ET_MCP_USERNAME | 启用时必填，必须是已存在账号 |
| `--mcp-allow-writes` | ET_MCP_ALLOW_WRITES | false |
| `--mcp-sites-file` | ET_MCP_SITES_FILE | 可选，场站 JSON 映射 |
| `--mcp-allowed-hosts` | ET_MCP_ALLOWED_HOSTS | 额外允许的 Host，逗号分隔；默认允许回环主机 |
| `--mcp-allowed-origins` | ET_MCP_ALLOWED_ORIGINS | 允许的浏览器 Origin，逗号分隔；默认拒绝所有带 Origin 的请求，原生客户端可不发送 Origin |

远程部署沿用管理端的 API 监听地址和端口；增加客户端实际使用的 Host，如 `sdwan.example.com`。浏览器调用另需设置完整 Origin，如 `https://sdwan.example.com:443`。由现有反向代理提供 HTTPS，转发 `/mcp`、Authorization 和 MCP 协议头；无需增加独立端口。`/mcp` 是 MCP 协议接口，直接在浏览器打开不等于初始化连接成功。

客户端示意配置（字段由具体客户端决定）：

```json
{
  "mcpServers": {
    "easytier-web": {
      "url": "https://sdwan.example.com/mcp",
      "headers": {"Authorization": "Bearer <runtime-token>"}
    }
  }
}
```

## 工具

| 工具 | 功能 |
| --- | --- |
| network_summary | 当前账号的平台概要和设备数量 |
| network_list_machines | 主机列表、心跳、管理在线状态 |
| network_list_sessions | 当前账号的管理会话 |
| network_list_instances | 主机上的运行及禁用实例 |
| network_get_instance_info | 指定实例运行信息 |
| network_get_metas | 实例名称、配置权限；单次 1–200 个 UUID |
| network_get_config | 读取完整 NetworkConfig，默认脱敏 |
| network_generate_config | JSON 配置转 TOML，默认脱敏 |
| network_parse_config | TOML 转 JSON 配置，默认脱敏 |
| network_validate_config | 在目标主机校验配置，不修改网络 |
| network_run_instance | 创建/运行实例，先校验后提交并回读；缺省 ID 时生成 UUID |
| network_save_config | 保存完整配置，核对 ID、读取基线、校验并回读 |
| network_set_instance_state | 启用或禁用实例，执行后回读 |
| network_remove_instance | 删除实例，执行后回读 |
| site_network_status | 按场站映射汇总管理状态和实例状态 |
| site_network_diagnose | 组合状态、配置和运行信息，给出证据与排查建议 |

机器和实例参数使用标准 UUID；上游 protobuf 四段整数 UUID 自动转换为标准字符串。工具对参数类型、必填项和未知字段进行验证。

## 配置与变更

配置读取、生成和解析的 `include_secrets` 默认 false；设为 true 可读取真实秘密，适用于可信客户端编辑配置。持有令牌的调用者具备此能力，不提供逐工具细分授权。

密码、网络密钥、私钥、令牌、TOML 内秘密和 URL 凭据默认脱敏。不能把 `<redacted>` 回写。保存配置使用完整 NetworkConfig，`config.instance_id` 必须匹配工具参数。

需要管理写入时，设置 `ET_MCP_ALLOW_WRITES=true`。进程内管理写入串行执行；创建和保存先校验。处理器仍使用原来的配置权限及集中管理冲突检查。上游拒绝集中托管网络的直接变更时，使用原有集中管理流程处理。

`outcome=accepted` 表示管理接口已接受，不代表异步状态已收敛；`outcome=unknown` 表示超时或服务端错误后结果不能确定。管理写入不自动重发，立即尝试回读并保留读回错误。`submitted_fields_match` / `state_matches` 只表示本次即时回读的匹配情况。

保存前的 `before_config_redacted` 已脱敏，不能直接恢复。执行前由操作者保管完整基线；本版本没有自动回滚、外部并发乐观锁或保证业务连通性的机制。禁用/删除承载管理链路的实例可能中断远程访问。

## 场站映射

通过 `ET_MCP_SITES_FILE` 指向本地 JSON 文件。相对路径以进程工作目录为基准，建议使用绝对路径。示例中的 UUID 必须替换为实际发现的值：

```json
{
  "sites": [
    {
      "site_id": "parking-demo",
      "name": "示例停车场",
      "machine_id": "11111111-2222-4333-8444-555555555555",
      "instance_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    }
  ]
}
```

重复的 site_id 或无效映射会拒绝执行。查询失败和权限不足标记为未知，不直接判为主机离线。诊断不执行 ping、端口扫描、路由器命令或后台定时监控；主机在线、实例运行与 NVR/摄像头可访问分别验证。

## 构建与测试

遵循当前上游 Rust 工具链及原生依赖要求（当前 Rust 1.95、Protobuf protoc 等）：

```powershell
cargo check -p easytier-web --locked
cargo test -p easytier-web restful::mcp --locked
```

测试在内存数据库和测试路由中验证 MCP 初始化、工具发现、调用、令牌绑定账号、秘密脱敏、错误处理和变更回读，不启动或迁移现有 `et.db`。真实平台节点和业务连通性仍需单独联调。

## 实现位置

- `src/restful/mcp.rs`：MCP 协议、鉴权、工具定义和组合业务。
- `src/restful/mcp_tests.rs`：原生 MCP 测试。
- `src/restful/mod.rs`：挂载 `/mcp`，复用原有进程内管理路由。
- `src/main.rs`：CLI 配置传入管理端。

采用官方 Rust MCP SDK `rmcp=3.5.1`，使用无状态 Streamable HTTP、JSON 响应并支持现有客户端使用的 initialize 生命周期（协议版本最高 2025-11-25）。全部工具调用都重新认证 HTTP 请求，不允许通过复用会话绕过访问令牌校验。
