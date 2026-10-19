//! Native Streamable HTTP MCP on the Web API listener. No subprocess or loopback HTTP.
#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
use std::{borrow::Cow, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use axum_login::AuthnBackend;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
        Tool, ToolAnnotations,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower::ServiceExt;
use uuid::Uuid;

use super::users::AuthSession;

const MASK: &str = "<redacted>";
const MAX_BODY: usize = 4 * 1024 * 1024;

#[derive(Clone, Default, clap::Args)]
pub struct McpOptions {
    /// Serve native Streamable HTTP MCP at /mcp on the API listener.
    #[arg(long, env = "ET_MCP_ENABLED", default_value = "false")]
    pub mcp_enabled: bool,
    /// MCP Bearer token; mapped to the existing user below, never a global admin bypass.
    #[arg(long, env = "ET_MCP_TOKEN", hide_env_values = true)]
    pub mcp_token: Option<String>,
    #[arg(long, env = "ET_MCP_USERNAME")]
    pub mcp_username: Option<String>,
    #[arg(long, env = "ET_MCP_ALLOW_WRITES", default_value = "false")]
    pub mcp_allow_writes: bool,
    #[arg(long, env = "ET_MCP_SITES_FILE")]
    pub mcp_sites_file: Option<PathBuf>,
    /// Additional hostnames (or host:port) accepted by /mcp. Loopback is always allowed.
    #[arg(long, env = "ET_MCP_ALLOWED_HOSTS", value_delimiter = ',')]
    pub mcp_allowed_hosts: Vec<String>,
    /// Browser Origins allowed to access /mcp. No Origin header is required for native clients.
    #[arg(long, env = "ET_MCP_ALLOWED_ORIGINS", value_delimiter = ',')]
    pub mcp_allowed_origins: Vec<String>,
}

impl std::fmt::Debug for McpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpOptions")
            .field("enabled", &self.mcp_enabled)
            .field("username", &self.mcp_username)
            .field("token", &self.mcp_token.as_ref().map(|_| MASK))
            .field("allow_writes", &self.mcp_allow_writes)
            .finish_non_exhaustive()
    }
}

impl McpOptions {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.mcp_enabled {
            anyhow::ensure!(
                self.mcp_token
                    .as_ref()
                    .is_some_and(|x| !x.trim().is_empty()),
                "ET_MCP_TOKEN is required when MCP is enabled"
            );
            anyhow::ensure!(
                self.mcp_username
                    .as_ref()
                    .is_some_and(|x| !x.trim().is_empty()),
                "ET_MCP_USERNAME must identify an existing Web user"
            );
        }
        Ok(())
    }
}

fn token_matches(headers: &axum::http::HeaderMap, expected: &str) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|x| x.to_str().ok())
        .and_then(|x| x.strip_prefix("Bearer "))
    else {
        return false;
    };
    bool::from(Sha256::digest(token.as_bytes()).ct_eq(&Sha256::digest(expected.as_bytes())))
}

async fn authenticate(
    options: Arc<McpOptions>,
    mut auth: AuthSession,
    mut request: Request,
    next: Next,
) -> Response {
    if !token_matches(
        request.headers(),
        options.mcp_token.as_deref().unwrap_or_default(),
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"error":"MCP bearer token required"})),
        )
            .into_response();
    }
    // Resolve the account on every request. Deleting the account revokes access;
    // an unrelated browser session cannot change the identity of this token.
    let id = match auth
        .backend
        .db()
        .get_user_id(options.mcp_username.as_deref().unwrap_or_default())
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"MCP user not found"})),
            )
                .into_response();
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    auth.user = match auth.backend.get_user(&id).await {
        Ok(Some(user)) => Some(user),
        _ => return StatusCode::FORBIDDEN.into_response(),
    };
    request.extensions_mut().insert(auth);
    next.run(request).await
}

pub(super) fn router(api: Router, options: McpOptions) -> Router {
    if !options.mcp_enabled {
        return Router::new();
    }
    let options = Arc::new(options);
    let handler = NativeMcp {
        api,
        options: options.clone(),
        writes: Arc::new(tokio::sync::Mutex::new(())),
    };
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(MAX_BODY)
        .with_allowed_origins(options.mcp_allowed_origins.clone())
        .enforce_origin_validation();
    config
        .allowed_hosts
        .extend(options.mcp_allowed_hosts.clone());
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    Router::new()
        .route_service("/mcp", service)
        .route_layer(middleware::from_fn(
            move |auth: AuthSession, req: Request, next: Next| {
                authenticate(options.clone(), auth, req, next)
            },
        ))
}

#[derive(Clone)]
struct NativeMcp {
    api: Router,
    options: Arc<McpOptions>,
    writes: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    machine_id: Option<Uuid>,
    instance_id: Option<Uuid>,
    instance_ids: Option<Vec<Uuid>>,
    config: Option<Map<String, Value>>,
    toml_config: Option<String>,
    include_secrets: Option<bool>,
    save: Option<bool>,
    disabled: Option<bool>,
    site_id: Option<String>,
}

struct Spec {
    name: &'static str,
    description: &'static str,
    fields: &'static [&'static str],
    required: &'static [&'static str],
    write: bool,
}

fn specs() -> Vec<Spec> {
    vec![
        Spec {
            name: "network_summary",
            description: "查询当前账号的管理平台设备数量，不等于在线数。",
            fields: &[],
            required: &[],
            write: false,
        },
        Spec {
            name: "network_list_machines",
            description: "列出当前账号主机、心跳及在线状态，UUID 转为标准字符串，秘密脱敏。",
            fields: &[],
            required: &[],
            write: false,
        },
        Spec {
            name: "network_list_sessions",
            description: "列出当前账号关联的管理会话，不代表数据隧道连通。",
            fields: &[],
            required: &[],
            write: false,
        },
        Spec {
            name: "network_list_instances",
            description: "查询主机的运行中与禁用实例。",
            fields: &["machine_id"],
            required: &["machine_id"],
            write: false,
        },
        Spec {
            name: "network_get_instance_info",
            description: "读取指定实例的运行信息，保留 info.map。",
            fields: &["machine_id", "instance_id"],
            required: &["machine_id", "instance_id"],
            write: false,
        },
        Spec {
            name: "network_get_metas",
            description: "批量查询 1–200 个实例的名称及配置权限。",
            fields: &["machine_id", "instance_ids"],
            required: &["machine_id", "instance_ids"],
            write: false,
        },
        Spec {
            name: "network_get_config",
            description: "读取完整实例配置；默认脱敏。include_secrets=true 仅供可信客户端编辑，不得回写脱敏占位符。",
            fields: &["machine_id", "instance_id", "include_secrets"],
            required: &["machine_id", "instance_id"],
            write: false,
        },
        Spec {
            name: "network_generate_config",
            description: "将 NetworkConfig JSON 转为 TOML，不修改网络，默认脱敏。",
            fields: &["config", "include_secrets"],
            required: &["config"],
            write: false,
        },
        Spec {
            name: "network_parse_config",
            description: "将 TOML 转为 NetworkConfig JSON，不修改网络，默认脱敏。",
            fields: &["toml_config", "include_secrets"],
            required: &["toml_config"],
            write: false,
        },
        Spec {
            name: "network_validate_config",
            description: "通过目标主机校验配置，不修改网络，输出脱敏。",
            fields: &["machine_id", "config"],
            required: &["machine_id", "config"],
            write: false,
        },
        Spec {
            name: "network_run_instance",
            description: "创建或运行实例；先校验后提交一次并回读，缺省实例 ID 时生成 UUID。",
            fields: &["machine_id", "config", "save"],
            required: &["machine_id", "config"],
            write: true,
        },
        Spec {
            name: "network_save_config",
            description: "保存完整配置，实例 ID 必须匹配；复用原生权限和所有权检查，执行后回读。",
            fields: &["machine_id", "instance_id", "config"],
            required: &["machine_id", "instance_id", "config"],
            write: true,
        },
        Spec {
            name: "network_set_instance_state",
            description: "启停实例：disabled=true 禁用、false 启用，可能中断远程访问。",
            fields: &["machine_id", "instance_id", "disabled"],
            required: &["machine_id", "instance_id", "disabled"],
            write: true,
        },
        Spec {
            name: "network_remove_instance",
            description: "删除实例，可能中断远程组网；提交后回读，不自动重试。",
            fields: &["machine_id", "instance_id"],
            required: &["machine_id", "instance_id"],
            write: true,
        },
        Spec {
            name: "site_network_status",
            description: "按本地场站映射汇总主机及实例状态，查询失败记为未知。",
            fields: &["site_id"],
            required: &["site_id"],
            write: false,
        },
        Spec {
            name: "site_network_diagnose",
            description: "组合场站状态、运行信息与配置，给出证据及建议，不执行业务端口探测。",
            fields: &["site_id"],
            required: &["site_id"],
            write: false,
        },
    ]
}

fn field_schema(name: &str) -> Value {
    match name {
        "machine_id" | "instance_id" => json!({"type":"string","format":"uuid"}),
        "instance_ids" => {
            json!({"type":"array","minItems":1,"maxItems":200,"items":{"type":"string","format":"uuid"}})
        }
        "config" => {
            json!({"type":"object","description":"目标版本完整 NetworkConfig，保留未知字段"})
        }
        "include_secrets" => json!({"type":"boolean","default":false}),
        "save" => json!({"type":"boolean","default":true}),
        "disabled" => json!({"type":"boolean"}),
        _ => json!({"type":"string","minLength":1}),
    }
}

impl Spec {
    fn tool(&self) -> Tool {
        let properties: Map<String, Value> = self
            .fields
            .iter()
            .map(|f| (f.to_string(), field_schema(f)))
            .collect();
        Tool::new(self.name, self.description, json!({
            "type":"object","properties":properties,"required":self.required,"additionalProperties":false,
        }).as_object().unwrap().clone()).with_annotations(
            ToolAnnotations::new().read_only(!self.write).destructive(self.write).idempotent(!self.write),
        )
    }

    fn arguments(&self, raw: Map<String, Value>) -> Result<Arguments, ErrorData> {
        if raw.keys().any(|key| !self.fields.contains(&key.as_str()))
            || self
                .required
                .iter()
                .any(|key| raw.get(*key).is_none_or(Value::is_null))
        {
            return Err(ErrorData::invalid_params(
                "Missing required or unexpected tool argument",
                None,
            ));
        }
        let a: Arguments = serde_json::from_value(Value::Object(raw))
            .map_err(|_| ErrorData::invalid_params("Invalid argument type or UUID", None))?;
        if a.instance_ids
            .as_ref()
            .is_some_and(|x| x.is_empty() || x.len() > 200)
            || a.site_id.as_ref().is_some_and(|x| x.trim().is_empty())
        {
            return Err(ErrorData::invalid_params("Invalid argument size", None));
        }
        Ok(a)
    }
}

#[derive(Debug)]
struct Failure {
    code: String,
    status: Option<u16>,
    unknown: bool,
}
impl Failure {
    fn new(code: &str) -> Self {
        Self {
            code: code.into(),
            status: None,
            unknown: false,
        }
    }
    fn json(&self) -> Value {
        json!({"code":self.code,"status":self.status,"outcome_unknown":self.unknown})
    }
}

impl NativeMcp {
    async fn api(
        &self,
        auth: &AuthSession,
        method: Method,
        path: String,
        body: Option<Value>,
        write: bool,
    ) -> Result<Value, Failure> {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                body.map(|v| Body::from(v.to_string()))
                    .unwrap_or_else(Body::empty),
            )
            .unwrap();
        req.extensions_mut().insert(auth.clone());
        let response = tokio::time::timeout(Duration::from_secs(30), self.api.clone().oneshot(req))
            .await
            .map_err(|_| Failure {
                code: "request_timeout".into(),
                status: None,
                unknown: write,
            })?
            .map_err(|_| Failure::new("internal_dispatch_failed"))?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_BODY)
            .await
            .map_err(|_| Failure {
                code: "invalid_response_body".into(),
                status: Some(status.as_u16()),
                unknown: write,
            })?;
        let value: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| Failure {
                code: "invalid_json_response".into(),
                status: Some(status.as_u16()),
                unknown: write,
            })?
        };
        if !status.is_success() {
            let code = value
                .get("code")
                .and_then(Value::as_str)
                .filter(|s| {
                    s.len() <= 100 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
                .unwrap_or("management_api_error");
            return Err(Failure {
                code: code.into(),
                status: Some(status.as_u16()),
                unknown: write && status.is_server_error(),
            });
        }
        if value
            .get("error")
            .is_some_and(|v| !v.is_null() && v != false && v != "")
        {
            return Err(Failure::new("configuration_conversion_failed"));
        }
        Ok(normalize(value))
    }

    async fn get(&self, auth: &AuthSession, path: String) -> Result<Value, Failure> {
        self.api(auth, Method::GET, path, None, false).await
    }

    async fn dispatch(
        &self,
        name: &str,
        a: Arguments,
        auth: &AuthSession,
    ) -> Result<Value, Failure> {
        let path = |suffix: &str| format!("/api/v1/machines/{}{suffix}", a.machine_id.unwrap());
        let result = match name {
            "network_summary" => self.get(auth, "/api/v1/summary".into()).await?,
            "network_list_machines" => self.get(auth, "/api/v1/machines".into()).await?,
            "network_list_sessions" => {
                json!({"sessions":self.get(auth,"/api/v1/sessions".into()).await?})
            }
            "network_list_instances" => self.get(auth, path("/networks")).await?,
            "network_get_instance_info" => {
                self.get(
                    auth,
                    path(&format!("/networks/info/{}", a.instance_id.unwrap())),
                )
                .await?
            }
            "network_get_config" => {
                self.get(
                    auth,
                    path(&format!("/networks/config/{}", a.instance_id.unwrap())),
                )
                .await?
            }
            "network_get_metas" => {
                self.api(
                    auth,
                    Method::POST,
                    path("/networks/metas"),
                    Some(json!({"instance_ids":a.instance_ids})),
                    false,
                )
                .await?
            }
            "network_generate_config" | "network_validate_config" | "network_parse_config" => {
                let (p, b) = match name {
                    "network_parse_config" => (
                        "/api/v1/parse-config".into(),
                        json!({"toml_config":a.toml_config}),
                    ),
                    "network_generate_config" => {
                        ("/api/v1/generate-config".into(), json!({"config":a.config}))
                    }
                    _ => (path("/validate-config"), json!({"config":a.config})),
                };
                if contains_mask(&b) {
                    return Err(Failure::new("redacted_config_cannot_be_submitted"));
                }
                self.api(auth, Method::POST, p, Some(b), false).await?
            }
            "site_network_status" | "site_network_diagnose" => {
                return self
                    .site(
                        auth,
                        a.site_id.as_deref().unwrap(),
                        name.ends_with("diagnose"),
                    )
                    .await;
            }
            _ => return self.mutate(name, a, auth).await,
        };
        Ok(if a.include_secrets.unwrap_or(false) {
            result
        } else {
            redact(result)
        })
    }

    async fn mutate(
        &self,
        name: &str,
        mut a: Arguments,
        auth: &AuthSession,
    ) -> Result<Value, Failure> {
        if !self.options.mcp_allow_writes {
            return Err(Failure::new("mcp_writes_disabled"));
        }
        let _guard = self.writes.lock().await;
        let machine = a.machine_id.unwrap();
        let base = format!("/api/v1/machines/{machine}");
        let instance = if name == "network_run_instance" {
            let config = a.config.as_mut().unwrap();
            let id = match config.get("instance_id") {
                Some(Value::String(s)) => {
                    Uuid::parse_str(s).map_err(|_| Failure::new("invalid_config_instance_id"))?
                }
                None | Some(Value::Null) => Uuid::new_v4(),
                _ => return Err(Failure::new("invalid_config_instance_id")),
            };
            config.insert("instance_id".into(), json!(id));
            id
        } else {
            a.instance_id.unwrap()
        };
        if let Some(config) = &a.config {
            if contains_mask(&json!(config)) {
                return Err(Failure::new("redacted_config_cannot_be_submitted"));
            }
            if config
                .get("instance_id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                != Some(instance)
            {
                return Err(Failure::new("instance_id_mismatch"));
            }
        }
        let mut before = None;
        if name == "network_save_config" {
            before = Some(redact(
                self.get(auth, format!("{base}/networks/config/{instance}"))
                    .await?,
            ));
        }
        if a.config.is_some() {
            self.api(
                auth,
                Method::POST,
                format!("{base}/validate-config"),
                Some(json!({"config":a.config})),
                false,
            )
            .await?;
        }
        let (method, url, body) = match name {
            "network_run_instance" => (
                Method::POST,
                format!("{base}/networks"),
                Some(json!({"config":a.config,"save":a.save.unwrap_or(true)})),
            ),
            "network_save_config" => (
                Method::PUT,
                format!("{base}/networks/config/{instance}"),
                Some(json!({"config":a.config})),
            ),
            "network_set_instance_state" => (
                Method::PUT,
                format!("{base}/networks/{instance}"),
                Some(json!({"disabled":a.disabled.unwrap()})),
            ),
            "network_remove_instance" => {
                (Method::DELETE, format!("{base}/networks/{instance}"), None)
            }
            _ => return Err(Failure::new("unknown_tool")),
        };
        let mut result = json!({"machine_id":machine,"instance_id":instance,"business_connectivity":"not_tested"});
        match self.api(auth, method, url, body, true).await {
            Ok(_) => result["outcome"] = json!("accepted"),
            Err(e) if e.unknown => {
                result["outcome"] = json!("unknown");
                result["error"] = e.json();
            }
            Err(e) => return Err(e),
        }
        if let Some(before) = before {
            result["before_config_redacted"] = before;
        }
        let read_url = if name == "network_save_config" {
            format!("{base}/networks/config/{instance}")
        } else {
            format!("{base}/networks")
        };
        match self.get(auth, read_url).await {
            Ok(v) => {
                if name == "network_save_config" {
                    result["submitted_fields_match"] = json!(
                        a.config
                            .as_ref()
                            .unwrap()
                            .iter()
                            .all(|(k, x)| v.get(k) == Some(x))
                    );
                } else if let (Some(running), Some(disabled)) = (
                    v.get("running_inst_ids").and_then(Value::as_array),
                    v.get("disabled_inst_ids").and_then(Value::as_array),
                ) {
                    let target = json!(instance);
                    result["state_matches"] = json!(match name {
                        "network_remove_instance" =>
                            !running.contains(&target) && !disabled.contains(&target),
                        "network_set_instance_state" if a.disabled == Some(true) =>
                            disabled.contains(&target),
                        _ => running.contains(&target),
                    });
                }
                result["readback"] = redact(v);
            }
            Err(e) => result["readback_error"] = e.json(),
        }
        tracing::info!(tool=name,machine_id=%machine,instance_id=%instance,outcome=%result["outcome"],"MCP management operation");
        Ok(result)
    }

    async fn site(&self, auth: &AuthSession, id: &str, diagnose: bool) -> Result<Value, Failure> {
        #[derive(Deserialize)]
        struct Sites {
            sites: Vec<Site>,
        }
        #[derive(Deserialize, serde::Serialize)]
        struct Site {
            site_id: String,
            name: Option<String>,
            machine_id: Uuid,
            instance_id: Uuid,
        }
        let file = self
            .options
            .mcp_sites_file
            .as_ref()
            .ok_or_else(|| Failure::new("sites_file_not_configured"))?;
        let text = tokio::fs::read_to_string(file)
            .await
            .map_err(|_| Failure::new("sites_file_unavailable"))?;
        let mappings: Sites =
            serde_json::from_str(&text).map_err(|_| Failure::new("invalid_sites_file"))?;
        let matches: Vec<_> = mappings
            .sites
            .into_iter()
            .filter(|s| s.site_id == id)
            .collect();
        if matches.len() != 1 {
            return Err(Failure::new("site_missing_or_duplicated"));
        }
        let site = &matches[0];
        let base = format!("/api/v1/machines/{}", site.machine_id);
        let mut result = json!({"site":site,"collected_at":chrono::Utc::now().to_rfc3339(),"management_status":"unknown","instance_status":"unknown","business_connectivity":"not_tested","errors":[]});
        let mut errors = vec![];
        match self.get(auth, "/api/v1/machines".into()).await {
            Ok(v) => {
                if let Some(rows) = v.get("machines").and_then(Value::as_array) {
                    if let Some(machine) = rows
                        .iter()
                        .find(|m| m.pointer("/info/machine_id") == Some(&json!(site.machine_id)))
                    {
                        result["management_status"] =
                            json!(match machine.get("online").and_then(Value::as_bool) {
                                Some(true) => "online",
                                Some(false) => "offline",
                                None => "unknown",
                            });
                        result["machine"] = redact(machine.clone());
                    }
                }
            }
            Err(e) => errors.push(json!({"step":"machines","error":e.json()})),
        }
        match self.get(auth, format!("{base}/networks")).await {
            Ok(v) => {
                if let (Some(r), Some(d)) = (
                    v.get("running_inst_ids").and_then(Value::as_array),
                    v.get("disabled_inst_ids").and_then(Value::as_array),
                ) {
                    let target = json!(site.instance_id);
                    result["instance_status"] = json!(if r.contains(&target) {
                        "running"
                    } else if d.contains(&target) {
                        "disabled"
                    } else {
                        "not_found"
                    });
                }
                result["instances"] = redact(v);
            }
            Err(e) => errors.push(json!({"step":"instances","error":e.json()})),
        }
        if diagnose {
            for (key, path) in [
                (
                    "runtime",
                    format!("{base}/networks/info/{}", site.instance_id),
                ),
                (
                    "config",
                    format!("{base}/networks/config/{}", site.instance_id),
                ),
            ] {
                match self.get(auth, path).await {
                    Ok(v) => result[key] = redact(v),
                    Err(e) => errors.push(json!({"step":key,"error":e.json()})),
                };
            }
            let mut findings = vec![];
            if result["management_status"] == "offline" {
                findings.push("管理平台报告主机离线，检查主机进程及管理连接");
            }
            if result["instance_status"] == "disabled" {
                findings.push("目标实例已禁用，核对停用原因");
            }
            if result["instance_status"] == "not_found" {
                findings.push("实例列表没有目标实例，核对账号范围与场站映射");
            }
            if !errors.is_empty()
                || result["management_status"] == "unknown"
                || result["instance_status"] == "unknown"
            {
                findings.push("部分状态未知，先排查接口错误、权限或版本，不将查询失败判定为离线");
            }
            findings.push("尚未执行 NVR、摄像头或业务端口连通性探测");
            result["findings"] = json!(findings);
        }
        result["errors"] = json!(errors);
        Ok(result)
    }
}

impl ServerHandler for NativeMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("easytier-web-mcp",env!("CARGO_PKG_VERSION")))
            .with_instructions("原生 EasyTier 管理接口。先发现机器和实例；秘密默认脱敏，写入可能中断远程连接，超时不得盲目重发。")
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        // Keep the initialize lifecycle used by existing HTTP MCP clients.
        Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::V_2025_11_25))
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        specs()
            .into_iter()
            .find(|s| s.name == name)
            .map(|s| s.tool())
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.is_some_and(|p| p.cursor.is_some()) {
            return Err(ErrorData::invalid_params("No further tool pages", None));
        }
        let mut result = ListToolsResult::default();
        result.tools = specs().iter().map(Spec::tool).collect();
        Ok(result)
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let spec = specs()
            .into_iter()
            .find(|s| s.name == request.name)
            .ok_or_else(|| ErrorData::invalid_params("Unknown tool", None))?;
        let args = spec.arguments(request.arguments.unwrap_or_default())?;
        let auth = context
            .extensions
            .get::<Parts>()
            .and_then(|p| p.extensions.get::<AuthSession>())
            .ok_or_else(|| {
                ErrorData::internal_error("Missing authenticated request context", None)
            })?;
        let result = match self.dispatch(spec.name, args, auth).await {
            Ok(value) => CallToolResult::structured(value),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(e.json().to_string())]),
        };
        Ok(result.into())
    }
}

fn contains_mask(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(MASK),
        Value::Array(a) => a.iter().any(contains_mask),
        Value::Object(m) => m.values().any(contains_mask),
        _ => false,
    }
}

fn sensitive(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "password",
        "secret",
        "token",
        "private_key",
        "privatekey",
        "credential",
        "cookie",
        "authorization",
    ]
    .iter()
    .any(|s| key.contains(s))
}

fn redact(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let v = if sensitive(&k) {
                        json!(MASK)
                    } else {
                        redact(v)
                    };
                    (k, v)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(redact).collect()),
        Value::String(s) => {
            if s.contains('\n') || s.contains('=') {
                if let Ok(t) = s.parse::<toml::Value>() {
                    if let Ok(v) = serde_json::to_value(t) {
                        if let Ok(t) = serde_json::from_value::<toml::Value>(redact(v)) {
                            if let Ok(s) = toml::to_string(&t) {
                                return json!(s);
                            }
                        }
                    }
                }
                if sensitive(&s) {
                    return json!(MASK);
                }
            }
            if s.contains("://") {
                if let Ok(mut u) = url::Url::parse(&s) {
                    let _ = u.set_username("");
                    let _ = u.set_password(None);
                    let pairs: Vec<(String, String)> = u
                        .query_pairs()
                        .map(|(k, v)| {
                            (
                                k.to_string(),
                                if sensitive(&k) {
                                    MASK.into()
                                } else {
                                    v.to_string()
                                },
                            )
                        })
                        .collect();
                    u.set_query(None);
                    if !pairs.is_empty() {
                        u.query_pairs_mut().extend_pairs(pairs);
                    }
                    return json!(u.to_string());
                }
            }
            json!(s)
        }
        _ => v,
    }
}

fn normalize(v: Value) -> Value {
    match v {
        Value::Object(m)
            if !m.is_empty()
                && m.keys()
                    .all(|k| ["part1", "part2", "part3", "part4"].contains(&k.as_str())) =>
        {
            let mut n = 0_u128;
            for i in 1..=4 {
                let p = m
                    .get(&format!("part{i}"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if p > u32::MAX as u64 {
                    return Value::Object(m);
                }
                n = (n << 32) | p as u128;
            }
            json!(Uuid::from_u128(n))
        }
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (k, normalize(v))).collect()),
        Value::Array(a) => Value::Array(a.into_iter().map(normalize).collect()),
        _ => v,
    }
}
