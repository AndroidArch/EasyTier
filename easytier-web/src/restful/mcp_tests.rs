use super::*;
use axum::routing::{get, post, put};
use axum_login::{AuthManagerLayerBuilder, tower_sessions::SessionManagerLayer};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower_sessions_sqlx_store::SqliteStore;

use crate::{db::Db, restful::users::Backend};

const MACHINE: &str = "11111111-2222-4333-8444-555555555555";
const INSTANCE: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

fn options() -> McpOptions {
    McpOptions {
        mcp_enabled: true,
        mcp_token: Some("test-token".into()),
        mcp_username: Some("mcp-user".into()),
        ..Default::default()
    }
}

async fn authenticated_app(api: Router, opts: McpOptions) -> (Router, i32) {
    let db = Db::memory_db().await;
    let user = db.auto_create_user("mcp-user").await.unwrap();
    // A second user demonstrates that the token is scoped to the selected account.
    db.auto_create_user("other-user").await.unwrap();
    let store = SqliteStore::new(db.inner());
    store.migrate().await.unwrap();
    let session_layer = SessionManagerLayer::new(store).with_secure(false);
    let layer = AuthManagerLayerBuilder::new(Backend::new(db), session_layer).build();
    (router(api, opts).layer(layer), user.id)
}

async fn rpc(app: &Router, message: Value, token: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(message.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
    let result = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&body)}));
    (status, result)
}

fn call(name: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})
}

#[test]
fn configuration_validation_and_debug_redaction() {
    assert!(McpOptions::default().validate().is_ok());
    assert!(
        McpOptions {
            mcp_enabled: true,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(options().validate().is_ok());
    assert!(!format!("{:?}", options()).contains("test-token"));
}

#[test]
fn tokens_are_required_and_compared_exactly() {
    let mut h = axum::http::HeaderMap::new();
    assert!(!token_matches(&h, "test"));
    h.insert(header::AUTHORIZATION, "Bearer test".parse().unwrap());
    assert!(token_matches(&h, "test"));
    assert!(!token_matches(&h, "other"));
    h.insert(header::AUTHORIZATION, "Basic test".parse().unwrap());
    assert!(!token_matches(&h, "test"));
}

#[test]
fn schemas_and_arguments_reject_unknown_fields_types_and_invalid_ids() {
    let all = specs();
    assert_eq!(all.len(), 16);
    assert_eq!(all.iter().filter(|s| s.write).count(), 4);
    let spec = all
        .iter()
        .find(|s| s.name == "network_set_instance_state")
        .unwrap();
    for invalid in [
        json!({}),
        json!({"machine_id":"../bad","instance_id":INSTANCE,"disabled":true}),
        json!({"machine_id":MACHINE,"instance_id":INSTANCE,"disabled":"false"}),
        json!({"machine_id":MACHINE,"instance_id":INSTANCE,"disabled":false,"command":"bad"}),
    ] {
        assert!(
            spec.arguments(invalid.as_object().unwrap().clone())
                .is_err()
        );
    }
    assert!(
        spec.arguments(
            json!({"machine_id":MACHINE,"instance_id":INSTANCE,"disabled":false})
                .as_object()
                .unwrap()
                .clone()
        )
        .is_ok()
    );
    assert_eq!(
        spec.tool().annotations.unwrap().destructive_hint,
        Some(true)
    );
}

#[test]
fn secrets_toml_urls_and_uuid_normalization() {
    let value = redact(
        json!({"network_secret":"secret-value", "secure_mode":{"local_private_key":"key-value"},
        "toml_config":"[network_identity]\nnetwork_secret = \"toml-secret\"\n",
        "peer_urls":["tcp://user:password@host:123?token=url-secret"]}),
    );
    let serialized = value.to_string();
    for secret in [
        "secret-value",
        "key-value",
        "toml-secret",
        "url-secret",
        "user:password",
    ] {
        assert!(!serialized.contains(secret));
    }
    assert!(contains_mask(&value));
    assert_eq!(
        normalize(
            json!({"part1":286331153,"part2":572670771,"part3":2219070805_u32,"part4":1431655765})
        ),
        json!(MACHINE)
    );
}

#[tokio::test]
async fn native_http_initialize_list_and_user_scoped_call() {
    let api = Router::new().route(
        "/api/v1/summary",
        get(|auth: AuthSession| async move {
            Json(json!({"user_id":auth.user.unwrap().db_user.id,"device_count":1}))
        }),
    );
    let (app, id) = authenticated_app(api, options()).await;
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
    assert_eq!(
        rpc(&app, initialize.clone(), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        rpc(&app, initialize.clone(), Some("wrong")).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, response) = rpc(&app, initialize, Some("test-token")).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["serverInfo"]["name"], "easytier-web-mcp");
    let (_, list) = rpc(
        &app,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        Some("test-token"),
    )
    .await;
    assert_eq!(
        list["result"]["tools"].as_array().unwrap().len(),
        16,
        "{list}"
    );
    let (_, data) = rpc(&app, call("network_summary", json!({})), Some("test-token")).await;
    assert_eq!(data["result"]["structuredContent"]["user_id"], id, "{data}");
    assert_eq!(data["result"]["structuredContent"]["device_count"], 1);
    let (_, bad) = rpc(
        &app,
        call("network_list_instances", json!({"machine_id":"bad"})),
        Some("test-token"),
    )
    .await;
    assert!(bad.get("error").is_some(), "{bad}");
}

#[tokio::test]
async fn disabled_or_missing_account_cannot_access_mcp() {
    let (app, _) = authenticated_app(Router::new(), McpOptions::default()).await;
    assert_eq!(
        rpc(&app, call("network_summary", json!({})), None).await.0,
        StatusCode::NOT_FOUND
    );
    let mut opts = options();
    opts.mcp_username = Some("does-not-exist".into());
    let (app, _) = authenticated_app(Router::new(), opts).await;
    assert_eq!(
        rpc(&app, call("network_summary", json!({})), Some("test-token"))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn host_and_origin_checks_protect_http_endpoint() {
    let (app, _) = authenticated_app(Router::new(), options()).await;
    for (name, value, expected) in [
        ("host", "attacker.example", StatusCode::FORBIDDEN),
        ("origin", "https://attacker.example", StatusCode::FORBIDDEN),
    ] {
        let mut req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("Host", if name == "host" { value } else { "localhost" })
            .header("Authorization", "Bearer test-token")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");
        if name == "origin" {
            req = req.header(name, value);
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn write_gate_validation_id_match_and_readback() {
    let count = Arc::new(AtomicUsize::new(0));
    let state = count.clone();
    let api=Router::new()
        .route("/api/v1/machines/{m}/validate-config",post(||async {Json(json!({"toml_config":"network_name=\"test\"\n"}))}))
        .route("/api/v1/machines/{m}/networks/config/{i}",get(||async {Json(json!({"instance_id":INSTANCE,"network_name":"test","network_secret":"hidden-secret"}))})
            .put(move ||{let count=state.clone();async move{count.fetch_add(1,Ordering::SeqCst);StatusCode::OK}}));
    let request = call(
        "network_save_config",
        json!({"machine_id":MACHINE,"instance_id":INSTANCE,"config":{"instance_id":INSTANCE,"network_name":"test","network_secret":"hidden-secret"}}),
    );
    let (app, _) = authenticated_app(api.clone(), options()).await;
    let (_, denied) = rpc(&app, request.clone(), Some("test-token")).await;
    assert_eq!(denied["result"]["isError"], true);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let mut opts = options();
    opts.mcp_allow_writes = true;
    let (app, _) = authenticated_app(api, opts).await;
    let (_, result) = rpc(&app, request, Some("test-token")).await;
    assert_eq!(
        result["result"]["structuredContent"]["outcome"], "accepted",
        "{result}"
    );
    assert_eq!(
        result["result"]["structuredContent"]["submitted_fields_match"],
        true
    );
    assert!(!result.to_string().contains("hidden-secret"));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let (_, bad) = rpc(
        &app,
        call(
            "network_save_config",
            json!({"machine_id":MACHINE,"instance_id":INSTANCE,"config":{"instance_id":MACHINE}}),
        ),
        Some("test-token"),
    )
    .await;
    assert_eq!(bad["result"]["isError"], true);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn conversion_error_on_200_becomes_tool_error_without_secret_leak() {
    let api = Router::new().route(
        "/api/v1/parse-config",
        post(|| async { Json(json!({"error":"bad secret-value","config":null})) }),
    );
    let (app, _) = authenticated_app(api, options()).await;
    let (_, result) = rpc(
        &app,
        call("network_parse_config", json!({"toml_config":"bad"})),
        Some("test-token"),
    )
    .await;
    assert_eq!(result["result"]["isError"], true);
    assert!(!result.to_string().contains("secret-value"));
}

#[tokio::test]
async fn failed_write_is_not_retried_and_unknown_outcome_keeps_readback() {
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let api = Router::new()
        .route(
            "/api/v1/machines/{m}/networks/{i}",
            put(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    StatusCode::GATEWAY_TIMEOUT
                }
            }),
        )
        .route(
            "/api/v1/machines/{m}/networks",
            get(|| async { Json(json!({"running_inst_ids":[INSTANCE],"disabled_inst_ids":[]})) }),
        );
    let mut opts = options();
    opts.mcp_allow_writes = true;
    let (app, _) = authenticated_app(api, opts).await;
    let (_, result) = rpc(
        &app,
        call(
            "network_set_instance_state",
            json!({"machine_id":MACHINE,"instance_id":INSTANCE,"disabled":true}),
        ),
        Some("test-token"),
    )
    .await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        result["result"]["structuredContent"]["outcome"], "unknown",
        "{result}"
    );
    assert_eq!(
        result["result"]["structuredContent"]["state_matches"],
        false
    );
}

#[tokio::test]
async fn site_api_errors_remain_unknown_instead_of_offline() {
    let file = std::env::temp_dir().join(format!("easytier-mcp-sites-{}.json", Uuid::new_v4()));
    tokio::fs::write(
        &file,
        json!({"sites":[{"site_id":"test","machine_id":MACHINE,"instance_id":INSTANCE}]})
            .to_string(),
    )
    .await
    .unwrap();
    let api = Router::new().fallback(|| async { StatusCode::SERVICE_UNAVAILABLE });
    let mut opts = options();
    opts.mcp_sites_file = Some(file.clone());
    let (app, _) = authenticated_app(api, opts).await;
    let (_, result) = rpc(
        &app,
        call("site_network_diagnose", json!({"site_id":"test"})),
        Some("test-token"),
    )
    .await;
    tokio::fs::remove_file(&file).await.unwrap();
    let data = &result["result"]["structuredContent"];
    assert_eq!(data["management_status"], "unknown", "{result}");
    assert_eq!(data["instance_status"], "unknown");
    assert_eq!(data["errors"].as_array().unwrap().len(), 4);
    assert_eq!(data["business_connectivity"], "not_tested");
}
