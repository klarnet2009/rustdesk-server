use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Form, Path, State, TypedHeader},
    headers::Cookie,
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration as ChronoDuration, Utc};
use hbb_common::{log, tokio, ResultType};
use ldap3::{drive, LdapConnAsync, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::peer::{PeerMap, PeerSnapshot};

const DEFAULT_BASE_PORT: u16 = 21_114;
const PORT_OFFSET: u16 = 100;
const SESSION_COOKIE: &str = "hbbs_session";
const SESSION_TTL_SECONDS: u64 = 60 * 30;

#[derive(Clone)]
struct AppState {
    peer_map: PeerMap,
    sessions: SessionStore,
    ldap: LdapConfig,
    ui: UiConfig,
}

impl AppState {
    fn new(peer_map: PeerMap) -> Self {
        Self {
            peer_map,
            sessions: SessionStore::new(),
            ldap: LdapConfig::from_env(),
            ui: UiConfig::from_env(),
        }
    }
}

#[derive(Clone)]
struct SessionStore {
    inner: Arc<tokio::sync::RwLock<HashMap<String, Session>>>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    async fn create_session(&self, username: &str, display_name: Option<String>) -> String {
        let session_id = Uuid::new_v4().to_string();
        let mut sessions = self.inner.write().await;
        sessions.insert(
            session_id.clone(),
            Session {
                username: username.to_owned(),
                display_name,
                expires_at: Instant::now() + Duration::from_secs(SESSION_TTL_SECONDS),
            },
        );
        session_id
    }

    async fn get(&self, session_id: &str) -> Option<Session> {
        let mut sessions = self.inner.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            if session.expires_at > Instant::now() {
                session.expires_at = Instant::now() + Duration::from_secs(SESSION_TTL_SECONDS);
                return Some(session.clone());
            }
            sessions.remove(session_id);
        }
        None
    }

    async fn remove(&self, session_id: &str) {
        self.inner.write().await.remove(session_id);
    }
}

#[derive(Clone)]
struct Session {
    username: String,
    display_name: Option<String>,
    expires_at: Instant,
}

impl Session {
    fn display_name(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&self.username)
    }
}

#[derive(Clone)]
struct UiConfig {
    secure_cookies: bool,
}

impl UiConfig {
    fn from_env() -> Self {
        Self {
            secure_cookies: env_flag("HBBS_WEB_SECURE_COOKIE"),
        }
    }
}

#[derive(Clone)]
struct LdapConfig {
    url: String,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    user_base_dn: String,
    user_attribute: String,
    required_group: Option<String>,
    group_attribute: String,
    display_name_attribute: Option<String>,
}
impl LdapConfig {
    fn from_env() -> Self {
        let default_url = "ldap://127.0.0.1:389".to_owned();
        let user_attribute =
            std::env::var("LDAP_USER_ATTRIBUTE").unwrap_or_else(|_| "uid".to_owned());
        let group_attribute =
            std::env::var("LDAP_GROUP_ATTRIBUTE").unwrap_or_else(|_| "memberOf".to_owned());
        let display_name_attribute = env_nonempty("LDAP_DISPLAY_NAME_ATTRIBUTE")
            .or_else(|| env_nonempty("LDAP_FULLNAME_ATTRIBUTE"))
            .or_else(|| env_nonempty("LDAP_NAME_ATTRIBUTE"))
            .or_else(|| Some("displayName".to_owned()));
        Self {
            url: std::env::var("LDAP_URL").unwrap_or(default_url),
            bind_dn: env_nonempty("LDAP_BIND_DN"),
            bind_password: env_nonempty("LDAP_BIND_PASSWORD"),
            user_base_dn: env_nonempty("LDAP_USER_BASE_DN")
                .or_else(|| env_nonempty("LDAP_BASE_DN"))
                .unwrap_or_default(),
            user_attribute,
            required_group: env_nonempty("LDAP_ALLOWED_GROUP"),
            group_attribute,
            display_name_attribute,
        }
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<LdapUser, AuthError> {
        if username.trim().is_empty() || password.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }

        let (conn, mut ldap) = LdapConnAsync::new(&self.url)
            .await
            .map_err(|err| AuthError::Connection(err.to_string()))?;
        drive!(conn);

        if let Some(bind_dn) = &self.bind_dn {
            let response = ldap
                .simple_bind(bind_dn, self.bind_password.as_deref().unwrap_or(""))
                .await
                .map_err(|err| AuthError::Connection(err.to_string()))?;
            response
                .success()
                .map_err(|err| AuthError::Ldap(err.to_string()))?;
        }

        let filter = format!(
            "({}={})",
            self.user_attribute,
            escape_ldap_value(username.trim())
        );
        let attribute_list = self.search_attributes();
        let attr_refs: Vec<&str> = attribute_list.iter().map(|attr| attr.as_str()).collect();
        let (results, _res) = ldap
            .search(&self.user_base_dn, Scope::Subtree, &filter, attr_refs)
            .await
            .map_err(|err| AuthError::Connection(err.to_string()))?;

        let entry = match results.into_iter().next() {
            Some(entry) => SearchEntry::construct(entry),
            None => return Err(AuthError::InvalidCredentials),
        };

        let dn = entry.dn.clone();
        let groups = find_attr(&entry, &self.group_attribute)
            .cloned()
            .unwrap_or_default();
        if let Some(required) = &self.required_group {
            let has_group = groups
                .iter()
                .any(|value| value.eq_ignore_ascii_case(required));
            if !has_group {
                return Err(AuthError::GroupRestriction);
            }
        }

        let display_name = self.extract_display_name(&entry);
        let response = ldap
            .simple_bind(&dn, password)
            .await
            .map_err(|err| AuthError::Connection(err.to_string()))?;
        response
            .success()
            .map_err(|_| AuthError::InvalidCredentials)?;
        let _ = ldap.unbind().await;

        Ok(LdapUser {
            dn,
            username: username.trim().to_owned(),
            display_name,
        })
    }

    fn search_attributes(&self) -> Vec<String> {
        let mut attrs = vec![self.group_attribute.clone(), "cn".to_owned()];
        if let Some(attr) = &self.display_name_attribute {
            if !attrs
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(attr))
            {
                attrs.push(attr.clone());
            }
        } else if !attrs
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case("displayName"))
        {
            attrs.push("displayName".to_owned());
        }
        attrs
    }

    fn extract_display_name(&self, entry: &SearchEntry) -> Option<String> {
        if let Some(attr) = &self.display_name_attribute {
            if let Some(values) = find_attr(entry, attr) {
                if let Some(value) = values.iter().find(|v| !v.trim().is_empty()) {
                    return Some(value.to_owned());
                }
            }
        }
        find_attr(entry, "displayName")
            .and_then(|values| values.iter().find(|v| !v.trim().is_empty()))
            .cloned()
            .or_else(|| {
                find_attr(entry, "cn")
                    .and_then(|values| values.iter().find(|v| !v.trim().is_empty()))
                    .cloned()
            })
    }
}

struct LdapUser {
    dn: String,
    username: String,
    display_name: Option<String>,
}

#[derive(Debug)]
enum AuthError {
    InvalidCredentials,
    GroupRestriction,
    Connection(String),
    Ldap(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "invalid credentials"),
            AuthError::GroupRestriction => write!(f, "missing required LDAP group"),
            AuthError::Connection(err) => write!(f, "LDAP connection error: {err}"),
            AuthError::Ldap(err) => write!(f, "LDAP error: {err}"),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Clone)]
struct DeviceRow {
    id: String,
    device_name: Option<String>,
    username: Option<String>,
    ip: Option<String>,
    last_seen: String,
}

impl From<PeerSnapshot> for DeviceRow {
    fn from(snapshot: PeerSnapshot) -> Self {
        let info = snapshot.info;
        Self {
            id: snapshot.id,
            device_name: optional_field(&info.device_name),
            username: optional_field(&info.username),
            ip: optional_field(&info.ip),
            last_seen: format_last_seen(snapshot.seconds_since_last_registration),
        }
    }
}

#[derive(Serialize)]
struct ConnectionSummary {
    id: String,
    ip: Option<String>,
    device_name: Option<String>,
    username: Option<String>,
    last_seen: String,
}

#[derive(Serialize)]
struct ConnectionDetail {
    id: String,
    guid: Option<String>,
    uuid: Option<String>,
    public_key: Option<String>,
    device_name: Option<String>,
    username: Option<String>,
    ip: Option<String>,
    info: crate::peer::PeerInfo,
    socket_addr: String,
    seconds_since_last_registration: u64,
    last_seen: String,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}
pub(crate) async fn spawn_api_server(peer_map: PeerMap) -> ResultType<()> {
    if !api_enabled() {
        log::info!("HTTP API server disabled via HBBS_API_ENABLED");
        return Ok(());
    }
    let addr = resolve_addr()?;
    let state = AppState::new(peer_map);
    log::info!("HTTP API listening on {}", addr);
    log::info!("LDAP server configured for web login: {}", state.ldap.url);
    if let Some(group) = &state.ldap.required_group {
        log::info!("LDAP access restricted to group: {}", group);
    }
    if state.ui.secure_cookies {
        log::info!("Web UI cookies marked as Secure");
    }
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let shutdown = async {
        if let Err(err) = crate::common::listen_signal().await {
            log::error!("HTTP API shutdown listener error: {}", err);
        }
    };
    let server = axum::serve(listener, router.into_make_service()).with_graceful_shutdown(shutdown);
    tokio::spawn(async move {
        if let Err(err) = server.await {
            log::error!("HTTP API server error: {}", err);
        }
    });
    Ok(())
}

fn api_enabled() -> bool {
    std::env::var("HBBS_API_ENABLED")
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(true)
}

fn resolve_addr() -> Result<SocketAddr, std::net::AddrParseError> {
    if let Ok(addr) = std::env::var("HBBS_API_ADDR") {
        let trimmed = addr.trim();
        if !trimmed.is_empty() {
            return trimmed.parse();
        }
    }
    let port = std::env::var("HBBS_API_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(default_port);
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

fn default_port() -> u16 {
    let base_port = std::env::var("PORT_FOR_API")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_BASE_PORT);
    let port = base_port as u32 + PORT_OFFSET as u32;
    if port > u16::MAX as u32 {
        u16::MAX
    } else {
        port as u16
    }
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/login", get(login_page).post(process_login))
        .route("/dashboard", get(dashboard))
        .route("/logout", post(logout))
        .route("/api/connections", get(list_connections))
        .route("/api/connections/:id", get(get_connection))
        .route(
            "/api/connections/:id/disconnect",
            post(disconnect_connection),
        )
        .with_state(state)
}

async fn root(State(state): State<AppState>, cookies: Option<TypedHeader<Cookie>>) -> Response {
    if extract_session(&state, cookies).await.is_some() {
        Redirect::to("/dashboard").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn login_page(
    State(state): State<AppState>,
    cookies: Option<TypedHeader<Cookie>>,
) -> Response {
    if extract_session(&state, cookies).await.is_some() {
        Redirect::to("/dashboard").into_response()
    } else {
        Html(render_login_page(None, None)).into_response()
    }
}

async fn process_login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let LoginForm { username, password } = form;
    let username_trimmed = username.trim().to_owned();

    if username_trimmed.is_empty() || password.is_empty() {
        return Html(render_login_page(
            Some("Введите имя пользователя и пароль."),
            Some(&username_trimmed),
        ))
        .into_response();
    }

    match state.ldap.authenticate(&username_trimmed, &password).await {
        Ok(user) => {
            log::info!("Web dashboard login succeeded for {}", user.username);
            let session_id = state
                .sessions
                .create_session(&user.username, user.display_name.clone())
                .await;
            let cookie = session_cookie(&session_id, state.ui.secure_cookies);
            let mut response = Redirect::to("/dashboard").into_response();
            if let Ok(header_value) = HeaderValue::from_str(&cookie) {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, header_value);
            }
            response
        }
        Err(error) => {
            log::warn!(
                "Web dashboard login failed for {}: {}",
                username_trimmed,
                error
            );
            Html(render_login_page(
                Some(auth_error_message(&error)),
                Some(&username_trimmed),
            ))
            .into_response()
        }
    }
}

async fn dashboard(
    State(state): State<AppState>,
    cookies: Option<TypedHeader<Cookie>>,
) -> Response {
    match extract_session(&state, cookies).await {
        Some((_id, session)) => {
            let mut devices: Vec<DeviceRow> = state
                .peer_map
                .snapshot_all()
                .await
                .into_iter()
                .map(DeviceRow::from)
                .collect();
            devices.sort_by(|a, b| a.id.cmp(&b.id));
            Html(render_dashboard(&session, &devices)).into_response()
        }
        None => Redirect::to("/login").into_response(),
    }
}

async fn logout(State(state): State<AppState>, cookies: Option<TypedHeader<Cookie>>) -> Response {
    if let Some((session_id, _)) = extract_session(&state, cookies).await {
        state.sessions.remove(&session_id).await;
    }
    let mut response = Redirect::to("/login").into_response();
    let cookie = clear_session_cookie(state.ui.secure_cookies);
    if let Ok(header_value) = HeaderValue::from_str(&cookie) {
        response
            .headers_mut()
            .append(header::SET_COOKIE, header_value);
    }
    response
}

async fn list_connections(State(state): State<AppState>) -> Json<Vec<ConnectionSummary>> {
    let items = state
        .peer_map
        .snapshot_all()
        .await
        .into_iter()
        .map(ConnectionSummary::from)
        .collect();
    Json(items)
}
async fn get_connection(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ConnectionDetail>, (StatusCode, Json<ApiError>)> {
    match state.peer_map.snapshot_for(&id).await {
        Some(snapshot) => Ok(Json(ConnectionDetail::from(snapshot))),
        None => Err(not_found(format!("Peer {id} not found"))),
    }
}

async fn disconnect_connection(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if state.peer_map.disconnect(&id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        not_found(format!("Peer {id} not found")).into_response()
    }
}

impl From<PeerSnapshot> for ConnectionSummary {
    fn from(snapshot: PeerSnapshot) -> Self {
        let info = snapshot.info;
        Self {
            id: snapshot.id,
            ip: optional_field(&info.ip),
            device_name: optional_field(&info.device_name),
            username: optional_field(&info.username),
            last_seen: format_last_seen(snapshot.seconds_since_last_registration),
        }
    }
}

impl From<PeerSnapshot> for ConnectionDetail {
    fn from(snapshot: PeerSnapshot) -> Self {
        let info = snapshot.info;
        let guid = snapshot.guid;
        let uuid = snapshot.uuid;
        let pk = snapshot.pk;
        Self {
            id: snapshot.id,
            guid: encode_optional(&guid),
            uuid: encode_optional(&uuid),
            public_key: encode_optional(&pk),
            device_name: optional_field(&info.device_name),
            username: optional_field(&info.username),
            ip: optional_field(&info.ip),
            info,
            socket_addr: snapshot.socket_addr.to_string(),
            seconds_since_last_registration: snapshot.seconds_since_last_registration,
            last_seen: format_last_seen(snapshot.seconds_since_last_registration),
        }
    }
}

fn encode_optional(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        None
    } else {
        Some(base64::encode(data))
    }
}

fn not_found(message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            error: message.into(),
        }),
    )
}

fn session_cookie(session_id: &str, secure: bool) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        SESSION_COOKIE,
        session_id,
        SESSION_TTL_SECONDS,
        if secure { "; Secure" } else { "" }
    )
}

fn clear_session_cookie(secure: bool) -> String {
    format!(
        "{}=deleted; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        SESSION_COOKIE,
        if secure { "; Secure" } else { "" }
    )
}

fn optional_field(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn format_last_seen(seconds: u64) -> String {
    let secs = seconds.min(i64::MAX as u64) as i64;
    let last_seen = Utc::now() - ChronoDuration::seconds(secs);
    last_seen.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn render_login_page(error: Option<&str>, username: Option<&str>) -> String {
    let error_html =
        error.map(|message| format!("<div class=\"error\">{}</div>", escape_html(message)));
    let username_value = username
        .filter(|value| !value.is_empty())
        .map(escape_html)
        .unwrap_or_default();

    format!(
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>RustDesk Server — Вход</title>\n    <style>\n        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; height: 100vh; }}\n        .card {{ background: rgba(15, 23, 42, 0.85); border-radius: 12px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 20px 45px rgba(15, 23, 42, 0.6); }}\n        h1 {{ margin: 0 0 24px; font-size: 24px; text-align: center; }}\n        label {{ display: block; margin-bottom: 6px; font-weight: 600; letter-spacing: 0.02em; }}\n        input[type=text], input[type=password] {{ width: 100%; padding: 12px 16px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.4); background: rgba(15, 23, 42, 0.6); color: #e2e8f0; font-size: 15px; margin-bottom: 18px; transition: border-color 0.2s ease, box-shadow 0.2s ease; }}\n        input[type=text]:focus, input[type=password]:focus {{ outline: none; border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2); }}\n        button {{ width: 100%; padding: 12px 16px; border: none; border-radius: 8px; background: linear-gradient(90deg, #38bdf8, #22d3ee); color: #0f172a; font-weight: 700; font-size: 15px; cursor: pointer; transition: transform 0.2s ease, box-shadow 0.2s ease; }}\n        button:hover {{ transform: translateY(-1px); box-shadow: 0 12px 24px rgba(56, 189, 248, 0.35); }}\n        .error {{ background: rgba(248, 113, 113, 0.15); border: 1px solid rgba(248, 113, 113, 0.45); color: #fecaca; padding: 12px 16px; border-radius: 8px; margin-bottom: 18px; font-size: 14px; }}\n        .footer {{ margin-top: 18px; font-size: 13px; color: #94a3b8; text-align: center; }}\n    </style>\n</head>\n<body>\n    <div class=\"card\">\n        <h1>Вход в панель RustDesk</h1>\n        {error_section}\n        <form method=\"post\" action=\"/login\">\n            <label for=\"username\">Имя пользователя</label>\n            <input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" value=\"{username}\" required>\n            <label for=\"password\">Пароль</label>\n            <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required>\n            <button type=\"submit\">Войти</button>\n        </form>\n        <div class=\"footer\">Авторизация через корпоративный LDAP</div>\n    </div>\n</body>\n</html>\n",
        error_section = error_html.unwrap_or_default(),
        username = username_value,
    )
}

fn render_dashboard(session: &Session, devices: &[DeviceRow]) -> String {
    let rows = if devices.is_empty() {
        "<tr><td colspan=\"5\" class=\"empty\">Нет активных подключений</td></tr>".to_owned()
    } else {
        devices
            .iter()
            .map(|device| {
                format!(
                    "<tr><td>{id}</td><td>{device}</td><td>{user}</td><td>{ip}</td><td>{last_seen}</td></tr>",
                    id = escape_html(device.id.as_str()),
                    device = escape_html(device.device_name.as_deref().unwrap_or("—")),
                    user = escape_html(device.username.as_deref().unwrap_or("—")),
                    ip = escape_html(device.ip.as_deref().unwrap_or("—")),
                    last_seen = escape_html(device.last_seen.as_str()),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>RustDesk Server — Панель</title>\n    <style>\n        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }}\n        header {{ padding: 24px 32px; background: rgba(15, 23, 42, 0.9); display: flex; align-items: center; justify-content: space-between; box-shadow: 0 12px 24px rgba(15, 23, 42, 0.5); position: sticky; top: 0; z-index: 10; }}\n        header h1 {{ margin: 0; font-size: 22px; }}\n        header .welcome {{ font-size: 15px; color: #94a3b8; margin-right: 24px; }}\n        main {{ padding: 32px; }}\n        table {{ width: 100%; border-collapse: collapse; background: rgba(15, 23, 42, 0.65); border-radius: 12px; overflow: hidden; box-shadow: 0 20px 40px rgba(15, 23, 42, 0.4); }}\n        th, td {{ padding: 16px 18px; text-align: left; border-bottom: 1px solid rgba(148, 163, 184, 0.2); font-size: 15px; }}\n        th {{ text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; color: #94a3b8; background: rgba(15, 23, 42, 0.85); }}\n        tr:hover {{ background: rgba(30, 41, 59, 0.85); }}\n        .empty {{ text-align: center; color: #94a3b8; font-style: italic; }}\n        form {{ margin: 0; }}\n        button.logout {{ border: none; background: rgba(248, 113, 113, 0.2); color: #fecaca; padding: 10px 18px; border-radius: 999px; font-weight: 600; cursor: pointer; transition: background 0.2s ease, transform 0.2s ease; }}\n        button.logout:hover {{ background: rgba(248, 113, 113, 0.35); transform: translateY(-1px); }}\n        @media (max-width: 768px) {{ main {{ padding: 16px; }} table {{ font-size: 13px; }} th, td {{ padding: 12px; }} header {{ flex-direction: column; align-items: flex-start; gap: 12px; }} }}\n    </style>\n</head>\n<body>\n    <header>\n        <h1>Подключенные устройства</h1>\n        <div style=\"display:flex; align-items:center; gap:16px;\">\n            <div class=\"welcome\">{welcome}</div>\n            <form method=\"post\" action=\"/logout\">\n                <button class=\"logout\" type=\"submit\">Выйти</button>\n            </form>\n        </div>\n    </header>\n    <main>\n        <table>\n            <thead>\n                <tr>\n                    <th>ID</th>\n                    <th>Имя ПК</th>\n                    <th>Пользователь</th>\n                    <th>IP адрес</th>\n                    <th>Последнее подключение</th>\n                </tr>\n            </thead>\n            <tbody>\n                {rows}\n            </tbody>\n        </table>\n    </main>\n</body>\n</html>\n",
        welcome = escape_html(&format!(
            "{} ({})",
            session.display_name(),
            session.username
        )),
        rows = rows,
    )
}

async fn extract_session(
    state: &AppState,
    cookies: Option<TypedHeader<Cookie>>,
) -> Option<(String, Session)> {
    let session_id = cookies
        .as_ref()
        .and_then(|TypedHeader(cookie)| cookie.get(SESSION_COOKIE))
        .map(|value| value.to_owned());
    if let Some(id) = session_id {
        if let Some(session) = state.sessions.get(&id).await {
            return Some((id, session));
        }
    }
    None
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn auth_error_message(error: &AuthError) -> &'static str {
    match error {
        AuthError::InvalidCredentials => "Неверное имя пользователя или пароль.",
        AuthError::GroupRestriction => {
            "У вас нет доступа к панели (отсутствует необходимая группа)."
        }
        AuthError::Connection(_) => "Не удалось подключиться к LDAP серверу.",
        AuthError::Ldap(_) => "Ошибка при обращении к LDAP серверу.",
    }
}

fn escape_ldap_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str(r"\5c"),
            '*' => escaped.push_str(r"\2a"),
            '(' => escaped.push_str(r"\28"),
            ')' => escaped.push_str(r"\29"),
            '\0' => escaped.push_str(r"\00"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn find_attr<'a>(entry: &'a SearchEntry, attr: &str) -> Option<&'a Vec<String>> {
    entry.attrs.iter().find_map(|(key, values)| {
        if key.eq_ignore_ascii_case(attr) {
            Some(values)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use hbb_common::bytes::Bytes;
    use hbb_common::tokio;
    use hyper::Body;
    use serde_json::Value;
    use tower::ServiceExt;

    fn temp_db_path(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("./tmp_{name}_{nanos}.sqlite3")
    }

    async fn setup_peer_map() -> PeerMap {
        let path = temp_db_path("api");
        std::env::set_var("DB_URL", &path);
        PeerMap::new().await.expect("peer map")
    }

    #[tokio::test]
    async fn list_returns_active_connections() {
        let map = setup_peer_map().await;
        let peer = map.get_or("alpha").await;
        {
            let mut guard = peer.write().await;
            guard.info.ip = "10.0.0.1".to_owned();
            guard.info.device_name = "Alpha-PC".to_owned();
            guard.info.username = "alice".to_owned();
            guard.last_reg_time = std::time::Instant::now();
            guard.guid = vec![1, 2, 3];
            guard.uuid = Bytes::from(vec![4, 5, 6]);
            guard.pk = Bytes::from(vec![7, 8, 9]);
        }
        let app = build_router(AppState::new(map.clone()));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/connections")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["id"], "alpha");
        assert_eq!(json[0]["ip"], "10.0.0.1");
        assert_eq!(json[0]["device_name"], "Alpha-PC");
        assert_eq!(json[0]["username"], "alice");
    }

    #[tokio::test]
    async fn detail_returns_not_found_for_unknown_peer() {
        let map = setup_peer_map().await;
        let app = build_router(AppState::new(map));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/connections/unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn disconnect_removes_peer_from_memory() {
        let map = setup_peer_map().await;
        let peer = map.get_or("beta").await;
        {
            let mut guard = peer.write().await;
            guard.info.ip = "10.0.0.2".to_owned();
            guard.info.device_name = "Beta-PC".to_owned();
            guard.info.username = "bob".to_owned();
            guard.last_reg_time = std::time::Instant::now();
        }
        let app = build_router(AppState::new(map.clone()));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/connections/beta/disconnect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(map.snapshot_for("beta").await.is_none());
    }
}
