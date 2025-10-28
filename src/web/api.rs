use std::net::SocketAddr;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hbb_common::{log, tokio, ResultType};
use serde::Serialize;

use crate::peer::{PeerMap, PeerSnapshot};

const DEFAULT_BASE_PORT: u16 = 21_114;
const PORT_OFFSET: u16 = 100;

#[derive(Clone)]
struct ApiState {
    peer_map: PeerMap,
}

#[derive(Serialize)]
struct ConnectionSummary {
    id: String,
    ip: Option<String>,
    seconds_since_last_registration: u64,
}

#[derive(Serialize)]
struct ConnectionDetail {
    id: String,
    guid: Option<String>,
    uuid: Option<String>,
    public_key: Option<String>,
    info: crate::peer::PeerInfo,
    socket_addr: String,
    seconds_since_last_registration: u64,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

pub(crate) async fn spawn_api_server(peer_map: PeerMap) -> ResultType<()> {
    if !api_enabled() {
        log::info!("HTTP API server disabled via HBBS_API_ENABLED");
        return Ok(());
    }
    let addr = resolve_addr()?;
    let state = ApiState { peer_map };
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
    log::info!("HTTP API listening on {}", addr);
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

fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/connections", get(list_connections))
        .route("/api/connections/:id", get(get_connection))
        .route(
            "/api/connections/:id/disconnect",
            post(disconnect_connection),
        )
        .with_state(state)
}

async fn list_connections(State(state): State<ApiState>) -> Json<Vec<ConnectionSummary>> {
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
    State(state): State<ApiState>,
) -> Result<Json<ConnectionDetail>, (StatusCode, Json<ApiError>)> {
    match state.peer_map.snapshot_for(&id).await {
        Some(snapshot) => Ok(Json(ConnectionDetail::from(snapshot))),
        None => Err(not_found(format!("Peer {id} not found"))),
    }
}

async fn disconnect_connection(
    Path(id): Path<String>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if state.peer_map.disconnect(&id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        not_found(format!("Peer {id} not found")).into_response()
    }
}

impl From<PeerSnapshot> for ConnectionSummary {
    fn from(snapshot: PeerSnapshot) -> Self {
        Self {
            id: snapshot.id,
            ip: if snapshot.info.ip.is_empty() {
                None
            } else {
                Some(snapshot.info.ip)
            },
            seconds_since_last_registration: snapshot.seconds_since_last_registration,
        }
    }
}

impl From<PeerSnapshot> for ConnectionDetail {
    fn from(snapshot: PeerSnapshot) -> Self {
        Self {
            id: snapshot.id,
            guid: encode_optional(&snapshot.guid),
            uuid: encode_optional(&snapshot.uuid),
            public_key: encode_optional(&snapshot.pk),
            info: snapshot.info,
            socket_addr: snapshot.socket_addr.to_string(),
            seconds_since_last_registration: snapshot.seconds_since_last_registration,
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
        let map = PeerMap::new().await.expect("peer map");
        map
    }

    #[tokio::test]
    async fn list_returns_active_connections() {
        let map = setup_peer_map().await;
        let peer = map.get_or("alpha").await;
        {
            let mut guard = peer.write().await;
            guard.info.ip = "10.0.0.1".to_owned();
            guard.last_reg_time = std::time::Instant::now();
            guard.guid = vec![1, 2, 3];
            guard.uuid = Bytes::from(vec![4, 5, 6]);
            guard.pk = Bytes::from(vec![7, 8, 9]);
        }
        let app = build_router(ApiState { peer_map: map.clone() });
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
    }

    #[tokio::test]
    async fn detail_returns_not_found_for_unknown_peer() {
        let map = setup_peer_map().await;
        let app = build_router(ApiState { peer_map: map });
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
            guard.last_reg_time = std::time::Instant::now();
        }
        let app = build_router(ApiState { peer_map: map.clone() });
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
