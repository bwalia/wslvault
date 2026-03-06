use axum::Json;
use serde_json::{json, Value};

pub async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "mcp-server"
    }))
}
