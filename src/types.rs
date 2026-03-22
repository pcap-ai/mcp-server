use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Serde types for the Pcap AI REST API ────────────────────────────────────

/// Response body from `POST /upload`.
#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    pub id: String,
}

/// Response body from `GET /check`.
#[derive(Debug, Deserialize)]
pub struct CheckResponse {
    pub status: String,
    pub download_url: Option<String>,
}

/// Response body from `GET /teaser`.
#[derive(Debug, Deserialize)]
pub struct TeaserResponse {
    pub markdown: String,
}

// ── Serde types for the MCP JSON-RPC 2.0 wire protocol ──────────────────────

/// An inbound JSON-RPC 2.0 request or notification.
/// Notifications have no `id` field.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// An outbound JSON-RPC 2.0 response (success or error).
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}
