//! pcap-ai-mcp — MCP server wrapping the Pcap AI REST API.
//!
//! Communicates over stdio using the Model Context Protocol (MCP) JSON-RPC 2.0
//! wire format. stdout is reserved exclusively for MCP messages; all
//! diagnostic output goes to stderr.

mod api;
mod mcp;
mod types;

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::mcp::{handle_request, make_error, make_success};
use crate::types::JsonRpcRequest;

// ── Constants ────────────────────────────────────────────────────────────────

const API_BASE: &str = "https://pcapai.com/api/v1/mcp";

// ── Main entry point ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Read the API key from the environment. Now optional.
    let api_key = std::env::var("PCAPAI_API_KEY").ok();

    if api_key.is_none() {
        eprintln!(
            "[pcap-ai-mcp] PCAPAI_API_KEY not set. Operating in Public Mode (Teaser summary)."
        );
    }

    eprintln!(
        "[pcap-ai-mcp] Pcap AI MCP Server v{} initialized. Ready for analysis.",
        env!("CARGO_PKG_VERSION")
    );

    // Build a shared HTTP client with a sensible timeout. The client is reused
    // across all requests to take advantage of connection pooling.
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("pcap-ai-mcp/", env!("CARGO_PKG_VERSION"),))
        .build()
        .context("Failed to build HTTP client")?;

    run_jsonrpc_loop(http_client, api_key, API_BASE).await
}

// ── JSON-RPC stdio event loop ────────────────────────────────────────────────

/// Read newline-delimited JSON-RPC messages from stdin, dispatch each one, and
/// write the response (if any) as a single JSON line to stdout.
async fn run_jsonrpc_loop(
    client: reqwest::Client,
    api_key: Option<String>,
    base_url: &str,
) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }

        eprintln!("[pcap-ai-mcp] <- {}", &line);

        // Parse the incoming JSON-RPC request. On parse failure, send a
        // standard JSON-RPC parse error (-32700).
        let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Err(e) => {
                eprintln!("[pcap-ai-mcp] Parse error: {e}");
                make_error(None, -32700, format!("Parse error: {e}"))
            }
            Ok(req) => {
                let id = req.id.clone();
                match handle_request(&client, api_key.as_deref(), req, base_url).await {
                    None => continue,
                    Some(Ok(result)) => make_success(id, result),
                    Some(Err(e)) => {
                        eprintln!("[pcap-ai-mcp] Handler error: {e:#}");
                        make_error(id, -32603, format!("{e:#}"))
                    }
                }
            }
        };

        let mut json_line = serde_json::to_string(&response)?;
        json_line.push('\n');
        eprintln!("[pcap-ai-mcp] -> {}", json_line.trim_end());
        stdout.write_all(json_line.as_bytes()).await?;
        stdout.flush().await?;
    }

    eprintln!("[pcap-ai-mcp] stdin closed. Shutting down.");
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::poll_until_complete;
    use crate::mcp::handle_request;
    use crate::types::{CheckResponse, UploadResponse};
    use mockito::Server;
    use serde_json::json;

    /// 1. API Contracts (Deserialization)
    #[tokio::test]
    async fn test_deserialize_upload_response() {
        let json_str = r#"{"id": "job_123"}"#;
        let resp: UploadResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(resp.id, "job_123");
    }

    #[tokio::test]
    async fn test_deserialize_check_response() {
        let json_str =
            r#"{"status": "completed", "download_url": "https://example.com/report.pdf"}"#;
        let resp: CheckResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(resp.status, "completed");
        assert_eq!(resp.download_url.unwrap(), "https://example.com/report.pdf");
    }

    /// 2. Input Validation (Unit Tests)
    #[tokio::test]
    async fn test_analyze_local_pcap_invalid_extension() {
        let client = reqwest::Client::new();
        // Create a dummy file that exists but has wrong extension
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("malware.exe");
        std::fs::write(&temp_file, "not a pcap").unwrap();

        let result = crate::api::analyze_local_pcap(
            &client,
            None,
            temp_file.to_str().unwrap(),
            "http://localhost",
        )
        .await;

        // Clean up
        let _ = std::fs::remove_file(temp_file);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported file type"));
    }

    #[tokio::test]
    async fn test_handle_tools_call_missing_arguments() {
        let client = reqwest::Client::new();
        let params = json!({
            "name": "generate_pdf_report",
            "arguments": {} // missing job_id
        });
        let result =
            crate::mcp::handle_tools_call(&client, Some("api_key"), &params, "http://localhost")
                .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing 'job_id' argument"));
    }

    /// 3. Polling Logic & Timeouts (Mocking via mockito)
    #[tokio::test]
    async fn test_poll_until_complete_success() {
        let mut server = Server::new_async().await;
        let client = reqwest::Client::new();

        // First call: processing
        let _m1 = server
            .mock("GET", "/check")
            .match_query(mockito::Matcher::UrlEncoded("id".into(), "job_123".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status": "processing"}"#)
            .create_async()
            .await;

        // Second call: completed
        let _m2 = server
            .mock("GET", "/check")
            .match_query(mockito::Matcher::UrlEncoded("id".into(), "job_123".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status": "completed"}"#)
            .create_async()
            .await;

        let result = poll_until_complete(&client, Some("key"), "job_123", &server.url()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_poll_until_complete_timeout() {
        let mut server = Server::new_async().await;
        let client = reqwest::Client::new();

        // Always returns processing
        let _m = server
            .mock("GET", "/check")
            .match_query(mockito::Matcher::UrlEncoded("id".into(), "job_123".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status": "processing"}"#)
            .expect_at_least(2)
            .create_async()
            .await;

        let result = poll_until_complete(&client, Some("key"), "job_123", &server.url()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Analysis timed out"));
    }

    #[tokio::test]
    async fn test_poll_until_complete_error_500() {
        let mut server = Server::new_async().await;
        let client = reqwest::Client::new();

        let _m = server
            .mock("GET", "/check")
            .match_query(mockito::Matcher::UrlEncoded("id".into(), "job_123".into()))
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let result = poll_until_complete(&client, Some("key"), "job_123", &server.url()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTP 500"));
    }

    /// 4. JSON-RPC Routing (Integration Tests)
    #[tokio::test]
    async fn test_handle_request_method_not_found() {
        let client = reqwest::Client::new();
        let req = JsonRpcRequest {
            id: Some(json!(1)),
            method: "hack_mainframe".to_string(),
            params: json!({}),
        };

        let result = handle_request(&client, None, req, "http://localhost")
            .await
            .unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Method not found"));
    }
}
