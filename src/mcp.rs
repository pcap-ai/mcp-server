use crate::api::{analyze_local_pcap, generate_pdf_tool_logic};
use crate::types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

// ── MCP lifecycle handlers ───────────────────────────────────────────────────

/// Handle the `initialize` handshake.
pub fn handle_initialize(_params: &Value) -> Result<Value> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "serverInfo": {
            "name": "pcap-ai-mcp",
            "version": env!("CARGO_PKG_VERSION")
        },
        "capabilities": {
            "tools": {}
        }
    }))
}

/// Return the list of tools this server exposes.
pub fn handle_tools_list(api_key: Option<&str>) -> Result<Value> {
    let mut tools = vec![];

    if api_key.is_some() {
        tools.push(json!({
            "name": "analyze_local_pcap",
            "description": "Analyzes a PCAP file and returns detailed JSON forensic data. \n\nINSTRUCTIONS FOR AI:\n1. Act as a Senior SOC Analyst. Analyze the returned JSON data and provide a professional summary of the threats to the user.\n2. You are free to structure the forensic breakdown as you see fit based on the JSON payload.\n3. CRITICAL MANDATE: You MUST explicitly offer to generate an official PDF report at the end of your response.\n4. Tell the user that the PDF generation is FREE (credits already consumed).\n5. Example phrasing: 'Would you like me to generate your free official PDF report?'\n5. Wait for the user to say 'yes' before calling the `generate_pdf_report` tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": { "type": "string", "description": "Absolute path to the .pcap file." }
                },
                "required": ["file_path"]
            }
        }));

        tools.push(json!({
            "name": "generate_pdf_report",
            "description": "Generates and retrieves the download link for the official PDF forensic report. \n\nINSTRUCTIONS FOR AI:\n1. Use this tool ONLY if the user explicitly requests a PDF report after a PCAP analysis.\n2. Pass the `job_id` obtained from the previous analysis.\n3. Return the generated URL as a clickable Markdown link.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": { "type": "string", "description": "The unique job ID of the completed analysis." }
                },
                "required": ["job_id"]
            }
        }));
    } else {
        tools.push(json!({
            "name": "analyze_local_pcap",
            "description": "Retrieves a clinical security summary of threats found in a PCAP file. Note: This is an unauthenticated scan. For full data, provide a PCAPAI_API_KEY.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": { "type": "string", "description": "Absolute path to the .pcap file." }
                },
                "required": ["file_path"]
            }
        }));
    }

    Ok(json!({ "tools": tools }))
}

// ── Tool call dispatcher ─────────────────────────────────────────────────────

pub async fn handle_tools_call(
    client: &reqwest::Client,
    api_key: Option<&str>,
    params: &Value,
    base_url: &str,
) -> Result<Value> {
    let name = params["name"]
        .as_str()
        .ok_or_else(|| anyhow!("tools/call: missing 'name' field"))?;

    match name {
        "analyze_local_pcap" => {
            let file_path = params["arguments"]["file_path"]
                .as_str()
                .unwrap_or_default();
            let result = analyze_local_pcap(client, api_key, file_path, base_url).await?;
            Ok(json!({ "content": [{ "type": "text", "text": result }], "isError": false }))
        }
        "generate_pdf_report" => {
            let job_id = params["arguments"]["job_id"]
                .as_str()
                .ok_or_else(|| anyhow!("generate_pdf_report: missing 'job_id' argument"))?;

            let result = generate_pdf_tool_logic(client, api_key, job_id, base_url).await?;
            Ok(json!({ "content": [{ "type": "text", "text": result }], "isError": false }))
        }
        other => Err(anyhow!("Unknown tool: {other}")),
    }
}

// ── Request dispatcher ───────────────────────────────────────────────────────

pub async fn handle_request(
    client: &reqwest::Client,
    api_key: Option<&str>,
    req: JsonRpcRequest,
    base_url: &str,
) -> Option<Result<Value>> {
    if req.id.is_none() && req.method == "notifications/initialized" {
        eprintln!("[pcap-ai-mcp] Received 'initialized' notification.");
        return None;
    }

    let result = match req.method.as_str() {
        "initialize" => handle_initialize(&req.params),
        "tools/list" => handle_tools_list(api_key),
        "tools/call" => handle_tools_call(client, api_key, &req.params, base_url).await,
        "ping" => Ok(json!({})),
        other => Err(anyhow!("Method not found: {other}")),
    };

    Some(result)
}

// ── JSON-RPC helpers ──────────────────────────────────────────────────────────

pub fn make_success(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

pub fn make_error(id: Option<Value>, code: i64, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError { code, message }),
    }
}
