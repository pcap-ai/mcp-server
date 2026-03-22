use crate::types::{CheckResponse, TeaserResponse, UploadResponse};
use anyhow::{bail, Context, Result};
use reqwest::multipart;
use std::path::Path;
use std::time::Duration;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of polling attempts before giving up.
#[cfg(not(test))]
const MAX_POLL_ATTEMPTS: u32 = 50;
#[cfg(test)]
const MAX_POLL_ATTEMPTS: u32 = 2;

#[cfg(not(test))]
const INITIAL_BACKOFF_SECS: u64 = 2;
#[cfg(test)]
const INITIAL_BACKOFF_SECS: u64 = 0;

const MAX_BACKOFF_SECS: u64 = 16;

// ── Core analysis pipeline ───────────────────────────────────────────────────

/// Full analysis pipeline:
///   1. Validate file exists and has a .pcap/.pcapng extension.
///   2. Upload via `POST /upload`.
///   3. Poll `GET /check` until completed.
///   4. Download the PDF from `GET /download`.
///   5. Save the PDF to `<original_dir>/<original_stem>_report.pdf`.
///   6. Return the absolute path to the saved PDF.
pub async fn analyze_local_pcap(
    client: &reqwest::Client,
    api_key: Option<&str>,
    file_path: &str,
    base_url: &str,
) -> Result<String> {
    let path = Path::new(file_path);

    // ── Step 1: Validate the input file ──────────────────────────────────────
    if !path.exists() {
        bail!("File not found: {file_path}");
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext != "pcap" && ext != "pcapng" {
        bail!("Unsupported file type '.{ext}'. Only .pcap and .pcapng files are accepted.");
    }

    eprintln!("[pcap-ai-mcp] Uploading: {file_path}");

    // ── Step 2: Upload the file ───────────────────────────────────────────────
    let upload_id = upload_pcap(client, api_key, path, base_url).await?;
    eprintln!("[pcap-ai-mcp] Upload accepted. ID: {upload_id}");

    // ── Step 3: Poll until the analysis is complete ───────────────────────────
    poll_until_complete(client, api_key, &upload_id, base_url).await?;
    eprintln!("[pcap-ai-mcp] Analysis complete.");

    // ── Step 4 & 5: Download or get teaser ─────────────────────
    if let Some(key) = api_key {
        eprintln!("[pcap-ai-mcp] Authenticated session. Getting full response...");
        let response_json = get_response(client, key, &upload_id, base_url).await?;

        Ok(format!(
            "✅ Analysis complete!\n\n**Job ID:** {}\n\n**Analysis JSON:**\n{}\n",
            upload_id, response_json
        ))
    } else {
        eprintln!("[pcap-ai-mcp] Public session. Getting teaser...");
        let teaser = get_teaser(client, &upload_id, base_url).await?;
        // Just return the markdown directly to the caller as requested.
        Ok(teaser)
    }
}

// ── Upload ───────────────────────────────────────────────────────────────────

/// Upload a PCAP file using `POST /upload` with multipart/form-data.
/// Returns the upload `id` to use for polling and download.
async fn upload_pcap(
    client: &reqwest::Client,
    api_key: Option<&str>,
    path: &Path,
    base_url: &str,
) -> Result<String> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open file: {}", path.display()))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("upload.pcap")
        .to_owned();

    // Use tokio-util's ReaderStream to stream the file from disk directly to the API
    // preventing memory exhaustion for large PCAPs.
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = reqwest::Body::wrap_stream(stream);

    let part = multipart::Part::stream(body)
        .file_name(file_name)
        .mime_str("application/octet-stream")?;

    let form = multipart::Form::new().part("file", part);

    let mut request = client.post(format!("{base_url}/upload")).multipart(form);

    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }

    let response = request
        .send()
        .await
        .context("Failed to reach Pcap AI upload endpoint")?;

    let status = response.status();

    if status.is_success() {
        let body: UploadResponse = response
            .json()
            .await
            .context("Upload response was not valid JSON")?;
        return Ok(body.id);
    }

    // Consume the body for the error message before the match.
    let body = response.text().await.unwrap_or_default();

    match status.as_u16() {
        413 => bail!("File is too large (HTTP 413). Pcap AI rejected the upload."),
        429 => bail!("API rate limit exceeded (HTTP 429). Please wait before retrying."),
        401 => {
            if api_key.is_some() {
                bail!("Unauthorized. Please ensure your PCAPAI_API_KEY is valid. Get one at https://pcapai.com/pricing");
            } else {
                bail!("Unauthorized. Public Mode is enabled, but the server rejected the upload without an API key. This may be a server configuration issue.");
            }
        }
        _ => bail!("Upload failed with HTTP {status}: {body}"),
    }
}

// ── Polling ──────────────────────────────────────────────────────────────────

/// Poll `GET /check?id=<upload_id>` with exponential backoff until the
/// analysis status is `"completed"`.
///
/// Backoff schedule: 2 s → 4 s → 8 s → … → 60 s (capped), for up to
/// `MAX_POLL_ATTEMPTS` attempts.
pub async fn poll_until_complete(
    client: &reqwest::Client,
    api_key: Option<&str>,
    upload_id: &str,
    base_url: &str,
) -> Result<()> {
    let mut delay = INITIAL_BACKOFF_SECS;

    for attempt in 1..=MAX_POLL_ATTEMPTS {
        eprintln!("[pcap-ai-mcp] Poll attempt {attempt}/{MAX_POLL_ATTEMPTS} (waiting {delay}s)…");
        tokio::time::sleep(Duration::from_secs(delay)).await;

        let url = if api_key.is_some() {
            format!("{base_url}/check")
        } else {
            format!("{base_url}/guest/check")
        };

        let mut request = client.get(url).query(&[("id", upload_id)]);

        if let Some(key) = api_key {
            request = request.bearer_auth(key);
        }

        let response = request
            .send()
            .await
            .context("Failed to reach Pcap AI check endpoint")?;

        let status = response.status();

        // HTTP 404 means the job hasn't been indexed yet — treat it as
        // "not ready" and keep polling rather than hard-failing.
        if status.as_u16() == 404 {
            eprintln!("[pcap-ai-mcp] Status: not ready (404), will retry…");
        } else if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("Polling failed with HTTP {status}: {body}");
        } else {
            let check: CheckResponse = response
                .json()
                .await
                .context("Check response was not valid JSON")?;

            eprintln!("[pcap-ai-mcp] Status: {}", check.status);

            match check.status.as_str() {
                "done" | "completed" => return Ok(()),
                "failed" | "error" => {
                    bail!("Pcap AI reported analysis failure for id={upload_id}")
                }
                // Any other status (e.g., "processing", "queued") means we keep waiting.
                _ => {}
            }
        }

        // Double the delay, but cap it to avoid extremely long waits.
        delay = (delay * 2).min(MAX_BACKOFF_SECS);
    }

    bail!(
        "Analysis timed out after {MAX_POLL_ATTEMPTS} polling attempts for id={upload_id}. \
         The file may still be processing; check Pcap AI directly."
    )
}

pub async fn get_teaser(
    client: &reqwest::Client,
    upload_id: &str,
    base_url: &str,
) -> Result<String> {
    let response = client
        .get(format!("{base_url}/teaser"))
        .query(&[("id", upload_id)])
        .send()
        .await
        .context("Failed to reach Pcap AI teaser endpoint")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Teaser request failed with HTTP {status}: {body}");
    }

    let teaser: TeaserResponse = response
        .json()
        .await
        .context("Teaser response was not valid JSON")?;

    Ok(teaser.markdown)
}

pub async fn get_response(
    client: &reqwest::Client,
    api_key: &str,
    upload_id: &str,
    base_url: &str,
) -> Result<String> {
    let response = client
        .get(format!("{base_url}/response"))
        .query(&[("id", upload_id)])
        .bearer_auth(api_key)
        .send()
        .await
        .context("Failed to reach Pcap AI response endpoint")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Response request failed with HTTP {status}: {body}");
    }

    Ok(response.text().await?)
}

// ── PDF Generation Tool Logic ───────────────────────────────────────────────

pub async fn generate_pdf_tool_logic(
    client: &reqwest::Client,
    api_key: Option<&str>,
    job_id: &str,
    base_url: &str,
) -> Result<String> {
    let key = api_key.ok_or_else(|| anyhow::anyhow!("This tool requires an API key."))?;

    eprintln!("[pcap-ai-mcp] Triggering PDF generation for job: {job_id}");

    // 1. Trigger the PDF generation
    let trigger_res = client
        .post(format!("{base_url}/generate_report"))
        .query(&[("id", job_id)])
        .bearer_auth(key)
        .send()
        .await
        .context("Failed to reach PDF generation endpoint")?;

    if !trigger_res.status().is_success() {
        let status = trigger_res.status();
        let body = trigger_res.text().await.unwrap_or_default();
        bail!("Failed to start PDF generation (HTTP {status}): {body}");
    }

    // 2. Poll until PDF is ready
    let mut delay = INITIAL_BACKOFF_SECS;
    for attempt in 1..=MAX_POLL_ATTEMPTS {
        eprintln!("[pcap-ai-mcp] PDF poll attempt {attempt}/{MAX_POLL_ATTEMPTS}...");
        tokio::time::sleep(Duration::from_secs(delay)).await;

        let check_res = client
            .get(format!("{base_url}/check_pdf_report"))
            .query(&[("id", job_id)])
            .bearer_auth(key)
            .send()
            .await
            .context("Failed to check PDF status")?;

        if check_res.status().as_u16() == 404 {
            bail!("Job ID not found or expired.");
        } else if !check_res.status().is_success() {
            let status = check_res.status();
            bail!("PDF polling failed with HTTP {status}");
        }

        let check: CheckResponse = check_res.json().await?;
        match check.status.as_str() {
            "ready" | "done" | "completed" => {
                let url = check.download_url.as_deref().unwrap_or("");
                return Ok(format!(
                    "PDF generated successfully. [Download Official PDF Report]({})",
                    url
                ));
            }
            "failed" | "error" => bail!("PDF generation failed on the server."),
            _ => {} // continue polling
        }
        delay = (delay * 2).min(MAX_BACKOFF_SECS);
    }

    bail!("PDF generation timed out.")
}
