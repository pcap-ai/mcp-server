<div align="center">

# 🦈 pcap-ai-mcp

**An open-source [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that connects AI assistants to [Pcap AI](https://pcapai.com) — a cloud-based security analysis service for `.pcap` and `.pcapng` network captures.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

## What It Does

`pcap-ai-mcp` runs as a background process alongside Claude Desktop (or any MCP-compatible client). When you ask Claude to _"analyze this pcap file"_, the server:

1. **Reads** the local `.pcap` or `.pcapng` file from disk.
2. **Uploads** it to the Pcap AI REST API.
3. **Polls** for completion with exponential backoff.
4. **Downloads** the AI-generated PDF security report.
5. **Saves** the PDF next to the original file (e.g., `capture_report.pdf`).
6. **Tells Claude** the exact path to the report.

---

## Prerequisites

| Requirement                                  | Notes                                                     |
| -------------------------------------------- | --------------------------------------------------------- |
| [Rust](https://rustup.rs) 1.75+              | `rustup show` to check                                    |
| A [Pcap AI](https://pcapai.com) API key      | Optional (needed for full JSON results and PDF downloads) |
| [Claude Desktop](https://claude.ai/download) | Or any MCP-compatible client                              |

---

## Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/pcap-ai/mcp-server.git
cd pcap-ai-mcp

# 2. Build the release binary (optimised, stripped)
cargo build --release

# The binary will be at:
./target/release/pcap-ai-mcp
```

---

## Configuration

### 1. Set Your API Key (Optional)

The server can read your API key from the `PCAPAI_API_KEY` environment variable. If not set, the server operates in **Public Mode**, providing a summary instead of the full analysis.

```bash
export PCAPAI_API_KEY="your-api-key-here"
```

### 2. Wire It Into Claude Desktop

Open (or create) your Claude Desktop configuration file:

| Platform | Path                                                              |
| -------- | ----------------------------------------------------------------- |
| macOS    | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows  | `%APPDATA%\Claude\claude_desktop_config.json`                     |
| Linux    | `~/.config/Claude/claude_desktop_config.json`                     |

Add the following entry under `mcpServers`:

```json
{
  "mcpServers": {
    "pcap-ai": {
      "command": "/absolute/path/to/pcap-ai-mcp",
      "env": {
        "PCAPAI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

> **Tip:** Replace `/absolute/path/to/...` with the actual path on your machine.  
> Run `pwd` inside the cloned repo directory to get it.

### 3. Restart Claude Desktop

After saving the config, fully quit and relaunch Claude Desktop. You should see the 🔌 MCP indicator in the interface.

---

## Usage

Once configured, simply ask Claude:

> _"Analyze the pcap file at `/Users/alice/captures/suspicious_traffic.pcap`"_

Claude will invoke the `analyze_local_pcap` tool automatically and return the location of the generated PDF report.

---

## Available Tool

| Tool                 | Description                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------- |
| `analyze_local_pcap` | Upload a local `.pcap`/`.pcapng` to Pcap AI, wait for analysis, and save the PDF report. |

**Input parameter:**

| Parameter   | Type     | Description                                                                       |
| ----------- | -------- | --------------------------------------------------------------------------------- |
| `file_path` | `string` | **Optional.** Absolute path to the capture file on disk. This path MUST be local. |

---

## Error Handling

The server returns clear error messages for common failure cases:

| Error            | Message                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------- |
| File not found   | `File not found: /path/to/file.pcap`                                                      |
| Wrong extension  | `Only .pcap and .pcapng files are accepted.`                                              |
| File too large   | `File is too large (HTTP 413). Pcap AI rejected the upload.`                              |
| Rate limited     | `API rate limit exceeded (HTTP 429). Please wait before retrying.`                        |
| Unauthorized     | `Unauthorized. Please ensure your PCAPAI_API_KEY is valid. Get one at pcapai.com/pricing` |
| Analysis timeout | `Analysis timed out after 20 polling attempts…`                                           |

---

## Architecture

```
Claude Desktop  ──stdio──►  pcap-ai-mcp  ──HTTPS──►  pcapai.com/api/v1
                  JSON-RPC 2.0              REST API
```

- **Transport**: JSON-RPC 2.0 over `stdio` (MCP spec compliant).
- **HTTP client**: `reqwest` with `rustls` (no OpenSSL dependency).
- **Async runtime**: `tokio`.
- **Diagnostics**: All logs go to `stderr`; `stdout` is reserved for MCP messages.

---

## 🛡️ macOS Security Note (Gatekeeper)

Since this binary is not signed with an Apple Developer certificate, macOS Gatekeeper will block it on the first run, showing a warning that "Apple could not verify the developer." This is standard behavior for open-source software distributed outside the Mac App Store.

To run the binary, you need to remove the "quarantine" flag set by the browser.

### Option 1: Using Terminal (Recommended)

Open your terminal, navigate to the folder where you downloaded the binary, and run the following commands:

```bash
# 1. Allow the binary to be executed
chmod +x pcap-ai-mcp-macos-arm64

# 2. Remove the macOS quarantine flag
xattr -d com.apple.quarantine pcap-ai-mcp-macos-arm64
```

---

## License

MIT — see [LICENSE](LICENSE).
