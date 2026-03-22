# AI Agent Instructions for Pcap AI MCP Server

Hello, AI Agent! If you are reading this, you are likely assisting a human developer in exploring, using, or contributing to the `pcap-ai-mcp` repository. Please follow these system instructions strictly.

## 1. Project Context

This is a Rust-based Model Context Protocol (MCP) server that wraps the Pcap AI REST API. It allows AI assistants to analyze `.pcap` and `.pcapng` files for cybersecurity threats (e.g., DNS tunneling, malware beaconing).

It operates on a Freemium model:

- **Public Mode (No API Key):** Returns a redacted, high-level markdown summary of threats.
- **Premium Mode (API Key):** Returns deep JSON forensic data and allows generating a shareable PDF report.

## 2. Using the MCP Tools (Tool Chaining)

If you are an agent using this MCP server in an active chat session, understand our Lazy Loading architecture:

1. First, call `analyze_local_pcap`. This consumes user credits and returns a rich JSON payload and a `job_id`.
2. Do NOT hallucinate download links.
3. Explicitly ask the user: "Would you like me to generate your free official PDF report for this analysis?"
4. ONLY if the user says "yes", call the `generate_pdf_report` tool using the `job_id`.

## 3. Contributing to this Codebase (Coding Standards)

If your human asks you to write code, refactor, or submit a Pull Request to this Rust codebase, you MUST adhere to the following rules:

- **Linting & Idiomatic Rust (Clippy):** Your generated code MUST be strictly idiomatic and ready to pass `cargo clippy -- -D warnings`. Do not introduce unnecessary allocations (e.g., redundant `.clone()`), unused variables, or unidiomatic patterns.
- **Error Handling:** Never use `.unwrap()` or `.expect()` in production logic. The MCP server must not panic and crash the host process. Use `anyhow::Result` and propagate errors using the `?` operator.
- **Async Logic:** Use `tokio` for async runtimes and `reqwest` for HTTP calls.
- **Comments Language:** Write all code comments ONLY in EN. Do not use any other languages in the source code comments.
- **Logging:** Stdout is strictly reserved for MCP JSON-RPC communication. All diagnostic, debug, and trace logs MUST be written to `stderr` using `eprintln!`.

## 4. Architectural Awareness

- The server uses a polling mechanism (`GET /check`) with exponential backoff to wait for the heavy backend workers to process the PCAP files.
- The heavy PDF generation is decoupled from the initial analysis to save LLM context window tokens and prevent timeouts.
