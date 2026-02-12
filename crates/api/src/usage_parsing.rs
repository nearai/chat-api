//! Parsing of usage (tokens + model) from OpenAI-style chat completion responses.
//!
//! - **Non-stream**: full JSON body with top-level `usage` and `model` (`parse_usage_from_bytes`).
//! - **Stream (SSE)**:
//!   - **Chat completions**: each `data:` line may have top-level `usage` and `model` (per-chunk usage); use `parse_usage_from_chat_completion_sse_line` and accumulate.
//!   - **Responses**: only the line with `"type": "response.completed"` has `response.usage` and `response.model`; use `parse_usage_from_response_completed_sse_line` and take that single usage.
//!
//! Usage object accepts both OpenAI naming (`prompt_tokens`, `completion_tokens`) and cloud-api (`input_tokens`, `output_tokens`).
//! `total_tokens` is optional (computed from input+output when missing). `model` is required.

use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use services::UserId;

/// Parsed usage from an OpenAI-style response (usage + model). Used for both non-stream and stream.
#[derive(Debug, Clone)]
pub struct ParsedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub model: String,
}

impl ParsedUsage {
    /// Merges another chunk's usage into this one (accumulation). Model is taken from `other`.
    pub fn merge(&mut self, other: &ParsedUsage) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.total_tokens += other.total_tokens;
        self.model = other.model.clone();
    }
}

/// Parses usage from a **non-streaming** chat completions response body.
/// Expects top-level `usage` and `model` (semantics: whole response usage for chat completions).
pub fn parse_chat_completion_usage_from_bytes(bytes: &[u8]) -> Option<ParsedUsage> {
    let root = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    parse_chat_completion_usage_from_json(&root)
}

/// Parses usage from a **non-streaming** /v1/responses body.
/// Expects top-level `usage` and `model` (semantics: whole response usage for /v1/responses).
pub fn parse_response_usage_from_bytes(bytes: &[u8]) -> Option<ParsedUsage> {
    let root = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    parse_response_usage_from_json(&root)
}

/// Chat completions: parse usage from a JSON value with top-level `usage` and `model`.
/// Expects OpenAI-style fields: `prompt_tokens`, `completion_tokens`, optional `total_tokens`.
fn parse_chat_completion_usage_from_json(root: &serde_json::Value) -> Option<ParsedUsage> {
    let usage = root.get("usage")?.as_object()?;
    let input_tokens = usage.get("prompt_tokens").and_then(|v| v.as_u64())?;
    let output_tokens = usage.get("completion_tokens").and_then(|v| v.as_u64())?;
    let total_tokens = usage
        .get("total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(input_tokens + output_tokens);
    let model = root
        .get("model")
        .and_then(|v| v.as_str())
        .map(String::from)?;
    Some(ParsedUsage {
        input_tokens,
        output_tokens,
        total_tokens,
        model,
    })
}

/// /v1/responses: parse usage from a JSON value with top-level `usage` and `model`.
/// Expects cloud-api-style fields: `input_tokens`, `output_tokens`, optional `total_tokens`.
fn parse_response_usage_from_json(root: &serde_json::Value) -> Option<ParsedUsage> {
    let usage = root.get("usage")?.as_object()?;
    let input_tokens = usage.get("input_tokens").and_then(|v| v.as_u64())?;
    let output_tokens = usage.get("output_tokens").and_then(|v| v.as_u64())?;
    let total_tokens = usage
        .get("total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(input_tokens + output_tokens);
    let model = root
        .get("model")
        .and_then(|v| v.as_str())
        .map(String::from)?;
    Some(ParsedUsage {
        input_tokens,
        output_tokens,
        total_tokens,
        model,
    })
}

/// Parses usage from one **chat/completions** SSE data line (`data: {...}`).
/// Expects top-level `usage` and `model` (per-chunk usage). Caller should accumulate across chunks.
/// Returns `None` for `[DONE]`, empty data, or if required fields are missing.
pub fn parse_usage_from_chat_completion_sse_line(line: &str) -> Option<ParsedUsage> {
    let data = line.strip_prefix("data: ")?;
    let data = data.trim_end_matches('\r').trim();
    if data == "[DONE]" || data.is_empty() {
        return None;
    }
    let root = serde_json::from_str::<serde_json::Value>(data).ok()?;
    parse_chat_completion_usage_from_json(&root)
}

/// Parses usage from one **/v1/responses** SSE data line only when `"type": "response.completed"`.
/// Expects `response.usage` and `response.model` (final usage for the whole response). Take once, no accumulation.
/// Returns `None` for other event types, `[DONE]`, empty data, or if required fields are missing.
pub fn parse_usage_from_response_completed_sse_line(line: &str) -> Option<ParsedUsage> {
    let data = line.strip_prefix("data: ")?;
    let data = data.trim_end_matches('\r').trim();
    if data == "[DONE]" || data.is_empty() {
        return None;
    }
    let root = serde_json::from_str::<serde_json::Value>(data).ok()?;
    if root.get("type").and_then(|v| v.as_str()) != Some("response.completed") {
        return None;
    }
    let response = root.get("response")?;
    parse_response_usage_from_json(response)
}

// ---------- Stream wrappers (usage tracking) ----------

/// Stream wrapper for **chat/completions** SSE: parses top-level usage per chunk and accumulates; records on stream end.
pub struct UsageTrackingStreamChatCompletions<S> {
    inner: S,
    buffer: String,
    usage: Option<ParsedUsage>,
    user_usage: Arc<dyn services::user_usage::UserUsageService>,
    pricing_cache: crate::model_pricing::ModelPricingCache,
    user_id: UserId,
}

impl<S> UsageTrackingStreamChatCompletions<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send,
{
    pub fn new(
        inner: S,
        user_usage: Arc<dyn services::user_usage::UserUsageService>,
        pricing_cache: crate::model_pricing::ModelPricingCache,
        user_id: UserId,
    ) -> Self {
        Self {
            inner,
            buffer: String::new(),
            usage: None,
            user_usage,
            pricing_cache,
            user_id,
        }
    }
}

impl<S> Stream for UsageTrackingStreamChatCompletions<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send,
{
    type Item = Result<Bytes, reqwest::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    this.buffer.push_str(text);
                    for line in this.buffer.lines() {
                        if let Some(u) = parse_usage_from_chat_completion_sse_line(line) {
                            match &mut this.usage {
                                Some(acc) => acc.merge(&u),
                                None => this.usage = Some(u),
                            }
                        }
                    }
                    if let Some(last_newline) = this.buffer.rfind('\n') {
                        this.buffer = this.buffer[last_newline + 1..].to_string();
                    }
                }
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(None) => {
                record_usage_on_stream_end(
                    this.usage.take(),
                    this.user_usage.clone(),
                    this.pricing_cache.clone(),
                    this.user_id,
                    "UsageTrackingStreamChatCompletions",
                );
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Stream wrapper for **/v1/responses** SSE: parses only `type: response.completed` and takes that single usage; records on stream end.
pub struct UsageTrackingStreamResponseCompleted<S> {
    inner: S,
    buffer: String,
    usage: Option<ParsedUsage>,
    user_usage: Arc<dyn services::user_usage::UserUsageService>,
    pricing_cache: crate::model_pricing::ModelPricingCache,
    user_id: UserId,
}

impl<S> UsageTrackingStreamResponseCompleted<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send,
{
    pub fn new(
        inner: S,
        user_usage: Arc<dyn services::user_usage::UserUsageService>,
        pricing_cache: crate::model_pricing::ModelPricingCache,
        user_id: UserId,
    ) -> Self {
        Self {
            inner,
            buffer: String::new(),
            usage: None,
            user_usage,
            pricing_cache,
            user_id,
        }
    }
}

impl<S> Stream for UsageTrackingStreamResponseCompleted<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send,
{
    type Item = Result<Bytes, reqwest::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    this.buffer.push_str(text);
                    for line in this.buffer.lines() {
                        if let Some(usage) = parse_usage_from_response_completed_sse_line(line) {
                            this.usage = Some(usage);
                        }
                    }
                    if let Some(last_newline) = this.buffer.rfind('\n') {
                        this.buffer = this.buffer[last_newline + 1..].to_string();
                    }
                }
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(None) => {
                record_usage_on_stream_end(
                    this.usage.take(),
                    this.user_usage.clone(),
                    this.pricing_cache.clone(),
                    this.user_id,
                    "UsageTrackingStreamResponseCompleted",
                );
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

fn record_usage_on_stream_end(
    usage: Option<ParsedUsage>,
    user_usage: Arc<dyn services::user_usage::UserUsageService>,
    pricing_cache: crate::model_pricing::ModelPricingCache,
    user_id: UserId,
    stream_name: &'static str,
) {
    if let Some(usage) = usage {
        tracing::debug!(
            "{}: parsed streaming usage for user_id={}, total_tokens={}, model={}",
            stream_name,
            user_id,
            usage.total_tokens,
            usage.model
        );
        if usage.total_tokens > 0 {
            tokio::spawn(async move {
                let cost_nano_usd = pricing_cache
                    .get_pricing(&usage.model)
                    .await
                    .map(|p| p.cost_nano_usd(usage.input_tokens, usage.output_tokens));
                if let Err(e) = user_usage
                    .record_usage_event(
                        user_id,
                        services::user_usage::METRIC_KEY_LLM_TOKENS,
                        usage.total_tokens as i64,
                        cost_nano_usd,
                        Some(usage.model.as_str()),
                    )
                    .await
                {
                    tracing::warn!(
                        "Failed to record usage from stream for user_id={}: {}",
                        user_id,
                        e
                    );
                }
            });
        }
    } else {
        tracing::debug!(
            "{}: no usage parsed from streaming response for user_id={}",
            stream_name,
            user_id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_chat_completion_usage_from_bytes, parse_response_usage_from_bytes,
        parse_usage_from_chat_completion_sse_line, parse_usage_from_response_completed_sse_line,
    };

    #[test]
    fn response_non_stream_full_fields() {
        let body = br#"{"model":"gpt-test","usage":{"total_tokens":12,"input_tokens":5,"output_tokens":7}}"#;
        let parsed = parse_response_usage_from_bytes(body).expect("should parse");
        assert_eq!(parsed.input_tokens, 5);
        assert_eq!(parsed.output_tokens, 7);
        assert_eq!(parsed.total_tokens, 12);
        assert_eq!(parsed.model, "gpt-test");
    }

    #[test]
    fn non_stream_openai_prompt_completion_tokens() {
        let body = br#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        let parsed = parse_chat_completion_usage_from_bytes(body).expect("should parse");
        assert_eq!(parsed.input_tokens, 10);
        assert_eq!(parsed.output_tokens, 5);
        assert_eq!(parsed.total_tokens, 15);
        assert_eq!(parsed.model, "gpt-4");
    }

    #[test]
    fn sse_chat_completion_chunk_parses() {
        let line = r#"data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"Qwen/Qwen3-VL-30B","choices":[],"usage":{"prompt_tokens":9,"total_tokens":20,"completion_tokens":11}}"#;
        let parsed = parse_usage_from_chat_completion_sse_line(line).expect("should parse");
        assert_eq!(parsed.input_tokens, 9);
        assert_eq!(parsed.output_tokens, 11);
        assert_eq!(parsed.total_tokens, 20);
        assert_eq!(parsed.model, "Qwen/Qwen3-VL-30B");
    }

    #[test]
    fn sse_chat_completion_done_returns_none() {
        assert!(parse_usage_from_chat_completion_sse_line("data: [DONE]").is_none());
    }

    #[test]
    fn sse_response_completed_parses_usage() {
        let line = r#"data: {"type":"response.completed","response":{"model":"gpt-test","usage":{"total_tokens":8,"input_tokens":3,"output_tokens":5}}}"#;
        let parsed = parse_usage_from_response_completed_sse_line(line).expect("should parse");
        assert_eq!(parsed.total_tokens, 8);
        assert_eq!(parsed.model, "gpt-test");
    }

    #[test]
    fn sse_response_completed_other_type_returns_none() {
        let line = r#"data: {"type":"response.delta","response":{"model":"gpt-test"}}"#;
        assert!(parse_usage_from_response_completed_sse_line(line).is_none());
    }

    #[test]
    fn sse_response_completed_missing_type_returns_none() {
        let line = r#"data: {"response":{"model":"gpt-test","usage":{"total_tokens":8,"input_tokens":3,"output_tokens":5}}}"#;
        assert!(parse_usage_from_response_completed_sse_line(line).is_none());
    }
}
