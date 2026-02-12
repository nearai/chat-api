//! Parsing of usage (tokens + model) from OpenAI-style chat completion responses.
//!
//! Two distinct shapes are handled by separate functions:
//! - **Non-stream**: full JSON body with top-level `usage` and `model`.
//! - **Stream (SSE)**: one `data: {...}` line with `"type": "response.completed"`; payload has `response.usage` and `response.model`.
//!
//! All fields are required; if any is missing, parsing returns `None`.

/// Parsed usage from an OpenAI-style response (usage + model). Used for both non-stream and stream.
#[derive(Debug, Clone)]
pub struct ParsedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub model: String,
}

/// Parses usage from a JSON object that has `usage` (with `total_tokens`, `input_tokens`, `output_tokens`) and `model`.
fn parse_usage_from_value(container: &serde_json::Value) -> Option<ParsedUsage> {
    let usage = container.get("usage")?.as_object()?;
    let total_tokens = usage.get("total_tokens")?.as_u64()?;
    let input_tokens = usage.get("input_tokens")?.as_u64()?;
    let output_tokens = usage.get("output_tokens")?.as_u64()?;
    let model = container
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

/// Parses usage from a **non-streaming** chat completion response body.
/// Expects top-level `usage` (with `total_tokens`, `input_tokens`, `output_tokens`) and `model`.
/// Returns `None` if any required field is missing.
pub fn parse_usage_from_bytes(bytes: &[u8]) -> Option<ParsedUsage> {
    let root = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    parse_usage_from_value(&root)
}

/// Parses usage from one **SSE** data line (`data: {...}`) only when `"type": "response.completed"`.
/// Expects `response.usage` and `response.model`.
/// Returns `None` for `[DONE]`, empty data, missing or non-`response.completed` `type`, or if any required field is missing.
pub fn parse_usage_from_sse_line(line: &str) -> Option<ParsedUsage> {
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
    parse_usage_from_value(response)
}

#[cfg(test)]
mod tests {
    use super::{parse_usage_from_bytes, parse_usage_from_sse_line};

    #[test]
    fn non_stream_full_fields() {
        let body = br#"{"model":"gpt-test","usage":{"total_tokens":12,"input_tokens":5,"output_tokens":7}}"#;
        let parsed = parse_usage_from_bytes(body).expect("should parse");
        assert_eq!(parsed.input_tokens, 5);
        assert_eq!(parsed.output_tokens, 7);
        assert_eq!(parsed.total_tokens, 12);
        assert_eq!(parsed.model, "gpt-test");
    }

    #[test]
    fn non_stream_missing_total_tokens_returns_none() {
        let body = br#"{"model":"gpt-test","usage":{"input_tokens":2,"output_tokens":3}}"#;
        let parsed = parse_usage_from_bytes(body);
        assert!(parsed.is_none());
    }

    #[test]
    fn sse_line_done_returns_none() {
        assert!(parse_usage_from_sse_line("data: [DONE]").is_none());
    }

    #[test]
    fn sse_line_response_completed_parses_usage() {
        let line = r#"data: {"type":"response.completed","response":{"model":"gpt-test","usage":{"total_tokens":8,"input_tokens":3,"output_tokens":5}}}"#;
        let parsed = parse_usage_from_sse_line(line).expect("should parse");
        assert_eq!(parsed.total_tokens, 8);
        assert_eq!(parsed.model, "gpt-test");
    }

    #[test]
    fn sse_line_other_type_returns_none() {
        let line = r#"data: {"type":"response.delta","response":{"model":"gpt-test"}}"#;
        assert!(parse_usage_from_sse_line(line).is_none());
    }

    #[test]
    fn sse_line_missing_type_returns_none() {
        let line = r#"data: {"response":{"model":"gpt-test","usage":{"total_tokens":8,"input_tokens":3,"output_tokens":5}}}"#;
        assert!(parse_usage_from_sse_line(line).is_none());
    }
}
