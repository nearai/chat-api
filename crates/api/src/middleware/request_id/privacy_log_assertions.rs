use super::logging_macro_scan::{
    contains_standalone_identifier, logging_macro_bodies, logs_raw_client_ip, logs_raw_identifier,
    logs_raw_oauth_authorization_url, logs_raw_oauth_state, logs_raw_response_headers,
    string_literals_removed,
};

pub(super) fn assert_production_logs_exclude_forbidden_expressions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(root).expect("workspace crates must be readable") {
        let source_dir = entry.expect("crate directory entry").path().join("src");
        if source_dir.is_dir() {
            collect_sources(&source_dir, &mut sources);
        }
    }

    let forbidden_substrings = ["VersionResponse"];
    let forbidden_identifiers = [
        "response_body",
        "request_body",
        "content_preview",
        "tool_arguments",
        "auth_value",
        "bearer_token",
        "session_token",
        "raw_signature",
        "signature_body",
    ];

    for (path, source) in sources {
        let syntax = syn::parse_file(&source).expect("source must parse");
        let mut collector = ProductionLogs::default();
        syn::visit::Visit::visit_file(&mut collector, &syntax);

        for body in collector.bodies {
            let code: String = string_literals_removed(&body)
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect();
            let path = path.as_str();
            assert_forbidden_substrings_absent(path, &body, &forbidden_substrings);
            assert_forbidden_identifiers_absent(path, &body, &code, &forbidden_identifiers);
            assert_no_raw_sensitive_logging(path, &body, &code);
            assert_no_credentials_or_errors(path, &body, &code);
        }
    }
}

fn assert_forbidden_substrings_absent(path: &str, body: &str, forbidden_substrings: &[&str]) {
    for expression in forbidden_substrings {
        assert!(
            !body.contains(expression),
            "{path} production logging macro must not contain {expression}: {body}"
        );
    }
}

fn assert_forbidden_identifiers_absent(
    path: &str,
    body: &str,
    code: &str,
    forbidden_identifiers: &[&str],
) {
    for identifier in forbidden_identifiers {
        assert!(
            !contains_standalone_identifier(code, identifier),
            "{path} production logging macro must not contain raw identifier {identifier}: {body}"
        );
    }
}

fn assert_no_raw_sensitive_logging(path: &str, body: &str, code: &str) {
    assert!(
        !(body.contains("response_headers")
            && (body.contains("{:?}") || body.contains("Response headers"))),
        "{path} production logging macro must not dump whole response_headers: {body}"
    );
    assert!(
        !logs_raw_response_headers(code),
        "{path} production logging macro must not dump whole response_headers: {body}"
    );
    assert!(
        !body.contains("/version response body"),
        "{path} production logging macro must not dump raw /version body structs: {body}"
    );
    assert!(
        !logs_raw_oauth_state(code),
        "{path} production logging macro must not log raw OAuth state: {body}"
    );
    assert!(
        !logs_raw_oauth_authorization_url(code),
        "{path} production logging macro must not log raw OAuth authorization URL: {body}"
    );
    assert!(
        !logs_raw_client_ip(code),
        "{path} production logging macro must not log raw client IP: {body}"
    );
}

fn collect_sources(directory: &std::path::Path, sources: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(directory).expect("source directory must be readable") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push((
                path.display().to_string(),
                std::fs::read_to_string(path).expect("source must be UTF-8"),
            ));
        }
    }
}

#[derive(Default)]
struct ProductionLogs {
    bodies: Vec<String>,
}

impl<'ast> syn::visit::Visit<'ast> for ProductionLogs {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        // Test fixtures intentionally log secret sentinels to exercise filtering.
        if item.attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string() == "test")
        }) {
            return;
        }

        syn::visit::visit_item_mod(self, item);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .expect("macro name")
            .ident
            .to_string();
        if matches!(
            name.as_str(),
            "info"
                | "warn"
                | "error"
                | "debug"
                | "trace"
                | "println"
                | "eprintln"
                | "dbg"
                | "event"
                | "info_span"
                | "debug_span"
                | "error_span"
                | "warn_span"
                | "trace_span"
                | "span"
        ) {
            let source = format!("{name}!({})", mac.tokens);
            self.bodies.extend(
                logging_macro_bodies(&source)
                    .into_iter()
                    .map(|(_, body)| body),
            );
        }
    }
}

fn assert_no_credentials_or_errors(path: &str, body: &str, code: &str) {
    // This helper returns a boolean; it never formats the headers passed to it.
    let safe_metadata = code.replace(
        "is_streaming_response(&proxy_response.headers)",
        "SAFE_STREAMING_FLAG",
    );
    let code = safe_metadata.as_str();

    for identifier in [
        "dashboard_url",
        "instance_url",
        "instance_token",
        "access_token",
        "refresh_token",
        "token",
        "token_hash",
        "api_key",
        "auth_secret",
        "private_key",
        "password",
        "url",
        "restart_url",
        "stop_url",
        "start_url",
        "manager_url",
        "images_url",
        "base_url",
        "manager_base_url",
        "mgr_url",
        "queue_url",
        "error_body",
        "body",
        "payload",
        "nonce_hex",
        "top_level_keys",
        "item_keys",
        "instance",
        "session",
        "credentials",
        "config",
        "request",
        "response",
        "params",
        "event",
        "instance_data",
        "accumulated_data",
        "headers",
        "response_headers",
        "tokens",
        "body_bytes",
        "text",
        "data",
        "buffer",
        "tags",
    ] {
        assert!(
            !logs_raw_identifier(code, identifier)
                && !body.contains(&format!("{{{identifier}}}"))
                && !body.contains(&format!("{{{identifier}:")),
            "{path} must not log raw {identifier}: {body}"
        );
    }

    for expression in [
        "token.chars()",
        "token_hash.chars()",
        "db_err.message()",
        "db_err.detail()",
        "db_err.hint()",
        "manager.url",
        "mgr.url",
        "config.near.rpc_url",
        "task_message.payload",
        ".uri()",
    ] {
        assert!(
            !code.contains(expression),
            "{path} must not log sensitive expression {expression}: {body}"
        );
    }

    for identifier in [
        "e",
        "err",
        "error",
        "other",
        "unexpected",
        "msg",
        "cleanup_err",
        "cleanup_error",
        "send_err",
        "restore_err",
    ] {
        let safe_calls_removed = code
            .replace(&format!("error_type(&{identifier})"), "SAFE_ERROR_TYPE")
            .replace(
                &format!("std::mem::discriminant(&{identifier})"),
                "SAFE_ERROR_CATEGORY",
            );

        assert!(
            !logs_raw_identifier(&safe_calls_removed, identifier)
                && !body.contains(&format!("{{{identifier}}}"))
                && !body.contains(&format!("{{{identifier}:")),
            "{path} must not format raw error {identifier}: {body}"
        );
    }
}

#[test]
fn source_guard_rejects_credentials_and_nested_errors() {
    for body in [
        r#""instance saved: {}", instance.dashboard_url"#,
        r#"dashboard_url = ?dashboard_url, "instance saved""#,
        r#""token={token}""#,
        r#""prefix {}", token.chars().take(8).collect::<String>()"#,
        r#"error = ?err, "upstream error""#,
        r#""internal error: {err:#}""#,
        r#""database row: {:?}", db_err.detail()"#,
        r#"?instance, "instance created""#,
    ] {
        let code: String = string_literals_removed(body)
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();

        let result = std::panic::catch_unwind(|| {
            assert_no_credentials_or_errors("regression fixture", body, &code);
        });

        assert!(result.is_err(), "source guard must reject: {body}");
    }
}
