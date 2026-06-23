use super::logging_macro_scan::{
    contains_standalone_identifier, logging_macro_bodies, logs_raw_client_ip,
    logs_raw_oauth_authorization_url, logs_raw_oauth_state, logs_raw_response_headers,
    string_literals_removed,
};

pub(super) fn assert_production_logs_exclude_forbidden_expressions() {
    let sources = [
        (
            "crates/api/src/routes/api.rs",
            include_str!("../../routes/api.rs"),
        ),
        (
            "crates/services/src/agent/service.rs",
            include_str!("../../../../services/src/agent/service.rs"),
        ),
        (
            "crates/services/src/auth/service.rs",
            include_str!("../../../../services/src/auth/service.rs"),
        ),
        (
            "crates/database/src/repositories/oauth_repository.rs",
            include_str!("../../../../database/src/repositories/oauth_repository.rs"),
        ),
        (
            "crates/api/src/routes/oauth.rs",
            include_str!("../../routes/oauth.rs"),
        ),
    ];
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
        for (line, body) in logging_macro_bodies(source) {
            let code = string_literals_removed(&body);
            assert_forbidden_substrings_absent(path, line, &body, &forbidden_substrings);
            assert_forbidden_identifiers_absent(path, line, &body, &code, &forbidden_identifiers);
            assert_no_raw_sensitive_logging(path, line, &body, &code);
        }
    }
}

fn assert_forbidden_substrings_absent(
    path: &str,
    line: usize,
    body: &str,
    forbidden_substrings: &[&str],
) {
    for expression in forbidden_substrings {
        assert!(
            !body.contains(expression),
            "{path}:{line} production logging macro must not contain {expression}: {body}"
        );
    }
}

fn assert_forbidden_identifiers_absent(
    path: &str,
    line: usize,
    body: &str,
    code: &str,
    forbidden_identifiers: &[&str],
) {
    for identifier in forbidden_identifiers {
        assert!(
            !contains_standalone_identifier(code, identifier),
            "{path}:{line} production logging macro must not contain raw identifier {identifier}: {body}"
        );
    }
}

fn assert_no_raw_sensitive_logging(path: &str, line: usize, body: &str, code: &str) {
    assert!(
        !(body.contains("response_headers")
            && (body.contains("{:?}") || body.contains("Response headers"))),
        "{path}:{line} production logging macro must not dump whole response_headers: {body}"
    );
    assert!(
        !logs_raw_response_headers(code),
        "{path}:{line} production logging macro must not dump whole response_headers: {body}"
    );
    assert!(
        !body.contains("/version response body"),
        "{path}:{line} production logging macro must not dump raw /version body structs: {body}"
    );
    assert!(
        !logs_raw_oauth_state(code),
        "{path}:{line} production logging macro must not log raw OAuth state: {body}"
    );
    assert!(
        !logs_raw_oauth_authorization_url(code),
        "{path}:{line} production logging macro must not log raw OAuth authorization URL: {body}"
    );
    assert!(
        !logs_raw_client_ip(code),
        "{path}:{line} production logging macro must not log raw client IP: {body}"
    );
}
