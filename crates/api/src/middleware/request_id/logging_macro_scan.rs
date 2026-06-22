pub(super) fn logging_macro_bodies(source: &str) -> Vec<(usize, String)> {
    let prefixes = [
        "tracing::debug!(",
        "tracing::info!(",
        "tracing::warn!(",
        "tracing::error!(",
        "tracing::trace!(",
        "debug!(",
        "info!(",
        "warn!(",
        "error!(",
        "trace!(",
    ];
    let mut bodies = Vec::new();
    let mut search_start = 0;

    while let Some((start, prefix_len)) = next_logging_macro(source, search_start, &prefixes) {
        let line = source[..start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        if let Some((body, end)) = read_parenthesized_body(source, start + prefix_len) {
            bodies.push((line, body));
            search_start = end;
        } else {
            search_start = start + prefix_len;
        }
    }

    bodies
}

pub(super) fn string_literals_removed(body: &str) -> String {
    let mut result = String::with_capacity(body.len());
    let mut in_string = false;
    let mut string_escape = false;
    for ch in body.chars() {
        if in_string {
            if string_escape {
                string_escape = false;
            } else if ch == '\\' {
                string_escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            result.push(' ');
            continue;
        }

        if ch == '"' {
            in_string = true;
            result.push(' ');
        } else {
            result.push(ch);
        }
    }

    result
}

pub(super) fn logs_raw_oauth_state(code: &str) -> bool {
    code.contains("params.state")
        || code.contains("oauth_state.state")
        || code.contains("state.state")
        || has_positional_argument_named(code, "state")
}

pub(super) fn logs_raw_oauth_authorization_url(code: &str) -> bool {
    [
        "auth_url",
        "oauth_url",
        "authorization_url",
        "redirect_uri",
        "frontend_callback",
    ]
    .iter()
    .any(|identifier| logs_raw_identifier(code, identifier))
        || logs_raw_member_access(code, "params.redirect_uri")
        || logs_raw_member_access(code, "params.frontend_callback")
        || logs_raw_member_access(code, "oauth_state.redirect_uri")
        || logs_raw_member_access(code, "oauth_state.frontend_callback")
        || logs_raw_member_access(code, "state.redirect_uri")
        || logs_raw_member_access(code, "state.frontend_callback")
}

pub(super) fn logs_raw_response_headers(code: &str) -> bool {
    logs_raw_identifier(code, "response_headers")
}

pub(super) fn logs_raw_client_ip(code: &str) -> bool {
    ["client_ip", "ip"]
        .iter()
        .any(|identifier| logs_raw_identifier(code, identifier))
}

pub(super) fn contains_standalone_identifier(body: &str, identifier: &str) -> bool {
    body.match_indices(identifier).any(|(start, _)| {
        let before = start
            .checked_sub(1)
            .and_then(|index| body.as_bytes().get(index))
            .copied();
        let after = body.as_bytes().get(start + identifier.len()).copied();

        !is_identifier_byte(before) && !is_identifier_byte(after)
    })
}

fn next_logging_macro(source: &str, start: usize, prefixes: &[&str]) -> Option<(usize, usize)> {
    prefixes
        .iter()
        .filter_map(|prefix| {
            source[start..]
                .find(prefix)
                .map(|offset| (start + offset, prefix.len()))
        })
        .min_by_key(|(offset, _)| *offset)
}

fn read_parenthesized_body(source: &str, body_start: usize) -> Option<(String, usize)> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut string_escape = false;
    for (offset, ch) in source[body_start..].char_indices() {
        if in_string {
            if string_escape {
                string_escape = false;
            } else if ch == '\\' {
                string_escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((
                        source[body_start..body_start + offset].to_string(),
                        body_start + offset + ch.len_utf8(),
                    ));
                }
            }
            _ => {}
        }
    }

    None
}

fn logs_raw_identifier(code: &str, identifier: &str) -> bool {
    has_positional_argument_named(code, identifier)
        || code.match_indices(identifier).any(|(start, _)| {
            let end = start + identifier.len();
            let previous = previous_non_whitespace_byte(code, start);
            let next = next_non_whitespace_byte(code, end);

            matches!(previous, Some(b'=' | b'?' | b'%'))
                && !matches!(next, Some(b'.'))
                && !is_identifier_byte(next)
        })
}

fn logs_raw_member_access(code: &str, member: &str) -> bool {
    code.match_indices(member).any(|(start, _)| {
        let next = next_non_whitespace_byte(code, start + member.len());
        !matches!(next, Some(b'.')) && !is_identifier_byte(next)
    })
}

fn previous_non_whitespace_byte(code: &str, end: usize) -> Option<u8> {
    code.as_bytes()
        .get(..end)?
        .iter()
        .rev()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
}

fn next_non_whitespace_byte(code: &str, start: usize) -> Option<u8> {
    code.as_bytes()
        .get(start..)?
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
}

fn has_positional_argument_named(code: &str, identifier: &str) -> bool {
    code.split(',').skip(1).any(|argument| {
        let trimmed = argument.trim();
        trimmed == identifier
            || trimmed
                .strip_prefix(identifier)
                .is_some_and(|tail| tail.trim_start().starts_with(')'))
    })
}

fn is_identifier_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|value| value.is_ascii_alphanumeric() || value == b'_')
}
