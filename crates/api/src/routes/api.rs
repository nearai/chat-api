use crate::consts::{
    MAX_DECOMPRESSED_RESPONSE_BODY_SIZE, MAX_REQUEST_BODY_SIZE, MAX_RESPONSE_BODY_SIZE,
};
use crate::middleware::auth::{AuthenticatedApiKey, AuthenticatedUser};
use crate::usage_parsing::{
    parse_chat_completion_usage_from_bytes, parse_response_usage_from_bytes,
    UsageTrackingStreamChatCompletions, UsageTrackingStreamResponseCompleted,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, delete, get, patch, post},
    Json, Router,
};
use bytes::Bytes;
use chrono::{Duration, Utc};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures::stream;
use http::{
    header::{CONTENT_ENCODING, CONTENT_LENGTH},
    HeaderValue,
};
use multer::Multipart;
use near_api::{Account, AccountId, NetworkConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use services::analytics::{ActivityType, RecordActivityRequest};
use services::consts::MODEL_PUBLIC_DEFAULT;
use services::metrics::consts::METRIC_RESPONSE_CREATED;
use services::subscription::ports::SubscriptionError;
use services::user::ports::{BanType, OAuthProvider};
use services::UserId;
use std::io::Read;
use utoipa::ToSchema;

/// Minimum required NEAR balance (1 NEAR in yoctoNEAR: 10^24)
const MIN_NEAR_BALANCE: u128 = 1_000_000_000_000_000_000_000_000;

/// Duration of user ban after NEAR balance check fails (in seconds)
const NEAR_BALANCE_BAN_DURATION_SECS: i64 = 60 * 60;

/// Duration to cache NEAR balance checks in memory (in seconds)
const NEAR_BALANCE_CACHE_TTL_SECS: i64 = 5 * 60;

/// Duration to cache model settings needed by /v1/responses in memory (in seconds)
const MODEL_SETTINGS_CACHE_TTL_SECS: i64 = 60;

/// Duration to cache system configs in memory (in seconds)
const SYSTEM_CONFIGS_CACHE_TTL_SECS: i64 = 60;

/// Fallback defaults for `model: "auto"` routing when no `auto_route` system config is set
pub const AUTO_ROUTE_MODEL: &str = "zai-org/GLM-5-FP8";
pub const AUTO_ROUTE_TEMPERATURE: f64 = 1.0;
pub const AUTO_ROUTE_TOP_P: f64 = 0.95;
pub const AUTO_ROUTE_MAX_TOKENS: u64 = 4096;

/// Error message when a user is banned
pub const USER_BANNED_ERROR_MESSAGE: &str =
    "Access temporarily restricted. Please try again later.";

/// Error message when subscription is required but user has none
pub const SUBSCRIPTION_REQUIRED_ERROR_MESSAGE: &str =
    "Active subscription required. Please subscribe to continue.";

/// OpenAPI tag constants for API documentation
mod openapi_tags {
    pub const PROXY: &str = "Proxy";
}

/// OpenAPI error description constants for API documentation
mod openapi_errors {
    pub const BAD_REQUEST: &str = "Bad request";
    pub const UNAUTHORIZED: &str = "Unauthorized";
    pub const OPENAI_API_ERROR: &str = "OpenAI API error";
}

use openapi_errors::*;
use openapi_tags::*;

/// Create retirement routes for legacy public conversation reads.
///
/// These paths historically supported optional authentication for public shares.
/// Keep that boundary while returning the same migration response as the
/// authenticated stateful routes.
pub fn create_optional_auth_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/v1/conversations/{conversation_id}",
            get(retired_stateful_api),
        )
        .route(
            "/v1/conversations/{conversation_id}/items",
            get(retired_stateful_api),
        )
}

/// Create the retired stateful surfaces without their authentication layer.
///
/// Conversation GET routes intentionally omit their handlers here: they merge
/// with `create_optional_auth_router` at the application boundary so public
/// shared reads retain their historical optional-auth behavior. Every other
/// request is protected by the caller's session-auth layer.
fn create_retired_stateful_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // The nested router's fallback is stored separately by Axum, which lets it
    // catch unknown descendants without conflicting with `{conversation_id}`.
    let conversations_router = Router::new()
        .route(
            "/",
            post(retired_stateful_api)
                .get(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}",
            post(retired_stateful_api)
                .delete(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}/shares",
            post(retired_stateful_api)
                .get(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}/shares/{share_id}",
            delete(retired_stateful_api).fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}/items",
            post(retired_stateful_api).fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}/pin",
            post(retired_stateful_api)
                .delete(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}/archive",
            post(retired_stateful_api)
                .delete(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{conversation_id}/clone",
            post(retired_stateful_api).fallback(retired_stateful_api),
        )
        .fallback(retired_stateful_api);

    let share_groups_router = Router::new()
        .route(
            "/",
            post(retired_stateful_api)
                .get(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{group_id}",
            patch(retired_stateful_api)
                .delete(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .fallback(retired_stateful_api);

    let files_router = Router::new()
        .route(
            "/",
            post(retired_stateful_api)
                .get(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{file_id}",
            get(retired_stateful_api)
                .delete(retired_stateful_api)
                .fallback(retired_stateful_api),
        )
        .route(
            "/{file_id}/content",
            get(retired_stateful_api).fallback(retired_stateful_api),
        )
        .fallback(retired_stateful_api);

    let shared_with_me_router = Router::new()
        .route(
            "/",
            get(retired_stateful_api).fallback(retired_stateful_api),
        )
        .fallback(retired_stateful_api);

    Router::new()
        .nest("/v1/conversations", conversations_router)
        .route("/v1/conversations/", any(retired_stateful_api))
        .nest("/v1/share-groups", share_groups_router)
        .route("/v1/share-groups/", any(retired_stateful_api))
        .nest("/v1/files", files_router)
        .route("/v1/files/", any(retired_stateful_api))
        .nest("/v1/shared-with-me", shared_with_me_router)
        .route("/v1/shared-with-me/", any(retired_stateful_api))
}

/// Create the unified API router with all v1 proxy and API routes.
///
/// Route groups and their middleware:
/// - Chat completions and images: dual auth + subscription + rate limited
/// - Responses: dual auth + subscription + rate limited, always no-store
/// - Model list, models, signature: dual auth only (not rate limited)
/// - Retired conversations, share groups, files: their existing auth boundary
pub fn create_api_router(
    rate_limit_state: crate::middleware::RateLimitState,
    dual_auth_state: crate::middleware::DualAuthState,
    auth_state: crate::middleware::AuthState,
    subscription_state: crate::middleware::SubscriptionState,
) -> Router<crate::state::AppState> {
    // Dual auth + subscription + rate limited: chat completions and images
    let llm_proxy_router = Router::new()
        .route("/v1/chat/completions", post(proxy_chat_completions))
        .route("/v1/images/generations", post(proxy_image_generations))
        .route("/v1/images/edits", post(proxy_image_edits))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state.clone(),
            crate::middleware::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            subscription_state.clone(),
            crate::middleware::subscription_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            dual_auth_state.clone(),
            crate::middleware::dual_auth_middleware,
        ));

    // Keep every Responses result out of shared caches, including failures
    // returned by authentication, subscription, or rate-limit middleware.
    let responses_proxy_router = Router::new()
        .route("/v1/responses", post(proxy_responses))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state,
            crate::middleware::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            subscription_state,
            crate::middleware::subscription_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            dual_auth_state.clone(),
            crate::middleware::dual_auth_middleware,
        ))
        .layer(axum::middleware::map_response(force_no_store_response));

    // Dual auth only (not rate limited): model list, models, signature
    let models_proxy_router = Router::new()
        .route("/v1/model/list", get(proxy_model_list))
        .route("/v1/models", get(proxy_models))
        .route("/v1/signature/{chat_id}", get(proxy_signature))
        .layer(axum::middleware::from_fn_with_state(
            dual_auth_state.clone(),
            crate::middleware::dual_auth_middleware,
        ));

    // Dual auth only: MCP passthrough for tool calls (separate from llm_proxy)
    let mcp_router =
        Router::new()
            .route("/mcp", post(proxy_mcp))
            .layer(axum::middleware::from_fn_with_state(
                dual_auth_state,
                crate::middleware::dual_auth_middleware,
            ));

    // Retired stateful routes retain their existing session-auth boundary. The
    // handlers deliberately do not access legacy services, the database, or
    // Cloud API; they only return a consistent migration response.
    let session_auth_routes = create_retired_stateful_router::<crate::state::AppState>().layer(
        axum::middleware::from_fn_with_state(auth_state, crate::middleware::auth_middleware),
    );

    Router::new()
        .merge(llm_proxy_router)
        .merge(responses_proxy_router)
        .merge(models_proxy_router)
        .merge(mcp_router)
        .merge(session_auth_routes)
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

/// Message returned by every retired stateful API route.
///
/// The stateful surfaces are intentionally still registered so clients receive
/// a clear migration signal rather than a proxy error from Cloud API.
pub const STATEFUL_API_RETIRED_MESSAGE: &str =
    "This stateful API has been retired. Use /v1/responses with store: false and include all context in each request.";

fn with_no_store_cache_control(mut response: Response) -> Response {
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

/// Accept only the HTTP no-op `identity` content coding. The request body is
/// inspected before it is normalized, so accepting a compressed representation
/// would let stateful fields evade the local stateless validation.
fn has_only_identity_content_encoding(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_ENCODING).iter().all(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
        })
    })
}

/// Apply no-store to every `/v1/responses` result, including middleware and
/// extractor rejections that do not enter `proxy_responses` itself.
async fn force_no_store_response(response: Response) -> Response {
    with_no_store_cache_control(response)
}

/// Return the stable migration response for legacy conversation, file, and
/// sharing routes. The route remains behind its existing authentication layer.
async fn retired_stateful_api() -> Response {
    with_no_store_cache_control(
        (
            StatusCode::GONE,
            Json(ErrorResponse {
                error: STATEFUL_API_RETIRED_MESSAGE.to_string(),
            }),
        )
            .into_response(),
    )
}

fn stateless_responses_bad_request(error: impl Into<String>) -> Response {
    with_no_store_cache_control(
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.into(),
            }),
        )
            .into_response(),
    )
}

/// Reject response fields that require Cloud API to retain conversation, file,
/// or response state. Keep the messages aligned with Cloud API so callers get
/// a stable 400 locally instead of a version-dependent upstream error.
fn validate_stateless_response_body(body: &serde_json::Value) -> Result<(), &'static str> {
    let request = body
        .as_object()
        .ok_or("The stateless Responses API requires a JSON object body.")?;

    if request.get("store").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err("The Responses API only supports store: false.");
    }

    if request
        .get("conversation")
        .is_some_and(|value| !value.is_null())
    {
        return Err("The stateless Responses API does not support conversation.");
    }

    if request
        .get("previous_response_id")
        .is_some_and(|value| !value.is_null())
    {
        return Err("The stateless Responses API does not support previous_response_id.");
    }

    if request
        .get("background")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Err("The stateless Responses API does not support background.");
    }

    if let Some(input_items) = request.get("input").and_then(serde_json::Value::as_array) {
        for item in input_items {
            match item.get("type").and_then(serde_json::Value::as_str) {
                Some("mcp_approval_response") => {
                    return Err(
                        "The stateless Responses API does not support MCP approval continuation.",
                    );
                }
                Some("function_call_output") => {
                    return Err(
                        "The stateless Responses API does not support function continuation.",
                    );
                }
                _ => {}
            }

            if item
                .get("content")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|parts| {
                    parts.iter().any(|part| {
                        part.get("type").and_then(serde_json::Value::as_str) == Some("input_file")
                    })
                })
            {
                return Err("The stateless Responses API does not support input_file.");
            }
        }
    }

    if let Some(tools) = request.get("tools").and_then(serde_json::Value::as_array) {
        for tool in tools {
            match tool.get("type").and_then(serde_json::Value::as_str) {
                Some("file_search") => {
                    return Err("The stateless Responses API does not support file_search.");
                }
                Some("function") => {
                    return Err(
                        "The stateless Responses API does not support function tools because they require continuation.",
                    );
                }
                Some("code_interpreter") => {
                    return Err(
                        "The stateless Responses API does not support code_interpreter because it requires continuation.",
                    );
                }
                Some("computer") => {
                    return Err(
                        "The stateless Responses API does not support computer because it requires continuation.",
                    );
                }
                Some("mcp")
                    if tool
                        .get("require_approval")
                        .and_then(serde_json::Value::as_str)
                        != Some("never") =>
                {
                    return Err(
                        "The stateless Responses API does not support MCP tools that require approval.",
                    );
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Normalize a valid JSON request at the proxy boundary. This makes the
/// no-store contract explicit even when a client omits `store`.
fn normalize_stateless_response_body(body: &mut serde_json::Value) -> Result<(), &'static str> {
    let request = body
        .as_object_mut()
        .ok_or("The stateless Responses API requires a JSON object body.")?;
    request.insert("store".to_string(), serde_json::Value::Bool(false));

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InvalidProxyPathSegment;

fn validate_proxy_path_segment(value: &str) -> Result<(), InvalidProxyPathSegment> {
    validate_proxy_path_segment_variant(value)?;

    let decoded = urlencoding::decode(value).map_err(|_| InvalidProxyPathSegment)?;
    if decoded.contains('%') {
        return Err(InvalidProxyPathSegment);
    }
    validate_proxy_path_segment_variant(&decoded)?;

    Ok(())
}

fn validate_proxy_path_segment_variant(value: &str) -> Result<(), InvalidProxyPathSegment> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
    {
        return Err(InvalidProxyPathSegment);
    }

    Ok(())
}

fn invalid_proxy_path_segment_response(field_name: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: format!("Invalid {field_name}: unsafe path segment"),
        }),
    )
        .into_response()
}

/// Proxy a single, stateless Responses request to Cloud API.
#[utoipa::path(
    post,
    path = "/v1/responses",
    tag = PROXY,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Response created successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned or model not available", body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_responses(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_responses: POST /v1/responses for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Check if user is currently banned before proceeding
    ensure_user_not_banned(&state, &user).await?;

    // Trigger an asynchronous NEAR balance check. This does NOT block the current request:
    // if the balance is too low, a ban will be created and will affect subsequent requests.
    spawn_near_balance_check(&state, &user);

    // Extract body bytes
    let body_bytes = extract_body_bytes(request).await?;

    // Parsed JSON body. A non-empty request has to be an uncompressed JSON
    // object so no stateful field can bypass local validation as opaque bytes.
    let mut body_json: Option<serde_json::Value> = None;
    // Optional system prompt resolved from model settings
    let mut model_system_prompt: Option<String> = None;
    // Model id from request body, if present
    let mut model_id_from_body: Option<String> = None;
    // Whether model settings came from cache
    let mut model_settings_cache_hit: Option<bool> = None;

    tracing::debug!(
        "Extracted request body: {} bytes for POST /v1/responses",
        body_bytes.len()
    );

    if !body_bytes.is_empty() {
        tracing::debug!(
            "Request body content redacted; body_size={} bytes",
            body_bytes.len()
        );

        if !has_only_identity_content_encoding(&headers) {
            return Err(stateless_responses_bad_request(
                "The stateless Responses API requires an uncompressed JSON object body.",
            ));
        }

        let body = serde_json::from_slice::<serde_json::Value>(&body_bytes).map_err(|e| {
            tracing::debug!(
                "Failed to parse /responses request body as JSON for user_id={}: {}",
                user.user_id,
                e
            );
            stateless_responses_bad_request(
                "The stateless Responses API requires an uncompressed JSON object body.",
            )
        })?;

        if !body.is_object() {
            return Err(stateless_responses_bad_request(
                "The stateless Responses API requires a JSON object body.",
            ));
        }

        body_json = Some(body);
    }

    // Reject every request feature that would make Cloud API retain state
    // before it can be forwarded. This avoids exposing version-dependent
    // upstream validation and makes the stateless contract explicit here.
    if let Some(ref body) = body_json {
        if let Err(error) = validate_stateless_response_body(body) {
            return Err(stateless_responses_bad_request(error));
        }
    }

    // Check model access based on subscription plan
    if let Some(ref body) = body_json {
        if let Some(model_id) = body.get("model").and_then(|v| v.as_str()) {
            enforce_model_access(&state, &user, model_id).await?;
        }
    }

    // Enforce model-level visibility based on settings if a model is specified
    if let Some(ref body) = body_json {
        if let Some(model_id) = body.get("model").and_then(|v| v.as_str()) {
            model_id_from_body = Some(model_id.to_string());

            // Use shared helper function to get model settings with caching
            match get_model_settings_with_cache(&state, model_id, user.user_id).await {
                Ok((prompt, cache_hit)) => {
                    model_system_prompt = prompt;
                    model_settings_cache_hit = cache_hit;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // Modify the request only for the existing model-level system prompt and
    // to make its no-store contract explicit. Do not inject author metadata:
    // it previously forced `store: true` and depended on conversation state.
    let modified_body_bytes = if let Some(mut body) = body_json {
        normalize_stateless_response_body(&mut body).map_err(stateless_responses_bad_request)?;

        // Inject model-level system prompt if present
        if let Some(system_prompt) = model_system_prompt.as_ref() {
            let new_instructions = match body.get("instructions").and_then(|v| v.as_str()) {
                Some(existing) if !existing.is_empty() => {
                    format!("{system_prompt}\n\n{existing}")
                }
                _ => system_prompt.clone(),
            };
            body["instructions"] = serde_json::Value::String(new_instructions);
        }

        match serde_json::to_vec(&body) {
            Ok(serialized) => Bytes::from(serialized),
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to modify request body".to_string(),
                    }),
                )
                    .into_response())
            }
        }
    } else {
        body_bytes
    };

    // Set content-length header
    // usize::to_string() only produces ASCII digits, which are always valid for HeaderValue
    let content_length = HeaderValue::from_str(&modified_body_bytes.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    tracing::debug!(
        "Forwarding POST /v1/responses to OpenAI for user_id={}",
        user.user_id
    );

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            "responses",
            headers.clone(),
            Some(modified_body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for POST /v1/responses (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from OpenAI: status={} for POST /v1/responses (user_id={})",
        proxy_response.status,
        user.user_id
    );

    // Record metrics for successful responses
    if (200..300).contains(&proxy_response.status) {
        state
            .metrics_service
            .record_count(METRIC_RESPONSE_CREATED, 1, &[]);

        // Record analytics in database
        if let Err(e) = state
            .analytics_service
            .record_activity(RecordActivityRequest {
                user_id: user.user_id,
                activity_type: ActivityType::Response,
                auth_method: None,
                metadata: model_id_from_body.as_ref().map(|model_id| {
                    let mut meta = serde_json::Map::new();
                    meta.insert(
                        "model_id".to_string(),
                        serde_json::Value::String(model_id.clone()),
                    );
                    if let Some(hit) = model_settings_cache_hit {
                        meta.insert(
                            "model_settings_cache_hit".to_string(),
                            serde_json::Value::Bool(hit),
                        );
                    }
                    serde_json::Value::Object(meta)
                }),
            })
            .await
        {
            tracing::warn!("Failed to record analytics for response creation: {}", e);
        }
    }

    // Wrap the response stream: record usage (token/cost)
    tracing::debug!(
        "proxy_responses: upstream status={}, content_type={:?}, is_streaming={}",
        proxy_response.status,
        proxy_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        is_streaming_response(&proxy_response.headers),
    );

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else if is_streaming_response(&proxy_response.headers) {
        let mut usage_stream = UsageTrackingStreamResponseCompleted::new(
            proxy_response.body,
            state.user_usage_service.clone(),
            state.subscription_service.clone(),
            state.model_pricing_cache.clone(),
            user.user_id,
        );
        if let Some(Extension(api_key)) = &api_key_ext {
            usage_stream = usage_stream
                .with_agent_ids(api_key.api_key_info.instance_id, api_key.api_key_info.id);
        }
        Body::from_stream(usage_stream)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Upstream stream error for user_id={}: {}", user.user_id, e);
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        // For non-streaming responses, decompress encoded payload before parsing usage.
        let usage_bytes = decompress_if_encoded(bytes.clone(), &proxy_response.headers)
            .unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to decompress non-stream response for user_id={}: {}",
                    user.user_id,
                    e
                );
                bytes.clone()
            });
        // Fire-and-forget: record usage in background to avoid blocking on pricing fetch + DB write
        let state_clone = state.clone();
        let user_id = user.user_id;
        let usage_bytes_clone = usage_bytes.clone();
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_response_usage_from_body(&state_clone, user_id, &usage_bytes_clone, api_key_opt)
                .await;
        });
        Body::from(bytes)
    };

    let response =
        build_response(proxy_response.status, proxy_response.headers, response_body).await?;
    Ok(with_no_store_cache_control(response))
}

/// Ensure that if the authenticated user logged in with NEAR (has a NEAR-linked account),
/// their on-chain balance is at least 1 NEAR before allowing expensive /v1/responses calls.
/// Paid users skip this check.
async fn ensure_near_balance_for_near_user(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
) -> Result<(), Response> {
    // Fetch user profile to inspect linked OAuth accounts
    let profile = state
        .user_service
        .get_user_profile(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get user profile for NEAR balance check (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to verify NEAR balance".to_string(),
                }),
            )
                .into_response()
        })?;

    // Find a linked NEAR account (provider_user_id stores the NEAR account ID)
    let near_account_id = profile
        .linked_accounts
        .iter()
        .find(|acc| acc.provider == OAuthProvider::Near)
        .map(|acc| acc.provider_user_id.clone());

    // If the user does not have a NEAR-linked account, skip the balance check
    let Some(account_id_str) = near_account_id else {
        return Ok(());
    };

    // Skip NEAR balance check for paid users (only after we know user has NEAR account)
    match state
        .subscription_service
        .has_paid_subscription(user.user_id)
        .await
    {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(
                "Failed to check paid subscription for user_id={}, proceeding with NEAR balance check: {}",
                user.user_id,
                e
            );
        }
    }

    tracing::info!(
        "Checking NEAR balance for user_id={} account_id={} (with cache)",
        user.user_id,
        account_id_str
    );

    // First, check in-memory cache to avoid frequent RPC calls
    {
        let cache = state.near_balance_cache.read().await;
        if let Some(entry) = cache.get(&account_id_str) {
            let age = Utc::now().signed_duration_since(entry.last_checked_at);
            if age.num_seconds() >= 0 && age.num_seconds() < NEAR_BALANCE_CACHE_TTL_SECS {
                tracing::debug!(
                    "Using cached NEAR balance for account '{}' (age={}s, balance={} yoctoNEAR)",
                    account_id_str,
                    age.num_seconds(),
                    entry.balance
                );

                // We only treat cached values as authoritative if they meet the minimum balance.
                // Low cached balances are ignored here so we can re-check on-chain after bans expire.
                if entry.balance >= MIN_NEAR_BALANCE {
                    return Ok(());
                }
            }
        }
    }

    // Parse NEAR account ID
    let account_id: AccountId = account_id_str.parse().map_err(|e| {
        tracing::error!(
            "Invalid NEAR account id '{}' for user_id={}: {}",
            account_id_str,
            user.user_id,
            e
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Invalid NEAR account id for user".to_string(),
            }),
        )
            .into_response()
    })?;

    let account = Account(account_id);

    let network_config = NetworkConfig::from_rpc_url("near", state.near_rpc_url.clone());

    let info = account
        .view()
        .fetch_from(&network_config)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch NEAR account info for account_id='{}': {}",
                account_id_str,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to fetch NEAR account info".to_string(),
                }),
            )
                .into_response()
        })?;

    let balance = info.data.amount.as_yoctonear();

    tracing::info!(
        "NEAR balance for account '{}' (user_id={}): {} yoctoNEAR",
        account_id_str,
        user.user_id,
        balance
    );

    if balance < MIN_NEAR_BALANCE {
        tracing::warn!(
            "NEAR balance too low for user_id={} account_id={} balance={} (required >= {})",
            user.user_id,
            account_id_str,
            balance,
            MIN_NEAR_BALANCE
        );

        // Ban user for a fixed duration when NEAR balance check fails
        if let Err(e) = state
            .user_service
            .ban_user_for_duration(
                user.user_id,
                BanType::NearBalanceLow,
                Some(format!(
                    "NEAR balance {} is below required minimum {}",
                    balance, MIN_NEAR_BALANCE
                )),
                Duration::seconds(NEAR_BALANCE_BAN_DURATION_SECS),
            )
            .await
        {
            tracing::error!(
                "Failed to create NEAR balance ban for user_id={}: {}",
                user.user_id,
                e
            );
        }

        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: USER_BANNED_ERROR_MESSAGE.to_string(),
            }),
        )
            .into_response())
    } else {
        let mut cache = state.near_balance_cache.write().await;
        cache.insert(
            account_id_str.clone(),
            crate::state::NearBalanceCacheEntry {
                last_checked_at: Utc::now(),
                balance,
            },
        );
        Ok(())
    }
}

/// Ensure the authenticated user is not currently banned
async fn ensure_user_not_banned(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
) -> Result<(), Response> {
    let is_banned = state
        .user_service
        .has_active_ban(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to check user ban status for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to verify user ban status".to_string(),
                }),
            )
                .into_response()
        })?;

    if is_banned {
        tracing::warn!("Blocked request for banned user_id={}", user.user_id);
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: USER_BANNED_ERROR_MESSAGE.to_string(),
            }),
        )
            .into_response());
    }

    Ok(())
}

/// Spawn an asynchronous NEAR balance check task.
///
/// This function is fire-and-forget: it does not affect the current request's outcome.
/// If the user's NEAR balance is found to be insufficient, a ban will be created and
/// subsequent requests will be blocked by `ensure_user_not_banned`.
fn spawn_near_balance_check(state: &crate::state::AppState, user: &AuthenticatedUser) {
    let state = state.clone();
    let user = user.clone();

    tokio::spawn(async move {
        if let Err(resp) = ensure_near_balance_for_near_user(&state, &user).await {
            tracing::debug!(
                "Asynchronous NEAR balance check completed with status={} for user_id={}",
                resp.status(),
                user.user_id
            );
        }
    });
}

/// Proxy model list endpoint - returns list of available models with public flags
#[utoipa::path(
    get,
    path = "/v1/model/list",
    tag = PROXY,
    responses(
        (status = 200, description = "Model list retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_model_list(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_model_list: GET /v1/model/list for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(Method::GET, "model/list", headers.clone(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for GET /v1/model/list (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from OpenAI: status={} for GET /v1/model/list (user_id={})",
        proxy_response.status,
        user.user_id
    );

    // If upstream returned non-success, just proxy as-is
    if !(200..300).contains(&proxy_response.status) {
        return build_response(
            proxy_response.status,
            proxy_response.headers,
            Body::from_stream(proxy_response.body),
        )
        .await;
    }

    // Buffer body into bytes
    let proxy_body = Body::from_stream(proxy_response.body);
    let body_bytes: Bytes = to_bytes(proxy_body, MAX_RESPONSE_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to read model list response body for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to read response body: {e}"),
                }),
            )
                .into_response()
        })?;

    let decompressed_body = decompress_if_encoded(body_bytes.clone(), &proxy_response.headers)
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to decompress model list response body for user_id={}: {}",
                user.user_id,
                e
            );
            body_bytes.clone()
        });

    // Try to parse JSON
    let mut body_json: serde_json::Value = match serde_json::from_slice(&decompressed_body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Failed to parse model list JSON for user_id={}: {}, returning original body",
                user.user_id,
                e
            );
            return build_response(
                proxy_response.status,
                proxy_response.headers,
                Body::from(body_bytes),
            )
            .await;
        }
    };

    let models_opt = body_json.get_mut("models").and_then(|v| v.as_array_mut());

    let Some(models_array) = models_opt else {
        tracing::debug!("No 'models' array found in model list response, returning original body");
        return Response::builder()
            .status(StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::OK))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&body_json).unwrap_or_else(|_| body_bytes.to_vec()),
            ))
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to build response: {e}"),
                    }),
                )
                    .into_response()
            });
    };

    // Collect all model IDs for batch settings lookup
    let mut model_ids: Vec<String> = Vec::new();
    for model in models_array.iter() {
        if let Some(model_id) = model.get("modelId").and_then(|v| v.as_str()) {
            model_ids.push(model_id.to_string());
        }
    }

    // Batch fetch settings for all models from the admin models table
    let settings_map = state
        .model_service
        .get_models_by_ids(&model_ids.iter().map(|s| s.as_str()).collect::<Vec<&str>>())
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to batch load model settings for model list: {}, defaulting all public={}",
                e,
                MODEL_PUBLIC_DEFAULT
            );
            std::collections::HashMap::new()
        });

    // Attach `public` flag to each model based on its stored settings
    let mut decorated_models = Vec::new();
    for mut model in std::mem::take(models_array) {
        let public_flag = model
            .get("modelId")
            .and_then(|v| v.as_str())
            .and_then(|id| settings_map.get(id).map(|m| m.settings.public))
            .unwrap_or(MODEL_PUBLIC_DEFAULT);

        if let Some(obj) = model.as_object_mut() {
            obj.insert("public".to_string(), serde_json::Value::Bool(public_flag));
        }

        decorated_models.push(model);
    }

    *body_json
        .get_mut("models")
        .expect("Models key must exist after previous check") =
        serde_json::Value::Array(decorated_models);

    let filtered_bytes = serde_json::to_vec(&body_json).unwrap_or_else(|e| {
        tracing::error!(
            "Failed to serialize filtered model list JSON: {}, returning original body",
            e
        );
        body_bytes.to_vec()
    });

    Response::builder()
        .status(StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::OK))
        .header("content-type", "application/json")
        .body(Body::from(filtered_bytes))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to build response: {e}"),
                }),
            )
                .into_response()
        })
}

/// Proxy signature endpoint - forwards signature requests to OpenAI
#[utoipa::path(
    get,
    path = "/v1/signature/{chat_id}",
    tag = PROXY,
    params(
        ("chat_id" = String, Path, description = "Chat ID to get signature for")
    ),
    responses(
        (status = 200, description = "Signature retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_signature(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(chat_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    validate_proxy_path_segment(&chat_id)
        .map_err(|_| invalid_proxy_path_segment_response("chat_id"))?;

    tracing::info!(
        "proxy_signature: GET /v1/signature/{} for user_id={}, session_id={}",
        chat_id,
        user.user_id,
        user.session_id
    );

    let path = format!("signature/{}", chat_id);

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(Method::GET, &path, headers.clone(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for GET /v1/signature/{} (user_id={}): {}",
                chat_id,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from OpenAI: status={} for GET /v1/signature/{} (user_id={})",
        proxy_response.status,
        chat_id,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Typed usage details for web_search (avoids raw Value construction).
#[derive(Serialize)]
struct WebSearchUsageDetails {
    request_type: &'static str,
}

#[derive(Debug, Deserialize)]
struct McpRequestEnvelope {
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

/// Proxy MCP requests to cloud-api and track successful web_search tool calls for end users.
async fn proxy_mcp(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    let body_bytes = extract_body_bytes(request).await?;
    let mcp_request = serde_json::from_slice::<McpRequestEnvelope>(&body_bytes).ok();
    let is_web_search_call = mcp_request
        .as_ref()
        .map(is_web_search_tool_call)
        .unwrap_or(false);

    let url = crate::cloud_api::mcp_url(&state.cloud_api_base_url);

    let api_key = state
        .vpc_credentials_service
        .get_api_key()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get VPC API key for MCP proxy: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "Cloud API credentials unavailable".to_string(),
                }),
            )
                .into_response()
        })?;

    let mut forward_headers = headers.clone();
    forward_headers.remove("authorization");
    forward_headers.remove("host");
    forward_headers.remove("content-length");
    forward_headers.remove("cookie");
    forward_headers.remove("x-org-id");
    forward_headers.remove("x-workspace-id");

    let mut request_builder = state
        .http_client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .body(body_bytes);

    for (key, value) in forward_headers.iter() {
        request_builder = request_builder.header(key, value);
    }

    let upstream_response = request_builder.send().await.map_err(|e| {
        tracing::error!("MCP proxy error for user_id={}: {}", user.user_id, e);
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: format!("Cloud API error: {e}"),
            }),
        )
            .into_response()
    })?;

    let status = upstream_response.status().as_u16();
    let response_headers = upstream_response.headers().clone();
    let response_body = upstream_response.bytes().await.map_err(|e| {
        tracing::error!(
            "Failed to read MCP response for user_id={}: {}",
            user.user_id,
            e
        );
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: format!("Failed to read cloud API response: {e}"),
            }),
        )
            .into_response()
    })?;

    if is_web_search_call && (200..300).contains(&status) {
        let decompressed_body = decompress_if_encoded(response_body.clone(), &response_headers)
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to decompress MCP response for user_id={}: {}",
                    user.user_id,
                    e
                );
                response_body.clone()
            });
        let response_json = serde_json::from_slice::<serde_json::Value>(&decompressed_body).ok();

        if response_json
            .as_ref()
            .map(is_successful_mcp_web_search_response)
            .unwrap_or(false)
        {
            let details = serde_json::to_value(WebSearchUsageDetails {
                request_type: "mcp.web_search",
            })
            .ok();

            let (instance_id, api_key_id) = api_key_ext
                .as_ref()
                .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
                .unwrap_or((None, None));

            let state_clone = state.clone();
            tokio::spawn(async move {
                let cost_nano_usd = state_clone
                    .web_search_pricing_cache
                    .get_cost_per_unit()
                    .await;
                let usage_params = services::user_usage::RecordUsageParams {
                    user_id: user.user_id,
                    metric_key: services::user_usage::METRIC_KEY_SERVICE_WEB_SEARCH.to_string(),
                    quantity: 1,
                    cost_nano_usd: Some(cost_nano_usd),
                    model_id: None,
                    instance_id,
                    api_key_id,
                    details,
                };

                let result = if instance_id.is_some() {
                    state_clone
                        .user_usage_service
                        .record_usage_and_update_balance(usage_params)
                        .await
                } else {
                    state_clone
                        .user_usage_service
                        .record_usage(usage_params)
                        .await
                };

                if let Err(e) = result {
                    tracing::warn!(
                        "Failed to record web search MCP usage for user_id={}: {}",
                        user.user_id,
                        e
                    );
                }
            });
        }
    }

    build_response(status, response_headers, Body::from(response_body)).await
}

fn is_web_search_tool_call(request: &McpRequestEnvelope) -> bool {
    request.method == "tools/call"
        && request
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(|value| value.as_str())
            == Some("web_search")
}

fn is_successful_mcp_web_search_response(response: &serde_json::Value) -> bool {
    if response.get("error").is_some() {
        return false;
    }

    response
        .get("result")
        .and_then(|result| result.get("isError"))
        .and_then(|value| value.as_bool())
        == Some(false)
}

/// Get system configs with in-memory TTL caching.
/// Returns `None` when no configs exist or on DB error (graceful degradation).
async fn get_system_configs_cached(
    state: &crate::state::AppState,
) -> Option<services::system_configs::ports::SystemConfigs> {
    // 1) Try cache first
    {
        let cache = state.system_configs_cache.read().await;
        if let Some(entry) = cache.as_ref() {
            let age = Utc::now().signed_duration_since(entry.last_checked_at);
            if age.num_seconds() >= 0 && age.num_seconds() < SYSTEM_CONFIGS_CACHE_TTL_SECS {
                return entry.configs.clone();
            }
        }
    }

    // 2) Cache miss or expired: fetch from DB and populate cache
    let configs = state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::warn!("Failed to load system configs, using defaults: {e}");
            e
        })
        .ok()
        .flatten();

    {
        let mut cache = state.system_configs_cache.write().await;
        *cache = Some(crate::state::SystemConfigsCacheEntry {
            last_checked_at: Utc::now(),
            configs: configs.clone(),
        });
    }

    configs
}

async fn enforce_model_access(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    model_id: &str,
) -> Result<(), Response> {
    match state
        .subscription_service
        .check_model_access(user.user_id, model_id)
        .await
    {
        Ok(()) => Ok(()),
        Err(SubscriptionError::ModelNotAllowedInPlan { model, plan }) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: SubscriptionError::ModelNotAllowedInPlan { model, plan }.to_string(),
            }),
        )
            .into_response()),
        Err(err) => {
            tracing::error!(
                "Failed to validate model access for user_id={}, model_id={}: {}",
                user.user_id,
                model_id,
                err
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to validate model access".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Helper function to get model settings with caching support.
/// Returns (system_prompt, cache_hit) if model is found and public.
/// Validates model visibility and populates cache if needed.
async fn get_model_settings_with_cache(
    state: &crate::state::AppState,
    model_id: &str,
    user_id: services::UserId,
) -> Result<(Option<String>, Option<bool>), Response> {
    let mut model_system_prompt: Option<String> = None;
    let mut model_settings_cache_hit: Option<bool> = None;

    // 1) Try cache first
    {
        let cache = state.model_settings_cache.read().await;
        if let Some(entry) = cache.get(model_id) {
            let age = Utc::now().signed_duration_since(entry.last_checked_at);
            if age.num_seconds() >= 0 && age.num_seconds() < MODEL_SETTINGS_CACHE_TTL_SECS {
                model_settings_cache_hit = Some(true);

                if !entry.public {
                    tracing::warn!(
                        "Blocking request for non-public model '{}' from user {} (cache)",
                        model_id,
                        user_id
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "This model is not available".to_string(),
                        }),
                    )
                        .into_response());
                }

                model_system_prompt = entry.system_prompt.clone();
            }
        }
    }

    // 2) Cache miss or expired: fetch from DB/service and populate cache
    if model_settings_cache_hit.is_none() {
        model_settings_cache_hit = Some(false);
        match state.model_service.get_model(model_id).await {
            Ok(Some(model)) => {
                // Populate cache
                {
                    let mut cache = state.model_settings_cache.write().await;
                    cache.insert(
                        model_id.to_string(),
                        crate::state::ModelSettingsCacheEntry {
                            last_checked_at: Utc::now(),
                            exists: true,
                            public: model.settings.public,
                            system_prompt: model.settings.system_prompt.clone(),
                        },
                    );
                }

                if !model.settings.public {
                    tracing::warn!(
                        "Blocking request for non-public model '{}' from user {}",
                        model_id,
                        user_id
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "This model is not available".to_string(),
                        }),
                    )
                        .into_response());
                }

                model_system_prompt = model.settings.system_prompt.clone();
            }
            Ok(None) => {
                // Model not in admin DB - allow by default per MODEL_PUBLIC_DEFAULT
                // Cache with defaults to avoid repeated DB hits
                {
                    let mut cache = state.model_settings_cache.write().await;
                    cache.insert(
                        model_id.to_string(),
                        crate::state::ModelSettingsCacheEntry {
                            last_checked_at: Utc::now(),
                            exists: false, // Not in DB but allowed with defaults
                            public: MODEL_PUBLIC_DEFAULT, // true by default
                            system_prompt: None,
                        },
                    );
                }

                // Continue with defaults
                model_system_prompt = None;
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to get model".to_string(),
                    }),
                )
                    .into_response())
            }
        }
    }

    Ok((model_system_prompt, model_settings_cache_hit))
}

/// Prepares chat completions request body with optional model system prompt injection.
async fn prepare_chat_completions_body(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    body_bytes: Bytes,
) -> Result<Bytes, Response> {
    let mut body_json: Option<serde_json::Value> = None;
    let mut model_system_prompt: Option<String> = None;

    let mut auto_routed = false;

    if !body_bytes.is_empty() {
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(v) => {
                body_json = Some(v);

                // Route "auto" model to the configured target with recommended defaults
                if let Some(body) = body_json.as_mut() {
                    if body.get("model").and_then(|v| v.as_str()) == Some("auto") {
                        tracing::info!("Auto-routing model: user_id={}", user.user_id);

                        // Load auto-route config from system configs (cached with TTL)
                        let auto_config = get_system_configs_cached(state)
                            .await
                            .and_then(|c| c.auto_route);

                        let route_model = auto_config
                            .as_ref()
                            .map(|c| c.model.as_str())
                            .unwrap_or(AUTO_ROUTE_MODEL);

                        body["model"] = json!(route_model);

                        // When config exists, only inject params explicitly set in it.
                        // When no config exists, use hardcoded fallback defaults.
                        if let Some(ref cfg) = auto_config {
                            if let Some(t) = cfg.temperature {
                                if body.get("temperature").is_none_or(|v| v.is_null()) {
                                    body["temperature"] = json!(t);
                                }
                            }
                            if let Some(p) = cfg.top_p {
                                if body.get("top_p").is_none_or(|v| v.is_null()) {
                                    body["top_p"] = json!(p);
                                }
                            }
                            if let Some(m) = cfg.max_tokens {
                                if body.get("max_tokens").is_none_or(|v| v.is_null()) {
                                    body["max_tokens"] = json!(m);
                                }
                            }
                        } else {
                            // No auto_route config set — use hardcoded fallback defaults
                            if body.get("temperature").is_none_or(|v| v.is_null()) {
                                body["temperature"] = json!(AUTO_ROUTE_TEMPERATURE);
                            }
                            if body.get("top_p").is_none_or(|v| v.is_null()) {
                                body["top_p"] = json!(AUTO_ROUTE_TOP_P);
                            }
                            if body.get("max_tokens").is_none_or(|v| v.is_null()) {
                                body["max_tokens"] = json!(AUTO_ROUTE_MAX_TOKENS);
                            }
                        }
                        auto_routed = true;
                    }
                }

                // Check model access based on subscription plan
                if let Some(model_id) = body_json
                    .as_ref()
                    .and_then(|b| b.get("model"))
                    .and_then(|v| v.as_str())
                {
                    enforce_model_access(state, user, model_id).await?;
                }

                if let Some(model_id) = body_json
                    .as_ref()
                    .and_then(|b| b.get("model"))
                    .and_then(|v| v.as_str())
                {
                    match get_model_settings_with_cache(state, model_id, user.user_id).await {
                        Ok((prompt, _)) => model_system_prompt = prompt,
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse request body as JSON for chat/completions (user_id={}): {}",
                    user.user_id,
                    e
                );
            }
        }
    }

    let modified_body_bytes = if let Some(mut body) = body_json {
        let mut modified = false;
        if let Some(system_prompt) = model_system_prompt.as_ref() {
            if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
                let has_system_message = messages
                    .iter()
                    .any(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"));
                if !has_system_message {
                    let system_msg = json!({ "role": "system", "content": system_prompt });
                    messages.insert(0, system_msg);
                    modified = true;
                } else if let Some(first_system_idx) = messages
                    .iter()
                    .position(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"))
                {
                    let first_system = &mut messages[first_system_idx];
                    if let Some(content_str) = first_system.get("content").and_then(|c| c.as_str())
                    {
                        first_system["content"] = serde_json::Value::String(format!(
                            "{}\n\n{}",
                            system_prompt, content_str
                        ));
                        modified = true;
                    } else if let Some(content_arr) = first_system
                        .get_mut("content")
                        .and_then(|c| c.as_array_mut())
                    {
                        content_arr.insert(0, json!({ "type": "text", "text": system_prompt }));
                        modified = true;
                    } else {
                        first_system["content"] =
                            serde_json::Value::String(system_prompt.to_string());
                        modified = true;
                    }
                }
            } else {
                body["messages"] = json!([{ "role": "system", "content": system_prompt }]);
                modified = true;
            }
        }
        modified |= ensure_stream_usage_options(&mut body);
        if modified || auto_routed {
            serde_json::to_vec(&body).map(Bytes::from).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to modify request body".to_string(),
                    }),
                )
                    .into_response()
            })
        } else {
            Ok(body_bytes)
        }
    } else {
        Ok(body_bytes)
    }?;
    Ok(modified_body_bytes)
}

fn ensure_stream_usage_options(body: &mut serde_json::Value) -> bool {
    if body.get("stream").and_then(|v| v.as_bool()) != Some(true) {
        return false;
    }

    let Some(body) = body.as_object_mut() else {
        return false;
    };

    match body
        .get_mut("stream_options")
        .and_then(|v| v.as_object_mut())
    {
        Some(options) => {
            if options.get("include_usage").and_then(|v| v.as_bool()) == Some(true) {
                return false;
            }
            options.insert("include_usage".to_string(), serde_json::Value::Bool(true));
        }
        None => {
            body.insert(
                "stream_options".to_string(),
                json!({ "include_usage": true }),
            );
        }
    }

    true
}

/// Configuration for proxying POST requests to cloud-api endpoints (no usage tracking).
/// Used by proxy_post_to_cloud_api for future POST endpoints that do not need usage tracking.
#[allow(dead_code)]
struct ProxyEndpointConfig {
    /// Path for the proxy service (e.g., "chat/completions")
    endpoint_path: &'static str,
    /// Full path for logging (e.g., "/v1/chat/completions")
    endpoint_full_path: &'static str,
    /// Whether to set the content-length header (false for multipart/form-data)
    set_content_length: bool,
    /// Whether to enable model system prompt injection
    enable_model_prompt: bool,
}

/// Shared helper for proxying POST requests to cloud-api endpoints (no usage tracking).
/// Use dedicated handlers (proxy_chat_completions, proxy_image_*) for endpoints that track usage.
///
/// Handles: ban check, NEAR check, body extraction, optional model prompt injection, forward, response.
#[allow(dead_code)]
async fn proxy_post_to_cloud_api(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    mut headers: HeaderMap,
    request: Request,
    config: ProxyEndpointConfig,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_post_to_cloud_api: POST {} for user_id={}, session_id={}",
        config.endpoint_full_path,
        user.user_id,
        user.session_id
    );

    // Check if user is currently banned before proceeding
    ensure_user_not_banned(state, user).await?;

    // Trigger an asynchronous NEAR balance check
    spawn_near_balance_check(state, user);

    // Extract body bytes
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "Extracted request body: {} bytes for POST {}",
        body_bytes.len(),
        config.endpoint_full_path
    );

    // Parse JSON body and handle model settings if enabled
    let mut body_json: Option<serde_json::Value> = None;
    let mut model_system_prompt: Option<String> = None;

    if config.enable_model_prompt && !body_bytes.is_empty() {
        // Try to parse JSON body for model settings lookup
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(v) => {
                body_json = Some(v);

                // Extract model ID and get model settings
                if let Some(model_id) = body_json
                    .as_ref()
                    .and_then(|b| b.get("model"))
                    .and_then(|v| v.as_str())
                {
                    match get_model_settings_with_cache(state, model_id, user.user_id).await {
                        Ok((prompt, _cache_hit)) => {
                            model_system_prompt = prompt;
                            // Cache hit/miss is tracked via analytics in proxy_responses, not needed here
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse request body as JSON for POST {} (user_id={}): {}",
                    config.endpoint_full_path,
                    user.user_id,
                    e
                );
            }
        }
    }

    // Inject system prompt into request body if present
    let modified_body_bytes = if let Some(mut body) = body_json {
        let mut modified = false;

        // For chat completions, inject system prompt as a system message
        if let Some(system_prompt) = model_system_prompt.as_ref() {
            if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
                // Check if there's already a system message
                let has_system_message = messages
                    .iter()
                    .any(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"));

                if !has_system_message {
                    // Prepend system message at the beginning
                    let system_msg = json!({
                        "role": "system",
                        "content": system_prompt
                    });
                    messages.insert(0, system_msg);
                    modified = true;
                } else {
                    // If system message exists, prepend to the first system message's content
                    if let Some(first_system_idx) = messages
                        .iter()
                        .position(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"))
                    {
                        let first_system = &mut messages[first_system_idx];

                        // Handle string content
                        if let Some(content_str) =
                            first_system.get("content").and_then(|c| c.as_str())
                        {
                            let new_content = format!("{system_prompt}\n\n{content_str}");
                            first_system["content"] = serde_json::Value::String(new_content);
                            modified = true;
                        }
                        // Handle array content format (for multimodal)
                        else if let Some(content_arr) = first_system
                            .get_mut("content")
                            .and_then(|c| c.as_array_mut())
                        {
                            // Prepend text content to the array efficiently
                            content_arr.insert(
                                0,
                                json!({
                                    "type": "text",
                                    "text": system_prompt
                                }),
                            );
                            modified = true;
                        }
                        // If content is missing or in unexpected format, replace with system prompt
                        else {
                            first_system["content"] =
                                serde_json::Value::String(system_prompt.to_string());
                            modified = true;
                        }
                    }
                }
            } else {
                // No messages array - create one with system message
                body["messages"] = json!([{
                    "role": "system",
                    "content": system_prompt
                }]);
                modified = true;
            }
        }

        if modified {
            match serde_json::to_vec(&body) {
                Ok(serialized) => Bytes::from(serialized),
                Err(_) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to modify request body".to_string(),
                        }),
                    )
                        .into_response())
                }
            }
        } else {
            body_bytes
        }
    } else {
        body_bytes
    };

    // Set content-length header if requested (skip for multipart/form-data)
    if config.set_content_length {
        let content_length = HeaderValue::from_str(&modified_body_bytes.len().to_string())
            .expect("usize to string conversion always produces valid HeaderValue");
        headers.insert(CONTENT_LENGTH, content_length);
    }

    // Forward the request to cloud-api
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            config.endpoint_path,
            headers.clone(),
            Some(modified_body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                config.endpoint_full_path,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from cloud-api: status={} for POST {} (user_id={})",
        proxy_response.status,
        config.endpoint_full_path,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Proxy chat completions endpoint - OpenAI-compatible chat completions with model system prompt injection and usage tracking.
#[utoipa::path(
    post,
    path = "/v1/chat/completions",
    tag = PROXY,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Chat completion created successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned or model not available", body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_chat_completions(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    const ENDPOINT_PATH: &str = "chat/completions";
    const ENDPOINT_FULL_PATH: &str = "/v1/chat/completions";

    tracing::info!(
        "proxy_chat_completions: POST {} for user_id={}, session_id={}",
        ENDPOINT_FULL_PATH,
        user.user_id,
        user.session_id
    );

    ensure_user_not_banned(&state, &user).await?;
    spawn_near_balance_check(&state, &user);

    let body_bytes = extract_body_bytes(request).await?;
    tracing::debug!(
        "Extracted request body: {} bytes for POST {}",
        body_bytes.len(),
        ENDPOINT_FULL_PATH
    );

    let modified_body_bytes = prepare_chat_completions_body(&state, &user, body_bytes).await?;
    let content_length = HeaderValue::from_str(&modified_body_bytes.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            ENDPOINT_PATH,
            headers.clone(),
            Some(modified_body_bytes.clone()),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                ENDPOINT_FULL_PATH,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from cloud-api: status={} for POST {} (user_id={})",
        proxy_response.status,
        ENDPOINT_FULL_PATH,
        user.user_id
    );

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else if is_streaming_response(&proxy_response.headers) {
        let mut usage_stream = UsageTrackingStreamChatCompletions::new(
            proxy_response.body,
            state.user_usage_service.clone(),
            state.subscription_service.clone(),
            state.model_pricing_cache.clone(),
            user.user_id,
        );
        if let Some(Extension(api_key)) = &api_key_ext {
            usage_stream = usage_stream
                .with_agent_ids(api_key.api_key_info.instance_id, api_key.api_key_info.id);
        }
        Body::from_stream(usage_stream)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "Upstream stream error for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        let usage_bytes = decompress_if_encoded(bytes.clone(), &proxy_response.headers)
            .unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to decompress non-stream response for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                bytes.clone()
            });
        // Return the original upstream bytes so they remain consistent with any forwarded content-encoding headers.
        let state_clone = state.clone();
        let user_id = user.user_id;
        let request_body = modified_body_bytes.clone();
        let response_body = usage_bytes.clone();
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_chat_usage_from_body(
                &state_clone,
                user_id,
                &request_body,
                &response_body,
                api_key_opt,
            )
            .await;
        });
        Body::from(bytes)
    };

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        response_body,
    )
    .await
}

/// Proxy image generation to cloud-api (OpenAI-compatible endpoint) with usage tracking.
#[utoipa::path(
    post,
    path = "/v1/images/generations",
    tag = PROXY,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Image generation request processed successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned", body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_image_generations(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    const ENDPOINT_PATH: &str = "images/generations";
    const ENDPOINT_FULL_PATH: &str = "/v1/images/generations";

    tracing::info!(
        "proxy_image_generations: POST {} for user_id={}, session_id={}",
        ENDPOINT_FULL_PATH,
        user.user_id,
        user.session_id
    );

    ensure_user_not_banned(&state, &user).await?;
    spawn_near_balance_check(&state, &user);

    let body_bytes = extract_body_bytes(request).await?;
    // Parse request JSON: model is required; n is optional, default 1.
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        tracing::error!(
            "Failed to parse image generations request body as JSON for user_id={}: {}",
            user.user_id,
            e
        );
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid JSON body for image generations request".to_string(),
            }),
        )
            .into_response()
    })?;

    let image_request_model = body_json
        .get("model")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!(
                "Missing or invalid `model` in image generations request for user_id={}",
                user.user_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "`model` is required for image generations".to_string(),
                }),
            )
                .into_response()
        })?
        .to_string();

    let image_count: u32 = match body_json.get("n") {
        None => 1,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                tracing::error!(
                    "Invalid `n` (must be positive integer) in image generations request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response()
            })?;
            if n == 0 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response());
            }
            u32::try_from(n).map_err(|_| {
                tracing::error!(
                    "`n` out of range in image generations request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer within valid range".to_string(),
                    }),
                )
                    .into_response()
            })?
        }
    };

    enforce_model_access(&state, &user, &image_request_model).await?;

    let content_length = HeaderValue::from_str(&body_bytes.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            ENDPOINT_PATH,
            headers.clone(),
            Some(body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                ENDPOINT_FULL_PATH,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "Upstream stream error for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        // Use image_count and model from the request to compute cost; we don't depend on response body shape.
        let state_clone = state.clone();
        let user_id = user.user_id;
        let model = image_request_model.clone();
        let qty = image_count as i64;
        let mk = services::user_usage::METRIC_KEY_IMAGE_GENERATE;
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_image_usage(
                &state_clone,
                user_id,
                mk,
                qty,
                Some(model.as_str()),
                api_key_opt,
            )
            .await;
        });
        Body::from(bytes)
    };

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        response_body,
    )
    .await
}

/// Proxy image edits to cloud-api (OpenAI-compatible endpoint) with usage tracking.
/// Note: This endpoint accepts multipart/form-data.
#[utoipa::path(
    post,
    path = "/v1/images/edits",
    tag = PROXY,
    request_body(content = Vec<u8>, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Image edit request processed successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned", body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_image_edits(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    const ENDPOINT_PATH: &str = "images/edits";
    const ENDPOINT_FULL_PATH: &str = "/v1/images/edits";

    tracing::info!(
        "proxy_image_edits: POST {} for user_id={}, session_id={}",
        ENDPOINT_FULL_PATH,
        user.user_id,
        user.session_id
    );

    ensure_user_not_banned(&state, &user).await?;
    spawn_near_balance_check(&state, &user);

    // Read full multipart body as bytes (to keep original formdata for forwarding).
    let body_bytes = extract_body_bytes(request).await?;

    // Parse Content-Type to extract boundary.
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!(
                "Missing or invalid Content-Type for image edits request (user_id={})",
                user.user_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Content-Type header with multipart boundary is required".to_string(),
                }),
            )
                .into_response()
        })?;

    let boundary = content_type
        .split(';')
        .find_map(|part| {
            let part = part.trim();
            part.strip_prefix("boundary=")
                .map(|b| b.trim_matches('"').to_string())
        })
        .ok_or_else(|| {
            tracing::error!(
                "Missing boundary in Content-Type for image edits request (user_id={})",
                user.user_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "multipart/form-data boundary is required".to_string(),
                }),
            )
                .into_response()
        })?;

    // Use multer to parse multipart fields from the raw bytes, without modifying them.
    let body_for_multipart = body_bytes.clone();
    let stream = stream::once(async move { Ok::<Bytes, std::io::Error>(body_for_multipart) });
    let mut multipart = Multipart::new(stream, boundary);

    let mut request_model: Option<String> = None;
    let mut request_n: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::error!(
            "Failed to parse multipart field for image edits (user_id={}): {}",
            user.user_id,
            e
        );
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid multipart/form-data body for image edits".to_string(),
            }),
        )
            .into_response()
    })? {
        let name = field.name().map(|s| s.to_string());
        match name.as_deref() {
            Some("model") => {
                let text = field.text().await.map_err(|e| {
                    tracing::error!(
                        "Failed to read `model` field in image edits request (user_id={}): {}",
                        user.user_id,
                        e
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "Invalid `model` field in image edits request".to_string(),
                        }),
                    )
                        .into_response()
                })?;
                request_model = Some(text);
            }
            Some("n") => {
                let text = field.text().await.map_err(|e| {
                    tracing::error!(
                        "Failed to read `n` field in image edits request (user_id={}): {}",
                        user.user_id,
                        e
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "Invalid `n` field in image edits request".to_string(),
                        }),
                    )
                        .into_response()
                })?;
                request_n = Some(text);
            }
            _ => {
                // Other fields: we don't need to inspect, but they remain in body_bytes for forwarding.
            }
        }
    }

    let request_model = request_model.ok_or_else(|| {
        tracing::error!(
            "Missing `model` field in image edits request for user_id={}",
            user.user_id
        );
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "`model` is required for image edits".to_string(),
            }),
        )
            .into_response()
    })?;

    // n is optional, default 1; if present must be a positive integer
    let image_count: u32 = match request_n.as_deref() {
        None | Some("") => 1,
        Some(s) => {
            let n: u64 = s.trim().parse().map_err(|_| {
                tracing::error!(
                    "Invalid `n` (must be positive integer) in image edits request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response()
            })?;
            if n == 0 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response());
            }
            u32::try_from(n).map_err(|_| {
                tracing::error!(
                    "`n` out of range in image edits request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer within valid range".to_string(),
                    }),
                )
                    .into_response()
            })?
        }
    };

    enforce_model_access(&state, &user, &request_model).await?;

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            ENDPOINT_PATH,
            headers.clone(),
            Some(body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                ENDPOINT_FULL_PATH,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "Upstream stream error for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        let state_clone = state.clone();
        let user_id = user.user_id;
        let model = request_model.clone();
        let mk = services::user_usage::METRIC_KEY_IMAGE_EDIT;
        let qty = image_count as i64;
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_image_usage(
                &state_clone,
                user_id,
                mk,
                qty,
                Some(model.as_str()),
                api_key_opt,
            )
            .await;
        });
        Body::from(bytes)
    };

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        response_body,
    )
    .await
}

/// Proxy models list to cloud-api (OpenAI-compatible endpoint: GET /v1/models)
#[utoipa::path(
    get,
    path = "/v1/models",
    tag = PROXY,
    responses(
        (status = 200, description = "Models list retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_models(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_models: GET /v1/models for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Forward the request to cloud-api
    let proxy_response = state
        .proxy_service
        .forward_request(Method::GET, "models", headers.clone(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for GET /v1/models (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from cloud-api: status={} for GET /v1/models (user_id={})",
        proxy_response.status,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

async fn build_response(status: u16, headers: HeaderMap, body: Body) -> Result<Response, Response> {
    // Build the response
    let mut response = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));

    // Copy headers from OpenAI response
    if let Some(response_headers) = response.headers_mut() {
        for (key, value) in headers.iter() {
            // Skip certain headers that shouldn't be forwarded:
            // - transfer-encoding: hyper handles this
            // - connection: hop-by-hop header
            // - content-length: may be incorrect if the proxy modified a body
            //   hyper will calculate the correct content-length automatically
            if key != "transfer-encoding" && key != "connection" && key != "content-length" {
                response_headers.insert(key, value.clone());
            }
        }
    }

    response.body(body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to build response: {e}"),
            }),
        )
            .into_response()
    })
}

/// Extract body bytes from a request
async fn extract_body_bytes(request: Request) -> Result<Bytes, Response> {
    tracing::debug!("Extracting body bytes from request");
    let result = axum::body::to_bytes(request.into_body(), MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read request body: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Failed to read request body: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::debug!(
        "Successfully extracted {} bytes from request body",
        result.len()
    );
    Ok(result)
}

/// Decompress response bytes according to Content-Encoding when supported.
fn decompress_if_encoded(bytes: Bytes, headers: &HeaderMap) -> Result<Bytes, std::io::Error> {
    fn read_to_vec_limited<R: Read>(
        reader: R,
        max_bytes: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut limited_reader = reader.take((max_bytes as u64).saturating_add(1));
        let mut out = Vec::new();
        limited_reader.read_to_end(&mut out)?;
        if out.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Decompressed payload exceeds {} bytes", max_bytes),
            ));
        }
        Ok(out)
    }

    let Some(encoding) = headers.get("content-encoding") else {
        return Ok(bytes);
    };
    let Ok(encoding_str) = encoding.to_str() else {
        return Ok(bytes);
    };

    let encoding_str_lower = encoding_str.to_ascii_lowercase();
    let encodings: Vec<String> = encoding_str_lower
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "identity")
        .collect();

    if encodings.is_empty() {
        return Ok(bytes);
    }

    tracing::debug!(
        "Response is '{}' encoded, decompressing for JSON parsing",
        encoding_str
    );

    let original = bytes;
    let mut decoded = original.clone();
    for enc in encodings.into_iter().rev() {
        let current = decoded.as_ref();
        decoded = match enc.as_str() {
            "gzip" | "x-gzip" => {
                let decoder = GzDecoder::new(current);
                Bytes::from(read_to_vec_limited(
                    decoder,
                    MAX_DECOMPRESSED_RESPONSE_BODY_SIZE,
                )?)
            }
            "deflate" => {
                let zlib_decoder = ZlibDecoder::new(current);
                match read_to_vec_limited(zlib_decoder, MAX_DECOMPRESSED_RESPONSE_BODY_SIZE) {
                    Ok(decompressed) => Bytes::from(decompressed),
                    Err(zlib_err) => {
                        tracing::debug!(
                            "Zlib-wrapped deflate decode failed ({}), trying raw DEFLATE fallback",
                            zlib_err
                        );
                        let raw_decoder = DeflateDecoder::new(current);
                        Bytes::from(read_to_vec_limited(
                            raw_decoder,
                            MAX_DECOMPRESSED_RESPONSE_BODY_SIZE,
                        )?)
                    }
                }
            }
            "br" => {
                let decoder = brotli::Decompressor::new(current, 4096);
                Bytes::from(read_to_vec_limited(
                    decoder,
                    MAX_DECOMPRESSED_RESPONSE_BODY_SIZE,
                )?)
            }
            "zstd" => {
                let decoder = zstd::stream::read::Decoder::new(current)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Bytes::from(read_to_vec_limited(
                    decoder,
                    MAX_DECOMPRESSED_RESPONSE_BODY_SIZE,
                )?)
            }
            unsupported => {
                tracing::debug!(
                    "Unsupported content-encoding '{}' for response decompression",
                    unsupported
                );
                // Keep passthrough behavior: if any encoding in the chain is unsupported,
                // return original bytes and let the caller forward without modification.
                return Ok(original);
            }
        };
    }

    tracing::debug!(
        "Decompressed {} bytes to {} bytes",
        original.len(),
        decoded.len()
    );
    Ok(decoded)
}

/// Returns true if response headers indicate a streaming (SSE) response.
fn is_streaming_response(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false)
}

/// Record image usage (metric_key + quantity; cost from model pricing × quantity).
/// Used for /v1/images/generations (image.generate, quantity=n) and /v1/images/edits (image.edit, quantity=1).
async fn record_image_usage(
    state: &crate::state::AppState,
    user_id: UserId,
    metric_key: &str,
    quantity: i64,
    model_name: Option<&str>,
    api_key_ext: Option<AuthenticatedApiKey>,
) {
    if quantity <= 0 {
        return;
    }
    let cost_nano_usd = if let Some(model) = model_name {
        state
            .model_pricing_cache
            .get_pricing(model)
            .await
            .map(|p| p.cost_nano_usd_for_images(quantity as u32))
            .unwrap_or(0)
    } else {
        0
    };

    let (instance_id, api_key_id) = api_key_ext
        .as_ref()
        .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
        .unwrap_or((None, None));

    let details = serde_json::json!({
        "request_type": "image_generation",
    });

    let params = services::user_usage::RecordUsageParams {
        user_id,
        metric_key: metric_key.to_string(),
        quantity,
        cost_nano_usd: Some(cost_nano_usd),
        model_id: model_name.map(|s| s.to_string()),
        instance_id,
        api_key_id,
        details: Some(details),
    };

    let result = if instance_id.is_some() {
        state
            .user_usage_service
            .record_usage_and_update_balance(params)
            .await
    } else {
        state.user_usage_service.record_usage(params).await
    };

    if let Err(e) = result {
        tracing::warn!(
            "Failed to record image usage for user_id={}: {}",
            user_id,
            e
        );
    } else if cost_nano_usd > 0 {
        if let Err(e) = state
            .subscription_service
            .reconcile_purchased_after_usage(user_id)
            .await
        {
            tracing::warn!(
                error = ?e,
                "Failed to reconcile purchased credits after image usage"
            );
        }
    }
}

/// Record token and cost usage from parsed **chat completions** response body.
/// Returns true if usage was recorded.
async fn record_chat_usage_from_body(
    state: &crate::state::AppState,
    user_id: UserId,
    request_body: &[u8],
    response_body: &[u8],
    api_key_ext: Option<AuthenticatedApiKey>,
) -> bool {
    let Some(usage) = parse_chat_completion_usage_from_bytes(response_body) else {
        return false;
    };
    if usage.total_tokens == 0 {
        return false;
    }

    // Extract request model name from request body
    let request_model = serde_json::from_slice::<serde_json::Value>(request_body)
        .ok()
        .and_then(|v| {
            v.get("model")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| usage.model.clone());

    let pricing = state.model_pricing_cache.get_pricing(&request_model).await;
    let cost_nano_usd = pricing.as_ref().map(|p| {
        p.cost_nano_usd(
            usage.input_tokens,
            usage.output_tokens,
            usage.cache_read_tokens,
        )
    });

    let input_cost = pricing
        .as_ref()
        .map(|p| p.input_cost_nano_usd(usage.input_tokens, usage.cache_read_tokens))
        .unwrap_or(0);
    let output_cost = pricing
        .as_ref()
        .map(|p| p.output_cost_nano_usd(usage.output_tokens))
        .unwrap_or(0);

    let (instance_id, api_key_id) = api_key_ext
        .as_ref()
        .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
        .unwrap_or((None, None));

    let details = serde_json::json!({
        "input_tokens": usage.input_tokens as i64,
        "output_tokens": usage.output_tokens as i64,
        "cache_read_tokens": usage.cache_read_tokens as i64,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "request_type": "chat_completion",
    });

    let params = services::user_usage::RecordUsageParams {
        user_id,
        metric_key: services::user_usage::METRIC_KEY_LLM_TOKENS.to_string(),
        quantity: usage.total_tokens as i64,
        cost_nano_usd,
        model_id: Some(usage.model.clone()),
        instance_id,
        api_key_id,
        details: Some(details),
    };

    let result = if instance_id.is_some() {
        state
            .user_usage_service
            .record_usage_and_update_balance(params)
            .await
    } else {
        state.user_usage_service.record_usage(params).await
    };

    if let Err(e) = result {
        tracing::warn!("Failed to record usage for user_id={}: {}", user_id, e);
        return false;
    }

    if cost_nano_usd.unwrap_or(0) > 0 {
        if let Err(e) = state
            .subscription_service
            .reconcile_purchased_after_usage(user_id)
            .await
        {
            tracing::warn!(
                error = ?e,
                "Failed to reconcile purchased credits after chat usage"
            );
        }
    }

    true
}

/// Record token and cost usage from parsed **/v1/responses** body.
/// Returns true if usage was recorded.
async fn record_response_usage_from_body(
    state: &crate::state::AppState,
    user_id: UserId,
    body: &[u8],
    api_key_ext: Option<AuthenticatedApiKey>,
) -> bool {
    let Some(usage) = parse_response_usage_from_bytes(body) else {
        return false;
    };
    if usage.total_tokens == 0 {
        return false;
    }

    let pricing = state.model_pricing_cache.get_pricing(&usage.model).await;
    let cost_nano_usd = pricing.as_ref().map(|p| {
        p.cost_nano_usd(
            usage.input_tokens,
            usage.output_tokens,
            usage.cache_read_tokens,
        )
    });

    let input_cost = pricing
        .as_ref()
        .map(|p| p.input_cost_nano_usd(usage.input_tokens, usage.cache_read_tokens))
        .unwrap_or(0);
    let output_cost = pricing
        .as_ref()
        .map(|p| p.output_cost_nano_usd(usage.output_tokens))
        .unwrap_or(0);

    let (instance_id, api_key_id) = api_key_ext
        .as_ref()
        .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
        .unwrap_or((None, None));

    let details = serde_json::json!({
        "input_tokens": usage.input_tokens as i64,
        "output_tokens": usage.output_tokens as i64,
        "cache_read_tokens": usage.cache_read_tokens as i64,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "request_type": "response",
    });

    let params = services::user_usage::RecordUsageParams {
        user_id,
        metric_key: services::user_usage::METRIC_KEY_LLM_TOKENS.to_string(),
        quantity: usage.total_tokens as i64,
        cost_nano_usd,
        model_id: Some(usage.model.clone()),
        instance_id,
        api_key_id,
        details: Some(details),
    };

    let result = if instance_id.is_some() {
        state
            .user_usage_service
            .record_usage_and_update_balance(params)
            .await
    } else {
        state.user_usage_service.record_usage(params).await
    };

    if let Err(e) = result {
        tracing::warn!("Failed to record usage for user_id={}: {}", user_id, e);
        return false;
    }

    if cost_nano_usd.unwrap_or(0) > 0 {
        if let Err(e) = state
            .subscription_service
            .reconcile_purchased_after_usage(user_id)
            .await
        {
            tracing::warn!(
                error = ?e,
                "Failed to reconcile purchased credits after response usage"
            );
        }
    }

    true
}

/// Collect a stream into bytes. Returns the first stream error instead of silently truncating.
async fn collect_stream_to_bytes(
    stream: impl futures::Stream<Item = Result<Bytes, reqwest::Error>>,
) -> Result<Bytes, reqwest::Error> {
    use futures::StreamExt;

    let mut collected = Vec::new();
    tokio::pin!(stream);

    while let Some(result) = stream.next().await {
        match result {
            Ok(bytes) => collected.extend_from_slice(&bytes),
            Err(e) => return Err(e),
        }
    }

    Ok(Bytes::from(collected))
}

#[cfg(test)]
mod tests {
    use super::{
        create_optional_auth_router, create_retired_stateful_router, decompress_if_encoded,
        ensure_stream_usage_options, has_only_identity_content_encoding,
        normalize_stateless_response_body, validate_proxy_path_segment,
        validate_stateless_response_body,
    };
    use axum::{body::Body, Router};
    use bytes::Bytes;
    use flate2::{write::DeflateEncoder, write::GzEncoder, write::ZlibEncoder, Compression};
    use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
    use serde_json::json;
    use std::io::Write;
    use tower::ServiceExt;

    fn headers(content_encoding: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-encoding",
            HeaderValue::from_str(content_encoding).unwrap(),
        );
        headers
    }

    #[test]
    fn stateless_responses_accept_only_identity_content_encoding() {
        let empty_headers = HeaderMap::new();
        assert!(has_only_identity_content_encoding(&empty_headers));

        let mut identity_headers = headers("identity");
        assert!(has_only_identity_content_encoding(&identity_headers));
        identity_headers.append("content-encoding", HeaderValue::from_static("IDENTITY"));
        assert!(has_only_identity_content_encoding(&identity_headers));

        let mixed_headers = headers("identity, gzip");
        assert!(!has_only_identity_content_encoding(&mixed_headers));
        let gzip_headers = headers("gzip");
        assert!(!has_only_identity_content_encoding(&gzip_headers));
    }

    async fn assert_retired_route(app: &Router, method: Method, path: &str) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("test request should be valid"),
            )
            .await
            .expect("router should not return an error");

        assert_eq!(
            response.status(),
            StatusCode::GONE,
            "unexpected route: {path}"
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[tokio::test]
    async fn retired_stateful_router_merges_optional_reads_and_catches_descendants() {
        // This is the same composition used by the application before the
        // respective optional/session authentication layers are applied.
        let app = create_optional_auth_router::<()>().merge(create_retired_stateful_router());

        assert_retired_route(&app, Method::GET, "/v1/conversations/conv_legacy").await;
        assert_retired_route(&app, Method::GET, "/v1/conversations/conv_legacy/items").await;
        assert_retired_route(&app, Method::PATCH, "/v1/conversations/conv_legacy").await;
        assert_retired_route(
            &app,
            Method::PATCH,
            "/v1/conversations/conv_legacy/unknown-child",
        )
        .await;
        assert_retired_route(&app, Method::GET, "/v1/conversations/").await;
        assert_retired_route(&app, Method::PATCH, "/v1/files/file_legacy/unknown-child").await;
        assert_retired_route(
            &app,
            Method::GET,
            "/v1/share-groups/group_legacy/unknown-child",
        )
        .await;
        assert_retired_route(&app, Method::GET, "/v1/shared-with-me/unknown-child").await;
    }

    fn gzip_encode(input: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib_encode(input: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn raw_deflate_encode(input: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_encode(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut compressor = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            compressor.write_all(input).unwrap();
        }
        out
    }

    fn zstd_encode(input: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(input, 1).unwrap()
    }

    #[test]
    fn validates_safe_proxy_path_segments() {
        for value in ["conv_abc123", "file-abc_123", "Qwen3.5-122B-A10B"] {
            assert!(
                validate_proxy_path_segment(value).is_ok(),
                "segment should be accepted: {value}"
            );
        }
    }

    #[test]
    fn rejects_proxy_path_segment_breakouts() {
        for value in [
            "",
            ".",
            "..",
            "../files",
            "..%2Ffiles",
            "%2e%2e%2ffiles",
            "%252e%252e%252ffiles",
            "abc%2Fdef",
            "abc%5Cdef",
            "abc%3Fadmin=true",
            "abc#fragment",
        ] {
            assert!(
                validate_proxy_path_segment(value).is_err(),
                "segment should be rejected: {value}"
            );
        }
    }

    #[test]
    fn stateless_responses_normalizes_store_without_author_metadata() {
        let mut body = json!({
            "model": "test-model",
            "input": "hello",
            "metadata": { "client_key": "client_value" }
        });

        normalize_stateless_response_body(&mut body).expect("stateless request should be valid");

        assert_eq!(body["store"], json!(false));
        assert_eq!(body["metadata"], json!({ "client_key": "client_value" }));
        assert!(body["metadata"].get("author_id").is_none());
        assert!(body["metadata"].get("author_name").is_none());
    }

    #[test]
    fn stateless_responses_rejects_every_cloud_stateful_feature() {
        let cases = [
            (
                json!({ "store": true }),
                "The Responses API only supports store: false.",
            ),
            (
                json!({ "conversation": "conv_legacy" }),
                "The stateless Responses API does not support conversation.",
            ),
            (
                json!({ "previous_response_id": "resp_legacy" }),
                "The stateless Responses API does not support previous_response_id.",
            ),
            (
                json!({ "background": true }),
                "The stateless Responses API does not support background.",
            ),
            (
                json!({ "input": [{ "type": "function_call_output" }] }),
                "The stateless Responses API does not support function continuation.",
            ),
            (
                json!({ "input": [{ "type": "mcp_approval_response" }] }),
                "The stateless Responses API does not support MCP approval continuation.",
            ),
            (
                json!({
                    "input": [{
                        "content": [{ "type": "input_file", "file_id": "file_legacy" }]
                    }]
                }),
                "The stateless Responses API does not support input_file.",
            ),
            (
                json!({ "tools": [{ "type": "file_search" }] }),
                "The stateless Responses API does not support file_search.",
            ),
            (
                json!({ "tools": [{ "type": "function" }] }),
                "The stateless Responses API does not support function tools because they require continuation.",
            ),
            (
                json!({ "tools": [{ "type": "code_interpreter" }] }),
                "The stateless Responses API does not support code_interpreter because it requires continuation.",
            ),
            (
                json!({ "tools": [{ "type": "computer" }] }),
                "The stateless Responses API does not support computer because it requires continuation.",
            ),
            (
                json!({ "tools": [{ "type": "mcp" }] }),
                "The stateless Responses API does not support MCP tools that require approval.",
            ),
            (
                json!({
                    "tools": [{
                        "type": "mcp",
                        "require_approval": { "never": { "tool_names": ["search"] } }
                    }]
                }),
                "The stateless Responses API does not support MCP tools that require approval.",
            ),
        ];

        for (body, expected) in cases {
            assert_eq!(
                validate_stateless_response_body(&body),
                Err(expected),
                "stateful body should be rejected: {body}"
            );
        }

        assert!(validate_stateless_response_body(&json!({
            "tools": [{ "type": "mcp", "require_approval": "never" }]
        }))
        .is_ok());
    }

    #[test]
    fn stateless_responses_require_a_json_object() {
        for body in [json!(null), json!(["not", "an", "object"]), json!("text")] {
            assert_eq!(
                validate_stateless_response_body(&body),
                Err("The stateless Responses API requires a JSON object body."),
                "non-object body should be rejected: {body}"
            );
        }
    }

    #[test]
    fn streaming_chat_requests_enable_usage_options() {
        let mut body = json!({
            "model": "ironclaw-model",
            "stream": true,
            "messages": [{"role": "user", "content": "Hello"}]
        });

        assert!(ensure_stream_usage_options(&mut body));
        assert_eq!(
            body["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn streaming_chat_requests_preserve_existing_stream_options() {
        let mut body = json!({
            "model": "ironclaw-model",
            "stream": true,
            "stream_options": {
                "chunk_size": 3,
                "include_usage": false
            }
        });

        assert!(ensure_stream_usage_options(&mut body));
        assert_eq!(
            body["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(body["stream_options"]["chunk_size"], json!(3));
    }

    #[test]
    fn non_streaming_chat_requests_do_not_add_usage_options() {
        let mut body = json!({
            "model": "ironclaw-model",
            "stream": false
        });

        assert!(!ensure_stream_usage_options(&mut body));
        assert!(body.get("stream_options").is_none());
    }

    #[test]
    fn keeps_unencoded_bytes_without_copy() {
        let bytes = Bytes::from_static(b"{\"ok\":true}");
        let ptr = bytes.as_ptr();
        let out = decompress_if_encoded(bytes, &HeaderMap::new()).unwrap();
        assert_eq!(out.as_ref(), b"{\"ok\":true}");
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn decodes_gzip() {
        let payload = br#"{"a":1}"#;
        let encoded = gzip_encode(payload);
        let out = decompress_if_encoded(Bytes::from(encoded), &headers("gzip")).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn decodes_brotli() {
        let payload = br#"{"b":"brotli"}"#;
        let encoded = brotli_encode(payload);
        let out = decompress_if_encoded(Bytes::from(encoded), &headers("br")).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn decodes_zstd() {
        let payload = br#"{"z":"std"}"#;
        let encoded = zstd_encode(payload);
        let out = decompress_if_encoded(Bytes::from(encoded), &headers("zstd")).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn decodes_deflate_with_zlib_wrapper() {
        let payload = br#"{"wrapped":true}"#;
        let encoded = zlib_encode(payload);
        let out = decompress_if_encoded(Bytes::from(encoded), &headers("deflate")).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn decodes_deflate_raw_fallback() {
        let payload = br#"{"raw":true}"#;
        assert_ne!(raw_deflate_encode(payload), zlib_encode(payload));
        let encoded = raw_deflate_encode(payload);
        let out = decompress_if_encoded(Bytes::from(encoded), &headers("deflate")).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn decodes_multiple_encodings_in_reverse_order() {
        let payload = br#"{"stack":"ok"}"#;
        let gzip_then_br = brotli_encode(&gzip_encode(payload));
        let out = decompress_if_encoded(Bytes::from(gzip_then_br), &headers("gzip, br")).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn skips_identity_encoding_without_copy() {
        let bytes = Bytes::from_static(b"{\"identity\":true}");
        let ptr = bytes.as_ptr();
        let out = decompress_if_encoded(bytes, &headers("identity")).unwrap();
        assert_eq!(out.as_ref(), b"{\"identity\":true}");
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn unsupported_encoding_returns_original() {
        let bytes = Bytes::from_static(b"{\"unknown\":true}");
        let out = decompress_if_encoded(bytes, &headers("snappy")).unwrap();
        assert_eq!(out.as_ref(), b"{\"unknown\":true}");
    }

    #[test]
    fn malformed_encoding_header_returns_original() {
        let bytes = Bytes::from_static(b"{\"ok\":1}");
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "content-encoding",
            HeaderValue::from_bytes(&[0x80, 0x81]).unwrap(),
        );
        let out = decompress_if_encoded(bytes, &hdrs).unwrap();
        assert_eq!(out.as_ref(), b"{\"ok\":1}");
    }
}
