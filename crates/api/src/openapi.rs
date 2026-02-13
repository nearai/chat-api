use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::OpenApi;

/// OpenAPI documentation configuration
#[derive(OpenApi)]
#[openapi(
    info(
        title = "NEAR AI Chat API",
        description = "A comprehensive chat API for Private Chat.",
        version = "1.0.0",
        contact(name = "NEAR AI Team", email = "support@near.ai"),
        license(name = "MIT",)
    ),
    paths(
        // Health endpoint
        crate::routes::health_check,
        // Auth endpoints
        crate::routes::oauth::google_login,
        crate::routes::oauth::github_login,
        crate::routes::oauth::oauth_callback,
        crate::routes::oauth::near_auth,
        crate::routes::oauth::logout,
        // User endpoints
        crate::routes::users::get_current_user,
        // Conversation endpoints
        crate::routes::api::create_conversation,
        crate::routes::api::list_conversations,
        crate::routes::api::get_conversation,
        crate::routes::api::update_conversation,
        crate::routes::api::delete_conversation,
        crate::routes::api::create_conversation_share,
        crate::routes::api::list_conversation_shares,
        crate::routes::api::delete_conversation_share,
        crate::routes::api::create_conversation_items,
        crate::routes::api::list_conversation_items,
        crate::routes::api::pin_conversation,
        crate::routes::api::unpin_conversation,
        crate::routes::api::archive_conversation,
        crate::routes::api::unarchive_conversation,
        crate::routes::api::clone_conversation,
        // Share group endpoints
        crate::routes::api::create_share_group,
        crate::routes::api::list_share_groups,
        crate::routes::api::update_share_group,
        crate::routes::api::delete_share_group,
        crate::routes::api::list_shared_with_me,
        // File endpoints
        crate::routes::api::upload_file,
        crate::routes::api::list_files,
        crate::routes::api::get_file,
        crate::routes::api::delete_file,
        crate::routes::api::get_file_content,
        // Proxy endpoints
        crate::routes::api::proxy_responses,
        crate::routes::api::proxy_chat_completions,
        crate::routes::api::proxy_image_generations,
        crate::routes::api::proxy_image_edits,
        crate::routes::api::proxy_models,
        crate::routes::api::proxy_model_list,
        crate::routes::api::proxy_signature,
        // Subscription endpoints
        crate::routes::subscriptions::create_subscription,
        crate::routes::subscriptions::cancel_subscription,
        crate::routes::subscriptions::list_plans,
        crate::routes::subscriptions::list_subscriptions,
        // Admin endpoints
        crate::routes::admin::list_users,
        crate::routes::admin::list_models,
        crate::routes::admin::batch_upsert_models,
        crate::routes::admin::delete_model,
        crate::routes::admin::revoke_vpc_credentials,
        crate::routes::admin::upsert_system_configs,
        crate::routes::admin::get_system_configs_admin,
        // Configs endpoints
        crate::routes::configs::get_system_configs,
        crate::routes::users::get_user_settings,
        crate::routes::users::update_user_settings_partially,
        crate::routes::users::update_user_settings,
        // Attestation endpoints
        crate::routes::attestation::get_attestation_report,
    ),
    components(schemas(
        // Request/Response models
        crate::routes::HealthResponse,
        crate::models::UserResponse,
        crate::models::UserListResponse,
        crate::models::LinkedAccountResponse,
        crate::models::UserProfileResponse,
        crate::models::AuthResponse,
        crate::error::ApiErrorResponse,
        // Auth request models
        crate::routes::oauth::LogoutRequest,
        crate::routes::oauth::NearAuthRequest,
        crate::routes::oauth::NearAuthResponse,
        // User settings models
        crate::models::UserSettingsResponse,
        crate::models::UpdateUserSettingsPartiallyRequest,
        crate::models::UpdateUserSettingsRequest,
        // Model settings / model admin models
        crate::models::ModelResponse,
        crate::models::ModelListResponse,
        crate::models::BatchUpsertModelsRequest,
        crate::models::UpdateModelRequest,
        // System configs models
        crate::models::SystemConfigsResponse,
        crate::models::UpsertSystemConfigsRequest,
        // Conversation share models
        crate::routes::api::ErrorResponse,
        crate::routes::api::ShareRecipientPayload,
        crate::routes::api::ShareTargetPayload,
        crate::routes::api::CreateConversationShareRequest,
        crate::routes::api::ConversationShareResponse,
        crate::routes::api::OwnerInfo,
        crate::routes::api::ConversationSharesListResponse,
        // Share group models
        crate::routes::api::CreateShareGroupRequest,
        crate::routes::api::UpdateShareGroupRequest,
        crate::routes::api::ShareGroupResponse,
        crate::routes::api::SharedConversationInfo,
        // File models
        crate::models::FileListResponse,
        crate::models::FileGetResponse,
        crate::routes::api::ListFilesParams,
        // Subscription models
        crate::routes::subscriptions::CreateSubscriptionRequest,
        crate::routes::subscriptions::CreateSubscriptionResponse,
        crate::routes::subscriptions::CancelSubscriptionResponse,
        crate::routes::subscriptions::ListSubscriptionsResponse,
        crate::routes::subscriptions::ListPlansResponse,
        services::subscription::ports::SubscriptionWithPlan,
        services::subscription::ports::SubscriptionPlan,
        // Attestation models
        crate::models::ApiGatewayAttestation,
        crate::models::ModelAttestation,
        crate::models::CombinedAttestationReport,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Health check and service status endpoints"),
        (name = "Auth", description = "OAuth authentication endpoints"),
        (name = "Users", description = "User profile management endpoints"),
        (name = "Conversations", description = "Conversation management endpoints (supports optional authentication for public sharing)"),
        (name = "Share Groups", description = "Share group management endpoints"),
        (name = "Files", description = "File management endpoints"),
        (name = "Proxy", description = "Proxy endpoints for OpenAI-compatible APIs"),
        (name = "Subscriptions", description = "Subscription management endpoints for Stripe integration"),
        (name = "Admin", description = "Admin management endpoints"),
        (name = "Configs", description = "System configuration endpoints"),
        (name = "attestation", description = "Attestation reporting endpoints for TEE verification")
    )
)]
pub struct ApiDoc;

/// Security scheme addon for Bearer token authentication
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "session_token",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("session_token")
                        .description(Some("Session token obtained from OAuth authentication"))
                        .build(),
                ),
            )
        }
    }
}
