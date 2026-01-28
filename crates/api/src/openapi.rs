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
        crate::routes::passkey::begin_registration,
        crate::routes::passkey::finish_registration,
        crate::routes::passkey::begin_authentication,
        crate::routes::passkey::finish_authentication,
        crate::routes::oauth::logout,
        // User endpoints
        crate::routes::users::get_current_user,
        crate::routes::users::list_my_passkeys,
        crate::routes::users::delete_my_passkey,
        // Conversation endpoints (with optional authentication)
        crate::routes::api::get_conversation,
        crate::routes::api::list_conversation_items,
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
        crate::routes::passkey::BeginAuthenticationRequest,
        crate::routes::passkey::BeginRegistrationResponse,
        crate::routes::passkey::BeginAuthenticationResponse,
        crate::routes::passkey::FinishRegistrationRequest,
        crate::routes::passkey::FinishRegistrationResponse,
        crate::routes::passkey::FinishAuthenticationRequest,
        crate::routes::passkey::FinishAuthenticationResponse,
        // User settings models
        crate::models::UserSettingsResponse,
        crate::models::UpdateUserSettingsPartiallyRequest,
        crate::models::UpdateUserSettingsRequest,
        // Passkey management models
        crate::routes::users::PasskeySummaryResponse,
        crate::routes::users::PasskeyListResponse,
        // Model settings / model admin models
        crate::models::ModelResponse,
        crate::models::ModelListResponse,
        crate::models::BatchUpsertModelsRequest,
        crate::models::UpdateModelRequest,
        // System configs models
        crate::models::SystemConfigsResponse,
        crate::models::UpsertSystemConfigsRequest,
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
