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
        // Auth endpoints
        crate::routes::oauth::google_login,
        crate::routes::oauth::github_login,
        crate::routes::oauth::oauth_callback,
        crate::routes::oauth::logout,
        // User endpoints
        crate::routes::users::get_current_user,
        // Admin endpoints
        crate::routes::admin::list_users,
        crate::routes::users::get_user_settings,
        crate::routes::users::update_user_settings_partially,
        crate::routes::users::update_user_settings,
        // Attestation endpoints
        crate::routes::attestation::get_attestation_report,
    ),
    components(schemas(
        // Request/Response models
        crate::models::UserResponse,
        crate::models::UserListResponse,
        crate::models::LinkedAccountResponse,
        crate::models::UserProfileResponse,
        crate::models::AuthResponse,
        crate::error::ApiErrorResponse,
        // User settings models
        crate::models::UserSettingsResponse,
        crate::models::UpdateUserSettingsPartiallyRequest,
        crate::models::UpdateUserSettingsRequest,
        // Attestation models
        crate::models::ApiGatewayAttestation,
        crate::models::ModelAttestation,
        crate::models::CombinedAttestationReport,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Auth", description = "OAuth authentication endpoints"),
        (name = "Users", description = "User profile management endpoints"),
        (name = "Admin", description = "Admin management endpoints"),
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
