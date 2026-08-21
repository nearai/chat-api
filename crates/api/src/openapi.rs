use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::OpenApi;

/// OpenAPI documentation configuration
#[derive(OpenApi)]
#[openapi(
    info(
        title = "NEAR AI Chat API",
        description = "An authenticated OpenAI-compatible inference proxy with temporary read-only Private Chat views for migration and export.",
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
        crate::routes::users::get_user_status,
        crate::routes::users::delete_current_user,
        crate::routes::users::get_my_usage,
        // Temporary Stage I owner-only Conversation endpoints
        crate::routes::api::list_conversations,
        crate::routes::api::get_conversation,
        crate::routes::api::list_conversation_items,
        // Temporary Stage I read-only File endpoints
        crate::routes::api::list_files,
        crate::routes::api::get_file,
        crate::routes::api::get_file_content,
        // Proxy endpoints
        crate::routes::api::proxy_responses,
        crate::routes::api::proxy_chat_completions,
        crate::routes::api::proxy_image_generations,
        crate::routes::api::proxy_image_edits,
        crate::routes::api::proxy_models,
        crate::routes::api::proxy_model_list,
        crate::routes::api::proxy_signature,
        // Credits endpoints
        crate::routes::credits::get_credits,
        crate::routes::credits::create_credit_checkout,
        crate::routes::credits::confirm_credit_purchase,
        // Subscription endpoints
        crate::routes::subscriptions::create_subscription,
        crate::routes::subscriptions::create_portal_session,
        crate::routes::subscriptions::cancel_subscription,
        crate::routes::subscriptions::resume_subscription,
        crate::routes::subscriptions::change_plan,
        crate::routes::subscriptions::list_plans,
        crate::routes::subscriptions::list_subscriptions,
        crate::routes::subscriptions::sync_near_staking_subscription,
        // Admin endpoints
        crate::routes::admin::list_users,
        crate::routes::admin::list_models,
        crate::routes::admin::batch_upsert_models,
        crate::routes::admin::delete_model,
        crate::routes::admin::revoke_vpc_credentials,
        crate::routes::admin::upsert_system_configs,
        crate::routes::admin::get_system_configs_admin,
        crate::routes::admin::get_usage_by_user_id,
        crate::routes::admin::get_top_usage,
        crate::routes::admin::admin_set_user_subscription,
        crate::routes::admin::admin_cancel_user_subscriptions,
        crate::routes::admin::admin_list_aml_reports,
        crate::routes::admin::admin_list_aml_allowlist,
        crate::routes::admin::admin_add_aml_allowlist_entry,
        crate::routes::admin::admin_remove_aml_allowlist_entry,
        crate::routes::admin::admin_set_aml_report_active,
        // Configs endpoints
        crate::routes::configs::get_system_configs,
        crate::routes::users::get_user_settings,
        crate::routes::users::update_user_settings_partially,
        crate::routes::users::update_user_settings,
        // Attestation endpoints
        crate::routes::attestation::get_attestation_report,
        // Agent endpoints
        crate::routes::agents::create_instance,
        crate::routes::agents::list_instances,
        crate::routes::agents::get_instance,
        crate::routes::admin::admin_list_all_instances,
        crate::routes::admin::admin_create_instance,
        crate::routes::admin::admin_delete_instance,
        crate::routes::admin::admin_start_instance,
        crate::routes::admin::admin_stop_instance,
        crate::routes::admin::admin_restart_instance,
        crate::routes::admin::admin_grant_instance_owner,
        crate::routes::admin::admin_sync_agent_status,
        crate::routes::admin::bi_list_users,
        crate::routes::admin::bi_users_summary,
        crate::routes::admin::bi_list_deployments,
        crate::routes::admin::bi_deployment_summary,
        crate::routes::admin::bi_status_history,
        crate::routes::admin::bi_usage,
        crate::routes::admin::bi_top_consumers,
        crate::routes::admin::admin_list_account_deletions,
        crate::routes::admin::admin_retry_account_deletion,
        crate::routes::agents::start_instance,
        crate::routes::agents::stop_instance,
        crate::routes::agents::restart_instance,
        crate::routes::agents::upgrade_instance,
        crate::routes::agents::check_upgrade_available,
        crate::routes::admin::admin_get_instance_config,
        crate::routes::admin::admin_patch_instance_config,
        crate::routes::admin::admin_create_backup,
        crate::routes::admin::admin_list_backups,
        crate::routes::admin::admin_get_backup,
        crate::routes::admin::admin_create_unbound_api_key,
        crate::routes::admin::admin_bind_api_key_to_instance,
        crate::routes::agents::create_api_key,
        crate::routes::agents::list_api_keys,
        crate::routes::agents::revoke_api_key,
        crate::routes::agents::get_instance_usage,
        crate::routes::agents::get_instance_balance,
    ),
    components(schemas(
        // Request/Response models
        crate::routes::admin::InstanceComposeConfig,
        crate::routes::HealthResponse,
        crate::models::UserResponse,
        crate::models::UserListResponse,
        crate::models::AdminUserResponse,
        crate::models::AdminUserListResponse,
        crate::models::LinkedAccountResponse,
        crate::models::UserProfileResponse,
        crate::models::UserAccountDeletionResponse,
        crate::routes::users::UserStatusResponse,
        services::user::ports::AccountDeletion,
        services::user::ports::AccountDeletionStatus,
        crate::routes::admin::AdminRetryAccountDeletionResponse,
        crate::routes::admin::GrantInstanceOwnerResponse,
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
        crate::models::AdminSetSubscriptionRequest,
        // Admin usage models (UserUsageResponse shared with /users/me/usage)
        crate::models::UserUsageResponse,
        crate::routes::admin::TopUsageResponse,
        crate::routes::api::ErrorResponse,
        // Temporary owner-only Conversation models
        // Temporary read-only File models
        crate::models::FileListResponse,
        crate::models::FileGetResponse,
        crate::routes::api::ListFilesParams,
        // Credits models
        crate::routes::credits::CreateCreditCheckoutRequest,
        crate::routes::credits::CreateCreditCheckoutResponse,
        crate::routes::credits::ConfirmCreditPurchaseRequest,
        services::subscription::ports::CreateCreditPurchaseOutcome,
        services::subscription::ports::CreditsSummary,
        // Subscription models
        crate::routes::subscriptions::CreateSubscriptionRequest,
        crate::routes::subscriptions::CreateSubscriptionResponse,
        crate::routes::subscriptions::CreatePortalSessionRequest,
        crate::routes::subscriptions::CreatePortalSessionResponse,
        crate::routes::subscriptions::CancelSubscriptionResponse,
        crate::routes::subscriptions::ResumeSubscriptionResponse,
        crate::routes::subscriptions::ChangePlanRequest,
        crate::routes::subscriptions::ChangePlanResponse,
        services::subscription::ports::ChangePlanOutcome,
        crate::routes::subscriptions::ListSubscriptionsResponse,
        crate::routes::subscriptions::ListPlansResponse,
        services::subscription::ports::NearStakingSyncSummary,
        services::subscription::ports::SubscriptionWithPlan,
        services::subscription::ports::SubscriptionPlan,
        services::aml::AmlCheckResult,
        services::aml::AmlRiskLevel,
        crate::routes::admin::AdminAmlReportResponse,
        crate::routes::admin::AdminAmlReportsResponse,
        crate::routes::admin::AdminAmlAllowlistEntryResponse,
        crate::routes::admin::AdminAmlAllowlistResponse,
        crate::routes::admin::AdminAmlAllowlistRequest,
        crate::routes::admin::AdminAmlReportStatusRequest,
        // Attestation models
        crate::models::ApiGatewayAttestation,
        crate::models::ModelAttestation,
        crate::models::CombinedAttestationReport,
        // Agent models
        crate::models::InstanceResponse,
        crate::routes::agents::CreateInstanceRequest,
        crate::routes::admin::AdminCreateInstanceRequest,
        crate::routes::admin::AdminCreateApiKeyRequest,
        crate::models::CreateApiKeyRequest,
        crate::models::CreateApiKeyResponse,
        crate::models::BindApiKeyRequest,
        crate::models::ApiKeyResponse,
        crate::routes::admin::SyncAgentStatusResponse,
        crate::models::UsageResponse,
        crate::models::BalanceResponse,
        crate::models::UsageQueryParams,
        crate::routes::agents::UpgradeAvailabilityResponse,
        // BI metrics (admin)
        crate::routes::admin::BiDeploymentQuery,
        crate::routes::admin::BiSummaryQuery,
        crate::routes::admin::BiUsageQuery,
        crate::routes::admin::BiTopConsumersQuery,
        crate::routes::admin::BiStatusHistoryQuery,
        crate::routes::admin::BiDeploymentListResponse,
        crate::routes::admin::BiUsageResponse,
        crate::routes::admin::BiTopConsumersResponse,
        crate::routes::admin::BiStatusHistoryResponse,
        services::bi_metrics::UserSummary,
        services::bi_metrics::UserSummaryPlanCount,
        services::bi_metrics::UserSummaryAgentCountBucket,
        services::bi_metrics::DeploymentRecord,
        services::bi_metrics::DeploymentStatusCount,
        services::bi_metrics::DeploymentSummary,
        services::bi_metrics::StatusChangeRecord,
        services::bi_metrics::UsageAggregation,
        services::bi_metrics::UsageGroupBy,
        services::bi_metrics::UsageRankBy,
        services::bi_metrics::TopConsumerGroupBy,
        services::bi_metrics::TopConsumer,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Health check and service status endpoints"),
        (name = "Auth", description = "OAuth authentication endpoints"),
        (name = "Users", description = "User profile management endpoints"),
        (name = "Conversations", description = "Temporary owner-only Conversation views for migration/export. Conversation sharing and all mutations return 410 Gone."),
        (name = "Files", description = "Temporary owner-only File views for migration/export. File mutations and unsupported legacy paths return 410 Gone."),
        (name = "Proxy", description = "Proxy endpoints for OpenAI-compatible APIs"),
        (name = "Credits", description = "Credit purchase and balance endpoints"),
        (name = "Subscriptions", description = "Subscription management endpoints"),
        (name = "Agents", description = "Agent instance management endpoints"),
        (name = "Admin", description = "Admin management endpoints"),
        (name = "Configs", description = "System configuration endpoints"),
        (name = "Attestation", description = "Attestation reporting endpoints for TEE verification")
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

#[cfg(test)]
mod tests {
    use super::ApiDoc;
    use utoipa::OpenApi;

    #[test]
    fn documents_owner_only_views_but_not_stateful_or_sharing_surfaces() {
        let spec = serde_json::to_value(ApiDoc::openapi()).expect("OpenAPI serialization");

        for path in [
            "/v1/conversations",
            "/v1/conversations/{conversation_id}",
            "/v1/conversations/{conversation_id}/items",
            "/v1/files",
            "/v1/files/{file_id}",
            "/v1/files/{file_id}/content",
        ] {
            assert!(
                spec["paths"].get(path).is_some(),
                "temporary read path {path} must be in OpenAPI"
            );
        }

        for path in [
            "/v1/conversations/{conversation_id}/shares",
            "/v1/conversations/{conversation_id}/shares/{share_id}",
            "/v1/conversations/{conversation_id}/pin",
            "/v1/conversations/{conversation_id}/archive",
            "/v1/conversations/{conversation_id}/clone",
            "/v1/share-groups",
            "/v1/share-groups/{group_id}",
            "/v1/shared-with-me",
        ] {
            assert!(
                spec["paths"].get(path).is_none(),
                "disabled stateful or sharing path {path} must not be in OpenAPI"
            );
        }
    }
}
