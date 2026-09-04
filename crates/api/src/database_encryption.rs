use crate::{middleware::AuthenticatedUser, state::AppState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::OnceLock;
use tokio::sync::Semaphore;
use uuid::Uuid;

const MAX_BATCH_BYTES: i64 = 8 * 1024 * 1024;
const WORKER_LOCK: i64 = 0x4e45415243484154;
static WORKER: OnceLock<Semaphore> = OnceLock::new();

fn worker() -> &'static Semaphore {
    WORKER.get_or_init(|| Semaphore::new(1))
}

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Json,
}

#[derive(Clone, Copy)]
struct Field {
    table: &'static str,
    column: &'static str,
    id_column: &'static str,
    kind: Kind,
    reason: &'static str,
    token: Option<(&'static str, &'static str)>,
}

const FIELDS: &[Field] = &[
    Field {
        table: "files",
        column: "filename",
        id_column: "encryption_id",
        kind: Kind::Text,
        reason: "User-provided file metadata",
        token: None,
    },
    Field {
        table: "conversation_share_groups",
        column: "name",
        id_column: "id",
        kind: Kind::Text,
        reason: "User-created share group name",
        token: Some(("name_search_token", "conversation_share_groups.name")),
    },
    Field {
        table: "conversation_share_group_members",
        column: "member_value",
        id_column: "id",
        kind: Kind::Text,
        reason: "Share recipient identity",
        token: Some((
            "member_value_search_token",
            "conversation_share_group_members.member_value",
        )),
    },
    Field {
        table: "conversation_shares",
        column: "recipient_value",
        id_column: "id",
        kind: Kind::Text,
        reason: "Share recipient identity",
        token: Some((
            "recipient_value_search_token",
            "conversation_shares.recipient_value",
        )),
    },
    Field {
        table: "conversation_shares",
        column: "org_email_pattern",
        id_column: "id",
        kind: Kind::Text,
        reason: "Organization sharing domain",
        token: Some(("org_domain_search_token", "conversation_shares.org_domain")),
    },
    Field {
        table: "user_activity_log",
        column: "metadata",
        id_column: "id",
        kind: Kind::Json,
        reason: "Conversation/file activity metadata",
        token: None,
    },
    Field {
        table: "oauth_tokens",
        column: "access_token",
        id_column: "id",
        kind: Kind::Text,
        reason: "OAuth access credential",
        token: None,
    },
    Field {
        table: "oauth_tokens",
        column: "refresh_token",
        id_column: "id",
        kind: Kind::Text,
        reason: "OAuth refresh credential",
        token: None,
    },
    Field {
        table: "agent_instances",
        column: "instance_token",
        id_column: "id",
        kind: Kind::Text,
        reason: "Agent credential",
        token: None,
    },
    Field {
        table: "agent_instances",
        column: "auth_session_token",
        id_column: "id",
        kind: Kind::Text,
        reason: "Agent session credential",
        token: None,
    },
    Field {
        table: "agent_instances",
        column: "instance_url",
        id_column: "id",
        kind: Kind::Text,
        reason: "Private agent service URL",
        token: None,
    },
    Field {
        table: "agent_instances",
        column: "dashboard_url",
        id_column: "id",
        kind: Kind::Text,
        reason: "Private agent dashboard URL",
        token: None,
    },
    Field {
        table: "user_passkey_credentials",
        column: "auth_secret",
        id_column: "user_id",
        kind: Kind::Text,
        reason: "Passkey credential",
        token: None,
    },
    Field {
        table: "user_passkey_credentials",
        column: "backup_passphrase",
        id_column: "user_id",
        kind: Kind::Text,
        reason: "Passkey recovery credential",
        token: None,
    },
];

const APPROVED: &[(&str, &str, &str)] = &[
    (
        "conversations",
        "id",
        "Opaque protocol identifier; authorization is enforced independently and primary-key migration cost outweighs correlation benefit",
    ),
    (
        "files",
        "id",
        "Opaque protocol identifier; authorization is enforced independently and primary-key migration cost outweighs correlation benefit",
    ),
    (
        "conversation_shares",
        "conversation_id",
        "Required relationship to the approved opaque conversation identifier",
    ),
    ("conversations", "user_id", "Required relationship key"),
    ("files", "user_id", "Required relationship key"),
    ("files", "purpose", "Queryable protocol enum"),
    (
        "conversation_share_group_members",
        "member_type",
        "Queryable recipient-type enum",
    ),
    (
        "conversation_shares",
        "share_type",
        "Queryable sharing enum",
    ),
    (
        "conversation_shares",
        "permission",
        "Queryable permission enum",
    ),
    (
        "conversation_shares",
        "recipient_type",
        "Queryable recipient-type enum",
    ),
    (
        "user_activity_log",
        "activity_type",
        "Queryable analytics event enum",
    ),
    (
        "user_activity_log",
        "auth_method",
        "Queryable authentication-method enum",
    ),
    (
        "database_encryption_jobs",
        "mode",
        "Operational migration state",
    ),
    (
        "database_encryption_jobs",
        "status",
        "Operational migration state",
    ),
    ("database_encryption_jobs", "scope", "Field names only"),
    (
        "database_encryption_jobs",
        "actions",
        "Operational migration state",
    ),
    (
        "database_encryption_jobs",
        "cursor",
        "Internal UUID cursor only",
    ),
    (
        "database_encryption_jobs",
        "progress",
        "Aggregate migration counts",
    ),
    (
        "database_encryption_jobs",
        "last_error_class",
        "Redacted error class",
    ),
    (
        "database_encryption_jobs",
        "last_error_message",
        "Redacted error class only",
    ),
    ("conversations", "created_at", "Operational timestamp"),
    ("conversations", "updated_at", "Operational timestamp"),
    ("files", "bytes", "Operational size counter"),
    ("files", "file_created_at", "Provider timestamp"),
    ("files", "file_expires_at", "Provider timestamp"),
    ("files", "created_at", "Operational timestamp"),
    ("files", "updated_at", "Operational timestamp"),
    ("files", "encryption_id", "Internal encryption context UUID"),
    (
        "conversation_share_groups",
        "id",
        "Internal relationship UUID",
    ),
    (
        "conversation_share_groups",
        "owner_user_id",
        "Required relationship key",
    ),
    (
        "conversation_share_groups",
        "created_at",
        "Operational timestamp",
    ),
    (
        "conversation_share_groups",
        "updated_at",
        "Operational timestamp",
    ),
    (
        "conversation_share_groups",
        "name_search_token",
        "Non-reversible keyed lookup token",
    ),
    (
        "conversation_share_group_members",
        "id",
        "Internal relationship UUID",
    ),
    (
        "conversation_share_group_members",
        "group_id",
        "Required relationship key",
    ),
    (
        "conversation_share_group_members",
        "created_at",
        "Operational timestamp",
    ),
    (
        "conversation_share_group_members",
        "member_value_search_token",
        "Non-reversible keyed lookup token",
    ),
    ("conversation_shares", "id", "Internal relationship UUID"),
    (
        "conversation_shares",
        "owner_user_id",
        "Required relationship key",
    ),
    (
        "conversation_shares",
        "group_id",
        "Required relationship key",
    ),
    ("conversation_shares", "created_at", "Operational timestamp"),
    ("conversation_shares", "updated_at", "Operational timestamp"),
    (
        "conversation_shares",
        "recipient_value_search_token",
        "Non-reversible keyed lookup token",
    ),
    (
        "conversation_shares",
        "org_domain_search_token",
        "Non-reversible keyed lookup token",
    ),
    ("user_activity_log", "id", "Internal event UUID"),
    ("user_activity_log", "user_id", "Required relationship key"),
    ("user_activity_log", "created_at", "Operational timestamp"),
    ("database_encryption_jobs", "id", "Internal job UUID"),
    (
        "database_encryption_jobs",
        "batch_size",
        "Operational batch limit",
    ),
    (
        "database_encryption_jobs",
        "max_rows",
        "Operational row limit",
    ),
    (
        "database_encryption_jobs",
        "admin_actor",
        "Administrative audit relationship",
    ),
    (
        "database_encryption_jobs",
        "created_at",
        "Operational timestamp",
    ),
    (
        "database_encryption_jobs",
        "started_at",
        "Operational timestamp",
    ),
    (
        "database_encryption_jobs",
        "completed_at",
        "Operational timestamp",
    ),
    (
        "database_encryption_jobs",
        "cancel_requested_at",
        "Operational timestamp",
    ),
];

const SENSITIVE_FIELDS: &[(&str, &str, &str)] = &[
    (
        "users",
        "email",
        "PII and equality lookup; encrypt with keyed token",
    ),
    ("users", "name", "User profile PII"),
    ("users", "avatar_url", "User profile URL"),
    (
        "oauth_accounts",
        "provider_user_id",
        "External identity; encrypt with keyed token",
    ),
    (
        "oauth_states",
        "state",
        "Authentication secret; replace lookup with keyed token",
    ),
    (
        "oauth_states",
        "redirect_uri",
        "User-controlled authentication URL",
    ),
    (
        "oauth_states",
        "frontend_callback",
        "User-controlled callback URL",
    ),
    ("user_settings", "content", "Arbitrary user settings JSON"),
    (
        "app_config",
        "value",
        "Application configuration may contain secrets",
    ),
    ("user_bans", "reason", "Free-form account enforcement data"),
    (
        "models",
        "settings",
        "Arbitrary administrative configuration JSON",
    ),
    (
        "system_configs",
        "value",
        "Arbitrary administrative configuration JSON",
    ),
    (
        "user_usage_event",
        "details",
        "Arbitrary usage metadata JSON",
    ),
    (
        "stripe_customers",
        "customer_id",
        "External billing identity; encrypt with keyed token",
    ),
    (
        "subscriptions",
        "subscription_id",
        "External billing identifier; encrypt with keyed token",
    ),
    (
        "subscriptions",
        "customer_id",
        "External billing identity; encrypt with keyed token",
    ),
    (
        "house_of_stake_credit_entitlement_snapshots",
        "subscription_id",
        "External billing identifier; replace with internal relationship key",
    ),
    (
        "credit_transactions",
        "reference_id",
        "External billing transaction identifier",
    ),
    (
        "payment_webhooks",
        "event_id",
        "External billing event identifier; encrypt with keyed token",
    ),
    ("payment_webhooks", "payload", "Raw billing webhook payload"),
    (
        "agent_instances",
        "instance_id",
        "External agent identifier; encrypt with keyed token",
    ),
    ("agent_instances", "name", "User-provided agent name"),
    (
        "agent_instances",
        "public_ssh_key",
        "User credential material",
    ),
    (
        "agent_instances",
        "agent_api_base_url",
        "Private service URL",
    ),
    ("agent_api_keys", "name", "User-provided credential label"),
    (
        "agent_instance_status_history",
        "change_reason",
        "Free-form audit text",
    ),
    (
        "email_verification_challenges",
        "email",
        "PII and equality lookup; encrypt with keyed token",
    ),
    ("email_verification_challenges", "ip_address", "Network PII"),
    (
        "email_verification_challenges",
        "provider_message_id",
        "External message identifier",
    ),
    (
        "user_account_deletions",
        "last_error",
        "Free-form error text may contain PII",
    ),
    (
        "user_account_deletions",
        "progress",
        "Arbitrary deletion workflow JSON",
    ),
    (
        "aml_risk_reports",
        "account_id",
        "Financial account identity; encrypt with keyed token",
    ),
    (
        "aml_risk_reports",
        "provider_report_id",
        "External AML report identifier",
    ),
    (
        "aml_risk_reports",
        "reason",
        "Sensitive AML decision detail",
    ),
    ("aml_risk_reports", "result", "Raw AML provider result"),
    (
        "aml_account_allowlist",
        "account_id",
        "Financial account identity; encrypt with keyed token",
    ),
    (
        "aml_account_allowlist",
        "reason",
        "Sensitive AML allowlist rationale",
    ),
];

const APPROVED_TEXT_FIELDS: &[(&str, &str)] = &[
    ("agent_api_keys", "key_hash"),
    ("agent_instances", "type"),
    ("agent_instances", "status"),
    ("agent_usage_log", "model_id"),
    ("agent_usage_log", "request_type"),
    ("agent_instance_status_history", "old_status"),
    ("agent_instance_status_history", "new_status"),
    ("aml_risk_reports", "flow"),
    ("aml_risk_reports", "provider"),
    ("aml_risk_reports", "address_type"),
    ("aml_risk_reports", "risk_level"),
    ("aml_risk_reports", "active_source"),
    ("app_config", "key"),
    ("credit_transactions", "type"),
    ("email_verification_challenges", "code_mac"),
    ("email_verification_challenges", "status"),
    (
        "house_of_stake_credit_entitlement_snapshots",
        "credited_stake_yocto",
    ),
    (
        "house_of_stake_credit_entitlement_snapshots",
        "last_observed_stake_yocto",
    ),
    ("models", "model_id"),
    ("near_used_nonces", "nonce_hex"),
    ("oauth_accounts", "provider"),
    ("oauth_states", "provider"),
    ("oauth_tokens", "provider"),
    ("payment_webhooks", "provider"),
    ("sessions", "token_hash"),
    ("subscriptions", "provider"),
    ("subscriptions", "price_id"),
    ("subscriptions", "status"),
    ("subscriptions", "pending_downgrade_target_price_id"),
    ("subscriptions", "pending_downgrade_from_price_id"),
    ("subscriptions", "pending_downgrade_status"),
    ("system_configs", "key"),
    ("user_account_deletions", "status"),
    ("user_bans", "ban_type"),
    ("user_usage_event", "metric_key"),
    ("user_usage_event", "model_id"),
];

const STRUCTURAL_TYPES: &[&str] = &[
    "uuid",
    "smallint",
    "integer",
    "bigint",
    "numeric",
    "real",
    "double precision",
    "boolean",
    "timestamp with time zone",
    "timestamp without time zone",
    "date",
    "bytea",
];

const CLASSIFIED_TABLES: &[&str] = &[
    "agent_api_keys",
    "agent_balance",
    "agent_instance_status_history",
    "agent_instances",
    "agent_usage_log",
    "aml_account_allowlist",
    "aml_risk_reports",
    "app_config",
    "conversation_share_group_members",
    "conversation_share_groups",
    "conversation_shares",
    "conversations",
    "credit_transactions",
    "database_encryption_jobs",
    "email_verification_challenges",
    "files",
    "house_of_stake_credit_entitlement_snapshots",
    "models",
    "near_used_nonces",
    "oauth_accounts",
    "oauth_states",
    "oauth_tokens",
    "payment_webhooks",
    "sessions",
    "stripe_customers",
    "subscriptions",
    "system_configs",
    "user_account_deletions",
    "user_activity_log",
    "user_bans",
    "user_credits",
    "user_passkey_credentials",
    "user_settings",
    "user_usage_event",
    "users",
];

#[derive(Default)]
struct Inventory {
    encryption_required: Vec<Value>,
    legacy_confidential: Vec<Value>,
    unclassified: Vec<Value>,
}

fn classification(
    table: &str,
    column: &str,
    data_type: &str,
) -> Option<(&'static str, &'static str)> {
    if FIELDS
        .iter()
        .any(|field| field.table == table && field.column == column)
    {
        return Some(("encrypt", "Stage I confidential field"));
    }
    if let Some((_, _, reason)) = APPROVED
        .iter()
        .find(|(known_table, known_column, _)| *known_table == table && *known_column == column)
    {
        return Some(("approved_plaintext", reason));
    }
    if table == "response_authors" || (table == "conversations" && column == "title") {
        return Some((
            "legacy_confidential",
            "Legacy conversation data must be removed or encrypted before migration",
        ));
    }
    if let Some((_, _, reason)) = SENSITIVE_FIELDS
        .iter()
        .find(|(known_table, known_column, _)| *known_table == table && *known_column == column)
    {
        return Some(("encryption_required", *reason));
    }
    if APPROVED_TEXT_FIELDS
        .iter()
        .any(|(known_table, known_column)| *known_table == table && *known_column == column)
    {
        return Some((
            "approved_plaintext",
            "Reviewed enum, identifier, hash, or numeric text",
        ));
    }
    (CLASSIFIED_TABLES.contains(&table) && STRUCTURAL_TYPES.contains(&data_type)).then_some((
        "approved_plaintext",
        "Reviewed structural or operational value",
    ))
}

async fn inventory(state: &AppState) -> anyhow::Result<Inventory> {
    let client = state.db_pool.get().await?;
    let rows = client.query("SELECT columns.table_name,columns.column_name,columns.data_type FROM information_schema.columns columns JOIN information_schema.tables tables USING(table_schema,table_name) WHERE columns.table_schema='public' AND tables.table_type='BASE TABLE' AND columns.table_name <> 'refinery_schema_history' ORDER BY columns.table_name,columns.ordinal_position", &[]).await?;
    let mut inventory = Inventory::default();
    for row in rows {
        let table: String = row.get(0);
        let column: String = row.get(1);
        let data_type: String = row.get(2);
        let (kind, reason) = classification(&table, &column, &data_type).unwrap_or((
            "unclassified",
            "No explicit sensitive or plaintext classification",
        ));
        let entry = json!({"table":table,"column":column,"data_type":data_type,"classification":kind,"reason":reason});
        match kind {
            "encryption_required" => inventory.encryption_required.push(entry),
            "legacy_confidential" => inventory.legacy_confidential.push(entry),
            "unclassified" => inventory.unclassified.push(entry),
            _ => {}
        }
    }
    Ok(inventory)
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Scope {
    #[serde(default)]
    tables: Vec<String>,
    #[serde(default)]
    fields: Vec<FieldName>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FieldName {
    table: String,
    column: String,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    scope: Scope,
    limit: Option<i64>,
    #[serde(default)]
    include_approved_plaintext: bool,
}

#[derive(Serialize)]
pub struct FieldCount {
    table: String,
    column: String,
    classification: &'static str,
    reason: &'static str,
    plaintext: i64,
    encrypted: i64,
    empty: i64,
    invalid_envelope: i64,
    scanned: i64,
    complete: bool,
}

fn bad(message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":{"code":"invalid_request","message":message.into()}})),
    )
}

fn internal(_: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(
            json!({"error":{"code":"internal_error","message":"database encryption operation failed"}}),
        ),
    )
}

fn selected(scope: &Scope) -> Result<Vec<&'static Field>, (StatusCode, Json<Value>)> {
    if scope
        .tables
        .iter()
        .any(|table| !FIELDS.iter().any(|field| field.table == table))
        || scope.fields.iter().any(|name| {
            !FIELDS
                .iter()
                .any(|field| field.table == name.table && field.column == name.column)
        })
    {
        return Err(bad("scope contains an unregistered field"));
    }
    let fields = FIELDS
        .iter()
        .filter(|field| {
            scope.tables.is_empty() && scope.fields.is_empty()
                || scope.tables.iter().any(|table| table == field.table)
                || scope
                    .fields
                    .iter()
                    .any(|name| name.table == field.table && name.column == field.column)
        })
        .collect::<Vec<_>>();
    if fields.is_empty() {
        Err(bad("scope contains no confidential fields"))
    } else {
        Ok(fields)
    }
}

async fn counts(
    state: &AppState,
    fields: &[&Field],
    limit: Option<i64>,
) -> anyhow::Result<Vec<FieldCount>> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| anyhow::anyhow!("database encryption is not configured"))?;
    let client = state.db_pool.get().await?;
    let mut result = Vec::new();
    for field in fields {
        let cap = limit.unwrap_or(i64::MAX).clamp(1, 100_000);
        let token = field
            .token
            .map(|(column, _)| column)
            .unwrap_or("NULL::bytea");
        let query = format!(
            "SELECT {id},{column}::text,{token} FROM {table} ORDER BY {id} LIMIT $1",
            id = field.id_column,
            column = field.column,
            table = field.table
        );
        let rows = client.query(&query, &[&cap]).await?;
        let total: i64 = client
            .query_one(&format!("SELECT count(*) FROM {}", field.table), &[])
            .await?
            .get(0);
        let mut count = FieldCount {
            table: field.table.into(),
            column: field.column.into(),
            classification: "encrypt",
            reason: field.reason,
            plaintext: 0,
            encrypted: 0,
            empty: 0,
            invalid_envelope: 0,
            scanned: rows.len() as i64,
            complete: rows.len() as i64 == total,
        };
        for row in rows {
            let Some(raw) = row.get::<_, Option<String>>(1) else {
                count.empty += 1;
                continue;
            };
            match serde_json::from_str::<Value>(&raw) {
                Ok(value) if database::field_encryption::is_envelope(&value) => {
                    let id: Uuid = row.get(0);
                    if database::field_encryption::decrypt(
                        &config.key,
                        &config.key_id,
                        field.table,
                        field.column,
                        id,
                        &raw,
                    )
                    .is_ok()
                        && (field.token.is_none() || row.get::<_, Option<Vec<u8>>>(2).is_some())
                    {
                        count.encrypted += 1
                    } else {
                        count.invalid_envelope += 1
                    }
                }
                _ => count.plaintext += 1,
            }
        }
        result.push(count);
    }
    Ok(result)
}

pub async fn scan(
    State(state): State<AppState>,
    Extension(_): Extension<AuthenticatedUser>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let fields = selected(&req.scope)?;
    let counts = counts(&state, &fields, req.limit).await.map_err(internal)?;
    let inventory = inventory(&state).await.map_err(internal)?;
    let totals = json!({
        "plaintext": counts.iter().map(|c| c.plaintext).sum::<i64>(),
        "encrypted": counts.iter().map(|c| c.encrypted).sum::<i64>(),
        "empty": counts.iter().map(|c| c.empty).sum::<i64>(),
        "invalid_envelope": counts.iter().map(|c| c.invalid_envelope).sum::<i64>(),
        "scanned": counts.iter().map(|c| c.scanned).sum::<i64>(),
        "complete": counts.iter().all(|c| c.complete),
    });
    Ok(Json(
        json!({"run_id":Uuid::new_v4(),"status":"completed","fields":counts,"totals":totals,"approved_plaintext":if req.include_approved_plaintext { json!(APPROVED.iter().map(|(table,column,reason)|json!({"table":table,"column":column,"classification":"approved_plaintext","reason":reason})).collect::<Vec<_>>()) } else { json!([]) },"encryption_required":inventory.encryption_required,"legacy_confidential":inventory.legacy_confidential,"unclassified":inventory.unclassified}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    DryRun,
    Execute,
    Verify,
}

#[derive(Deserialize)]
pub struct CreateJobRequest {
    mode: Mode,
    scope: Scope,
    #[serde(default = "default_batch")]
    batch_size: i64,
    max_rows: Option<i64>,
    actions: Vec<String>,
}

fn default_batch() -> i64 {
    100
}

pub async fn create_job(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedUser>,
    Json(mut req): Json<CreateJobRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| bad("database encryption is not configured"))?;
    if !(1..=1000).contains(&req.batch_size) || req.max_rows.is_some_and(|value| value <= 0) {
        return Err(bad("invalid batch_size or max_rows"));
    }
    if !matches!(req.mode, Mode::Verify)
        && req.scope.tables.is_empty()
        && req.scope.fields.is_empty()
    {
        return Err(bad("an explicit scope is required"));
    }
    if matches!(req.mode, Mode::Execute) && !config.write_enabled {
        return Err(bad("execute requires DB_ENCRYPTION_WRITE_ENABLED=true"));
    }
    let action = if matches!(req.mode, Mode::Verify) {
        "verify"
    } else {
        "encrypt"
    };
    if req.actions.as_slice() != [action] {
        return Err(bad("actions do not match mode"));
    }
    req.scope.tables.sort();
    req.scope.tables.dedup();
    req.scope.fields.sort();
    req.scope.fields.dedup();
    selected(&req.scope)?;
    let mode = match req.mode {
        Mode::DryRun => "dry_run",
        Mode::Execute => "execute",
        Mode::Verify => "verify",
    };
    let id = Uuid::new_v4();
    let scope_value = serde_json::to_value(&req.scope).map_err(internal)?;
    let actions_value = json!(req.actions);
    let client = state.db_pool.get().await.map_err(internal)?;
    client.execute("INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size,max_rows,admin_actor) VALUES($1,$2,'queued',$3,$4,$5,$6,$7)", &[&id,&mode,&scope_value,&actions_value,&req.batch_size,&req.max_rows,&admin.user_id.0]).await.map_err(internal)?;
    drop(client);
    tokio::spawn(async move {
        let Ok(_permit) = worker().acquire().await else {
            return;
        };
        if let Err(_error) = run_job(&state, id).await {
            tracing::error!(job_id=%id,error_class="database_encryption_job_failed","Database encryption job failed");
            if let Ok(client) = state.db_pool.get().await {
                let _=client.execute("UPDATE database_encryption_jobs SET status='failed',last_error_class='batch_failed',last_error_message='batch_failed',completed_at=NOW() WHERE id=$1",&[&id]).await;
            }
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"job_id":id,"status":"queued","mode":mode,"scope":scope_value,"actions":actions_value,"cursor":{},"progress":{}}),
        ),
    ))
}

async fn run_job(state: &AppState, id: Uuid) -> anyhow::Result<()> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| anyhow::anyhow!("database encryption is not configured"))?;
    let mut client = state.db_pool.get().await?;
    let Some(job)=client.query_opt("UPDATE database_encryption_jobs SET status='running',started_at=COALESCE(started_at,NOW()) WHERE id=$1 AND status IN ('queued','running') RETURNING mode,scope,batch_size,max_rows,cursor,progress",&[&id]).await? else { return Ok(()) };
    let mode: String = job.get(0);
    let scope: Scope = serde_json::from_value(job.get(1))?;
    let batch: i64 = job.get(2);
    let max: Option<i64> = job.get(3);
    let cursor: Value = job.get(4);
    let progress: Value = job.get(5);
    let fields = selected(&scope).map_err(|_| anyhow::anyhow!("invalid scope"))?;
    let mut field_index = cursor["field_index"].as_u64().unwrap_or(0) as usize;
    let mut after = cursor["after_id"]
        .as_str()
        .and_then(|v| Uuid::parse_str(v).ok())
        .unwrap_or(Uuid::nil());
    let mut processed = progress["processed"].as_i64().unwrap_or(0);
    let mut encrypted = progress["encrypted"].as_i64().unwrap_or(0);
    let mut plaintext = progress["plaintext"].as_i64().unwrap_or(0);
    let mut invalid = progress["invalid_envelopes"].as_i64().unwrap_or(0);
    while field_index < fields.len() && max.is_none_or(|limit| processed < limit) {
        let field = fields[field_index];
        let cap = max
            .map(|limit| (limit - processed).min(batch))
            .unwrap_or(batch);
        let tx = client.transaction().await?;
        tx.batch_execute("SET LOCAL statement_timeout='30s'")
            .await?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&WORKER_LOCK])
            .await?;
        if tx.query_one("SELECT cancel_requested_at IS NOT NULL FROM database_encryption_jobs WHERE id=$1 FOR UPDATE",&[&id]).await?.get::<_,bool>(0) { tx.execute("UPDATE database_encryption_jobs SET status='cancelled',completed_at=NOW() WHERE id=$1",&[&id]).await?; tx.commit().await?; return Ok(()); }
        let token = field
            .token
            .map(|(column, _)| column)
            .unwrap_or("NULL::bytea");
        let query=format!("WITH candidates AS (SELECT {id},{column}::text value,{token} search_token FROM {table} WHERE {id}>$1 AND {column} IS NOT NULL ORDER BY {id} LIMIT $2 FOR UPDATE), sized AS (SELECT *,sum(octet_length(value)) OVER(ORDER BY {id}) bytes,row_number() OVER(ORDER BY {id}) row_no FROM candidates) SELECT {id},value,search_token FROM sized WHERE bytes<=$3 OR row_no=1 ORDER BY {id}",id=field.id_column,column=field.column,table=field.table);
        let rows = tx.query(&query, &[&after, &cap, &MAX_BATCH_BYTES]).await?;
        if rows.is_empty() {
            field_index += 1;
            after = Uuid::nil();
            tx.commit().await?;
            continue;
        }
        let mut ids = Vec::new();
        let mut values = Vec::new();
        let mut tokens = Vec::new();
        for row in rows {
            let row_id: Uuid = row.get(0);
            after = row_id;
            processed += 1;
            let raw: Option<String> = row.get(1);
            let Some(raw) = raw else { continue };
            match serde_json::from_str::<Value>(&raw) {
                Ok(value) if database::field_encryption::is_envelope(&value) => {
                    if database::field_encryption::decrypt(
                        &config.key,
                        &config.key_id,
                        field.table,
                        field.column,
                        row_id,
                        &raw,
                    )
                    .is_err()
                        || (field.token.is_some() && row.get::<_, Option<Vec<u8>>>(2).is_none())
                    {
                        invalid += 1
                    }
                }
                _ if mode == "execute" => {
                    ids.push(row_id);
                    if let Some((_, domain)) = field.token {
                        let normalized = if field.column == "org_email_pattern" {
                            raw.trim()
                                .trim_start_matches('%')
                                .trim_start_matches('@')
                                .to_lowercase()
                        } else {
                            raw.trim().to_lowercase()
                        };
                        tokens.push(database::field_encryption::search_token(
                            &config.key,
                            domain,
                            &normalized,
                        )?);
                    }
                    values.push(database::field_encryption::encrypt(
                        &config.key,
                        &config.key_id,
                        field.table,
                        field.column,
                        row_id,
                        &raw,
                    )?);
                }
                _ => plaintext += 1,
            }
        }
        if mode == "execute" && !ids.is_empty() {
            let expression = match field.kind {
                Kind::Text => "batch.value",
                Kind::Json => "batch.value::jsonb",
            };
            if let Some((token_column, _)) = field.token {
                let update=format!("UPDATE {table} target SET {column}={expression},{token_column}=batch.token FROM UNNEST($1::uuid[],$2::text[],$3::bytea[]) batch(id,value,token) WHERE target.{id}=batch.id",table=field.table,column=field.column,id=field.id_column);
                encrypted += tx.execute(&update, &[&ids, &values, &tokens]).await? as i64;
            } else {
                let update=format!("UPDATE {table} target SET {column}={expression} FROM UNNEST($1::uuid[],$2::text[]) batch(id,value) WHERE target.{id}=batch.id",table=field.table,column=field.column,id=field.id_column);
                encrypted += tx.execute(&update, &[&ids, &values]).await? as i64;
            }
        }
        tx.execute("UPDATE database_encryption_jobs SET progress=$2,cursor=$3 WHERE id=$1",&[&id,&json!({"processed":processed,"encrypted":encrypted,"plaintext":plaintext,"invalid_envelopes":invalid}),&json!({"field_index":field_index,"after_id":after})]).await?;
        tx.commit().await?;
    }
    let inventory = if mode == "verify" {
        inventory(state).await?
    } else {
        Inventory::default()
    };
    let pass = mode != "verify"
        || plaintext == 0
            && invalid == 0
            && inventory.encryption_required.is_empty()
            && inventory.unclassified.is_empty()
            && inventory.legacy_confidential.is_empty();
    client.execute("UPDATE database_encryption_jobs SET status='completed',completed_at=NOW(),progress=progress||$2 WHERE id=$1",&[&id,&json!({"pass":pass,"encryption_required":inventory.encryption_required,"legacy_confidential":inventory.legacy_confidential,"unclassified":inventory.unclassified})]).await?;
    Ok(())
}

pub async fn recover_jobs(state: AppState) {
    let Ok(client) = state.db_pool.get().await else {
        return;
    };
    let Ok(rows) = client.query("UPDATE database_encryption_jobs SET status='queued' WHERE status='running' RETURNING id", &[]).await else { return };
    let mut ids = rows
        .into_iter()
        .map(|row| row.get::<_, Uuid>(0))
        .collect::<Vec<_>>();
    if let Ok(rows) = client
        .query(
            "SELECT id FROM database_encryption_jobs WHERE status='queued' ORDER BY created_at",
            &[],
        )
        .await
    {
        ids.extend(rows.into_iter().map(|row| row.get::<_, Uuid>(0)));
    }
    ids.sort();
    ids.dedup();
    drop(client);
    for id in ids {
        let worker_state = state.clone();
        tokio::spawn(async move {
            let Ok(_permit) = worker().acquire().await else {
                return;
            };
            let _ = run_job(&worker_state, id).await;
        });
    }
}

pub async fn get_job(
    State(state): State<AppState>,
    Extension(_): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client = state.db_pool.get().await.map_err(internal)?;
    let row=client.query_opt("SELECT id,status,mode,scope,actions,progress,cursor,created_at,started_at,completed_at,last_error_class,last_error_message FROM database_encryption_jobs WHERE id=$1",&[&id]).await.map_err(internal)?.ok_or_else(||bad("job not found"))?;
    Ok(Json(
        json!({"job_id":row.get::<_,Uuid>(0),"status":row.get::<_,String>(1),"mode":row.get::<_,String>(2),"scope":row.get::<_,Value>(3),"actions":row.get::<_,Value>(4),"progress":row.get::<_,Value>(5),"cursor":row.get::<_,Value>(6),"created_at":row.get::<_,chrono::DateTime<chrono::Utc>>(7),"started_at":row.get::<_,Option<chrono::DateTime<chrono::Utc>>>(8),"completed_at":row.get::<_,Option<chrono::DateTime<chrono::Utc>>>(9),"last_error_class":row.get::<_,Option<String>>(10),"last_error_message":row.get::<_,Option<String>>(11)}),
    ))
}

pub async fn cancel_job(
    State(state): State<AppState>,
    Extension(_): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client = state.db_pool.get().await.map_err(internal)?;
    let changed=client.execute("UPDATE database_encryption_jobs SET cancel_requested_at=NOW(),status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,completed_at=CASE WHEN status='queued' THEN NOW() ELSE completed_at END WHERE id=$1 AND status IN('queued','running')",&[&id]).await.map_err(internal)?;
    if changed == 0 {
        return Err(bad("job is not cancellable"));
    }
    drop(client);
    get_job(
        State(state),
        Extension(AuthenticatedUser {
            user_id: services::UserId(Uuid::nil()),
            session_id: services::SessionId(Uuid::nil()),
        }),
        Path(id),
    )
    .await
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    #[serde(default)]
    scope: Scope,
    batch_size: Option<i64>,
    #[serde(default = "yes")]
    fail_on_approved_plaintext_without_reason: bool,
}
fn yes() -> bool {
    true
}
pub async fn verify(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedUser>,
    Json(req): Json<VerifyRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if !req.fail_on_approved_plaintext_without_reason {
        return Err(bad(
            "verification cannot ignore unclassified plaintext columns",
        ));
    }
    create_job(
        State(state),
        Extension(admin),
        Json(CreateJobRequest {
            mode: Mode::Verify,
            scope: req.scope,
            batch_size: req.batch_size.unwrap_or_else(default_batch),
            max_rows: None,
            actions: vec!["verify".into()],
        }),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_required_stage_one_values() {
        for (table, column) in [
            ("files", "filename"),
            ("conversation_share_groups", "name"),
            ("conversation_share_group_members", "member_value"),
            ("conversation_shares", "recipient_value"),
            ("conversation_shares", "org_email_pattern"),
            ("user_activity_log", "metadata"),
            ("oauth_tokens", "access_token"),
            ("oauth_tokens", "refresh_token"),
            ("agent_instances", "instance_token"),
            ("agent_instances", "auth_session_token"),
            ("agent_instances", "instance_url"),
            ("agent_instances", "dashboard_url"),
            ("user_passkey_credentials", "auth_secret"),
            ("user_passkey_credentials", "backup_passphrase"),
        ] {
            assert!(FIELDS
                .iter()
                .any(|field| field.table == table && field.column == column));
        }
    }

    #[test]
    fn scope_rejects_unknown_fields_and_selects_registered_fields() {
        assert!(selected(&Scope {
            tables: vec!["unknown".into()],
            fields: vec![]
        })
        .is_err());
        let fields = selected(&Scope {
            tables: vec![],
            fields: vec![FieldName {
                table: "files".into(),
                column: "filename".into(),
            }],
        })
        .unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].table, "files");
    }

    #[test]
    fn opaque_provider_identifiers_are_explicitly_approved() {
        for (table, column) in [
            ("conversations", "id"),
            ("files", "id"),
            ("conversation_shares", "conversation_id"),
        ] {
            assert_eq!(
                classification(table, column, "character varying")
                    .unwrap()
                    .0,
                "approved_plaintext"
            );
            assert!(APPROVED
                .iter()
                .any(|(known_table, known_column, reason)| *known_table == table
                    && *known_column == column
                    && reason.contains("identifier")));
        }
    }

    #[test]
    fn broader_confidential_tables_require_encryption() {
        for (table, column) in [
            ("users", "email"),
            ("subscriptions", "customer_id"),
            ("aml_risk_reports", "result"),
        ] {
            let (kind, reason) = classification(table, column, "character varying").unwrap();
            assert_eq!(kind, "encryption_required");
            assert!(!reason.is_empty());
        }
        assert!(classification("new_unreviewed_table", "payload", "jsonb").is_none());
    }
}
