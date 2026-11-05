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
    AgentSecret,
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

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Scope {
    #[serde(default)]
    tables: Vec<String>,
    #[serde(default)]
    fields: Vec<FieldName>,
    #[serde(default, skip_serializing_if = "JobOptions::is_default")]
    options: JobOptions,
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
    legacy_encrypted: i64,
    empty: i64,
    invalid_envelope: i64,
    scanned: i64,
    complete: bool,
    stale: i64,
    by_key_id: std::collections::BTreeMap<String, i64>,
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

fn conflict(message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::CONFLICT,
        Json(json!({"error":{"code":"conflict","message":message.into()}})),
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

fn normalized_token_value(domain: &str, value: &str) -> String {
    if domain == "conversation_share_groups.name" {
        value.to_string()
    } else {
        value.trim().to_lowercase()
    }
}

fn search_token_matches(
    key: &[u8; 32],
    field: &Field,
    plaintext: &str,
    stored: Option<&[u8]>,
) -> bool {
    let Some((_, domain)) = field.token else {
        return true;
    };
    let Some(stored) = stored else {
        return false;
    };
    database::field_encryption::search_token(
        key,
        domain,
        &normalized_token_value(domain, plaintext),
    )
    .is_ok_and(|expected| expected == stored)
}

fn row_id_expression(field: &Field, qualifier: Option<&str>) -> String {
    let prefix = qualifier.map_or_else(String::new, |value| format!("{value}."));
    if field.table == "files" && field.column == "filename" {
        let id = format!("{prefix}id");
        format!(
            "CASE WHEN {id} ~* '^file-[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$' THEN substring({id} from 6)::uuid END"
        )
    } else {
        format!("{prefix}{}", field.id_column)
    }
}

mod batch;
mod checkpoint;
mod completion;
mod inventory;
mod jobs;
mod progress;
mod projection;
mod registry;
mod scan;
mod status;
mod throttle;
mod values;
mod worker;
mod writes;
use inventory::*;
pub use jobs::create_job;
pub use requests::CreateJobRequest;
use requests::Mode;
mod requests;
pub use lifecycle::recover_jobs;
use lifecycle::{execute_writes_enabled, mark_job_failed, write_gate_blocks};
use progress::*;
use registry::*;
use values::*;
use worker::run_job;
mod lifecycle;
pub use scan::{keys, scan};
pub use status::{cancel_job, get_job, verify, VerifyRequest};
#[cfg(test)]
mod tests;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
struct JobOptions {
    #[serde(default, deserialize_with = "requests::optional_batch_delay")]
    batch_delay_ms: Option<u64>,
}

impl JobOptions {
    fn is_default(&self) -> bool {
        self.batch_delay_ms.is_none_or(|delay| delay == 0)
    }
}

fn batch_delay<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value > 10_000 {
        return Err(serde::de::Error::custom(
            "batch_delay_ms must be between 0 and 10000",
        ));
    }
    Ok(value)
}
