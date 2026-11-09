use super::*;
use anyhow::Context;
async fn counts(
    state: &AppState,
    fields: &[&Field],
    limit: Option<i64>,
) -> anyhow::Result<Vec<FieldCount>> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| anyhow::anyhow!("database encryption is not configured"))?;
    let ring = config.ring();
    let client = state.db_pool.get().await?;
    let mut result = Vec::new();
    for field in fields {
        let row_id = row_id_expression(field, None);
        let cap = limit.unwrap_or(i64::MAX).clamp(1, 100_000);
        let token = field
            .token
            .map(|(column, _)| column)
            .unwrap_or("NULL::bytea");
        let query = format!(
            "SELECT {row_id} AS row_id,{column}::text,{token} FROM {table} WHERE {row_id} IS NOT NULL ORDER BY row_id LIMIT $1",
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
            legacy_encrypted: 0,
            empty: 0,
            invalid_envelope: 0,
            scanned: rows.len() as i64,
            complete: rows.len() as i64 == total,
            stale: 0,
            by_key_id: Default::default(),
        };
        for row in rows {
            let Some(raw) = row.get::<_, Option<String>>(1) else {
                count.empty += 1;
                continue;
            };
            let classified = read_value(ring, field, row.get(0), &raw);
            if let Ok(value) = &classified {
                if let Some(key_id) = value.key_id(ring) {
                    *count.by_key_id.entry(key_id.to_owned()).or_default() += 1;
                }
            }
            match classified {
                Ok(StoredValue::Current(plaintext)) => {
                    let stored_token: Option<Vec<u8>> = row.get(2);
                    if search_token_matches(
                        ring.write_key(),
                        field,
                        &plaintext,
                        stored_token.as_deref(),
                    ) {
                        count.encrypted += 1
                    } else {
                        count.invalid_envelope += 1
                    }
                }
                Ok(StoredValue::Stale { plaintext, key_id }) => {
                    count.stale += 1;
                    let key = ring
                        .lookup(key_id)
                        .context("authenticated encryption key missing from ring")?;
                    let stored_token: Option<Vec<u8>> = row.get(2);
                    if search_token_matches(key, field, &plaintext, stored_token.as_deref()) {
                        count.encrypted += 1;
                    } else {
                        count.invalid_envelope += 1;
                    }
                }
                Ok(StoredValue::LegacyEncrypted(_)) => count.legacy_encrypted += 1,
                Ok(StoredValue::Plaintext(_)) => count.plaintext += 1,
                Err(_) => count.invalid_envelope += 1,
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
    let mut by_key_id = std::collections::BTreeMap::<String, i64>::new();
    for count in &counts {
        for (key_id, amount) in &count.by_key_id {
            *by_key_id.entry(key_id.clone()).or_default() += amount;
        }
    }
    let totals = json!({
        "stale": counts.iter().map(|c| c.stale).sum::<i64>(),
        "by_key_id": by_key_id,
        "plaintext": counts.iter().map(|c| c.plaintext).sum::<i64>(),
        "encrypted": counts.iter().map(|c| c.encrypted).sum::<i64>(),
        "legacy_encrypted": counts.iter().map(|c| c.legacy_encrypted).sum::<i64>(),
        "empty": counts.iter().map(|c| c.empty).sum::<i64>(),
        "invalid_envelope": counts.iter().map(|c| c.invalid_envelope).sum::<i64>(),
        "scanned": counts.iter().map(|c| c.scanned).sum::<i64>(),
        "complete": counts.iter().all(|c| c.complete),
    });
    Ok(Json(
        json!({"run_id":Uuid::new_v4(),"status":"completed","fields":counts,"totals":totals,"approved_plaintext":if req.include_approved_plaintext { json!(APPROVED.iter().chain(REVIEWED_PLAINTEXT_FIELDS.iter()).map(|(table,column,_)| { let (_,reason)=classification(table,column,"text").expect("registered field"); json!({"table":table,"column":column,"classification":"approved_plaintext","reason":reason}) }).collect::<Vec<_>>()) } else { json!([]) },"legacy_confidential":inventory.legacy_confidential,"unclassified":inventory.unclassified}),
    ))
}

pub async fn keys(
    State(state): State<AppState>,
    Extension(_): Extension<AuthenticatedUser>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| bad("database encryption is not configured"))?;
    let ring = config.ring();
    Ok(Json(json!({
        "write_key_id":ring.write_id(),
        "read_key_ids":ring.ids().into_iter().filter(|id| *id != ring.write_id()).collect::<Vec<_>>(),
        "fingerprints":ring.fingerprints(),
        "write_enabled":config.write_enabled,
        "agent_secrets_write_enabled":config.agent_secrets_write_enabled,
        "app_config_write_enabled":config.app_config_write_enabled,
    })))
}
