use super::*;
pub async fn create_job(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedUser>,
    Json(mut req): Json<CreateJobRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let delay = requests::requested_delay(&req.scope, req.batch_delay_ms)?;
    let config = state
        .db_pool
        .field_encryption()
        .ok_or_else(|| bad("database encryption is not configured"))?;
    if !(1..=1000).contains(&req.batch_size) || req.max_rows.is_some_and(|value| value <= 0) {
        return Err(bad("invalid batch_size or max_rows"));
    }
    if matches!(req.mode, Mode::Verify) && req.max_rows.is_some() {
        return Err(bad("verify jobs cannot set max_rows"));
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
    requests::validate_actions(&req.mode, &req.actions)?;
    let fields = selected(&req.scope)?;
    if matches!(req.mode, Mode::Execute)
        && fields
            .iter()
            .any(|field| matches!(field.kind, Kind::AgentSecret))
        && !config.agent_secrets_write_enabled
    {
        return Err(bad(
            "execute for agent credentials requires DB_ENCRYPTION_AGENT_SECRETS_WRITE_ENABLED=true",
        ));
    }
    if matches!(req.mode, Mode::Execute)
        && fields.iter().any(|field| field.table == "app_config")
        && !config.app_config_write_enabled
    {
        return Err(bad(
            "execute for app config requires DB_ENCRYPTION_APP_CONFIG_WRITE_ENABLED=true",
        ));
    }
    // Freeze table/default scopes at creation. A later registry update must not
    // add fields to an already-authorized job when it resumes.
    req.scope = Scope {
        tables: Vec::new(),
        options: JobOptions {
            batch_delay_ms: Some(delay),
        },
        fields: fields
            .iter()
            .map(|field| FieldName {
                table: field.table.into(),
                column: field.column.into(),
            })
            .collect(),
    };
    req.scope.fields.sort();
    let mode = match req.mode {
        Mode::DryRun => "dry_run",
        Mode::Execute => "execute",
        Mode::Verify => "verify",
    };
    let id = Uuid::new_v4();
    let scope_value = serde_json::to_value(&req.scope).map_err(internal)?;
    let actions_value = json!(req.actions);
    let client = state.db_pool.get().await.map_err(internal)?;
    if mode == "execute" && req.actions == ["encrypt"] {
        let collisions: bool = client
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM conversation_share_group_members
                    WHERE member_value_search_token IS NULL
                    GROUP BY group_id,member_type,LOWER(BTRIM(member_value)) HAVING count(*) > 1
                    UNION ALL
                    SELECT 1 FROM conversation_shares
                    WHERE share_type='direct' AND recipient_value_search_token IS NULL
                    GROUP BY conversation_id,recipient_type,LOWER(BTRIM(recipient_value)) HAVING count(*) > 1
                )",
                &[],
            )
            .await
            .map_err(internal)?
            .get(0);
        if collisions {
            return Err(conflict(
                "normalized share recipient collisions must be remediated before execute",
            ));
        }
    }
    client.execute("INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size,max_rows,admin_actor) VALUES($1,$2,'queued',$3,$4,$5,$6,$7)", &[&id,&mode,&scope_value,&actions_value,&req.batch_size,&req.max_rows,&admin.user_id.0]).await.map_err(internal)?;
    drop(client);
    tokio::spawn(async move {
        let Ok(_permit) = state.database_encryption_worker.semaphore.acquire().await else {
            return;
        };
        if let Err(_error) = run_job(&state, id).await {
            tracing::error!(job_id=%id,error_class="database_encryption_job_failed","Database encryption job failed");
            let _ = mark_job_failed(&state, id, "batch_failed", "batch_failed").await;
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"job_id":id,"status":"queued","mode":mode,"scope":scope_value,"actions":actions_value,"cursor":{},"progress":{}}),
        ),
    ))
}
