use super::*;
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
    #[serde(default, deserialize_with = "requests::optional_batch_delay")]
    batch_delay_ms: Option<u64>,
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
            batch_size: req.batch_size.unwrap_or_else(requests::default_batch),
            max_rows: None,
            batch_delay_ms: req.batch_delay_ms,
            actions: vec!["verify".into()],
        }),
    )
    .await
}
