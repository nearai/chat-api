use super::fixture::{random_key, Fixture, OLD};
use database::field_encryption;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[tokio::test]
async fn recovered_dry_run_restarts_in_memory_state_and_matches_execute_conflicts() {
    let f = Fixture::new().await;
    let previous_key = random_key();
    let mut config = f.db.pool().field_encryption().unwrap();
    let mut previous_keys = config
        .ring()
        .keys()
        .skip(1)
        .map(|(id, key)| (id.to_owned(), *key))
        .collect::<Vec<_>>();
    previous_keys.push(("rotation-v0".into(), previous_key));
    config.ring = field_encryption::KeyRing::new(
        config.ring().write_id().into(),
        *config.ring().write_key(),
        previous_keys,
    )
    .unwrap();
    f.db.pool().set_field_encryption(config);
    let later = Uuid::from_u128(u128::MAX);
    let raw = field_encryption::encrypt(
        &previous_key,
        "rotation-v0",
        "conversation_share_groups",
        "name",
        later,
        &f.name,
    )
    .unwrap();
    let token =
        field_encryption::search_token(&previous_key, "conversation_share_groups.name", &f.name)
            .unwrap();
    let client = f.db.pool().get().await.unwrap();
    client.execute("INSERT INTO conversation_share_groups(id,owner_user_id,name,name_search_token) VALUES($1,$2,$3,$4)",&[&later,&f.user,&raw,&token]).await.unwrap();
    let id = Uuid::new_v4();
    let scope = json!({"fields":[{"table":"conversation_share_groups","column":"name"}],"options":{"batch_delay_ms":0}});
    let cursor = json!({"field_index":0,"after_id":f.group});
    let progress =
        json!({"processed":1,"stale":1,"rewrapped":1,"tokens_rewritten":1,"by_key_id":{"db-v1":1}});
    client.execute("INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size,cursor,progress) VALUES($1,'dry_run','running',$2,$3,1,$4,$5)",&[&id,&scope,&json!(["rewrap"]),&cursor,&progress]).await.unwrap();
    drop(client);
    let before = f.stored().await;
    api::database_encryption::recover_jobs(f.state.clone()).await;
    let resumed = f.wait_job(&id.to_string()).await;
    assert_eq!(resumed["progress"]["processed"], 2);
    assert_eq!(resumed["progress"]["rewrapped"], 1);
    assert_eq!(resumed["progress"]["token_conflicts"], 1);
    assert_eq!(f.stored().await, before);
    let execute = f.job("execute", "rewrap").await;
    assert_eq!(execute["progress"]["token_conflicts"], 1);
    let row =
        f.db.pool()
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT name,name_search_token FROM conversation_share_groups WHERE id=$1",
                &[&later],
            )
            .await
            .unwrap();
    assert_eq!(row.get::<_, String>(0), raw);
    assert_eq!(row.get::<_, Vec<u8>>(1), token);
    let final_progress: Value =
        execute["progress"]["fields"]["conversation_share_groups.name"].clone();
    assert_eq!(
        resumed["progress"]["rewrapped"],
        final_progress["rewrapped"]
    );
    f.cleanup().await;
}

#[tokio::test]
async fn recovered_verify_does_not_pass_from_stale_pre_rotation_checkpoint() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    let scope =
        json!({"fields":[{"table":"files","column":"filename"}],"options":{"batch_delay_ms":0}});
    let previous_ring = field_encryption::KeyRing::new("db-v1".into(), *OLD, vec![]).unwrap();
    let cursor = json!({"field_index":0,"after_id":f.user,"ring_context":{
        "version":1,
        "write_id":"db-v1",
        "read_ids":["db-v1"],
        "fingerprints":previous_ring.fingerprints()
    }});
    let progress = json!({"processed":1,"stale":0,"invalid_envelopes":0,"by_key_id":{"db-v1":1}});
    let client = f.db.pool().get().await.unwrap();
    client.execute(
        "INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size,cursor,progress) VALUES($1,'verify','running',$2,$3,1,$4,$5)",
        &[&id,&scope,&json!(["verify"]),&cursor,&progress],
    ).await.unwrap();
    drop(client);

    api::database_encryption::recover_jobs(f.state.clone()).await;
    let resumed = wait_job_bounded(&f, &id.to_string()).await;
    assert_eq!(resumed["last_error_class"], "key_ring_changed");
    assert_eq!(resumed["progress"]["pass"], false);
    f.cleanup().await;
}

#[tokio::test]
async fn recovered_jobs_fail_closed_on_changed_or_missing_ring_context() {
    let f = Fixture::with_recovery_interval(Duration::from_secs(3600)).await;
    let original_ring = f.db.pool().field_encryption().unwrap().ring().clone();
    let id = Uuid::new_v4();
    let cursor =
        json!({"field_index":0,"after_id":f.user,"ring_context":ring_context(&original_ring)});
    let progress = json!({"processed":1,"stale":1,"by_key_id":{"db-v1":1}});

    seed_job(&f, id, "verify", cursor.clone(), progress.clone()).await;
    let changed_writer = field_encryption::KeyRing::new(
        "rotation-v3".into(),
        *original_ring.write_key(),
        original_ring
            .keys()
            .skip(1)
            .map(|(key_id, key)| (key_id.to_owned(), *key))
            .collect(),
    )
    .unwrap();
    set_ring(&f, changed_writer.clone());
    api::database_encryption::recover_jobs(f.state.clone()).await;
    let failed_verify = stored_job(&f, id).await;
    assert_eq!(failed_verify["status"], "failed");
    assert_eq!(failed_verify["last_error_class"], "key_ring_changed");
    assert_eq!(failed_verify["progress"]["pass"], false);
    assert_eq!(failed_verify["progress"]["processed"], 1);
    assert_eq!(failed_verify["progress"]["stale"], 1);
    assert_eq!(failed_verify["progress"]["by_key_id"]["db-v1"], 1);

    let before = f.stored().await;
    let execute_id = Uuid::new_v4();
    seed_job(&f, execute_id, "execute", cursor, progress.clone()).await;
    api::database_encryption::recover_jobs(f.state.clone()).await;
    let failed_execute = stored_job(&f, execute_id).await;
    assert_eq!(failed_execute["status"], "failed");
    assert_eq!(failed_execute["last_error_class"], "key_ring_changed");
    assert_eq!(f.stored().await, before);

    let fingerprint_id = Uuid::new_v4();
    let context_ring = changed_writer.clone();
    seed_job(
        &f,
        fingerprint_id,
        "execute",
        json!({"field_index":0,"after_id":f.user,"ring_context":ring_context(&context_ring)}),
        progress.clone(),
    )
    .await;
    let changed_fingerprint = field_encryption::KeyRing::new(
        "rotation-v3".into(),
        random_key(),
        context_ring
            .keys()
            .skip(1)
            .map(|(key_id, key)| (key_id.to_owned(), *key))
            .collect(),
    )
    .unwrap();
    set_ring(&f, changed_fingerprint);
    api::database_encryption::recover_jobs(f.state.clone()).await;
    let failed_fingerprint = stored_job(&f, fingerprint_id).await;
    assert_eq!(failed_fingerprint["last_error_class"], "key_ring_changed");
    assert_eq!(f.stored().await, before);

    let missing_id = Uuid::new_v4();
    seed_job(
        &f,
        missing_id,
        "verify",
        json!({"field_index":0,"after_id":f.user}),
        json!({"processed":1,"stale":1,"by_key_id":{"db-v1":1}}),
    )
    .await;
    set_ring(&f, changed_writer.clone());
    api::database_encryption::recover_jobs(f.state.clone()).await;
    let failed_missing = stored_job(&f, missing_id).await;
    assert_eq!(
        failed_missing["last_error_class"],
        "checkpoint_key_config_missing"
    );
    assert_eq!(failed_missing["progress"]["pass"], false);
    assert_eq!(failed_missing["progress"]["stale"], 1);

    set_ring(&f, original_ring.clone());
    let resumed_id = Uuid::new_v4();
    seed_job(
        &f,
        resumed_id,
        "verify",
        json!({"field_index":0,"after_id":f.user,"ring_context":ring_context(&original_ring)}),
        progress,
    )
    .await;
    api::database_encryption::recover_jobs(f.state.clone()).await;
    let resumed = stored_job(&f, resumed_id).await;
    assert_eq!(resumed["status"], "completed");
    assert_eq!(resumed["progress"]["pass"], false);
    assert_eq!(resumed["progress"]["processed"], 1);
    assert_eq!(resumed["progress"]["stale"], 1);
    assert_eq!(resumed["progress"]["by_key_id"]["db-v1"], 1);

    let new_ring = changed_writer;
    set_ring(&f, new_ring);
    let fresh = f
        .server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(http::header::AUTHORIZATION, f.auth.clone())
        .json(&json!({"mode":"verify","scope":{"fields":[{"table":"files","column":"filename"}]},"batch_size":1,"batch_delay_ms":0,"actions":["verify"]}))
        .await;
    assert_eq!(fresh.status_code(), 202);
    let fresh: Value = fresh.json();
    let fresh = wait_job_bounded(&f, fresh["job_id"].as_str().unwrap()).await;
    assert_eq!(fresh["status"], "completed");
    assert_eq!(fresh["progress"]["stale"], 1);
    assert_eq!(fresh["progress"]["pass"], false);
    f.cleanup().await;
}

fn ring_context(ring: &field_encryption::KeyRing) -> Value {
    json!({
        "version": 1,
        "write_id": ring.write_id(),
        "read_ids": ring.ids(),
        "fingerprints": ring.fingerprints()
    })
}

fn set_ring(f: &Fixture, ring: field_encryption::KeyRing) {
    let mut config = f.db.pool().field_encryption().unwrap();
    config.ring = ring;
    f.db.pool().set_field_encryption(config);
}

async fn seed_job(f: &Fixture, id: Uuid, mode: &str, cursor: Value, progress: Value) {
    let client = f.db.pool().get().await.unwrap();
    let scope =
        json!({"fields":[{"table":"files","column":"filename"}],"options":{"batch_delay_ms":0}});
    client.execute(
        "INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size,cursor,progress) VALUES($1,$2,'running',$3,$4,1,$5,$6)",
        &[&id,&mode,&scope,&json!([if mode == "verify" { "verify" } else { "rewrap" }]),&cursor,&progress],
    ).await.unwrap();
}

async fn stored_job(f: &Fixture, id: Uuid) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        api::database_encryption::recover_jobs(f.state.clone()).await;
        let job: Value = {
            let client = f.db.pool().get().await.unwrap();
            client.query_one("SELECT jsonb_build_object('status',status,'last_error_class',last_error_class,'progress',progress) FROM database_encryption_jobs WHERE id=$1", &[&id]).await.unwrap().get(0)
        };
        if matches!(
            job["status"].as_str(),
            Some("completed" | "failed" | "cancelled")
        ) {
            return job;
        }
        assert!(
            Instant::now() < deadline,
            "database encryption recovery job {id} did not reach a terminal status within 5 seconds: {job}"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

async fn wait_job_bounded(f: &Fixture, id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = f
            .server
            .get(&format!("/v1/admin/database-encryption/jobs/{id}"))
            .add_header(http::header::AUTHORIZATION, f.auth.clone())
            .await;
        let job: Value = response.json();
        if matches!(
            job["status"].as_str(),
            Some("completed" | "failed" | "cancelled")
        ) {
            return job;
        }
        assert!(
            Instant::now() < deadline,
            "database encryption job exceeded 5 second recovery bound: {job}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
