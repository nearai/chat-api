use super::fixture::Fixture;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn periodic_recovery_resumes_a_job_orphaned_after_startup() {
    let f = Fixture::with_recovery_interval(Duration::from_secs(3600)).await;
    let client = f.db.pool().get().await.unwrap();
    let startup_job = Uuid::new_v4();
    let scope = json!({"fields":[{"table":"files","column":"filename"}]});
    client
        .execute(
            "INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size)
             VALUES($1,'dry_run','queued',$2,$3,1)",
            &[&startup_job, &scope, &json!(["rewrap"])],
        )
        .await
        .unwrap();
    drop(client);
    let recovery = tokio::spawn(api::database_encryption::recover_jobs_periodically(
        f.state.clone(),
        Duration::from_millis(1),
    ));
    let recovery = AbortOnDrop(recovery);
    f.wait_job(&startup_job.to_string()).await;
    let client = f.db.pool().get().await.unwrap();
    let id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size)
             VALUES($1,'execute','running',$2,$3,1)",
            &[&id, &scope, &json!(["rewrap"])],
        )
        .await
        .unwrap();
    drop(client);

    let completed = f.wait_job(&id.to_string()).await;

    assert_eq!(completed["progress"]["rewrapped"], 1);
    drop(recovery);
    f.cleanup().await;
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
