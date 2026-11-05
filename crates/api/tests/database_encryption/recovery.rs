use super::fixture::Fixture;
use database::field_encryption;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn recovered_dry_run_replays_projection_and_matches_execute_conflicts() {
    let f = Fixture::new().await;
    let mut config = f.db.pool().field_encryption().unwrap();
    config.previous_keys.push(("rotation-v0".into(), [31; 32]));
    f.db.pool().set_field_encryption(config);
    let later = Uuid::from_u128(u128::MAX);
    let raw = field_encryption::encrypt(
        &[31; 32],
        "rotation-v0",
        "conversation_share_groups",
        "name",
        later,
        &f.name,
    )
    .unwrap();
    let token =
        field_encryption::search_token(&[31; 32], "conversation_share_groups.name", &f.name)
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
