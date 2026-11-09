use crate::common::{create_test_server_with_state, mock_login, TestServerConfig};
use axum_test::TestServer;
use database::{field_encryption, Database};
use http::{HeaderName, HeaderValue};
use serde_json::{json, Value};
use services::db_pool::FieldEncryptionConfig;
use std::sync::LazyLock;
use std::time::Duration;
use uuid::Uuid;

pub static OLD: LazyLock<[u8; 32]> = LazyLock::new(random_key);
pub static WRITE: LazyLock<[u8; 32]> = LazyLock::new(random_key);

pub fn random_key() -> [u8; 32] {
    use rand::{Rng, TryRngCore};
    rand::rngs::OsRng.unwrap_err().random()
}

pub struct Fixture {
    pub server: TestServer,
    pub db: Database,
    pub state: api::AppState,
    pub auth: HeaderValue,
    pub user: Uuid,
    pub conversation: String,
    pub file: String,
    pub group: Uuid,
    pub share: Uuid,
    pub member: Uuid,
    pub oauth: Uuid,
    pub email: String,
    pub name: String,
    _recovery: RecoveryTask,
    _cleanup: DatabaseCleanup,
}

pub fn ring_config() -> FieldEncryptionConfig {
    FieldEncryptionConfig {
        ring: field_encryption::KeyRing::new(
            "rotation-v2".into(),
            *WRITE,
            vec![("db-v1".into(), *OLD)],
        )
        .unwrap(),
        write_enabled: true,
        agent_secrets_write_enabled: true,
        app_config_write_enabled: false,
    }
}

impl Fixture {
    pub async fn new() -> Self {
        Self::with_recovery_interval(Duration::from_millis(10)).await
    }

    pub async fn with_recovery_interval(interval: Duration) -> Self {
        dotenvy::dotenv().ok();
        let config = config::Config::from_env();
        let control = Database::from_config(&config.database).await.unwrap();
        let database_name = format!("rotation_{}", Uuid::new_v4().simple());
        control
            .pool()
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {database_name}"))
            .await
            .unwrap();
        let cleanup = DatabaseCleanup {
            database_name: database_name.clone(),
            config: config.database.clone(),
        };
        let (server, db, state) = create_test_server_with_state(TestServerConfig {
            database_name: Some(database_name.clone()),
            field_encryption: Some(ring_config()),
            ..Default::default()
        })
        .await;
        let user = Uuid::new_v4();
        let conversation = format!("conv-{user}");
        let file = format!("file-{user}");
        let group = Uuid::new_v4();
        let share = Uuid::new_v4();
        let member = Uuid::new_v4();
        let oauth = Uuid::new_v4();
        let email = format!("recipient-{user}@example.com");
        let name = "Rotation team".to_string();
        let client = db.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO users(id,email) VALUES($1,$2)",
                &[&user, &format!("{user}@example.com")],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO conversations(id,user_id) VALUES($1,$2)",
                &[&conversation, &user],
            )
            .await
            .unwrap();
        let old = |table, column, id, value| {
            field_encryption::encrypt(&OLD, "db-v1", table, column, id, value).unwrap()
        };
        let token =
            |domain, value: &str| field_encryption::search_token(&OLD, domain, value).unwrap();
        client.execute("INSERT INTO files(id,user_id,bytes,file_created_at,filename,purpose) VALUES($1,$2,1,1,$3,'assistants')", &[&file,&user,&old("files","filename",user,"rotation.txt")]).await.unwrap();
        client.execute("INSERT INTO conversation_share_groups(id,owner_user_id,name,name_search_token) VALUES($1,$2,$3,$4)", &[&group,&user,&old("conversation_share_groups","name",group,&name),&token("conversation_share_groups.name",&name)]).await.unwrap();
        client.execute("INSERT INTO conversation_share_group_members(id,group_id,member_type,member_value,member_value_search_token) VALUES($1,$2,'email',$3,$4)", &[&member,&group,&old("conversation_share_group_members","member_value",member,&email),&token("conversation_share_group_members.member_value",&email)]).await.unwrap();
        client.execute("INSERT INTO conversation_shares(id,conversation_id,owner_user_id,share_type,permission,recipient_type,recipient_value,recipient_value_search_token) VALUES($1,$2,$3,'direct','read','email',$4,$5)", &[&share,&conversation,&user,&old("conversation_shares","recipient_value",share,&email),&token("conversation_shares.recipient_value",&email)]).await.unwrap();
        client.execute("INSERT INTO oauth_tokens(id,user_id,provider,access_token) VALUES($1,$2,'google',$3)", &[&oauth,&user,&old("oauth_tokens","access_token",oauth,"rotation-access")]).await.unwrap();
        drop(client);
        let login = mock_login(&server, "rotation@admin.org").await;
        let auth = HeaderValue::from_str(&format!("Bearer {login}")).unwrap();
        let recovery = RecoveryTask(tokio::spawn(
            api::database_encryption::recover_jobs_periodically(state.clone(), interval),
        ));
        Self {
            server,
            db,
            state,
            auth,
            user,
            conversation,
            file,
            group,
            share,
            member,
            oauth,
            email,
            name,
            _recovery: recovery,
            _cleanup: cleanup,
        }
    }

    pub async fn job(&self, mode: &str, action: &str) -> Value {
        let response = self.server.post("/v1/admin/database-encryption/jobs")
            .add_header(HeaderName::from_static("authorization"),self.auth.clone())
            .json(&json!({"mode":mode,"scope":{"tables":["files","conversation_shares","conversation_share_groups","conversation_share_group_members","oauth_tokens"]},"batch_size":1,"batch_delay_ms":1,"actions":[action]})).await;
        assert_eq!(response.status_code(), 202, "{}", response.text());
        let accepted: Value = response.json();
        self.wait_job(accepted["job_id"].as_str().unwrap()).await
    }

    pub async fn wait_job(&self, id: &str) -> Value {
        for _ in 0..400 {
            let response = self
                .server
                .get(&format!("/v1/admin/database-encryption/jobs/{}", id))
                .add_header(HeaderName::from_static("authorization"), self.auth.clone())
                .await;
            let result: Value = response.json();
            match result["status"].as_str() {
                Some("completed") => return result,
                Some("cancelled" | "failed") => {
                    panic!("rotation job {id} terminated before completion: {result}");
                }
                Some("queued" | "running") => {}
                status => panic!("rotation job {id} returned an invalid status {status:?}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("rotation job timed out");
    }

    pub async fn stored(&self) -> Vec<(String, Option<Vec<u8>>)> {
        let client = self.db.pool().get().await.unwrap();
        let mut values = Vec::new();
        for (table, column, id, token) in [
            ("files", "filename", self.user, "NULL::bytea"),
            (
                "conversation_share_groups",
                "name",
                self.group,
                "name_search_token",
            ),
            (
                "conversation_share_group_members",
                "member_value",
                self.member,
                "member_value_search_token",
            ),
            (
                "conversation_shares",
                "recipient_value",
                self.share,
                "recipient_value_search_token",
            ),
            ("oauth_tokens", "access_token", self.oauth, "NULL::bytea"),
        ] {
            let selector = if table == "files" {
                "substring(id from 6)::uuid"
            } else {
                "id"
            };
            let row = client
                .query_one(
                    &format!("SELECT {column},{token} FROM {table} WHERE {selector}=$1"),
                    &[&id],
                )
                .await
                .unwrap();
            values.push((row.get(0), row.get(1)));
        }
        values
    }

    pub async fn cleanup(self) {
        // The guard also runs when construction or an assertion panics.
        drop(self);
    }
}

struct RecoveryTask(tokio::task::JoinHandle<()>);

impl Drop for RecoveryTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct DatabaseCleanup {
    database_name: String,
    config: config::DatabaseConfig,
}

impl Drop for DatabaseCleanup {
    fn drop(&mut self) {
        let database_name = self.database_name.clone();
        let config = self.config.clone();
        // A fresh runtime/connection avoids waiting on tasks owned by the test's
        // current-thread runtime while it is unwinding or dropping the fixture.
        let cleanup = std::thread::spawn(move || -> anyhow::Result<()> {
            tokio::runtime::Runtime::new()?.block_on(async move {
                let control = Database::from_config(&config).await?;
                control
                    .pool()
                    .get()
                    .await?
                    .batch_execute(&format!("DROP DATABASE {database_name} WITH (FORCE)"))
                    .await?;
                Ok(())
            })
        })
        .join();
        if !matches!(cleanup, Ok(Ok(()))) {
            if std::thread::panicking() {
                eprintln!("isolated rotation database cleanup failed during unwinding");
            } else {
                panic!("isolated rotation database cleanup failed");
            }
        }
    }
}
