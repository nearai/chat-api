#![cfg(feature = "test")]
mod common;
use api::usage_parsing::{
    forward_usage_stream, UsageTrackingStreamChatCompletions, UsageTrackingStreamResponseCompleted,
};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::json;
use services::user::ports::UserRepository;
use std::pin::Pin;
use uuid::Uuid;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

type TrackedStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

async fn exercise(responses: bool, agent: bool, disconnect_before_usage: bool, eof: bool) {
    let pricing = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "inputCostPerToken":{"amount":2,"scale":9,"currency":"USD"},
            "outputCostPerToken":{"amount":3,"scale":9,"currency":"USD"},
            "costPerImage":{"amount":0,"scale":9,"currency":"USD"}
        })))
        .mount(&pricing)
        .await;
    let (_server, db, state) = common::create_test_server_with_state(Default::default()).await;
    let user = db
        .user_repository()
        .create_user(format!("stream-{}@example.com", Uuid::new_v4()), None, None)
        .await
        .unwrap();
    let client = db.pool().get().await.unwrap();
    let instance = Uuid::new_v4();
    let key = Uuid::new_v4();
    if agent {
        client.execute("INSERT INTO agent_instances (id,user_id,instance_id,name,instance_url,instance_token) VALUES ($1,$2,$3,'test','http://localhost','test')",
            &[&instance,&user.id,&instance.to_string()]).await.unwrap();
        client.execute("INSERT INTO agent_api_keys (id,instance_id,user_id,key_hash,name) VALUES ($1,$2,$3,$4,'test')",
            &[&key,&instance,&user.id,&key.to_string()]).await.unwrap();
        client
            .execute(
                "INSERT INTO agent_balance (instance_id) VALUES ($1) ON CONFLICT DO NOTHING",
                &[&instance],
            )
            .await
            .unwrap();
    }
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, reqwest::Error>>(8);
    let inner = tokio_stream::wrappers::ReceiverStream::new(receiver);
    let cache = api::model_pricing::ModelPricingCache::new(pricing.uri());
    let tracked: TrackedStream = if responses {
        let stream = UsageTrackingStreamResponseCompleted::new(
            inner,
            state.user_usage_service.clone(),
            state.subscription_service.clone(),
            cache,
            user.id,
        );
        Box::pin(if agent {
            stream.with_agent_ids(Some(instance), key)
        } else {
            stream
        })
    } else {
        let stream = UsageTrackingStreamChatCompletions::new(
            inner,
            state.user_usage_service.clone(),
            state.subscription_service.clone(),
            cache,
            user.id,
        );
        Box::pin(if agent {
            stream.with_agent_ids(Some(instance), key)
        } else {
            stream
        })
    };
    let usage = if responses {
        "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"test\",\"usage\":{\"input_tokens\":5,\"output_tokens\":7}}}\n\n"
    } else {
        "data: {\"model\":\"test\",\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":7},\"text\":\"你好\"}\n\n"
    };
    if disconnect_before_usage {
        let first = Bytes::from_static(b"data: {\"delta\":\"hello\"}\n\n");
        let mut body =
            axum::body::Body::from_stream(forward_usage_stream(tracked)).into_data_stream();
        sender.send(Ok(first.clone())).await.unwrap();
        assert_eq!(body.next().await.unwrap().unwrap(), first);
        drop(body);
        // Split UTF-8 and SSE data across network chunks after the disconnect.
        for chunk in usage.as_bytes().chunks(3) {
            sender
                .send(Ok(Bytes::copy_from_slice(chunk)))
                .await
                .unwrap();
        }
        drop(sender);
    } else {
        let mut tracked = tracked;
        sender
            .send(Ok(Bytes::copy_from_slice(usage.as_bytes())))
            .await
            .unwrap();
        assert_eq!(
            tracked.next().await.unwrap().unwrap().as_ref(),
            usage.as_bytes()
        );
        if eof {
            drop(sender);
            assert!(tracked.next().await.is_none());
        }
        drop(tracked);
    }
    let mut rows = Vec::new();
    for _ in 0..100 {
        rows = client.query("SELECT quantity,cost_nano_usd,instance_id,api_key_id FROM user_usage_event WHERE user_id=$1", &[&user.id]).await.unwrap();
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        rows.len(),
        1,
        "usage must be recorded after disconnect/drop/EOF"
    );
    assert_eq!(rows[0].get::<_, i64>(0), 12);
    assert_eq!(rows[0].get::<_, Option<i64>>(1), Some(31));
    assert_eq!(rows[0].get::<_, Option<Uuid>>(2), agent.then_some(instance));
    assert_eq!(rows[0].get::<_, Option<Uuid>>(3), agent.then_some(key));
    if agent {
        let row = client
            .query_one(
                "SELECT total_spent,total_requests FROM agent_balance WHERE instance_id=$1",
                &[&instance],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 31);
        assert_eq!(row.get::<_, i64>(1), 1);
    }
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM user_usage_event WHERE user_id=$1",
                &[&user.id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[tokio::test]
async fn client_disconnect_before_final_usage_still_bills_both_apis_and_auth_types() {
    for responses in [false, true] {
        for agent in [false, true] {
            exercise(responses, agent, true, false).await;
        }
    }
}
#[tokio::test]
async fn dropping_after_usage_without_eof_records_once() {
    for responses in [false, true] {
        exercise(responses, false, false, false).await;
    }
}
#[tokio::test]
async fn eof_followed_by_drop_does_not_double_charge() {
    for responses in [false, true] {
        exercise(responses, false, false, true).await;
    }
}
