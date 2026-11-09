use api::routes::api::STATEFUL_API_RETIRED_MESSAGE;
use axum_test::TestServer;
use http::{HeaderValue, Method, StatusCode};
use serde_json::Value;

pub async fn assert_retired_paths(server: &TestServer, paths: &[String], token: &str) {
    for authorization in [
        None,
        Some("Bearer invalid".to_string()),
        Some(format!("Bearer {token}")),
    ] {
        for path in paths {
            for method in [
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ] {
                let mut request = server.method(method.clone(), path);

                if let Some(value) = &authorization {
                    request = request.add_header(
                        http::header::AUTHORIZATION,
                        HeaderValue::from_str(value).expect("test authorization"),
                    );
                }

                let response = request.await;

                assert_eq!(response.status_code(), StatusCode::GONE, "{method} {path}");
                assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");

                if method != Method::HEAD {
                    let body: Value = response.json();
                    assert_eq!(body["error"], STATEFUL_API_RETIRED_MESSAGE);
                }
            }
        }
    }
}
