use http::{HeaderName, HeaderValue};
use uuid::Uuid;

pub const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

pub fn bearer_header(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header is valid")
}

pub fn header_value<'a>(response: &'a axum_test::TestResponse, name: &HeaderName) -> &'a str {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("response should include requested header")
}

pub fn assert_uuid_header(response: &axum_test::TestResponse) -> String {
    let request_id = header_value(response, &REQUEST_ID);
    Uuid::parse_str(request_id).expect("x-request-id should be UUID shaped");
    request_id.to_string()
}

pub async fn create_request_id_test_server() -> axum_test::TestServer {
    std::env::set_var("AGENT_API_TOKEN", "request-id-contract-test-token");
    crate::common::create_test_server().await
}
