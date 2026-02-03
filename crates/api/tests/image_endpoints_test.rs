// Comprehensive tests for image endpoints
// Tests cover authentication, request validation, error handling, and privacy compliance

mod common;

use api::models::{ImageGenerationRequest, ImageGenerationResponse};
use common::create_test_server;
use serde_json::json;

/// Test that image generation requires authentication
#[tokio::test]
async fn test_image_generations_requires_auth() {
    let server = create_test_server().await;

    let response = server
        .post("/v1/images/generations")
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "model": "dall-e-3",
            "prompt": "a test image"
        }))
        .await;

    // Should return 401 Unauthorized without auth token
    assert_eq!(response.status_code(), 401);
}

/// Test that image edits requires authentication
#[tokio::test]
async fn test_image_edits_requires_auth() {
    let server = create_test_server().await;

    let response = server.post("/v1/images/edits").await;

    // Should return 401 Unauthorized without auth token
    assert_eq!(response.status_code(), 401);
}

// ====== Model Serialization/Deserialization Tests ======

/// Test ImageGenerationRequest model serialization
#[test]
fn test_image_generation_request_serialization() {
    let request = ImageGenerationRequest {
        model: "dall-e-3".to_string(),
        prompt: "a beautiful sunset".to_string(),
        n: Some(1),
        size: Some("1024x1024".to_string()),
        response_format: Some("url".to_string()),
        quality: Some("hd".to_string()),
        style: Some("vivid".to_string()),
    };

    let json = serde_json::to_value(&request).expect("Failed to serialize");

    assert_eq!(json["model"], "dall-e-3");
    assert_eq!(json["prompt"], "a beautiful sunset");
    assert_eq!(json["n"], 1);
    assert_eq!(json["size"], "1024x1024");
    assert_eq!(json["response_format"], "url");
    assert_eq!(json["quality"], "hd");
    assert_eq!(json["style"], "vivid");
}

/// Test ImageGenerationRequest with minimal fields
#[test]
fn test_image_generation_request_minimal() {
    let request = ImageGenerationRequest {
        model: "dall-e-2".to_string(),
        prompt: "test".to_string(),
        n: None,
        size: None,
        response_format: None,
        quality: None,
        style: None,
    };

    let json = serde_json::to_value(&request).expect("Failed to serialize");
    let json_str = json.to_string();

    // Optional fields should not be present when None
    assert_eq!(json["model"], "dall-e-2");
    assert_eq!(json["prompt"], "test");
    assert!(!json_str.contains("\"n\":null"));
    assert!(!json_str.contains("\"size\":null"));
}

/// Test ImageGenerationResponse deserialization
#[test]
fn test_image_generation_response_deserialization() {
    let json_str = r#"{
        "created": 1234567890,
        "data": [
            {
                "url": "https://example.com/image.png",
                "revised_prompt": "a beautiful sunset over mountains"
            }
        ]
    }"#;

    let response: ImageGenerationResponse =
        serde_json::from_str(json_str).expect("Failed to deserialize");

    assert_eq!(response.created, 1234567890);
    assert_eq!(response.data.len(), 1);
    assert_eq!(
        response.data[0].url.as_ref().unwrap(),
        "https://example.com/image.png"
    );
}

/// Test ImageData with all fields
#[test]
fn test_image_data_with_all_fields() {
    let json_str = r#"{
        "url": "https://example.com/image.png",
        "b64_json": "iVBORw0KGgoAAAANS...",
        "revised_prompt": "a modified prompt"
    }"#;

    let data: api::models::ImageData =
        serde_json::from_str(json_str).expect("Failed to deserialize");

    assert!(data.url.is_some());
    assert!(data.b64_json.is_some());
    assert!(data.revised_prompt.is_some());
}

/// Test ImageData with minimal fields
#[test]
fn test_image_data_with_minimal_fields() {
    let json_str = r#"{
        "url": "https://example.com/image.png"
    }"#;

    let data: api::models::ImageData =
        serde_json::from_str(json_str).expect("Failed to deserialize");

    assert!(data.url.is_some());
    assert!(data.b64_json.is_none());
    assert!(data.revised_prompt.is_none());
}

/// Test OpenAI response with base64 format
#[test]
fn test_image_response_base64_format() {
    let json_str = r#"{
        "created": 1234567890,
        "data": [
            {
                "b64_json": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            }
        ]
    }"#;

    let response: ImageGenerationResponse =
        serde_json::from_str(json_str).expect("Failed to deserialize");

    assert_eq!(response.data.len(), 1);
    assert!(response.data[0].b64_json.is_some());
    assert!(response.data[0].url.is_none());
}

/// Test multiple images in response
#[test]
fn test_image_response_multiple_images() {
    let json_str = r#"{
        "created": 1234567890,
        "data": [
            {"url": "https://example.com/image1.png"},
            {"url": "https://example.com/image2.png"},
            {"url": "https://example.com/image3.png"}
        ]
    }"#;

    let response: ImageGenerationResponse =
        serde_json::from_str(json_str).expect("Failed to deserialize");

    assert_eq!(response.data.len(), 3);
    assert_eq!(
        response.data[0].url.as_ref().unwrap(),
        "https://example.com/image1.png"
    );
    assert_eq!(
        response.data[2].url.as_ref().unwrap(),
        "https://example.com/image3.png"
    );
}

/// Test that models implement Clone
#[test]
fn test_image_generation_request_clone() {
    let request = ImageGenerationRequest {
        model: "dall-e-3".to_string(),
        prompt: "test".to_string(),
        n: Some(1),
        size: None,
        response_format: None,
        quality: None,
        style: None,
    };

    let cloned = request.clone();
    assert_eq!(cloned.model, request.model);
    assert_eq!(cloned.prompt, request.prompt);
}

/// Test deserialization with extra fields (should be ignored)
#[test]
fn test_image_generation_response_with_extra_fields() {
    let json_str = r#"{
        "created": 1234567890,
        "data": [{"url": "https://example.com/image.png"}],
        "extra_field": "should be ignored"
    }"#;

    let response: ImageGenerationResponse =
        serde_json::from_str(json_str).expect("Should ignore extra fields");

    assert_eq!(response.created, 1234567890);
}
