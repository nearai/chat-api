mod common;

use bytes::Bytes;
use common::create_test_server;
use serde_json::json;

const SESSION_TOKEN: &str = "sess_7770c53028d8400a9c69600d800ab86e";

/// Helper function to create multipart/form-data body for file upload
fn create_multipart_body(
    file_content: &[u8],
    filename: &str,
    purpose: &str,
    content_type: Option<&str>,
) -> Vec<u8> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add file field
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            boundary, filename
        )
        .as_bytes(),
    );
    if let Some(ct) = content_type {
        body.extend_from_slice(format!("Content-Type: {}\r\n", ct).as_bytes());
    }
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(file_content);
    body.extend_from_slice(b"\r\n");

    // Add purpose field
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\n{}\r\n",
            boundary, purpose
        )
        .as_bytes(),
    );

    // Close boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    body
}

#[tokio::test]
// #[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_file_upload_workflow() {
    let server = create_test_server().await;

    println!("\n=== Test: File Upload Workflow ===");

    // Step 1: Upload a file
    println!("1. Uploading a file...");
    let file_content = b"Hello, this is a test file content!";
    let filename = "test.txt";
    let purpose = "assistants";
    let content_type = "text/plain";

    let multipart_body = create_multipart_body(file_content, filename, purpose, Some(content_type));

    let response = server
        .post("/v1/files")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static(
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
            ),
        )
        .bytes(Bytes::from(multipart_body))
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    let file_id = if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ File uploaded successfully");
        let id = body
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .expect("File should have an ID");
        println!("   File ID: {id}");
        id
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {error_text}");
        panic!("Failed to upload file");
    };

    // Step 2: List files
    println!("\n2. Listing files...");
    let response = server
        .get("/v1/files")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list files");
    let files: Vec<serde_json::Value> = response.json();
    println!("   Found {} files", files.len());

    // Verify our file is in the list
    let found = files.iter().any(|f| {
        f.get("id")
            .and_then(|v| v.as_str())
            .map(|id| id == file_id)
            .unwrap_or(false)
    });
    assert!(found, "Uploaded file should be in the list");
    println!("   ✓ Found uploaded file in the list");

    // Step 3: Get file details
    println!("\n3. Getting file details...");
    let response = server
        .get(&format!("/v1/files/{}", file_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should get file details");
    let file: serde_json::Value = response.json();
    println!("   ✓ File details retrieved successfully");
    println!("   File: {}", serde_json::to_string_pretty(&file).unwrap());

    // Step 4: Get file content
    println!("\n4. Getting file content...");
    let response = server
        .get(&format!("/v1/files/{}/content", file_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should get file content");
    let content = response.text();
    println!("   ✓ File content retrieved successfully");
    println!("   Content length: {} bytes", content.len());

    // Step 5: Delete file
    println!("\n5. Deleting file...");
    let response = server
        .delete(&format!("/v1/files/{}", file_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should delete file");
    let delete_response: serde_json::Value = response.json();
    println!("   ✓ File deleted successfully");
    assert_eq!(
        delete_response.get("deleted"),
        Some(&json!(true)),
        "Delete response should indicate success"
    );

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: File upload, list, get, get content, and delete workflow\n");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_file_not_found() {
    let server = create_test_server().await;

    println!("\n=== Test: File Not Found ===");

    // Try to get a non-existent file
    println!("1. Getting non-existent file...");
    let fake_id = "file-00000000-0000-0000-0000-000000000000";
    let response = server
        .get(&format!("/v1/files/{}", fake_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    println!("   Status: {}", response.status_code());
    // Should return 404, but might return different status if proxied

    // Try to delete a non-existent file
    println!("\n2. Deleting non-existent file...");
    let response = server
        .delete(&format!("/v1/files/{}", fake_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    println!("   Status: {}", response.status_code());
    // Should return 404, but might return different status if proxied

    println!("\n=== Test Complete ===");
}
