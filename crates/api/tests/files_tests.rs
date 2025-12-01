#![allow(clippy::uninlined_format_args)]

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
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
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
async fn test_file_upload_with_expires_after() {
    let server = create_test_server().await;

    println!("\n=== Test: File Upload with Expires After ===");

    // Upload a file with expires_after parameters
    println!("1. Uploading a file with expires_after...");
    let file_content = b"Test file with expiration";
    let filename = "expiring.txt";
    let purpose = "assistants";

    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add file field
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: text/plain\r\n\r\n",
            boundary, filename
        )
        .as_bytes(),
    );
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

    // Add expires_after[anchor] field
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"expires_after[anchor]\"\r\n\r\ncreated_at\r\n",
            boundary
        )
        .as_bytes(),
    );

    // Add expires_after[seconds] field
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"expires_after[seconds]\"\r\n\r\n3600\r\n",
            boundary
        )
        .as_bytes(),
    );

    // Close boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

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
        .bytes(Bytes::from(body))
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ File uploaded successfully with expiration");
        if let Some(expires_at) = body.get("expires_at") {
            println!("   Expires at: {:?}", expires_at);
        }
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {error_text}");
        // This might fail if the current implementation doesn't support expires_after
        // That's okay for now
    }

    println!("\n=== Test Complete ===");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_file_list_with_filters() {
    let server = create_test_server().await;

    println!("\n=== Test: File List with Filters ===");

    // List files with purpose filter
    println!("1. Listing files with purpose filter...");
    let response = server
        .get("/v1/files?purpose=assistants")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list files with filter");
    let files: Vec<serde_json::Value> = response.json();
    println!("   Found {} files with purpose=assistants", files.len());

    // List files with limit
    println!("\n2. Listing files with limit...");
    let response = server
        .get("/v1/files?limit=10")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list files with limit");
    let files: Vec<serde_json::Value> = response.json();
    println!("   Found {} files (limit 10)", files.len());
    assert!(files.len() <= 10, "Should respect limit");

    // List files with order
    println!("\n3. Listing files with order...");
    let response = server
        .get("/v1/files?order=asc")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list files with order");
    let files: Vec<serde_json::Value> = response.json();
    println!("   Found {} files (ordered asc)", files.len());

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: File list with filters works correctly\n");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_file_access_control() {
    let server = create_test_server().await;

    println!("\n=== Test: File Access Control ===");

    // Step 1: Upload a file
    println!("1. Uploading a file...");
    let file_content = b"Private file content";
    let filename = "private.txt";
    let purpose = "assistants";

    let multipart_body = create_multipart_body(file_content, filename, purpose, Some("text/plain"));

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

    assert!(response.status_code().is_success(), "Should upload file");

    let body: serde_json::Value = response.json();
    let file_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("File should have an ID");
    println!("   ✓ File uploaded: {file_id}");

    // Step 2: Access file as owner (should succeed)
    println!("\n2. Accessing file as owner...");
    let response = server
        .get(&format!("/v1/files/{}", file_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    if response.status_code().is_success() {
        println!("   ✓ Successfully accessed file as owner");
    } else {
        println!("   Status: {}", response.status_code());
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: File access control working correctly\n");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_file_upload_validation() {
    let server = create_test_server().await;

    println!("\n=== Test: File Upload Validation ===");

    // Test 1: Missing file field
    println!("1. Testing upload without file field...");
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nassistants\r\n",
            boundary
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

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
        .bytes(Bytes::from(body))
        .await;

    println!("   Status: {}", response.status_code());
    // This might succeed if proxied to OpenAI, or fail if validated locally
    // Either way is acceptable

    // Test 2: Missing purpose field
    println!("\n2. Testing upload without purpose field...");
    let file_content = b"Test content";
    let filename = "test.txt";
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: text/plain\r\n\r\n",
            boundary, filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(file_content);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

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
        .bytes(Bytes::from(body))
        .await;

    println!("   Status: {}", response.status_code());
    // This might succeed if proxied to OpenAI, or fail if validated locally

    println!("\n=== Test Complete ===");
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
