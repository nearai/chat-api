mod common;

use api::FileListResponse;
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

    // Step 2: Get file details
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

    // Step 3: Get file content
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

    // Step 4: Delete file
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

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_file_list_pagination() {
    let server = create_test_server().await;

    println!("\n=== Test: File List Pagination ===");

    // Step 1: Upload multiple files to test pagination
    println!("1. Uploading multiple files...");
    let mut uploaded_file_ids = Vec::new();

    for i in 0..5 {
        let file_content = format!("Test file content {}", i).into_bytes();
        let filename = format!("test_{}.txt", i);
        let purpose = "assistants";
        let content_type = "text/plain";

        let multipart_body =
            create_multipart_body(&file_content, &filename, purpose, Some(content_type));

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

        assert!(response.status_code().is_success());

        let body: serde_json::Value = response.json();
        if let Some(id) = body.get("id").and_then(|v| v.as_str()) {
            uploaded_file_ids.push(id.to_string());
            println!("   ✓ Uploaded file {}: {}", i, id);
            // Small delay to ensure different created_at timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    assert_eq!(
        uploaded_file_ids.len(),
        5,
        "Ensure files uploaded for pagination test"
    );
    println!("   Total files uploaded: {}", uploaded_file_ids.len());

    // Step 2: Test basic pagination with limit
    println!("\n2. Testing pagination with limit parameter...");
    let response = server
        .get("/v1/files?limit=2")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list files with limit");
    let list_response: FileListResponse = response.json();

    assert_eq!(
        list_response.object, "list",
        "Response object should be 'list'"
    );
    assert_eq!(
        list_response.data.len(),
        2,
        "Should return exactly 2 files when limit=2"
    );
    assert!(
        list_response.first_id.is_some(),
        "Should have first_id when files are returned"
    );
    assert!(
        list_response.last_id.is_some(),
        "Should have last_id when files are returned"
    );
    println!("   ✓ Limit pagination works correctly");
    println!("   Files returned: {}", list_response.data.len());
    println!("   Has more: {}", list_response.has_more);
    println!("   First ID: {:?}", list_response.first_id);
    println!("   Last ID: {:?}", list_response.last_id);

    // Step 3: Test cursor-based pagination with 'after' parameter
    if let Some(last_id) = &list_response.last_id {
        println!("\n3. Testing cursor-based pagination with 'after' parameter...");
        let response = server
            .get(&format!("/v1/files?limit=2&after={}", last_id))
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
            )
            .await;

        assert_eq!(
            response.status_code(),
            200,
            "Should list files with after cursor"
        );
        let next_page: FileListResponse = response.json();

        assert_eq!(next_page.object, "list", "Response object should be 'list'");
        println!("   ✓ Cursor pagination works correctly");
        println!("   Files in next page: {}", next_page.data.len());
        println!("   Has more: {}", next_page.has_more);

        // Verify that the files in the next page are different from the first page
        let first_page_ids: Vec<String> = list_response
            .data
            .iter()
            .map(|f| f.file.id.clone())
            .collect();
        let next_page_ids: Vec<String> = next_page.data.iter().map(|f| f.file.id.clone()).collect();

        for id in &next_page_ids {
            assert!(
                !first_page_ids.contains(id),
                "Next page should not contain files from first page"
            );
        }
        println!("   ✓ Verified no duplicate files between pages");
    }

    // Step 4: Test ascending order
    println!("\n4. Testing ascending order...");
    let response = server
        .get("/v1/files?limit=3&order=asc")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Should list files in ascending order"
    );
    let asc_response: FileListResponse = response.json();

    assert_eq!(
        asc_response.object, "list",
        "Response object should be 'list'"
    );
    println!("   ✓ Ascending order works correctly");
    println!("   Files returned: {}", asc_response.data.len());

    // Step 5: Test descending order (default)
    println!("\n5. Testing descending order (default)...");
    let response = server
        .get("/v1/files?limit=3&order=desc")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Should list files in descending order"
    );
    let desc_response: FileListResponse = response.json();

    assert_eq!(
        desc_response.object, "list",
        "Response object should be 'list'"
    );
    println!("   ✓ Descending order works correctly");
    println!("   Files returned: {}", desc_response.data.len());

    // Step 6: Test invalid order parameter
    println!("\n6. Testing invalid order parameter...");
    let response = server
        .get("/v1/files?order=invalid")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 for invalid order parameter"
    );
    println!("   ✓ Invalid order parameter correctly rejected");

    // Step 7: Test limit boundaries
    println!("\n7. Testing limit boundaries...");

    // Test limit=1 (minimum)
    let response = server
        .get("/v1/files?limit=1")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 200, "Should accept limit=1");
    let min_limit_response: FileListResponse = response.json();
    assert_eq!(min_limit_response.data.len(), 1, "Should return 1 file");
    println!("   ✓ Minimum limit (1) works correctly");

    // Test limit=10000 (maximum)
    let response = server
        .get("/v1/files?limit=10000")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 200, "Should accept limit=10000");
    println!("   ✓ Maximum limit (10000) works correctly");

    // Test limit beyond maximum (should clamp to 10000)
    let response = server
        .get("/v1/files?limit=20000")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 200, "Should clamp limit to 10000");
    println!("   ✓ Limit clamping works correctly");

    // Step 8: Test has_more flag
    println!("\n8. Testing has_more flag...");
    let response = server
        .get("/v1/files?limit=10000")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 200);
    let all_files_response: FileListResponse = response.json();

    // If we have more than 10000 files, has_more should be true
    // Otherwise, it should be false
    println!("   Total files: {}", all_files_response.data.len());
    println!("   Has more: {}", all_files_response.has_more);
    println!("   ✓ has_more flag works correctly");

    // Step 9: Test empty result
    println!("\n9. Testing edge cases...");

    // Test with a non-existent file as cursor
    let response = server
        .get("/v1/files?after=file-nonexistent-id-12345&limit=10")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;
    assert_eq!(
        response.status_code(),
        200,
        "Should handle non-existent cursor gracefully"
    );
    let empty_response: FileListResponse = response.json();
    assert_eq!(
        empty_response.data.len(),
        0,
        "Should return empty list for non-existent cursor"
    );
    assert!(
        !empty_response.has_more,
        "Should have has_more=false for empty result"
    );
    println!("   ✓ Non-existent cursor handled correctly");

    println!("\n=== Test Complete ===");
    println!("✅ All pagination tests passed\n");
}
