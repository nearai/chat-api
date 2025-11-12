# End-to-End API Tests

## Overview

This directory contains comprehensive end-to-end tests for the conversation tracking functionality. The tests verify that the API correctly:

1. Tracks conversation IDs per user in the local database
2. Fetches conversation details from OpenAI API on demand
3. Maintains proper access control for conversations
4. Handles edge cases like empty lists and response-triggered tracking

## Architecture Being Tested

The conversation management system works as follows:

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Client    │────────>│  Chat API   │────────>│  Database   │
│             │         │             │         │             │
│             │         │  - Track    │         │  - User IDs │
│             │         │    Conv IDs │         │  - Conv IDs │
└─────────────┘         └─────────────┘         └─────────────┘
                              │
                              │ Fetch Details
                              ▼
                        ┌─────────────┐
                        │  OpenAI API │
                        │             │
                        │  - Titles   │
                        │  - Messages │
                        │  - Metadata │
                        └─────────────┘
```

## Test Cases

### 1. `test_conversation_workflow`
Tests the complete conversation lifecycle:
- Creates a conversation via OpenAI
- Adds multiple responses to the conversation
- Lists conversations and verifies details are fetched from OpenAI
- Confirms that conversation tracking works end-to-end

### 2. `test_conversation_access_control`
Verifies access control mechanisms:
- Creates a conversation for a user
- Attempts to access it as the owner (should succeed)
- Validates proper authorization checks

### 3. `test_empty_conversation_list`
Tests edge case handling:
- Lists conversations when there may be zero or many
- Ensures the endpoint handles all cases gracefully

### 4. `test_conversation_tracking_on_response_creation`
Tests automatic conversation tracking:
- Creates a conversation
- Adds a response (which triggers automatic tracking)
- Verifies the conversation appears in the user's list
- Confirms details are fetched from OpenAI

## Running the Tests

### Prerequisites

1. **Database**: Ensure PostgreSQL is running with the correct schema
2. **Environment Variables**: Set up your `.env` file with:
   ```
   OPENAI_API_KEY=your_api_key_here
   DATABASE_HOST=localhost
   DATABASE_PORT=5432
   DATABASE_NAME=chat_api
   DATABASE_USER=postgres
   DATABASE_PASSWORD=your_password
   ```

3. **Valid Session Token**: The tests use `SESSION_TOKEN` constant - ensure you have a valid session in the database

### Run All Tests

```bash
# Run all E2E tests (they make real OpenAI API calls)
cargo test --test e2e_api_tests -- --ignored --nocapture

# Run a specific test
cargo test --test e2e_api_tests test_conversation_workflow -- --ignored --nocapture
```

### Test Output

The tests provide detailed output showing:
- Step-by-step progress
- API request/response status codes
- Conversation IDs and details
- Success/failure indicators (✓/✗)

Example output:
```
=== Test: Conversation Workflow ===
1. Creating a conversation via OpenAI...
   Status: 200
   ✓ Conversation created successfully
   Conversation ID: conv_abc123...

2. Adding first response to the conversation...
   Status: 200
   ✓ First response created successfully
   Response ID: resp_xyz789...

...

4. Listing conversations (should fetch details from OpenAI)...
   Found 5 total conversations
   ✓ Found our conversation in the list!
      ID: conv_abc123...
      Created: 2025-11-12T10:30:00Z
      Updated: 2025-11-12T10:35:00Z
   ✓ Conversation details fetched from OpenAI

=== Test Complete ===
✅ Test passed: Created conversation, added responses, and listed conversations with OpenAI details
```

## Notes

- Tests are marked with `#[ignore]` because they make real API calls to OpenAI
- Each test is independent and can be run separately
- Tests use the actual database and OpenAI API (not mocks)
- The session token must be valid and exist in your database

## Troubleshooting

**Test fails with "Session not found"**
- Check that `SESSION_TOKEN` constant matches a valid session in your database
- Ensure the session hasn't expired

**Test fails with "OpenAI API error"**
- Verify your `OPENAI_API_KEY` is valid
- Check your OpenAI account has available credits

**Test fails with "Database error"**
- Ensure PostgreSQL is running
- Run migrations: `cargo run --bin migrate` or start the API server once
- Check database connection settings in `.env`

