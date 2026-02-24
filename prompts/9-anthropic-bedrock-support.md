# Task: Anthropic & AWS Bedrock Support

## Objective
Add first-class support for Anthropic's Claude API and AWS Bedrock with provider-specific optimizations.

## Current State
- Generic HTTPS proxy works but no provider-specific handling
- No awareness of Anthropic/Bedrock message formats
- No optimized masking for Claude's message structure

## Specification

### Functional Requirements
1. Auto-detect Anthropic API requests:
   - Host: `api.anthropic.com`
   - Endpoints: `/v1/messages`, `/v1/complete`
2. Auto-detect AWS Bedrock requests:
   - Host: `bedrock-runtime.*.amazonaws.com`
   - Model IDs: `anthropic.claude-*`, `meta.llama*`, etc.
3. Provider-specific request parsing:
   - Anthropic: messages array with `content` blocks
   - Bedrock: body encoded in JSON under `body` field
4. Deep content inspection:
   - Scan text content in all message roles (user, assistant)
   - Scan tool definitions and parameters
   - Preserve JSON structure after masking
5. Provider metadata in audit log:
   - Model name/ID
   - Token counts (if available)
   - Provider-specific request IDs

### Technical Requirements
1. Implement `internal/providers/anthropic.go`:
   - `AnthropicProvider` implementing `Provider` interface
   - Request/response parsing for Messages API
   - Streaming support for SSE responses
2. Implement `internal/providers/bedrock.go`:
   - `BedrockProvider` implementing `Provider` interface
   - AWS signature verification (optional)
   - Multi-model support (Claude, Llama, etc.)
3. Add `internal/providers/provider.go` interface:
   ```go
   type Provider interface {
       Name() string
       Matches(req *http.Request) bool
       ParseRequest(body []byte) (*ProviderRequest, error)
       ParseResponse(body []byte) (*ProviderResponse, error)
       MaskRequest(req *ProviderRequest, items []SanitizedItem) ([]byte, error)
       RestoreResponse(resp *ProviderResponse, items []SanitizedItem) ([]byte, error)
   }
   ```
4. Integrate with existing proxy inspector

### Acceptance Criteria
- [ ] Anthropic Messages API requests are correctly parsed
- [ ] Bedrock Claude requests are correctly parsed
- [ ] Masking preserves JSON structure and escaping
- [ ] Streaming responses work for both providers
- [ ] Provider metadata appears in audit logs
- [ ] Works with existing OpenAI support
- [ ] All existing tests pass

### Testing Requirements
1. Add unit tests for Anthropic message parsing
2. Add unit tests for Bedrock message parsing
3. Test with real Anthropic API (integration test with mock)
4. Test with AWS Bedrock (integration test with mock)
5. Test streaming responses for both providers
6. Add tests in `internal/providers/anthropic_test.go`
7. Add tests in `internal/providers/bedrock_test.go`

### Files to Create/Modify
- `internal/providers/provider.go` - NEW: provider interface
- `internal/providers/anthropic.go` - NEW: Anthropic provider
- `internal/providers/anthropic_test.go` - NEW: Anthropic tests
- `internal/providers/bedrock.go` - NEW: Bedrock provider
- `internal/providers/bedrock_test.go` - NEW: Bedrock tests
- `internal/proxy/mitm/inspector.go` - integrate provider detection
- `internal/audit/audit.go` - add provider metadata fields
- `README.md` - document Anthropic/Bedrock support

## Anthropic API Example

### Request Format
```json
POST https://api.anthropic.com/v1/messages
x-api-key: sk-ant-...
anthropic-version: 2023-06-01

{
  "model": "claude-3-5-sonnet-20241022",
  "max_tokens": 1024,
  "messages": [
    {
      "role": "user",
      "content": "Contact me at alice@company.com"
    }
  ]
}
```

### Masked Request
```json
{
  "model": "claude-3-5-sonnet-20241022",
  "max_tokens": 1024,
  "messages": [
    {
      "role": "user",
      "content": "Contact me at [EMAIL_1]"
    }
  ]
}
```

### Response Format
```json
{
  "id": "msg_123",
  "type": "message",
  "role": "assistant",
  "content": [
    {
      "type": "text",
      "text": "I'll reach out to [EMAIL_1] shortly."
    }
  ],
  "model": "claude-3-5-sonnet-20241022",
  "usage": {
    "input_tokens": 15,
    "output_tokens": 10
  }
}
```

### Restored Response
```json
{
  "content": [
    {
      "type": "text",
      "text": "I'll reach out to alice@company.com shortly."
    }
  ]
}
```

## AWS Bedrock Example

### Request Format
```json
POST https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke

{
  "anthropic_version": "bedrock-2023-05-31",
  "max_tokens": 1024,
  "messages": [
    {
      "role": "user",
      "content": [{"type": "text", "text": "My API key is sk-1234567890abcdef"}]
    }
  ]
}
```

### Masked Request
```json
{
  "messages": [
    {
      "role": "user",
      "content": [{"type": "text", "text": "My API key is [API_KEY_1]"}]
    }
  ]
}
```

## Non-Goals
- Supporting all Bedrock models (focus on Claude + popular ones)
- AWS credentials management or signing
- Token counting or cost estimation
- Rate limiting or quota management
