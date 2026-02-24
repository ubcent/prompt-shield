# Task: Streaming Response Modification

## Objective
Enable Velar to restore masked placeholders in streaming responses from AI providers, not just in complete responses.

## Current State
- Streaming responses are forwarded as-is without restoration
- Placeholders like `[EMAIL_1]` appear in streaming responses to client apps
- This breaks user experience when using streaming mode with AI providers

## Specification

### Functional Requirements
1. Detect when upstream response is streaming (Transfer-Encoding: chunked or SSE)
2. Parse streaming chunks on-the-fly
3. Replace placeholders with original values in each chunk before forwarding
4. Maintain order and timing of chunks
5. Handle partial placeholders split across chunk boundaries

### Technical Requirements
1. Implement `StreamingRestorer` type in `internal/sanitizer/streaming.go`
2. Add buffer for handling split placeholders across chunks
3. Ensure zero memory leaks for long-running streams
4. Preserve original stream timing characteristics (no artificial delays)

### Acceptance Criteria
- [ ] Streaming OpenAI responses correctly restore masked emails/phones
- [ ] Partial chunks with split placeholders are handled correctly
- [ ] Memory usage stays constant during 10-minute streaming session
- [ ] Latency overhead per chunk is < 1ms
- [ ] All existing tests pass

### Testing Requirements
1. Add unit tests for `StreamingRestorer` with mock chunks
2. Add integration test with simulated SSE stream
3. Test edge case: placeholder split exactly at chunk boundary
4. Add benchmark test for chunk processing latency
5. Update `internal/sanitizer/sanitizer_test.go` with streaming scenarios

### Files to Modify
- `internal/proxy/proxy.go` - add streaming detection logic
- `internal/sanitizer/streaming.go` - NEW: implement streaming restorer
- `internal/sanitizer/sanitizer_test.go` - add streaming tests

## Example

**Input stream chunks:**
```
chunk1: "Contact me at [EM"
chunk2: "AIL_1] for details"
```

**Output stream chunks:**
```
chunk1: "Contact me at alice@co"
chunk2: "mpany.com for details"
```

## Non-Goals
- Modifying request streaming (already works)
- Supporting binary stream formats
- Real-time placeholder detection in streams (use existing session state)
