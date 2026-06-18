# CLAUDE.md — Webhook Listener

## Purpose
Receives GitHub push events via webhook, validates payloads, and dispatches
sandbox creation requests. This is the entry point of the entire pipeline.

## Tech
- Runtime: Node.js (Express)
- Entry: server.js
- Port: 3000 (configurable via PORT env var)

## Payload Flow
1. GitHub sends POST to /webhook on push event
2. Validate HMAC signature using WEBHOOK_SECRET
3. Extract repo URL, branch, commit SHA, changed files
4. POST to sandbox manager (Python) with structured payload
5. Return 200 immediately — processing is async

## Validation Rules
- ALWAYS verify X-Hub-Signature-256 header before processing
- Reject non-push events with 204
- Reject payloads > 5MB with 413
- Log all received events (sanitized — no tokens in logs)

## Files
- server.js          → Express app, route handlers
- validate.js        → HMAC signature validation
- dispatch.js        → Sends structured payload to sandbox manager
- package.json       → Node dependencies

## Testing
- Tests live in /tests/webhook/
- Run: npm test (from this directory)
- Mock payloads in /tests/webhook/fixtures/

## Dependencies
- express
- crypto (built-in, for HMAC)
- axios (dispatch to sandbox manager)

## Security Notes
- Never log raw webhook payloads in production
- Never expose WEBHOOK_SECRET in error messages
- Rate limit: 100 requests/minute per IP
