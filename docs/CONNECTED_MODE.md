# Connected Mode

TrustScope works fully offline with local evidence storage. Connected Mode enables optional cloud features for enhanced monitoring and attestations.

## Connecting to Cloud

```bash
# Initiate browser-based authentication
trustscope cloud connect

# Check connection status
trustscope cloud status
```

The connect command:
1. Opens your browser to TrustScope authentication
2. Waits for authentication callback
3. Stores API credentials locally at `~/.trustscope/credentials.json`
4. Offers to import existing local traces to cloud

## Features by Tier

### Monitor (Free)
- Full local evidence store
- All 18 detection engines
- Cloud sync with PII redaction
- Basic policy checks

### Protect
- Everything in Monitor
- Behavioral analysis (`trustscope_explain_behavior`)
- Agent DNA baselines
- Compliance reporting

### Protect+
- Everything in Protect
- **NL Diagnosis**: LLM-powered natural language explanations of detected anomalies
- **Signed Attestations**: Ed25519 cryptographic signatures on attestations

### Enterprise
- Everything in Protect+
- SIEM integration (Splunk, Datadog, etc.)
- Custom policy definitions
- Dedicated support

## Cloud Sync

When connected, traces are automatically synced to the cloud:

```
Local Evidence Store
        │
        ▼
   PII Redaction
        │
        ▼
   Async Queue
        │
        ▼
   Cloud API (with exponential backoff)
```

### Privacy Guarantees

1. **PII Redaction**: All personally identifiable information is stripped before sync
   - Email addresses
   - Phone numbers
   - Credit card numbers
   - Social security numbers
   - IP addresses (internal ranges preserved as placeholders)

2. **Secret Detection**: API keys, passwords, and tokens are masked
   - AWS keys
   - GitHub tokens
   - Database credentials
   - Bearer tokens

3. **Body Exclusion**: Raw request/response bodies never leave local storage

4. **Fail Open**: If cloud is unavailable, local operations continue unaffected

## Trace Import

When connecting for the first time with existing local traces:

```bash
trustscope cloud connect
# Detects 150 local traces
# Prompts: "Import existing traces to cloud? (y/n)"
```

Traces are imported in batches of 100 with progress indication.

## API Key Storage

Credentials are stored at `~/.trustscope/credentials.json` with mode `0600`:

```json
{
  "accessToken": "ts_...",
  "refreshToken": "...",
  "expiresAt": "2024-02-01T00:00:00Z",
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "tier": "protect_plus"
  }
}
```

## Layer 2 NL Diagnosis

With Protect+ tier, `trustscope_explain_behavior` returns natural language explanations:

```json
{
  "diagnosis": [
    {
      "label": "elevated_file_operations",
      "confidence": 0.87,
      "explanation": "The agent performed 47 file write operations in the last hour, compared to a baseline of 12. This spike coincided with a code refactoring task and appears intentional based on the consistent file patterns."
    }
  ]
}
```

Without cloud connection or with lower tier, diagnosis provides statistical labels only.

## Signed Attestations

With Protect+ tier, attestations can be cryptographically signed:

```typescript
// Request signed attestation
trustscope_get_attestation({
  agent_id: "my-agent",
  sign: true
})
```

Response includes Ed25519 signature:

```json
{
  "id": "att_abc123",
  "signed": true,
  "signature": "a1b2c3...",
  "public_key": "d4e5f6...",
  "claims": { ... }
}
```

Verify with CLI:

```bash
trustscope verify --signature attestation.json
```

## Disconnecting

To disconnect from cloud:

```bash
rm ~/.trustscope/credentials.json
```

Local operations continue normally. Queued traces remain in the local sync queue until reconnected or manually cleared.

## Troubleshooting

### "Layer 2 unavailable"

- Check cloud connection: `trustscope cloud status`
- Verify tier includes NL diagnosis: Protect+ required
- Check network connectivity

### "Signing requires protect_plus tier"

- Upgrade at https://trustscope.ai/pricing
- Or omit `sign: true` for unsigned attestations

### Sync queue growing

- Check `trustscope cloud status` for queue size
- Verify network connectivity
- Check for auth errors in sync logs
