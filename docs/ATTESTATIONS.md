# Attestations

Attestations are cryptographically verifiable statements about agent behavior over a time window. They provide proof of governance participation and compliance.

## Generating Attestations

### Via MCP Tool

```typescript
trustscope_get_attestation({
  agent_id: "my-agent",
  window_start: "2024-01-01T00:00:00Z",  // optional, defaults to 24h ago
  window_end: "2024-01-02T00:00:00Z",    // optional, defaults to now
  sign: true                              // optional, requires protect_plus tier
})
```

### Response Format

```json
{
  "id": "att_abc123xyz789",
  "agent_id": "my-agent",
  "window": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-02T00:00:00Z"
  },
  "claims": {
    "trace_count": 150,
    "blocked_count": 3,
    "compliance_rate": 0.98,
    "chain_valid": true,
    "first_trace": "tr_first123",
    "last_trace": "tr_last456",
    "evidence_root": "sha256:a1b2c3d4...",
    "traces_governed": 142,
    "policy_checks": 87,
    "policy_violations": 3,
    "detections_triggered": 5,
    "participation_score": 94.7,
    "hash_chain_intact": true,
    "enforcement_coverage": "full"
  },
  "signed": true,
  "signature": "8f4a2b1c...",
  "public_key": "d9e8f7a6...",
  "created_at": "2024-01-02T12:00:00Z",
  "note": "Ed25519 signed attestation. Verify with trustscope verify --signature"
}
```

## Claims Reference

| Claim | Type | Description |
|-------|------|-------------|
| `trace_count` | number | Total traces in window |
| `blocked_count` | number | Traces that were blocked |
| `compliance_rate` | number | Ratio of allowed/total (0-1) |
| `chain_valid` | boolean | Hash chain integrity verified |
| `first_trace` | string | ID of first trace in window |
| `last_trace` | string | ID of last trace in window |
| `evidence_root` | string | SHA-256 hash of last trace |
| `traces_governed` | number | Traces from MCP or gateway sources |
| `policy_checks` | number | Number of policy check operations |
| `policy_violations` | number | Blocked policy violations |
| `detections_triggered` | number | Traces with detection alerts |
| `participation_score` | number | Governance participation (0-100) |
| `hash_chain_intact` | boolean | No tampering detected |
| `enforcement_coverage` | string | "none", "partial", or "full" |

## Signing

Attestations are signed using Ed25519:

1. Claims are serialized to canonical JSON (sorted keys, no whitespace)
2. Signed with the private key at `~/.trustscope/keys/ed25519.key`
3. Signature and public key included in response

### Key Management

Keys are stored at:
```
~/.trustscope/keys/
  ed25519.key    # Private key (mode 0600)
  ed25519.pub    # Public key (mode 0644)
```

Keys are automatically generated on first signed attestation request.

### Key Rotation

To rotate keys:

```typescript
// Programmatic
import { rotateKeys } from 'trustscope/crypto/signing';
rotateKeys();
```

Or manually delete and regenerate:
```bash
rm ~/.trustscope/keys/ed25519.*
# Next signed attestation will generate new keys
```

**Warning**: Key rotation invalidates all previous signatures.

## Verification

### CLI Verification

```bash
# Verify attestation file
trustscope verify --signature attestation.json

# Verbose output (shows all claims)
trustscope verify --signature attestation.json --verbose
```

Output:
```
  Attestation Signature Verification
  ────────────────────────────────────

  Attestation ID: att_abc123xyz789
  Agent ID: my-agent
  Public Key: d9e8f7a6...

  ✓ Signature is VALID
  ✓ Public key matches local signing key
```

### Programmatic Verification

```typescript
import { verifyAttestation } from 'trustscope/crypto/signing';

const isValid = verifyAttestation(
  attestation.claims,
  attestation.signature,
  attestation.public_key
);

console.log(isValid); // true or false
```

### Third-Party Verification

Any Ed25519 implementation can verify attestations:

```python
# Python example using nacl
import json
import nacl.signing

claims = {...}  # From attestation.claims
canonical = json.dumps(claims, sort_keys=True, separators=(',', ':'))
signature = bytes.fromhex(attestation['signature'])
public_key = bytes.fromhex(attestation['public_key'])

verify_key = nacl.signing.VerifyKey(public_key)
try:
    verify_key.verify(canonical.encode(), signature)
    print("Valid")
except nacl.exceptions.BadSignature:
    print("Invalid")
```

## Attestation Storage

Attestations are stored in the evidence database:

```sql
SELECT * FROM attestations WHERE agent_id = 'my-agent';
```

## Use Cases

### Compliance Audits

Generate attestations at regular intervals to prove governance:

```typescript
// Daily attestation
trustscope_get_attestation({
  agent_id: "production-agent",
  window_start: yesterday,
  window_end: today,
  sign: true
});
```

### Incident Investigation

After a security event, generate attestation of the window:

```typescript
trustscope_get_attestation({
  agent_id: "agent-involved",
  window_start: "2024-01-15T10:00:00Z",
  window_end: "2024-01-15T12:00:00Z",
  sign: true
});
```

### Third-Party Verification

Share signed attestations with auditors:

1. Export attestation JSON
2. Provide public key
3. Auditor verifies signature independently
4. Claims can be validated against their own observations

## Tier Requirements

| Feature | Tier |
|---------|------|
| Unsigned attestations | Monitor (free) |
| Basic claims | Monitor (free) |
| Enhanced claims | Protect |
| Ed25519 signatures | Protect+ |
| Custom claim fields | Enterprise |
