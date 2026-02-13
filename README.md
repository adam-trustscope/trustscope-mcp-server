# TrustScope

Runtime governance for AI agents. Monitor, detect, and audit agent behavior with cryptographic evidence trails.

## Features

- **11 MCP Tools** - Full governance API for AI agents
- **18 Detection Engines** - 10 statistical + 8 pattern-based anomaly detectors
- **Evidence Store** - SQLite with SHA-256 hash chain for tamper-evident audit trails
- **Policy Engine** - Default policy pack with configurable rules
- **Connected Mode** - Cloud sync with PII redaction, NL diagnosis, and signed attestations
- **CLI Commands** - watch, scan, verify, export, cloud connect

## Installation

```bash
npm install trustscope
```

## Quick Start

### MCP Server (Claude Desktop / IDE Integration)

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "trustscope": {
      "command": "npx",
      "args": ["trustscope", "mcp"]
    }
  }
}
```

### Watch Mode (LLM Proxy)

Intercept and monitor LLM API calls:

```bash
# Start proxy on port 8081
npx trustscope watch --port 8081

# Point your LLM client at http://localhost:8081
# Proxy forwards to OpenAI/Anthropic with full monitoring
```

### Hybrid Mode (MCP + Watch)

Run both MCP server and watch proxy with shared evidence store:

```bash
npx trustscope hybrid --port 8081
```

## CLI Commands

```bash
trustscope mcp          # Start MCP server (stdio)
trustscope watch        # Start LLM proxy monitor
trustscope hybrid       # Combined MCP + Watch mode
trustscope scan <dir>   # Scan codebase for security issues
trustscope verify       # Verify evidence chain integrity
trustscope export       # Export traces to CSV/JSON
trustscope cloud connect # Connect to TrustScope cloud
trustscope cloud status  # Check cloud connection status
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `trustscope_check_policy` | Check if action is allowed by policy |
| `trustscope_check_detection` | Run anomaly detection on action |
| `trustscope_log_action` | Log action to evidence store |
| `trustscope_list_traces` | Query evidence store |
| `trustscope_list_policies` | Get active policies |
| `trustscope_list_approvals` | Get pending/approved actions |
| `trustscope_approve` | Approve a pending action |
| `trustscope_get_agent_dna` | Get/update agent behavioral baseline |
| `trustscope_get_compliance` | Generate compliance report |
| `trustscope_explain_behavior` | Analyze agent behavior patterns |
| `trustscope_get_attestation` | Generate signed attestation |

## Detection Engines

### Statistical Engines (10)
- Velocity spike detection
- Entropy analysis
- Time-of-day anomalies
- Session length drift
- Error rate spikes
- Cost anomalies
- Token usage patterns
- Tool concentration
- Burst detection
- Cooldown violations

### Pattern Engines (8)
- Action-label mismatch
- Forbidden tool access
- Privilege escalation
- Data exfiltration patterns
- Prompt injection indicators
- Credential handling
- Looping behavior
- HTTP method mismatches

## Connected Mode

TrustScope can optionally connect to the cloud for enhanced features:

```bash
# Connect to TrustScope cloud
trustscope cloud connect

# Check status
trustscope cloud status
```

### Cloud Features by Tier

| Feature | Monitor | Protect | Protect+ | Enterprise |
|---------|---------|---------|----------|------------|
| Local evidence store | ✓ | ✓ | ✓ | ✓ |
| 18 detection engines | ✓ | ✓ | ✓ | ✓ |
| Cloud sync | ✓ | ✓ | ✓ | ✓ |
| Policy checks | ✓ | ✓ | ✓ | ✓ |
| Behavior analysis | - | ✓ | ✓ | ✓ |
| NL Diagnosis | - | - | ✓ | ✓ |
| Signed attestations | - | - | ✓ | ✓ |
| SIEM integration | - | - | - | ✓ |
| Custom policies | - | - | - | ✓ |

See [docs/CONNECTED_MODE.md](docs/CONNECTED_MODE.md) for details.

## Attestations

Generate cryptographically verifiable attestations of agent behavior:

```bash
# Via MCP tool
trustscope_get_attestation({ agent_id: "my-agent", sign: true })

# Verify signature
trustscope verify --signature attestation.json
```

See [docs/ATTESTATIONS.md](docs/ATTESTATIONS.md) for format and verification details.

## Evidence Store

All traces are stored locally in SQLite with a SHA-256 hash chain:

```
.trustscope/
  evidence.db       # SQLite database
  keys/
    ed25519.key     # Private signing key (mode 0600)
    ed25519.pub     # Public key
```

Verify chain integrity:

```bash
trustscope verify
trustscope verify --verbose  # Show details
trustscope verify --quick    # Last 100 traces only
```

## Privacy

- PII is automatically redacted before cloud sync
- Raw request/response bodies never leave local storage
- Secrets and credentials are detected and masked
- Cloud sync is optional and fails open

## License

MIT
