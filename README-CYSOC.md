# CYSOC Terminal and Autonomous SOC Analyst

CYSOC is EasyShark v2's terminal-native security operations workspace. It combines
packet forensics, natural-language investigation, durable alert/case management,
multi-sensor correlation, independent evaluation oracles, and safely bounded response
automation in one terminal.

This guide covers two related features:

- **SOC analyst mode:** runs an autonomous evidence-backed investigation and creates
  a prioritized SOC assessment.
- **CYSOC terminal:** provides the persistent operational workspace used to triage
  alerts, investigate cases, hunt entities, correlate telemetry, and manage response.

V2 does not contain or serve the web UI. The web UI remains in the sibling V3 tree.

## 1. Quick start

Install the normal v2 dependencies and open a capture:

```powershell
python main.py .\capture.pcap
```

From the EasyShark prompt, open CYSOC:

```text
pcap > soc-analyst terminal
```

The direct alias is:

```text
pcap > cysoc-terminal
```

Run autonomous SOC triage:

```text
cysoc > triage Investigate possible command-and-control activity
```

Return to the normal EasyShark terminal without terminating it:

```text
cysoc > back
```

`exit`, `quit`, and `main` have the same return behavior inside CYSOC.

## 2. One-shot SOC analyst mode

SOC analyst mode can run without entering the interactive terminal:

```powershell
python main.py .\capture.pcap --autonomous --mode soc-analyst `
  --mission "Triage, scope, and document suspicious activity"
```

Linux/macOS equivalent:

```bash
python3 main.py capture.pcap --autonomous --mode soc-analyst \
  --mission "Triage, scope, and document suspicious activity"
```

Inside the normal shell, the equivalent command is:

```text
pcap > soc-analyst Triage, scope, and document suspicious activity
```

The saved report includes:

- P1–P4 priority and disposition.
- Grounded evidence coverage, or an explicit “not measured” value when the report
  contains no evidence-graph claims.
- Preserved raw, numeric, critic, and calibrated hypothesis confidence.
- Affected-host scope and configured asset materiality.
- Normalized and deduplicated IOCs.
- Threat-intelligence quality rather than presence-only escalation.
- MITRE techniques, adversary next-step projections, and recommended hunts.
- Finding-specific local and approval-gated response recommendations.
- Human-review decision and concrete reasons.

The report is automatically registered as a durable CYSOC case.

## 3. What happens during triage

```text
capture
  -> packet metadata and bidirectional flows
  -> deterministic detectors and TLS fingerprints
  -> behavioral-baseline comparison
  -> evidence bundle, narrative, and evidence graph
  -> hypothesis DAG and local forensic tools
  -> within-run critic
  -> final incident synthesis
  -> autonomous SOC assessment
  -> durable case, timeline, recommendations, and oracle records
```

The critic can accept or reject evidence inside the current investigation. It is not
treated as ground truth for future learning. Automatic cross-run learning is gated by
independent oracle outcomes.

## 4. CYSOC command reference

### Environment and alert queue

```text
overview                         Current capture, model, case, and event status
pulse                            Active alert counts, cases, and hot assets
queue [p1,p2] [status=new]       Prioritized alert queue
alert ack <alert-id>             Acknowledge an alert
alert close <alert-id>           Close an alert
alert false-positive <alert-id>  Record a false positive
alert reopen <alert-id>          Return an alert to the new queue
detections                       Rule volume and false-positive health
```

### Telemetry ingestion and connectors

```text
ingest <file.json|jsonl> [source]
autotriage [limit] [window-seconds]
connectors
connector pull <source> <https-url> [TOKEN_ENV]
```

Imports normalize common SIEM, EDR, identity, DNS, firewall, proxy, email, and cloud
fields into vendor-neutral observations while retaining the original JSON for audit.
Terminal imports and HTTPS pulls automatically group new alerts into cases using
structured asset, identity, IOC, and address fields. Grouping is time-bounded,
idempotent, promotes priority when stronger evidence arrives, and never executes a
response. `autotriage` processes any older unlinked alerts explicitly.

The HTTPS connector is read-only and requires:

- An `https://` URL.
- The exact hostname in `EASYSHARK_CONNECTOR_HOSTS`.
- An optional token supplied through the named environment variable.
- A bounded JSON response.

Example:

```powershell
$env:EASYSHARK_CONNECTOR_HOSTS="sentinel.example.com,splunk.example.com"
$env:SENTINEL_TOKEN="replace-with-secret"
```

```text
cysoc > connector pull sentinel https://sentinel.example.com/api/alerts SENTINEL_TOKEN
```

### Cases and timelines

```text
cases [status]
case <case-id>
case create <P1|P2|P3|P4> <title>
case assign <case-id> <analyst>
case status <case-id> <status>
case priority <case-id> <P1|P2|P3|P4>
case disposition <case-id> <value>
case note <case-id> <note>
case link <case-id> <alert-id>
case timeline <case-id>
```

Cases, linked alerts, notes, report imports, decisions, and response requests are
retained in the case timeline.

### Hunting, correlation, and fusion

```text
hunt <IP|host|identity|IOC|text>
correlate <entity>
fuse [entity]
similar <case-id|case description>
campaign list
campaign build <case-id>
```

- `hunt` searches alerts, normalized observations, and cases.
- `correlate` shows the cross-source timeline for one entity.
- `fuse` requires observations from at least two independent sources in the active
  15-minute window.
- `similar` uses local case vectors; case content is not sent to an embedding API.
- `campaign build` groups a seed case with sufficiently similar historical cases.

### Behavioral baselines

```text
baseline status
baseline observe <entity> <feature> <numeric-value>
baseline check <entity> <feature> <numeric-value>
```

Baselines are separated by entity, feature, and hour of day. Fewer than five samples
returns `ready: false`. During autonomous triage, a flow is checked before the current
observation is learned.

Examples:

```text
cysoc > baseline observe FIN-LAPTOP-22 bytes_out 120000
cysoc > baseline check FIN-LAPTOP-22 bytes_out 5000000
```

### Oracles, calibration, and benchmarking

```text
benchmark generate <directory>
benchmark corpus <manifest.json>
oracle
oracle rederive <report.json>
rescore-intel <threat-intel.json>
```

Supported independent oracle sources are:

1. Labelled capture corpus.
2. Synthetic attack captures.
3. Deterministic evidence-graph re-derivation.
4. Delayed threat-intelligence labels.
5. Agreement between deterministic and model investigation paths.

Corpus results include precision, recall, Brier score, and expected calibration error
(ECE). Generate and run a smoke corpus:

```text
cysoc > benchmark generate ".easyshark/synthetic-corpus"
cysoc > benchmark corpus ".easyshark/synthetic-corpus/manifest.json"
cysoc > benchmark corpus "PCAP_SAMPLES/generated/manifest.json"
cysoc > oracle
```

The generated seven-case suite contains a benign control plus deterministic beaconing,
horizontal scanning, DNS tunnelling, exfiltration, direct prompt injection, and
fragmented prompt injection captures. Its versioned manifest records SHA-256,
generator version, seed, source, and license for every PCAP. The runner rejects empty
or unsupported manifests, duplicate case IDs, path escapes, missing files, and hash
mismatches. This verifies detector plumbing; it is not a production accuracy benchmark.
Production validation still requires the independently labelled corpus described in
`agentcontext/test.md`.

### Threat intelligence

```text
update-feeds [feodo|urlhaus|threatfox]
ioc-check <IP|domain|URL|hash>
rescore-intel <local-feed.json>
```

Remote providers require their documented API keys. Threat-intelligence presence
alone never forces a P1. The SOC assessment distinguishes unknown, malicious, and
independently supported records.

### Response and approval

```text
action request <case-id> <action>
action approve <action-id> [approver]
action deny <action-id> [approver]
response local <case-id> <tag|watchlist|snapshot> <target> [ttl-seconds]
response status [case-id]
response expire
```

Response levels are deliberately separate:

| Level | Examples | Current behavior |
|---|---|---|
| Local reversible | tag, watchlist, snapshot | Stored locally with TTL and automatic reversion |
| Approval-gated | isolate, block, disable account, quarantine | Approval is recorded; no external execution occurs without a separate authenticated connector |
| Prohibited | delete, wipe, destroy, exfiltrate | Rejected |

Approving an action does not execute it. EasyShark currently ships no automatically
enabled production containment connector.

### Packet-forensics commands available inside CYSOC

CYSOC delegates the existing EasyShark forensic surface:

```text
anomalies | timeline
analyze <natural-language question>
investigate <question>
report
alerts | packets | flows
protocols | ips | dns | creds
filter <expression> | search <regex>
dissect <packet-number> | hex <packet-number>
follow tcp|udp <flow-number>
events [limit]
reports | evidence [index]
sessions | memory
capture ...
```

## 5. Detection capabilities

The deterministic path currently covers:

- Beaconing.
- DNS anomalies and tunnelling signals.
- Exfiltration ratios and volume.
- Horizontal and vertical scanning.
- Protocol/port mismatch.
- Lateral movement.
- Long and low-and-slow connections.
- Domain-reputation signals.
- TLS ClientHello metadata anomalies with JA3/JA4-style fingerprints.
- Prompt-injection-like packet payloads.

TLS inspection does not decrypt application content. Missing SNI or a rare
fingerprint is evidence for investigation, not automatic proof of compromise.

## 6. Asset materiality

Set `EASYSHARK_ASSET_POLICY` to a local JSON file using the format in
`config/assets.example.json`:

```json
{
  "assets": {
    "FIN-LAPTOP-22": {
      "criticality": "high",
      "owner": "finance",
      "tags": ["regulated"]
    }
  }
}
```

Criticality is one priority input. It cannot turn unsupported model output into a
confirmed incident.

## 7. Prompt-injection boundary

Traffic and imported security events are attacker-controlled input. EasyShark:

- Wraps packet/tool evidence in typed untrusted-observation envelopes.
- Never places packet-derived text in a system-prompt position.
- Marks observed content as having no instruction semantics.
- Detects instruction-like content as a security finding.
- Blocks injection-like content from the local response path.

Prompt-injection protection is a release gate for any future external response
connector. The remaining red-team tests are listed in `agentcontext/test.md`.

## 8. Recursive learning

Automatic tool and prompt patterns are learned only from independent oracle outcomes.
The RSI lifecycle remains:

```text
candidate -> at least 3 oracle labels -> active at >=0.75
                                  \----> retired below 0.40
```

The critic is an in-run quality gate and never automatic cross-run fitness. Explicit
analyst feedback remains available as a compatibility/manual override.

## 9. Model providers and degradation

The active cloud routing order is:

```text
OpenCode Zen -> OpenRouter -> Groq -> deterministic/offline degradation
```

Provider keys and per-role model overrides are documented in `.env.example`.
The architecture is cloud-only — no local model daemon is used.

If every provider is unavailable, deterministic packet commands, detections, hunting,
cases, timelines, reports, and local SOC operations remain available. A model-backed
answer may degrade or be unavailable rather than inventing evidence.

## 10. Generated-code sandbox

Generated analysis code uses the local-process sandbox by default. Available modes:

```powershell
$env:EASYSHARK_SANDBOX_BACKEND="local"       # default
$env:EASYSHARK_SANDBOX_BACKEND="auto"        # OpenSandbox when configured
$env:EASYSHARK_SANDBOX_BACKEND="opensandbox" # require OpenSandbox
```

For OpenSandbox, install `requirements-opensandbox.txt` and configure:

```powershell
$env:OPEN_SANDBOX_DOMAIN="localhost:8080"
$env:OPEN_SANDBOX_PROTOCOL="http"
$env:OPEN_SANDBOX_API_KEY="replace-if-required"
```

The adapter applies resource/output/time limits, deny-by-default egress, and cleanup.
It receives analysis context rather than the original PCAP file. OpenSandbox escape
and failure-mode testing remains a production-readiness requirement.

## 11. Storage and configuration

| Purpose | Default | Override |
|---|---|---|
| SOC alerts, observations, cases, actions, baselines | `~/.easyshark/cysoc.db` | `EASYSHARK_SOC_DB` |
| Oracle outcomes and calibration | `~/.easyshark/oracle.db` | `EASYSHARK_ORACLE_DB` |
| Reports | `~/.easyshark/reports/` | `EASYSHARK_REPORTS_DIR` |
| Threat-intelligence cache | `~/.easyshark/threat-intel.json` | `EASYSHARK_THREAT_FEED_CACHE` |
| Asset criticality | none | `EASYSHARK_ASSET_POLICY` |
| Connector hosts | deny all | `EASYSHARK_CONNECTOR_HOSTS` |

PCAP bytes remain local. Connector tokens and provider keys belong in environment
variables and must not be written into reports or commands saved in shell history.

## 12. Example SOC workflow

```text
pcap > soc-analyst terminal
cysoc > ingest sentinel-alerts.jsonl sentinel
cysoc > ingest edr-events.jsonl edr
cysoc > pulse
cysoc > queue p1,p2
cysoc > fuse FIN-LAPTOP-22
cysoc > triage Investigate FIN-LAPTOP-22 and scope related activity
cysoc > cases
cysoc > case CYSOC-20260812-AB12
cysoc > correlate FIN-LAPTOP-22
cysoc > hunt bad.example
cysoc > similar CYSOC-20260812-AB12
cysoc > campaign build CYSOC-20260812-AB12
cysoc > case note CYSOC-20260812-AB12 EDR collection requested
cysoc > response local CYSOC-20260812-AB12 watchlist bad.example 3600
cysoc > action request CYSOC-20260812-AB12 Isolate FIN-LAPTOP-22
cysoc > action approve 1 soc-lead
```

The final approval line records authorization only. It does not isolate the endpoint.

## 13. Current validation status

Locally verified:

- Python compilation.
- Automated unit and integration regression suite.
- CYSOC entry and return behavior.
- Alert, case, hunt, and approval workflows.
- Synthetic corpus generation and scoring.
- Behavioral baseline, multi-sensor fusion, case retrieval, campaigns, and expiring
  local-response state.
- Prompt-injection finding and untrusted evidence boundaries.

Still required before production readiness:

- At least 500 independently labelled captures.
- Held-out ECE below 0.10.
- Demonstrated false-positive reduction without recall regression.
- Model-backed prompt-injection red-team runs over generated and external captures.
- Production connector testing in vendor test tenants.
- Sandbox escape, scale, recovery, and soak testing.
- Connector-specific external-response safety testing.

See the complete checklist in [`agentcontext/test.md`](agentcontext/test.md).

## 14. Related documentation

- [`agentcontext/architecture.md`](agentcontext/architecture.md) — current v2
  architecture and trust boundaries.
- [`agentcontext/soc.md`](agentcontext/soc.md) — gap analysis, implementation record,
  and success criteria.
- [`agentcontext/test.md`](agentcontext/test.md) — remaining functional and production
  validation plan.
- [`README.md`](README.md) — general EasyShark installation and command guide.
