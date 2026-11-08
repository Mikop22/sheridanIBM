# SignalZero proposed backend contract

Status: **implemented Threats and asset-aware decision contract**. FastAPI loads Member 1's prediction export once at startup. The tracked default exposes the genuine top 25 and a configured full CSV exposes the complete cohort. The versioned `/v1` prediction, explanation, and event workflows remain separate backend contracts.

The frontend validates every successful response with Zod schemas in `frontend/lib/types/contracts.ts`. Unknown or malformed responses fail visibly in live mode; the frontend does not substitute demo data.

## Runtime configuration

Copy the root `.env.example` to `frontend/.env.local` for local development.

```env
NEXT_PUBLIC_SIGNALZERO_API_MODE=live
NEXT_PUBLIC_SIGNALZERO_API_BASE_URL=http://127.0.0.1:8000
```

- `demo` remains available and uses explicitly simulated repository fixtures.
- `live` calls the configured base URL and displays configuration, network, HTTP, and validation errors.
- The base URL is public browser configuration. Never place API keys, Slack secrets, Jira credentials, or service tokens in a `NEXT_PUBLIC_` variable.
- If authenticated server-to-server access becomes necessary, add a server-side proxy owned by the backend architecture rather than exposing credentials to the browser.

## Common conventions

- Content type: `application/json`.
- Dates and timestamps: ISO 8601 strings in UTC.
- Months: `YYYY-MM`.
- Missing information is `null`, not `0`, an empty string, or an invented value.
- `rankingScore` is a relative ordering score. It is **not** a calibrated probability. `epss` is the only exploitation probability field in this contract.
- Successful list responses include `source: "live"`.

### Error response

All non-2xx responses should use:

```json
{
  "error": {
    "code": "invalid_month",
    "message": "month must use YYYY-MM format",
    "details": null,
    "requestId": "req_01J..."
  }
}
```

Recommended statuses: `400` invalid input, `404` unknown resource, `409` conflicting state, `422` validation failure, `429` rate limited, and `500/503` backend failure.

## GET /api/overview

Returns dashboard totals plus prioritized vulnerabilities.

```json
{
  "summary": {
    "totalVulnerabilities": 1284,
    "criticalPriority": 18,
    "exposedAssets": 36,
    "predictionHorizonDays": 30
  },
  "priorityVulnerabilities": [
    {
      "cveId": "CVE-2025-12345",
      "description": "Example vulnerability",
      "snapshotMonth": "2025-12",
      "cvss": 9.1,
      "epss": 0.72,
      "modelRank": 4,
      "rankingScore": 8.42,
      "rankingScoreKind": "relative",
      "traditionalRank": 96,
      "predictedRisk": "Critical",
      "evidenceIndicators": [],
      "affectedAsset": { "id": "AST-001", "name": "Identity gateway", "service": "Authentication" },
      "detectedAt": "2025-12-18T14:30:00Z"
    }
  ],
  "generatedAt": "2025-12-18T14:35:00Z",
  "source": "live"
}
```

Required: all keys. Every summary value may be `null` when it cannot be computed. The frontend displays `Not available` and never substitutes demo totals into a live response. Vulnerability nullability is documented below.

## GET /api/vulnerabilities

Returns the validated vulnerability collection used by Overview and Hidden Threats.

```json
{
  "vulnerabilities": [
    {
      "cveId": "CVE-2025-12345",
      "description": null,
      "snapshotMonth": "2026-04",
      "cvss": null,
      "epss": 0.14,
      "modelRank": 1,
      "rankingScore": 0.317252,
      "rankingScoreKind": "relative",
      "traditionalRank": 684,
      "predictedRisk": null,
      "evidenceIndicators": [
        {
          "key": "exploit-chatter",
          "label": "Exploit chatter",
          "value": "rising",
          "status": "present",
          "observedAt": "2025-12-18T00:00:00Z",
          "source": "threat-intelligence",
          "explanation": "Discussion increased before the snapshot cutoff."
        }
      ],
      "affectedAsset": null,
      "detectedAt": null,
      "modelVersion": "member1-v1-locked-ensemble",
      "scoreScale": {"minimum": 0.0, "maximum": 1.0, "higher_is_riskier": true},
      "scoreInterpretation": "Relative ensemble ranking score; not a calibrated exploitation probability.",
      "componentScores": {"score_v1_ensemble": 0.317252},
      "artifact": {"artifactId": "sha256:...", "sourceKind": "summary_json", "recordCount": 25},
      "missingInformation": ["vulnerability description", "CVSS score", "EPSS score", "affected asset associations"],
      "assetMatchStatus": "unknown",
      "investigationState": "investigating",
      "operationalDecision": "INVESTIGATE",
      "decisionReasons": [{"code": "NO_EXPLICIT_ASSET_MAPPING", "message": "No synthetic scenario mapping exists.", "sourceRefs": ["asset:mapping:missing"]}],
      "assetDecisions": [],
      "remediationEligibility": "NEEDS_INVESTIGATION",
      "agentEligible": false,
      "suggestedAction": "Validate whether the finding applies to any inventoried asset.",
      "groundedExplanation": {"provider": "local", "generation_status": "complete"}
    }
  ],
  "generatedAt": null,
  "source": "live"
}
```

`description`, `cvss`, `epss`, `traditionalRank`, `predictedRisk`, `affectedAsset`, `detectedAt`, and `generatedAt` may be `null`. The model rank and ranking score are present for validated artifact rows. Operational priority is separate from the uncalibrated ranking score. `assetDecisions` preserves every per-asset outcome even when the top-level fields show the deterministic highest-priority aggregate.

## GET /api/vulnerabilities/{id}

Returns one vulnerability using the same schema.

```json
{
  "vulnerability": { "cveId": "CVE-2025-12345", "description": "Example vulnerability", "snapshotMonth": null, "cvss": 9.1, "epss": 0.72, "modelRank": 4, "rankingScore": 8.42, "rankingScoreKind": "relative", "traditionalRank": 96, "predictedRisk": "Critical", "evidenceIndicators": [], "affectedAsset": null, "detectedAt": null },
  "source": "live"
}
```

Return `404` with the standard error object when the CVE is unknown.

## Historical evaluation

There is no user-facing replay route. Temporal evaluation, leakage validation, and
Hits@K comparison remain internal backend/model capabilities and are not dashboard
presentation contracts.

## GET /api/assets

```json
{
  "assets": [
    { "assetId": "demo-asset-identity", "name": "Demo Identity Gateway", "vendor": null, "product": "demo-auth-middleware", "version": "4.2.0-synthetic", "environment": "Production", "internetExposed": true, "businessCriticality": "Critical", "owner": "Demo Identity Team", "repositoryIdentifier": "demo/identity-gateway", "componentPackage": "demo-auth-middleware", "synthetic": true }
  ],
  "matches": [
    { "cveId": "CVE-2026-2699", "assetId": "demo-asset-identity", "matchStatus": "Confirmed", "canonicalMatchStatus": "confirmed_affected", "supportingEvidence": ["Synthetic scenario assertion only; not verified real-world CVE applicability."], "predictedRisk": null, "provenance": "internally_consistent_synthetic_scenario_not_external_product_intelligence" }
  ],
  "organizationLabel": "SignalZero Synthetic Demo Organization",
  "synthetic": true,
  "provenance": "internally_consistent_synthetic_scenario_not_external_product_intelligence",
  "source": "live"
}
```

Nullable asset fields: `vendor`, `product`, `version`, `internetExposed`, `owner`, `repositoryIdentifier`, and `componentPackage`. Use `Unknown` for unknown environment or criticality. `verified_for_demo` never means externally verified CVE applicability. Missing mappings remain unknown, not unaffected.

## GET /api/alerts

```json
{
  "alerts": [
    {
      "alertId": "ALT-1048",
      "cveId": "CVE-2025-12345",
      "assetId": "AST-001",
      "assetName": "Identity gateway",
      "priority": "Critical",
      "triggerReason": "Confirmed exposed match entered the critical tier.",
      "createdAt": "2025-12-18T14:30:00Z",
      "updatedAt": "2025-12-18T14:42:00Z",
      "slackDelivery": { "provider": "slack", "status": "delivered", "operation": null, "attemptedAt": "2025-12-18T14:31:00Z", "deliveredAt": "2025-12-18T14:31:01Z", "externalId": "170...", "externalUrl": null, "errorCode": null, "errorMessage": null },
      "jiraDelivery": { "provider": "jira", "status": "delivered", "operation": "updated", "attemptedAt": "2025-12-18T14:31:00Z", "deliveredAt": "2025-12-18T14:31:02Z", "externalId": "SEC-1048", "externalUrl": "https://jira.example.invalid/browse/SEC-1048", "errorCode": null, "errorMessage": null },
      "lifecycle": "Open",
      "occurrenceCount": 2,
      "evidence": ["Product and version match."],
      "history": [{ "timestamp": "2025-12-18T14:42:00Z", "label": "Duplicate merged", "detail": "Existing alert updated.", "kind": "detection" }],
      "dedupeKey": "CVE-2025-12345::AST-001",
      "simulated": false
    }
  ],
  "decisions": [
    {
      "recommendationId": "rec-...",
      "findingId": "finding-...",
      "cveId": "CVE-2026-2699",
      "assetId": "demo-asset-identity",
      "operationalDecision": "URGENT",
      "workflowStatus": "pending_approval",
      "reasonCodes": ["VERIFIED_SYNTHETIC_ASSET_MATCH", "TOP_RANKED_CRITICAL_EXPOSED_ASSET"],
      "evidenceRefs": ["prediction:rank", "demo-evidence-identity-match"],
      "remediationEligibility": "CODE_REMEDIABLE",
      "agentEligible": true,
      "executionAuthorized": false,
      "proposedNextAction": "Prioritize immediate human review and remediation planning; do not execute changes.",
      "createdAt": "2026-04-30T23:59:59Z",
      "decidedAt": null,
      "decidedBy": null,
      "decisionReason": null,
      "activityHistory": [{"eventId": "synthetic-event-001", "processedAt": "2026-04-30T23:59:59Z", "reasonCode": "VERIFIED_SYNTHETIC_ASSET_MATCH", "reusedRecommendation": false}]
    }
  ],
  "source": "live"
}
```

`assetName` and every integration result field other than `provider`, `status`, and `operation` may be `null`. `operation` is required but nullable: use `created`, `updated`, or `commented` for a successful Jira operation and `null` for Slack or when no Jira operation completed. A `delivered` Jira result with `operation: null` is displayed only as delivered; the frontend does not assume a ticket was created.

Delivery status is one of `not-attempted`, `pending`, `delivered`, `failed`, or `simulated-not-sent`. Slack and Jira states are independent, so partial delivery is represented by returning each provider's actual state. Do not report `delivered` without provider confirmation. Use `failed` with `errorCode`/`errorMessage` for confirmed failure and `pending` when the final state is not yet known.

Duplicate alert decisions remain backend-owned; use CVE + asset identity as the stable deduplication key.

The `alerts` array remains the compatibility surface for future provider-confirmed Slack
and Jira activity. Iteration 6 populates `decisions` only. `agentEligible` records
technical eligibility for a future job; `executionAuthorized` remains false and no
coding agent is invoked.

## Backend implementation checklist

- [x] `GET /api/overview`
- [x] `GET /api/vulnerabilities`
- [x] `GET /api/vulnerabilities/{id}`
- [x] `/api/replay` removed
- [x] `GET /api/assets`
- [x] `GET /api/alerts`
- [x] Direct unauthenticated loopback access for the local milestone; no browser secret is required
- [x] Explicit CORS configuration for `http://localhost:3000`
- [ ] Production environment values and deployment documentation
- [ ] Server-side Slack/Jira adapters, credentials, retry policy, and provider-confirmed delivery results

Slack/Jira mutations, autonomous alert decisions, model training, and prediction execution are intentionally outside this frontend contract.
