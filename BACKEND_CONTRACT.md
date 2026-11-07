# SignalZero proposed backend contract

Status: **proposed handoff contract**. This repository currently contains no application API routes and does not implement the ML or AI backend. All endpoints below still need to be implemented by the backend engineer unless their service already exposes an equivalent contract.

The frontend validates every successful response with Zod schemas in `lib/types/contracts.ts`. Unknown or malformed responses fail visibly in live mode; the frontend does not substitute demo data.

## Runtime configuration

Copy `.env.example` to `.env.local` for local development.

```env
NEXT_PUBLIC_SIGNALZERO_API_MODE=demo
NEXT_PUBLIC_SIGNALZERO_API_BASE_URL=http://localhost:8000
```

- `demo` is the default and uses repository fixtures.
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

Required: all keys. Nullable: `predictionHorizonDays` and the nullable vulnerability fields documented below.

## GET /api/vulnerabilities

Returns the validated vulnerability collection used by Overview and Hidden Threats.

```json
{
  "vulnerabilities": [
    {
      "cveId": "CVE-2025-12345",
      "description": "Example vulnerability",
      "snapshotMonth": null,
      "cvss": null,
      "epss": 0.14,
      "modelRank": 42,
      "rankingScore": 7.18,
      "rankingScoreKind": "relative",
      "traditionalRank": 684,
      "predictedRisk": "High",
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
      "detectedAt": null
    }
  ],
  "generatedAt": "2025-12-18T14:35:00Z",
  "source": "live"
}
```

`cvss`, `epss`, `modelRank`, `rankingScore`, `traditionalRank`, `predictedRisk`, `snapshotMonth`, `affectedAsset`, and `detectedAt` may be `null`. Indicator `value`, `observedAt`, `source`, and `explanation` may also be `null`.

## GET /api/vulnerabilities/{id}

Returns one vulnerability using the same schema.

```json
{
  "vulnerability": { "cveId": "CVE-2025-12345", "description": "Example vulnerability", "snapshotMonth": null, "cvss": 9.1, "epss": 0.72, "modelRank": 4, "rankingScore": 8.42, "rankingScoreKind": "relative", "traditionalRank": 96, "predictedRisk": "Critical", "evidenceIndicators": [], "affectedAsset": null, "detectedAt": null },
  "source": "live"
}
```

Return `404` with the standard error object when the CVE is unknown.

## GET /api/replay?month=YYYY-MM

Returns rankings frozen at the prediction cutoff, comparison baselines, and outcomes observed only after prediction and no later than the evaluation cutoff.

```json
{
  "month": "2024-02",
  "predictionSnapshot": { "capturedAt": "2024-02-29", "featureCutoff": "2024-02-29" },
  "rankings": [
    {
      "rank": 1,
      "predictedRisk": "Critical",
      "vulnerability": { "cveId": "CVE-2024-21412", "description": "Example historical vulnerability", "snapshotMonth": "2024-02", "cvss": 8.1, "epss": 0.71, "modelRank": 1, "rankingScore": null, "rankingScoreKind": "unknown", "traditionalRank": null, "predictedRisk": "Critical", "evidenceIndicators": [], "affectedAsset": null, "detectedAt": null }
    }
  ],
  "baselines": [
    { "method": "CVSS baseline", "hitsAt500": 251, "note": "Measured with the same cutoff." }
  ],
  "evaluationCutoff": "2024-05-31",
  "laterOutcomes": [
    { "cveId": "CVE-2024-21412", "status": "confirmed-kev", "kevAddedAt": "2024-03-01", "observedByCutoff": true }
  ],
  "source": "live"
}
```

### Historical cutoff rule

Predictive features must contain only information available on or before `featureCutoff`. `laterOutcomes` must never be included in the feature payload. An outcome may be returned only if it was known on or before `evaluationCutoff`; otherwise use `status: "unknown"`, `kevAddedAt: null`, and `observedByCutoff: false`.

## GET /api/assets

```json
{
  "assets": [
    { "assetId": "AST-001", "name": "Identity gateway", "vendor": "Example Vendor", "product": "Gateway", "version": "24.0.4", "environment": "Production", "internetExposed": true, "businessCriticality": "Critical", "owner": "Identity Platform" }
  ],
  "matches": [
    { "cveId": "CVE-2025-12345", "assetId": "AST-001", "matchStatus": "Confirmed", "supportingEvidence": ["Product and version range match."], "predictedRisk": "Critical" }
  ],
  "organizationLabel": "Demo Corp",
  "source": "live"
}
```

Nullable asset fields: `vendor`, `product`, `version`, `internetExposed`, and `owner`. Use `Unknown` for unknown environment or criticality. `organizationLabel` and match `predictedRisk` may be `null`.

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
      "slackDelivery": { "provider": "slack", "status": "delivered", "attemptedAt": "2025-12-18T14:31:00Z", "deliveredAt": "2025-12-18T14:31:01Z", "externalId": "170...", "externalUrl": null, "errorCode": null, "errorMessage": null },
      "jiraDelivery": { "provider": "jira", "status": "not-attempted", "attemptedAt": null, "deliveredAt": null, "externalId": null, "externalUrl": null, "errorCode": null, "errorMessage": null },
      "lifecycle": "Open",
      "occurrenceCount": 2,
      "evidence": ["Product and version match."],
      "history": [{ "timestamp": "2025-12-18T14:42:00Z", "label": "Duplicate merged", "detail": "Existing alert updated.", "kind": "detection" }],
      "dedupeKey": "CVE-2025-12345::AST-001",
      "simulated": false
    }
  ],
  "source": "live"
}
```

`assetName` and every integration result field other than `provider` and `status` may be `null`. Duplicate alert decisions remain backend-owned; use CVE + asset identity as the stable deduplication key.

## Backend implementation checklist

- [ ] `GET /api/overview`
- [ ] `GET /api/vulnerabilities`
- [ ] `GET /api/vulnerabilities/{id}`
- [ ] `GET /api/replay?month=YYYY-MM`
- [ ] `GET /api/assets`
- [ ] `GET /api/alerts`
- [ ] Authentication/server proxy decision, if the backend cannot be called safely from the browser
- [ ] CORS configuration for the SignalZero frontend origin
- [ ] Production environment values and deployment documentation

Slack/Jira mutations, autonomous alert decisions, model training, and prediction execution are intentionally outside this frontend contract.
