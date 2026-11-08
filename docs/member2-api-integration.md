# Member 2 API integration

Core backend paths are under `/v1`; the frontend compatibility paths use `/api`.
Payloads reject unexpected
fields, and errors use the stable envelope:

```json
{
  "schema_version": "1.0",
  "error": {"code": "validation_error", "message": "Request validation failed.", "details": []},
  "trace_id": "request-..."
}
```

## Prediction and explanations

- `POST /v1/predictions` creates an in-memory prediction and returns `201`.
- `GET /v1/predictions/{prediction_id}` retrieves it.
- `POST /v1/predictions/{prediction_id}/explanation` returns grounded facts,
  interpretations, limitations, and provider metadata.

Explanation `generation_status` values are `complete`, `unavailable`, and
`invalid_output`. External-provider failures return the deterministic local
explanation; check `provider` and, when present,
`provider_metadata.actual_provider` and `provider_metadata.fallback_status` rather
than assuming the configured provider generated the response. A minimal successful
local response includes:

```json
{
  "schema_version": "1.0",
  "prediction_id": "synthetic-prediction-001",
  "provider": "local",
  "generation_status": "complete",
  "context": {
    "prediction_snapshot": "2026-01-15",
    "model_version": "synthetic-model-v1",
    "model_score": 0.82,
    "score_scale": {"minimum": 0.0, "maximum": 1.0, "higher_is_riskier": true},
    "score_meaning": "This is the submitted model score; higher values are declared riskier. It is not treated as an exploitation probability.",
    "evidence": [],
    "missing_information": ["supporting evidence"]
  },
  "observed_facts": [{"text": "...", "source_refs": ["prediction:score"]}],
  "interpretations": [],
  "limitations": ["This explanation is limited to the submitted prediction and evidence."],
  "trace_id": "local-...",
  "provider_metadata": {"engine": "deterministic-template-v1", "actual_provider": "local", "fallback_status": "not_used"}
}
```

External model-authored free text is never returned directly. On a successful
external call, deterministic interpretation text reports only the model's validated
selection of submitted `source_refs`. Hugging Face metadata also reports the
response model and routed inference provider; an identity mismatch uses local fallback.

## Threats API and missing data

- `GET /api/vulnerabilities` returns the startup-loaded Member 1 prediction artifact.
  The tracked default contains the genuine top 25; configure
  `PREDICTION_ARTIFACT_PATH` for the complete CSV export.
- `GET /api/vulnerabilities/{cve}` performs a case-insensitive CVE lookup.
- Ranking scores remain relative model outputs and are not labelled as exploitation
  probabilities. Missing descriptions, CVSS, EPSS, feature contributions, and asset
  associations are returned as null or explicit missing-information entries.
- `/api/assets` returns seven explicitly synthetic company assets plus synthetic-scenario
  CVE mappings together with the synthetic operations inventory used by the judge script.
  `verified_for_demo` means internally consistent for the demonstration, not externally
  verified product applicability.
- `/api/alerts` combines persisted deterministic event decisions with recorded operations
  findings and mocked or configured delivery status. Recording mode never claims that Slack
  or Jira delivery occurred.
- There is no Time Machine / `/api/replay` product surface; historical evaluation remains
  backend-only library code.

The current frontend hidden-threat adapter treats a null `traditionalRank` as being
outside the baseline top 500. Member 2 must require a non-null rank before applying
that label. Unknown rank means unevaluable, not a ranking disagreement.

Browser clients require their exact origin in `CORS_ALLOWED_ORIGINS` (comma-separated).
The default empty allowlist intentionally permits only same-origin access.

## Security events and recommendations

- `POST /v1/security-events` evaluates and persists a validated event deterministically.
- `POST /v1/security-events?dry_run=true` uses the identical policy without writing any
  event, recommendation, approval, or audit state.
- `GET /v1/security-events/{event_id}` retrieves its persisted outcome.
- `GET /v1/predictions/{prediction_id}/recommendations` lists persisted records.
- `POST /v1/recommendations/{recommendation_id}/decision` accepts
  `{"schema_version":"1.0","action":"approve|reject","actor":"...","reason":"..."}`.

Event `processing_status` values are `no_action`, `recommendation_created`, and
`insufficient_information`. Recommendation `workflow_status` values are
`recorded`, `investigating`, `pending_approval`, `approved`, and `rejected`.
Operational decisions are `MONITOR`, `INVESTIGATE`, `ACTION_REQUIRED`, and `URGENT`.
Approval only records workflow intent; it never executes remediation.

The demonstration policy requires model rank and asset context jointly. Rank bands 1–5
and 1–15 are configurable demo defaults, not validated production thresholds or
percentiles. High criticality or internet exposure alone cannot produce
`ACTION_REQUIRED`. Unknown applicability remains unknown; only higher-ranked unknowns
enter investigation while lower-ranked unknowns remain monitored.

The response includes structured reasons, evidence, remediation eligibility, a stable
finding identity, and a material-evidence fingerprint. A new event with unchanged
material evidence reuses its recommendation. A material model, policy, correlation, or
asset-context change creates another persisted evaluation. Technical agent eligibility
always returns `execution_authorized: false` in this iteration.

The synthetic event request is available in
`backend/contracts/v1/examples/security-event-create.synthetic.json`. A successful
above-threshold outcome has this shape:

```json
{
  "schema_version": "1.0",
  "event_id": "synthetic-event-001",
  "prediction_id": "synthetic-prediction-001",
  "processing_status": "recommendation_created",
  "reason_code": "configured_threshold_met",
  "reason": "The existing score ... meets the configured threshold ...",
  "matched_vulnerability_id": "SYNTH-VULN-001",
  "matched_asset_id": "synthetic-asset-001",
  "recommendation_id": "rec-...",
  "processed_at": "2026-01-15T12:05:00Z"
}
```

Common stable errors include `validation_error` (`422`), `prediction_not_found`
or `event_not_found` (`404`), `event_already_exists` (`409`), and
`invalid_recommendation_transition` (`409`). Every HTTP response includes an
`X-Trace-ID` header.

Synthetic request payloads are available under `backend/contracts/v1/examples/`.
