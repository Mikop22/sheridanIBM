# Member 2 API integration

All public paths are under `/v1` except `/health`. Payloads reject unexpected
fields, and errors use the stable envelope:

```json
{
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
  "observed_facts": [{"text": "...", "source_refs": ["prediction:score"]}],
  "interpretations": [],
  "limitations": ["This explanation is limited to the submitted prediction and evidence."],
  "trace_id": "local-...",
  "provider_metadata": {"engine": "deterministic-template-v1"}
}
```

## Security events and recommendations

- `POST /v1/security-events` evaluates a validated event deterministically.
- `GET /v1/security-events/{event_id}` retrieves its persisted outcome.
- `GET /v1/predictions/{prediction_id}/recommendations` lists persisted records.
- `POST /v1/recommendations/{recommendation_id}/decision` accepts
  `{"schema_version":"1.0","action":"approve|reject","actor":"...","reason":"..."}`.

Event `processing_status` values are `no_action`, `recommendation_created`, and
`insufficient_information`. Recommendation `workflow_status` values are
`pending_approval`, `approved`, and `rejected`. Approval only records workflow
intent; it never executes remediation.

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
