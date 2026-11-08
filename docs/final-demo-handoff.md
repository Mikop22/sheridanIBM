# SignalZero final backend handoff

The backend is ready for the deterministic workflow and local IBM Granite demo.
Historical replay remains intentionally unavailable until Member 1 provides a
validated out-of-sample export. Synthetic tests are never served as live findings.

## Start the local services on Windows

Start or verify Ollama in one PowerShell terminal. Use the full executable path if
`ollama` is not on `PATH`:

```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve
Invoke-RestMethod http://127.0.0.1:11434/api/version
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" list
```

The installed model must include `granite4:3b`. Do not download a substitute during
the demo. Start FastAPI in a second terminal:

```powershell
cd C:\Users\jrair\Coding\sheridanIBM\backend
python -m pip install -e ".[dev]"
$env:EXPLANATION_PROVIDER="ollama"
$env:OLLAMA_BASE_URL="http://127.0.0.1:11434"
$env:OLLAMA_MODEL="granite4:3b"
$env:CORS_ALLOWED_ORIGINS="http://localhost:3000"
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Configure Member 2's frontend and use its normal development command:

```dotenv
NEXT_PUBLIC_SIGNALZERO_API_MODE=live
NEXT_PUBLIC_SIGNALZERO_API_BASE_URL=http://127.0.0.1:8000
```

From the integrated repository with Node.js 22.22 or newer:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev -- --port 3000
```

## Available endpoints

- `GET /health`
- `POST /v1/predictions`
- `GET /v1/predictions/{prediction_id}`
- `POST /v1/predictions/{prediction_id}/explanation`
- `POST /v1/security-events`
- `GET /v1/security-events/{event_id}`
- `GET /v1/predictions/{prediction_id}/recommendations`
- `POST /v1/recommendations/{recommendation_id}/decision`
- `GET /api/overview`
- `GET /api/vulnerabilities` and `GET /api/vulnerabilities/{id}`
- `GET /api/assets`
- `GET /api/alerts`

The Threats collection uses the startup-loaded Member 1 artifact. Fields absent from
that artifact remain null or explicitly unknown rather than being filled from demo
fixtures. Historical replay remains internal and `/api/replay` is not exposed.

## Required real-data handoff

Member 1 must provide one row-level CSV or Parquet export with these columns:

- `cve_id`, `description`, `published_at`, `month`, `feature_cutoff`,
  `evaluation_cutoff`;
- `model_score`, `model_score_minimum`, `model_score_maximum`,
  `model_higher_is_riskier`, `model_version`;
- `is_out_of_sample`, `split_name`;
- `cvss_score`, `cvss_source`, `cvss_observed_at`;
- `epss_score`, `epss_observed_at`;
- `kev_date_added`;
- optional evidence JSON containing only `evidence_id`, `source`, and `observed_at`.

The existing domain models and evaluation services accept these values without a
redesign. A thin file loader and replay-response mapper still need to be wired after
the real export arrives. Enable a month only after its rows pass cutoff, provenance,
score-semantics, and out-of-sample validation end to end.

Member 2 must keep the base URL above and correct the Hidden Threats filter so
`traditionalRank === null` means unknown. Only a non-null rank greater than the
selected budget may count as a baseline disagreement.

## Minimal demo procedure

1. Verify Ollama and start FastAPI with the commands above; confirm `GET /health`.
2. Submit `contracts/v1/examples/prediction-create.synthetic.json` and state that it
   is a workflow fixture, not a historical finding.
3. Request its explanation and verify `provider=ollama`, model `granite4:3b`, and
   `fallback_status=not_used`.
4. Submit `security-event-create.synthetic.json`, inspect the recommendation, and
   record approval. Explain that approval records intent and executes nothing.
5. Run the frontend in live mode. Empty/null states are expected until real data is
   connected; replay must show its unavailable error rather than demo statistics.
6. After Member 1's export arrives, validate one month, compare model/CVSS/EPSS on
   the same cohort, then demonstrate a genuine hidden-threat disagreement if one
   exists. Do not promise that the model outperforms a baseline.

Current blockers are the missing Member 1 export, the thin real-data loader/mapper,
and Member 2's null-rank correction. No credentials, cloud inference, remediation,
or additional backend architecture is required for the local workflow demo.
