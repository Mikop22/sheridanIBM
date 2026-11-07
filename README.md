# Sheridan Datathon 2026 — Before the Breach

Member 3's backend provides versioned prediction contracts and evidence-grounded
explanations. The default deterministic provider runs entirely offline. Optional
Hugging Face and IBM watsonx.ai providers share the same validated explanation
contract and always fall back to the deterministic engine on failure.

## Run locally

```powershell
cd backend
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for generated API documentation. The default
configuration is `EXPLANATION_PROVIDER=local`.

## Explanation providers

Copy `.env.example` to `backend/.env` (a safe local-only file is already present
in this checkout). Keep `EXPLANATION_PROVIDER=local` for offline operation.

For temporary Hugging Face inference, set:

```dotenv
EXPLANATION_PROVIDER=huggingface
HF_TOKEN=your-token
HF_MODEL_ID=an-inference-provider-model-you-selected
```

Requests use Hugging Face's OpenAI-compatible chat endpoint. The backend never
selects or substitutes a model automatically.

For IBM Granite later, set:

```dotenv
EXPLANATION_PROVIDER=watsonx
WATSONX_API_KEY=your-ibm-cloud-api-key
WATSONX_PROJECT_ID=your-project-id
WATSONX_URL=https://your-region.ml.cloud.ibm.com
WATSONX_MODEL_ID=a-supported-granite-model-you-selected
```

watsonx.ai authentication uses reusable, expiring IBM IAM tokens. External output
is accepted only as Pydantic-validated JSON with prediction-backed source
references. Confirmed facts remain deterministic. Missing configuration, timeouts,
authentication failures, unavailable models, rate limits, and invalid output all
return the local explanation with truthful fallback metadata.

## Deterministic security events

Security events are correlated only with an already submitted prediction, its
vulnerability identifiers, affected assets, and evidence. Alert thresholds are
bound to an exact score scale and direction. Update these values for Member 1's
declared score semantics; a mismatch records `insufficient_information`:

```dotenv
EVENT_DATABASE_PATH=security_events.db
EVENT_RISK_THRESHOLD=0.75
EVENT_THRESHOLD_SCALE_MINIMUM=0.0
EVENT_THRESHOLD_SCALE_MAXIMUM=1.0
EVENT_THRESHOLD_HIGHER_IS_RISKIER=true
```

SQLite persists event idempotency, recommendations, approval state, and minimal
audit history. It does not persist predictions, and all database files are
Git-ignored. Event processing never calls Hugging Face or watsonx.ai.

## Hashed text features

The provisional Member 1 adapter exposes
`TextHashingTransformer.transform(records)` and returns a deterministic sparse
matrix with 4,096 columns by default. It uses only allowlisted pre-prediction
description fields and does not download a model or produce semantic neural
embeddings.

See [Member 1 feature integration](docs/member1-feature-integration.md) for the
Python interface and leakage controls, [Member 2 API integration](docs/member2-api-integration.md)
for endpoint states and errors, and the [offline synthetic demo](docs/offline-demo.md)
for the complete judged workflow.

## API workflow

Create a prediction using the explicitly synthetic example:

```powershell
curl.exe -X POST http://127.0.0.1:8000/v1/predictions `
  -H "Content-Type: application/json" `
  --data-binary "@contracts/v1/examples/prediction-create.synthetic.json"
```

Then retrieve and explain it:

```powershell
curl.exe http://127.0.0.1:8000/v1/predictions/synthetic-prediction-001
curl.exe -X POST http://127.0.0.1:8000/v1/predictions/synthetic-prediction-001/explanation
```

Submit the matching synthetic security event, inspect its recommendation, and
record approval without executing remediation:

```powershell
$outcome = curl.exe -X POST http://127.0.0.1:8000/v1/security-events `
  -H "Content-Type: application/json" `
  --data-binary "@contracts/v1/examples/security-event-create.synthetic.json" |
  ConvertFrom-Json

curl.exe http://127.0.0.1:8000/v1/security-events/synthetic-event-001
curl.exe http://127.0.0.1:8000/v1/predictions/synthetic-prediction-001/recommendations

$decision = '{"action":"approve","actor":"synthetic-reviewer","reason":"Synthetic demo approval only."}'
curl.exe -X POST "http://127.0.0.1:8000/v1/recommendations/$($outcome.recommendation_id)/decision" `
  -H "Content-Type: application/json" `
  -d $decision
```

The resulting recommendation remains a workflow record. Approval does not run
commands, modify infrastructure, patch software, or change accounts.

Run verification from `backend/`:

```powershell
python -m pytest
ruff check .
ruff format --check .
```

No automated test contacts an external service. After configuring exactly one
external provider, explicitly opt into one live smoke test with:

```powershell
$env:LIVE_PROVIDER_SMOKE="1"
python -m pytest tests/test_live_provider.py -q
```

The live test fails if the request falls back to local. It can consume provider
credits and is never run by default. See [AGENTS.md](AGENTS.md) for integration
conventions.
