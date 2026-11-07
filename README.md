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
