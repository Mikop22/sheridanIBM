# Sheridan Datathon 2026 — Before the Breach

Member 3's backend provides versioned prediction contracts and deterministic,
evidence-grounded explanations. Milestone 1 runs entirely locally: it requires
no IBM Cloud account, credentials, model access, or network connection.

## Run locally

```powershell
cd backend
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for generated API documentation. The default
configuration is `EXPLANATION_PROVIDER=local`.

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

Run verification from `backend/` with `python -m pytest` and
`ruff check .`. See [AGENTS.md](AGENTS.md) for integration conventions.
