# Offline synthetic demonstration

This walkthrough uses visibly synthetic fixtures. It demonstrates system behavior,
not genuine ML findings, and makes no network or remediation calls.

From `backend/`:

```powershell
$env:EXPLANATION_PROVIDER="local"
uvicorn app.main:app --reload
```

In another terminal, submit and retrieve the synthetic prediction:

```powershell
curl.exe -X POST http://127.0.0.1:8000/v1/predictions `
  -H "Content-Type: application/json" `
  --data-binary "@contracts/v1/examples/prediction-create.synthetic.json"
curl.exe http://127.0.0.1:8000/v1/predictions/synthetic-prediction-001
```

Generate the grounded local explanation, process the event, inspect the
recommendation, and record a decision:

```powershell
curl.exe -X POST http://127.0.0.1:8000/v1/predictions/synthetic-prediction-001/explanation

$outcome = curl.exe -X POST http://127.0.0.1:8000/v1/security-events `
  -H "Content-Type: application/json" `
  --data-binary "@contracts/v1/examples/security-event-create.synthetic.json" |
  ConvertFrom-Json

curl.exe http://127.0.0.1:8000/v1/predictions/synthetic-prediction-001/recommendations

$decision = '{"schema_version":"1.0","action":"approve","actor":"synthetic-reviewer","reason":"Synthetic demo approval only."}'
curl.exe -X POST "http://127.0.0.1:8000/v1/recommendations/$($outcome.recommendation_id)/decision" `
  -H "Content-Type: application/json" `
  -d $decision
```

The corresponding reproducible automated check is:

```powershell
python -m pytest tests/test_end_to_end_offline.py -q
```
