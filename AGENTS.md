# Member 3 Engineering Guide

## Scope

This repository area owns backend contracts, grounded explanations, future IBM
Granite integration, security-event automation, and embedding feature adapters.
Do not modify Member 1's model/training code or build Member 2's frontend.

## Commands

Run from `backend/`:

- Install: `python -m pip install -e ".[dev]"`
- Start: `uvicorn app.main:app --reload`
- Test: `python -m pytest`
- Lint: `ruff check .`
- Export contracts: `python scripts/export_schemas.py`

## Contract conventions

- Public contracts are versioned under `/v1` and use `schema_version: "1.0"`.
- Treat the prediction schema as an adapter boundary until Member 1 confirms
  their output. Do not couple routes to model implementation details.
- Scores always include their declared scale and direction. Never infer or
  replace score semantics.
- Fixtures containing invented data must be visibly marked synthetic.
- Contract changes require schema, fixture, and API test updates.

## Evidence rules

- Explanations may only restate submitted prediction fields or referenced
  evidence. They must never invent CVE facts, assets, scores, or remediation.
- Keep observed facts separate from interpretations and limitations.
- Every fact and interpretation carries machine-checkable source references.
- Local output must remain deterministic. Granite is an optional future
  enhancement and its output must pass the same validation.

## Security and integration pitfalls

- Never commit `.env`, IBM credentials, model IDs guessed from documentation,
  production data, or secrets in fixtures and logs.
- The Milestone 1 repository is process-local and intentionally non-durable.
- `EXPLANATION_PROVIDER=local` must work without network access.
- Keep route handlers thin and modules focused; avoid speculative services,
  databases, authentication, and dependencies.
