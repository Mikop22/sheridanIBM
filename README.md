# Sheridan Datathon 2026 — Before the Breach

Member 3's backend provides versioned prediction contracts and evidence-grounded
explanations. The default deterministic provider runs entirely offline. Local IBM
Granite through Ollama shares the same validated explanation contract and always
falls back to the deterministic engine on failure.

## Run the integrated application

Create local environment files from `.env.example`, then start each process in a
separate PowerShell window. The frontend runs on `http://localhost:3000` and calls
FastAPI at `http://127.0.0.1:8000` in live mode.

```powershell
Copy-Item .env.example .env.local
Copy-Item .env.example backend/.env

# Window 1
cd backend
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Window 2, from the repository root
npm ci
npm run dev -- --port 3000
```

Live mode never substitutes demo fixtures after an API failure. To use the
frontend's explicitly simulated fixtures instead, set
`NEXT_PUBLIC_SIGNALZERO_API_MODE=demo` in `.env.local` and restart the frontend.

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
in this checkout). Keep `EXPLANATION_PROVIDER=local` for deterministic offline
operation. To use the locally installed IBM Granite model, start Ollama and set:

```dotenv
EXPLANATION_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=granite4:3b
```

The endpoint must be an HTTP loopback origin; hosted Ollama endpoints are rejected.
The backend verifies that Ollama identifies the requested model as Granite before
inference. Output is accepted only as Pydantic-validated JSON with prediction-backed
source references. Model-authored free text is not exposed: the API reports only the
validated source selection using deterministic wording. Missing models, timeouts,
unavailable Ollama, identity mismatches, and invalid output all return the local
explanation with truthful fallback metadata.

For a browser frontend, configure an explicit comma-separated origin allowlist;
wildcards are rejected:

```dotenv
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

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
Git-ignored. Event processing never calls Granite or another explanation provider.

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

No ordinary automated test contacts an inference service. With Ollama running,
explicitly opt into one local Granite smoke test with:

```powershell
$env:EXPLANATION_PROVIDER="ollama"
$env:LIVE_PROVIDER_SMOKE="1"
python -m pytest tests/test_live_provider.py -q
```

The live test fails if the request falls back to the deterministic provider and is
never run by default. It does not require an account, API key, or paid inference.
See [AGENTS.md](AGENTS.md) for integration conventions.
## Frontend development and hosting reference

The following notes are retained from the frontend branch for its Vinext and
Cloudflare development workflow.

# vinext-starter

A clean full-stack starter running on [vinext](https://github.com/cloudflare/vinext), with optional Cloudflare D1 and Drizzle support.

## Prerequisites

- Node.js `>=22.13.0`
- Portable: Windows, macOS, or Linux; no Bash required
- Managed Linux: managed Linux runtime with Bash, `flock`, `curl`, `sha256sum`, and GNU `timeout`
- Git and `tar` (including Windows `tar.exe`) are required for publishing; portable publication does not require Bash

## Sites Lifecycle

The Sites initializer copies the shared starter and selects managed-linux only when `SITES_MANAGED_LINUX_CONTAINER=1`; otherwise it selects portable. It saves the selection only in ignored `.sites-runtime/execution-profile.json`. Both profiles copy/configure first, then use the plugin's separate `install-dependencies.mjs` step to measure installation independently. Edit source under `app/` and follow the Sites skill for installation, preview, builds, and publishing.

Run `node <plugin-root>/scripts/configure-execution-profile.mjs` only when the profile is unknown for the current checkout and environment. Profile changes do not alter tracked source or require reinstalling otherwise-valid dependencies; restart an existing preview to use the new selection. Do not commit or upload `.sites-runtime/`.

This starter does not use `wrangler.jsonc`.

Publish archives outside the source checkout or under its ignored `outputs/` directory. Local `.env*`, `.dev.vars*`, TypeScript build state, and tool runtime directories are ignored; keep the hosting manifest, migrations, and authored scripts in source control.

`install:ci` runs `npm ci` once against the shared lockfile, disables parent-workspace discovery, and includes required dev/optional dependencies despite production/omit settings. Sharp defaults to prebuilt binaries unless explicitly configured otherwise. Do not overlap installers.

- **Portable:** Preserve host HOME, npm cache, registry, proxy, temporary paths, retry/concurrency settings, and lifecycle-script policy. Use `--prefer-offline --no-audit --no-fund`.
- **Managed Linux:** Use the existing project-local HOME/cache/tmp setup and Linux install lock, tarball preflight, and timeout. Restore the image-seeded npm cache only when its lockfile hash matches; retain network fallback. Builds keep their existing timeout. These helpers are not invoked by the portable profile.

`scripts/sites-env.mjs` preserves the caller's HOME, npm cache, proxy, XDG, and temporary-directory configuration while defaulting Wrangler and Miniflare state to the checkout. If npm reports an unwritable cache, select a writable path with `npm_config_cache` for that install. The `dev` and `start` scripts also keep Wrangler logs inside the checkout. Generated `.sites-runtime/` and `.wrangler/` directories are disposable and ignored by Git.

On portable, `npm run dev` uses `vinext dev` with HMR, starting at port 5173. Vinext records the running server in ignored `.vinext/` state, rejects an ordinary duplicate launch, and recovers stale state after a stopped process; exactly simultaneous starts can race. Pass `--port <port>` or `--hostname <host>` after `npm run dev --` when needed; keep portable previews on loopback.

For managed Linux browser QA, follow the Sites skill's managed preview reference. The daemon runs the project's Vite dev script with `--host 0.0.0.0 --port 4173 --strictPort`; use the CLI's returned URL. The ignored local profile survives the daemon's cleared environment.

The portable profile simulates ChatGPT sign-in only for loopback development requests. Visit `/signin-with-chatgpt?return_to=/` to sign in as `local_seedy` (`seedy@sites.test`, display name `Seedy`) and `/signout-with-chatgpt?return_to=/` to sign out. The development cookie preserves that identity across server restarts. Mock auth is disabled in the managed-linux profile and is not included in production builds; hosted authentication remains dispatch-owned.

The Worker uses `vinext/server/fetch-handler`, including Vinext's config-aware image handling. After building, `npm start` runs that Worker locally through Wrangler on `127.0.0.1`, sharing `.wrangler/state` with dev preview and local D1 migrations; it does not deploy the site or simulate sign-in. Use the URL printed by the server. Pass `npm start -- --port <port>` to select a different built-preview port.

Local previews use Miniflare's placeholder `Request.cf` metadata without a network lookup. Set `CLOUDFLARE_CF_FETCH_ENABLED=true` to opt into fetching preview metadata; this setting does not change hosted request metadata.

Local tool usage metrics are disabled by default. Set `WRANGLER_SEND_METRICS=true` to opt in.

## Included Shape

- edit site code under `app/`
- `app/chatgpt-auth.ts` provides optional dispatch-owned ChatGPT sign-in helpers
- `.openai/hosting.json` declares optional Sites D1 and R2 bindings
- `vite.config.ts` simulates declared bindings for local development
- `worker/index.ts` is the production Worker entrypoint and preserves request-scoped connector bindings
- `scripts/vite/` contains the maintained Vite integrations and the vendored Sites plugin license
- `scripts/connector-preview/` contains the local connector preview Worker and session helpers
- the remaining `scripts/` files select execution profiles and run installation, development, and builds; the plugin's helpers orchestrate the Sites lifecycle
- `dist/` contains generated deployment output; `.vinext/`, `.wrangler/`, and `.sites-runtime/` contain ignored local tool state
- `db/index.ts` reads the D1 binding from the Cloudflare Worker environment
- `db/schema.ts` starts intentionally empty
- `@cloudflare/workers-types` provides Worker types; `cloudflare-env.d.ts` declares optional `DB`/`BUCKET` bindings—update these declarations if binding names change
- `examples/d1/` contains an optional D1 example surface
- `drizzle.config.ts` supports local migration generation when needed

## Workspace Auth Headers

Signed-in visitors receive both `oai-authenticated-user-id` and `oai-authenticated-user-email`. Private Sites require every visitor to sign in; public Sites may also have anonymous visitors, for whom neither header is present.

The user ID is stable for the same user on the same Site and different across Sites. Use it as the durable user key; use email and name for display or contact purposes.

SIWC-authenticated workspace sites may also receive `oai-authenticated-user-full-name` when the user's SIWC profile has a non-empty `name` claim. The full-name value is percent-encoded UTF-8 and is accompanied by `oai-authenticated-user-full-name-encoding: percent-encoded-utf-8`.

Treat the full name as optional and fall back to email when it is absent:

```tsx
import { headers } from "next/headers";

export default async function Home() {
  const requestHeaders = await headers();
  const userId = requestHeaders.get("oai-authenticated-user-id");
  const email = requestHeaders.get("oai-authenticated-user-email");
  const encodedFullName = requestHeaders.get("oai-authenticated-user-full-name");
  const fullName =
    encodedFullName &&
    requestHeaders.get("oai-authenticated-user-full-name-encoding") ===
      "percent-encoded-utf-8"
      ? decodeURIComponent(encodedFullName)
      : null;

  const displayName = fullName ?? email;
  // ...
}
```

## Optional Dispatch-Owned ChatGPT Sign-In

Import the ready-to-use helpers from `app/chatgpt-auth.ts` when the site needs optional or required ChatGPT sign-in:

- Use `getChatGPTUser()` for optional signed-in UI.
- Use the returned `userId` as the stable user key for user-owned records; do not use email as a durable identifier.
- Use `requireChatGPTUser(returnTo)` for server-rendered pages that should send anonymous visitors through Sign in with ChatGPT.
- In a Server Component, start sign-in with `<a href={chatGPTSignInPath(returnTo)} target="_top">`. The auth helper module is server-only; do not import it into a Client Component.
- Do not use `fetch`, XHR, a client-side router, or a framework link that can prefetch the sign-in route. SIWC must start as a top-level navigation.
- Never request the AuthAPI authorization endpoint directly. The dispatch-owned `/signin-with-chatgpt` route must start the SIWC flow.
- Use `chatGPTSignOutPath(returnTo)` for browser sign-out links or actions.
- Pass a same-origin relative `returnTo` path for the destination after sign-in or sign-out. The helper validates and safely encodes it.
- Mark protected pages with `export const dynamic = "force-dynamic"` because they depend on per-request identity headers.

Dispatch owns `/signin-with-chatgpt`, `/signout-with-chatgpt`, `/callback`, the OAuth cookies, and identity header injection. Do not implement app routes for those reserved paths. Routes that do not import and call the helper remain anonymous-compatible.

SIWC establishes identity only; it does not prove workspace membership. Use the Sites hosting platform's access policy controls for workspace-wide restrictions, or enforce explicit server-side membership or allowlist checks.

Use SIWC for account pages, user-specific dashboards, saved records, and write actions tied to the current ChatGPT user. Leave public content anonymous.

## Local D1 migrations

For a D1-backed local preview, generate SQL with `npm run db:generate`. Build once through the Sites skill's build entrypoint (or `npm run build` for standalone use) to generate `dist/server/wrangler.json`, rebuilding if bindings change. From the project root, apply each pending migration in order:

```sh
node --import ./scripts/sites-env.mjs ./node_modules/wrangler/bin/wrangler.js d1 execute DB --local --config dist/server/wrangler.json --persist-to .wrangler/state --file drizzle/0000_example.sql
```

Replace the filename with the pending migration and `DB` with your D1 binding name if different. Use `.wrangler/state`, not `.wrangler/state/v3`; Wrangler adds the versioned directories. Do not replay migrations already applied locally. This updates only the preview database; publishing applies production migrations separately.

## Diagnostic Commands

- `npm run install:ci`: perform the one locked dependency install
- `npm run dev`: start the Vite/Vinext development server
- `npm run build`: build the deployable Sites artifact
- `npm run start`: preview the built Worker locally with D1/R2 support
- `npm run db:generate`: generate Drizzle migrations after schema changes

When using the Sites plugin, follow its skill instructions for installation, builds, and publishing. These npm commands remain available for standalone use.

The portable build runs Vinext directly without a host `timeout` command. The managed-linux build uses `scripts/build-verified.sh` and its existing `SITES_BUILD_TIMEOUT` setting.

## Learn More

- [vinext Documentation](https://github.com/cloudflare/vinext)
- [Drizzle D1 Guide](https://orm.drizzle.team/docs/get-started/d1-new)
