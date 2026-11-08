# IBM Granite predictive-feature ablation

## Current state and gate

The backend currently uses `granite4:3b` through loopback Ollama only for grounded
explanations. It does not provide ranking or embedding features. External output is
restricted to selecting submitted source references; deterministic local output is
the fallback.

Do not start the predictive experiment until all of the following are recorded:

- an IBM embedding model whose documentation explicitly supports embeddings;
- its exact model identifier, immutable digest, tokenizer, dimensions, and license;
- a functioning local runtime or an approved, cost-bounded external endpoint;
- the raw temporal cohorts required by `model/src/ensemble_v1.py`;
- confirmation that every description was available at its prediction cutoff.

The configured generative `granite4:3b` model must not be assumed to satisfy the
embedding requirement. A missing historical-text guarantee blocks the experiment
rather than being replaced with current NVD text.

## Locked comparison

The baseline is the unchanged Member 1 v1 ensemble, including its cohorts, Tier A
and B definitions, six base learners, random seeds, temporal splits, undersampling,
and level-2 fitting. The experiment adds frozen Granite description embeddings to
the existing features; it does not remove TF-IDF or change another model setting.

Run a bounded pilot over a complete temporal cohort first. Train on the same earlier
months and score every candidate in the selected later months so coverage and top-K
metrics remain comparable. If the pilot is directionally useful, repeat the exact
2024-to-2025 causal evaluation and nested validation used by the baseline.

Report, for baseline and experiment on identical rows:

- Hits@100 and Hits@500;
- NDCG@100 and NDCG@250;
- PR-AUC and calibration error;
- candidate and positive coverage;
- embedding and training runtime.

Cache embeddings by the SHA-256 hash of the normalized input plus model digest.
Record the source-row hash, cutoff, model metadata, library versions, hardware,
seeds, and experiment configuration. Never send CVE labels, KEV outcomes,
post-snapshot observations, or remediation text to the embedding adapter.

The production prediction artifact remains unchanged unless the experiment improves
the competition objective under this comparison. Experiment failures or unavailable
infrastructure cannot affect the Threats API.
