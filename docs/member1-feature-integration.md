# Member 1 text-feature integration

No Member 1 dataset, model module, or training interface is present in this
checkout. This adapter is therefore provisional and is not wired into a training
pipeline.

## Interface

Run from `backend/`:

```python
from app.features import TextHashingConfig, TextHashingTransformer

records = [
    {
        "vulnerability_description": "Description available at prediction time.",
        "vendor_description": "Optional vendor text available at prediction time.",
        "product_description": "Optional product text available at prediction time.",
    }
]

transformer = TextHashingTransformer(TextHashingConfig(n_features=4096))
features = transformer.transform(records)
metadata = transformer.metadata.as_dict()
```

`features` is a SciPy CSR matrix with shape `(record_count, n_features)`. Input
row ordering is preserved. Missing, `null`, whitespace-only, and empty supported
fields contribute an all-zero row or field contribution. Batch and individual
transforms are identical. The transformer is stateless and has no `fit` step.

The output is `hashed_text_features` version `1.0`, using field-namespaced word
unigrams and bigrams, `alternate_sign=False`, and L2 row normalization. Hashing
collisions are possible by design. These are sparse lexical features, not semantic
neural embeddings.

## Leakage boundary

Only these provisional fields can contribute:

- `vulnerability_description`
- `vendor_description`
- `product_description`

Unknown metadata fields such as a row identifier are ignored. Known target or
post-outcome fields—including `label`, `score`, `rank`, exploitation observations,
future exploitation, and remediation outcomes—raise
`ProhibitedFeatureFieldError`.

The caller must additionally guarantee that every supplied description was
available on or before the prediction snapshot. The adapter cannot infer a
field's historical availability from plain text.

## Required confirmation from Member 1

Before production integration, confirm:

- actual dataset column names and which descriptions exist at inference time;
- snapshot-time filtering rules and the authoritative cutoff column;
- stable record ordering/key used to align the sparse matrix with numeric features;
- desired feature dimension and downstream sparse-matrix compatibility;
- prediction score minimum, maximum, direction, meaning, and calibration;
- operational alert threshold on that exact score scale.

Until the score information is confirmed, mismatched or incomplete event threshold
semantics continue to return `insufficient_information`.
