## 1. Repository Structure

```text
/main
├── README.md                                  # Architecture, methodology, and decision log
├── requirements.txt                           # Python package dependencies
├── src/                                       # Core production pipeline
│   ├── __init__.py
│   ├── features.py                            # Builds 125-feature matrices (safe vs. grey vs. leaky tiers)
│   ├── utils.py                               # Shared evaluation metrics, Platt scaling, Copula rankers, tier loaders
│   └── ensemble_v1.py                         # Locked-in v1 submission pipeline (6 Level-1 models + Copula/Simplex Level-2)
├── experiments/                               # Chronological experimental progression
│   ├── 01_logreg_vs_rf.py                     # Baseline Logistic Regression vs. Random Forest & feature tier ablations
│   ├── 02_tfidf_integration.py                # 9-architecture study of sparse TF-IDF (hstack, SVD, OOF stacking)
│   ├── 03_gbdt_and_lambdamart.py              # Metadata historical validity audit + LightGBM, CatBoost Ordered & XGBoost LambdaMART
│   ├── 04_optimize_weights.py                 # Iterative simplex weight selection (Caruana Stepwise & Coordinate Ascent)
│   ├── 05_stacking_meta_learners.py           # Benchmark of 6 Level-2 stacking meta-learners vs. iterative weighting
│   └── 06_hard_negative_sampling.py           # 4-part case-control / hard-negative & uniform random undersampling for LightGBM
└── results/                                   # Saved JSON evaluation reports & v1 submission summary
    ├── eval_results.json
    ├── tfidf_ensemble_results.json
    ├── gbdt_ranking_results.json
    ├── ensemble_weight_optimization.json
    ├── meta_learners_results.json
    ├── hard_negative_sampling_results.json
    └── submission_v1_summary.json             # Locked-in v1 metrics, learned weights, and top 25 2026 predictions
```

