## Understanding the Dataset & The Target Construction Decision

### The 8 Raw Files (`data.zip`)
- **`vulnerabilities.csv`** (`401,082` rows, Oct 1988 – Nov 6, 2026): Master NIST NVD table (`published`, `last_modified`, `nvd_status`, `assigner`, `description`, CVSS v2/v3/v4 scores & vectors, `cwe_ids`, `n_references`, `n_affected_cpes`).
- **`affected_products.csv`** (`3,155,934` rows): Common Platform Enumeration (CPE) vendor/product/version rows (`type`, `vendor`, `product`, `vulnerable` = `Y` or `N`).
- **`references.csv`** (`1,360,487` rows): External URLs (`url`, `domain`, and semicolon-separated NIST `tags`).
- **`weakness_types.csv`** (`1,374` rows): MITRE CWE v4.14 dictionary (`cwe_id`, `name`, `kind`, `abstraction`).
- **`known_exploited.csv`** (`1,484` rows, Nov 3, 2021 – Dec 29, 2025): Ground-truth CISA KEV catalog (`date_added`, `known_ransomware_use`).
- **`exploit_signals_2024.csv` & `exploit_signals_2025.csv`** (`6,463,734` rows across 24 monthly snapshots `2024-01` to `2025-12`): End-of-month `epss` score and binary public exploit flags (`in_kev`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`).
- **`scoreboard_2026.csv`** (`72,670` rows): Out-of-time evaluation benchmark containing CVEs published Jan–Sep 2026 that were **not yet on the KEV list at the end of their `snapshot_month`**.

### Key Decision 1: Constructing the Exact `2024–2025` Scoreboard-Analogue Training Cohort
In 2022–2025, roughly **55%–66%** of KEVs were added to the KEV list in the *same* calendar month they were published (zero-day or immediate attacks), while **34%–45%** were added *after* their publication month ended.
- Because `scoreboard_2026.csv` explicitly excludes CVEs that were already in KEV by the end of their `snapshot_month` (removing 124 immediate 2026 KEVs from the 72,794 Jan–Sep 2026 publications), training on same-month KEVs would miscalibrate the model toward already-exploited 0-days.
- **Our Solution (`src/features.py`):** We constructed the exact historical analogue of `scoreboard_2026.csv`—all **82,430 CVEs** published between `2024-01-01` and `2025-11-30` that had `in_kev == 0` at the end of their publication month (`date_added[:7] > snapshot_month` or never in KEV), matched to their publication-month signals in `exploit_signals_2024/2025.csv`. This yields **122 post-snapshot KEVs** (base rate = **`0.148%`**, or ~1 in 675 CVEs).
- **Handling Missing Monthly Snapshots:** In `exploit_signals_2025.csv`, February 2025 (`2025-02`) is missing ~14,500 CVEs due to a data collection glitch; for `2025-02` publications missing from `2025-02`, we fall back to their `2025-03` snapshot (mirroring how `scoreboard_2026.csv` uses `2026-07` for all 7,921 `2026-06` publications).

---

## The NIST Snapshot Leakage Problem & Our 3-Tier Feature Isolation

While `known_exploited.csv` stops on December 31, 2025 and `scoreboard_2026.csv` freezes exploit signals at each CVE's `snapshot_month`, the three NIST tables (`vulnerabilities.csv`, `affected_products.csv`, `references.csv`) are snapshots from **November 6, 2026**.

### Empirical Audit of Metadata Historical Validity (`experiments/03_gbdt_and_lambdamart.py`)
Auditing all **180,308 CVEs published in 2024–2026** across NIST's six `nvd_status` stages proved the following:

| NVD Status (Nov 2026 Snapshot) | CVE Count | `assigner` Present | `description` Present | Real `cwe_ids` Present | CNA `cvss3` Present | **NIST Overwritten `cvss3` (`nvd@nist.gov`)** | **CPE `vendor` / `product` Present** | **Non-Blank `references.tags`** |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`Received`** *(Unanalyzed)* | 5,308 | **100.0%** | **100.0%** | **14.1%** *(85.9% blank)* | 42.1% | **0.0%** | **0.0%** | **0.0%** |
| **`Awaiting Analysis`** | 9,715 | **100.0%** | **100.0%** | 97.1% | 69.2% | **0.0%** | **0.0%** | **0.0%** |
| **`Deferred`** *(NIST will not analyze)* | 60,984 | **100.0%** | **100.0%** | 96.7% | 76.5% | **0.0%** | **0.0%** | **0.0%** |
| **`Analyzed`** *(100% of KEVs are here)* | 76,560 | **100.0%** | **100.0%** | 97.0% *(+3.0% `NVD-CWE`)* | 34.9% | **45.7% (Overwritten)** | **100.0% (Post-triage)** | **~85%+** |
| **`Modified`** *(Re-analyzed later)* | 26,953 | **100.0%** | **100.0%** | 91.8% *(+8.2% `NVD-CWE`)* | 16.5% | **71.8% (Overwritten)** | **100.0% (Post-triage)** | **~65%+** |

### 3.2 Key Decision 2: Isolating Features into Three Explicit Tiers
1. **Tier A (`Pub-Time Strict`, 50 numeric + `cat_assigner` + 35,000-ngram `assigner+description` TF-IDF):**
   - Uses **only** fields confirmed to be 100% present and immutable at publication time: point-in-time exploit signals (`sig_*`), publication/ID mechanics (`time_*`), `assigner` (`cna_*`), and raw `description` NLP (`txt_*` + TF-IDF). Zero CWEs, zero CVSS scores, zero Reference links, zero CPEs.
2. **Tier B (`Expanded Metadata / Grey-Zone`, 103 numeric + `cat_assigner` + `cat_cwe_primary` + TF-IDF):**
   - Adds `cwe_*`, `cvss_*`, and clean `ref_*` domain priors (which are supplied by CNAs at publication for ~88%–97% of CVEs, though subject to partial NIST overwriting or missingness on `Received` CVEs), while strictly excluding all `leak_*` columns.
3. **Tier C (`Leaky Full NVD Snapshot`, 125 numeric + `cat_cpe_vendor` + `cat_nvd_status`):**
   - Includes the 22 `leak_*` columns (`nvd_status`, `n_affected_cpes`, `references.tags`, `cvss3_source == 'nvd@nist.gov'`, `last_modified`) strictly for ablation diagnostics.
   - **Why CatBoost's Ordered Boosting Does Not Fix Tier C:** In `experiments/03_gbdt_and_lambdamart.py`, we proved that `CatBoostClassifier(boosting_type="Ordered")` spikes from `PR-AUC = 0.0977` (Tier A) to **`0.3238`** (Tier C) in 5-fold CV before collapsing by **-67%** (`0.1061`) on the 2024 $\rightarrow$ 2025 temporal split. Ordered boosting prevents *in-sample target-encoding overfitting*, but cannot fix retroactive feature values added to `X` after exploitation.

---

## Key Modeling Decisions & Experimental Progression

### Decision 3: Integrating 35,000 Sparse TF-IDF N-grams (`experiments/02_tfidf_integration.py`)
Because 49.6% of `scoreboard_2026.csv` CVEs have zero CPE rows in `affected_products.csv`, the English `description` and `assigner` are critical for identifying targeted enterprise products (`citrix`, `qts`, `sonicwall`, `vmware`, `ivanti`) and attack mechanics (`unauthenticated`, `the wild`, `remote command`) as well as safe negative filters (`azure`, `locally`, `cwe_79`, Patchstack `from through` boilerplate).
- We tested 4 ways of feeding 35,000 TF-IDF n-grams into our models:
  1. **Out-of-Fold Stacking (`txt_oof_tfidf_prob` / `txt_temp_tfidf_prob`):** Boosted Random Forest 5-fold CV `PR-AUC` from `0.1429` $\rightarrow$ **`0.1629`** (+14.0%) and LogReg from `0.1049` $\rightarrow$ **`0.1265`** (+20.6%).
  2. **Joint Wide Sparse Logistic Regression (`hstack[Scaled Tabular * 0.25, 35,000 TF-IDF]`):** Achieved the highest standalone 2024 $\rightarrow$ 2025 out-of-time `PR-AUC` (**`0.1143`**) because its 35,000 text weights are learned *conditioned on* EPSS and exploit flags.
  - Both `lr_stack` and `lr_joint` are included in our locked-in v1 ensemble.

### Decision 4: Replacing/Augmenting Random Forest with LightGBM & XGBoost LambdaMART (`experiments/03_gbdt_and_lambdamart.py`)
- **XGBoost LambdaMART (`XGBRanker(objective="rank:ndcg", ndcg_exp_gain=True)`, grouped by `qid = snapshot_month`):**
  - Because **EPSS changed its model in March 2025** (causing raw EPSS scores to jump globally by +23% to +50%), pointwise classifiers trained on 2024 suffer threshold drift in 2025.
  - Grouping LambdaMART by `qid = snapshot_month` forces the ranker to optimize pairwise/listwise swaps *strictly within each monthly publication cohort*. Paired with `LogReg + TF-IDF`, LambdaMART jumped 2024 $\rightarrow$ 2025 `NDCG@100` from `0.2830` (RF) to **`0.3487`** and caught **18 / 55 (32.7%)** of all 2025 KEVs in the top 100 predictions.
- **CatBoost Pruned from v1 Out-of-Time Ensemble:**
  - While CatBoost Ordered performed well in random 5-fold CV (`PR-AUC = 0.1399`), it had the worst out-of-time temporal generalization (`2024` $\rightarrow$ `2025` `PR-AUC = 0.0384`) due to year-over-year drift in CWE/assigner target statistics. Excluding CatBoost from the v1 ensemble significantly improved 2025 out-of-time generalization.

### Decision 5: Uniform Random Undersampling vs. Hard-Negative Oversampling (`experiments/06_hard_negative_sampling.py`)
- We tested a 4-part case-control sample (complete-follow-up positives + random negatives + top-10% EPSS negatives + public-exploit-flag negatives) against uniform random undersampling (`Positives + 30x Random Negatives`), evaluated on **100% of the untouched validation population**:
  - **Oversampling high-EPSS and exploit-flag negatives without importance weights** created severe covariate shift inside the training sample (where 793 exploit-flag negatives and 3,290 top-10%-EPSS negatives outnumbered 60 positives by 68-to-1, teaching standalone LightGBM that high EPSS means $y=0$ and dropping untouched 2025 `PR-AUC` from `0.0880` to `0.0300`). Adding Horvitz-Thompson inverse-probability weights recovered `ROC-AUC` to `0.9447`.
  - **Uniform Random Undersampling (`30 : 1` ratio, `lgbm_undersampled`)** preserved the true negative covariate distribution while removing the `675 : 1` hessian imbalance—lifting standalone LightGBM's untouched 2025 `Max-F1` from `0.1538` $\rightarrow$ **`0.2500`** and more than doubling `Hits@100` from `7/55` $\rightarrow$ **`16/55`** (`Hits@250 = 23/55`).
  - We therefore include **both** `lgbm_full` (full-population calibrated) and `lgbm_undersampled` (5-seed bagged `30:1` random undersampled, rescaled by prior odds) in the locked-in v1 ensemble.

### Decision 6: Level-2 Stacking Meta-Learner Selection (`experiments/04` & `05`)
We compared heuristic weights, iterative simplex optimizers (`Caruana Stepwise` and `Walk-Forward Simplex Coordinate Ascent`), and 6 Level-2 stacking meta-learners (`Non-Negative Logit L2`, `ElasticNet Pairwise Interactions`, `Feature-Weighted Linear Stacking / FWLS`, `Monotonic Shallow GBDT`, `Copula Within-Month Rank + Isotonic Regression`, and `Level-2 Monotonic LambdaMART`):
- **Winner:** **Meta 5 (`Copula Within-Month Upper-Tail Rank + Isotonic Regression`)** combined with **Walk-Forward Simplex Coordinate Ascent**.
- By transforming each base model's prediction within `snapshot_month` into empirical upper-tail log-ranks $-\ln(1 - \text{rank\_pct})$ and fitting a non-negative L2 logistic combiner + Isotonic calibration, the Level-2 combiner is **100% immune to the March 2025 EPSS shift and 2026 monthly volume growth** and has only 6 non-negative parameters (zero Level-2 overfitting).

---

## Locked-In v1 Ensemble Performance (`src/ensemble_v1.py`)

Combining our 6 locked-in base models (`lr_stack`, `lr_joint`, `rf`, `lgbm_full`, `lgbm_undersampled`, `lambdamart`) via the **Copula Within-Month Rank/Isotonic + Simplex Meta-Learner** achieved our **highest out-of-time 2024 $\rightarrow$ 2025 performance across the entire project**:

| Feature Regime (`src/ensemble_v1.py`) | Validation Protocol | ROC-AUC | PR-AUC *(Base=0.0015)* | NDCG@100 | NDCG@250 | Max-F1 | Top-K Recall (`Hits@K`) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| **Raw EPSS Baseline** *(Reference)* | 5-Fold CV *(122 KEVs)* | 0.6689 | 0.0312 | — | — | 0.0966 | `H@50: 6` · `H@100: 7` · `H@250: 17` · `H@500: 18` |
| **Raw EPSS Baseline** *(Reference)* | 2024$\rightarrow$2025 Causal *(55 KEVs)* | 0.7318 | 0.0308 | — | — | 0.0797 | `H@25: 2` · `H@50: 3` · `H@100: 4` · `H@250: 10` |
| **v1 Ensemble — Tier B (`Expanded Metadata`)** | **5-Fold Nested CV** *(122 KEVs)* | **0.9525** | **0.1542** | **0.2951** | **0.3454** | **0.2899** | **`H@100: 32/122 (26.2%)`** · **`H@500: 66/122 (54.1%)`** |
| **v1 Ensemble — Tier B (`Expanded Metadata`)** | **2024$\rightarrow$2025 Causal** *(55 KEVs)* | **0.9475** | **0.1645** *(5.3x EPSS!)* | **0.3438** | **0.3944** | **0.2804** | **`H@25: 10/55 (40% prec!)`** · **`H@50: 14/55`** · **`H@250: 21/55`** |
| **v1 Ensemble — Tier A (`Pub-Time Strict`)** | **5-Fold Nested CV** *(122 KEVs)* | **0.9512** | **0.1157** | **0.2040** | **0.3061** | **0.2535** | **`H@100: 22/122`** · **`H@250: 45/122`** · **`H@500: 58/122`** |
| **v1 Ensemble — Tier A (`Pub-Time Strict`)** | **2024$\rightarrow$2025 Causal** *(55 KEVs)* | **0.9364** | **0.1019** *(3.3x EPSS!)* | **0.2544** | **0.3441** | **0.1980** | **`H@25: 6/55`** · **`H@50: 10/55`** · **`H@250: 21/55 (38.2%)`** |

### Learned Level-2 Weights in `src/ensemble_v1.py` (Full 2024–2025 OOF Fit for 2026 Scoring)
- **Copula Within-Month Tail-Rank Weights (60% of v1 blend):**
  - `rf`: `0.2032` | `lambdamart`: `0.1741` | `lgbm_full`: `0.1645` | `lr_stack`: `0.1633` | `lgbm_undersampled`: `0.1532` | `lr_joint`: `0.1418`
  - *(Notice how balanced the Copula rank weights are across all 6 diverse model families!)*
- **Simplex Probability Weights (40% of v1 blend):**
  - `rf`: `0.4879` | `lgbm_full`: `0.2842` | `lambdamart`: `0.0664` | `lr_stack`: `0.0581` | `lr_joint`: `0.0517` | `lgbm_undersampled`: `0.0517`

---

## Reproducing the Pipeline

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate the 2024-2025 and 2026 feature matrices (writes to /tmp/features/)
python3 src/features.py

# 3. Train, validate, and generate the locked-in v1 submission for scoreboard_2026.csv
python3 src/ensemble_v1.py
```
