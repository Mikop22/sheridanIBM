#!/usr/bin/env python3
"""
Stratified Hard-Negative & Right-Censoring Aware Sampling Experiment for LightGBM.

Implements and tests the 4-part case-control / hard-negative sampling design:
  1. All available positive examples with complete follow-up (`snapshot_month <= cutoff`
     so right-censored late-horizon observations do not contaminate training).
  2. A random sample of easy/background negative examples (`k_random` per positive,
     or a fixed fraction of background negatives).
  3. Additional "hard negatives" from the upper within-month EPSS percentiles
     (top 5% / 10% EPSS within each publication month Cohort that never entered KEV).
  4. Additional "hard negatives" with public exploit indicators (`exploitdb`, `metasploit`,
     `nuclei`, or `poc_github == 1`) that had no observed KEV listing during the
     follow-up horizon.

Crucial Requirement:
  - Training uses the constructed hard-negative + random-negative sample (both
    unweighted and with Horvitz-Thompson inverse-probability importance weights
    `sample_weight = 1 / pi_i` to test calibration vs. discriminative ranking).
  - Final evaluation ALWAYS uses 100% of the untouched validation population!
"""

import json
import os
import time

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from scipy.sparse import csr_matrix, hstack
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

from eval_gbdt_ranking import (
    FEAT_DIR,
    compute_all_metrics,
    get_tier_columns,
    prepare_strict_and_expanded_data,
)

def add_within_cohort_epss_pct(df: pd.DataFrame) -> pd.DataFrame:
    """Compute within-month cohort EPSS percentile rank among newly published CVEs."""
    df = df.copy()
    df["cohort_epss_pct"] = df.groupby("snapshot_month")["sig_epss_raw"].rank(pct=True)
    return df


def build_hard_negative_sample(
    df_tr: pd.DataFrame,
    complete_followup_cutoff: str | None = None,
    epss_upper_pct: float = 0.90,
    random_neg_ratio: int = 20,
    use_importance_weights: bool = False,
    seed: int = 42,
) -> tuple[pd.DataFrame, np.ndarray]:
    """
    Construct the 4-part training sample from `df_tr`:
      1. All positives (optionally restricted to `snapshot_month <= complete_followup_cutoff`
         for complete follow-up).
      2. All negatives with public exploit indicators (`sig_any_flag == 1`).
      3. All negatives in the upper EPSS percentile (`cohort_epss_pct >= epss_upper_pct`).
      4. A random sample of remaining "easy/background" negatives (`random_neg_ratio`
         per positive, or up to available easy negatives).

    If `use_importance_weights=True`, assigns inverse sampling probability weights:
      - Positives, exploit-flag hard negatives, and high-EPSS hard negatives were
        sampled with probability pi = 1.0 -> weight = 1.0.
      - Random background negatives were sampled with probability
        pi = n_sampled_easy / n_total_easy -> weight = n_total_easy / n_sampled_easy
        (restoring the true population prior!).
    """
    rng = np.random.RandomState(seed)

    if complete_followup_cutoff is not None:
        df_pool = df_tr[df_tr["snapshot_month"] <= complete_followup_cutoff].copy()
    else:
        df_pool = df_tr.copy()

    pos_mask = df_pool["target_kev"].values == 1
    neg_mask = ~pos_mask

    # Bucket 1: All Positives with complete follow-up
    df_pos = df_pool.loc[pos_mask]
    n_pos = len(df_pos)

    # Bucket 4: Hard Negatives with public exploit indicators (`sig_any_flag == 1`)
    flag_neg_mask = neg_mask & (df_pool["sig_any_flag"].values == 1)

    # Bucket 3: Hard Negatives from upper EPSS percentiles (`cohort_epss_pct >= epss_upper_pct`)
    epss_neg_mask = neg_mask & (~flag_neg_mask) & (df_pool["cohort_epss_pct"].values >= epss_upper_pct)

    # Bucket 2: Remaining "Easy / Background" Negatives
    easy_neg_mask = neg_mask & (~flag_neg_mask) & (~epss_neg_mask)

    df_hard_flag = df_pool.loc[flag_neg_mask]
    df_hard_epss = df_pool.loc[epss_neg_mask]
    df_easy_pool = df_pool.loc[easy_neg_mask]

    n_easy_total = len(df_easy_pool)
    n_easy_sample = min(n_easy_total, max(n_pos * random_neg_ratio, 1500))
    sampled_easy_idx = rng.choice(df_easy_pool.index.values, size=n_easy_sample, replace=False)
    df_easy_sampled = df_pool.loc[sampled_easy_idx]

    df_sampled = pd.concat([df_pos, df_hard_flag, df_hard_epss, df_easy_sampled], axis=0)

    if use_importance_weights:
        easy_weight = float(n_easy_total) / float(max(n_easy_sample, 1))
        weights = np.concatenate(
            [
                np.ones(len(df_pos), dtype=np.float64),
                np.ones(len(df_hard_flag), dtype=np.float64),
                np.ones(len(df_hard_epss), dtype=np.float64),
                np.full(len(df_easy_sampled), easy_weight, dtype=np.float64),
            ]
        )
    else:
        weights = np.ones(len(df_sampled), dtype=np.float64)

    # Shuffle sample order deterministically
    perm = rng.permutation(len(df_sampled))
    return df_sampled.iloc[perm].reset_index(drop=True), weights[perm]


def fit_lgbm(
    df_tr: pd.DataFrame,
    df_val: pd.DataFrame,
    lgb_cols: list,
    cat_code_cols: list,
    sample_weight: np.ndarray | None = None,
) -> np.ndarray:
    y_tr = df_tr["target_kev"].values.astype(np.int32)
    X_tr = df_tr[lgb_cols].copy()
    X_val = df_val[lgb_cols].copy()
    for c in cat_code_cols:
        X_tr[c] = X_tr[c].astype("category")
        X_val[c] = X_val[c].astype("category")

    clf = LGBMClassifier(
        n_estimators=250,
        learning_rate=0.03,
        num_leaves=15,
        max_depth=5,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.7,
        reg_alpha=1.0,
        reg_lambda=5.0,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    clf.fit(X_tr, y_tr, sample_weight=sample_weight)
    return clf.predict_proba(X_val)[:, 1]


def fit_lr_tfidf(
    df_tr: pd.DataFrame,
    df_val: pd.DataFrame,
    tier_cfg: dict,
    X_tfidf_tr,
    X_tfidf_val,
) -> np.ndarray:
    y_tr = df_tr["target_kev"].values.astype(np.int32)
    num_cols = tier_cfg["num_cols"]
    num_no_tf = tier_cfg["num_no_tf"]

    sc = StandardScaler()
    X_tr_std = sc.fit_transform(df_tr[num_cols].values.astype(np.float64))
    X_val_std = sc.transform(df_val[num_cols].values.astype(np.float64))
    lr_stack = LogisticRegression(C=0.1, max_iter=500, random_state=42).fit(X_tr_std, y_tr)
    p_stack = lr_stack.predict_proba(X_val_std)[:, 1]

    sc_notf = StandardScaler()
    X_notf_tr = sc_notf.fit_transform(df_tr[num_no_tf].values.astype(np.float64))
    X_notf_val = sc_notf.transform(df_val[num_no_tf].values.astype(np.float64))
    Xj_tr = hstack([csr_matrix(X_notf_tr * 0.25), X_tfidf_tr], format="csr")
    Xj_val = hstack([csr_matrix(X_notf_val * 0.25), X_tfidf_val], format="csr")
    lr_joint = LogisticRegression(C=0.5, max_iter=500, random_state=42).fit(Xj_tr, y_tr)
    p_joint = lr_joint.predict_proba(Xj_val)[:, 1]

    return 0.5 * p_stack + 0.5 * p_joint


def run_sampling_experiments_for_tier(
    df_train: pd.DataFrame,
    tier_name: str,
    tier_cfg_cv: dict,
    tier_cfg_temp: dict,
    X_tr_strict_tfidf,
):
    print(f"\n======================================================================", flush=True)
    print(f"Testing Hard-Negative & Right-Censored Sampling on {tier_name}", flush=True)
    print(f"======================================================================", flush=True)

    lgb_cols_cv = tier_cfg_cv["num_cols"] + tier_cfg_cv["cat_code_cols"]
    cat_cols_cv = tier_cfg_cv["cat_code_cols"]
    y_all = df_train["target_kev"].values.astype(np.int32)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    n = len(df_train)

    oof_preds = {
        "1. Baseline: Full Population LightGBM (100% of negatives)": np.zeros(n),
        "2. Naive Random Undersampling Only (20x random negs, NO hard negs)": np.zeros(n),
        "3. Hard-Negative Sample (Pos + Exploit-Flag Negs + Top-10% EPSS + 20x Rand)": np.zeros(n),
        "4. Hard-Negative Sample + Complete Follow-Up Filter (cutoff <= 2025-09)": np.zeros(n),
        "5. Hard-Negative Sample + Horvitz-Thompson Inverse-Prob Weights": np.zeros(n),
        "6. Multi-Seed Bagged Hard-Negative LightGBM (5 random negative draws)": np.zeros(n),
        "7. Ensemble: Full-Pop LightGBM + Hard-Neg LightGBM": np.zeros(n),
        "8. Ensemble: Hard-Neg LightGBM (Rank) + LogReg+TF-IDF (Rank)": np.zeros(n),
    }

    for fold_idx, (tr_idx, val_idx) in enumerate(skf.split(df_train, y_all)):
        df_tr = df_train.iloc[tr_idx].reset_index(drop=True)
        # Untouched full validation fold!
        df_val = df_train.iloc[val_idx].reset_index(drop=True)

        # 1. Baseline: Full population LightGBM
        p_full = fit_lgbm(df_tr, df_val, lgb_cols_cv, cat_cols_cv)
        oof_preds["1. Baseline: Full Population LightGBM (100% of negatives)"][val_idx] = p_full

        # 2. Naive Random Undersampling Only (Positives + 30x random negatives, no targeted hard negs)
        rng = np.random.RandomState(42 + fold_idx)
        pos_df = df_tr[df_tr["target_kev"] == 1]
        neg_df = df_tr[df_tr["target_kev"] == 0]
        rand_neg_df = neg_df.sample(n=min(len(neg_df), len(pos_df) * 30), random_state=42 + fold_idx)
        df_naive = pd.concat([pos_df, rand_neg_df]).sample(frac=1.0, random_state=42)
        oof_preds["2. Naive Random Undersampling Only (20x random negs, NO hard negs)"][val_idx] = (
            fit_lgbm(df_naive, df_val, lgb_cols_cv, cat_cols_cv)
        )

        # 3. 4-Part Hard-Negative Sample (Unweighted)
        df_hn, _ = build_hard_negative_sample(
            df_tr,
            complete_followup_cutoff=None,
            epss_upper_pct=0.90,
            random_neg_ratio=20,
            use_importance_weights=False,
            seed=42 + fold_idx,
        )
        p_hn = fit_lgbm(df_hn, df_val, lgb_cols_cv, cat_cols_cv)
        oof_preds["3. Hard-Negative Sample (Pos + Exploit-Flag Negs + Top-10% EPSS + 20x Rand)"][val_idx] = p_hn

        # 4. 4-Part Hard-Negative Sample + Complete Follow-Up Filter (exclude Oct-Nov 2025 right-censored months)
        df_hn_cf, _ = build_hard_negative_sample(
            df_tr,
            complete_followup_cutoff="2025-09",
            epss_upper_pct=0.90,
            random_neg_ratio=20,
            use_importance_weights=False,
            seed=42 + fold_idx,
        )
        p_hn_cf = fit_lgbm(df_hn_cf, df_val, lgb_cols_cv, cat_cols_cv)
        oof_preds["4. Hard-Negative Sample + Complete Follow-Up Filter (cutoff <= 2025-09)"][val_idx] = p_hn_cf

        # 5. 4-Part Hard-Negative Sample + Horvitz-Thompson Inverse-Probability Weights
        df_hn_ht, w_ht = build_hard_negative_sample(
            df_tr,
            complete_followup_cutoff="2025-09",
            epss_upper_pct=0.90,
            random_neg_ratio=20,
            use_importance_weights=True,
            seed=42 + fold_idx,
        )
        p_hn_ht = fit_lgbm(df_hn_ht, df_val, lgb_cols_cv, cat_cols_cv, sample_weight=w_ht)
        oof_preds["5. Hard-Negative Sample + Horvitz-Thompson Inverse-Prob Weights"][val_idx] = p_hn_ht

        # 6. Multi-Seed Bagged Hard-Negative LightGBM (5 draws of random background negatives)
        bag_preds = np.zeros(len(df_val), dtype=np.float64)
        for bag_s in range(5):
            df_bag, _ = build_hard_negative_sample(
                df_tr,
                complete_followup_cutoff="2025-09",
                epss_upper_pct=0.90,
                random_neg_ratio=20,
                use_importance_weights=False,
                seed=100 * fold_idx + bag_s,
            )
            bag_preds += fit_lgbm(df_bag, df_val, lgb_cols_cv, cat_cols_cv) / 5.0
        oof_preds["6. Multi-Seed Bagged Hard-Negative LightGBM (5 random negative draws)"][val_idx] = bag_preds

        # 7. Blend Full-Pop LightGBM + Bagged Hard-Negative LightGBM
        # Note: p_full is on [0, 1] with base rate ~0.0015, while bag_preds has base rate ~0.015.
        # Scale bag_preds by prior odds or rank-average so both contribute equally!
        r_full = pd.Series(p_full).rank(pct=True).values
        r_bag = pd.Series(bag_preds).rank(pct=True).values
        oof_preds["7. Ensemble: Full-Pop LightGBM + Hard-Neg LightGBM"][val_idx] = (
            0.5 * p_full + 0.5 * (bag_preds * 0.12)
        )

        # 8. Ensemble: Bagged Hard-Neg LightGBM + LogReg+TF-IDF
        p_lr = fit_lr_tfidf(
            df_train.iloc[tr_idx],
            df_train.iloc[val_idx],
            tier_cfg_cv,
            X_tr_strict_tfidf[tr_idx],
            X_tr_strict_tfidf[val_idx],
        )
        oof_preds["8. Ensemble: Hard-Neg LightGBM (Rank) + LogReg+TF-IDF (Rank)"][val_idx] = (
            0.5 * p_lr + 0.5 * (bag_preds * 0.12)
        )

    print("\n--- 5-Fold Stratified CV Results (Evaluated on 100% Untouched Validation Population: 82,430 CVEs, 122 KEVs) ---", flush=True)
    cv_summary = {}
    for name, s in oof_preds.items():
        m = compute_all_metrics(y_all, s)
        cv_summary[name] = m
        print(
            f"  {name:75s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d} | H@250={m['hits@250']:2d} | H@500={m['hits@500']:2d}",
            flush=True,
        )

    # =========================================================================
    # Causal Temporal Split: Train 2024 (Sampled) -> Test on Untouched Full 2025 (42,562 CVEs, 55 KEVs)
    # =========================================================================
    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values
    df_24 = df_train.iloc[np.where(is_24)[0]].reset_index(drop=True)
    df_25 = df_train.iloc[np.where(is_25)[0]].reset_index(drop=True)
    y_25 = df_25["target_kev"].values.astype(np.int32)

    lgb_cols_temp = tier_cfg_temp["num_cols"] + tier_cfg_temp["cat_code_cols"]
    cat_cols_temp = tier_cfg_temp["cat_code_cols"]

    # Inspect sample composition on 2024 training pool
    df_sample_demo, _ = build_hard_negative_sample(
        df_24, complete_followup_cutoff="2024-11", epss_upper_pct=0.90, random_neg_ratio=20, seed=42
    )
    n_pos_24 = int((df_sample_demo["target_kev"] == 1).sum())
    n_flag_24 = int(((df_sample_demo["target_kev"] == 0) & (df_sample_demo["sig_any_flag"] == 1)).sum())
    n_epss_24 = int(
        (
            (df_sample_demo["target_kev"] == 0)
            & (df_sample_demo["sig_any_flag"] == 0)
            & (df_sample_demo["cohort_epss_pct"] >= 0.90)
        ).sum()
    )
    n_easy_24 = len(df_sample_demo) - n_pos_24 - n_flag_24 - n_epss_24
    print(
        f"\n  [2024 Sample Composition] Total={len(df_sample_demo):,} rows (vs {len(df_24):,} full 2024): "
        f"Positives={n_pos_24}, Exploit-Flag Hard Negs={n_flag_24}, "
        f"Top-10% EPSS Hard Negs={n_epss_24:,}, Random Easy Negs={n_easy_24:,}",
        flush=True,
    )

    p25_full = fit_lgbm(df_24, df_25, lgb_cols_temp, cat_cols_temp)

    pos_24_df = df_24[df_24["target_kev"] == 1]
    neg_24_df = df_24[df_24["target_kev"] == 0]
    df_naive_24 = pd.concat(
        [pos_24_df, neg_24_df.sample(n=len(pos_24_df) * 30, random_state=42)]
    ).sample(frac=1.0, random_state=42)
    p25_naive = fit_lgbm(df_naive_24, df_25, lgb_cols_temp, cat_cols_temp)

    df_hn_24, _ = build_hard_negative_sample(
        df_24, complete_followup_cutoff=None, epss_upper_pct=0.90, random_neg_ratio=20, seed=42
    )
    p25_hn = fit_lgbm(df_hn_24, df_25, lgb_cols_temp, cat_cols_temp)

    df_hn_cf_24, _ = build_hard_negative_sample(
        df_24, complete_followup_cutoff="2024-11", epss_upper_pct=0.90, random_neg_ratio=20, seed=42
    )
    p25_hn_cf = fit_lgbm(df_hn_cf_24, df_25, lgb_cols_temp, cat_cols_temp)

    df_hn_ht_24, w_ht_24 = build_hard_negative_sample(
        df_24,
        complete_followup_cutoff="2024-11",
        epss_upper_pct=0.90,
        random_neg_ratio=20,
        use_importance_weights=True,
        seed=42,
    )
    p25_hn_ht = fit_lgbm(df_hn_ht_24, df_25, lgb_cols_temp, cat_cols_temp, sample_weight=w_ht_24)

    bag_25 = np.zeros(len(df_25), dtype=np.float64)
    for bag_s in range(5):
        df_b, _ = build_hard_negative_sample(
            df_24, complete_followup_cutoff="2024-11", epss_upper_pct=0.90, random_neg_ratio=20, seed=200 + bag_s
        )
        bag_25 += fit_lgbm(df_b, df_25, lgb_cols_temp, cat_cols_temp) / 5.0

    p25_lr = fit_lr_tfidf(df_24, df_25, tier_cfg_temp, X_tr_strict_tfidf[is_24], X_tr_strict_tfidf[is_25])

    temp_preds = {
        "1. Baseline: Full Population LightGBM (100% of negatives)": p25_full,
        "2. Naive Random Undersampling Only (20x random negs, NO hard negs)": p25_naive,
        "3. Hard-Negative Sample (Pos + Exploit-Flag Negs + Top-10% EPSS + 20x Rand)": p25_hn,
        "4. Hard-Negative Sample + Complete Follow-Up Filter (cutoff <= 2024-11)": p25_hn_cf,
        "5. Hard-Negative Sample + Horvitz-Thompson Inverse-Prob Weights": p25_hn_ht,
        "6. Multi-Seed Bagged Hard-Negative LightGBM (5 random negative draws)": bag_25,
        "7. Ensemble: Full-Pop LightGBM + Hard-Neg LightGBM": 0.5 * p25_full + 0.5 * (bag_25 * 0.12),
        "8. Ensemble: Hard-Neg LightGBM + LogReg+TF-IDF": 0.5 * p25_lr + 0.5 * (bag_25 * 0.12),
    }

    ks = (25, 50, 100, 250)
    print("\n--- Causal Temporal Split (Train 2024 Sample -> Evaluated on 100% Untouched 2025 Population: 42,562 CVEs, 55 KEVs) ---", flush=True)
    temp_summary = {}
    for name, s in temp_preds.items():
        m = compute_all_metrics(y_25, s, ks=ks)
        temp_summary[name] = m
        print(
            f"  {name:75s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@25={m['hits@25']:2d} | H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d}/55 | H@250={m['hits@250']:2d}/55",
            flush=True,
        )

    return {
        "sample_composition_2024": {
            "total_sampled": int(len(df_sample_demo)),
            "total_full_2024": int(len(df_24)),
            "positives": n_pos_24,
            "hard_neg_exploit_flags": n_flag_24,
            "hard_neg_upper_epss": n_epss_24,
            "random_easy_negs": n_easy_24,
        },
        "cv_5fold_untouched_val": cv_summary,
        "temporal_2024_to_2025_untouched_val": temp_summary,
    }


def main():
    t0 = time.time()
    df_train = pd.read_csv(os.path.join(FEAT_DIR, "features_train_2024_2025.csv"))
    df_2026 = pd.read_csv(os.path.join(FEAT_DIR, "features_scoreboard_2026.csv"))

    df_train, _, X_tr_strict_tfidf, _ = prepare_strict_and_expanded_data(df_train, df_2026)
    df_train = add_within_cohort_epss_pct(df_train)

    tiers_cv = get_tier_columns(df_train, temporal=False)
    tiers_temp = get_tier_columns(df_train, temporal=True)

    results = {}
    for t_name in (
        "Tier A (Pub-Time Strict)",
        "Tier B (Expanded Metadata / Grey-Zone)",
    ):
        results[t_name] = run_sampling_experiments_for_tier(
            df_train, t_name, tiers_cv[t_name], tiers_temp[t_name], X_tr_strict_tfidf
        )

    out_path = os.path.join(FEAT_DIR, "hard_negative_sampling_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved hard-negative sampling experiment results to {out_path} in {time.time() - t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()
