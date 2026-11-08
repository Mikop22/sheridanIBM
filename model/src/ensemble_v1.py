#!/usr/bin/env python3
"""
Locked-in v1 Production Submission Ensemble for Vulnerability Exploitation (KEV) Prediction.

Architecture:
  - Level-1 Base Learners (6 distinct model families):
      1. `lr_stack`      : Stacked L2 Logistic Regression (Dense Tabular + OOF TF-IDF)
      2. `lr_joint`      : Joint Wide Sparse L2 Logistic Regression (`hstack[Tabular, 35k TF-IDF]`)
      3. `rf`            : Unweighted Random Forest (400 deep trees, `max_depth=12`)
      4. `lgbm_full`     : Full-Population Leaf-Wise LightGBM with native categorical splits
      5. `lgbm_undersmp` : Multi-Seed Bagged Uniform Random Undersampled LightGBM (`30:1` ratio)
      6. `lambdamart`    : Within-Month Listwise XGBoost LambdaMART (`rank:ndcg`, `qid=snapshot_month`)

  - Level-2 Meta-Learner (`Meta 5 + Walk-Forward Simplex Blend`):
      Combines **Meta 5 (Copula Within-Month Upper-Tail Rank + Isotonic Regression)**
      with **Walk-Forward Simplex Coordinate Ascent** probability weights, providing
      both high top-K precision and complete invariance to month-to-month EPSS scale
      shifts (such as the March 2025 EPSS model upgrade and 2026 volume growth).

Outputs:
  - `/tmp/features/submission_v1_scoreboard_2026.csv` (and summary in `results/submission_v1_summary.json`)
  - Includes both `Tier B (Expanded Metadata)` and `Tier A (Pub-Time Strict)` scores
    so downstream consumers can select either regime or their blend.
"""

import json
import os
import sys
import time

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from scipy.optimize import minimize
from scipy.sparse import csr_matrix, hstack
from scipy.special import expit
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRanker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils import (
    FEAT_DIR,
    RESULTS_DIR,
    compute_all_metrics,
    fast_ap_and_ndcg100,
    get_tier_columns,
    prepare_strict_and_expanded_data,
    sigmoid_calibrate,
    within_month_ranks,
)

BASE_MODELS = [
    "lr_stack",
    "lr_joint",
    "rf",
    "lgbm_full",
    "lgbm_undersampled",
    "lambdamart",
]


def fit_predict_v1_base_models(
    df_tr: pd.DataFrame,
    df_val: pd.DataFrame,
    tier_cfg: dict,
    X_tfidf_tr,
    X_tfidf_val,
) -> dict[str, np.ndarray]:
    """Fit all 6 v1 base models on `df_tr` and predict on `df_val`."""
    y_tr = df_tr["target_kev"].values.astype(np.int32)
    num_cols = tier_cfg["num_cols"]
    num_no_tf = tier_cfg["num_no_tf"]
    cat_code_cols = tier_cfg["cat_code_cols"]

    X_num_tr = df_tr[num_cols].values.astype(np.float64)
    X_num_val = df_val[num_cols].values.astype(np.float64)

    # 1. Stacked L2 Logistic Regression
    sc = StandardScaler()
    X_tr_std = sc.fit_transform(X_num_tr)
    X_val_std = sc.transform(X_num_val)
    lr_stack = LogisticRegression(C=0.1, max_iter=500, random_state=42)
    lr_stack.fit(X_tr_std, y_tr)
    p_lr_stack = lr_stack.predict_proba(X_val_std)[:, 1]

    # 2. Joint Wide Sparse L2 Logistic Regression (hstack[Tabular, 35k TF-IDF])
    sc_notf = StandardScaler()
    X_notf_tr_std = sc_notf.fit_transform(df_tr[num_no_tf].values.astype(np.float64))
    X_notf_val_std = sc_notf.transform(df_val[num_no_tf].values.astype(np.float64))
    Xj_tr = hstack([csr_matrix(X_notf_tr_std * 0.25), X_tfidf_tr], format="csr")
    Xj_val = hstack([csr_matrix(X_notf_val_std * 0.25), X_tfidf_val], format="csr")
    lr_joint = LogisticRegression(C=0.5, max_iter=500, random_state=42)
    lr_joint.fit(Xj_tr, y_tr)
    p_lr_joint = lr_joint.predict_proba(Xj_val)[:, 1]

    # 3. Random Forest (Unweighted, 350 trees)
    rf = RandomForestClassifier(
        n_estimators=350,
        max_depth=12,
        min_samples_leaf=5,
        max_features="sqrt",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_num_tr, y_tr)
    p_rf = rf.predict_proba(X_num_val)[:, 1]

    # 4. Full-Population LightGBM
    lgb_cols = num_cols + cat_code_cols
    X_lgb_tr = df_tr[lgb_cols].copy()
    X_lgb_val = df_val[lgb_cols].copy()
    for c in cat_code_cols:
        X_lgb_tr[c] = X_lgb_tr[c].astype("category")
        X_lgb_val[c] = X_lgb_val[c].astype("category")

    lgbm_full = LGBMClassifier(
        n_estimators=250,
        learning_rate=0.03,
        num_leaves=15,
        max_depth=5,
        min_child_samples=25,
        subsample=0.8,
        colsample_bytree=0.7,
        reg_alpha=1.0,
        reg_lambda=5.0,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    lgbm_full.fit(X_lgb_tr, y_tr)
    p_lgbm_full = lgbm_full.predict_proba(X_lgb_val)[:, 1]

    # 5. Multi-Seed Bagged Uniform Random Undersampled LightGBM (Positives + 30x Random Negatives)
    pos_df = df_tr[df_tr["target_kev"] == 1]
    neg_df = df_tr[df_tr["target_kev"] == 0]
    n_neg_sample = min(len(neg_df), len(pos_df) * 30)
    p_lgbm_under = np.zeros(len(df_val), dtype=np.float64)
    n_bags = 5
    for b in range(n_bags):
        df_sub = pd.concat(
            [pos_df, neg_df.sample(n=n_neg_sample, random_state=100 + b)]
        ).sample(frac=1.0, random_state=200 + b)
        X_sub = df_sub[lgb_cols].copy()
        for c in cat_code_cols:
            X_sub[c] = X_sub[c].astype("category")
        y_sub = df_sub["target_kev"].values.astype(np.int32)
        clf_sub = LGBMClassifier(
            n_estimators=250,
            learning_rate=0.03,
            num_leaves=15,
            max_depth=5,
            min_child_samples=20,
            subsample=0.8,
            colsample_bytree=0.7,
            reg_alpha=1.0,
            reg_lambda=5.0,
            random_state=300 + b,
            n_jobs=-1,
            verbose=-1,
        )
        clf_sub.fit(X_sub, y_sub)
        p_lgbm_under += clf_sub.predict_proba(X_lgb_val)[:, 1] / float(n_bags)

    # Rescale undersampled probability to match population prior odds
    prior_ratio = (len(pos_df) / max(len(df_tr), 1)) / (len(pos_df) / max(len(pos_df) + n_neg_sample, 1))
    p_lgbm_under_cal = (p_lgbm_under * prior_ratio) / (
        p_lgbm_under * prior_ratio + (1.0 - p_lgbm_under)
    )

    # 6. Within-Month Listwise XGBoost LambdaMART (`rank:ndcg`)
    tr_order = np.argsort(df_tr["snapshot_month"].values)
    df_tr_sorted = df_tr.iloc[tr_order]
    y_tr_sorted = y_tr[tr_order]
    qid_tr = pd.Categorical(df_tr_sorted["snapshot_month"]).codes

    X_xgb_tr = df_tr_sorted[lgb_cols].values.astype(np.float64)
    X_xgb_val = df_val[lgb_cols].values.astype(np.float64)

    xgb_ranker = XGBRanker(
        objective="rank:ndcg",
        ndcg_exp_gain=True,
        n_estimators=200,
        learning_rate=0.03,
        max_depth=4,
        min_child_weight=10,
        subsample=0.8,
        colsample_bytree=0.7,
        reg_alpha=1.0,
        reg_lambda=5.0,
        tree_method="hist",
        random_state=42,
        n_jobs=-1,
    )
    xgb_ranker.fit(X_xgb_tr, y_tr_sorted, qid=qid_tr)
    raw_margin_val = xgb_ranker.predict(X_xgb_val)
    raw_margin_tr = xgb_ranker.predict(df_tr[lgb_cols].values.astype(np.float64))
    p_lambdamart = sigmoid_calibrate(raw_margin_val, y_tr, raw_margin_tr)

    return {
        "lr_stack": p_lr_stack,
        "lr_joint": p_lr_joint,
        "rf": p_rf,
        "lgbm_full": p_lgbm_full,
        "lgbm_undersampled": p_lgbm_under_cal,
        "lambdamart": p_lambdamart,
    }


def fit_predict_copula_plus_simplex_meta(
    P_tr: np.ndarray,
    months_tr: np.ndarray,
    y_tr: np.ndarray,
    P_te: np.ndarray,
    months_te: np.ndarray,
) -> tuple[np.ndarray, dict]:
    """
    Fit the locked-in Level-2 Combiner:
      - Component A (60%): Meta 5 Copula Within-Month Upper-Tail Rank (`-log(1 - rank_pct)`)
        + Non-Negative L2 Logistic Regression + Isotonic Calibration.
      - Component B (40%): Simplex Coordinate Ascent probability blend.
    """
    n_models = P_tr.shape[1]

    # --- Component A: Copula Within-Month Rank + Isotonic ---
    R_tr = within_month_ranks(P_tr, months_tr)
    R_te = within_month_ranks(P_te, months_te)
    T_tr = -np.log(1.0 - np.clip(R_tr, 0.0, 0.9995))
    T_te = -np.log(1.0 - np.clip(R_te, 0.0, 0.9995))

    sc = StandardScaler()
    X_tr = sc.fit_transform(T_tr)
    X_te = sc.transform(T_te)

    p0 = np.zeros(n_models + 1, dtype=np.float64)
    p0[:n_models] = 1.0 / n_models
    p0[n_models] = -6.0

    def copula_obj(params):
        w = params[:n_models]
        b = params[n_models]
        z = np.clip(X_tr @ w + b, -30.0, 30.0)
        loss = np.mean(np.logaddexp(0.0, z) - y_tr * z)
        return float(loss + 0.005 * np.sum(w ** 2))

    bounds = [(0.0, 10.0)] * n_models + [(-20.0, 5.0)]
    res = minimize(copula_obj, p0, method="L-BFGS-B", bounds=bounds)
    w_cop = res.x[:n_models]
    b_cop = res.x[n_models]

    raw_tr = X_tr @ w_cop + b_cop
    raw_te = X_te @ w_cop + b_cop

    iso = IsotonicRegression(y_min=1e-5, y_max=0.999, out_of_bounds="clip")
    iso.fit(raw_tr, y_tr)
    p_copula_te = 0.5 * iso.predict(raw_te) + 0.5 * expit(np.clip(raw_te, -30.0, 30.0))

    # --- Component B: Simplex Coordinate Ascent on Probability Matrix ---
    w_simp = np.ones(n_models, dtype=np.float64) / float(n_models)

    def simp_obj(w_vec):
        pred = np.clip(P_tr @ w_vec, 1e-6, 1.0 - 1e-6)
        ap, ndcg = fast_ap_and_ndcg100(y_tr, pred)
        reg = 0.015 * np.sum((w_vec - 1.0 / n_models) ** 2)
        return 0.70 * ap + 0.30 * ndcg - reg

    best_sc = simp_obj(w_simp)
    alphas = np.linspace(0.0, 0.5, 26)
    for _ in range(25):
        improved = False
        for m in range(n_models):
            e_m = np.zeros(n_models, dtype=np.float64)
            e_m[m] = 1.0
            best_a = 0.0
            for a in alphas[1:]:
                w_cand = (1.0 - a) * w_simp + a * e_m
                sc_val = simp_obj(w_cand)
                if sc_val > best_sc + 1e-6:
                    best_sc = sc_val
                    best_a = a
                    improved = True
            if best_a > 0:
                w_simp = (1.0 - best_a) * w_simp + best_a * e_m
        if not improved:
            break
    w_simp = w_simp / np.sum(w_simp)
    p_simplex_te = P_te @ w_simp

    # Final locked-in blend: 60% Copula Rank-Isotonic + 40% Simplex Probability Blend
    p_final = 0.60 * p_copula_te + 0.40 * p_simplex_te
    w_cop_norm = w_cop / max(np.sum(w_cop), 1e-8)

    meta_info = {
        "copula_rank_weights": {BASE_MODELS[i]: round(float(w_cop_norm[i]), 4) for i in range(n_models)},
        "simplex_prob_weights": {BASE_MODELS[i]: round(float(w_simp[i]), 4) for i in range(n_models)},
    }
    return p_final, meta_info


def run_tier_pipeline(
    df_train: pd.DataFrame,
    df_2026: pd.DataFrame,
    tier_name: str,
    tier_cfg_cv: dict,
    tier_cfg_temp: dict,
    X_tr_strict_tfidf,
    X_2026_strict_tfidf,
) -> tuple[np.ndarray, dict]:
    t0 = time.time()
    print(f"\n======================================================================", flush=True)
    print(f"Building Locked-In v1 Ensemble for {tier_name}", flush=True)
    print(f"======================================================================", flush=True)

    y_all = df_train["target_kev"].values.astype(np.int32)
    months_all = df_train["snapshot_month"].values
    n = len(df_train)
    n_m = len(BASE_MODELS)

    # 1. 5-Fold Stratified CV Out-of-Fold Matrix
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_indices = list(skf.split(df_train, y_all))
    P_oof = np.zeros((n, n_m), dtype=np.float64)

    for tr_idx, val_idx in fold_indices:
        p_d = fit_predict_v1_base_models(
            df_train.iloc[tr_idx].reset_index(drop=True),
            df_train.iloc[val_idx].reset_index(drop=True),
            tier_cfg_cv,
            X_tr_strict_tfidf[tr_idx],
            X_tr_strict_tfidf[val_idx],
        )
        for j, m_name in enumerate(BASE_MODELS):
            P_oof[val_idx, j] = p_d[m_name]

    oof_v1 = np.zeros(n, dtype=np.float64)
    for tr_idx, val_idx in fold_indices:
        oof_v1[val_idx], _ = fit_predict_copula_plus_simplex_meta(
            P_oof[tr_idx], months_all[tr_idx], y_all[tr_idx], P_oof[val_idx], months_all[val_idx]
        )

    cv_metrics = compute_all_metrics(y_all, oof_v1)
    print(
        f"  [5-Fold Nested CV] ROC={cv_metrics['roc_auc']:.4f} | PR-AUC={cv_metrics['pr_auc']:.4f} | "
        f"NDCG@100={cv_metrics['ndcg@100']:.4f} | Max-F1={cv_metrics['max_f1']:.4f} | "
        f"H@100={cv_metrics['hits@100']:2d}/122 | H@250={cv_metrics['hits@250']:2d}/122",
        flush=True,
    )

    # 2. Causal Walk-Forward 2024 -> 2025 Validation
    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values
    df_24 = df_train.iloc[np.where(is_24)[0]].reset_index(drop=True)
    df_25 = df_train.iloc[np.where(is_25)[0]].reset_index(drop=True)
    X_tf_24 = X_tr_strict_tfidf[is_24]
    X_tf_25 = X_tr_strict_tfidf[is_25]

    wf_splits = [
        (
            df_24["snapshot_month"] <= "2024-04",
            (df_24["snapshot_month"] >= "2024-05") & (df_24["snapshot_month"] <= "2024-08"),
        ),
        (
            df_24["snapshot_month"] <= "2024-08",
            df_24["snapshot_month"] >= "2024-09",
        ),
    ]
    P_wf_list, y_wf_list, m_wf_list = [], [], []
    for tr_m, val_m in wf_splits:
        tr_i = np.where(tr_m.values)[0]
        val_i = np.where(val_m.values)[0]
        p_d = fit_predict_v1_base_models(
            df_24.iloc[tr_i].reset_index(drop=True),
            df_24.iloc[val_i].reset_index(drop=True),
            tier_cfg_temp,
            X_tf_24[tr_i],
            X_tf_24[val_i],
        )
        P_wf_list.append(np.column_stack([p_d[m] for m in BASE_MODELS]))
        y_wf_list.append(df_24.iloc[val_i]["target_kev"].values.astype(np.int32))
        m_wf_list.append(df_24.iloc[val_i]["snapshot_month"].values)

    P_wf_24 = np.vstack(P_wf_list)
    y_wf_24 = np.concatenate(y_wf_list)
    m_wf_24 = np.concatenate(m_wf_list)

    preds_25_d = fit_predict_v1_base_models(df_24, df_25, tier_cfg_temp, X_tf_24, X_tf_25)
    P_te_25 = np.column_stack([preds_25_d[m] for m in BASE_MODELS])
    y_te_25 = df_25["target_kev"].values.astype(np.int32)
    m_te_25 = df_25["snapshot_month"].values

    p_25_v1, wf_meta_info = fit_predict_copula_plus_simplex_meta(
        P_wf_24, m_wf_24, y_wf_24, P_te_25, m_te_25
    )
    temp_metrics = compute_all_metrics(y_te_25, p_25_v1, ks=(25, 50, 100, 250))
    print(
        f"  [2024->2025 Causal] ROC={temp_metrics['roc_auc']:.4f} | PR-AUC={temp_metrics['pr_auc']:.4f} | "
        f"NDCG@100={temp_metrics['ndcg@100']:.4f} | Max-F1={temp_metrics['max_f1']:.4f} | "
        f"H@25={temp_metrics['hits@25']:2d}/55 | H@50={temp_metrics['hits@50']:2d}/55 | "
        f"H@100={temp_metrics['hits@100']:2d}/55 | H@250={temp_metrics['hits@250']:2d}/55",
        flush=True,
    )

    # 3. Fit Full 2024-2025 Base Models & Score 2026 Scoreboard (`72,670` CVEs)
    preds_2026_d = fit_predict_v1_base_models(
        df_train, df_2026, tier_cfg_cv, X_tr_strict_tfidf, X_2026_strict_tfidf
    )
    P_te_2026 = np.column_stack([preds_2026_d[m] for m in BASE_MODELS])
    m_te_2026 = df_2026["snapshot_month"].values

    p_2026_v1, full_meta_info = fit_predict_copula_plus_simplex_meta(
        P_oof, months_all, y_all, P_te_2026, m_te_2026
    )
    print(f"  Scored 72,670 scoreboard_2026 CVEs in {time.time() - t0:.1f}s", flush=True)

    return p_2026_v1, P_te_2026, {
        "cv_5fold_metrics": cv_metrics,
        "temporal_2024_to_2025_metrics": temp_metrics,
        "walk_forward_2024_weights": wf_meta_info,
        "full_2024_2025_weights": full_meta_info,
    }


def main():
    t_start = time.time()
    df_train = pd.read_csv(os.path.join(FEAT_DIR, "features_train_2024_2025.csv"))
    df_2026 = pd.read_csv(os.path.join(FEAT_DIR, "features_scoreboard_2026.csv"))

    (
        df_train,
        df_2026,
        _,
        X_tr_strict_tfidf,
        X_2026_strict_tfidf,
        _,
    ) = prepare_strict_and_expanded_data(df_train, df_2026)

    tiers_cv = get_tier_columns(df_train, temporal=False)
    tiers_temp = get_tier_columns(df_train, temporal=True)

    p26_tier_b, P26_base_b, info_b = run_tier_pipeline(
        df_train,
        df_2026,
        "Tier B (Expanded Metadata / Grey-Zone)",
        tiers_cv["Tier B (Expanded Metadata / Grey-Zone)"],
        tiers_temp["Tier B (Expanded Metadata / Grey-Zone)"],
        X_tr_strict_tfidf,
        X_2026_strict_tfidf,
    )
    p26_tier_a, P26_base_a, info_a = run_tier_pipeline(
        df_train,
        df_2026,
        "Tier A (Pub-Time Strict)",
        tiers_cv["Tier A (Pub-Time Strict)"],
        tiers_temp["Tier A (Pub-Time Strict)"],
        X_tr_strict_tfidf,
        X_2026_strict_tfidf,
    )

    # Combined v1 score: 75% Tier B (Expanded Metadata) + 25% Tier A (Pub-Time Strict safety anchor)
    p26_final = 0.75 * p26_tier_b + 0.25 * p26_tier_a

    sub_df = pd.DataFrame(
        {
            "cve_id": df_2026["cve_id"],
            "published": df_2026["published"],
            "snapshot_month": df_2026["snapshot_month"],
            "score_v1_ensemble": np.round(p26_final, 6),
            "score_tier_b_expanded": np.round(p26_tier_b, 6),
            "score_tier_a_strict": np.round(p26_tier_a, 6),
            "base_lr_stack": np.round(P26_base_b[:, 0], 6),
            "base_lr_joint_tfidf": np.round(P26_base_b[:, 1], 6),
            "base_rf": np.round(P26_base_b[:, 2], 6),
            "base_lgbm_full": np.round(P26_base_b[:, 3], 6),
            "base_lgbm_undersampled": np.round(P26_base_b[:, 4], 6),
            "base_xgb_lambdamart": np.round(P26_base_b[:, 5], 6),
        }
    )
    sub_df = sub_df.sort_values("score_v1_ensemble", ascending=False).reset_index(drop=True)

    sub_path = os.path.join(FEAT_DIR, "submission_v1_scoreboard_2026.csv")
    sub_df.to_csv(sub_path, index=False)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary_path = os.path.join(RESULTS_DIR, "submission_v1_summary.json")
    summary_data = {
        "architecture": "v1 Locked Ensemble (6 Base Models + Copula Within-Month Rank/Isotonic + Simplex Blend)",
        "base_models": BASE_MODELS,
        "tier_b_expanded": info_b,
        "tier_a_strict": info_a,
        "top_25_predictions_2026": sub_df.head(25).to_dict(orient="records"),
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(f"\nSaved locked-in v1 submission ({len(sub_df):,} rows) to {sub_path}")
    print(f"Saved v1 summary & top 25 predictions to {summary_path} in {time.time() - t_start:.1f}s")


if __name__ == "__main__":
    main()
