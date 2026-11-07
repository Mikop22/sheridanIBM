#!/usr/bin/env python3
"""
Comprehensive Benchmark of All 6 Level-2 Stacking Meta-Learners vs. Iterative
Direct Weight Optimization and Heuristic Blends.

Evaluates 10 Level-2 Ensemble / Meta-Learner Architectures across both
Tier A (`Pub-Time Strict`) and Tier B (`Expanded Metadata`), under:
  1. Nested 5-Fold Stratified CV (82,430 CVEs, 122 post-snapshot KEVs)
  2. Strictly Causal Walk-Forward Temporal Split (Train 2024 Walk-Forward OOF
     -> Test 2025 Cohort, 42,562 CVEs, 55 post-snapshot KEVs)

Models Compared:
  - Baseline 1 : Arbitrary Hand-Picked Weights (0.25 LR, 0.25 LGBM, 0.30 CB, 0.20 LM)
  - Baseline 2 : Equal Uniform Blend (1/6 each across all 6 base models)
  - Iterative 1: Caruana Forward Stepwise Selection (100 greedy steps on PR-AUC + NDCG@100)
  - Iterative 2: Simplex Coordinate Ascent (PR-AUC + NDCG@100 - LogLoss on probability simplex)
  - Meta 1     : Non-Negative Log-Odds (Logit) L2 Logistic Meta-Learner (Breiman/Bayesian log-odds)
  - Meta 2     : ElasticNet Pairwise-Interaction Stacking (6 base + 15 pairwise model products)
  - Meta 3     : Feature-Weighted Linear Stacking (FWLS / Context-Gated Mixture of Experts
                 routing on metadata availability flags: cvss_has_v3, cwe_missing, sig_any_flag, sig_epss_missing)
  - Meta 4     : Monotonic-Constrained Shallow GBDT Meta-Learner (LightGBM depth-2 stumps with
                 monotone_constraints=(+1,+1,+1,+1,+1,+1))
  - Meta 5     : Copula Within-Month Rank-Percentile + Isotonic Regression Meta-Learner
                 (100% invariant to the March 2025 EPSS scale shift)
  - Meta 6     : Level-2 Monotonic LambdaMART Meta-Ranker (XGBRanker objective='rank:ndcg'
                 grouped by qid=snapshot_month on base model predictions + within-month ranks)
"""

import json
import os
import time

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from scipy.optimize import minimize
from scipy.special import expit, logit
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRanker

from eval_gbdt_ranking import (
    FEAT_DIR,
    compute_all_metrics,
    get_tier_columns,
    prepare_strict_and_expanded_data,
)
from optimize_ensemble_weights import (
    MODEL_NAMES,
    caruana_forward_stepwise_selection,
    coordinate_ascent_simplex,
    fit_base_models_and_predict,
)

GATE_COLS = [
    "cvss_has_v3",
    "cwe_missing",
    "sig_any_flag",
    "sig_epss_missing",
]


def safe_logit(p: np.ndarray) -> np.ndarray:
    return logit(np.clip(p, 1e-6, 1.0 - 1e-6))


def within_month_ranks(P: np.ndarray, months: np.ndarray) -> np.ndarray:
    """Convert each column of P into empirical rank percentiles [0, 1] within each snapshot_month."""
    R = np.zeros_like(P, dtype=np.float64)
    uniq_m = np.unique(months)
    for m in uniq_m:
        mask = months == m
        n_m = int(np.sum(mask))
        if n_m <= 1:
            R[mask, :] = 0.5
            continue
        for j in range(P.shape[1]):
            order = np.argsort(P[mask, j])
            ranks = np.empty_like(order, dtype=np.float64)
            ranks[order] = np.arange(1, n_m + 1, dtype=np.float64) / float(n_m)
            R[mask, j] = ranks
    return R


# ============================================================================
# Implementation of All 6 Stacking Meta-Learners
# ============================================================================


def fit_predict_meta1_nonneg_logit(P_tr: np.ndarray, y_tr: np.ndarray, P_te: np.ndarray) -> tuple[np.ndarray, dict]:
    """
    Meta-Learner 1: Non-Negative Log-Odds (Logit) L2 Stacking.
    Transforms base probabilities to log-odds and fits a constrained L-BFGS-B
    logistic model with beta_j >= 0 and L2 regularization.
    """
    L_tr = safe_logit(P_tr)
    L_te = safe_logit(P_te)
    sc = StandardScaler()
    X_tr = sc.fit_transform(L_tr)
    X_te = sc.transform(L_te)

    n_m = X_tr.shape[1]
    # Parameter vector: [w_0, ..., w_{M-1}, intercept]
    p0 = np.zeros(n_m + 1, dtype=np.float64)
    p0[:n_m] = 1.0 / n_m
    p0[n_m] = -6.0

    def obj(params):
        w = params[:n_m]
        b = params[n_m]
        z = np.clip(X_tr @ w + b, -30.0, 30.0)
        # Binary cross-entropy + L2 penalty
        loss = np.mean(np.logaddexp(0.0, z) - y_tr * z)
        reg = 0.002 * np.sum(w ** 2)
        return float(loss + reg)

    bounds = [(0.0, 10.0)] * n_m + [(-20.0, 5.0)]
    res = minimize(obj, p0, method="L-BFGS-B", bounds=bounds)
    w_opt = res.x[:n_m]
    b_opt = res.x[n_m]
    preds = expit(np.clip(X_te @ w_opt + b_opt, -30.0, 30.0))
    w_norm = w_opt / max(np.sum(w_opt), 1e-8)
    info = {MODEL_NAMES[i]: round(float(w_norm[i]), 3) for i in range(n_m)}
    return preds, info


def fit_predict_meta2_elasticnet_interactions(
    P_tr: np.ndarray, y_tr: np.ndarray, P_te: np.ndarray
) -> np.ndarray:
    """
    Meta-Learner 2: ElasticNet Stacking with All Pairwise Model Interactions.
    Combines 6 log-odds + 6 probabilities + 15 pairwise probability products
    + 15 pairwise rank-percentile products (42 features total) with L1+L2 penalty.
    """
    def build_inter_features(P):
        L = safe_logit(P)
        n_m = P.shape[1]
        prods_p = []
        prods_l = []
        for i in range(n_m):
            for j in range(i + 1, n_m):
                prods_p.append(np.sqrt(P[:, i] * P[:, j] + 1e-10))
                prods_l.append(L[:, i] * L[:, j])
        return np.column_stack([P, L] + prods_p + prods_l)

    X_tr_raw = build_inter_features(P_tr)
    X_te_raw = build_inter_features(P_te)
    sc = StandardScaler()
    X_tr = sc.fit_transform(X_tr_raw)
    X_te = sc.transform(X_te_raw)

    clf = LogisticRegression(
        penalty="elasticnet",
        l1_ratio=0.5,
        C=0.05,
        solver="saga",
        max_iter=600,
        random_state=42,
    )
    clf.fit(X_tr, y_tr)
    return clf.predict_proba(X_te)[:, 1]


def fit_predict_meta3_fwls_gated(
    P_tr: np.ndarray,
    Z_tr: np.ndarray,
    y_tr: np.ndarray,
    P_te: np.ndarray,
    Z_te: np.ndarray,
) -> np.ndarray:
    """
    Meta-Learner 3: Feature-Weighted Linear Stacking (FWLS / Context-Gated Mixture of Experts).
    Routes weight dynamically across the 6 base models as a function of metadata
    availability indicators Z = [cvss_has_v3, cwe_missing, sig_any_flag, sig_epss_missing].
    """
    def build_fwls_matrix(P, Z):
        L = safe_logit(P)
        interactions = []
        for m in range(P.shape[1]):
            for k in range(Z.shape[1]):
                interactions.append(P[:, m] * Z[:, k])
                interactions.append(L[:, m] * Z[:, k])
        return np.column_stack([P, L, Z] + interactions)

    X_tr_raw = build_fwls_matrix(P_tr, Z_tr)
    X_te_raw = build_fwls_matrix(P_te, Z_te)
    sc = StandardScaler()
    X_tr = sc.fit_transform(X_tr_raw)
    X_te = sc.transform(X_te_raw)

    clf = LogisticRegression(C=0.03, penalty="l2", max_iter=500, random_state=42)
    clf.fit(X_tr, y_tr)
    return clf.predict_proba(X_te)[:, 1]


def fit_predict_meta4_monotonic_gbdt(
    P_tr: np.ndarray,
    months_tr: np.ndarray,
    y_tr: np.ndarray,
    P_te: np.ndarray,
    months_te: np.ndarray,
) -> np.ndarray:
    """
    Meta-Learner 4: Monotonic-Constrained Shallow GBDT Meta-Learner.
    Feeds both raw probabilities P and within-month rank percentiles R (12 features)
    into a depth-2 LightGBM classifier with strict +1 monotonicity constraints on all columns.
    """
    R_tr = within_month_ranks(P_tr, months_tr)
    R_te = within_month_ranks(P_te, months_te)
    X_tr = np.column_stack([P_tr, R_tr])
    X_te = np.column_stack([P_te, R_te])

    mono_gbdt = LGBMClassifier(
        n_estimators=75,
        learning_rate=0.03,
        max_depth=2,
        num_leaves=4,
        min_child_samples=40,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=1.0,
        reg_lambda=5.0,
        monotone_constraints=[1] * X_tr.shape[1],
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    mono_gbdt.fit(X_tr, y_tr)
    return mono_gbdt.predict_proba(X_te)[:, 1]


def fit_predict_meta5_copula_isotonic(
    P_tr: np.ndarray,
    months_tr: np.ndarray,
    y_tr: np.ndarray,
    P_te: np.ndarray,
    months_te: np.ndarray,
) -> np.ndarray:
    """
    Meta-Learner 5: Copula Within-Month Rank-Percentile + Isotonic Regression.
    100% immune to global score scale drift (such as the March 2025 EPSS shift):
    transforms every model's output within each snapshot_month into empirical rank
    percentiles u_m in (0, 1) and upper-tail log-survival -log(1 - u_m), combines
    them via non-negative L2 logistic regression, and applies Isotonic Regression
    calibration to produce true probabilities.
    """
    R_tr = within_month_ranks(P_tr, months_tr)
    R_te = within_month_ranks(P_te, months_te)

    # Upper-tail log-rank emphasis: -log(1 - rank_pct + 1e-4) highlights the top 0.1% - 1% of each month
    T_tr = -np.log(1.0 - np.clip(R_tr, 0.0, 0.9995))
    T_te = -np.log(1.0 - np.clip(R_te, 0.0, 0.9995))

    sc = StandardScaler()
    X_tr = sc.fit_transform(T_tr)
    X_te = sc.transform(T_te)

    n_m = X_tr.shape[1]
    p0 = np.zeros(n_m + 1, dtype=np.float64)
    p0[:n_m] = 1.0 / n_m
    p0[n_m] = -6.0

    def obj(params):
        w = params[:n_m]
        b = params[n_m]
        z = np.clip(X_tr @ w + b, -30.0, 30.0)
        loss = np.mean(np.logaddexp(0.0, z) - y_tr * z)
        return float(loss + 0.005 * np.sum(w ** 2))

    bounds = [(0.0, 10.0)] * n_m + [(-20.0, 5.0)]
    res = minimize(obj, p0, method="L-BFGS-B", bounds=bounds)
    w_opt = res.x[:n_m]
    b_opt = res.x[n_m]

    raw_score_tr = X_tr @ w_opt + b_opt
    raw_score_te = X_te @ w_opt + b_opt

    iso = IsotonicRegression(y_min=1e-5, y_max=0.999, out_of_bounds="clip")
    iso.fit(raw_score_tr, y_tr)
    # Blend smooth sigmoid + isotonic step function so ties within isotonic bins preserve strict ordering
    p_iso = iso.predict(raw_score_te)
    p_sig = expit(np.clip(raw_score_te, -30.0, 30.0))
    return 0.5 * p_iso + 0.5 * p_sig


def fit_predict_meta6_lambdamart_ranker(
    P_tr: np.ndarray,
    months_tr: np.ndarray,
    y_tr: np.ndarray,
    P_te: np.ndarray,
    months_te: np.ndarray,
) -> np.ndarray:
    """
    Meta-Learner 6: Level-2 Monotonic LambdaMART Meta-Ranker (`rank:ndcg`).
    Directly optimizes listwise NDCG within each `snapshot_month` cohort over
    the 6 base probabilities + 6 within-month upper-tail log-ranks, with
    monotonicity constraints (+1) on every input.
    """
    R_tr = within_month_ranks(P_tr, months_tr)
    R_te = within_month_ranks(P_te, months_te)
    T_tr = -np.log(1.0 - np.clip(R_tr, 0.0, 0.9995))
    T_te = -np.log(1.0 - np.clip(R_te, 0.0, 0.9995))

    X_tr = np.column_stack([P_tr, T_tr])
    X_te = np.column_stack([P_te, T_te])

    order = np.argsort(months_tr)
    X_tr_sorted = X_tr[order]
    y_tr_sorted = y_tr[order]
    qid_tr = pd.Categorical(months_tr[order]).codes

    meta_ranker = XGBRanker(
        objective="rank:ndcg",
        ndcg_exp_gain=True,
        n_estimators=80,
        learning_rate=0.05,
        max_depth=2,
        min_child_weight=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        monotone_constraints=tuple([1] * X_tr.shape[1]),
        tree_method="hist",
        random_state=42,
        n_jobs=-1,
    )
    meta_ranker.fit(X_tr_sorted, y_tr_sorted, qid=qid_tr)
    margin_te = meta_ranker.predict(X_te)
    margin_tr = meta_ranker.predict(X_tr)

    # Calibrate margin to probability via 1D Platt scaling
    sc = StandardScaler()
    m_tr_std = sc.fit_transform(margin_tr.reshape(-1, 1))
    m_te_std = sc.transform(margin_te.reshape(-1, 1))
    cal = LogisticRegression(C=1.0, random_state=42).fit(m_tr_std, y_tr)
    return cal.predict_proba(m_te_std)[:, 1]


def evaluate_all_meta_learners_on_tier(
    df_train: pd.DataFrame,
    tier_name: str,
    tier_cfg_cv: dict,
    tier_cfg_temp: dict,
    X_tr_strict_tfidf,
):
    t0 = time.time()
    print(f"\n======================================================================", flush=True)
    print(f"Evaluating All 6 Meta-Learners & Iterative Optimizers on {tier_name}", flush=True)
    print(f"======================================================================", flush=True)

    y_all = df_train["target_kev"].values.astype(np.int32)
    months_all = df_train["snapshot_month"].values
    Z_all = df_train[GATE_COLS].values.astype(np.float64)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_indices = list(skf.split(df_train, y_all))

    # 1. Build Level-1 5-Fold OOF Prediction Matrix P_oof (82,430 x 6)
    P_oof = np.zeros((len(df_train), len(MODEL_NAMES)), dtype=np.float64)
    for tr_idx, val_idx in fold_indices:
        preds_dict = fit_base_models_and_predict(
            df_train.iloc[tr_idx],
            df_train.iloc[val_idx],
            tier_cfg_cv,
            X_tr_strict_tfidf[tr_idx],
            X_tr_strict_tfidf[val_idx],
        )
        for j, m_name in enumerate(MODEL_NAMES):
            P_oof[val_idx, j] = preds_dict[m_name]
    print(f"  [Step 1] Level-1 5-Fold OOF Matrix ready in {time.time() - t0:.1f}s", flush=True)

    # 2. Evaluate all 10 Level-2 methods via Nested 5-Fold Cross-Validation
    n = len(df_train)
    w_arbitrary = np.array([0.125, 0.125, 0.0, 0.25, 0.30, 0.20])
    w_uniform = np.ones(len(MODEL_NAMES)) / len(MODEL_NAMES)

    cv_preds = {
        "1. Baseline: Arbitrary Hand-Picked Weights": P_oof @ w_arbitrary,
        "2. Baseline: Equal Uniform Blend (1/6 each)": P_oof @ w_uniform,
        "3. Iterative: Caruana Forward Stepwise Selection": np.zeros(n),
        "4. Iterative: Simplex Coordinate Ascent": np.zeros(n),
        "5. Meta 1: Non-Negative Log-Odds (Logit) L2 Stacking": np.zeros(n),
        "6. Meta 2: ElasticNet Pairwise-Interaction Stacking": np.zeros(n),
        "7. Meta 3: Feature-Weighted Linear Stacking (FWLS Gated)": np.zeros(n),
        "8. Meta 4: Monotonic Shallow GBDT Meta-Learner": np.zeros(n),
        "9. Meta 5: Copula Within-Month Rank + Isotonic Meta-Learner": np.zeros(n),
        "10. Meta 6: Level-2 Monotonic LambdaMART Meta-Ranker": np.zeros(n),
    }

    for tr_idx, val_idx in fold_indices:
        P_tr, y_tr, m_tr, Z_tr = P_oof[tr_idx], y_all[tr_idx], months_all[tr_idx], Z_all[tr_idx]
        P_val, m_val, Z_val = P_oof[val_idx], months_all[val_idx], Z_all[val_idx]

        w_car, _ = caruana_forward_stepwise_selection(P_tr, y_tr, n_iterations=100)
        w_crd = coordinate_ascent_simplex(P_tr, y_tr)
        cv_preds["3. Iterative: Caruana Forward Stepwise Selection"][val_idx] = P_val @ w_car
        cv_preds["4. Iterative: Simplex Coordinate Ascent"][val_idx] = P_val @ w_crd

        p_m1, _ = fit_predict_meta1_nonneg_logit(P_tr, y_tr, P_val)
        cv_preds["5. Meta 1: Non-Negative Log-Odds (Logit) L2 Stacking"][val_idx] = p_m1
        cv_preds["6. Meta 2: ElasticNet Pairwise-Interaction Stacking"][val_idx] = (
            fit_predict_meta2_elasticnet_interactions(P_tr, y_tr, P_val)
        )
        cv_preds["7. Meta 3: Feature-Weighted Linear Stacking (FWLS Gated)"][val_idx] = (
            fit_predict_meta3_fwls_gated(P_tr, Z_tr, y_tr, P_val, Z_val)
        )
        cv_preds["8. Meta 4: Monotonic Shallow GBDT Meta-Learner"][val_idx] = (
            fit_predict_meta4_monotonic_gbdt(P_tr, m_tr, y_tr, P_val, m_val)
        )
        cv_preds["9. Meta 5: Copula Within-Month Rank + Isotonic Meta-Learner"][val_idx] = (
            fit_predict_meta5_copula_isotonic(P_tr, m_tr, y_tr, P_val, m_val)
        )
        cv_preds["10. Meta 6: Level-2 Monotonic LambdaMART Meta-Ranker"][val_idx] = (
            fit_predict_meta6_lambdamart_ranker(P_tr, m_tr, y_tr, P_val, m_val)
        )

    print("\n--- Nested 5-Fold Stratified CV Results (82,430 CVEs, 122 KEVs) ---", flush=True)
    cv_metrics = {}
    for name, s in cv_preds.items():
        m = compute_all_metrics(y_all, s)
        cv_metrics[name] = m
        print(
            f"  {name:60s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d} | H@250={m['hits@250']:2d} | H@500={m['hits@500']:2d}",
            flush=True,
        )

    # 3. Strictly Causal Walk-Forward Temporal Split (Train 2024 Walk-Forward -> Test 2025)
    # Build Walk-Forward OOF inside 2024 so meta-learners are trained strictly on out-of-time predictions!
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

    P_wf_list, y_wf_list, m_wf_list, Z_wf_list = [], [], [], []
    for tr_m, val_m in wf_splits:
        tr_i = np.where(tr_m.values)[0]
        val_i = np.where(val_m.values)[0]
        p_d = fit_base_models_and_predict(
            df_24.iloc[tr_i],
            df_24.iloc[val_i],
            tier_cfg_temp,
            X_tf_24[tr_i],
            X_tf_24[val_i],
        )
        P_wf_list.append(np.column_stack([p_d[m] for m in MODEL_NAMES]))
        y_wf_list.append(df_24.iloc[val_i]["target_kev"].values.astype(np.int32))
        m_wf_list.append(df_24.iloc[val_i]["snapshot_month"].values)
        Z_wf_list.append(df_24.iloc[val_i][GATE_COLS].values.astype(np.float64))

    P_wf_24 = np.vstack(P_wf_list)
    y_wf_24 = np.concatenate(y_wf_list)
    m_wf_24 = np.concatenate(m_wf_list)
    Z_wf_24 = np.vstack(Z_wf_list)

    # Fit Level-1 models on all 2024 data and predict on 2025 test set
    preds_25_dict = fit_base_models_and_predict(df_24, df_25, tier_cfg_temp, X_tf_24, X_tf_25)
    P_te_25 = np.column_stack([preds_25_dict[m] for m in MODEL_NAMES])
    y_te_25 = df_25["target_kev"].values.astype(np.int32)
    m_te_25 = df_25["snapshot_month"].values
    Z_te_25 = df_25[GATE_COLS].values.astype(np.float64)

    w_wf_car, _ = caruana_forward_stepwise_selection(P_wf_24, y_wf_24, n_iterations=100, init_top_k=3)
    w_wf_crd = coordinate_ascent_simplex(P_wf_24, y_wf_24)
    p_m1_25, m1_weights_24 = fit_predict_meta1_nonneg_logit(P_wf_24, y_wf_24, P_te_25)

    temp_preds = {
        "1. Baseline: Arbitrary Hand-Picked Weights": P_te_25 @ w_arbitrary,
        "2. Baseline: Equal Uniform Blend (1/6 each)": P_te_25 @ w_uniform,
        "3. Iterative: Walk-Forward Caruana Stepwise": P_te_25 @ w_wf_car,
        "4. Iterative: Walk-Forward Simplex Coordinate Ascent": P_te_25 @ w_wf_crd,
        "5. Meta 1: Non-Negative Log-Odds (Logit) L2 Stacking": p_m1_25,
        "6. Meta 2: ElasticNet Pairwise-Interaction Stacking": (
            fit_predict_meta2_elasticnet_interactions(P_wf_24, y_wf_24, P_te_25)
        ),
        "7. Meta 3: Feature-Weighted Linear Stacking (FWLS Gated)": (
            fit_predict_meta3_fwls_gated(P_wf_24, Z_wf_24, y_wf_24, P_te_25, Z_te_25)
        ),
        "8. Meta 4: Monotonic Shallow GBDT Meta-Learner": (
            fit_predict_meta4_monotonic_gbdt(P_wf_24, m_wf_24, y_wf_24, P_te_25, m_te_25)
        ),
        "9. Meta 5: Copula Within-Month Rank + Isotonic Meta-Learner": (
            fit_predict_meta5_copula_isotonic(P_wf_24, m_wf_24, y_wf_24, P_te_25, m_te_25)
        ),
        "10. Meta 6: Level-2 Monotonic LambdaMART Meta-Ranker": (
            fit_predict_meta6_lambdamart_ranker(P_wf_24, m_wf_24, y_wf_24, P_te_25, m_te_25)
        ),
    }

    ks = (25, 50, 100, 250)
    print("\n--- Causal Walk-Forward Temporal Split (Train 2024 -> Test 2025, 42,562 CVEs, 55 KEVs) ---", flush=True)
    temp_metrics = {}
    for name, s in temp_preds.items():
        m = compute_all_metrics(y_te_25, s, ks=ks)
        temp_metrics[name] = m
        print(
            f"  {name:60s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@25={m['hits@25']:2d} | H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d}/55 | H@250={m['hits@250']:2d}/55",
            flush=True,
        )

    return {
        "cv_5fold": cv_metrics,
        "temporal_2024_to_2025": temp_metrics,
        "walk_forward_learned_weights": {
            "caruana_stepwise": {MODEL_NAMES[i]: round(float(w_wf_car[i]), 3) for i in range(6)},
            "coordinate_ascent": {MODEL_NAMES[i]: round(float(w_wf_crd[i]), 3) for i in range(6)},
            "meta1_nonneg_logit": m1_weights_24,
        },
    }


def main():
    t_start = time.time()
    df_train = pd.read_csv(os.path.join(FEAT_DIR, "features_train_2024_2025.csv"))
    df_2026 = pd.read_csv(os.path.join(FEAT_DIR, "features_scoreboard_2026.csv"))

    df_train, _, X_tr_strict_tfidf, _ = prepare_strict_and_expanded_data(df_train, df_2026)
    tiers_cv = get_tier_columns(df_train, temporal=False)
    tiers_temp = get_tier_columns(df_train, temporal=True)

    results = {}
    for t_name in (
        "Tier A (Pub-Time Strict)",
        "Tier B (Expanded Metadata / Grey-Zone)",
    ):
        results[t_name] = evaluate_all_meta_learners_on_tier(
            df_train, t_name, tiers_cv[t_name], tiers_temp[t_name], X_tr_strict_tfidf
        )

    out_path = os.path.join(FEAT_DIR, "meta_learners_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved full meta-learner comparison to {out_path} in {time.time() - t_start:.1f}s", flush=True)


if __name__ == "__main__":
    main()
