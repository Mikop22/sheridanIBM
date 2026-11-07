#!/usr/bin/env python3
"""
Iterative Ensemble Weight Optimization for CVE Exploitation (KEV) Prediction.

Replaces arbitrary hand-picked weights with three principled iterative optimization
algorithms evaluated strictly out-of-sample (Nested OOF for 5-Fold CV, and Causal
Within-2024 Temporal Validation for the 2024 -> 2025 split):

  1. Caruana's Forward Stepwise Ensemble Selection (Greedy Hillclimbing with
     Replacement, T=100 iterations) optimizing PR-AUC + NDCG@100.
  2. Simplex Coordinate Ascent (`coordinate_ascent_simplex` on the probability
     simplex w_i >= 0, sum(w_i) = 1) optimizing PR-AUC + NDCG@100 - LogLoss.
  3. Convex SLSQP Log-Loss Stacking (minimizing regularized Cross-Entropy on the
     probability simplex).

Evaluates across candidate pool of 6 distinct base models:
  - `lr_stack`   : Stacked L2 Logistic Regression (Tabular + OOF TF-IDF)
  - `lr_joint`   : Joint Wide Sparse L2 Logistic Regression (`hstack[Tabular, 35k TF-IDF]`)
  - `rf`         : Random Forest (Unweighted, 300 trees)
  - `lgbm`       : LightGBM Classifier (leaf-wise GBDT with categorical splits)
  - `catboost`   : CatBoost Classifier (`Ordered` boosting with categorical target stats)
  - `lambdamart` : XGBoost LambdaMART (`rank:ndcg` grouped by `snapshot_month`)
"""

import json
import os
import time

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier
from scipy.optimize import minimize
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRanker

from eval_gbdt_ranking import (
    FEAT_DIR,
    compute_all_metrics,
    get_tier_columns,
    prepare_strict_and_expanded_data,
    sigmoid_calibrate,
)

MODEL_NAMES = [
    "lr_stack",
    "lr_joint",
    "rf",
    "lgbm",
    "catboost",
    "lambdamart",
]


def fast_ap_and_ndcg100(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    """
    Ultra-fast computation of Average Precision (PR-AUC) and NDCG@100 for binary
    labels with rare positives (only ~55-122 positives out of 40k-82k rows).
    Instead of sorting all 82,430 negative elements, computes the exact rank of each
    positive element in O(N * N_pos) vectorized operations + argpartition for top 100.
    """
    pos_scores = scores[y_true == 1]
    n_pos = len(pos_scores)
    if n_pos == 0:
        return 0.0, 0.0

    # Sort the positive scores descending (only 55-122 elements!)
    pos_sorted = np.sort(pos_scores)[::-1]
    # For each positive score, count how many total items have score >= pos_sorted[i]
    # Broadcasting (n_pos, N) is 122 x 82,430 booleans = 10MB, takes ~1.2ms!
    ranks = np.sum(scores[None, :] >= pos_sorted[:, None], axis=1).astype(np.float64)
    precisions_at_pos = np.arange(1, n_pos + 1, dtype=np.float64) / np.maximum(ranks, 1.0)
    ap = float(np.mean(precisions_at_pos))

    # NDCG@100: only positives with rank <= 100 contribute to DCG@100!
    in_top100 = ranks <= 100.0
    if np.any(in_top100):
        dcg = float(np.sum(1.0 / np.log2(ranks[in_top100] + 1.0)))
    else:
        dcg = 0.0
    ideal_k = min(n_pos, 100)
    idcg = float(np.sum(1.0 / np.log2(np.arange(2, ideal_k + 2, dtype=np.float64))))
    ndcg100 = dcg / idcg if idcg > 0 else 0.0
    return ap, ndcg100


def fit_base_models_and_predict(
    df_tr: pd.DataFrame,
    df_val: pd.DataFrame,
    tier_cfg: dict,
    X_tfidf_tr,
    X_tfidf_val,
) -> dict:
    """Fit all 6 base models on df_tr and return dictionary of predictions on df_val."""
    y_tr = df_tr["target_kev"].values.astype(np.int32)
    num_cols = tier_cfg["num_cols"]
    num_no_tf = tier_cfg["num_no_tf"]
    cat_str_cols = tier_cfg["cat_str_cols"]
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

    # 3. Random Forest (Unweighted)
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=5,
        max_features="sqrt",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_num_tr, y_tr)
    p_rf = rf.predict_proba(X_num_val)[:, 1]

    # 4. LightGBM
    lgb_cols = num_cols + cat_code_cols
    X_lgb_tr = df_tr[lgb_cols].copy()
    X_lgb_val = df_val[lgb_cols].copy()
    for c in cat_code_cols:
        X_lgb_tr[c] = X_lgb_tr[c].astype("category")
        X_lgb_val[c] = X_lgb_val[c].astype("category")

    lgbm = LGBMClassifier(
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
    lgbm.fit(X_lgb_tr, y_tr)
    p_lgbm = lgbm.predict_proba(X_lgb_val)[:, 1]

    # 5. CatBoost Ordered
    cb_cols = num_cols + cat_str_cols
    cb = CatBoostClassifier(
        iterations=350,
        learning_rate=0.04,
        depth=5,
        l2_leaf_reg=5.0,
        boosting_type="Ordered",
        cat_features=cat_str_cols,
        random_seed=42,
        thread_count=-1,
        verbose=0,
    )
    cb.fit(df_tr[cb_cols], y_tr)
    p_cb = cb.predict_proba(df_val[cb_cols])[:, 1]

    # 6. XGBoost LambdaMART (`rank:ndcg` grouped by `snapshot_month`)
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
        "lgbm": p_lgbm,
        "catboost": p_cb,
        "lambdamart": p_lambdamart,
    }


def caruana_forward_stepwise_selection(
    P: np.ndarray, y: np.ndarray, n_iterations: int = 100, init_top_k: int = 2
) -> tuple[np.ndarray, list]:
    """
    Caruana et al. (2004) Forward Stepwise Ensemble Selection with Replacement.
    At each step t = 1..T, adds the model column j that maximizes the composite
    ranking objective: 0.70 * PR-AUC + 0.30 * NDCG@100.
    """
    n_samples, n_models = P.shape
    counts = np.zeros(n_models, dtype=np.float64)

    single_scores = []
    for j in range(n_models):
        ap, ndcg = fast_ap_and_ndcg100(y, P[:, j])
        single_scores.append(0.70 * ap + 0.30 * ndcg)

    seed_indices = np.argsort(-np.array(single_scores))[:init_top_k]
    running_sum = np.zeros(n_samples, dtype=np.float64)
    for idx in seed_indices:
        counts[idx] += 1.0
        running_sum += P[:, idx]

    history = []
    for step in range(init_top_k + 1, n_iterations + 1):
        best_j = -1
        best_obj = -1.0
        for j in range(n_models):
            cand_pred = (running_sum + P[:, j]) / float(step)
            ap, ndcg = fast_ap_and_ndcg100(y, cand_pred)
            obj = 0.70 * ap + 0.30 * ndcg
            if obj > best_obj:
                best_obj = obj
                best_j = j
        counts[best_j] += 1.0
        running_sum += P[:, best_j]
        if step in (5, 10, 25, 50, 100):
            w_curr = counts / np.sum(counts)
            cur_pred = P @ w_curr
            ap_c, ndcg_c = fast_ap_and_ndcg100(y, cur_pred)
            history.append(
                {
                    "step": step,
                    "pr_auc": round(ap_c, 4),
                    "ndcg@100": round(ndcg_c, 4),
                    "weights": {MODEL_NAMES[i]: round(float(w_curr[i]), 3) for i in range(n_models)},
                }
            )

    weights = counts / np.sum(counts)
    return weights, history


def coordinate_ascent_simplex(P: np.ndarray, y: np.ndarray, n_passes: int = 25) -> np.ndarray:
    """
    Iterative Coordinate Ascent on the Probability Simplex (w >= 0, sum(w) = 1).
    In each pass, cycles through each model m and performs a 1D line search over
    alpha in [0, 0.5] for (1 - alpha) * w_current + alpha * e_m.
    """
    n_samples, n_models = P.shape
    w = np.ones(n_models, dtype=np.float64) / float(n_models)

    def eval_obj(w_vec):
        pred = np.clip(P @ w_vec, 1e-6, 1.0 - 1e-6)
        ap, ndcg = fast_ap_and_ndcg100(y, pred)
        ll = log_loss(y, pred)
        reg = 0.015 * np.sum((w_vec - 1.0 / n_models) ** 2)
        return 0.70 * ap + 0.30 * ndcg - 0.5 * ll - reg

    best_score = eval_obj(w)
    alphas = np.linspace(0.0, 0.5, 26)

    for _ in range(n_passes):
        improved = False
        for m in range(n_models):
            e_m = np.zeros(n_models, dtype=np.float64)
            e_m[m] = 1.0
            best_alpha = 0.0
            for a in alphas[1:]:
                w_cand = (1.0 - a) * w + a * e_m
                sc = eval_obj(w_cand)
                if sc > best_score + 1e-6:
                    best_score = sc
                    best_alpha = a
                    improved = True
            if best_alpha > 0:
                w = (1.0 - best_alpha) * w + best_alpha * e_m
        if not improved:
            break

    return w / np.sum(w)


def optimize_logloss_stacking(P: np.ndarray, y: np.ndarray) -> np.ndarray:
    """
    Convex SLSQP Optimization on the Probability Simplex minimizing penalized
    Cross-Entropy (Log-Loss) in probability space.
    """
    n_models = P.shape[1]
    w0 = np.ones(n_models, dtype=np.float64) / float(n_models)

    def loss_fn(w):
        w_norm = w / np.sum(w)
        pred = np.clip(P @ w_norm, 1e-6, 1.0 - 1e-6)
        return log_loss(y, pred) + 0.0002 * np.sum((w_norm - 1.0 / n_models) ** 2)

    bounds = [(0.0, 1.0)] * n_models
    constraints = {"type": "eq", "fun": lambda w: np.sum(w) - 1.0}
    res = minimize(loss_fn, w0, method="SLSQP", bounds=bounds, constraints=constraints)
    w_opt = np.maximum(res.x, 0.0)
    return w_opt / np.sum(w_opt)


def run_tier_optimization(
    df_train: pd.DataFrame,
    tier_name: str,
    tier_cfg_cv: dict,
    tier_cfg_temp: dict,
    X_tr_strict_tfidf,
):
    t0 = time.time()
    print(f"\n======================================================================", flush=True)
    print(f"Running Iterative Ensemble Weight Optimization for {tier_name}", flush=True)
    print(f"======================================================================", flush=True)

    y_all = df_train["target_kev"].values.astype(np.int32)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    P_oof = np.zeros((len(df_train), len(MODEL_NAMES)), dtype=np.float64)
    fold_indices = list(skf.split(df_train, y_all))

    for fold_idx, (tr_idx, val_idx) in enumerate(fold_indices):
        preds_dict = fit_base_models_and_predict(
            df_train.iloc[tr_idx],
            df_train.iloc[val_idx],
            tier_cfg_cv,
            X_tr_strict_tfidf[tr_idx],
            X_tr_strict_tfidf[val_idx],
        )
        for j, m_name in enumerate(MODEL_NAMES):
            P_oof[val_idx, j] = preds_dict[m_name]
    print(f"  Generated 5-fold OOF matrix in {time.time() - t0:.1f}s", flush=True)

    oof_nested_caruana = np.zeros(len(df_train), dtype=np.float64)
    oof_nested_coord = np.zeros(len(df_train), dtype=np.float64)
    oof_nested_logloss = np.zeros(len(df_train), dtype=np.float64)

    for fold_idx, (tr_idx, val_idx) in enumerate(fold_indices):
        w_car, _ = caruana_forward_stepwise_selection(P_oof[tr_idx], y_all[tr_idx], n_iterations=100)
        w_crd = coordinate_ascent_simplex(P_oof[tr_idx], y_all[tr_idx])
        w_ll = optimize_logloss_stacking(P_oof[tr_idx], y_all[tr_idx])

        oof_nested_caruana[val_idx] = P_oof[val_idx] @ w_car
        oof_nested_coord[val_idx] = P_oof[val_idx] @ w_crd
        oof_nested_logloss[val_idx] = P_oof[val_idx] @ w_ll

    w_car_full, car_history = caruana_forward_stepwise_selection(P_oof, y_all, n_iterations=100)
    w_crd_full = coordinate_ascent_simplex(P_oof, y_all)
    w_ll_full = optimize_logloss_stacking(P_oof, y_all)

    w_arbitrary = np.array([0.125, 0.125, 0.0, 0.25, 0.30, 0.20])
    w_uniform = np.ones(len(MODEL_NAMES)) / len(MODEL_NAMES)

    print("\n--- Learned Weights on Full 2024-2025 OOF Matrix ---", flush=True)
    print("  Arbitrary Hand-Picked :", {MODEL_NAMES[i]: round(float(w_arbitrary[i]), 3) for i in range(6)})
    print("  Caruana Stepwise (100):", {MODEL_NAMES[i]: round(float(w_car_full[i]), 3) for i in range(6)})
    print("  Simplex Coord Ascent  :", {MODEL_NAMES[i]: round(float(w_crd_full[i]), 3) for i in range(6)})
    print("  Convex LogLoss Stack  :", {MODEL_NAMES[i]: round(float(w_ll_full[i]), 3) for i in range(6)}, flush=True)

    cv_schemes = {
        "Arbitrary Hand-Picked (0.25 LR, 0.25 LGBM, 0.30 CB, 0.20 LM)": P_oof @ w_arbitrary,
        "Equal Uniform Weights (1/6 each across all 6 models)": P_oof @ w_uniform,
        "Nested Iterative: Convex Log-Loss Stacking (SLSQP)": oof_nested_logloss,
        "Nested Iterative: Simplex Coordinate Ascent": oof_nested_coord,
        "Nested Iterative: Caruana Forward Stepwise Selection": oof_nested_caruana,
    }
    print("\n--- 5-Fold Stratified CV Comparison (Strictly Out-of-Fold) ---", flush=True)
    cv_summary = {}
    for name, s in cv_schemes.items():
        m = compute_all_metrics(y_all, s)
        cv_summary[name] = m
        print(
            f"  {name:60s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | H@100={m['hits@100']:2d} | H@250={m['hits@250']:2d}",
            flush=True,
        )

    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values
    df_24 = df_train.iloc[np.where(is_24)[0]].reset_index(drop=True)
    df_25 = df_train.iloc[np.where(is_25)[0]].reset_index(drop=True)
    X_tf_24 = X_tr_strict_tfidf[is_24]
    X_tf_25 = X_tr_strict_tfidf[is_25]
    y_24 = df_24["target_kev"].values.astype(np.int32)
    y_25 = df_25["target_kev"].values.astype(np.int32)

    P_oof_24 = np.zeros((len(df_24), len(MODEL_NAMES)), dtype=np.float64)
    skf_24 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for tr_i, val_i in skf_24.split(df_24, y_24):
        p_d = fit_base_models_and_predict(
            df_24.iloc[tr_i],
            df_24.iloc[val_i],
            tier_cfg_temp,
            X_tf_24[tr_i],
            X_tf_24[val_i],
        )
        for j, m_name in enumerate(MODEL_NAMES):
            P_oof_24[val_i, j] = p_d[m_name]

    preds_25_dict = fit_base_models_and_predict(df_24, df_25, tier_cfg_temp, X_tf_24, X_tf_25)
    P_test_25 = np.column_stack([preds_25_dict[m] for m in MODEL_NAMES])

    w_car_24, _ = caruana_forward_stepwise_selection(P_oof_24, y_24, n_iterations=100)
    w_crd_24 = coordinate_ascent_simplex(P_oof_24, y_24)
    w_ll_24 = optimize_logloss_stacking(P_oof_24, y_24)

    P_oof_24_ranks = np.column_stack(
        [pd.Series(P_oof_24[:, j]).rank(pct=True).values for j in range(len(MODEL_NAMES))]
    )
    P_test_25_ranks = np.column_stack(
        [pd.Series(P_test_25[:, j]).rank(pct=True).values for j in range(len(MODEL_NAMES))]
    )
    w_car_rank_24, _ = caruana_forward_stepwise_selection(P_oof_24_ranks, y_24, n_iterations=100)
    w_oracle_25, _ = caruana_forward_stepwise_selection(P_test_25, y_25, n_iterations=100)

    print("\n--- Causal Weights Learned Strictly on 2024 OOF (Applied to 2025 Test) ---", flush=True)
    print("  2024 Caruana Stepwise (Prob) :", {MODEL_NAMES[i]: round(float(w_car_24[i]), 3) for i in range(6)})
    print("  2024 Caruana Stepwise (Rank) :", {MODEL_NAMES[i]: round(float(w_car_rank_24[i]), 3) for i in range(6)})
    print("  2024 Simplex Coord Ascent    :", {MODEL_NAMES[i]: round(float(w_crd_24[i]), 3) for i in range(6)})
    print("  2024 Convex LogLoss Stack    :", {MODEL_NAMES[i]: round(float(w_ll_24[i]), 3) for i in range(6)})
    print("  [Ref] 2025 Oracle Stepwise   :", {MODEL_NAMES[i]: round(float(w_oracle_25[i]), 3) for i in range(6)}, flush=True)

    ks = (25, 50, 100, 250)
    temp_schemes = {
        "Arbitrary Hand-Picked (0.25 LR, 0.25 LGBM, 0.30 CB, 0.20 LM)": P_test_25 @ w_arbitrary,
        "Equal Uniform Weights (1/6 each across all 6 models)": P_test_25 @ w_uniform,
        "Causal 2024 Iterative: Convex Log-Loss Stacking (SLSQP)": P_test_25 @ w_ll_24,
        "Causal 2024 Iterative: Simplex Coordinate Ascent": P_test_25 @ w_crd_24,
        "Causal 2024 Iterative: Caruana Forward Stepwise (Prob)": P_test_25 @ w_car_24,
        "Causal 2024 Iterative: Hybrid Prob + Rank Caruana": (
            0.5 * (P_test_25 @ w_car_24) / np.max(P_test_25 @ w_car_24)
            + 0.5 * (P_test_25_ranks @ w_car_rank_24)
        ),
        "[Oracle Upper Bound] 2025 In-Sample Caruana Stepwise": P_test_25 @ w_oracle_25,
    }

    print("\n--- Causal Temporal Split (2024 -> 2025) Comparison ---", flush=True)
    temp_summary = {}
    for name, s in temp_schemes.items():
        m = compute_all_metrics(y_25, s, ks=ks)
        temp_summary[name] = m
        print(
            f"  {name:60s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d}/55 | H@250={m['hits@250']:2d}/55",
            flush=True,
        )

    print(f"Completed {tier_name} weight optimization in {time.time() - t0:.1f}s", flush=True)
    return {
        "learned_weights_full_oof": {
            "arbitrary": {MODEL_NAMES[i]: round(float(w_arbitrary[i]), 4) for i in range(6)},
            "caruana_stepwise": {MODEL_NAMES[i]: round(float(w_car_full[i]), 4) for i in range(6)},
            "coordinate_ascent": {MODEL_NAMES[i]: round(float(w_crd_full[i]), 4) for i in range(6)},
            "logloss_stacking": {MODEL_NAMES[i]: round(float(w_ll_full[i]), 4) for i in range(6)},
        },
        "learned_weights_causal_2024": {
            "caruana_stepwise_prob": {MODEL_NAMES[i]: round(float(w_car_24[i]), 4) for i in range(6)},
            "caruana_stepwise_rank": {MODEL_NAMES[i]: round(float(w_car_rank_24[i]), 4) for i in range(6)},
            "coordinate_ascent": {MODEL_NAMES[i]: round(float(w_crd_24[i]), 4) for i in range(6)},
            "logloss_stacking": {MODEL_NAMES[i]: round(float(w_ll_24[i]), 4) for i in range(6)},
            "oracle_2025_reference": {MODEL_NAMES[i]: round(float(w_oracle_25[i]), 4) for i in range(6)},
        },
        "caruana_iteration_history": car_history,
        "cv_5fold_comparison": cv_summary,
        "temporal_2024_to_2025_comparison": temp_summary,
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
        results[t_name] = run_tier_optimization(
            df_train, t_name, tiers_cv[t_name], tiers_temp[t_name], X_tr_strict_tfidf
        )

    out_path = os.path.join(FEAT_DIR, "ensemble_weight_optimization.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved iterative weight optimization results to {out_path} in {time.time() - t_start:.1f}s", flush=True)


if __name__ == "__main__":
    main()
