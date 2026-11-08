#!/usr/bin/env python3
"""
Train and Evaluate Logistic Regression vs. Random Forest on the Vulnerability
Exploitation (KEV) Feature Matrix.

Evaluates both models under two validation protocols:
  1. 5-Fold Stratified Cross-Validation (using 5-fold out-of-fold TF-IDF text
     features `txt_oof_tfidf_prob`).
  2. Strictly Causal Temporal Split: Train on 2024 publications (39,868 CVEs, 67
     post-snapshot KEVs) -> Validate on 2025 publications (42,562 CVEs, 55
     post-snapshot KEVs), using strictly causal `txt_temp_tfidf_prob`.

Also compares three feature regimes:
  - Tier 0 (Signal-Only): 18 point-in-time EPSS & exploit flags (`sig_*`).
  - Tier 1 (Clean / Inference-Safe): All 103 point-in-time safe & grey features
    (`sig_*`, `time_*`, `cna_*`, `txt_*`, `cvss_*`, `cwe_*`, `ref_*` excluding
    `leak_*` and post-attack `ref_url_sec_news` / `ref_count_log`).
  - Tier 2 (All Features + `leak_*`): Adds the 22 post-publication NIST triage
    and Nov 2026 snapshot features (`leak_*`) to quantify the exact magnitude
    of target leakage.
"""

import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

FEAT_DIR = os.environ.get("CVE_OUT_DIR", "/tmp/features")
RESULTS_PATH = os.path.join(FEAT_DIR, "eval_results.json")


def precision_recall_at_k(y_true: np.ndarray, y_score: np.ndarray, k: int):
    order = np.argsort(-y_score)
    top_k = y_true[order[:k]]
    hits = int(np.sum(top_k))
    prec = hits / float(k)
    rec = hits / float(max(np.sum(y_true), 1))
    return hits, prec, rec


def max_f1_score(y_true: np.ndarray, y_score: np.ndarray):
    prec, rec, thresh = precision_recall_curve(y_true, y_score)
    denom = prec + rec
    f1s = np.where(denom > 0, 2 * prec * rec / denom, 0.0)
    best_idx = int(np.argmax(f1s))
    best_th = float(thresh[min(best_idx, len(thresh) - 1)]) if len(thresh) > 0 else 0.5
    return float(f1s[best_idx]), float(prec[best_idx]), float(rec[best_idx]), best_th


def compute_all_metrics(y_true: np.ndarray, y_score: np.ndarray, ks=(50, 100, 250, 500)):
    roc_auc = float(roc_auc_score(y_true, y_score))
    pr_auc = float(average_precision_score(y_true, y_score))
    brier = float(brier_score_loss(y_true, y_score))
    best_f1, f1_p, f1_r, best_th = max_f1_score(y_true, y_score)

    res = {
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier": round(brier, 5),
        "max_f1": round(best_f1, 4),
        "f1_precision": round(f1_p, 4),
        "f1_recall": round(f1_r, 4),
        "best_threshold": round(best_th, 4),
    }
    for k in ks:
        hits, p_k, r_k = precision_recall_at_k(y_true, y_score, k)
        res[f"hits@{k}"] = hits
        res[f"prec@{k}"] = round(p_k, 4)
        res[f"rec@{k}"] = round(r_k, 4)
    return res


def get_feature_sets(df: pd.DataFrame):
    meta_cols = {"cve_id", "published", "snapshot_month", "target_kev", "txt_temp_tfidf_prob"}
    all_feat_cols = [c for c in df.columns if c not in meta_cols]

    leaky_cols = {
        c
        for c in all_feat_cols
        if c.startswith("leak_") or c in ("ref_url_sec_news", "ref_count_log", "ref_uniq_domains")
    }
    clean_cols_cv = [c for c in all_feat_cols if c not in leaky_cols]
    clean_cols_temp = [
        ("txt_temp_tfidf_prob" if c == "txt_oof_tfidf_prob" else c) for c in clean_cols_cv
    ]

    sig_cols = [c for c in all_feat_cols if c.startswith("sig_")]

    return {
        "sig_only": sig_cols,
        "clean_103": clean_cols_cv,
        "clean_103_temporal": clean_cols_temp,
        "all_with_leaky_125": all_feat_cols,
    }


def make_logreg(class_weight="balanced", C=0.1):
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    C=C,
                    penalty="l2",
                    class_weight=class_weight,
                    max_iter=500,
                    random_state=42,
                ),
            ),
        ]
    )


def make_rf(class_weight="balanced_subsample", n_estimators=400, max_depth=12, min_samples_leaf=10):
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        max_features="sqrt",
        class_weight=class_weight,
        n_jobs=-1,
        random_state=42,
    )


def evaluate_5fold_cv(df: pd.DataFrame, feat_cols: list, label: str):
    X = df[feat_cols].values.astype(np.float64)
    y = df["target_kev"].values.astype(np.int32)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    oof_lr_bal = np.zeros(len(df), dtype=np.float64)
    oof_lr_unw = np.zeros(len(df), dtype=np.float64)
    oof_rf_bal = np.zeros(len(df), dtype=np.float64)
    oof_rf_unw = np.zeros(len(df), dtype=np.float64)

    for tr_idx, val_idx in skf.split(X, y):
        X_tr, y_tr = X[tr_idx], y[tr_idx]
        X_val = X[val_idx]

        lr_bal = make_logreg(class_weight="balanced", C=0.05)
        lr_bal.fit(X_tr, y_tr)
        oof_lr_bal[val_idx] = lr_bal.predict_proba(X_val)[:, 1]

        lr_unw = make_logreg(class_weight=None, C=0.1)
        lr_unw.fit(X_tr, y_tr)
        oof_lr_unw[val_idx] = lr_unw.predict_proba(X_val)[:, 1]

        rf_bal = make_rf(class_weight="balanced_subsample", n_estimators=300, max_depth=10, min_samples_leaf=15)
        rf_bal.fit(X_tr, y_tr)
        oof_rf_bal[val_idx] = rf_bal.predict_proba(X_val)[:, 1]

        rf_unw = make_rf(class_weight=None, n_estimators=300, max_depth=12, min_samples_leaf=5)
        rf_unw.fit(X_tr, y_tr)
        oof_rf_unw[val_idx] = rf_unw.predict_proba(X_val)[:, 1]

    oof_ens = 0.5 * oof_lr_unw + 0.5 * oof_rf_unw

    results = {
        "LogReg (Balanced)": compute_all_metrics(y, oof_lr_bal),
        "LogReg (Unweighted L2)": compute_all_metrics(y, oof_lr_unw),
        "RandomForest (Balanced)": compute_all_metrics(y, oof_rf_bal),
        "RandomForest (Unweighted)": compute_all_metrics(y, oof_rf_unw),
        "Ensemble (LogReg + RF)": compute_all_metrics(y, oof_ens),
    }
    return results, oof_lr_unw, oof_rf_unw, oof_rf_bal


def evaluate_temporal_split(df: pd.DataFrame, feat_cols: list):
    is_2024 = df["published"].str.startswith("2024").values
    is_2025 = df["published"].str.startswith("2025").values

    X_tr = df.loc[is_2024, feat_cols].values.astype(np.float64)
    y_tr = df.loc[is_2024, "target_kev"].values.astype(np.int32)
    X_val = df.loc[is_2025, feat_cols].values.astype(np.int32 if False else np.float64)
    y_val = df.loc[is_2025, "target_kev"].values.astype(np.int32)

    epss_val = df.loc[is_2025, "sig_epss_raw"].values.astype(np.float64)

    lr_bal = make_logreg(class_weight="balanced", C=0.05)
    lr_bal.fit(X_tr, y_tr)
    p_lr_bal = lr_bal.predict_proba(X_val)[:, 1]

    lr_unw = make_logreg(class_weight=None, C=0.1)
    lr_unw.fit(X_tr, y_tr)
    p_lr_unw = lr_unw.predict_proba(X_val)[:, 1]

    rf_bal = make_rf(class_weight="balanced_subsample", n_estimators=400, max_depth=10, min_samples_leaf=15)
    rf_bal.fit(X_tr, y_tr)
    p_rf_bal = rf_bal.predict_proba(X_val)[:, 1]

    rf_unw = make_rf(class_weight=None, n_estimators=400, max_depth=12, min_samples_leaf=5)
    rf_unw.fit(X_tr, y_tr)
    p_rf_unw = rf_unw.predict_proba(X_val)[:, 1]

    p_ens = 0.5 * p_lr_unw + 0.5 * p_rf_unw

    ks = (25, 50, 100, 250)
    return {
        "n_train_2024": int(len(y_tr)),
        "pos_train_2024": int(np.sum(y_tr)),
        "n_val_2025": int(len(y_val)),
        "pos_val_2025": int(np.sum(y_val)),
        "metrics": {
            "Raw EPSS Baseline": compute_all_metrics(y_val, epss_val, ks=ks),
            "LogReg (Balanced)": compute_all_metrics(y_val, p_lr_bal, ks=ks),
            "LogReg (Unweighted L2)": compute_all_metrics(y_val, p_lr_unw, ks=ks),
            "RandomForest (Balanced)": compute_all_metrics(y_val, p_rf_bal, ks=ks),
            "RandomForest (Unweighted)": compute_all_metrics(y_val, p_rf_unw, ks=ks),
            "Ensemble (LogReg + RF)": compute_all_metrics(y_val, p_ens, ks=ks),
        },
    }


def extract_feature_importances_and_2026_preds(df_train: pd.DataFrame, df_2026: pd.DataFrame, feat_cols: list):
    X_tr = df_train[feat_cols].values.astype(np.float64)
    y_tr = df_train["target_kev"].values.astype(np.int32)
    X_26 = df_2026[feat_cols].values.astype(np.float64)

    lr = make_logreg(class_weight=None, C=0.1)
    lr.fit(X_tr, y_tr)
    lr_coefs = lr.named_steps["clf"].coef_[0]

    rf = make_rf(class_weight="balanced_subsample", n_estimators=400, max_depth=10, min_samples_leaf=15)
    rf.fit(X_tr, y_tr)
    rf_imps = rf.feature_importances_

    rf_unw = make_rf(class_weight=None, n_estimators=400, max_depth=12, min_samples_leaf=5)
    rf_unw.fit(X_tr, y_tr)
    rf_unw_imps = rf_unw.feature_importances_

    p26_lr = lr.predict_proba(X_26)[:, 1]
    p26_rf = rf_unw.predict_proba(X_26)[:, 1]
    p26_rf_bal = rf.predict_proba(X_26)[:, 1]
    p26_ens = 0.5 * p26_lr + 0.5 * p26_rf

    df_preds = pd.DataFrame(
        {
            "cve_id": df_2026["cve_id"],
            "published": df_2026["published"],
            "snapshot_month": df_2026["snapshot_month"],
            "epss": df_2026["sig_epss_raw"],
            "any_exploit_flag": df_2026["sig_any_flag"],
            "prob_logreg": np.round(p26_lr, 6),
            "prob_rf_unweighted": np.round(p26_rf, 6),
            "prob_rf_balanced": np.round(p26_rf_bal, 6),
            "prob_ensemble": np.round(p26_ens, 6),
        }
    )
    df_preds.sort_values("prob_ensemble", ascending=False, inplace=True)
    preds_path = os.path.join(FEAT_DIR, "predictions_scoreboard_2026.csv")
    df_preds.to_csv(preds_path, index=False)

    top_lr_pos = sorted(
        zip(feat_cols, lr_coefs), key=lambda x: x[1], reverse=True
    )[:15]
    top_lr_neg = sorted(zip(feat_cols, lr_coefs), key=lambda x: x[1])[:10]
    top_rf_bal = sorted(
        zip(feat_cols, rf_imps), key=lambda x: x[1], reverse=True
    )[:15]
    top_rf_unw = sorted(
        zip(feat_cols, rf_unw_imps), key=lambda x: x[1], reverse=True
    )[:15]

    return {
        "top_logreg_positive_coefs": [(k, round(float(v), 4)) for k, v in top_lr_pos],
        "top_logreg_negative_coefs": [(k, round(float(v), 4)) for k, v in top_lr_neg],
        "top_rf_balanced_importances": [(k, round(float(v), 4)) for k, v in top_rf_bal],
        "top_rf_unweighted_importances": [(k, round(float(v), 4)) for k, v in top_rf_unw],
        "top_15_scoreboard_2026_predictions": df_preds.head(15).to_dict(orient="records"),
    }


def main():
    t0 = time.time()
    train_path = os.path.join(FEAT_DIR, "features_train_2024_2025.csv")
    test_path = os.path.join(FEAT_DIR, "features_scoreboard_2026.csv")
    print("Loading engineered feature matrices...")
    df_train = pd.read_csv(train_path)
    df_2026 = pd.read_csv(test_path)

    feat_sets = get_feature_sets(df_train)
    for k, v in feat_sets.items():
        print(f"  Feature set '{k}': {len(v)} features")

    y_all = df_train["target_kev"].values.astype(np.int32)
    epss_baseline_metrics = compute_all_metrics(
        y_all, df_train["sig_epss_raw"].values.astype(np.float64)
    )

    print("\n=== 1. 5-Fold Stratified CV: Clean Features (103 features) ===")
    cv_clean, oof_lr_clean, oof_rf_clean, oof_rf_bal_clean = evaluate_5fold_cv(
        df_train, feat_sets["clean_103"], "clean_103"
    )
    cv_clean["Raw EPSS Baseline"] = epss_baseline_metrics
    for model_name, m in cv_clean.items():
        print(
            f"  {model_name:28s} | ROC-AUC: {m['roc_auc']:.4f} | PR-AUC: {m['pr_auc']:.4f} | "
            f"Max-F1: {m['max_f1']:.4f} | Hits@100: {m['hits@100']:2d}/122 ({m['rec@100']*100:4.1f}%) | "
            f"Hits@250: {m['hits@250']:2d}/122 ({m['rec@250']*100:4.1f}%)"
        )

    print("\n=== 2. 5-Fold Stratified CV: Signal-Only Features (18 features) ===")
    cv_sig, _, _, _ = evaluate_5fold_cv(df_train, feat_sets["sig_only"], "sig_only")
    for model_name, m in cv_sig.items():
        print(
            f"  {model_name:28s} | ROC-AUC: {m['roc_auc']:.4f} | PR-AUC: {m['pr_auc']:.4f} | "
            f"Max-F1: {m['max_f1']:.4f} | Hits@100: {m['hits@100']:2d}/122 | Hits@250: {m['hits@250']:2d}/122"
        )

    print("\n=== 3. 5-Fold Stratified CV: All Features Including Leaky NIST Triage (125 features) ===")
    cv_leaky, _, _, _ = evaluate_5fold_cv(
        df_train, feat_sets["all_with_leaky_125"], "all_with_leaky_125"
    )
    for model_name, m in cv_leaky.items():
        print(
            f"  {model_name:28s} | ROC-AUC: {m['roc_auc']:.4f} | PR-AUC: {m['pr_auc']:.4f} | "
            f"Max-F1: {m['max_f1']:.4f} | Hits@100: {m['hits@100']:2d}/122 | Hits@250: {m['hits@250']:2d}/122"
        )

    print("\n=== 4. Strictly Causal Temporal Split (Train 2024 -> Test 2025): Clean Features (103 features) ===")
    temp_clean = evaluate_temporal_split(df_train, feat_sets["clean_103_temporal"])
    print(
        f"  Train 2024: {temp_clean['n_train_2024']:,} CVEs ({temp_clean['pos_train_2024']} KEVs) -> "
        f"Test 2025: {temp_clean['n_val_2025']:,} CVEs ({temp_clean['pos_val_2025']} KEVs)"
    )
    for model_name, m in temp_clean["metrics"].items():
        print(
            f"  {model_name:28s} | ROC-AUC: {m['roc_auc']:.4f} | PR-AUC: {m['pr_auc']:.4f} | "
            f"Max-F1: {m['max_f1']:.4f} | Hits@50: {m['hits@50']:2d}/55 | "
            f"Hits@100: {m['hits@100']:2d}/55 ({m['rec@100']*100:4.1f}%) | "
            f"Hits@250: {m['hits@250']:2d}/55 ({m['rec@250']*100:4.1f}%)"
        )

    print("\n=== 5. Extracting Feature Importances & Scoring 2026 Scoreboard ===")
    fi_and_preds = extract_feature_importances_and_2026_preds(
        df_train, df_2026, feat_sets["clean_103"]
    )
    print("  Top 10 Logistic Regression Positive Standardized Coefficients:")
    for k, v in fi_and_preds["top_logreg_positive_coefs"][:10]:
        print(f"    {k:32s}: {v:+.4f}")
    print("  Top 8 Logistic Regression Negative Standardized Coefficients:")
    for k, v in fi_and_preds["top_logreg_negative_coefs"][:8]:
        print(f"    {k:32s}: {v:+.4f}")
    print("  Top 10 Random Forest (Balanced) Feature Importances:")
    for k, v in fi_and_preds["top_rf_balanced_importances"][:10]:
        print(f"    {k:32s}: {v:.4f}")
    print("  Top 10 Random Forest (Unweighted) Feature Importances:")
    for k, v in fi_and_preds["top_rf_unweighted_importances"][:10]:
        print(f"    {k:32s}: {v:.4f}")

    summary = {
        "n_train_rows": int(len(df_train)),
        "n_train_positives": int(np.sum(y_all)),
        "n_scoreboard_2026_rows": int(len(df_2026)),
        "feature_counts": {k: len(v) for k, v in feat_sets.items()},
        "cv_5fold_clean_103": cv_clean,
        "cv_5fold_sig_only_18": cv_sig,
        "cv_5fold_leaky_125": cv_leaky,
        "temporal_2024_to_2025_clean_103": temp_clean,
        "feature_importances_and_2026": fi_and_preds,
    }
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved full evaluation report to {RESULTS_PATH} in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
