#!/usr/bin/env python3
"""
Benchmark LightGBM, CatBoost (Ordered Target Statistics), and XGBoost LambdaMART
against Random Forest and Logistic Regression + TF-IDF across Three Metadata
Contamination Tiers.

Explicitly addresses the NIST Current-Snapshot Metadata Problem:
  - Tier A (`Pub-Time Strict`, 47 features + Pure Assigner/Description TF-IDF):
      Uses ONLY features confirmed to be immutable/present at publication time:
      point-in-time exploit signals (`sig_*`), publication dates & CVE ID mechanics
      (`time_*`), `assigner` (`cna_*` + raw categorical `assigner`), and raw English
      `description` (`txt_*` + TF-IDF on `assigner` + `description` ONLY).
      Excludes CWEs, CVSS, References, and CPEs.
  - Tier B (`Expanded Metadata / Grey-Zone`, 103 features + TF-IDF):
      Adds `cwe_*`, `cvss_*`, and `ref_*` (which are supplied by CNAs for many CVEs
      at publication, but are missing on 57%-86% of `Received` CVEs and can be
      overwritten or enriched by NIST/CISA after exploitation).
  - Tier C (`Leaky Full NVD Snapshot`, 125 features + CPE Vendor/Status):
      Adds `leak_*` (`nvd_status`, `affected_products.csv` vendor/CPEs, `references.tags`,
      `cvss3_source='nvd@nist.gov'`, `last_modified`), proving empirically that
      CatBoost's Ordered Boosting (`boosting_type='Ordered'`) cannot prevent
      retroactive snapshot leakage when the feature value itself was added post-attack.
"""

import csv
import json
import os
import re
import time
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier, Pool
from lightgbm import LGBMClassifier
from scipy.sparse import csr_matrix, hstack, vstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    ndcg_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRanker

DATA_DIR = os.environ.get("CVE_DATA_DIR", "/tmp/data")
FEAT_DIR = os.environ.get("CVE_OUT_DIR", "/tmp/features")


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
    f1s = np.where(denom > 0, 2 * prec * rec / np.where(denom > 0, denom, 1.0), 0.0)
    best_idx = int(np.argmax(f1s))
    best_th = float(thresh[min(best_idx, len(thresh) - 1)]) if len(thresh) > 0 else 0.5
    return float(f1s[best_idx]), float(prec[best_idx]), float(rec[best_idx]), best_th


def rank_normalize(scores: np.ndarray) -> np.ndarray:
    """Map arbitrary model scores (e.g. LambdaMART margins) to [0, 1] via rank percentile."""
    order = np.argsort(scores)
    ranks = np.empty_like(order, dtype=np.float64)
    ranks[order] = np.arange(len(scores), dtype=np.float64)
    return ranks / max(len(scores) - 1, 1)


def sigmoid_calibrate(scores: np.ndarray, y_true_train: np.ndarray, scores_train: np.ndarray) -> np.ndarray:
    """Fit 1D Platt scaling on training margins to map LambdaMART scores to calibrated probabilities."""
    s_tr = scores_train.reshape(-1, 1)
    s_te = scores.reshape(-1, 1)
    sc = StandardScaler()
    s_tr_std = sc.fit_transform(s_tr)
    s_te_std = sc.transform(s_te)
    lr = LogisticRegression(C=1.0, random_state=42)
    lr.fit(s_tr_std, y_true_train)
    return lr.predict_proba(s_te_std)[:, 1]


def compute_all_metrics(y_true: np.ndarray, y_score: np.ndarray, ks=(50, 100, 250, 500)):
    roc_auc = float(roc_auc_score(y_true, y_score))
    pr_auc = float(average_precision_score(y_true, y_score))
    ndcg100 = float(ndcg_score([y_true], [y_score], k=100))
    ndcg250 = float(ndcg_score([y_true], [y_score], k=250))
    best_f1, f1_p, f1_r, best_th = max_f1_score(y_true, y_score)

    res = {
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "ndcg@100": round(ndcg100, 4),
        "ndcg@250": round(ndcg250, 4),
        "max_f1": round(best_f1, 4),
        "f1_precision": round(f1_p, 4),
        "f1_recall": round(f1_r, 4),
    }
    for k in ks:
        hits, p_k, r_k = precision_recall_at_k(y_true, y_score, k)
        res[f"hits@{k}"] = hits
        res[f"prec@{k}"] = round(p_k, 4)
        res[f"rec@{k}"] = round(r_k, 4)
    return res


def audit_metadata_availability():
    """Quantify historical validity & availability limitations across NVD statuses."""
    stats = defaultdict(Counter)
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["published"] >= "2024-01-01":
                st = r["nvd_status"]
                c = stats[st]
                c["total"] += 1
                if r["assigner"]:
                    c["assigner"] += 1
                if r["description"]:
                    c["description"] += 1
                if r["cwe_ids"] and not r["cwe_ids"].startswith("NVD-"):
                    c["cwe_real"] += 1
                if r["cwe_ids"].startswith("NVD-"):
                    c["cwe_nvd_placeholder"] += 1
                if r["cvss3_score"]:
                    if r["cvss3_source"] == "nvd@nist.gov":
                        c["cvss3_nist"] += 1
                    elif r["cvss3_source"] == "134c704f-9b21-4f2e-91b3-4a467353bcc0":
                        c["cvss3_cisa"] += 1
                    else:
                        c["cvss3_cna"] += 1
                if r["cvss4_score"]:
                    c["cvss4"] += 1
                if int(r["n_affected_cpes"] or 0) > 0:
                    c["has_cpes"] += 1

    out = {}
    for st in ("Received", "Awaiting Analysis", "Undergoing Analysis", "Deferred", "Analyzed", "Modified"):
        c = stats[st]
        tot = max(c["total"], 1)
        out[st] = {
            "total": c["total"],
            "assigner_pct": round(c["assigner"] / tot * 100, 1),
            "description_pct": round(c["description"] / tot * 100, 1),
            "cwe_real_pct": round(c["cwe_real"] / tot * 100, 1),
            "cwe_nvd_pct": round(c["cwe_nvd_placeholder"] / tot * 100, 1),
            "cvss3_cna_pct": round(c["cvss3_cna"] / tot * 100, 1),
            "cvss3_cisa_pct": round(c["cvss3_cisa"] / tot * 100, 1),
            "cvss3_nist_pct": round(c["cvss3_nist"] / tot * 100, 1),
            "cvss4_pct": round(c["cvss4"] / tot * 100, 1),
            "has_cpes_pct": round(c["has_cpes"] / tot * 100, 1),
        }
    return out


def prepare_strict_and_expanded_data(df_train: pd.DataFrame, df_2026: pd.DataFrame):
    t0 = time.time()
    print("[1/4] Preparing raw categorical columns & strictly publication-time TF-IDF...")

    vulns = {}
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            vulns[r["cve_id"]] = r

    kev_dict = {}
    with open(os.path.join(DATA_DIR, "known_exploited.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            kev_dict[r["cve_id"]] = r["date_added"]

    # Map primary CPE vendor per CVE (for Tier C leaky categorical test)
    cpe_primary_vendor = {}
    with open(os.path.join(DATA_DIR, "affected_products.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["cve_id"]
            if cid not in cpe_primary_vendor and r["vulnerable"] == "Y":
                cpe_primary_vendor[cid] = r["vendor"]

    # Build strictly publication-time text documents: ONLY assigner + description (NO CWE, NO domain)
    def make_strict_doc(cid):
        v = vulns[cid]
        ass_tok = re.sub(r"[^a-zA-Z0-9]+", "_", v["assigner"].lower())
        return f"asstok_{ass_tok} {v['description']}"

    pre24_docs, pre24_y = [], []
    for cid, v in vulns.items():
        if "2018-01-01" <= v["published"] < "2024-01-01":
            is_k = 1 if (cid in kev_dict and kev_dict[cid] < "2024-01-01") else 0
            if is_k or (hash(cid) % 8 == 0):
                pre24_docs.append(make_strict_doc(cid))
                pre24_y.append(is_k)
    pre24_y = np.array(pre24_y, dtype=np.int32)

    train_strict_docs = [make_strict_doc(cid) for cid in df_train["cve_id"]]
    vec_strict = TfidfVectorizer(
        max_features=35000,
        ngram_range=(1, 2),
        min_df=4,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    X_all_strict_tfidf = vec_strict.fit_transform(pre24_docs + train_strict_docs)
    n_pre = len(pre24_docs)
    X_pre_strict_tfidf = X_all_strict_tfidf[:n_pre]
    X_tr_strict_tfidf = X_all_strict_tfidf[n_pre:]

    y = df_train["target_kev"].values.astype(np.int32)
    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values

    # Compute strict OOF TF-IDF prob (5-fold CV) and strict causal TF-IDF prob (2024->2025)
    oof_strict_tfidf = np.zeros(len(df_train), dtype=np.float64)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for tr_idx, val_idx in skf.split(X_tr_strict_tfidf, y):
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42)
        clf.fit(
            vstack([X_pre_strict_tfidf, X_tr_strict_tfidf[tr_idx]]),
            np.concatenate([pre24_y, y[tr_idx]]),
        )
        oof_strict_tfidf[val_idx] = clf.predict_proba(X_tr_strict_tfidf[val_idx])[:, 1]

    temp_strict_tfidf = np.zeros(len(df_train), dtype=np.float64)
    clf_pre24 = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42)
    clf_pre24.fit(X_pre_strict_tfidf, pre24_y)
    temp_strict_tfidf[is_24] = clf_pre24.predict_proba(X_tr_strict_tfidf[is_24])[:, 1]

    clf_pre25 = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42)
    clf_pre25.fit(
        vstack([X_pre_strict_tfidf, X_tr_strict_tfidf[is_24]]),
        np.concatenate([pre24_y, y[is_24]]),
    )
    temp_strict_tfidf[is_25] = clf_pre25.predict_proba(X_tr_strict_tfidf[is_25])[:, 1]

    df_train = df_train.copy()
    df_train["txt_strict_oof_tfidf_prob"] = oof_strict_tfidf
    df_train["txt_strict_temp_tfidf_prob"] = temp_strict_tfidf

    # Add raw categorical columns for CatBoost / LightGBM
    df_train["cat_assigner"] = [vulns[cid]["assigner"] or "MISSING" for cid in df_train["cve_id"]]
    df_train["cat_cwe_primary"] = [
        (vulns[cid]["cwe_ids"].split(";")[0] if vulns[cid]["cwe_ids"] else "MISSING")
        for cid in df_train["cve_id"]
    ]
    df_train["cat_cpe_vendor"] = [
        cpe_primary_vendor.get(cid, "MISSING") for cid in df_train["cve_id"]
    ]
    df_train["cat_nvd_status"] = [vulns[cid]["nvd_status"] for cid in df_train["cve_id"]]

    # Integer-encode categoricals for LightGBM / XGBoost
    for col in ("cat_assigner", "cat_cwe_primary", "cat_cpe_vendor", "cat_nvd_status"):
        df_train[col + "_code"] = df_train[col].astype("category").cat.codes.astype(np.int32)

    print(f"      Prepared strict & expanded datasets in {time.time() - t0:.1f}s")
    return df_train, X_pre_strict_tfidf, X_tr_strict_tfidf, pre24_y


def get_tier_columns(df: pd.DataFrame, temporal: bool = False):
    """Return numeric feature lists and categorical column names for Tiers A, B, and C."""
    sig_cols = [c for c in df.columns if c.startswith("sig_")]
    time_cols = [c for c in df.columns if c.startswith("time_")]
    cna_cols = [c for c in df.columns if c.startswith("cna_")]
    txt_base_cols = [
        c
        for c in df.columns
        if c.startswith("txt_")
        and c
        not in (
            "txt_oof_tfidf_prob",
            "txt_temp_tfidf_prob",
            "txt_strict_oof_tfidf_prob",
            "txt_strict_temp_tfidf_prob",
        )
    ]
    cvss_cols = [c for c in df.columns if c.startswith("cvss_")]
    cwe_cols = [c for c in df.columns if c.startswith("cwe_")]
    ref_clean_cols = [
        c
        for c in df.columns
        if c.startswith("ref_") and c not in ("ref_url_sec_news", "ref_count_log", "ref_uniq_domains")
    ]
    leak_cols = [
        c
        for c in df.columns
        if c.startswith("leak_") or c in ("ref_url_sec_news", "ref_count_log", "ref_uniq_domains")
    ]

    strict_tf_col = "txt_strict_temp_tfidf_prob" if temporal else "txt_strict_oof_tfidf_prob"
    exp_tf_col = "txt_temp_tfidf_prob" if temporal else "txt_oof_tfidf_prob"

    tier_a_num = sig_cols + time_cols + cna_cols + txt_base_cols + [strict_tf_col]
    tier_b_num = sig_cols + time_cols + cna_cols + txt_base_cols + [exp_tf_col] + cvss_cols + cwe_cols + ref_clean_cols
    tier_c_num = tier_b_num + leak_cols

    return {
        "Tier A (Pub-Time Strict)": {
            "num_cols": tier_a_num,
            "num_no_tf": sig_cols + time_cols + cna_cols + txt_base_cols,
            "cat_str_cols": ["cat_assigner"],
            "cat_code_cols": ["cat_assigner_code"],
        },
        "Tier B (Expanded Metadata / Grey-Zone)": {
            "num_cols": tier_b_num,
            "num_no_tf": sig_cols + time_cols + cna_cols + txt_base_cols + cvss_cols + cwe_cols + ref_clean_cols,
            "cat_str_cols": ["cat_assigner", "cat_cwe_primary"],
            "cat_code_cols": ["cat_assigner_code", "cat_cwe_primary_code"],
        },
        "Tier C (Leaky Full NVD Snapshot)": {
            "num_cols": tier_c_num,
            "num_no_tf": sig_cols + time_cols + cna_cols + txt_base_cols + cvss_cols + cwe_cols + ref_clean_cols + leak_cols,
            "cat_str_cols": ["cat_assigner", "cat_cwe_primary", "cat_cpe_vendor", "cat_nvd_status"],
            "cat_code_cols": [
                "cat_assigner_code",
                "cat_cwe_primary_code",
                "cat_cpe_vendor_code",
                "cat_nvd_status_code",
            ],
        },
    }


def fit_predict_all_models_on_fold(
    df_tr: pd.DataFrame,
    df_val: pd.DataFrame,
    tier_cfg: dict,
    X_tfidf_tr,
    X_tfidf_val,
):
    y_tr = df_tr["target_kev"].values.astype(np.int32)
    num_cols = tier_cfg["num_cols"]
    num_no_tf = tier_cfg["num_no_tf"]
    cat_str_cols = tier_cfg["cat_str_cols"]
    cat_code_cols = tier_cfg["cat_code_cols"]

    X_num_tr = df_tr[num_cols].values.astype(np.float64)
    X_num_val = df_val[num_cols].values.astype(np.float64)

    # 1. Logistic Regression (Stacked L2 + Joint Sparse TF-IDF)
    sc = StandardScaler()
    X_tr_std = sc.fit_transform(X_num_tr)
    X_val_std = sc.transform(X_num_val)
    lr_stack = LogisticRegression(C=0.1, max_iter=500, random_state=42)
    lr_stack.fit(X_tr_std, y_tr)
    p_lr_stack = lr_stack.predict_proba(X_val_std)[:, 1]

    sc_notf = StandardScaler()
    X_notf_tr_std = sc_notf.fit_transform(df_tr[num_no_tf].values.astype(np.float64))
    X_notf_val_std = sc_notf.transform(df_val[num_no_tf].values.astype(np.float64))
    Xj_tr = hstack([csr_matrix(X_notf_tr_std * 0.25), X_tfidf_tr], format="csr")
    Xj_val = hstack([csr_matrix(X_notf_val_std * 0.25), X_tfidf_val], format="csr")
    lr_joint = LogisticRegression(C=0.5, max_iter=500, random_state=42)
    lr_joint.fit(Xj_tr, y_tr)
    p_lr_joint = lr_joint.predict_proba(Xj_val)[:, 1]

    p_lr_tfidf = 0.5 * p_lr_stack + 0.5 * p_lr_joint

    # 2. Random Forest (Unweighted)
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

    # 3. LightGBM (with native categorical handling)
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

    # 4. CatBoost (Ordered Boosting with native categorical strings)
    cb_cols = num_cols + cat_str_cols
    X_cb_tr = df_tr[cb_cols]
    X_cb_val = df_val[cb_cols]
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
    cb.fit(X_cb_tr, y_tr)
    p_cb = cb.predict_proba(X_cb_val)[:, 1]

    # 5. XGBoost LambdaMART (`rank:ndcg` grouped by `snapshot_month`)
    # XGBRanker requires training rows to be sorted by `qid` (snapshot_month)
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
        "1. LogReg + TF-IDF (Linear Baseline)": p_lr_tfidf,
        "2. Random Forest (Standalone)": p_rf,
        "3. LightGBM (Standalone)": p_lgbm,
        "4. CatBoost Ordered (Standalone)": p_cb,
        "5. XGBoost LambdaMART (Standalone)": p_lambdamart,
        "6. Ensemble: LogReg+TF-IDF + Random Forest": 0.50 * p_rf + 0.50 * p_lr_tfidf,
        "7. Ensemble: LogReg+TF-IDF + LightGBM": 0.50 * p_lgbm + 0.50 * p_lr_tfidf,
        "8. Ensemble: LogReg+TF-IDF + CatBoost": 0.50 * p_cb + 0.50 * p_lr_tfidf,
        "9. Ensemble: LogReg+TF-IDF + XGBoost LambdaMART": 0.50 * p_lambdamart + 0.50 * p_lr_tfidf,
        "10. Super-Ensemble (LightGBM + CatBoost + LambdaMART + TF-IDF LR)": (
            0.25 * p_lgbm + 0.30 * p_cb + 0.20 * p_lambdamart + 0.25 * p_lr_tfidf
        ),
    }


def evaluate_tier_5fold_cv(df_train: pd.DataFrame, tier_name: str, tier_cfg: dict, X_tr_strict_tfidf):
    t0 = time.time()
    print(f"\n=== Running 5-Fold Stratified CV for {tier_name} ({len(tier_cfg['num_cols'])} num + {len(tier_cfg['cat_str_cols'])} cat features) ===")
    y = df_train["target_kev"].values.astype(np.int32)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    oof_dict = {}
    for tr_idx, val_idx in skf.split(df_train, y):
        df_tr = df_train.iloc[tr_idx]
        df_val = df_train.iloc[val_idx]
        fold_preds = fit_predict_all_models_on_fold(
            df_tr, df_val, tier_cfg, X_tr_strict_tfidf[tr_idx], X_tr_strict_tfidf[val_idx]
        )
        for m_name, preds in fold_preds.items():
            if m_name not in oof_dict:
                oof_dict[m_name] = np.zeros(len(df_train), dtype=np.float64)
            oof_dict[m_name][val_idx] = preds

    res = {}
    for m_name, preds in oof_dict.items():
        m = compute_all_metrics(y, preds)
        res[m_name] = m
        print(
            f"  {m_name:66s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d} | H@250={m['hits@250']:2d} | H@500={m['hits@500']:2d}"
        )
    print(f"  Completed {tier_name} 5-Fold CV in {time.time() - t0:.1f}s")
    return res


def evaluate_tier_temporal(df_train: pd.DataFrame, tier_name: str, tier_cfg: dict, X_tr_strict_tfidf):
    t0 = time.time()
    print(f"\n=== Running Causal Temporal Split (2024 -> 2025) for {tier_name} ===")
    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values

    df_tr = df_train.iloc[np.where(is_24)[0]]
    df_val = df_train.iloc[np.where(is_25)[0]]
    y_val = df_val["target_kev"].values.astype(np.int32)

    preds_dict = fit_predict_all_models_on_fold(
        df_tr, df_val, tier_cfg, X_tr_strict_tfidf[is_24], X_tr_strict_tfidf[is_25]
    )

    ks = (25, 50, 100, 250)
    res = {}
    for m_name, preds in preds_dict.items():
        m = compute_all_metrics(y_val, preds, ks=ks)
        res[m_name] = m
        print(
            f"  {m_name:66s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"NDCG@100={m['ndcg@100']:.4f} | F1={m['max_f1']:.4f} | "
            f"H@25={m['hits@25']:2d} | H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d}/55 | H@250={m['hits@250']:2d}/55"
        )
    print(f"  Completed {tier_name} Temporal Split in {time.time() - t0:.1f}s")
    return res


def main():
    t_start = time.time()
    metadata_audit = audit_metadata_availability()

    df_train = pd.read_csv(os.path.join(FEAT_DIR, "features_train_2024_2025.csv"))
    df_2026 = pd.read_csv(os.path.join(FEAT_DIR, "features_scoreboard_2026.csv"))

    df_train, X_pre_strict_tfidf, X_tr_strict_tfidf, pre24_y = prepare_strict_and_expanded_data(
        df_train, df_2026
    )

    tiers_cv = get_tier_columns(df_train, temporal=False)
    tiers_temp = get_tier_columns(df_train, temporal=True)

    cv_results = {}
    temp_results = {}

    for t_name in (
        "Tier A (Pub-Time Strict)",
        "Tier B (Expanded Metadata / Grey-Zone)",
        "Tier C (Leaky Full NVD Snapshot)",
    ):
        cv_results[t_name] = evaluate_tier_5fold_cv(
            df_train, t_name, tiers_cv[t_name], X_tr_strict_tfidf
        )
        temp_results[t_name] = evaluate_tier_temporal(
            df_train, t_name, tiers_temp[t_name], X_tr_strict_tfidf
        )

    out_path = os.path.join(FEAT_DIR, "gbdt_ranking_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "metadata_availability_audit": metadata_audit,
                "cv_5fold_by_tier": cv_results,
                "temporal_2024_to_2025_by_tier": temp_results,
            },
            f,
            indent=2,
        )
    print(f"\nSaved full LightGBM / CatBoost / XGBoost LambdaMART benchmark to {out_path} in {time.time() - t_start:.1f}s")


if __name__ == "__main__":
    main()
