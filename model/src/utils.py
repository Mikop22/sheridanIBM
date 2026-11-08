#!/usr/bin/env python3
"""
Shared utilities, metrics, metadata tier definitions, and base model trainers
for Vulnerability Exploitation (KEV) Prediction.
"""

import csv
import os
import re
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from scipy.optimize import minimize
from scipy.sparse import csr_matrix, hstack, vstack
from scipy.special import expit
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    log_loss,
    ndcg_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from lightgbm import LGBMClassifier
from xgboost import XGBRanker

DATA_DIR = os.environ.get("CVE_DATA_DIR", "/tmp/data")
FEAT_DIR = os.environ.get("CVE_OUT_DIR", "/tmp/features")
RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def precision_recall_at_k(y_true: np.ndarray, y_score: np.ndarray, k: int) -> tuple[int, float, float]:
    order = np.argsort(-y_score)
    top_k = y_true[order[:k]]
    hits = int(np.sum(top_k))
    prec = hits / float(k)
    rec = hits / float(max(np.sum(y_true), 1))
    return hits, prec, rec


def max_f1_score(y_true: np.ndarray, y_score: np.ndarray) -> tuple[float, float, float, float]:
    prec, rec, thresh = precision_recall_curve(y_true, y_score)
    denom = prec + rec
    f1s = np.where(denom > 0, 2 * prec * rec / np.where(denom > 0, denom, 1.0), 0.0)
    best_idx = int(np.argmax(f1s))
    best_th = float(thresh[min(best_idx, len(thresh) - 1)]) if len(thresh) > 0 else 0.5
    return float(f1s[best_idx]), float(prec[best_idx]), float(rec[best_idx]), best_th


def fast_ap_and_ndcg100(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    """Vectorized O(N * N_pos) exact computation of PR-AUC and NDCG@100 for rare positives."""
    pos_scores = scores[y_true == 1]
    n_pos = len(pos_scores)
    if n_pos == 0:
        return 0.0, 0.0

    pos_sorted = np.sort(pos_scores)[::-1]
    ranks = np.sum(scores[None, :] >= pos_sorted[:, None], axis=1).astype(np.float64)
    precisions_at_pos = np.arange(1, n_pos + 1, dtype=np.float64) / np.maximum(ranks, 1.0)
    ap = float(np.mean(precisions_at_pos))

    in_top100 = ranks <= 100.0
    dcg = float(np.sum(1.0 / np.log2(ranks[in_top100] + 1.0))) if np.any(in_top100) else 0.0
    ideal_k = min(n_pos, 100)
    idcg = float(np.sum(1.0 / np.log2(np.arange(2, ideal_k + 2, dtype=np.float64))))
    ndcg100 = dcg / idcg if idcg > 0 else 0.0
    return ap, ndcg100


def compute_all_metrics(y_true: np.ndarray, y_score: np.ndarray, ks=(50, 100, 250, 500)) -> dict:
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


def sigmoid_calibrate(
    scores: np.ndarray, y_true_train: np.ndarray, scores_train: np.ndarray
) -> np.ndarray:
    """1D Platt scaling to map raw ranking margins (e.g. LambdaMART) to calibrated probabilities."""
    sc = StandardScaler()
    s_tr_std = sc.fit_transform(scores_train.reshape(-1, 1))
    s_te_std = sc.transform(scores.reshape(-1, 1))
    lr = LogisticRegression(C=1.0, random_state=42)
    lr.fit(s_tr_std, y_true_train)
    return lr.predict_proba(s_te_std)[:, 1]


def within_month_ranks(P: np.ndarray, months: np.ndarray) -> np.ndarray:
    """Convert each column of P into empirical rank percentiles [0, 1] within each snapshot_month."""
    R = np.zeros_like(P, dtype=np.float64)
    for m in np.unique(months):
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


def prepare_strict_and_expanded_data(df_train: pd.DataFrame, df_2026: pd.DataFrame):
    """
    Build strictly publication-time TF-IDF matrices (`assigner` + `description` only)
    and attach aligned categorical codes across both `df_train` and `df_2026`.
    """
    vulns = {}
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            vulns[r["cve_id"]] = r

    kev_dict = {}
    with open(os.path.join(DATA_DIR, "known_exploited.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            kev_dict[r["cve_id"]] = r["date_added"]

    cpe_primary_vendor = {}
    with open(os.path.join(DATA_DIR, "affected_products.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["cve_id"]
            if cid not in cpe_primary_vendor and r["vulnerable"] == "Y":
                cpe_primary_vendor[cid] = r["vendor"]

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
    test_2026_strict_docs = [make_strict_doc(cid) for cid in df_2026["cve_id"]]

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
    X_2026_strict_tfidf = vec_strict.transform(test_2026_strict_docs)

    y = df_train["target_kev"].values.astype(np.int32)
    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values

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

    clf_full_strict = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42)
    clf_full_strict.fit(
        vstack([X_pre_strict_tfidf, X_tr_strict_tfidf]),
        np.concatenate([pre24_y, y]),
    )
    test_2026_strict_tfidf = clf_full_strict.predict_proba(X_2026_strict_tfidf)[:, 1]

    df_train = df_train.copy()
    df_2026 = df_2026.copy()
    df_train["txt_strict_oof_tfidf_prob"] = oof_strict_tfidf
    df_train["txt_strict_temp_tfidf_prob"] = temp_strict_tfidf
    df_2026["txt_strict_oof_tfidf_prob"] = test_2026_strict_tfidf
    df_2026["txt_strict_temp_tfidf_prob"] = test_2026_strict_tfidf

    for df_curr in (df_train, df_2026):
        df_curr["cat_assigner"] = [vulns[cid]["assigner"] or "MISSING" for cid in df_curr["cve_id"]]
        df_curr["cat_cwe_primary"] = [
            (vulns[cid]["cwe_ids"].split(";")[0] if vulns[cid]["cwe_ids"] else "MISSING")
            for cid in df_curr["cve_id"]
        ]
        df_curr["cat_cpe_vendor"] = [
            cpe_primary_vendor.get(cid, "MISSING") for cid in df_curr["cve_id"]
        ]
        df_curr["cat_nvd_status"] = [vulns[cid]["nvd_status"] for cid in df_curr["cve_id"]]

    # Consistent categorical encoding across train + 2026
    for col in ("cat_assigner", "cat_cwe_primary", "cat_cpe_vendor", "cat_nvd_status"):
        all_cats = pd.Index(df_train[col].unique()).union(pd.Index(df_2026[col].unique()))
        df_train[col + "_code"] = pd.Categorical(df_train[col], categories=all_cats).codes.astype(np.int32)
        df_2026[col + "_code"] = pd.Categorical(df_2026[col], categories=all_cats).codes.astype(np.int32)

    return df_train, df_2026, X_pre_strict_tfidf, X_tr_strict_tfidf, X_2026_strict_tfidf, pre24_y


def get_tier_columns(df: pd.DataFrame, temporal: bool = False) -> dict:
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
