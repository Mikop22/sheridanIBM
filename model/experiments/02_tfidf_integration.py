#!/usr/bin/env python3
"""
Evaluate All Ways of Including TF-IDF in Logistic Regression, Random Forest, and Their Ensemble.

Compares 9 architectures across both 5-Fold Stratified CV and the Strictly Causal
2024 -> 2025 Temporal Split:
  1. Tabular LogReg Only (102 clean features, NO TF-IDF)
  2. Tabular Random Forest Only (102 clean features, NO TF-IDF)
  3. Tabular Ensemble Only (LR + RF, NO TF-IDF)
  4. Standalone Sparse TF-IDF LogReg (35,000 text/CNA/CWE n-grams trained on pre-2024 + train)
  5. Joint Sparse LogReg (`hstack[102 Tabular, 35,000 TF-IDF]` — wide linear model)
  6. Random Forest + TruncatedSVD (`102 Tabular + 32 SVD TF-IDF components + OOF TF-IDF`)
  7. Stacked LogReg (`102 Tabular + Out-of-Fold TF-IDF probability`)
  8. Stacked Random Forest (`102 Tabular + Out-of-Fold TF-IDF probability`)
  9. 3-Way Multi-Modal TF-IDF Ensemble (`Stacked RF + Stacked LR + Joint Sparse TF-IDF LR`)
"""

import csv
import json
import os
import re
import time

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack, vstack
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

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


def load_clean_documents(df_train: pd.DataFrame):
    t0 = time.time()
    print("[1/4] Building strictly publish-time documents (Assigner + CWE + Description)...")
    vulns = {}
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            vulns[r["cve_id"]] = r

    kev_dict = {}
    with open(os.path.join(DATA_DIR, "known_exploited.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            kev_dict[r["cve_id"]] = r["date_added"]

    def make_doc(cid):
        v = vulns[cid]
        ass_tok = re.sub(r"[^a-zA-Z0-9]+", "_", v["assigner"].lower())
        cwe_tok = " ".join(
            f"cwetok_{c.replace('-', '_').lower()}"
            for c in v["cwe_ids"].split(";")
            if c and not c.startswith("NVD-")
        )
        return f"asstok_{ass_tok} {cwe_tok} {v['description']}"

    pre24_docs = []
    pre24_y = []
    for cid, v in vulns.items():
        if "2018-01-01" <= v["published"] < "2024-01-01":
            is_k = 1 if (cid in kev_dict and kev_dict[cid] < "2024-01-01") else 0
            if is_k or (hash(cid) % 8 == 0):
                pre24_docs.append(make_doc(cid))
                pre24_y.append(is_k)

    train_docs = [make_doc(cid) for cid in df_train["cve_id"]]
    print(
        f"      Built {len(train_docs):,} train docs and {len(pre24_docs):,} pre-2024 docs "
        f"({sum(pre24_y)} KEVs) in {time.time() - t0:.1f}s"
    )
    return pre24_docs, np.array(pre24_y, dtype=np.int32), train_docs


def main():
    df_train = pd.read_csv(os.path.join(FEAT_DIR, "features_train_2024_2025.csv"))

    meta_cols = {"cve_id", "published", "snapshot_month", "target_kev", "txt_temp_tfidf_prob"}
    leaky_cols = {
        c
        for c in df_train.columns
        if c.startswith("leak_") or c in ("ref_url_sec_news", "ref_count_log", "ref_uniq_domains")
    }
    tab_cols_102 = [
        c
        for c in df_train.columns
        if c not in meta_cols and c not in leaky_cols and c != "txt_oof_tfidf_prob"
    ]
    tab_cols_103_cv = [c for c in df_train.columns if c not in meta_cols and c not in leaky_cols]
    tab_cols_103_temp = [
        ("txt_temp_tfidf_prob" if c == "txt_oof_tfidf_prob" else c) for c in tab_cols_103_cv
    ]

    pre24_docs, pre24_y, train_docs = load_clean_documents(df_train)

    vec = TfidfVectorizer(
        max_features=35000,
        ngram_range=(1, 2),
        min_df=4,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    X_all_tfidf = vec.fit_transform(pre24_docs + train_docs)
    n_pre = len(pre24_docs)
    X_pre_tfidf = X_all_tfidf[:n_pre]
    X_tr_tfidf = X_all_tfidf[n_pre:]

    svd = TruncatedSVD(n_components=32, random_state=42)
    X_tr_svd = svd.fit_transform(X_tr_tfidf)

    y = df_train["target_kev"].values.astype(np.int32)
    X_tab102 = df_train[tab_cols_102].values.astype(np.float64)
    X_tab103 = df_train[tab_cols_103_cv].values.astype(np.float64)

    print("[2/4] Running 5-Fold Stratified CV across all 9 architectures...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    n = len(df_train)
    oof = {k: np.zeros(n) for k in range(1, 10)}

    for tr_idx, val_idx in skf.split(X_tab102, y):
        sc102 = StandardScaler()
        X102_tr = sc102.fit_transform(X_tab102[tr_idx])
        X102_val = sc102.transform(X_tab102[val_idx])

        sc103 = StandardScaler()
        X103_tr = sc103.fit_transform(X_tab103[tr_idx])
        X103_val = sc103.transform(X_tab103[val_idx])

        # 1. Tabular LogReg (102 feats, NO TF-IDF)
        lr102 = LogisticRegression(C=0.1, max_iter=500, random_state=42).fit(X102_tr, y[tr_idx])
        p_lr102 = lr102.predict_proba(X102_val)[:, 1]
        oof[1][val_idx] = p_lr102

        # 2. Tabular RF (102 feats, NO TF-IDF)
        rf102 = RandomForestClassifier(
            n_estimators=300, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42
        ).fit(X_tab102[tr_idx], y[tr_idx])
        p_rf102 = rf102.predict_proba(X_tab102[val_idx])[:, 1]
        oof[2][val_idx] = p_rf102

        # 3. Tabular Ensemble (NO TF-IDF)
        oof[3][val_idx] = 0.5 * p_lr102 + 0.5 * p_rf102

        # 4. Standalone Sparse TF-IDF LogReg (Pre-2024 + Fold Train)
        tf_bal = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42).fit(
            vstack([X_pre_tfidf, X_tr_tfidf[tr_idx]]), np.concatenate([pre24_y, y[tr_idx]])
        )
        p_tf_bal = tf_bal.predict_proba(X_tr_tfidf[val_idx])[:, 1]
        oof[4][val_idx] = p_tf_bal

        # 5. Joint Sparse LogReg (hstack[102 Tabular, 35k TF-IDF])
        Xj_tr = hstack([csr_matrix(X102_tr * 0.25), X_tr_tfidf[tr_idx]], format="csr")
        Xj_val = hstack([csr_matrix(X102_val * 0.25), X_tr_tfidf[val_idx]], format="csr")
        lr_j = LogisticRegression(C=0.5, max_iter=500, random_state=42).fit(Xj_tr, y[tr_idx])
        p_lr_j = lr_j.predict_proba(Xj_val)[:, 1]
        oof[5][val_idx] = p_lr_j

        # 6. Random Forest + 32 SVD TF-IDF + OOF TF-IDF
        X_svd_tr = np.column_stack([X_tab103[tr_idx], X_tr_svd[tr_idx]])
        X_svd_val = np.column_stack([X_tab103[val_idx], X_tr_svd[val_idx]])
        rf_svd = RandomForestClassifier(
            n_estimators=300, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42
        ).fit(X_svd_tr, y[tr_idx])
        p_rf_svd = rf_svd.predict_proba(X_svd_val)[:, 1]
        oof[6][val_idx] = p_rf_svd

        # 7. Stacked LogReg (102 Tabular + OOF TF-IDF feature)
        lr103 = LogisticRegression(C=0.1, max_iter=500, random_state=42).fit(X103_tr, y[tr_idx])
        p_lr103 = lr103.predict_proba(X103_val)[:, 1]
        oof[7][val_idx] = p_lr103

        # 8. Stacked RF (102 Tabular + OOF TF-IDF feature)
        rf103 = RandomForestClassifier(
            n_estimators=300, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42
        ).fit(X_tab103[tr_idx], y[tr_idx])
        p_rf103 = rf103.predict_proba(X_tab103[val_idx])[:, 1]
        oof[8][val_idx] = p_rf103

        # 9. 3-Way Multi-Modal Ensemble (Stacked RF + Stacked LR + Joint Sparse TF-IDF LR)
        oof[9][val_idx] = 0.50 * p_rf103 + 0.25 * p_lr103 + 0.25 * p_lr_j

    names = {
        1: "1. Tabular LogReg Only (102 feats, NO TF-IDF)",
        2: "2. Tabular RF Only (102 feats, NO TF-IDF)",
        3: "3. Tabular Ensemble (LR + RF, NO TF-IDF)",
        4: "4. Standalone Sparse TF-IDF LogReg (35k n-grams only)",
        5: "5. Joint Sparse LogReg (hstack[102 Tabular, 35k TF-IDF])",
        6: "6. Random Forest + 32 TruncatedSVD TF-IDF + OOF TF-IDF",
        7: "7. Stacked LogReg (102 Tabular + OOF TF-IDF feature)",
        8: "8. Stacked Random Forest (102 Tabular + OOF TF-IDF feature)",
        9: "9. 3-Way Ensemble (Stacked RF + Stacked LR + Joint TF-IDF LR)",
    }

    cv_results = {}
    print("\n=== 5-Fold Stratified CV Results ===")
    for k in range(1, 10):
        m = compute_all_metrics(y, oof[k])
        cv_results[names[k]] = m
        print(
            f"  {names[k]:62s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"F1={m['max_f1']:.4f} | H@50={m['hits@50']:2d} | H@100={m['hits@100']:2d} | "
            f"H@250={m['hits@250']:2d} | H@500={m['hits@500']:2d}"
        )

    print("\n[3/4] Running Strictly Causal Temporal Split (Train 2024 -> Test 2025)...")
    is_24 = df_train["published"].str.startswith("2024").values
    is_25 = df_train["published"].str.startswith("2025").values
    y_tr, y_val = y[is_24], y[is_25]

    X102_raw_tr, X102_raw_val = X_tab102[is_24], X_tab102[is_25]
    X103_temp = df_train[tab_cols_103_temp].values.astype(np.float64)
    X103_raw_tr, X103_raw_val = X103_temp[is_24], X103_temp[is_25]

    sc102 = StandardScaler()
    X102_tr = sc102.fit_transform(X102_raw_tr)
    X102_val = sc102.transform(X102_raw_val)

    sc103 = StandardScaler()
    X103_tr = sc103.fit_transform(X103_raw_tr)
    X103_val = sc103.transform(X103_raw_val)

    lr102 = LogisticRegression(C=0.1, max_iter=500, random_state=42).fit(X102_tr, y_tr)
    p_lr102_25 = lr102.predict_proba(X102_val)[:, 1]

    rf102 = RandomForestClassifier(
        n_estimators=400, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42
    ).fit(X102_raw_tr, y_tr)
    p_rf102_25 = rf102.predict_proba(X102_raw_val)[:, 1]

    tf_bal_24 = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42).fit(
        vstack([X_pre_tfidf, X_tr_tfidf[is_24]]), np.concatenate([pre24_y, y_tr])
    )
    p_tf_bal_25 = tf_bal_24.predict_proba(X_tr_tfidf[is_25])[:, 1]

    Xj_tr = hstack([csr_matrix(X102_tr * 0.25), X_tr_tfidf[is_24]], format="csr")
    Xj_val = hstack([csr_matrix(X102_val * 0.25), X_tr_tfidf[is_25]], format="csr")
    lr_j = LogisticRegression(C=0.5, max_iter=500, random_state=42).fit(Xj_tr, y_tr)
    p_lr_j_25 = lr_j.predict_proba(Xj_val)[:, 1]

    rf_svd = RandomForestClassifier(
        n_estimators=400, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42
    ).fit(np.column_stack([X103_raw_tr, X_tr_svd[is_24]]), y_tr)
    p_rf_svd_25 = rf_svd.predict_proba(np.column_stack([X103_raw_val, X_tr_svd[is_25]]))[:, 1]

    lr103 = LogisticRegression(C=0.1, max_iter=500, random_state=42).fit(X103_tr, y_tr)
    p_lr103_25 = lr103.predict_proba(X103_val)[:, 1]

    rf103 = RandomForestClassifier(
        n_estimators=400, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42
    ).fit(X103_raw_tr, y_tr)
    p_rf103_25 = rf103.predict_proba(X103_raw_val)[:, 1]

    temp_preds = {
        names[1]: p_lr102_25,
        names[2]: p_rf102_25,
        names[3]: 0.5 * p_lr102_25 + 0.5 * p_rf102_25,
        names[4]: p_tf_bal_25,
        names[5]: p_lr_j_25,
        names[6]: p_rf_svd_25,
        names[7]: p_lr103_25,
        names[8]: p_rf103_25,
        names[9]: 0.50 * p_rf103_25 + 0.25 * p_lr103_25 + 0.25 * p_lr_j_25,
    }

    temp_results = {}
    ks = (25, 50, 100, 250)
    print("\n=== Strictly Causal Temporal Split (2024 -> 2025) Results ===")
    for k in range(1, 10):
        nm = names[k]
        m = compute_all_metrics(y_val, temp_preds[nm], ks=ks)
        temp_results[nm] = m
        print(
            f"  {nm:62s} | ROC={m['roc_auc']:.4f} | PR-AUC={m['pr_auc']:.4f} | "
            f"F1={m['max_f1']:.4f} | H@25={m['hits@25']:2d} | H@50={m['hits@50']:2d} | "
            f"H@100={m['hits@100']:2d}/55 | H@250={m['hits@250']:2d}/55"
        )

    # Top n-grams from clean description+CNA+CWE TF-IDF
    clf_full = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300, random_state=42).fit(
        vstack([X_pre_tfidf, X_tr_tfidf]), np.concatenate([pre24_y, y])
    )
    vocab = vec.get_feature_names_out()
    coefs = clf_full.coef_[0]
    top_pos = [(str(vocab[i]), round(float(coefs[i]), 3)) for i in np.argsort(-coefs)[:15]]
    top_neg = [(str(vocab[i]), round(float(coefs[i]), 3)) for i in np.argsort(coefs)[:15]]

    out_path = os.path.join(FEAT_DIR, "tfidf_ensemble_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "cv_5fold": cv_results,
                "temporal_2024_to_2025": temp_results,
                "top_positive_ngrams": top_pos,
                "top_negative_ngrams": top_neg,
            },
            f,
            indent=2,
        )
    print("\n[4/4] Saved full TF-IDF ensemble comparison to", out_path)


if __name__ == "__main__":
    main()
