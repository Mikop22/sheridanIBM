#!/usr/bin/env python3
"""
Publication-time product-token graph experiments.

The scoreboard decision is frozen at the end of each CVE's publication month.
Every count below uses only CVEs published before that month, and counts a
past CVE as a KEV only when its CISA date_added is also before that month.

Experiments
  1. Coverage of a closed product list vs. an open capitalized-product vocabulary.
  2. One-hop historical KEV rate, added to Tier A LightGBM. Vocabulary is chosen
     on 2024-09..2024-12 after fitting 2024-01..2024-08, then scored once on 2025.
  3. Whether that rate is redundant with the assigner prior.
  4. Campaign recency (days since last KEV, trailing 90 days, 365-day half-life).
  5. Sibling / vendor hop for rare tokens.
  6. Within-month product uniqueness.
  7. Leak controls: CPE vendor edges from the Nov 2026 snapshot, the frozen
     reference-domain prior, and a product rate that ignores the date_added cutoff.
  8. A 10-neighbor outcome rate on the rarest qualifying token.
  9. A neural graph is not trained unless the sibling hop beats the one-hop rate
     by at least two stable top-25 hits on 2025.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from scipy.stats import spearmanr
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.features import (  # noqa: E402
    ENTERPRISE_ASSIGNERS,
    TOP_TARGET_ENTITIES,
    VDB_BOUNTY_ASSIGNERS,
    WORDPRESS_ASSIGNERS,
)
from src.utils import DATA_DIR, FEAT_DIR, RESULTS_DIR, precision_recall_at_k  # noqa: E402

SMOOTH = 20.0
SEEDS = (0, 1, 2)
HIGH_DF = 0.02
HALF_LIFE_MONTHS = 12.0
RECENT_WINDOW = 3  # ~90 days
MIN_DF_CHOICES = (2, 5)

STOP = {
    "about", "above", "after", "affect", "affected", "affecting", "affects", "again",
    "against", "all", "allow", "allowed", "allowing", "allows", "already", "also",
    "among", "and", "another", "any", "api", "are", "arbitrary", "asp", "attacker",
    "attackers", "authentication", "available", "based", "because", "been", "before",
    "being", "between", "both", "but", "can", "cannot", "cause", "causes", "certain",
    "code", "command", "commands", "component", "components", "could", "cve", "data",
    "denial", "does", "due", "during", "each", "either", "error", "example", "execute",
    "executed", "execution", "exploit", "exploited", "exploitation", "file", "files",
    "flaw", "flaws", "for", "from", "function", "functions", "get", "had", "has",
    "have", "html", "http", "https", "impact", "improper", "information", "input",
    "buffer", "bypass", "device", "devices", "interface", "into", "injection",
    "issue", "issues", "its", "json", "lead", "leads", "local", "management",
    "may", "memory", "overflow", "platform",
    "module", "modules", "more", "most", "multiple", "must", "network", "neutralization",
    "not", "note", "null", "only", "onto", "open", "other", "over", "parameter",
    "parameters", "path", "paths", "pdf", "php", "png", "possible", "post", "prior",
    "privilege", "privileges", "product", "products", "remote", "request", "requests",
    "response", "result", "results", "server", "servers", "service", "services",
    "software", "some", "sql", "ssh", "ssl", "successful", "successfully", "such",
    "system", "systems", "tcp", "than", "that", "the", "their", "then", "there",
    "these", "this", "through", "tls", "udp", "unauthenticated", "under", "uri",
    "url", "used", "user", "users", "using", "validation", "version", "versions",
    "via", "vulnerability", "vulnerabilities", "was", "were", "when", "where",
    "which", "while", "who", "whose", "will", "with", "within", "without", "would",
    "xml", "xss", "csrf", "rce", "cpu", "ram", "dns", "jpg",
}

RE_PHRASE = re.compile(
    r"\b([A-Z][A-Za-z0-9.+_-]*(?:\s+[A-Z][A-Za-z0-9.+_-]*){1,3})\b"
)
RE_CAMEL = re.compile(
    r"\b((?:[A-Z][a-z0-9]+){2,}|[A-Z]{2,}[a-z]+[A-Za-z0-9]*|"
    r"[A-Za-z]+(?:-[A-Za-z0-9]+){1,}|\d+[A-Za-z][A-Za-z0-9-]*|"
    r"[A-Za-z]*\d[A-Za-z0-9-]*)\b"
)
RE_SINGLE = re.compile(r"\b([A-Z][a-z]{3,})\b")
RE_ACRONYM = re.compile(r"\b([A-Z]{3,6})\b")
RE_UUID = re.compile(r"^[0-9a-f-]{16,}$", re.I)

# Short tokens map only on exact match. Longer stems map by prefix.
EXACT_VENDOR = {
    "ipad": "apple",
    "macos": "apple",
    "asa": "cisco",
    "esxi": "vmware",
    "nsx": "vmware",
    "jira": "atlassian",
    "sudo": "sudo",
    "exim": "exim",
    "ami": "ami",
    "spx": "ami",
}
PREFIX_VENDOR = (
    ("forti", "fortinet"),
    ("palo alto", "paloalto"),
    ("pan-os", "paloalto"),
    ("globalprotect", "paloalto"),
    ("firepower", "cisco"),
    ("anyconnect", "cisco"),
    ("adaptive security", "cisco"),
    ("cisco", "cisco"),
    ("connect secure", "ivanti"),
    ("pulse connect", "ivanti"),
    ("ivanti", "ivanti"),
    ("vcenter", "vmware"),
    ("vmware", "vmware"),
    ("netscaler", "citrix"),
    ("citrix", "citrix"),
    ("sonicwall", "sonicwall"),
    ("microsoft exchange", "microsoft"),
    ("microsoft", "microsoft"),
    ("sharepoint", "microsoft"),
    ("win32k", "microsoft"),
    ("internet explorer", "microsoft"),
    ("windows", "microsoft"),
    ("chromium", "google"),
    ("chrome", "google"),
    ("android", "google"),
    ("webkit", "apple"),
    ("iphone", "apple"),
    ("linux kernel", "linux"),
    ("openssh", "openssh"),
    ("apache", "apache"),
    ("wordpress", "wordpress"),
    ("jenkins", "jenkins"),
    ("gitlab", "gitlab"),
    ("confluence", "atlassian"),
    ("bitbucket", "atlassian"),
    ("coldfusion", "adobe"),
    ("acrobat", "adobe"),
    ("magento", "adobe"),
    ("weblogic", "oracle"),
    ("peoplesoft", "oracle"),
    ("java se", "oracle"),
    ("juniper", "juniper"),
    ("junos", "juniper"),
    ("freetype", "freetype"),
    ("xwiki", "xwiki"),
    ("wazuh", "wazuh"),
    ("kentico", "kentico"),
    ("veracore", "veracore"),
    ("simplehelp", "simplehelp"),
    ("7-zip", "7zip"),
    ("7zip", "7zip"),
    ("samsung", "samsung"),
    ("synology", "synology"),
    ("zyxel", "zyxel"),
)
# Linux kernel CNA publishes under this UUID rather than an email.
ASSIGNER_VENDOR_OVERRIDE = {
    "416baaa9-dc9f-4396-8d5f-8c081fb06d67": "linux",
}
GENERIC_ASSIGNER_LABELS = {
    "com", "org", "net", "gov", "security", "psirt", "secure", "cve", "cna",
    "disclosure", "support", "secalert", "product", "cert", "sirt", "noreply",
    "info", "contact", "mail", "gmail", "googlegroups",
}


def vendor_of_token(tok: str) -> str | None:
    if tok in EXACT_VENDOR:
        return EXACT_VENDOR[tok]
    for pref, vend in PREFIX_VENDOR:
        if tok == pref or tok.startswith(pref + " ") or tok.startswith(pref):
            return vend
    return None


def assigner_vendor(assigner: str) -> str | None:
    raw = (assigner or "").strip()
    low = raw.lower()
    if low in ASSIGNER_VENDOR_OVERRIDE:
        return ASSIGNER_VENDOR_OVERRIDE[low]
    if low == "cve@mitre.org":
        return None
    if any(k in low for k in WORDPRESS_ASSIGNERS + VDB_BOUNTY_ASSIGNERS):
        return None
    if RE_UUID.match(low):
        return None
    if "@" not in low:
        return None
    user, dom = low.split("@", 1)
    labels = [p for p in re.split(r"[^a-z0-9]+", dom) if p]
    base = ""
    if len(labels) >= 2:
        base = labels[-2]
        if base in GENERIC_ASSIGNER_LABELS and len(labels) >= 3:
            base = labels[-3]
    if base in GENERIC_ASSIGNER_LABELS or len(base) < 3:
        user_labels = [p for p in re.split(r"[^a-z0-9]+", user) if p and p not in GENERIC_ASSIGNER_LABELS]
        base = user_labels[0] if user_labels else ""
    if len(base) < 3 or base in GENERIC_ASSIGNER_LABELS:
        return None
    return base


HYPHEN_JUNK_SUFFIX = {
    "based", "related", "specific", "dependent", "only", "level", "side", "form",
    "type", "aware", "driven", "grade", "wide", "free", "source", "the",
}
WEAKNESS_TOKENS = {
    "use-after-free", "out-of-bounds", "denial-of-service", "man-in-the-middle",
    "web-based", "open-source", "buffer-overflow", "cross-site", "sql-injection",
}


def _keep_token(tok: str, *, min_len: int) -> bool:
    if len(tok) < min_len or tok in STOP or tok in WEAKNESS_TOKENS:
        return False
    if not any(ch.isalpha() for ch in tok):
        return False
    if "-" in tok and tok.split("-")[-1] in HYPHEN_JUNK_SUFFIX:
        return False
    return True


def extract_open_tokens(desc: str) -> list[str]:
    found: list[str] = []
    if not desc:
        return found
    for m in RE_PHRASE.finditer(desc):
        words = []
        for w in m.group(1).split():
            wl = w.lower().strip(".'’")
            if not _keep_token(wl, min_len=4) and not any(ch.isdigit() for ch in wl):
                continue
            words.append(wl)
        if len(words) >= 2:
            found.append(" ".join(words))
        elif len(words) == 1 and (any(ch.isdigit() for ch in words[0]) or "-" in words[0]):
            found.append(words[0])
    for m in RE_CAMEL.finditer(desc):
        t = m.group(1).lower()
        if _keep_token(t, min_len=3):
            found.append(t)
    for m in RE_SINGLE.finditer(desc):
        # Sentence-initial product names ("Wazuh is...") are real. Stopwords
        # remove the ordinary sentence openers.
        t = m.group(1).lower()
        if _keep_token(t, min_len=4):
            found.append(t)
    for m in RE_ACRONYM.finditer(desc):
        t = m.group(1).lower()
        if _keep_token(t, min_len=3):
            found.append(t)
    # Closed list is case-insensitive and is part of the open candidate pool,
    # so a lowercase "linux kernel" is not invisible to the open vocabulary.
    for m in TOP_TARGET_ENTITIES.findall(desc):
        t = m.lower().strip()
        if t:
            found.append(t)
    out: list[str] = []
    seen = set()
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
        if len(out) >= 15:
            break
    return out


def extract_closed_tokens(desc: str) -> list[str]:
    seen = set()
    out = []
    for m in TOP_TARGET_ENTITIES.findall(desc or ""):
        t = m.lower().strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def slice_name(enterprise: int, mitre: int, vdb: int, wordpress: int) -> str:
    if enterprise:
        return "enterprise"
    if mitre:
        return "mitre"
    if vdb:
        return "vdb"
    if wordpress:
        return "wordpress"
    return "other"


def lgbm_predict(X_tr, y_tr, X_te, seed: int) -> np.ndarray:
    clf = LGBMClassifier(
        n_estimators=250,
        learning_rate=0.03,
        num_leaves=15,
        max_depth=5,
        min_child_samples=25,
        subsample=0.8,
        colsample_bytree=0.7,
        reg_alpha=1.0,
        reg_lambda=5.0,
        random_state=seed,
        n_jobs=4,
        verbose=-1,
    )
    clf.fit(X_tr, y_tr)
    proba = clf.predict_proba(X_te)[:, 1]
    if seed == SEEDS[0]:
        lgbm_predict.importances = clf.feature_importances_.astype(int)  # type: ignore[attr-defined]
    return proba


def ranking_summary(y: np.ndarray, scores: np.ndarray, ids: np.ndarray) -> dict:
    order = np.argsort(-scores, kind="mergesort")
    top25 = order[:25]
    top250 = order[:250]
    hits25 = int(y[top25].sum())
    hit_ids = [str(ids[i]) for i in top25 if y[i] == 1]
    pr = float(average_precision_score(y, scores)) if y.sum() and y.sum() < len(y) else 0.0
    roc = float(roc_auc_score(y, scores)) if y.sum() and y.sum() < len(y) else 0.0
    h100, p100, _ = precision_recall_at_k(y, scores, 100)
    return {
        "pr_auc": round(pr, 4),
        "roc_auc": round(roc, 4),
        "hits@25": hits25,
        "prec@25": round(hits25 / 25.0, 4),
        "hits@100": int(h100),
        "prec@100": round(float(p100), 4),
        "top25_positives": hit_ids,
        "wordpress_in_top250": None,  # filled by caller when the mask is available
        "_top250_idx": top250,
    }


def aggregate_seeds(runs: list[dict]) -> dict:
    keys = ["pr_auc", "roc_auc", "hits@25", "prec@25", "hits@100", "prec@100"]
    out = {f"mean_{k}": round(float(np.mean([r[k] for r in runs])), 4) for k in keys}
    out["hits@25_by_seed"] = [r["hits@25"] for r in runs]
    out["pr_auc_by_seed"] = [r["pr_auc"] for r in runs]
    counts = Counter()
    for r in runs:
        counts.update(r["top25_positives"])
    stable = sorted([cid for cid, n in counts.items() if n >= 2])
    out["stable_top25_positives"] = stable
    out["stable_hits@25"] = len(stable)
    wp = [r["wordpress_in_top250"] for r in runs]
    out["wordpress_in_top250_by_seed"] = wp
    return out


def stable_delta(base: dict, other: dict) -> dict:
    b = set(base["stable_top25_positives"])
    o = set(other["stable_top25_positives"])
    return {
        "gained": sorted(o - b),
        "lost": sorted(b - o),
        "gained_n": len(o - b),
        "lost_n": len(b - o),
        "net_stable_hits": len(o) - len(b),
    }


def load_graph_tables():
    t0 = time.time()
    print("[1/4] Loading KEV dates, descriptions, and the training matrix...", flush=True)
    kev_month = {}
    with open(os.path.join(DATA_DIR, "known_exploited.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            da = (r.get("date_added") or "")[:7]
            if len(da) == 7:
                kev_month[r["cve_id"]] = da

    feat = pd.read_csv(os.path.join(FEAT_DIR, "features_train_2024_2025.csv"))
    cohort_ids = set(feat["cve_id"])

    token_to_id: dict[str, int] = {}
    id_to_tok: list[str] = []
    closed_flags: list[bool] = []

    def intern(tok: str, closed: bool) -> int:
        i = token_to_id.get(tok)
        if i is None:
            i = len(id_to_tok)
            token_to_id[tok] = i
            id_to_tok.append(tok)
            closed_flags.append(closed)
        elif closed:
            closed_flags[i] = True
        return i

    cve_ids: list[str] = []
    pub_months: list[str] = []
    kev_months: list[str | None] = []
    assigners: list[str] = []
    tok_flat: list[int] = []
    tok_off = [0]
    n_docs = 0
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            pub = (r.get("published") or "")[:7]
            if len(pub) != 7:
                continue
            desc = r.get("description") or ""
            closed = extract_closed_tokens(desc)
            opened = extract_open_tokens(desc)
            ids = []
            seen = set()
            for t in closed:
                i = intern(t, True)
                if i not in seen:
                    seen.add(i)
                    ids.append(i)
            for t in opened:
                i = intern(t, False)
                if i not in seen:
                    seen.add(i)
                    ids.append(i)
            cve_ids.append(r["cve_id"])
            pub_months.append(pub)
            kev_months.append(kev_month.get(r["cve_id"]))
            assigners.append(r.get("assigner") or "")
            tok_flat.extend(ids)
            tok_off.append(len(tok_flat))
            n_docs += 1
            if n_docs % 100000 == 0:
                print(f"      tokenized {n_docs:,} CVEs, {len(id_to_tok):,} tokens", flush=True)

    tok_flat_arr = np.asarray(tok_flat, dtype=np.int32)
    tok_off_arr = np.asarray(tok_off, dtype=np.int64)
    is_closed = np.asarray(closed_flags, dtype=bool)
    print(
        f"      {n_docs:,} CVEs, {len(id_to_tok):,} tokens "
        f"({int(is_closed.sum())} closed-list types) in {time.time() - t0:.1f}s",
        flush=True,
    )

    print("[2/4] Reading CPE vendors for the leak-control arm...", flush=True)
    cpe_vendors: dict[str, list[str]] = defaultdict(list)
    with open(os.path.join(DATA_DIR, "affected_products.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("vulnerable") != "Y":
                continue
            cid = r["cve_id"]
            vend = (r.get("vendor") or "").strip().lower()
            if not vend or vend in {"*", "-"}:
                continue
            cur = cpe_vendors[cid]
            if vend not in cur and len(cur) < 8:
                cur.append(vend)
    print(f"      CPE vendors for {len(cpe_vendors):,} CVEs in {time.time() - t0:.1f}s", flush=True)

    return {
        "feat": feat,
        "cohort_ids": cohort_ids,
        "cve_ids": cve_ids,
        "pub_months": pub_months,
        "kev_months": kev_months,
        "assigners": assigners,
        "tok_flat": tok_flat_arr,
        "tok_off": tok_off_arr,
        "id_to_tok": id_to_tok,
        "is_closed": is_closed,
        "cpe_vendors": cpe_vendors,
    }


def build_features(tables: dict) -> pd.DataFrame:
    """Walk months once and attach graph columns to the training matrix."""
    t0 = time.time()
    print("[3/4] Walking publication months and building graph features...", flush=True)
    feat = tables["feat"]
    cve_ids = tables["cve_ids"]
    pub_months = tables["pub_months"]
    kev_months = tables["kev_months"]
    assigners = tables["assigners"]
    tok_flat = tables["tok_flat"]
    tok_off = tables["tok_off"]
    id_to_tok = tables["id_to_tok"]
    is_closed = tables["is_closed"]
    cpe_vendors = tables["cpe_vendors"]
    n_tok = len(id_to_tok)
    n_cve = len(cve_ids)

    id_index = {cid: i for i, cid in enumerate(cve_ids)}
    months = sorted(set(pub_months) | {m for m in kev_months if m})
    month_index = {m: i for i, m in enumerate(months)}

    # Per-CVE vendor ids (token vendors + assigner vendor) and CPE vendor ids.
    vendor_to_id: dict[str, int] = {}

    def vend_id(name: str) -> int:
        i = vendor_to_id.get(name)
        if i is None:
            i = len(vendor_to_id)
            vendor_to_id[name] = i
        return i

    cve_vendor_ids: list[list[int]] = [[] for _ in range(n_cve)]
    cve_cpe_ids: list[list[int]] = [[] for _ in range(n_cve)]
    for i in range(n_cve):
        names = []
        av = assigner_vendor(assigners[i])
        if av:
            names.append("a:" + av)
        toks = tok_flat[tok_off[i] : tok_off[i + 1]]
        for t in toks:
            tv = vendor_of_token(id_to_tok[int(t)])
            if tv:
                names.append("t:" + tv)
        # Dedup, assigner-vendor and token-vendor stay distinct namespaces so a
        # token sibling rate is not mixed with the assigner prior's population.
        seen = set()
        for name in names:
            if name not in seen:
                seen.add(name)
                cve_vendor_ids[i].append(vend_id(name))
        for v in cpe_vendors.get(cve_ids[i], []):
            cve_cpe_ids[i].append(vend_id("cpe:" + v))

    n_vend = max(len(vendor_to_id), 1)
    by_pub: dict[str, list[int]] = defaultdict(list)
    by_kev: dict[str, list[int]] = defaultdict(list)
    for i in range(n_cve):
        by_pub[pub_months[i]].append(i)
        km = kev_months[i]
        if km:
            by_kev[km].append(i)

    # Same-month token counts for 2024-2025 publications (structural, unlabeled).
    month_tok_count: dict[str, Counter] = defaultdict(Counter)
    for m, idxs in by_pub.items():
        if m < "2024-01" or m > "2025-12":
            continue
        cnt = month_tok_count[m]
        for i in idxs:
            cnt.update(int(t) for t in tok_flat[tok_off[i] : tok_off[i + 1]])

    tok_n = np.zeros(n_tok, dtype=np.int32)
    tok_k = np.zeros(n_tok, dtype=np.int32)
    tok_k_dirty = np.zeros(n_tok, dtype=np.int32)
    tok_last_kev = np.full(n_tok, -1, dtype=np.int16)
    hl_n = np.zeros(n_tok, dtype=np.float64)
    hl_k = np.zeros(n_tok, dtype=np.float64)
    hl_stamp = np.zeros(n_tok, dtype=np.int16)
    recent = np.zeros(n_tok, dtype=np.int32)
    recent_ring: list[np.ndarray] = []
    knn_pub = np.full((n_tok, 10), -1, dtype=np.int16)
    knn_kev = np.full((n_tok, 10), -1, dtype=np.int16)
    knn_ptr = np.zeros(n_tok, dtype=np.int8)
    vend_n = np.zeros(n_vend, dtype=np.int32)
    vend_k = np.zeros(n_vend, dtype=np.int32)
    cpe_n = np.zeros(n_vend, dtype=np.int32)
    cpe_k = np.zeros(n_vend, dtype=np.int32)
    cpe_k_dirty = np.zeros(n_vend, dtype=np.int32)

    cohort_pos = {cid: i for i, cid in enumerate(feat["cve_id"])}
    n_feat = len(feat)
    col_names = [
        "g_closed_rate", "g_closed_support", "g_closed_n_tokens", "g_closed_fallback",
        "g_open2_rate", "g_open2_support", "g_open2_n_tokens", "g_open2_fallback",
        "g_open5_rate", "g_open5_support", "g_open5_n_tokens", "g_open5_fallback",
        "g_closed_days_since_kev", "g_closed_recent90", "g_closed_halflife_rate",
        "g_open2_days_since_kev", "g_open2_recent90", "g_open2_halflife_rate",
        "g_open5_days_since_kev", "g_open5_recent90", "g_open5_halflife_rate",
        "g_closed_sibling_rate", "g_closed_sibling_support", "g_closed_sibling_fallback",
        "g_open2_sibling_rate", "g_open2_sibling_support", "g_open2_sibling_fallback",
        "g_open5_sibling_rate", "g_open5_sibling_support", "g_open5_sibling_fallback",
        "g_closed_wm_count", "g_closed_wm_unique",
        "g_open2_wm_count", "g_open2_wm_unique",
        "g_open5_wm_count", "g_open5_wm_unique",
        "g_closed_knn_rate", "g_closed_knn_n",
        "g_open2_knn_rate", "g_open2_knn_n",
        "g_open5_knn_rate", "g_open5_knn_n",
        "g_dirty_closed_rate", "g_dirty_open2_rate", "g_dirty_open5_rate",
        "g_cpe_rate", "g_cpe_support", "g_cpe_fallback",
        "g_cpe_dirty_rate", "g_cpe_dirty_fallback",
        "g_best_tok_open2", "g_best_tok_open5", "g_best_tok_closed",
    ]
    store = {c: np.zeros(n_feat, dtype=np.float64) for c in col_names if not c.startswith("g_best")}
    best_tok = {c: np.array([""] * n_feat, dtype=object) for c in col_names if c.startswith("g_best")}
    store["g_closed_fallback"].fill(1)
    store["g_open2_fallback"].fill(1)
    store["g_open5_fallback"].fill(1)
    store["g_closed_sibling_fallback"].fill(1)
    store["g_open2_sibling_fallback"].fill(1)
    store["g_open5_sibling_fallback"].fill(1)
    store["g_cpe_fallback"].fill(1)
    store["g_cpe_dirty_fallback"].fill(1)
    store["g_closed_days_since_kev"].fill(9999)
    store["g_open2_days_since_kev"].fill(9999)
    store["g_open5_days_since_kev"].fill(9999)

    def select(token_ids, k_arr, n_arr, base, min_df, closed_only, tot_n):
        if token_ids.size == 0:
            return None
        n = n_arr[token_ids].astype(np.float64)
        k = k_arr[token_ids].astype(np.float64)
        keep = n >= min_df
        if closed_only:
            keep = keep & is_closed[token_ids]
        else:
            keep = keep & ~((n > HIGH_DF * tot_n) & (~is_closed[token_ids]))
        if not np.any(keep):
            return None
        n = n[keep]
        k = k[keep]
        kept = token_ids[keep]
        rate = (k + SMOOTH * base) / (n + SMOOTH)
        best_rate = rate.max()
        cand = np.flatnonzero(np.isclose(rate, best_rate))
        j = cand[int(np.argmax(n[cand]))]
        return kept, n, k, rate, int(j)

    tot_n = 0
    tot_k = 0
    cohort_rows_by_month: dict[str, list[int]] = defaultdict(list)
    for cid, m in zip(feat["cve_id"], feat["snapshot_month"]):
        if cid in id_index:
            cohort_rows_by_month[m].append(id_index[cid])

    missing = 0
    for m in months:
        base = tot_k / tot_n if tot_n else 0.0
        m_idx = month_index[m]
        if m in cohort_rows_by_month and tot_n > 0:
            for i in cohort_rows_by_month[m]:
                row = cohort_pos.get(cve_ids[i])
                if row is None:
                    missing += 1
                    continue
                toks = tok_flat[tok_off[i] : tok_off[i + 1]]
                specs = (
                    ("closed", 1, True),
                    ("open2", 2, False),
                    ("open5", 5, False),
                )
                chosen = {}
                for name, min_df, closed_only in specs:
                    sel = select(toks, tok_k, tok_n, base, min_df, closed_only, tot_n)
                    prefix = f"g_{name}"
                    if sel is None:
                        store[f"{prefix}_rate"][row] = base
                        store[f"{prefix}_fallback"][row] = 1
                        chosen[name] = None
                        continue
                    kept, n, k, rate, j = sel
                    store[f"{prefix}_rate"][row] = float(rate[j])
                    store[f"{prefix}_support"][row] = float(n[j])
                    store[f"{prefix}_n_tokens"][row] = float(len(kept))
                    store[f"{prefix}_fallback"][row] = 0
                    best_tok[f"g_best_tok_{name}"][row] = id_to_tok[int(kept[j])]
                    chosen[name] = (int(kept[j]), float(n[j]), float(k[j]), float(rate[j]))

                for name in ("closed", "open2", "open5"):
                    ch = chosen[name]
                    prefix = f"g_{name}"
                    if ch is None:
                        store[f"{prefix}_halflife_rate"][row] = base
                        store[f"{prefix}_knn_rate"][row] = base
                        store[f"{prefix}_sibling_rate"][row] = base
                        store[f"g_dirty_{name}_rate"][row] = base
                        continue
                    t, n_t, k_t, _ = ch
                    last = int(tok_last_kev[t])
                    if last >= 0:
                        store[f"{prefix}_days_since_kev"][row] = float((m_idx - last) * 30)
                    store[f"{prefix}_recent90"][row] = float(recent[t])
                    dt = max(0, m_idx - int(hl_stamp[t]))
                    factor = 0.5 ** (dt / HALF_LIFE_MONTHS)
                    hn = hl_n[t] * factor
                    hk = hl_k[t] * factor
                    store[f"{prefix}_halflife_rate"][row] = float((hk + SMOOTH * base) / (hn + SMOOTH))
                    # dirty label rate for this same token
                    dk = float(tok_k_dirty[t])
                    store[f"g_dirty_{name}_rate"][row] = float((dk + SMOOTH * base) / (n_t + SMOOTH))
                    tv = vendor_of_token(id_to_tok[t])
                    if tv is not None and ("t:" + tv) in vendor_to_id:
                        vi = vendor_to_id["t:" + tv]
                        sn = max(int(vend_n[vi]) - int(n_t), 0)
                        sk = max(int(vend_k[vi]) - int(k_t), 0)
                        store[f"{prefix}_sibling_support"][row] = float(sn)
                        store[f"{prefix}_sibling_rate"][row] = float((sk + SMOOTH * base) / (sn + SMOOTH))
                        store[f"{prefix}_sibling_fallback"][row] = 0 if sn > 0 else 1
                    else:
                        store[f"{prefix}_sibling_rate"][row] = base
                    wm = month_tok_count.get(pub_months[i], {})
                    wm_c = int(wm.get(t, 0)) if wm else 0
                    store[f"{prefix}_wm_count"][row] = float(wm_c)
                    store[f"{prefix}_wm_unique"][row] = 1.0 if wm_c == 1 else 0.0
                    pubs = knn_pub[t]
                    kevs = knn_kev[t]
                    valid = (pubs >= 0) & (pubs < m_idx)
                    if np.any(valid):
                        labels = valid & (kevs >= 0) & (kevs < m_idx)
                        store[f"{prefix}_knn_n"][row] = float(valid.sum())
                        store[f"{prefix}_knn_rate"][row] = float(labels.sum() / valid.sum())
                    else:
                        store[f"{prefix}_knn_rate"][row] = base

                # CPE leak features. Edge is the Nov 2026 snapshot.
                cpe_ids = cve_cpe_ids[i]
                if cpe_ids:
                    ns = cpe_n[cpe_ids].astype(np.float64)
                    ks = cpe_k[cpe_ids].astype(np.float64)
                    rate = (ks + SMOOTH * base) / (ns + SMOOTH)
                    j = int(np.argmax(rate))
                    store["g_cpe_rate"][row] = float(rate[j])
                    store["g_cpe_support"][row] = float(ns[j])
                    store["g_cpe_fallback"][row] = 0.0
                    dks = cpe_k_dirty[cpe_ids].astype(np.float64)
                    drate = (dks + SMOOTH * base) / (ns + SMOOTH)
                    store["g_cpe_dirty_rate"][row] = float(drate.max())
                    store["g_cpe_dirty_fallback"][row] = 0.0
                else:
                    store["g_cpe_rate"][row] = base
                    store["g_cpe_dirty_rate"][row] = base

        # Apply this month's publications, then this month's KEV additions.
        # Counts are vectorized per month. The 10-neighbor ring stays per CVE so
        # the neighbors are the most recent publications of that token.
        if m in by_pub:
            pub_idxs = by_pub[m]
            tok_parts = []
            dirty_parts = []
            for i in pub_idxs:
                sl = tok_flat[tok_off[i] : tok_off[i + 1]]
                if sl.size:
                    tok_parts.append(sl)
                    if kev_months[i] is not None:
                        dirty_parts.append(sl)
                    ptrs = knn_ptr[sl]
                    knn_pub[sl, ptrs] = m_idx
                    knn_kev[sl, ptrs] = month_index[kev_months[i]] if kev_months[i] else -1
                    knn_ptr[sl] = (ptrs + 1) % 10
                for vi in cve_vendor_ids[i]:
                    vend_n[vi] += 1
                for vi in cve_cpe_ids[i]:
                    cpe_n[vi] += 1
                    if kev_months[i] is not None:
                        cpe_k_dirty[vi] += 1
            tot_n += len(pub_idxs)
            if tok_parts:
                all_toks = np.concatenate(tok_parts)
                uniq, counts = np.unique(all_toks, return_counts=True)
                tok_n[uniq] += counts.astype(np.int32)
                dt = np.maximum(0, m_idx - hl_stamp[uniq])
                factor = np.power(0.5, dt / HALF_LIFE_MONTHS)
                hl_n[uniq] = hl_n[uniq] * factor + counts
                hl_k[uniq] = hl_k[uniq] * factor
                hl_stamp[uniq] = m_idx
            if dirty_parts:
                dirty_toks = np.concatenate(dirty_parts)
                uniq_d, counts_d = np.unique(dirty_toks, return_counts=True)
                tok_k_dirty[uniq_d] += counts_d.astype(np.int32)
        if m in by_kev:
            kev_idxs = [i for i in by_kev[m] if pub_months[i] <= m]
            tok_parts = []
            for i in kev_idxs:
                sl = tok_flat[tok_off[i] : tok_off[i + 1]]
                if sl.size:
                    tok_parts.append(sl)
                for vi in cve_vendor_ids[i]:
                    vend_k[vi] += 1
                for vi in cve_cpe_ids[i]:
                    cpe_k[vi] += 1
            tot_k += len(kev_idxs)
            inc = np.zeros(n_tok, dtype=np.int32)
            if tok_parts:
                all_toks = np.concatenate(tok_parts)
                uniq, counts = np.unique(all_toks, return_counts=True)
                counts_i = counts.astype(np.int32)
                tok_k[uniq] += counts_i
                tok_last_kev[uniq] = np.int16(m_idx)
                dt = np.maximum(0, m_idx - hl_stamp[uniq])
                factor = np.power(0.5, dt / HALF_LIFE_MONTHS)
                hl_n[uniq] = hl_n[uniq] * factor
                hl_k[uniq] = hl_k[uniq] * factor + counts
                hl_stamp[uniq] = np.int16(m_idx)
                inc[uniq] = counts_i
            if len(recent_ring) == RECENT_WINDOW:
                recent -= recent_ring.pop(0)
            recent_ring.append(inc)
            recent += inc

    print(
        f"      graph features attached in {time.time() - t0:.1f}s "
        f"(history CVEs={tot_n:,}, history KEVs visible at end={tot_k:,}, missing cohort rows={missing})",
        flush=True,
    )
    out = feat.copy()
    for c, arr in store.items():
        out[c] = arr
    for c, arr in best_tok.items():
        out[c] = arr
    return out


TIER_A_EXCLUDE = {"txt_oof_tfidf_prob"}


def tier_a_columns(df: pd.DataFrame) -> list[str]:
    cols = []
    for c in df.columns:
        if c in TIER_A_EXCLUDE:
            continue
        if c.startswith(("sig_", "time_", "cna_", "txt_")):
            cols.append(c)
    return cols


def fit_config(df: pd.DataFrame, tr_mask: np.ndarray, te_mask: np.ndarray, cols: list[str], seeds=SEEDS) -> dict:
    y_tr = df.loc[tr_mask, "target_kev"].to_numpy(dtype=np.int32)
    y_te = df.loc[te_mask, "target_kev"].to_numpy(dtype=np.int32)
    ids = df.loc[te_mask, "cve_id"].to_numpy()
    wp = df.loc[te_mask, "cna_is_wordpress"].to_numpy()
    X_tr = df.loc[tr_mask, cols].to_numpy(dtype=np.float64)
    X_te = df.loc[te_mask, cols].to_numpy(dtype=np.float64)
    runs = []
    importances = None
    for seed in seeds:
        scores = lgbm_predict(X_tr, y_tr, X_te, seed)
        summary = ranking_summary(y_te, scores, ids)
        summary["wordpress_in_top250"] = int(wp[summary.pop("_top250_idx")].sum())
        runs.append(summary)
        if seed == SEEDS[0]:
            importances = getattr(lgbm_predict, "importances", None)
            runs[-1]["_scores"] = scores
    agg = aggregate_seeds(runs)
    if importances is not None:
        order = np.argsort(-importances)
        agg["top_importances_seed0"] = [
            {"feature": cols[int(i)], "split_count": int(importances[int(i)])} for i in order[:12]
        ]
    agg["_scores_seed0"] = runs[0].pop("_scores")
    agg["n_train"] = int(tr_mask.sum())
    agg["n_train_pos"] = int(y_tr.sum())
    agg["n_test"] = int(te_mask.sum())
    agg["n_test_pos"] = int(y_te.sum())
    return agg


def coverage_table(df: pd.DataFrame, year: str) -> dict:
    sub = df[df["published"].str.startswith(year)]
    pos = sub[sub["target_kev"] == 1]
    neg = sub[sub["target_kev"] == 0]

    def pack(frame: pd.DataFrame, prefix: str) -> dict:
        matched = frame[f"g_{prefix}_fallback"].to_numpy() == 0
        prior = matched & (frame[f"g_{prefix}_rate"].to_numpy() > 0)
        # A matched token can have a shrunk rate near the base rate with k=0.
        # Use support>0 and rate above an impossible floor: k>=1 iff rate > SMOOTH*base/(n+SMOOTH)
        # which is not recoverable here. Store nothing else; approximate with
        # "matched and support>=min and the recorded rate is not a pure fallback".
        # prior-KEV is computed below from a dedicated column if present.
        return {
            "rows": int(len(frame)),
            "matched": int(matched.sum()),
            "matched_frac": round(float(matched.mean()) if len(frame) else 0.0, 4),
        }

    out = {}
    for prefix in ("closed", "open2", "open5"):
        out[prefix] = {"positives": pack(pos, prefix), "negatives": pack(neg, prefix)}
        # slice among positives
        slices = {}
        for sl, g in pos.groupby("slice", sort=False):
            slices[str(sl)] = pack(g, prefix)
        out[prefix]["positive_slices"] = slices
    return out


def annotate_ids(df: pd.DataFrame, cve_ids: list[str], prefix: str) -> list[dict]:
    rows = []
    indexed = df.set_index("cve_id", drop=False)
    for cid in cve_ids:
        if cid not in indexed.index:
            rows.append({"cve_id": cid})
            continue
        r = indexed.loc[cid]
        if isinstance(r, pd.DataFrame):
            r = r.iloc[0]
        rows.append(
            {
                "cve_id": cid,
                "slice": str(r["slice"]),
                "assigner": str(r["assigner"]),
                "published": str(r["published"])[:10],
                "best_token": str(r[f"g_best_tok_{prefix}"]),
                "rate": round(float(r[f"g_{prefix}_rate"]), 5),
                "support": int(r[f"g_{prefix}_support"]),
                "fallback": int(r[f"g_{prefix}_fallback"]),
                "sibling_rate": round(float(r[f"g_{prefix}_sibling_rate"]), 5),
                "recent90": int(r[f"g_{prefix}_recent90"]),
            }
        )
    return rows


def low_support_hits(
    df_te: pd.DataFrame, scores: np.ndarray, support: np.ndarray, fallback: np.ndarray, y: np.ndarray
) -> dict:
    order = np.argsort(-scores, kind="mergesort")
    top = order[:25]
    low = (fallback == 0) & (support < 5)
    pos = y == 1
    pos_low = pos & low
    in_top = np.zeros(len(y), dtype=bool)
    in_top[top] = True
    ranks = np.empty(len(y), dtype=np.int32)
    ranks[order] = np.arange(1, len(y) + 1)
    return {
        "positives_low_support": int(pos_low.sum()),
        "low_support_positives_in_top25": int((pos_low & in_top).sum()),
        "mean_rank_low_support_positives": (
            round(float(ranks[pos_low].mean()), 1) if pos_low.any() else None
        ),
    }


def main():
    t_start = time.time()
    tables = load_graph_tables()
    df = build_features(tables)
    # Attach assigner text for reporting. Feature matrix does not carry it.
    assigner_of = dict(zip(tables["cve_ids"], tables["assigners"]))
    df["assigner"] = df["cve_id"].map(assigner_of).fillna("")
    df["slice"] = [
        slice_name(int(e), int(m), int(v), int(w))
        for e, m, v, w in zip(
            df["cna_is_enterprise"], df["cna_is_mitre"], df["cna_is_vdb_bounty"], df["cna_is_wordpress"]
        )
    ]
    hist_n = np.expm1(df["cna_hist_cves_log"].to_numpy(dtype=np.float64))
    df["assigner_informative"] = (
        (df["cna_is_enterprise"].to_numpy() == 1) | (hist_n >= 10)
    ).astype(int)

    te_preview = df[df["published"].str.startswith("2025")]
    pos_preview = te_preview[te_preview["target_kev"] == 1]
    print(
        "      2025 fallback fractions "
        f"closed={te_preview['g_closed_fallback'].mean():.3f} "
        f"open2={te_preview['g_open2_fallback'].mean():.3f} "
        f"open5={te_preview['g_open5_fallback'].mean():.3f} "
        f"cpe={te_preview['g_cpe_fallback'].mean():.3f}",
        flush=True,
    )
    print(
        "      2025 KEV matched "
        f"closed={(pos_preview['g_closed_fallback']==0).sum()}/{len(pos_preview)} "
        f"open2={(pos_preview['g_open2_fallback']==0).sum()}/{len(pos_preview)} "
        f"open5={(pos_preview['g_open5_fallback']==0).sum()}/{len(pos_preview)}",
        flush=True,
    )
    print("[4/4] Fitting LightGBM configurations...", flush=True)
    base_cols = tier_a_columns(df)
    # Graph columns must not already be inside Tier A. They use a g_ prefix.
    assert not any(c.startswith("g_") for c in base_cols)

    is_2024 = df["published"].str.startswith("2024").to_numpy()
    is_2025 = df["published"].str.startswith("2025").to_numpy()
    h1 = df["snapshot_month"].between("2024-01", "2024-08").to_numpy()
    h2 = df["snapshot_month"].between("2024-09", "2024-12").to_numpy()

    vocab_cols = {
        "closed": ["g_closed_rate", "g_closed_support", "g_closed_n_tokens", "g_closed_fallback"],
        "open2": ["g_open2_rate", "g_open2_support", "g_open2_n_tokens", "g_open2_fallback"],
        "open5": ["g_open5_rate", "g_open5_support", "g_open5_n_tokens", "g_open5_fallback"],
    }
    recency_cols = {}
    sibling_cols = {}
    wm_cols = {}
    knn_cols = {}
    for name in ("closed", "open2", "open5"):
        recency_cols[name] = [
            f"g_{name}_days_since_kev", f"g_{name}_recent90", f"g_{name}_halflife_rate",
        ]
        sibling_cols[name] = [
            f"g_{name}_sibling_rate", f"g_{name}_sibling_support", f"g_{name}_sibling_fallback",
        ]
        wm_cols[name] = [f"g_{name}_wm_count", f"g_{name}_wm_unique"]
        knn_cols[name] = [f"g_{name}_knn_rate", f"g_{name}_knn_n"]

    # --- Experiment 1: coverage (no model) ---
    coverage = {"2024": coverage_table(df, "2024"), "2025": coverage_table(df, "2025")}
    # Prior-KEV coverage: a matched row whose best token has been a KEV.
    # days_since < 9999 means tok_last_kev was set, i.e. k>=1 at some point before the month.
    for year in ("2024", "2025"):
        sub = df[df["published"].str.startswith(year) & (df["target_kev"] == 1)]
        for prefix in ("closed", "open2", "open5"):
            matched = sub[f"g_{prefix}_fallback"].to_numpy() == 0
            had_kev = matched & (sub[f"g_{prefix}_days_since_kev"].to_numpy() < 9999)
            coverage[year][prefix]["positives"]["matched_with_prior_kev"] = int(had_kev.sum())
            slices = {}
            for sl, g in sub.groupby("slice"):
                mm = g[f"g_{prefix}_fallback"].to_numpy() == 0
                hk = mm & (g[f"g_{prefix}_days_since_kev"].to_numpy() < 9999)
                slices[str(sl)] = {"matched": int(mm.sum()), "matched_with_prior_kev": int(hk.sum()), "rows": int(len(g))}
            coverage[year][prefix]["positive_slices_prior_kev"] = slices

    # Nonzero 90-day mass.
    te = df[is_2025]
    recent_nonzero = {}
    for prefix in ("closed", "open2", "open5"):
        recent_nonzero[f"{prefix}_frac_rows"] = round(float((te[f"g_{prefix}_recent90"] > 0).mean()), 4)
        recent_nonzero[f"{prefix}_frac_positives"] = round(
            float((te.loc[te.target_kev == 1, f"g_{prefix}_recent90"] > 0).mean()), 4
        )

    # --- Experiment 2 selection on 2024 H2, one seed ---
    print("      selecting vocabulary on 2024-09..12", flush=True)
    h2_runs = {}
    h2_runs["baseline"] = fit_config(df, h1, h2, base_cols, seeds=(0,))
    for name, cols in vocab_cols.items():
        h2_runs[name] = fit_config(df, h1, h2, base_cols + cols, seeds=(0,))
    # Selection: highest hits@25, then PR-AUC, among graph configs. Baseline is the reference.
    def rank_key(name):
        r = h2_runs[name]
        return (r["hits@25_by_seed"][0], r["pr_auc_by_seed"][0])

    selected = max(vocab_cols, key=rank_key)
    baseline_h2_hits = h2_runs["baseline"]["hits@25_by_seed"][0]
    selected_beats_h2 = h2_runs[selected]["hits@25_by_seed"][0] >= baseline_h2_hits + 1

    # --- 2025 evaluations, 3 seeds ---
    print(f"      2025 evaluation, selected vocabulary={selected}", flush=True)
    results_2025 = {}
    results_2025["baseline_tier_a"] = fit_config(df, is_2024, is_2025, base_cols)
    for name, cols in vocab_cols.items():
        print(f"        one-hop {name}", flush=True)
        results_2025[f"onehop_{name}"] = fit_config(df, is_2024, is_2025, base_cols + cols)

    sel = selected
    print("        recency, sibling, within-month, knn, leaks", flush=True)
    results_2025["recency"] = fit_config(
        df, is_2024, is_2025, base_cols + vocab_cols[sel] + recency_cols[sel]
    )
    results_2025["sibling"] = fit_config(
        df, is_2024, is_2025, base_cols + vocab_cols[sel] + sibling_cols[sel]
    )
    results_2025["within_month"] = fit_config(
        df, is_2024, is_2025, base_cols + vocab_cols[sel] + wm_cols[sel]
    )
    results_2025["onehop_recency_sibling_wm"] = fit_config(
        df, is_2024, is_2025, base_cols + vocab_cols[sel] + recency_cols[sel] + sibling_cols[sel] + wm_cols[sel]
    )
    results_2025["knn"] = fit_config(
        df, is_2024, is_2025, base_cols + vocab_cols[sel] + knn_cols[sel]
    )
    results_2025["leak_cpe_timecut"] = fit_config(
        df, is_2024, is_2025, base_cols + ["g_cpe_rate", "g_cpe_support", "g_cpe_fallback"]
    )
    results_2025["leak_cpe_dirty"] = fit_config(
        df, is_2024, is_2025, base_cols + ["g_cpe_dirty_rate", "g_cpe_dirty_fallback"]
    )
    results_2025["leak_ref_domain_frozen"] = fit_config(
        df, is_2024, is_2025, base_cols + ["ref_domain_max_kev_rate"]
    )
    results_2025["leak_product_dirty"] = fit_config(
        df, is_2024, is_2025, base_cols + [f"g_dirty_{sel}_rate"] + vocab_cols[sel]
    )

    # Experiment 3: assigner prior vs product rate, with and without the rest of Tier A.
    print("        assigner vs product", flush=True)
    results_2025["assigner_prior_only"] = fit_config(df, is_2024, is_2025, ["cna_kev_prior_rate"])
    results_2025["product_rate_only"] = fit_config(df, is_2024, is_2025, vocab_cols[sel])
    results_2025["assigner_plus_product"] = fit_config(
        df, is_2024, is_2025, ["cna_kev_prior_rate"] + vocab_cols[sel]
    )

    # Drop bulky score vectors before JSON, but keep seed-0 scores for slice stats.
    score_cache = {}
    for key, payload in list(results_2025.items()):
        score_cache[key] = payload.pop("_scores_seed0")
    for payload in h2_runs.values():
        payload.pop("_scores_seed0", None)

    te_df = df.loc[is_2025].reset_index(drop=True)
    y_te = te_df["target_kev"].to_numpy()
    support = te_df[f"g_{sel}_support"].to_numpy()
    fallback = te_df[f"g_{sel}_fallback"].to_numpy()
    low_stats = {
        "onehop": low_support_hits(te_df, score_cache[f"onehop_{sel}"], support, fallback, y_te),
        "sibling": low_support_hits(te_df, score_cache["sibling"], support, fallback, y_te),
    }
    # Uninformative-slice membership of stable top-25 hits.
    uninf = set(te_df.loc[te_df["assigner_informative"] == 0, "cve_id"])
    def uninf_count(ids):
        return sorted(cid for cid in ids if cid in uninf)

    deltas = {}
    base_stable = results_2025["baseline_tier_a"]
    for key, payload in results_2025.items():
        if key == "baseline_tier_a":
            continue
        deltas[key] = stable_delta(base_stable, payload)
        detail_prefix = "closed" if "closed" in key else sel
        deltas[key]["gained_detail"] = annotate_ids(df, deltas[key]["gained"], detail_prefix)
        deltas[key]["lost_detail"] = annotate_ids(df, deltas[key]["lost"], detail_prefix)
        deltas[key]["gained_uninformative_assigner"] = uninf_count(deltas[key]["gained"])
        deltas[key]["lost_uninformative_assigner"] = uninf_count(deltas[key]["lost"])

    # Spearman of the chosen product rate vs the assigner prior on 2025.
    spear = spearmanr(te_df[f"g_{sel}_rate"], te_df["cna_kev_prior_rate"])
    spear_uninf = spearmanr(
        te_df.loc[te_df.assigner_informative == 0, f"g_{sel}_rate"],
        te_df.loc[te_df.assigner_informative == 0, "cna_kev_prior_rate"],
    )

    # Neural-graph gate.
    onehop_stable = results_2025[f"onehop_{sel}"]["stable_hits@25"]
    sibling_stable = results_2025["sibling"]["stable_hits@25"]
    neural_gate = {
        "trained": False,
        "reason": (
            "Sibling stable top-25 hits beat the one-hop rate by at least 2, so a neural aggregator would be the next experiment."
            if sibling_stable >= onehop_stable + 2
            else "Sibling stable top-25 hits do not beat the one-hop rate by 2. A message-passing layer is not trained."
        ),
        "onehop_stable_hits@25": onehop_stable,
        "sibling_stable_hits@25": sibling_stable,
    }

    def slim(payload: dict) -> dict:
        return {k: v for k, v in payload.items() if k != "top_importances_seed0"}

    report = {
        "protocol": {
            "tier": "Tier A numeric columns plus causal txt_temp_tfidf_prob. Raw assigner id is not a categorical feature.",
            "train_2025_eval": "published in 2024",
            "test_2025_eval": "published in 2025, features frozen at snapshot_month",
            "vocab_selection": "fit 2024-01..2024-08, choose vocabulary on 2024-09..2024-12 by hits@25 then PR-AUC, seed 0",
            "seeds": list(SEEDS),
            "stable_hit": "positive CVE in the top 25 for at least 2 of 3 seeds",
            "smoothing": SMOOTH,
            "high_df_fraction": HIGH_DF,
            "half_life_months": HALF_LIFE_MONTHS,
            "selected_vocabulary": sel,
            "selected_beats_2024h2_baseline_by_1_hit": bool(selected_beats_h2),
            "positives": {"2024_h1": int(df.loc[h1, "target_kev"].sum()), "2024_h2": int(df.loc[h2, "target_kev"].sum()), "2025": int(y_te.sum())},
        },
        "experiment_1_coverage": coverage,
        "experiment_4_recency_mass": recent_nonzero,
        "experiment_2_h2_selection_seed0": {k: slim(v) | {"hits@25": v["hits@25_by_seed"][0], "pr_auc": v["pr_auc_by_seed"][0]} for k, v in h2_runs.items()},
        "experiment_2025": {k: slim(v) for k, v in results_2025.items()},
        "importances_seed0": {
            k: results_2025[k].get("top_importances_seed0")
            for k in (f"onehop_{sel}", "recency", "sibling", "leak_cpe_dirty", "leak_product_dirty")
        },
        "deltas_vs_baseline_stable_top25": deltas,
        "experiment_3_spearman_product_vs_assigner": {
            "all_2025": {"correlation": round(float(spear.correlation), 4), "pvalue": float(spear.pvalue)},
            "uninformative_assigner_2025": {
                "correlation": round(float(spear_uninf.correlation), 4),
                "pvalue": float(spear_uninf.pvalue),
                "rows": int((te_df.assigner_informative == 0).sum()),
            },
        },
        "experiment_5_low_support": low_stats,
        "experiment_8_neural_gate": neural_gate,
        "runtime_seconds": round(time.time() - t_start, 1),
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "temporal_graph_experiments.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Wrote {out_path}", flush=True)

    print("\n=== 2024 H2 selection (seed 0) ===", flush=True)
    for k, v in h2_runs.items():
        print(f"  {k:16} hits@25={v['hits@25_by_seed'][0]:2d}  PR-AUC={v['pr_auc_by_seed'][0]:.4f}", flush=True)
    print(f"selected={sel} beats_h2={selected_beats_h2}", flush=True)
    print("\n=== 2025 mean over 3 seeds ===", flush=True)
    for k, v in results_2025.items():
        d = deltas.get(k)
        extra = ""
        if d:
            extra = f"  stable {v['stable_hits@25']:2d}  gained {d['gained_n']} lost {d['lost_n']}"
        print(
            f"  {k:28} hits@25={v['mean_hits@25']:.2f} {v['hits@25_by_seed']}  "
            f"PR-AUC={v['mean_pr_auc']:.4f}{extra}",
            flush=True,
        )
    print("neural:", neural_gate["reason"], flush=True)
    print(f"Total runtime: {time.time() - t_start:.1f}s", flush=True)


if __name__ == "__main__":
    main()
