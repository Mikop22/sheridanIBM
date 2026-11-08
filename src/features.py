#!/usr/bin/env python3
"""
Feature Engineering Pipeline for Vulnerability Exploitation (KEV) Prediction.

Builds a comprehensive, modular feature matrix for:
  1. The 2024-2025 Scoreboard-Analogue Training/Validation Cohort (CVEs published
     Jan 2024 - Nov 2025 that were NOT yet in CISA KEV at the end of their
     snapshot_month, matched to their point-in-time exploit signals).
  2. The 2026 Scoreboard Benchmark Cohort (`scoreboard_2026.csv`, 72,670 rows).

All historical prior encodings (Assigner, CWE, Reference Domain, CPE Vendor/Product,
and TF-IDF text probabilities) are computed strictly without temporal or target leakage:
  - Prior tables use expanding historical windows (only CVEs published before the
    target cohort's snapshot month, plus historical pre-2024 data).
  - Two TF-IDF text features are produced:
      * `txt_oof_tfidf_prob`  : 5-fold Stratified CV out-of-fold probability
      * `txt_temp_tfidf_prob` : Strictly causal probability (trained only on pre-2024
                                for 2024 rows, and pre-2025 for 2025 rows) for the
                                2024 -> 2025 temporal split evaluation.
  - Columns are explicitly tagged by safety tier:
      * `sig_*`  : [SAFE] Point-in-time EPSS & exploit flags at snapshot_month
      * `time_*` : [SAFE] Publication, reservation lag, snapshot window, and burst metrics
      * `cna_*`  : [SAFE] Assigner (CNA) category & historical KEV/EPSS priors
      * `txt_*`  : [SAFE] NLP keyword flags, vendor/product entity regex, & TF-IDF scores
      * `cwe_*`  : [SAFE/GREY] CWE multiplicity, MITRE abstraction/kind, & historical KEV priors
      * `cvss_*` : [GREY] CVSS v3 & v4 scores, parsed vectors, & composite flags
      * `ref_*`  : [GREY] Reference URL/domain pattern flags & domain historical KEV priors
      * `leak_*` : [LEAKY-2026] Post-publication NIST triage status, CPE counts, reference tags,
                   and Nov 2026 modification dates (isolated for ablation studies)
"""

import calendar
import csv
import math
import os
import re
import time
from collections import Counter, defaultdict
from datetime import date

import numpy as np
import pandas as pd
from scipy.sparse import vstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold

DATA_DIR = os.environ.get("CVE_DATA_DIR", "/tmp/data")
OUT_DIR = os.environ.get("CVE_OUT_DIR", "/tmp/features")


def parse_date(d_str: str) -> date:
    return date(int(d_str[0:4]), int(d_str[5:7]), int(d_str[8:10]))


def month_end_date(ym_str: str) -> date:
    y, m = int(ym_str[0:4]), int(ym_str[5:7])
    last_day = calendar.monthrange(y, m)[1]
    return date(y, m, last_day)


def is_near_patch_tuesday(d: date) -> int:
    """Return 1 if date is on or within +2 days of the 2nd Tuesday of the month."""
    first_day = date(d.year, d.month, 1)
    offset = (1 - first_day.weekday()) % 7
    second_tuesday_day = 1 + offset + 7
    return 1 if second_tuesday_day <= d.day <= second_tuesday_day + 2 else 0


KW_RCE = re.compile(
    r"\b(remote code execution|rce|arbitrary code|arbitrary command|command injection|"
    r"os command|execute arbitrary|code execution|arbitrary shell)\b",
    re.I,
)
KW_AUTH_BYPASS = re.compile(
    r"\b(authentication bypass|auth bypass|unauthenticated|without authentication|"
    r"pre-auth|preauth|improper authentication|missing authentication|bypass authentication|"
    r"hardcoded credential|default credential|default password)\b",
    re.I,
)
KW_PRIV_ESC = re.compile(
    r"\b(privilege escalation|elevate privileges|gain root|root privileges|"
    r"system privileges|local privilege|elevation of privilege)\b",
    re.I,
)
KW_MEM_CORR = re.compile(
    r"\b(use-after-free|use after free|out-of-bounds write|buffer overflow|"
    r"heap-based buffer|stack-based buffer|type confusion|integer overflow|"
    r"memory corruption|double free)\b",
    re.I,
)
KW_DESERIAL_TRAVERSAL = re.compile(
    r"\b(deserialization|deserialize|untrusted data|path traversal|directory traversal|"
    r"arbitrary file upload|arbitrary file write|arbitrary file read|file inclusion|"
    r"server-side request forgery|ssrf|xml external entity|xxe)\b",
    re.I,
)
KW_SQLI = re.compile(r"\b(sql injection|sqli|blind sql)\b", re.I)
KW_XSS_CSRF = re.compile(
    r"\b(cross-site scripting|xss|cross-site request forgery|csrf|open redirect)\b",
    re.I,
)
KW_DOS_LOW = re.compile(
    r"\b(denial of service|denial-of-service|\bdos\b|null pointer dereference|"
    r"out-of-bounds read|application crash|infinite loop)\b",
    re.I,
)
KW_URGENCY_WILD = re.compile(
    r"(actively exploited|in the wild|zero-day|0-day|unsupported when assigned)",
    re.I,
)
KW_APPLIANCE_EDGE = re.compile(
    r"\b(firewall|vpn|gateway|router|hypervisor|load balancer|management interface|"
    r"ssl vpn|wan|webmail|firmware|appliance|domain controller|active directory)\b",
    re.I,
)
KW_WORDPRESS = re.compile(r"\b(wordpress|wp-|woocommerce|elementor)\b", re.I)
KW_CODE_PATH = re.compile(
    r"(\.(php|jsp|aspx|asp|cgi|dll|sys|exe|sh|py|jar)\b|/[a-z0-9_-]+/[a-z0-9_.-]+)",
    re.I,
)

TOP_TARGET_ENTITIES = re.compile(
    r"\b(windows|microsoft exchange|sharepoint|win32k|internet explorer|edge|"
    r"ios|macos|ipados|webkit|safari|chrome|chromium|v8|android|pixel|"
    r"cisco ios|asa|adaptive security|anyconnect|firepower|"
    r"ivanti|connect secure|pulse connect|endpoint manager|avalanche|"
    r"fortios|fortigate|fortiproxy|fortimanager|fortisiem|"
    r"pan-os|globalprotect|palo alto|"
    r"vmware|vcenter|esxi|nsx|workspace one|aria|"
    r"citrix|netscaler|adc|"
    r"weblogic|e-business suite|peoplesoft|java se|"
    r"coldfusion|acrobat|commerce|magento|"
    r"confluence|jira|bitbucket|bamboo|"
    r"gitlab|teamcity|jenkins|roundcube|zimbra|owncloud|nextcloud|"
    r"sonicwall|sra|sma|zyxel|qnap|synology|d-link|netgear|mikrotik|tp-link|"
    r"f5|big-ip|juniper|junos|barracuda|check point|sophos|watchguard|"
    r"apache http|struts|log4j|activemq|tomcat|ofbiz|superset|hugegraph|"
    r"spring framework|spring cloud|linux kernel|openssh|sudo|exim)\b",
    re.I,
)

ENTERPRISE_ASSIGNERS = (
    "microsoft",
    "apple",
    "cisco",
    "google",
    "fortinet",
    "ivanti",
    "paloalto",
    "vmware",
    "oracle",
    "adobe",
    "citrix",
    "juniper",
    "f5.com",
    "redhat",
    "sonicwall",
    "zyxel",
    "qnap",
    "dlink",
    "atlassian",
)
WORDPRESS_ASSIGNERS = ("patchstack", "wordfence", "wpscan")
VDB_BOUNTY_ASSIGNERS = ("vuldb", "huntr", "zerodayinitiative", "vulncheck", "github")

TOP_KEV_CWES = [
    "CWE-20",
    "CWE-78",
    "CWE-787",
    "CWE-416",
    "CWE-119",
    "CWE-22",
    "CWE-502",
    "CWE-94",
    "CWE-843",
    "CWE-264",
    "CWE-287",
    "CWE-79",
    "CWE-89",
    "CWE-918",
    "CWE-434",
    "CWE-284",
    "CWE-125",
    "CWE-190",
    "CWE-306",
    "CWE-798",
]


def load_all_raw_data():
    t0 = time.time()
    print("[1/5] Loading raw CSV tables from", DATA_DIR)

    cwe_meta = {}
    with open(os.path.join(DATA_DIR, "weakness_types.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cwe_meta[r["cwe_id"]] = {
                "kind": r["kind"],
                "abstraction": r["abstraction"] or "BLANK",
            }

    kev_dict = {}
    with open(os.path.join(DATA_DIR, "known_exploited.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            kev_dict[r["cve_id"]] = {
                "date_added": r["date_added"],
                "ransomware": 1 if r["known_ransomware_use"] == "Known" else 0,
            }

    scoreboard_rows = {}
    with open(os.path.join(DATA_DIR, "scoreboard_2026.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            scoreboard_rows[r["cve_id"]] = r

    vulns = {}
    with open(os.path.join(DATA_DIR, "vulnerabilities.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            vulns[r["cve_id"]] = r

    print(
        f"      Loaded {len(vulns):,} vulns, {len(kev_dict):,} KEVs, "
        f"{len(scoreboard_rows):,} scoreboard_2026 rows in {time.time() - t0:.1f}s"
    )
    return cwe_meta, kev_dict, scoreboard_rows, vulns


def build_cohorts_and_signals(vulns, kev_dict, scoreboard_rows):
    t0 = time.time()
    print("[2/5] Matching 2024-2025 monthly exploit signals to build Scoreboard-Analogue cohort...")

    cand_24_25 = {}
    for cid, v in vulns.items():
        pub = v["published"]
        if "2024-01-01" <= pub <= "2025-11-30":
            pm = pub[:7]
            cand_24_25[cid] = pm

    pub_signals = {}
    fallback_25_03 = {}
    monthly_epss_values = defaultdict(list)

    for fn in ("exploit_signals_2024.csv", "exploit_signals_2025.csv"):
        path = os.path.join(DATA_DIR, fn)
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                m = r["month"]
                cid = r["cve_id"]
                if r["epss"]:
                    monthly_epss_values[m].append(float(r["epss"]))
                pm = cand_24_25.get(cid)
                if pm is not None:
                    if m == pm:
                        pub_signals[cid] = r
                    elif pm == "2025-02" and m == "2025-03":
                        fallback_25_03[cid] = r

    for cid, r in scoreboard_rows.items():
        if r["epss"]:
            monthly_epss_values[r["snapshot_month"]].append(float(r["epss"]))

    month_epss_sorted = {
        m: np.sort(np.array(vals, dtype=np.float64))
        for m, vals in monthly_epss_values.items()
    }

    train_cohort = []
    for cid, pm in cand_24_25.items():
        v = vulns[cid]
        kev_info = kev_dict.get(cid)
        if cid in pub_signals:
            sig = pub_signals[cid]
            snap_m = pm
        elif pm == "2025-02" and cid in fallback_25_03:
            sig = fallback_25_03[cid]
            snap_m = "2025-03"
        else:
            sig = {
                "month": pm,
                "cve_id": cid,
                "epss": "",
                "in_kev": "0",
                "exploitdb": "0",
                "metasploit": "0",
                "nuclei": "0",
                "poc_github": "0",
            }
            snap_m = pm

        if sig.get("in_kev") == "1":
            continue
        if kev_info and kev_info["date_added"][:7] <= snap_m:
            continue

        y = 1 if kev_info is not None else 0
        train_cohort.append(
            {
                "cve_id": cid,
                "published": v["published"],
                "snapshot_month": snap_m,
                "epss": sig["epss"],
                "exploitdb": sig["exploitdb"],
                "metasploit": sig["metasploit"],
                "nuclei": sig["nuclei"],
                "poc_github": sig["poc_github"],
                "target_kev": y,
                "date_added": kev_info["date_added"] if kev_info else "",
                "split_group": "train_24_25",
            }
        )

    train_cohort.sort(key=lambda x: (x["published"], x["cve_id"]))

    test_2026_cohort = []
    for cid, r in scoreboard_rows.items():
        test_2026_cohort.append(
            {
                "cve_id": cid,
                "published": r["published"],
                "snapshot_month": r["snapshot_month"],
                "epss": r["epss"],
                "exploitdb": r["exploitdb"],
                "metasploit": r["metasploit"],
                "nuclei": r["nuclei"],
                "poc_github": r["poc_github"],
                "target_kev": -1,
                "date_added": "",
                "split_group": "scoreboard_2026",
            }
        )
    test_2026_cohort.sort(key=lambda x: (x["published"], x["cve_id"]))

    pos_cnt = sum(x["target_kev"] for x in train_cohort)
    print(
        f"      Built 2024-2025 cohort: {len(train_cohort):,} CVEs ({pos_cnt} post-snapshot KEVs, "
        f"{pos_cnt / len(train_cohort) * 100:.3f}%) and 2026 scoreboard: {len(test_2026_cohort):,} CVEs "
        f"in {time.time() - t0:.1f}s"
    )
    return train_cohort, test_2026_cohort, month_epss_sorted


def aggregate_references_and_cpes(vulns, kev_dict):
    t0 = time.time()
    print("[3/5] Aggregating references.csv (1.36M rows) and affected_products.csv (3.16M rows)...")

    hist_cves = {}
    for cid, v in vulns.items():
        pub = v["published"]
        if pub < "2024-01-01":
            is_k = 1 if (cid in kev_dict and kev_dict[cid]["date_added"] < "2024-01-01") else 0
            hist_cves[cid] = is_k

    hist_base_rate = sum(hist_cves.values()) / max(len(hist_cves), 1)

    ref_domains_per_cve = defaultdict(list)
    ref_flags_per_cve = defaultdict(lambda: [0, 0, 0, 0, 0, 0, 0])

    domain_hist_total = Counter()
    domain_hist_kev = Counter()

    re_commit = re.compile(r"(/commit/|/pull/|/issues/|/blob/|git\.kernel\.org)", re.I)
    re_exploit_url = re.compile(
        r"(exploit-db\.com|packetstorm|0day\.today|metasploit|nuclei-templates|/poc|exploit)",
        re.I,
    )
    re_major_vendor_dom = re.compile(
        r"(microsoft\.com|apple\.com|cisco\.com|adobe\.com|oracle\.com|fortiguard\.com|"
        r"ivanti\.com|paloaltonetworks\.com|vmware\.com|google\.com|android\.com|kb\.cert\.org)",
        re.I,
    )
    re_sec_news_dom = re.compile(
        r"(bleepingcomputer\.com|thehackernews\.com|rapid7\.com|mandiant\.com|crowdstrike\.com|"
        r"unit42|securelist\.com|talosintelligence\.com|cisa\.gov|securityweek\.com|darkreading\.com)",
        re.I,
    )

    with open(os.path.join(DATA_DIR, "references.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["cve_id"]
            dom = r["domain"]
            url = r["url"]
            tags = r["tags"]

            ref_domains_per_cve[cid].append(dom)
            fl = ref_flags_per_cve[cid]
            if re_commit.search(url):
                fl[0] = 1
            if re_exploit_url.search(url):
                fl[1] = 1
            if re_major_vendor_dom.search(dom):
                fl[2] = 1
            if re_sec_news_dom.search(dom):
                fl[3] = 1
            if tags:
                fl[6] = 1
                if "Exploit" in tags:
                    fl[4] = 1
                if "Patch" in tags or "Vendor Advisory" in tags:
                    fl[5] = 1

    for cid, doms in ref_domains_per_cve.items():
        if cid in hist_cves:
            is_k = hist_cves[cid]
            for d in set(doms):
                domain_hist_total[d] += 1
                if is_k:
                    domain_hist_kev[d] += 1

    cpe_stats_per_cve = defaultdict(lambda: [0, 0, 0, 0, 0, 0])
    cpe_vendors_per_cve = defaultdict(set)

    vendor_hist_total = Counter()
    vendor_hist_kev = Counter()

    with open(os.path.join(DATA_DIR, "affected_products.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["cve_id"]
            st = cpe_stats_per_cve[cid]
            if r["vulnerable"] == "Y":
                st[0] += 1
                tp = r["type"]
                if tp == "operating_system":
                    st[2] = 1
                elif tp == "hardware":
                    st[3] = 1
                elif tp == "application":
                    st[4] = 1
                if (
                    r["version_start_including"]
                    or r["version_start_excluding"]
                    or r["version_end_including"]
                    or r["version_end_excluding"]
                ):
                    st[5] = 1
                cpe_vendors_per_cve[cid].add(r["vendor"])
            else:
                st[1] += 1

    for cid, vends in cpe_vendors_per_cve.items():
        if cid in hist_cves:
            is_k = hist_cves[cid]
            for vnd in vends:
                vendor_hist_total[vnd] += 1
                if is_k:
                    vendor_hist_kev[vnd] += 1

    print(f"      Aggregated references and CPEs in {time.time() - t0:.1f}s")
    return (
        hist_base_rate,
        ref_domains_per_cve,
        ref_flags_per_cve,
        domain_hist_total,
        domain_hist_kev,
        cpe_stats_per_cve,
        cpe_vendors_per_cve,
        vendor_hist_total,
        vendor_hist_kev,
    )


def parse_cvss4_vector(vec: str):
    if not vec:
        return 0, 0, 0, 0, 0
    av_net = 1 if "/AV:N" in vec else 0
    ac_low = 1 if "/AC:L" in vec else 0
    at_none = 1 if "/AT:N" in vec else 0
    pr_none = 1 if "/PR:N" in vec else 0
    ui_none = 1 if "/UI:N" in vec else 0
    return av_net, ac_low, at_none, pr_none, ui_none


def build_feature_matrices(
    cwe_meta,
    kev_dict,
    vulns,
    train_cohort,
    test_2026_cohort,
    month_epss_sorted,
    hist_base_rate,
    ref_domains_per_cve,
    ref_flags_per_cve,
    domain_hist_total,
    domain_hist_kev,
    cpe_stats_per_cve,
    cpe_vendors_per_cve,
    vendor_hist_total,
    vendor_hist_kev,
):
    t0 = time.time()
    print("[4/5] Computing expanding historical priors, burst statistics, and NLP features...")

    pub_day_counts = Counter()
    pub_day_assigner_counts = Counter()
    for cid, v in vulns.items():
        p = v["published"]
        a = v["assigner"]
        pub_day_counts[p] += 1
        pub_day_assigner_counts[(p, a)] += 1

    all_cves_sorted = []
    for cid, v in vulns.items():
        pub_m = v["published"][:7]
        da = kev_dict[cid]["date_added"][:7] if cid in kev_dict else "9999-99"
        cwes = [c for c in v["cwe_ids"].split(";") if c] if v["cwe_ids"] else []
        all_cves_sorted.append((pub_m, da, v["assigner"], cwes))
    all_cves_sorted.sort(key=lambda x: x[0])

    target_months = sorted(
        set(r["snapshot_month"] for r in train_cohort)
        | set(r["snapshot_month"] for r in test_2026_cohort)
    )

    assigner_priors_by_month = {}
    cwe_priors_by_month = {}

    for tm in target_months:
        a_tot = Counter()
        a_kev = Counter()
        c_tot = Counter()
        c_kev = Counter()
        tot_n = 0
        tot_k = 0
        for pub_m, da, ass, cwes in all_cves_sorted:
            if pub_m >= tm:
                break
            tot_n += 1
            is_k = 1 if da < tm else 0
            tot_k += is_k
            a_tot[ass] += 1
            if is_k:
                a_kev[ass] += 1
            for c in cwes:
                c_tot[c] += 1
                if is_k:
                    c_kev[c] += 1
        base_r = tot_k / max(tot_n, 1)
        assigner_priors_by_month[tm] = (a_tot, a_kev, base_r)
        cwe_priors_by_month[tm] = (c_tot, c_kev, base_r)

    print("      Fitting TF-IDF + L2 Logistic text models (5-fold OOF and causal temporal)...")
    pre24_pos_texts = []
    pre24_neg_texts = []
    for cid, v in vulns.items():
        if "2018-01-01" <= v["published"] < "2024-01-01":
            is_k = 1 if (cid in kev_dict and kev_dict[cid]["date_added"] < "2024-01-01") else 0
            if is_k:
                pre24_pos_texts.append(v["description"])
            elif hash(cid) % 8 == 0:
                pre24_neg_texts.append(v["description"])

    train_texts = [vulns[r["cve_id"]]["description"] for r in train_cohort]
    train_y = np.array([r["target_kev"] for r in train_cohort], dtype=np.int32)
    is_2024_mask = np.array([r["published"].startswith("2024") for r in train_cohort])
    is_2025_mask = np.array([r["published"].startswith("2025") for r in train_cohort])
    test_2026_texts = [vulns[r["cve_id"]]["description"] for r in test_2026_cohort]

    tfidf = TfidfVectorizer(
        max_features=25000,
        ngram_range=(1, 2),
        min_df=5,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    all_fit_texts = pre24_pos_texts + pre24_neg_texts + train_texts
    X_all_tfidf = tfidf.fit_transform(all_fit_texts)
    n_pre24 = len(pre24_pos_texts) + len(pre24_neg_texts)
    X_pre24_tfidf = X_all_tfidf[:n_pre24]
    y_pre24 = np.array(
        [1] * len(pre24_pos_texts) + [0] * len(pre24_neg_texts), dtype=np.int32
    )
    X_train_tfidf = X_all_tfidf[n_pre24:]
    X_test_2026_tfidf = tfidf.transform(test_2026_texts)

    # 1. 5-Fold Stratified OOF text probabilities
    oof_text_prob = np.zeros(len(train_cohort), dtype=np.float64)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for tr_idx, val_idx in skf.split(X_train_tfidf, train_y):
        X_tr_fold = vstack([X_pre24_tfidf, X_train_tfidf[tr_idx]])
        y_tr_fold = np.concatenate([y_pre24, train_y[tr_idx]])
        clf_txt = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300)
        clf_txt.fit(X_tr_fold, y_tr_fold)
        oof_text_prob[val_idx] = clf_txt.predict_proba(X_train_tfidf[val_idx])[:, 1]

    # 2. Strictly Causal Temporal text probabilities (for 2024 -> 2025 temporal split)
    temp_text_prob = np.zeros(len(train_cohort), dtype=np.float64)
    clf_pre24_only = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300)
    clf_pre24_only.fit(X_pre24_tfidf, y_pre24)
    temp_text_prob[is_2024_mask] = clf_pre24_only.predict_proba(
        X_train_tfidf[is_2024_mask]
    )[:, 1]

    clf_pre25 = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300)
    clf_pre25.fit(
        vstack([X_pre24_tfidf, X_train_tfidf[is_2024_mask]]),
        np.concatenate([y_pre24, train_y[is_2024_mask]]),
    )
    temp_text_prob[is_2025_mask] = clf_pre25.predict_proba(
        X_train_tfidf[is_2025_mask]
    )[:, 1]

    # 3. Full text model for 2026 scoreboard predictions
    clf_txt_full = LogisticRegression(C=1.0, class_weight="balanced", max_iter=300)
    clf_txt_full.fit(
        vstack([X_pre24_tfidf, X_train_tfidf]), np.concatenate([y_pre24, train_y])
    )
    test_2026_text_prob = clf_txt_full.predict_proba(X_test_2026_tfidf)[:, 1]

    def extract_row_features(cohort_list, text_probs_oof, text_probs_temp):
        rows_out = []
        prior_smooth = 20.0

        for idx, item in enumerate(cohort_list):
            cid = item["cve_id"]
            v = vulns[cid]
            snap_m = item["snapshot_month"]
            pub_str = item["published"]
            pub_d = parse_date(pub_str)
            snap_end_d = month_end_date(snap_m)

            epss_str = item["epss"]
            epss_missing = 1 if not epss_str else 0
            epss_raw = float(epss_str) if epss_str else 0.0
            epss_clipped = min(max(epss_raw, 1e-6), 1.0 - 1e-6)
            epss_log10 = math.log10(epss_clipped)
            epss_logit = math.log(epss_clipped / (1.0 - epss_clipped))

            m_arr = month_epss_sorted.get(snap_m)
            if m_arr is not None and len(m_arr) > 0 and not epss_missing:
                rank_idx = np.searchsorted(m_arr, epss_raw, side="right")
                epss_pct_rank = float(rank_idx) / float(len(m_arr))
            else:
                epss_pct_rank = 0.0

            edb = 1 if item["exploitdb"] == "1" else 0
            msf = 1 if item["metasploit"] == "1" else 0
            nuc = 1 if item["nuclei"] == "1" else 0
            poc = 1 if item["poc_github"] == "1" else 0
            flag_sum = edb + msf + nuc + poc
            any_flag = 1 if flag_sum > 0 else 0
            weaponized = 1 if (msf == 1 or nuc == 1) else 0

            parts = cid.split("-")
            cve_id_year = int(parts[1]) if len(parts) >= 3 and parts[1].isdigit() else pub_d.year
            cve_id_seq = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
            res_lag_years = max(-1, min(20, pub_d.year - cve_id_year))
            days_to_snap_end = max(0, (snap_end_d - pub_d).days)
            patch_tue = is_near_patch_tuesday(pub_d)
            same_day_all = pub_day_counts[pub_str]
            same_day_ass = pub_day_assigner_counts[(pub_str, v["assigner"])]

            ass = v["assigner"]
            ass_low = ass.lower()
            is_ent_cna = 1 if any(k in ass_low for k in ENTERPRISE_ASSIGNERS) else 0
            is_wp_cna = 1 if any(k in ass_low for k in WORDPRESS_ASSIGNERS) else 0
            is_vdb_cna = 1 if any(k in ass_low for k in VDB_BOUNTY_ASSIGNERS) else 0
            is_mitre_cna = 1 if ass == "cve@mitre.org" else 0

            a_tot, a_kev, base_r = assigner_priors_by_month[snap_m]
            cna_hist_n = a_tot[ass]
            cna_hist_k = a_kev[ass]
            cna_kev_rate = (cna_hist_k + prior_smooth * base_r) / (cna_hist_n + prior_smooth)

            desc = v["description"] or ""
            desc_len = len(desc)
            desc_words = len(desc.split())
            kw_rce = 1 if KW_RCE.search(desc) else 0
            kw_auth = 1 if KW_AUTH_BYPASS.search(desc) else 0
            kw_priv = 1 if KW_PRIV_ESC.search(desc) else 0
            kw_mem = 1 if KW_MEM_CORR.search(desc) else 0
            kw_deser = 1 if KW_DESERIAL_TRAVERSAL.search(desc) else 0
            kw_sqli = 1 if KW_SQLI.search(desc) else 0
            kw_xss = 1 if KW_XSS_CSRF.search(desc) else 0
            kw_dos = 1 if KW_DOS_LOW.search(desc) else 0
            kw_wild = 1 if KW_URGENCY_WILD.search(desc) else 0
            kw_edge = 1 if KW_APPLIANCE_EDGE.search(desc) else 0
            kw_wp = 1 if KW_WORDPRESS.search(desc) else 0
            kw_path = 1 if KW_CODE_PATH.search(desc) else 0
            kw_target_ent = len(set(m.lower() for m in TOP_TARGET_ENTITIES.findall(desc)))

            has_cvss3 = 1 if v["cvss3_score"] else 0
            cvss3_score = float(v["cvss3_score"]) if has_cvss3 else 0.0
            cvss3_exp = float(v["cvss3_exploitability_score"]) if v["cvss3_exploitability_score"] else 0.0
            cvss3_imp = float(v["cvss3_impact_score"]) if v["cvss3_impact_score"] else 0.0

            sev_map = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            cvss3_sev_ord = sev_map.get(v["cvss3_severity"], -1)

            av_net = 1 if v["attack_vector"] == "NETWORK" else 0
            av_loc = 1 if v["attack_vector"] == "LOCAL" else 0
            ac_low = 1 if v["attack_complexity"] == "LOW" else 0
            pr_none = 1 if v["privileges_required"] == "NONE" else 0
            pr_low = 1 if v["privileges_required"] == "LOW" else 0
            ui_none = 1 if v["user_interaction"] == "NONE" else 0
            scope_chg = 1 if v["scope"] == "CHANGED" else 0

            imp_map = {"NONE": 0, "LOW": 1, "HIGH": 2}
            c_imp = imp_map.get(v["confidentiality_impact"], 0)
            i_imp = imp_map.get(v["integrity_impact"], 0)
            a_imp = imp_map.get(v["availability_impact"], 0)
            cia_sum = c_imp + i_imp + a_imp
            goldilocks_v3 = 1 if (av_net and ac_low and pr_none and ui_none) else 0

            has_cvss4 = 1 if v["cvss4_score"] else 0
            cvss4_score = float(v["cvss4_score"]) if has_cvss4 else 0.0
            v4_net, v4_acl, v4_atn, v4_prn, v4_uin = parse_cvss4_vector(v["cvss4_vector"])
            goldilocks_v4 = 1 if (v4_net and v4_acl and v4_atn and v4_prn and v4_uin) else 0

            unified_cvss = cvss3_score if has_cvss3 else (cvss4_score if has_cvss4 else 0.0)
            has_any_cvss = 1 if (has_cvss3 or has_cvss4) else 0
            unified_net = 1 if (av_net or v4_net) else 0
            unified_goldilocks = 1 if (goldilocks_v3 or goldilocks_v4) else 0

            cwe_list = [c for c in v["cwe_ids"].split(";") if c] if v["cwe_ids"] else []
            n_cwes = len(cwe_list)
            cwe_missing = 1 if n_cwes == 0 else 0
            c_tot, c_kev, c_base_r = cwe_priors_by_month[snap_m]

            cwe_rates = []
            cwe_cnts = []
            has_pillar = 0
            has_class = 0
            has_base = 0
            has_variant = 0
            for c in cwe_list:
                cn = c_tot[c]
                ck = c_kev[c]
                cwe_rates.append((ck + prior_smooth * c_base_r) / (cn + prior_smooth))
                cwe_cnts.append(ck)
                meta = cwe_meta.get(c)
                if meta:
                    ab = meta["abstraction"]
                    if ab == "Pillar":
                        has_pillar = 1
                    elif ab == "Class":
                        has_class = 1
                    elif ab == "Base":
                        has_base = 1
                    elif ab == "Variant":
                        has_variant = 1

            cwe_max_rate = max(cwe_rates) if cwe_rates else c_base_r
            cwe_sum_kevs = sum(cwe_cnts) if cwe_cnts else 0

            doms = ref_domains_per_cve.get(cid, [])
            n_refs = int(v["n_references"] or 0)
            n_uniq_doms = len(set(doms))
            r_fl = ref_flags_per_cve[cid]

            dom_rates = [
                (domain_hist_kev[d] + prior_smooth * hist_base_rate)
                / (domain_hist_total[d] + prior_smooth)
                for d in set(doms)
            ]
            dom_max_rate = max(dom_rates) if dom_rates else hist_base_rate

            st = v["nvd_status"]
            leak_status_analyzed = 1 if st == "Analyzed" else 0
            leak_status_modified = 1 if st == "Modified" else 0
            leak_status_deferred = 1 if st == "Deferred" else 0
            leak_status_unanalyzed = 1 if st in ("Awaiting Analysis", "Received", "Undergoing Analysis") else 0

            leak_cvss_src_nist = 1 if v["cvss3_source"] == "nvd@nist.gov" else 0
            leak_cvss_src_cisa = 1 if v["cvss3_source"] == "134c704f-9b21-4f2e-91b3-4a467353bcc0" else 0
            leak_cwe_nvd_placeholder = (
                1 if ("NVD-CWE-noinfo" in cwe_list or "NVD-CWE-Other" in cwe_list) else 0
            )

            cpe_st = cpe_stats_per_cve[cid]
            leak_n_cpes = int(v["n_affected_cpes"] or 0)
            leak_has_cpes = 1 if leak_n_cpes > 0 else 0
            leak_cpe_vuln_y = cpe_st[0]
            leak_cpe_vuln_n = cpe_st[1]
            leak_cpe_has_os = cpe_st[2]
            leak_cpe_has_hw = cpe_st[3]
            leak_cpe_has_range = cpe_st[5]

            vends = cpe_vendors_per_cve.get(cid, set())
            vend_rates = [
                (vendor_hist_kev[vnd] + prior_smooth * hist_base_rate)
                / (vendor_hist_total[vnd] + prior_smooth)
                for vnd in vends
            ]
            leak_cpe_vendor_max_rate = max(vend_rates) if vend_rates else hist_base_rate

            mod_d = parse_date(v["last_modified"])
            leak_days_pub_to_mod = (mod_d - pub_d).days

            row_dict = {
                "cve_id": cid,
                "published": pub_str,
                "snapshot_month": snap_m,
                "target_kev": item["target_kev"],
                "sig_epss_raw": epss_raw,
                "sig_epss_missing": epss_missing,
                "sig_epss_log10": epss_log10,
                "sig_epss_logit": epss_logit,
                "sig_epss_pct_rank": epss_pct_rank,
                "sig_epss_gt_005": 1 if epss_raw >= 0.005 else 0,
                "sig_epss_gt_01": 1 if epss_raw >= 0.01 else 0,
                "sig_epss_gt_05": 1 if epss_raw >= 0.05 else 0,
                "sig_epss_gt_10": 1 if epss_raw >= 0.10 else 0,
                "sig_exploitdb": edb,
                "sig_metasploit": msf,
                "sig_nuclei": nuc,
                "sig_poc_github": poc,
                "sig_flag_sum": flag_sum,
                "sig_any_flag": any_flag,
                "sig_weaponized": weaponized,
                "sig_epss_x_flag": epss_pct_rank * any_flag,
                "sig_epss_x_nuclei": epss_pct_rank * nuc,
                "time_cve_id_seq_log": math.log1p(max(0, cve_id_seq)),
                "time_res_lag_years": res_lag_years,
                "time_is_same_year_id": 1 if res_lag_years == 0 else 0,
                "time_is_prior_year_id": 1 if res_lag_years == 1 else 0,
                "time_days_to_snap_end": days_to_snap_end,
                "time_pub_month": pub_d.month,
                "time_patch_tuesday": patch_tue,
                "time_same_day_cves_log": math.log1p(same_day_all),
                "time_same_day_assigner_log": math.log1p(same_day_ass),
                "cna_is_enterprise": is_ent_cna,
                "cna_is_wordpress": is_wp_cna,
                "cna_is_vdb_bounty": is_vdb_cna,
                "cna_is_mitre": is_mitre_cna,
                "cna_hist_cves_log": math.log1p(cna_hist_n),
                "cna_hist_kevs_log": math.log1p(cna_hist_k),
                "cna_kev_prior_rate": cna_kev_rate,
                "txt_desc_len_log": math.log1p(desc_len),
                "txt_desc_words_log": math.log1p(desc_words),
                "txt_kw_rce": kw_rce,
                "txt_kw_auth_bypass": kw_auth,
                "txt_kw_priv_esc": kw_priv,
                "txt_kw_mem_corr": kw_mem,
                "txt_kw_deserial_trav": kw_deser,
                "txt_kw_sqli": kw_sqli,
                "txt_kw_xss_csrf": kw_xss,
                "txt_kw_dos": kw_dos,
                "txt_kw_wild_unsupported": kw_wild,
                "txt_kw_appliance_edge": kw_edge,
                "txt_kw_wordpress": kw_wp,
                "txt_kw_code_path": kw_path,
                "txt_target_entity_matches": kw_target_ent,
                "txt_oof_tfidf_prob": float(text_probs_oof[idx]),
                "txt_temp_tfidf_prob": float(text_probs_temp[idx]),
                "cvss_has_v3": has_cvss3,
                "cvss_v3_score": cvss3_score,
                "cvss_v3_exploitability": cvss3_exp,
                "cvss_v3_impact": cvss3_imp,
                "cvss_v3_sev_ord": cvss3_sev_ord,
                "cvss_v3_av_network": av_net,
                "cvss_v3_av_local": av_loc,
                "cvss_v3_ac_low": ac_low,
                "cvss_v3_pr_none": pr_none,
                "cvss_v3_pr_low": pr_low,
                "cvss_v3_ui_none": ui_none,
                "cvss_v3_scope_changed": scope_chg,
                "cvss_v3_cia_sum": cia_sum,
                "cvss_v3_goldilocks": goldilocks_v3,
                "cvss_has_v4": has_cvss4,
                "cvss_v4_score": cvss4_score,
                "cvss_v4_goldilocks": goldilocks_v4,
                "cvss_unified_score": unified_cvss,
                "cvss_has_any": has_any_cvss,
                "cvss_unified_network": unified_net,
                "cvss_unified_goldilocks": unified_goldilocks,
                "cwe_count": n_cwes,
                "cwe_missing": cwe_missing,
                "cwe_max_kev_rate": cwe_max_rate,
                "cwe_sum_hist_kevs_log": math.log1p(cwe_sum_kevs),
                "cwe_abs_pillar": has_pillar,
                "cwe_abs_class": has_class,
                "cwe_abs_base": has_base,
                "cwe_abs_variant": has_variant,
                "ref_count_log": math.log1p(n_refs),
                "ref_uniq_domains": n_uniq_doms,
                "ref_url_commit_pr": r_fl[0],
                "ref_url_exploit_poc": r_fl[1],
                "ref_url_major_vendor": r_fl[2],
                "ref_url_sec_news": r_fl[3],
                "ref_domain_max_kev_rate": dom_max_rate,
                "leak_status_analyzed": leak_status_analyzed,
                "leak_status_modified": leak_status_modified,
                "leak_status_deferred": leak_status_deferred,
                "leak_status_unanalyzed": leak_status_unanalyzed,
                "leak_cvss_src_nist": leak_cvss_src_nist,
                "leak_cvss_src_cisa": leak_cvss_src_cisa,
                "leak_cwe_nvd_placeholder": leak_cwe_nvd_placeholder,
                "leak_ref_tag_exploit": r_fl[4],
                "leak_ref_tag_patch_adv": r_fl[5],
                "leak_ref_has_any_tag": r_fl[6],
                "leak_n_cpes_log": math.log1p(leak_n_cpes),
                "leak_has_cpes": leak_has_cpes,
                "leak_cpe_vuln_y_log": math.log1p(leak_cpe_vuln_y),
                "leak_cpe_vuln_n_log": math.log1p(leak_cpe_vuln_n),
                "leak_cpe_has_os": leak_cpe_has_os,
                "leak_cpe_has_hw": leak_cpe_has_hw,
                "leak_cpe_has_range": leak_cpe_has_range,
                "leak_cpe_vendor_max_kev_rate": leak_cpe_vendor_max_rate,
                "leak_days_pub_to_mod": leak_days_pub_to_mod,
            }

            cwe_set = set(cwe_list)
            for top_cwe in TOP_KEV_CWES:
                col_name = f"cwe_is_{top_cwe.replace('-', '_')}"
                row_dict[col_name] = 1 if top_cwe in cwe_set else 0

            rows_out.append(row_dict)

        return pd.DataFrame(rows_out)

    df_train = extract_row_features(train_cohort, oof_text_prob, temp_text_prob)
    df_test_2026 = extract_row_features(test_2026_cohort, test_2026_text_prob, test_2026_text_prob)

    os.makedirs(OUT_DIR, exist_ok=True)
    train_path = os.path.join(OUT_DIR, "features_train_2024_2025.csv")
    test_path = os.path.join(OUT_DIR, "features_scoreboard_2026.csv")
    df_train.to_csv(train_path, index=False)
    df_test_2026.to_csv(test_path, index=False)

    print(
        f"[5/5] Saved feature matrices in {time.time() - t0:.1f}s:\n"
        f"      - {train_path}: {df_train.shape[0]:,} rows x {df_train.shape[1]} columns\n"
        f"      - {test_path}: {df_test_2026.shape[0]:,} rows x {df_test_2026.shape[1]} columns"
    )
    return df_train, df_test_2026


def main():
    t_start = time.time()
    cwe_meta, kev_dict, scoreboard_rows, vulns = load_all_raw_data()
    train_cohort, test_2026_cohort, month_epss_sorted = build_cohorts_and_signals(
        vulns, kev_dict, scoreboard_rows
    )
    (
        hist_base_rate,
        ref_domains_per_cve,
        ref_flags_per_cve,
        domain_hist_total,
        domain_hist_kev,
        cpe_stats_per_cve,
        cpe_vendors_per_cve,
        vendor_hist_total,
        vendor_hist_kev,
    ) = aggregate_references_and_cpes(vulns, kev_dict)

    build_feature_matrices(
        cwe_meta,
        kev_dict,
        vulns,
        train_cohort,
        test_2026_cohort,
        month_epss_sorted,
        hist_base_rate,
        ref_domains_per_cve,
        ref_flags_per_cve,
        domain_hist_total,
        domain_hist_kev,
        cpe_stats_per_cve,
        cpe_vendors_per_cve,
        vendor_hist_total,
        vendor_hist_kev,
    )
    print(f"Total feature engineering runtime: {time.time() - t_start:.1f}s")


if __name__ == "__main__":
    main()
