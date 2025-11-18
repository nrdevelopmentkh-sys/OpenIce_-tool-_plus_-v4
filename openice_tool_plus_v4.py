#!/usr/bin/env python3
"""
OpenICE Tool Plus v4 — Professional Multi-Report Generator
Features:
 - Batch import (CSV/JSON) of targets
 - Multi-format outputs: JSON evidence + Telegram TXT + GitHub MD
 - Case auto-numbering and folder structure
 - SHA256 hashing for attachments (if provided)
 - Classification (porn, malware, scam, spam, impersonation)
 - Optional: Create GitHub Issue (requires PAT); must confirm interactively
 - Logging of operations

Usage:
  python openice_tool_plus_v4.py --input sample_targets.csv
  python openice_tool_plus_v4.py --input sample_targets.json --auto --github-token YOUR_TOKEN
"""

import os
import csv
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
import requests
import sys

# -------------------------
# Configuration defaults
# -------------------------
OUTPUT_BASE = Path("reports")
LOGS = Path("logs")
LOGS.mkdir(exist_ok=True)
OUTPUT_BASE.mkdir(exist_ok=True)

CASE_COUNTER_FILE = OUTPUT_BASE / ".case_counter"
DEFAULT_GITHUB_API = "https://api.github.com"

# -------------------------
# Keyword sets for classification
# -------------------------
CLASS_KEYWORDS = {
    "sexual": ["porn", "nsfw", "sex", "nude", "sexual", "explicit"],
    "malware": [".apk", "malware", "trojan", "virus", "payload", "exploit"],
    "spam": ["spam", "join my channel", "buy now", "advert", "promotion"],
    "scam": ["scam", "fraud", "investment", "earn money", "get rich"],
    "impersonation": ["impostor", "impersonat", "fake profile", "clone"],
}

# -------------------------
# Utilities
# -------------------------
def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {msg}"
    print(entry)
    with open(LOGS / "openice_v4.log", "a", encoding="utf-8") as fh:
        fh.write(entry + "\n")

def read_case_counter():
    if CASE_COUNTER_FILE.exists():
        try:
            n = int(CASE_COUNTER_FILE.read_text(encoding="utf-8").strip())
            return n
        except:
            return 0
    return 0

def write_case_counter(n):
    CASE_COUNTER_FILE.write_text(str(n), encoding="utf-8")

def next_case_id(prefix="case"):
    n = read_case_counter() + 1
    write_case_counter(n)
    stamp = datetime.utcnow().strftime("%Y%m%d")
    return f"{prefix}_{stamp}_{n:03d}"

def sha256_of_file(path):
    p = Path(path)
    if not p.exists():
        return None
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def classify_evidence(evidence_list):
    text = " ".join(evidence_list).lower()
    scores = {k: 0 for k in CLASS_KEYWORDS}
    for k, kws in CLASS_KEYWORDS.items():
        for kw in kws:
            if kw in text:
                scores[k] += 1
    # choose top classification by score
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top, top_score = sorted_scores[0]
    if top_score == 0:
        return "unknown"
    # transform some names
    mapping = {
        "sexual": "sexual_content",
        "malware": "malware_distribution",
        "spam": "spam_promotion",
        "scam": "scam_fraud",
        "impersonation": "impersonation"
    }
    return mapping.get(top, top)

def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

# -------------------------
# Input parsers
# -------------------------
def load_csv_targets(path):
    """
    Expect CSV with headers:
    target,platform,type,evidence_list (semicolon separated), attachments (semicolon separated)
    example:
    https://t.me/flairsupporting,telegram,channel,"https://t.me/flairsupporting/188;https://t.me/flairsupporting/189","screens/1.jpg;screens/2.jpg"
    """
    targets = []
    with open(path, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            evid = [s.strip() for s in (row.get("evidence_list") or "").split(";") if s.strip()]
            atts = [s.strip() for s in (row.get("attachments") or "").split(";") if s.strip()]
            targets.append({
                "target": row.get("target") or "",
                "platform": row.get("platform") or "telegram",
                "type": row.get("type") or "channel",
                "evidence": evid,
                "attachments": atts,
                "notes": row.get("notes") or ""
            })
    return targets

def load_json_targets(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # expected format: {"targets":[{...}, ...]}
    return data.get("targets", data)  # support both list or wrapper

# -------------------------
# Report builders
# -------------------------
def build_telegram_text(case_id, target):
    lines = []
    lines.append(f"Subject: Abuse Report – {case_id} – {target.get('target')}")
    lines.append("")
    lines.append("Hello Telegram Trust & Safety,")
    lines.append("")
    lines.append("I would like to report the following entity which appears to violate Telegram's Terms of Service.")
    lines.append("")
    lines.append(f"Target: {target.get('target')}")
    lines.append(f"Platform: {target.get('platform')}")
    lines.append(f"Type: {target.get('type')}")
    cls = target.get("classification")
    if cls:
        lines.append(f"Classification: {cls}")
    lines.append("")
    lines.append("Evidence / Links:")
    for e in target.get("evidence", []):
        lines.append(f" - {e}")
    lines.append("")
    if target.get("attachments"):
        lines.append("Attachments (local paths):")
        for a in target.get("attachments", []):
            lines.append(f" - {a} (sha256: {target.get('attachments_hashes',{}).get(a)})")
    if target.get("notes"):
        lines.append("")
        lines.append("Notes:")
        lines.append(target.get("notes"))
    lines.append("")
    lines.append("I confirm I did NOT download any suspicious files; this report is based on observed posts and screenshots.")
    lines.append("")
    lines.append("Please investigate and take appropriate action.")
    lines.append("")
    lines.append("Sincerely,")
    lines.append("OpenICE Reporting")
    lines.append("")
    return "\n".join(lines)

def build_github_md(case_id, target):
    md = []
    md.append(f"# 🚨 OpenICE Abuse Report — {case_id}")
    md.append("")
    md.append(f"**Target**: {target.get('target')}")
    md.append(f"**Platform**: {target.get('platform')}")
    md.append(f"**Type**: {target.get('type')}")
    if target.get("classification"):
        md.append(f"**Classification**: `{target.get('classification')}`")
    md.append("")
    md.append("## Evidence")
    for e in target.get("evidence", []):
        md.append(f"- {e}")
    if target.get("attachments"):
        md.append("")
        md.append("## Attachments (local)")
        for a in target.get("attachments", []):
            md.append(f"- {a} (sha256: `{target.get('attachments_hashes',{}).get(a)}`)")
    if target.get("notes"):
        md.append("")
        md.append("## Notes")
        md.append(target.get("notes"))
    md.append("")
    md.append("**Generated by OpenICE Tool Plus v4**")
    return "\n".join(md)

def build_evidence_json(case_id, target):
    out = {
        "case_id": case_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target.get("target"),
        "platform": target.get("platform"),
        "type": target.get("type"),
        "classification": target.get("classification"),
        "evidence": target.get("evidence", []),
        "attachments": [],
        "notes": target.get("notes","")
    }
    for a in target.get("attachments", []):
        out["attachments"].append({
            "path": a,
            "sha256": target.get("attachments_hashes",{}).get(a)
        })
    return out

# -------------------------
# GitHub helper
# -------------------------
def create_github_issue(owner_repo, title, body, token):
    """
    owner_repo: "owner/repo"
    token: personal access token with repo scope (issues)
    """
    url = f"{DEFAULT_GITHUB_API}/repos/{owner_repo}/issues"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {"title": title, "body": body}
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code in (200,201):
        return r.json()
    else:
        return {"error": r.status_code, "text": r.text}

# -------------------------
# Core processing
# -------------------------
def process_targets(targets, case_id, output_dir, github_owner_repo=None, github_token=None, auto_push=False):
    case_dir = safe_mkdir(output_dir / case_id)
    save_dir = safe_mkdir(case_dir / "evidence")
    results = []
    for t in targets:
        # normalize fields
        t = dict(t)  # copy
        t.setdefault("evidence", [])
        t.setdefault("attachments", [])
        # compute attachment hashes
        a_hashes = {}
        for a in t["attachments"]:
            h = sha256_of_file(a)
            a_hashes[a] = h
        t["attachments_hashes"] = a_hashes
        # classification
        t["classification"] = classify_evidence(t["evidence"])
        # build files
        telegram_text = build_telegram_text(case_id, t)
        github_md = build_github_md(case_id, t)
        evidence_json = build_evidence_json(case_id, t)
        # filenames (safe)
        safe_name = (t.get("target") or "target").replace("http://","").replace("https://","").replace("/","_").replace(":", "_")
        # write files
        txt_path = case_dir / f"{safe_name}_telegram_report.txt"
        md_path = case_dir / f"{safe_name}_github_issue.md"
        json_path = case_dir / f"{safe_name}_evidence.json"
        txt_path.write_text(telegram_text, encoding="utf-8")
        md_path.write_text(github_md, encoding="utf-8")
        json_path.write_text(json.dumps(evidence_json, indent=2, ensure_ascii=False), encoding="utf-8")
        # copy attachments info (we don't copy files automatically, just list)
        results.append({
            "target": t.get("target"),
            "platform": t.get("platform"),
            "type": t.get("type"),
            "txt": str(txt_path),
            "md": str(md_path),
            "json": str(json_path),
            "classification": t["classification"],
            "attachment_hashes": a_hashes
        })
        log(f"Generated reports for target: {t.get('target')} -> {txt_path.name}, {md_path.name}, {json_path.name}")

        # Optionally create GitHub issue
        if github_owner_repo and github_token and auto_push:
            title = f"OpenICE Abuse Report — {t.get('target')}"
            body = github_md + f"\n\n_Auto-generated by OpenICE Tool Plus v4 — case: {case_id}_"
            resp = create_github_issue(github_owner_repo, title, body, github_token)
            if isinstance(resp, dict) and resp.get("error"):
                log(f"GitHub issue creation failed for {t.get('target')}: {resp.get('error')} {resp.get('text')}")
            else:
                issue_url = resp.get("html_url")
                log(f"GitHub issue created: {issue_url}")
                # append issue url to md file
                md_path.write_text(github_md + f"\n\n**GitHub Issue:** {issue_url}\n", encoding="utf-8")

    # write summary
    summary = {
        "case_id": case_id,
        "generated_at": datetime.utcnow().isoformat()+"Z",
        "targets": results
    }
    (case_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"Case {case_id} processing complete. Outputs in {case_dir}")
    return case_dir

# -------------------------
# CLI Entry
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="OpenICE Tool Plus v4 — Batch Multi-Report Generator")
    p.add_argument("--input", "-i", required=True, help="Input CSV or JSON file with targets")
    p.add_argument("--prefix", "-p", default="openice_case", help="Case prefix for folder naming")
    p.add_argument("--out", "-o", default=str(OUTPUT_BASE), help="Output base folder")
    p.add_argument("--github-token", help="GitHub Personal Access Token (optional)")
    p.add_argument("--github-repo", help="GitHub owner/repo to create issues (e.g. user/repo)")
    p.add_argument("--auto", action="store_true", help="Run non-interactive (auto accept prompts)")
    p.add_argument("--auto-push", action="store_true", help="Automatically push GitHub issues (requires token & repo)")
    return p.parse_args()

def main():
    args = parse_args()
    inp = Path(args.input)
    if not inp.exists():
        log(f"Input file not found: {inp}")
        sys.exit(1)
    # load targets
    if inp.suffix.lower() == ".csv":
        targets = load_csv_targets(inp)
    elif inp.suffix.lower() in (".json", ".jsn"):
        targets = load_json_targets(inp)
    else:
        log("Unsupported input format. Use CSV or JSON.")
        sys.exit(1)
    if not targets:
        log("No targets loaded. Exiting.")
        sys.exit(0)

    # case id
    case_id = next_case_id(args.prefix)
    out_base = Path(args.out)
    safe_mkdir(out_base)

    # interactive confirmation (if not auto)
    log(f"Loaded {len(targets)} targets. Case ID will be: {case_id}")
    if not args.auto:
        print("\nFirst 3 targets preview:")
        for t in targets[:3]:
            print(" -", t.get("target"), "|", t.get("platform"), "|", t.get("type"))
        proceed = input("\nProceed to generate reports? (y/N) ").strip().lower()
        if proceed != "y":
            log("Aborted by user.")
            sys.exit(0)
    else:
        log("Auto mode: proceeding without interactive confirmation.")

    # process
    case_dir = process_targets(
        targets,
        case_id,
        out_base,
        github_owner_repo=args.github_repo,
        github_token=args.github_token,
        auto_push=args.auto_push
    )

    log(f"All done. Case folder: {case_dir}")

if __name__ == "__main__":
    main()
