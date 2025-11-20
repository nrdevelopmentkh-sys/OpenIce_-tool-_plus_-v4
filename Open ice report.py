#pylint:disable= 'invalid syntax (linker64, line 10)'
import os
import json
import hashlib
from datetime import datetime

CASE_NAME = "porn_abuse_case_01"

targets = [
    {
        "type": "telegram_user",@flairpower
        "user_id": "6357300240",
        "username": "@flairsupporting",
        "reason": "Pornographic promotional account distributing explicit content",
        "evidence": [
            "Account posts explicit sexual images",
            "Uses Telegram posts to promote sexual services",
            "Violates Telegram Rules: porn distribution"
        ]
    }
]

# --- Create result folder ---
os.makedirs(CASE_NAME, exist_ok=True)

# --- Auto-generate time ---
timestamp = datetime.now().isoformat()

# --- Auto classify content ---
def classify_content(evidence_list):
    score = 0
    for ev in evidence_list:
        ev_low = ev.lower()
        if "porn" in ev_low or "explicit" in ev_low or "sexual" in ev_low:
            score += 2
        if "promotion" in ev_low or "advertising" in ev_low:
            score += 1
    if score >= 3:
        return "High-Risk Pornographic Abuse"
    elif score == 2:
        return "Medium Sexual Content"
    return "Low Risk"

# --- Hash generator for integrity ---
def make_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

# Main JSON data structure
DATA = {
    "case_id": CASE_NAME,
    "generated_at": timestamp,
    "tool_version": "OpenICE Tool Plus v3",
    "targets": []
}

for t in targets:
    abuse_type = classify_content(t["evidence"])
    h = make_hash(t["username"] + t["user_id"])
    DATA["targets"].append({
        "type": t["type"],
        "user_id": t["user_id"],
        "username": t["username"],
        "classification": abuse_type,
        "integrity_hash": h,
        "reason": t["reason"],
        "evidence": t["evidence"]
    })

# --- Save JSON ---
with open(f"{CASE_NAME}/evidence.json", "w", encoding="utf-8") as f:
    json.dump(DATA, f, indent=4, ensure_ascii=False)

# --- Save TXT report ---
with open(f"{CASE_NAME}/report.txt", "w", encoding="utf-8") as f:
    f.write(f"OpenICE Abuse Report - {CASE_NAME}\n")
    f.write(f"Generated: {timestamp}\n")
    f.write("=================================\n\n")
    for t in DATA["targets"]:
        f.write(f"Target Username: {t['username']}\n")
        f.write(f"User ID: {t['user_id']}\n")
        f.write(f"Classification: {t['classification']}\n")
        f.write(f"Hash: {t['integrity_hash']}\n")
        f.write(f"Reason: {t['reason']}\n")
        f.write("Evidence:\n")
        for e in t['evidence']:
            f.write(f" - {e}\n")
        f.write("\n---------------------------------\n\n")

# --- Save GitHub Markdown Issue ---
md = f"# 🚨 OpenICE Abuse Report: {CASE_NAME}\n"
md += f"Generated: **{timestamp}**\n"
md += "Tool: **OpenICE Tool Plus v3**\n\n"

for t in DATA["targets"]:
    md += f"""
## 🔥 Target: {t['username']}
- **ID:** {t['user_id']}
- **Type:** {t['type']}
- **Classification:** {t['classification']}
- **Integrity Hash:** `{t['integrity_hash']}`
- **Reason:** {t['reason']}

### Evidence
"""
    for e in t["evidence"]:
        md += f"- {e}\n"

with open(f"{CASE_NAME}/github_issue.md", "w", encoding="utf-8") as f:
    f.write(md)

print("✅ OpenICE Tool Plus v3 completed!")
print(f"📁 Output saved inside: {CASE_NAME}/")
