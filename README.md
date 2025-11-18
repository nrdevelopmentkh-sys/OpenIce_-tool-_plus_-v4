# OpenICE Tool Plus — v4 (Professional)

OpenICE Tool Plus v4 is a professional multi-report generator for abuse and malware investigations.
It helps security researchers and moderators collect evidence and generate polished reports for:
- Telegram Trust & Safety (TXT)
- GitHub Issues (Markdown)
- Machine-readable evidence (JSON)

**Important:** This tool **does NOT** automatically send reports to Telegram. Manual submission is required for platform abuse channels. Use auto GitHub issue creation only with a Personal Access Token and careful review.

---

## Features

- Batch import targets from CSV or JSON
- Generate per-target reports: TXT (Telegram), MD (GitHub), JSON (evidence)
- Case auto-numbering and folder organization
- SHA256 hashing for local attachments (if present)
- Classification by keywords: sexual, malware, scam, spam, impersonation
- Optional GitHub issue creation (requires PAT & opt-in `--auto-push`)
- Logging and summary output
- Safe-by-default (does not upload user files)

---

## Quickstart

### Requirements
- Python 3.8+
- `requests` (only needed for GitHub integration)
```bash
python -m pip install requests
Files included

openice_tool_plus_v4.py — main script

sample_targets.csv — sample CSV input

sample_targets.json — sample JSON input

config/settings.json — default settings

.github/workflows/openice-ci.yml — CI workflow to run reports and upload artifacts

Run locally (interactive)

python openice_tool_plus_v4.py --input sample_targets.csv --prefix porn_abuse_case_01

Run non-interactive (auto)

python openice_tool_plus_v4.py --input sample_targets.csv --prefix porn_abuse_case_01 --auto

Create GitHub issues automatically (use with caution)

python openice_tool_plus_v4.py --input sample_targets.csv --prefix porn_abuse_case_01 \
  --auto --github-token YOUR_GITHUB_PAT --github-repo youruser/yourrepo --auto-push

> Warning: Auto-pushing issues requires a PAT with repo scope for private repos, or public_repo for public repos. Use responsibly.

Folder layout (after run)

reports/
└── porn_abuse_case_01_YYYYMMDD_NNN/
    ├── <target>_telegram_report.txt
    ├── <target>_github_issue.md
    ├── <target>_evidence.json
    ├── summary.json
    └── evidence/   (attachment paths listed; files not copied automatically)


---

Contributing

Follow safe-handling: never include raw CSAM or malware binaries in the repository.

Use screenshots and links only (redact sensitive PII).
Open PRs for improvements.

License

This project is released under the MIT License. See LICENSE file.

