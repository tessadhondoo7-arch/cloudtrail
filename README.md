# CloudTrail Threat Detection & MITRE ATT&CK Mapper

A local-only, defensive Python tool that analyses AWS CloudTrail JSON log files,
detects suspicious activity with explainable rules, maps findings to MITRE ATT&CK
techniques, and measures detection quality against labeled ground truth.

> **Status:** Milestone 1 (project foundation). No detection logic yet.

## Goals

- Load AWS CloudTrail JSON files
- Validate and normalize events
- Detect suspicious patterns using explainable rules
- Map supported findings to verified MITRE ATT&CK techniques
- Evaluate detections against labeled ground truth (precision, recall, F1, confusion matrix)
- Provide a CLI and, later, a Streamlit dashboard

## Safety principles

- **Local only:** no AWS account or credentials required; works on log files on disk.
- **Defensive only:** detection and analysis, no offensive tooling.
- **No secrets in the repo:** use synthetic data; real logs and credentials are git-ignored.

## Project structure

```
.
├── README.md
├── pyproject.toml          # Package metadata
├── requirements.txt        # Dependencies for development
├── src/cloudtrail_mapper/  # Application source code
├── config/                 # Detection rules and settings
├── data/synthetic/         # Synthetic CloudTrail logs (safe to commit)
├── data/labels/            # Ground-truth labels for evaluation
├── tests/                  # Automated tests (pytest)
├── reports/                # Generated output (git-ignored)
└── docs/                   # Documentation
```

## Setup (Windows / PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run tests

```powershell
pytest
```

## Roadmap

1. Project foundation ✅
2. Load and validate CloudTrail events
3. Normalize events
4. Explainable detection rules
5. MITRE ATT&CK mapping
6. Evaluation against ground truth
7. CLI
8. Streamlit dashboard
