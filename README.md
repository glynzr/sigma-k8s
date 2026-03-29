# Sigma Detection Coverage Analysis — MITRE ATT&CK Containers

A static analysis tool that measures how well the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule repository covers the [MITRE ATT&CK Containers matrix](https://attack.mitre.org/matrices/enterprise/containers/) (v18).

## What It Does

The script scans the entire Sigma rule repository, extracts ATT&CK technique tags from each YAML rule, and maps them against the 37 unique techniques in the ATT&CK Containers platform. It produces:

- **`coverage_table.csv`** — per-technique breakdown (technique ID, name, tactic, rule count, covered/not)
- **`stats_summary.txt`** — key statistics ready to paste into a paper or report
- **`navigator_layer.json`** — ATT&CK Navigator heatmap (import at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/))

## Key Findings

| Metric | Value |
|---|---|
| Sigma rules scanned | 3,679 |
| ATT&CK Container techniques | 37 |
| Techniques with ≥1 Sigma rule | 25 (67.6%) |
| Techniques with 0 Sigma rules | 12 (32.4%) |
| Container-specific techniques covered | 4 / 13 (30.8%) |

The most critical gaps are container-native techniques with **zero** Sigma coverage:

- `T1610` — Deploy Container
- `T1612` — Build Image on Host
- `T1613` — Container and Resource Discovery
- `T1204.003` — User Execution: Malicious Image
- `T1053.007` — Scheduled Task/Job: Container Orchestration Job
- `T1098.006` — Account Manipulation: Additional Container Cluster Roles
- `T1543.005` — Create or Modify System Process: Container Service
- `T1496.001 / T1496.002` — Resource Hijacking (Compute / Bandwidth)

Real-world campaigns like **TeamTNT**, **Hildegard**, and **RBAC Buster** rely heavily on these uncovered techniques, achieving only 33–40% Sigma coverage.

## Setup

**Requirements:** Python 3.10+, `pyyaml`

```bash
pip install pyyaml

git clone --depth=1 https://github.com/SigmaHQ/sigma.git

python sigma_container_analysis.py --sigma-dir ./sigma
```

Results are written to `./results/` by default.

```
Options:
  --sigma-dir PATH   Path to cloned SigmaHQ/sigma repo  (default: ./sigma)
  --outdir PATH      Output directory                    (default: ./results)
```

## Methodology

Sigma rules are parsed as YAML and ATT&CK technique IDs are extracted from the `tags` field using a regex (`attack.tXXXX` pattern). A technique is considered *covered* if at least one rule in the `rules/`, `rules-emerging-threats/`, or `rules-threat-hunting/` directories references it.

Techniques that appear in multiple ATT&CK tactics (e.g. `T1078 Valid Accounts` appears in Initial Access, Persistence, and Defense Evasion) are deduplicated and counted once. Coverage scores in the Navigator layer reflect rule count depth (1 rule → score 1, 10+ rules → score 5).

> **Limitation:** This is a static tag-based analysis. A rule tagged with a technique ID does not guarantee that the rule is deployable or effective in a container environment — it only confirms the rule author intended that mapping. Operational effectiveness would require live environment testing.

## Files

```
sigma_container_analysis.py   Main analysis script
results/
  coverage_table.csv          Per-technique coverage table
  stats_summary.txt           Summary statistics
  navigator_layer.json        ATT&CK Navigator heatmap layer
```

## ATT&CK Navigator

To view the heatmap:

1. Go to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **Open Existing Layer** → **Upload from local**
3. Select `results/navigator_layer.json`

Red cells = no Sigma coverage. Green cells = 5+ rules.

## Data Sources

- Sigma rules: [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) 
- ATT&CK Containers matrix v18: [attack.mitre.org](https://attack.mitre.org/matrices/enterprise/containers/)
- Campaign techniques sourced from Trend Micro, Palo Alto Unit42, CrowdStrike, and Aqua Security Nautilus threat reports

