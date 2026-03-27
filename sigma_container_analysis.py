#!/usr/bin/env python3
"""
Sigma Detection Rule Coverage Analysis for MITRE ATT&CK Containers
===================================================================

SETUP :
    pip install pyyaml requests
    git clone --depth=1 https://github.com/SigmaHQ/sigma.git
    python sigma_container_analysis.py --sigma-dir ./sigma

OUTPUTS:
    results/coverage_table.csv      
    results/stats_summary.txt       
    results/gap_analysis.csv        -> uncovered techniques
    results/navigator_layer.json    -> ATT&CK Navigator heatmap
"""

import argparse
import csv
import json
import os
import re
from collections import defaultdict
from pathlib import Path

import yaml

# ── GROUND TRUTH: ATT&CK Containers Matrix v18 ──────────────────────────────
# Source: https://attack.mitre.org/matrices/enterprise/containers/
# extracted from MITRE ATT&CK v18 (March 2025)

CONTAINERS_TECHNIQUES = {
    # ── Initial Access (TA0001) ──────────────────────────────────────────────
    "T1190":     {"name": "Exploit Public-Facing Application",       "tactic": "Initial Access",       "container_specific": False},
    "T1133":     {"name": "External Remote Services",                 "tactic": "Initial Access",       "container_specific": False},
    "T1078":     {"name": "Valid Accounts",                           "tactic": "Initial Access",       "container_specific": False},
    "T1078.001": {"name": "Valid Accounts: Default Accounts",         "tactic": "Initial Access",       "container_specific": False},
    "T1078.003": {"name": "Valid Accounts: Local Accounts",           "tactic": "Initial Access",       "container_specific": False},

    # ── Execution (TA0002) ───────────────────────────────────────────────────
    "T1609":     {"name": "Container Administration Command",         "tactic": "Execution",            "container_specific": True},
    "T1610":     {"name": "Deploy Container",                         "tactic": "Execution",            "container_specific": True},
    "T1053.007": {"name": "Scheduled Task/Job: Container Orchestration Job", "tactic": "Execution",   "container_specific": True},
    "T1204.003": {"name": "User Execution: Malicious Image",          "tactic": "Execution",            "container_specific": True},

    # ── Persistence (TA0003) ─────────────────────────────────────────────────
    "T1098.006": {"name": "Account Manipulation: Additional Container Cluster Roles", "tactic": "Persistence", "container_specific": True},
    "T1136.001": {"name": "Create Account: Local Account",           "tactic": "Persistence",          "container_specific": False},
    "T1543.005": {"name": "Create or Modify System Process: Container Service", "tactic": "Persistence", "container_specific": True},
    "T1133_p":   {"name": "External Remote Services",                 "tactic": "Persistence",          "container_specific": False},
    "T1525":     {"name": "Implant Internal Image",                   "tactic": "Persistence",          "container_specific": True},
    "T1053.007_p": {"name": "Scheduled Task/Job: Container Orchestration Job", "tactic": "Persistence", "container_specific": True},
    "T1078_p":   {"name": "Valid Accounts",                           "tactic": "Persistence",          "container_specific": False},

    # ── Privilege Escalation (TA0004) ────────────────────────────────────────
    "T1098.006_pe": {"name": "Account Manipulation: Additional Container Cluster Roles", "tactic": "Privilege Escalation", "container_specific": True},
    "T1543.005_pe": {"name": "Create or Modify System Process: Container Service", "tactic": "Privilege Escalation", "container_specific": True},
    "T1611":     {"name": "Escape to Host",                           "tactic": "Privilege Escalation", "container_specific": True},
    "T1068":     {"name": "Exploitation for Privilege Escalation",    "tactic": "Privilege Escalation", "container_specific": False},
    "T1053.007_pe": {"name": "Scheduled Task/Job: Container Orchestration Job", "tactic": "Privilege Escalation", "container_specific": True},
    "T1078_pe":  {"name": "Valid Accounts",                           "tactic": "Privilege Escalation", "container_specific": False},

    # ── Defense Evasion (TA0005) ─────────────────────────────────────────────
    "T1612":     {"name": "Build Image on Host",                      "tactic": "Defense Evasion",      "container_specific": True},
    "T1610_de":  {"name": "Deploy Container",                         "tactic": "Defense Evasion",      "container_specific": True},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion",      "container_specific": False},
    "T1070":     {"name": "Indicator Removal",                        "tactic": "Defense Evasion",      "container_specific": False},
    "T1036.005": {"name": "Masquerading: Match Legitimate Resource Name or Location", "tactic": "Defense Evasion", "container_specific": False},
    "T1036.010": {"name": "Masquerading: Masquerade Account Name",    "tactic": "Defense Evasion",      "container_specific": False},
    "T1550.001": {"name": "Use Alternate Authentication Material: Application Access Token", "tactic": "Defense Evasion", "container_specific": False},
    "T1078_de":  {"name": "Valid Accounts",                           "tactic": "Defense Evasion",      "container_specific": False},

    # ── Credential Access (TA0006) ───────────────────────────────────────────
    "T1110":     {"name": "Brute Force",                              "tactic": "Credential Access",    "container_specific": False},
    "T1110.001": {"name": "Brute Force: Password Guessing",           "tactic": "Credential Access",    "container_specific": False},
    "T1110.003": {"name": "Brute Force: Password Spraying",           "tactic": "Credential Access",    "container_specific": False},
    "T1110.004": {"name": "Brute Force: Credential Stuffing",         "tactic": "Credential Access",    "container_specific": False},
    "T1528":     {"name": "Steal Application Access Token",           "tactic": "Credential Access",    "container_specific": False},
    "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access", "container_specific": False},
    "T1552.007": {"name": "Unsecured Credentials: Container API",     "tactic": "Credential Access",    "container_specific": True},

    # ── Discovery (TA0007) ───────────────────────────────────────────────────
    "T1613":     {"name": "Container and Resource Discovery",         "tactic": "Discovery",            "container_specific": True},
    "T1046":     {"name": "Network Service Discovery",                "tactic": "Discovery",            "container_specific": False},
    "T1069":     {"name": "Permission Groups Discovery",              "tactic": "Discovery",            "container_specific": False},

    # ── Lateral Movement (TA0008) ────────────────────────────────────────────
    "T1550.001_lm": {"name": "Use Alternate Authentication Material: Application Access Token", "tactic": "Lateral Movement", "container_specific": False},

    # ── Impact (TA0040) ──────────────────────────────────────────────────────
    "T1485":     {"name": "Data Destruction",                         "tactic": "Impact",               "container_specific": False},
    "T1499":     {"name": "Endpoint Denial of Service",               "tactic": "Impact",               "container_specific": False},
    "T1490":     {"name": "Inhibit System Recovery",                  "tactic": "Impact",               "container_specific": False},
    "T1498":     {"name": "Network Denial of Service",                "tactic": "Impact",               "container_specific": False},
    "T1496.001": {"name": "Resource Hijacking: Compute Hijacking",    "tactic": "Impact",               "container_specific": True},
    "T1496.002": {"name": "Resource Hijacking: Bandwidth Hijacking",  "tactic": "Impact",               "container_specific": True},
}

# Deduplicated unique technique IDs (same technique in multiple tactics = one entry)
UNIQUE_TECHNIQUE_IDS = {
    "T1190", "T1133", "T1078", "T1078.001", "T1078.003",
    "T1609", "T1610", "T1053.007", "T1204.003",
    "T1098.006", "T1136.001", "T1543.005", "T1525",
    "T1611", "T1068",
    "T1612", "T1562.001", "T1070", "T1036.005", "T1036.010", "T1550.001",
    "T1110", "T1110.001", "T1110.003", "T1110.004", "T1528", "T1552.001", "T1552.007",
    "T1613", "T1046", "T1069",
    "T1485", "T1499", "T1490", "T1498", "T1496.001", "T1496.002",
}

CONTAINER_SPECIFIC_IDS = {
    "T1609", "T1610", "T1053.007", "T1204.003",
    "T1098.006", "T1543.005", "T1525",
    "T1611",
    "T1612",
    "T1552.007",
    "T1613",
    "T1496.001", "T1496.002",
}

# Real-world container attacks mapped to techniques 
REAL_WORLD_ATTACKS = {
    "TeamTNT (2020-2021)": {
        "techniques": ["T1610", "T1613", "T1496.001", "T1552.007", "T1070"],
        "source": "Trend Micro / Palo Alto Unit42 threat reports",
        "description": "Cryptomining via exposed Docker APIs, credential theft from container metadata"
    },
    "Hildegard (2021)": {
        "techniques": ["T1609", "T1611", "T1613", "T1496.001", "T1543.005"],
        "source": "Unit42 Palo Alto research report",
        "description": "Kubernetes compromise via misconfigured kubelets, container escape"
    },
    "Siloscape (2021)": {
        "techniques": ["T1611", "T1068", "T1204.003"],
        "source": "Unit42 Palo Alto report",
        "description": "First known malware targeting Windows containers, escape to host"
    },
    "Kiss-a-Dog (2022)": {
        "techniques": ["T1610", "T1609", "T1496.001", "T1562.001"],
        "source": "CrowdStrike / Aqua Security reports",
        "description": "Cryptomining via exposed Docker/Kubernetes APIs, defense evasion"
    },
    "RBAC Buster (2023)": {
        "techniques": ["T1098.006", "T1613", "T1552.007"],
        "source": "Aqua Security Nautilus research",
        "description": "Cluster privilege escalation via RBAC manipulation"
    },
}

# ── SIGMA RULE PARSER ────────────────────────────────────────────────────────

def extract_attack_tags(rule_path: Path) -> list[str]:
    """Extract ATT&CK technique IDs from a Sigma rule YAML file."""
    try:
        with open(rule_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return []
        tags = data.get("tags", []) or []
        techniques = []
        for tag in tags:
            tag = str(tag).lower()
            # Match attack.tXXXX or attack.tXXXX.XXX patterns
            match = re.search(r'attack\.(t\d{4}(?:\.\d{3})?)', tag)
            if match:
                techniques.append(match.group(1).upper())
        return techniques
    except Exception:
        return []


def scan_sigma_repo(sigma_dir: str) -> dict:
    """
    Scan all Sigma YAML rules and count coverage per technique.
    Returns {technique_id: [list_of_rule_files]}
    """
    sigma_path = Path(sigma_dir)
    rule_dirs = [
        sigma_path / "rules",
        sigma_path / "rules-emerging-threats",
        sigma_path / "rules-threat-hunting",
    ]

    coverage = defaultdict(list)
    total_rules = 0
    container_rules = 0

    for rule_dir in rule_dirs:
        if not rule_dir.exists():
            continue
        for rule_file in rule_dir.rglob("*.yml"):
            total_rules += 1
            tags = extract_attack_tags(rule_file)
            for tid in tags:
                if tid in UNIQUE_TECHNIQUE_IDS:
                    coverage[tid].append(str(rule_file.name))
                    # Count rules in container-relevant directories
                    if any(d in str(rule_file).lower()
                           for d in ["container", "kubernetes", "k8s", "docker"]):
                        container_rules += 1

    return dict(coverage), total_rules, container_rules


# ── ANALYSIS ─────────────────────────────────────────────────────────────────

def analyze_coverage(coverage: dict) -> dict:
    """Compute all statistics needed for the paper."""

    total_techniques = len(UNIQUE_TECHNIQUE_IDS)
    covered = {tid: rules for tid, rules in coverage.items()
               if rules and tid in UNIQUE_TECHNIQUE_IDS}
    uncovered = UNIQUE_TECHNIQUE_IDS - set(covered.keys())

    container_specific_covered = {
        tid for tid in CONTAINER_SPECIFIC_IDS if tid in covered
    }
    container_specific_uncovered = CONTAINER_SPECIFIC_IDS - container_specific_covered

    # Rule density: techniques with only 1 rule (fragile coverage)
    single_rule = {tid for tid, rules in covered.items() if len(rules) == 1}

    # Tactic breakdown
    tactic_total = defaultdict(int)
    tactic_covered = defaultdict(int)
    for tid, info in CONTAINERS_TECHNIQUES.items():
        base_id = tid.split("_")[0]  # strip suffix used for dedup
        if base_id in UNIQUE_TECHNIQUE_IDS:
            tactic_total[info["tactic"]] += 1
    # count per unique tactic
    seen_per_tactic = defaultdict(set)
    for tid, info in CONTAINERS_TECHNIQUES.items():
        base_id = tid.split("_")[0]
        if base_id in UNIQUE_TECHNIQUE_IDS:
            seen_per_tactic[info["tactic"]].add(base_id)
    tactic_total = {t: len(ids) for t, ids in seen_per_tactic.items()}
    tactic_covered_map = defaultdict(int)
    for tid in covered:
        for raw_tid, info in CONTAINERS_TECHNIQUES.items():
            base_id = raw_tid.split("_")[0]
            if base_id == tid:
                tactic_covered_map[info["tactic"]] += 1
                break

    # Attack campaign mapping
    campaign_coverage = {}
    for campaign, data in REAL_WORLD_ATTACKS.items():
        used = data["techniques"]
        covered_in_campaign = [t for t in used if t in covered]
        campaign_coverage[campaign] = {
            "techniques_used": used,
            "covered": covered_in_campaign,
            "uncovered": [t for t in used if t not in covered],
            "coverage_pct": len(covered_in_campaign) / len(used) * 100,
        }

    return {
        "total_techniques": total_techniques,
        "covered_count": len(covered),
        "uncovered_count": len(uncovered),
        "coverage_pct": len(covered) / total_techniques * 100,
        "container_specific_total": len(CONTAINER_SPECIFIC_IDS),
        "container_specific_covered": len(container_specific_covered),
        "container_specific_uncovered": sorted(container_specific_uncovered),
        "container_specific_coverage_pct": len(container_specific_covered) / len(CONTAINER_SPECIFIC_IDS) * 100,
        "single_rule_techniques": sorted(single_rule),
        "uncovered_techniques": sorted(uncovered),
        "covered_techniques": covered,
        "tactic_breakdown": {
            t: {
                "total": tactic_total.get(t, 0),
                "covered": tactic_covered_map.get(t, 0),
            }
            for t in tactic_total
        },
        "campaign_coverage": campaign_coverage,
    }


# ── OUTPUT GENERATORS ────────────────────────────────────────────────────────

def write_coverage_table(stats: dict, outdir: Path):
    """Table I for the paper: per-technique coverage."""
    rows = []

    # Covered techniques
    for tid in sorted(stats["covered_techniques"]):
        rules = stats["covered_techniques"][tid]
        # Find technique name
        name = "Unknown"
        for raw_tid, info in CONTAINERS_TECHNIQUES.items():
            if raw_tid.split("_")[0] == tid:
                name = info["name"]
                tactic = info["tactic"]
                cs = info["container_specific"]
                break
        rows.append({
            "Technique ID": tid,
            "Technique Name": name,
            "Tactic": tactic,
            "Container-Specific": "Yes" if cs else "No",
            "Sigma Rules": len(rules),
            "Coverage": "YES",
        })

    # Uncovered techniques
    for tid in sorted(stats["uncovered_techniques"]):
        name = tactic = "Unknown"
        cs = False
        for raw_tid, info in CONTAINERS_TECHNIQUES.items():
            if raw_tid.split("_")[0] == tid:
                name = info["name"]
                tactic = info["tactic"]
                cs = info["container_specific"]
                break
        rows.append({
            "Technique ID": tid,
            "Technique Name": name,
            "Tactic": tactic,
            "Container-Specific": "Yes" if cs else "No",
            "Sigma Rules": 0,
            "Coverage": "NO",
        })

    outfile = outdir / "coverage_table.csv"
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda x: x["Technique ID"]))
    print(f"  [OK] {outfile}")


def write_stats_summary(stats: dict, total_rules: int, outdir: Path):
    """Key numbers for the paper's abstract and results section."""
    lines = [
        "=" * 60,
        "RESULTS SUMMARY — paste into paper",
        "=" * 60,
        "",
        "── ABSTRACT NUMBERS ──────────────────────────────────────",
        f"Total Sigma rules scanned:         {total_rules:,}",
        f"ATT&CK Container techniques:       {stats['total_techniques']}",
        f"Techniques with ≥1 Sigma rule:     {stats['covered_count']}",
        f"Techniques with 0 Sigma rules:     {stats['uncovered_count']}",
        f"Overall coverage rate:             {stats['coverage_pct']:.1f}%",
        f"Container-specific techniques:     {stats['container_specific_total']}",
        f"Container-specific covered:        {stats['container_specific_covered']}",
        f"Container-specific coverage:       {stats['container_specific_coverage_pct']:.1f}%",
        f"Techniques with only 1 rule:       {len(stats['single_rule_techniques'])}",
        "",
        "── TACTIC BREAKDOWN (Table II) ───────────────────────────",
    ]

    for tactic, counts in sorted(stats["tactic_breakdown"].items()):
        pct = counts["covered"] / counts["total"] * 100 if counts["total"] else 0
        lines.append(
            f"  {tactic:<30} {counts['covered']}/{counts['total']} ({pct:.0f}%)"
        )

    lines += [
        "",
        "── UNCOVERED CONTAINER-SPECIFIC TECHNIQUES ───────────────",
        "(These are the most critical gaps — container-native attacks with no detection)",
    ]
    for tid in stats["container_specific_uncovered"]:
        name = "Unknown"
        for raw_tid, info in CONTAINERS_TECHNIQUES.items():
            if raw_tid.split("_")[0] == tid:
                name = info["name"]
                break
        lines.append(f"  {tid}  {name}")

    lines += [
        "",
        "── REAL-WORLD ATTACK CAMPAIGN COVERAGE ───────────────────",
    ]
    for campaign, data in stats["campaign_coverage"].items():
        lines.append(f"  {campaign}")
        lines.append(f"    Techniques used: {data['techniques_used']}")
        lines.append(f"    Sigma covered:   {data['covered']}")
        lines.append(f"    Not covered:     {data['uncovered']}")
        lines.append(f"    Coverage rate:   {data['coverage_pct']:.0f}%")
        lines.append("")

    outfile = outdir / "stats_summary.txt"
    with open(outfile, "w") as f:
        f.write("\n".join(lines))
    print(f"  [OK] {outfile}")
    print("\n".join(lines))


def write_navigator_layer(stats: dict, outdir: Path):
    """ATT&CK Navigator JSON layer — import at mitre-attack.github.io/attack-navigator/"""
    techniques_layer = []
    for tid, rules in stats["covered_techniques"].items():
        count = len(rules)
        # Score 1-5 based on rule count
        score = min(5, max(1, count))
        techniques_layer.append({
            "techniqueID": tid,
            "score": score,
            "color": "",
            "comment": f"{count} Sigma rule(s)",
            "enabled": True,
            "metadata": [],
            "showSubtechniques": True,
        })
    for tid in stats["uncovered_techniques"]:
        techniques_layer.append({
            "techniqueID": tid,
            "score": 0,
            "color": "#FF6666",
            "comment": "NO Sigma coverage",
            "enabled": True,
            "metadata": [],
            "showSubtechniques": True,
        })

    layer = {
        "name": "Sigma Coverage — ATT&CK Containers",
        "versions": {"attack": "18", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Sigma rule coverage for MITRE ATT&CK Containers platform techniques",
        "filters": {"platforms": ["Containers"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average",
                   "showID": True, "showName": True, "showAggregateScores": True,
                   "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#FF6666", "#FFD700", "#00AA00"],
            "minValue": 0,
            "maxValue": 5,
        },
        "legendItems": [
            {"label": "No coverage (0 rules)", "color": "#FF6666"},
            {"label": "Low (1 rule)",          "color": "#FFD700"},
            {"label": "Good (5+ rules)",        "color": "#00AA00"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    outfile = outdir / "navigator_layer.json"
    with open(outfile, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"  [OK] {outfile} — import at https://mitre-attack.github.io/attack-navigator/")


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sigma Coverage Analysis for ATT&CK Containers ",
    )
    parser.add_argument(
        "--sigma-dir", default="./sigma",
        help="Path to cloned SigmaHQ/sigma repo (default: ./sigma)"
    )
    parser.add_argument(
        "--outdir", default="./results",
        help="Output directory for results (default: ./results)"
    )
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    sigma_path = Path(args.sigma_dir)
    if not sigma_path.exists():
        print(f"ERROR: {sigma_path} not found.")
        print("Clone the SigmaHQ repo first:")
        print("  git clone --depth=1 https://github.com/SigmaHQ/sigma.git")
        return

    print(f"\nScanning Sigma rules in: {sigma_path.absolute()}")
    coverage, total_rules, container_rules = scan_sigma_repo(args.sigma_dir)
    print(f"  Total YAML rules found:       {total_rules:,}")
    print(f"  Container-related rule files: {container_rules:,}")
    print(f"  Container techniques matched: {len(coverage)}")

    print("\nAnalyzing coverage...")
    stats = analyze_coverage(coverage)

    print("\nWriting results...")
    write_coverage_table(stats, outdir)
    write_stats_summary(stats, total_rules, outdir)
    write_navigator_layer(stats, outdir)

    print(f"\nDone. All results in: {outdir.absolute()}/")



if __name__ == "__main__":
    main()
