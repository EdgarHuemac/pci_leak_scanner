#!/usr/bin/env python3
"""
PCI Leak Scanner — A command-line tool to detect PCI DSS data leakage in files and logs.
"""

import argparse
import csv
import json
import multiprocessing
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ──────────────────────────────────────────────
# ANSI color helpers
# ──────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
WHITE  = "\033[97m"
MAGENTA = "\033[95m"

def colorize(text: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text

CONFIDENCE_COLOR = {
    "critical": RED,
    "high":     RED,
    "medium":   YELLOW,
    "low":      CYAN,
}

# ──────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────
@dataclass
class RulePattern:
    name: str
    regex: str
    confidence: str        # Low / Medium / High / Critical
    validate_luhn: bool = False
    compiled: Any = field(default=None, repr=False)

@dataclass
class Rule:
    rule_code: str
    description: str
    mitigation: str
    patterns: list[RulePattern]

@dataclass
class Finding:
    file: str
    line_number: int
    rule_code: str
    rule_description: str
    pattern_name: str
    confidence: str
    match: str
    context_before: list[str]
    context_after: list[str]
    mitigation: str
    luhn_valid: bool | None = None

# ──────────────────────────────────────────────
# Luhn algorithm
# ──────────────────────────────────────────────
def luhn_check(number: str) -> bool:
    """Return True if the digit string passes the Luhn (mod-10) check."""
    digits = [int(d) for d in number if d.isdigit()]
    if not digits:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

# ──────────────────────────────────────────────
# Rule loader & validator
# ──────────────────────────────────────────────
REQUIRED_RULE_KEYS = {"rule_code", "description", "mitigation", "patterns"}
REQUIRED_PATTERN_KEYS = {"name", "regex", "confidence"}
VALID_CONFIDENCES = {"low", "medium", "high", "critical"}

def load_rules(rules_dir: str) -> list[Rule]:
    rules: list[Rule] = []
    rules_path = Path(rules_dir)
    if not rules_path.is_dir():
        print(colorize(f"[ERROR] Rules directory not found: {rules_dir}", RED))
        sys.exit(1)

    json_files = [f for f in rules_path.glob("*.json") if f.name != "globals.json"]
    if not json_files:
        print(colorize(f"[WARN] No .json rule files found in {rules_dir}", YELLOW))
        return rules

    for jf in json_files:
        try:
            with open(jf, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(colorize(f"[SCHEMA ERROR] {jf.name}: invalid JSON — {e}", RED))
            continue

        # Handle both single rule object and array of rules
        rule_list = data if isinstance(data, list) else [data]

        for raw in rule_list:
            missing = REQUIRED_RULE_KEYS - raw.keys()
            if missing:
                print(colorize(f"[SCHEMA ERROR] {jf.name}: missing keys {missing}", RED))
                continue

            patterns: list[RulePattern] = []
            valid = True
            for p in raw.get("patterns", []):
                pm = REQUIRED_PATTERN_KEYS - p.keys()
                if pm:
                    print(colorize(f"[SCHEMA ERROR] {jf.name}/{raw['rule_code']}: pattern missing {pm}", RED))
                    valid = False
                    break
                conf = p["confidence"].lower()
                if conf not in VALID_CONFIDENCES:
                    print(colorize(f"[SCHEMA ERROR] {jf.name}: unknown confidence '{p['confidence']}'", RED))
                    valid = False
                    break
                try:
                    compiled = re.compile(p["regex"])
                except re.error as e:
                    print(colorize(f"[SCHEMA ERROR] {jf.name}/{raw['rule_code']}: bad regex — {e}", RED))
                    valid = False
                    break
                patterns.append(RulePattern(
                    name=p["name"],
                    regex=p["regex"],
                    confidence=conf,
                    validate_luhn=p.get("validate_luhn", False),
                    compiled=compiled,
                ))

            if valid and patterns:
                rules.append(Rule(
                    rule_code=raw["rule_code"],
                    description=raw["description"],
                    mitigation=raw["mitigation"],
                    patterns=patterns,
                ))

    return rules

# ──────────────────────────────────────────────
# Globals / allow-list loader
# ──────────────────────────────────────────────
@dataclass
class Globals:
    ignored_strings: list[str] = field(default_factory=list)
    ignored_extensions: list[str] = field(default_factory=list)
    ignored_directories: list[str] = field(default_factory=list)

def load_globals(rules_dir: str) -> Globals:
    g = Globals()
    gfile = Path(rules_dir) / "globals.json"
    if not gfile.exists():
        return g
    try:
        with open(gfile, encoding="utf-8") as f:
            data = json.load(f)
        g.ignored_strings = [s.lower() for s in data.get("ignored_strings", [])]
        g.ignored_extensions = [e.lower() for e in data.get("ignored_extensions", [])]
        g.ignored_directories = data.get("ignored_directories", [])
    except Exception as e:
        print(colorize(f"[WARN] Could not load globals.json: {e}", YELLOW))
    return g

# ──────────────────────────────────────────────
# File collection
# ──────────────────────────────────────────────
def collect_files(
    targets: list[str],
    recursive: bool,
    globals_cfg: Globals,
    max_size_mb: float | None,
) -> list[Path]:
    collected: list[Path] = []

    def should_skip_path(p: Path) -> bool:
        # Ignored directories anywhere in path
        for part in p.parts:
            if part in globals_cfg.ignored_directories:
                return True
        # Ignored extensions
        if p.suffix.lower() in globals_cfg.ignored_extensions:
            return True
        # Size check
        if max_size_mb is not None:
            try:
                size_mb = p.stat().st_size / (1024 * 1024)
                if size_mb > max_size_mb:
                    print(colorize(f"[SKIP] {p} — exceeds --max-size ({size_mb:.1f} MB > {max_size_mb} MB)", DIM))
                    return True
            except OSError:
                pass
        return False

    for target in targets:
        p = Path(target)
        if p.is_file():
            if not should_skip_path(p):
                collected.append(p)
        elif p.is_dir():
            pattern = "**/*" if recursive else "*"
            for fp in p.glob(pattern):
                if fp.is_file() and not should_skip_path(fp):
                    collected.append(fp)
        else:
            print(colorize(f"[WARN] Target not found: {target}", YELLOW))

    return sorted(set(collected))

# ──────────────────────────────────────────────
# Core scanner (per-file, runs in worker)
# ──────────────────────────────────────────────
def scan_file(args_tuple) -> list[Finding]:
    file_path, rules, globals_cfg, context_lines = args_tuple
    findings: list[Finding] = []

    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError) as e:
        return findings

    for line_no, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")

        for rule in rules:
            for pattern in rule.patterns:
                for m in pattern.compiled.finditer(stripped):
                    match_str = m.group()

                    # Allow-list: skip ignored literal strings
                    if match_str.lower() in globals_cfg.ignored_strings:
                        continue

                    # Luhn validation
                    luhn_valid = None
                    confidence = pattern.confidence
                    if pattern.validate_luhn:
                        digits_only = re.sub(r"\D", "", match_str)
                        luhn_valid = luhn_check(digits_only)
                        # Upgrade confidence if Luhn passes
                        if luhn_valid and confidence == "high":
                            confidence = "critical"
                        elif luhn_valid and confidence == "medium":
                            confidence = "high"
                        elif not luhn_valid and confidence in ("high", "critical"):
                            confidence = "medium"

                    ctx_before = [
                        lines[i].rstrip("\n")
                        for i in range(max(0, line_no - 1 - context_lines), line_no - 1)
                    ]
                    ctx_after = [
                        lines[i].rstrip("\n")
                        for i in range(line_no, min(len(lines), line_no + context_lines))
                    ]

                    findings.append(Finding(
                        file=str(file_path),
                        line_number=line_no,
                        rule_code=rule.rule_code,
                        rule_description=rule.description,
                        pattern_name=pattern.name,
                        confidence=confidence,
                        match=match_str,
                        context_before=ctx_before,
                        context_after=ctx_after,
                        mitigation=rule.mitigation,
                        luhn_valid=luhn_valid,
                    ))

    return findings

# ──────────────────────────────────────────────
# Output formatters
# ──────────────────────────────────────────────
def print_finding(finding: Finding, verbosity: int) -> None:
    conf = finding.confidence.lower()
    color = CONFIDENCE_COLOR.get(conf, CYAN)
    conf_label = finding.confidence.upper()

    # Default output
    header = (
        f"{colorize(conf_label, color + BOLD)} │ "
        f"{colorize(finding.file, WHITE)}:{colorize(str(finding.line_number), BOLD)} │ "
        f"[{colorize(finding.rule_code, MAGENTA)}] │ "
        f"Match: {colorize(repr(finding.match), color)}"
    )
    print(header)

    if verbosity >= 1:
        print(f"  {DIM}Pattern : {finding.pattern_name}{RESET}")
        print(f"  {DIM}Confidence : {conf_label}{RESET}", end="")
        if finding.luhn_valid is not None:
            luhn_str = colorize("✓ Luhn valid", GREEN) if finding.luhn_valid else colorize("✗ Luhn invalid", DIM)
            print(f"  {luhn_str}", end="")
        print()
        print(f"  {DIM}Rule : {finding.rule_description}{RESET}")

    if verbosity >= 2:
        print(f"  {YELLOW}Mitigation : {finding.mitigation}{RESET}")
        if finding.context_before or finding.context_after:
            print(f"  {DIM}── Context ──────────────────────{RESET}")
            for cl in finding.context_before:
                print(f"  {DIM}  {cl}{RESET}")
            print(f"  {color}→ {finding.match}{RESET}")
            for cl in finding.context_after:
                print(f"  {DIM}  {cl}{RESET}")

    print()

def export_json(findings: list[Finding], out_path: str) -> None:
    data = []
    for f in findings:
        d = asdict(f)
        d.pop("compiled", None)
        data.append(d)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(colorize(f"[+] JSON report saved → {out_path}", GREEN))

def export_csv(findings: list[Finding], out_path: str) -> None:
    fields = ["file", "line_number", "rule_code", "rule_description",
              "pattern_name", "confidence", "match", "luhn_valid", "mitigation"]
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for f in findings:
            row = {k: getattr(f, k) for k in fields}
            writer.writerow(row)
    print(colorize(f"[+] CSV report saved → {out_path}", GREEN))

def export_sarif(findings: list[Finding], out_path: str, rules: list[Rule]) -> None:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pci-scanner",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/pci-scanner",
                    "rules": [
                        {
                            "id": r.rule_code,
                            "name": r.description,
                            "shortDescription": {"text": r.description},
                            "helpUri": "",
                            "properties": {"mitigation": r.mitigation},
                        }
                        for r in rules
                    ],
                }
            },
            "results": [
                {
                    "ruleId": f.rule_code,
                    "level": "error" if f.confidence in ("high", "critical") else "warning",
                    "message": {"text": f"{f.pattern_name}: {f.match}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line_number},
                        }
                    }],
                    "properties": {
                        "confidence": f.confidence,
                        "luhn_valid": f.luhn_valid,
                        "mitigation": f.mitigation,
                    },
                }
                for f in findings
            ],
        }],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    print(colorize(f"[+] SARIF report saved → {out_path}", GREEN))

# ──────────────────────────────────────────────
# Summary banner
# ──────────────────────────────────────────────
def print_summary(findings: list[Finding], files_scanned: int, elapsed: float) -> None:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.confidence.lower()] = counts.get(f.confidence.lower(), 0) + 1

    print(colorize("━" * 60, DIM))
    print(colorize(f"  PCI SCAN COMPLETE", BOLD + WHITE))
    print(colorize("━" * 60, DIM))
    print(f"  Files scanned : {colorize(str(files_scanned), WHITE)}")
    print(f"  Time elapsed  : {colorize(f'{elapsed:.2f}s', WHITE)}")
    print(f"  Total findings: {colorize(str(len(findings)), BOLD + WHITE)}")
    print()
    print(f"  {colorize('CRITICAL', RED + BOLD)} : {counts.get('critical', 0)}")
    print(f"  {colorize('HIGH    ', RED)}    : {counts.get('high', 0)}")
    print(f"  {colorize('MEDIUM  ', YELLOW)}  : {counts.get('medium', 0)}")
    print(f"  {colorize('LOW     ', CYAN)}    : {counts.get('low', 0)}")
    print(colorize("━" * 60, DIM))

# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pci-scanner",
        description="PCI DSS Data Leakage Scanner — finds sensitive data in logs and files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pci-scanner scan /var/log/app.log
  pci-scanner scan ./logs/ --recursive -v
  pci-scanner scan ./src/ -r --output-format json --output-file report.json
  pci-scanner scan app.log --max-size 50 -vv --context 3
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan subcommand ──────────────────────
    sp = sub.add_parser("scan", help="Scan files or directories for PCI leakage")
    sp.add_argument("targets", nargs="+", metavar="PATH",
                    help="File(s) or directory to scan")
    sp.add_argument("-r", "--recursive", action="store_true",
                    help="Recurse into sub-directories")
    sp.add_argument("-v", "--verbose", action="count", default=0,
                    help="Increase verbosity (-v, -vv)")
    sp.add_argument("--rules-dir", default=str(Path(__file__).parent / "rules"),
                    metavar="DIR", help="Directory containing JSON rule files (default: ./rules)")
    sp.add_argument("--context", type=int, default=2, metavar="N",
                    help="Number of context lines before/after match (default: 2)")
    sp.add_argument("--max-size", type=float, metavar="MB",
                    help="Skip files larger than this size in MB")
    sp.add_argument("--workers", type=int, default=multiprocessing.cpu_count(),
                    metavar="N", help="Parallel worker processes (default: CPU count)")
    sp.add_argument("--output-format", choices=["json", "csv", "sarif"],
                    metavar="FMT", help="Export format: json, csv, sarif")
    sp.add_argument("--output-file", metavar="FILE",
                    help="Path for the exported report")
    sp.add_argument("--no-color", action="store_true",
                    help="Disable color output")
    sp.add_argument("--quiet", action="store_true",
                    help="Suppress per-finding output (summary only)")

    # ── rules subcommand ─────────────────────
    rp = sub.add_parser("rules", help="List loaded rules")
    rp.add_argument("--rules-dir", default=str(Path(__file__).parent / "rules"),
                    metavar="DIR")

    return parser


def cmd_rules(args) -> None:
    rules = load_rules(args.rules_dir)
    print(colorize(f"\n  {len(rules)} rules loaded from {args.rules_dir}\n", BOLD + WHITE))
    for r in rules:
        print(f"  {colorize(r.rule_code, MAGENTA + BOLD)}  {r.description}")
        for p in r.patterns:
            col = CONFIDENCE_COLOR.get(p.confidence.lower(), CYAN)
            print(f"    {colorize('●', col)} [{p.confidence}] {p.name}"
                  + (" (Luhn)" if p.validate_luhn else ""))
        print()


def cmd_scan(args) -> None:
    start = time.time()

    # Disable color if requested or not a tty
    if args.no_color or not sys.stdout.isatty():
        global RED, YELLOW, CYAN, GREEN, BOLD, DIM, WHITE, MAGENTA, RESET
        RED = YELLOW = CYAN = GREEN = BOLD = DIM = WHITE = MAGENTA = RESET = ""

    # Load rules and globals
    rules = load_rules(args.rules_dir)
    if not rules:
        print(colorize("[ERROR] No valid rules loaded. Exiting.", RED))
        sys.exit(1)
    globals_cfg = load_globals(args.rules_dir)

    print(colorize(f"\n  PCI Leak Scanner  │  {len(rules)} rules loaded\n", BOLD + WHITE))

    # Collect files
    files = collect_files(args.targets, args.recursive, globals_cfg, args.max_size)
    if not files:
        print(colorize("[WARN] No files to scan.", YELLOW))
        sys.exit(0)

    print(colorize(f"  Scanning {len(files)} file(s) with {args.workers} worker(s)...\n", DIM))

    # Build task args
    tasks = [(fp, rules, globals_cfg, args.context) for fp in files]

    all_findings: list[Finding] = []

    # Use multiprocessing pool
    use_progress = HAS_TQDM and not args.quiet and sys.stdout.isatty()

    with multiprocessing.Pool(processes=args.workers) as pool:
        if use_progress:
            it = tqdm(
                pool.imap_unordered(scan_file, tasks),
                total=len(tasks),
                unit="file",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
            )
        else:
            it = pool.imap_unordered(scan_file, tasks)

        for findings in it:
            all_findings.extend(findings)
            if not args.quiet:
                for f in findings:
                    print_finding(f, args.verbose)

    elapsed = time.time() - start

    # Summary
    print_summary(all_findings, len(files), elapsed)

    # Export
    if args.output_format:
        out_file = args.output_file or f"pci_report.{args.output_format}"
        if args.output_format == "json":
            export_json(all_findings, out_file)
        elif args.output_format == "csv":
            export_csv(all_findings, out_file)
        elif args.output_format == "sarif":
            export_sarif(all_findings, out_file, rules)

    # Exit code: non-zero if critical/high findings
    critical_count = sum(1 for f in all_findings if f.confidence in ("critical", "high"))
    sys.exit(1 if critical_count > 0 else 0)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "rules":
        cmd_rules(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
