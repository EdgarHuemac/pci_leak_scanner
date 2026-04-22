# PCI Leak Scanner

A fast, extensible command-line tool to detect PCI DSS data leakage in log files, source code, and any raw text. Identifies credit card numbers, API keys, passwords, tokens, and more using a hot-pluggable JSON rule engine.

---

## Features

| Capability | Detail |
|---|---|
| **6 rule categories** out of the box | PANs, CVVs, API keys, passwords, PII, crypto wallets |
| **Luhn algorithm** validation | Distinguishes real card numbers from random digit strings |
| **Multiprocessing** | Scans multiple files in parallel using all CPU cores |
| **Streaming reads** | Line-by-line processing — handles arbitrarily large log files |
| **Color-coded output** | 🔴 Critical / 🟡 Medium / 🔵 Low |
| **3 export formats** | JSON, CSV, SARIF (CI/CD ready) |
| **Allow-listing** | Ignore test cards, directories, file extensions |
| **Context lines** | Shows N lines before/after each match |
| **Hot-pluggable rules** | Drop a `.json` file in `/rules` — no code changes needed |

---

## Quick Start

```bash
# Install dependency (optional but recommended for progress bar)
pip install tqdm

# Scan a single file
python pci_scanner.py scan /var/log/app.log

# Scan a directory recursively with verbose output
python pci_scanner.py scan ./logs/ --recursive -v

# Full verbose with context and export to JSON
python pci_scanner.py scan ./src/ -r -vv --context 3 --output-format json --output-file report.json

# Export SARIF for CI/CD pipeline integration
python pci_scanner.py scan ./logs/ -r --output-format sarif --output-file results.sarif

# List all loaded rules
python pci_scanner.py rules
```

---

## CLI Reference

### `scan` command

```
pci-scanner scan [OPTIONS] PATH [PATH ...]
```

| Option | Default | Description |
|---|---|---|
| `-r, --recursive` | off | Recurse into sub-directories |
| `-v` | off | Verbose: adds pattern name, confidence, Luhn result |
| `-vv` | off | Very verbose: adds mitigation advice + context lines |
| `--rules-dir DIR` | `./rules` | Directory containing JSON rule files |
| `--context N` | `2` | Lines of context before/after each match |
| `--max-size MB` | none | Skip files larger than this size in MB |
| `--workers N` | CPU count | Parallel worker processes |
| `--output-format` | none | `json`, `csv`, or `sarif` |
| `--output-file FILE` | auto | Path for exported report |
| `--no-color` | off | Disable ANSI color output |
| `--quiet` | off | Suppress per-finding output (summary only) |

**Exit codes:**
- `0` — No HIGH or CRITICAL findings
- `1` — At least one HIGH or CRITICAL finding (useful for CI gates)

### `rules` command

```
pci-scanner rules [--rules-dir DIR]
```

Lists all loaded rules and their patterns with confidence levels.

---

## Verbosity Levels

**Default** (no flags):
```
CRITICAL │ app.log:5 │ [PCI_FIN_0001] │ Match: '4532015112830366'
```

**`-v` (verbose):**
```
CRITICAL │ app.log:5 │ [PCI_FIN_0001] │ Match: '4532015112830366'
  Pattern    : Visa Card
  Confidence : CRITICAL  ✓ Luhn valid
  Rule       : Detection of Primary Account Numbers (PAN)
```

**`-vv` (very verbose):**
```
CRITICAL │ app.log:5 │ [PCI_FIN_0001] │ Match: '4532015112830366'
  Pattern    : Visa Card
  Confidence : CRITICAL  ✓ Luhn valid
  Rule       : Detection of Primary Account Numbers (PAN)
  Mitigation : Ensure logs are masked. Use tokenization or vaulting...
  ── Context ──────────────────────
    2024-01-15 INFO  [PaymentService] Processing payment for user_id=10482
  → 4532015112830366
    2024-01-15 INFO  [PaymentService] Authorization: Bearer eyJ...
```

---

## Rule File Format

Drop any `.json` file into the `rules/` directory. The scanner loads all rules at startup and validates their schema.

```json
{
  "rule_code": "PCI_CUSTOM_001",
  "description": "Human-readable description of what this rule detects",
  "mitigation": "Recommended steps to remediate this type of leak",
  "patterns": [
    {
      "name": "Pattern label shown in output",
      "regex": "your_regex_here",
      "confidence": "High",
      "validate_luhn": false
    }
  ]
}
```

### Schema fields

| Field | Required | Values |
|---|---|---|
| `rule_code` | ✅ | Unique string, e.g. `PCI_FIN_0001` |
| `description` | ✅ | Human-readable string |
| `mitigation` | ✅ | Remediation guidance string |
| `patterns` | ✅ | Array of pattern objects |
| `patterns[].name` | ✅ | Label for this pattern |
| `patterns[].regex` | ✅ | Python-compatible regex string |
| `patterns[].confidence` | ✅ | `Low`, `Medium`, `High`, or `Critical` |
| `patterns[].validate_luhn` | ❌ | `true`/`false` (default: `false`) |

Rule files can contain a single object **or** a JSON array of rule objects.

### Confidence + Luhn escalation

When `validate_luhn: true` and the match passes the Luhn check:
- `High` → escalates to `Critical`
- `Medium` → escalates to `High`

When Luhn fails on a `High`/`Critical` pattern, confidence is downgraded to `Medium` to reduce false positives.

---

## Allow-List Configuration (`rules/globals.json`)

```json
{
  "ignored_strings": [
    "4111111111111111",
    "MASKED",
    "REDACTED"
  ],
  "ignored_extensions": [
    ".png", ".exe", ".zip"
  ],
  "ignored_directories": [
    ".git", "node_modules", "__pycache__"
  ]
}
```

- **`ignored_strings`**: Exact match values to skip (case-insensitive). Useful for well-known test card numbers.
- **`ignored_extensions`**: Binary or non-text file types to skip.
- **`ignored_directories`**: Directory names to skip at any depth in the traversal.

---

## Built-in Rules

| Rule Code | Category | Patterns |
|---|---|---|
| `PCI_FIN_0001` | Credit Card PANs | Visa, MasterCard, Amex, Discover, Diners, JCB, Generic 16-digit |
| `PCI_FIN_0002` | CVV / CVC codes | CVV context patterns, card keyword proximity |
| `PCI_AUTH_0001` | Auth Tokens & API Keys | Bearer tokens, JWTs, AWS keys, GitHub PATs, Stripe keys, generic secrets |
| `PCI_AUTH_0002` | Plaintext Passwords | Password in URL, field assignment, Basic Auth in URL |
| `PCI_PII_0001` | PII / Banking Data | US SSN, ABA routing numbers, IBAN, card expiry, cardholder name |
| `PCI_PII_0002` | Cryptocurrency | Bitcoin (P2PKH + SegWit), Ethereum addresses, WIF private keys |

---

## CI/CD Integration Example

```yaml
# GitHub Actions example
- name: PCI Leak Scan
  run: |
    python pci_scanner.py scan ./logs/ --recursive \
      --output-format sarif \
      --output-file pci-results.sarif \
      --quiet

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pci-results.sarif
```

The tool exits with code `1` if any HIGH or CRITICAL findings are detected, making it suitable as a pipeline gate.

---

## Project Structure

```
pci_scanner/
├── pci_scanner.py          # Main CLI tool
├── requirements.txt        # tqdm (optional)
├── sample_test.log         # Example log with test PCI data
└── rules/
    ├── globals.json            # Allow-list configuration
    ├── PCI_FIN_credit_cards.json
    ├── PCI_AUTH_tokens.json
    └── PCI_PII_banking.json
```

---

## Requirements

- Python 3.10+
- `tqdm` (optional — for progress bar on large directory scans)

```bash
pip install tqdm
```

No other external dependencies.
