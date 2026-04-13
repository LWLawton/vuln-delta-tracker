# Vulnerability Delta Tracker (v1)

A lightweight Python tool to compare two vulnerability scan CSV exports and identify:

- New findings
- Resolved findings
- Persistent findings

---

## 🚀 Why this tool?

Security teams waste time reviewing the same vulnerabilities every scan cycle.

This tool helps you focus only on what changed.

---

## 📥 Inputs

Two CSV files:
- Previous scan
- Current scan

Supported fields (auto-detected):
- hostname / host / ip
- plugin id / vuln id / qid
- port (optional)
- severity (optional)

---

## 📤 Outputs

Generated in `/output`:

- `new_findings.csv`
- `resolved_findings.csv`
- `persistent_findings.csv`

---

## 🛠️ Installation

```bash
pip install pandas
