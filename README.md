⚔️ MITRE ATT&CK Detection Rule Builder
> **Describe a security behavior. Get production-ready KQL and SPL detection rules — instantly.**
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)
![Microsoft Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?logo=microsoft)
![Splunk](https://img.shields.io/badge/SIEM-Splunk-000000?logo=splunk)
![Gemini AI](https://img.shields.io/badge/AI-Google%20Gemini-4285F4?logo=google)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
---
What it does
Type a behavior in plain English. The tool maps it to MITRE ATT&CK techniques and generates ready-to-deploy detection rules for both Microsoft Sentinel (KQL) and Splunk (SPL). Optionally use Google Gemini AI to get a plain-English explanation of what each rule does, why it matters, and what false positives look like.
---
Features
Behavior-to-Technique Mapping — natural language input maps to ATT&CK technique IDs
Dual-SIEM Rule Generation — both KQL (Sentinel) and SPL (Splunk) for every technique
Google Gemini Integration — AI-generated rule explanations for analyst onboarding
Direct Technique Lookup — query by technique ID (e.g. `T1110`) directly
JSON Export — machine-readable rule output for integration with SOAR playbooks
8 Techniques Covered — T1078, T1110, T1021, T1071, T1566, T1059, T1486, T1055
---
Quickstart
```bash
git clone https://github.com/vinith-sec/mitre-rule-builder.git
cd mitre-rule-builder
pip install -r requirements.txt

# From a behavior description
python rule_builder.py --behavior "brute force on Entra ID accounts"

# From a technique ID
python rule_builder.py --technique T1110

# With Gemini AI explanation
export GEMINI_API_KEY="your_free_gemini_api_key"
python rule_builder.py --behavior "C2 beaconing over DNS" --explain

# Export to JSON for SOAR
python rule_builder.py --technique T1021 --export rules.json --format json

# List all available techniques
python rule_builder.py --list
```
---
Example output
```
======================================================================
  MITRE ATT&CK DETECTION RULE BUILDER
  Generated: 2025-04-01 14:22 UTC
======================================================================

┌─ T1110 — Brute Force
│  Tactic     : Credential Access
│  Description: Adversaries use brute force to gain access to accounts.
│
├── MICROSOFT SENTINEL (KQL)
│
│  // T1110 — Brute Force / Password Spray
│  SigninLogs
│  | where TimeGenerated > ago(1h)
│  | where ResultType != "0"
│  | summarize FailureCount = count() by UserPrincipalName, bin(TimeGenerated, 5m)
│  | where FailureCount > 10
│  | order by FailureCount desc
│
├── SPLUNK (SPL)
│
│  index=windows EventCode=4625
│  | stats count as failure_count by user, _time span=5m
│  | where failure_count > 10
│
└─────────────────────────────────────────────────────────────────────
```
---
Available techniques
ID	Technique	Tactic
T1078	Valid Accounts	Defense Evasion / Persistence
T1110	Brute Force	Credential Access
T1021	Remote Services (Lateral Movement)	Lateral Movement
T1071	C2 Communication (DNS Beaconing)	Command and Control
T1566	Phishing	Initial Access
T1059	Command and Scripting Interpreter	Execution
T1486	Data Encrypted for Impact (Ransomware)	Impact
T1055	Process Injection	Defense Evasion
---
Gemini API (free)
Get a free API key at aistudio.google.com — no credit card required.
```bash
export GEMINI_API_KEY="AIza..."
python rule_builder.py --behavior "ransomware mass file encryption" --explain
```
---
Project structure
```
mitre-rule-builder/
├── rule_builder.py   # Core engine
├── requirements.txt
└── README.md
```
---
Author
Vinith Kumaragurubaran — SOC Analyst | CompTIA Security+ | Cisco CCNA  
linkedin.com/in/vinith-kumaragurubaran · github.com/vinith-sec
