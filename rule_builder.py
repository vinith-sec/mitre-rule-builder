"""
MITRE ATT&CK Detection Rule Builder
=====================================
Maps security behaviors to ATT&CK techniques and auto-generates
Microsoft Sentinel (KQL) and Splunk (SPL) detection rules.
Optionally uses Google Gemini AI for natural-language rule explanation.

Author : Vinith Kumaragurubaran | github.com/vinith-sec
License: MIT
"""

import os
import json
import argparse
import datetime
import requests

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# ── ATT&CK Technique Library ──────────────────────────────────────────────────
TECHNIQUES = {
    "T1078": {
        "name":    "Valid Accounts",
        "tactic":  "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": "Adversaries use compromised credentials to maintain access.",
        "keywords": ["valid accounts", "credential", "stolen credentials", "account takeover"],
        "kql": """// T1078 — Valid Accounts
// Detects sign-ins from rare or anomalous locations for a given user
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"  // Successful sign-in
| summarize
    SigninCount   = count(),
    Countries     = make_set(LocationDetails.countryOrRegion),
    IPAddresses   = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 5m)
| where array_length(Countries) > 1
| project TimeGenerated, UserPrincipalName, SigninCount, Countries, IPAddresses
| order by TimeGenerated desc""",
        "spl": """// T1078 — Valid Accounts (Splunk)
index=azure_ad sourcetype=azure:aad:signin result_type=0
| stats count as signin_count values(src_ip) as ip_list values(country) as countries
    by user, _time span=5m
| where mvcount(countries) > 1
| table _time user signin_count ip_list countries
| sort -_time""",
    },
    "T1110": {
        "name":    "Brute Force",
        "tactic":  "Credential Access",
        "description": "Adversaries use brute force to gain access to accounts.",
        "keywords": ["brute force", "password spray", "failed login", "multiple failures", "lockout"],
        "kql": """// T1110 — Brute Force / Password Spray
// Detects >10 failed sign-ins for a single user within 5 minutes
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"  // Failed sign-in
| summarize
    FailureCount = count(),
    ErrorCodes   = make_set(ResultType),
    SourceIPs    = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailureCount > 10
| project TimeGenerated, UserPrincipalName, FailureCount, ErrorCodes, SourceIPs
| order by FailureCount desc""",
        "spl": """// T1110 — Brute Force (Splunk)
index=windows EventCode=4625
| stats count as failure_count values(src_ip) as src_ips by user, _time span=5m
| where failure_count > 10
| table _time user failure_count src_ips
| sort -failure_count""",
    },
    "T1021": {
        "name":    "Remote Services — Lateral Movement",
        "tactic":  "Lateral Movement",
        "description": "Adversaries use legitimate remote services to move through the environment.",
        "keywords": ["lateral movement", "smb", "rdp", "remote desktop", "psexec", "wmi", "east-west"],
        "kql": """// T1021 — Lateral Movement via SMB
// Detects a single host connecting to >5 internal systems over SMB in 10 minutes
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where RemotePort in (445, 139)          // SMB ports
| where ActionType == "ConnectionSuccess"
| summarize
    TargetCount = dcount(RemoteIP),
    Targets     = make_set(RemoteIP)
    by DeviceName, LocalIP, bin(TimeGenerated, 10m)
| where TargetCount > 5
| project TimeGenerated, DeviceName, LocalIP, TargetCount, Targets
| order by TargetCount desc""",
        "spl": """// T1021 — Lateral Movement via SMB (Splunk)
index=network dest_port=445 action=allowed
| stats dc(dest_ip) as target_count values(dest_ip) as targets by src_ip, _time span=10m
| where target_count > 5
| table _time src_ip target_count targets
| sort -target_count""",
    },
    "T1071": {
        "name":    "Application Layer Protocol — C2",
        "tactic":  "Command and Control",
        "description": "Adversaries communicate with C2 using common application protocols to blend in.",
        "keywords": ["c2", "command and control", "beacon", "beaconing", "dns tunnel", "exfiltration", "callback"],
        "kql": """// T1071 — C2 Beaconing via DNS
// Detects high-frequency DNS queries to a single external domain (beacon pattern)
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "A"
| where not(ipv4_is_private(ClientIP))   // external destinations
| summarize
    QueryCount  = count(),
    UniqueHosts = dcount(Computer)
    by Name, bin(TimeGenerated, 5m)
| where QueryCount > 30 and UniqueHosts == 1  // single host, high frequency
| project TimeGenerated, SuspiciousDomain = Name, QueryCount, UniqueHosts
| order by QueryCount desc""",
        "spl": """// T1071 — C2 DNS Beaconing (Splunk)
index=dns query_type=A
| stats count as query_count dc(src_ip) as unique_src by query, _time span=5m
| where query_count > 30 AND unique_src == 1
| table _time query query_count unique_src
| sort -query_count""",
    },
    "T1566": {
        "name":    "Phishing",
        "tactic":  "Initial Access",
        "description": "Adversaries send phishing emails to gain initial access.",
        "keywords": ["phishing", "spear phishing", "malicious attachment", "credential harvest", "spf fail", "dkim fail"],
        "kql": """// T1566 — Phishing Email Detection
// Detects inbound emails failing SPF/DKIM with suspicious attachment types
EmailEvents
| where TimeGenerated > ago(24h)
| where EmailDirection == "Inbound"
| where AuthenticationDetails has "SPF:Fail" or AuthenticationDetails has "DKIM:Fail"
| where AttachmentCount > 0
| project
    TimeGenerated,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    AuthenticationDetails,
    AttachmentCount,
    UrlCount
| order by TimeGenerated desc""",
        "spl": """// T1566 — Phishing Detection (Splunk)
index=email direction=inbound (spf_result=fail OR dkim_result=fail) attachment_count>0
| table _time sender recipient subject spf_result dkim_result attachment_count
| sort -_time""",
    },
    "T1059": {
        "name":    "Command and Scripting Interpreter",
        "tactic":  "Execution",
        "description": "Adversaries use scripting interpreters to execute malicious commands.",
        "keywords": ["powershell", "cmd", "script", "command interpreter", "bash", "wscript", "cscript"],
        "kql": """// T1059 — Suspicious PowerShell Execution
// Detects PowerShell launched from unusual parent processes with encoded commands
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "bypass", "-nop", "iex", "invoke-expression")
| where InitiatingProcessFileName !in~ ("explorer.exe", "svchost.exe")
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    AccountName
| order by TimeGenerated desc""",
        "spl": """// T1059 — Suspicious PowerShell (Splunk)
index=windows EventCode=4688 NewProcessName="*powershell.exe"
    (CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*iex*")
| table _time ComputerName ParentProcessName CommandLine user
| sort -_time""",
    },
    "T1486": {
        "name":    "Data Encrypted for Impact — Ransomware",
        "tactic":  "Impact",
        "description": "Adversaries encrypt files to disrupt availability and extort victims.",
        "keywords": ["ransomware", "encrypt", "ransom", "lockbit", "file extension", "mass rename"],
        "kql": """// T1486 — Ransomware File Mass Modification
// Detects a single process modifying >100 files within 2 minutes
DeviceFileEvents
| where TimeGenerated > ago(30m)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| summarize
    FileCount    = count(),
    Extensions   = make_set(tostring(split(FileName, ".")[-1]))
    by InitiatingProcessFileName, DeviceName, bin(TimeGenerated, 2m)
| where FileCount > 100
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileCount, Extensions
| order by FileCount desc""",
        "spl": """// T1486 — Ransomware Mass File Modification (Splunk)
index=sysmon EventCode=11
| stats count as file_count values(TargetFilename) as files by Image, ComputerName, _time span=2m
| where file_count > 100
| table _time ComputerName Image file_count files
| sort -file_count""",
    },
    "T1055": {
        "name":    "Process Injection",
        "tactic":  "Defense Evasion / Privilege Escalation",
        "description": "Adversaries inject code into processes to evade detection and escalate privileges.",
        "keywords": ["process injection", "dll injection", "hollowing", "shellcode", "inject"],
        "kql": """// T1055 — Process Injection
// Detects unusual cross-process memory writes (common injection indicator)
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName !in~ ("svchost.exe", "csrss.exe", "lsass.exe")
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    ProcessId,
    FileName
| order by TimeGenerated desc""",
        "spl": """// T1055 — Process Injection (Splunk Sysmon)
index=sysmon EventCode=8
| where SourceImage != TargetImage
| table _time ComputerName SourceImage TargetImage
| sort -_time""",
    },
}


# ── Behavior → Technique mapping ──────────────────────────────────────────────
def map_behavior(behavior: str) -> list:
    """Map a free-text behavior description to MITRE techniques."""
    behavior_lower = behavior.lower()
    matches = []
    for tid, data in TECHNIQUES.items():
        if any(kw in behavior_lower for kw in data["keywords"]):
            matches.append(tid)
    return matches


# ── Gemini AI explanation ─────────────────────────────────────────────────────
def gemini_explain(technique_id: str, technique_name: str, kql: str) -> str:
    """Use Gemini API to explain a detection rule in plain English."""
    if not GEMINI_API_KEY:
        return "(Gemini API key not set — set GEMINI_API_KEY env variable for AI explanations)"

    prompt = (
        f"You are a SOC analyst explaining a Microsoft Sentinel KQL detection rule to a junior analyst.\n\n"
        f"Technique: {technique_id} — {technique_name}\n\n"
        f"KQL Rule:\n{kql}\n\n"
        f"Explain in 3 bullet points: (1) what this rule detects, (2) why it matters, "
        f"(3) what a false positive might look like. Be concise and practical."
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code == 200:
            return r.json()["candidates"][0]["content"]["parts"][0]["text"]
        return f"Gemini API error: HTTP {r.status_code}"
    except Exception as e:
        return f"Gemini API error: {e}"


# ── Rule output ───────────────────────────────────────────────────────────────
def build_rule_output(technique_ids: list, explain: bool = False) -> str:
    lines = [
        "=" * 70,
        "  MITRE ATT&CK DETECTION RULE BUILDER",
        f"  Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 70,
        "",
    ]
    if not technique_ids:
        lines.append("[!] No matching MITRE techniques found. Try more specific keywords.")
        lines.append("    Examples: 'brute force', 'lateral movement via SMB', 'C2 beaconing', 'phishing'")
        return "\n".join(lines)

    for tid in technique_ids:
        t = TECHNIQUES[tid]
        lines += [
            f"┌─ {tid} — {t['name']}",
            f"│  Tactic     : {t['tactic']}",
            f"│  Description: {t['description']}",
            "│",
            "├── MICROSOFT SENTINEL (KQL)",
            "│",
            *[f"│  {l}" for l in t["kql"].strip().split("\n")],
            "│",
            "├── SPLUNK (SPL)",
            "│",
            *[f"│  {l}" for l in t["spl"].strip().split("\n")],
            "│",
        ]
        if explain:
            explanation = gemini_explain(tid, t["name"], t["kql"])
            lines += [
                "├── AI EXPLANATION (Gemini)",
                "│",
                *[f"│  {l}" for l in explanation.strip().split("\n")],
                "│",
            ]
        lines += ["└" + "─" * 69, ""]

    return "\n".join(lines)


# ── Export to file ────────────────────────────────────────────────────────────
def export_rules(technique_ids: list, output_path: str, fmt: str = "txt"):
    content = build_rule_output(technique_ids, explain=False)
    if fmt == "json":
        data = {
            "generated": datetime.datetime.utcnow().isoformat(),
            "techniques": [
                {
                    "id":       tid,
                    "name":     TECHNIQUES[tid]["name"],
                    "tactic":   TECHNIQUES[tid]["tactic"],
                    "kql":      TECHNIQUES[tid]["kql"].strip(),
                    "spl":      TECHNIQUES[tid]["spl"].strip(),
                }
                for tid in technique_ids if tid in TECHNIQUES
            ]
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
    else:
        with open(output_path, "w") as f:
            f.write(content)
    print(f"[✓] Rules exported → {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Detection Rule Builder — generate KQL and SPL rules from behaviors"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--behavior", "-b", help='Describe the behavior (e.g. "brute force on Entra ID")')
    group.add_argument("--technique", "-t", help='Direct technique ID lookup (e.g. T1110)')
    group.add_argument("--list",      "-l", action="store_true", help="List all available techniques")

    parser.add_argument("--explain", "-e", action="store_true",
                        help="Use Gemini AI to explain each rule (requires GEMINI_API_KEY)")
    parser.add_argument("--export", help="Export rules to file (e.g. rules.txt or rules.json)")
    parser.add_argument("--format", choices=["txt", "json"], default="txt", help="Export format")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable MITRE ATT&CK Techniques:\n")
        for tid, t in TECHNIQUES.items():
            print(f"  {tid}  {t['name']:<45} {t['tactic']}")
        print()
        return

    if args.technique:
        tid = args.technique.upper()
        if tid not in TECHNIQUES:
            print(f"[!] Technique {tid} not in library. Run --list to see available techniques.")
            return
        technique_ids = [tid]
    else:
        print(f"\n[*] Mapping behavior: \"{args.behavior}\"")
        technique_ids = map_behavior(args.behavior)
        if technique_ids:
            print(f"[✓] Matched techniques: {', '.join(technique_ids)}\n")
        else:
            print("[!] No techniques matched. Try: brute force, lateral movement, C2, phishing, ransomware")

    output = build_rule_output(technique_ids, explain=args.explain)
    print(output)

    if args.export:
        export_rules(technique_ids, args.export, args.format)


if __name__ == "__main__":
    main()
