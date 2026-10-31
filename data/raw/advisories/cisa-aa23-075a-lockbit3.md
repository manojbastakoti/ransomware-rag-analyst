---
doc_id: cisa-aa23-075a-lockbit3
title: "#StopRansomware: LockBit 3.0"
source_type: cisa_advisory
publisher: FBI, CISA, MS-ISAC
advisory_id: AA23-075A
published: 2023-03-16
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a
actor: LockBit 3.0
aliases: LockBit Black; LockBit 2.0; LockBit
model: RaaS
sectors: critical_infrastructure; multi_sector
---
# #StopRansomware: LockBit 3.0 (AA23-075A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and indicators of compromise (IOCs).

## Overview
LockBit 3.0, also known as "LockBit Black", is a Ransomware-as-a-Service (RaaS) variant and a continuation of LockBit 2.0 and LockBit. The advisory notes code similarities with BlackMatter and BlackCat ransomware. Affiliates deploy it against a wide range of businesses and critical infrastructure organizations. Before encrypting data, affiliates steal files and threaten to publish them on Tor darknet leak sites. The FBI, CISA and MS-ISAC recommend hardening credentials, phishing-resistant MFA, patching, network segmentation and immutable offline backups.

## Initial Access
LockBit 3.0 affiliates gain initial access through exploitation of Remote Desktop Protocol (RDP) and other external remote services (T1133), drive-by compromise (T1189), phishing and spearphishing campaigns (T1566), abuse of valid accounts (T1078), and exploitation of public-facing applications (T1190).

## Execution, Persistence and Defense Evasion
Affiliates used the Chocolatey package manager as a software deployment tool (T1072). The malware can enable automatic logon to persist and escalate privileges (T1547 Boot or Logon Autostart Execution). LockBit 3.0 sends encrypted host and bot information to its C2 servers (T1027 Obfuscated Files or Information), deletes itself from disk after running (T1070.004 File Deletion), and requires a password to decrypt and launch its main component (T1480.001 Execution Guardrails: Environmental Keying), which hinders analysis.

## Credential Access, Discovery and Lateral Movement
Affiliates dumped LSASS memory with ProcDump (T1003.001 OS Credential Dumping: LSASS Memory). They scanned networks with SoftPerfect Network Scanner (T1046 Network Service Discovery) and enumerated hostnames, domains, drives and shares (T1082 System Information Discovery). The malware skips systems whose language settings match an exclusion list (T1614.001 System Language Discovery). Splashtop remote desktop software was used for lateral movement (T1021.001 Remote Desktop Protocol). FileZilla was used for C2 (T1071.002 File Transfer Protocols) and Plink to automate SSH actions (T1572 Protocol Tunnel).

## Tools
Custom: Stealbit (exfiltration) and the LockBit 3.0 encryptor. Freeware and open-source tools repurposed by affiliates: rclone, MEGA MegaSync, Impacket, Sysinternals PsExec and ProcDump, Mimikatz, Ngrok, Plink, FileZilla, WinSCP, Splashtop, SoftPerfect Network Scanner and Chocolatey. Penetration-testing frameworks Metasploit and Cobalt Strike were also observed, and PowerShell and batch scripts were seen in most intrusions.

## Exfiltration and Extortion
Before encryption, affiliates exfiltrate sensitive files using Stealbit, rclone (T1567.002 Exfiltration to Cloud Storage), MEGA and public file-sharing services (T1567 Exfiltration Over Web Service). The ransom note threatens to publish data on Tor leak sites and warns that competitors could buy it.

## Impact
LockBit 3.0 encrypts data on local and remote devices (T1486 Data Encrypted for Impact), terminates processes and services (T1489 Service Stop), deletes volume shadow copies (T1490 Inhibit System Recovery), deletes logs and empties the recycle bin (T1485 Data Destruction), and changes the wallpaper and icons to LockBit branding (T1491.001 Internal Defacement).

## Mitigations
Keep multiple copies of sensitive data and servers in a physically separate, segmented, secure location. Apply NIST password guidance (long passwords, hashing, no reuse, lockout after failed attempts). Require phishing-resistant MFA for webmail, VPNs and critical systems. Keep operating systems, software and firmware patched. Segment networks to limit lateral movement. Log and monitor network traffic and use EDR to detect lateral connections. Keep antivirus updated with real-time detection on all hosts. Audit domain controllers, servers, workstations and Active Directory for new or unrecognized accounts. Enforce least privilege and just-in-time administrative access. Disable unused ports. Add external-sender email banners and disable hyperlinks in received email. Disable command-line and scripting activity where possible. Maintain encrypted, immutable, offline backups covering the whole organization and test restoration. Validate security controls against the advisory's ATT&CK techniques.
