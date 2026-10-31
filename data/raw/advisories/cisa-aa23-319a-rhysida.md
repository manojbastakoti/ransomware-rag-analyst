---
doc_id: cisa-aa23-319a-rhysida
title: "#StopRansomware: Rhysida Ransomware"
source_type: cisa_advisory
publisher: FBI, CISA, MS-ISAC
advisory_id: AA23-319A
published: 2023-11-15
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a
actor: Rhysida
aliases: Vice Society (similarities); DEV-0832
model: RaaS
sectors: education; healthcare; manufacturing; technology; government
---
# #StopRansomware: Rhysida Ransomware (AA23-319A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
Rhysida ransomware has been observed since May 2023 targeting education, healthcare, manufacturing, information technology and government organizations as "targets of opportunity". Open-source reporting notes similarities with Vice Society (DEV-0832) activity and indicates Rhysida operates as Ransomware-as-a-Service, with ransoms split between the group and affiliates.

## Initial Access
Rhysida actors abuse valid credentials on VPN access points, often where MFA was not enabled (T1078 Valid Accounts). They exploited Zerologon (CVE-2020-1472) in Microsoft Netlogon (T1190) and conducted successful phishing attacks (T1566).

## Execution and Defense Evasion
Actors ran PowerShell discovery commands and scripts (T1059.001), often in hidden windows (T1564.003), and batch scripts via cmd.exe to stage the ransomware (T1059.003). The encryptor PE is injected into running processes (T1055.002 Portable Executable Injection). They cleared System, Application and Security logs with wevtutil (T1070.001 Clear Windows Event Logs), deleted the encryptor after running (T1070.004) and modified the registry via cmd.exe (T1112).

## Credential Access and Discovery
Actors dumped NTDS credentials with secretsdump and ntdsutil (T1003.003 NTDS). Discovery used ipconfig (T1016), net group (T1018, T1069.002), whoami and net (T1033), net localgroup (T1069.001), net user (T1087.002) and nltest for domain trusts (T1482). PowerView was used for reconnaissance.

## Lateral Movement and Tools
Lateral movement used RDP (T1021.001), PuTTY over SSH (T1021.004) and heavy use of PsExec. AnyDesk was used for remote access and persistence (T1219). PortStarter, a Go-based backdoor, modifies firewall settings and opens ports to C2 servers. The encryptor has been seen named conhost.exe.

## Impact and Extortion
Rhysida encrypts data using a 4096-bit RSA key with ChaCha20 (T1486). It practices double extortion, threatening to publish exfiltrated data, with Bitcoin payment (T1657). A PDF ransom note named "CriticalBreachDetected" provides a unique code and a Tor portal.

## Mitigations
Prioritize patching known exploited vulnerabilities on internet-facing systems. Require phishing-resistant MFA for webmail, VPNs and critical-system accounts. Restrict command-line and scripting use; restrict PowerShell via Group Policy to specific administrators and upgrade it. Enable command-line auditing, process tracking and enhanced PowerShell logging with at least 180 days retention, forwarded to a hardened central log server. Limit RDP to known users with MFA and Remote Credential Guard, log attempts and enforce lockouts. Allowlist approved remote access tools. Segment networks, monitor with EDR, apply least privilege and just-in-time access. Keep offline, encrypted, immutable backups in a separate location and test them. Add external email banners and disable hyperlinks.
