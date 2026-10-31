---
doc_id: cisa-aa25-071a-medusa
title: "#StopRansomware: Medusa Ransomware"
source_type: cisa_advisory
publisher: FBI, CISA, MS-ISAC
advisory_id: AA25-071A
published: 2025-03-12
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
actor: Medusa
aliases: 
model: RaaS
sectors: healthcare; education; legal; insurance; technology; manufacturing; critical_infrastructure
---
# #StopRansomware: Medusa Ransomware (AA25-071A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
Medusa is a Ransomware-as-a-Service (RaaS) variant first identified in June 2021. It began as a closed operation and later moved to an affiliate model, though developers still control ransom negotiation. As of February 2025, over 300 victims were affected across medical, education, legal, insurance, technology and manufacturing sectors. Medusa is unrelated to MedusaLocker and to the Medusa mobile malware.

## Initial Access
Medusa developers recruit initial access brokers (IABs) on cybercriminal forums. Access is also gained through phishing to steal credentials (T1566) and exploitation of unpatched vulnerabilities (T1190) including ScreenConnect CVE-2024-1709 and Fortinet EMS SQL injection CVE-2023-48788.

## Defense Evasion
Medusa actors rely on living-off-the-land tools. They delete previously installed tools and PowerShell command history (T1070, T1070.003), obfuscate strings and run base64-encoded commands (T1027, T1027.013), and attempt to kill or delete EDR tools, sometimes using vulnerable or signed drivers (T1562.001 Disable or Modify Tools).

## Discovery and Credential Access
Network enumeration used Advanced IP Scanner and SoftPerfect Network Scanner (T1046). Actors enumerated files (T1083), shares (T1135), network configuration (T1016), system information via systeminfo (T1082) and domain groups (T1069.002). Mimikatz was used to dump LSASS (T1003.001).

## Lateral Movement and Command and Control
Lateral movement used RDP (T1021.001), PsExec to run payloads as SYSTEM (T1569.002), PowerShell and cmd.exe (T1059.001, T1059.003), WMI (T1047), and many legitimate remote access tools (T1219): AnyDesk, Atera, ConnectWise, eHorus, N-able, SimpleHelp and Splashtop. PDQ Deploy and BigFix were used to deploy the encryptor (T1072 Software Deployment Tools). Tools were transferred with PowerShell, cmd and certutil (T1105). A powerfun.ps1 stager created TLS reverse or bind shells over port 443 (T1071.001), and Ligolo and Cloudflared were used for tunneling. A domain account was created for persistence (T1136.002).

## Exfiltration, Impact and Extortion
Rclone sends data to Medusa C2 servers (T1567.002). The encryptor gaze.exe encrypts files with AES-256 and the .medusa extension (T1486), deletes shadow copies (T1490), stops backup, security and database services (T1489) and manually shuts down and encrypts virtual machines (T1529). Medusa uses double extortion with a .onion leak site and countdown timers; victims can pay $10,000 to add a day. The note gives 48 hours to make contact via Tor chat or Tox. One victim was contacted by a second actor after paying, a possible triple-extortion scheme.

## Mitigations
Keep multiple copies of sensitive data and servers in separate secure locations. Follow NIST password standards. Require MFA for webmail, VPNs and critical systems. Patch, prioritizing known exploited vulnerabilities on internet-facing systems. Segment networks, monitor traffic with EDR, and require VPNs or jump hosts for remote access. Monitor for unauthorized scanning and block unknown origins from internal remote services. Audit admin accounts, apply least privilege and check AD for unrecognized accounts. Disable unnecessary command-line and scripting and unused ports. Keep offline, encrypted, immutable backups and test restoration.
