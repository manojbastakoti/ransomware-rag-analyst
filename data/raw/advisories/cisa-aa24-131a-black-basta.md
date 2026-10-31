---
doc_id: cisa-aa24-131a-black-basta
title: "#StopRansomware: Black Basta"
source_type: cisa_advisory
publisher: FBI, CISA, HHS, MS-ISAC
advisory_id: AA24-131A
published: 2024-05-10
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
actor: Black Basta
aliases: 
model: RaaS
sectors: healthcare; critical_infrastructure
---
# #StopRansomware: Black Basta (AA24-131A, updated 2024-11-08)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
Black Basta is a Ransomware-as-a-Service (RaaS) variant first identified in April 2022. As of May 2024 its affiliates had impacted over 500 organizations globally, mainly in North America, Europe and Australia, encrypting and stealing data from at least 12 of 16 critical infrastructure sectors, including Healthcare and Public Health (HPH).

## Initial Access
Affiliates primarily use spearphishing (T1566). Researchers also reported Qakbot as an initial access vector. Starting February 2024, affiliates exploited ConnectWise ScreenConnect vulnerability CVE-2024-1709 (T1190 Exploit Public-Facing Application). Valid credentials were abused in some cases (T1078). A newer social-engineering pattern combines email bombing with phone calls or Microsoft Teams messages in which the actor poses as technical support (T1566.004 Spearphishing Voice) and convinces users to install remote access tools such as Quick Assist or AnyDesk (T1204 User Execution).

## Discovery, Privilege Escalation and Defense Evasion
Affiliates used SoftPerfect network scanner (netscan.exe) for discovery, and ran reconnaissance tools with innocuous file names such as "Intel" or "Dell" (T1036 Masquerading). For privilege escalation they used credential scraping with Mimikatz and exploited ZeroLogon, NoPac and PrintNightmare (T1068 Exploitation for Privilege Escalation). A tool called Backstab was used to disable EDR (T1562.001 Disable or Modify Tools), and PowerShell was used to disable antivirus products (T1059.001).

## Lateral Movement and Tools
Lateral movement used BITSAdmin, PsExec, Remote Desktop Protocol (RDP), Splashtop, ScreenConnect and Cobalt Strike beacons. Remote access tools include AnyDesk, Microsoft Quick Assist, ScreenConnect and Splashtop.

## Exfiltration and Extortion
Black Basta uses double extortion. Data is exfiltrated with RClone and in some cases WinSCP to actor-controlled accounts. Ransom notes usually omit a ransom demand or payment instructions and instead provide a unique code and a Tor .onion URL. Victims typically have 10 to 12 days to pay before data is published on the "Basta News" leak site.

## Impact
Affiliates delete volume shadow copies with vssadmin.exe (T1490 Inhibit System Recovery) and encrypt files using ChaCha20 with an RSA-4096 public key (T1486 Data Encrypted for Impact).

## Mitigations
Install OS, software and firmware updates promptly, prioritizing Known Exploited Vulnerabilities (KEV). Require phishing-resistant MFA, especially for privileged accounts. Train users to recognize and report phishing and help-desk impersonation. Secure remote access software following joint guidance. Back up critical systems and device configurations. Apply the #StopRansomware Guide. HPH organizations should know all assets and dependencies, protect ePHI, and prioritize vulnerability management using KEV, EPSS, CVSS and SSVC. Validate security controls against the advisory's ATT&CK techniques.
