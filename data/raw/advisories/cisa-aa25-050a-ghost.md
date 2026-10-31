---
doc_id: cisa-aa25-050a-ghost
title: "#StopRansomware: Ghost (Cring) Ransomware"
source_type: cisa_advisory
publisher: FBI, CISA, MS-ISAC
advisory_id: AA25-050A
published: 2025-02-19
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-050a
actor: Ghost
aliases: Cring; Crypt3r; Phantom; Strike; Hello; Wickrme; HsHarada; Rapture
model: closed_group
sectors: critical_infrastructure; education; healthcare; government; religious; technology; manufacturing; smb
---
# #StopRansomware: Ghost (Cring) Ransomware (AA25-050A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
Ghost actors, located in China, have conducted financially motivated ransomware attacks since early 2021 against organizations in more than 70 countries, including critical infrastructure, schools and universities, healthcare, government networks, religious institutions, technology and manufacturing companies, and small and medium-sized businesses. The group rotates names and file extensions; aliases include Cring, Crypt3r, Phantom, Strike, Hello, Wickrme, HsHarada and Rapture. Samples include Cring.exe, Ghost.exe, ElysiumO.exe and Locker.exe.

## Initial Access
Ghost gains access by exploiting public-facing applications with known, unpatched CVEs (T1190): Fortinet FortiOS CVE-2018-13379, Adobe ColdFusion CVE-2010-2861 and CVE-2009-3960, Microsoft SharePoint CVE-2019-0604, and the Microsoft Exchange ProxyShell chain (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207). Web shells are uploaded for persistence (T1505.003).

## Execution, Privilege Escalation and Persistence
Actors use PowerShell to deploy Cobalt Strike Beacon (T1059.001), cmd.exe to download content (T1059.003) and WMI to run PowerShell on other systems (T1047). Privilege escalation uses open-source tools such as BadPotato, GodPotato, SharpZeroLogon and SharpGPPPass (T1068) and SYSTEM token theft (T1134.001). Actors change passwords of existing accounts (T1098) and create local and domain accounts (T1136.001, T1136.002).

## Defense Evasion, Credential Access and Discovery
Ghost disables antivirus including Windows Defender (T1562.001), hides PowerShell activity (T1564.003) and clears Windows event logs (T1070.001). Credentials are dumped with hashdump and Mimikatz (T1003). Discovery uses Ladon 911 and SharpNBTScan (T1018), process listing (T1057), domain admin enumeration (T1087.002), SharpShares (T1135) and security software discovery (T1518.001).

## Command and Control, Exfiltration and Impact
C2 runs over HTTP/HTTPS via Cobalt Strike (T1071.001); IOX is used as a reverse proxy. Exfiltration is limited — usually less than hundreds of gigabytes — via the C2 channel and web shells (T1041) and limited Mega.nz use (T1567.002). Ghost actors typically spend only a short time in a network before deploying ransomware. It encrypts files (T1486), disables the Volume Shadow Copy Service and deletes shadow copies (T1490). Demands are typically tens to hundreds of thousands of dollars in cryptocurrency; notes claim stolen data will be sold.

## Mitigations
Keep known-good backups offline or segmented from source systems. Patch operating systems, software and firmware promptly, especially the exploited Fortinet, ColdFusion, SharePoint and Exchange flaws. Segment networks. Require phishing-resistant MFA for privileged and email accounts. Train users on phishing. Monitor for unauthorized PowerShell use and apply least privilege. Allowlist applications, scripts and network traffic. Alert on unusual network activity such as scans, admin account changes and unexpected scripts. Disable unused ports such as RDP, FTP 21 and SMB 445 or restrict them behind VPN/firewalls. Use email filtering with DMARC, DKIM and SPF.
