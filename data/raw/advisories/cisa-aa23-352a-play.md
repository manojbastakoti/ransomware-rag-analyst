---
doc_id: cisa-aa23-352a-play
title: "#StopRansomware: Play Ransomware"
source_type: cisa_advisory
publisher: FBI, CISA, ASD's ACSC
advisory_id: AA23-352A
published: 2023-12-18
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a
actor: Play
aliases: Playcrypt
model: closed_group
sectors: critical_infrastructure; multi_sector
---
# #StopRansomware: Play Ransomware (AA23-352A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
The Play ransomware group (also known as Playcrypt) has affected a wide range of businesses and critical infrastructure in North America, South America and Europe since June 2022, with incidents in Australia from April to November 2023. The FBI was aware of about 300 affected entities as of October 2023. Play is presumed to be a closed group designed to "guarantee the secrecy of deals" rather than a RaaS.

## Initial Access
Play actors abuse valid accounts (T1078) and exploit public-facing applications (T1190), specifically FortiOS vulnerabilities CVE-2018-13379 and CVE-2020-12812 and Microsoft Exchange ProxyNotShell (CVE-2022-41040, CVE-2022-41082). They also use external-facing services such as RDP and VPN (T1133 External Remote Services).

## Discovery and Defense Evasion
Play uses AdFind for Active Directory queries and Grixba to enumerate network configuration and scan for antivirus (T1016, T1518.001 Security Software Discovery). GMER, IOBit and PowerTool are used to disable antivirus and remove log files (T1562.001 Disable or Modify Tools, T1070.001 Clear Windows Event Logs).

## Credential Access, Lateral Movement and C2
Actors search for unsecured credentials (T1552) and use Mimikatz to dump credentials (T1003), plus WinPEAS to find privilege escalation paths. C2 and lateral movement use Cobalt Strike, SystemBC and PsExec. Executables are distributed within the environment (T1570 Lateral Tool Transfer) and through Group Policy Objects (T1484.001 Group Policy Modification).

## Exfiltration and Impact
Play splits and compresses data into .RAR files with WinRAR (T1560.001) and moves them with WinSCP to actor-controlled accounts (T1048 Exfiltration Over Alternative Protocol). Encryption uses AES-RSA hybrid with intermittent encryption, skipping system files; encrypted files get a .play extension and a ReadMe.txt note is placed in C:\ (T1486). Double extortion: the note has no initial demand and directs victims to an email address; payment in cryptocurrency; refusal leads to publication on a Tor leak site (T1657).

## Mitigations
Keep multiple copies of sensitive data in segmented, secure locations. Follow NIST password guidance. Require administrator credentials to install software. Require MFA for webmail, VPN and critical systems. Prioritize patching of known exploited vulnerabilities in internet-facing systems; deploy the latest Exchange updates or disable OWA if patching is not possible. Segment networks, monitor traffic including lateral movement, and use EDR. Filter traffic from unknown origins to internal remote services. Audit accounts and AD, apply least privilege and just-in-time admin access. Disable unused ports and scripting where possible. Keep offline, encrypted, immutable backups and test restoration.
