---
doc_id: cisa-aa24-109a-akira
title: "#StopRansomware: Akira Ransomware"
source_type: cisa_advisory
publisher: FBI, CISA, Europol EC3, NCSC-NL
advisory_id: AA24-109A
published: 2024-04-18
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
actor: Akira
aliases: Megazord; Akira_v2
model: affiliate
sectors: critical_infrastructure; multi_sector
---
# #StopRansomware: Akira Ransomware (AA24-109A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
Akira ransomware has been active since March 2023 and has impacted a wide range of businesses and critical infrastructure entities in North America, Europe and Australia. Variants include the original C++ Windows encryptor (appends .akira), the Rust-based Megazord (appends .powerranges), and Akira_v2, a Rust-based encryptor for VMware ESXi and Linux. Akira uses double extortion: it exfiltrates data before encrypting systems.

## Initial Access
Akira actors mainly gain access through VPN services without multifactor authentication, largely by exploiting Cisco vulnerabilities CVE-2020-3259 and CVE-2023-20269 (T1190 Exploit Public-Facing Application). Other vectors are external-facing services such as RDP (T1133 External Remote Services), spearphishing attachments and links (T1566.001, T1566.002), and abuse of valid credentials (T1078).

## Persistence and Credential Access
Actors created new domain accounts, for example "itadm", for persistence (T1136.002 Create Account: Domain Account). They dumped credentials with Mimikatz and LaZagne (T1003 OS Credential Dumping) including LSASS memory access (T1003.001). Veeam credential tools (VeeamHax, Veeam-GetCreds.ps1) and Kerberos ticket dumping were also observed.

## Discovery and Defense Evasion
Discovery used SoftPerfect and Advanced IP Scanner (T1016), nltest /dclist (T1018 Remote System Discovery), nltest and net for domain trusts (T1482), PCHunter64 (T1082), tasklist (T1057) and net group/localgroup commands (T1069). To disable antivirus, actors used a bring-your-own-vulnerable-driver (BYOVD) approach with PowerTool and the Zemana AntiMalware driver (T1562.001 Disable or Modify Tools).

## Command and Control and Exfiltration
Remote access and C2 used AnyDesk, MobaXterm, RustDesk (T1219 Remote Access Software), Ngrok and Cloudflare Tunnel (T1090 Proxy). Data was compressed and split with WinRAR (T1560.001), then exfiltrated with WinSCP and FileZilla (T1048 Exfiltration Over Alternative Protocol), CloudZilla (T1537 Transfer Data to Cloud Account) and RClone to cloud storage such as Mega (T1567.002).

## Impact and Extortion
Akira encrypts systems with a hybrid ChaCha20/RSA scheme (T1486) and deletes volume shadow copies (T1490 Inhibit System Recovery). No initial ransom demand is left; each victim gets a unique code and a .onion URL. Payment is demanded in Bitcoin, and actors threaten to publish data on Tor and have called victim companies (T1657 Financial Theft).

## Mitigations
Keep multiple copies of sensitive data in a physically separate, secure location. Require long NIST-compliant passwords. Enable MFA for all services, especially webmail, VPNs and critical systems — VPNs without MFA were the main entry point. Patch internet-facing systems, prioritizing known exploited vulnerabilities such as the Cisco ASA/FTD flaws. Segment networks, monitor traffic and use EDR. Block unknown or untrusted origins from reaching remote access services. Audit Active Directory for new or unrecognized accounts. Apply least privilege and just-in-time admin access. Disable unused ports and command-line/scripting where possible. Keep offline, encrypted, immutable backups and test restoration.
