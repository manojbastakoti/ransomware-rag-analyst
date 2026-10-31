---
doc_id: ransomware-prevention-baseline
title: "Ransomware Prevention Baseline (cross-advisory synthesis)"
source_type: playbook
publisher: Group 3B synthesis of CISA #StopRansomware advisory mitigation sections
advisory_id: synthesis
published: 2026-10-30
url: https://www.cisa.gov/stopransomware
actor: generic
aliases: 
model: n/a
sectors: multi_sector; healthcare
---
# Ransomware Prevention Baseline

> Synthesis written by the project team from the "Mitigations" sections that recur across the ten #StopRansomware advisories in this corpus (LockBit 3.0, ALPHV Blackcat, Black Basta, Akira, Play, Rhysida, Medusa, Ghost, Daixin, Interlock). Each control lists the advisories that recommend it.

## Backups and Recovery
Maintain offline, encrypted, immutable backups that cover the whole organization, stored in a physically separate, segmented location, and regularly test restoration. Ransomware groups routinely delete volume shadow copies (T1490) and target backup software credentials (for example Akira's Veeam credential tools), so online backups and shadow copies alone are not sufficient. Recommended in: LockBit 3.0, Akira, Play, Rhysida, Medusa, Ghost, Daixin, Interlock, Black Basta.

## Identity and Multifactor Authentication
Require phishing-resistant MFA (FIDO/WebAuthn or PKI) for webmail, VPNs, remote access and privileged and backup accounts. VPNs without MFA were the main entry point for Akira, Rhysida and Daixin, and ALPHV Blackcat affiliates bypassed weaker MFA using adversary-in-the-middle phishing (Evilginx2). Follow NIST password guidance and audit Active Directory for new or unrecognized accounts, since many groups create accounts for persistence (Akira "itadm", Blackcat "aadmin", Medusa and Ghost domain accounts).

## Patch Internet-Facing Systems
Prioritize Known Exploited Vulnerabilities (KEV) on internet-facing systems: VPN appliances (Cisco ASA/FTD, Fortinet FortiOS), remote management (ConnectWise ScreenConnect CVE-2024-1709), Microsoft Exchange (ProxyShell, ProxyNotShell), SharePoint, ColdFusion and Fortinet EMS. Use KEV, EPSS, CVSS and SSVC to prioritize. Exploit Public-Facing Application (T1190) appears in every advisory in this corpus.

## Remote Access and RMM Control
Allowlist approved remote access tools and block unauthorized or portable RMM software (AnyDesk, Splashtop, ScreenConnect, Atera, SimpleHelp, Quick Assist), which nearly every group abuses (T1219). Restrict RDP to known users through a VPN or jump host with MFA, log attempts, enforce lockouts and close unused ports such as 3389, 445 and 21.

## Segmentation and Least Privilege
Segment networks into tiers so critical systems (EHR, virtualization, backups, domain controllers) are isolated. Apply least privilege and just-in-time administrative access, disable admin accounts when not needed, and require admin credentials to install software.

## Logging, Monitoring and EDR
Deploy EDR on all hosts including virtual machines and monitor for lateral movement. Enable command-line auditing, process tracking and enhanced PowerShell logging with at least 180 days retention, forwarded to a hardened central log server. Alert on scanning, admin account changes, unexpected scripts and tampering with security tools (T1562.001). Restrict PowerShell and disable command-line and scripting activity where not required.

## User Awareness and Email Security
Train users to recognize phishing, helpdesk impersonation by phone, SMS or Microsoft Teams (Black Basta, Blackcat), fake browser updates and ClickFix fake CAPTCHAs (Interlock). Add external-sender email banners, disable hyperlinks in received email, use DNS filtering, and enforce DMARC, DKIM and SPF.

## Validate Controls
Every advisory recommends exercising security controls against the listed MITRE ATT&CK techniques, comparing detection and prevention results, and tuning controls based on the outcome.
