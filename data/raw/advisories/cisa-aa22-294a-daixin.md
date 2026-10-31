---
doc_id: cisa-aa22-294a-daixin
title: "#StopRansomware: Daixin Team"
source_type: cisa_advisory
publisher: FBI, CISA, HHS
advisory_id: AA22-294A
published: 2022-10-21
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-294a
actor: Daixin Team
aliases: Daixin Group
model: extortion_group
sectors: healthcare
---
# #StopRansomware: Daixin Team (AA22-294A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
The Daixin Team is a ransomware and data extortion group that has targeted U.S. businesses, predominantly in the Healthcare and Public Health (HPH) Sector, since at least June 2022. It encrypted servers supporting healthcare services including electronic health records (EHR), diagnostics, imaging and intranet systems, and stole personally identifiable information (PII) and patient health information (PHI). Third-party reporting says its ransomware is based on leaked Babuk Locker source code.

## Initial Access
Daixin actors gain access through virtual private network (VPN) servers. In one confirmed case they likely exploited an unpatched VPN server vulnerability (T1190). In another they used previously compromised credentials to access a legacy VPN server without MFA (T1078 Valid Accounts). VPN credentials were likely obtained via a phishing email with a malicious attachment (T1598.002 Spearphishing Attachment).

## Lateral Movement and Privilege Escalation
Actors moved laterally with RDP (T1563.002 RDP Hijacking) and SSH (T1563.001 SSH Hijacking). They attempted to obtain privileged credentials through credential dumping (T1003) and pass the hash (T1550.002). Privileged accounts were used to reset passwords for VMware ESXi servers (T1098 Account Manipulation) through VMware vCenter Server, and SSH was used to connect to ESXi servers for ransomware deployment.

## Exfiltration
Daixin used Rclone to exfiltrate data to a dedicated virtual private server, and Ngrok as a reverse proxy for exfiltration (T1567 Exfiltration Over Web Service). Stolen PII and PHI were used to threaten release if the ransom was not paid.

## Impact
The ransomware encrypts ESXi-hosted files and specific VM-related file extensions, disrupting healthcare services (T1486 Data Encrypted for Impact).

## Mitigations for Healthcare Organizations
Promptly patch VPNs, remote access and virtualization software, prioritizing known exploited vulnerabilities. Enforce phishing-resistant MFA on webmail, VPNs, critical systems and privileged and backup accounts. Restrict, monitor and log RDP; require MFA, use VPN or VDI for external access and disable unused ports such as 3389. Disable unneeded ports, protocols and external management interfaces (SSH, Telnet, HTTP). Segment networks into tiers for critical systems. Use PKI and certificates to authenticate connections to networks, IoT medical devices and EHR systems. Apply least privilege. Encrypt PII/PHI at rest and in transit, store patient data only on protected internal systems, and follow HIPAA security practices. Monitor IoT medical devices for erratic behavior. Keep offline, encrypted, immutable backups, test restoration, and maintain an incident response and breach notification plan. Limit SMB and remove SMBv1.
