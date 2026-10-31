---
doc_id: cisa-ransomware-response-checklist
title: "CISA Ransomware Response Checklist (#StopRansomware Guide, Part 2)"
source_type: playbook
publisher: CISA, MS-ISAC, FBI, NSA
advisory_id: StopRansomware-Guide-2023
published: 2023-05-23
url: https://www.cisa.gov/stopransomware/ive-been-hit-ransomware
actor: generic
aliases: 
model: n/a
sectors: multi_sector
---
# Ransomware Response Checklist (CISA #StopRansomware Guide)

> Analyst-curated summary of CISA's public response checklist. The first three steps should be followed in sequence.

## Detection and Analysis
1. Determine which systems were impacted and immediately isolate them. If several systems or subnets appear impacted, take the network offline at the switch level. If that is not immediately possible, unplug affected devices or remove them from Wi-Fi. For cloud resources, take a snapshot of volumes for later forensic review.
2. Coordinate isolation using out-of-band communication such as phone calls, because attackers may be monitoring email and chat and could otherwise move laterally or deploy ransomware more widely.
3. Power down devices only as a last resort, if they cannot be disconnected from the network, because shutting down destroys evidence in volatile memory.
4. Triage impacted systems for restoration using a predefined critical asset list (health and safety, revenue, critical services and their dependencies). Track systems that were not impacted so they can be deprioritized.
5. Review antivirus, EDR, IDS/IPS and logs for evidence of earlier "dropper" malware such as Bumblebee, Dridex, Emotet, QakBot or Anchor — ransomware may indicate a previous, unresolved compromise.
6. Confer with the incident response team and document an initial understanding of what happened.

## Threat Hunting During Response
Enterprise hunting priorities: newly created or escalated Active Directory accounts; suspicious VPN and other logins; misuse of built-in tools that impair recovery such as bcdedit.exe, vssadmin.exe and wbadmin.exe; Cobalt Strike beacons; unexpected remote monitoring and management (RMM) software; unexpected PowerShell or PsTools/PsExec use; credential dumping (Mimikatz, NTDSutil.exe); unusual endpoint-to-endpoint traffic; data exfiltration tools such as Rclone, Rsync and FTP/SFTP; and new services or scheduled tasks. Cloud: enable tools that detect and prevent changes to IAM, network security and data protection resources, and automate responses such as disabling overly permissive firewall rules.

## Reporting and Notification
Follow the incident response and communications plan to notify internal and external stakeholders: IT, managed security providers, cyber insurer, and senior leadership. Consider reporting to CISA, the local FBI field office, the FBI Internet Crime Complaint Center (IC3) or the U.S. Secret Service, and request assistance. Coordinate accurate internal and external messaging with communications staff. If data was breached, follow breach notification requirements. CISA, MS-ISAC and federal law enforcement do not recommend paying a ransom: payment does not guarantee decryption and attackers have issued follow-on extortion demands.

## Containment and Eradication
If no initial mitigation is possible, capture system images and memory from a sample of affected devices, collect logs, precursor malware samples and IOCs, prioritizing volatile or short-retention data such as memory, Windows Security logs and firewall buffers. Consult federal law enforcement about possible decryptors. Research trusted guidance for the specific variant; stop or disable known ransomware binaries and remove associated registry values and files. Identify the systems and accounts involved in the initial breach, including email accounts. Based on breach details, contain further access by disabling VPNs, remote access servers, single sign-on resources and public-facing cloud assets as needed.

## Investigating Server-Side Encryption
If an infected workstation is encrypting server data: review Sessions and Open Files on affected servers; check file ownership and ransom notes for the associated user; review TerminalServices-RemoteConnectionManager logs for RDP connections; review Windows Security, SMB and related logs; and run a packet capture (for example Wireshark) on the server with a filter to identify IP addresses actively writing or renaming files.

## Persistence Hunting and Rebuild
Investigate outside-in persistence (rogue accounts, perimeter backdoors, exploitable external vulnerabilities) and inside-out persistence (malware implants, living-off-the-land tools such as Cobalt Strike or PsExec, PowerShell scripts) using EDR, account audits, centralized logs and forensics. Rebuild systems by priority of critical services using pre-configured standard images or infrastructure-as-code templates. Once the environment is fully cleaned and rebuilt, reset passwords for all affected systems and accounts, remove malicious persistence, apply patches and upgrades, and rotate customer-managed encryption keys. The designated IT or security authority declares the incident over based on established criteria.

## Recovery and Post-Incident Activity
Reconnect systems and restore data from offline, encrypted backups based on critical-service priority. Ensure only clean systems join the recovery network, for example a new VLAN. Document lessons learned and update policies, plans and procedures. Consider sharing lessons learned and IOCs with CISA or the sector ISAC.
