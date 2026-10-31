---
doc_id: cisa-aa23-353a-alphv-blackcat
title: "#StopRansomware: ALPHV Blackcat"
source_type: cisa_advisory
publisher: FBI, CISA, HHS
advisory_id: AA23-353A
published: 2023-12-19
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a
actor: ALPHV Blackcat
aliases: ALPHV; BlackCat; Sphynx
model: RaaS
sectors: healthcare; critical_infrastructure
---
# #StopRansomware: ALPHV Blackcat (AA23-353A, updated 2024-02-27)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
ALPHV Blackcat is a Ransomware-as-a-Service (RaaS) operation whose administrators provide the platform to affiliates. A rewritten variant, "ALPHV Blackcat Ransomware 2.0 Sphynx", announced in February 2023, can encrypt Windows and Linux devices and VMware instances. The healthcare sector was the most commonly victimized sector since mid-December 2023, out of nearly 70 leaked victims. Some affiliates steal data and extort victims without deploying ransomware at all.

## Initial Access
Affiliates use social engineering: they pose as company IT or helpdesk staff by phone call or SMS to obtain employee credentials (T1598 Phishing for Information), using open-source research on the target. They use compromised accounts to gain access (T1586 Compromise Accounts), and adversary-in-the-middle phishing with Evilginx2 to capture MFA codes, login credentials and session cookies (T1557 Adversary-in-the-Middle).

## Credential Access and Lateral Movement
Affiliates obtained passwords from local networks, deleted servers and domain controllers to move laterally (T1555 Credentials from Password Stores). They used Kerberos token generation for domain access, including creating an account named "aadmin" (T1558 Steal or Forge Kerberos Tickets).

## Tools
Remote access: AnyDesk, Mega sync, Splashtop; also SimpleHelp, ScreenConnect and MeshCentral in IOC tables. Tunneling: Plink and Ngrok. C2 beacons: Brute Ratel C4 and Cobalt Strike. Credential capture: Evilginx2. Metasploit was abused as an allowlisted application for defense evasion. POORTRY and STONESTOP were used to terminate security processes (T1562.001 Disable or Modify Tools).

## Exfiltration and Extortion
Data is exfiltrated with Mega.nz or Dropbox (T1567.002 Exfiltration to Cloud Storage). After exfiltration and/or encryption (T1486 Data Encrypted for Impact), actors contact victims through Tor, Tox, email or encrypted apps. Affiliates offer paid "vulnerability reports" and "security recommendations". The ransom note follows the pattern RECOVER-(seven-digit extension) FILES.txt.

## Mitigations
Regularly inventory authorized and unauthorized devices and software. Prioritize remediation of known exploited vulnerabilities. Enforce MFA with strong passwords, preferably phishing-resistant FIDO/WebAuthn or PKI-based MFA, because Blackcat affiliates bypass weaker MFA with adversary-in-the-middle phishing. Close unused ports and remove unnecessary applications. Use application allowlisting and block portable or unauthorized remote access programs; secure approved remote access tools per CISA guidance. Monitor network traffic including lateral movement, use EDR, monitor internal email and messaging and establish a traffic baseline. Train users to recognize and report helpdesk-impersonation social engineering and phishing. Validate controls against the listed ATT&CK techniques.

## Incident Response Guidance
If compromise is detected: isolate affected hosts, reimage compromised systems, issue new account credentials, collect and review artifacts such as running processes, network connections and logs, and report the incident to CISA and the FBI (IC3).
