---
doc_id: cisa-aa25-203a-interlock
title: "#StopRansomware: Interlock"
source_type: cisa_advisory
publisher: FBI, CISA, HHS, MS-ISAC
advisory_id: AA25-203A
published: 2025-07-22
url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a
actor: Interlock
aliases: 
model: unknown
sectors: healthcare; critical_infrastructure; multi_sector
---
# #StopRansomware: Interlock (AA25-203A)

> Analyst-curated summary of a public joint advisory. Consult the original URL for full text and IOCs.

## Overview
Interlock is a financially motivated, opportunistic ransomware operation first observed in late September 2024, targeting businesses and critical infrastructure in North America and Europe. Open-source reporting notes similarities with Rhysida ransomware. Interlock has encryptors for Windows, Linux and FreeBSD, and encrypted files use the .1nt3rlock extension.

## Initial Access
Unusually for ransomware, Interlock gains access through drive-by downloads from compromised legitimate websites (T1189 Drive-by Compromise), using fake Google Chrome or Microsoft Edge updates and later files masquerading as security software updates. It also uses the "ClickFix" technique: fake CAPTCHA pages that trick users into pasting and running a Base64-encoded PowerShell command (T1204.004 Malicious Copy and Paste).

## Execution, Persistence and Discovery
PowerShell scripts drop files, change the registry and perform reconnaissance (T1059.001). Persistence uses a Startup folder file and a "Chrome Updater" Run key (T1547.001, T1036.005 Masquerading). Discovery commands include WindowsIdentity.GetCurrent() (T1033), systeminfo and Get-PSDrive (T1082), tasklist /svc and Get-Service (T1007) and arp -a (T1016).

## Credential Access and Lateral Movement
Interlock runs Lumma Stealer and Berserk Stealer (T1056 Input Capture), a keylogger klg.dll that logs to conhost.txt (T1056.001) and cht.exe to steal browser credentials (T1555.003). Kerberoasting may have been used to compromise domain admin accounts (T1558.003). Valid and domain accounts are reused for lateral movement (T1078, T1078.002) over RDP (T1021.001), with AnyDesk, PuTTY, PsExec and ScreenConnect (T1219). Cobalt Strike, SystemBC, Interlock RAT and NodeSnake RAT provide C2.

## Exfiltration, Impact and Extortion
Azure Storage Explorer is used to browse victims' Azure storage (T1530), AzCopy uploads data to Azure blob storage (T1567.002) and WinSCP is also used (T1048). After encryption a DLL is run with rundll32 (T1218.011) and deletes the encryption binary (T1070.004). Data is encrypted with AES/RSA (T1486). Double extortion: notes give a unique code and Tor .onion URL with no initial demand, payment is in Bitcoin, and actors have published stolen data on their leak site.

## Mitigations
Use DNS filtering and web access firewalls to block malicious sites. Train users to spot social engineering such as fake updates and ClickFix fake CAPTCHAs. Keep multiple copies of critical data in separate locations. Use long NIST passwords and require MFA broadly after implementing ICAM. Patch internet-facing systems, prioritizing known exploited vulnerabilities. Deploy EDR on VMs, systems and networks. Segment networks and monitor traffic. Block untrusted origins from internal remote services. Audit AD for unrecognized accounts, enforce least privilege and just-in-time admin. Disable unused ports and command-line/scripting where not required. Keep offline, encrypted, immutable backups and test restoration.
