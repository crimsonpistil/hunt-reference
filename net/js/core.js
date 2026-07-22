// ── HUNT REFERENCE - core.js ──
// Shared UI logic for all tactic pages.
// DATA must be loaded before this file via a tactic-specific data/*.js script tag.

// ── CMS TEMPLATES ──
const CMS_TEMPLATES = {
  T1595: { title:'T1595 - Active Scanning', body:`## TAG - RECON\n### Technique: Active Scanning, T1595\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n\nNotes:` },
  T1589: { title:'T1589 - Gather Victim Identity Information', body:`## TAG - RECON\n### Technique: Gather Victim Identity Information, T1589\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Usernames, Emails, Employee Names, Credentials, etc.)\n\nNotes:` },
  T1590: { title:'T1590 - Gather Victim Network Information', body:`## TAG - RECON\n### Technique: Gather Victim Network Information, T1590\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Domains, Topology, IPs, ASN, VPN Vendor, etc.)\n\nNotes:` },
  T1591: { title:'T1591 - Gather Victim Org Information', body:`## TAG - RECON\n### Technique: Gather Victim Org Information, T1591\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Departments, Divisions, Roles, Vendors, etc.)\n\nNotes:` },
  T1592: { title:'T1592 - Gather Victim Host Information', body:`## TAG - RECON\n### Technique: Gather Victim Host Information, T1592\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Hardware, Software Version, Firmware, OS, etc.)\n\nNotes:` },
  T1593: { title:'T1593 - Search Open Websites / Domains', body:`## TAG - RECON\n### Technique: Search Open Websites / Domains, T1593\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Employee Profiles, Credentials, Source Code, etc.)\n\nNotes:` },
  T1594: { title:'T1594 - Search Victim-Owned Websites', body:`## TAG - RECON\n### Technique: Search Victim-Owned Websites, T1594\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Tech Stack, Exposed Files, CMS Version, etc.)\n\nNotes:` },
  T1596: { title:'T1596 - Search Technical Databases', body:`## TAG - RECON\n### Technique: Search Technical Databases, T1596\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (WHOIS, Passive DNS, Cert History, Scan Data, etc.)\n\nNotes:` },
  T1597: { title:'T1597 - Search Closed Sources', body:`## TAG - RECON\n### Technique: Search Closed Sources, T1597\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Credentials, Breach Data, Purchased Info, etc.)\n\nNotes:` },
  T1598: { title:'T1598 - Phishing for Information', body:`## TAG - RECON\n### Technique: Phishing for Information, T1598\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Credentials, MFA Tokens, Employee Info, etc.)\n\nNotes:` },
  T1078: { title:'T1078 - Valid Accounts', body:`## TAG - INITIAL ACCESS\n### Technique: Valid Accounts, T1078\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Account Type: (Default / Domain / Local / Cloud)\n- Username Observed:\n- Auth Result: (Success / Failure)\n- MFA Status:\n\nNotes:` },
  T1091: { title:'T1091 - Replication Through Removable Media', body:`## TAG - INITIAL ACCESS\n### Technique: Replication Through Removable Media, T1091\n- Time:\n- Source Host:\n- USB Event Time (if known):\n- Destination IP(s):\n- Port(s):\n- Propagation Method: (SMB / HTTP fetch / Air-gap bridge)\n- Payload Observed:\n\nNotes:` },
  T1133: { title:'T1133 - External Remote Services', body:`## TAG - INITIAL ACCESS\n### Technique: External Remote Services, T1133\n- Time:\n- Source IP / Geo / ASN:\n- Destination IP(s):\n- Port(s):\n- Service: (VPN / RDP / SSH / Citrix / Cloud)\n- Username Observed:\n- Auth Result:\n- Anomaly: (New geo / Off hours / Brute / Tor)\n\nNotes:` },
  T1189: { title:'T1189 - Drive-by Compromise', body:`## TAG - INITIAL ACCESS\n### Technique: Drive-by Compromise, T1189\n- Time:\n- Internal Host:\n- Browsed URL / Domain:\n- Redirect Chain:\n- Final Destination IP:\n- Payload Type: (Exploit / Document / PE)\n- Post-exploit C2:\n\nNotes:` },
  T1190: { title:'T1190 - Exploit Public-Facing Application', body:`## TAG - INITIAL ACCESS\n### Technique: Exploit Public-Facing Application, T1190\n- Time:\n- Source IP:\n- Target Server:\n- Port(s):\n- Application / CVE:\n- Exploit Type: (SQLi / Cmd Inj / LFI / Deserialization / Log4Shell / VPN CVE)\n- HTTP Response Code:\n- Post-exploit Callback:\n\nNotes:` },
  T1195: { title:'T1195 - Supply Chain Compromise', body:`## TAG - INITIAL ACCESS\n### Technique: Supply Chain Compromise, T1195\n- Time:\n- Affected Host / Build Server:\n- Destination IP(s) / Domain:\n- Compromise Type: (Dependency / Software / Hardware)\n- Package or Vendor:\n- C2 Pattern Observed:\n\nNotes:` },
  T1200: { title:'T1200 - Hardware Additions', body:`## TAG - INITIAL ACCESS\n### Technique: Hardware Additions, T1200\n- Time:\n- Switch Port / VLAN:\n- MAC Address / OUI:\n- Device Type: (Rogue switch / USB-Eth / Implant / Rogue AP / BMC)\n- DHCP Hostname:\n- Outbound Activity:\n\nNotes:` },
  T1566: { title:'T1566 - Phishing', body:`## TAG - INITIAL ACCESS\n### Technique: Phishing, T1566\n- Time:\n- Sender / From Domain:\n- Recipient(s):\n- Delivery: (Attachment / Link / Service)\n- Attachment Filename / Hash:\n- Click Destination URL:\n- Credential POST Observed:\n- AiTM / MFA Bypass:\n\nNotes:` },
  T1659: { title:'T1659 - Content Injection', body:`## TAG - INITIAL ACCESS\n### Technique: Content Injection, T1659\n- Time:\n- Source IP / Server:\n- Internal Victim:\n- Injection Type: (HTTP Response / DNS / BGP / TLS Downgrade)\n- Injected Content / Domain:\n- Affected Domain / Prefix:\n\nNotes:` },
  T1071: { title:'T1071 - Application Layer Protocol', body:`## TAG - C2\n### Technique: Application Layer Protocol, T1071\n- Time:\n- Source IP:\n- Destination IP / Domain:\n- Port(s):\n- Protocol: (HTTP / HTTPS / FTP / SMB / SMTP / DNS)\n- Beacon Interval (s):\n- URI Pattern:\n- User-Agent:\n- JA3/JA4:\n\nNotes:` },
  T1568: { title:'T1568 - Dynamic Resolution', body:`## TAG - C2\n### Technique: Dynamic Resolution, T1568\n- Time:\n- Source IP:\n- DNS Query Pattern:\n- Resolution Type: (DGA / Fast Flux / DNS Calculation)\n- NXDOMAIN Rate:\n- Successful Resolution Domain:\n- Resolved IP(s):\n- TTL Observed:\n\nNotes:` },
  T1102: { title:'T1102 - Web Service', body:`## TAG - C2\n### Technique: Web Service, T1102\n- Time:\n- Source IP:\n- Service: (Pastebin / GitHub / Discord / Telegram / Slack / Cloud Storage)\n- Endpoint URI:\n- HTTP Method:\n- Process:\n- Direction: (Dead Drop / Bidirectional / One-Way Exfil)\n\nNotes:` },
  T1573: { title:'T1573 - Encrypted Channel', body:`## TAG - C2\n### Technique: Encrypted Channel, T1573\n- Time:\n- Source IP:\n- Destination IP:\n- TLS Version:\n- JA3 / JA3S:\n- JA4 / JA4S:\n- Cert Issuer:\n- Cert Subject:\n- Cert Issued (Date):\n- Crypto Type: (Symmetric / Asymmetric / Custom)\n\nNotes:` },
  T1095: { title:'T1095 - Non-Application Layer Protocol', body:`## TAG - C2\n### Technique: Non-Application Layer Protocol, T1095\n- Time:\n- Source IP:\n- Destination IP:\n- Protocol: (ICMP / Raw TCP / Raw UDP / GRE / SCTP)\n- Port (if applicable):\n- Payload Size:\n- Payload Entropy:\n- Packet Count / Duration:\n\nNotes:` },
  T1090: { title:'T1090 - Proxy', body:`## TAG - C2\n### Technique: Proxy, T1090\n- Time:\n- Source IP:\n- Destination IP:\n- Proxy Type: (.001 Internal / .002 External / .003 Multi-hop / .004 Domain Fronting)\n- Port(s):\n- SNI:\n- Host Header:\n- ASN / Provider:\n\nNotes:` },
  T1572: { title:'T1572 - Protocol Tunneling', body:`## TAG - C2\n### Technique: Protocol Tunneling, T1572\n- Time:\n- Source IP:\n- Destination IP:\n- Tunnel Protocol: (SSH / HTTPS / WebSocket / DoH / VPN)\n- Port:\n- Session Duration:\n- Bytes (src/dst):\n- SSH Banner / SNI:\n\nNotes:` },
  T1105: { title:'T1105 - Ingress Tool Transfer', body:`## TAG - C2\n### Technique: Ingress Tool Transfer, T1105\n- Time:\n- Source Host:\n- Destination IP / Domain:\n- LOLBin: (certutil / bitsadmin / PowerShell / curl / wget)\n- User-Agent:\n- File Type Downloaded:\n- File Hash (if known):\n- Encoded Payload (Y/N):\n\nNotes:` },
  T1571: { title:'T1571 - Non-Standard Port', body:`## TAG - C2\n### Technique: Non-Standard Port, T1571\n- Time:\n- Source IP:\n- Destination IP:\n- Port:\n- Detected Protocol (Zeek DPD):\n- Expected Protocol for Port:\n- Session Duration:\n\nNotes:` },
  T1219: { title:'T1219 - Remote Access Software', body:`## TAG - C2\n### Technique: Remote Access Software, T1219\n- Time:\n- Source Host:\n- Destination IP / SNI:\n- RMM Tool: (TeamViewer / AnyDesk / ConnectWise / Splashtop / RustDesk / ngrok / Cloudflare Tunnel / Tailscale)\n- Process Path:\n- Authorized for Host (Y/N):\n\nNotes:` },
  T1018: { title:'T1018 - Remote System Discovery', body:`## TAG - DISCOVERY\n### Technique: Remote System Discovery, T1018\n- Time:\n- Source IP:\n- Destination IP / Subnet:\n- Discovery Method: (ICMP sweep / ARP scan / NBNS / DNS-PTR / SMB probe / AXFR)\n- Hosts Identified:\n- Subnets Touched:\n\nNotes:` },
  T1046: { title:'T1046 - Network Service Discovery', body:`## TAG - DISCOVERY\n### Technique: Network Service Discovery, T1046\n- Time:\n- Source IP:\n- Target Range / Hosts:\n- Scan Type: (TCP SYN / Horizontal sweep / Banner grab / SNMP / masscan)\n- Ports Probed:\n- Tool Inferred: (nmap / masscan / zmap / nikto / custom)\n\nNotes:` },
  T1135: { title:'T1135 - Network Share Discovery', body:`## TAG - DISCOVERY\n### Technique: Network Share Discovery, T1135\n- Time:\n- Source IP:\n- Target Server(s):\n- RPC Interface: (srvsvc NetShareEnum / IPC$ / DFS referral)\n- Shares Discovered:\n- Auth Context: (Anonymous / Authenticated user / Domain admin)\n\nNotes:` },
  T1087: { title:'T1087 - Account Discovery', body:`## TAG - DISCOVERY\n### Technique: Account Discovery, T1087\n- Time:\n- Source IP:\n- Target DC:\n- Method: (LDAP filter / SAMR RPC / Kerberos AS-REQ enum / BloodHound)\n- Filter / Opnum:\n- Accounts Enumerated:\n- Sub-technique: (.001 Local / .002 Domain / .003 Email / .004 Cloud)\n\nNotes:` },
  T1069: { title:'T1069 - Permission Groups Discovery', body:`## TAG - DISCOVERY\n### Technique: Permission Groups Discovery, T1069\n- Time:\n- Source IP:\n- Target DC:\n- Group Queried: (Domain Admins / Enterprise Admins / Schema Admins / adminCount=1 / gMSA)\n- Method: (LDAP / LDAP_MATCHING_RULE_IN_CHAIN / SAMR / net.exe RPC)\n- Members Enumerated:\n\nNotes:` },
  T1482: { title:'T1482 - Domain Trust Discovery', body:`## TAG - DISCOVERY\n### Technique: Domain Trust Discovery, T1482\n- Time:\n- Source IP:\n- Target DC:\n- Trust Direction Discovered:\n- Trust Type: (Parent-child / External / Forest / Realm)\n- Method: (LDAP trustedDomain / LSARPC / nltest / RootDSE / cross-trust DNS SRV)\n\nNotes:` },
  T1083: { title:'T1083 - File and Directory Discovery', body:`## TAG - DISCOVERY\n### Technique: File and Directory Discovery, T1083\n- Time:\n- Source Host:\n- Target Share / Path:\n- File Patterns Searched: (web.config / *.kdbx / id_rsa / unattend.xml / etc.)\n- Tool: (Snaffler / PowerShell Get-ChildItem / robocopy /L / custom)\n- Files Identified:\n\nNotes:` },
  T1016: { title:'T1016 - System Network Configuration Discovery', body:`## TAG - DISCOVERY\n### Technique: System Network Configuration Discovery, T1016\n- Time:\n- Source Host:\n- Service Queried: (icanhazip / ifconfig.me / IMDS 169.254.169.254 / ipinfo.io)\n- Process:\n- Discovery Type: (External IP / Cloud metadata / Network interfaces)\n\nNotes:` },
  T1049: { title:'T1049 - System Network Connections Discovery', body:`## TAG - DISCOVERY\n### Technique: System Network Connections Discovery, T1049\n- Time:\n- Source IP:\n- Target Host:\n- RPC Interface: (svcctl / WMI / netstat-equivalent)\n- Services Enumerated:\n- Reason Inferred: (Defense evasion / Privilege escalation / Lateral movement)\n\nNotes:` },
  T1033: { title:'T1033 - System Owner / User Discovery', body:`## TAG - DISCOVERY\n### Technique: System Owner / User Discovery, T1033\n- Time:\n- Source IP:\n- Target DC:\n- SIDs Looked Up:\n- Method: (LSARPC LsaLookupSids / whoami / LDAP self-query / SAMR)\n- Resolved Usernames:\n\nNotes:` },
  'T1021.001': { title:'T1021.001 - Remote Services: RDP', body:`## TAG - LATERAL MOVEMENT\n### Technique: Remote Services: Remote Desktop Protocol, T1021.001\n- Time:\n- Source IP:\n- Destination IP:\n- Auth Method: (CredSSP/NLA / Standard RDP Security)\n- Session Duration:\n- Username (if known):\n- BlueKeep / Tunneling Indicators:\n\nNotes:` },
  'T1021.002': { title:'T1021.002 - Remote Services: SMB / Admin Shares', body:`## TAG - LATERAL MOVEMENT\n### Technique: Remote Services: SMB / Windows Admin Shares, T1021.002\n- Time:\n- Source IP:\n- Destination IP:\n- Share Accessed: (ADMIN$ / C$ / IPC$ / D$)\n- Service Name (if created):\n- Pipe Name: (psexesvc / paexec / remcom / impacket-*)\n- File Written:\n\nNotes:` },
  'T1021.003': { title:'T1021.003 - Remote Services: DCOM', body:`## TAG - LATERAL MOVEMENT\n### Technique: Remote Services: Distributed Component Object Model, T1021.003\n- Time:\n- Source IP:\n- Destination IP:\n- CLSID: (MMC20 / ShellWindows / ShellBrowserWindow / Excel)\n- Method Invoked: (ExecuteShellCommand / ShellExecute / DDEInitiate)\n- Command Executed:\n\nNotes:` },
  'T1021.004': { title:'T1021.004 - Remote Services: SSH', body:`## TAG - LATERAL MOVEMENT\n### Technique: Remote Services: SSH, T1021.004\n- Time:\n- Source IP:\n- Destination IP:\n- Auth Method: (publickey / password)\n- Session Duration:\n- Agent Forwarded: (Y/N - host-side correlation needed)\n- Username (if known):\n\nNotes:` },
  'T1021.006': { title:'T1021.006 - Remote Services: WinRM', body:`## TAG - LATERAL MOVEMENT\n### Technique: Remote Services: Windows Remote Management, T1021.006\n- Time:\n- Source IP:\n- Destination IP:\n- Port: (5985 HTTP / 5986 HTTPS)\n- User-Agent: (Microsoft WinRM Client / Ruby / Faraday)\n- Cmdlet (if logged):\n- Session Type: (Invoke-Command / Enter-PSSession)\n\nNotes:` },
  T1570: { title:'T1570 - Lateral Tool Transfer', body:`## TAG - LATERAL MOVEMENT\n### Technique: Lateral Tool Transfer, T1570\n- Time:\n- Source IP:\n- Destination IP:\n- Share / Path:\n- Filename:\n- File Type: (.exe / .dll / .ps1 / .7z / archive)\n- File Hash:\n- Tool Identification (if known):\n\nNotes:` },
  T1210: { title:'T1210 - Exploitation of Remote Services', body:`## TAG - LATERAL MOVEMENT\n### Technique: Exploitation of Remote Services, T1210\n- Time:\n- Source IP:\n- Destination IP:\n- Service Exploited: (SMBv1 / Netlogon / Spooler / other)\n- CVE: (CVE-2017-0144 EternalBlue / CVE-2020-1472 ZeroLogon / CVE-2021-34527 PrintNightmare)\n- Patch Status:\n- Exploit Outcome: (success / fail / unknown)\n\nNotes:` },
  T1563: { title:'T1563 - Remote Service Session Hijacking', body:`## TAG - LATERAL MOVEMENT\n### Technique: Remote Service Session Hijacking, T1563\n- Time:\n- Source IP:\n- Destination IP:\n- Hijacked Session ID:\n- Original User:\n- Hijacker Process: (tscon.exe with /dest)\n- Detection Source: (Event 4778 / EDR / network anomaly)\n\nNotes:` },
  'T1558.003': { title:'T1558.003 - Kerberoasting', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Kerberoasting, T1558.003\n- Time:\n- Source IP:\n- DC:\n- SPN(s) Roasted:\n- Etype Requested: (RC4-HMAC = 23 / AES = 17/18)\n- Account Names:\n- Hash Cracked: (Y/N - password if cracked)\n- Tool Inferred: (Rubeus / Impacket / PowerView)\n\nNotes:` },
  'T1558.004': { title:'T1558.004 - AS-REProasting', body:`## TAG - CREDENTIAL ACCESS\n### Technique: AS-REProasting, T1558.004\n- Time:\n- Source IP:\n- DC:\n- Accounts with DONT_REQ_PREAUTH:\n- LDAP Filter Observed:\n- Hash Cracked: (Y/N)\n- Tool Inferred: (Rubeus asreproast / Impacket GetNPUsers)\n\nNotes:` },
  'T1003.006': { title:'T1003.006 - DCSync', body:`## TAG - CREDENTIAL ACCESS\n### Technique: DCSync, T1003.006\n- Time:\n- Source IP: (CRITICAL: should be DC; non-DC = compromise)\n- DC Replicated From:\n- DN Replicated: (CN=krbtgt / CN=Administrator / specific user)\n- Auth Source Account: (which privileged account performed DCSync)\n- Tool Inferred: (Mimikatz / Impacket secretsdump / DSInternals)\n- krbtgt Hash Obtained: (Y/N - implies Golden Ticket capability)\n\nNotes:` },
  'T1110.003': { title:'T1110.003 - Password Spraying', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Password Spraying, T1110.003\n- Time:\n- Source IP:\n- Spray Type: (Kerberos AS-REQ / NTLM SMB / NTLM HTTP / OWA)\n- Usernames Tried: (count + sample)\n- Successful Auth: (Y/N - which user)\n- Password Used (if known):\n- Source Reputation: (residential proxy / VPN / cloud)\n- External or Internal:\n\nNotes:` },
  T1187: { title:'T1187 - Forced Authentication', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Forced Authentication, T1187\n- Time:\n- Source IP:\n- Target IP: (system being coerced)\n- RPC Interface: (MS-EFSR / MS-RPRN / MS-DFSNM / MS-FSRVP)\n- Coercion Vector: (PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce)\n- Captured Hash / Relayed Auth:\n- Relay Destination (if relayed): (AD CS / LDAP / SMB)\n- Outcome: (hash captured / cert issued / lateral movement)\n\nNotes:` },
  'T1557.001': { title:'T1557.001 - LLMNR/NBT-NS Poisoning', body:`## TAG - CREDENTIAL ACCESS\n### Technique: LLMNR/NBT-NS Poisoning and SMB Relay, T1557.001\n- Time:\n- Responder Source IP: (the poisoner)\n- Victim Source IP: (whose hash was captured)\n- Auth Type Captured: (Net-NTLMv2 / NTLMv1 / Kerberos)\n- Relayed-To Destination: (if relayed: SMB / LDAP / AD CS)\n- LLMNR/NBT-NS Disabled in GPO: (Y/N)\n\nNotes:` },
  'T1558.001': { title:'T1558.001 - Golden Ticket', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Golden Ticket, T1558.001\n- Time:\n- Source IP:\n- krbtgt Hash Source: (DCSync evidence - link to T1003.006 hunt)\n- Forged User Identity:\n- Ticket Lifetime: (anomalous if >10 hrs)\n- Ticket Etype: (RC4 = anomalous in modern AD)\n- krbtgt Rotation Status: (last rotation date)\n- Detection Method: (Zeek correlation / Event 4769 anomaly)\n\nNotes:` },
  'T1558.002': { title:'T1558.002 - Silver Ticket', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Silver Ticket, T1558.002\n- Time:\n- Source IP:\n- Service Targeted: (CIFS / HTTP / MSSQL / specific SPN)\n- Service Account Hash Source:\n- Forged User Identity:\n- Detection Method: (service log Event 4624 / Zeek correlation)\n- gMSA in Use: (Y/N)\n\nNotes:` },
  'T1110.004': { title:'T1110.004 - Credential Stuffing', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Credential Stuffing, T1110.004\n- Time:\n- Source IP:\n- Target Endpoint: (OWA / ADFS / M365 / VPN portal / custom)\n- Username:\n- Password Source: (known breach / unknown)\n- Source Reputation: (residential proxy / Tor / known bad)\n- Successful Auth: (Y/N)\n- IP Rotation Pattern: (single IP / rotating proxy network)\n\nNotes:` },
  'T1552.004': { title:'T1552.004 - Private Keys', body:`## TAG - CREDENTIAL ACCESS\n### Technique: Unsecured Private Keys, T1552.004\n- Time:\n- Source IP:\n- Destination IP:\n- Key File: (id_rsa / id_ed25519 / .pem / .ppk)\n- Transport: (SMB / SCP / SFTP / HTTPS)\n- Subsequent Use Detected: (SSH from destination using key - Y/N)\n- Owner of Key:\n\nNotes:` },
  'T1003.001': { title:'T1003.001 - LSASS Memory', body:`## TAG - CREDENTIAL ACCESS\n### Technique: LSASS Memory Dumping, T1003.001\n- Time:\n- Source IP:\n- Destination IP:\n- Dump Filename: (lsass.dmp / random name)\n- File Size: (LSASS dumps typically 50-150MB)\n- Tool Inferred: (Mimikatz / ProcDump / comsvcs.dll MiniDump / custom)\n- Dump Server: (legitimate $CRASH_DUMP_SERVERS or unknown)\n- Subsequent Outbound Exfil: (Y/N)\n\nNotes:` },
  'T1556.006': { title:'T1556.006 - MFA Fatigue', body:`## TAG - CREDENTIAL ACCESS\n### Technique: MFA Fatigue / Push Bombing, T1556.006\n- Time:\n- Target User:\n- IDP Provider: (Okta / Azure AD / Duo / Ping)\n- Push Count: (number of MFA prompts within window)\n- Source Auth IP: (where the auth attempts originated)\n- Source IP Geolocation:\n- User Eventually Approved: (Y/N - and timestamp)\n- Number-Matching MFA Enabled: (Y/N)\n\nNotes:` },
  T1039: { title:'T1039 - Data from Network Shared Drive', body:`## TAG - COLLECTION\n### Technique: Data from Network Shared Drive, T1039\n- Time:\n- Source IP:\n- File Server:\n- Share(s) Accessed:\n- File Count Read:\n- Unique Directories Touched:\n- Filename Patterns: (high-sensitivity matches?)\n- User Account:\n- User Role: (matches share content?)\n\nNotes:` },
  'T1213.001': { title:'T1213.001 - Confluence', body:`## TAG - COLLECTION\n### Technique: Confluence Repository Collection, T1213.001\n- Time:\n- Source IP:\n- Confluence Host:\n- Search Query Count:\n- CQL Queries Observed:\n- Pages/Spaces Downloaded:\n- User Account:\n- Tool Inferred: (manual / confluence-dump / custom)\n\nNotes:` },
  'T1213.002': { title:'T1213.002 - SharePoint', body:`## TAG - COLLECTION\n### Technique: SharePoint Repository Collection, T1213.002\n- Time:\n- Source IP:\n- SharePoint Host: (on-prem / M365)\n- Search Query Count:\n- KQL Queries Observed:\n- Sites/Lists Enumerated:\n- Documents Downloaded:\n- User Account:\n\nNotes:` },
  'T1213.003': { title:'T1213.003 - Code Repositories', body:`## TAG - COLLECTION\n### Technique: Code Repository Collection, T1213.003\n- Time:\n- Source IP:\n- Git Host: (GitLab / Gitea / Bitbucket / GHE)\n- Repos Cloned: (count + sample names)\n- Sensitive Repos Touched: (Y/N)\n- User Account:\n- Subsequent Outbound Transfer: (Y/N)\n\nNotes:` },
  'T1114.001': { title:'T1114.001 - Local Email Collection', body:`## TAG - COLLECTION\n### Technique: Local Email Collection, T1114.001\n- Time:\n- Source IP:\n- Destination IP:\n- File Path: (.pst / .ost / .nst)\n- File Size: (PST/OST often 1-50GB)\n- User Account:\n- Subsequent Outbound Transfer: (Y/N)\n\nNotes:` },
  'T1114.002': { title:'T1114.002 - Remote Email Collection', body:`## TAG - COLLECTION\n### Technique: Remote Email Collection, T1114.002\n- Time:\n- Source IP:\n- Exchange/M365 Host:\n- API: (EWS / Graph / IMAP)\n- Operation: (FindItem / GetItem / ExportItems)\n- Mailbox(es) Accessed:\n- Item Count Retrieved:\n- User Account / Service Principal:\n\nNotes:` },
  'T1114.003': { title:'T1114.003 - Email Forwarding Rule', body:`## TAG - COLLECTION\n### Technique: Email Forwarding Rule, T1114.003\n- Time:\n- Source IP:\n- Affected Mailbox:\n- Rule Name:\n- Forward-To Address: (external?)\n- Rule Trigger: (all mail / keyword filter)\n- Delete-After-Forward: (Y/N)\n- API Used: (EWS / Graph / Set-InboxRule)\n- User/Threat Actor:\n\nNotes:` },
  T1530: { title:'T1530 - Data from Cloud Storage', body:`## TAG - COLLECTION\n### Technique: Data from Cloud Storage, T1530\n- Time:\n- Source IP:\n- Cloud Provider: (AWS S3 / Azure Blob / GCS)\n- Bucket(s) / Container(s):\n- Object Count Listed:\n- Object Count Downloaded:\n- Total Volume:\n- IAM Identity / SAS Token Used:\n- Cloud-Side Audit Log Reviewed: (CloudTrail / Activity / GCS audit)\n\nNotes:` },
  'T1602.002': { title:'T1602.002 - Network Device Config Dump', body:`## TAG - COLLECTION\n### Technique: Network Device Configuration Dump, T1602.002\n- Time:\n- Source IP:\n- Network Device:\n- Method: (SNMP CISCO-CONFIG-COPY / SSH show running / direct console)\n- SNMP Community / Credential Used:\n- Destination of Config: (TFTP / SCP target)\n- Config File Captured: (Y/N - preserved?)\n- Volt Typhoon Indicators: (LOTL / no-tools)\n\nNotes:` },
  'T1074.001': { title:'T1074.001 - Local Data Staging', body:`## TAG - COLLECTION\n### Technique: Local Data Staging, T1074.001\n- Time:\n- Source IP / Host:\n- Staging Path: ($Recycle.Bin / Windows\\\\Temp / ProgramData / Public)\n- Files Staged: (count + sample names)\n- Total Volume:\n- File Types: (.zip / .rar / .dat / .bin)\n- Subsequent Activity: (read / outbound transfer)\n\nNotes:` },
  'T1074.002': { title:'T1074.002 - Remote Data Staging', body:`## TAG - COLLECTION\n### Technique: Remote Data Staging, T1074.002\n- Time:\n- Source IPs: (multiple - list)\n- Staging Host: (the destination receiving aggregated data)\n- Total Volume Aggregated:\n- File Types Staged:\n- Window of Aggregation:\n- Egress Path of Staging Host: (direct internet / via proxy)\n- Subsequent Outbound Activity: (Y/N)\n\nNotes:` },
  'T1560.001': { title:'T1560.001 - Archive via Utility', body:`## TAG - COLLECTION\n### Technique: Archive via Utility, T1560.001\n- Time:\n- Source IP:\n- Destination IP:\n- Archive File: (name + extension)\n- Archive Format: (.zip / .rar / .7z / .tar.gz)\n- Archive Size:\n- Password-Protected: (Y/N - header bit)\n- Tool Inferred: (7-Zip / WinRAR / tar / custom)\n- Staged-Then-Archived Pattern: (links to T1074 hunt?)\n\nNotes:` },
  T1041: { title:'T1041 - Exfiltration Over C2 Channel', body:`## TAG - EXFILTRATION\n### Technique: Exfil Over C2 Channel, T1041\n- Time:\n- Source IP:\n- Destination IP / SNI:\n- Channel: (HTTPS / DNS tunnel / custom)\n- Total Bytes Out:\n- Bytes-Out:Bytes-In Ratio:\n- POST Burst Pattern: (Y/N - count + body sizes)\n- Linked C2 Detection: (TA0011 hunt ID)\n\nNotes:` },
  'T1048.001': { title:'T1048.001 - Exfil Over Symmetric Encrypted', body:`## TAG - EXFILTRATION\n### Technique: Exfil Over Symmetric Encrypted Non-C2, T1048.001\n- Time:\n- Source IP:\n- Destination IP:\n- Destination Port:\n- Protocol: (custom / non-TLS encrypted)\n- Payload Entropy:\n- Bytes Transferred:\n- Crypto Inferred: (AES / RC4 / XOR / unknown)\n\nNotes:` },
  'T1048.002': { title:'T1048.002 - Exfil Over Asymmetric Encrypted (SSH)', body:`## TAG - EXFILTRATION\n### Technique: Exfil Over SSH/SCP/SFTP, T1048.002\n- Time:\n- Source IP:\n- Destination IP:\n- Destination Reputation: (residential / hosting / unknown)\n- Bytes Transferred:\n- Tool Inferred: (scp / sftp / rclone / Mega CLI)\n- User Account / Process:\n- Sanctioned SSH Destination: (Y/N - allowlist match?)\n\nNotes:` },
  'T1048.003': { title:'T1048.003 - Exfil Over Unencrypted Protocol', body:`## TAG - EXFILTRATION\n### Technique: Exfil Over Unencrypted Non-C2 (FTP/SMB), T1048.003\n- Time:\n- Source IP:\n- Destination IP:\n- Protocol: (FTP STOR / FTPS / outbound SMB)\n- Filename(s):\n- Bytes Transferred:\n- Sanctioned Destination: (Y/N)\n- Note: outbound SMB to internet = essentially always malicious\n\nNotes:` },
  'T1567.001': { title:'T1567.001 - Exfil to Code Repository', body:`## TAG - EXFILTRATION\n### Technique: Exfil to Code Repo (GitHub/GitLab), T1567.001\n- Time:\n- Source IP:\n- Source User Role: (developer / non-developer)\n- Git Host: (github.com / gitlab.com / bitbucket.org)\n- Bytes Pushed:\n- Repo Name (if visible):\n- Public/Private Repo:\n- Account Used: (corp SSO / personal)\n\nNotes:` },
  'T1567.002': { title:'T1567.002 - Exfil to Cloud Storage', body:`## TAG - EXFILTRATION\n### Technique: Exfil to Cloud Storage, T1567.002\n- Time:\n- Source IP:\n- Cloud Service: (Mega / Anonfiles / Bunkr / Dropbox / OneDrive / Google Drive)\n- Service Tier: (exfil-friendly anonymous OR mainstream)\n- Bytes Uploaded:\n- Bytes-Out:Bytes-In Ratio:\n- Cloud-Side Audit Available: (Y/N - checked?)\n- User Account:\n\nNotes:` },
  'T1567.003': { title:'T1567.003 - Exfil to Text Storage Sites', body:`## TAG - EXFILTRATION\n### Technique: Exfil to Paste/Text Storage, T1567.003\n- Time:\n- Source IP:\n- Site: (pastebin.com / transfer.sh / ix.io / privatebin / other)\n- Bytes Posted:\n- Encrypted Paste: (Y/N - PrivateBin etc)\n- Source User Role:\n- Inferred Content: (credentials / config / data)\n\nNotes:` },
  'T1567.004': { title:'T1567.004 - Exfil Over Webhook', body:`## TAG - EXFILTRATION\n### Technique: Exfil Over Webhook (Discord/Slack/Telegram), T1567.004\n- Time:\n- Source IP / Host:\n- Service: (Discord / Slack / Telegram / other)\n- Webhook URL Pattern: (e.g. discord.com/api/webhooks/{id}/{token})\n- Bytes Posted:\n- POST Frequency:\n- Stealer Family Inferred: (RedLine / Raccoon / Vidar / LummaC2 / unknown)\n- Linked Initial Access: (phishing / drive-by / loader)\n\nNotes:` },
  T1029: { title:'T1029 - Scheduled Transfer', body:`## TAG - EXFILTRATION\n### Technique: Scheduled Transfer, T1029\n- Time of Transfer:\n- Source IP / Host:\n- Source Type: (workstation / server)\n- Destination:\n- Bytes Transferred:\n- Off-Hours: (Y/N - define window)\n- Day of Week:\n- User Activity at Time: (idle per EDR? / no recent input)\n- Schedule Pattern: (recurring? interval?)\n\nNotes:` },
  T1030: { title:'T1030 - Data Transfer Size Limits', body:`## TAG - EXFILTRATION\n### Technique: Chunked / Size-Limited Transfer, T1030\n- Time Window:\n- Source IP:\n- Destination IP / SNI:\n- Chunk Size Range: (e.g. 1-5MB per flow)\n- Flow Count in Window:\n- Aggregate Bytes:\n- Linked Destination Service: (T1567 destination?)\n- Detection Method: (SIEM aggregation / NDR)\n\nNotes:` },
  T1020: { title:'T1020 - Automated Exfiltration', body:`## TAG - EXFILTRATION\n### Technique: Automated Exfiltration, T1020\n- Source IP:\n- Destination IP / SNI:\n- Flow Interval Mean: (seconds)\n- Flow Interval Stddev: (seconds - low = automation)\n- Flow Count in Window:\n- Detection Tool: (RITA / commercial NDR / SIEM query)\n- Linked C2 Beacon: (TA0011 hunt ID if same source)\n- Process / Service Inferred:\n\nNotes:` },
};

// ── STATE ──
let activeTech = 'all';
let activeApt  = null;
let huntOpen   = false;
let totalRows  = 0;
let selectedRows = new Set();
let huntItems  = {};     // rowId -> { indicator, techId, severity, addedAt, row }
let rowRegistry = {};    // rowId -> { row, techId }

// ── OPERATING MODE (air-gapped vs connected) ──
// Air-gapped: off-network indicators are tripwires that should never fire.
// Connected: those same indicators are valid detection targets (external C2,
// exfil, etc. are exactly what you hunt on a connected network).
// The mode flips display only - underlying data is unchanged.
const MODE_STORAGE_KEY = 'cpt_hunt_mode';
const TRIPWIRE_PREFIX = '[OFF-NET TRIPWIRE] ';
// The air-gap escalation note is prepended to tripwire rows. Detect+strip in connected mode.
const AIRGAP_NOTE_RE = /^\[AIR-GAP TRIPWIRE\][^]*?(?:thorough investigation\.|priority-1 escalation[^.]*\.)\s*/;

function getMode() {
  const m = localStorage.getItem(MODE_STORAGE_KEY);
  return (m === 'connected') ? 'connected' : 'airgap';  // default air-gapped
}

function setMode(mode) {
  localStorage.setItem(MODE_STORAGE_KEY, mode === 'connected' ? 'connected' : 'airgap');
}

function isTripwireRow(row) {
  return !!(row && row.indicator && row.indicator.startsWith(TRIPWIRE_PREFIX));
}

// Indicator name as it should appear given the current mode.
// Air-gapped: strip the bracketed prefix, prepend a warning glyph.
// Connected: strip the bracketed prefix entirely (it's just a normal indicator).
function displayIndicator(row) {
  if (!isTripwireRow(row)) return row.indicator;
  const base = row.indicator.slice(TRIPWIRE_PREFIX.length);
  return getMode() === 'airgap' ? ('\u26A0 ' + base) : base;
}

// Notes as they should appear given the current mode.
// Connected mode strips the air-gap escalation preamble (it's misleading there).
function displayNotes(row) {
  if (!row.notes) return row.notes;
  if (getMode() === 'connected' && isTripwireRow(row)) {
    return row.notes.replace(AIRGAP_NOTE_RE, '');
  }
  return row.notes;
}

// ── PERSISTENCE ──
// Hunt items survive across tabs and browser sessions via localStorage.
// Schema versioning lets us migrate or discard incompatible saved data.
const HUNT_STORAGE_KEY = 'hunt_reference_hunts_v1';
const HUNT_SCHEMA_VERSION = 1;

function loadHunts() {
  try {
    const raw = localStorage.getItem(HUNT_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed._v !== HUNT_SCHEMA_VERSION) {
      console.warn('Hunt storage schema mismatch; discarding old data.');
      localStorage.removeItem(HUNT_STORAGE_KEY);
      return;
    }
    huntItems = parsed.items || {};
  } catch (e) {
    console.error('Failed to load hunts from localStorage:', e);
    huntItems = {};
  }
}

function saveHunts() {
  try {
    const payload = { _v: HUNT_SCHEMA_VERSION, items: huntItems };
    localStorage.setItem(HUNT_STORAGE_KEY, JSON.stringify(payload));
  } catch (e) {
    // QuotaExceededError is the realistic failure mode.
    console.error('Failed to save hunts to localStorage:', e);
  }
}

// Cross-tab sync: when another tab modifies the hunt list, refresh ours.
window.addEventListener('storage', e => {
  if (e.key !== HUNT_STORAGE_KEY) return;
  loadHunts();
  renderHunt();
  // Refresh star button states for indicators on the current page.
  document.querySelectorAll('.ind-row').forEach(rowEl => {
    const rowId = rowEl.dataset.rowId;
    const star = rowEl.querySelector('.star-btn');
    if (!star) return;
    if (huntItems[rowId]) {
      star.innerHTML = '&#9733;';
      star.classList.add('starred');
    } else {
      star.innerHTML = '&#9734;';
      star.classList.remove('starred');
    }
  });
});

// ── HELPERS ──
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function aptOrigins(apt) {
  return apt.map(a => {
    if (a.cls === 'apt-cn') return 'CN';
    if (a.cls === 'apt-ru') return 'RU';
    if (a.cls === 'apt-ir') return 'IR';
    if (a.cls === 'apt-kp') return 'KP';
    return '';
  }).join(' ');
}

function copyText(text, btn, label) {
  navigator.clipboard.writeText(text.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = label || 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
  });
}

// ── BUILD ROW ──
function buildRow(row, techId, rowId) {
  const searchText = [
    row.indicator, row.notes, row.arkime, row.kibana, row.suricata,
    row.apt.map(a => a.name + ' ' + (a.note||'')).join(' '),
    (row.malware||[]).map(a => a.name + ' ' + (a.note||'')).join(' '),
    (row.activity||[]).map(a => a.name + ' ' + (a.note||'')).join(' '),
    row.cite || '', techId
  ].join(' ').toLowerCase();

  const el = document.createElement('div');
  el.className = 'ind-row';
  if (isTripwireRow(row) && getMode() === 'airgap') {
    el.classList.add('tripwire');
  }
  el.dataset.tech = techId;
  el.dataset.apt  = aptOrigins(row.apt);
  el.dataset.text = searchText;
  el.dataset.rowId = rowId;
  el.dataset.techId = techId;

  // ── collapsed bar ──
  const bar = document.createElement('div');
  bar.className = 'ind-collapsed';
  const isStarred = !!huntItems[rowId];
  bar.innerHTML = `
    <input type="checkbox" class="row-check" title="Select for export">
    <button class="star-btn${isStarred ? ' starred' : ''}" title="Add to hunt">${isStarred ? '&#9733;' : '&#9734;'}</button>
    <span class="ind-name">${esc(displayIndicator(row))}</span>
    <div class="quick-tools">
      ${row.arkime ? '<button class="qtool qt-a" title="Copy Arkime">ARK</button>' : ''}
      <button class="qtool qt-k" title="Copy Kibana">KQL</button>
      <button class="qtool qt-s" title="Copy Suricata">SUR</button>
    </div>
    <span class="expand-icon">&#9662;</span>`;

  bar.querySelector('.row-check').addEventListener('click', e => {
    e.stopPropagation();
    toggleSelect(rowId, e.target);
  });
  bar.querySelector('.star-btn').addEventListener('click', e => {
    e.stopPropagation();
    toggleHuntItem(rowId, e.target);
  });
  if (row.arkime) {
    bar.querySelector('.qt-a').addEventListener('click', e => {
      e.stopPropagation();
      copyText(envApply(row.arkime, 'arkime').text, e.target);
    });
  }
  bar.querySelector('.qt-k').addEventListener('click', e => {
    e.stopPropagation();
    copyText(envApply(row.kibana, 'kibana').text, e.target);
  });
  bar.querySelector('.qt-s').addEventListener('click', e => {
    e.stopPropagation();
    copyText(envApply(row.suricata, 'suricata').text, e.target);
  });
  bar.addEventListener('click', () => el.classList.toggle('open'));

  // ── detail panel ──
  const detail = document.createElement('div');
  detail.className = 'ind-detail';

  // tab bar - Arkime tab only shown when row has an arkime query
  const tabs = [
    ['t-ark', 'Arkime',       !!row.arkime],
    ['t-kib', 'Kibana',       true],
    ['t-sur', 'Suricata',     true],
    ['t-not', 'Notes',        true],
    ['t-apt', 'APT',          true],
    ['t-cms', 'CMS Template', true],
  ];
  const tabBar = document.createElement('div');
  tabBar.className = 'tab-bar';
  let firstBtn = null;
  tabs.forEach(([cls, label, show]) => {
    if (!show) return;
    const btn = document.createElement('button');
    btn.className = 'dtab ' + cls;
    btn.dataset.key = cls.replace('t-', '');
    btn.textContent = label;
    btn.addEventListener('click', () => switchTab(detail, btn));
    tabBar.appendChild(btn);
    if (!firstBtn) { btn.classList.add('active'); firstBtn = btn; }
  });
  detail.appendChild(tabBar);

  // code panels

  // ---------------------------------------------------------------
  // Query block splitting.
  //
  // Many indicators carry several INDEPENDENT queries in one field,
  // each introduced by a `// label` header. Rendering them as a single
  // blob means the Copy button hands the analyst several concatenated
  // queries that are not valid as one query. splitBlocks() separates
  // them so each gets its own label and its own Copy button.
  //
  // Three comment roles are recognised:
  //   header       `// label` at the start of a block
  //   continuation a second `// line` before any query content
  //   annotation   `// note` AFTER query lines, explaining the clause
  //                above it (stays attached to that block)
  //
  // Returns null when there is nothing to split, so single-query
  // fields render exactly as before.
  // ---------------------------------------------------------------

  // ---------------------------------------------------------------
  // Environment profile substitution.
  // Arkime/Kibana queries get $VARIABLES replaced from the saved profile;
  // Suricata rules are left alone because Suricata resolves its own vars.
  // Unmapped variables are surfaced loudly: a query pasted with $MPNET still
  // in it returns zero hits, which reads as a clean network.
  // ---------------------------------------------------------------
  function envApply(text, field) {
    if (!window.TonkEnv) return { text: text, unmapped: [] };
    return window.TonkEnv.substitute(text, field);
  }

  function splitBlocks(text) {
    if (!text || text.indexOf('//') === -1) return null;
    const blocks = [];
    let cur = null, sawBlank = false;

    text.split('\n').forEach(line => {
      const isComment = /^\s*\/\//.test(line);
      if (isComment) {
        const t = line.replace(/^\s*\/\/\s?/, '').trim();
        if (cur && cur.query.trim() && !sawBlank) {
          cur.annotations.push(t);                 // trailing annotation
        } else if (cur && !cur.query.trim()) {
          cur.label = (cur.label ? cur.label + ' ' : '') + t;  // continuation
        } else {
          cur = { label: t, query: '', annotations: [] };      // new block
          blocks.push(cur);
        }
        sawBlank = false;
        return;
      }
      if (!line.trim()) { sawBlank = true; return; }
      if (!cur) { cur = { label: '', query: '', annotations: [] }; blocks.push(cur); }
      cur.query += (cur.query ? '\n' : '') + line;
      sawBlank = false;
    });

    const usable = blocks.filter(b => b.query.trim());
    return usable.length > 1 ? usable : null;
  }

  function codePanel(langCls, langLabel, content, envField) {
    var _env = envApply(content, envField);
    content = _env.text;
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    wrap.innerHTML = `<div class="code-hdr"><span class="code-lang ${langCls}">${langLabel}</span></div>`;
    const hdr = wrap.querySelector('.code-hdr');
    if (_env.unmapped && _env.unmapped.length) {
      const warn = document.createElement('span');
      warn.className = 'env-unmapped';
      warn.textContent = '\u26a0 ' + _env.unmapped.length + ' unmapped';
      warn.title = 'Not mapped in the environment profile: ' + _env.unmapped.join(', ')
                 + '\nThis query will not return what you expect until they are set.';
      hdr.appendChild(warn);
    }

    const blocks = splitBlocks(content);

    // Single query: unchanged behaviour.
    if (!blocks) {
      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyText(content, copyBtn));
      hdr.appendChild(copyBtn);
      const pre = document.createElement('pre');
      pre.className = 'code-body';
      pre.textContent = content;
      wrap.appendChild(pre);
      return wrap;
    }

    // Several queries: one copy button each, plus a count and copy-all.
    const count = document.createElement('span');
    count.className = 'block-count';
    count.textContent = blocks.length + ' queries';
    hdr.appendChild(count);
    const copyAll = document.createElement('button');
    copyAll.className = 'copy-btn';
    copyAll.textContent = 'Copy all';
    copyAll.addEventListener('click', () => copyText(content, copyAll));
    hdr.appendChild(copyAll);

    blocks.forEach((b, i) => {
      const blk = document.createElement('div');
      blk.className = 'query-block';

      const bh = document.createElement('div');
      bh.className = 'query-block-hdr';
      const lbl = document.createElement('span');
      lbl.className = 'query-block-label';
      lbl.textContent = b.label || ('Query ' + (i + 1));
      const cb = document.createElement('button');
      cb.className = 'copy-btn copy-btn-sm';
      cb.textContent = 'Copy';
      cb.addEventListener('click', () => copyText(b.query, cb));
      bh.appendChild(lbl);
      bh.appendChild(cb);
      blk.appendChild(bh);

      const pre = document.createElement('pre');
      pre.className = 'code-body';
      pre.textContent = b.query;
      blk.appendChild(pre);

      b.annotations.forEach(a => {
        const an = document.createElement('div');
        an.className = 'query-block-note';
        an.textContent = a;
        blk.appendChild(an);
      });

      wrap.appendChild(blk);
    });
    return wrap;
  }

  // panels - only build ark panel if row has an arkime query
  const panels = {
    ...(row.arkime ? { 'ark': codePanel('l-ark', 'Arkime SPI/Search', row.arkime, 'arkime') } : {}),
    'kib': codePanel('l-kib', 'Kibana KQL',        row.kibana, 'kibana'),
    'sur': codePanel('l-sur', 'Suricata Rule',     row.suricata, 'suricata'),
    'not': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = displayNotes(row); return d; })(),
    'apt': (() => {
      const d = document.createElement('div');

      // Render one association entry (name badge + optional note).
      const renderEntry = (a) => {
        const item = document.createElement('div');
        item.className = 'apt-item';
        item.innerHTML = `<span class="apt-badge ${a.cls || 'apt-mul'}" style="font-size:11px">${esc(a.name)}</span>`;
        if (a.note) {
          const note = document.createElement('div');
          note.className = 'apt-item-note';
          note.textContent = a.note;
          item.appendChild(note);
        }
        return item;
      };

      // Render a labeled section for a bucket, only if it has entries.
      const renderSection = (arr, label) => {
        if (!Array.isArray(arr) || !arr.length) return;
        if (label) {
          const h = document.createElement('div');
          h.className = 'apt-section-head';
          h.textContent = label;
          d.appendChild(h);
        }
        arr.forEach(a => d.appendChild(renderEntry(a)));
      };

      // Actors first (no header - the primary attribution), then the
      // non-actor buckets clearly separated so they are never mistaken for
      // threat-group attribution.
      renderSection(row.apt, null);
      renderSection(row.malware, 'Malware & Tooling');
      renderSection(row.activity, 'Activity & Roles');

      if (row.cite) {
        const cite = document.createElement('div');
        cite.className = 'apt-cite';
        cite.textContent = row.cite;
        d.appendChild(cite);
      }
      return d;
    })(),
    'cms': (() => {
      const d = document.createElement('div');
      const tpl = CMS_TEMPLATES[techId];
      if (tpl) {
        const hdr = document.createElement('div');
        hdr.className = 'cms-hdr';
        const title = document.createElement('span');
        title.className = 'cms-title';
        title.textContent = tpl.title;
        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.style.borderColor = 'var(--teal)';
        copyBtn.textContent = 'Copy Template';
        copyBtn.addEventListener('click', () => copyText(tpl.body, copyBtn, 'Copied!'));
        hdr.appendChild(title);
        hdr.appendChild(copyBtn);
        const pre = document.createElement('pre');
        pre.className = 'cms-body-pre';
        pre.textContent = tpl.body;
        d.appendChild(hdr);
        d.appendChild(pre);
      } else {
        d.innerHTML = '<span style="color:var(--text3);font-size:12px">No CMS template for this technique yet.</span>';
      }
      return d;
    })(),
  };

  const panelKeys = ['ark','kib','sur','not','apt','cms'];
  panelKeys.forEach((key, i) => {
    if (!panels[key]) return;
    const wrap = document.createElement('div');
    wrap.className = 'tab-panel';
    wrap.dataset.key = key;
    if (key === (row.arkime ? 'ark' : 'kib')) wrap.classList.add('active');
    wrap.appendChild(panels[key]);
    detail.appendChild(wrap);
  });

  el.appendChild(bar);
  el.appendChild(detail);
  rowRegistry[rowId] = { row, techId };
  return el;
}

function switchTab(detail, activeBtn) {
  detail.querySelectorAll('.dtab').forEach(b => b.classList.remove('active'));
  detail.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  activeBtn.classList.add('active');
  const key = activeBtn.dataset.key;
  const panel = detail.querySelector(`.tab-panel[data-key="${key}"]`);
  if (panel) panel.classList.add('active');
}

// ── RENDER ──
function render() {
  const content = document.getElementById('content');
  const toc     = document.getElementById('toc');
  const sidebarStats = document.getElementById('sidebar-stats');
  if (!content) return;

  DATA.forEach(tech => {
    // TOC
    const tocItem = document.createElement('div');
    tocItem.className = 'toc-item';
    tocItem.dataset.tech = tech.id;
    tocItem.innerHTML = `<span class="toc-id">${tech.id}</span><span class="toc-count">${tech.rows.length}</span>`;
    tocItem.addEventListener('click', () => {
      document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
      const btn = document.querySelector(`.fbtn[data-tech="${tech.id}"]`);
      if (btn) { btn.classList.add('active'); activeTech = tech.id; applyFilters(); }
      document.getElementById('tech-' + tech.id)?.scrollIntoView({ behavior:'smooth', block:'start' });
    });
    if (toc) toc.appendChild(tocItem);

    // Section
    const section = document.createElement('div');
    section.className = 'technique-section';
    section.id = 'tech-' + tech.id;
    section.dataset.tech = tech.id;

    const hdr = document.createElement('div');
    hdr.className = 'tech-header';
    hdr.innerHTML = `<span class="tech-id">${tech.id}</span><span class="tech-name">${tech.name}</span><span class="tech-count">${tech.rows.length}</span><span class="tech-desc">${tech.desc || ''}</span><span class="tech-toggle">&#9662;</span>`;
    hdr.addEventListener('click', () => section.classList.toggle('collapsed'));
    section.appendChild(hdr);

    const wrap = document.createElement('div');
    wrap.className = 'rows-wrap';

    let lastSub = '';
    tech.rows.forEach((row, i) => {
      if (row.sub && row.sub !== lastSub) {
        const div = document.createElement('div');
        div.className = 'sub-divider';
        div.textContent = row.sub;
        wrap.appendChild(div);
        lastSub = row.sub;
      }
      const rowId = tech.id + '_' + i;
      wrap.appendChild(buildRow(row, tech.id, rowId));
      totalRows++;
    });

    section.appendChild(wrap);
    content.appendChild(section);
  });

  if (sidebarStats) {
    sidebarStats.innerHTML = DATA.map(t =>
      `<div><span style="color:var(--accent);font-family:var(--mono)">${t.id}</span> - ${t.rows.length}</div>`
    ).join('') + `<div style="margin-top:6px;color:var(--text2)">Total: <strong>${totalRows}</strong></div>`;
  }

  updateStats(totalRows, totalRows);
}

// ── SELECT / EXPORT SELECTED ──
function toggleSelect(rowId, cb) {
  if (cb.checked) selectedRows.add(rowId);
  else selectedRows.delete(rowId);
  const btn = document.getElementById('export-selected-btn');
  if (btn) btn.style.display = selectedRows.size > 0 ? 'flex' : 'none';
}

function exportSelected() {
  if (!selectedRows.size) return;
  let out = `Hunt Reference - Selected Indicators\nExported: ${new Date().toLocaleString()}\n${'='.repeat(60)}\n\n`;
  selectedRows.forEach(rowId => {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    const { row, techId } = entry;
    out += `[${techId}] ${displayIndicator(row)}\n${'-'.repeat(50)}\n${row.arkime ? `ARKIME:\n${envApply(row.arkime,'arkime').text}\n\n` : ''}KIBANA:\n${envApply(row.kibana,'kibana').text}\n\nSURICATA:\n${row.suricata}\n\nNOTES:\n${displayNotes(row)}\n\n${'='.repeat(60)}\n\n`;
  });
  download(out, 'selected_indicators.txt', 'text/plain');
}

// ── HUNT ──
function toggleHunt() {
  huntOpen = !huntOpen;
  document.getElementById('hunt-panel').classList.toggle('open', huntOpen);
}

function toggleHuntItem(rowId, starBtn) {
  if (huntItems[rowId]) {
    delete huntItems[rowId];
    starBtn.innerHTML = '&#9734;';
    starBtn.classList.remove('starred');
  } else {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    huntItems[rowId] = {
      indicator: entry.row.indicator,
      techId: entry.techId,
      severity: 'high',
      addedAt: Date.now(),
      row: entry.row  // full row data - enables cross-tactic export from any page
    };
    starBtn.innerHTML = '&#9733;';
    starBtn.classList.add('starred');
    if (!huntOpen) { huntOpen = true; document.getElementById('hunt-panel').classList.add('open'); }
  }
  saveHunts();
  renderHunt();
}

function renderHunt() {
  const list = document.getElementById('hunt-list');
  const countEl = document.getElementById('hunt-count');
  const keys = Object.keys(huntItems);

  if (!keys.length) {
    list.innerHTML = '<div class="hunt-empty">No indicators added. Click &#9734; on any row.</div>';
    if (countEl) countEl.style.display = 'none';
    return;
  }

  if (countEl) { countEl.textContent = keys.length; countEl.style.display = 'inline'; }

  // Sort by addedAt ascending - oldest first, building a hunt timeline.
  // Items added before persistence existed have no addedAt and sort as 0 (top).
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Group consecutive items by techId and insert a small header before each new group.
  let html = '';
  let lastTech = null;
  sortedKeys.forEach(rowId => {
    const item = huntItems[rowId];
    if (item.techId !== lastTech) {
      html += `<div class="hunt-group-header">${item.techId}</div>`;
      lastTech = item.techId;
    }
    const ts = item.addedAt
      ? new Date(item.addedAt).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' })
      : '';
    html += `<div class="hunt-item">
      <span class="hunt-item-tech">${item.techId}</span>
      <span class="hunt-item-name">${esc((item.row ? displayIndicator(item.row) : null) || item.indicator)}</span>
      ${ts ? `<span class="hunt-item-ts" title="Added">${ts}</span>` : ''}
      <select class="sev-sel sev-${item.severity}" data-rowid="${rowId}">
        <option value="critical" ${item.severity==='critical'?'selected':''}>CRITICAL</option>
        <option value="high"     ${item.severity==='high'    ?'selected':''}>HIGH</option>
        <option value="medium"   ${item.severity==='medium'  ?'selected':''}>MEDIUM</option>
        <option value="low"      ${item.severity==='low'     ?'selected':''}>LOW</option>
      </select>
      <button class="hunt-remove" data-rowid="${rowId}">&#10005;</button>
    </div>`;
  });
  list.innerHTML = html;

  // CSP-safe: wire up handlers via listeners instead of inline on* attributes
  list.querySelectorAll('.sev-sel').forEach(sel => {
    sel.addEventListener('change', () => setSev(sel.dataset.rowid, sel));
  });
  list.querySelectorAll('.hunt-remove').forEach(btn => {
    btn.addEventListener('click', () => removeHunt(btn.dataset.rowid));
  });
}

function setSev(rowId, sel) {
  if (huntItems[rowId]) {
    huntItems[rowId].severity = sel.value;
    sel.className = 'sev-sel sev-' + sel.value;
    saveHunts();
  }
}

function removeHunt(rowId) {
  delete huntItems[rowId];
  const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
  if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  saveHunts();
  renderHunt();
}

function clearHunt() {
  Object.keys(huntItems).forEach(rowId => {
    const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
    if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  });
  huntItems = {};
  saveHunts();
  renderHunt();
}

function exportHunt(fmt) {
  const keys = Object.keys(huntItems);
  if (!keys.length) return;

  // Sort by addedAt to preserve hunt timeline order in exports.
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Use stored row data first; fall back to rowRegistry for items added before
  // persistence existed, or that for some reason lack the .row field.
  const getRow = rowId => huntItems[rowId].row || (rowRegistry[rowId] && rowRegistry[rowId].row);

  if (fmt === 'csv') {
    const q = s => '"' + String(s||'').replace(/"/g,'""').replace(/\n/g,' ') + '"';
    let csv = 'Order,Added,Severity,Technique,Indicator,Arkime,Kibana,Suricata,Notes\n';
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toISOString() : '';
      csv += [i+1, ts, item.severity.toUpperCase(), item.techId, displayIndicator(r), envApply(r.arkime,'arkime').text, envApply(r.kibana,'kibana').text, r.suricata, displayNotes(r)].map(q).join(',') + '\n';
    });
    download(csv, 'hunt_package.csv', 'text/csv');
  } else {
    let out = `Hunt Package\nExported: ${new Date().toLocaleString()}\nIndicators: ${sortedKeys.length}\n${'='.repeat(60)}\n\n`;
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toLocaleString() : 'unknown';
      out += `[${i+1}] [${item.severity.toUpperCase()}] ${item.techId} - ${displayIndicator(r)}\nAdded: ${ts}\n${'-'.repeat(50)}\n${r.arkime ? `ARKIME:\n${envApply(r.arkime,'arkime').text}\n\n` : ''}KIBANA:\n${envApply(r.kibana,'kibana').text}\n\nSURICATA:\n${r.suricata}\n\nNOTES:\n${displayNotes(r)}\n\n${'='.repeat(60)}\n\n`;
    });
    download(out, 'hunt_package.txt', 'text/plain');
  }
}

function download(content, filename, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── SEARCH + FILTER ──
function highlight(text, terms) {
  let result = esc(text);
  terms.forEach(t => {
    if (!t) return;
    const re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')', 'gi');
    result = result.replace(re, '<mark>$1</mark>');
  });
  return result;
}

function applyFilters() {
  const q   = (document.getElementById('search')?.value || '').toLowerCase().trim();
  const aq  = (document.getElementById('apt-search')?.value || '').toLowerCase().trim();
  const terms = q ? q.split(/\s+/).filter(Boolean) : [];
  let visible = 0;

  document.querySelectorAll('.ind-row').forEach(row => {
    const techMatch = activeTech === 'all' || row.dataset.tech === activeTech;
    const aptMatch  = !activeApt  || row.dataset.apt.includes(activeApt);
    const textMatch = !terms.length || terms.every(t => row.dataset.text.includes(t));
    const aptTxt    = !aq || row.dataset.text.includes(aq);

    if (techMatch && aptMatch && textMatch && aptTxt) {
      row.classList.remove('hidden');
      visible++;
      const nameEl = row.querySelector('.ind-name');
      if (nameEl) {
        const orig = row.querySelector('[data-row-id]')?.dataset.rowId
          ? rowRegistry[row.dataset.rowId]?.row.indicator
          : nameEl.textContent;
        if (orig) nameEl.innerHTML = highlight(orig, [...terms, aq].filter(Boolean));
      }
    } else {
      row.classList.add('hidden');
    }
  });

  document.querySelectorAll('.technique-section').forEach(sec => {
    sec.style.display = sec.querySelectorAll('.ind-row:not(.hidden)').length ? '' : 'none';
    const tocItem = document.querySelector(`.toc-item[data-tech="${sec.dataset.tech}"]`);
    if (tocItem) tocItem.classList.toggle('active', sec.dataset.tech === activeTech);
  });

  document.getElementById('no-results').style.display = visible ? 'none' : 'block';
  updateStats(visible, totalRows);
}

function updateStats(visible, total) {
  const el = document.getElementById('stats');
  if (el) el.textContent = `${visible} / ${total} indicators`;
}

// ── EVENT LISTENERS ──
document.getElementById('search')?.addEventListener('input', applyFilters);
document.getElementById('apt-search')?.addEventListener('input', applyFilters);

document.querySelectorAll('.fbtn[data-tech]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTech = btn.dataset.tech;
    applyFilters();
  });
});

document.querySelectorAll('.fbtn[data-apt]').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.apt;
    if (activeApt === key) {
      activeApt = null;
      btn.className = 'fbtn';
    } else {
      document.querySelectorAll('.fbtn[data-apt]').forEach(b => b.className = 'fbtn');
      activeApt = key;
      btn.classList.add('apt-' + key.toLowerCase());
    }
    applyFilters();
  });
});

// CSP-safe wiring for static header / hunt-panel buttons (replaces inline onclick)
document.getElementById('export-selected-btn')?.addEventListener('click', exportSelected);
document.querySelector('.hunt-btn')?.addEventListener('click', toggleHunt);
document.querySelectorAll('.hunt-export-btn').forEach(btn => {
  const act = btn.dataset.act;
  if (act === 'txt' || act === 'csv') {
    btn.addEventListener('click', () => exportHunt(act));
  } else if (act === 'clear') {
    btn.addEventListener('click', clearHunt);
  }
});

// ── INIT ──
loadHunts();
render();
applyFilters();
renderHunt();
injectModeToggle();

// ── OPERATING-MODE TOGGLE (header) ──
// Injected via JS so all pages get it without hand-editing each HTML file.
function injectModeToggle() {
  const host = document.querySelector('.header-right');
  if (!host) return;
  const mode = getMode();
  const wrap = document.createElement('div');
  wrap.className = 'mode-toggle';
  wrap.title = 'Air-gapped: off-network indicators are tripwires that should never fire.\nConnected: those indicators are valid detection targets.';
  wrap.innerHTML = `
    <button class="mode-opt${mode === 'airgap' ? ' active' : ''}" data-mode="airgap">Air-gapped</button>
    <button class="mode-opt${mode === 'connected' ? ' active' : ''}" data-mode="connected">Connected</button>`;
  wrap.querySelectorAll('.mode-opt').forEach(btn => {
    btn.addEventListener('click', () => {
      const newMode = btn.dataset.mode;
      if (newMode === getMode()) return;
      setMode(newMode);
      location.reload();  // clean re-render with no stale DOM
    });
  });
  // Place it first in the header-right cluster
  host.insertBefore(wrap, host.firstChild);
}


// ── SIDEBAR COLLAPSE ──
(function () {
  const sidebar   = document.getElementById('sidebar');
  const toggle    = document.getElementById('sidebar-toggle');
  const container = document.querySelector('.container');
  const backdrop  = document.getElementById('sidebar-backdrop');
  const mobileBtn = document.getElementById('mobile-sidebar-btn');
  if (!sidebar || !toggle) return;

  const MOBILE_BP = 900;
  const isMobile  = () => window.innerWidth <= MOBILE_BP;

  // Restore desktop collapsed state across page loads
  const PREF_KEY = 'sidebar_collapsed';
  let desktopCollapsed = localStorage.getItem(PREF_KEY) === '1';

  function applyDesktop() {
    sidebar.classList.toggle('collapsed', desktopCollapsed);
    if (container) container.classList.toggle('sidebar-collapsed', desktopCollapsed);
    toggle.setAttribute('title', desktopCollapsed ? 'Expand sidebar' : 'Collapse sidebar');
    toggle.innerHTML = desktopCollapsed ? '&#9654;' : '&#9776;';
  }

  function openMobile() {
    sidebar.classList.add('mobile-open');
    sidebar.classList.remove('collapsed');
    if (backdrop) backdrop.classList.add('active');
    if (mobileBtn) mobileBtn.classList.add('hidden');
  }

  function closeMobile() {
    sidebar.classList.remove('mobile-open');
    sidebar.classList.add('collapsed');
    if (backdrop) backdrop.classList.remove('active');
    if (mobileBtn) mobileBtn.classList.remove('hidden');
  }

  function initState() {
    if (isMobile()) {
      sidebar.classList.add('collapsed');
      sidebar.classList.remove('mobile-open');
      if (container) container.classList.remove('sidebar-collapsed');
      if (backdrop) backdrop.classList.remove('active');
      if (mobileBtn) mobileBtn.classList.remove('hidden');
    } else {
      sidebar.classList.remove('mobile-open', 'collapsed');
      if (backdrop) backdrop.classList.remove('active');
      if (mobileBtn) mobileBtn.classList.add('hidden');
      applyDesktop();
    }
  }

  toggle.addEventListener('click', () => {
    if (!isMobile()) {
      desktopCollapsed = !desktopCollapsed;
      localStorage.setItem(PREF_KEY, desktopCollapsed ? '1' : '0');
      applyDesktop();
    }
  });

  if (mobileBtn) {
    mobileBtn.addEventListener('click', openMobile);
  }

  if (backdrop) {
    backdrop.addEventListener('click', closeMobile);
  }

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && isMobile() && sidebar.classList.contains('mobile-open')) {
      closeMobile();
    }
  });

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(initState, 80);
  });

  initState();
})();
