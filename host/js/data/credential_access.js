// ── HOST REFERENCE: Credential Access (TA0006) ──
// Techniques for credential theft, dumping, and harvesting on host endpoints.

const DATA = [
  {
    id: "T1003.001",
    name: "OS Credential Dumping: LSASS Memory",
    desc: "Extraction of credential material from the Local Security Authority Subsystem Service (lsass.exe) process memory. LSASS holds NTLM hashes, Kerberos tickets, and plaintext passwords (if WDigest is enabled). This is the single most common credential access technique in enterprise intrusions and the one most likely to escalate a single-host compromise to domain-wide access.",
    rows: [
      {
        sub: "T1003.001 - LSASS Process Access and Memory Dump (Mimikatz, comsvcs, nanodump)",
        os: "win",
        indicator: "A process opening a handle to lsass.exe with memory-read rights (PROCESS_VM_READ, PROCESS_QUERY_INFORMATION) or creating a memory dump of lsass.exe via MiniDumpWriteDump, comsvcs.dll, or direct NTAPI calls, the definitive host signal for credential harvesting",
        sysmon: `// Sysmon EID 10 (ProcessAccess) - the primary detection
// Any process accessing lsass.exe with read-capable rights.
TargetImage=*\\lsass.exe
GrantedAccess contains:
  0x1010   // PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ
  0x1410   // + PROCESS_QUERY_INFORMATION
  0x1FFFFF // PROCESS_ALL_ACCESS (Mimikatz default)
  0x0810   // PROCESS_QUERY_LIMITED + VM_READ (nanodump)

// Filter known-good callers (tune to your environment):
// SourceImage NOT IN:
//   *\\csrss.exe, *\\lsass.exe, *\\MsMpEng.exe,
//   *\\svchost.exe, *\\wininit.exe, *\\vmtoolsd.exe

// Sysmon EID 1 - comsvcs.dll dump via rundll32
Image=*\\rundll32.exe
CommandLine=*comsvcs*MiniDump*

// Sysmon EID 11 (FileCreate) - lsass dump file
TargetFilename=(*lsass*.dmp OR *lsass*.zip OR *debug*.dmp)

// Sysmon EID 7 (ImageLoad) - dbgcore.dll or dbghelp.dll
// loaded by a non-debugging process (dump API dependency)
Image NOT IN (*\\WerFault.exe, *\\devenv.exe, *\\windbg.exe)
ImageLoaded=(*\\dbgcore.dll OR *\\dbghelp.dll)`,
        kibana: `// LSASS process access with suspicious rights
winlog.event_id: 10
AND winlog.event_data.TargetImage: *lsass.exe
AND winlog.event_data.GrantedAccess: ("0x1010" OR "0x1410"
  OR "0x1FFFFF" OR "0x0810" OR "0x01410" OR "0x143a")
AND NOT winlog.event_data.SourceImage: (*csrss* OR *lsass*
  OR *MsMpEng* OR *svchost* OR *wininit*)

// comsvcs.dll MiniDump
winlog.event_id: 1
AND process.command_line: (*comsvcs* AND *MiniDump*)

// LSASS dump file creation
winlog.event_id: 11
AND file.path: (*lsass*.dmp OR *lsass*.zip)

// Credential dump tool signatures
winlog.event_id: 1
AND process.command_line: (*sekurlsa* OR *logonpasswords*
  OR *lsadump* OR *kerberos::list* OR *token::elevate*)`,
        powershell: `# LSASS access hunt
Write-Host "[*] === Recent LSASS access events (Sysmon EID 10) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=10
} -MaxEvents 10000 -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[8].Value -like '*lsass*' } |
  Select-Object TimeCreated,
    @{n='Source';e={$_.Properties[4].Value}},
    @{n='Access';e={$_.Properties[10].Value}} |
  Where-Object { $_.Source -notmatch 'csrss|lsass|MsMpEng|svchost|wininit' }

Write-Host "[*] === Credential Guard status ==="
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -EA SilentlyContinue |
  Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus

Write-Host "[*] === WDigest plaintext caching ==="
Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -EA SilentlyContinue

Write-Host "[*] === RunAsPPL (LSA Protection) ==="
Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -EA SilentlyContinue

Write-Host "[*] === Recent dump files ==="
Get-ChildItem -Path C:\\Windows\\Temp,C:\\Temp,$env:TEMP -Filter '*.dmp' -Recurse -EA SilentlyContinue |
  Where-Object { $_.Name -match 'lsass|debug|procdump' }`,
        registry: `Hardening keys (pre-attack posture):
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa
  RunAsPPL = 1  (LSA Protection - blocks unsigned access)

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest
  UseLogonCredential = 0  (disables plaintext caching)

HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation
  AllowDefaultCredentials = 0  (restrict credential delegation)

Attack artifacts:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa
  RunAsPPL = 0  (attacker disabled LSA Protection)

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest
  UseLogonCredential = 1  (attacker enabled plaintext caching)`,
        tools: `Sysmon (EID 10 is the decisive detection)
Microsoft Defender for Endpoint (Credential Guard alerts)
Windows Credential Guard (hardware isolation of LSASS)
LSA Protection / RunAsPPL (blocks unsigned callers)
ASR Rule: Block credential stealing from LSASS`,
        ossdetect: `Sigma:
- win_sysmon_cred_dump_lsass_access.yml
- win_proc_creation_comsvcs_minidump.yml
- win_proc_creation_procdump_lsass.yml
- win_file_creation_lsass_dump.yml

Elastic Detection Rules:
- Credential Dumping - LSASS Memory
- LSASS Memory Dump via Comsvcs DLL

YARA:
- Mimikatz strings in memory / on disk`,
        notes: "LSASS credential dumping is the pivot point of most enterprise intrusions. A single LSASS dump typically yields domain admin hashes if any privileged user has logged into that machine. Sysmon EID 10 (ProcessAccess) targeting lsass.exe is the primary detection and should be deployed as a high-priority alert with aggressive tuning of known-good callers. Modern evasion includes direct syscalls (ntdll unhooking), duplicate handle abuse, PPL bypass via vulnerable drivers, and silent process exit dumps. Credential Guard (VBS-based LSASS isolation) is the strongest preventive control because it moves credentials into an isolated VM that is inaccessible even to kernel-mode attackers. LSA Protection (RunAsPPL) is a weaker but widely deployable alternative that blocks unsigned callers from accessing LSASS.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "LSASS credential harvesting documented across SolarWinds and follow-on intrusions for lateral movement." },
          { cls: "apt-cn", name: "APT41", note: "LSASS dumping as standard post-exploitation step in enterprise intrusions." },
          { cls: "apt-kp", name: "Lazarus", note: "Credential harvesting from LSASS in both espionage and financially motivated operations." },
          { cls: "apt-ru", name: "APT28", note: "LSASS access for credential theft in GRU operations." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "secretsdump.py performs remote LSASS dumping via DCOM/WMI." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "logonpasswords and hashdump commands in beacon perform LSASS memory reads." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "LSASS dumping is the universal first credential step for domain-wide ransomware deployment." }
        ],
        cite: "MITRE ATT&CK T1003.001"
      }
    ]
  },
  {
    id: "T1003.002",
    name: "OS Credential Dumping: Security Account Manager (SAM)",
    desc: "Extraction of local account NTLM hashes from the SAM registry hive. Unlike LSASS (which holds cached domain credentials), the SAM contains only local accounts, but these often include shared local admin passwords that enable lateral movement across the network.",
    rows: [
      {
        sub: "T1003.002 - SAM Registry Hive Export (reg save, shadow copy, in-memory extraction)",
        os: "win",
        indicator: "Extraction of the SAM registry hive via reg.exe save, volume shadow copy access, or direct registry API calls to harvest local account NTLM hashes for offline cracking or pass-the-hash lateral movement",
        sysmon: `// Sysmon EID 1 - reg.exe saving SAM/SYSTEM hives
Image=*\\reg.exe
CommandLine=*save* AND (*SAM* OR *SYSTEM* OR *SECURITY*)

// Sysmon EID 1 - shadow copy access to SAM
CommandLine=*\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*SAM*
OR CommandLine=*vssadmin*create*shadow*

// Sysmon EID 11 - SAM hive file creation in attacker path
TargetFilename=(*\\sam.save OR *\\sam.hiv OR *\\sam.bak
  OR *\\system.save OR *\\system.hiv)`,
        kibana: `// reg save SAM/SYSTEM
process.name: "reg.exe"
AND process.command_line: (*save* AND (*SAM* OR *SYSTEM* OR *SECURITY*))

// Shadow copy creation (prerequisite for offline SAM access)
process.name: "vssadmin.exe"
AND process.command_line: *create*shadow*

// esentutl copy of SAM
process.name: "esentutl.exe"
AND process.command_line: (*SAM* OR *SYSTEM* OR *SECURITY*)`,
        powershell: `# SAM dump detection
Write-Host "[*] === reg save commands in Sysmon ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match 'reg.*save.*(SAM|SYSTEM|SECURITY)' } |
  Select-Object TimeCreated,
    @{n='CmdLine';e={$_.Properties[10].Value.Substring(0,200)}}

Write-Host "[*] === Recent shadow copies ==="
vssadmin list shadows 2>$null

Write-Host "[*] === SAM hive files in temp paths ==="
Get-ChildItem -Path C:\\Windows\\Temp,C:\\Temp,$env:TEMP -Recurse -EA SilentlyContinue |
  Where-Object { $_.Name -match '(sam|system|security)\\.(save|hiv|bak|dump)$' }`,
        registry: `Source hives (attack targets):
HKLM\\SAM  (local account hashes)
HKLM\\SYSTEM  (contains the boot key to decrypt SAM)
HKLM\\SECURITY  (cached domain credentials, LSA secrets)

All three are needed for offline extraction. reg save
requires local admin. The SYSTEM hive provides the SysKey
(boot key) needed to decrypt the SAM hashes.`,
        tools: `Sysmon (EID 1 command line + EID 11 file creation)
secretsdump.py (Impacket - remote SAM extraction)
CrackMapExec (--sam flag for mass SAM dumping)
Microsoft LAPS (mitigates shared local admin passwords)`,
        ossdetect: `Sigma:
- win_proc_creation_reg_save_sam.yml
- win_proc_creation_shadow_copy_creation.yml

Elastic Detection Rules:
- SAM Registry Hive Dump
- Volume Shadow Copy Creation`,
        notes: "SAM dumping yields local account hashes. In environments without LAPS (Local Administrator Password Solution), the same local admin password is often reused across every workstation, making a single SAM dump equivalent to lateral access to the entire fleet. The detection is straightforward: reg save targeting SAM/SYSTEM/SECURITY hives, shadow copy creation followed by SAM file access, or esentutl.exe copying the hive files. The hardening control is LAPS (randomized local admin passwords per machine) combined with disabling the local Administrator account where possible.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SAM hive extraction for local credential harvesting in enterprise intrusions." },
          { cls: "apt-cn", name: "APT41", note: "SAM and SYSTEM hive dumping documented in tech sector operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Local credential extraction as part of lateral movement operations." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "secretsdump performs SAM extraction locally and remotely." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "SAM dumping for local admin hash reuse across fleet before encryption." }
        ],
        cite: "MITRE ATT&CK T1003.002"
      }
    ]
  },
  {
    id: "T1003.006",
    name: "OS Credential Dumping: DCSync",
    desc: "Abuse of Active Directory replication privileges (DS-Replication-Get-Changes-All) to request password hashes directly from a domain controller without running code on the DC itself. This is the stealthiest credential dumping technique because it uses legitimate AD replication protocol and leaves no artifact on the DC filesystem.",
    rows: [
      {
        sub: "T1003.006 - DCSync Replication Request (Mimikatz lsadump::dcsync, Impacket secretsdump)",
        os: "win",
        indicator: "A non-domain-controller machine or non-machine account issuing Directory Replication Service (DRS) GetNCChanges requests, the AD-side event that catches DCSync regardless of the tool used",
        sysmon: `// DCSync detection is on the DOMAIN CONTROLLER, not the attacker host.
// Security EID 4662 - DS-Replication-Get-Changes access
// This fires on the DC when replication is requested.

// The attacker-side signals (Sysmon on the source host):
// Sysmon EID 3 (NetworkConnect) - outbound to DC on port 135/49xxx
// (MS-DRSR uses RPC, initial on 135, then high port)
Image NOT IN (*\\lsass.exe, *\\svchost.exe, *\\dns.exe)
DestinationPort=(135 OR range 49152-65535)
DestinationHostname=*dc* OR DestinationIp=<DC_IP>

// Sysmon EID 1 - tool execution
CommandLine=(*lsadump::dcsync* OR *secretsdump* OR *-just-dc*)`,
        kibana: `// DC-side: Directory Replication Service access
// (must be collected from domain controllers)
winlog.event_id: 4662
AND winlog.event_data.Properties: (*1131f6ad* OR *1131f6aa* OR *89e95b76*)
AND NOT winlog.event_data.SubjectUserName: (*$)
// Machine accounts end in $; non-$ accounts requesting replication = DCSync

// Attacker-side: tool command lines
winlog.event_id: 1
AND process.command_line: (*dcsync* OR *secretsdump* OR *-just-dc*
  OR *GetNCChanges* OR *DRS_REPL*)`,
        powershell: `# DCSync detection and posture check
Write-Host "[*] === Accounts with Replicating Directory Changes ==="
Import-Module ActiveDirectory -EA SilentlyContinue

# Find non-default principals with replication rights
$domain = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:\\$domain"
$acl.Access | Where-Object {
  $_.ObjectType -match '1131f6ad|1131f6aa|89e95b76'
} | Select-Object IdentityReference, ActiveDirectoryRights,
  @{n='Right';e={
    switch -Regex ($_.ObjectType) {
      '1131f6ad' {'DS-Replication-Get-Changes-All'}
      '1131f6aa' {'DS-Replication-Get-Changes'}
      '89e95b76' {'DS-Replication-Get-Changes-In-Filtered-Set'}
    }
  }}

Write-Host "[*] === Recent 4662 replication events on this DC ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4662
} -MaxEvents 500 -EA SilentlyContinue |
  Where-Object { $_.Message -match '1131f6ad' -and $_.Message -notmatch '\\$$' } |
  Select-Object TimeCreated, @{n='User';e={
    ($_.Message -split 'Account Name:\\s+')[1] -split '\\s' | Select-Object -First 1
  }}`,
        registry: `No local registry artifact. DCSync is a network-level AD operation.

The three GUIDs to monitor in EID 4662:
  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2  DS-Replication-Get-Changes-All
  1131f6aa-9c07-11d1-f79f-00c04fc2dcd2  DS-Replication-Get-Changes
  89e95b76-444d-4c62-991a-0facbeda640c  DS-Replication-Get-Changes-In-Filtered-Set

By default, only Domain Controllers, Domain Admins, and
Enterprise Admins have these rights. Any other principal
with these rights is a misconfiguration or backdoor.`,
        tools: `Sysmon (attacker-side RPC connections to DC)
Security event log on DCs (EID 4662)
BloodHound / SharpHound (maps DCSync-capable principals)
PingCastle (flags excessive replication rights)`,
        ossdetect: `Sigma:
- win_security_dcsync.yml
- win_security_ad_replication_non_machine_account.yml

Elastic Detection Rules:
- Potential Credential Access via DCSync

BloodHound:
- DCSync edge in attack path graph`,
        notes: "DCSync is the most dangerous credential access technique because it extracts ALL domain password hashes (including krbtgt for Golden Ticket) without touching the DC filesystem, without running code on the DC, and using a legitimate AD protocol that many monitoring solutions don't inspect. The detection relies on Security EID 4662 on the DC showing a non-machine account requesting DS-Replication-Get-Changes-All. Machine accounts (ending in $) legitimately replicate, so the filter is: any principal WITHOUT a trailing $ requesting replication. The proactive control is auditing who has replication rights (should be only DCs, DA, EA) and alerting on any delegation of those rights to non-standard accounts.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "DCSync for domain-wide credential extraction in post-SolarWinds operations." },
          { cls: "apt-cn", name: "APT41", note: "DCSync as standard lateral movement escalation in enterprise intrusions." },
          { cls: "apt-ru", name: "APT28", note: "Domain credential harvesting via replication protocol abuse." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "secretsdump -just-dc performs DCSync via DRSUAPI." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "dcsync command in beacon for domain hash extraction." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "DCSync for krbtgt hash extraction before domain-wide encryption deployment." }
        ],
        cite: "MITRE ATT&CK T1003.006"
      }
    ]
  },
  {
    id: "T1003.008",
    name: "OS Credential Dumping: /etc/passwd and /etc/shadow",
    desc: "Reading or exfiltrating /etc/shadow (hashed passwords) and /etc/passwd (account enumeration) from Linux systems. /etc/shadow is readable only by root, so access implies root-level compromise. The hashes can be cracked offline to recover plaintext passwords for credential reuse across systems.",
    rows: [
      {
        sub: "T1003.008 - /etc/shadow Access and Credential Harvesting",
        os: "linux",
        indicator: "Non-standard processes reading /etc/shadow or /etc/gshadow, or tools like unshadow, hashcat, or john being run against shadow-format hashes, indicating credential harvesting for offline cracking or lateral movement",
        sysmon: `// Auditd rules - shadow file reads (the key detection)
-w /etc/shadow -p r -k shadow_read
-w /etc/gshadow -p r -k shadow_read
-w /etc/passwd -p r -k passwd_read

// Sysmon for Linux EID 1 - credential tools
Image matches: *unshadow* OR *john* OR *hashcat*
OR CommandLine matches: *shadow* AND (*cat* OR *cp* OR *scp* OR *base64*)

// cat/head/tail on shadow (interactive operator reading creds)
Image=(*/cat OR */head OR */tail OR */less OR */more)
CommandLine=*/etc/shadow*`,
        kibana: `// Shadow file reads via auditd
auditd.log.key: "shadow_read"
AND NOT process.name: ("sshd" OR "login" OR "su" OR "sudo"
  OR "passwd" OR "useradd" OR "groupadd" OR "chage")

// Direct shadow file access commands
process.args: "/etc/shadow"
AND process.name: ("cat" OR "cp" OR "scp" OR "head" OR "tail"
  OR "base64" OR "xxd" OR "curl")

// Credential cracking tools
process.name: ("john" OR "hashcat" OR "unshadow")`,
        powershell: `# Shadow file access hunt
echo "[*] === /etc/shadow permissions ==="
ls -la /etc/shadow /etc/gshadow 2>/dev/null

echo ""
echo "[*] === Auditd records for shadow reads ==="
ausearch -k shadow_read -ts recent 2>/dev/null | head -30

echo ""
echo "[*] === Recent processes that accessed shadow ==="
ausearch -f /etc/shadow -ts today 2>/dev/null |
  grep -oP 'exe="[^"]*"' | sort | uniq -c | sort -rn

echo ""
echo "[*] === Check for shadow copies in writable dirs ==="
find /tmp /dev/shm /var/tmp /home -name 'shadow*' -o -name '*shadow*' 2>/dev/null

echo ""
echo "[*] === Cracking tools on disk ==="
which john hashcat unshadow 2>/dev/null
find / -name 'john' -o -name 'hashcat' -type f 2>/dev/null | head -5`,
        registry: `No registry artifact (Linux technique).

Key files:
- /etc/shadow: hashed passwords (root-readable only, mode 640)
- /etc/gshadow: group password hashes
- /etc/passwd: account list (world-readable, no hashes on modern systems)

Shadow hash format: $id$salt$hash
  $1$ = MD5 (weak), $5$ = SHA-256, $6$ = SHA-512 (default)
  $y$ = yescrypt (modern default on Debian 12+)`,
        tools: `osquery:
  SELECT * FROM file WHERE path='/etc/shadow';
  -- Check permissions and mtime

Auditd (the primary detection):
  -w /etc/shadow -p r -k shadow_read

AIDE / Tripwire:
  Integrity monitoring on /etc/shadow

Falco:
  rule: Read sensitive file untrusted (covers /etc/shadow)`,
        ossdetect: `Sigma:
- lnx_auditd_shadow_file_read.yml

Falco:
- Read sensitive file untrusted
- Read sensitive file after startup

Wazuh:
- FIM on /etc/shadow (modification alert)
- Auditd integration for read-access alerts

osquery:
- file table: shadow permission changes`,
        notes: "/etc/shadow access by a non-authentication process (anything other than sshd, login, su, sudo, passwd, chage) is a high-confidence credential theft indicator. The auditd read-watch (-p r) on /etc/shadow is the decisive detection because it catches all access methods: cat, cp, scp, Python open(), or any other file read. The main false positive sources are authentication subsystem processes and account management tools. After harvesting, the attacker either cracks hashes offline (john/hashcat) or uses the hashes directly if the system uses a weak algorithm. The yescrypt algorithm (default on Debian 12+) is designed to be resistant to GPU cracking, making credential reuse the more likely exploitation path than brute force.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Shadow file harvesting on compromised Linux servers for credential reuse." },
          { cls: "apt-kp", name: "Lazarus", note: "Linux credential theft documented in server-targeting campaigns." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Credential harvesting from Linux infrastructure during pre-positioning operations." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Hands-on intruders", note: "cat /etc/shadow is a universal first action after gaining root on a Linux host." },
          { cls: "apt-mul", name: "TeamTNT", note: "Shadow file exfil for credential reuse across cloud infrastructure." }
        ],
        cite: "MITRE ATT&CK T1003.008"
      }
    ]
  },
  {
    id: "T1558.003",
    name: "Steal or Forge Kerberos Tickets: Kerberoasting",
    desc: "Requesting Kerberos TGS tickets for service accounts (SPNs), then cracking the tickets offline to recover the service account plaintext password. Kerberoasting is devastating because service accounts often have weak passwords, high privileges, and no lockout policy, and the attack generates only normal-looking TGS requests.",
    rows: [
      {
        sub: "T1558.003 - Kerberoasting (mass TGS-REQ for SPN-registered service accounts)",
        os: "win",
        indicator: "A single user account requesting TGS tickets (EID 4769) for multiple SPN-registered service accounts in a short time window using RC4 encryption (etype 0x17), the behavioral pattern that distinguishes Kerberoasting from legitimate service access",
        sysmon: `// Kerberoasting detection is primarily through Security event logs
// on the Domain Controller, not Sysmon on the attacker host.

// Attacker-side Sysmon signals:
// EID 1 - known Kerberoasting tool execution
CommandLine matches:
  *Invoke-Kerberoast* OR *Rubeus*kerberoast*
  OR *GetUserSPNs* OR *-request -outputfile*
  OR *setspn* -T * -Q */*

// EID 3 - Kerberos TGS traffic to DC port 88
DestinationPort=88
// (high volume; correlate with tool execution timeline)`,
        kibana: `// DC-side: TGS requests with RC4 encryption (Kerberoasting signature)
winlog.event_id: 4769
AND winlog.event_data.TicketEncryptionType: "0x17"
AND winlog.event_data.Status: "0x0"
AND NOT winlog.event_data.ServiceName: (*$ OR krbtgt)

// High-volume TGS requests from single user (behavioral)
// Use Kibana Lens: count of 4769 by TargetUserName per 5min
// Alert when count > 10 unique ServiceNames from one account

// Tool execution
winlog.event_id: 1
AND process.command_line: (*Kerberoast* OR *GetUserSPNs*
  OR *Rubeus* OR *setspn*)

// PowerShell Kerberoasting
winlog.event_id: 4104
AND script_block_text: (*KerberosRequestorSecurityToken*
  OR *Invoke-Kerberoast* OR *Request-SPNTicket*)`,
        powershell: `# Kerberoasting posture check and detection
Write-Host "[*] === SPN-registered service accounts ==="
Import-Module ActiveDirectory -EA SilentlyContinue
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet,Enabled |
  Select-Object SamAccountName, Enabled, PasswordLastSet,
    @{n='SPNs';e={$_.ServicePrincipalName -join '; '}} |
  Format-Table -Auto

Write-Host "[*] === Recent TGS requests with RC4 (EID 4769, etype 0x17) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4769
} -MaxEvents 2000 -EA SilentlyContinue |
  Where-Object { $_.Properties[5].Value -eq '0x17' -and
    $_.Properties[0].Value -notmatch '\\$$' } |
  Group-Object { $_.Properties[0].Value } |
  Select-Object Count, Name | Sort-Object Count -Descending

Write-Host "[*] === Kerberoasting tool artifacts ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104
} -MaxEvents 500 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'Kerberoast|KerberosRequestor|GetUserSPN' } |
  Select-Object TimeCreated, @{n='Script';e={$_.Message.Substring(0,200)}}`,
        registry: `No persistent registry artifact from Kerberoasting itself.

Detection context:
- EID 4769 Ticket Encryption Type 0x17 = RC4-HMAC
  (attackers request RC4 because it is fastest to crack)
- Modern AD defaults to AES (0x12), so RC4 requests are
  anomalous in AES-capable environments
- Service accounts with SPNs are the targets; enumerate
  them proactively and enforce strong passwords or gMSAs`,
        tools: `BloodHound / SharpHound (maps Kerberoastable accounts)
Rubeus (kerberoast command)
Impacket GetUserSPNs.py
hashcat (mode 13100 for krb5tgs)
Group Managed Service Accounts (gMSA - the fix)`,
        ossdetect: `Sigma:
- win_security_kerberoasting.yml
- win_security_susp_rc4_tgs_request.yml

Elastic Detection Rules:
- Kerberoasting Activity
- Suspicious RC4 Kerberos Ticket Request

BloodHound:
- Kerberoastable accounts highlighted in graph`,
        notes: "Kerberoasting generates only EID 4769 (TGS request) on the DC, which is a normal Kerberos operation. The detection relies on behavioral anomalies: (1) RC4 encryption type (0x17) in an AES-capable environment, (2) high volume of TGS requests from a single user to different SPNs in a short window, (3) requests for service accounts that the requesting user has never accessed before. The fix is not detection but prevention: replace service account passwords with Group Managed Service Accounts (gMSAs, which auto-rotate 120+ character passwords), or enforce 25+ character passwords on all SPN-registered accounts. Targeted Kerberoasting (requesting a single high-value SPN) is much harder to detect because it generates only one TGS event.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Kerberoasting for service account credential access in enterprise intrusions." },
          { cls: "apt-cn", name: "APT41", note: "Kerberoasting documented as part of AD escalation in technology sector operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Service account credential theft in enterprise-targeted campaigns." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "GetUserSPNs.py is the standard Kerberoasting tool." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Rubeus integration for in-memory Kerberoasting." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Kerberoasting for service account credentials during domain escalation before encryption." }
        ],
        cite: "MITRE ATT&CK T1558.003"
      }
    ]
  },
  {
    id: "T1552.004",
    name: "Unsecured Credentials: Private Keys",
    desc: "Discovery and theft of SSH private keys, PGP keys, cloud API keys, and TLS certificate private keys from compromised hosts. SSH keys are particularly valuable because they provide passwordless authentication to other systems and often have no expiration date, making them a silent lateral movement path.",
    rows: [
      {
        sub: "T1552.004 - SSH Private Key Theft and Credential File Harvesting",
        os: "linux",
        indicator: "Enumeration or exfiltration of SSH private keys from ~/.ssh/ directories, /etc/ssh/ host keys, or other private key files identified by find/grep sweeps targeting key file headers (BEGIN RSA/DSA/EC/OPENSSH PRIVATE KEY) or common key file extensions",
        sysmon: `// Auditd rules for SSH key directory access
-w /root/.ssh/ -p r -k ssh_key_access
-w /home/ -p r -k ssh_key_access
-w /etc/ssh/ -p r -k ssh_host_key_access

// Sysmon for Linux EID 1 - key enumeration commands
CommandLine matches:
  *find*-name*id_rsa* OR *find*-name*id_ed25519*
  OR *find*-name*.pem*
  OR *grep*-r*BEGIN*PRIVATE*KEY*
  OR *cat*/.ssh/id_*`,
        kibana: `// SSH key file reads
auditd.log.key: ("ssh_key_access" OR "ssh_host_key_access")
AND NOT process.name: ("sshd" OR "ssh" OR "ssh-agent" OR "ssh-keygen")

// Key enumeration sweeps
process.name: "find"
AND process.args: (*id_rsa* OR *id_ed25519* OR *id_ecdsa* OR *.pem*)

// Direct key file reads
process.args: (*/ssh/id_* OR */ssh/host_* OR *BEGIN*PRIVATE*)
AND process.name: ("cat" OR "cp" OR "scp" OR "base64" OR "curl")`,
        powershell: `# SSH key theft detection
echo "[*] === All SSH private keys on this host ==="
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \\
  -o -name 'id_dsa' -o -name '*.pem' 2>/dev/null |
  while read f; do
    echo "  $f ($(stat -c '%U:%G %a %y' "$f"))"
  done

echo ""
echo "[*] === SSH host keys ==="
ls -la /etc/ssh/ssh_host_*_key 2>/dev/null

echo ""
echo "[*] === Auditd records for key access ==="
ausearch -k ssh_key_access -ts recent 2>/dev/null | head -20

echo ""
echo "[*] === Keys in unusual locations ==="
find /tmp /dev/shm /var/tmp -name 'id_*' -o -name '*.pem' 2>/dev/null

echo ""
echo "[*] === SSH config for key forwarding (agent forwarding risk) ==="
grep -r 'ForwardAgent' /etc/ssh/ /home/*/.ssh/config 2>/dev/null`,
        registry: `No registry artifact (Linux technique).

Key file locations:
- ~/.ssh/id_rsa, id_ed25519, id_ecdsa (user keys)
- /etc/ssh/ssh_host_*_key (host keys)
- /path/to/*.pem (TLS/cloud keys)

SSH agent forwarding risk:
If ForwardAgent=yes is set, an attacker on a jump host
can use the forwarded agent socket to authenticate as
the user to downstream systems without possessing the key.
Agent socket path: /tmp/ssh-*/agent.*`,
        tools: `osquery:
  SELECT * FROM file WHERE directory LIKE '%/.ssh/'
    AND filename LIKE 'id_%' AND filename NOT LIKE '%.pub';
Auditd (read-watch on key directories)
Falco (sensitive file read rules)
ssh-audit (key algorithm assessment)`,
        ossdetect: `Sigma:
- lnx_auditd_ssh_key_access.yml
Falco:
- Read sensitive file untrusted (/root/.ssh, /home/*/.ssh)
Wazuh:
- FIM on ~/.ssh/ directories
osquery:
- Scheduled: file table sweep for new key files`,
        notes: "SSH key theft is the Linux equivalent of credential dumping: a single stolen key provides passwordless access to every system where the corresponding public key is authorized. Unlike passwords, keys have no lockout policy, no expiration by default, and no authentication log that distinguishes key-based access from legitimate use. The detection focuses on non-SSH processes reading key files (auditd read-watch is the primary control) and on enumeration commands (find/grep sweeps for key headers). Agent forwarding creates an additional risk: an attacker on a jump host with ForwardAgent=yes can hijack the forwarded agent socket to authenticate downstream without ever touching the private key file. Disable agent forwarding globally and use ProxyJump instead.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH key harvesting for persistent lateral access across Linux infrastructure." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "SSH credential theft during critical infrastructure pre-positioning." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH key theft in server-targeting campaigns." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "TeamTNT", note: "SSH key harvesting from compromised cloud hosts for lateral propagation." },
          { cls: "apt-mul", name: "Hands-on intruders", note: "find / -name id_rsa is a universal post-root action on Linux." }
        ],
        cite: "MITRE ATT&CK T1552.004"
      }
    ]
  },
];
