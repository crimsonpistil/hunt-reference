const DATA = [
  {
    id: "T1033",
    name: "System Owner/User Discovery",
    desc: "Determining the current user context, privilege level, and domain membership. whoami /all is the canonical first command after foothold because it answers three questions simultaneously: who am I, what groups am I in, and what privileges do I hold.",
    rows: [
      {
        sub: "T1033 - User Context Enumeration (whoami, query user, id)",
        os: "win",
        indicator: "Execution of whoami (especially with /priv, /groups, /all flags), query user, qwinsta, or id to determine the current security context, privilege level, and active sessions on the compromised host",
        sysmon: `// Sysmon EID 1 - whoami with enumeration flags
Image=*\\\\whoami.exe
// /priv = checking for SeDebugPrivilege, /all = full enum

// Session enumeration
Image=(*\\\\query.exe OR *\\\\qwinsta.exe OR *\\\\quser.exe)

// Suspicious parent: whoami from web server or LOLBin
ParentImage=(*\\\\w3wp.exe OR *\\\\httpd.exe OR *\\\\rundll32.exe OR *\\\\mshta.exe)`,
        kibana: `// whoami with enumeration flags
process.name: "whoami.exe"
AND process.args: ("/priv" OR "/groups" OR "/all")

// Suspicious parent for whoami
process.name: "whoami.exe"
AND process.parent.name: ("w3wp.exe" OR "httpd.exe" OR "rundll32.exe")

// Linux
process.name: ("id" OR "whoami" OR "w" OR "who")`,
        powershell: `# User discovery detection
Write-Host "[*] === whoami executions ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[4].Value -like '*whoami*' } |
  Select-Object TimeCreated,
    @{n='Parent';e={$_.Properties[20].Value.Split('\\')[-1]}},
    @{n='CmdLine';e={$_.Properties[10].Value}}`,
        registry: "No registry artifact. Detection is process-based.\n\nKey whoami output for threat assessment:\n  /priv: SeDebugPrivilege = can dump LSASS\n  /priv: SeImpersonatePrivilege = potato escalation possible\n  /groups: Domain Admins = domain-level access already held",
        tools: "Sysmon (EID 1 command line)\nSecurity EID 4688 (process creation)\nAuditd execve monitoring (Linux)",
        ossdetect: "Sigma:\n- win_proc_creation_whoami_execution.yml\n- win_proc_creation_whoami_priv_groups.yml\nElastic:\n- Whoami Process Activity",
        notes: "whoami alone is low-confidence. Detection value comes from context: parent process (whoami from w3wp.exe is post-exploit), flags (/priv and /all are attacker-oriented), and timing (whoami + ipconfig + net user within 30 seconds is a discovery burst). Focus on SEQUENCES rather than individual commands.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "whoami /all as standard first post-exploitation command." },
          { cls: "apt-ru", name: "APT29", note: "User context enumeration in systematic post-compromise discovery." },
          { cls: "apt-kp", name: "Lazarus", note: "whoami and session enumeration in initial foothold assessment." }
        ],
        malware: [
          { cls: "apt-mul", name: "Cobalt Strike", note: "shell whoami /all is the default first beacon command." }
        ],
        activity: [
          { cls: "apt-mul", name: "All Operators", note: "Near-universal first post-foothold command regardless of actor." }
        ],
        cite: "MITRE ATT&CK T1033"
      }
    ]
  },
  {
    id: "T1082",
    name: "System Information Discovery",
    desc: "Gathering host configuration: OS version, architecture, hostname, domain membership, installed patches, uptime. systeminfo returns patch level, which attackers use to identify missing patches for local privilege escalation.",
    rows: [
      {
        sub: "T1082 - System Profiling (systeminfo, hostname, uname, wmic os)",
        os: "win",
        indicator: "Execution of systeminfo, hostname, ver, wmic os get, or uname -a to profile the OS, patch level, domain membership, and hardware for exploit compatibility and targeting decisions",
        sysmon: `// Sysmon EID 1 - system profiling
Image=(*\\\\systeminfo.exe OR *\\\\hostname.exe)
Image=*\\\\wmic.exe AND CommandLine=(*os*get* OR *computersystem*get*)

// PowerShell variants
CommandLine=(*Get-ComputerInfo* OR *Win32_OperatingSystem*)

// Linux: Image=(*/uname OR */hostnamectl OR */lsb_release)`,
        kibana: `// Windows system profiling
process.name: ("systeminfo.exe" OR "hostname.exe")
OR (process.name: "wmic.exe" AND process.command_line: (*os* OR *computersystem*))

// Linux
process.name: ("uname" OR "hostnamectl" OR "lsb_release")`,
        powershell: `# System profiling detection
Write-Host "[*] === systeminfo/hostname executions ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[4].Value -match 'systeminfo|hostname' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}`,
        registry: "No registry artifact from the commands.\n\nCommonly queried keys during system discovery:\n  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion (OS version)\n  HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName (hostname)",
        tools: "Sysmon (EID 1)\nSecurity EID 4688\nAuditd (Linux)",
        ossdetect: "Sigma:\n- win_proc_creation_systeminfo.yml\nElastic:\n- System Information Discovery",
        notes: "systeminfo is notable because it returns the hotfix list, which attackers cross-reference against known LPE CVEs. An attacker running systeminfo followed by searching hotfixes for missing patches is a distinct chain. On Linux, uname -a + cat /etc/os-release + dpkg -l is the equivalent sequence.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "systeminfo for patch-level assessment and escalation planning." },
          { cls: "apt-ru", name: "APT28", note: "System profiling in structured GRU discovery operations." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "All Operators", note: "System profiling is universal in the discovery phase." }
        ],
        cite: "MITRE ATT&CK T1082"
      }
    ]
  },
  {
    id: "T1016",
    name: "System Network Configuration Discovery",
    desc: "Enumerating network configuration to map local topology and identify adjacent subnets for lateral movement. ipconfig /all finds the DNS server (likely a DC), arp -a finds live hosts, route print identifies reachable subnets.",
    rows: [
      {
        sub: "T1016 - Network Config Enumeration (ipconfig, ifconfig, route, arp, ip addr)",
        os: "win",
        indicator: "Execution of ipconfig /all, route print, arp -a, or Linux equivalents (ip addr, ip route, ss) to map local network topology, DNS infrastructure, and adjacent subnets for lateral movement planning",
        sysmon: `// Sysmon EID 1 - Windows network config
Image=(*\\\\ipconfig.exe OR *\\\\route.exe OR *\\\\arp.exe OR *\\\\netsh.exe)

// Linux: Image=(*/ip OR */ifconfig OR */route OR */arp OR */ss)`,
        kibana: `// Windows
process.name: ("ipconfig.exe" OR "route.exe" OR "arp.exe" OR "netsh.exe")

// Linux
process.name: ("ip" OR "ifconfig" OR "route" OR "ss" OR "netstat")`,
        powershell: `# Network config discovery detection
Write-Host "[*] === Network discovery commands ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[4].Value -match 'ipconfig|route\\.exe|arp\\.exe|netsh' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,150)}}`,
        registry: "No registry artifact.\n\nNetwork config stored at:\n  HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        tools: "Sysmon (EID 1)\nAuditd (Linux)",
        ossdetect: "Sigma:\n- win_proc_creation_network_discovery.yml\nElastic:\n- Network Configuration Discovery",
        notes: "The detection value is in the SEQUENCE: ipconfig alone is noise, but ipconfig + arp + route + net view within 60 seconds from a single process tree is a structured discovery burst. Detect the pattern, not the individual command.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Network topology mapping for lateral movement planning." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Living-off-the-land network enumeration during pre-positioning." },
          { cls: "apt-ru", name: "APT29", note: "Network configuration discovery in post-compromise enumeration." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "All Operators", note: "Universal in the discovery phase." }
        ],
        cite: "MITRE ATT&CK T1016"
      }
    ]
  },
  {
    id: "T1087.002",
    name: "Account Discovery: Domain Account",
    desc: "Enumerating AD accounts, group memberships, and trust relationships. net user /domain and net group 'Domain Admins' /domain reveal who has privileged access and which service accounts are Kerberoasting targets. ADFind is heavily associated with ransomware pre-staging.",
    rows: [
      {
        sub: "T1087.002 - Domain Account and Group Enumeration (net user/group /domain, nltest, ADFind)",
        os: "win",
        indicator: "Execution of domain enumeration commands to map privileged accounts, group memberships, and trust relationships for credential targeting and lateral movement planning",
        sysmon: `// Sysmon EID 1 - net.exe domain enumeration
Image=(*\\\\net.exe OR *\\\\net1.exe)
CommandLine=(*user*/domain* OR *group*/domain*
  OR *"Domain Admins"* OR *"Enterprise Admins"*)

// nltest domain trust enumeration
Image=*\\\\nltest.exe
CommandLine=(*dclist* OR *domain_trusts* OR *dsgetdc*)

// PowerShell AD cmdlets
CommandLine=(*Get-ADUser* OR *Get-ADGroup* OR *Get-ADComputer*
  OR *Get-ADDomain* OR *[adsisearcher]*)

// ADFind (ransomware pre-staging indicator)
Image=*\\\\adfind.exe`,
        kibana: `// net domain enumeration
process.name: ("net.exe" OR "net1.exe")
AND process.command_line: (*"/domain"*)

// Privileged group enumeration
process.command_line: (*"Domain Admins"* OR *"Enterprise Admins"*)

// nltest
process.name: "nltest.exe"
AND process.command_line: (*dclist* OR *domain_trusts*)

// ADFind
process.name: "adfind.exe"

// PowerShell AD
script_block_text: (*Get-ADUser* OR *Get-ADGroup* OR *adsisearcher*)`,
        powershell: `# Domain enumeration detection
Write-Host "[*] === Domain enumeration commands ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match 'net.*/domain|nltest|adfind|Get-AD' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}`,
        registry: "No registry artifact.\n\nLDAP queries generated by these commands are logged in Security EID 4662 on DCs if Directory Service Access audit is enabled.",
        tools: "Sysmon (EID 1)\nPowerShell ScriptBlock logging (EID 4104)\nSecurity EID 4661/4662 on DCs\nBloodHound / SharpHound",
        ossdetect: "Sigma:\n- win_proc_creation_net_domain_enum.yml\n- win_proc_creation_nltest.yml\n- win_proc_creation_adfind.yml\nElastic:\n- Domain Account Discovery\n- Active Directory Enumeration via nltest",
        notes: "ADFind is a strong ransomware pre-staging indicator: Conti, Ryuk, and BlackBasta playbooks all document ADFind as a required step. The combination of net group 'Domain Admins' /domain followed by Kerberoasting or DCSync should be treated as a confirmed attack chain.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Systematic AD enumeration for targeting privileged accounts." },
          { cls: "apt-cn", name: "APT41", note: "Domain account and group enumeration in enterprise intrusions." },
          { cls: "apt-kp", name: "Lazarus", note: "AD enumeration for lateral movement targeting." },
          { cls: "apt-ru", name: "APT28", note: "Domain discovery for credential targeting in GRU operations." }
        ],
        malware: [
          { cls: "apt-mul", name: "Cobalt Strike", note: "net domain commands and PowerView for AD enumeration." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "ADFind + BloodHound is a documented step in Conti/Ryuk/BlackBasta playbooks." }
        ],
        cite: "MITRE ATT&CK T1087.002"
      }
    ]
  },
  {
    id: "T1518.001",
    name: "Software Discovery: Security Software Discovery",
    desc: "Identifying installed AV, EDR, SIEM forwarders, and host IDS. This drives defense evasion decisions: which tools to disable, which processes to avoid, and what detection gaps exist.",
    rows: [
      {
        sub: "T1518.001 - Security Software Enumeration (AV/EDR process and service discovery)",
        os: "win",
        indicator: "Execution of commands specifically targeting security product processes and services (MsMpEng, CrowdStrike, SentinelOne, Sophos, Tanium, Splunk forwarders) to assess which defenses to evade or disable",
        sysmon: `// Sysmon EID 1 - security-targeted tasklist/wmic
Image=(*\\\\tasklist.exe OR *\\\\wmic.exe)
CommandLine=(*AntiVirus* OR *MsMpEng* OR *csfalcon* OR *SentinelOne*
  OR *CylanceSvc* OR *Sophos* OR *crowdstrike* OR *Tanium*
  OR *splunkd* OR *winlogbeat* OR *ossec* OR *wazuh*)

// PowerShell security product query
CommandLine=(*Get-MpComputerStatus* OR *SecurityCenter2* OR *AntiVirusProduct*)

// Linux: ps aux | grep falcon/ossec/wazuh/auditd/sysmon`,
        kibana: `// Security product enumeration
process.name: ("tasklist.exe" OR "wmic.exe" OR "sc.exe")
AND process.command_line: (*AntiVirus* OR *falcon* OR *SentinelOne*
  OR *crowdstrike* OR *Sophos* OR *splunk* OR *ossec* OR *wazuh*)

// SecurityCenter WMI query
process.command_line: *SecurityCenter2*`,
        powershell: `# Security software discovery detection
Write-Host "[*] === Security product queries ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match 'AntiVirus|MsMpEng|falcon|SentinelOne|Sophos|crowdstrike|SecurityCenter|Get-MpComputerStatus' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}`,
        registry: "Security software registered at:\n  HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av\n  WMI: root\\SecurityCenter2\\AntiVirusProduct",
        tools: "Sysmon (EID 1)\nPowerShell ScriptBlock logging\nAuditd (Linux)",
        ossdetect: "Sigma:\n- win_proc_creation_security_software_discovery.yml\nElastic:\n- Security Software Discovery",
        notes: "Security discovery followed by Set-MpPreference exclusions or service stops is an active attack chain, not just reconnaissance. The attacker's next action depends on what they find: Defender only means AMSI bypass; CrowdStrike means driver-level evasion needed; no EDR means unrestricted operations.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Security tool enumeration before evasion approach selection." },
          { cls: "apt-ru", name: "APT29", note: "EDR and SIEM discovery as precursor to defense evasion." }
        ],
        malware: [
          { cls: "apt-mul", name: "Cobalt Strike", note: "Seatbelt and situational awareness enumerate security products." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Security product ID drives the EDR-killer or Defender-disabling step." }
        ],
        cite: "MITRE ATT&CK T1518.001"
      }
    ]
  },
  {
    id: "T1057",
    name: "Process Discovery",
    desc: "Listing running processes to identify security tools, injection targets, and active user sessions. tasklist and ps aux reveal the host's operational state.",
    rows: [
      {
        sub: "T1057 - Process Listing (tasklist, Get-Process, ps aux, wmic process)",
        os: "win",
        indicator: "Execution of tasklist, Get-Process, wmic process list, or ps aux to enumerate running processes for security tool identification, injection target selection, and token theft opportunities",
        sysmon: `// Sysmon EID 1 - process enumeration
Image=(*\\\\tasklist.exe)
Image=*\\\\wmic.exe AND CommandLine=*process*list*
CommandLine=(*Get-Process* OR *Get-WmiObject*Win32_Process*)

// Linux: Image=(*/ps) AND CommandLine=(*aux* OR *-ef*)
// Output redirect (saving results): CommandLine=(*tasklist*>* OR *ps*>*)`,
        kibana: `// Process listing
process.name: "tasklist.exe"
OR (process.name: "wmic.exe" AND process.command_line: *process*)
OR process.command_line: *Get-Process*

// Linux
process.name: "ps"
AND process.args: ("aux" OR "-ef")`,
        powershell: `# Process discovery detection
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[4].Value -match 'tasklist' -or
    $_.Properties[10].Value -match 'Get-Process|Win32_Process' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,150)}}`,
        registry: "No registry artifact.",
        tools: "Sysmon (EID 1)\nAuditd (Linux)",
        ossdetect: "Sigma:\n- win_proc_creation_tasklist.yml\nElastic:\n- Process Discovery via Tasklist",
        notes: "Low-confidence individually but high-value as a sequence component. An attacker uses tasklist to find: security tools to evade, browsers with saved creds, processes running as other users for token theft, and suitable injection targets. The piped-to-file variant (tasklist > procs.txt) indicates staging for exfil, which is higher-confidence.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Process enumeration for injection targeting and security assessment." },
          { cls: "apt-ru", name: "APT29", note: "Process discovery in structured post-compromise reconnaissance." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "All Operators", note: "tasklist/ps is universal in post-foothold discovery." }
        ],
        cite: "MITRE ATT&CK T1057"
      }
    ]
  },
  {
    id: "T1135",
    name: "Network Share Discovery",
    desc: "Enumerating accessible network shares for data staging, lateral movement paths, and sensitive file repositories. net share shows local exports; net view \\\\host shows remote shares; admin shares (C$, ADMIN$) are the lateral movement paths PsExec uses.",
    rows: [
      {
        sub: "T1135 - Network Share Enumeration (net share, net view, smbclient, Get-SmbShare)",
        os: "win",
        indicator: "Execution of net share, net view, Get-SmbShare, or smbclient -L to enumerate local and remote network shares for lateral movement path identification and sensitive data discovery",
        sysmon: `// Sysmon EID 1 - share enumeration
Image=(*\\\\net.exe OR *\\\\net1.exe)
CommandLine=(*share* OR *view*)

// PowerShell: CommandLine=(*Get-SmbShare* OR *Win32_Share*)
// Linux: Image=*/smbclient AND CommandLine=*-L*
// Linux: Image=*/showmount AND CommandLine=*-e*`,
        kibana: `// Share enumeration
process.name: ("net.exe" OR "net1.exe")
AND process.command_line: (*share* OR *view*)

// PowerShell
process.command_line: (*Get-SmbShare* OR *Win32_Share*)`,
        powershell: `# Share discovery detection
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match 'net.*(share|view)|Get-SmbShare' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}`,
        registry: "Shares defined at:\n  HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares\n\nDefault admin shares: C$, ADMIN$, IPC$ (always present on domain-joined Windows).",
        tools: "Sysmon (EID 1 + EID 3 SMB)\nSecurity EID 5140/5145 (share access audit)\nCrackMapExec (--shares)\nBloodHound",
        ossdetect: "Sigma:\n- win_proc_creation_net_share_discovery.yml\nElastic:\n- Network Share Discovery",
        notes: "Share discovery bridges account enumeration and lateral movement. The admin shares (C$, ADMIN$) are the paths PsExec and Impacket use. net view /all shows hidden shares. On Linux, showmount -e and smbclient -L are equivalents.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Share enumeration for lateral movement path identification." },
          { cls: "apt-ru", name: "APT29", note: "Share discovery for data staging and collection." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Share enumeration identifies network drives to encrypt beyond the local host." }
        ],
        cite: "MITRE ATT&CK T1135"
      }
    ]
  },
  {
    id: "T1049",
    name: "System Network Connections Discovery",
    desc: "Listing active connections and listening ports to identify established sessions, connected hosts, and exposed services. Established connections to internal hosts reveal authenticated lateral movement paths.",
    rows: [
      {
        sub: "T1049 - Active Connection Enumeration (netstat, ss, Get-NetTCPConnection, lsof)",
        os: "linux",
        indicator: "Execution of netstat -ano, ss -tunlp, or Get-NetTCPConnection to enumerate active connections, listening ports, and associated PIDs for lateral movement targeting and network mapping",
        sysmon: `// Windows: Image=*\\\\netstat.exe AND CommandLine=(*-ano* OR *-b*)
// PowerShell: CommandLine=*Get-NetTCPConnection*

// Linux - auditd rules
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/ss -k net_discovery
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/netstat -k net_discovery

// Linux: Image=(*/ss OR */netstat) AND CommandLine=(*-tunlp* OR *-ano*)
// Image=*/lsof AND CommandLine=*-i*`,
        kibana: `// Windows
process.name: "netstat.exe"
AND process.args: ("-ano" OR "-b")

// PowerShell
process.command_line: *Get-NetTCPConnection*

// Linux
process.name: ("ss" OR "netstat")
AND process.args: ("-tunlp" OR "-ano")`,
        powershell: `# Connection discovery detection
# Windows:
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[4].Value -match 'netstat' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,150)}}

# Linux: ausearch -k net_discovery -ts recent`,
        registry: "No registry artifact.",
        tools: "Sysmon (EID 1)\nAuditd (Linux)\nosquery: SELECT * FROM listening_ports; SELECT * FROM process_open_sockets;",
        ossdetect: "Sigma:\n- win_proc_creation_netstat.yml\nElastic:\n- Network Connection Discovery",
        notes: "Distinct from T1016 (config discovery). Config tells the attacker what networks are REACHABLE; connection discovery tells them what hosts are actively TALKING to this one. Established connections reveal already-authenticated paths. ss -tunlp is preferred over netstat on Linux for speed and reliable PID mapping.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Connection enumeration for lateral movement target identification." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Living-off-the-land network discovery on compromised infrastructure." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "All Operators", note: "netstat/ss is standard in post-foothold discovery." }
        ],
        cite: "MITRE ATT&CK T1049"
      }
    ]
  },
];
