const DATA = [
  {
    id: "T1021.002",
    name: "Remote Services: SMB/Windows Admin Shares",
    desc: "Lateral movement via SMB admin shares (C$, ADMIN$, IPC$) using tools like PsExec, sc.exe, or Impacket smbexec/wmiexec. The destination host sees a service creation (PsExec pattern), named pipe access, and logon type 3 events. This is the most common lateral movement technique in enterprise intrusions.",
    rows: [
      {
        sub: "T1021.002 - PsExec-style Service Creation on Destination Host",
        os: "win",
        indicator: "A new service created on a remote host with a short random name (PSEXESVC pattern) or a service whose ImagePath points to a binary in ADMIN$ or a writable share path, the definitive destination-side artifact of PsExec and Impacket smbexec lateral movement",
        sysmon: `// Sysmon EID 13 (RegistryValueSet) - service ImagePath creation
TargetObject=*\\Services\\PSEXESVC*
OR TargetObject=*\\Services\\*\\ImagePath*
  AND Details=(*ADMIN$* OR *\\\\127.0.0.1\\* OR *cmd.exe /c*)

// Sysmon EID 17/18 (PipeCreated/PipeConnected)
PipeName=\\PSEXESVC* OR PipeName=\\RemCom*
  OR PipeName=\\svcctl  // Impacket service control

// Sysmon EID 1 - service binary execution from ADMIN$
Image=*\\ADMIN$\\* OR Image=*\\Windows\\PSEXESVC*

// Security EID 7045 - new service installed
// (System log, not Sysmon, but critical for detection)`,
        kibana: `// PsExec service creation
winlog.event_id: 7045
AND winlog.event_data.ServiceName: (PSEXESVC* OR *RemCom* OR *BTOBTO*)
OR (winlog.event_id: 7045 AND winlog.event_data.ImagePath: (*ADMIN$* OR *cmd* OR *powershell*))

// Named pipe creation (PsExec signature)
winlog.event_id: (17 OR 18)
AND winlog.event_data.PipeName: (*PSEXESVC* OR *RemCom* OR *svcctl*)

// Logon type 3 (network) from non-DC source followed by service creation
winlog.event_id: 4624
AND winlog.event_data.LogonType: "3"
AND winlog.event_data.AuthenticationPackageName: "NTLM"`,
        powershell: `# PsExec artifact detection on destination host
Write-Host "[*] === Recent service installations (EID 7045) ==="
Get-WinEvent -FilterHashtable @{
  LogName='System'; Id=7045
} -MaxEvents 50 -EA SilentlyContinue |
  Select-Object TimeCreated,
    @{n='Service';e={$_.Properties[0].Value}},
    @{n='ImagePath';e={$_.Properties[1].Value}},
    @{n='Account';e={$_.Properties[4].Value}} |
  Format-Table -Auto

Write-Host "[*] === PSEXESVC artifacts ==="
Get-Service -Name PSEXESVC -EA SilentlyContinue
Get-ChildItem C:\\Windows\\PSEXESVC.exe -EA SilentlyContinue

Write-Host "[*] === Named pipes ==="
Get-ChildItem \\\\.\\pipe\\ -EA SilentlyContinue |
  Where-Object { $_.Name -match 'PSEXE|RemCom|svcctl|atsvc' }

Write-Host "[*] === Network logons (type 3) in last hour ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4624
} -MaxEvents 200 -EA SilentlyContinue |
  Where-Object { $_.Properties[8].Value -eq '3' } |
  Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='Source';e={$_.Properties[18].Value}} |
  Where-Object { $_.Source -and $_.Source -ne '-' }`,
        registry: `Service creation artifacts:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<random-name>
  ImagePath pointing to ADMIN$, C$ share, or cmd /c command

PsExec variants to watch for:
- PSEXESVC (original Sysinternals)
- RemComSvc (open-source RemCom)
- Random 8-char names (Impacket smbexec)
- BTOBTO (older Impacket default)`,
        tools: `Sysmon (EID 13 service registry + EID 17/18 named pipes)
System event log (EID 7045 service install)
Security event log (EID 4624 logon type 3)
Impacket detection (smbexec, psexec, wmiexec)`,
        ossdetect: `Sigma:
- win_security_psexec_service.yml
- win_system_new_service_creation.yml
- win_pipe_psexec.yml

Elastic Detection Rules:
- PsExec Network Connection
- Remote Service Installation`,
        notes: "PsExec lateral movement leaves three artifact layers on the destination: (1) service creation in the System event log (EID 7045) and registry, (2) named pipe creation (PSEXESVC or variant), and (3) network logon (EID 4624 type 3). Impacket variants use random service names and cmd.exe /c commands as the ImagePath, making the service-name pattern less reliable than the ImagePath content. The most durable detection is: any EID 7045 where the ImagePath contains ADMIN$, a UNC path, or a cmd/powershell command. Legitimate remote service installations (SCCM, GPO) use MSI packages or known service names, not raw command-line ImagePaths.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "PsExec and SMB lateral movement documented in enterprise intrusions." },
          { cls: "apt-cn", name: "APT41", note: "SMB admin share access for lateral movement across Windows infrastructure." },
          { cls: "apt-kp", name: "Lazarus", note: "PsExec-style service creation during ransomware and destructive operations." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "smbexec/psexec create temporary services with random names and cmd.exe ImagePaths." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "PsExec and jump psexec64 commands for lateral movement." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "PsExec is the most common lateral deployment mechanism for domain-wide ransomware." }
        ],
        cite: "MITRE ATT&CK T1021.002"
      }
    ]
  },
  {
    id: "T1021.001",
    name: "Remote Services: Remote Desktop Protocol",
    desc: "Lateral movement via RDP (TCP 3389). The destination host logs type 10 (RemoteInteractive) logon events. RDP is particularly dangerous because it gives the attacker a full GUI session, enables clipboard and drive redirection for data staging, and blends with legitimate admin traffic.",
    rows: [
      {
        sub: "T1021.001 - RDP Logon from Internal Source (type 10 lateral pivot)",
        os: "win",
        indicator: "Logon type 10 (RemoteInteractive) from an internal source IP that is not an authorized admin workstation or jump server, indicating RDP lateral movement between compromised hosts rather than legitimate administration",
        sysmon: `// Security EID 4624 - logon type 10 (RemoteInteractive)
LogonType=10
SourceNetworkAddress=10.* OR 172.16.* OR 192.168.*
// Filter: NOT from known jump servers or admin workstations

// TerminalServices-RemoteConnectionManager/Operational EID 1149
// (RDP authentication succeeded - fires before 4624)

// Sysmon EID 3 - inbound RDP connection
DestinationPort=3389 AND Initiated=false

// Security EID 4778/4779 - session reconnect/disconnect
// (indicates persistent RDP session reuse)`,
        kibana: `// RDP logon type 10 from internal source
winlog.event_id: 4624
AND winlog.event_data.LogonType: "10"
AND source.ip: (10.* OR 172.16.* OR 192.168.*)
AND NOT source.ip: (<jump_server_IPs>)

// RDP connection manager events
winlog.channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
AND winlog.event_id: 1149

// Session reconnect (persistent lateral access)
winlog.event_id: (4778 OR 4779)`,
        powershell: `# RDP lateral movement detection
Write-Host "[*] === RDP logons (type 10) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4624
} -MaxEvents 500 -EA SilentlyContinue |
  Where-Object { $_.Properties[8].Value -eq '10' } |
  Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='Source';e={$_.Properties[18].Value}},
    @{n='LogonID';e={$_.Properties[7].Value}} |
  Format-Table -Auto

Write-Host "[*] === RDP connection history ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149
} -MaxEvents 20 -EA SilentlyContinue |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[0].Value}},
    @{n='Source';e={$_.Properties[2].Value}}

Write-Host "[*] === NLA status ==="
Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -EA SilentlyContinue`,
        registry: `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server
  fDenyTSConnections = 0  (RDP enabled)
  
HKLM\\...\\Terminal Server\\WinStations\\RDP-Tcp
  UserAuthentication = 1  (NLA required - hardening)
  PortNumber = 3389 (or modified port)

HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers
  Lists RDP destinations this user has connected TO
  (source-side artifact for tracking lateral pivots)`,
        tools: `Security event log (EID 4624 type 10, 4778/4779)
TerminalServices logs (EID 1149)
Sysmon (EID 3 inbound 3389)
Network segmentation (restrict RDP to jump servers)`,
        ossdetect: `Sigma:
- win_security_rdp_logon_from_internal.yml
- win_rdp_hijack_shadowing.yml

Elastic Detection Rules:
- RDP Logon from Internal Source
- Unusual RDP Session Duration`,
        notes: "RDP lateral movement blends with legitimate administration, making behavioral context essential: which source IPs are authorized for RDP, which accounts normally use RDP, and does the timing match administrative patterns. The most reliable detection is a whitelist approach: maintain a list of authorized RDP source IPs (jump servers, admin workstations) and alert on any type 10 logon from a source not on the list. RDP session reconnects (EID 4778) indicate an attacker maintaining a persistent session across multiple work periods. On the source host, HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers records every RDP destination, providing a lateral movement map.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "RDP lateral movement documented in enterprise intrusions." },
          { cls: "apt-ru", name: "APT29", note: "RDP pivoting between compromised hosts during long-dwell operations." },
          { cls: "apt-kp", name: "Lazarus", note: "RDP used for interactive lateral movement in destructive campaigns." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "RDP is both the initial access vector and lateral movement mechanism in many ransomware operations." },
          { cls: "apt-mul", name: "Hands-on intruders", note: "RDP provides full GUI for interactive file staging and tool deployment." }
        ],
        cite: "MITRE ATT&CK T1021.001"
      }
    ]
  },
  {
    id: "T1021.004",
    name: "Remote Services: SSH",
    desc: "Lateral movement between Linux hosts (or to/from Windows with OpenSSH) via SSH using stolen credentials or harvested private keys. SSH lateral movement is difficult to distinguish from legitimate administration because it uses the same protocol and generates the same authentication events.",
    rows: [
      {
        sub: "T1021.004 - SSH Lateral Movement (stolen keys, credential reuse, tunneling)",
        os: "linux",
        indicator: "SSH authentication from a host that was recently compromised (temporal correlation with other alerts), using credentials not associated with the authenticating user's normal access pattern, or SSH sessions originating from a web server or application host that should not be initiating outbound SSH",
        sysmon: `// Source host - outbound SSH connections from unexpected processes
// Auditd execve monitoring:
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/ssh -k ssh_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/scp -k ssh_exec

// Sysmon for Linux EID 1
Image=*/ssh AND CommandLine NOT IN (known automation patterns)

// Destination host - auth.log / secure log
// Accepted publickey for <user> from <source_ip>
// Look for source IPs that are internal servers, not admin workstations

// SSH tunnel indicators (-L, -R, -D, -J flags)
CommandLine=*ssh* AND (*-L * OR *-R * OR *-D * OR *-N -f*)`,
        kibana: `// SSH authentication from internal non-admin hosts
system.auth.ssh.event: "Accepted"
AND source.ip: (10.* OR 172.16.* OR 192.168.*)
AND NOT source.ip: (<admin_workstation_IPs>)

// SSH command execution from unexpected parent processes
process.name: "ssh"
AND process.parent.name: ("apache2" OR "nginx" OR "httpd"
  OR "java" OR "python" OR "node" OR "php-fpm")

// SSH tunneling (port forwarding)
process.name: "ssh"
AND process.args: ("-L" OR "-R" OR "-D" OR "-N")`,
        powershell: `# SSH lateral movement detection
echo "[*] === Recent SSH authentications ==="
grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -20
grep 'Accepted' /var/log/secure 2>/dev/null | tail -20

echo ""
echo "[*] === Active SSH sessions ==="
ss -tnp | grep ':22'
who -a

echo ""
echo "[*] === SSH processes with unusual parents ==="
ps auxf | grep '[s]sh ' | grep -v 'grep'

echo ""
echo "[*] === Auditd SSH execution records ==="
ausearch -k ssh_exec -ts recent 2>/dev/null | head -20

echo ""
echo "[*] === SSH tunnels (port forwarding) ==="
ps aux | grep '[s]sh.*-[LRD]'`,
        registry: `No registry artifact (Linux technique).

SSH lateral artifacts:
Source host:
  ~/.ssh/known_hosts (new entries = new targets)
  ~/.bash_history (ssh commands if not cleared)
  /var/log/auth.log (outbound SSH from this host)

Destination host:
  /var/log/auth.log or /var/log/secure
  /var/log/wtmp (login records)
  ~/.ssh/authorized_keys (injected keys)`,
        tools: `Auditd (SSH execve monitoring)
auth.log / journalctl -u sshd
osquery: logged_in_users, process_events
Falco: unexpected SSH from server processes`,
        ossdetect: `Sigma:
- lnx_auditd_ssh_lateral_movement.yml

Falco:
- SSH connection from unexpected process
- Launch SSH from non-standard parent

osquery:
- logged_in_users cross-referenced with process_events`,
        notes: "SSH lateral movement is the Linux equivalent of RDP/PsExec on Windows. Detection relies on behavioral context rather than protocol signatures: which hosts normally SSH to which other hosts, which accounts are authorized for interactive SSH, and which processes should be spawning SSH clients. A web server (apache, nginx) spawning ssh is near-certain lateral movement. SSH tunneling (-L local, -R remote, -D SOCKS) enables network pivoting through a compromised host, effectively turning it into a proxy. The -N flag (no command) combined with -f (background) is the signature of a persistent tunnel with no interactive session.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH lateral movement across Linux infrastructure in tech sector operations." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "SSH pivoting between compromised infrastructure hosts during pre-positioning." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH with stolen keys for lateral movement in server-targeting campaigns." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "TeamTNT", note: "SSH key harvesting and automated lateral propagation across cloud hosts." },
          { cls: "apt-mul", name: "Hands-on intruders", note: "SSH is the universal lateral movement mechanism on Linux." }
        ],
        cite: "MITRE ATT&CK T1021.004"
      }
    ]
  },
  {
    id: "T1021.006",
    name: "Remote Services: Windows Remote Management (WinRM)",
    desc: "Lateral movement via WinRM (PowerShell Remoting, ports 5985/5986). WinRM enables remote PowerShell execution and is increasingly used by both administrators and attackers. Unlike PsExec, WinRM does not create a service and leaves fewer filesystem artifacts, making it stealthier.",
    rows: [
      {
        sub: "T1021.006 - WinRM Remote PowerShell Session (Enter-PSSession, Invoke-Command)",
        os: "win",
        indicator: "Inbound WinRM connections resulting in a PowerShell remoting session (wsmprovhost.exe spawned by svchost.exe) on the destination host, particularly from source IPs that are not management servers or authorized admin workstations",
        sysmon: `// Sysmon EID 1 - wsmprovhost.exe spawn (WinRM session host)
Image=*\\wsmprovhost.exe
ParentImage=*\\svchost.exe
// wsmprovhost.exe is the WinRM session process; its children
// are whatever commands the remote user executes.

// Sysmon EID 3 - inbound WinRM connection
DestinationPort=(5985 OR 5986)
Initiated=false

// Security EID 4624 - logon type 3 with WinRM
LogonType=3
LogonProcessName=NtLmSsp OR AuthenticationPackageName=Negotiate
// Cross-reference with WinRM event 91 on destination`,
        kibana: `// WinRM session process creation
process.name: "wsmprovhost.exe"
AND process.parent.name: "svchost.exe"

// Inbound WinRM connections
destination.port: (5985 OR 5986)
AND event.category: "network"

// WinRM operational log
winlog.channel: "Microsoft-Windows-WinRM/Operational"
AND winlog.event_id: (91 OR 168)`,
        powershell: `# WinRM lateral detection
Write-Host "[*] === Active WinRM sessions ==="
Get-WSManInstance -ComputerName localhost -ResourceURI winrm/config -Enumerate -EA SilentlyContinue

Write-Host "[*] === wsmprovhost processes (active remote sessions) ==="
Get-Process wsmprovhost -EA SilentlyContinue |
  Select-Object Id, StartTime, @{n='Children';e={
    (Get-CimInstance Win32_Process -Filter "ParentProcessId=$($_.Id)" -EA SilentlyContinue).Name -join ', '
  }}

Write-Host "[*] === WinRM operational events ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-WinRM/Operational'; Id=91,168
} -MaxEvents 20 -EA SilentlyContinue |
  Select-Object TimeCreated, Id, Message | Format-Table -Auto`,
        registry: `WinRM configuration:
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN

WinRM enabled check:
  winrm get winrm/config  (or Test-WSMan)

Hardening:
  Restrict WinRM to specific source IPs via GPO
  Disable WinRM on hosts that don't need remote management
  Use JEA (Just Enough Administration) to constrain sessions`,
        tools: `Sysmon (EID 1 wsmprovhost + EID 3 port 5985/5986)
WinRM Operational log (EID 91, 168)
Security log (EID 4624 type 3)
PowerShell ScriptBlock logging (EID 4104 - captures remote commands)`,
        ossdetect: `Sigma:
- win_proc_creation_winrm_session.yml
- win_security_winrm_lateral.yml

Elastic Detection Rules:
- WinRM Remote Shell Session
- Incoming WinRM Execution`,
        notes: "WinRM is stealthier than PsExec because it does not create a service, does not write a binary to ADMIN$, and uses a legitimate management protocol. The primary artifact on the destination is the wsmprovhost.exe process, which hosts the remote PowerShell session. Commands executed through the session appear as children of wsmprovhost.exe, making process-tree analysis the key detection technique. PowerShell ScriptBlock logging (EID 4104) on the destination captures the actual commands the attacker runs through the remote session, even if they use Invoke-Command with encoded arguments.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "WinRM for stealthy lateral movement in enterprise intrusions." },
          { cls: "apt-cn", name: "APT41", note: "PowerShell Remoting for lateral execution across Windows infrastructure." }
        ],
        malware: [
          { cls: "apt-mul", name: "Cobalt Strike", note: "jump winrm and remote-exec winrm commands for WinRM lateral movement." }
        ],
        activity: [
          { cls: "apt-mul", name: "Advanced Operators", note: "WinRM preferred over PsExec by stealthy operators to avoid service creation artifacts." }
        ],
        cite: "MITRE ATT&CK T1021.006"
      }
    ]
  },
  {
    id: "T1550.002",
    name: "Use Alternate Authentication Material: Pass the Hash",
    desc: "Authentication using stolen NTLM hashes without knowing the plaintext password. Pass-the-hash enables lateral movement using credentials dumped from LSASS or SAM without cracking them first. The destination host sees a network logon (type 3) with NTLM authentication, which is indistinguishable from legitimate NTLM auth without additional context.",
    rows: [
      {
        sub: "T1550.002 - Pass the Hash Logon Anomaly (NTLM type 3 with abnormal context)",
        os: "win",
        indicator: "Network logon (type 3) using NTLM authentication where the source workstation name does not match the authenticated account's normal workstation, or where the account is performing type 3 logons from hosts it has never authenticated from before, indicating credential material reuse from a compromised host",
        sysmon: `// Security EID 4624 - type 3 NTLM logon (PtH signature)
LogonType=3
AuthenticationPackageName=NTLM
// Key fields for anomaly detection:
//   WorkstationName: should match the source hostname
//   SourceNetworkAddress: the actual source IP
//   TargetUserName: the account being used
// PtH anomaly: WorkstationName is the ATTACKER's hostname,
// not the machine where the credentials belong.

// Security EID 4776 - NTLM authentication on DC
// Package field = MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
// Workstation field reveals the authenticating host

// Sysmon EID 1 - PtH tool execution (source host)
CommandLine=(*sekurlsa::pth* OR *pth-* OR *-hashes *
  OR *pass-the-hash* OR *overpass*)`,
        kibana: `// NTLM type 3 logons (PtH candidates)
winlog.event_id: 4624
AND winlog.event_data.LogonType: "3"
AND winlog.event_data.AuthenticationPackageName: "NTLM"
AND NOT winlog.event_data.TargetUserName: (*$ OR ANONYMOUS*)

// DC-side NTLM validation
winlog.event_id: 4776
AND winlog.event_data.PackageName: "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"

// PtH tool signatures
process.command_line: (*sekurlsa::pth* OR *-hashes * OR *overpass*)`,
        powershell: `# Pass-the-Hash detection
Write-Host "[*] === NTLM type 3 logons (recent) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4624
} -MaxEvents 500 -EA SilentlyContinue |
  Where-Object {
    $_.Properties[8].Value -eq '3' -and
    $_.Properties[14].Value -eq 'NTLM'
  } |
  Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='Source';e={$_.Properties[18].Value}},
    @{n='Workstation';e={$_.Properties[11].Value}} |
  Where-Object { $_.User -notmatch '\\$$|ANONYMOUS' } |
  Format-Table -Auto

Write-Host "[*] === NTLM audit configuration ==="
Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name RestrictReceivingNTLMTraffic -EA SilentlyContinue`,
        registry: `Hardening:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa
  LmCompatibilityLevel = 5  (NTLMv2 only, refuse LM/NTLM)

HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0
  RestrictReceivingNTLMTraffic = 2  (deny all NTLM)
  RestrictSendingNTLMTraffic = 2  (deny all NTLM)
  AuditReceivingNTLMTraffic = 2  (audit all NTLM before blocking)

Note: Blocking NTLM entirely breaks many legacy applications.
Audit mode first, then selective blocking.`,
        tools: `Security event log (EID 4624, 4776)
NTLM auditing (EID 8001-8004 in NTLM operational log)
Credential Guard (prevents hash extraction from LSASS)
Windows Defender Remote Credential Guard`,
        ossdetect: `Sigma:
- win_security_pass_the_hash.yml
- win_security_ntlm_logon_anomaly.yml

Elastic Detection Rules:
- Potential Pass the Hash Activity

Microsoft Defender for Identity:
- Pass-the-Hash alert (behavioral baseline)`,
        notes: "Pass-the-hash is extremely difficult to detect with a single event because NTLM type 3 logons are normal network authentication. Detection requires behavioral context: baseline which accounts authenticate from which workstations, then alert on deviations. The WorkstationName field in EID 4624 is self-reported by the source and can be spoofed, but most PtH tools report the attacker's actual hostname, creating a mismatch between the account's normal workstation and the PtH source. The strategic mitigation is Credential Guard (prevents hash extraction) combined with progressive NTLM reduction (audit, then restrict, then block). Protected Users group members cannot authenticate via NTLM at all.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Pass-the-hash for lateral movement in GRU operations." },
          { cls: "apt-ru", name: "APT29", note: "NTLM credential reuse for lateral movement across enterprise networks." },
          { cls: "apt-cn", name: "APT41", note: "Pass-the-hash documented in technology sector intrusions." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "NTLM hash authentication built into all Impacket lateral movement tools." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "pth command for pass-the-hash lateral movement." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Pass-the-hash with dumped local admin hashes for fleet-wide lateral movement." }
        ],
        cite: "MITRE ATT&CK T1550.002"
      }
    ]
  },
,
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    desc: "Remote code execution via WMI (wmic process call create, Invoke-WmiMethod, Impacket wmiexec). WMI lateral movement is stealthier than PsExec because it does not create a service, does not write to ADMIN$, and uses a protocol (DCOM/RPC) that blends with legitimate management traffic. The trade-off is that WMI provides no interactive session, only blind command execution, making it the preferred vector for automated lateral deployment.",
    rows: [
      {
        sub: "T1047 - WMI Remote Process Creation (wmic, Invoke-WmiMethod, wmiexec)",
        os: "win",
        indicator: "Remote process creation via WMI where the parent process is WmiPrvSE.exe (the WMI Provider Host), indicating a process was spawned by a remote WMI call rather than local execution, the destination-side artifact that catches all WMI lateral movement tools",
        sysmon: `// Sysmon EID 1 - process created by WmiPrvSE.exe (destination host)
// This is THE detection: any child of WmiPrvSE is a WMI-spawned process.
ParentImage=*\\WmiPrvSE.exe
Image=(*\\cmd.exe OR *\\powershell.exe OR *\\mshta.exe
  OR *\\rundll32.exe OR *\\regsvr32.exe)
// WmiPrvSE legitimately spawns scrcons.exe (WMI script consumer)
// and some SCCM/monitoring tools. Filter by your environment.

// Source host - wmic process call create
Image=*\\wmic.exe
CommandLine=*process*call*create*

// Source host - PowerShell WMI remote execution
// Invoke-WmiMethod, Invoke-CimMethod with -ComputerName
CommandLine=(*Invoke-WmiMethod* OR *Invoke-CimMethod*)
AND CommandLine=*-ComputerName*

// Sysmon EID 3 - DCOM/RPC connections (WMI transport)
DestinationPort=135
Image NOT IN (*\\svchost.exe, *\\WmiPrvSE.exe, *\\mmc.exe)`,
        kibana: `// WmiPrvSE child processes (destination host - the key detection)
process.parent.name: "WmiPrvSE.exe"
AND process.name: ("cmd.exe" OR "powershell.exe" OR "mshta.exe"
  OR "rundll32.exe" OR "regsvr32.exe" OR "certutil.exe")

// wmic remote execution (source host)
process.name: "wmic.exe"
AND process.command_line: (*process* AND *call* AND *create*)

// PowerShell WMI/CIM remote (source host)
winlog.event_id: 4104
AND script_block_text: (*Invoke-WmiMethod* OR *Invoke-CimMethod*)
AND script_block_text: *ComputerName*

// WMI Operational log - remote connection received (destination)
winlog.channel: "Microsoft-Windows-WMI-Activity/Operational"
AND winlog.event_id: (5857 OR 5860 OR 5861)`,
        powershell: `# WMI lateral movement detection
Write-Host "[*] === WmiPrvSE child processes (remote WMI execution) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 10000 -EA SilentlyContinue |
  Where-Object { $_.Properties[20].Value -like '*WmiPrvSE*' } |
  Select-Object TimeCreated,
    @{n='Child';e={$_.Properties[4].Value}},
    @{n='CmdLine';e={$_.Properties[10].Value.Substring(0,[Math]::Min(200,$_.Properties[10].Value.Length))}} |
  Where-Object { $_.Child -notmatch 'scrcons|WmiPrvSE|mofcomp' }

Write-Host "[*] === wmic process call create commands ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match 'wmic.*process.*call.*create' } |
  Select-Object TimeCreated,
    @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}

Write-Host "[*] === WMI Operational events (remote connections) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857,5860,5861
} -MaxEvents 20 -EA SilentlyContinue |
  Select-Object TimeCreated, Id, Message | Format-Table -Auto`,
        registry: `WMI event subscription persistence (related but separate technique T1546.003):
HKLM\SOFTWARE\Microsoft\WBEM\ESS\*
  Permanent event subscriptions that survive reboot.

WMI process creation leaves no direct registry artifact.
Detection relies on:
1. Process tree: WmiPrvSE.exe parent (Sysmon EID 1)
2. Network: DCOM/RPC connection on port 135 (Sysmon EID 3)
3. WMI Operational log (EID 5857, 5860, 5861)

wmic.exe deprecation note:
  Microsoft deprecated wmic.exe in Windows 11 but it remains
  present on Server editions and older Windows versions.
  PowerShell CIM cmdlets are the modern replacement both
  for administration and for attacker tooling.`,
        tools: `Sysmon (EID 1 parent-child is the primary detection)
WMI-Activity Operational log (EID 5857/5860/5861)
Security EID 4688 (process creation with parent tracking)
Impacket wmiexec (the most common offensive tool)
CrackMapExec (--wmi-exec flag)`,
        ossdetect: `Sigma:
- win_proc_creation_wmiprvse_child.yml
- win_proc_creation_wmic_remote_exec.yml
- win_wmi_activity_remote_connection.yml

Elastic Detection Rules:
- Suspicious WMI Execution
- WMI Remote Process Creation

Microsoft Defender for Endpoint:
- Suspicious WMI activity alert`,
        notes: "WMI lateral movement detection hinges on one artifact: the parent-child relationship. Any process whose parent is WmiPrvSE.exe was spawned by a WMI call, and if the WMI call originated remotely, that process is lateral movement. The false positive surface is manageable: legitimate remote WMI calls come from SCCM, monitoring tools (PRTG, SolarWinds), and admin scripts. Baseline your environment's legitimate WmiPrvSE children and alert on anything outside that set. Impacket's wmiexec is particularly stealthy because it uses a semi-interactive shell over WMI output objects, never writing to disk on the target. The only artifact is the WmiPrvSE -> cmd.exe parent-child edge.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "WMI remote execution for stealthy lateral movement in enterprise intrusions." },
          { cls: "apt-cn", name: "APT41", note: "WMI process creation documented in technology sector lateral movement." },
          { cls: "apt-kp", name: "Lazarus", note: "WMI-based lateral execution in financially motivated campaigns." },
          { cls: "apt-ru", name: "APT28", note: "wmic process call create for lateral command execution." }
        ],
        malware: [
          { cls: "apt-mul", name: "Impacket", note: "wmiexec.py provides semi-interactive shell over WMI, the most common offensive WMI tool." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "jump wmi and remote-exec wmi for WMI-based lateral movement." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "WMI used alongside PsExec for parallel lateral deployment across domain hosts." }
        ],
        cite: "MITRE ATT&CK T1047"
      }
    ]
  },
  {
    id: "T1570",
    name: "Lateral Tool Transfer",
    desc: "Copying attacker tools, payloads, and scripts between compromised hosts via SMB shares, admin shares (C$, ADMIN$), RDP clipboard/drive redirection, SCP/SFTP, or certutil/bitsadmin downloads from internal staging servers. This is the logistics step between gaining access to a new host and executing on it.",
    rows: [
      {
        sub: "T1570 - Internal File Transfer via SMB Shares, certutil, and bitsadmin",
        os: "win",
        indicator: "File transfers between internal hosts using admin shares (C$, ADMIN$), certutil -urlcache, bitsadmin /transfer, or PowerShell copy operations targeting internal IPs, indicating tool staging for lateral movement execution",
        sysmon: `// Sysmon EID 11 (FileCreate) - files written to admin shares
TargetFilename=*\\ADMIN$\\* OR TargetFilename=*\\C$\\*

// Sysmon EID 1 - certutil downloading from internal source
Image=*\\certutil.exe
CommandLine=*-urlcache* AND CommandLine=(*10.* OR *172.16.* OR *192.168.*)

// Sysmon EID 1 - bitsadmin internal transfer
Image=*\\bitsadmin.exe
CommandLine=*/transfer* AND CommandLine=(*10.* OR *172.16.* OR *192.168.*)

// Sysmon EID 1 - PowerShell copy to remote host
Image=*\\powershell.exe
CommandLine=(*Copy-Item* AND *-Path* AND *\\\\*)

// Sysmon EID 3 - SMB connections to internal hosts (port 445)
DestinationPort=445
DestinationIp=(10.* OR 172.16.* OR 192.168.*)
Image NOT IN (*\\System, *\\svchost.exe)`,
        kibana: `// File writes to admin shares
file.path: (*ADMIN$* OR *C$*)
AND event.action: "created"

// certutil internal download
process.name: "certutil.exe"
AND process.command_line: *urlcache*
AND process.command_line: (10.* OR 172.16.* OR 192.168.*)

// bitsadmin internal transfer
process.name: "bitsadmin.exe"
AND process.command_line: */transfer*

// PowerShell remote copy
process.command_line: (*Copy-Item* AND *\\\\*)

// Internal SMB file operations (high volume, use for correlation)
destination.port: 445
AND destination.ip: (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)`,
        powershell: `# Lateral tool transfer detection
Write-Host "[*] === Files written to admin shares (Sysmon EID 11) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=11
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[5].Value -match 'ADMIN\$|C\$' } |
  Select-Object TimeCreated,
    @{n='File';e={$_.Properties[5].Value}},
    @{n='Process';e={$_.Properties[4].Value}}

Write-Host "[*] === certutil/bitsadmin with internal URLs ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match '(certutil.*urlcache|bitsadmin.*/transfer).*(10\.|172\.16|192\.168)' } |
  Select-Object TimeCreated, @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}

Write-Host "[*] === New executables in Windows\Temp ==="
Get-ChildItem C:\Windows\Temp\*.exe -EA SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-24) }`,
        registry: `No direct registry artifact from the file transfer itself.

Common staging locations to monitor:
  C:\Windows\Temp\
  C:\ProgramData\
  C:\Users\Public\
  ADMIN$ (maps to C:\Windows)
  C$ (maps to C:\)

BITS transfer jobs persist across reboots:
  bitsadmin /list /allusers  (enumerate active transfers)
  PowerShell: Get-BitsTransfer -AllUsers`,
        tools: `Sysmon (EID 11 file creation + EID 1 tool commands + EID 3 SMB)
BITS event log (Microsoft-Windows-Bits-Client/Operational)
Security EID 5145 (network share access audit)
EDR file write telemetry`,
        ossdetect: `Sigma:
- win_proc_creation_certutil_download.yml
- win_proc_creation_bitsadmin_download.yml
- win_file_creation_admin_share.yml

Elastic Detection Rules:
- Certutil URL Download
- Bitsadmin File Transfer
- File Written to Admin Share`,
        notes: "Lateral tool transfer is the logistics step that connects initial access to execution on a new host. The most common pattern is PsExec-style: copy the payload to ADMIN$ or C$, then execute it remotely via service creation or WMI. Detection at the file-write stage catches the attack before execution, giving defenders a window to intervene. Admin share writes (ADMIN$, C$) from non-standard processes should be baselined and alerted. certutil and bitsadmin downloading from internal IPs (not external) are strong indicators of internal staging because these tools are rarely used for legitimate internal file transfers when robocopy and Copy-Item exist.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Internal tool staging via SMB shares and admin shares for lateral deployment." },
          { cls: "apt-ru", name: "APT29", note: "Tool transfer through admin shares documented in enterprise lateral movement." },
          { cls: "apt-kp", name: "Lazarus", note: "Payload staging on internal shares before execution across target hosts." }
        ],
        malware: [
          { cls: "apt-mul", name: "Cobalt Strike", note: "upload and lateral movement commands write to admin shares before execution." },
          { cls: "apt-mul", name: "Impacket", note: "psexec and smbexec copy service binaries to ADMIN$ before creating the service." }
        ],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Mass file copy of encryption binary to C$ or ADMIN$ on all domain hosts before simultaneous execution." }
        ],
        cite: "MITRE ATT&CK T1570"
      }
    ]
  },

];