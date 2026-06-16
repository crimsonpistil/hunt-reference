const DATA = [
  {
    id: "T1490",
    name: "Inhibit System Recovery",
    desc: "Deletion of volume shadow copies, disabling of Windows Recovery Environment, and removal of backup catalogs to prevent defenders from restoring systems after encryption or destruction. This is the near-universal first action in the ransomware kill chain, often executed minutes before encryption begins.",
    rows: [
      {
        sub: "T1490 - Shadow Copy Deletion and Recovery Disabling (vssadmin, bcdedit, wbadmin, wmic)",
        os: "win",
        indicator: "Execution of vssadmin delete shadows, bcdedit /set recoveryenabled no, wbadmin delete catalog, or wmic shadowcopy delete, the pre-encryption commands that eliminate the primary recovery path for ransomware victims",
        sysmon: `// Sysmon EID 1 - recovery inhibition commands
Image=*\\vssadmin.exe AND CommandLine=*delete*shadows*
Image=*\\bcdedit.exe AND CommandLine=(*recoveryenabled* OR *safeboot* OR *bootstatuspolicy*)
Image=*\\wbadmin.exe AND CommandLine=*delete*catalog*
Image=*\\wmic.exe AND CommandLine=*shadowcopy*delete*

// PowerShell variant
Image=*\\powershell.exe AND CommandLine=*Win32_ShadowCopy*Delete*

// Volume Shadow Copy Service stopped
// System EID 7036: VSS service entered stopped state`,
        kibana: `// Shadow copy deletion (any method)
(process.name: "vssadmin.exe" AND process.command_line: *delete*shadow*)
OR (process.name: "bcdedit.exe" AND process.command_line: (*recoveryenabled* OR *safeboot*))
OR (process.name: "wbadmin.exe" AND process.command_line: *delete*catalog*)
OR (process.name: "wmic.exe" AND process.command_line: *shadowcopy*delete*)

// PowerShell WMI variant
winlog.event_id: 4104
AND script_block_text: (*Win32_ShadowCopy* AND *Delete*)

// VSS service manipulation
winlog.event_id: 7036
AND winlog.event_data.param1: "Volume Shadow Copy"
AND winlog.event_data.param2: "stopped"`,
        powershell: `# Recovery inhibition detection
Write-Host "[*] === Current shadow copies ==="
vssadmin list shadows 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "  No shadows found (may have been deleted)" }

Write-Host "[*] === Recovery environment status ==="
bcdedit /enum | Select-String 'recoveryenabled|safeboot'

Write-Host "[*] === VSS service status ==="
Get-Service VSS | Select-Object Status, StartType

Write-Host "[*] === Recent recovery-related commands ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match 'vssadmin.*delete|bcdedit.*recovery|wbadmin.*delete|shadowcopy.*delete' } |
  Select-Object TimeCreated,
    @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}`,
        registry: `BCD store modifications:
  bcdedit /set {default} recoveryenabled No
  bcdedit /set {default} bootstatuspolicy ignoreallfailures
  bcdedit /set {default} safeboot minimal (force safe mode)

VSS service:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS
  Start value changed from 3 (Manual) to 4 (Disabled)

Windows Backup:
  wbadmin delete catalog -quiet removes all backup metadata`,
        tools: `Sysmon (EID 1 command line detection)
System event log (EID 7036 service state changes)
Canary files / tripwire directories
Pre-staged offline backups (the actual recovery path)`,
        ossdetect: `Sigma:
- win_proc_creation_delete_shadow_copies.yml
- win_proc_creation_bcdedit_disable_recovery.yml
- win_proc_creation_wbadmin_delete_catalog.yml

Elastic Detection Rules:
- Volume Shadow Copy Deletion
- Recovery Environment Modification

Microsoft Defender for Endpoint:
- Ransomware behavior blocking (shadow copy deletion trigger)`,
        notes: "Shadow copy deletion is the single highest-confidence pre-ransomware indicator. In a non-ransomware context, vssadmin delete shadows is almost never run legitimately (backup software manages VSS through APIs, not CLI). A detection rule on this command with an immediate automated response (isolate host, preserve evidence) can stop ransomware deployment in the minutes between recovery inhibition and encryption start. The time gap between shadow deletion and encryption varies by ransomware family: some delete shadows immediately before encrypting (seconds), others prepare the environment hours in advance. Multiple recovery-inhibiting commands in sequence (vssadmin + bcdedit + wbadmin) is near-100% confidence ransomware staging.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Recovery inhibition before destructive and ransomware operations." },
          { cls: "apt-ru", name: "Sandworm", note: "Shadow copy deletion before wiper deployment in Ukraine-targeted operations." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Universal pre-encryption step across all ransomware families." }
        ],
        cite: "MITRE ATT&CK T1490"
      }
    ]
  },
  {
    id: "T1489",
    name: "Service Stop",
    desc: "Stopping critical services (backup agents, AV, databases, Exchange) before encryption or destruction to maximize damage and prevent detection. Service stopping is the second step in the ransomware kill chain after recovery inhibition and before file encryption.",
    rows: [
      {
        sub: "T1489 - Pre-Encryption Service Kill (AV, backup agents, databases, Exchange)",
        os: "win",
        indicator: "Bulk stopping or killing of security, backup, and database services using net stop, sc stop, taskkill, or PowerShell Stop-Service, particularly when multiple critical services are stopped in rapid succession, the behavioral signature of ransomware pre-staging",
        sysmon: `// Sysmon EID 1 - bulk service stop commands
Image=*\\net.exe AND CommandLine=*stop*
Image=*\\net1.exe AND CommandLine=*stop*
Image=*\\sc.exe AND CommandLine=*stop*
Image=*\\taskkill.exe AND CommandLine=(/F /IM)

// High-value services commonly targeted:
// AV: MsMpSvc, Symantec*, McAfee*, Sophos*, CrowdStrike*
// Backup: veeam, BackupExec, ArcServe, ShadowProtect
// DB: MSSQLSERVER, MySQL*, Oracle*, PostgreSQL*
// Mail: MSExchangeIS, MSExchangeTransport

// Sysmon EID 1 - PowerShell service stop
Image=*\\powershell.exe AND CommandLine=*Stop-Service*`,
        kibana: `// Bulk service stops
process.name: ("net.exe" OR "net1.exe" OR "sc.exe")
AND process.command_line: *stop*
AND process.command_line: (*sql* OR *backup* OR *exchange*
  OR *veeam* OR *sophos* OR *symantec* OR *crowdstrike*
  OR *defender* OR *sentinel*)

// taskkill targeting security/backup processes
process.name: "taskkill.exe"
AND process.command_line: (/F AND /IM)

// System EID 7036 - service stopped events (bulk)
winlog.event_id: 7036
AND winlog.event_data.param2: "stopped"`,
        powershell: `# Service stop detection
Write-Host "[*] === Recently stopped critical services ==="
$critical = @('MsMpSvc','WinDefend','Sense','MSSQLSERVER','MySQL',
  'veeam','BackupExecAgentBrowser','ShadowProtectSvc',
  'MSExchangeIS','wuauserv','wscsvc')
foreach ($svc in $critical) {
  $s = Get-Service -Name $svc -EA SilentlyContinue
  if ($s -and $s.Status -ne 'Running') {
    Write-Host "  NOT RUNNING: $svc ($($s.Status))"
  }
}

Write-Host "[*] === net stop / sc stop commands (Sysmon) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[10].Value -match '(net|sc).*stop|taskkill.*/[fF]' } |
  Select-Object TimeCreated,
    @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}} |
  Format-Table -Auto`,
        registry: `Service start type modification (disabling services):
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>
  Start = 4  (Disabled; changed from 2=Auto or 3=Manual)

Some ransomware disables services via registry rather than
stopping them, ensuring they don't restart after reboot.`,
        tools: `Sysmon (EID 1 command detection)
System event log (EID 7036 service stop)
EDR behavioral detection (bulk service manipulation)
Application-specific monitoring (SQL, Exchange health)`,
        ossdetect: `Sigma:
- win_proc_creation_service_stop.yml
- win_proc_creation_taskkill_security.yml

Elastic Detection Rules:
- Suspicious Service Stop
- Security Software Stopped

Microsoft Defender for Endpoint:
- Tampering detection (Defender service manipulation)`,
        notes: "Ransomware operators stop services for two reasons: (1) to unlock files held open by databases and mail servers so they can be encrypted, and (2) to disable security tools that might detect or block the encryption process. The bulk nature is the key detection signal: a single net stop is normal administration, but 5+ service stops targeting different categories (AV + backup + database) within minutes is near-certain ransomware staging. Some ransomware families embed hardcoded service lists (Conti, REvil, BlackMatter each have documented target lists), and the specific combination of services stopped can be used for family attribution.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Service stopping before destructive and ransomware operations." },
          { cls: "apt-ru", name: "Sandworm", note: "Service manipulation before wiper deployment." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Bulk service killing is universal across all ransomware families; the specific service lists are family-attributable." }
        ],
        cite: "MITRE ATT&CK T1489"
      }
    ]
  },
  {
    id: "T1485",
    name: "Data Destruction",
    desc: "Deliberate destruction of data, filesystems, or entire disks to deny availability. Unlike ransomware (which holds data for ransom), destructive wipers permanently destroy data with no recovery path. Wipers are primarily associated with nation-state operations (Sandworm, Lazarus) and are the most damaging host-side impact technique.",
    rows: [
      {
        sub: "T1485 - Wiper and Destructive Overwrite Detection (dd, shred, cipher, format)",
        os: "linux",
        indicator: "Execution of disk-overwriting commands (dd targeting block devices, shred on critical files/partitions, or mkfs/format on mounted filesystems), particularly when targeting system partitions, boot sectors, or when preceded by service stops and recovery inhibition",
        sysmon: `// Auditd rules for destructive commands
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dd -k destructive
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/shred -k destructive
-a always,exit -F arch=b64 -S execve -F exe=/sbin/mkfs -k destructive

// Sysmon for Linux EID 1
Image=*/dd AND CommandLine=*of=/dev/sd* OR *of=/dev/nvme*
Image=*/shred AND CommandLine=*/dev/*
Image=*/mkfs* AND CommandLine=*/dev/sd* OR */dev/nvme*

// rm -rf targeting system directories
Image=*/rm AND CommandLine=*-rf* AND CommandLine=(*/etc* OR */var* OR */boot* OR */home*)`,
        kibana: `// Disk-level destructive commands
process.name: "dd"
AND process.args: ("of=/dev/sd*" OR "of=/dev/nvme*" OR "of=/dev/vd*")

// shred on devices or critical directories
process.name: "shred"
AND process.args: ("/dev/*" OR "/boot/*" OR "/etc/*")

// Filesystem recreation on mounted devices
process.name: ("mkfs" OR "mkfs.ext4" OR "mkfs.xfs")

// Bulk file destruction
process.name: "rm"
AND process.args: "-rf"
AND process.args: ("/etc" OR "/var" OR "/boot" OR "/home" OR "/")`,
        powershell: `# Destructive activity detection
echo "[*] === Auditd destructive command records ==="
ausearch -k destructive -ts recent 2>/dev/null | head -30

echo ""
echo "[*] === dd processes targeting block devices ==="
ps aux | grep '[d]d.*of=/dev'

echo ""
echo "[*] === Boot sector integrity ==="
# Check if MBR/GPT is intact
dd if=/dev/sda bs=512 count=1 2>/dev/null | xxd | head -5

echo ""
echo "[*] === Recently modified system directories ==="
find /etc /boot -mmin -60 -type f 2>/dev/null | head -20`,
        registry: `No registry artifact (Linux technique).

Windows equivalent commands:
- cipher /w:C:\\ (overwrite free space)
- format C: /Q (quick format)
- Clean-Disk (PowerShell Storage module)
- dd on Windows (WSL or ported binary)

Wiper malware families:
- WhisperGate (Ukraine 2022): corrupts MBR then overwrites files
- HermeticWiper (Ukraine 2022): uses EaseUS driver for disk-level wipe
- CaddyWiper (Ukraine 2022): zeros files then destroys partition table
- Destover (Sony Pictures 2014): MBR overwrite + file deletion`,
        tools: `Auditd (execve monitoring for destructive commands)
Falco (dd/shred targeting block devices)
osquery (process_events with command line filtering)
Immutable backups (the actual recovery control)`,
        ossdetect: `Sigma:
- lnx_auditd_dd_block_device.yml
- lnx_auditd_shred_destructive.yml

Falco:
- Destructive command execution
- Write to block device

Wazuh:
- Auditd integration for destructive command alerts`,
        notes: "Wiper attacks are the most severe host-side impact because data is irrecoverably destroyed. Unlike ransomware, there is no negotiation path. Detection must be fast enough to trigger automated isolation before the wipe completes. The most reliable detection is auditd monitoring of dd/shred/mkfs commands targeting block devices (/dev/sd*, /dev/nvme*), which should never happen in normal operations. On Windows, the equivalent is cipher /w or direct disk writes via kernel drivers (as used by HermeticWiper). The only real mitigation is offline/immutable backups that the attacker cannot reach from the compromised network.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "WhisperGate, HermeticWiper, CaddyWiper, and other destructive tools deployed against Ukraine." },
          { cls: "apt-kp", name: "Lazarus", note: "Destructive wipers (Destover, KillDisk) in retaliatory and financially motivated operations." },
          { cls: "apt-ir", name: "APT33", note: "Shamoon/DistTrack wiper operations against Saudi Arabian and Gulf state targets." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Some ransomware operators deploy wipers when negotiations fail or as deliberate destruction." }
        ],
        cite: "MITRE ATT&CK T1485"
      }
    ]
  },
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    desc: "File encryption for extortion (ransomware). Detection focuses on the behavioral indicators of bulk file encryption: high-volume file rename/write operations, known ransomware file extensions, ransom note creation, and the process-level indicators of encryption routines (high CPU, sequential file access across directories).",
    rows: [
      {
        sub: "T1486 - Ransomware Encryption Behavioral Indicators (bulk rename, ransom notes, extension change)",
        os: "win",
        indicator: "A single process performing high-volume sequential file operations (open, read, write, rename) across multiple directories, changing file extensions to a ransomware-associated pattern, and creating ransom note files (README.txt, DECRYPT.html, RECOVER-FILES.txt) in each visited directory",
        sysmon: `// Sysmon EID 11 (FileCreate) - ransom note creation
TargetFilename=(*README*.txt OR *DECRYPT*.html OR *RECOVER*
  OR *HOW_TO_DECRYPT* OR *RESTORE_FILES* OR *ransom*)
// Alert on first occurrence: this is the ransom note drop.

// Sysmon EID 2 (FileCreateTime) - bulk timestamp changes
// High volume of timestamp modifications from a single process
// indicates bulk file encryption (encrypted file gets new mtime).

// Sysmon EID 1 - known ransomware command patterns
CommandLine=(*-encrypt* OR *-ransom* OR *.onion*)

// Canary file detection:
// Place tripwire files (e.g., 000-canary.docx) at the top of
// monitored directories. Sysmon EID 11/23 on these files
// fires BEFORE the bulk of encryption completes.`,
        kibana: `// Ransom note file creation
winlog.event_id: 11
AND file.name: (*README* OR *DECRYPT* OR *RECOVER* OR *RESTORE*
  OR *HOW_TO* OR *ransom*)

// High-volume file operations from single process
// (requires aggregation: count of EID 11 by process per minute)

// Known ransomware extensions
file.extension: ("locked" OR "encrypted" OR "crypted" OR "crypt"
  OR "enc" OR "ransom" OR "ryk" OR "conti" OR "lockbit"
  OR "blackcat" OR "alphv" OR "royal" OR "play")

// Canary file access
file.path: *000-canary*`,
        powershell: `# Ransomware indicator detection
Write-Host "[*] === Ransom note files ==="
Get-ChildItem -Path C:\\ -Recurse -Depth 3 -EA SilentlyContinue |
  Where-Object { $_.Name -match 'README|DECRYPT|RECOVER|RESTORE|HOW_TO|ransom' -and $_.Extension -match '\\.(txt|html|hta)$' } |
  Select-Object FullName, CreationTime | Format-Table -Auto

Write-Host "[*] === Files with ransomware extensions ==="
Get-ChildItem -Path C:\\Users -Recurse -Depth 4 -EA SilentlyContinue |
  Where-Object { $_.Extension -match '\\.(locked|encrypted|crypted|enc|ryk|conti|lockbit)$' } |
  Select-Object FullName -First 10

Write-Host "[*] === High-CPU processes (potential encryption) ==="
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU,
  @{n='Path';e={$_.Path}} | Format-Table -Auto

Write-Host "[*] === Shadow copy status (should still exist) ==="
vssadmin list shadows 2>$null`,
        registry: `Ransomware may modify:
HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
  (persistence for encryption restarter after reboot)

HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
  legalnoticecaption / legalnoticetext (ransom message at logon)

Desktop wallpaper change:
HKCU\\Control Panel\\Desktop\\Wallpaper
  (changed to ransom notice image)`,
        tools: `Sysmon (EID 11 file creation, EID 23 file delete)
Canary/tripwire files (early warning system)
EDR behavioral detection (bulk file encryption patterns)
Windows Controlled Folder Access (ransomware protection)`,
        ossdetect: `Sigma:
- win_file_creation_ransom_note.yml
- win_proc_creation_ransomware_indicators.yml

Elastic Detection Rules:
- Ransomware Note File Creation
- High Volume of File Encryption Indicators

Microsoft Defender for Endpoint:
- Ransomware behavior blocking
- Controlled Folder Access alerts`,
        notes: "Ransomware encryption detection is a race against time: once encryption starts, every second of delay means more files lost. The most effective early warning is canary/tripwire files placed alphabetically first in monitored directories (000-canary.docx). Ransomware typically enumerates directories alphabetically, so the canary is encrypted first, triggering an alert before the bulk of files are affected. The automated response chain should be: canary alert -> immediate host isolation -> preserve evidence -> assess blast radius. Post-encryption forensics focuses on identifying the ransomware family (from the ransom note, extension pattern, and encryption markers in file headers) to determine if a decryptor exists.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Maui and other ransomware deployed in financially motivated operations targeting healthcare and critical infrastructure." },
          { cls: "apt-ru", name: "Sandworm", note: "NotPetya (destructive ransomware disguised as extortion) deployed globally via MeDoc supply chain." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "LockBit, BlackCat/ALPHV, Royal, Play, Cl0p, and dozens of other families with distinct encryption patterns and ransom note templates." }
        ],
        cite: "MITRE ATT&CK T1486"
      }
    ]
  },
,
  {
    id: "T1561.002",
    name: "Disk Wipe: Disk Structure Wipe",
    desc: "Destruction of disk partition tables, Master Boot Records (MBR), or GUID Partition Tables (GPT) to render systems unbootable. Unlike file-level wiping (T1485), disk structure wipes target the boot infrastructure itself, making recovery impossible without reimaging. This is the signature technique of nation-state destructive operations (Sandworm, Lazarus) and separates true wiper attacks from ransomware.",
    rows: [
      {
        sub: "T1561.002 - MBR/GPT Overwrite and Partition Table Destruction",
        os: "win",
        indicator: "Direct write access to the physical disk (PhysicalDrive0) or to the first sectors of a block device, targeting the MBR (sector 0) or GPT headers, which renders the system unbootable and unrecoverable without reimaging from backup",
        sysmon: `// Windows - Sysmon EID 9 (RawAccessRead) to PhysicalDrive
// Direct disk reads are a precursor to disk writes.
// Sysmon does not log raw disk WRITES, only reads.
Device=*PhysicalDrive*

// Sysmon EID 1 - known wiper tool patterns
CommandLine=(*PhysicalDrive* OR *\\.\\PhysicalDrive*)
OR CommandLine=(*dd*of=*\\.\\* OR *format*\\.\\*)

// Sysmon EID 7 - EaseUS driver load (HermeticWiper)
ImageLoaded=*epmntdrv* OR ImageLoaded=*empntdrv*

// Windows - kernel driver loading for disk access
// Wipers like HermeticWiper use signed drivers to get
// kernel-level disk write access.
// Sysmon EID 6 (DriverLoad) - unsigned or unusual drivers
Signed=false

// Linux - Auditd: dd targeting block devices
-a always,exit -F arch=b64 -S open -F path=/dev/sda -F perm=w -k disk_write
-a always,exit -F arch=b64 -S open -F path=/dev/nvme0n1 -F perm=w -k disk_write`,
        kibana: `// Raw disk access (Sysmon EID 9)
winlog.event_id: 9
AND winlog.event_data.Device: *PhysicalDrive*
AND NOT process.name: ("System" OR "MsMpEng.exe" OR "vssvc.exe")

// Wiper tool patterns
process.command_line: (*PhysicalDrive* OR *\\.\\PhysicalDrive*)

// Suspicious driver loads (kernel-level disk access)
winlog.event_id: 6
AND NOT winlog.event_data.Signed: "true"

// Linux: dd targeting block devices
process.name: "dd"
AND process.args: ("of=/dev/sda" OR "of=/dev/nvme0n1"
  OR "of=/dev/vda" OR "of=/dev/xvda")`,
        powershell: `# MBR/GPT wipe detection
Write-Host "[*] === Raw disk access events (Sysmon EID 9) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=9
} -MaxEvents 100 -EA SilentlyContinue |
  Select-Object TimeCreated,
    @{n='Process';e={$_.Properties[4].Value}},
    @{n='Device';e={$_.Properties[6].Value}}

Write-Host "[*] === MBR integrity check ==="
# Read first 512 bytes of disk and check for valid boot signature
$disk = [IO.File]::OpenRead('\\.\PhysicalDrive0')
$mbr = New-Object byte[] 512
$disk.Read($mbr, 0, 512) | Out-Null
$disk.Close()
$sig = [BitConverter]::ToString($mbr[510..511])
Write-Host "  Boot signature: $sig (expected: 55-AA)"
if ($sig -ne '55-AA') { Write-Host "  WARNING: Invalid MBR signature - possible wipe" }

Write-Host "[*] === Unsigned driver loads (Sysmon EID 6) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=6
} -MaxEvents 50 -EA SilentlyContinue |
  Where-Object { $_.Properties[5].Value -ne 'true' } |
  Select-Object TimeCreated, @{n='Driver';e={$_.Properties[3].Value}}`,
        registry: `No direct registry artifact from the disk write itself.
The system may be unbootable after the wipe completes.

Known wiper disk access patterns:
- WhisperGate: overwrites MBR with ransom note, then Stage 2
  corrupts files (January 2022, Ukraine)
- HermeticWiper: uses signed EaseUS partition driver
  (empntdrv.sys) for kernel-level disk destruction
  (February 2022, Ukraine)
- CaddyWiper: zeros files then destroys partition table
  using DeviceIoControl IOCTL_DISK_SET_DRIVE_LAYOUT
  (March 2022, Ukraine)
- Destover: direct MBR overwrite + file wipe
  (Sony Pictures, 2014)
- StoneDrill/Shamoon: MBR + file overwrite
  (Saudi Arabia, 2012/2016/2018)`,
        tools: `Sysmon (EID 9 raw disk access, EID 6 driver loads)
Windows Defender (behavior-based wiper detection)
Velociraptor (disk forensic artifacts)
UEFI Secure Boot (prevents unsigned boot modification)
Offline backups (the actual recovery path)`,
        ossdetect: `Sigma:
- win_sysmon_raw_disk_access.yml
- win_driver_load_unsigned.yml

Elastic Detection Rules:
- Direct Disk Access via PhysicalDrive
- Suspicious Driver Load

Microsoft Defender for Endpoint:
- Wiper behavior detection
- Boot sector modification alert`,
        notes: "MBR/GPT wipe detection is critical because it distinguishes nation-state destructive operations from commodity ransomware. Ransomware encrypts files but leaves the disk structure intact (the ransom note needs to display at boot). Wipers destroy the disk structure itself, making the system permanently unbootable. Detection is challenging because the wipe happens at the raw disk level, below the filesystem where most monitoring operates. Sysmon EID 9 (RawAccessRead) catches the precursor reads but not the writes. Kernel-level driver loads (EID 6) are the proxy signal: wipers like HermeticWiper load signed third-party drivers to get kernel disk access. UEFI Secure Boot provides some protection by preventing modified boot code from executing, but a GPT wipe still renders the system unbootable even if Secure Boot is enabled. The only real recovery is offline/immutable backups.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "WhisperGate, HermeticWiper, CaddyWiper, and multiple other disk-destructive tools deployed against Ukraine (2022-2024)." },
          { cls: "apt-kp", name: "Lazarus", note: "Destover (Sony Pictures 2014), KillDisk (multiple campaigns), MBR overwrite in destructive operations." },
          { cls: "apt-ir", name: "APT33", note: "Shamoon/DistTrack MBR wiper deployed against Saudi Aramco and Gulf state targets (2012, 2016, 2018)." }
        ],
        malware: [],
        activity: [],
        cite: "MITRE ATT&CK T1561.002"
      }
    ]
  },
  {
    id: "T1529",
    name: "System Shutdown/Reboot",
    desc: "Forced system shutdown or reboot to complete a destructive or disruptive operation. Ransomware reboots into a modified boot screen displaying the ransom note. Wipers reboot to force the corrupted MBR/GPT to take effect. Legitimate reboots are scheduled and announced; attacker-initiated reboots are immediate and unexpected.",
    rows: [
      {
        sub: "T1529 - Forced Shutdown/Reboot (immediate, unscheduled, post-attack trigger)",
        os: "win",
        indicator: "Execution of shutdown.exe or init with immediate/force flags (/s /f /t 0, shutdown -h now) outside of scheduled maintenance windows, particularly when preceded by shadow copy deletion, service stopping, or encryption activity, indicating the final step of a destructive or ransomware operation",
        sysmon: `// Windows - Sysmon EID 1: forced shutdown commands
Image=*\\shutdown.exe
CommandLine=(*\/s*\/f* OR *\/r*\/f* OR *\/s*\/t*0* OR *\/r*\/t*0*)

// PowerShell shutdown
Image=*\\powershell.exe
CommandLine=(*Stop-Computer*-Force* OR *Restart-Computer*-Force*)

// Linux - Auditd: shutdown/reboot commands
-a always,exit -F arch=b64 -S execve -F exe=/sbin/shutdown -k shutdown_cmd
-a always,exit -F arch=b64 -S execve -F exe=/sbin/reboot -k shutdown_cmd
-a always,exit -F arch=b64 -S execve -F exe=/sbin/poweroff -k shutdown_cmd
-a always,exit -F arch=b64 -S execve -F exe=/sbin/init -k shutdown_cmd

// Sysmon for Linux EID 1
Image=(*/shutdown OR */reboot OR */poweroff OR */halt)
CommandLine=(*-h*now* OR *-r*now* OR *--force*)`,
        kibana: `// Windows forced shutdown
process.name: "shutdown.exe"
AND process.command_line: (*"/s"* AND *"/f"*) OR (*"/r"* AND *"/f"*)

// PowerShell forced shutdown
process.command_line: (*Stop-Computer*Force* OR *Restart-Computer*Force*)

// Linux forced shutdown
process.name: ("shutdown" OR "reboot" OR "poweroff" OR "halt" OR "init")
AND process.args: ("now" OR "-h" OR "--force" OR "0" OR "6")

// Security EID 1074 (System Shutdown Initiated)
winlog.event_id: 1074`,
        powershell: `# Shutdown detection
Write-Host "[*] === Recent shutdown commands (Sysmon) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Properties[4].Value -match 'shutdown|restart' -or
    $_.Properties[10].Value -match 'Stop-Computer|Restart-Computer' } |
  Select-Object TimeCreated,
    @{n='Cmd';e={$_.Properties[10].Value.Substring(0,200)}}

Write-Host "[*] === System shutdown events (EID 1074) ==="
Get-WinEvent -FilterHashtable @{
  LogName='System'; Id=1074
} -MaxEvents 10 -EA SilentlyContinue |
  Select-Object TimeCreated, Message | Format-Table -Auto

# Linux equivalent:
# last -x shutdown reboot
# journalctl --list-boots
# ausearch -k shutdown_cmd -ts recent`,
        registry: `Windows shutdown reason tracking:
  Security EID 1074: System has been shutdown by a process
    Records: process name, reason code, shutdown type
  
  System EID 6006: Event Log service was stopped (clean shutdown)
  System EID 6008: Previous shutdown was unexpected (crash/forced)
  
  EID 6008 (unexpected shutdown) following EID 6006 absence
  indicates a hard power-off or forced shutdown that bypassed
  the normal shutdown sequence.`,
        tools: `Security event log (EID 1074 shutdown initiated)
System event log (EID 6006/6008 shutdown type)
Sysmon (EID 1 shutdown command)
UPS/PDU logs (correlate power events with host events)`,
        ossdetect: `Sigma:
- win_proc_creation_forced_shutdown.yml
- win_system_unexpected_shutdown.yml

Elastic Detection Rules:
- System Shutdown Command Execution

Wazuh:
- Rule 18100: System shutdown
- Auditd integration for shutdown commands`,
        notes: "A forced shutdown or reboot is rarely the primary detection for an attack. Its value is as a CORRELATION indicator: shutdown preceded by shadow copy deletion + service stops + file encryption = confirmed ransomware completion. Shutdown preceded by MBR overwrite = confirmed wiper activation. Shutdown alone (without preceding attack indicators) is usually legitimate maintenance. The investigation workflow is: detect the shutdown event, then look BACKWARD in the timeline for the attack chain that preceded it. On Linux, 'last -x shutdown reboot' shows the reboot history, and 'journalctl --list-boots' shows each boot with timestamps, revealing gaps where the system was down.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Forced reboot after wiper deployment to activate corrupted boot sector." },
          { cls: "apt-kp", name: "Lazarus", note: "System shutdown as final step in destructive operations." }
        ],
        malware: [],
        activity: [
          { cls: "apt-mul", name: "Ransomware", note: "Forced reboot to display ransom note at boot screen or to complete full-disk encryption." }
        ],
        cite: "MITRE ATT&CK T1529"
      }
    ]
  },

];