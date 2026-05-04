// TA0008 - Lateral Movement
// 8 techniques · 31 indicators · network-visible east-west detection

const DATA = [
  {
    id: "T1021.001",
    name: "Remote Services: Remote Desktop Protocol",
    desc: "RDP lateral movement - source/destination anomalies, CredSSP authentication, BlueKeep, RDP-over-HTTPS",
    rows: [
      {
        sub: "T1021.001 - Source/Destination Anomalies",
        indicator: "Workstation-to-workstation RDP - peer lateral movement pattern",
        arkime: `ip.src == $WORKSTATIONS
&& ip.dst == $WORKSTATIONS
&& port.dst == 3389
&& protocols == rdp
&& ip.src != $RDP_JUMP_HOSTS`,
        kibana: `source.ip: $WORKSTATIONS
AND destination.ip: $WORKSTATIONS
AND destination.port: 3389
AND NOT source.ip: $RDP_JUMP_HOSTS`,
        suricata: `alert tcp $WORKSTATIONS any
  -> $WORKSTATIONS 3389
  (msg:"TA0008 T1021.001 Workstation
    to workstation RDP unusual
    lateral movement";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9100101; rev:1;)`,
        notes: "In healthy networks, RDP flows from admin workstations and jump hosts to servers - not between user workstations. Workstation-to-workstation RDP is a strong lateral movement indicator. Build $RDP_JUMP_HOSTS allowlist from your sanctioned admin sources (PAW devices, jump servers, IT support workstations). Build $WORKSTATIONS from your VLAN allocation. After exclusions, peer RDP is essentially always either an unsanctioned IT shortcut or active lateral movement. Particularly powerful when combined with EDR - the source process initiating mstsc.exe or RDP-related WMI calls confirms the activity. Pair with subsequent network traffic from the destination workstation (does it start probing more hosts? exfiltrating data?) for full kill-chain correlation.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Workstation-to-workstation RDP documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal pre-encryption lateral movement pattern across ransomware affiliate operations." },
          { cls: "apt-cn", name: "APT41", note: "RDP lateral movement in operations against technology and gaming sectors." },
          { cls: "apt-ru", name: "APT29", note: "RDP lateral movement in espionage operations including SolarWinds compromise." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA Scattered Spider advisory and across virtually every ransomware incident report. The pattern is essentially universal in lateral movement playbooks." }
        ],
        cite: "MITRE ATT&CK T1021.001, CISA AA23-320A"
      },
      {
        sub: "T1021.001 - Source/Destination Anomalies",
        indicator: "RDP fan-out from single source - one host RDP'ing to many destinations",
        arkime: `ip.src == $INTERNAL
&& port.dst == 3389
&& protocols == rdp
&& unique-dst-count groupby
  ip.src > 5 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 3389
AND network.protocol: rdp`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 3389
  (msg:"TA0008 T1021.001 RDP fan-out
    single source many destinations
    lateral movement";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 5, seconds 600;
  classtype:trojan-activity;
  sid:9100102; rev:1;)`,
        notes: "Adversaries with valid credentials work through the network methodically - RDPing to many hosts in sequence to find the right target. Even legitimate IT admins typically RDP to a small set of servers; sustained RDP fan-out (5+ distinct destinations in 10 minutes from one source) is anomalous. The pattern is especially clean when adversaries are doing post-exploitation enumeration via RDP rather than scripted means. Tune the threshold based on environment: in a small environment 5 might be normal admin behavior; in a large enterprise 5+ within 10 minutes from a single non-admin source is strong signal. Pair with EDR for mstsc.exe parent-process analysis - adversary RDP often originates from cmd.exe, powershell.exe, or unusual parents.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "RDP fan-out documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Hallmark of ransomware affiliate operations - methodically RDP through environments to identify high-value systems before encryption." },
          { cls: "apt-ru", name: "APT29", note: "RDP fan-out in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "RDP-based lateral discovery in operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented extensively in CISA, FBI, and Mandiant reporting." }
        ],
        cite: "MITRE ATT&CK T1021.001, CISA AA23-320A"
      },
      {
        sub: "T1021.001 - Source/Destination Anomalies",
        indicator: "RDP from external source - internet-facing RDP exposure abuse",
        arkime: `ip.src == $EXTERNAL
&& ip.src != $RDP_GATEWAY_ALLOWLIST
&& port.dst == 3389
&& protocols == rdp
&& ip.dst == $INTERNAL
&& session.duration > 30`,
        kibana: `source.ip: NOT $INTERNAL
AND NOT source.ip: $RDP_GATEWAY_ALLOWLIST
AND destination.port: 3389
AND destination.ip: $INTERNAL`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 3389
  (msg:"TA0008 T1021.001 External
    RDP connection internet-exposed
    RDP abuse";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9100103; rev:1;)`,
        notes: "Internet-facing RDP is one of the top initial access vectors for ransomware - exposed RDP servers get credential-sprayed within hours of going online (Shodan-discoverable). Adversaries who succeed often use the same RDP access for lateral movement once inside. Detection: any external IP connecting to internal RDP that isn't your sanctioned RDP gateway (CloudFlare, Citrix Gateway, RD Gateway, AWS Session Manager). The detection IS the alert - there should be NO direct external RDP to your internal network. If you find any, you have a perimeter exposure problem regardless of whether the connection is malicious. Many environments inherit these exposures from M&A activity or shadow IT - periodic scanning of your own external IP space (Shodan, custom port scans) catches them.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "External RDP is one of the top ransomware initial access vectors per CISA, FBI, and industry reporting." },
          { cls: "apt-mul", name: "Initial Access Brokers", note: "IABs specifically target Shodan-discoverable RDP for credential spray attacks." },
          { cls: "apt-cn", name: "APT41", note: "External RDP abuse documented in some technology sector operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in numerous incident reports as primary ransomware initial access vector." }
        ],
        cite: "MITRE ATT&CK T1021.001, T1133, CISA ransomware advisories"
      },
      {
        sub: "T1021.001 - Authentication Patterns",
        indicator: "Multiple RDP credential failures from single source - credential brute force or spray",
        arkime: `ip.src == $INTERNAL
&& port.dst == 3389
&& protocols == rdp
&& rdp.result == failed
&& session-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 3389
AND network.protocol: rdp
AND rdp.auth_result: "failure"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 3389
  (msg:"TA0008 T1021.001 RDP
    credential failure burst
    brute force or spray";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:trojan-activity;
  sid:9100104; rev:1;)`,
        notes: "RDP brute force / password spray patterns: many failed authentication attempts from one source against one or many targets within a short window. RDP doesn't have great network-visible authentication state - TLS/CredSSP encrypts the actual credentials - but Zeek's RDP analyzer can capture the connection sequence and infer success/failure from session lengths. Failed RDP auths typically last 1-2 seconds (TLS handshake + auth + reject). Successful auths last longer (full session establishment, screen data flowing). A burst of short-lived RDP connections from one source = brute force or spray. Pair with Windows Event ID 4625 (failed logon) on destination hosts for definitive correlation. Adversaries who've compromised one set of credentials often try the same credentials across many targets - lateral spray.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "RDP credential attacks documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal across ransomware operations." },
          { cls: "apt-mul", name: "Initial Access Brokers", note: "IABs heavily use RDP brute force as primary entry vector." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all ransomware operations." }
        ],
        cite: "MITRE ATT&CK T1021.001, T1110, CISA AA23-320A"
      },
      {
        sub: "T1021.001 - Authentication Patterns",
        indicator: "RDP NLA negotiation downgrade - CredSSP downgrade attempt",
        arkime: `ip.src == $INTERNAL
&& port.dst == 3389
&& protocols == rdp
&& rdp.cookie == "*Cookie: mstshash=*"
&& rdp.security-protocol ==
  Standard
&& ip.src != $LEGACY_RDP_CLIENTS`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 3389
AND rdp.cookie: *mstshash*
AND rdp.security_protocol: "standard"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 3389
  (msg:"TA0008 T1021.001 RDP
    Standard Security downgrade
    NLA bypass attempt";
  flow:established,to_server;
  content:"Cookie|3a| mstshash=";
  content:!"|01 00 08 00|"; within:50;
  classtype:trojan-activity;
  sid:9100105; rev:1;)`,
        notes: "RDP supports multiple security layers: Standard RDP Security (legacy, weak, vulnerable to MITM), TLS, and CredSSP/NLA (Network Level Authentication - most secure, requires authentication BEFORE session establishment). NLA is the modern default and adversaries sometimes try to downgrade to weaker security to bypass MITM defenses or exploit older vulnerabilities. The Standard Security protocol negotiation pattern is visible in cleartext during the RDP X.224 connection request. Modern environments should require NLA - workstations attempting Standard Security RDP are either misconfigured or attempting downgrade. Maintain $LEGACY_RDP_CLIENTS for known-legitimate sources (older systems, embedded devices). Combine with subsequent CredSSP negotiation absence - if a session goes from Standard Security request directly to RDP data without the NLA exchange, that's a successful downgrade.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "RDP downgrade attacks documented in some operations." },
          { cls: "apt-mul", name: "Red Team", note: "Documented in offensive security research." },
          { cls: "apt-mul", name: "Multi", note: "RDP security downgrade attacks are documented in offensive security research and in some advanced threat actor operations targeting environments with mixed legacy infrastructure." }
        ],
        cite: "MITRE ATT&CK T1021.001, industry research"
      },
      {
        sub: "T1021.001 - Exploit Signatures",
        indicator: "BlueKeep exploit traffic - CVE-2019-0708 MS_T120 channel abuse",
        arkime: `ip.src == $INTERNAL
&& port.dst == 3389
&& protocols == rdp
&& payload == "*MS_T120*"
// BlueKeep's full byte signature (TPKT header +
// MS_T120 channel reference) requires regex on
// binary payload - not expressible in pure Arkime.
// See Suricata pcre column for full byte-pattern match.
// Logical spec: payload matches
//   /\\x03\\x00.{2}\\x02\\xf0\\x80.*MS_T120/`,
        kibana: `destination.port: 3389
AND _exists_: rdp.channel
AND rdp.channel: "MS_T120"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 3389
  (msg:"TA0008 T1021.001 BlueKeep
    CVE-2019-0708 MS_T120 channel
    exploit attempt";
  flow:established,to_server;
  content:"|03 00|"; depth:2;
  content:"MS_T120"; within:200;
  classtype:trojan-activity;
  sid:9100106; rev:1;)`,
        notes: "BlueKeep (CVE-2019-0708) is a wormable RDP pre-authentication RCE in Windows 7, Server 2008, Server 2008 R2. The vulnerability is in how RDP handles the MS_T120 internal virtual channel - adversaries bind it to a non-default channel and trigger a use-after-free. Network signature: a client-side request to bind 'MS_T120' as a virtual channel during the RDP MCS Connect Initial phase, which doesn't happen in legitimate RDP traffic (MS_T120 is reserved for internal Windows use). Detection at the MS_T120 string level catches both Metasploit's BlueKeep module and most public PoCs. Modern Windows is patched (MS19-7), but unpatched Server 2008 R2 and Windows 7 systems still exist in many environments - particularly OT, healthcare, and legacy ICS networks. Worth maintaining the signature even though widespread exploitation has subsided.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "BlueKeep exploitation documented in some operations targeting unpatched legacy infrastructure." },
          { cls: "apt-mul", name: "Red Team", note: "Standard red team tooling - Metasploit BlueKeep module." },
          { cls: "apt-mul", name: "Cryptominers", note: "DejaBlue/BlueKeep wormable variants used by various cryptominer operations." },
          { cls: "apt-mul", name: "Multi", note: "CISA and Microsoft issued urgent advisories in 2019. Used by various actors targeting unpatched legacy systems." }
        ],
        cite: "MITRE ATT&CK T1021.001, T1210, CVE-2019-0708, CISA Alert AA19-168A"
      },
      {
        sub: "T1021.001 - Tunneled RDP",
        indicator: "RDP-over-HTTPS / Gateway abuse - RDP traffic to non-gateway destination on TCP/443",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& protocols == [tls && rdp]
&& ip.dst != $RDP_GATEWAYS
&& tls.sni != $LEGITIMATE_RDP_SNI
&& session.duration > 60`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND _exists_: rdp.connect_request
AND NOT destination.ip: $RDP_GATEWAYS`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0008 T1021.001 RDP over
    HTTPS to non-gateway destination
    possible tunneled RDP";
  flow:established,to_server;
  content:"|03 00 00|"; offset:0; depth:3;
  classtype:trojan-activity;
  sid:9100107; rev:1;)`,
        notes: "RDP can be tunneled over HTTPS via Remote Desktop Gateway (legitimate, $RDP_GATEWAYS) or via custom tunneling (ngrok, Chisel, Cloudflare Tunnel, custom implants). Detection requires either app-layer inspection (DPD detecting RDP inside TLS - Zeek's tls + rdp protocol detection) or destination IP analysis. RDP traffic to a non-corporate-gateway destination on 443 is anomalous. Particularly relevant in modern operations where Scattered Spider and similar actors use Cloudflare Tunnel + RDP to maintain persistent access without traditional VPN. Pair with the T1572 protocol tunneling indicators for cross-tactic kill-chain visibility - RDP-over-Cloudflare-Tunnel involves both T1021.001 (RDP) and T1572 (tunneling).",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "RDP tunneling for persistence documented in CISA AA23-320A - Cloudflare Tunnel + RDP increasingly common." },
          { cls: "apt-cn", name: "APT41", note: "RDP tunneling in operations against technology sector targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Modern ransomware operations use tunneled RDP to bypass perimeter controls." },
          { cls: "apt-mul", name: "Multi", note: "Cloudflare Tunnel + RDP increasingly common as a VPN alternative for adversaries." }
        ],
        cite: "MITRE ATT&CK T1021.001, T1572, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1021.002",
    name: "Remote Services: SMB / Windows Admin Shares",
    desc: "PsExec, smbexec, wmiexec - ADMIN$/C$/IPC$ access, service binary drops, named pipe execution",
    rows: [
      {
        sub: "T1021.002 - Administrative Share Access",
        indicator: "ADMIN$ tree connect from non-admin source - administrative share access",
        arkime: `ip.src == $INTERNAL
&& ip.src != $ADMIN_HOSTS
&& port.dst == 445
&& protocols == smb
&& smb.share-name == ADMIN$
&& smb.command == tree-connect`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $ADMIN_HOSTS
AND destination.port: 445
AND smb.share.name: "ADMIN$"
AND smb.command: "tree_connect"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1021.002 ADMIN$
    tree connect non-admin source
    lateral movement";
  flow:established,to_server;
  content:"|ff 53 4d 42 75|";
  content:"ADMIN$"; nocase;
  classtype:trojan-activity;
  sid:9100201; rev:1;)`,
        notes: "ADMIN$ is a hidden administrative share that maps to %SystemRoot% (typically C:\\Windows). Access requires local admin rights on the target. Legitimate use: SCCM agent operations, IT management tools, manual administrative maintenance from sanctioned admin workstations. Adversary use: PsExec drops PSEXESVC.exe to ADMIN$, smbexec writes batch files, wmiexec uses ADMIN$ for output redirection. Build $ADMIN_HOSTS allowlist tightly - your actual sanctioned admin sources, NOT the broader IT VLAN. After exclusions, ADMIN$ access from workstations is essentially always lateral movement. Pair with subsequent svcctl RPC calls (sid 9100204) - the ADMIN$ access alone is enumeration; ADMIN$ + service creation is execution.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "ADMIN$ lateral movement documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate operations - PsExec is the dominant lateral movement tool." },
          { cls: "apt-ru", name: "APT29", note: "ADMIN$-based lateral movement in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "PsExec and Impacket usage across operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all advanced threat actor operations and ransomware playbooks. PsExec, Impacket, CrackMapExec - all use ADMIN$." }
        ],
        cite: "MITRE ATT&CK T1021.002, CISA AA23-320A"
      },
      {
        sub: "T1021.002 - Administrative Share Access",
        indicator: "C$ administrative drive access - root C: drive enumeration via SMB",
        arkime: `ip.src == $INTERNAL
&& ip.src != $ADMIN_HOSTS
&& port.dst == 445
&& protocols == smb
&& smb.share-name == [
  C$ || D$ || ADMIN$ || IPC$
]
&& smb.command == tree-connect
&& unique-share-count groupby
  ip.src,ip.dst > 2 within 60s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $ADMIN_HOSTS
AND destination.port: 445
AND smb.share.name: (
  "C$" OR "D$" OR "ADMIN$" OR "IPC$"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1021.002 Multiple
    administrative share access
    burst lateral movement";
  flow:established,to_server;
  content:"|ff 53 4d 42 75|";
  pcre:"/(C\\$|D\\$|ADMIN\\$|IPC\\$)/";
  threshold:type both,
    track by_src,
    count 2, seconds 60;
  classtype:trojan-activity;
  sid:9100202; rev:1;)`,
        notes: "C$ maps to the entire C: drive - full filesystem read/write access for local administrators. Adversaries use C$ for: dropping arbitrary tools to non-system paths (C$\\Users\\Public\\), reading sensitive files (C$\\Users\\<victim>\\.aws\\credentials, browser data), staging exfiltration. Multiple admin share access from one source within seconds (e.g. tree-connect to C$ then ADMIN$ then IPC$ in 30 seconds) is the PsExec / Impacket pattern: enumerate IPC$ for RPC binding, write binary to ADMIN$, execute via svcctl, retrieve output via C$. The detection catches the multi-share access pattern. Pair with SMB write operations to ADMIN$ for service binary deployment confirmation (sid 9100203).",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Multi-admin-share access documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "PsExec/Impacket/CrackMapExec network fingerprint - universal in ransomware operations." },
          { cls: "apt-cn", name: "APT41", note: "Admin share enumeration in operations." },
          { cls: "apt-ru", name: "APT29", note: "Admin share access in espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and across ransomware operations." }
        ],
        cite: "MITRE ATT&CK T1021.002, T1570"
      },
      {
        sub: "T1021.002 - Service Binary Drops",
        indicator: "Executable write to ADMIN$ - service binary drop preceding remote execution",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == [write || create]
&& smb.share-name == ADMIN$
&& smb.filename == [
  *.exe
  || *.dll
  || *.bat
  || *.ps1
  || *.vbs
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.share.name: "ADMIN$"
AND smb.command: ("write" OR "create")
AND file.name: /.+\\.(exe|dll|bat|ps1|vbs)$/`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1021.002 Executable
    written to ADMIN$ service
    binary deployment";
  flow:established,to_server;
  content:"ADMIN$";
  content:"|4d 5a|"; within:1024;
  classtype:trojan-activity;
  sid:9100203; rev:1;)`,
        notes: "PsExec and equivalents drop their service binary to ADMIN$ before invoking it: PsExec writes PSEXESVC.exe, Impacket psexec.py writes a randomly-named .exe, smbexec writes a batch file. The SMB command sequence is tree-connect to ADMIN$ → create file → write data → close. Zeek smb_files.log captures filename and write operations. The Suricata signature looks for the PE magic bytes 'MZ' (0x4D 0x5A) within 1KB of the ADMIN$ tree connect - catches PE writes to admin shares. False positives: legitimate SCCM updates, Windows Update Server pushes - both should be allowlisted by source. After exclusions, executable writes to ADMIN$ are the highest-confidence single network signal for SMB lateral movement. Particularly powerful when the destination is a workstation rather than a server.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Executable drops to ADMIN$ documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Canonical SMB lateral movement fingerprint across ransomware operations." },
          { cls: "apt-ru", name: "APT29", note: "ADMIN$ binary drops in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Service binary deployment in operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK, CISA Scattered Spider advisory, and across ransomware incident reports." }
        ],
        cite: "MITRE ATT&CK T1021.002, T1570, CISA AA23-320A"
      },
      {
        sub: "T1021.002 - Service Creation",
        indicator: "svcctl service creation following ADMIN$ access - PsExec service registration",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  367abb81-9844-35f1-ad32-98f038001003
&& dcerpc.opnum == [12 || 24 || 31]
&& session-after-share-access
  ADMIN$ within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "367abb81-9844-35f1-ad32-98f038001003"
AND dcerpc.opnum: (12 OR 24 OR 31)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1021.002 svcctl
    service creation following SMB
    lateral movement";
  flow:established,to_server;
  content:"|81 bb 7a 36 44 98 f1 35|";
  classtype:trojan-activity;
  sid:9100204; rev:1;)`,
        notes: "After dropping the service binary to ADMIN$, PsExec uses the svcctl RPC interface (UUID 367abb81-9844-35f1-ad32-98f038001003) to create and start the service. Key opnums: RCreateServiceW (opnum 12), RStartServiceW (opnum 19), RDeleteService (opnum 2), RChangeServiceConfigW (opnum 24), RControlService (opnum 1). The full PsExec sequence: ADMIN$ tree-connect → write PSEXESVC.exe → svcctl create service → svcctl start service → connect to \\\\.\\pipe\\psexesvc for I/O. Detection at the svcctl RPC level catches the service creation step. Combine with ADMIN$ write detection (sid 9100203) - they should occur within 60 seconds of each other. Together they're essentially proof of remote execution. Particularly clean signal in environments with restricted SCCM (where legitimate svcctl traffic is rare).",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "svcctl service creation documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Canonical PsExec/Impacket execution mechanism - universal in ransomware operations." },
          { cls: "apt-ru", name: "APT29", note: "Service creation for execution in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "PsExec service mechanism in operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK T1021.002, T1543.003, CISA Scattered Spider advisory, and across virtually every ransomware incident report." }
        ],
        cite: "MITRE ATT&CK T1021.002, T1543.003"
      },
      {
        sub: "T1021.002 - Named Pipe Execution",
        indicator: "PsExec named pipe - \\\\.\\pipe\\psexesvc execution channel",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.pipe-name == [
  *psexesvc*
  || *paexec*
  || *remcom*
  || *csexec*
  || *impacket-*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.named_pipe: (
  *psexesvc* OR *paexec*
  OR *remcom* OR *csexec*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1021.002 PsExec
    or variant named pipe lateral
    execution";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  pcre:"/\\\\\\\\PIPE\\\\\\\\(psexesvc|paexec|
    remcom|csexec)/i";
  classtype:trojan-activity;
  sid:9100205; rev:1;)`,
        notes: "PsExec uses the named pipe \\\\.\\pipe\\psexesvc for stdin/stdout/stderr redirection between the controlling host and the executed command. Variants: PAExec (\\\\.\\pipe\\paexec), RemCom (\\\\.\\pipe\\remcom_communication), CSExec, Impacket psexec.py uses customizable but often default-named pipes. Detection at the pipe-name level is high-confidence - these are essentially never used outside their respective tools. Modern Cobalt Strike SMB beacons use customizable pipe names (default postex_, status_, msagent_) which are covered in the C2 indicators (T1090.001 sid 9109002). This indicator targets the classic PsExec family specifically. Sophisticated operators rename pipes - but defaults still appear in many real operations. Worth maintaining as low-cost coverage even with caveats.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "PsExec usage documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal across ransomware operations - PsExec is the dominant lateral movement tool." },
          { cls: "apt-cn", name: "APT41", note: "PsExec and Impacket variants in operations." },
          { cls: "apt-mul", name: "Red Team", note: "Standard red team tooling." },
          { cls: "apt-mul", name: "Multi", note: "PsExec named pipe signatures documented as primary detection by Microsoft Defender, CrowdStrike, and Mandiant." }
        ],
        cite: "MITRE ATT&CK T1021.002, S0029 (PsExec), CISA AA23-320A"
      },
      {
        sub: "T1021.002 - Named Pipe Execution",
        indicator: "wmiexec output redirection - Impacket wmiexec.py file pattern",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == read
&& smb.share-name == ADMIN$
// Impacket wmiexec.py writes output files named
// __<timestamp>.<microseconds> - filename pattern
// requires regex, not expressible in pure Arkime.
// See Suricata pcre column.
// Logical spec: smb.filename matches /__\\d+\\.\\d+/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.share.name: "ADMIN$"
AND smb.command: "read"
AND file.name: /__\\d+\\.\\d+/`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1021.002 Impacket
    wmiexec output redirection
    file pattern";
  flow:established,from_server;
  pcre:"/__\\d{10,}\\.\\d+/";
  classtype:trojan-activity;
  sid:9100206; rev:1;)`,
        notes: "Impacket's wmiexec.py creates output files on the target with names like '__1234567890.123' (timestamp.fraction) in ADMIN$ - the executed command's stdout/stderr is redirected here, then the script reads back the file via SMB and deletes it. The filename pattern is highly distinctive: double underscore + 10+ digit number + period + fractional digits. Other Impacket tools (atexec.py, smbexec.py) use similar patterns. Zeek smb_files.log captures the filenames; the regex catches the canonical Impacket signature. Modern Impacket forks sometimes change the format - the upstream repo's pattern remains the dominant signature. Adversaries using stock Impacket (which is most of them) generate this pattern; only those who modify Impacket source escape it.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Impacket usage documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Ransomware", note: "Impacket near-universal in ransomware operations." },
          { cls: "apt-cn", name: "APT41", note: "Impacket usage in operations against technology and gaming sectors." },
          { cls: "apt-ru", name: "APT29", note: "Impacket usage in espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Impacket wmiexec/smbexec/atexec documented in essentially every ransomware operation. Output file naming pattern documented in Mandiant, CrowdStrike, and Microsoft research." }
        ],
        cite: "MITRE ATT&CK T1021.002, T1047, S0357 (Impacket)"
      }
    ]
  },
  {
    id: "T1021.003",
    name: "Remote Services: Distributed Component Object Model",
    desc: "DCOM lateral movement - IRemoteSCMActivator, MMC20.Application, ShellWindows, Excel.Application CLSIDs",
    rows: [
      {
        sub: "T1021.003 - DCOM Activation",
        indicator: "IRemoteSCMActivator RPC bind - DCOM remote activation interface",
        arkime: `ip.src == $INTERNAL
&& port.dst == 135
&& protocols == dcerpc
&& dcerpc.interface ==
  000001a0-0000-0000-c000-000000000046
&& dcerpc.opnum == [3 || 4]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 135
AND dcerpc.interface_uuid: "000001a0-0000-0000-c000-000000000046"
AND dcerpc.opnum: (3 OR 4)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 135
  (msg:"TA0008 T1021.003 IRemote
    SCMActivator DCOM remote object
    activation";
  flow:established,to_server;
  content:"|a0 01 00 00 00 00 00 00|";
  content:"|c0 00 00 00 00 00 00 46|";
  within:50;
  classtype:trojan-activity;
  sid:9100301; rev:1;)`,
        notes: "IRemoteSCMActivator (UUID 000001a0-0000-0000-c000-000000000046) is the DCOM interface used to activate COM objects on a remote machine. Opnum 3 (RemoteCreateInstance) and 4 (RemoteGetClassObject) are the activation methods - adversaries call these with the CLSID of the object they want to instantiate. The traffic occurs on TCP/135 (RPC endpoint mapper) and then on a dynamically-allocated high port (49152-65535) for the actual object communication. Detection at the IRemoteSCMActivator level catches the activation phase. Legitimate DCOM use exists (some enterprise applications use it heavily - particularly older SCADA/ICS apps and some Office automation), so build $DCOM_CLIENTS allowlist for sanctioned sources.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "DCOM lateral movement documented in red team tradecraft." },
          { cls: "apt-cn", name: "APT41", note: "DCOM usage in operations against technology sector targets." },
          { cls: "apt-ru", name: "APT28", note: "DCOM lateral movement documented in some operations." },
          { cls: "apt-mul", name: "Multi", note: "Particularly relevant in environments with strong SMB lateral movement defenses. Documented in MITRE ATT&CK and in red team tradecraft." }
        ],
        cite: "MITRE ATT&CK T1021.003"
      },
      {
        sub: "T1021.003 - MMC20.Application",
        indicator: "MMC20.Application CLSID - canonical DCOM lateral movement signature",
        arkime: `ip.src == $INTERNAL
&& port.dst == 135
&& protocols == dcerpc
&& payload == "*49B2791A-B1AE-4C90-9B8E-E860BA07F889*"`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 135
AND _exists_: dcerpc.activation_clsid
AND dcerpc.activation_clsid: "49b2791a-b1ae-4c90-9b8e-e860ba07f889"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 135
  (msg:"TA0008 T1021.003 MMC20
    Application DCOM activation
    lateral movement";
  flow:established,to_server;
  content:"|1a 79 b2 49 ae b1 90 4c|";
  content:"|9b 8e e8 60 ba 07 f8 89|";
  within:8;
  classtype:trojan-activity;
  sid:9100302; rev:1;)`,
        notes: "MMC20.Application (CLSID 49B2791A-B1AE-4C90-9B8E-E860BA07F889) is the COM object for Microsoft Management Console. Its Document.ActiveView.ExecuteShellCommand method allows remote command execution - Matt Nelson's original research published in 2017 made this the canonical DCOM lateral movement technique. Tools: Invoke-DCOM (PowerShell), Cobalt Strike's dcom command, custom scripts. Detection: the CLSID byte pattern in DCERPC activation traffic is highly distinctive - almost no legitimate use case for remote MMC20.Application instantiation. Microsoft has not deprecated this interface; mitigation requires disabling DCOM on workstations or restricting MMC.exe permissions. Worth alerting on every match - false positive rate near zero.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Standard red team tradecraft - Invoke-DCOM, Cobalt Strike dcom command." },
          { cls: "apt-cn", name: "APT41", note: "DCOM lateral movement in operations." },
          { cls: "apt-mul", name: "Cobalt Strike Operators", note: "Cobalt Strike's built-in dcom command uses MMC20.Application." },
          { cls: "apt-mul", name: "Multi", note: "MMC20.Application abuse documented in MITRE ATT&CK, in extensive red team training, and in advanced threat operations. The Matt Nelson research that popularized the technique is widely cited." }
        ],
        cite: "MITRE ATT&CK T1021.003, Enigma0x3 research"
      },
      {
        sub: "T1021.003 - ShellWindows / ShellBrowserWindow",
        indicator: "ShellWindows / ShellBrowserWindow CLSID - DCOM lateral movement variants",
        arkime: `ip.src == $INTERNAL
&& port.dst == 135
&& protocols == dcerpc
&& payload == [
  *9BA05972-F6A8-11CF-A442-00A0C90A8F39*
  || *C08AFD90-F2A1-11D1-8455-00A0C91F3880*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 135
AND dcerpc.activation_clsid: (
  "9ba05972-f6a8-11cf-a442-00a0c90a8f39"
  OR "c08afd90-f2a1-11d1-8455-00a0c91f3880"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 135
  (msg:"TA0008 T1021.003 ShellWindows
    or ShellBrowserWindow DCOM
    lateral movement";
  flow:established,to_server;
  pcre:"/(72 59 a0 9b a8 f6 cf 11|
    90 fd 8a c0 a1 f2 d1 11)/i";
  classtype:trojan-activity;
  sid:9100303; rev:1;)`,
        notes: "ShellWindows (CLSID 9BA05972-F6A8-11CF-A442-00A0C90A8F39) and ShellBrowserWindow (CLSID C08AFD90-F2A1-11D1-8455-00A0C91F3880) are alternative DCOM lateral movement vectors using the same Document.Application.ShellExecute or Document.Application.Open methods to execute arbitrary commands. They were Nelson's follow-on research after MMC20.Application, providing alternatives when MMC20 was restricted. Detection at the CLSID byte pattern level. Like MMC20.Application, near-zero false positive rate - these objects are essentially never remotely instantiated for legitimate reasons. Worth maintaining alongside the MMC20 signature for full DCOM lateral movement coverage.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Alternative to MMC20.Application in red team operations." },
          { cls: "apt-cn", name: "APT41", note: "ShellWindows DCOM in some operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and in offensive security research." }
        ],
        cite: "MITRE ATT&CK T1021.003"
      },
      {
        sub: "T1021.003 - Excel DCOM",
        indicator: "Excel.Application DDE DCOM - Excel-based DCOM lateral execution",
        arkime: `ip.src == $INTERNAL
&& port.dst == 135
&& protocols == dcerpc
&& payload == [
  *00020812-0000-0000-C000-000000000046*
  || *00024500-0000-0000-C000-000000000046*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 135
AND dcerpc.activation_clsid: (
  "00020812-0000-0000-c000-000000000046"
  OR "00024500-0000-0000-c000-000000000046"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 135
  (msg:"TA0008 T1021.003 Excel
    Application DCOM lateral
    execution";
  flow:established,to_server;
  pcre:"/(12 08 02 00 00 00 00 00|
    00 45 02 00 00 00 00 00)/i";
  content:"|c0 00 00 00 00 00 00 46|";
  within:30;
  classtype:trojan-activity;
  sid:9100304; rev:1;)`,
        notes: "Excel.Application (CLSIDs 00020812-... and 00024500-... depending on version) provides DDEInitiate and RegisterXLL methods that can be abused for remote code execution via DCOM. Less common than MMC20.Application but documented in research and in some operations. The technique requires Excel installed on the target - limits applicability to workstation-heavy environments. Detection at the CLSID byte pattern. False positives possible: legitimate Excel automation across networks (rare in modern environments - replaced by APIs and PowerBI). Worth maintaining as low-cost coverage. Particularly relevant in finance and analytics environments where Excel COM automation may be more common.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Excel DCOM documented in offensive security research." },
          { cls: "apt-mul", name: "Multi", note: "Documented in offensive security research, particularly Cybereason and SpecterOps research on Office COM lateral movement." }
        ],
        cite: "MITRE ATT&CK T1021.003, T1559.002"
      }
    ]
  },
  {
    id: "T1021.004",
    name: "Remote Services: SSH",
    desc: "SSH lateral movement - peer SSH, fan-out, agent forwarding, brute force in Linux/cloud environments",
    rows: [
      {
        sub: "T1021.004 - Internal SSH",
        indicator: "Internal SSH from non-admin source - peer SSH lateral movement",
        arkime: `ip.src == $INTERNAL
&& ip.src != $SSH_ADMINS
&& ip.dst == $INTERNAL
&& port.dst == 22
&& protocols == ssh
&& session.duration > 30`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $SSH_ADMINS
AND destination.ip: $INTERNAL
AND destination.port: 22
AND network.protocol: ssh`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 22
  (msg:"TA0008 T1021.004 Internal
    SSH non-admin source lateral
    movement";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  classtype:trojan-activity;
  sid:9100401; rev:1;)`,
        notes: "In well-segmented environments, SSH should originate from a small set of admin sources: jump hosts, bastion servers, IT admin workstations, automation systems (Ansible, Salt, Puppet). Build $SSH_ADMINS tightly. Internal SSH from compromised workstations or unexpected sources is a strong lateral movement indicator. Particularly relevant in cloud environments where SSH is the primary admin protocol for Linux workloads - adversaries who compromise one EC2 instance often pivot to others via SSH using harvested keys. Pair with T1552.004 (Private Keys) detection - if you observe a host accessing SSH private keys (.ssh/id_rsa, ~/.aws/credentials) followed by SSH to a new destination, that's a clear credential-then-lateral chain.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH lateral movement against Linux servers in technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH usage in operations targeting Linux infrastructure." },
          { cls: "apt-mul", name: "Cloud-focused threats", note: "SSH lateral movement in cloud environments where SSH is primary admin protocol." },
          { cls: "apt-mul", name: "Multi", note: "Documented in operations against Linux-heavy and cloud infrastructure." }
        ],
        cite: "MITRE ATT&CK T1021.004"
      },
      {
        sub: "T1021.004 - Fan-out",
        indicator: "SSH fan-out from single source - one host SSH'ing to many destinations",
        arkime: `ip.src == $INTERNAL
&& ip.src != $AUTOMATION_HOSTS
&& port.dst == 22
&& protocols == ssh
&& unique-dst-count groupby
  ip.src > 5 within 600s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $AUTOMATION_HOSTS
AND destination.port: 22
AND network.protocol: ssh`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 22
  (msg:"TA0008 T1021.004 SSH fan-out
    single source many destinations";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  threshold:type both,
    track by_src,
    count 5, seconds 600;
  classtype:trojan-activity;
  sid:9100402; rev:1;)`,
        notes: "Adversaries with valid SSH credentials/keys often work through Linux infrastructure methodically. The pattern: one source SSHing to 5+ distinct destinations within 10 minutes. Legitimate automation (Ansible runs, configuration management) produces similar patterns from $AUTOMATION_HOSTS - exclude these. After exclusions, sustained SSH fan-out is essentially always either red team or threat actor. The detection has minimal false positives in environments where SSH automation is centralized to specific source hosts. Build $AUTOMATION_HOSTS to include your actual sanctioned Ansible/Salt/Puppet/Chef sources. Cloud environments may need additional exclusions for CI/CD systems and orchestration tools.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH fan-out in advanced threat operations." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH-based lateral discovery in operations." },
          { cls: "apt-mul", name: "Cryptominers", note: "SSH fan-out common in cryptominer deployment patterns (Sysrv-hello, Kinsing) spreading across compromised infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat operations and in cryptominer deployment patterns." }
        ],
        cite: "MITRE ATT&CK T1021.004"
      },
      {
        sub: "T1021.004 - Agent Forwarding",
        indicator: "SSH agent forwarding session - chained SSH access via forwarded credentials",
        arkime: `ip.src == $INTERNAL
&& port.dst == 22
&& protocols == ssh
&& ssh.auth-method == publickey
&& ssh.agent-forwarding == true
&& session.duration > 60`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 22
AND ssh.auth_method: "publickey"
AND _exists_: ssh.agent_forwarding`,
        suricata: `[SSH agent forwarding detection
requires SSH protocol decryption
or host-side audit logging.
Network-only detection cannot
distinguish forwarded auth from
normal pubkey auth.]
N/A pure Suricata`,
        notes: "SSH agent forwarding (-A flag, ForwardAgent yes) lets a session use the original client's SSH keys to authenticate further hops. Adversaries abuse this for lateral movement: compromise a user's session on Host A → user SSHs to Host B with -A → adversary on Host B uses the forwarded agent socket to SSH to Host C without ever knowing the user's keys. Detection at the network layer is hard - agent forwarding doesn't change the wire-protocol signature visibly. SSH protocol uses RFC 4254 channel types but the channel name 'auth-agent@openssh.com' is sent encrypted. Detection requires either: (1) host-side ssh daemon logging with LogLevel VERBOSE+, (2) auditd hooks on socket creation, or (3) SSH bastion proxies (Teleport, Boundary) that log explicitly. Mention here for completeness - best detected at the host or bastion layer.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Agent forwarding abuse documented in offensive security research." },
          { cls: "apt-cn", name: "APT41", note: "Agent forwarding in operations against Linux-heavy environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in offensive security research and in advanced threat operations targeting Linux-heavy environments." }
        ],
        cite: "MITRE ATT&CK T1021.004, T1563.001"
      },
      {
        sub: "T1021.004 - Brute Force",
        indicator: "SSH brute force / password spray - many auth failures from single source",
        arkime: `ip.src == $INTERNAL
&& port.dst == 22
&& protocols == ssh
&& session.duration < 5
&& packets.src < 20
&& unique-dst-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 22
AND network.protocol: ssh
AND event.duration < 5000000
AND network.packets < 20`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 22
  (msg:"TA0008 T1021.004 SSH burst
    of short failed connections
    brute force or spray";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:trojan-activity;
  sid:9100404; rev:1;)`,
        notes: "SSH brute force and password spray patterns produce many short-lived connections from one source. Successful SSH auths last seconds-to-hours; failed auths terminate quickly (typically <2 seconds, with <20 packets). The detection: 10+ short-lived SSH connections from one source in 5 minutes against many distinct destinations. Internet-facing SSH brute force is heavily filtered by tools like fail2ban - internal SSH brute force is less commonly defended and is a strong lateral movement indicator. Tools: hydra, medusa, custom scripts, Metasploit ssh_login. Build $SSH_HEALTHCHECKS allowlist for monitoring tools that legitimately make short SSH connections (uptime checkers, configuration drift detection). After exclusions, this pattern is essentially always either red team or active threat actor.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH brute force in operations targeting Linux infrastructure." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH credential attacks in operations." },
          { cls: "apt-mul", name: "Cryptominers", note: "SSH brute force universal in cryptominer operations (Sysrv-hello, Kinsing)." },
          { cls: "apt-mul", name: "Multi", note: "Documented in cryptominer operations and in advanced threat operations targeting Linux infrastructure." }
        ],
        cite: "MITRE ATT&CK T1021.004, T1110"
      }
    ]
  },
  {
    id: "T1021.006",
    name: "Remote Services: Windows Remote Management",
    desc: "WinRM / PowerShell Remoting - WS-Management traffic on TCP/5985-5986, Evil-WinRM, sustained PSSessions",
    rows: [
      {
        sub: "T1021.006 - Source/Destination",
        indicator: "WinRM connection from non-admin source - TCP/5985 / 5986 lateral movement",
        arkime: `ip.src == $INTERNAL
&& ip.src != $WINRM_ADMINS
&& port.dst == [5985 || 5986]
&& protocols == http
&& session.duration > 5`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $WINRM_ADMINS
AND destination.port: (5985 OR 5986)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [5985,5986]
  (msg:"TA0008 T1021.006 WinRM
    connection non-admin source
    lateral movement";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9100601; rev:1;)`,
        notes: "WinRM is rarely used in environments without explicit deployment - most workstations don't speak it, and the WinRM service is disabled by default on workstation editions. Server-to-server WinRM is more common (Exchange, SCCM, PowerShell-based automation), but workstation-to-server or peer WinRM is anomalous. Build $WINRM_ADMINS allowlist tightly. The detection has very low false-positive rate after exclusions because legitimate WinRM use is concentrated in specific known sources. Pair with PowerShell logging (Event ID 4103/4104) on destination hosts for definitive correlation. Adversary tools that use WinRM: PowerShell Remoting (native), Evil-WinRM, Invoke-Command in scripts, Cobalt Strike's PowerShell pivot.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "WinRM use documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "WinRM extensively used in SolarWinds compromise - Enter-PSSession to maintain hands-on-keyboard access." },
          { cls: "apt-cn", name: "APT41", note: "WinRM lateral movement in operations against technology sector." },
          { cls: "apt-mul", name: "Ransomware", note: "WinRM-based lateral movement in modern ransomware operations as alternative to PsExec." },
          { cls: "apt-mul", name: "Multi", note: "Documented across modern advanced threat operations." }
        ],
        cite: "MITRE ATT&CK T1021.006, CISA AA23-320A"
      },
      {
        sub: "T1021.006 - Source/Destination",
        indicator: "WinRM fan-out from single source - one host running PSSession to many destinations",
        arkime: `ip.src == $INTERNAL
&& port.dst == [5985 || 5986]
&& unique-dst-count groupby
  ip.src > 5 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (5985 OR 5986)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [5985,5986]
  (msg:"TA0008 T1021.006 WinRM
    fan-out single source many
    destinations";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 5, seconds 600;
  classtype:trojan-activity;
  sid:9100602; rev:1;)`,
        notes: "Adversaries with valid credentials often use Invoke-Command -ComputerName @($targets) to fan out PowerShell execution across many hosts simultaneously. The network pattern: one source establishing WinRM connections to 5+ distinct destinations within 10 minutes. Legitimate management automation (Ansible, custom PowerShell DSC) can produce similar patterns from sanctioned automation hosts - these should be in $WINRM_ADMINS or a separate $AUTOMATION_HOSTS exclusion. After exclusions, fan-out from non-automation sources is essentially always either red team operations or active threat actor activity. Particularly clean signal in environments where PowerShell-based mass administration isn't used.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "WinRM fan-out documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "Invoke-Command fan-out for parallel execution across compromised hosts." },
          { cls: "apt-cn", name: "APT41", note: "PowerShell Remoting fan-out in operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Fan-out for parallel encryption deployment." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat operations and ransomware playbooks. Particularly common in operations targeting AD-integrated server environments." }
        ],
        cite: "MITRE ATT&CK T1021.006"
      },
      {
        sub: "T1021.006 - WS-Management Protocol",
        indicator: "WS-Management SOAP request - wsman endpoint pattern",
        arkime: `ip.src == $INTERNAL
&& port.dst == [5985 || 5986]
&& protocols == http
&& http.uri == "*/wsman*"
&& http.method == POST
&& http.user-agent == "*Microsoft WinRM Client*"`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (5985 OR 5986)
AND url.path: */wsman*
AND http.request.method: "POST"
AND user_agent.original: *Microsoft WinRM Client*`,
        suricata: `alert http $HOME_NET any
  -> $HOME_NET [5985,5986]
  (msg:"TA0008 T1021.006 WS-Management
    SOAP POST to wsman endpoint";
  flow:established,to_server;
  content:"POST"; http.method;
  content:"/wsman"; http.uri;
  content:"Microsoft WinRM Client";
  http.header;
  classtype:trojan-activity;
  sid:9100603; rev:1;)`,
        notes: "The WS-Management protocol uses HTTP POST to the /wsman endpoint with SOAP envelope payloads. The User-Agent for the native Windows client is 'Microsoft WinRM Client' - distinctive and rarely spoofed even by adversary tools. PowerShell Remoting and Invoke-Command both use the native client. Evil-WinRM and other Ruby/Python-based tools have their own User-Agent strings (often 'Ruby' or 'Python-Requests') - those are different signatures. The native client is the dominant pattern in operations using PowerShell. WinRM HTTP traffic IS encrypted at the application layer (Kerberos/SPNEGO wrap-and-unwrap on the SOAP body), so the User-Agent and URI are visible but content isn't - perfect for detection without privacy concerns.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "PowerShell Remoting via native WinRM client in SolarWinds compromise." },
          { cls: "apt-cn", name: "APT41", note: "WinRM client traffic in operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "PowerShell Remoting documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Multi", note: "Documented in Microsoft and Mandiant research as primary lateral movement detection." }
        ],
        cite: "MITRE ATT&CK T1021.006"
      },
      {
        sub: "T1021.006 - Tool Fingerprints",
        indicator: "Evil-WinRM tool fingerprint - Ruby-based WinRM client signature",
        arkime: `ip.src == $INTERNAL
&& port.dst == [5985 || 5986]
&& protocols == http
&& http.user-agent == [
  *Ruby*
  || *Faraday*
]
&& http.uri == "*/wsman*"
// Note: Faraday match here is a substring match.
// Original regex anchored to start of UA (/^Faraday/).
// Pure Arkime cannot anchor on string start - the
// substring match may catch UAs containing "Faraday"
// elsewhere. Acceptable trade-off for this indicator.`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (5985 OR 5986)
AND user_agent.original: (*Ruby* OR Faraday*)
AND url.path: */wsman*`,
        suricata: `alert http $HOME_NET any
  -> $HOME_NET [5985,5986]
  (msg:"TA0008 T1021.006 Evil-WinRM
    Ruby Faraday client signature";
  flow:established,to_server;
  content:"/wsman"; http.uri;
  pcre:"/User-Agent:[^\\r\\n]*(Ruby|
    Faraday)/i"; http.header;
  classtype:trojan-activity;
  sid:9100604; rev:1;)`,
        notes: "Evil-WinRM is the most popular non-Microsoft WinRM client - written in Ruby, used heavily in red team operations and HackTheBox-style exploitation. It uses the Faraday HTTP library, producing User-Agent strings containing 'Ruby' or 'Faraday'. These are essentially never seen in legitimate enterprise WinRM traffic. The signature catches both the canonical Evil-WinRM and most Ruby-based custom WinRM clients. Detection is high-confidence: legitimate WinRM uses 'Microsoft WinRM Client' UA; Ruby/Faraday UA on /wsman = adversary tool. Sophisticated operators may patch Evil-WinRM to spoof the Microsoft UA, but most don't. Worth maintaining as low-cost coverage for the common case.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Standard red team tooling - Evil-WinRM in HackTheBox and OSCP exploitation." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Evil-WinRM use documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Ransomware", note: "Evil-WinRM in some ransomware operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA Scattered Spider advisory and in extensive red team training materials. Particularly common in operations against Linux-attacker-host setups targeting Windows environments." }
        ],
        cite: "MITRE ATT&CK T1021.006, CISA AA23-320A"
      },
      {
        sub: "T1021.006 - Interactive Sessions",
        indicator: "Sustained WinRM session - long-lived PSSession indicating interactive access",
        arkime: `ip.src == $INTERNAL
&& port.dst == [5985 || 5986]
&& session.duration > 1800
&& databytes.src > 50000
&& databytes.dst > 50000`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (5985 OR 5986)
AND event.duration > 1800000000
AND source.bytes > 50000
AND destination.bytes > 50000`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [5985,5986]
  (msg:"TA0008 T1021.006 Long-lived
    WinRM session sustained
    interactive access";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 1, seconds 1800;
  classtype:trojan-activity;
  sid:9100605; rev:1;)`,
        notes: "Most legitimate WinRM use is short-lived: Invoke-Command runs, returns output, disconnects. Sustained 30+ minute WinRM sessions indicate Enter-PSSession (interactive remote shell) - the adversary opens a PowerShell prompt on the target and works there. The pattern: long session with substantial bidirectional data flow. Legitimate use: rare - usually a sysadmin troubleshooting a specific issue interactively. Sustained interactive PSSessions, especially during off-hours or from non-admin sources, are essentially always either red team operations or threat actor lateral movement. Combine with hostname/destination analysis: Enter-PSSession to a domain controller from a workstation = high-confidence pre-DCSync activity.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Enter-PSSession extensively used in SolarWinds compromise for hands-on-keyboard activity." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Interactive PSSession documented in CISA AA23-320A." },
          { cls: "apt-cn", name: "APT41", note: "Interactive remote shell sessions in operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat actor operations. APT29's SolarWinds operation extensively used Enter-PSSession for hands-on-keyboard activity." }
        ],
        cite: "MITRE ATT&CK T1021.006"
      }
    ]
  },
  {
    id: "T1570",
    name: "Lateral Tool Transfer",
    desc: "Internal tool staging - bulk SMB file copies of executables/scripts/archives from non-fileserver sources",
    rows: [
      {
        sub: "T1570 - Lateral Tool Transfer",
        indicator: "Bulk SMB file copy from non-fileserver source - adversary tool staging",
        arkime: `ip.src == $INTERNAL
&& ip.src != $FILE_SERVERS
&& port.dst == 445
&& protocols == smb
&& smb.command == write
&& smb.filename == [
  *.exe
  || *.dll
  || *.bat
  || *.ps1
  || *.vbs
  || *.7z
  || *.zip
  || *.rar
]
&& session-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $FILE_SERVERS
AND destination.port: 445
AND smb.command: "write"
AND file.name: /.+\\.(exe|dll|bat|ps1|vbs|7z|zip|rar)$/`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1570 Bulk executable
    write to SMB tool staging";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  pcre:"/\\.(exe|dll|bat|ps1|vbs|7z|
    zip|rar)/i";
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:trojan-activity;
  sid:9157001; rev:1;)`,
        notes: "After establishing a foothold, adversaries copy tools to multiple internal hosts: PsExec, BloodHound, Cobalt Strike beacons, custom binaries, archive files containing tool collections. The pattern: bulk SMB write of executable/script/archive files from one non-file-server source. Build $FILE_SERVERS allowlist (sanctioned file servers, SCCM distribution points). After exclusions, sustained executable file writes via SMB from a workstation source = adversary tool staging. Particularly powerful when destinations are administrative shares (combine with sid 9100203 for ADMIN$ writes specifically). Pair with EDR file-creation events on destination hosts for definitive correlation. Sophisticated adversaries sometimes archive their tools (.7z, .rar, .zip with passwords) to defeat content inspection - extension monitoring catches this anyway.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Tool staging documented in CISA AA23-320A operations - pre-encryption tool deployment." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal pre-encryption tool staging - most visible phase of ransomware operations." },
          { cls: "apt-ru", name: "APT29", note: "Tool staging in espionage operations including SolarWinds." },
          { cls: "apt-cn", name: "APT41", note: "Tool deployment via SMB across operations." },
          { cls: "apt-mul", name: "Multi", note: "Universal across advanced threat operations and ransomware playbooks. The pre-encryption tool staging phase is where ransomware operators are most visible." }
        ],
        cite: "MITRE ATT&CK T1570, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1210",
    name: "Exploitation of Remote Services",
    desc: "Wormable lateral movement via service exploits - EternalBlue (MS17-010), ZeroLogon, PrintNightmare",
    rows: [
      {
        sub: "T1210 - EternalBlue",
        indicator: "EternalBlue / SMB1 exploit pattern - MS17-010 trans2 abuse",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.dialect == [
  NT LM 0.12 || PC NETWORK PROGRAM 1.0
]
&& smb.command == [
  trans2 || nt_trans
]
// EternalBlue's SMB header byte signature
// (\\xff\\x53\\x4d\\x42\\x32 = "\\xffSMB2") requires
// regex on binary payload - not expressible in
// pure Arkime. See Suricata pcre column.
// Logical spec: payload matches /\\xff\\x53\\x4d\\x42\\x32/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.dialect: ("NT LM 0.12" OR "PC NETWORK PROGRAM 1.0")
AND smb.command: ("trans2" OR "nt_trans")`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1210 EternalBlue
    MS17-010 SMB1 trans2 exploit
    pattern";
  flow:established,to_server;
  content:"|ff 53 4d 42 32|";
  content:"|00 00 00 00 00 00 00 00|";
  within:50;
  content:"|fe 00 00 00|"; within:200;
  classtype:trojan-activity;
  sid:9121001; rev:1;)`,
        notes: "EternalBlue (MS17-010, CVE-2017-0144) is the SMB1 vulnerability used by WannaCry, NotPetya, and many subsequent attacks. The exploit uses crafted SMB1 trans2/nt_trans requests with specific patterns that produce a buffer overflow in the SMB driver. Detection at the SMB1 dialect level catches the vulnerable protocol use; combined with trans2/nt_trans commands and characteristic byte patterns, near-zero false positive rate. Modern environments should disable SMB1 entirely - but it remains active in many legacy OT, healthcare, and embedded systems. Maintaining detection coverage is important even though widespread exploitation has decreased - particularly in environments where MS17-010 patching is incomplete (which is many environments). The signature catches both Metasploit's eternalblue module and direct PoC implementations.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "EternalBlue used in WannaCry (May 2017) - attributed to North Korea by US, UK, and other governments." },
          { cls: "apt-ru", name: "APT28", note: "EternalBlue use in NotPetya (June 2017) - attributed to Russian military intelligence (Sandworm)." },
          { cls: "apt-mul", name: "WannaCry", note: "Self-propagating ransomware that spread via EternalBlue in May 2017, hitting 200,000+ systems globally." },
          { cls: "apt-mul", name: "NotPetya", note: "Destructive wiper masquerading as ransomware - caused $10B+ damages in June 2017." },
          { cls: "apt-mul", name: "Multi", note: "Continues to appear in operations against legacy systems. Documented in CISA Alert TA17-132A and extensive industry reporting." }
        ],
        cite: "MITRE ATT&CK T1210, CVE-2017-0144, CISA TA17-132A"
      },
      {
        sub: "T1210 - ZeroLogon",
        indicator: "ZeroLogon exploit - MS-NRPC NetrServerAuthenticate3 with all-zero client credential",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345678-1234-abcd-ef00-01234567cffb
&& dcerpc.opnum == 26
// ZeroLogon all-zero credential signature requires
// regex on binary payload - not expressible in pure
// Arkime. See Suricata pcre column.
// Logical spec: payload matches /\\x00{16}/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345678-1234-abcd-ef00-01234567cffb"
AND dcerpc.opnum: 26`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0008 T1210 ZeroLogon
    CVE-2020-1472 NetrServer
    Authenticate3 zero credential";
  flow:established,to_server;
  content:"|78 56 34 12 34 12 cd ab|";
  content:"|00 00 00 00 00 00 00 00|";
  distance:0; within:200;
  content:"|00 00 00 00 00 00 00 00|";
  distance:0; within:50;
  classtype:trojan-activity;
  sid:9121002; rev:1;)`,
        notes: "ZeroLogon (CVE-2020-1472) is a critical authentication bypass in MS-NRPC (Netlogon Remote Protocol) - the AES-CFB8 implementation has a flaw where 1-in-256 attempts with all-zero ciphertext succeed. Exploits send NetrServerAuthenticate3 calls (NETLOGON interface UUID 12345678-1234-abcd-ef00-01234567cffb, opnum 26) with all-zero client credentials repeatedly until success. Network signature: NetrServerAuthenticate3 calls with zero-byte client credential fields, often in rapid bursts (the exploit needs ~256 attempts on average). Detection: count NetrServerAuthenticate3 calls per source per minute - burst patterns indicate active exploitation. Microsoft patched in August 2020; environments with unpatched DCs remain critically vulnerable. Pair with subsequent DCSync activity (which often follows successful ZeroLogon) for kill-chain visibility.",
        apt: [
          { cls: "apt-ir", name: "MuddyWater", note: "ZeroLogon exploitation in operations against government targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Rapidly weaponized post-disclosure - used by Ryuk, Conti, and others to compromise domain controllers." },
          { cls: "apt-mul", name: "Ryuk", note: "Ryuk ransomware operators used ZeroLogon for DC compromise in late 2020 operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA Emergency Directive 20-04 and extensive industry reporting. Rapidly weaponized after disclosure in 2020." }
        ],
        cite: "MITRE ATT&CK T1210, CVE-2020-1472, CISA ED 20-04"
      },
      {
        sub: "T1210 - PrintNightmare",
        indicator: "PrintNightmare exploit - RpcAddPrinterDriverEx with malicious driver path",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345678-1234-abcd-ef00-0123456789ab
&& dcerpc.opnum == 89
&& payload == [
  *\\??\\UNC\\*
  || *.dll*
]
// Full UNC-path-with-DLL signature requires regex - the
// list above catches the components. See Suricata pcre column.
// Logical spec: payload matches /\\\\\\?\\?\\\\UNC\\\\|\\\\\\\\.+\\\\.+\\.dll/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345678-1234-abcd-ef00-0123456789ab"
AND dcerpc.opnum: 89`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0008 T1210 PrintNightmare
    RpcAddPrinterDriverEx exploit";
  flow:established,to_server;
  content:"|78 56 34 12 34 12 cd ab|";
  pcre:"/(\\\\\\?\\\\UNC\\\\|
    \\\\\\\\[^\\x00]+\\.dll)/i";
  classtype:trojan-activity;
  sid:9121003; rev:1;)`,
        notes: "PrintNightmare (CVE-2021-1675, CVE-2021-34527) is a vulnerability in the Windows Print Spooler service - RpcAddPrinterDriverEx (opnum 89 in the spoolss interface) accepts a driver path that the spooler loads with SYSTEM privileges, allowing arbitrary code execution. Exploits provide UNC paths to remote DLLs (\\\\attacker\\share\\evil.dll) that get loaded as printer drivers. Network signature: RpcAddPrinterDriverEx calls with UNC paths or .dll references in the parameters. Detection challenge: legitimate printer driver installation uses this same RPC - but only from sanctioned print servers (SCCM, your print management infrastructure). Build $PRINT_SERVERS allowlist; alert on RpcAddPrinterDriverEx from anywhere else. Microsoft has issued multiple patches; many environments still have unpatched systems particularly in OT and healthcare networks.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "PrintNightmare exploitation in espionage operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Used by Conti, Vice Society, and other ransomware operators for privilege escalation and lateral movement." },
          { cls: "apt-mul", name: "Vice Society", note: "PrintNightmare in operations targeting education sector." },
          { cls: "apt-mul", name: "Conti", note: "PrintNightmare for SYSTEM-level execution in pre-encryption phase." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA alerts and extensive industry reporting since 2021." }
        ],
        cite: "MITRE ATT&CK T1210, CVE-2021-34527, CISA Alerts"
      }
    ]
  },
  {
    id: "T1563",
    name: "Remote Service Session Hijacking",
    desc: "RDP / SSH session takeover - tscon-based RDP hijacking, primarily host-side detection required",
    rows: [
      {
        sub: "T1563 - RDP Session Takeover",
        indicator: "RDP session takeover via tscon - disconnected session hijacking",
        arkime: `[Network detection of tscon-based
RDP session hijacking is limited.
The hijack is host-side: SYSTEM-
privileged tscon /dest:rdp-tcp
attaches to disconnected session.
Network signal limited to:
- Subsequent RDP traffic from
  hijacked session host
- Anomalous user activity from
  the destination IP]
Best detected via Windows
Event ID 4778 (session connect)
+ EDR command-line monitoring`,
        kibana: `[Network-only detection
limited - rely on host
event log correlation]`,
        suricata: `[T1563.002 RDP session hijacking
is primarily host-side. Network
indicators are limited to
post-hijack traffic anomalies
which look like normal RDP.
Host detection via Event 4778
and EDR is required.]
N/A pure network detection`,
        notes: "Microsoft's tscon.exe utility, when run with SYSTEM privileges, allows attaching to a disconnected RDP session WITHOUT requiring the original user's credentials - a classic privilege escalation and lateral movement technique. The full attack: adversary on Server X with SYSTEM access, identifies a disconnected RDP session belonging to a Domain Admin, runs 'tscon <session-id> /dest:rdp-tcp' and inherits the session. From the network perspective, the RDP traffic just continues - no new authentication, no new connection. Detection requires Windows Event ID 4778 (session connect) and EDR command-line monitoring for tscon.exe with /dest parameters. Mention here for kill-chain completeness - this is a critical lateral movement technique that network-only detection misses entirely. Pair with privileged user behavior analytics: a Domain Admin's session 'continuing' from a host they never logged into is the smoking gun.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "tscon RDP hijacking documented in Alexander Korznikov 2017 research and in red team operations." },
          { cls: "apt-mul", name: "Insider", note: "Particularly relevant for malicious insiders with shared admin server access." },
          { cls: "apt-mul", name: "Multi", note: "Documented in offensive security research. Particularly relevant for environments with shared admin servers." }
        ],
        cite: "MITRE ATT&CK T1563.002"
      }
    ]
  }
];
