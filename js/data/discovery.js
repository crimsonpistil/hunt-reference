// TA0007 — Discovery
// 10 techniques · 42 indicators · network-visible east-west detection focus

const DATA = [
  {
    id: "T1018",
    name: "Remote System Discovery",
    desc: "Host enumeration — ICMP/ARP sweeps, NetBIOS broadcasts, DNS PTR queries, SMB host probes",
    rows: [
      {
        sub: "T1018 — ICMP Sweeps",
        indicator: "ICMP echo sweep — single source pinging many internal hosts in a short window",
        arkime: `ip.src == $INTERNAL
&& protocols == icmp
&& icmp.type == 8
&& ip.dst == $INTERNAL
&& unique-dst-count groupby
  ip.src > 20 within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $INTERNAL
AND network.protocol: icmp
AND icmp.type: 8`,
        suricata: `alert icmp $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0007 T1018 ICMP echo
    sweep many internal hosts
    discovery";
  itype:8;
  threshold:type both,
    track by_src,
    count 20, seconds 60;
  classtype:attempted-recon;
  sid:9101801; rev:1;)`,
        notes: "The classic host-discovery primitive: ping every IP in a subnet, see who responds. nmap -sn, fping, PowerShell Test-Connection loops, custom scanners all produce this pattern. Suricata's `track by_src, count 20, seconds 60` aggregates by source — alerting only when one host pings 20+ distinct destinations in a minute. Tune the threshold to your environment: monitoring tools (Smokeping, sanctioned scanners) may legitimately ping many hosts and should be in $MONITORING_HOSTS exclusion. Workstations and servers shouldn't initiate ICMP sweeps. The detection is noisy in environments with active monitoring infrastructure — invest the time to build a clean exclusion list. Pair with EDR for definitive process attribution (ping.exe, nmap.exe, PowerShell, Python).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "ICMP host enumeration documented across operations against technology and gaming sectors." },
          { cls: "apt-ru", name: "APT29", note: "ICMP sweeps documented in espionage operations including SolarWinds compromise." },
          { cls: "apt-mul", name: "Ransomware", note: "ICMP sweeps universal in ransomware affiliate operations during pre-encryption network mapping." },
          { cls: "apt-mul", name: "Red Team", note: "Standard red team and pen test reconnaissance methodology." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and in virtually every major incident report covering the discovery phase." }
        ],
        cite: "MITRE ATT&CK T1018, industry reporting"
      },
      {
        sub: "T1018 — ICMP Sweeps",
        indicator: "ICMP fan-out from non-monitoring host — sustained ping pattern across multiple subnets",
        arkime: `ip.src == $INTERNAL
&& ip.src != $MONITORING_HOSTS
&& protocols == icmp
&& icmp.type == 8
&& unique-subnet-count groupby
  ip.src > 3 within 300s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $MONITORING_HOSTS
AND network.protocol: icmp
AND icmp.type: 8`,
        suricata: `alert icmp $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0007 T1018 ICMP fan-out
    across multiple subnets
    network reconnaissance";
  itype:8;
  threshold:type both,
    track by_src,
    count 100, seconds 300;
  classtype:attempted-recon;
  sid:9101802; rev:1;)`,
        notes: "More refined than sid 9101801: looks for ping activity spanning multiple subnets from one source within 5 minutes. Adversary doing network mapping pings 10.0.1.0/24, then 10.0.2.0/24, then 10.0.3.0/24 — covering the address space methodically. This pattern is much rarer than single-subnet pings (which can be legitimate broadcast-storm-investigation). Multi-subnet ICMP fan-out from a workstation is essentially always reconnaissance. Tune by counting distinct /24s touched: 3+ subnets = strong signal, 5+ = certain reconnaissance. Combine with packet timing analysis — adversary scanners often produce highly regular timing (every 10ms exactly), legitimate troubleshooting is bursty.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Multi-subnet host enumeration in operations against multi-VLAN enterprise environments." },
          { cls: "apt-kp", name: "Lazarus", note: "Network mapping documented in financial sector targeting." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate playbooks for pre-encryption target identification." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat actor operations and ransomware affiliate playbooks. Standard pre-lateral-movement reconnaissance." }
        ],
        cite: "MITRE ATT&CK T1018, industry threat hunting guidance"
      },
      {
        sub: "T1018 — ARP & NetBIOS Discovery",
        indicator: "ARP scan — high rate of ARP requests from single source covering address range",
        arkime: `ip.src == $INTERNAL
&& protocols == arp
&& arp.opcode == 1
&& unique-arp-target-count
  groupby ip.src > 50
  within 60s`,
        kibana: `source.mac: NOT null
AND network.protocol: arp
AND _exists_: arp.target_ip`,
        suricata: `[ARP-level traffic is often
not visible to Suricata
deployed on routed segments.
Detection requires sensors
on the L2 broadcast domain
or netflow/Zeek arp.log]
N/A standard Suricata`,
        notes: "ARP scans (arp-scan, nmap -PR, custom L2 scanners) flood the local broadcast domain with ARP requests for every address in a target range — building a layer-2 host inventory. The signal: one MAC sending 50+ ARP requests for distinct target IPs in 60 seconds. Detection requires L2 visibility — a sensor on the same VLAN as the source, or Zeek deployed at the broadcast domain. Most Suricata deployments are routed-segment monitoring and don't see ARP. If you have Zeek with arp analyzer enabled, arp.log captures every request with sender/target IPs. The detection is high-confidence: legitimate ARP traffic is bursty and small-scale (host coming online, gateway lookup) — sustained scan-rate ARP is essentially always reconnaissance. Particularly effective in flat networks (lab environments, IoT VLANs) where adversaries enumerate quickly.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "L2 host enumeration documented in offensive security tooling and red team operations." },
          { cls: "apt-mul", name: "Ransomware", note: "ARP scans common in ransomware affiliate operations — particularly in flat networks." },
          { cls: "apt-mul", name: "Insider", note: "Insider threat reconnaissance often uses ARP scans on local segments." },
          { cls: "apt-mul", name: "Multi", note: "Less commonly used by sophisticated nation-state actors who prefer stealthier passive techniques (NBNS, LLMNR observation), but standard fare for ransomware affiliates and lower-sophistication operations." }
        ],
        cite: "MITRE ATT&CK T1018, industry tooling"
      },
      {
        sub: "T1018 — ARP & NetBIOS Discovery",
        indicator: "NetBIOS Name Service queries — broadcast NBNS scanning for hostname enumeration",
        arkime: `ip.src == $INTERNAL
&& port.dst == 137
&& protocols == nbns
&& unique-nbns-target-count
  groupby ip.src > 30
  within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 137
AND network.protocol: netbios-ns`,
        suricata: `alert udp $HOME_NET any
  -> $HOME_NET 137
  (msg:"TA0007 T1018 NetBIOS NBNS
    name service query burst
    host enumeration";
  flow:to_server;
  threshold:type both,
    track by_src,
    count 30, seconds 60;
  classtype:attempted-recon;
  sid:9101803; rev:1;)`,
        notes: "NetBIOS Name Service (NBNS, UDP/137) is a legacy Windows hostname-resolution protocol. Adversaries use it for two reconnaissance patterns: (1) NBNS broadcasts to enumerate Windows hostnames in the local broadcast domain — nbtstat, nmap NSE scripts, custom tools (2) NBNS queries to specific IPs to retrieve their NetBIOS name — building a hostname/IP map. NBNS is mostly deprecated in modern AD environments (replaced by DNS) but still active in many networks for legacy compatibility. Workstation behavior: occasional NBNS queries during normal operation. Adversary behavior: rapid-fire NBNS to many distinct targets. Build per-source NBNS query rate baselines — adversary scans stand out clearly. Pair with LLMNR query analysis (UDP/5355) for the modern equivalent.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "NBNS scanning during Cloud Hopper operations against MSPs." },
          { cls: "apt-ru", name: "APT28", note: "NetBIOS enumeration for AD reconnaissance documented in espionage operations." },
          { cls: "apt-mul", name: "Ransomware", note: "NBNS enumeration appears in many ransomware affiliate playbooks targeting legacy environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and in standard pentest tooling (nbtscan, nmap nbstat NSE script)." }
        ],
        cite: "MITRE ATT&CK T1018, MITRE ATT&CK T1135"
      },
      {
        sub: "T1018 — DNS-Based Host Discovery",
        indicator: "Reverse DNS PTR queries against internal ranges — host enumeration via DNS",
        arkime: `ip.src == $INTERNAL
&& ip.src != $DNS_SERVERS
&& protocols == dns
&& dns.query-type == PTR
&& dns.host =~ /\\.in-addr\\.arpa$/
&& unique-ptr-count groupby
  ip.src > 50 within 300s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $DNS_SERVERS
AND dns.question.type: "PTR"
AND dns.question.name: *in-addr.arpa`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0007 T1018 Reverse DNS
    PTR query burst internal
    host enumeration";
  flow:stateless;
  dns.query;
  pcre:"/in-addr\\.arpa$/";
  threshold:type both,
    track by_src,
    count 50, seconds 300;
  classtype:attempted-recon;
  sid:9101804; rev:1;)`,
        notes: "Reverse DNS lookups (PTR queries against in-addr.arpa) resolve IP addresses to hostnames. Adversaries enumerate internal hostnames by issuing PTR queries against every IP in a target range — much stealthier than ICMP sweeps because DNS traffic is universally allowed and rarely scrutinized. Tools: nslookup loops, dnsrecon, custom PowerShell. The signal: a non-DNS-server internal host issuing 50+ PTR queries against in-addr.arpa zones in 5 minutes. DNS servers themselves do this legitimately when handling client lookups — exclude $DNS_SERVERS. Workstations and application servers should rarely issue bulk PTR queries. The query stream looks like 1.0.10.in-addr.arpa, 2.0.10.in-addr.arpa, 3.0.10.in-addr.arpa, etc. — easy pattern to spot in Zeek dns.log. Combine with EDR for nslookup.exe/PowerShell process attribution.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "DNS-based reconnaissance documented in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "DNS-based host enumeration in technology sector operations." },
          { cls: "apt-kp", name: "Lazarus", note: "DNS PTR enumeration in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Stealth alternative to ICMP sweeps — particularly useful in environments with strict ICMP egress filtering. Documented in MITRE ATT&CK and SANS threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1018, SANS hunting"
      },
      {
        sub: "T1018 — DNS-Based Host Discovery",
        indicator: "AD-integrated DNS zone transfer attempt — AXFR query against internal DNS",
        arkime: `ip.src == $INTERNAL
&& ip.src != $DNS_SERVERS
&& protocols == dns
&& dns.query-type == AXFR
&& port.dst == 53`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $DNS_SERVERS
AND dns.question.type: "AXFR"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 53
  (msg:"TA0007 T1018 DNS zone
    transfer AXFR attempt full
    zone enumeration";
  flow:established,to_server;
  content:"|00 00 fc 00 01|";
  classtype:attempted-recon;
  sid:9101805; rev:1;)`,
        notes: "AXFR (Authoritative Transfer) is a DNS query that requests a complete copy of a zone — every record. Used legitimately between primary and secondary DNS servers for zone replication. From any other source, AXFR is reconnaissance — the adversary is trying to enumerate every host in your AD-integrated DNS zone in a single query. Most environments restrict AXFR to specific source IPs at the DNS server level, but misconfigurations are common. The signal: AXFR query from any non-DNS-server internal host. Detection: Zeek dns.log captures the query type explicitly. AXFR uses TCP/53 (not UDP) because zone data is typically too large for UDP — Suricata content match looks for the type code 0x00fc (252, AXFR) in the question section. Block AXFR from non-replicate sources at DNS server config; alert on attempts.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "AXFR attempts documented in some operations targeting misconfigured DNS infrastructure." },
          { cls: "apt-ru", name: "APT28", note: "AXFR-based reconnaissance documented in espionage operations." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology (dnsrecon, fierce, dig)." },
          { cls: "apt-mul", name: "Multi", note: "Less commonly seen in modern advanced operations because most enterprises restrict AXFR — when it works, the signal is high-confidence adversary activity." }
        ],
        cite: "MITRE ATT&CK T1018, industry tooling"
      },
      {
        sub: "T1018 — SMB-Based Discovery",
        indicator: "SMB connection burst from single source — host enumeration via SMB probes",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& unique-dst-count groupby
  ip.src > 20 within 60s
&& ip.dst == $INTERNAL`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND destination.ip: $INTERNAL`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1018 SMB connection
    burst host enumeration";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  threshold:type both,
    track by_src,
    count 20, seconds 60;
  classtype:attempted-recon;
  sid:9101806; rev:1;)`,
        notes: "Adversaries enumerate hosts by attempting SMB connections — even unauthenticated, the SMB negotiate response reveals the host's existence, OS version (in older SMB1), domain name, and signing requirements. The signal is one source connecting to TCP/445 on 20+ distinct destinations in 60 seconds. Tools: nmap -p 445, CrackMapExec (cme), enum4linux, custom PowerShell loops. CrackMapExec specifically is an extremely common red team and threat actor tool — its initial enumeration phase produces this exact pattern. Build $SMB_LEGITIMATE_HOSTS for hosts that legitimately connect to many SMB destinations (DCs, file servers replicating, backup systems). Workstations connecting to many SMB destinations rapidly is anomalous. The pattern often immediately precedes lateral movement attempts.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SMB-based host enumeration via CrackMapExec documented in operations." },
          { cls: "apt-cn", name: "APT41", note: "SMB enumeration in operations against technology and gaming sectors." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate operations as pre-lateral-movement enumeration." },
          { cls: "apt-mul", name: "Scattered Spider", note: "CrackMapExec usage documented in CISA AA23-320A operations against hospitality and technology sectors." },
          { cls: "apt-mul", name: "Multi", note: "Pre-lateral-movement enumeration phase consistent across operations. Documented in CISA Scattered Spider advisory, ransomware incident reports, and standard red team tradecraft." }
        ],
        cite: "MITRE ATT&CK T1018, CISA AA23-320A"
      },
      {
        sub: "T1018 — SMB-Based Discovery",
        indicator: "SMB null session probe — anonymous SMB connection for host info gathering",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.username == ""
&& smb.session-setup == true`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.user.name: ""
AND _exists_: smb.session_setup`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1018 SMB null
    session anonymous probe
    host info gathering";
  flow:established,to_server;
  content:"|ff 53 4d 42 73|";
  content:"|00 00|"; distance:0;
  classtype:attempted-recon;
  sid:9101807; rev:1;)`,
        notes: "SMB null sessions are anonymous logons (empty username, empty password) that historically provided access to a wealth of information: user lists, group memberships, domain SIDs, share lists. Modern Windows defaults block null session enumeration — but legacy systems, misconfigured shares, and Linux SMB implementations (Samba) often still permit them. Adversaries probe systematically: connect with null credentials, query the IPC$ share, enumerate everything available. The signal: SMB session_setup with empty username from a non-trusted host. Zeek smb.log captures usernames; smb_auth.log captures auth attempts including null sessions. Pair with EDR for correlation — net.exe with /user:\"\" (empty), enum4linux, rpcclient anonymous binds.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Null sessions used in MSP targeting during Cloud Hopper." },
          { cls: "apt-ru", name: "APT28", note: "Null sessions in operations against legacy government systems." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology — enum4linux, rpcclient anonymous binds." },
          { cls: "apt-mul", name: "Multi", note: "Documented in standard pentest methodology and in nation-state operations targeting legacy environments." }
        ],
        cite: "MITRE ATT&CK T1018, T1087, industry tooling"
      }
    ]
  },
  {
    id: "T1046",
    name: "Network Service Discovery",
    desc: "Port scans and service enumeration — TCP SYN scans, horizontal sweeps, banner grabs, scanner fingerprints",
    rows: [
      {
        sub: "T1046 — TCP Port Scans",
        indicator: "TCP SYN scan — half-open probes to many ports on single target",
        arkime: `ip.src == $INTERNAL
&& ip.src != $SCAN_SOURCES
&& protocols == tcp
&& tcp.flags == S
&& unique-dst-port-count
  groupby ip.src,ip.dst > 30
  within 60s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $SCAN_SOURCES
AND tcp.flags: "S"
AND NOT tcp.flags: "A"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0007 T1046 TCP SYN scan
    many ports single target";
  flags:S,12;
  threshold:type both,
    track by_src,
    count 30, seconds 60;
  classtype:attempted-recon;
  sid:9104601; rev:1;)`,
        notes: "The most fundamental port scan: send SYN packets to many destination ports on a single target. Open ports respond with SYN-ACK, closed ports with RST, filtered ports drop silently. nmap -sS (default scan), masscan, zmap, custom scanners all produce this pattern. Detection: count distinct destination ports per (src, dst) pair — 30+ in 60s is essentially certain scanning behavior. False positives: legitimate vulnerability scanners (Nessus, Qualys, Rapid7, OpenVAS) produce identical patterns and MUST be in $SCAN_SOURCES exclusion. Build the exclusion carefully — these scanners often run from dedicated VLANs or specific source IPs. After exclusions, this detection is near-zero-FP. Pair with EDR for nmap.exe, masscan, PowerShell Test-NetConnection loops attribution.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Port scanning documented across operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Port scanning in financial sector targeting." },
          { cls: "apt-ru", name: "APT29", note: "Port scanning in espionage operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate operations during pre-encryption network mapping." },
          { cls: "apt-mul", name: "Multi", note: "Every advanced threat actor performs port scanning during the discovery phase. Documented in MITRE ATT&CK and in essentially every major incident report." }
        ],
        cite: "MITRE ATT&CK T1046, industry reporting"
      },
      {
        sub: "T1046 — TCP Port Scans",
        indicator: "Horizontal port sweep — single port across many hosts (service discovery)",
        arkime: `ip.src == $INTERNAL
&& ip.src != $SCAN_SOURCES
&& protocols == tcp
&& port.dst == [
  22 || 445 || 3389 || 5985
  || 5986 || 1433 || 3306
  || 5432 || 6379 || 27017
]
&& unique-dst-count groupby
  ip.src,port.dst > 20
  within 60s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $SCAN_SOURCES
AND destination.port: (
  22 OR 445 OR 3389 OR 5985
  OR 5986 OR 1433 OR 3306
  OR 5432 OR 6379 OR 27017
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [22,445,3389,
   5985,5986,1433,3306,5432,
   6379,27017]
  (msg:"TA0007 T1046 Horizontal
    port sweep specific service
    across many hosts";
  flow:to_server;
  flags:S;
  threshold:type both,
    track by_src,
    count 20, seconds 60;
  classtype:attempted-recon;
  sid:9104602; rev:1;)`,
        notes: "Horizontal scan = one port, many hosts. The adversary wants to find every host running a specific service: every SSH server (22), every SMB share (445), every RDP host (3389), every WinRM endpoint (5985/5986), every SQL server (1433/3306/5432), every Redis (6379), every MongoDB (27017). This is the most common scan pattern in lateral movement preparation — find the target service, then attempt credential abuse against it. The signal is much cleaner than vertical scans because legitimate clients don't connect to one service across 20+ hosts in a minute (DCs and management hosts are rare exceptions). Build $SERVICE_CLIENTS allowlist for legitimate per-service-port traffic patterns. Workstations sweeping RDP across many hosts = essentially always pre-lateral-movement reconnaissance.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A — RDP/SSH sweeps for lateral movement." },
          { cls: "apt-ru", name: "APT29", note: "Service enumeration in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Horizontal sweeps in technology sector targeting." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware operations — find all RDP/SMB hosts before lateral movement." },
          { cls: "apt-mul", name: "Multi", note: "CrackMapExec, BloodHound's collector, custom PowerShell loops all produce this pattern. Documented in CISA Scattered Spider advisory and ransomware incident reporting." }
        ],
        cite: "MITRE ATT&CK T1046, CISA AA23-320A"
      },
      {
        sub: "T1046 — TCP Port Scans",
        indicator: "Common-port-set probe — nmap default top-1000-ports scan signature",
        arkime: `ip.src == $INTERNAL
&& ip.src != $SCAN_SOURCES
&& protocols == tcp
&& tcp.flags == S
&& dst-port-set-overlap-with
  nmap-top-1000 > 80%
&& session-count groupby
  ip.src,ip.dst > 100
  within 120s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $SCAN_SOURCES
AND tcp.flags: "S"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0007 T1046 Likely nmap
    top ports scan many ports
    single host";
  flow:to_server;
  flags:S;
  threshold:type both,
    track by_src,
    count 100, seconds 120;
  classtype:attempted-recon;
  sid:9104603; rev:1;)`,
        notes: "nmap's default scan probes the 'top 1000' most common ports — a specific list defined in nmap's services file. The set has characteristic patterns: dense in the 1-1024 range, includes common service ports (445, 3389, 1433, 5985), specific high ports (8080, 8443, 27017, 50000). Detection at the port-set level (rather than just count) increases confidence — the probability of legitimate traffic touching exactly nmap's top-1000 set is essentially zero. Implementation in Zeek via custom scripts or in your SIEM via aggregation+set-membership analysis. Suricata's threshold-based approach is simpler but noisier — 100+ SYN connections to one host in 120 seconds catches the volume signature. Pair with Zeek conn.log for the precise port set.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Default nmap scans common in red team operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Default nmap scans appear in lower-sophistication ransomware affiliate operations." },
          { cls: "apt-cn", name: "APT41", note: "Documented use of nmap with default parameters in some operations." },
          { cls: "apt-mul", name: "Multi", note: "Sophisticated nation-state operators typically use customized scan parameters but nmap defaults still appear regularly in incident response." }
        ],
        cite: "MITRE ATT&CK T1046, industry tooling"
      },
      {
        sub: "T1046 — Service Banner Grabs & Version Probes",
        indicator: "SSH banner grab — opening connection to TCP/22 and reading banner without authentication",
        arkime: `ip.src == $INTERNAL
&& ip.src != $SSH_CLIENTS
&& port.dst == 22
&& protocols == ssh
&& session.duration < 5
&& packets.src < 5
&& unique-dst-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $SSH_CLIENTS
AND destination.port: 22
AND event.duration < 5000000
AND network.packets < 5`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 22
  (msg:"TA0007 T1046 SSH banner
    grab pattern many short
    connections";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:attempted-recon;
  sid:9104604; rev:1;)`,
        notes: "SSH banners are sent in cleartext by both client and server during the initial handshake before encryption. Banner-grab tools (nmap -sV, ssh banner scanners, custom Python) connect, read the banner, disconnect — producing very short-duration connections (<5 seconds) with minimal packets. The banner reveals the SSH implementation and version (OpenSSH_8.9p1, dropbear_2022.83, libssh_0.10.4) — useful for adversary target selection (vulnerable versions, fingerprinting). Detection: short SSH connections with low packet count from a non-typical-SSH-client host to many destinations. Build $SSH_CLIENTS allowlist for hosts that legitimately initiate SSH (admin workstations, automation accounts). Most workstations don't initiate SSH at all.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH banner enumeration in Linux-heavy environments." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH enumeration in financial sector targeting." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology." },
          { cls: "apt-mul", name: "Multi", note: "Particularly relevant for Linux-heavy environments. Documented in standard pentest methodology and in advanced threat actor reconnaissance." }
        ],
        cite: "MITRE ATT&CK T1046, industry tooling"
      },
      {
        sub: "T1046 — Service Banner Grabs & Version Probes",
        indicator: "HTTP server banner / version probe — methodical Server header collection",
        arkime: `ip.src == $INTERNAL
&& ip.src != $WEB_CLIENTS
&& protocols == http
&& http.method == [HEAD || OPTIONS]
&& session.duration < 5
&& unique-dst-count groupby
  ip.src > 20 within 300s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $WEB_CLIENTS
AND http.request.method: (
  "HEAD" OR "OPTIONS"
)
AND event.duration < 5000000`,
        suricata: `alert http $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0007 T1046 HTTP HEAD or
    OPTIONS probe burst banner
    enumeration";
  flow:established,to_server;
  content:"HEAD "; depth:5;
  threshold:type both,
    track by_src,
    count 20, seconds 300;
  classtype:attempted-recon;
  sid:9104605; rev:1;)`,
        notes: "HTTP HEAD and OPTIONS methods retrieve response headers without the body — perfect for banner grabbing. Adversaries use them to identify web server implementations (Apache 2.4.x, nginx 1.20.x, IIS 10.0), application versions (X-Powered-By: PHP/8.1.0), and exposed methods. Tools: nmap -sV with HTTP probes, nikto, Burp Suite, custom Python (requests.head()). The signal: many HEAD/OPTIONS requests from one source to many distinct internal web servers. Browsers don't typically issue HEAD requests; standard application traffic uses GET/POST. Vulnerability scanners (Nessus, Qualys) issue HEAD probes — exclude their source IPs. After exclusions, sustained HEAD/OPTIONS bursts are reconnaissance.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Web server enumeration in operations targeting web-facing infrastructure." },
          { cls: "apt-ir", name: "APT33", note: "HTTP enumeration in energy sector targeting." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology — nikto, Burp Suite scanner." },
          { cls: "apt-mul", name: "Multi", note: "Documented in standard pentest methodology and in nation-state pre-exploitation reconnaissance." }
        ],
        cite: "MITRE ATT&CK T1046, industry tooling"
      },
      {
        sub: "T1046 — Service Banner Grabs & Version Probes",
        indicator: "SNMP enumeration — community string brute force or systematic OID walk",
        arkime: `ip.src == $INTERNAL
&& ip.src != $SNMP_MGMT
&& protocols == snmp
&& port.dst == 161
&& unique-dst-count groupby
  ip.src > 10 within 60s`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $SNMP_MGMT
AND destination.port: 161
AND network.protocol: snmp`,
        suricata: `alert udp $HOME_NET any
  -> $HOME_NET 161
  (msg:"TA0007 T1046 SNMP query
    burst enumeration or community
    string brute force";
  flow:to_server;
  threshold:type both,
    track by_src,
    count 10, seconds 60;
  classtype:attempted-recon;
  sid:9104606; rev:1;)`,
        notes: "SNMP (UDP/161) provides extensive system information when accessible: network interface lists, routing tables, ARP caches, running processes, installed software. Default community strings ('public' for read, 'private' for read-write) are still common in many environments — a goldmine for adversaries. Tools: snmpwalk, snmpcheck, onesixtyone (community string brute force), nmap snmp-* NSE scripts. The signal: SNMP requests from non-management-host sources, especially with bursts to many distinct devices (community string sprays) or sustained traffic to one device (full OID walks). Build $SNMP_MGMT allowlist for sanctioned monitoring (LibreNMS, Observium, Zabbix, PRTG). Workstations and application servers shouldn't issue SNMP queries.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SNMP enumeration of network infrastructure documented." },
          { cls: "apt-ir", name: "APT33", note: "SNMP-based reconnaissance in energy sector operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Some ransomware operations include SNMP enumeration to identify network device targets." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat actor operations targeting network infrastructure (routers, switches, firewalls) for both reconnaissance and lateral movement to network device access." }
        ],
        cite: "MITRE ATT&CK T1046, industry reporting"
      },
      {
        sub: "T1046 — Scanner Tool Fingerprints",
        indicator: "Masscan / zmap fingerprint — extremely high-rate SYN scan with characteristic packet structure",
        arkime: `ip.src == $INTERNAL
&& protocols == tcp
&& tcp.flags == S
&& tcp.window-size == [
  1024 || 0
]
&& packet-rate groupby
  ip.src > 1000 within 10s`,
        kibana: `source.ip: $INTERNAL
AND tcp.flags: "S"
AND tcp.window: (1024 OR 0)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0007 T1046 Masscan or
    zmap high-rate SYN scan
    fingerprint";
  flow:stateless;
  flags:S;
  window:1024;
  threshold:type both,
    track by_src,
    count 500, seconds 10;
  classtype:attempted-recon;
  sid:9104607; rev:1;)`,
        notes: "masscan and zmap are mass-scanning tools designed for internet-wide scans — they produce SYN packets at rates 100-1000x higher than nmap (millions of packets per second possible). They use distinctive packet structures: small TCP window sizes (1024 or 0), specific TTL values, and hardcoded sequence number patterns. Detection: a single source generating 500+ SYN packets in 10 seconds is essentially never legitimate traffic — even aggressive vulnerability scanners run slower than this. Internal masscan use is rare but appears in some red team and ransomware affiliate operations for rapid pre-encryption network mapping. Tune the threshold based on your scanner allowlist — if Nessus runs at moderate rates, 500/10s catches masscan but not Nessus.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "High-rate scanning documented in modern ransomware operations where speed is critical (encrypt before being detected)." },
          { cls: "apt-mul", name: "Red Team", note: "masscan/zmap usage in red team operations for rapid network mapping." },
          { cls: "apt-mul", name: "Multi", note: "Sophisticated nation-state actors typically use slower, stealthier scans to avoid detection." }
        ],
        cite: "MITRE ATT&CK T1046, industry tooling"
      }
    ]
  },
  {
    id: "T1135",
    name: "Network Share Discovery",
    desc: "SMB share enumeration — srvsvc NetShareEnum, tree connect bursts, SYSVOL/IPC$ probes, DFS namespace queries",
    rows: [
      {
        sub: "T1135 — srvsvc Share Enumeration",
        indicator: "srvsvc NetShareEnum DCERPC call — canonical share enumeration primitive",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  4b324fc8-1670-01d3-1278-5a47bf6ee188
&& dcerpc.opnum == [15 || 16]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "4b324fc8-1670-01d3-1278-5a47bf6ee188"
AND dcerpc.opnum: (15 OR 16)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1135 srvsvc
    NetShareEnum DCERPC call
    share enumeration";
  flow:established,to_server;
  content:"|c8 4f 32 4b 70 16 d3 01|";
  classtype:attempted-recon;
  sid:9113501; rev:1;)`,
        notes: "The srvsvc RPC interface (UUID 4b324fc8-1670-01d3-1278-5a47bf6ee188) provides share management — including NetShareEnumAll (opnum 15) and NetShareEnum (opnum 16) which return the list of shares on a system. This is the underlying RPC call made by 'net view \\\\target', 'PowerView Get-NetShare', 'CrackMapExec --shares', and most share enumeration tools. Detection: Zeek dce_rpc.log captures the interface UUID and opnum explicitly. Suricata content match looks for the UUID bytes (in network byte order) in the DCERPC bind/call. Legitimate share enumeration: file explorers browsing network neighborhood, IT management tools. Suspicious: workstations or non-IT-admin accounts issuing NetShareEnum against many internal targets in sequence. Pair with subsequent SMB tree connect attempts to identified shares.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Share enumeration during SolarWinds compromise lateral movement." },
          { cls: "apt-cn", name: "APT41", note: "srvsvc enumeration in technology sector operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate operations during pre-encryption discovery." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Share enumeration documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Foundational share discovery primitive — used by virtually every advanced threat actor and ransomware operator. Documented in CISA Scattered Spider advisory, ransomware incident reports, and BloodHound data collection methodology." }
        ],
        cite: "MITRE ATT&CK T1135, CISA AA23-320A"
      },
      {
        sub: "T1135 — SMB Tree Connect Enumeration",
        indicator: "SMB tree connect to many distinct share names — share enumeration via tree connect attempts",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == tree-connect
&& unique-share-count groupby
  ip.src,ip.dst > 5
  within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "tree_connect"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1135 SMB tree
    connect burst many shares
    enumeration attempt";
  flow:established,to_server;
  content:"|ff 53 4d 42 75|";
  threshold:type both,
    track by_src,
    count 5, seconds 60;
  classtype:attempted-recon;
  sid:9113502; rev:1;)`,
        notes: "Some share enumeration tools work by attempting tree connects to common share names (ADMIN$, C$, IPC$, NETLOGON, SYSVOL, plus dictionary-based guesses like 'shared', 'public', 'data', 'backup'). The pattern: rapid sequence of tree_connect attempts with different UNC paths from one source to one target. Successful connects indicate accessible shares; access denied responses indicate the share exists but isn't accessible. Both responses are useful intelligence to the adversary. Zeek smb_files.log and smb.log capture tree connect operations. The signal is per-(src,dst) share count — 5+ distinct shares in a minute is anomalous (legitimate users typically connect to known shares, not enumerate many). Combine with successful-vs-denied response distribution: many denied = brute-force enumeration.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Tree connect enumeration in ransomware operations identifying writable shares for staging." },
          { cls: "apt-cn", name: "APT41", note: "Share probing in technology sector operations." },
          { cls: "apt-mul", name: "Red Team", note: "Standard red team enumeration via CrackMapExec --shares." },
          { cls: "apt-mul", name: "Multi", note: "Various PowerShell enumeration scripts. CrackMapExec --shares produces this pattern." }
        ],
        cite: "MITRE ATT&CK T1135, industry reporting"
      },
      {
        sub: "T1135 — SYSVOL & GPP Hunting",
        indicator: "SYSVOL enumeration burst — repeated access to domain controller SYSVOL share",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& ip.dst == $DOMAIN_CONTROLLERS
&& smb.share-name == [
  *SYSVOL* || *NETLOGON*
]
&& session-count groupby
  ip.src > 10 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $DOMAIN_CONTROLLERS
AND smb.share.name: (
  *SYSVOL* OR *NETLOGON*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0007 T1135 SYSVOL
    NETLOGON access burst possible
    GPP credential search";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  pcre:"/(SYSVOL|NETLOGON)/i";
  threshold:type both,
    track by_src,
    count 10, seconds 600;
  classtype:attempted-recon;
  sid:9113503; rev:1;)`,
        notes: "SYSVOL is the domain-controller share where Group Policy Objects (GPOs), startup/logon scripts, and ADMX templates are stored. Famously contained 'cpassword' values in Group Policy Preferences (GPP) until MS14-025 deprecated the feature — and many environments still have stale legacy GPP files with reversibly-encrypted credentials. Tools: PowerSploit Get-GPPPassword, BloodHound's data collection, Get-DomainPolicy. The signal: a single non-DC host doing repeated access to SYSVOL/NETLOGON shares — legitimate Group Policy processing happens on logon and at refresh intervals (~90 minutes), so burst access patterns are anomalous. Workstations should hit SYSVOL infrequently; sustained or rapid access is reconnaissance. Pair with EDR for PowerShell process correlation.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SYSVOL credential hunting in operations." },
          { cls: "apt-kp", name: "Lazarus", note: "GPP password extraction documented in financial sector operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal — GPP cpassword extraction is a standard ransomware affiliate technique." },
          { cls: "apt-mul", name: "Multi", note: "SYSVOL enumeration for GPP credential extraction is documented in MITRE ATT&CK T1552.006 and is a classic post-exploitation credential access technique." }
        ],
        cite: "MITRE ATT&CK T1135, T1552.006"
      },
      {
        sub: "T1135 — IPC$ Probes",
        indicator: "IPC$ probe sequence — anonymous IPC$ connections preceding share enumeration",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.share-name == IPC$
&& smb.username == ""
&& session-count groupby
  ip.src > 5 within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.share.name: "IPC$"
AND smb.user.name: ""`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1135 IPC$ anonymous
    probe burst share enumeration
    precursor";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  content:"IPC$"; nocase;
  threshold:type both,
    track by_src,
    count 5, seconds 300;
  classtype:attempted-recon;
  sid:9113504; rev:1;)`,
        notes: "IPC$ is the inter-process communication share — used as a transport for RPC calls including srvsvc share enumeration. Adversary tools first connect to IPC$ (often anonymously, sometimes with discovered credentials), then issue srvsvc calls through it to enumerate shares. The IPC$ connection sequence is more visible than the encrypted RPC payload. Multiple anonymous IPC$ connections from one source = enumeration sweep across hosts. Pair this with sid 9113501 (NetShareEnum DCERPC call) — together they confirm the full enumeration sequence. Anonymous IPC$ is restricted by default in modern Windows but legacy systems and Samba implementations often still permit it. Detection in Zeek smb.log captures the username and share access; null-username + IPC$ + many destinations = reconnaissance.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "IPC$ enumeration during MSP targeting in Cloud Hopper operations." },
          { cls: "apt-ru", name: "APT28", note: "Anonymous IPC$ probes in espionage operations against legacy government systems." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology — enum4linux, rpcclient anonymous binds." },
          { cls: "apt-mul", name: "Multi", note: "Documented in standard pentest methodology and in advanced threat actor reconnaissance." }
        ],
        cite: "MITRE ATT&CK T1135, industry tooling"
      },
      {
        sub: "T1135 — Bulk File Enumeration",
        indicator: "Bulk file share index access — File explorer-style directory enumeration across many shares",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == [
  find-first || find-next
  || query-directory
]
&& unique-path-count groupby
  ip.src > 50 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: (
  "find_first2" OR "find_next2"
  OR "query_directory"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1135 SMB directory
    query burst across many paths
    bulk enumeration";
  flow:established,to_server;
  content:"|ff 53 4d 42 32|";
  threshold:type both,
    track by_src,
    count 50, seconds 600;
  classtype:attempted-recon;
  sid:9113505; rev:1;)`,
        notes: "After identifying accessible shares, adversaries enumerate their contents — looking for credential files, configuration data, password lists, source code, customer databases. Tools: PowerShell Get-ChildItem -Recurse against UNC paths, Snaffler, manyriahs, custom scripts. The SMB protocol primitive is FIND_FIRST2/FIND_NEXT2 (SMB1) or QUERY_DIRECTORY (SMB2). The signal: rapid sequence of directory queries across many distinct paths from one source. Legitimate file usage typically focuses on a small set of paths at a time; rapid enumeration across 50+ paths in 10 minutes is reconnaissance. Snaffler in particular is increasingly common — it specifically searches for files matching credential patterns (web.config, *.kdbx, id_rsa, .git, unattend.xml). Pair with EDR.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Universal — pre-encryption file inventory and exfil target identification." },
          { cls: "apt-cn", name: "APT41", note: "Bulk enumeration in data theft operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Snaffler usage documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Universal in ransomware operations and in advanced threat actor data theft operations. Snaffler specifically is documented in CISA Scattered Spider advisory and in red team tradecraft." }
        ],
        cite: "MITRE ATT&CK T1135, T1083, CISA AA23-320A"
      },
      {
        sub: "T1135 — DFS Namespace Discovery",
        indicator: "DFS namespace enumeration — DFS referral query patterns",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == get-dfs-referral
&& session-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "get_dfs_referral"`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1135 DFS referral
    burst namespace enumeration";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:attempted-recon;
  sid:9113506; rev:1;)`,
        notes: "DFS (Distributed File System) provides a unified namespace across multiple file servers — \\\\domain.local\\dfs\\... resolves to the actual file server hosting the content. Adversaries query DFS namespaces to discover the full set of file servers and shares available across the domain. The SMB primitive is GET_DFS_REFERRAL — a specific SMB command type that's rarely used by typical clients (browsers and Office apps issue these only when accessing DFS-published paths). The signal: DFS referral burst from one source. Legitimate DFS clients issue referrals occasionally during access; sustained enumeration is anomalous. Particularly relevant in enterprises with extensive DFS deployments — discovery via DFS is much faster than manual share-by-share enumeration. Zeek smb.log captures DFS referral commands.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "DFS-based discovery in enterprise environments with extensive DFS deployments." },
          { cls: "apt-cn", name: "APT41", note: "DFS enumeration in operations against large enterprise targets." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology in DFS-heavy environments." },
          { cls: "apt-mul", name: "Multi", note: "DFS-based discovery is documented in advanced threat actor reconnaissance, particularly in operations against large enterprise environments with extensive DFS deployments." }
        ],
        cite: "MITRE ATT&CK T1135, industry reporting"
      }
    ]
  },
  {
    id: "T1087",
    name: "Account Discovery",
    desc: ".001 Local · .002 Domain · .003 Email · .004 Cloud — LDAP enumeration, BloodHound signatures, Kerberos pre-auth probing, SAMR RPC",
    rows: [
      {
        sub: "T1087.002 — Domain Account Discovery (LDAP)",
        indicator: "LDAP user enumeration query — search filter for all user objects",
        arkime: `ip.src == $INTERNAL
&& ip.src != $LDAP_CLIENTS
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /\\(objectClass=user\\)|
   \\(objectCategory=person\\)|
   \\(samAccountType=805306368\\)/
&& ldap.scope == subtree`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $LDAP_CLIENTS
AND destination.port: (389 OR 636)
AND ldap.filter: (
  *objectClass=user*
  OR *objectCategory=person*
  OR *samAccountType=805306368*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1087.002 LDAP user
    enumeration query bulk";
  flow:established,to_server;
  content:"objectClass=user";
  classtype:attempted-recon;
  sid:9108701; rev:1;)`,
        notes: "The canonical AD user enumeration filter: '(objectClass=user)' or its variants '(objectCategory=person)' and '(samAccountType=805306368)' — the SAM account type for normal users. With subtree scope, this returns every user object in the domain. Tools: PowerView Get-DomainUser, ldapsearch, ADSearch, BloodHound SharpHound (--CollectionMethods Default includes user enumeration), Get-ADUser -Filter *. Build $LDAP_CLIENTS allowlist for legitimate sources: AD-integrated applications, IT management tools, sanctioned admin workstations. Workstations and non-IT-admin accounts shouldn't issue bulk user enumeration queries. LDAPS (TCP/636) requires TLS inspection or Microsoft 4662 event log correlation; LDAP (TCP/389) is in cleartext and visible to Suricata. Microsoft Channel Binding and LDAP Signing requirements have made LDAP-on-389 increasingly rare in modern environments.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "LDAP enumeration during SolarWinds compromise." },
          { cls: "apt-cn", name: "APT41", note: "User enumeration in operations against AD environments." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware operations targeting AD environments." },
          { cls: "apt-mul", name: "Scattered Spider", note: "BloodHound usage extensively documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Multi", note: "Universal across AD-targeting threat actor operations. Documented in CISA AA23-320A, MITRE ATT&CK, and BloodHound documentation." }
        ],
        cite: "MITRE ATT&CK T1087.002, CISA AA23-320A"
      },
      {
        sub: "T1087.002 — BloodHound Signatures",
        indicator: "BloodHound SharpHound LDAP query signature — complex nested filter pattern",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /\\(\\|\\(samAccountType=
   805306368\\)\\(samAccountType=
   805306369\\)\\(samAccountType=
   536870912\\)\\(samAccountType=
   536870913\\)\\(objectCategory=
   group\\)\\(objectCategory=
   organizationalUnit\\)/
&& ldap.attributes-count > 20`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: *samAccountType=805306368*
AND ldap.filter: *samAccountType=805306369*
AND ldap.filter: *objectCategory=group*`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1087.002 BloodHound
    SharpHound LDAP query pattern";
  flow:established,to_server;
  content:"samAccountType=805306368";
  content:"samAccountType=805306369";
  distance:0; within:200;
  content:"objectCategory=group";
  distance:0; within:300;
  classtype:trojan-activity;
  sid:9108702; rev:1;)`,
        notes: "SharpHound (BloodHound's data collector) issues LDAP queries with a specific complex filter that combines multiple samAccountType values (users 805306368, machines 805306369, group-managed accounts 536870912/536870913) and objectCategory filters in a single OR clause. This combined filter is essentially never used by legitimate applications — it's a SharpHound fingerprint. Detection in Zeek ldap.log captures the full filter string; in Suricata, multi-content matching across the filter components catches the signature. SharpHound also requests an unusually large attribute set (20+ attributes per user object including samAccountName, memberOf, servicePrincipalName, userAccountControl, primaryGroupID, msDS-AllowedToDelegateTo) — additional confirmation. Legitimate AD enumeration tools request fewer, more targeted attributes.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "BloodHound use documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "BloodHound use in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "BloodHound use in operations against AD environments." },
          { cls: "apt-mul", name: "Ransomware", note: "BloodHound near-universal in ransomware affiliate operations." },
          { cls: "apt-mul", name: "Red Team", note: "BloodHound is the dominant AD attack path enumeration tool used by both red teams and threat actors." }
        ],
        cite: "MITRE ATT&CK T1087.002, T1018, CISA AA23-320A"
      },
      {
        sub: "T1087.002 — Kerberoasting Precursors",
        indicator: "LDAP query for service accounts — servicePrincipalName filter (Kerberoasting precursor)",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /\\(servicePrincipalName=
   \\*\\)|
   \\(.*servicePrincipalName.*\\)/
&& ldap.scope == subtree`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: *servicePrincipalName*`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1087.002 LDAP SPN
    query Kerberoasting precursor";
  flow:established,to_server;
  content:"servicePrincipalName";
  classtype:attempted-recon;
  sid:9108703; rev:1;)`,
        notes: "Service Principal Names (SPNs) identify Kerberos service instances — every domain account with an SPN can have a Kerberos service ticket requested for it, which can then be cracked offline (Kerberoasting). Adversaries query LDAP with filter '(servicePrincipalName=*)' to find all accounts with SPNs registered. Tools: PowerView Get-DomainUser -SPN, GetUserSPNs.py (Impacket), Rubeus, BloodHound. The query is the immediate precursor to T1558.003 Kerberoasting. Detection at the LDAP filter level catches the enumeration phase before the credential attack begins — early intervention opportunity. Legitimate apps occasionally query SPN attributes for specific accounts; the pattern '(servicePrincipalName=*)' (wildcard, returning all SPN-bearing accounts) is highly distinctive of attack tooling.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SPN enumeration documented in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Kerberoasting precursor documented across operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Extensively uses Kerberoasting per CISA AA23-320A." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate operations targeting AD." },
          { cls: "apt-mul", name: "Multi", note: "SPN enumeration as Kerberoasting precursor is documented across virtually all advanced threat actor operations and ransomware playbooks." }
        ],
        cite: "MITRE ATT&CK T1087.002, T1558.003, CISA AA23-320A"
      },
      {
        sub: "T1087.002 — ASREProasting Precursors",
        indicator: "LDAP query for accounts with PreAuth disabled — ASREProasting precursor",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /userAccountControl:1\\.2\\.840
   \\.113556\\.1\\.4\\.803:=4194304/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: *4194304*`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1087.002 LDAP query
    for DONT_REQ_PREAUTH accounts
    ASREProasting precursor";
  flow:established,to_server;
  content:"4194304";
  classtype:attempted-recon;
  sid:9108704; rev:1;)`,
        notes: "Accounts with the DONT_REQ_PREAUTH flag (UserAccountControl bit 0x400000 = 4194304) don't require Kerberos pre-authentication — the KDC will issue an AS-REP encrypted with the user's password hash to anyone who asks, allowing offline cracking (ASREProasting). The LDAP query filter to find these accounts uses the LDAP_MATCHING_RULE_BIT_AND OID '1.2.840.113556.1.4.803' against userAccountControl with value 4194304. Tools: GetNPUsers.py (Impacket), Rubeus, PowerView Get-DomainUser -PreauthNotRequired. The OID '1.2.840.113556.1.4.803:=4194304' is essentially unique to ASREProasting reconnaissance — legitimate applications don't query for this UAC flag combination. Pre-auth-disabled accounts are rare in modern environments (most have it enabled) but legacy service accounts and unix-integrated accounts often have it disabled.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "ASREProasting in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "ASREProasting precursor enumeration in operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "ASREProasting documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "ASREProasting common in ransomware affiliate operations targeting legacy accounts." },
          { cls: "apt-mul", name: "Multi", note: "Closely tied to T1558.004 ASREProasting. Documented in advanced threat actor operations and ransomware playbooks." }
        ],
        cite: "MITRE ATT&CK T1087.002, T1558.004"
      },
      {
        sub: "T1087.002 — SAMR RPC Enumeration",
        indicator: "SAMR EnumDomainUsers RPC call — RPC-based user enumeration",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345778-1234-abcd-ef00-0123456789ac
&& dcerpc.opnum == [13 || 14 || 15]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345778-1234-abcd-ef00-0123456789ac"
AND dcerpc.opnum: (13 OR 14 OR 15)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0007 T1087.002 SAMR
    EnumDomainUsers RPC call";
  flow:established,to_server;
  content:"|78 57 34 12 34 12 cd ab|";
  classtype:attempted-recon;
  sid:9108705; rev:1;)`,
        notes: "SAMR (Security Account Manager Remote) is the RPC interface for managing local and domain accounts. Interface UUID: 12345778-1234-abcd-ef00-0123456789ac. Key opnums for enumeration: SamrEnumerateDomainsInSamServer (opnum 6), SamrEnumerateUsersInDomain (opnum 13), SamrEnumerateGroupsInDomain (opnum 11), SamrEnumerateAliasesInDomain (opnum 15). This is the RPC-layer alternative to LDAP user enumeration — used by 'net user /domain', 'net group /domain', and various enumeration tools. Detection: Zeek dce_rpc.log captures the interface UUID and opnum. Suricata content match on the UUID byte pattern. Important note: Microsoft restricted SAMR access to non-admins in Windows 10 1607+ and added the SamrPwdNotRequired blocking — but legacy systems and some configurations still allow it. Pair with EDR for net.exe/PowerView attribution.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "SAMR enumeration during Cloud Hopper MSP targeting." },
          { cls: "apt-ru", name: "APT28", note: "SAMR enumeration in espionage operations." },
          { cls: "apt-mul", name: "Ransomware", note: "SAMR enumeration in ransomware affiliate operations against legacy environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and in numerous advanced threat actor operations. Documented in Microsoft security guidance and in BloodHound's SAMR collection methodology." }
        ],
        cite: "MITRE ATT&CK T1087.002, BloodHound documentation"
      },
      {
        sub: "T1087.002 — Kerberos Username Enumeration",
        indicator: "Kerberos pre-authentication probing — username enumeration via AS-REQ responses",
        arkime: `ip.src == $INTERNAL
&& port.dst == 88
&& protocols == kerberos
&& kerberos.msg-type == AS-REQ
&& kerberos.error-code == [
  KDC_ERR_C_PRINCIPAL_UNKNOWN
  || KDC_ERR_PREAUTH_REQUIRED
]
&& unique-username-count
  groupby ip.src > 30
  within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 88
AND kerberos.msg_type: "AS-REQ"
AND kerberos.error_code: (
  "KDC_ERR_C_PRINCIPAL_UNKNOWN"
  OR "KDC_ERR_PREAUTH_REQUIRED"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 88
  (msg:"TA0007 T1087.002 Kerberos
    AS-REQ error burst username
    enumeration";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 30, seconds 300;
  classtype:attempted-recon;
  sid:9108706; rev:1;)`,
        notes: "Kerberos AS-REQ responses leak username validity: 'KDC_ERR_C_PRINCIPAL_UNKNOWN' means the username doesn't exist; 'KDC_ERR_PREAUTH_REQUIRED' means the username exists but pre-auth is required (need a valid password). Adversaries enumerate usernames by sending AS-REQ for candidate names and parsing the error responses. Tools: kerbrute (Ropnop's username enumerator), MSF auxiliary/gather/kerberos_enumusers, GetUserSPNs.py with target list, Impacket. The signal: a single source generating many AS-REQ errors with these specific error codes. Zeek krb.log captures error codes explicitly. Threshold-based detection: 30+ unique usernames probed in 5 minutes is essentially always enumeration. Pair with subsequent password spray attempts (T1110.003) — username enumeration commonly precedes spraying.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Kerberos enumeration in SolarWinds and ongoing operations." },
          { cls: "apt-cn", name: "APT41", note: "Username enumeration in operations against AD environments." },
          { cls: "apt-ir", name: "APT33", note: "Kerberos enumeration in energy sector targeting." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Kerberos username enumeration documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all advanced threat actor operations targeting AD environments. Frequently precedes password spray attempts." }
        ],
        cite: "MITRE ATT&CK T1087.002, T1110.003, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1069",
    name: "Permission Groups Discovery",
    desc: ".001 Local · .002 Domain · .003 Cloud — Group membership enumeration via LDAP, BloodHound recursive queries, SAMR RPC, gMSA discovery",
    rows: [
      {
        sub: "T1069.002 — Privileged Group Enumeration",
        indicator: "LDAP query for privileged groups — Domain Admins / Enterprise Admins / Schema Admins membership",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /CN=Domain Admins|
   CN=Enterprise Admins|
   CN=Schema Admins|
   adminCount=1/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: (
  *Domain Admins*
  OR *Enterprise Admins*
  OR *Schema Admins*
  OR *adminCount=1*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1069.002 LDAP query
    for privileged group members";
  flow:established,to_server;
  pcre:"/(Domain Admins|
    Enterprise Admins|
    Schema Admins|
    adminCount=1)/i";
  classtype:attempted-recon;
  sid:9106901; rev:1;)`,
        notes: "Privileged group membership enumeration is the highest-value reconnaissance against AD. Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, and Server Operators are the standard targets. The 'adminCount=1' attribute is automatically set by AdminSDHolder on members of protected groups — querying for it returns all currently/previously privileged accounts. Tools: PowerView Get-DomainGroupMember -Identity 'Domain Admins', net group 'Domain Admins' /domain, Get-ADGroupMember (RSAT), BloodHound. Detection at the LDAP filter level is high-confidence — these specific group names appearing in queries from non-admin-tool sources is essentially always reconnaissance. Pair with EDR for tool attribution.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Privileged group enumeration during SolarWinds compromise." },
          { cls: "apt-cn", name: "APT41", note: "Domain Admin enumeration in operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A — direct precursor to lateral movement to DCs." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal — Domain Admin enumeration is standard pre-domain-takeover reconnaissance." },
          { cls: "apt-mul", name: "Multi", note: "Universal across AD-targeting threat operations. Direct precursor to T1078.002 Domain Account abuse and lateral movement to DCs." }
        ],
        cite: "MITRE ATT&CK T1069.002, CISA AA23-320A"
      },
      {
        sub: "T1069.002 — BloodHound Recursive Queries",
        indicator: "LDAP query for group memberOf chains — recursive group membership analysis",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /memberOf:1\\.2\\.840\\.113556
   \\.1\\.4\\.1941:=/
&& ldap.scope == subtree`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: *1.2.840.113556.1.4.1941*`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1069.002 LDAP_
    MATCHING_RULE_IN_CHAIN query
    recursive group enumeration";
  flow:established,to_server;
  content:"1.2.840.113556.1.4.1941";
  classtype:attempted-recon;
  sid:9106902; rev:1;)`,
        notes: "The LDAP_MATCHING_RULE_IN_CHAIN OID '1.2.840.113556.1.4.1941' performs recursive (transitive) group membership lookups — finding all users who are members of a group either directly OR through any chain of nested groups. Critical for adversaries because nested groups are extensively used in enterprise AD designs and direct member enumeration misses indirect access. Tools: PowerView Get-DomainGroupMember -Recurse, BloodHound (uses this OID extensively for path analysis), Get-ADGroupMember -Recursive. The OID is rarely used by legitimate applications — it's expensive (recursive expansion across the entire group hierarchy) and most apps prefer direct membership checks. Suricata content match on the OID string catches the signature definitively. Combined with target group name analysis (Domain Admins recursive lookup), this is one of the highest-confidence BloodHound indicators.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "BloodHound usage extensively documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "BloodHound use in SVR operations." },
          { cls: "apt-cn", name: "APT41", note: "BloodHound use in operations against AD environments." },
          { cls: "apt-mul", name: "Ransomware", note: "BloodHound near-universal in ransomware affiliate operations." },
          { cls: "apt-mul", name: "Multi", note: "BloodHound's signature query for attack path analysis. Documented in BloodHound source code, in Microsoft AD security guidance, and in CISA Scattered Spider advisory." }
        ],
        cite: "MITRE ATT&CK T1069.002, CISA AA23-320A"
      },
      {
        sub: "T1069.002 — SAMR Group Enumeration",
        indicator: "SAMR EnumDomainGroups RPC call — RPC-based group enumeration",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345778-1234-abcd-ef00-0123456789ac
&& dcerpc.opnum == [11 || 7 || 25]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345778-1234-abcd-ef00-0123456789ac"
AND dcerpc.opnum: (11 OR 7 OR 25)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0007 T1069.002 SAMR
    EnumDomainGroups RPC call";
  flow:established,to_server;
  content:"|78 57 34 12 34 12 cd ab|";
  classtype:attempted-recon;
  sid:9106903; rev:1;)`,
        notes: "SAMR (interface 12345778-1234-abcd-ef00-0123456789ac) opnum 11 is SamrEnumerateGroupsInDomain — equivalent to LDAP group enumeration but via RPC. Opnum 7 is SamrLookupNamesInDomain (resolve names to RIDs). Opnum 25 is SamrGetMembersInGroup. Tools: 'net group /domain', PowerView Get-DomainGroup, Impacket samrdump.py. SAMR-based enumeration is the older mechanism — most modern tools have migrated to LDAP — but legacy environments and specific RPC-based attack tools still produce SAMR traffic. Microsoft restricted non-admin SAMR access in Windows 10 1607+ via 'Restrict clients allowed to make remote calls to SAM' setting, but many environments don't enforce this. Pair with sid 9108705 (SAMR user enumeration) for full RPC-layer account/group discovery coverage.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "SAMR group enumeration during Cloud Hopper MSP targeting." },
          { cls: "apt-ru", name: "APT28", note: "SAMR-based group enumeration in espionage operations." },
          { cls: "apt-mul", name: "Ransomware", note: "SAMR enumeration in ransomware affiliate operations against legacy environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and in advanced threat actor operations against legacy AD environments." }
        ],
        cite: "MITRE ATT&CK T1069.002, T1087.002"
      },
      {
        sub: "T1069 — net.exe RPC Bursts",
        indicator: "net group / net localgroup execution — host-side enumeration with network-visible RPC traffic",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface == [
  samr || lsarpc
]
&& session-count groupby
  ip.src,ip.dst > 5
  within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: (
  "12345778-1234-abcd-ef00-0123456789ac"
  OR "12345778-1234-abcd-ef00-0123456789ab"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0007 T1069 SAMR or
    LSARPC burst from single host
    net group enumeration";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  threshold:type both,
    track by_src,
    count 5, seconds 60;
  classtype:attempted-recon;
  sid:9106904; rev:1;)`,
        notes: "'net group /domain', 'net localgroup administrators', 'net group \"Domain Admins\" /domain' all generate RPC traffic to a domain controller through SAMR and LSARPC interfaces. The exact RPC opnum sequence varies by command — but the burst of multiple SAMR/LSARPC calls from one source within seconds is a recognizable signature of net.exe enumeration. lsarpc UUID is 12345778-1234-abcd-ef00-0123456789ab (note: nearly identical to SAMR but ending 'ab' vs SAMR's 'ac'). Detection: count distinct RPC calls to AD interfaces from one source per minute — burst patterns indicate enumeration. Better detection lives at the EDR layer with command-line monitoring; network detection provides confirmation and ground truth. Particularly valuable in environments without comprehensive EDR coverage.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "net.exe enumeration in operations against AD environments." },
          { cls: "apt-kp", name: "Lazarus", note: "net.exe usage in financial sector targeting." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal — net.exe is the most basic AD reconnaissance technique used across post-exploitation operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK, MITRE LOLBAS, and essentially every IR report." }
        ],
        cite: "MITRE ATT&CK T1069.002, MITRE LOLBAS"
      },
      {
        sub: "T1069.002 — gMSA Enumeration",
        indicator: "LDAP query for group-managed service accounts (gMSA) — privileged service account enumeration",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /\\(objectClass=msDS-Group
   ManagedServiceAccount\\)|
   \\(samAccountType=
   536870913\\)/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: (
  *msDS-GroupManagedServiceAccount*
  OR *samAccountType=536870913*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1069.002 LDAP query
    for gMSA accounts";
  flow:established,to_server;
  content:"msDS-GroupManagedServiceAccount";
  classtype:attempted-recon;
  sid:9106905; rev:1;)`,
        notes: "Group-Managed Service Accounts (gMSAs) are AD-managed service accounts with auto-rotating passwords. Enumerating them is interesting to adversaries because: (1) gMSAs often have privileged access to specific services and resources, (2) the msDS-ManagedPassword attribute can be retrieved by accounts in PrincipalsAllowedToRetrieveManagedPassword — if those principals are compromised, the gMSA password can be retrieved (Golden gMSA attack). Tools: PowerView Get-DomainGMSA, Impacket gMSA dumper, BloodHound. The samAccountType 536870913 is specific to gMSAs. Legitimate apps occasionally query gMSA attributes; bulk enumeration of all gMSAs is anomalous. Particularly relevant in environments with extensive service account use (which is most modern enterprises).",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "gMSA enumeration in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "gMSA discovery in operations against modern AD environments." },
          { cls: "apt-mul", name: "Red Team", note: "Golden gMSA attack research by Semperis and others — increasingly common in red team operations." },
          { cls: "apt-mul", name: "Multi", note: "Increasingly relevant as gMSA adoption grows in enterprise environments." }
        ],
        cite: "MITRE ATT&CK T1069.002, T1558"
      }
    ]
  },
  {
    id: "T1482",
    name: "Domain Trust Discovery",
    desc: "AD trust relationship enumeration — LDAP trustedDomain queries, LSARPC trust calls, nltest signatures, RootDSE, cross-trust DNS",
    rows: [
      {
        sub: "T1482 — LDAP Trust Enumeration",
        indicator: "LDAP query for trustedDomain objects — direct trust relationship enumeration",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.filter =~
  /\\(objectClass=trustedDomain\\)|
   \\(objectCategory=trustedDomain\\)/`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.filter: (
  *objectClass=trustedDomain*
  OR *objectCategory=trustedDomain*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1482 LDAP query
    for trustedDomain objects
    trust enumeration";
  flow:established,to_server;
  content:"trustedDomain";
  classtype:attempted-recon;
  sid:9148201; rev:1;)`,
        notes: "trustedDomain objects in AD's CN=System container store the configuration of every trust relationship: trust direction (inbound/outbound/bidirectional), trust type (parent-child, external, forest), trust transitivity, and SID filtering settings. Querying for objectClass=trustedDomain returns the full list of trusts. Tools: PowerView Get-DomainTrust, ldapsearch, BloodHound (collects trust data automatically), Get-ADTrust (RSAT). Legitimate AD-aware applications occasionally query trust info — but bulk enumeration from a workstation source is anomalous. The query is essentially a flag for upcoming cross-trust attack tooling. Pair with subsequent Kerberos cross-realm ticket requests (TGT requests against trusted domain DCs) for confirmation of attack progression.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Trust enumeration during SolarWinds compromise to identify victim's external trust relationships." },
          { cls: "apt-cn", name: "APT41", note: "Trust discovery in operations against multi-domain enterprises." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Trust enumeration via BloodHound documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Ransomware", note: "Trust enumeration in ransomware operations targeting multi-domain environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all advanced AD-targeting threat operations. Documented in CISA, Mandiant, and Microsoft research." }
        ],
        cite: "MITRE ATT&CK T1482, BloodHound documentation"
      },
      {
        sub: "T1482 — LSARPC Trust Calls",
        indicator: "LSARPC trust enumeration — LsaEnumerateTrustedDomains / LsaQueryTrustedDomainInfo RPC calls",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345778-1234-abcd-ef00-0123456789ab
&& dcerpc.opnum == [
  13 || 47 || 48 || 64
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345778-1234-abcd-ef00-0123456789ab"
AND dcerpc.opnum: (13 OR 47 OR 48 OR 64)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0007 T1482 LSARPC trust
    enumeration RPC call";
  flow:established,to_server;
  content:"|78 57 34 12 34 12 cd ab|";
  classtype:attempted-recon;
  sid:9148202; rev:1;)`,
        notes: "LSARPC interface (UUID 12345778-1234-abcd-ef00-0123456789ab) provides the Local Security Authority RPC API including trust queries: LsaEnumerateTrustedDomains (opnum 13), LsaQueryInfoTrustedDomain (opnum 47), LsaQueryTrustedDomainInfoByName (opnum 48), LsaEnumerateTrustedDomainsEx (opnum 64). 'nltest /domain_trusts' uses these calls. Tools: nltest, PowerView, BloodHound, Impacket lsalookup.py. Detection: Zeek dce_rpc.log captures interface UUID and opnum — alert when these specific opnums appear from non-admin sources. The trust enumeration RPC calls are essentially never used by typical applications — these are administrative APIs. False positives extremely rare.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "LSARPC trust enumeration in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Trust enumeration in operations against multi-domain enterprises." },
          { cls: "apt-mul", name: "Ransomware", note: "Trust enumeration in ransomware operations targeting multi-domain environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and in advanced threat actor operations. Near-universal precursor to cross-trust attacks." }
        ],
        cite: "MITRE ATT&CK T1482, T1558"
      },
      {
        sub: "T1482 — nltest Signatures",
        indicator: "nltest /domain_trusts execution — characteristic netlogon RPC pattern",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345678-1234-abcd-ef00-01234567cffb
&& dcerpc.opnum == [40 || 27]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345678-1234-abcd-ef00-01234567cffb"
AND dcerpc.opnum: (40 OR 27)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 445
  (msg:"TA0007 T1482 NETLOGON
    DsrEnumerateDomainTrusts RPC
    nltest signature";
  flow:established,to_server;
  content:"|78 56 34 12 34 12 cd ab|";
  classtype:attempted-recon;
  sid:9148203; rev:1;)`,
        notes: "NETLOGON interface (UUID 12345678-1234-abcd-ef00-01234567cffb) provides additional trust query APIs used by nltest: DsrEnumerateDomainTrusts (opnum 40), NetrLogonGetTrustRid (opnum 27). 'nltest /domain_trusts' is one of the simplest and most common trust enumeration commands — single line, no admin privileges required against most environments. The RPC interface UUID byte pattern is distinct from SAMR/LSARPC. Detection: Zeek dce_rpc.log captures it. nltest also has /trusted_domains (similar enumeration), /dsgetdc:domainname (DC discovery), and /domain_trust_info options — different opnums. Pair with EDR command-line monitoring for nltest.exe execution. The technique is documented as a primary trust discovery method in MITRE ATT&CK and in essentially every AD attack methodology.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "nltest usage in operations against AD environments." },
          { cls: "apt-ru", name: "APT28", note: "Trust enumeration via nltest in espionage operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "nltest documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "nltest near-universal in ransomware affiliate playbooks." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE LOLBAS, in CISA Scattered Spider advisory, and in numerous IR reports. Essentially universal across AD-aware threat operations." }
        ],
        cite: "MITRE ATT&CK T1482, MITRE LOLBAS, CISA AA23-320A"
      },
      {
        sub: "T1482 — RootDSE Queries",
        indicator: "RootDSE attribute query — Forest / Domain configuration discovery",
        arkime: `ip.src == $INTERNAL
&& port.dst == [389 || 636]
&& protocols == ldap
&& ldap.scope == base
&& ldap.dn == ""
&& ldap.attributes == [
  *namingContexts*
  || *configurationNamingContext*
  || *rootDomainNamingContext*
  || *forestFunctionality*
  || *domainFunctionality*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (389 OR 636)
AND ldap.scope: "base"
AND ldap.dn: ""
AND ldap.attributes: (
  *namingContexts*
  OR *configurationNamingContext*
  OR *rootDomainNamingContext*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS
  [389,636]
  (msg:"TA0007 T1482 RootDSE query
    for AD configuration namespace
    discovery";
  flow:established,to_server;
  content:"namingContexts";
  classtype:attempted-recon;
  sid:9148204; rev:1;)`,
        notes: "RootDSE (Root Directory Service Entry) is a special LDAP entry at the empty DN '' that returns server-level information about the directory. Querying its attributes reveals: namingContexts (all naming contexts the DC hosts, including external trust domains), configurationNamingContext (the Configuration partition DN), rootDomainNamingContext (the forest root domain), forestFunctionality and domainFunctionality (DFL/FFL levels), supportedLDAPVersion, supportedSASLMechanisms. Adversaries query RootDSE early in reconnaissance to map the AD topology and identify cross-trust opportunities. Tools: PowerView Get-DomainSearcher, ADExplorer, BloodHound. Detection: LDAP base-scope query with empty DN against DCs from non-admin-tool sources. Many AD-integrated apps issue RootDSE queries legitimately at startup — but the specific attribute set (namingContexts + configurationNamingContext + rootDomainNamingContext together) is more common in reconnaissance than in legitimate apps.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "RootDSE reconnaissance in espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "AD topology mapping via RootDSE." },
          { cls: "apt-mul", name: "Red Team", note: "Standard early-stage AD discovery via PowerView and ADExplorer." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat actor operations and in BloodHound's data collection methodology." }
        ],
        cite: "MITRE ATT&CK T1482, BloodHound documentation"
      },
      {
        sub: "T1482 — Cross-Trust DNS Discovery",
        indicator: "Cross-trust DNS query — SRV record lookup for foreign domain DC discovery",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.query-type == SRV
&& dns.host =~
  /_ldap\\._tcp\\..+/
&& dns.host != $LOCAL_DOMAIN_SRV
&& session-count groupby
  ip.src > 5 within 600s`,
        kibana: `source.ip: $INTERNAL
AND dns.question.type: "SRV"
AND dns.question.name: *_ldap._tcp.*
AND NOT dns.question.name: *.$LOCAL_DOMAIN`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0007 T1482 Cross-trust
    SRV query foreign domain DC
    discovery";
  flow:stateless;
  dns.query;
  pcre:"/_ldap\\._tcp\\./i";
  threshold:type both,
    track by_src,
    count 5, seconds 600;
  classtype:attempted-recon;
  sid:9148205; rev:1;)`,
        notes: "After enumerating trust relationships, adversaries discover the DCs of trusted domains via DNS SRV record lookups: _ldap._tcp.<trustdomain.local>, _kerberos._tcp.<trustdomain.local>, _ldap._tcp.dc._msdcs.<trustdomain.local>. These queries reveal the foreign DC IPs needed for cross-trust attacks (SID History abuse, foreign Kerberos ticket forging). Detection: SRV queries for _ldap._tcp or _kerberos._tcp outside your local domain namespace. Build $LOCAL_DOMAIN_SRV from your AD topology — anything else querying foreign domain SRV records is anomalous. Particularly relevant in enterprises with M&A-acquired domains or partner forest trusts. Pair with subsequent connections to the foreign DC IPs for confirmation of cross-trust progression.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Cross-trust DC discovery in multi-domain espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Foreign DC discovery in operations against multi-domain enterprises." },
          { cls: "apt-mul", name: "Ransomware", note: "Cross-trust enumeration in ransomware operations targeting multi-domain environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat actor operations targeting multi-domain enterprise environments. Direct precursor to SID History abuse and forest-level lateral movement." }
        ],
        cite: "MITRE ATT&CK T1482, T1558.001"
      }
    ]
  },
  {
    id: "T1083",
    name: "File and Directory Discovery",
    desc: "File system enumeration — recursive SMB directory walks, credential-pattern file searches",
    rows: [
      {
        sub: "T1083 — Recursive SMB Directory Enumeration",
        indicator: "Recursive SMB directory enumeration — Get-ChildItem -Recurse pattern across remote shares",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == query-directory
&& smb.tree-disconnect-rate
  groupby ip.src < 0.05
&& session.duration > 300
&& databytes.dst > 100000`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "query_directory"
AND event.duration > 300000000
AND destination.bytes > 100000`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1083 Recursive SMB
    directory enumeration sustained
    high volume";
  flow:established,to_server;
  content:"|ff 53 4d 42 32|";
  threshold:type both,
    track by_src,
    count 200, seconds 300;
  classtype:attempted-recon;
  sid:9108301; rev:1;)`,
        notes: "After identifying accessible shares (T1135), adversaries enumerate their contents recursively — finding sensitive files, source code, credentials, customer data. The network signal: sustained SMB sessions with continuous QUERY_DIRECTORY commands (SMB2) over many minutes, with substantial response data (directory listings). Tools: PowerShell Get-ChildItem -Recurse against UNC paths, Snaffler (specifically searches for credential-pattern files), Manyhats/Snaffler-derivatives, robocopy /L (list mode). Distinguishing from legitimate file usage: legitimate users open specific files; adversaries walk entire directory trees. Sustained high-volume query_directory traffic is the hallmark. Snaffler's pattern is particularly distinctive: rapid directory enumeration with file extension/name pattern matching against a wordlist. Pair with EDR.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Universal — pre-encryption file inventory and exfil target identification." },
          { cls: "apt-cn", name: "APT41", note: "Bulk file enumeration in data theft operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Snaffler usage documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Universal in ransomware operations and in advanced threat data theft. Snaffler and similar tools documented in CISA Scattered Spider advisory." }
        ],
        cite: "MITRE ATT&CK T1083, T1135, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1016",
    name: "System Network Configuration Discovery",
    desc: "Network configuration awareness — external IP lookups, cloud metadata service queries",
    rows: [
      {
        sub: "T1016 — External IP Lookup",
        indicator: "External IP lookup from non-browser process — adversary self-IP discovery",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *icanhazip.com*
  || *ifconfig.me*
  || *api.ipify.org*
  || *checkip.amazonaws.com*
  || *ipinfo.io*
  || *ip-api.com*
  || *whatismyip.com*
]
&& process != [
  *chrome* || *firefox*
  || *edge* || *safari*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *icanhazip.com*
  OR *ifconfig.me*
  OR *api.ipify.org*
  OR *checkip.amazonaws.com*
  OR *ipinfo.io*
  OR *ip-api.com*
  OR *whatismyip.com*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0007 T1016 External IP
    lookup possible self-discovery";
  flow:established,to_server;
  pcre:"/Host:\\s*(icanhazip|
    ifconfig\\.me|api\\.ipify|
    checkip\\.amazonaws|
    ipinfo\\.io|ip-api|
    whatismyip)/i";
  http.header;
  classtype:trojan-activity;
  sid:9101601; rev:1;)`,
        notes: "Adversaries use IP-lookup services to discover their own external IP — needed for C2 callback configuration, geo-awareness, and avoiding self-targeting. Same indicator surfaces in T1568.003 (DNS Calculation precursor) but the use case here is different: T1016 is general network configuration awareness, T1568.003 is C2 endpoint derivation. Process correlation distinguishes legitimate browser traffic (a user clicking 'what's my IP') from implant self-discovery (PowerShell, custom binary, python-requests). The detection has minimal false positives once browser exclusions are applied.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "External IP lookup documented in espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "IP awareness in financial sector targeting." },
          { cls: "apt-cn", name: "APT41", note: "External IP discovery in operations." },
          { cls: "apt-mul", name: "Multi", note: "Near-universal post-exploitation indicator across stealer malware, custom implants, and ransomware. Documented in MITRE ATT&CK T1016 and across virtually every malware analysis report." }
        ],
        cite: "MITRE ATT&CK T1016, industry reporting"
      },
      {
        sub: "T1016 — Cloud Metadata Service",
        indicator: "Public cloud metadata service query — IMDS access from compromised cloud workload",
        arkime: `ip.src == $INTERNAL
&& ip.dst == [
  169.254.169.254
  || fd00:ec2::254
]
&& protocols == http
&& process != [
  *cloud-init* || *aws-*
  || *azure-* || *gcp-*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: (
  "169.254.169.254"
  OR "fd00:ec2::254"
)
AND network.protocol: http`,
        suricata: `alert http $HOME_NET any
  -> 169.254.169.254 any
  (msg:"TA0007 T1016 Cloud metadata
    service query non-cloud-tool
    process";
  flow:established,to_server;
  classtype:attempted-recon;
  sid:9101602; rev:1;)`,
        notes: "Cloud Instance Metadata Service (IMDS) at 169.254.169.254 provides instance configuration data including (in vulnerable IMDSv1 configs) instance role temporary credentials — a critical privilege escalation primitive in cloud environments. Adversaries who land on a cloud workload (EC2, Azure VM, GCP instance) immediately query IMDS to extract credentials, security group rules, network interface info, and user-data scripts (often containing secrets). Detection: HTTP traffic to 169.254.169.254 from non-cloud-init processes. AWS strongly recommends IMDSv2 (which requires session tokens and prevents SSRF abuse) — environments still on IMDSv1 are particularly vulnerable. The attack pattern is documented extensively in cloud security research (Capital One breach 2019, numerous SSRF-to-credential-theft incidents).",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "IMDS abuse for cloud credential theft documented in CISA AA23-320A operations." },
          { cls: "apt-cn", name: "APT41", note: "Cloud workload IMDS abuse in operations against cloud-heavy targets." },
          { cls: "apt-mul", name: "Cloud-focused threats", note: "IMDS abuse documented across many cloud breach incidents including Capital One 2019." },
          { cls: "apt-mul", name: "Multi", note: "Documented in numerous cloud breach incidents and in CISA cloud security guidance. Particularly relevant for hybrid environments with cloud workloads." }
        ],
        cite: "MITRE ATT&CK T1016, T1552.005, CISA cloud advisories"
      }
    ]
  },
  {
    id: "T1049",
    name: "System Network Connections Discovery",
    desc: "Service and connection enumeration — Windows Service Control Manager RPC queries",
    rows: [
      {
        sub: "T1049 — svcctl Service Enumeration",
        indicator: "Bulk Windows Service Control Manager queries — service enumeration via svcctl RPC",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  367abb81-9844-35f1-ad32-98f038001003
&& dcerpc.opnum == [14 || 15 || 27]
&& session-count groupby
  ip.src > 5 within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "367abb81-9844-35f1-ad32-98f038001003"
AND dcerpc.opnum: (14 OR 15 OR 27)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1049 svcctl service
    enumeration RPC burst";
  flow:established,to_server;
  content:"|81 bb 7a 36 44 98 f1 35|";
  threshold:type both,
    track by_src,
    count 5, seconds 60;
  classtype:attempted-recon;
  sid:9104901; rev:1;)`,
        notes: "Windows Service Control Manager RPC interface (UUID 367abb81-9844-35f1-ad32-98f038001003) provides service enumeration: REnumServicesStatusW (opnum 14), REnumServicesStatusExW (opnum 42), RQueryServiceStatusEx (opnum 27). Adversaries enumerate services to identify: vulnerable service binaries with weak permissions (privilege escalation), security tool services to disable (defense evasion), application services for lateral movement targets. Tools: 'sc query', 'tasklist /svc', 'Get-Service', PowerView Get-WMIObject. The svcctl RPC interface is rarely used in normal application traffic — a burst of svcctl calls from one source against many remote hosts is anomalous. Note: svcctl is also used legitimately by IT management tools (SCCM, monitoring agents) — exclude their source IPs.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Service enumeration in operations against AD environments." },
          { cls: "apt-mul", name: "Ransomware", note: "Service enumeration to identify security software services to terminate before encryption." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat actor operations and ransomware playbooks (identifying security software services to terminate before encryption)." }
        ],
        cite: "MITRE ATT&CK T1049, T1007"
      }
    ]
  },
  {
    id: "T1033",
    name: "System Owner / User Discovery",
    desc: "User identity discovery — SID-to-username resolution, whoami patterns",
    rows: [
      {
        sub: "T1033 — LSARPC SID Lookups",
        indicator: "LSARPC LsaLookupSids burst — SID-to-username resolution for many SIDs",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345778-1234-abcd-ef00-0123456789ab
&& dcerpc.opnum == [15 || 76]
&& session-count groupby
  ip.src > 10 within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345778-1234-abcd-ef00-0123456789ab"
AND dcerpc.opnum: (15 OR 76)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0007 T1033 LsaLookupSids
    burst many SID resolutions";
  flow:established,to_server;
  content:"|78 57 34 12 34 12 cd ab|";
  threshold:type both,
    track by_src,
    count 10, seconds 60;
  classtype:attempted-recon;
  sid:9103301; rev:1;)`,
        notes: "LSARPC LsaLookupSids (opnum 15) and LsaLookupSids2 (opnum 76) resolve SIDs to usernames — useful for adversaries who've harvested SIDs (from process tokens, DACLs, or AD queries) and need to map them to user-friendly names. The detection target: bulk SID lookups (10+ SIDs in a minute from one source) which is the pattern produced by tools enumerating discovered SID lists. Legitimate use: Windows Event Log services, security tools translating audit events. Suspicious: workstation processes lookup-bursting many SIDs in sequence. The technique often appears in BloodHound's SAMR collection method as a fallback when LDAP enumeration is restricted. Pair with EDR for definitive process attribution — PowerShell, Impacket lookupsid.py, custom enumeration tools.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SID enumeration in operations against AD environments." },
          { cls: "apt-ru", name: "APT29", note: "SID-to-username mapping in espionage operations." },
          { cls: "apt-mul", name: "Red Team", note: "Standard pentest methodology — Impacket lookupsid.py, BloodHound SAMR fallback collection." },
          { cls: "apt-mul", name: "Multi", note: "Documented in BloodHound's data collection methodology and in advanced threat actor operations targeting AD environments." }
        ],
        cite: "MITRE ATT&CK T1033, BloodHound documentation"
      }
    ]
  }
];
