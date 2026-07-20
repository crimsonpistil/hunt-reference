/* ============================================================================
 * TONK  -  SCAN CORRELATION TABLE
 * ----------------------------------------------------------------------------
 * Turns a parsed nmap/Henmap CSV row into a hunt-plan lead.
 * This file is DATA ONLY. It owns no scan logic and holds no state.
 * It is the one artifact in this pipeline that is yours: the mapping from
 * "what a scan observed" to "what to hunt, and where in TONK to go".
 *
 * INPUT ROW (Henmap CSV columns):
 *   ip_address, os_match, os_accuracy, port_number, protocol, state,
 *   service, product, version
 *
 * ROUTER RULE (applied per open row, in this order):
 *   1. EXPLOIT branch (PLAYBOOKS) - if product/version is present AND matches
 *      an exploits[] entry's fingerprint. Strong, specific signal.
 *   2. HUNT branch - else match service/port against services[]. Broad signal.
 *   3. ROLE check (always, in parallel) - os_match -> roles[] gives a device
 *      role hint that rode in free on the scan. If the row's service is not in
 *      that role's expected set, raise a DEVIATION flag on the lead. This is
 *      the "printer running a database = wrong" logic with no authored map.
 *
 * EPISTEMICS (non-negotiable, matches ATTRIB's discipline):
 *   - Every exploit entry is verified:false. A scan reports exposure. It never
 *     confirms compromise or even vulnerability. `version` is nmap's best-effort
 *     banner guess and is frequently blank or wrong. Susceptible != compromised,
 *     and reported != verified. The `confirm` field says what turns a banner
 *     into a real finding, and it always requires leaving the scan.
 *   - `signal` (strong|moderate|weak) + `noise` (low|med|high) exist so the
 *     emitter can rank. A lone distinctive deviation must outrank a common
 *     service open on forty hosts. Ranking is the product, same as ATTRIB.
 *
 * All `ref` paths point at pages that exist in this kit. No dead links.
 * ==========================================================================*/

const SCAN_CORRELATION = {

  meta: {
    version: "1.0",
    schema: "service|product -> technique|exploit, routed to HUNT or PLAYBOOKS",
    seeded_from: "TestTargs_hosts.csv (118 hosts, 338 open ports)",
    router: "product+version present & matched -> exploit(PLAYBOOKS); else service/port -> HUNT; os_match -> role deviation flag in parallel",
    note: "Bare-service leads are weak by design. Strength comes from a version match, a role deviation, or a zone/boundary violation - not from the port alone."
  },

  /* ---------------------------------------------------------------------------
   * ROLE HINTS  -  os_match -> device role, expected service classes.
   * `expect` = service/keyword classes normal for this role.
   * A row whose service is outside `expect` gets a DEVIATION flag.
   * `env` routes the whole device to the matching environment playbook.
   * ------------------------------------------------------------------------ */
  roles: [
    { os_re: "VMware ESXi|ESXi",           role: "hypervisor",
      expect: ["vmware-auth","https","http","http-alt","tmi","glrpc","ssh","soap","svrloc"],
      env: "/playbooks/environments/cloud-control.html",
      note: "Mgmt plane. Compromise = mass VM impact. ESXi 6.0.0 is EOL." },
    { os_re: "iLO|Integrated Lights-Out",  role: "oob-mgmt",
      expect: ["ssh","https","http","ilo-vm"],
      env: "/playbooks/triage/edge-device.html",
      note: "Out-of-band mgmt. Must be tightly segmented; reachability itself is a finding." },
    { os_re: "Lexmark|printer",            role: "printer",
      expect: ["ipp","printer","jetdirect","thinprint","http","https","snmp"],
      env: "/playbooks/environments/airgap-ot.html",
      note: "Printers harvest LDAP creds (pass-back) and are never patched." },
    { os_re: "Crestron|XPanel",            role: "ics-av-control",
      expect: ["http","https","ssh","telnet","tmi"],
      env: "/playbooks/environments/airgap-ot.html",
      note: "AV/building control. OT-class. Default creds are the norm." },
    { os_re: "Symbol AP|Ubiquiti|OpenWrt|switch|USW", role: "network-gear",
      expect: ["ssh","http","https","telnet","snmp","svrloc"],
      env: "/playbooks/environments/soho-router.html",
      note: "Switch/AP/router. Server-class services here are wrong." },
    { os_re: "temperature sensor|E-MICRO|NTI", role: "ot-sensor",
      expect: ["http","https","snmp"],
      env: "/playbooks/environments/airgap-ot.html",
      note: "Environmental sensor. Anything beyond its own mgmt UI is a deviation." },
    { os_re: "Windows Server",             role: "windows-server",
      expect: ["msrpc","netbios-ssn","microsoft-ds","ldap","http","https","ms-wbt-server","http-rpc"],
      env: "/playbooks/environments/hybrid-ad.html",
      note: "Check for AD roles (LDAP/AD CS). RDP/WinRM exposure = lateral surface." },
    { os_re: "SIMATIC|Siemens.*S7|Siemens S7|S7-[0-9]", role:"plc-siemens",
      expect:["iso-tsap","profinet","pn-io","http","https","snmp","ntp"],
      env:"/playbooks/environments/airgap-ot.html",
      note:"Siemens PLC (S7comm on 102). Enterprise services here are wrong." },
    { os_re: "Allen-Bradley|Rockwell|Logix|1756|1769|MicroLogix", role:"plc-rockwell",
      expect:["enip","cip","http","https","snmp"],
      env:"/playbooks/environments/airgap-ot.html",
      note:"Rockwell PLC (EtherNet/IP on 44818)." },
    { os_re: "Modicon|Schneider|Triconex|Tricon|Wonderware", role:"plc-schneider",
      expect:["mbap","modbus","enip","tristation","http","https"],
      env:"/playbooks/environments/airgap-ot.html",
      note:"Schneider (Modbus/502). Triconex = SAFETY system - escalate ANY reachability." },
    { os_re: "Omron|Sysmac|\\bFINS\\b", role:"plc-omron",
      expect:["omron","fins","enip","http"], env:"/playbooks/environments/airgap-ot.html",
      note:"Omron PLC (FINS on 9600)." },
    { os_re: "MELSEC|Mitsubishi", role:"plc-mitsubishi",
      expect:["melsec","melsoft","http"], env:"/playbooks/environments/airgap-ot.html",
      note:"Mitsubishi PLC." },
    { os_re: "Tridium|Niagara|JACE|WAGO|Beckhoff|Phoenix Contact|CODESYS|\\bPLC\\b|\\bRTU\\b|\\bSCADA\\b|controller", role:"ot-controller",
      expect:["niagara-fox","fox","bacnet","codesys","mbap","modbus","http","https","ssh","snmp"],
      env:"/playbooks/environments/airgap-ot.html",
      note:"Generic OT controller / BAS / RTU. Trust the PROTOCOL over the OS - many report as embedded Linux." },
    { os_re: "Moxa|NPort", role:"serial-gateway",
      expect:["moxa","nport","telnet","http","https","ssh","snmp"],
      env:"/playbooks/environments/airgap-ot.html",
      note:"Serial-to-IP gateway. IT/OT bridge point - default creds common." },
    { os_re: "FreeBSD|Linux|Debian|Ubuntu", role: "unix-host",
      expect: ["ssh","http","https","domain","smtp","imap","rpcbind","nfs","mysql","rsync","ldap"],
      env: "/playbooks/environments/linux-fleet.html",
      note: "General *nix host. Baseline expected-service set is broad." }
  ],

  /* ---------------------------------------------------------------------------
   * HUNT LEADS  -  service/port -> ATT&CK technique -> HUNT tactic page.
   * `hunt` is a STARTER pull only. The authoritative queries live on the
   * referenced HUNT page's data file; this is the on-ramp, not the source.
   * ------------------------------------------------------------------------ */
  services: [
    { match:{ service:["ssh"], port:[22,2222] }, route:"hunt",
      tech:[{id:"T1021.004",name:"Remote Services: SSH"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If SSH is reachable on {ip}, then an actor with valid or brute-forced credentials could use it for lateral movement or persistence.",
      hunt:"Zeek ssh.log: new client subnet, auth_success after failures, off-hours. Arkime: protocols==ssh, many-to-one source.",
      signal:"weak", noise:"high",
      note:"Ubiquitous here (91 hosts). Only interesting on a role that should not expose it, or a NEW source." },

    { match:{ service:["ms-wbt-server","vmrdp"], port:[3389,2179] }, route:"hunt",
      tech:[{id:"T1021.001",name:"Remote Services: RDP"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If RDP is reachable on {ip}, then an actor could use captured or sprayed credentials to move laterally to it.",
      hunt:"Zeek/Arkime: rdp sessions, source outside admin jump range, first-seen source->{ip} on 3389.",
      signal:"moderate", noise:"med",
      note:"RDP on a non-jump host is a role deviation - check roles[]." },

    { match:{ service:["http"], port:[5985,5986] }, route:"hunt",
      tech:[{id:"T1021.006",name:"Remote Services: WinRM"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If WinRM (5985/5986) is reachable on {ip}, then an actor could use it for remote command execution and lateral movement.",
      hunt:"Arkime: dst.port==5985/5986, POST /wsman. Zeek http.log to those ports. Correlate with 4688/PS logs host-side.",
      signal:"moderate", noise:"med" },

    { match:{ service:["vnc"], port:[5900,5901] }, route:"hunt",
      tech:[{id:"T1021.005",name:"Remote Services: VNC"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If VNC is reachable on {ip}, then an actor could use it for hands-on-keyboard control, often with weak or no auth.",
      hunt:"Arkime: protocols==vnc / dst.port 5900-5901. Flag any external source.",
      signal:"moderate", noise:"med" },

    { match:{ service:["shell","exec","login"], port:[512,513,514] }, route:"hunt",
      tech:[{id:"T1021",name:"Remote Services"},{id:"T1552.001",name:"Unsecured Credentials"}], tactic:"credential",
      ref:"/hunt/credential.html",
      hyp:"If an r-service (rsh/rlogin/rexec) is open on {ip}, then credentials cross the wire in cleartext and trust relationships can be abused.",
      hunt:"Arkime: dst.port 512-514. Any traffic here is legacy and suspect.",
      signal:"strong", noise:"low",
      note:"These should not exist. Presence alone is a finding." },

    { match:{ service:["telnet"], port:[23,9000] }, route:"hunt",
      tech:[{id:"T1021",name:"Remote Services"},{id:"T1040",name:"Network Sniffing"}], tactic:"credential",
      ref:"/hunt/credential.html",
      hyp:"If telnet is open on {ip}, then credentials are exposed in cleartext and the device is likely default-configured.",
      hunt:"Arkime: protocols==telnet. Zeek: any telnet session, capture auth.",
      signal:"strong", noise:"low",
      note:"Common on ICS/AV gear (Crestron). Cleartext mgmt = high value." },

    { match:{ service:["http","https","http-alt","http-proxy","soap","glrpc","tmi","websnp"],
             port:[80,443,8000,8080,8081,8084,8300,9080,5000,5001,5050,5357,9876] }, route:"hunt",
      tech:[{id:"T1190",name:"Exploit Public-Facing Application"},{id:"T1071.001",name:"Web Protocols (C2)"}], tactic:"initial_access",
      ref:"/hunt/initial_access.html",
      hyp:"If a web service is reachable on {ip}, then it is a candidate for public-facing exploitation or, outbound, for web-based C2.",
      hunt:"Suricata: web attack sigs to {ip}. Arkime: http.uri anomalies, webshell patterns, rare user-agents. Zeek http.log new server.",
      signal:"weak", noise:"high",
      note:"Route to PLAYBOOKS instead when product+version identifies a known-vuln stack (see exploits[])." },

    { match:{ service:["domain","dns"], port:[53] }, route:"hunt",
      tech:[{id:"T1071.004",name:"DNS (C2)"},{id:"T1048",name:"Exfil Over Alternative Protocol"}], tactic:"c2",
      ref:"/hunt/c2.html",
      hyp:"If {ip} answers DNS but is not a designated resolver, then it could be staging DNS tunneling for C2 or exfiltration.",
      hunt:"Zeek dns.log: high-entropy/long qnames, TXT volume, {ip} as unexpected server. Arkime: dns to/from {ip}.",
      signal:"moderate", noise:"med",
      note:"Weak on a known resolver (roles[]); strong on anything else." },

    { match:{ service:["smtp"], port:[25,465,587] }, route:"hunt",
      tech:[{id:"T1071.003",name:"Mail Protocols"}], tactic:"c2",
      ref:"/hunt/c2.html",
      hyp:"If SMTP is reachable on {ip}, then it could be abused as an open relay for BEC or as a mail-based C2/exfil channel.",
      hunt:"Zeek smtp.log: relay attempts, unusual senders. Also see /playbooks/triage/bec.html.",
      signal:"weak", noise:"high" },

    { match:{ service:["imap","imaps","pop3","pop3s"], port:[143,993,110,995] }, route:"hunt",
      tech:[{id:"T1114",name:"Email Collection"}], tactic:"collection",
      ref:"/hunt/collection.html",
      hyp:"If a mail-access service is reachable on {ip}, then compromised creds could be used to harvest mailbox contents.",
      hunt:"Zeek: imap/pop sessions from new sources; volume spikes.",
      signal:"weak", noise:"med" },

    { match:{ service:["netbios-ssn","microsoft-ds","smb"], port:[139,445] }, route:"hunt",
      tech:[{id:"T1021.002",name:"SMB / Admin Shares"},{id:"T1135",name:"Network Share Discovery"},{id:"T1187",name:"Forced Authentication"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If SMB is reachable on {ip}, then it is a lateral-movement and share-enumeration surface, and a coercion (forced-auth) target.",
      hunt:"Zeek smb_files/smb_mapping: admin$ / C$ access, new source. Arkime: dst.port 445 many-to-one. Host-side: 5140/5145.",
      signal:"moderate", noise:"med",
      note:"If OS is Windows + SMBv1, escalate to exploits[] EternalBlue. If Samba, see exploits[] SambaCry." },

    { match:{ service:["msrpc"], port:[135] }, route:"hunt",
      tech:[{id:"T1021.003",name:"DCOM"},{id:"T1047",name:"WMI"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If MSRPC (135) is reachable on {ip}, then DCOM/WMI-based remote execution and RPC coercion vectors are exposed.",
      hunt:"Zeek dce_rpc.log: IObjectExporter, Task Scheduler, SVCCTL binds from new sources.",
      signal:"moderate", noise:"med",
      note:"With AD CS + LDAP present, escalate to exploits[] PetitPotam/ADCS." },

    { match:{ service:["ldap","ldaps"], port:[389,636,3268,3269] }, route:"hunt",
      tech:[{id:"T1087.002",name:"Domain Account Discovery"},{id:"T1069.002",name:"Domain Groups"}], tactic:"discovery",
      ref:"/hunt/discovery.html",
      hyp:"If LDAP is reachable on {ip}, then an actor can enumerate accounts, groups, and AD structure for targeting.",
      hunt:"Zeek: ldap binds/searches from non-admin sources; anonymous binds. Large searchRequest volume.",
      signal:"moderate", noise:"med",
      note:"636 + Windows server + msrpc = AD DC. Consider PetitPotam/ADCS relay path." },

    { match:{ service:["rpcbind","nfs","nfs_acl","nlockmgr","rquotad","mountd"], port:[111,2049] }, route:"hunt",
      tech:[{id:"T1135",name:"Network Share Discovery"},{id:"T1039",name:"Data from Network Shared Drive"}], tactic:"collection",
      ref:"/hunt/collection.html",
      hyp:"If NFS/portmapper is reachable on {ip}, then world-readable or no_root_squash exports could expose data directly.",
      hunt:"showmount enumeration offline; Zeek: nfs mounts from unexpected clients; large reads.",
      signal:"moderate", noise:"med" },

    { match:{ service:["rsync"], port:[873] }, route:"hunt",
      tech:[{id:"T1039",name:"Data from Network Shared Drive"},{id:"T1105",name:"Ingress Tool Transfer"}], tactic:"collection",
      ref:"/hunt/collection.html",
      hyp:"If rsync is reachable on {ip}, then unauthenticated modules could allow bulk read or write of data.",
      hunt:"Zeek/Arkime: 873 sessions, large transfers, new source.",
      signal:"moderate", noise:"med" },

    { match:{ service:["mysql","mariadb","ms-sql-s","postgresql","oracle"], port:[3306,1433,5432,1521] }, route:"hunt",
      tech:[{id:"T1210",name:"Exploitation of Remote Services"},{id:"T1213",name:"Data from Information Repositories"}], tactic:"collection",
      ref:"/hunt/collection.html",
      hyp:"If a database is reachable on {ip}, then weak auth or known CVEs could expose or exfiltrate repository data.",
      hunt:"Zeek: db logins from app-tier only? flag others. Arkime: large result-set transfers.",
      signal:"moderate", noise:"med" },

    { match:{ service:["ftp"], port:[21] }, route:"hunt",
      tech:[{id:"T1105",name:"Ingress Tool Transfer"},{id:"T1552.001",name:"Unsecured Credentials"}], tactic:"initial_access",
      ref:"/hunt/initial_access.html",
      hyp:"If FTP is reachable on {ip}, then cleartext creds and anonymous access make it a foothold and staging point.",
      hunt:"Zeek ftp.log: anonymous logins, STOR of executables, new source.",
      signal:"moderate", noise:"med",
      note:"If product is ProFTPD/vsftpd, check exploits[] for version-gated CVEs." },

    { match:{ service:["squid-http","http-proxy"], port:[3128,8080] }, route:"hunt",
      tech:[{id:"T1090",name:"Proxy"},{id:"T1071.001",name:"Web Protocols"}], tactic:"c2",
      ref:"/hunt/c2.html",
      hyp:"If an open proxy is reachable on {ip}, then it could be used to relay C2 or launder outbound traffic.",
      hunt:"Arkime: {ip} as proxy hop, unexpected CONNECT volume, external destinations.",
      signal:"moderate", noise:"med" },

    { match:{ service:["ipp","printer","jetdirect","thinprint","finger","lpd"], port:[79,515,631,9100,4000] }, route:"hunt",
      tech:[{id:"T1187",name:"Forced Authentication"},{id:"T1040",name:"Network Sniffing"}], tactic:"credential",
      ref:"/hunt/credential.html",
      hyp:"If a printer exposes management/print services on {ip}, then LDAP pass-back and stored scan-to-* creds are a harvest target.",
      hunt:"Inspect device LDAP config offline; Zeek: printer -> DC LDAP binds; unexpected outbound from printer VLAN.",
      signal:"moderate", noise:"med",
      note:"See exploits[] for Lexmark/PrintNightmare-adjacent spooler path." },

    { match:{ service:["vmware-auth","vmrdp","iscsi","ilo-vm","ismserver"], port:[902,2179,3260,3261,17988,9500] }, route:"hunt",
      tech:[{id:"T1021",name:"Remote Services"},{id:"T1210",name:"Exploitation of Remote Services"}], tactic:"lateral",
      ref:"/hunt/lateral.html",
      hyp:"If a virtualization/storage mgmt service is reachable on {ip}, then the hypervisor control plane is exposed to lateral abuse.",
      hunt:"Arkime: 902/2179/3260 sources; Zeek: iSCSI initiators outside storage net.",
      signal:"moderate", noise:"med",
      note:"With ESXi product/OS, escalate to exploits[] ESXi chain." },

    { match:{ service:["svrloc","slp"], port:[427] }, route:"exploit",
      tech:[{id:"T1046",name:"Network Service Discovery"}], tactic:"discovery",
      ref:"/playbooks/exploits/esxi-chain.html",
      hyp:"If OpenSLP (427) is reachable on {ip} and this is an ESXi host, then it exposes the ESXiArgs ransomware vector directly.",
      hunt:"Confirm ESXi build; 427/udp reachable is the classic pre-ESXiArgs tell.",
      signal:"strong", noise:"low",
      note:"427 on ESXi is the single highest-value row in this dataset. Routed to PLAYBOOKS." }
  ],

  /* ---------------------------------------------------------------------------
   * EXPLOIT LEADS  -  product[/version] -> exploit -> PLAYBOOKS.
   * `match.product_re` is a regex against the product field.
   * `match.version` (optional) narrows to vulnerable ranges. When a version
   *   is present and OUTSIDE the range, the emitter should say "reported
   *   version is NOT in the known-vuln range" - a version finding that clears,
   *   which is as useful as one that fires.
   * ALL entries are verified:false. `confirm` always requires leaving the scan.
   * Entries whose products are absent from the seed CSV are kept so the table
   * is complete for the kit's full PLAYBOOKS set and fires on future scans.
   * ------------------------------------------------------------------------ */
  exploits: [
    { match:{ product_re:"VMware ESXi|VMware Authentication Daemon|ESXi", port:[427,902,443,8300,9080] },
      cve:["CVE-2021-21974","CVE-2019-5544","CVE-2020-3992"], verified:false,
      exploit:"ESXi OpenSLP heap overflow -> ESXiArgs mass ransomware",
      ref:"/playbooks/exploits/esxi-chain.html", also:["/playbooks/triage/ransomware.html"],
      signal:"strong", noise:"low", actors:["RaaS ecosystem"],
      confirm:"Get exact ESXi build number (not the banner). 6.0.0 is EOL and unpatched by definition. Verify 427/udp OpenSLP is actually enabled.",
      note:"126 rows in the seed are ESXi 6.0.0/7.0.3. This is the primary exposure in the environment." },

    { match:{ product_re:"OpenSSH", version:{ ge:"8.5", lt:"9.8", family:"glibc-linux" } },
      cve:["CVE-2024-6387"], verified:false,
      exploit:"regreSSHion - unauth RCE via signal handler race (glibc Linux)",
      ref:"/playbooks/environments/linux-fleet.html",
      signal:"moderate", noise:"med", actors:[],
      confirm:"Race is hard to win in practice (hours-to-days) and needs glibc Linux; not BSD/Windows. Confirm distro + patch, not banner. OpenSSH 10.x and <=8.4 are NOT in range.",
      note:"Seed has 8.x/9.x incl 9.6/9.7 (in range) and 10.x (clears). Good version-gate example." },

    { match:{ product_re:"Apache httpd", version:{ in:["2.4.49","2.4.50"] } },
      cve:["CVE-2021-41773","CVE-2021-42013"], verified:false,
      exploit:"Apache path traversal -> file disclosure / RCE (cgi enabled)",
      ref:"/playbooks/environments/linux-fleet.html",
      signal:"strong", noise:"low", actors:["commodity","botnets"],
      confirm:"ONLY 2.4.49/2.4.50 with require-all-denied removed. Seed's 2.4.58/2.4.57/2.4.37 are NOT vulnerable to this - the table clears them.",
      note:"Kept as a discriminator: shows a version finding that correctly does NOT fire on Katie's versions." },

    { match:{ product_re:"Samba smbd", version:{ ge:"3.5.0", le:"4.6.3" } },
      cve:["CVE-2017-7494"], verified:false,
      exploit:"SambaCry - is_known_pipename() writable-share RCE",
      ref:"/playbooks/exploits/eternalblue.html",
      signal:"moderate", noise:"med", actors:["cryptominers","commodity"],
      confirm:"Needs a writable share + ability to load an .so. Confirm Samba version and share perms. Distinct from EternalBlue (that is Windows SMBv1).",
      note:"Seed has Samba 3.X-4.X and 4 - possibly in range. Routed to the SMB playbook." },

    { match:{ product_re:"Microsoft.*netbios|Microsoft.*microsoft-ds|Windows.*SMB", os_re:"Windows", requires:"SMBv1" },
      cve:["CVE-2017-0144 (MS17-010)"], verified:false,
      exploit:"EternalBlue - SMBv1 remote kernel RCE / wormable",
      ref:"/playbooks/exploits/eternalblue.html", also:["/playbooks/triage/ransomware.html"],
      signal:"weak", noise:"low", actors:["Sandworm","Lazarus","WannaCry/NotPetya lineage"],
      confirm:"REQUIRES SMBv1 enabled. Server 2019 disables it by default, so this likely clears unless SMBv1 was turned back on. Confirm dialect, do not assume from 445.",
      note:"445 alone does NOT imply EternalBlue. Gate strictly on SMBv1 or this is pure noise." },

    { match:{ product_re:"Integrated Lights-Out|iLO", os_re:"iLO 4", version:{ lt:"2.53" } },
      cve:["CVE-2017-12542"], verified:false,
      exploit:"HP iLO 4 auth bypass + RCE (Connection header overflow)",
      ref:"/playbooks/triage/edge-device.html",
      signal:"strong", noise:"low", actors:["APT (OOB persistence)","commodity"],
      confirm:"iLO4 firmware < 2.53. Seed shows iLO4 + version 1.30 -> in range. Confirm firmware, then treat OOB compromise as full-host + persistence.",
      note:"OOB mgmt RCE is a durable, high-value finding. iLO reachability itself is worth a segmentation review." },

    { match:{ product_re:"ProFTPD" },
      cve:["CVE-2015-3306","CVE-2019-12815"], verified:false,
      exploit:"ProFTPD mod_copy unauth file copy -> RCE / arbitrary read-write",
      ref:"/playbooks/environments/linux-fleet.html",
      signal:"moderate", noise:"med", actors:["commodity"],
      confirm:"mod_copy enabled (SITE CPFR/CPTO). Confirm version + module set. Banner alone is not enough.",
      note:"No version in seed banner - falls to moderate until confirmed." },

    { match:{ product_re:"vsftpd", version:{ eq:"2.3.4" } },
      cve:["backdoor (2011 build)"], verified:false,
      exploit:"vsftpd 2.3.4 smiley-face backdoor (:) opens 6200)",
      ref:"/playbooks/environments/linux-fleet.html",
      signal:"strong", noise:"low", actors:[],
      confirm:"ONLY the trojaned 2.3.4 build. Seed has vsftpd 3.0.5, which is CLEAN - the table explicitly clears it.",
      note:"Discriminator entry: proves version matters. 3.0.5 != 2.3.4." },

    { match:{ product_re:"Lexmark", os_re:"Lexmark|printer" },
      cve:["CVE-2023-40593 (family)","print-spooler class"], verified:false,
      exploit:"Lexmark firmware RCE family + LDAP pass-back credential theft",
      ref:"/playbooks/exploits/printnightmare.html",
      signal:"moderate", noise:"med", actors:["commodity","cred-harvesters"],
      confirm:"Pull device firmware + LDAP config offline. The credential-harvest angle (scan-to-folder / address-book LDAP) is often higher value than firmware RCE.",
      note:"Printers are a standing credential-exposure surface more than an RCE one." },

    { match:{ product_re:"Windows.*RPC|Windows RPC", os_re:"Windows", requires:"LDAP+AD-CS" },
      cve:["PetitPotam + ESC8 relay"], verified:false,
      exploit:"PetitPotam coercion -> NTLM relay to AD CS web enrollment",
      ref:"/playbooks/exploits/petitpotam-adcs.html",
      signal:"moderate", noise:"med", actors:["APT29","ransomware affiliates"],
      confirm:"Needs AD CS web enrollment (certsrv) reachable + MS-EFSR/MS-RPRN callable. Confirm AD CS role present; msrpc(135)+ldap(636) in seed are the prerequisites, not proof.",
      note:"Fires only when the RPC surface coincides with an AD CS enrollment endpoint." },

    /* --- kept for kit completeness; products not in the seed CSV --- */
    { match:{ product_re:"Microsoft Exchange|OWA|Exchange" },
      cve:["CVE-2021-26855 (ProxyLogon)"], verified:false,
      exploit:"ProxyLogon SSRF -> auth bypass -> RCE (Exchange)",
      ref:"/playbooks/exploits/proxylogon.html", signal:"strong", noise:"low",
      actors:["HAFNIUM","multiple APT"], confirm:"Exchange build/CU + patch state.",
      note:"Not in seed; fires when Exchange appears." },

    { match:{ product_re:"log4j|vCenter|Struts|Java|Solr|VMware.*vCenter" },
      cve:["CVE-2021-44228 (Log4Shell)"], verified:false,
      exploit:"Log4Shell JNDI lookup -> RCE in any logging-reachable Java app",
      ref:"/playbooks/exploits/log4shell.html", signal:"strong", noise:"med",
      actors:["commodity","APT","cryptominers"],
      confirm:"Version fingerprint rarely reveals log4j. Confirm by app + outbound LDAP/RMI callback in traffic.",
      note:"vCenter (paired with the ESXi estate here) is the realistic Log4Shell target." },

    { match:{ product_re:"NetScaler|Citrix" },
      cve:["CVE-2023-4966 (Citrix Bleed)"], verified:false,
      exploit:"Citrix Bleed session-token disclosure",
      ref:"/playbooks/exploits/citrix-bleed.html", signal:"strong", noise:"low",
      actors:["ransomware affiliates","LockBit"], confirm:"NetScaler build.",
      note:"Not in seed." },

    { match:{ product_re:"Ivanti|Pulse|Connect Secure" },
      cve:["CVE-2023-46805 + CVE-2024-21887"], verified:false,
      exploit:"Ivanti Connect Secure auth bypass + command injection chain",
      ref:"/playbooks/exploits/ivanti-chain.html", signal:"strong", noise:"low",
      actors:["APT (edge)"], confirm:"Appliance version + ICT results.",
      note:"Not in seed." },

    { match:{ product_re:"PAN-OS|Palo Alto|FortiGate|Fortinet|FortiOS" },
      cve:["CVE-2024-3400 (PAN-OS)","CVE-2022-40684 (FortiOS)"], verified:false,
      exploit:"Edge firewall mgmt-plane auth bypass / command injection",
      ref:"/playbooks/exploits/panos-fortigate.html", signal:"strong", noise:"low",
      actors:["APT (edge)"], confirm:"Appliance version; mgmt plane should never be scan-reachable.",
      note:"Not in seed." },

    { match:{ product_re:"SharePoint" },
      cve:["ToolShell chain"], verified:false,
      exploit:"SharePoint deserialization/auth-bypass RCE chain",
      ref:"/playbooks/exploits/sharepoint-chain.html", signal:"strong", noise:"low",
      actors:["APT","ransomware"], confirm:"SharePoint build + patch.",
      note:"Not in seed." }
  ],

  /* ---------------------------------------------------------------------------
   * ICS / OT PROTOCOL EXPOSURE  -  industrial protocol -> ATT&CK for ICS (T0xxx).
   * HIGH signal / LOW noise. Most of these protocols carry NO native
   * authentication, so on them REACHABILITY IMPLIES CONTROLLABILITY: a device
   * that answers will honor commands from anything that can route to it. The
   * decisive question the scan cannot answer is WHICH PURDUE ZONE the scanner
   * sits in relative to the device - so every hypothesis names the boundary
   * check and hands it to the operator (TONK reads the zone map, never owns it).
   *
   * Matched on nmap's distinctive service string or a distinctive high port.
   * Ambiguous low ports that collide with IT in a mixed scan are deliberately
   * NOT matched by bare port: EtherNet/IP is 44818 only (not UDP/2222, which is
   * SSH-alt here); ROC-Plus/4000 is omitted (collides with ThinPrint). This
   * block therefore fires on zero rows of an all-IT scan - which is correct.
   *
   * verified:false like everything else - but for these, reachable IS the
   * finding, because the protocol provides no other gate. Ports/services and
   * ATT&CK-ICS IDs verified against nmap NSE + MITRE ATT&CK for ICS.
   * ------------------------------------------------------------------------ */
  ics: [
    { match:{ service:["mbap","modbus"], port:[502] }, protocol:"Modbus TCP", purdue:"L1-L2",
      tech:[{id:"T0855",name:"Unauthorized Command Message"},{id:"T0836",name:"Modify Parameter"},{id:"T0846",name:"Remote System Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["PIPEDREAM/INCONTROLLER (Schneider)","commodity ICS scanners"],
      hyp:"If Modbus/502 answers on {ip}, then anything that can route to it can read and write coils/registers with no auth and no encryption. Reachability equals control.",
      confirm:"Identify the scanner's Purdue zone relative to {ip}. If this was reached across a level boundary (e.g. from L3/enterprise), that zone violation is the finding. Then hunt in Zeek/Arkime for who else speaks 502 to it and any write functions (FC 5/6/15/16).",
      note:"Schneider Modicon speaks Modbus. PIPEDREAM targeted it directly." },

    { match:{ service:["iso-tsap"], port:[102] }, protocol:"Siemens S7comm / ISO-TSAP", purdue:"L1-L2",
      tech:[{id:"T0843",name:"Program Download"},{id:"T0855",name:"Unauthorized Command Message"},{id:"T0846",name:"Remote System Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["Stuxnet (S7)","Sandworm (via IEC-61850/ICCP on 102)"],
      hyp:"If 102/ISO-TSAP answers on {ip}, then it is likely Siemens S7 (or ICCP / IEC-61850 MMS, which share 102). Classic S7comm has no auth; STOP and program-download are unauthenticated.",
      confirm:"Disambiguate S7 vs ICCP vs MMS (s7-info). Zone-check. For S7, hunt STOP / PLC-download function traffic and engineering-station sources.",
      note:"Port 102 is shared by S7comm, ICCP (TASE.2) and IEC-61850 MMS - identify which before acting." },

    { match:{ service:["enip","cip"], port:[44818] }, protocol:"EtherNet/IP + CIP (Rockwell/Allen-Bradley)", purdue:"L1-L2",
      tech:[{id:"T0855",name:"Unauthorized Command Message"},{id:"T0846",name:"Remote System Discovery"},{id:"T0888",name:"Remote System Information Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["PIPEDREAM/INCONTROLLER (Rockwell)","commodity"],
      hyp:"If EtherNet/IP/44818 answers on {ip}, then CIP accepts CPU STOP and program up/download with no auth. enip-info reveals the exact model (e.g. 1756-Lxx Logix).",
      confirm:"Pull enip-info for model/revision offline. Zone-check. Hunt CIP write/STOP services from non-engineering sources. (Matched on 44818 only - UDP/2222 is excluded to avoid your SSH-alt rows.)",
      note:"Rockwell ControlLogix/CompactLogix. INCONTROLLER's TAGRUN targeted this." },

    { match:{ service:["dnp","dnp3"], port:[20000] }, protocol:"DNP3", purdue:"L1-L2",
      tech:[{id:"T0855",name:"Unauthorized Command Message"},{id:"T0848",name:"Rogue Master"},{id:"T0846",name:"Remote System Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["electric-sector threats","Industroyer lineage"],
      hyp:"If DNP3/20000 answers on {ip}, then without DNP3 Secure Authentication a rogue master can issue control (operate / direct-operate) to this outstation.",
      confirm:"Is DNP3-SA in use? Usually not. Zone-check. Hunt for unexpected masters and unsolicited-response manipulation.",
      note:"Common in electric and water utilities. Rogue-master (T0848) is the signature abuse." },

    { match:{ service:["iec-104","iec104"], port:[2404] }, protocol:"IEC 60870-5-104", purdue:"L1-L2",
      tech:[{id:"T0855",name:"Unauthorized Command Message"},{id:"T0869",name:"Standard Application Layer Protocol"}],
      ref:"/playbooks/environments/airgap-ot.html", also:["/playbooks/actors/sandworm.html"], signal:"strong", noise:"low",
      actors:["Sandworm (Industroyer / Industroyer2)"],
      hyp:"If IEC-104/2404 answers on {ip}, then unauthenticated ASDU control commands can operate breakers and switches. This is the exact protocol Industroyer2 weaponized against the grid.",
      confirm:"Zone-check. Hunt for C_SC / C_DC (single/double command) ASDUs from unexpected controlling stations. Cross-reference the Sandworm playbook.",
      note:"European transmission-grid protocol. Industroyer (2016) and Industroyer2 (2022) both drove 104." },

    { match:{ service:["bacnet"], port:[47808] }, protocol:"BACnet/IP", purdue:"L1-L2",
      tech:[{id:"T0846",name:"Remote System Discovery"},{id:"T0888",name:"Remote System Information Discovery"},{id:"T0855",name:"Unauthorized Command Message"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low",
      actors:["commodity building-automation scanners"],
      hyp:"If BACnet/47808 answers on {ip}, then building-automation points (HVAC, access control, lighting) are enumerable and writable without auth.",
      confirm:"WhoIs / ReadProperty enumeration reveals the device inventory. Zone-check against your BAS segment. Life-safety points (smoke control, stairwell pressurization) rank highest.",
      note:"Facility/BAS side. Lower kinetic risk than process control, but access-control and smoke systems matter." },

    { match:{ service:["opcua","opc-ua","opcua-tcp"], port:[4840] }, protocol:"OPC UA", purdue:"L2-L3",
      tech:[{id:"T0888",name:"Remote System Information Discovery"},{id:"T0846",name:"Remote System Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low",
      actors:["PIPEDREAM/INCONTROLLER (OPC UA module)"],
      hyp:"If OPC UA/4840 answers on {ip}, then it aggregates process data across many devices - a high-value pivot, and PIPEDREAM shipped a dedicated OPC UA module.",
      confirm:"Check whether the endpoint enforces a security policy (many run None / anonymous). Zone-check. OPC UA sits at the IT/OT seam and is often the reachable stepping-stone into L1/L2.",
      note:"Aggregation point - one compromise reaches many downstream devices. Matched on 4840 binary only, not 80/443 XML." },

    { match:{ service:["niagara-fox","fox"], port:[1911,4911] }, protocol:"Niagara Fox (Tridium)", purdue:"L2",
      tech:[{id:"T0846",name:"Remote System Discovery"},{id:"T0812",name:"Default Credentials"},{id:"T0888",name:"Remote System Information Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low",
      actors:["commodity","default-credential abuse"],
      hyp:"If Niagara Fox/1911 answers on {ip}, then fox-info leaks station/host/version, and Tridium platforms have a long history of default creds and disclosure CVEs.",
      confirm:"fox-info offline for version. Check for default credentials. Zone-check the BAS segment.",
      note:"Very common building-automation framework - broad install base, broad exposure." },

    { match:{ service:["codesys"], port:[2455,1200] }, protocol:"CODESYS runtime", purdue:"L1-L2",
      tech:[{id:"T0843",name:"Program Download"},{id:"T0855",name:"Unauthorized Command Message"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["PIPEDREAM/INCONTROLLER (CODESYS)","CODESYS CVE set"],
      hyp:"If CODESYS/2455 answers on {ip}, then the runtime underlies dozens of PLC brands; older versions allow unauthenticated program download and carry a large CVE set.",
      confirm:"Identify runtime version. Zone-check. CODESYS is a shared OEM runtime, so the same exposure spans many vendors at once.",
      note:"PIPEDREAM's CODESYS module targeted this broadly across brands." },

    { match:{ service:["omron","fins"], port:[9600] }, protocol:"Omron FINS", purdue:"L1-L2",
      tech:[{id:"T0855",name:"Unauthorized Command Message"},{id:"T0846",name:"Remote System Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["PIPEDREAM/INCONTROLLER (Omron)"],
      hyp:"If Omron FINS/9600 answers on {ip}, then FINS commands (run/stop, memory read-write) are accepted without auth. PIPEDREAM shipped a dedicated Omron module.",
      confirm:"Zone-check. Hunt FINS run/stop and memory-area write commands from non-engineering hosts.",
      note:"Omron Sysmac/CJ/CS - one of PIPEDREAM's three named PLC targets." },

    { match:{ service:["profinet","pn-io"], port:[34962,34963,34964] }, protocol:"PROFINET", purdue:"L1",
      tech:[{id:"T0842",name:"Network Sniffing"},{id:"T0846",name:"Remote System Discovery"},{id:"T0814",name:"Denial of Service"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low", actors:["commodity"],
      hyp:"If PROFINET/34962-4 is present on {ip}, then real-time fieldbus is reachable at L1 - DCP discovery and PN-IO manipulation become possible.",
      confirm:"PROFINET is normally L1-only; reaching it from above the cell/field zone is itself the violation. Hunt DCP set-name / set-IP.",
      note:"Siemens fieldbus. Presence above L1 is the signal." },

    { match:{ service:["melsec","melsoft"], port:[5006,5007] }, protocol:"Mitsubishi MELSEC-Q", purdue:"L1-L2",
      tech:[{id:"T0855",name:"Unauthorized Command Message"},{id:"T0888",name:"Remote System Information Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low", actors:["commodity"],
      hyp:"If MELSEC/5007 answers on {ip}, then Mitsubishi PLC CPU info and control are reachable; MELSOFT has weak-to-no auth.",
      confirm:"melsecq-discover for CPU model. Zone-check.", note:"Common in APAC manufacturing lines." },

    { match:{ service:["pcworx","proconos"], port:[20547,1962] }, protocol:"Phoenix Contact PCWorx / ProConOS", purdue:"L1-L2",
      tech:[{id:"T0843",name:"Program Download"},{id:"T0888",name:"Remote System Information Discovery"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low", actors:["commodity"],
      hyp:"If PCWorx/20547 answers on {ip}, then Phoenix Contact controller info and program interaction are exposed without auth.",
      confirm:"pcworx-info offline. Zone-check.", note:"Phoenix Contact ILC/AXC controllers." },

    { match:{ service:["tristation"], port:[1502] }, protocol:"Triconex TriStation (Safety Instrumented System)", purdue:"SIS / L1",
      tech:[{id:"T0800",name:"Activate Firmware Update Mode"},{id:"T0836",name:"Modify Parameter"},{id:"T0855",name:"Unauthorized Command Message"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"strong", noise:"low",
      actors:["TRITON / TRISIS (Xenotime)"],
      hyp:"If TriStation/1502 answers on {ip}, then a Schneider Triconex SAFETY controller is reachable - the exact target of TRITON, the malware built to disable safety systems. This is a life-safety finding.",
      confirm:"A safety-instrumented system reachable from anywhere but its dedicated engineering station is top-severity, full stop. Verify the source and escalate. Do NOT actively probe the SIS.",
      note:"SIS is the last line before physical harm. TRITON/TRISIS targeted Triconex specifically - treat reachability as critical." },

    { match:{ service:["moxa","nport"], port:[4800,4900] }, protocol:"Moxa NPort serial gateway", purdue:"L1-L2 bridge",
      tech:[{id:"T0842",name:"Network Sniffing"},{id:"T0846",name:"Remote System Discovery"},{id:"T0812",name:"Default Credentials"}],
      ref:"/playbooks/environments/airgap-ot.html", signal:"moderate", noise:"low", actors:["commodity"],
      hyp:"If a Moxa NPort serial gateway answers on {ip}, then it bridges IP to raw serial field devices - the seam where routable networks meet non-routable OT.",
      confirm:"Serial gateways are prime IT/OT bridge points and ship with default creds. Zone-check and credential-check.",
      note:"Bridges are how a routable-network foothold reaches serial-only field gear." }
  ]
};

/* Expose for the browser generator page (top-level const does not attach to window). */
if (typeof window !== "undefined") window.SCAN_CORRELATION = SCAN_CORRELATION;
/* Node/CommonJS export for the offline intake reader / test harness. */
if (typeof module !== "undefined" && module.exports) module.exports = SCAN_CORRELATION;
