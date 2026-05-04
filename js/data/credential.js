// TA0006 - Credential Access
// 12 techniques · 20 indicators · AD-protocol detection (Kerberos, NTLM, LDAP, DCERPC)

const DATA = [
  {
    id: "T1558.003",
    name: "Steal or Forge Kerberos Tickets: Kerberoasting",
    desc: "RC4 TGS-REQ harvesting for offline cracking - Rubeus, Impacket GetUserSPNs, PowerView Invoke-Kerberoast",
    rows: [
      {
        sub: "T1558.003 - RC4 Ticket Requests",
        indicator: "Kerberos TGS-REQ with RC4-HMAC etype - Kerberoasting signature",
        arkime: `ip.src == $INTERNAL
&& port.dst == 88
&& protocols == kerberos
&& kerberos.msg-type == 12
&& kerberos.cipher == rc4-hmac
&& kerberos.sname != krbtgt`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 88
AND kerberos.msg_type: "tgs-req"
AND kerberos.cipher: "rc4-hmac"
AND NOT kerberos.cname: krbtgt`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 88
  (msg:"TA0006 T1558.003 Kerberos
    TGS-REQ with RC4-HMAC etype
    Kerberoasting signature";
  flow:established,to_server;
  content:"|a0 03 02 01 05|"; depth:5;
  content:"|a1 03 02 01 0c|"; within:20;
  content:"|a0 03 02 01 17|";
  classtype:trojan-activity;
  sid:9155801; rev:1;)`,
        notes: "In modern AD environments (2008 R2+), Kerberos defaults to AES256 for service tickets when both client and server support it. RC4-HMAC (etype 23, encoded as 0x17 in ASN.1) is requested explicitly by Kerberoasting tools to produce crackable hashes. Detection: TGS-REQ messages where etype includes RC4 but doesn't include AES, or where the requested service is anomalous. Tools: Rubeus (kerberoast command), Impacket GetUserSPNs.py, PowerView Invoke-Kerberoast, BloodHound's roastable users query. The msg-type=12 = TGS-REQ; cipher=rc4-hmac in Zeek's kerberos.log is the canonical detection field. Modern environments should set 'msDS-SupportedEncryptionTypes' on service accounts to AES-only - accounts still permitting RC4 are the roastable targets. Pair with subsequent service ticket use (rare for Kerberoasting since the goal is offline cracking) for full-chain.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Kerberoasting is universal in red team operations - first thing every operator runs after gaining domain user access." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-ir", name: "APT34", note: "Kerberoasting in operations against Middle Eastern government and energy targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate playbooks for service account credential compromise." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all advanced threat actor operations targeting AD environments." }
        ],
        cite: "MITRE ATT&CK T1558.003, CISA AA23-320A"
      },
      {
        sub: "T1558.003 - Pre-Roast Enumeration",
        indicator: "Bulk SPN enumeration via LDAP preceding Kerberoasting - service account discovery",
        arkime: `ip.src == $INTERNAL
&& ip.src != $LDAP_ADMINS
&& port.dst == 389
&& protocols == ldap
&& ldap.filter =~
  /servicePrincipalName=\\*/i
&& ldap.scope == subtree`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $LDAP_ADMINS
AND destination.port: 389
AND ldap.filter: *servicePrincipalName=*
AND ldap.scope: "subtree"`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 389
  (msg:"TA0006 T1558.003 LDAP query
    for servicePrincipalName SPN
    enumeration pre-Kerberoast";
  flow:established,to_server;
  content:"servicePrincipalName=*";
  nocase;
  classtype:trojan-activity;
  sid:9155802; rev:1;)`,
        notes: "Before Kerberoasting, adversaries enumerate which accounts have SPNs (and are therefore roastable). The standard query is an LDAP search with filter '(&(samAccountType=805306368)(servicePrincipalName=*))' - find user accounts (not computer accounts) with SPNs. PowerView Get-DomainUser -SPN, BloodHound's collector, Impacket GetUserSPNs all use this pattern. The enumeration phase precedes the actual TGS-REQ requests by seconds-to-minutes. Detection at the LDAP filter level catches this preparation step. Pair with sid 9155801 (RC4 TGS-REQ) for full kill-chain visibility - first the enum, then the roast. Legitimate use: AD admin tools (Active Directory Users and Computers, PowerShell AD module) - restrict to $LDAP_ADMINS allowlist. After exclusions, this query from a workstation is essentially always pre-Kerberoasting.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Standard pre-Kerberoasting enumeration via PowerView, BloodHound, Impacket." },
          { cls: "apt-mul", name: "Scattered Spider", note: "SPN enumeration documented in CISA AA23-320A operations." },
          { cls: "apt-ir", name: "APT34", note: "AD enumeration including SPN discovery in operations." },
          { cls: "apt-ru", name: "APT29", note: "SPN enumeration in espionage operations including SolarWinds." },
          { cls: "apt-mul", name: "Multi", note: "The canonical pre-Kerberoasting step. Documented across virtually all advanced operations." }
        ],
        cite: "MITRE ATT&CK T1558.003, T1087.002"
      },
      {
        sub: "T1558.003 - Bulk Roasting",
        indicator: "TGS-REQ burst from single source - bulk roasting across multiple SPNs",
        arkime: `ip.src == $INTERNAL
&& port.dst == 88
&& protocols == kerberos
&& kerberos.msg-type == 12
&& unique-sname-count groupby
  ip.src > 5 within 60s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 88
AND kerberos.msg_type: "tgs-req"`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 88
  (msg:"TA0006 T1558.003 TGS-REQ
    burst single source many
    SPNs Kerberoasting";
  flow:established,to_server;
  content:"|a1 03 02 01 0c|";
  threshold:type both,
    track by_src,
    count 5, seconds 60;
  classtype:trojan-activity;
  sid:9155803; rev:1;)`,
        notes: "After enumerating SPNs, adversaries request service tickets for many of them in rapid succession - Rubeus kerberoast hits all roastable accounts by default; Impacket GetUserSPNs with -request flag does the same. The burst pattern: 5+ TGS-REQ messages from one source for 5+ distinct SPNs within 60 seconds. Legitimate Kerberos traffic rarely produces this pattern - applications request tickets for the specific services they need, one or two at a time. The bulk pattern is essentially diagnostic of Kerberoasting tooling. Pair with sid 9155801 (RC4 etype) - the same TGS-REQ messages should also have RC4 etype. The combined signature (burst + RC4) is essentially Kerberoasting proof. Tune threshold based on environment: very busy app servers or some legacy services may produce baseline TGS-REQ volume that warrants higher thresholds for those source IPs.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Bulk roasting is the standard Rubeus/Impacket/PowerView tooling pattern." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Bulk Kerberoasting is universal in ransomware operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA Scattered Spider advisory and across red team and threat actor operations." }
        ],
        cite: "MITRE ATT&CK T1558.003, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1558.004",
    name: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    desc: "Targeting accounts with UF_DONT_REQUIRE_PREAUTH - AS-REQ without PA-ENC-TIMESTAMP, RC4 AS-REP",
    rows: [
      {
        sub: "T1558.004 - Target Enumeration",
        indicator: "LDAP query for UF_DONT_REQUIRE_PREAUTH - AS-REProast target enumeration",
        arkime: `ip.src == $INTERNAL
&& ip.src != $LDAP_ADMINS
&& port.dst == 389
&& protocols == ldap
&& ldap.filter =~
  /userAccountControl:1\\.2\\.840\\.113556\\.1\\.4\\.803:=4194304/i`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $LDAP_ADMINS
AND destination.port: 389
AND ldap.filter: *userAccountControl*4194304*`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 389
  (msg:"TA0006 T1558.004 LDAP query
    for DONT_REQ_PREAUTH flag
    AS-REProast enumeration";
  flow:established,to_server;
  content:"4194304"; nocase;
  content:"1.2.840.113556.1.4.803";
  classtype:trojan-activity;
  sid:9155804; rev:1;)`,
        notes: "The standard AS-REProasting enumeration query uses the AD bitwise-AND matching rule (OID 1.2.840.113556.1.4.803) to find accounts where userAccountControl has the 0x400000 (4194304 decimal) bit set - the DONT_REQ_PREAUTH flag. Tools: Rubeus asreproast, Impacket GetNPUsers.py, PowerView Get-DomainUser -PreauthNotRequired. The LDAP filter pattern is highly distinctive - the bitwise-AND matching rule with 4194304 is essentially never used legitimately. Detection at the filter level catches the preparation step before AS-REP requests. Modern best practice: ZERO accounts should have DONT_REQ_PREAUTH set. If your environment has any, they're security debt - typically legacy service accounts or accounts created by older identity management products. Periodic audit query: 'Get-ADUser -Filter * -Properties UserAccountControl | ? { $_.UserAccountControl -band 4194304 }'.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "AS-REProast enumeration via Rubeus, Impacket, PowerView." },
          { cls: "apt-mul", name: "Scattered Spider", note: "AS-REProasting documented in CISA AA23-320A." },
          { cls: "apt-ir", name: "APT34", note: "AD enumeration including AS-REProast targets." },
          { cls: "apt-mul", name: "Multi", note: "Documented across advanced threat operations and red team engagements." }
        ],
        cite: "MITRE ATT&CK T1558.004, T1087.002"
      },
      {
        sub: "T1558.004 - AS-REQ Without Preauth",
        indicator: "Kerberos AS-REQ without preauth - AS-REProast ticket request",
        arkime: `ip.src == $INTERNAL
&& port.dst == 88
&& protocols == kerberos
&& kerberos.msg-type == 10
&& kerberos.padata-type != 2
&& kerberos.cipher == rc4-hmac`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 88
AND kerberos.msg_type: "as-req"
AND NOT kerberos.padata_type: "PA-ENC-TIMESTAMP"
AND kerberos.cipher: "rc4-hmac"`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 88
  (msg:"TA0006 T1558.004 AS-REQ
    without PA-ENC-TIMESTAMP
    AS-REProasting attempt";
  flow:established,to_server;
  content:"|a1 03 02 01 0a|"; depth:10;
  content:!"|a1 03 02 01 02|"; within:200;
  classtype:trojan-activity;
  sid:9155805; rev:1;)`,
        notes: "Normal Kerberos AS-REQ exchanges include PA-ENC-TIMESTAMP (padata-type 2) - a timestamp encrypted with the user's password hash, proving they know the password before the KDC issues the AS-REP. AS-REProasting bypasses this: AS-REQ without PA-ENC-TIMESTAMP, KDC returns AS-REP with encrypted ticket data anyway because the account allows it. Detection: AS-REQ messages (msg-type 10) without padata-type 2. Combined with RC4 etype, this is essentially diagnostic of AS-REProasting. The negative content match in Suricata (content:!\"|a1 03 02 01 02|\" within preauth field) catches the missing PA-ENC-TIMESTAMP. Zeek's kerberos.log captures padata-type cleanly; Kibana detection is straightforward. Note: legitimate AS-REQ from misconfigured accounts will fire this - but those accounts ARE the security debt that needs fixing, so the alerts are still actionable.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "AS-REProasting in red team operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A." },
          { cls: "apt-ir", name: "APT34", note: "AS-REProast in operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and across red team operations. Less common than Kerberoasting but produces cleaner crackable hashes when applicable." }
        ],
        cite: "MITRE ATT&CK T1558.004"
      }
    ]
  },
  {
    id: "T1003.006",
    name: "OS Credential Dumping: DCSync",
    desc: "DRSUAPI replication abuse - DsGetNCChanges from non-DC source for password hash extraction",
    rows: [
      {
        sub: "T1003.006 - DRSUAPI Bind",
        indicator: "DRSUAPI bind from non-DC source - DCSync interface activation",
        arkime: `ip.src == $INTERNAL
&& ip.src != $DOMAIN_CONTROLLERS
&& port.dst == 135
&& protocols == dcerpc
&& dcerpc.interface ==
  e3514235-4b06-11d1-ab04-00c04fc2dcd2
&& dcerpc.opnum == [0 || 3]`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $DOMAIN_CONTROLLERS
AND destination.port: 135
AND dcerpc.interface_uuid: "e3514235-4b06-11d1-ab04-00c04fc2dcd2"`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 135
  (msg:"TA0006 T1003.006 DRSUAPI
    bind from non-DC source DCSync
    activity";
  flow:established,to_server;
  content:"|35 42 51 e3 06 4b d1 11|";
  content:"|ab 04 00 c0 4f c2 dc d2|";
  within:8;
  classtype:trojan-activity;
  sid:9100601; rev:1;)`,
        notes: "DRSUAPI (UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2) is the Directory Replication Service Remote Protocol. Legitimate use: domain controllers replicating with each other. Adversary use: Mimikatz lsadump::dcsync, Impacket secretsdump.py, DSInternals, Get-ADReplAccount. The first sign of DCSync on the network is an RPC bind to the DRSUAPI interface from a non-DC source. Tight detection: $DOMAIN_CONTROLLERS allowlist excludes DC-to-DC replication; ANY other source binding to DRSUAPI is DCSync. Near-zero false positives. Pair with sid 9100602 (DsGetNCChanges call) for definitive proof - the bind is the activation, the subsequent opnum 3 call is the actual hash request. Particularly important to alert on regardless of source - even from another server, DCSync indicates compromise of a privileged account.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "DCSync via Mimikatz lsadump::dcsync is universal in red team operations after privilege escalation." },
          { cls: "apt-ru", name: "APT29", note: "DCSync extensively used in SolarWinds compromise to obtain krbtgt hash for Golden Tickets." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware operations targeting AD environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all advanced threat operations targeting AD environments." }
        ],
        cite: "MITRE ATT&CK T1003.006, CISA AA23-320A"
      },
      {
        sub: "T1003.006 - Replication Call",
        indicator: "DsGetNCChanges call - actual replication / hash retrieval request",
        arkime: `ip.src == $INTERNAL
&& ip.src != $DOMAIN_CONTROLLERS
&& port.dst == 135
&& protocols == dcerpc
&& dcerpc.interface ==
  e3514235-4b06-11d1-ab04-00c04fc2dcd2
&& dcerpc.opnum == 3`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $DOMAIN_CONTROLLERS
AND destination.port: 135
AND dcerpc.interface_uuid: "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
AND dcerpc.opnum: 3`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 135
  (msg:"TA0006 T1003.006 DsGetNC
    Changes from non-DC source
    DCSync hash retrieval";
  flow:established,to_server;
  content:"|35 42 51 e3 06 4b d1 11|";
  content:"|03 00 00 00|"; within:50;
  classtype:trojan-activity;
  sid:9100602; rev:1;)`,
        notes: "DsGetNCChanges (opnum 3) is the actual replication call - this is where password hashes are returned. The request includes the DN of the object to replicate (typically CN=krbtgt for Golden Ticket setup, or specific user/admin DNs). The response contains encrypted password hashes that the attacker decrypts using the session key. Detection: opnum 3 calls to DRSUAPI from non-DC sources. The signature is essentially proof of DCSync - it goes beyond binding the interface to actually requesting replication. Mimikatz, Impacket secretsdump, DSInternals all generate this traffic. Critical to alert on - DCSync is one of the highest-severity events in any AD environment. Combine with subsequent Kerberos activity from the same source (forged ticket use) for kill-chain through to T1558.001 Golden Ticket.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Mimikatz lsadump::dcsync universal in red team operations." },
          { cls: "apt-ru", name: "APT29", note: "DCSync for krbtgt hash extraction in SolarWinds compromise." },
          { cls: "apt-mul", name: "Scattered Spider", note: "DCSync documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware operations for full domain compromise." },
          { cls: "apt-mul", name: "Multi", note: "Documented in Microsoft, Mandiant, CrowdStrike research. Universal in advanced AD attack playbooks." }
        ],
        cite: "MITRE ATT&CK T1003.006"
      }
    ]
  },
  {
    id: "T1110.003",
    name: "Brute Force: Password Spraying",
    desc: "One password against many users - Kerberos AS-REQ burst, NTLM auth burst patterns",
    rows: [
      {
        sub: "T1110.003 - Kerberos Spray",
        indicator: "Kerberos AS-REQ burst with many distinct CNAMEs - Kerberos password spray",
        arkime: `ip.src == $INTERNAL
&& port.dst == 88
&& protocols == kerberos
&& kerberos.msg-type == 10
&& unique-cname-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 88
AND kerberos.msg_type: "as-req"`,
        suricata: `alert tcp $HOME_NET any
  -> $DOMAIN_CONTROLLERS 88
  (msg:"TA0006 T1110.003 Kerberos
    AS-REQ burst many usernames
    password spray";
  flow:established,to_server;
  content:"|a1 03 02 01 0a|";
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:trojan-activity;
  sid:9111003; rev:1;)`,
        notes: "Password spraying via Kerberos: one password tried against many usernames produces a burst of AS-REQ messages from one source for many distinct CNAMEs (client principal names). Tools: Rubeus brute, kerbrute, Spray365. The pattern: 10+ distinct CNAMEs in AS-REQ from one source within 5 minutes. Failed AS-REQ produces KRB-ERROR with code KDC_ERR_PREAUTH_FAILED (24) for valid users with wrong password, KDC_ERR_C_PRINCIPAL_UNKNOWN (6) for invalid users - adversaries can use the response codes to enumerate valid usernames separately from the spray. Pair with Windows Event ID 4768 (TGT requested) failure events on DCs for definitive correlation. Particularly important to detect during off-hours or from unusual source IPs (cloud, residential) which indicate external password sprays after credential leaks.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Password spraying documented in CISA AA23-320A - primary initial access technique." },
          { cls: "apt-ru", name: "APT29", note: "Spraying extensively used in SolarWinds compromise and ongoing operations." },
          { cls: "apt-ir", name: "APT34", note: "Password spraying in operations against Middle Eastern targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware affiliate initial access." },
          { cls: "apt-mul", name: "Multi", note: "Universal in modern operations across virtually all threat actor categories." }
        ],
        cite: "MITRE ATT&CK T1110.003, CISA AA23-320A"
      },
      {
        sub: "T1110.003 - NTLM Spray",
        indicator: "NTLM authentication burst with many usernames - SMB / HTTP password spray",
        arkime: `ip.src == $INTERNAL
&& port.dst == [445 || 80 || 443]
&& ntlm.username != null
&& unique-username-count groupby
  ip.src > 10 within 300s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (445 OR 80 OR 443)
AND _exists_: ntlm.username`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [445,80,443]
  (msg:"TA0006 T1110.003 NTLM auth
    burst many usernames password
    spray";
  flow:established,to_server;
  content:"NTLMSSP|00|"; nocase;
  threshold:type both,
    track by_src,
    count 10, seconds 300;
  classtype:trojan-activity;
  sid:9111004; rev:1;)`,
        notes: "NTLM password spraying targets services that accept NTLM authentication: SMB (TCP/445), HTTP (TCP/80), HTTPS (TCP/443) for IIS apps, OWA, ADFS. Tools: CrackMapExec, MailSniper, custom scripts. The username field is visible in the NTLMSSP_AUTHENTICATE message even though the password hash is not - Zeek's ntlm.log captures usernames. Pattern: 10+ distinct usernames from one source within 5 minutes against the same or different targets. Internal NTLM spraying (workstation to file servers) indicates lateral spray after initial compromise; external NTLM spraying (internet-facing OWA, ADFS) is initial access. Both are critical to catch. Modern advice: disable NTLM where possible (Kerberos-only environments). Where NTLM remains, this signature is high-confidence.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "NTLM spraying documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "External NTLM spraying against OWA documented as primary initial access vector for Cozy Bear operations." },
          { cls: "apt-ir", name: "APT34", note: "OWA/ADFS spraying in operations." },
          { cls: "apt-mul", name: "Ransomware", note: "External-facing NTLM spraying universal in ransomware initial access." },
          { cls: "apt-mul", name: "Initial Access Brokers", note: "IABs heavily use NTLM spraying against internet-facing services." },
          { cls: "apt-mul", name: "Multi", note: "Documented as primary initial access vector across CISA, FBI, NCSC reporting." }
        ],
        cite: "MITRE ATT&CK T1110.003"
      }
    ]
  },
  {
    id: "T1187",
    name: "Forced Authentication",
    desc: "RPC coercion attacks - PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), DFSCoerce (MS-DFSNM)",
    rows: [
      {
        sub: "T1187 - PetitPotam",
        indicator: "PetitPotam - MS-EFSRPC EfsRpcOpenFileRaw / OpenSecuredFile call",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  c681d488-d850-11d0-8c52-00c04fd90f7e
&& dcerpc.opnum == [0 || 4 || 5 || 7 || 9 || 10 || 11 || 12 || 13 || 15]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "c681d488-d850-11d0-8c52-00c04fd90f7e"
AND dcerpc.opnum: (0 OR 4 OR 5 OR 7 OR 9 OR 10 OR 11 OR 12 OR 13 OR 15)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0006 T1187 PetitPotam
    MS-EFSR coercion call";
  flow:established,to_server;
  content:"|88 d4 81 c6 50 d8 d0 11|";
  content:"|8c 52 00 c0 4f d9 0f 7e|";
  within:8;
  classtype:trojan-activity;
  sid:9118701; rev:1;)`,
        notes: "MS-EFSRPC (Encrypting File System Remote Protocol, UUID c681d488-d850-11d0-8c52-00c04fd90f7e) was originally for managing encrypted file system operations remotely. PetitPotam (Lionel Gilles, 2021) discovered that several functions accept arbitrary UNC paths and trigger NTLM authentication to fetch them: EfsRpcOpenFileRaw (opnum 0), EfsRpcEncryptFileSrv (4), EfsRpcDecryptFileSrv (5), EfsRpcQueryUsersOnFile (7), EfsRpcQueryRecoveryAgents (9), EfsRpcRemoveUsersFromFile (10), EfsRpcAddUsersToFile (11), EfsRpcSetFileEncryptionKey (12), EfsRpcNotSupported (13), EfsRpcOpenSecuredFile (15). All can be called by any authenticated user against any system with the EFS service running. Microsoft has progressively patched some opnums; others remain. Detection at the interface level catches all PetitPotam variants. Combine with subsequent NTLM authentication from target to attacker for full chain confirmation.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "PetitPotam universal in modern red team AD attack chains. Combined with AD CS ESC8 = Domain Admin in one shot." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Coercion attacks documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Used by Conti, BlackCat, and across ransomware operations targeting AD environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented as primary path to Domain Admin in modern AD attacks. SpecterOps research." }
        ],
        cite: "MITRE ATT&CK T1187, T1557"
      },
      {
        sub: "T1187 - PrinterBug",
        indicator: "PrinterBug - MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  12345678-1234-abcd-ef00-0123456789ab
&& dcerpc.opnum == 65`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "12345678-1234-abcd-ef00-0123456789ab"
AND dcerpc.opnum: 65`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0006 T1187 PrinterBug
    MS-RPRN spooler coercion";
  flow:established,to_server;
  content:"|78 56 34 12 34 12 cd ab|";
  content:"|41 00 00 00|"; within:50;
  classtype:trojan-activity;
  sid:9118702; rev:1;)`,
        notes: "MS-RPRN (Print System Remote Protocol, UUID 12345678-1234-abcd-ef00-0123456789ab) - RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65) accepts an arbitrary UNC path for the change-notification destination, causing the target system to authenticate to the path. Discovered as 'PrinterBug' by Lee Christensen (SpecterOps, 2018) and documented in the original SpoolService research. Particularly devastating against domain controllers because the spooler service runs by default on DCs (until disabled per modern hardening guidance). Combined with AD CS Web Enrollment relay, PrinterBug → DA is a one-shot attack. Modern environments should disable the Print Spooler service on DCs (CIS benchmark recommendation). Detection at the spooler RPC opnum is high-confidence; legitimate use of opnum 65 is rare.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "PrinterBug + AD CS relay = one-shot Domain Admin in unhardened environments." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Coercion attacks documented in CISA AA23-320A." },
          { cls: "apt-ru", name: "APT28", note: "PrinterBug exploitation in some operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in extensive offensive security research. SpecterOps Lee Christensen original research." }
        ],
        cite: "MITRE ATT&CK T1187"
      },
      {
        sub: "T1187 - DFSCoerce",
        indicator: "DFSCoerce - MS-DFSNM coercion call",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == dcerpc
&& dcerpc.interface ==
  4fc742e0-4a10-11cf-8273-00aa004ae673
&& dcerpc.opnum == [12 || 13]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND dcerpc.interface_uuid: "4fc742e0-4a10-11cf-8273-00aa004ae673"
AND dcerpc.opnum: (12 OR 13)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0006 T1187 DFSCoerce
    MS-DFSNM coercion call";
  flow:established,to_server;
  content:"|e0 42 c7 4f 10 4a cf 11|";
  classtype:trojan-activity;
  sid:9118703; rev:1;)`,
        notes: "MS-DFSNM (DFS Namespace Management, UUID 4fc742e0-4a10-11cf-8273-00aa004ae673) - DFSCoerce (Filip Dragović, 2022) abuses NetrDfsRemoveStdRoot (opnum 12) and NetrDfsAddStdRoot (opnum 13) which accept UNC paths and trigger authentication. Less commonly mitigated than PetitPotam (Microsoft's PetitPotam patches don't help here). Particularly relevant against domain controllers running the DFS Namespace service. Detection at the interface UUID + opnum level. The technique is essentially identical to PetitPotam in flow - coerce auth, capture or relay. SpecterOps' Coercer.py tool implements this and many other coercion techniques in a single framework - common in red team operations. Worth maintaining alongside PetitPotam and PrinterBug for full coercion coverage.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "DFSCoerce in modern red team operations as PetitPotam alternative." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Coercion attacks documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Multi", note: "Disclosed 2022 by Filip Dragović as alternative when Microsoft's patches addressed EFSR. Used in modern operations and red team engagements." }
        ],
        cite: "MITRE ATT&CK T1187"
      }
    ]
  },
  {
    id: "T1557.001",
    name: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
    desc: "Responder-style attacks - answering broadcast name queries, capturing/relaying NTLM authentication",
    rows: [
      {
        sub: "T1557.001 - Responder Activity",
        indicator: "Responder fingerprint - answers to LLMNR/NBT-NS from non-DNS source",
        arkime: `ip.dst == $INTERNAL
&& port.src == [5355 || 137]
&& ip.src != $DNS_SERVERS
&& protocols == [llmnr || nbns]
&& dns.answer-count > 0`,
        kibana: `destination.ip: $INTERNAL
AND source.port: (5355 OR 137)
AND NOT source.ip: $DNS_SERVERS
AND _exists_: dns.answers`,
        suricata: `alert udp $HOME_NET [5355,137]
  -> $HOME_NET any
  (msg:"TA0006 T1557.001 LLMNR or
    NBT-NS response from non-DNS
    source Responder activity";
  flow:to_client;
  content:"|81 80|"; depth:4;
  classtype:trojan-activity;
  sid:9155701; rev:1;)`,
        notes: "Legitimate LLMNR/NBT-NS responders are: every Windows host on the broadcast domain (which is the problem - any host can answer), but in practice, large-scale answering (one host responding to many queries) is anomalous. Responder by default answers ALL queries - fingerprint: source IP appearing in many LLMNR/NBT-NS responses to many destinations within minutes. Detection: count responses by source IP per minute; any source answering more than a baseline (typically 5-10 unique destinations per 60 seconds) is suspicious. Modern best practice: DISABLE LLMNR and NBT-NS via Group Policy. Once disabled, ANY LLMNR/NBT-NS response on the network is adversary activity (zero false positive). The detection improvements when LLMNR is disabled are dramatic - strongly recommend pursuing this in environments where you have GPO control.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Universal in red team and internal pentest operations - first thing every operator runs after gaining LAN access." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Coercion / poisoning attacks documented in CISA AA23-320A." },
          { cls: "apt-mul", name: "Internal Pentests", note: "Documented in countless engagement reports as primary credential harvesting technique." },
          { cls: "apt-mul", name: "Multi", note: "Universal in operations with LAN access and modern AD targets." }
        ],
        cite: "MITRE ATT&CK T1557.001"
      },
      {
        sub: "T1557.001 - NTLM Relay",
        indicator: "NTLM authentication to non-server destination - relayed/captured authentication",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $INTERNAL
&& ip.dst != $SERVERS
&& port.dst == [445 || 80 || 443]
&& ntlm.challenge != null
&& session.duration < 10`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $INTERNAL
AND NOT destination.ip: $SERVERS
AND destination.port: (445 OR 80 OR 443)
AND _exists_: ntlm.challenge`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [445,80,443]
  (msg:"TA0006 T1557.001 NTLM
    authentication to non-server
    destination relay or capture";
  flow:established,to_server;
  content:"NTLMSSP|00 02 00 00 00|";
  classtype:trojan-activity;
  sid:9155702; rev:1;)`,
        notes: "After Responder/Inveigh/mitm6 captures an NTLM authentication, the attacker either: (1) saves the Net-NTLMv2 hash for offline cracking, or (2) relays it in real-time to another target (ntlmrelayx, Inveigh-Relay). The relay scenario produces a distinctive pattern: NTLM authentication FROM a workstation TO another workstation that doesn't normally accept NTLM logins. Build $SERVERS allowlist (your actual servers - file servers, app servers, DCs); any NTLM auth to a non-server internal destination is suspicious. Particularly diagnostic: NTLM auth TO a workstation = relayed credentials (workstations rarely accept incoming NTLM unless misconfigured). The challenge-response can also be relayed to LDAP/LDAPS for ACL modification, to MSSQL for xp_cmdshell, or to AD CS for certificate enrollment.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "NTLM relay universal in red team operations targeting AD environments." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A coercion and relay operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Modern ransomware operations use NTLM relay + AD CS for Domain Admin." },
          { cls: "apt-mul", name: "Multi", note: "Combined with PetitPotam/PrinterBug (T1187) and AD CS abuse, this is one of the primary paths to Domain Admin in modern environments." }
        ],
        cite: "MITRE ATT&CK T1557.001, T1187"
      }
    ]
  },
  {
    id: "T1558.001",
    name: "Steal or Forge Kerberos Tickets: Golden Ticket",
    desc: "krbtgt-forged TGT - TGS-REQ without preceding AS-REQ, anomalous ticket lifetimes and encryption types",
    rows: [
      {
        sub: "T1558.001 - Forged TGT Use",
        indicator: "Kerberos TGS-REQ from session lacking AS-REQ predecessor - forged TGT use",
        arkime: `ip.src == $INTERNAL
&& port.dst == 88
&& protocols == kerberos
&& kerberos.msg-type == 12
&& no-prior-as-req-from-src
  within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 88
AND kerberos.msg_type: "tgs-req"
AND NOT _exists_: previous_as_req_correlation`,
        suricata: `[Network detection of forged
Golden Tickets requires session
correlation across AS-REQ and
TGS-REQ messages. Suricata's
stateless model cannot do this
across long timeframes. Detection
via Zeek scripts that track
AS-REQ/TGS-REQ pairs, or via
host-side Event ID 4769 with
unusual ticket characteristics.]
N/A pure Suricata`,
        notes: "Golden Tickets are forged TGTs encrypted with the krbtgt account's NT hash (obtained via DCSync). The forged ticket can claim any user identity, any group membership, any expiration. Network signature: TGS-REQ messages where no prior AS-REQ exists for the same client principal - the 'TGT' came from nowhere on the wire. Zeek-based correlation can detect this (track AS-REQ events, alert on TGS-REQ without preceding AS-REQ within reasonable timeframe). Other detection signatures: ticket lifetimes anomalously long (10 years+ default in Mimikatz), ticket encryption type RC4 when AES is expected, account names that don't exist in AD. Rotating krbtgt password twice (12-hour spacing) invalidates all existing Golden Tickets - recommended whenever DCSync is observed. Particularly important to detect because Golden Tickets persist across user/admin password resets.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Golden Tickets in advanced red team operations - preferred persistence after full domain compromise." },
          { cls: "apt-ru", name: "APT29", note: "Golden Ticket persistence documented in SolarWinds compromise - survived initial remediation." },
          { cls: "apt-cn", name: "APT41", note: "Golden Tickets in long-term operations against technology and gaming sectors." },
          { cls: "apt-mul", name: "Ransomware", note: "Golden Tickets in some ransomware operations targeting AD environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in advanced threat operations including APT29 (SolarWinds). Persistence mechanism preferred when full domain compromise is achieved." }
        ],
        cite: "MITRE ATT&CK T1558.001"
      }
    ]
  },
  {
    id: "T1558.002",
    name: "Steal or Forge Kerberos Tickets: Silver Ticket",
    desc: "Service-key-forged TGS - AP-REQ presentation without preceding TGS-REQ, single-service scope",
    rows: [
      {
        sub: "T1558.002 - Forged Service Ticket",
        indicator: "Kerberos AP-REQ for service without preceding TGS-REQ - forged service ticket",
        arkime: `ip.src == $INTERNAL
&& port.dst == [445 || 80 || 88]
&& protocols == kerberos
&& kerberos.msg-type == 14
&& no-prior-tgs-req-from-src
  for-sname within 60s`,
        kibana: `source.ip: $INTERNAL
AND _exists_: kerberos.ap_req
AND NOT _exists_: previous_tgs_req_correlation`,
        suricata: `[Network detection of forged
Silver Tickets requires session
correlation across TGS-REQ and
AP-REQ presentation. Like Golden
Ticket detection, this requires
stateful correlation - typically
implemented in Zeek scripts
rather than Suricata signatures.]
N/A pure Suricata`,
        notes: "Silver Tickets are forged service tickets (TGS) encrypted with a service account's NT hash. They bypass the KDC entirely - the attacker presents the forged TGS directly to the target service, which trusts it because it's encrypted with its own key. Network signature: AP-REQ messages (msg-type 14) presenting a service ticket without any preceding TGS-REQ from the same client to the KDC. Even harder to detect than Golden Tickets because Silver Tickets don't touch the KDC at all. Detection requires service-side log correlation (Event ID 4624 with anomalous ticket characteristics) or Zeek-based session tracking. Mitigation: rotate service account passwords regularly (Silver Tickets remain valid until the password changes), use group Managed Service Accounts (gMSA) which auto-rotate.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Silver Tickets in advanced red team operations for stealthy service-specific persistence." },
          { cls: "apt-mul", name: "Persistent Operators", note: "Used by long-term threat actors targeting specific services without DC visibility." },
          { cls: "apt-mul", name: "Multi", note: "Less common than Golden Tickets due to limited scope (one service per ticket) but harder to detect. Used for stealthy persistence in advanced operations." }
        ],
        cite: "MITRE ATT&CK T1558.002"
      }
    ]
  },
  {
    id: "T1110.004",
    name: "Brute Force: Credential Stuffing",
    desc: "Leaked credential testing at scale - external auth bursts against many usernames",
    rows: [
      {
        sub: "T1110.004 - External Stuffing",
        indicator: "Authentication burst from external source against many accounts - leaked credential testing",
        arkime: `ip.src == $EXTERNAL
&& port.dst == [443 || 80]
&& http.uri =~
  /\\/login|\\/auth|\\/signin|\\/owa/i
&& unique-username-count groupby
  ip.src > 20 within 600s`,
        kibana: `source.ip: NOT $INTERNAL
AND destination.port: (443 OR 80)
AND url.path: (*login* OR *auth* OR *signin* OR *owa*)`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET [443,80]
  (msg:"TA0006 T1110.004 External
    auth burst many usernames
    credential stuffing";
  flow:established,to_server;
  pcre:"/(login|auth|signin|owa)/i";
  threshold:type both,
    track by_src,
    count 20, seconds 600;
  classtype:trojan-activity;
  sid:9111005; rev:1;)`,
        notes: "Credential stuffing tests username/password pairs from data breaches against your authentication endpoints. Differs from password spraying in that each attempt uses a different password (the leaked one for that user) - but the network pattern is similar: many distinct usernames from limited source IPs. Modern stuffing tools rotate IPs through residential proxy networks to evade rate limits - detection at the URI + username-count aggregation catches the pattern even when IP rotation hides single sources. Most relevant for internet-facing authentication: OWA/EWS/M365, ADFS, Okta, custom web apps, VPN portals (SSL VPN). Pair with: source IP reputation (residential proxy networks are high-suspicion), geographic anomalies (login attempts from countries the user has never been to), user-agent anomalies (automation framework UAs).",
        apt: [
          { cls: "apt-mul", name: "Initial Access Brokers", note: "Credential stuffing is primary IAB entry vector before selling access to ransomware operators." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Stuffing against M365 and Okta documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Cybercrime", note: "Universal across cybercrime operations targeting external services." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA, FBI, and industry reporting as primary external attack vector." }
        ],
        cite: "MITRE ATT&CK T1110.004"
      }
    ]
  },
  {
    id: "T1552.004",
    name: "Unsecured Credentials: Private Keys",
    desc: "SSH/PGP/certificate private key file access - id_rsa, .pem, .key, .ppk patterns",
    rows: [
      {
        sub: "T1552.004 - Private Key Exfiltration",
        indicator: "SMB / SCP file access for SSH private keys - id_rsa exfiltration pattern",
        arkime: `ip.src == $INTERNAL
&& port.dst == [445 || 22]
&& smb.filename =~
  /id_rsa|id_dsa|id_ecdsa|id_ed25519|
   \\.pem|\\.key|\\.ppk/i`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (445 OR 22)
AND file.name: (id_rsa* OR id_dsa* OR id_ecdsa* OR id_ed25519* OR *.pem OR *.key OR *.ppk)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET [445,22]
  (msg:"TA0006 T1552.004 SSH
    private key file access
    via SMB or SCP";
  flow:established,to_server;
  pcre:"/(id_rsa|id_dsa|id_ecdsa|
    id_ed25519|\\.pem|\\.key|
    \\.ppk)/i";
  classtype:trojan-activity;
  sid:9155204; rev:1;)`,
        notes: "Private keys are typically host-side artifacts but adversaries often exfiltrate them across the network: copying ~/.ssh/id_rsa from compromised Linux/Mac systems to attacker storage, dragging .pem files via SMB from jump hosts to staging shares, exfiltrating .ppk (PuTTY private keys) from Windows admin systems. Detection: filename patterns in SMB or SSH file transfer logs. The list covers the main SSH key types (RSA, DSA, ECDSA, Ed25519), generic .pem (PKCS#8 format used for many key types), .key (catch-all), .ppk (PuTTY). False positives possible: legitimate backup software, configuration management. Build $BACKUP_HOSTS allowlist. Pair with subsequent SSH activity from the destination host using the keys - the smoking-gun chain is 'private key copied from A to B → B uses key to SSH to C'.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "SSH key theft in red team operations targeting cloud and Linux infrastructure." },
          { cls: "apt-cn", name: "APT41", note: "SSH key theft documented in operations against technology and gaming sector targets." },
          { cls: "apt-kp", name: "Lazarus", note: "Key theft in cryptocurrency-targeted operations." },
          { cls: "apt-mul", name: "Cloud-focused threats", note: "Particularly relevant in cloud-native environments where SSH keys are primary auth method." },
          { cls: "apt-mul", name: "Multi", note: "Documented across cloud-focused threat operations." }
        ],
        cite: "MITRE ATT&CK T1552.004"
      }
    ]
  },
  {
    id: "T1003.001",
    name: "OS Credential Dumping: LSASS Memory",
    desc: "LSASS process memory dumping - exfiltration of .dmp files via SMB after host-side capture",
    rows: [
      {
        sub: "T1003.001 - LSASS Dump Exfiltration",
        indicator: "SMB write of memory dump files - exfiltrating LSASS dumps",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == write
&& smb.filename =~
  /lsass\\.dmp|lsass.{0,5}\\.dmp|
   \\.dmp$|memory\\.dmp/i
&& smb.filesize > 10485760`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "write"
AND file.name: (*lsass*.dmp* OR *.dmp OR *memory.dmp)
AND file.size > 10485760`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0006 T1003.001 SMB write
    of memory dump file LSASS
    exfiltration";
  flow:established,to_server;
  pcre:"/(lsass\\.dmp|memory\\.dmp|
    \\.dmp)/i";
  classtype:trojan-activity;
  sid:9100301; rev:1;)`,
        notes: "LSASS memory dumping (Mimikatz, ProcDump, Task Manager, comsvcs.dll MiniDump, custom tools) produces a .dmp file (typically 50-150MB for LSASS). Adversaries then exfiltrate the dump for offline credential extraction with pypykatz or Mimikatz. Network signal at the exfiltration step: SMB write of large .dmp files. The 10MB minimum threshold filters out small unrelated dumps. False positives: legitimate crash dumps being moved by IT, Windows Error Reporting (WER) artifacts - both should originate from sanctioned crash-collection servers ($CRASH_DUMP_SERVERS allowlist). After exclusions, large .dmp file movement is typically credential exfiltration. Pair with subsequent activity that suggests offline credential cracking: outbound traffic to attacker infrastructure, downloads of Mimikatz tools.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "LSASS dumping documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "LSASS dumps used in SolarWinds compromise." },
          { cls: "apt-cn", name: "APT41", note: "LSASS dumping in operations across multiple sectors." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware operations for credential harvesting before encryption." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all advanced threat operations." }
        ],
        cite: "MITRE ATT&CK T1003.001, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1556.006",
    name: "Modify Authentication Process: Multi-Factor Authentication",
    desc: "MFA fatigue / push bombing - repeated MFA prompts to wear users down into accepting",
    rows: [
      {
        sub: "T1556.006 - Push Bombing",
        indicator: "Repeated MFA push approvals from same source - push bombing pattern",
        arkime: `[Detection requires MFA provider
log access, not network only.
Okta system log: events of type
'user.authentication.auth_via_mfa'
with status 'DENIED' or 'PENDING'
in rapid succession from same
authentication context.
M365 Sign-in log: failed MFA
events from same IP/user pairing
within minutes.
Duo logs: similar pattern in
authentication response codes.]
N/A pure network detection`,
        kibana: `[MFA provider sign-in logs
required - Okta, Azure AD,
Duo, Ping Identity etc.
Look for: many MFA prompts
to same user from same auth
context within minutes,
followed by eventual approval.]`,
        suricata: `[T1556.006 MFA fatigue is detected
in the MFA provider's logs, not
on the network. The authentication
flow happens between user device
and MFA service - typically not
visible to enterprise network
monitoring unless TLS-decrypted
(which generally isn't done for
SaaS auth traffic).]
N/A pure Suricata`,
        notes: "MFA fatigue / push bombing: adversary has valid username + password, attempts authentication repeatedly, generating MFA push notifications to the user's phone. After enough prompts (sometimes hundreds), users accept one out of habit, exhaustion, or confusion. Documented Scattered Spider operations sent 100+ pushes over a single day to break victims. Detection requires MFA provider log access - Okta system logs, Azure AD sign-in logs, Duo logs. Mention here for kill-chain completeness because this is a critical modern Credential Access technique. Mitigations: number-matching MFA (user must type a number from the prompt), FIDO2 hardware tokens (no push to fatigue), behavioral analytics in the IDP that detects unusual MFA prompt frequency. SOC playbook: receive 'unusual MFA volume' alert from IDP → contact user via known channel → investigate authentication source.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "MFA fatigue heavily documented in CISA AA23-320A - 100+ pushes per victim observed." },
          { cls: "apt-ru", name: "APT29", note: "MFA fatigue against Microsoft, Okta, and others in 2022-2024 operations." },
          { cls: "apt-mul", name: "Cybercrime", note: "Increasingly common across cybercrime operations targeting SaaS environments." },
          { cls: "apt-mul", name: "Multi", note: "Increasingly common across operations targeting M365, Okta, Duo MFA-protected environments." }
        ],
        cite: "MITRE ATT&CK T1556.006, CISA AA23-320A"
      }
    ]
  }
];
