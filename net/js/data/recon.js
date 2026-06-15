const DATA = [
  {
    id: "T1589",
    name: "Gather Victim Identity Information",
    desc: ".001 Credentials · .002 Email Addresses · .003 Employee Names",
    rows: [
      {
        sub: "T1589.001 - Credentials",
        indicator: "[OFF-NET TRIPWIRE] Azure AD / O365 GetCredentialType username enumeration",
        arkime: "ip.src != $MPNET\n&& http.method == POST\n&& host.http ==\n  *login.microsoftonline.com*\n&& http.uri ==\n  */GetCredentialType*\n&& packets.src > 5",
        kibana: "NOT source.ip: $MPNET\nAND url.domain:\n  \"login.microsoftonline.com\"\nAND url.path: *GetCredentialType*\nAND http.request.method: POST",
        suricata: "alert http $EXTERNAL_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1589.001 AzureAD\n    GetCredentialType user enum\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  content:\"/common/GetCredentialType\";\n  http.uri;\n  threshold:type both,\n    track by_src,\n    count 10, seconds 60;\n  classtype:attempted-recon;\n  sid:9158901; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Returns UPN existence, auth method, and federation status without authentication. Tools: AADInternals, o365enum, TREVORspray. Enumerate thousands of usernames via this endpoint. Monitor via proxy/CASB egress logs - this hits Microsoft infrastructure, not your perimeter directly.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Used GetCredentialType enumeration to profile Microsoft corporate O365 tenants prior to 2024 corporate email compromise." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Profiles O365 tenants of academic, NGO, and government contractor targets using AADInternals-equivalent tooling." },
          { cls: "apt-kp", name: "Kimsuky", note: "Enumerates O365 users at think tanks and policy organizations." },
          { cls: "apt-cn", name: "ZIRCONIUM", note: "Used O365 user enumeration as precursor to credential phishing campaigns targeting presidential campaign staffers." }
        ],
        cite: "MITRE ATT&CK T1589.001, Microsoft MSTIC, industry reporting"
      },
      {
        sub: "T1589.001 - Credentials",
        indicator: "O365 Autodiscover username validation",
        arkime: "ip.src != $MPNET\n&& http.method == [GET, POST]\n&& host.http == [\"*autodiscover*\", \"*outlook.office365.com*\"]\n&& http.uri == [\"*/autodiscover.xml*\", \"*/autodiscover.json*\", \"*/mapi/emsmdb*\", \"*/mapi/nspi*\"]",
        kibana: "NOT source.ip: $MPNET\nAND url.domain: (\n  *autodiscover*\n  OR \"outlook.office365.com\"\n)\nAND url.path: (\n  *autodiscover.xml*\n  OR *autodiscover.json*\n  OR *mapi/emsmdb*\n  OR *mapi/nspi*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1589.001\n    Autodiscover user enum\";\n  flow:established,to_server;\n  pcre:\"/(autodiscover\\.xml|\n    autodiscover\\.json|\n    mapi\\/emsmdb|\n    mapi\\/nspi)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 30;\n  classtype:attempted-recon;\n  sid:9158902; rev:1;)",
        notes: "Autodiscover returns different HTTP response codes (200 vs 401 vs 404) per username - classic oracle. MAPI/NSPI endpoints particularly abused for Outlook profile enumeration. Tools: MailSniper, ruler, o365recon. 200 response to autodiscover with no prior auth session is a strong signal.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Autodiscover enumeration against on-premises Exchange in MSP customer environments during Cloud Hopper." },
          { cls: "apt-ru", name: "APT28", note: "Autodiscover and MAPI/NSPI enumeration against Exchange at election campaign/government targets." },
          { cls: "apt-ir", name: "APT33", note: "Autodiscover endpoint enumeration against on-premises Exchange at energy sector targets." }
        ],
        cite: "MITRE ATT&CK T1589.001, CISA Exchange advisories, industry reporting"
      },
      {
        sub: "T1589.001 - Credentials",
        indicator: "OWA / EWS user enumeration via timed response differential",
        arkime: "ip.src != $MPNET\n&& http.method == POST\n&& host.http == [\"*owa*\", \"*webmail*\", \"*exchange*\"]\n&& http.uri == [\"*/owa/auth.owa*\", \"*/EWS/Exchange.asmx*\"]\n&& http.statuscode == [401, 403, 200]\n&& packets.src > 10",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: POST\nAND url.path: (\n  *owa/auth.owa*\n  OR *EWS/Exchange.asmx*\n  OR */ews/*\n)\nAND http.response.status_code:\n  (401 OR 403 OR 200)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1589.001 OWA/EWS\n    auth endpoint enum\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(owa\\/auth\\.owa|\n    EWS\\/Exchange\\.asmx|\n    ews\\/exchange)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 60;\n  classtype:attempted-user;\n  sid:9158903; rev:1;)",
        notes: "OWA returns subtly different responses for valid vs invalid usernames - timing oracle. EWS abused by MailSniper and ruler for both enumeration and post-auth data collection. Monitor sustained POST volume outside business hours especially. A patient operator at 1 request/30 seconds will slip under the threshold - supplement with 24-hour cumulative Kibana query.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "OWA/EWS enumeration as standard step in MSP compromise chains using MailSniper-equivalent tooling." },
          { cls: "apt-ir", name: "APT33", note: "OWA targeted at energy sector/defense contractor organizations for credential collection." },
          { cls: "apt-ru", name: "APT28", note: "OWA enumeration against government and military Exchange deployments." },
          { cls: "apt-kp", name: "Kimsuky", note: "OWA credential enumeration against South Korean government organizations and US think tanks." }
        ],
        cite: "MITRE ATT&CK T1589.001, CISA AA21-116A, industry reporting"
      },
      {
        sub: "T1589.001 - Credentials",
        indicator: "[OFF-NET TRIPWIRE] Credential validation against breach / leak check APIs - internal host",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*haveibeenpwned.com*\", \"*dehashed.com*\", \"*leakcheck.io*\", \"*snusbase.com*\", \"*intelx.io*\", \"*breachdirectory.org*\"]\n&& http.method == [GET, POST]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"haveibeenpwned.com\"\n  OR \"dehashed.com\"\n  OR \"leakcheck.io\"\n  OR \"snusbase.com\"\n  OR \"intelx.io\"\n  OR \"breachdirectory.org\"\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1589.001 Internal\n    host breach DB query\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    haveibeenpwned\\.com|\n    dehashed\\.com|\n    leakcheck\\.io|snusbase\\.com|\n    intelx\\.io|\n    breachdirectory\\.org)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9158904; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Internal hosts querying breach databases against your own domain = red team (document it) or compromised host validating harvested creds before use. Dehashed/Snusbase/IntelX are paid API services - automated bulk queries from an endpoint = adversarial tooling signal. Correlate source host identity.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Validated harvested credential lists against breach databases prior to financial sector targeting and credential stuffing." },
          { cls: "apt-ir", name: "APT33", note: "Used breach database lookups to identify previously compromised employee accounts at energy sector targets." },
          { cls: "apt-mul", name: "Multi", note: "Common in post-compromise and insider threat scenarios. Criminal access broker workflows." }
        ],
        cite: "MITRE ATT&CK T1589.001, T1586.002, industry reporting"
      },
      {
        sub: "T1589.002 - Email Addresses",
        indicator: "SMTP VRFY / EXPN enumeration against mail servers",
        arkime: "ip.src != $MPNET\n&& port.dst == 25\n&& protocols == smtp\n&& databytes.src > 0\n&& ip.src != $ALLOWED_MX",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 25\nAND NOT source.ip: $ALLOWED_MX\nAND network.transport: tcp",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $SMTP_SERVERS 25\n  (msg:\"RECON T1589.002 SMTP\n    VRFY/EXPN email enum\";\n  flow:established,to_server;\n  content:\"VRFY \"; nocase;\n  classtype:attempted-recon;\n  sid:9158905; rev:1;)",
        notes: "VRFY confirms address existence; EXPN expands list membership. Both should be disabled on all internet-facing MTAs - misconfigurations persist on legacy Exchange/Postfix. Add a second rule for EXPN (SID+1). RCPT TO oracle still works even when VRFY/EXPN are disabled - catch-all configuration eliminates this entirely.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "SMTP VRFY/EXPN to validate email lists before spearphishing campaigns targeting academics and journalists." },
          { cls: "apt-kp", name: "Kimsuky", note: "Enumerates email addresses at South Korean government orgs and US think tanks via SMTP." },
          { cls: "apt-mul", name: "Multi", note: "Widely used by criminal actors for spam list building." }
        ],
        cite: "MITRE ATT&CK T1589.002, CISA advisories, industry reporting"
      },
      {
        sub: "T1589.002 - Email Addresses",
        indicator: "SMTP RCPT TO oracle - valid vs invalid address discrimination",
        arkime: "ip.src != $MPNET\n&& port.dst == 25\n&& protocols == smtp\n&& ip.src != $ALLOWED_MX\n&& packets.src > 20\n&& packets.dst > 20",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 25\nAND NOT source.ip: $ALLOWED_MX\nAND network.packets > 40",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $SMTP_SERVERS 25\n  (msg:\"RECON T1589.002 SMTP\n    RCPT TO oracle enum\";\n  flow:established,to_server;\n  content:\"RCPT TO:\"; nocase;\n  threshold:type both,\n    track by_src, count 10,\n    seconds 60;\n  classtype:attempted-recon;\n  sid:9158906; rev:1;)",
        notes: "Even with VRFY/EXPN disabled - different response codes for valid/invalid RCPT TO = oracle. High packet count with many RCPT TO lines in SMTP stream is the indicator. Tools: smtp-user-enum, Metasploit smtp_enum, swaks. Catch-all configuration eliminates this entirely.",
        apt: [
          { cls: "apt-ir", name: "APT35", note: "RCPT TO enumeration to build validated email lists when VRFY/EXPN disabled - documented against academic institutions and news organizations." },
          { cls: "apt-kp", name: "Kimsuky", note: "RCPT TO oracle against Korean government and US think tank mail infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Heavily used by criminal IABs building target lists for ransomware affiliate programs." }
        ],
        cite: "MITRE ATT&CK T1589.002, industry reporting"
      },
      {
        sub: "T1589.002 - Email Addresses",
        indicator: "O365 / Google Workspace email format validation via login page",
        arkime: "ip.src != $MPNET\n&& http.method == POST\n&& host.http == [\"*login.microsoftonline.com*\", \"*accounts.google.com*\"]\n&& http.uri == [\"*/common/GetCredentialType*\", \"*/_/signin/sl/lookup*\", \"*/signin/v2/challenge*\"]\n&& packets.src > 10",
        kibana: "NOT source.ip: $MPNET\nAND url.domain: (\n  \"login.microsoftonline.com\"\n  OR \"accounts.google.com\"\n)\nAND url.path: (\n  *GetCredentialType*\n  OR *signin/sl/lookup*\n  OR *signin/v2/challenge*\n)\nAND http.request.method: POST",
        suricata: "alert http $EXTERNAL_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1589.002 Cloud IdP\n    email address enumeration\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(GetCredentialType|\n    signin\\/sl\\/lookup|\n    signin\\/v2\\/challenge)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src,\n    count 15, seconds 60;\n  classtype:attempted-recon;\n  sid:9158907; rev:1;)",
        notes: "Google's /_/signin/sl/lookup returns different responses for registered vs unregistered addresses. Combined with GetCredentialType for O365, adversaries validate entire LinkedIn-harvested employee lists against both platforms in minutes. Monitor via CASB/proxy for internal hosts performing this in bulk.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "Validates LinkedIn-harvested email lists against O365 GetCredentialType and Google signin/sl/lookup before phishing campaigns." },
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Cloud IdP enumeration to profile O365 tenants and validate executive accounts before credential spray." },
          { cls: "apt-kp", name: "Kimsuky", note: "Validates email lists at policy organizations and government agencies against both Microsoft and Google endpoints." },
          { cls: "apt-cn", name: "ZIRCONIUM", note: "Cloud IdP validation as precursor to credential phishing against political and government personnel." }
        ],
        cite: "MITRE ATT&CK T1589.002, Microsoft MSTIC, industry reporting"
      },
      {
        sub: "T1589.002 - Email Addresses",
        indicator: "Web scraping of staff directory / contact pages for email harvesting",
        arkime: "ip.src != $MPNET\n&& http.method == GET\n&& http.uri == [\"*/staff*\", \"*/team*\", \"*/people*\", \"*/directory*\", \"*/contact*\", \"*/about*\", \"*/leadership*\", \"*/board*\", \"*/faculty*\", \"*/experts*\"]\n&& databytes.src > 50000\n&& packets.src > 40",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *staff* OR *team*\n  OR *people* OR *directory*\n  OR *contact* OR *about*\n  OR *leadership* OR *board*\n  OR *faculty*\n)\nAND http.response.bytes > 50000",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1589.002 Staff\n    directory scraping\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/\\/(staff|team|people|\n    directory|contact|about|\n    leadership|board|faculty|\n    experts)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src,\n    count 20, seconds 60;\n  classtype:web-application-activity;\n  sid:9158908; rev:1;)",
        notes: "High-volume GETs to people/directory pages from single IP with large response bytes = automated scraping. Correlate UA - Python-requests, HeadlessChrome, PhantomJS common. Adversaries derive email format (first.last@, flast@) from scraped names then validate against cloud IdP endpoints. Directory scraping → cloud IdP validation is a documented two-step chain.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "Scrapes academic/research/think tank staff directories to identify high-value spearphishing targets." },
          { cls: "apt-kp", name: "Kimsuky", note: "Targets government agency and defense contractor staff directories for precision targeting packages." },
          { cls: "apt-cn", name: "APT10", note: "Scraped MSP staff directories to identify system administrators for targeted credential attacks during Cloud Hopper." },
          { cls: "apt-ru", name: "Cozy Bear", note: "Mapped staff directories at think tanks and NGOs prior to SolarWinds-era intrusions." }
        ],
        cite: "MITRE ATT&CK T1589.002, T1591.003, industry reporting"
      },
      {
        sub: "T1589.003 - Employee Names",
        indicator: "[OFF-NET TRIPWIRE] LinkedIn / OSINT enrichment API queries from internal hosts",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*linkedin.com*\", \"*hunter.io*\", \"*rocketreach.co*\", \"*clearbit.com*\", \"*apollo.io*\", \"*zoominfo.com*\"]\n&& http.uri == [\"*/search/results*\", \"*/company/*\", \"*/v2/people*\", \"*/prospector*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"linkedin.com\"\n  OR \"hunter.io\"\n  OR \"rocketreach.co\"\n  OR \"clearbit.com\"\n  OR \"apollo.io\"\n  OR \"zoominfo.com\"\n)\nAND url.path: (\n  *search/results*\n  OR */company/*\n  OR *people*\n  OR *prospector*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1589.003 Internal\n    host bulk OSINT people lookup\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    hunter\\.io|rocketreach\\.co|\n    clearbit\\.com|apollo\\.io|\n    zoominfo\\.com)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9158909; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Hunter.io, RocketReach, Apollo, Clearbit are identity enrichment APIs - bulk queries from internal hosts against your own domain are a red flag. Baseline expected use from sales/marketing teams. Anomalous volume from IT/security endpoints warrants investigation. LinkedIn scraping at high velocity generates 429s visible in proxy logs.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Identity enrichment platforms to map org structures at financial sector targets prior to BEC operations." },
          { cls: "apt-ir", name: "APT33", note: "People-search APIs to identify OT staff and privileged account holders at energy sector targets." },
          { cls: "apt-mul", name: "FIN7", note: "Zoominfo and equivalent platforms to filter and profile targets by revenue, role, and sector." }
        ],
        cite: "MITRE ATT&CK T1589.003, T1591.004, industry reporting"
      },
      {
        sub: "T1589.003 - Employee Names",
        indicator: "LDAP / LDAPS external anonymous bind or unauthenticated enumeration",
        arkime: "ip.src != $MPNET\n&& port.dst == [389, 636, 3268, 3269]\n&& protocols == [ldap, ldaps]\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: (\n  389 OR 636\n  OR 3268 OR 3269\n)\nAND network.transport: tcp",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET [389,636,3268,3269]\n  (msg:\"RECON T1589.003 External\n    LDAP/LDAPS enum attempt\";\n  flow:established,to_server;\n  content:\"|30|\"; depth:1;\n  classtype:attempted-recon;\n  sid:9158910; rev:1;)",
        notes: "External LDAP reach = P1 misconfiguration. Anonymous bind dumps usernames, emails, group memberships, org structure from AD without credentials. LDAPS requires TLS but doesn't prevent anonymous enumeration. Remediate firewall rules before tuning detection. Internally, non-DC hosts with large LDAP queries to DCs during off-hours = lateral movement precursor.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Exploited internet-exposed LDAP in MSP environments to enumerate AD - usernames, group memberships, privileged accounts." },
          { cls: "apt-ru", name: "APT28", note: "LDAP enumeration against government AD environments to map group structures and identify high-value accounts." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "LDAP enumeration post-initial-access to map AD structure and identify service accounts in critical infrastructure." },
          { cls: "apt-ir", name: "APT33", note: "LDAP queries to enumerate OT-adjacent accounts at energy sector targets." }
        ],
        cite: "MITRE ATT&CK T1589.003, T1087.002, CISA advisories, industry reporting"
      },
      {
        sub: "T1589.003 - Employee Names",
        indicator: "Kerberos user enumeration - AS-REQ without pre-auth (Kerbrute)",
        arkime: "ip.src != $MPNET\n&& port.dst == 88\n&& protocols == [krb5, udp]\n&& databytes.src > 0\n&& packets.src > 10",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 88\nAND network.transport: (\n  tcp OR udp\n)",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 88\n  (msg:\"RECON T1589.003 External\n    Kerberos AS-REQ user enum\";\n  content:\"|6a|\";\n  offset:0; depth:1;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 30;\n  classtype:attempted-recon;\n  sid:9158911; rev:1;)",
        notes: "KDC_ERR_PREAUTH_REQUIRED (error 25) = user exists; KDC_ERR_C_PRINCIPAL_UNKNOWN (error 6) = doesn't. Noiseless from endpoint logs but very visible at port 88. Content '|6a|' = AS-REQ DER application tag. Port 88 externally reachable = P1. Internally, 20+ AS-REQ exchanges per minute from non-admin host to single DC = Kerberoasting precursor.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Kerbrute-equivalent AS-REQ enumeration against government/military AD before Kerberoasting and credential attacks." },
          { cls: "apt-cn", name: "APT41", note: "Kerberos AS-REQ enumeration internally post-initial-access to identify service accounts with SPNs for Kerberoasting." },
          { cls: "apt-kp", name: "Lazarus", note: "AS-REQ enumeration against financial sector AD to identify high-privilege accounts prior to BEC and SWIFT fraud." }
        ],
        cite: "MITRE ATT&CK T1589.003, T1558.003, industry reporting"
      },
      {
        sub: "T1589.003 - Employee Names",
        indicator: "Azure AD / Entra ID federation metadata and OpenID configuration harvesting",
        arkime: "ip.src != $MPNET\n&& http.method == GET\n&& host.http ==\n  *login.microsoftonline.com*\n&& http.uri == [\"*/.well-known/openid-config*\", \"*/federationmetadata/*\", \"*/v2.0/.well-known*\", \"*/discovery/keys*\"]",
        kibana: "NOT source.ip: $MPNET\nAND url.domain:\n  \"login.microsoftonline.com\"\nAND url.path: (\n  *openid-configuration*\n  OR *federationmetadata*\n  OR *discovery/keys*\n  OR *v2.0/.well-known*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1589 AzureAD tenant\n    federation metadata harvest\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(openid-configuration|\n    federationmetadata|\n    discovery\\/keys|\n    v2\\.0\\/.well-known)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 30;\n  classtype:attempted-recon;\n  sid:9158912; rev:1;)",
        notes: "Exposes tenant ID, supported auth flows, token endpoint URLs, and signing keys - all required for targeted Azure AD attacks. The /discovery/keys endpoint exposes the token-signing certificate used for golden SAML forgery (T1606.002). Federation metadata reveals ADFS use and claims. Tenant-specific namespace is more targeted than /common/ - flag especially.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Harvested federation metadata as prerequisite for 2023-2024 Microsoft corporate intrusion and Teams-based social engineering." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Profiles Entra ID tenants of academic institutions, using federation metadata to identify ADFS configs for golden SAML attacks." },
          { cls: "apt-cn", name: "APT41", note: "Enumerates federation metadata to identify ADFS misconfigurations for golden SAML token forgery (T1606.002)." }
        ],
        cite: "MITRE ATT&CK T1589.003, T1606.002, Microsoft MSTIC, industry reporting"
      }
    ]
  },
  {
    id: "T1590",
    name: "Gather Victim Network Information",
    desc: ".001 Domain Properties · .002 DNS · .003 Network Trust · .004 Topology · .005 IP Addresses · .006 Security Appliances",
    rows: [
      {
        sub: "T1590.001 - Domain Properties",
        indicator: "WHOIS / RDAP automated org and domain queries",
        arkime: "ip.src != $MPNET\n&& port.dst == 43\n&& protocols == tcp\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 43\nAND network.transport: tcp",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 43\n  (msg:\"RECON T1590.001 Inbound\n    WHOIS query port 43\";\n  flow:established,to_server;\n  classtype:attempted-recon;\n  sid:9159004; rev:1;)",
        notes: "Port 43 TCP is WHOIS. Inbound to your authoritative server from external IPs is uncommon. RDAP (HTTP/443) is the modern replacement - watch for outbound internal hits to rdap.arin.net and rdap.ripe.net querying your own ASN.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Used WHOIS/domain registration data to map org relationships and identify MSP connections to critical infrastructure." },
          { cls: "apt-ru", name: "APT29", note: "Queried domain registration and RDAP data to map subsidiary relationships during pre-SolarWinds recon." },
          { cls: "apt-mul", name: "Multi", note: "Standard early-phase technique across CN/RU/IR actors." }
        ],
        cite: "MITRE ATT&CK T1590.001, industry reporting"
      },
      {
        sub: "T1590.002 - DNS",
        indicator: "DNS zone transfer attempt - AXFR / IXFR",
        arkime: "ip.src != $MPNET\n&& protocols == dns\n&& dns.query.type == [AXFR, IXFR]\n&& port.dst == 53",
        kibana: "NOT source.ip: $MPNET\nAND dns.question.type: (\n  \"AXFR\" OR \"IXFR\"\n)\nAND destination.port: 53",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $DNS_SERVERS 53\n  (msg:\"RECON T1590.002 DNS zone\n    transfer AXFR/IXFR attempt\";\n  flow:established,to_server;\n  content:\"|00 FC|\";\n  offset:2; depth:2;\n  classtype:attempted-recon;\n  sid:9159001; rev:1;)",
        notes: "AXFR (type 252) over TCP dumps entire zone - all hostnames, IPs, mail servers, internal naming. Must be blocked to all but authorised secondaries. Any external AXFR that reaches your resolver = misconfiguration AND active recon. IXFR (type 251) is incremental - watch both. Content '|00 FC|' is AXFR type in wire format.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Zone transfer attempts against MSP DNS infrastructure in Cloud Hopper to enumerate customer environments." },
          { cls: "apt-ru", name: "Sandworm", note: "DNS enumeration including AXFR attempts against Ukrainian government infrastructure." },
          { cls: "apt-ir", name: "APT33", note: "DNS enumeration against energy sector targets to map OT network naming." }
        ],
        cite: "MITRE ATT&CK T1590.002, CISA AA20-296A, industry reporting"
      },
      {
        sub: "T1590.002 - DNS",
        indicator: "Bulk subdomain brute-force / DNS enumeration",
        arkime: "ip.src != $MPNET\n&& protocols == dns\n&& dns.query.type == A\n&& host.dns == \"*.<YOUR_DOMAIN>\"\n&& packets.src > 50",
        kibana: "NOT source.ip: $MPNET\nAND dns.question.type: \"A\"\nAND dns.question.name:\n  *.<YOUR_DOMAIN>\nAND NOT dns.resolved_ip: *",
        suricata: "alert dns $EXTERNAL_NET any\n  -> $DNS_SERVERS any\n  (msg:\"RECON T1590.002 Subdomain\n    brute-force enumeration\";\n  dns.query;\n  pcre:\"/^[a-z0-9\\-]{2,30}\n    \\.<YOUR_DOMAIN>\\.com$/i\";\n  threshold:type both,\n    track by_src,\n    count 20, seconds 30;\n  classtype:attempted-recon;\n  sid:9159002; rev:1;)",
        notes: "Tools: dnsx, amass, subfinder, fierce. High NXDOMAIN ratio from single source IP is strongest signal - correlate query count vs NXDOMAIN response count. 70%+ NXDOMAIN rate from one source over 60 seconds = near-certain brute force. Watch slow-and-low variants staying under per-minute thresholds.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Thorough subdomain enumeration to identify dev/staging environments with weaker controls." },
          { cls: "apt-ru", name: "APT28", note: "Subdomain enumeration equivalent tooling pre-intrusion against government and military targets." },
          { cls: "apt-ir", name: "APT33", note: "Maps subsidiary and operational subdomain infrastructure to identify IT/OT boundary systems." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Subdomain enumeration against US critical infrastructure to identify exposed management interfaces." }
        ],
        cite: "MITRE ATT&CK T1590.002, industry reporting"
      },
      {
        sub: "T1590.003 - Network Trust Dependencies",
        indicator: "CDP / LLDP passive topology leakage",
        arkime: "ip.src == $MPNET\n&& protocols == [cdp, lldp]",
        kibana: "source.ip: $MPNET\nAND network.protocol: (\n  \"cdp\" OR \"lldp\"\n)\nAND destination.mac: (\n  \"01:00:0c:cc:cc:cc\"\n  OR \"01:80:c2:00:00:0e\"\n)",
        suricata: "alert pkthdr any any -> any any\n  (msg:\"RECON T1590.003 CDP/LLDP\n    topology leakage\";\n  content:\"|AA AA 03 00 00 0C|\";\n  offset:0; depth:6;\n  classtype:policy-violation;\n  sid:9159008; rev:1;)",
        notes: "CDP/LLDP broadcasts device vendor, model, IOS version, management IP, VLAN, and port ID to every adjacent host. Adversary with any segment foothold can passively capture these - zero active probes, no IDS alerts. Disable on all access-facing ports. Zeek CDP/LLDP analyzer is cleaner than Suricata for this detection. Presence implies adversary is already on segment.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Passively captured CDP/LLDP to map Layer 2/3 topology of Ukrainian ICS networks before destructive operations." },
          { cls: "apt-cn", name: "APT41", note: "Passive L2 enumeration post-initial-access to plan lateral movement paths." },
          { cls: "apt-mul", name: "Multi", note: "Post-compromise indicator - requires existing foothold." }
        ],
        cite: "MITRE ATT&CK T1590.003, ICS-CERT, industry reporting"
      },
      {
        sub: "T1590.004 - Network Topology",
        indicator: "Traceroute - TTL-exceeded ICMP mapping",
        arkime: "ip.src != $MPNET\n&& protocols == icmp\n&& icmp.type == 11\n&& icmp.code == 0\n&& packets.src > 5",
        kibana: "NOT source.ip: $MPNET\nAND network.transport: icmp\nAND icmp.type: 11\nAND icmp.code: 0",
        suricata: "alert icmp $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1590.004 Traceroute\n    ICMP TTL-exceeded mapping\";\n  itype:11; icode:0;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 15;\n  classtype:attempted-recon;\n  sid:9159005; rev:1;)",
        notes: "ICMP type 11 code 0 = 'TTL exceeded in transit' from your routers in response to probes with incrementing TTL. Maps hop-by-hop topology including internal routing infrastructure. Also watch UDP traceroute (ports 33434-33534) and tcptraceroute.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Traceroute-based topology mapping of Ukrainian power grid/government networks prior to 2015-2016 destructive attacks." },
          { cls: "apt-cn", name: "APT40", note: "Traceroute-based mapping of maritime and government target perimeters." },
          { cls: "apt-ir", name: "APT33", note: "Network topology mapping to identify IT/OT boundary routers at energy sector targets." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Mapped routing infrastructure to understand network paths to OT systems." }
        ],
        cite: "MITRE ATT&CK T1590.004, CISA AA22-076A, industry reporting"
      },
      {
        sub: "T1590.004 - Network Topology",
        indicator: "UDP traceroute - high-port probing (33434-33534)",
        arkime: "ip.src != $MPNET\n&& protocols == udp\n&& port.dst >= 33434\n&& port.dst <= 33534\n&& databytes.src == 0",
        kibana: "NOT source.ip: $MPNET\nAND network.transport: udp\nAND destination.port:\n  [33434 TO 33534]\nAND destination.bytes: 0",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 33434:33534\n  (msg:\"RECON T1590.004 UDP\n    traceroute high-port probe\";\n  dsize:0;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 15;\n  classtype:attempted-recon;\n  sid:9159006; rev:1;)",
        notes: "Classic Unix traceroute uses UDP 33434+ with incrementing TTL. Zero-byte payload distinguishes traceroute probes from legitimate UDP services. Windows traceroute uses ICMP echo by default - cover both. tcptraceroute (TCP SYN to 80/443) requires TTL pattern analysis.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "UDP traceroute in ICS network reconnaissance phases." },
          { cls: "apt-cn", name: "APT41", note: "Automated network mapping suites combining UDP and ICMP traceroute." },
          { cls: "apt-mul", name: "Multi", note: "Used broadly across CN/RU/IR actor toolkits as part of automated network enumeration." }
        ],
        cite: "MITRE ATT&CK T1590.004, industry reporting"
      },
      {
        sub: "T1590.004 - Network Topology",
        indicator: "SNMP community string enumeration - v1/v2c",
        arkime: "ip.src != $MPNET\n&& port.dst == 161\n&& protocols == udp\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 161\nAND network.transport: udp",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 161\n  (msg:\"RECON T1590.004 External\n    SNMP v1/v2c enumeration\";\n  content:\"|30|\"; offset:0;\n  depth:1;\n  classtype:attempted-recon;\n  sid:9159007; rev:1;)",
        notes: "Community strings (public, private, community, cisco, snmp) tried in bulk by onesixtyone and snmpwalk. Successful read exposes interface tables, ARP cache, routing table, CDP neighbors - complete internal topology map. Content '|30|' matches BER sequence tag opening every SNMP PDU. External UDP/161 reaching devices = misconfiguration finding.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "SNMP enumeration against MSP network devices - used harvested interface/ARP tables to map customer topology." },
          { cls: "apt-ru", name: "Dragonfly", note: "Systematic SNMP community string sweeps against energy sector IT/OT boundary devices prior to ICS targeting." },
          { cls: "apt-ir", name: "APT33", note: "SNMP enumeration against oil/gas sector network devices to identify OT segments." }
        ],
        cite: "MITRE ATT&CK T1590.004, CISA AA21-008A, ICS-CERT advisories"
      },
      {
        sub: "T1590.005 - IP Addresses",
        indicator: "Reverse DNS / PTR walking of your IP ranges",
        arkime: "ip.src != $MPNET\n&& protocols == dns\n&& dns.query.type == PTR\n&& host.dns == *.in-addr.arpa\n&& packets.src > 30",
        kibana: "NOT source.ip: $MPNET\nAND dns.question.type: \"PTR\"\nAND dns.question.name:\n  *.in-addr.arpa",
        suricata: "alert dns $EXTERNAL_NET any\n  -> $DNS_SERVERS any\n  (msg:\"RECON T1590.005 PTR sweep\n    reverse DNS enumeration\";\n  dns.query;\n  content:\".in-addr.arpa\";\n  threshold:type both,\n    track by_src,\n    count 15, seconds 20;\n  classtype:attempted-recon;\n  sid:9159003; rev:1;)",
        notes: "Sequential PTR queries map hostnames to IPs without touching hosts directly. Confirm sequential last-octet increments in Arkime to distinguish from legitimate resolver behavior. Walking a /24 in under 60 seconds with incrementing octets = near-certain automated enumeration.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Reverse DNS walking to map MSP customer IP allocations during Cloud Hopper." },
          { cls: "apt-ru", name: "Sandworm", note: "PTR enumeration against Ukrainian government and energy IP ranges to build target maps." },
          { cls: "apt-mul", name: "Multi", note: "Documented across multiple CISA and NSA advisories as a standard pre-exploitation technique." }
        ],
        cite: "MITRE ATT&CK T1590.005, CISA AA22-076A, industry reporting"
      },
      {
        sub: "T1590.005 - IP Addresses",
        indicator: "[OFF-NET TRIPWIRE] ASN / BGP enumeration via external looking glass - from internal host",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*bgp.he.net*\", \"*stat.ripe.net*\", \"*bgpview.io*\", \"*ipinfo.io*\", \"*ipwhois.io*\", \"*team-cymru.com*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"bgp.he.net\"\n  OR \"stat.ripe.net\"\n  OR \"bgpview.io\"\n  OR \"ipinfo.io\"\n  OR \"ipwhois.io\"\n  OR \"team-cymru.com\"\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1590.005 Internal\n    host querying BGP/ASN service\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    bgp\\.he\\.net|\n    stat\\.ripe\\.net|\n    bgpview\\.io|ipinfo\\.io|\n    ipwhois\\.io|\n    team-cymru\\.com)/i\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159009; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Internal endpoints hitting BGP looking glasses = red team or adversary-in-network pre-lateral-movement recon. Legitimate NOC uses internal tooling. Enrich source host identity and cross-reference recent authentication events. Requires existing foothold.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Queried BGP/ASN data from compromised MSP hosts to map customer IP allocations during Cloud Hopper." },
          { cls: "apt-ru", name: "APT29", note: "Internal IP range mapping via external ASN lookup during dwell-time recon phases prior to SolarWinds lateral movement." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "IP and ASN enumeration to understand routing relationships between target orgs and ISPs." }
        ],
        cite: "MITRE ATT&CK T1590.005, industry reporting"
      },
      {
        sub: "T1590.005 - IP Addresses",
        indicator: "Shodan / Censys / BinaryEdge crawler IPs probing perimeter",
        arkime: "ip.src == [\"66.240.192.0/19\", \"198.20.69.0/24\", \"162.142.125.0/24\", \"71.6.135.0/24\", \"45.33.32.0/24\", 93.120.27.62]\n&& port.dst != [80, 443]",
        kibana: "source.ip: (\n  \"66.240.0.0/14\"\n  OR \"162.142.125.0/24\"\n  OR \"71.6.135.0/24\"\n  OR \"198.20.69.0/24\"\n  OR \"45.33.32.0/24\"\n)",
        suricata: "alert ip [\n  66.240.192.0/19,\n  198.20.69.0/24,\n  162.142.125.0/24,\n  71.6.135.0/24,\n  45.33.32.0/24\n] any -> $HOME_NET any\n  (msg:\"RECON T1590.005\n    Shodan/Censys scanner IP\";\n  classtype:attempted-recon;\n  sid:9159010; rev:1;)",
        notes: "Shodan (66.240.x, 198.20.69.x), Censys (162.142.125.x), BinaryEdge (45.33.x). If these IPs reach anything beyond your public web tier, you have an exposure. Use GreyNoise API for dynamic enrichment - static CIDRs go stale. Your Shodan indexed exposure IS the adversary's target list.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Reviews Shodan/Censys data to identify exposed services on maritime/defense/government targets prior to exploitation." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Queried Shodan for exposed management interfaces (RDP, VNC, OT protocols) on US critical infrastructure." },
          { cls: "apt-ir", name: "APT33", note: "Used Shodan to identify exposed ICS interfaces and VPN endpoints in energy sector targets." }
        ],
        cite: "MITRE ATT&CK T1590.005, T1596.005, CISA advisories, industry reporting"
      },
      {
        sub: "T1590.006 - Network Security Appliances",
        indicator: "VPN gateway IKE vendor-ID fingerprinting",
        arkime: "ip.src != $MPNET\n&& port.dst == [500, 4500]\n&& protocols == udp\n&& databytes.src > 28\n&& databytes.src < 500",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: (500 OR 4500)\nAND network.transport: udp\nAND destination.bytes: [28 TO 500]",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET [500,4500]\n  (msg:\"RECON T1590.006 IKE VPN\n    gateway fingerprint probe\";\n  dsize:28<>500;\n  threshold:type both,\n    track by_src, count 3,\n    seconds 30;\n  classtype:attempted-recon;\n  sid:9159011; rev:1;)",
        notes: "IKEv1 vendor-IDs uniquely identify VPN vendor and version (Cisco ASA, Palo Alto, Fortinet, Check Point, SonicWall). ike-scan enumerates in seconds. Version disclosure enables CVE selection - CVE-2024-21762 FortiOS, CVE-2023-46805 Ivanti both preceded by systematic IKE fingerprinting. IKEv2 less verbose but still fingerprintable via transform sets.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Systematic IKE VPN fingerprinting of US critical infrastructure prior to LOTL footholds per CISA AA23-144A." },
          { cls: "apt-ir", name: "APT33", note: "Fingerprinted Pulse Secure/Fortinet VPN gateways before CVE-2019-11510 and CVE-2018-13379 exploitation." },
          { cls: "apt-ru", name: "APT28", note: "Targeted Cisco ASA VPN gateways via IKE enumeration prior to CVE-2018-0101 exploitation." },
          { cls: "apt-ir", name: "Charming Kitten", note: "IKE fingerprinting to identify Fortinet and Citrix appliances in academic/government target networks." }
        ],
        cite: "MITRE ATT&CK T1590.006, CISA AA23-144A, CISA AA20-073A, industry reporting"
      },
      {
        sub: "T1590.006 - Network Security Appliances",
        indicator: "SSL-VPN portal path fingerprinting - vendor-deterministic URI probing",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*/dana-na/auth/*\", \"*/remote/logincheck*\", \"*/+CSCOE+/logon.html*\", \"*/global-protect/*\", \"*/sslvpn/Login/*\", \"*/my.policy*\", \"*/php/login.php*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  */dana-na/auth/*\n  OR */remote/logincheck*\n  OR */+CSCOE+/*\n  OR */global-protect/*\n  OR */sslvpn/Login/*\n  OR */my.policy*\n  OR */php/login.php*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1590.006 SSL-VPN\n    portal path fingerprinting\";\n  flow:established,to_server;\n  pcre:\"/\\/(dana-na\\/auth|\n    remote\\/logincheck|\n    \\+CSCOE\\+\\/logon|\n    global-protect|\n    sslvpn\\/Login|\n    my\\.policy|\n    php\\/login)/ix\";\n  http.uri;\n  classtype:attempted-recon;\n  sid:9159012; rev:1;)",
        notes: "/dana-na/auth/ = Ivanti/Pulse Secure, /remote/logincheck = Fortinet, /+CSCOE+/ = Cisco AnyConnect, /global-protect/ = Palo Alto GlobalProtect, /sslvpn/Login/ = SonicWall, /my.policy = F5 BIG-IP APM. Single GET uniquely identifies vendor. APT33 path probing preceded Pulse/Fortinet exploitation by 4-6 weeks in documented intrusions. 200 response = trigger patch verification immediately.",
        apt: [
          { cls: "apt-ir", name: "APT33", note: "Probed /dana-na/auth/ and /remote/logincheck paths at scale before mass exploitation of CVE-2019-11510 and CVE-2018-13379 - 4-6 weeks preceding exploitation." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Probed /global-protect/ and Cisco AnyConnect paths against US critical infrastructure per CISA AA23-144A." },
          { cls: "apt-ru", name: "APT29", note: "Probed Fortinet SSL-VPN paths prior to CVE-2022-42475 exploitation in government/defense targeting." },
          { cls: "apt-kp", name: "Lazarus", note: "SSL-VPN portal path probing against financial sector targets to identify exploitable remote access infrastructure." }
        ],
        cite: "MITRE ATT&CK T1590.006, CISA AA23-144A, CISA AA21-062A, industry reporting"
      },
      {
        sub: "T1590.006 - Network Security Appliances",
        indicator: "Security appliance vendor banner in HTTP response headers",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.statuscode == [403, 400, 407]",
        kibana: "NOT source.ip: $MPNET\nAND http.response.status_code:\n  (400 OR 403 OR 407)\nAND http.response.headers.server: (\n  *Fortinet* OR *PAN-OS*\n  OR *Cisco* OR *F5*\n  OR *Barracuda* OR *Juniper*\n  OR *SonicWall*\n)",
        suricata: "alert http $HTTP_SERVERS any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1590.006 Appliance\n    banner in egress response\";\n  flow:established,from_server;\n  pcre:\"/Server\\s*:\\s*[^\\r\\n]*(\n    Fortinet|PAN-OS|Cisco|\n    Check.?Point|Barracuda|\n    F5|Juniper|SonicWall)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159013; rev:1;)",
        notes: "This rule fires on egress - your own appliance advertising its identity. Remediate: suppress or genericize Server headers, customize block pages to remove product branding. Check Point, Fortinet, F5 all have suppression settings. Banner disclosure is passive intel - adversaries receive it without triggering any alert unless you instrument egress responses.",
        apt: [
          { cls: "apt-ir", name: "APT33", note: "Correlates HTTP Server header disclosures with Shodan data and SSL-VPN path probing to build confirmed target profiles." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Documented using banner disclosure correlated with internet scan data for target profiling." },
          { cls: "apt-mul", name: "Multi/IAB", note: "Initial access brokers harvest appliance banners to build commercial target lists sold to ransomware and nation-state operators." }
        ],
        cite: "MITRE ATT&CK T1590.006, industry reporting, CISA KEV catalog"
      }
    ]
  },
  {
    id: "T1591",
    name: "Gather Victim Org Information",
    desc: ".001 Physical Locations · .002 Business Relationships",
    rows: [
      {
        sub: "T1591.001 - Physical Locations",
        indicator: "HR scraper bots hitting career / about / team pages",
        arkime: "ip.src != $MPNET\n&& http.uri == [\"*careers*\", \"*recruit*\", \"*apply*\", \"*about*\", \"*team*\", \"*join*\"]\n&& databytes.src > 50000\n&& packets.src > 30",
        kibana: "NOT source.ip: $MPNET\nAND url.path: (\n  *careers* OR *about*\n  OR *team* OR *recruit*\n  OR *apply* OR *join*\n)\nAND http.response.bytes > 50000",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1591 Org scrape\n    HR page high volume\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  content:\"/careers\"; http.uri;\n  threshold:type threshold,\n    track by_src,\n    count 20, seconds 60;\n  classtype:web-application-activity;\n  sid:9159101; rev:1;)",
        notes: "High-volume GETs to /careers, /about, /team from single external IP in short window. Correlate UA - Python-requests, curl, headless browser UAs (HeadlessChrome, PhantomJS) common. Adversaries derive org chart, tech stack, and high-value target roles from job descriptions.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used LLMs to gather information about satellite capabilities and org structure." },
          { cls: "apt-kp", name: "Lazarus", note: "Studied publicly available org info to tailor spearphishing against specific departments and individuals." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Conducted extensive pre-compromise recon to gather information about targeted organizations." },
          { cls: "apt-mul", name: "FIN7", note: "Compiled victim lists by filtering companies by revenue using Zoominfo." }
        ],
        cite: "MITRE ATT&CK T1591, industry reporting"
      },
      {
        sub: "T1591.001 - Physical Locations",
        indicator: "Bulk subsidiary / affiliate DNS enumeration",
        arkime: "ip.src != $MPNET\n&& protocols == dns\n&& dns.query.type == A\n&& host.dns == *.corp.*\n&& packets.src > 50",
        kibana: "NOT source.ip: $MPNET\nAND dns.question.type: \"A\"\nAND dns.question.name: (\n  *corp* OR *internal*\n  OR *dev* OR *staging*\n  OR *subsidiary*\n)",
        suricata: "alert dns $EXTERNAL_NET any\n  -> $DNS_SERVERS any\n  (msg:\"RECON T1591 Subsidiary\n    DNS bulk enum\";\n  dns.query;\n  content:\".corp.\";\n  threshold:type both,\n    track by_src,\n    count 15, seconds 30;\n  classtype:attempted-recon;\n  sid:9159102; rev:1;)",
        notes: "External IPs resolving many internal subdomain patterns suggests org structure mapping. Pair with passive DNS to identify which names actually resolved vs NXDOMAIN flood. Watch NXDOMAIN ratio across all sources combined for slow-and-low variants.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Maps subsidiary and affiliate infrastructure to identify weakest-link entry points prior to supply chain operations." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Enumerated subsidiary DNS as part of pre-compromise mapping of US critical infrastructure." },
          { cls: "apt-ru", name: "Sandworm", note: "Targeted partner/subsidiary DNS to identify pivot paths into Ukrainian government and ICS networks." }
        ],
        cite: "MITRE ATT&CK T1591, industry reporting"
      },
      {
        sub: "T1591.001 - Physical Locations",
        indicator: "WHOIS / RDAP automated org and domain queries",
        arkime: "ip.src != $MPNET\n&& port.dst == 43\n&& protocols == tcp\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 43\nAND network.transport: tcp",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 43\n  (msg:\"RECON T1591 Inbound\n    WHOIS query port 43\";\n  flow:established,to_server;\n  classtype:attempted-recon;\n  sid:9159103; rev:1;)",
        notes: "Port 43 TCP is WHOIS. Inbound to your authoritative server from external IPs is uncommon outside of automation or targeted recon tooling mapping registered domains and ASN contacts. RDAP (HTTP/443) is the modern replacement - watch for outbound internal hits to rdap.arin.net and rdap.ripe.net querying your own ASN.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Used WHOIS and domain registration data to map organizational relationships and identify MSP connections." },
          { cls: "apt-ru", name: "APT29", note: "Queried domain registration and RDAP data to map subsidiary relationships prior to SolarWinds." },
          { cls: "apt-mul", name: "Multi", note: "Standard early-phase technique across CN/RU/IR actors - typically automated tooling." }
        ],
        cite: "MITRE ATT&CK T1591, industry reporting"
      },
      {
        sub: "T1591.002 - Business Relationships",
        indicator: "[OFF-NET TRIPWIRE] Business relationship / third-party vendor enumeration via OSINT",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*zoominfo.com*\", \"*dnb.com*\", \"*opencorporates.com*\", \"*crunchbase.com*\", \"*pitchbook.com*\", \"*sec.gov*\"]\n&& http.uri == [\"*/company/*\", \"*/search*\", \"*/v2/organizations*\", \"*/filings*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"zoominfo.com\"\n  OR \"dnb.com\"\n  OR \"opencorporates.com\"\n  OR \"crunchbase.com\"\n  OR \"pitchbook.com\"\n  OR \"sec.gov\"\n)\nAND url.path: (\n  */company/* OR *search*\n  OR *organizations*\n  OR *filings*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1591 Internal host\n    business relationship OSINT\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    zoominfo\\.com|dnb\\.com|\n    opencorporates\\.com|\n    crunchbase\\.com|\n    pitchbook\\.com)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159104; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Internal hosts querying business intelligence platforms against your own org or vendors may indicate a compromised host mapping third-party relationships for supply chain targeting. Baseline expected use from BD/sales teams - anomalous volume from IT or security hosts is the flag.",
        apt: [
          { cls: "apt-mul", name: "FIN7", note: "Compiled victim lists by filtering companies by revenue using Zoominfo." },
          { cls: "apt-cn", name: "APT41", note: "Researches business relationships to identify supply chain access paths." },
          { cls: "apt-ru", name: "Cozy Bear", note: "Mapped partner and contractor relationships prior to SolarWinds supply chain compromise." }
        ],
        cite: "MITRE ATT&CK T1591.002, industry reporting"
      }
    ]
  },
  {
    id: "T1592",
    name: "Gather Victim Host Information",
    desc: ".001 Hardware · .002 Software · .003 Firmware · .004 Client Configurations",
    rows: [
      {
        sub: "T1592.001 - Hardware",
        indicator: "NetBIOS Name Service (NBNS) enumeration - external host querying your broadcast domain",
        arkime: "ip.src != $MPNET\n&& port.dst == 137\n&& protocols == udp\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 137\nAND network.transport: udp",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 137\n  (msg:\"RECON T1592.001 External\n    NBNS name query\";\n  content:\"|00 00|\";\n  offset:2; depth:2;\n  classtype:attempted-recon;\n  sid:9159201; rev:1;)",
        notes: "NBNS (UDP/137) resolves NetBIOS names to IPs and returns the NetBIOS name, workgroup/domain name, and MAC address. External NBNS should never reach internal hosts. Internally, watch for non-Windows hosts generating NBNS queries in bulk - Responder generates distinctive query patterns visible in Zeek nbns.log.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Used NetBIOS enumeration for MSP network host discovery during Cloud Hopper, mapping workstation and server names without touching AD." },
          { cls: "apt-ru", name: "APT28", note: "Used NBNS and SMB enumeration to identify host hardware configurations and domain membership in government network targeting." },
          { cls: "apt-mul", name: "Multi", note: "Documented in multiple CISA advisories as a standard network discovery technique used post-initial-access." }
        ],
        cite: "MITRE ATT&CK T1592.001, CISA advisories, industry reporting"
      },
      {
        sub: "T1592.001 - Hardware",
        indicator: "NBNS broadcast sweep - internal host performing name resolution sweep",
        arkime: "ip.src == $MPNET\n&& port.dst == 137\n&& protocols == udp\n&& ip.dst == 255.255.255.255\n&& packets.src > 20",
        kibana: "source.ip: $MPNET\nAND destination.port: 137\nAND network.transport: udp\nAND destination.ip: \"255.255.255.255\"",
        suricata: "alert udp $HOME_NET any\n  -> 255.255.255.255 137\n  (msg:\"RECON T1592.001 Internal\n    NBNS broadcast sweep\";\n  content:\"|20|\";\n  offset:12; depth:1;\n  threshold:type both,\n    track by_src,\n    count 20, seconds 30;\n  classtype:attempted-recon;\n  sid:9159202; rev:1;)",
        notes: "An internal host broadcasting NBNS queries to 255.255.255.255 at high volume = scanner (nmap -sU, nbtscan, enum4linux) or host discovery tool. Content '|20|' at offset 12 matches NetBIOS encoded name wildcard. 20+ in 30 seconds from a single non-DC host is anomalous. Post-foothold indicator - combine with source host identity and off-hours timing.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Uses NBNS broadcast sweeps post-initial-access to enumerate workstation/server names without touching AD LDAP." },
          { cls: "apt-cn", name: "APT41", note: "Performs internal NBNS enumeration using nbtscan-equivalent tooling to build host inventory maps before lateral movement." },
          { cls: "apt-mul", name: "Multi", note: "Documented post-compromise discovery technique in multiple CISA and FBI ransomware/nation-state advisories." }
        ],
        cite: "MITRE ATT&CK T1592.001, T1016, CISA advisories"
      },
      {
        sub: "T1592.001 - Hardware",
        indicator: "UPnP SSDP M-SEARCH - device hardware discovery via multicast probe",
        arkime: "ip.src != $MPNET\n&& port.dst == 1900\n&& protocols == udp\n&& http.method == M-SEARCH\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 1900\nAND network.transport: udp",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 1900\n  (msg:\"RECON T1592.001 UPnP SSDP\n    M-SEARCH device discovery\";\n  content:\"M-SEARCH\"; depth:8;\n  content:\"ssdp:discover\";\n  classtype:attempted-recon;\n  sid:9159203; rev:1;)",
        notes: "SSDP M-SEARCH to UDP/1900 discovers UPnP devices - printers, NAS, routers, IoT - and returns device type, model, manufacturer, and firmware version. External SSDP reaching internal devices = perimeter misconfiguration. Internally, SSDP M-SEARCH from non-IoT hosts is anomalous. Tools: Miranda, UPnP-Inspector, Metasploit UPnP scanner.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Used UPnP enumeration to identify network-connected hardware in Ukrainian industrial environments." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Enumerated UPnP-capable devices in SOHO environments to identify hardware with exploitable UPnP implementations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA ICS advisories as a technique used to map hardware in OT-adjacent network segments." }
        ],
        cite: "MITRE ATT&CK T1592.001, CISA ICS advisories, industry reporting"
      },
      {
        sub: "T1592.001 - Hardware",
        indicator: "UPnP description XML fetch - hardware detail harvest post-SSDP discovery",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*/rootDesc.xml*\", \"*/upnp/desc*\", \"*/device.xml*\", \"*/DeviceDescription*\", \"*/igd.xml*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *rootDesc.xml*\n  OR *upnp/desc*\n  OR *device.xml*\n  OR *DeviceDescription*\n  OR *igd.xml*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1592.001 UPnP\n    device description XML fetch\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(rootDesc\\.xml|\n    upnp\\/desc|device\\.xml|\n    DeviceDescription|\n    igd\\.xml)/ix\";\n  http.uri;\n  classtype:attempted-recon;\n  sid:9159204; rev:1;)",
        notes: "After SSDP discovery, adversaries fetch the UPnP device description XML containing the full hardware profile: manufacturer, model number, serial number, firmware version, and UPnP services. Two-step chain: SSDP discovers what's present, description XML retrieves details. A 200 response to rootDesc.xml from an external IP is both a misconfiguration and an active hardware disclosure event.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Fetched UPnP device description XML from SOHO routers to confirm device models for targeted firmware exploitation per CISA AA23-144A." },
          { cls: "apt-ru", name: "Sandworm", note: "Retrieved UPnP device descriptions from network-connected hardware in target environments." },
          { cls: "apt-mul", name: "Multi", note: "Well-documented technique in penetration testing and nation-state toolkits for hardware inventory collection." }
        ],
        cite: "MITRE ATT&CK T1592.001, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1592.001 - Hardware",
        indicator: "WMI remote queries - external or lateral WMI hardware enumeration (DCOM/RPC)",
        arkime: "ip.src != $MPNET\n&& port.dst == [135, 445]\n&& protocols == [dce-rpc, smb]\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: (135 OR 445)\nAND network.transport: tcp\nAND source.bytes > 0\nAND destination.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET [135,445]\n  (msg:\"RECON T1592.001 External\n    WMI/DCOM hardware enum\";\n  flow:established,to_server;\n  content:\"|05 00|\"; depth:2;\n  threshold:type both,\n    track by_src,\n    count 3, seconds 30;\n  classtype:attempted-recon;\n  sid:9159205; rev:1;)",
        notes: "WMI over DCOM (TCP/135 + dynamic high ports) allows remote hardware enumeration - Win32_ComputerSystem returns manufacturer/model/memory. External TCP/135 or TCP/445 should never reach internal hosts. Content '|05 00|' matches DCE/RPC bind header. Zeek dce_rpc.log captures operation names - look for IWbemServices::ExecQuery calls.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Uses remote WMI queries extensively post-initial-access to enumerate hardware configuration across target environments." },
          { cls: "apt-ru", name: "APT28", note: "Uses WMI remote enumeration against government/military targets, using hardware inventory to select architecture-appropriate payloads." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses WMI remote queries in financial sector intrusions to profile workstation hardware before deploying tooling." }
        ],
        cite: "MITRE ATT&CK T1592.001, T1047, CISA advisories, industry reporting"
      },
      {
        sub: "T1592.001 - Hardware",
        indicator: "MAC address OUI harvesting via ARP sweep - hardware vendor identification",
        arkime: "ip.src == $MPNET\n&& protocols == arp\n&& packets.src > 30",
        kibana: "source.ip: $MPNET\nAND network.type: \"ipv4\"\nAND network.transport: \"arp\"",
        suricata: "alert arp $HOME_NET any\n  -> any any\n  (msg:\"RECON T1592.001 ARP sweep\n    MAC/OUI hardware enumeration\";\n  content:\"|00 01|\"; offset:6;\n  depth:2;\n  threshold:type both,\n    track by_src,\n    count 30, seconds 30;\n  classtype:attempted-recon;\n  sid:9159206; rev:1;)",
        notes: "ARP responses include the MAC address of each responding host. The first three octets (OUI) identify the hardware vendor - Cisco, Dell, Fortinet, Raspberry Pi, VMware. An internal host generating 30+ ARP requests in 30 seconds is performing a sweep. Requires existing foothold (ARP is layer 2). Zeek arp.log captures all ARP activity including OUIs.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Performed ARP-based hardware enumeration in Ukrainian network environments to identify Cisco, GE, and Siemens hardware on OT-adjacent segments." },
          { cls: "apt-cn", name: "APT41", note: "Uses ARP sweeps post-initial-access to identify hardware vendors and select appropriate exploitation paths." },
          { cls: "apt-mul", name: "Multi", note: "Post-compromise indicator - requires existing segment access." }
        ],
        cite: "MITRE ATT&CK T1592.001, T1018, industry reporting"
      },
      {
        sub: "T1592.002 - Software",
        indicator: "mDNS / Bonjour service browse - software and service inventory via multicast DNS",
        arkime: "ip.src != $MPNET\n&& port.dst == 5353\n&& protocols == udp\n&& ip.dst == 224.0.0.251\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 5353\nAND network.transport: udp\nAND destination.ip: \"224.0.0.251\"",
        suricata: "alert udp $EXTERNAL_NET any\n  -> 224.0.0.251 5353\n  (msg:\"RECON T1592.002 mDNS\n    Bonjour service enumeration\";\n  content:\"|00 0c|\"; offset:2;\n  depth:2;\n  classtype:attempted-recon;\n  sid:9159207; rev:1;)",
        notes: "mDNS (UDP/5353 to multicast 224.0.0.251) allows zero-config service discovery - any host can query for _http._tcp, _smb._tcp, _ssh._tcp, _printer._tcp and receive responses advertising software names, versions, and hostnames. External mDNS reaching internal segments = perimeter misconfiguration. Content '|00 0c|' matches PTR record type used for service browsing.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Used mDNS enumeration in SOHO environments to identify software services on network-connected devices." },
          { cls: "apt-ru", name: "Sandworm", note: "Used mDNS service browsing to enumerate software on network-connected devices in Ukrainian target environments." },
          { cls: "apt-mul", name: "Multi", note: "Included in Metasploit auxiliary scanner suite and multiple post-exploitation frameworks." }
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 - Software",
        indicator: "HTTP Server header software version disclosure in egress responses",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.statuscode == [200, 301, 302, 400, 403, 404]",
        kibana: "NOT source.ip: $MPNET\nAND http.response.status_code: (\n  200 OR 301 OR 302\n  OR 400 OR 403 OR 404\n)\nAND http.response.headers.server: (\n  *Apache* OR *nginx*\n  OR *Microsoft-IIS*\n  OR *PHP* OR *Tomcat*\n  OR *Jetty* OR *Werkzeug*\n  OR *OpenSSL*\n)",
        suricata: "alert http $HTTP_SERVERS any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1592.002 HTTP Server\n    header software version\n    disclosure\";\n  flow:established,from_server;\n  pcre:\"/Server\\s*:\\s*[^\\r\\n]*(\n    Apache\\/|nginx\\/|\n    Microsoft-IIS\\/|PHP\\/|\n    Tomcat\\/|Jetty\\/|\n    Werkzeug\\/|OpenSSL\\/)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159209; rev:1;)",
        notes: "HTTP Server headers advertising specific versions (Apache/2.4.49, nginx/1.18.0, PHP/7.4.3) give adversaries a precise CVE selection guide. This rule fires on egress - your own servers advertising their stack. Remediate: Apache: ServerTokens Prod; nginx: server_tokens off. Also watch X-Powered-By, X-Generator, X-AspNet-Version headers.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Harvests HTTP Server header version strings from maritime/defense/government web infrastructure for CVE-targeted exploitation." },
          { cls: "apt-ir", name: "APT33", note: "Systematically collects HTTP Server header disclosures from energy sector web infrastructure to select exploitation paths." },
          { cls: "apt-mul", name: "Multi", note: "Passive intel - adversaries collect from normal web traffic without generating probe traffic." }
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 - Software",
        indicator: "X-Powered-By / X-Generator header - CMS and framework version disclosure",
        arkime: "ip.src != $MPNET\n&& protocols == http",
        kibana: "NOT source.ip: $MPNET\nAND http.response.headers: (\n  *X-Powered-By*\n  OR *X-Generator*\n  OR *X-AspNet-Version*\n  OR *X-AspNetMvc-Version*\n  OR *X-Drupal-Cache*\n)",
        suricata: "alert http $HTTP_SERVERS any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1592.002 CMS/framework\n    version header disclosure\";\n  flow:established,from_server;\n  pcre:\"/X-(Powered-By|Generator|\n    AspNet-Version|\n    AspNetMvc-Version|\n    Drupal-Cache)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159210; rev:1;)",
        notes: "X-Powered-By exposes PHP/ASP.NET/Express version; X-Generator exposes WordPress/Drupal/Joomla version; X-AspNet-Version exposes .NET runtime. Default in most frameworks - requires explicit suppression. Combined with Server headers, gives adversaries a complete software stack fingerprint in a single HTTP response.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Collects framework/CMS version headers to identify WordPress plugin versions, PHP runtime, and .NET versions for CVE exploitation." },
          { cls: "apt-ir", name: "APT33", note: "Harvests X-Powered-By and X-AspNet-Version from energy sector and defense contractor web applications." },
          { cls: "apt-mul", name: "FIN7", note: "Uses CMS version disclosure from X-Generator headers to identify vulnerable WordPress/Drupal installations in POS/hospitality targeting." }
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 - Software",
        indicator: "SMB protocol negotiation - OS and software version fingerprinting",
        arkime: "ip.src != $MPNET\n&& port.dst == 445\n&& protocols == smb\n&& databytes.src > 0\n&& databytes.dst > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 445\nAND network.transport: tcp\nAND source.bytes > 0\nAND destination.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 445\n  (msg:\"RECON T1592.002 SMB\n    negotiate software fingerprint\";\n  flow:established,to_server;\n  content:\"|ff 53 4d 42|\"; depth:5;\n  classtype:attempted-recon;\n  sid:9159211; rev:1;)",
        notes: "SMB protocol negotiation reveals OS version, SMB dialect (SMB1/2/3), and build number - enough to identify Windows version down to patch level without authentication. Content '|ff 53 4d 42|' = SMB1 header magic; SMB2 uses '|fe 53 4d 42|'. External TCP/445 should never reach internal hosts. Zeek smb.log captures dialect negotiation details.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Uses SMB negotiation fingerprinting to identify Windows versions and SMB dialect support, selecting CVEs like EternalBlue and PrintNightmare." },
          { cls: "apt-cn", name: "APT10", note: "Used SMB negotiation fingerprinting against MSP environments to identify Windows versions across customer workstation fleets." },
          { cls: "apt-kp", name: "Lazarus", note: "Used SMB software fingerprinting to identify systems running vulnerable SMB before lateral movement via EternalBlue." }
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 - Software",
        indicator: "RDP protocol negotiation - software version and NLA configuration fingerprinting",
        arkime: "ip.src != $MPNET\n&& port.dst == 3389\n&& protocols == rdp\n&& databytes.src > 0\n&& databytes.dst > 0\n&& packets.src < 5",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 3389\nAND network.transport: tcp\nAND source.bytes > 0\nAND destination.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET 3389\n  (msg:\"RECON T1592.002 RDP\n    software/NLA config fingerprint\";\n  flow:established,to_server;\n  content:\"|03 00|\"; depth:2;\n  classtype:attempted-recon;\n  sid:9159212; rev:1;)",
        notes: "RDP connection negotiation reveals whether NLA is enforced, RDP protocol version, and supported encryption levels - before any authentication. Connect-and-disconnect with low packet count (<5) from external IP is the classic RDP fingerprint pattern. Content '|03 00|' matches TPKT header. Tools: rdp-sec-check, nmap RDP scripts. NLA disabled = pre-auth attack surface (BlueKeep CVE-2019-0708).",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Fingerprints RDP NLA configuration and version on financial sector targets to identify systems vulnerable to credential spray or CVE exploitation." },
          { cls: "apt-ru", name: "APT28", note: "Uses RDP protocol negotiation fingerprinting against government targets to identify Windows versions before RDP-based lateral movement." },
          { cls: "apt-mul", name: "Multi", note: "Documented in multiple CISA ransomware advisories as pre-exploitation recon used by IABs to build lists of exposed vulnerable RDP endpoints." }
        ],
        cite: "MITRE ATT&CK T1592.002, CISA ransomware advisories, industry reporting"
      },
      {
        sub: "T1592.003 - Firmware",
        indicator: "SNMP sysDescr OID walk - firmware version string harvest from network devices",
        arkime: "ip.src != $MPNET\n&& port.dst == 161\n&& protocols == udp\n&& databytes.src > 0\n&& databytes.src < 200",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 161\nAND network.transport: udp\nAND destination.bytes: [1 TO 200]",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 161\n  (msg:\"RECON T1592.003 SNMP\n    sysDescr firmware harvest\";\n  content:\"|30|\"; depth:1;\n  content:\"|06 09 2b 06 01 02 01\n    01 01 00|\";\n  classtype:attempted-recon;\n  sid:9159213; rev:1;)",
        notes: "SNMP sysDescr OID (1.3.6.1.2.1.1.1.0) returns full device description including OS version, firmware version, hardware model, and build date. Content '|06 09 2b 06 01 02 01 01 01 00|' is the BER-encoded OID for sysDescr. A single successful read from an external IP = CVE selection guide. Correlate with T1590.004 SNMP community string enumeration - the community string brute is the precursor.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Used SNMP sysDescr queries against MSP network devices to enumerate Cisco IOS and Juniper JUNOS firmware versions." },
          { cls: "apt-ru", name: "Dragonfly", note: "Performed systematic SNMP sysDescr harvesting against energy sector network equipment per CISA ICS-CERT advisories." },
          { cls: "apt-ir", name: "APT33", note: "Queried SNMP sysDescr on oil and gas sector network infrastructure to identify Cisco, Fortinet, and Juniper firmware versions." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Used SNMP firmware version enumeration against US critical infrastructure network equipment during pre-positioning." }
        ],
        cite: "MITRE ATT&CK T1592.003, CISA ICS-CERT, CISA AA23-144A"
      },
      {
        sub: "T1592.003 - Firmware",
        indicator: "SNMP bulk walk - full MIB firmware and configuration harvest",
        arkime: "ip.src != $MPNET\n&& port.dst == 161\n&& protocols == udp\n&& databytes.src > 200\n&& packets.src > 10",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 161\nAND network.transport: udp\nAND destination.bytes > 200\nAND network.packets > 10",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 161\n  (msg:\"RECON T1592.003 SNMP bulk\n    MIB walk firmware harvest\";\n  content:\"|30|\"; depth:1;\n  content:\"|a5|\"; offset:5;\n  depth:1;\n  threshold:type both,\n    track by_src,\n    count 10, seconds 30;\n  classtype:attempted-recon;\n  sid:9159214; rev:1;)",
        notes: "SNMP GetBulkRequest (PDU type 0xa5) retrieves multiple OIDs in a single request. A full MIB walk returns sysDescr, interfaces, ARP tables, routing tables, CDP neighbor data, and proprietary MIBs containing running config hashes and boot image names - a complete device profile. High packet count + large payload from external IP to UDP/161 = active bulk walk.",
        apt: [
          { cls: "apt-ru", name: "Dragonfly", note: "Performed full SNMP MIB walks against energy sector network devices, harvesting complete device profiles including firmware versions and running config hashes." },
          { cls: "apt-cn", name: "APT10", note: "Conducted bulk SNMP walks against MSP-managed network devices to extract full device profiles for customer environments." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA ICS-CERT advisories - a single successful community string enables complete device state visibility." }
        ],
        cite: "MITRE ATT&CK T1592.003, CISA ICS-CERT advisories, industry reporting"
      },
      {
        sub: "T1592.003 - Firmware",
        indicator: "Network device HTTP management interface - firmware version page probing",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*/firmware*\", \"*/version*\", \"*/cgi-bin/luci*\", \"*/webui/login*\", \"*/admin/status.php*\", \"*/system/device-info*\", \"*/api/v1/system/info*\", \"*/rest/system/info*\"]\n&& host.http != $ALLOWED_DEFAULTS",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *firmware* OR *version*\n  OR */cgi-bin/luci*\n  OR */webui/login*\n  OR */admin/status.php*\n  OR */system/device-info*\n  OR */api/v1/system/info*\n  OR */rest/system/info*\n)\nAND NOT url.domain: $ALLOWED_DEFAULTS",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1592.003 Device mgmt\n    firmware version page probe\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(firmware|version|\n    cgi-bin\\/luci|webui\\/login|\n    admin\\/status\\.php|\n    system\\/device-info|\n    api\\/v1\\/system\\/info|\n    rest\\/system\\/info)/ix\";\n  http.uri;\n  classtype:attempted-recon;\n  sid:9159215; rev:1;)",
        notes: "Network devices expose firmware version information on management web interface pages - often without authentication on the version/status/about page. Path signatures: /cgi-bin/luci = OpenWRT/LEDE, /webui/login = UTM appliances, /api/v1/system/info = Ubiquiti/Aruba/Ruckus. A 200 response disclosing a firmware version = immediate patch status check. Cross-reference response body against CVE database.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Probed network device HTTP management interfaces to enumerate firmware versions on SOHO routers and enterprise network equipment per CISA AA23-144A." },
          { cls: "apt-ir", name: "APT33", note: "Queried HTTP management interfaces of network appliances in energy sector environments." },
          { cls: "apt-ru", name: "Sandworm", note: "Probed management interface firmware version pages on Ukrainian network infrastructure equipment." }
        ],
        cite: "MITRE ATT&CK T1592.003, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1592.003 - Firmware",
        indicator: "TFTP read request - firmware image or config file retrieval attempt",
        arkime: "ip.src != $MPNET\n&& port.dst == 69\n&& protocols == udp\n&& databytes.src > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: 69\nAND network.transport: udp\nAND destination.bytes > 0",
        suricata: "alert udp $EXTERNAL_NET any\n  -> $HOME_NET 69\n  (msg:\"RECON T1592.003 TFTP read\n    request firmware enumeration\";\n  content:\"|00 01|\"; depth:2;\n  classtype:attempted-recon;\n  sid:9159216; rev:1;)",
        notes: "TFTP (UDP/69) used by network devices for firmware updates and config backup - an exposed TFTP server may serve firmware images and running configs without any authentication. Content '|00 01|' is the TFTP Read Request opcode. External UDP/69 reaching your network = critical misconfiguration. Cisco devices historically stored running-config via TFTP. Zeek tftp.log captures filenames requested.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Exploited exposed TFTP servers in MSP environments to retrieve Cisco running configurations and firmware images without authentication." },
          { cls: "apt-ru", name: "Dragonfly", note: "Targeted TFTP servers on energy sector networks to retrieve network device configurations and firmware images per CISA ICS-CERT advisories." },
          { cls: "apt-mul", name: "Multi", note: "External UDP/69 is cited in multiple NSA and CISA hardening guides as a high-priority remediation item." }
        ],
        cite: "MITRE ATT&CK T1592.003, CISA ICS-CERT, NSA hardening guides"
      },
      {
        sub: "T1592.003 - Firmware",
        indicator: "[OFF-NET TRIPWIRE] TLS certificate CN / SAN - device firmware version and model disclosure",
        arkime: "ip.src != $MPNET\n&& protocols == tls\n&& cert.subject.cn == [\"*FortiGate*\", \"*SonicWall*\", \"*pfSense*\", \"*OPNsense*\", \"*Cisco*\", \"*Juniper*\", \"*Ubiquiti*\", \"*MikroTik*\", \"*Synology*\", \"*QNAP*\", \"*router*\", \"*firewall*\", \"*ESXi*\", \"*vCenter*\", \"*iLO*\", \"*iDRAC*\"]",
        kibana: "NOT source.ip: $MPNET\nAND tls.server.x509.subject.common_name: (\n  *FortiGate* OR *SonicWall*\n  OR *pfSense* OR *OPNsense*\n  OR *Cisco* OR *Juniper*\n  OR *Ubiquiti* OR *MikroTik*\n  OR *Synology* OR *QNAP*\n  OR *router* OR *firewall*\n)",
        suricata: "alert tls $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1592.003 TLS cert\n    device model/firmware disclose\";\n  flow:established,from_server;\n  tls.cert_subject;\n  pcre:\"/CN=[^,]*(FortiGate|\n    SonicWall|pfSense|OPNsense|\n    Cisco|Juniper|Ubiquiti|\n    MikroTik|Synology|QNAP|\n    router|firewall)/ix\";\n  classtype:policy-violation;\n  sid:9159217; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Network devices generating self-signed TLS certs often include device model, hostname, and sometimes firmware version in the CN or SAN fields. A FortiGate self-signed cert with CN=FortiGate-100F reveals exact hardware model - adversaries correlate with Shodan to track firmware update history. Remediate: replace self-signed certs with CA-issued certs with generic CNs.",
        apt: [
          { cls: "apt-ir", name: "APT33", note: "Collects TLS certificate CN/SAN data from network device management interfaces to identify device models and correlate with Shodan data." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Harvests TLS certificate metadata from network device management interfaces to identify hardware models and correlate against CVE-vulnerable firmware versions." },
          { cls: "apt-mul", name: "Multi", note: "Passive intelligence source - adversaries collect from Shodan indexed scans without generating probe traffic." }
        ],
        cite: "MITRE ATT&CK T1592.003, industry reporting"
      },
      {
        sub: "T1592.004 - Client Configurations",
        indicator: "JA3 / JA4 known scanner TLS fingerprint - tool identification via ClientHello",
        arkime: "ip.src != $MPNET\n&& protocols == tls\n&& tls.ja3 == [\"e7d705a3286e19ea42f587b344ee6865\", \"6734f37431670b3ab4292b8f60f29984\", \"4d7a28d6f2263ed61de88ca66eb011e3\", \"b386946a5a44d1ddcc843bc75336dfce\", \"a0e9f5d64349fb13191bc781f81f42e1\"]",
        kibana: "NOT source.ip: $MPNET\nAND tls.client.ja3: (\n  \"e7d705a3286e19ea42f587b344ee6865\"\n  OR \"6734f37431670b3ab4292b8f60f29984\"\n  OR \"4d7a28d6f2263ed61de88ca66eb011e3\"\n  OR \"b386946a5a44d1ddcc843bc75336dfce\"\n  OR \"a0e9f5d64349fb13191bc781f81f42e1\"\n)",
        suricata: "alert tls $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1592.004 Known\n    scanner JA3 fingerprint\";\n  ja3.hash;\n  content:\"e7d705a3286e19ea42f587b344ee6865\";\n  classtype:attempted-recon;\n  sid:9159218; rev:1;)",
        notes: "Known scanner JA3 hashes (maintain a current blocklist - these rotate with tool updates): e7d705a3 = Metasploit, 6734f374 = zgrab2 default, 4d7a28d6 = Nmap SSL probe, b386946a = Masscan TLS, a0e9f5d6 = curl/7 default. Evasion: cipher reordering changes the hash. Pair with JA4 (more stable) and behavioral heuristics. Maintain a living blocklist from SSLBL (abuse.ch).",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "JA3 scanner fingerprint matches primarily catch unsophisticated actors and automated tooling - nation-state actors rotate TLS parameters to evade JA3." }
        ],
        activity: [
          { cls: "apt-mul", name: "IAB", note: "Initial access brokers running bulk scanning frequently use default tool configurations generating known JA3 hashes." }
        ],
        cite: "MITRE ATT&CK T1592.004, abuse.ch SSLBL, industry reporting"
      },
      {
        sub: "T1592.004 - Client Configurations",
        indicator: "JA4 fingerprint anomaly - tool TLS stack versus claimed browser UA mismatch",
        arkime: "ip.src != $MPNET\n&& protocols == tls\n&& tls.ja3 != $BROWSER_JA3_BASELINE\n&& http.user-agent == [\"*Mozilla*\", \"*Chrome*\", \"*Firefox*\", \"*Safari*\", \"*Edge*\"]\n// JA4 is not available in Arkime 4.3.1 (Arkime 5+ only, accessible as http.ja4). This rule falls\n// back to JA3 - lower entropy than JA4 but still useful for catching tool-vs-browser mismatches.\n\n// See Suricata column for JA4 if your sensor supports it.",
        kibana: "NOT source.ip: $MPNET\nAND tls.client.ja4: *\nAND NOT tls.client.ja4:\n  $BROWSER_JA4_BASELINE\nAND user_agent.original: (\n  *Mozilla* OR *Chrome*\n  OR *Firefox* OR *Safari*\n  OR *Edge*\n)",
        suricata: "alert tls $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1592.004 JA4\n    mismatch - tool spoofing\n    browser UA\";\n  flow:established,to_server;\n  ja3.hash; content:!\"\";\n  classtype:attempted-recon;\n  sid:9159219; rev:1;)",
        notes: "A tool claiming to be Chrome but generating a non-Chrome JA4 hash is spoofing its UA - the TLS ClientHello doesn't lie. Chrome, Firefox, and Edge have stable, well-documented JA4 fingerprints. Build a baseline of expected JA4 values and alert on deviations paired with browser UA strings. This catches adversaries who rotate UA strings but don't implement browser-accurate TLS stacks. Requires Zeek JA4 package.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Uses custom tooling with spoofed browser UA strings that generate non-browser JA4 fingerprints - mismatch detectable via JA4 analysis." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Deploys credential harvesting infrastructure with browser-mimicking UA strings but Python/Go TLS stacks - JA4 catches the mismatch." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Uses browser-mimicking UA strings but non-browser TLS stacks in AiTM phishing infrastructure." }
        ],
        cite: "MITRE ATT&CK T1592.004, industry reporting"
      },
      {
        sub: "T1592.004 - Client Configurations",
        indicator: "JA4S - server TLS response fingerprinting for rogue/AiTM infrastructure detection",
        arkime: "ip.dst == $MPNET\n&& protocols == tls\n&& tls.ja3s != $ALLOWED_SERVERS",
        kibana: "destination.ip: $MPNET\nAND NOT tls.server.ja3s:\n  $ALLOWED_SERVERS\nAND tls.server.not_before:\n  [now-14d TO now]",
        suricata: "alert tls $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1592.004 JA4S\n    unknown server TLS config\";\n  flow:established,from_server;\n  ja3.hash; content:!\"\";\n  classtype:policy-violation;\n  sid:9159220; rev:1;)",
        notes: "JA4S fingerprints the server-side TLS response (ServerHello). Known-good server JA4S values are stable for your infrastructure - a newly appearing JA4S that doesn't match any known server = rogue service or adversary infrastructure. AiTM proxies have characteristic JA4S values distinct from legitimate IdP servers (Okta, Azure AD, Google). Build a JA4S allowlist for your servers and alert on deviations.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "AiTM infrastructure generates JA4S values distinct from legitimate Microsoft and Okta TLS server responses." },
          { cls: "apt-mul", name: "Scattered Spider", note: "AiTM proxy infrastructure has documented JA4S values differing from legitimate IdP servers." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Credential harvesting pages generate JA4S values inconsistent with the legitimate Google/Microsoft servers they mimic." }
        ],
        cite: "MITRE ATT&CK T1592.004, T1598, industry reporting"
      },
      {
        sub: "T1592.004 - Client Configurations",
        indicator: "Passive OS fingerprinting - TCP stack anomaly indicating scanner or non-standard OS",
        kibana: "NOT source.ip: $MPNET\nAND tcp.flags: \"S\"\nAND NOT tcp.flags: \"A\"\nAND network.transport: tcp",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1592.004 Passive OS\n    fingerprint TCP anomaly\";\n  flags:S,12;\n  flow:stateless;\n  ttl:255;\n  window:1024;\n  classtype:attempted-recon;\n  sid:9159221; rev:1;)",
        notes: "TCP SYN packets contain OS fingerprinting data in IP TTL, TCP window size, MSS, and options order. Baseline values: Linux = TTL 64, window ~29200; Windows = TTL 128, window 65535; Cisco IOS = TTL 255, window 4128; Masscan = TTL 255, window 1024; Zmap = TTL 255, window 65535. Integrate p0f or Zeek OS fingerprinting for passive identification. Arkime community fingerprint plugin surfaces p0f data in session records.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Uses Masscan-equivalent tooling with characteristic TCP stack (TTL=255, window=1024) for large-scale port sweeps - passive TCP fingerprinting identifies this even when UAs are customized." },
          { cls: "apt-ru", name: "APT28", note: "Network scanning tooling generates distinctive TCP stack signatures detectable via passive OS fingerprinting per NSA/CISA AA20-296A." },
          { cls: "apt-mul", name: "Multi", note: "Most evasion-resistant scanning detection method - TCP stack parameters require OS-level changes to spoof convincingly." }
        ],
        cite: "MITRE ATT&CK T1592.004, NSA/CISA AA20-296A, industry reporting"
      },
      {
        sub: "T1592.004 - Client Configurations",
        indicator: "JA4H mismatch - HTTP header order inconsistent with claimed browser",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.user-agent == [\"*Chrome*\", \"*Firefox*\", \"*Safari*\", \"*Edge*\"]",
        kibana: "NOT source.ip: $MPNET\nAND user_agent.original: (\n  *Chrome* OR *Firefox*\n  OR *Safari* OR *Edge*\n)\nAND NOT http.request.headers.order:\n  $BROWSER_HEADER_BASELINE",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1592.004 JA4H\n    header order browser UA\n    mismatch\";\n  flow:established,to_server;\n  content:\"Mozilla/5.0\"; http.header;\n  pcre:\"/^(?!.*(Host|User-Agent|\n    Accept|Accept-Language|\n    Accept-Encoding|Connection))/x\";\n  http.header;\n  classtype:attempted-recon;\n  sid:9159222; rev:1;)",
        notes: "JA4H fingerprints HTTP clients by header order, count, accept-language, and cookie/referer presence. Chrome, Firefox, Edge each have stable header orders. Known orders: Chrome = Host, Connection, Accept, User-Agent, Accept-Encoding, Accept-Language; Python-requests = Host, User-Agent, Accept-Encoding, Accept, Connection (no Accept-Language). Effective for catching web scanner and phishing kit traffic spoofing browser UAs. Requires Zeek JA4 package.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses browser-mimicking UA strings but Python-requests or Go http.Client header orders detectable via JA4H analysis." },
          { cls: "apt-kp", name: "Kimsuky", note: "Automated reconnaissance tooling with spoofed browser UAs but scripting library header orders, detectable via JA4H." },
          { cls: "apt-mul", name: "Multi", note: "Particularly effective against phishing kits - kits written in PHP/Python/Go rarely implement accurate browser header ordering." }
        ],
        cite: "MITRE ATT&CK T1592.004, industry reporting"
      },
      {
        sub: "T1592.004 - Client Configurations",
        indicator: "WPAD / PAC file request - network proxy configuration disclosure",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*/wpad.dat*\", \"*/proxy.pac*\", \"*/wpad/wpad.dat*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *wpad.dat*\n  OR *proxy.pac*\n  OR *wpad/wpad.dat*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1592.004 WPAD PAC\n    proxy config disclosure\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(wpad\\.dat|\n    proxy\\.pac|\n    wpad\\/wpad\\.dat)/ix\";\n  http.uri;\n  classtype:attempted-recon;\n  sid:9159223; rev:1;)",
        notes: "WPAD requests reveal that the client uses automatic proxy detection - and if your PAC file is served, it discloses internal proxy hostnames, IP ranges, and bypass lists. External requests for wpad.dat should never reach your web servers. WPAD poisoning via Responder is a documented credential harvesting technique - internal clients broadcasting WPAD requests are vulnerable. Disable WPAD on all clients or configure proxy settings explicitly.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Exploited WPAD broadcast requests using Responder-equivalent tooling to serve malicious PAC files, redirecting traffic through adversary-controlled proxies." },
          { cls: "apt-mul", name: "Multi", note: "WPAD poisoning via NBNS/mDNS is documented in multiple penetration testing frameworks and commonly observed in post-compromise lateral movement." }
        ],
        cite: "MITRE ATT&CK T1592.004, T1557, industry reporting"
      }
    ]
  },
  {
    id: "T1593",
    name: "Search Open Websites / Domains",
    desc: ".001 Social Media · .002 Search Engines · .003 Code Repositories",
    rows: [
      {
        sub: "T1593.001 - Social Media",
        indicator: "[OFF-NET TRIPWIRE] LinkedIn bulk profile / company scraping from internal host",
        arkime: "ip.src == $MPNET\n&& host.http == *linkedin.com*\n&& http.method == GET\n&& http.uri == [\"*/search/results/people*\", \"*/company/*\", \"*/in/*\", \"*/posts/*\"]\n&& databytes.src > 20000\n&& packets.src > 20",
        kibana: "source.ip: $MPNET\nAND url.domain: \"linkedin.com\"\nAND http.request.method: GET\nAND url.path: (\n  *search/results/people*\n  OR */company/*\n  OR */in/*\n  OR */posts/*\n)\nAND http.response.bytes > 20000",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1593.001 Internal\n    LinkedIn bulk profile scrape\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  content:\"linkedin.com\"; host.http;\n  pcre:\"/(search\\/results\\/people|\n    \\/company\\/|\n    \\/in\\/[a-z0-9\\-]+\\/)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src,\n    count 20, seconds 60;\n  classtype:policy-violation;\n  sid:9159301; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. High-volume LinkedIn profile and company page fetches from single internal host = automated scraping. Legitimate LinkedIn use is interactive - 20+ profile GETs in 60 seconds from one endpoint is anomalous. LinkedIn rate limiting generates 429 responses visible in proxy logs - a 429 from LinkedIn is itself an indicator. Baseline sales/recruiting team use first.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses LinkedIn profile scraping to identify high-value targets at academic, NGO, and government organizations before spearphishing." },
          { cls: "apt-kp", name: "Kimsuky", note: "Scrapes LinkedIn profiles of South Korean government and US policy organization staff to identify personnel with access to target information." },
          { cls: "apt-cn", name: "APT10", note: "Scraped LinkedIn profiles of MSP employees to identify system administrators during Cloud Hopper." }
        ],
        cite: "MITRE ATT&CK T1593.001, T1589.003, industry reporting"
      },
      {
        sub: "T1593.001 - Social Media",
        indicator: "[OFF-NET TRIPWIRE] Social platform bulk org mention queries from internal host",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*twitter.com*\", \"*x.com*\", \"*reddit.com*\", \"*glassdoor.com*\", \"*facebook.com*\"]\n&& http.uri == [\"*/search*\", \"*/query*\", \"*/api/search*\", \"*/graphql*\"]\n&& databytes.src > 10000\n&& packets.src > 15",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"twitter.com\" OR \"x.com\"\n  OR \"reddit.com\"\n  OR \"glassdoor.com\"\n  OR \"facebook.com\"\n)\nAND url.path: (\n  *search* OR *query*\n  OR *api/search*\n  OR *graphql*\n)\nAND http.response.bytes > 10000",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1593.001 Internal\n    social platform bulk search\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    twitter\\.com|x\\.com|\n    reddit\\.com|glassdoor\\.com|\n    facebook\\.com)/ix\";\n  http.header;\n  threshold:type both,\n    track by_src,\n    count 15, seconds 60;\n  classtype:policy-violation;\n  sid:9159302; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Adversaries query social platforms for mentions of your org, employee names, and internal tool names. Reddit contains employee posts mentioning internal tools and outages. Glassdoor reviews often disclose internal technology stacks in detail. GraphQL endpoints on Twitter/X and Facebook are used by automated tools to bulk-harvest org-related content.",
        apt: [
          { cls: "apt-kp", name: "Kimsuky", note: "Conducts social media reconnaissance across multiple platforms to build target profiles of government and policy organization employees." },
          { cls: "apt-ru", name: "Cozy Bear", note: "Used social media intelligence gathering to identify and profile targets prior to spearphishing." },
          { cls: "apt-mul", name: "Multi", note: "Social media platform searches for org-specific content from internal hosts is a documented post-compromise reconnaissance behavior." }
        ],
        cite: "MITRE ATT&CK T1593.001, industry reporting"
      },
      {
        sub: "T1593.002 - Search Engines",
        indicator: "[OFF-NET TRIPWIRE] Google / Bing dork queries targeting your own domain from internal host",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*google.com*\", \"*bing.com*\", \"*duckduckgo.com*\"]\n&& http.uri == [\"*site:<YOUR_DOMAIN>*\", \"*inurl:<YOUR_DOMAIN>*\", \"*filetype:*\", \"*intitle:index.of*\", \"*\"internal use only\"*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"google.com\" OR \"bing.com\"\n  OR \"duckduckgo.com\"\n)\nAND url.query: (\n  *site:<YOUR_DOMAIN>* OR *inurl:*\n  OR *filetype:* OR *intitle:*\n  OR *\"internal use only\"*\n  OR *confidential*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1593.002 Internal\n    host Google dorking own domain\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    google\\.com|bing\\.com|\n    duckduckgo\\.com)/ix\";\n  http.header;\n  pcre:\"/(site%3A|inurl%3A|\n    filetype%3A|intitle%3A|\n    internal.use.only|\n    confidential)/ix\";\n  http.uri;\n  classtype:policy-violation;\n  sid:9159303; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Google dork operators (site:, inurl:, filetype:, intitle:) allow targeted searches for exposed files and sensitive content. An internal host running dork queries against your own domain is either red team activity (document it) or a compromised host performing pre-exfil intelligence gathering. URL-encoded operators (%3A = :) used by automated tools - the Suricata PCRE matches both encoded and decoded forms.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used Google dorking to identify exposed files, login pages, and sensitive content on target organization websites." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Uses targeted Google dork queries to find publicly accessible documents containing employee information and technology details on target websites." },
          { cls: "apt-kp", name: "Kimsuky", note: "Uses search engine dorking to identify exposed documents on government and research organization websites prior to targeted phishing." }
        ],
        cite: "MITRE ATT&CK T1593.002, industry reporting"
      },
      {
        sub: "T1593.002 - Search Engines",
        indicator: "[OFF-NET TRIPWIRE] Shodan / Censys / FOFA search API queries from internal host - own org lookup",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*shodan.io*\", \"*censys.io*\", \"*zoomeye.org*\", \"*fofa.info*\", \"*binaryedge.io*\"]\n&& http.uri == [\"*/shodan/host/search*\", \"*/api/v2/hosts/search*\", \"*/search*\"]\n&& http.method == GET",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"shodan.io\" OR \"censys.io\"\n  OR \"zoomeye.org\"\n  OR \"fofa.info\"\n  OR \"binaryedge.io\"\n)\nAND url.path: (\n  *search* OR *hosts/search*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1593.002 Internal\n    host Shodan/Censys/FOFA\n    own-org search\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    shodan\\.io|censys\\.io|\n    zoomeye\\.org|fofa\\.info|\n    binaryedge\\.io)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159304; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Internal hosts querying Shodan or Censys API against your own org's IP ranges = either security team exposure assessment (document and baseline) or a compromised host mapping your internet-facing attack surface. FOFA (fofa.info) and ZoomEye (zoomeye.org) are Chinese internet-wide scan databases - internal hits from non-security-team endpoints are a strong indicator of CN-attributed adversarial tooling.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Uses FOFA and ZoomEye (Chinese internet scan databases) to search for exposed services - internal hits indicate adversary tooling performing attack surface mapping." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Queried Shodan and Censys for exposed management interfaces on US critical infrastructure during pre-positioning operations." },
          { cls: "apt-ir", name: "APT33", note: "Used Shodan API queries to map exposed services on energy sector targets." }
        ],
        cite: "MITRE ATT&CK T1593.002, T1596.005, industry reporting"
      },
      {
        sub: "T1593.003 - Code Repositories",
        indicator: "[OFF-NET TRIPWIRE] GitHub API search for org secrets / internal naming from internal host",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*github.com*\", \"*api.github.com*\"]\n&& http.uri == [\"*/search/code*\", \"*/search?q=*\"]\n&& http.uri == [\"*password*\", \"*secret*\", \"*api_key*\", \"*token*\", \"*<YOUR_DOMAIN>*\", \"*internal*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"github.com\"\n  OR \"api.github.com\"\n)\nAND url.path: (\n  *search/code*\n  OR *search/repositories*\n)\nAND url.query: (\n  *<YOUR_DOMAIN>* OR *internal*\n  OR *password* OR *secret*\n  OR *api_key* OR *token*\n  OR *BEGIN+RSA*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1593.003 Internal\n    GitHub code search secret\n    exposure hunting\";\n  flow:established,to_server;\n  content:\"api.github.com\"; host.http;\n  content:\"/search/code\"; http.uri;\n  pcre:\"/(password|secret|\n    api_key|token|BEGIN.RSA|\n    BEGIN.PGP|internal|corp)/ix\";\n  http.uri;\n  classtype:policy-violation;\n  sid:9159305; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. GitHub code search API queries targeting your org's domain, internal naming conventions, or credential keywords from internal hosts = security team secret scanning (document it) or compromised host hunting for accidentally committed credentials. GitHub API rate-limits at 10 req/min for authenticated users - 403 responses in proxy logs indicate automated tooling hitting rate limits.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Searches GitHub for accidentally committed credentials, API keys, and internal configuration data from target organizations." },
          { cls: "apt-ru", name: "Cozy Bear", note: "Searched code repositories for credentials and configuration files related to target organizations." },
          { cls: "apt-ir", name: "APT33", note: "Used GitHub secret scanning techniques against energy sector and defense contractor repositories to identify accidentally committed credentials." }
        ],
        cite: "MITRE ATT&CK T1593.003, CISA advisories, industry reporting"
      },
      {
        sub: "T1593.003 - Code Repositories",
        indicator: "[OFF-NET TRIPWIRE] git clone over HTTPS - bulk repository cloning from suspicious endpoint",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& host.http == [\"*github.com*\", \"*gitlab.com*\", \"*bitbucket.org*\"]\n&& http.user-agent == *git/*\n&& http.uri == [\"*/info/refs*\", \"*/git-upload-pack*\"]\n&& databytes.dst > 100000",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"github.com\" OR \"gitlab.com\"\n  OR \"bitbucket.org\"\n)\nAND user_agent.original: *git/*\nAND url.path: (\n  *info/refs*\n  OR *git-upload-pack*\n)\nAND destination.bytes > 100000",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1593.003 Git clone\n    bulk repo download\";\n  flow:established,to_server;\n  content:\"git/\"; http.header;\n  content:\"/info/refs\"; http.uri;\n  threshold:type both,\n    track by_src,\n    count 5, seconds 300;\n  classtype:policy-violation;\n  sid:9159306; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Git clone over HTTPS generates a two-step HTTP exchange: GET /repo.git/info/refs?service=git-upload-pack (discovery) followed by POST /repo.git/git-upload-pack (pack download). User-Agent is always git/[version] - unforgeable without breaking git protocol. Bulk cloning of multiple repos from your org's namespace from an endpoint that isn't a known CI/CD system is anomalous. Large databytes.dst reflects repository size.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has cloned target organization code repositories to harvest credentials, API keys, and internal infrastructure details." },
          { cls: "apt-ru", name: "APT29", note: "Cloned repositories related to target organizations during pre-compromise intelligence gathering." },
          { cls: "apt-mul", name: "Multi", note: "Git clone activity against your org's repos from non-CI/CD endpoints is a documented post-compromise data staging behavior." }
        ],
        cite: "MITRE ATT&CK T1593.003, industry reporting"
      },
      {
        sub: "T1593.003 - Code Repositories",
        indicator: "Self-hosted GitLab / Bitbucket SCM API enumeration - external repository listing",
        arkime: "ip.src != $MPNET\n&& host.http == [\"*gitlab.<YOUR_DOMAIN>*\", \"*bitbucket.<YOUR_DOMAIN>*\", \"*git.<YOUR_DOMAIN>*\"]\n&& http.method == GET\n&& http.uri == [\"*/api/v4/projects*\", \"*/rest/api/1.0/repos*\", \"*/explore/repos*\", \"*/api/v4/users*\"]",
        kibana: "NOT source.ip: $MPNET\nAND url.domain: (\n  *gitlab.<YOUR_DOMAIN>*\n  OR *bitbucket.<YOUR_DOMAIN>*\n  OR *git.<YOUR_DOMAIN>*\n)\nAND url.path: (\n  */api/v4/projects*\n  OR */rest/api/1.0/repos*\n  OR */explore/repos*\n  OR */api/v4/users*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1593.003 External\n    internal SCM API enumeration\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(api\\/v4\\/projects|\n    rest\\/api\\/1\\.0\\/repos|\n    explore\\/repos|\n    api\\/v4\\/users)/ix\";\n  http.uri;\n  classtype:attempted-recon;\n  sid:9159307; rev:1;)",
        notes: "Self-hosted GitLab and Bitbucket expose REST APIs that list all repositories and users - even without authentication if misconfigured with public visibility. /api/v4/projects returns all repositories an unauthenticated user can see. External access to these endpoints from unknown IPs = repository enumeration. A 200 response with a large JSON payload from an external IP = critical misconfiguration - your repo list is public.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Enumerated self-hosted GitLab and Bitbucket instances via unauthenticated API endpoints per FBI and CISA advisories." },
          { cls: "apt-ir", name: "APT33", note: "Targeted self-hosted SCM instances at defense contractor and energy sector organizations to enumerate repositories." },
          { cls: "apt-mul", name: "Multi", note: "Unauthenticated SCM API access is a critical misconfiguration - remediate before tuning detection." }
        ],
        cite: "MITRE ATT&CK T1593.003, FBI/CISA advisories, industry reporting"
      }
    ]
  },
  {
    id: "T1595",
    name: "Active Scanning",
    desc: ".001 IP Blocks · .002 Vulnerability Scanning · .003 Wordlist Scanning",
    rows: [
      {
        sub: "T1595.001 - Scanning IP Blocks",
        indicator: "SYN scan pattern - single packet each direction, no data exchange",
        arkime: "ip.src != $MPNET\n&& packets.src == 1\n&& packets.dst == 1\n&& databytes.src == 0\n&& databytes.dst == 0\n&& tcpflags.syn == 1\n&& tcpflags.ack == 0",
        kibana: "NOT source.ip: $MPNET\nAND tcp.flags: \"S\"\nAND NOT tcp.flags: \"A\"\nAND network.packets: 2\nAND source.bytes: 0\nAND destination.bytes: 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1595 SYN scan\";\n  flags:S,12; flow:stateless;\n  threshold:type both,\n    track by_src,\n    count 20, seconds 10;\n  classtype:attempted-recon;\n  sid:9159501; rev:1;)",
        notes: "flags:S,12 matches SYN only, ignoring RST/ACK/FIN. Exactly 1 pkt each direction with 0 databytes is the SYN→SYN-ACK→RST fingerprint. High count threshold avoids false positives on slow apps.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Systematic port sweeps of maritime/gov targets prior to exploitation." },
          { cls: "apt-ru", name: "APT28", note: "Broad port surveys pre-operation documented against NATO targets." },
          { cls: "apt-ru", name: "Sandworm", note: "Mass pre-exploitation scanning of Ukrainian infrastructure." },
          { cls: "apt-mul", name: "Multi/IAB", note: "Mass pre-exploitation scanning. Default tool UAs primarily seen from opportunistic actors and initial access brokers." }
        ],
        cite: "MITRE ATT&CK T1595.001, industry reporting"
      },
      {
        sub: "T1595.001 - Scanning IP Blocks",
        indicator: "External hosts touching common ports - 0 payload",
        arkime: "ip.src != $MPNET\n&& databytes.dst == 0\n&& port.dst == [21,22,23,25,53,\n80,110,135,139,143,\n443,445,1433,1521,\n3306,3389,5900,\n8080,8443,8888]",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: (21 OR 22\n  OR 23 OR 25 OR 53 OR 80\n  OR 110 OR 135 OR 139 OR 143\n  OR 443 OR 445 OR 1433 OR 1521\n  OR 3306 OR 3389 OR 5900\n  OR 8080 OR 8443 OR 8888)\nAND destination.bytes: 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET [21,22,23,25,53,\n   80,110,135,139,143,\n   443,445,1433,1521,3306,\n   3389,5900,8080,8443,8888]\n  (msg:\"RECON T1595 Zero-payload\n    probe common ports\";\n  flags:S,12; dsize:0;\n  threshold:type both,\n    track by_src,\n    count 10, seconds 30;\n  classtype:attempted-recon;\n  sid:9159502; rev:1;)",
        notes: "DB ports (1433 MSSQL, 1521 Oracle, 3306 MySQL), VNC (5900), alt-HTTP included. Zero databytes.dst confirms knock with no follow-through. Enrich with GeoIP - RDP from Eastern Europe at 03:00 UTC is a tier-1 alert.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Cloud Hopper targeted RDP/SMB extensively against MSP environments." },
          { cls: "apt-kp", name: "Lazarus", note: "Probes DB/RDP ports against financial targets." },
          { cls: "apt-ru", name: "APT28", note: "Broad port surveys pre-operation." }
        ],
        cite: "MITRE ATT&CK T1595.001, industry reporting"
      },
      {
        sub: "T1595.001 - Scanning IP Blocks",
        indicator: "ICMP ping sweep - external host sweeping your address space",
        arkime: "ip.src != $MPNET\n&& protocols == icmp\n&& icmp.type == 8\n&& icmp.code == 0\n&& ip.dst == $MPNET\n&& packets.src > 10",
        kibana: "NOT source.ip: $MPNET\nAND network.transport: icmp\nAND icmp.type: 8\nAND icmp.code: 0\nAND destination.ip: $MPNET",
        suricata: "alert icmp $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1595.001 ICMP ping\n    sweep host discovery\";\n  itype:8; icode:0;\n  threshold:type both,\n    track by_src,\n    count 10, seconds 10;\n  classtype:attempted-recon;\n  sid:9159505; rev:1;)",
        notes: "ICMP type 8 code 0 = echo request. Burst of pings to sequential IPs from a single external source = host discovery sweep before port scanning. Check ip.dst for sequential increment pattern in Arkime. Many orgs block inbound ICMP at perimeter - adversaries fall back to TCP SYN host discovery instead.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "ICMP host discovery sweeps as standard first step in network enumeration of maritime/defense/gov IP ranges." },
          { cls: "apt-ru", name: "Sandworm", note: "ICMP sweep-based host discovery against Ukrainian government and energy sector IP allocations prior to destructive operations." },
          { cls: "apt-ru", name: "APT28", note: "Automated pre-scan ICMP sweeps in network reconnaissance toolkits against NATO member networks." },
          { cls: "apt-cn", name: "Volt Typhoon", note: "Host discovery including ICMP sweeps to enumerate live systems in US critical infrastructure IP ranges." }
        ],
        cite: "MITRE ATT&CK T1595.001, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1595.002 - Vulnerability Scanning",
        indicator: "Web recon / directory enumeration - sensitive path probing",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*robots.txt*\", \"*sitemap*\", \"*.env*\", \"*/.git/*\", \"*/.svn/*\", \"*/wp-config*\", \"*/config.php*\", \"*/web.config*\", \"*/phpinfo*\", \"*/server-status*\", \"*/admin/*\", \"*/actuator/*\", \"*/swagger*\", \"*/api-docs*\", \"*/.aws/credentials*\", \"*/backup*\", \"*/.htpasswd*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *robots.txt* OR *sitemap*\n  OR *.env* OR *.git*\n  OR *.svn* OR *wp-config*\n  OR *phpinfo* OR *server-status*\n  OR */admin/* OR */actuator/*\n  OR *swagger* OR *api-docs*\n  OR *.aws/credentials*\n  OR *backup* OR *.htpasswd*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1595 Dir enum\n    sensitive path probe\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/\\/(robots\\.txt|sitemap|\n    \\.env|\\.git|\\.svn|wp-config|\n    phpinfo|server-status|admin|\n    actuator|swagger|api-docs|\n    backup|\\.htpasswd|\\.aws)/ix\";\n  http.uri;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 60;\n  classtype:web-application-activity;\n  sid:9159503; rev:1;)",
        notes: "Path list covers: source control leaks (.git, .svn), cloud cred leaks (.aws/credentials), Spring Boot (actuator), REST API discovery (swagger, api-docs), Apache internals (server-status). Any 200 response to these paths is a critical finding regardless of scanning intent.",
        apt: [
          { cls: "apt-ir", name: "APT33", note: "Heavily targets exposed cloud credentials and config files against energy/defense sector targets." },
          { cls: "apt-cn", name: "APT41", note: "Probes web apps pre-supply-chain compromise." },
          { cls: "apt-mul", name: "FIN7", note: "Directory enum for POS/hospitality targeting." }
        ],
        cite: "MITRE ATT&CK T1595.002, industry reporting"
      },
      {
        sub: "T1595.002 - Vulnerability Scanning",
        indicator: "CVE-specific exploit probe patterns - known-exploited path fingerprinting",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.method == GET\n&& http.uri == [\"*jndi:ldap*\", \"*jndi:rmi*\", \"*/owa/auth/x.js*\", \"*/vpns/portal/scripts/*\", \"*/mgmt/tm/util/bash*\", \"*/mgmt/tm/sys/config*\", \"*/solr/admin/cores*\", \"*/actuator/heapdump*\", \"*/actuator/env*\", \"*/wp-json/wp/v2/users*\", \"*/telescope/requests*\", \"*/dana-na/auth/saml-sso*\"]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: GET\nAND url.path: (\n  *jndi:ldap* OR *jndi:rmi*\n  OR */owa/auth/x.js*\n  OR */vpns/portal/scripts/*\n  OR */mgmt/tm/util/bash*\n  OR */mgmt/tm/sys/config*\n  OR */solr/admin/cores*\n  OR */actuator/heapdump*\n  OR */actuator/env*\n  OR */wp-json/wp/v2/users*\n  OR */telescope/requests*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1595.002 CVE-specific\n    exploit path probe\";\n  flow:established,to_server;\n  pcre:\"/(\\$\\{jndi:|\n    \\/owa\\/auth\\/x\\.js|\n    \\/vpns\\/portal\\/scripts|\n    \\/mgmt\\/tm\\/util\\/bash|\n    \\/solr\\/admin\\/cores|\n    \\/actuator\\/(heapdump|env)|\n    \\/wp-json\\/wp\\/v2\\/users|\n    \\/telescope\\/requests)/ix\";\n  http.uri;\n  classtype:web-application-activity;\n  sid:9159506; rev:1;)",
        notes: "CVE mapping: jndi:ldap/rmi = Log4Shell (CVE-2021-44228), /owa/auth/x.js = ProxyLogon (CVE-2021-26855), /vpns/portal/scripts/ = Citrix ADC (CVE-2019-19781), /mgmt/tm/util/bash = F5 iControl (CVE-2021-22986), /solr/admin/cores = Apache Solr RCE, /actuator/heapdump = Spring Boot. A single hit on any of these from an external IP is P1 - maintain a living list updated against CISA KEV additions.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Probed F5 iControl and Citrix paths weeks before exploitation per CISA AA23-144A." },
          { cls: "apt-ir", name: "APT33", note: "Log4Shell path probing within 48 hours of public disclosure against energy/defense web infrastructure." },
          { cls: "apt-kp", name: "Lazarus", note: "ProxyLogon path probing (/owa/auth/x.js) against financial sector Exchange infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "CVE-specific path probing documented across all major nation-state actors following high-profile vulnerability disclosures." }
        ],
        cite: "MITRE ATT&CK T1595.002, CISA KEV, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1595.002 - Vulnerability Scanning",
        indicator: "Banner grabbing - service version harvest via connect-and-RST",
        arkime: "ip.src != $MPNET\n&& port.dst == [21,22,23,25,110,\n  143,389,445,3306,\n  3389,5432,5900,8080]\n&& packets.src == 1\n&& packets.dst >= 1\n&& databytes.src == 0\n&& databytes.dst > 0",
        kibana: "NOT source.ip: $MPNET\nAND destination.port: (\n  21 OR 22 OR 23 OR 25\n  OR 110 OR 143 OR 389\n  OR 445 OR 3306 OR 3389\n  OR 5432 OR 5900 OR 8080\n)\nAND source.packets: 1\nAND destination.packets >= 1\nAND source.bytes: 0\nAND destination.bytes > 0",
        suricata: "alert tcp $EXTERNAL_NET any\n  -> $HOME_NET\n  [21,22,23,25,110,143,\n   389,445,3306,3389,\n   5432,5900,8080]\n  (msg:\"RECON T1595.002 Banner\n    grab connect-and-RST\";\n  flow:established,to_server;\n  dsize:0;\n  threshold:type both,\n    track by_src,\n    count 5, seconds 30;\n  classtype:attempted-recon;\n  sid:9159507; rev:1;)",
        notes: "Client connects, server sends banner, client immediately RSTs without sending data. Zero databytes.src with non-zero databytes.dst across multiple service ports from same source IP. SSH banners reveal OpenSSH version; FTP reveals server software; SMTP reveals MTA and version. Zeek service.log provides cleaner banner capture for post-incident analysis.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Banner grabbing as standard service enumeration step in MSP network reconnaissance during Cloud Hopper." },
          { cls: "apt-cn", name: "APT40", note: "Service banner grabbing against maritime/government perimeters to build software inventory before CVE selection." },
          { cls: "apt-ru", name: "Dragonfly", note: "Banner grabbing against energy sector exposed services to identify unpatched software at IT/OT boundaries." }
        ],
        cite: "MITRE ATT&CK T1595.002, T1592.002, NSA/CISA advisories, industry reporting"
      },
      {
        sub: "T1595.002 - Vulnerability Scanning",
        indicator: "Known scanner user-agents hitting infrastructure",
        arkime: "ip.src != $MPNET\n&& http.user-agent == [\"*nmap*\", \"*nikto*\", \"*masscan*\", \"*zgrab*\", \"*gobuster*\", \"*nuclei*\", \"*sqlmap*\", \"*ffuf*\", \"*feroxbuster*\", \"*wpscan*\", \"*acunetix*\", \"*nessus*\", \"*metasploit*\", \"*hydra*\", \"*python-requests*\", \"*go-http-client*\", \"*libwww-perl*\"]",
        kibana: "NOT source.ip: $MPNET\nAND user_agent.original: (\n  *nmap* OR *nikto*\n  OR *masscan* OR *zgrab*\n  OR *gobuster* OR *nuclei*\n  OR *sqlmap* OR *ffuf*\n  OR *feroxbuster* OR *wpscan*\n  OR *acunetix* OR *nessus*\n  OR *metasploit* OR *hydra*\n  OR *python-requests*\n  OR *go-http-client*\n  OR *libwww-perl*\n)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1595 Scanner UA\";\n  flow:established,to_server;\n  pcre:\"/User-Agent\\s*:\\s*\n    [^\\r\\n]*(nmap|nikto|masscan|\n    zgrab|gobuster|nuclei|sqlmap|\n    ffuf|feroxbuster|wpscan|\n    acunetix|nessus|metasploit|\n    hydra|python-requests|\n    go-http-client|\n    libwww-perl)/ix\";\n  http.header;\n  classtype:web-application-activity;\n  sid:9159504; rev:1;)",
        notes: "Includes modern wordlist fuzzers (ffuf, feroxbuster, wfuzz), CMS scanners (wpscan, joomscan), commercial scanners (Acunetix, Nessus, Qualys), exploitation frameworks (Metasploit, Hydra), scripting defaults (python-requests, go-http-client, libwww-perl). Skilled adversaries spoof UAs - absence does NOT clear a session. Pair with JA3/JA4.",
        apt: [
          { cls: "apt-mul", name: "Multi/IAB", note: "Default tool UAs primarily from opportunistic actors and initial access brokers. Nation-state actors typically customize UA strings." }
        ],
        cite: "MITRE ATT&CK T1595.002, industry reporting"
      },
      {
        sub: "T1595.003 - Wordlist Scanning",
        indicator: "High 4xx response ratio from single external IP - wordlist exhaustion",
        arkime: "ip.src != $MPNET\n&& protocols == http\n&& http.statuscode == [400, 403, 404, 405]\n&& packets.src > 50",
        kibana: "NOT source.ip: $MPNET\nAND http.response.status_code: (\n  400 OR 403 OR 404 OR 405\n)\n| stats count by source.ip\n| where count > 50",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1595.003 High 4xx\n    ratio wordlist exhaustion\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  http.stat_code;\n  content:\"404\";\n  threshold:type both,\n    track by_src,\n    count 50, seconds 60;\n  classtype:web-application-activity;\n  sid:9159508; rev:1;)",
        notes: "Wordlist scanners (gobuster, ffuf, feroxbuster) generate characteristic 404/403/400 bursts regardless of UA string. Single external IP generating 50+ 4xx responses across varied URI paths in 60 seconds = near-certain wordlist scanning. UA-spoof-resistant companion to the scanner UA row. Use bucket aggregation in Kibana (source.ip + status_code) - signal is in the volume, not individual requests.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Wordlist-based web enumeration with custom UA strings as standard pre-compromise step - 4xx ratio catches this where UA matching fails." },
          { cls: "apt-ir", name: "APT33", note: "Directory brute-forcing with rotated UA strings against energy/defense web apps." },
          { cls: "apt-mul", name: "FIN7", note: "ffuf and feroxbuster with custom UAs in POS/hospitality sector web app recon." }
        ],
        activity: [
          { cls: "apt-mul", name: "IAB", note: "Initial access brokers run ffuf/feroxbuster with spoofed UAs against bulk target lists - 4xx ratio is the only reliable indicator when UA rotation is in play." }
        ],
        cite: "MITRE ATT&CK T1595.003, industry reporting"
      }
    ]
  },
  {
    id: "T1596",
    name: "Search Technical Databases",
    desc: ".001/.002 WHOIS & History · .003 Passive DNS · .004 Certificate Transparency · .005 Scan Databases",
    rows: [
      {
        sub: "T1596.001 - WHOIS / .002 WHOIS History",
        indicator: "[OFF-NET TRIPWIRE] RDAP / WHOIS API query - internal host querying registration data for own domain",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*rdap.arin.net*\", \"*rdap.ripe.net*\", \"*rdap.apnic.net*\", \"*whois.domaintools.com*\", \"*whoisxmlapi.com*\", \"*whoisfreaks.com*\"]\n&& http.method == GET\n&& http.uri == [\"*/ip/*\", \"*/domain/*\", \"*/autnum/*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"rdap.arin.net\"\n  OR \"rdap.ripe.net\"\n  OR \"rdap.apnic.net\"\n  OR \"whois.domaintools.com\"\n  OR \"whoisxmlapi.com\"\n  OR \"whoisfreaks.com\"\n)\nAND url.path: (\n  */ip/* OR */domain/*\n  OR */autnum/*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.001 Internal\n    host RDAP/WHOIS API query\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    rdap\\.arin\\.net|\n    rdap\\.ripe\\.net|\n    rdap\\.apnic\\.net|\n    whois\\.domaintools\\.com|\n    whoisxmlapi\\.com|\n    whoisfreaks\\.com)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159401; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Internal hosts querying RDAP or commercial WHOIS APIs against your own domain or IP ranges = NOC/security team activity (baseline and document) or a compromised host mapping registration data. Automated bulk queries from endpoints are anomalous. Port 43 TCP (legacy WHOIS) is covered in T1590.001 - this row covers the modern RDAP/HTTP equivalent.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Queried RDAP and WHOIS data to map organizational relationships between target organizations and their ISPs, identifying OT-segment IP ranges." },
          { cls: "apt-ru", name: "APT29", note: "Queried domain registration and RDAP data to map subsidiary and partner relationships during pre-SolarWinds reconnaissance." },
          { cls: "apt-mul", name: "Multi", note: "Post-compromise indicator - adversaries map your registered IP space to plan lateral movement and identify overlooked internet-exposed ranges." }
        ],
        cite: "MITRE ATT&CK T1596.001, industry reporting"
      },
      {
        sub: "T1596.001 - WHOIS / .002 WHOIS History",
        indicator: "[OFF-NET TRIPWIRE] WHOIS history / DomainTools API - historical registration data query from internal host",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*domaintools.com*\", \"*whoisology.com*\", \"*whoxy.com*\", \"*whoishistory.com*\", \"*completedns.com*\"]\n&& http.method == GET\n&& http.uri == [\"*/history/*\", \"*/reverse/*\", \"*/hosting-history/*\", \"*/whois-history/*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"domaintools.com\"\n  OR \"whoisology.com\"\n  OR \"whoxy.com\"\n  OR \"whoishistory.com\"\n)\nAND url.path: (\n  *history* OR *reverse*\n  OR *hosting-history*\n  OR *whois-history*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.002 Internal\n    host WHOIS history query\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    domaintools\\.com|\n    whoisology\\.com|\n    whoxy\\.com|\n    whoishistory\\.com|\n    completedns\\.com)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159402; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. WHOIS history services reveal historical registrant data, previous name servers, past IP associations, and ownership changes. Adversaries use this to identify previously used infrastructure and overlooked decommissioned services. DomainTools reverse WHOIS (find all domains registered to the same email/org) maps your entire domain portfolio - extremely high intelligence value.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Uses WHOIS history data to map target organization domain registration history and identify the full domain portfolio." },
          { cls: "apt-ir", name: "APT33", note: "Queries WHOIS history services to identify historically registered domains associated with target organizations." },
          { cls: "apt-mul", name: "Multi", note: "WHOIS history queries from internal hosts against your own domain portfolio are a documented post-compromise intelligence gathering technique." }
        ],
        cite: "MITRE ATT&CK T1596.002, industry reporting"
      },
      {
        sub: "T1596.003 - Passive DNS",
        indicator: "[OFF-NET TRIPWIRE] Passive DNS database query - internal host querying pDNS for own infrastructure history",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*passivetotal.org*\", \"*api.passivetotal.org*\", \"*virustotal.com*\", \"*robtex.com*\", \"*dnsdb.info*\", \"*farsightsecurity.com*\", \"*community.riskiq.com*\"]\n&& http.method == GET\n&& http.uri == [\"*/dns/passive*\", \"*/resolutions*\", \"*/pdns*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"passivetotal.org\"\n  OR \"virustotal.com\"\n  OR \"robtex.com\"\n  OR \"dnsdb.info\"\n  OR \"farsightsecurity.com\"\n  OR \"community.riskiq.com\"\n)\nAND url.path: (\n  *dns/passive* OR *resolutions*\n  OR *pdns* OR *domain*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.003 Internal\n    host passive DNS query own\n    infrastructure\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    passivetotal\\.org|\n    api\\.passivetotal\\.org|\n    virustotal\\.com|robtex\\.com|\n    dnsdb\\.info|\n    farsightsecurity\\.com|\n    community\\.riskiq\\.com)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159403; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Passive DNS databases record historical DNS resolutions - what IPs a hostname resolved to over time. Internal hosts querying pDNS for your own hostnames map your historical DNS footprint, potentially exposing decommissioned services still in DNS and past infrastructure still accessible. Farsight DNSDB is extremely comprehensive. These queries also create intelligence-leakage risk on top of the detection signal.",
        apt: [
          { cls: "apt-cn", name: "APT10", note: "Queried passive DNS databases to map historical DNS resolutions for MSP customer infrastructure, locating decommissioned but still-accessible services." },
          { cls: "apt-ru", name: "APT29", note: "Used passive DNS data to map infrastructure relationships between target organizations and hosting providers during pre-SolarWinds reconnaissance." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Queries passive DNS databases to track target organization infrastructure changes over time, identifying new services and decommissioned endpoints." }
        ],
        cite: "MITRE ATT&CK T1596.003, industry reporting"
      },
      {
        sub: "T1596.004 - Certificate Transparency",
        indicator: "[OFF-NET TRIPWIRE] Certificate Transparency log query - CT log scraping for org subdomain enumeration",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*crt.sh*\", \"*certspotter.com*\", \"*sslmate.com*\", \"*transparencyreport.google.com*\", \"*censys.io*\"]\n&& http.method == GET\n&& http.uri == [\"*/?q=*\", \"*/search*\", \"*/api/v1/certs*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"crt.sh\" OR \"certspotter.com\"\n  OR \"sslmate.com\"\n  OR \"censys.io\"\n  OR \"ct.googleapis.com\"\n)\nAND url.path: (\n  *?q=* OR *search*\n  OR *api/v1/certs*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.004 Internal\n    host CT log subdomain query\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    crt\\.sh|certspotter\\.com|\n    sslmate\\.com|\n    ct\\.googleapis\\.com|\n    censys\\.io)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159404; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects connections to off-MPNet infrastructure that should be unreachable from an air-gapped environment. Any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Certificate Transparency logs record every TLS certificate issued for your domain - including wildcard certs revealing subdomain patterns, SAN entries listing internal hostnames, and certs for decommissioned services. A crt.sh query for %.<YOUR_DOMAIN> returns every cert ever issued. CT logs are public and queryable without authentication - adversaries use this as a zero-noise subdomain enumeration technique that never touches your infrastructure.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Queries CT logs to enumerate subdomains of target organizations before active scanning, identifying dev/staging/internal services with public certs." },
          { cls: "apt-ru", name: "APT28", note: "Uses CT log queries to identify target organization subdomains and map infrastructure scope prior to exploitation." },
          { cls: "apt-ir", name: "APT33", note: "Queries CT logs to identify TLS certificates for energy sector and defense contractor subdomains without any active probing." }
        ],
        cite: "MITRE ATT&CK T1596.004, industry reporting"
      },
      {
        sub: "T1596.004 - Certificate Transparency",
        indicator: "[OFF-NET TRIPWIRE] CT stream monitoring - real-time WebSocket feed for newly issued cert tracking",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*certstream.calidog.io*\", \"*ct.cloudflare.com*\", \"*mammoth.ct.comodo.com*\"]\n&& protocols == wss\n&& databytes.dst > 0",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"certstream.calidog.io\"\n  OR \"ct.cloudflare.com\"\n  OR \"mammoth.ct.comodo.com\"\n)\nAND network.protocol: \"websocket\"",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.004 Internal\n    host CT stream monitoring\n    websocket\";\n  flow:established,to_server;\n  content:\"certstream\"; http.uri;\n  content:\"Upgrade: websocket\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159405; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. CertStream provides a real-time WebSocket feed of all newly issued CT log certificates. A persistent WebSocket connection to certstream.calidog.io from an endpoint that isn't a known security monitoring system is anomalous - it's a running process. Adversaries can use this feed to monitor when you issue new certificates, revealing new services and infrastructure as they come online. Relatively niche but high-signal when it fires from unexpected endpoints.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "CT stream monitoring from internal hosts is primarily observed in security operations contexts - from unexpected endpoints it indicates adversary automation tracking newly issued infrastructure certificates." }
        ],
        cite: "MITRE ATT&CK T1596.004, industry reporting"
      },
      {
        sub: "T1596.005 - Scan Databases",
        indicator: "[OFF-NET TRIPWIRE] Shodan / Censys historical host data API - own infrastructure exposure query",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*api.shodan.io*\", \"*search.censys.io*\", \"*api.censys.io*\", \"*app.binaryedge.io*\"]\n&& http.method == GET\n&& http.uri == [\"*/shodan/host/*\", \"*/v2/hosts/*\", \"*/api/v2/hosts/search*\", \"*/v1/query/ip*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"api.shodan.io\"\n  OR \"search.censys.io\"\n  OR \"api.censys.io\"\n  OR \"app.binaryedge.io\"\n)\nAND url.path: (\n  *shodan/host*\n  OR *v2/hosts*\n  OR *hosts/search*\n  OR *query/ip*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.005 Internal\n    host Shodan/Censys historical\n    data query own IP\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    api\\.shodan\\.io|\n    search\\.censys\\.io|\n    api\\.censys\\.io|\n    app\\.binaryedge\\.io)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159406; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Shodan and Censys host APIs return historical scan data for a specific IP - all open ports ever observed, banners captured, TLS certificates indexed. An internal host querying these APIs for your own IP ranges retrieves exactly what adversaries see when they look you up. Legitimate security team activity - document and baseline it. From unexpected endpoints = compromised host or insider reconnaissance.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Queried Shodan and Censys host APIs for US critical infrastructure IP ranges to identify historically exposed management interfaces." },
          { cls: "apt-ir", name: "APT33", note: "Used Shodan historical host data to monitor energy sector target infrastructure for new service exposures and version changes." },
          { cls: "apt-cn", name: "APT40", note: "Queries Censys and Shodan APIs for maritime and government target IP ranges to build comprehensive historical exposure profiles." }
        ],
        cite: "MITRE ATT&CK T1596.005, CISA advisories, industry reporting"
      },
      {
        sub: "T1596.005 - Scan Databases",
        indicator: "[OFF-NET TRIPWIRE] VirusTotal / OTX / URLScan - own infrastructure submitted to threat intel platform",
        arkime: "ip.src == $MPNET\n&& host.http == [\"*virustotal.com*\", \"*otx.alienvault.com*\", \"*urlscan.io*\", \"*urlvoid.com*\"]\n&& http.method == [GET, POST]\n&& http.uri == [\"*/api/v3/domains/*\", \"*/api/v3/ip_addresses/*\", \"*/api/v1/indicators/*\", \"*/result/*\", \"*/scan*\"]",
        kibana: "source.ip: $MPNET\nAND url.domain: (\n  \"virustotal.com\"\n  OR \"otx.alienvault.com\"\n  OR \"urlscan.io\"\n  OR \"urlvoid.com\"\n)\nAND url.path: (\n  *api/v3/domains*\n  OR *api/v3/ip_addresses*\n  OR *api/v1/indicators*\n  OR *result* OR *scan*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1596.005 Internal\n    host submitting own infra to\n    threat intel platform\";\n  flow:established,to_server;\n  pcre:\"/Host\\s*:\\s*(\n    virustotal\\.com|\n    otx\\.alienvault\\.com|\n    urlscan\\.io|\n    urlvoid\\.com)/ix\";\n  http.header;\n  classtype:policy-violation;\n  sid:9159407; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Submitting your own domain or IP to VirusTotal from an internal host leaks intelligence - VT results are visible to all paid subscribers. A compromised host checking if infrastructure is flagged = adversary verifying C2 isn't burned. URLScan.io takes public screenshots of submitted URLs - submitting an internal URL creates a permanent public screenshot of your internal web applications. Critical OPSEC failure if observed from unexpected endpoints.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Submitted infrastructure components to threat intel platforms from compromised hosts to verify detection status before deploying additional tooling." },
          { cls: "apt-mul", name: "Multi", note: "Adversaries inside target networks have been documented submitting infrastructure to VT and OTX to verify whether C2 domains and payloads are flagged." }
        ],
        cite: "MITRE ATT&CK T1596.005, industry reporting"
      }
    ]
  },
  {
    id: "T1598",
    name: "Phishing for Information",
    desc: ".001 Spearphishing Service · .002 Spearphishing Attachment · .003 Spearphishing Link",
    rows: [
      {
        sub: "T1598.003 - Spearphishing Link",
        indicator: "[OFF-NET TRIPWIRE] Spearphishing link - internal host clicking newly registered suspicious domain",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.method == GET\n&& host.http != $ALLOWED_DEFAULTS\n&& host.http == [\"*login*\", \"*verify*\", \"*secure*\", \"*account*\", \"*signin*\", \"*auth*\", \"*microsoft*\", \"*office365*\"]",
        kibana: "source.ip: $MPNET\nAND NOT url.domain: $ALLOWED_DEFAULTS\nAND url.path: (\n  *login* OR *verify*\n  OR *secure* OR *account*\n  OR *update* OR *confirm*\n  OR *signin* OR *auth*\n)\nAND tls.server.not_before:\n  [now-30d TO now]",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1598.003 Click to\n    suspicious login domain\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/(login|verify|secure|\n    account|update|confirm|\n    signin|auth)/i\";\n  http.uri;\n  classtype:social-engineering;\n  sid:9159801; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Correlate domain age via threat intel (WHOIS, PassiveDNS). Domains registered within 30 days containing auth-themed keywords are high-risk. Typosquats (micros0ft, g00gle, rn-icrosoft) require fuzzy matching against your known-good list.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Used spearphishing links to compromise credentials." },
          { cls: "apt-kp", name: "Kimsuky", note: "Tailored spearphishing emails to gather victim information including contact lists." },
          { cls: "apt-cn", name: "ZIRCONIUM", note: "Targeted presidential campaign staffers with credential phishing emails." },
          { cls: "apt-kp", name: "Moonstone Sleet", note: "Interacted with victims via email to gather information." }
        ],
        cite: "MITRE ATT&CK T1598.003, industry reporting"
      },
      {
        sub: "T1598.003 - Spearphishing Link",
        indicator: "[OFF-NET TRIPWIRE] Internal host POSTing credentials to external harvester page",
        arkime: "ip.src == $MPNET\n&& http.method == POST\n&& host.http != $ALLOWED_DEFAULTS\n&& http.uri == [\"*login*\", \"*signin*\", \"*verify*\", \"*auth*\", \"*password*\", \"*credential*\"]\n&& databytes.src > 50\n&& databytes.src < 500",
        kibana: "source.ip: $MPNET\nAND http.request.method: POST\nAND NOT url.domain: $ALLOWED_DEFAULTS\nAND url.path: (\n  *login* OR *signin*\n  OR *verify* OR *auth*\n  OR *account* OR *password*\n)\nAND http.request.body.bytes > 50\nAND http.request.body.bytes < 500",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1598 Cred POST\n    to external URI\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(login|signin|verify|\n    auth|account|confirm|\n    password|credential)/i\";\n  http.uri;\n  content:\"password=\";\n  http.request_body;\n  classtype:social-engineering;\n  sid:9159802; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. POST body 50-500 bytes is the sweet spot for a username+password submission. Also match 'passwd=', 'pwd=', 'pass=', 'credential=' variants. Pair with proxy category for the destination domain.",
        apt: [
          { cls: "apt-ir", name: "APT33", note: "Dedicated credential harvesting infrastructure targeting energy/aviation via fake O365/OWA portals." },
          { cls: "apt-ir", name: "Charming Kitten", note: "HYPERSCRAPE tool collects credentials from fake Gmail and Yahoo portals." },
          { cls: "apt-ru", name: "APT29", note: "Used credential harvesting pages as initial access in multiple government intrusions." },
          { cls: "apt-kp", name: "Kimsuky", note: "Deploys credential harvesting pages mimicking Korean government and academic portals." }
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
      {
        sub: "T1598.003 - Spearphishing Link",
        indicator: "AiTM / Evilginx proxy - session cookie harvest post-MFA",
        arkime: "ip.src == $MPNET\n&& protocols == https\n&& host.http != $ALLOWED_DEFAULTS",
        kibana: "source.ip: $MPNET\nAND NOT tls.server.name: $ALLOWED_DEFAULTS\nAND http.response.headers.set_cookie: *\nAND tls.server.not_before:\n  [now-14d TO now]\nAND NOT url.domain: $ALLOWED_DEFAULTS",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HOME_NET any\n  (msg:\"RECON T1598 AiTM proxy\n    Set-Cookie unknown domain\";\n  flow:established,from_server;\n  content:\"Set-Cookie:\"; http.header;\n  content:\"Secure\"; http.header;\n  content:\"HttpOnly\"; http.header;\n  threshold:type both,\n    track by_dst, count 2,\n    seconds 10;\n  classtype:social-engineering;\n  sid:9159803; rev:1;)",
        notes: "AiTM frameworks (Evilginx2, Modlishka, Muraena) proxy the real IdP - MFA succeeds but session token is captured. Look for Secure+HttpOnly cookies set by domains NOT in your IdP list (Okta, Azure AD, Duo). Follow up in identity logs: successful MFA + new device or impossible travel = confirmed incident.",
        apt: [
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Used AiTM phishing against Microsoft corporate and government targets 2023-2024." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Deployed Evilginx2 infrastructure targeting academic and government O365 tenants." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Deployed EvilProxy at scale against MGM Resorts and Caesars Entertainment." }
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
      {
        sub: "T1598.003 - Spearphishing Link",
        indicator: "MFA token harvesting - rapid sequential TOTP/OTP submission",
        arkime: "ip.src != $MPNET\n&& http.method == POST\n&& http.uri == [\"*mfa*\", \"*otp*\", \"*totp*\", \"*2fa*\", \"*verify*\", \"*code*\", \"*challenge*\"]\n&& packets.src > 5\n&& http.statuscode == [200, 302, 401]",
        kibana: "NOT source.ip: $MPNET\nAND http.request.method: POST\nAND url.path: (\n  *mfa* OR *otp* OR *totp*\n  OR *2fa* OR *verify*\n  OR *code* OR *challenge*\n)\nAND http.response.status_code:\n  (200 OR 302 OR 401)",
        suricata: "alert http $EXTERNAL_NET any\n  -> $HTTP_SERVERS any\n  (msg:\"RECON T1598 MFA OTP\n    brute/harvest attempt\";\n  flow:established,to_server;\n  content:\"POST\"; http.method;\n  pcre:\"/(mfa|otp|totp|2fa|\n    verify|challenge|token)/i\";\n  http.uri;\n  threshold:type both,\n    track by_src, count 5,\n    seconds 30;\n  classtype:attempted-user;\n  sid:9159804; rev:1;)",
        notes: "Real-time kits (EvilProxy) relay OTP within the 30s TOTP window - creates a burst of POSTs to /mfa or /verify endpoints. Also watch for MFA fatigue: repeated push notifications to the same account in short window - visible in IdP logs, not network traffic.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Pioneered MFA fatigue (push bombing) attacks at scale." },
          { cls: "apt-ru", name: "Midnight Blizzard", note: "MFA bypass operations against Microsoft corporate using real-time relay." },
          { cls: "apt-kp", name: "Lazarus", note: "OTP relay against cryptocurrency exchange staff to bypass 2FA." },
          { cls: "apt-kp", name: "Kimsuky", note: "Real-time phishing kits relaying OTP codes during government/policy targeting." }
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
      {
        sub: "T1598.002 - Spearphishing Attachment",
        indicator: "DNS OOB callback - encoded subdomain from phishing document",
        arkime: "ip.src == $MPNET\n&& protocols == dns\n&& dns.query.type == [A, AAAA, TXT]\n&& host.dns != $ALLOWED_DEFAULTS\n// Encoded-subdomain detection (long hex or base64 strings) requires regex - does not always play nice in Arkime. \n// See Suricata pcre column or use Kibana KQLegex syntax for runtime matching.\n\n// Logical spec: host.dns matches\n//   /[0-9a-f]{8,}\\./ or /[A-Za-z0-9+]{16,}\\./",
        kibana: "source.ip: $MPNET\nAND dns.question.type: (\n  \"A\" OR \"AAAA\" OR \"TXT\"\n)\nAND dns.question.name: /\n  [0-9a-f]{8,}\\.|\n  [A-Za-z0-9]{20,}\\.\n/",
        suricata: "alert dns $HOME_NET any\n  -> any any\n  (msg:\"RECON T1598 OOB DNS\n    encoded subdomain callback\";\n  dns.query;\n  pcre:\"/^([0-9a-f]{8,}|\n    [A-Za-z0-9+\\/]{16,})\\./i\";\n  classtype:attempted-recon;\n  sid:9159805; rev:1;)",
        notes: "DOCX remote templates, OLE links, XXE, SVG/CSS imports fire DNS lookups encoding victim hostname/user/IP in the subdomain. TXT queries used for data exfil. Flag any internal host resolving a subdomain with 8+ consecutive hex chars or 16+ base64 chars.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Remote template injection with OOB DNS callbacks to confirm document opens in maritime/government targeting." },
          { cls: "apt-ru", name: "APT28", note: "DNS OOB extensively in spearphishing document delivery for victim profiling." },
          { cls: "apt-ir", name: "APT35", note: "Burp Collaborator-style callbacks in credential harvesting campaigns." },
          { cls: "apt-kp", name: "Kimsuky", note: "OOB DNS callbacks in documents targeting South Korean government and US think tanks." }
        ],
        cite: "MITRE ATT&CK T1598.002, industry reporting"
      },
      {
        sub: "T1598.002 - Spearphishing Attachment",
        indicator: "[OFF-NET TRIPWIRE] Remote template fetch - post-email open outbound connection",
        arkime: "ip.src == $MPNET\n&& protocols == http\n&& http.uri == [\"*.dotx*\", \"*.dot*\", \"*.xltx*\", \"*.potx*\", \"*.sct*\", \"*.hta*\", \"*.wsdl*\"]\n&& host.http != $ALLOWED_DEFAULTS\n&& http.hasheader.src.value == [\"*outlook*\", \"*mail*\", \"*webmail*\", \"*owa*\"]",
        kibana: "source.ip: $MPNET\nAND NOT url.domain: $ALLOWED_DEFAULTS\nAND url.path: (\n  *.dotx* OR *.dot*\n  OR *.xltx* OR *.potx*\n  OR *.sct* OR *.hta*\n  OR *.wsdl*\n)\nAND http.request.referrer: (\n  *outlook* OR *mail*\n  OR *webmail* OR *owa*\n)",
        suricata: "alert http $HOME_NET any\n  -> $EXTERNAL_NET any\n  (msg:\"RECON T1598.002 Remote\n    template fetch post-email\";\n  flow:established,to_server;\n  content:\"GET\"; http.method;\n  pcre:\"/\\.(dotx?|xltx|potx|\n    sct|hta|wsdl)(\\?|$)/i\";\n  http.uri;\n  classtype:social-engineering;\n  sid:9159806; rev:1;)",
        notes: "[AIR-GAP TRIPWIRE] This indicator detects outbound traffic from MPNET to off-MPNET infrastructure. In a properly air-gapped environment this query should never produce hits; any hit indicates a likely air-gap violation: bridged USB tether, rogue cellular modem, vendor/maintenance laptop bridging networks, supply-chain implant calling home, or misconfigured perimeter device. Treat as priority-1 escalation; do not dismiss as false positive without thorough investigation. Clean document fetches malicious template on open (T1221). Outlook/OWA referrer + .dotx from unknown external host is strong correlation. UNC path triggers (SMB to external IP) won't appear in HTTP logs - catch in Zeek conn.log. The document itself evades AV; the network fetch is the only detection opportunity.",
        apt: [
          { cls: "apt-cn", name: "APT40", note: "Remote template injection in spearphishing docs targeting maritime/defense/government sectors." },
          { cls: "apt-cn", name: "APT41", note: "Remote template injection as supply chain pre-positioning - clean doc passes email gateway scanning." },
          { cls: "apt-ru", name: "APT28", note: "Used .dotx remote templates in election-related targeting of campaign and government staff." },
          { cls: "apt-ir", name: "Charming Kitten", note: "Remote template injection targeting academic and research institutions." }
        ],
        cite: "MITRE ATT&CK T1598.002, T1221, industry reporting"
      },
      {
        sub: "T1598.001 - Spearphishing Service",
        indicator: "Inbound phishing infrastructure - newly registered MX hitting mail gateway",
        arkime: "ip.dst == $MAIL_SERVERS\n&& port.dst == [25, 587]\n&& protocols == smtp\n&& ip.src != $ALLOWED_MX\n&& ip.src != $ALLOWED_DEFAULTS",
        kibana: "destination.ip: $MAIL_SERVERS\nAND destination.port: (25 OR 587)\nAND NOT source.ip: $ALLOWED_MX\nAND NOT source.ip: $ALLOWED_DEFAULTS\nAND tls.server.not_before:\n  [now-30d TO now]",
        suricata: "alert smtp $EXTERNAL_NET any\n  -> $SMTP_SERVERS [25,587]\n  (msg:\"RECON T1598 Inbound SMTP\n    unknown/new sending IP\";\n  flow:established,to_server;\n  content:\"EHLO\"; nocase;\n  threshold:type both,\n    track by_src, count 3,\n    seconds 60;\n  classtype:social-engineering;\n  sid:9159807; rev:1;)",
        notes: "Pair with SPF/DKIM/DMARC fail tags. New sending IP + DMARC fail + auth-themed subject = near-certain spearphish. Enrich against GreyNoise, Spamhaus, AbuseIPDB. Cross-reference vendor email allowlist - legitimate vendors do sometimes send from new IPs.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "Rotates dedicated phishing infrastructure per campaign with newly registered domains and fresh IPs." },
          { cls: "apt-kp", name: "Kimsuky", note: "Newly registered domains and fresh IPs for spearphishing against policy orgs and government contractors." },
          { cls: "apt-ru", name: "APT29", note: "Dedicated purpose-built phishing infrastructure in SolarWinds pre-compromise campaign." },
          { cls: "apt-kp", name: "Moonstone Sleet", note: "Interacted with victims via email to gather information and build rapport prior to malicious activity." }
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      }
    ]
  }
];
