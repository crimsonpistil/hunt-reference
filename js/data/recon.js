const DATA = [
  {
    id: "T1589",
    name: "Gather Victim Identity Information",
    desc: ".001 Credentials · .002 Email Addresses · .003 Employee Names",
    rows: [
      {
        sub: "T1589.001 — Credentials",
        indicator: "Azure AD / O365 GetCredentialType username enumeration",
        arkime: `ip.src != $INTERNAL
&& http.method == POST
&& http.host ==
  *login.microsoftonline.com*
&& http.uri ==
  */GetCredentialType*
&& packets.src > 5`,
        kibana: `NOT source.ip: $INTERNAL
AND url.domain:
  "login.microsoftonline.com"
AND url.path: *GetCredentialType*
AND http.request.method: POST`,
        suricata: `alert http $EXTERNAL_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1589.001 AzureAD
    GetCredentialType user enum";
  flow:established,to_server;
  content:"POST"; http.method;
  content:"/common/GetCredentialType";
  http.uri;
  threshold:type both,
    track by_src,
    count 10, seconds 60;
  classtype:attempted-recon;
  sid:9158901; rev:1;)`,
        notes: "Returns UPN existence, auth method, and federation status without authentication. Tools: AADInternals, o365enum, TREVORspray. Enumerate thousands of usernames via this endpoint. Monitor via proxy/CASB egress logs — this hits Microsoft infrastructure, not your perimeter directly.",
        apt: [
          { name: "Midnight Blizzard", cls: "apt-ru", note: "Used GetCredentialType enumeration to profile Microsoft corporate O365 tenants prior to 2024 corporate email compromise." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Profiles O365 tenants of academic, NGO, and government contractor targets using AADInternals-equivalent tooling." },
          { name: "Kimsuky", cls: "apt-kp", note: "Enumerates O365 users at think tanks and policy organizations." },
          { name: "ZIRCONIUM", cls: "apt-cn", note: "Used O365 user enumeration as precursor to credential phishing campaigns targeting presidential campaign staffers." },
        ],
        cite: "MITRE ATT&CK T1589.001, Microsoft MSTIC, industry reporting"
      },
      {
        sub: "T1589.001 — Credentials",
        indicator: "O365 Autodiscover username validation",
        arkime: `ip.src != $INTERNAL
&& http.method == [GET || POST]
&& http.host == [
  *autodiscover*
  || *outlook.office365.com*
]
&& http.uri == [
  */autodiscover.xml*
  || */autodiscover.json*
  || */mapi/emsmdb*
  || */mapi/nspi*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND url.domain: (
  *autodiscover*
  OR "outlook.office365.com"
)
AND url.path: (
  *autodiscover.xml*
  OR *autodiscover.json*
  OR *mapi/emsmdb*
  OR *mapi/nspi*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1589.001
    Autodiscover user enum";
  flow:established,to_server;
  pcre:"/(autodiscover\\.xml|
    autodiscover\\.json|
    mapi\\/emsmdb|
    mapi\\/nspi)/ix";
  http.uri;
  threshold:type both,
    track by_src, count 5,
    seconds 30;
  classtype:attempted-recon;
  sid:9158902; rev:1;)`,
        notes: "Autodiscover returns different HTTP response codes (200 vs 401 vs 404) per username — classic oracle. MAPI/NSPI endpoints particularly abused for Outlook profile enumeration. Tools: MailSniper, ruler, o365recon. 200 response to autodiscover with no prior auth session is a strong signal.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Autodiscover enumeration against on-premises Exchange in MSP customer environments during Cloud Hopper." },
          { name: "APT28", cls: "apt-ru", note: "Autodiscover and MAPI/NSPI enumeration against Exchange at election campaign/government targets." },
          { name: "APT33", cls: "apt-ir", note: "Autodiscover endpoint enumeration against on-premises Exchange at energy sector targets." },
        ],
        cite: "MITRE ATT&CK T1589.001, CISA Exchange advisories, industry reporting"
      },
      {
        sub: "T1589.001 — Credentials",
        indicator: "OWA / EWS user enumeration via timed response differential",
        arkime: `ip.src != $INTERNAL
&& http.method == POST
&& http.host == [
  *owa* || *webmail*
  || *exchange*
]
&& http.uri == [
  */owa/auth.owa*
  || */EWS/Exchange.asmx*
]
&& http.statuscode == [
  401 || 403 || 200
]
&& packets.src > 10`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: POST
AND url.path: (
  *owa/auth.owa*
  OR *EWS/Exchange.asmx*
  OR */ews/*
)
AND http.response.status_code:
  (401 OR 403 OR 200)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1589.001 OWA/EWS
    auth endpoint enum";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(owa\\/auth\\.owa|
    EWS\\/Exchange\\.asmx|
    ews\\/exchange)/ix";
  http.uri;
  threshold:type both,
    track by_src, count 5,
    seconds 60;
  classtype:attempted-user;
  sid:9158903; rev:1;)`,
        notes: "OWA returns subtly different responses for valid vs invalid usernames — timing oracle. EWS abused by MailSniper and ruler for both enumeration and post-auth data collection. Monitor sustained POST volume outside business hours especially. A patient operator at 1 request/30 seconds will slip under the threshold — supplement with 24-hour cumulative Kibana query.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "OWA/EWS enumeration as standard step in MSP compromise chains using MailSniper-equivalent tooling." },
          { name: "APT33", cls: "apt-ir", note: "OWA targeted at energy sector/defense contractor organizations for credential collection." },
          { name: "APT28", cls: "apt-ru", note: "OWA enumeration against government and military Exchange deployments." },
          { name: "Kimsuky", cls: "apt-kp", note: "OWA credential enumeration against South Korean government organizations and US think tanks." },
        ],
        cite: "MITRE ATT&CK T1589.001, CISA AA21-116A, industry reporting"
      },
      {
        sub: "T1589.001 — Credentials",
        indicator: "Credential validation against breach / leak check APIs — internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *haveibeenpwned.com*
  || *dehashed.com*
  || *leakcheck.io*
  || *snusbase.com*
  || *intelx.io*
  || *breachdirectory.org*
]
&& http.method == [GET || POST]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "haveibeenpwned.com"
  OR "dehashed.com"
  OR "leakcheck.io"
  OR "snusbase.com"
  OR "intelx.io"
  OR "breachdirectory.org"
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1589.001 Internal
    host breach DB query";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    haveibeenpwned\\.com|
    dehashed\\.com|
    leakcheck\\.io|snusbase\\.com|
    intelx\\.io|
    breachdirectory\\.org)/ix";
  http.header;
  classtype:policy-violation;
  sid:9158904; rev:1;)`,
        notes: "Internal hosts querying breach databases against your own domain = red team (document it) or compromised host validating harvested creds before use. Dehashed/Snusbase/IntelX are paid API services — automated bulk queries from an endpoint = adversarial tooling signal. Correlate source host identity.",
        apt: [
          { name: "Lazarus", cls: "apt-kp", note: "Validated harvested credential lists against breach databases prior to financial sector targeting and credential stuffing." },
          { name: "APT33", cls: "apt-ir", note: "Used breach database lookups to identify previously compromised employee accounts at energy sector targets." },
          { name: "Multi", cls: "apt-mul", note: "Common in post-compromise and insider threat scenarios. Criminal access broker workflows." },
        ],
        cite: "MITRE ATT&CK T1589.001, T1586.002, industry reporting"
      },
      {
        sub: "T1589.002 — Email Addresses",
        indicator: "SMTP VRFY / EXPN enumeration against mail servers",
        arkime: `ip.src != $INTERNAL
&& port.dst == 25
&& protocols == smtp
&& databytes.src > 0
&& ip.src != $KNOWN_MX`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 25
AND NOT source.ip: $KNOWN_MX
AND network.transport: tcp`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $SMTP_SERVERS 25
  (msg:"RECON T1589.002 SMTP
    VRFY/EXPN email enum";
  flow:established,to_server;
  content:"VRFY "; nocase;
  classtype:attempted-recon;
  sid:9158905; rev:1;)`,
        notes: "VRFY confirms address existence; EXPN expands list membership. Both should be disabled on all internet-facing MTAs — misconfigurations persist on legacy Exchange/Postfix. Add a second rule for EXPN (SID+1). RCPT TO oracle still works even when VRFY/EXPN are disabled — catch-all configuration eliminates this entirely.",
        apt: [
          { name: "Charming Kitten", cls: "apt-ir", note: "SMTP VRFY/EXPN to validate email lists before spearphishing campaigns targeting academics and journalists." },
          { name: "Kimsuky", cls: "apt-kp", note: "Enumerates email addresses at South Korean government orgs and US think tanks via SMTP." },
          { name: "Multi", cls: "apt-mul", note: "Widely used by criminal actors for spam list building." },
        ],
        cite: "MITRE ATT&CK T1589.002, CISA advisories, industry reporting"
      },
      {
        sub: "T1589.002 — Email Addresses",
        indicator: "SMTP RCPT TO oracle — valid vs invalid address discrimination",
        arkime: `ip.src != $INTERNAL
&& port.dst == 25
&& protocols == smtp
&& ip.src != $KNOWN_MX
&& packets.src > 20
&& packets.dst > 20`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 25
AND NOT source.ip: $KNOWN_MX
AND network.packets > 40`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $SMTP_SERVERS 25
  (msg:"RECON T1589.002 SMTP
    RCPT TO oracle enum";
  flow:established,to_server;
  content:"RCPT TO:"; nocase;
  threshold:type both,
    track by_src, count 10,
    seconds 60;
  classtype:attempted-recon;
  sid:9158906; rev:1;)`,
        notes: "Even with VRFY/EXPN disabled — different response codes for valid/invalid RCPT TO = oracle. High packet count with many RCPT TO lines in SMTP stream is the indicator. Tools: smtp-user-enum, Metasploit smtp_enum, swaks. Catch-all configuration eliminates this entirely.",
        apt: [
          { name: "APT35", cls: "apt-ir", note: "RCPT TO enumeration to build validated email lists when VRFY/EXPN disabled — documented against academic institutions and news organizations." },
          { name: "Kimsuky", cls: "apt-kp", note: "RCPT TO oracle against Korean government and US think tank mail infrastructure." },
          { name: "Multi", cls: "apt-mul", note: "Heavily used by criminal IABs building target lists for ransomware affiliate programs." },
        ],
        cite: "MITRE ATT&CK T1589.002, industry reporting"
      },
      {
        sub: "T1589.002 — Email Addresses",
        indicator: "O365 / Google Workspace email format validation via login page",
        arkime: `ip.src != $INTERNAL
&& http.method == POST
&& http.host == [
  *login.microsoftonline.com*
  || *accounts.google.com*
]
&& http.uri == [
  */common/GetCredentialType*
  || */_/signin/sl/lookup*
  || */signin/v2/challenge*
]
&& packets.src > 10`,
        kibana: `NOT source.ip: $INTERNAL
AND url.domain: (
  "login.microsoftonline.com"
  OR "accounts.google.com"
)
AND url.path: (
  *GetCredentialType*
  OR *signin/sl/lookup*
  OR *signin/v2/challenge*
)
AND http.request.method: POST`,
        suricata: `alert http $EXTERNAL_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1589.002 Cloud IdP
    email address enumeration";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(GetCredentialType|
    signin\\/sl\\/lookup|
    signin\\/v2\\/challenge)/ix";
  http.uri;
  threshold:type both,
    track by_src,
    count 15, seconds 60;
  classtype:attempted-recon;
  sid:9158907; rev:1;)`,
        notes: "Google's /_/signin/sl/lookup returns different responses for registered vs unregistered addresses. Combined with GetCredentialType for O365, adversaries validate entire LinkedIn-harvested employee lists against both platforms in minutes. Monitor via CASB/proxy for internal hosts performing this in bulk.",
        apt: [
          { name: "Charming Kitten", cls: "apt-ir", note: "Validates LinkedIn-harvested email lists against O365 GetCredentialType and Google signin/sl/lookup before phishing campaigns." },
          { name: "Midnight Blizzard", cls: "apt-ru", note: "Cloud IdP enumeration to profile O365 tenants and validate executive accounts before credential spray." },
          { name: "Kimsuky", cls: "apt-kp", note: "Validates email lists at policy organizations and government agencies against both Microsoft and Google endpoints." },
          { name: "ZIRCONIUM", cls: "apt-cn", note: "Cloud IdP validation as precursor to credential phishing against political and government personnel." },
        ],
        cite: "MITRE ATT&CK T1589.002, Microsoft MSTIC, industry reporting"
      },
      {
        sub: "T1589.002 — Email Addresses",
        indicator: "Web scraping of staff directory / contact pages for email harvesting",
        arkime: `ip.src != $INTERNAL
&& http.method == GET
&& http.uri == [
  */staff* || */team*
  || */people* || */directory*
  || */contact* || */about*
  || */leadership* || */board*
  || */faculty* || */experts*
]
&& databytes.src > 50000
&& packets.src > 40`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *staff* OR *team*
  OR *people* OR *directory*
  OR *contact* OR *about*
  OR *leadership* OR *board*
  OR *faculty*
)
AND http.response.bytes > 50000`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1589.002 Staff
    directory scraping";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/\\/(staff|team|people|
    directory|contact|about|
    leadership|board|faculty|
    experts)/ix";
  http.uri;
  threshold:type both,
    track by_src,
    count 20, seconds 60;
  classtype:web-application-activity;
  sid:9158908; rev:1;)`,
        notes: "High-volume GETs to people/directory pages from single IP with large response bytes = automated scraping. Correlate UA — Python-requests, HeadlessChrome, PhantomJS common. Adversaries derive email format (first.last@, flast@) from scraped names then validate against cloud IdP endpoints. Directory scraping → cloud IdP validation is a documented two-step chain.",
        apt: [
          { name: "Charming Kitten", cls: "apt-ir", note: "Scrapes academic/research/think tank staff directories to identify high-value spearphishing targets." },
          { name: "Kimsuky", cls: "apt-kp", note: "Targets government agency and defense contractor staff directories for precision targeting packages." },
          { name: "APT10", cls: "apt-cn", note: "Scraped MSP staff directories to identify system administrators for targeted credential attacks during Cloud Hopper." },
          { name: "Cozy Bear", cls: "apt-ru", note: "Mapped staff directories at think tanks and NGOs prior to SolarWinds-era intrusions." },
        ],
        cite: "MITRE ATT&CK T1589.002, T1591.003, industry reporting"
      },
      {
        sub: "T1589.003 — Employee Names",
        indicator: "LinkedIn / OSINT enrichment API queries from internal hosts",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *linkedin.com*
  || *hunter.io*
  || *rocketreach.co*
  || *clearbit.com*
  || *apollo.io*
  || *zoominfo.com*
]
&& http.uri == [
  */search/results*
  || */company/*
  || */v2/people*
  || */prospector*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "linkedin.com"
  OR "hunter.io"
  OR "rocketreach.co"
  OR "clearbit.com"
  OR "apollo.io"
  OR "zoominfo.com"
)
AND url.path: (
  *search/results*
  OR */company/*
  OR *people*
  OR *prospector*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1589.003 Internal
    host bulk OSINT people lookup";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    hunter\\.io|rocketreach\\.co|
    clearbit\\.com|apollo\\.io|
    zoominfo\\.com)/ix";
  http.header;
  classtype:policy-violation;
  sid:9158909; rev:1;)`,
        notes: "Hunter.io, RocketReach, Apollo, Clearbit are identity enrichment APIs — bulk queries from internal hosts against your own domain are a red flag. Baseline expected use from sales/marketing teams. Anomalous volume from IT/security endpoints warrants investigation. LinkedIn scraping at high velocity generates 429s visible in proxy logs.",
        apt: [
          { name: "Lazarus", cls: "apt-kp", note: "Identity enrichment platforms to map org structures at financial sector targets prior to BEC operations." },
          { name: "APT33", cls: "apt-ir", note: "People-search APIs to identify OT staff and privileged account holders at energy sector targets." },
          { name: "FIN7", cls: "apt-mul", note: "Zoominfo and equivalent platforms to filter and profile targets by revenue, role, and sector." },
        ],
        cite: "MITRE ATT&CK T1589.003, T1591.004, industry reporting"
      },
      {
        sub: "T1589.003 — Employee Names",
        indicator: "LDAP / LDAPS external anonymous bind or unauthenticated enumeration",
        arkime: `ip.src != $INTERNAL
&& port.dst == [
  389 || 636 || 3268 || 3269
]
&& protocols == [ldap || ldaps]
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: (
  389 OR 636
  OR 3268 OR 3269
)
AND network.transport: tcp`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET [389,636,3268,3269]
  (msg:"RECON T1589.003 External
    LDAP/LDAPS enum attempt";
  flow:established,to_server;
  content:"|30|"; depth:1;
  classtype:attempted-recon;
  sid:9158910; rev:1;)`,
        notes: "External LDAP reach = P1 misconfiguration. Anonymous bind dumps usernames, emails, group memberships, org structure from AD without credentials. LDAPS requires TLS but doesn't prevent anonymous enumeration. Remediate firewall rules before tuning detection. Internally, non-DC hosts with large LDAP queries to DCs during off-hours = lateral movement precursor.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Exploited internet-exposed LDAP in MSP environments to enumerate AD — usernames, group memberships, privileged accounts." },
          { name: "APT28", cls: "apt-ru", note: "LDAP enumeration against government AD environments to map group structures and identify high-value accounts." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "LDAP enumeration post-initial-access to map AD structure and identify service accounts in critical infrastructure." },
          { name: "APT33", cls: "apt-ir", note: "LDAP queries to enumerate OT-adjacent accounts at energy sector targets." },
        ],
        cite: "MITRE ATT&CK T1589.003, T1087.002, CISA advisories, industry reporting"
      },
      {
        sub: "T1589.003 — Employee Names",
        indicator: "Kerberos user enumeration — AS-REQ without pre-auth (Kerbrute)",
        arkime: `ip.src != $INTERNAL
&& port.dst == 88
&& protocols == [krb5 || udp]
&& databytes.src > 0
&& packets.src > 10`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 88
AND network.transport: (
  tcp OR udp
)`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 88
  (msg:"RECON T1589.003 External
    Kerberos AS-REQ user enum";
  content:"|6a|";
  offset:0; depth:1;
  threshold:type both,
    track by_src, count 5,
    seconds 30;
  classtype:attempted-recon;
  sid:9158911; rev:1;)`,
        notes: "KDC_ERR_PREAUTH_REQUIRED (error 25) = user exists; KDC_ERR_C_PRINCIPAL_UNKNOWN (error 6) = doesn't. Noiseless from endpoint logs but very visible at port 88. Content '|6a|' = AS-REQ DER application tag. Port 88 externally reachable = P1. Internally, 20+ AS-REQ exchanges per minute from non-admin host to single DC = Kerberoasting precursor.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Kerbrute-equivalent AS-REQ enumeration against government/military AD before Kerberoasting and credential attacks." },
          { name: "APT41", cls: "apt-cn", note: "Kerberos AS-REQ enumeration internally post-initial-access to identify service accounts with SPNs for Kerberoasting." },
          { name: "Lazarus", cls: "apt-kp", note: "AS-REQ enumeration against financial sector AD to identify high-privilege accounts prior to BEC and SWIFT fraud." },
        ],
        cite: "MITRE ATT&CK T1589.003, T1558.003, industry reporting"
      },
      {
        sub: "T1589.003 — Employee Names",
        indicator: "Azure AD / Entra ID federation metadata and OpenID configuration harvesting",
        arkime: `ip.src != $INTERNAL
&& http.method == GET
&& http.host ==
  *login.microsoftonline.com*
&& http.uri == [
  */.well-known/openid-config*
  || */federationmetadata/*
  || */v2.0/.well-known*
  || */discovery/keys*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND url.domain:
  "login.microsoftonline.com"
AND url.path: (
  *openid-configuration*
  OR *federationmetadata*
  OR *discovery/keys*
  OR *v2.0/.well-known*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1589 AzureAD tenant
    federation metadata harvest";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(openid-configuration|
    federationmetadata|
    discovery\\/keys|
    v2\\.0\\/.well-known)/ix";
  http.uri;
  threshold:type both,
    track by_src, count 5,
    seconds 30;
  classtype:attempted-recon;
  sid:9158912; rev:1;)`,
        notes: "Exposes tenant ID, supported auth flows, token endpoint URLs, and signing keys — all required for targeted Azure AD attacks. The /discovery/keys endpoint exposes the token-signing certificate used for golden SAML forgery (T1606.002). Federation metadata reveals ADFS use and claims. Tenant-specific namespace is more targeted than /common/ — flag especially.",
        apt: [
          { name: "Midnight Blizzard", cls: "apt-ru", note: "Harvested federation metadata as prerequisite for 2023–2024 Microsoft corporate intrusion and Teams-based social engineering." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Profiles Entra ID tenants of academic institutions, using federation metadata to identify ADFS configs for golden SAML attacks." },
          { name: "APT41", cls: "apt-cn", note: "Enumerates federation metadata to identify ADFS misconfigurations for golden SAML token forgery (T1606.002)." },
        ],
        cite: "MITRE ATT&CK T1589.003, T1606.002, Microsoft MSTIC, industry reporting"
      },
    ]
  },
  {
    id: "T1590",
    name: "Gather Victim Network Information",
    desc: ".001 Domain Properties · .002 DNS · .003 Network Trust · .004 Topology · .005 IP Addresses · .006 Security Appliances",
    rows: [
      {
        sub: "T1590.001 — Domain Properties",
        indicator: "WHOIS / RDAP automated org and domain queries",
        arkime: `ip.src != $INTERNAL
&& port.dst == 43
&& protocols == tcp
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 43
AND network.transport: tcp`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 43
  (msg:"RECON T1590.001 Inbound
    WHOIS query port 43";
  flow:established,to_server;
  classtype:attempted-recon;
  sid:9159004; rev:1;)`,
        notes: "Port 43 TCP is WHOIS. Inbound to your authoritative server from external IPs is uncommon. RDAP (HTTP/443) is the modern replacement — watch for outbound internal hits to rdap.arin.net and rdap.ripe.net querying your own ASN.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Used WHOIS/domain registration data to map org relationships and identify MSP connections to critical infrastructure." },
          { name: "APT29", cls: "apt-ru", note: "Queried domain registration and RDAP data to map subsidiary relationships during pre-SolarWinds recon." },
          { name: "Multi", cls: "apt-mul", note: "Standard early-phase technique across CN/RU/IR actors." },
        ],
        cite: "MITRE ATT&CK T1590.001, industry reporting"
      },
      {
        sub: "T1590.002 — DNS",
        indicator: "DNS zone transfer attempt — AXFR / IXFR",
        arkime: `ip.src != $INTERNAL
&& protocols == dns
&& dns.query-type == [AXFR || IXFR]
&& port.dst == 53`,
        kibana: `NOT source.ip: $INTERNAL
AND dns.question.type: (
  "AXFR" OR "IXFR"
)
AND destination.port: 53`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $DNS_SERVERS 53
  (msg:"RECON T1590.002 DNS zone
    transfer AXFR/IXFR attempt";
  flow:established,to_server;
  content:"|00 FC|";
  offset:2; depth:2;
  classtype:attempted-recon;
  sid:9159001; rev:1;)`,
        notes: "AXFR (type 252) over TCP dumps entire zone — all hostnames, IPs, mail servers, internal naming. Must be blocked to all but authorised secondaries. Any external AXFR that reaches your resolver = misconfiguration AND active recon. IXFR (type 251) is incremental — watch both. Content '|00 FC|' is AXFR type in wire format.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Zone transfer attempts against MSP DNS infrastructure in Cloud Hopper to enumerate customer environments." },
          { name: "Sandworm", cls: "apt-ru", note: "DNS enumeration including AXFR attempts against Ukrainian government infrastructure." },
          { name: "APT33", cls: "apt-ir", note: "DNS enumeration against energy sector targets to map OT network naming." },
        ],
        cite: "MITRE ATT&CK T1590.002, CISA AA20-296A, industry reporting"
      },
      {
        sub: "T1590.002 — DNS",
        indicator: "Bulk subdomain brute-force / DNS enumeration",
        arkime: `ip.src != $INTERNAL
&& protocols == dns
&& dns.query-type == A
&& dns.host == *.yourdomain.com
&& packets.src > 50
&& node:*`,
        kibana: `NOT source.ip: $INTERNAL
AND dns.question.type: "A"
AND dns.question.name:
  *.yourdomain.com
AND NOT dns.resolved_ip: *`,
        suricata: `alert dns $EXTERNAL_NET any
  -> $DNS_SERVERS any
  (msg:"RECON T1590.002 Subdomain
    brute-force enumeration";
  dns.query;
  pcre:"/^[a-z0-9\\-]{2,30}
    \\.yourdomain\\.com$/i";
  threshold:type both,
    track by_src,
    count 20, seconds 30;
  classtype:attempted-recon;
  sid:9159002; rev:1;)`,
        notes: "Tools: dnsx, amass, subfinder, fierce. High NXDOMAIN ratio from single source IP is strongest signal — correlate query count vs NXDOMAIN response count. 70%+ NXDOMAIN rate from one source over 60 seconds = near-certain brute force. Watch slow-and-low variants staying under per-minute thresholds.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Thorough subdomain enumeration to identify dev/staging environments with weaker controls." },
          { name: "APT28", cls: "apt-ru", note: "Subdomain enumeration equivalent tooling pre-intrusion against government and military targets." },
          { name: "APT33", cls: "apt-ir", note: "Maps subsidiary and operational subdomain infrastructure to identify IT/OT boundary systems." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Subdomain enumeration against US critical infrastructure to identify exposed management interfaces." },
        ],
        cite: "MITRE ATT&CK T1590.002, industry reporting"
      },
      {
        sub: "T1590.003 — Network Trust Dependencies",
        indicator: "CDP / LLDP passive topology leakage",
        arkime: `ip.src == $INTERNAL
&& protocols == [cdp || lldp]
&& ip.dst == [
  01:00:0C:CC:CC:CC
  || 01:80:C2:00:00:0E
]`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: (
  "cdp" OR "lldp"
)
AND destination.mac: (
  "01:00:0c:cc:cc:cc"
  OR "01:80:c2:00:00:0e"
)`,
        suricata: `alert pkthdr any any -> any any
  (msg:"RECON T1590.003 CDP/LLDP
    topology leakage";
  content:"|AA AA 03 00 00 0C|";
  offset:0; depth:6;
  classtype:policy-violation;
  sid:9159008; rev:1;)`,
        notes: "CDP/LLDP broadcasts device vendor, model, IOS version, management IP, VLAN, and port ID to every adjacent host. Adversary with any segment foothold can passively capture these — zero active probes, no IDS alerts. Disable on all access-facing ports. Zeek CDP/LLDP analyzer is cleaner than Suricata for this detection. Presence implies adversary is already on segment.",
        apt: [
          { name: "Sandworm", cls: "apt-ru", note: "Passively captured CDP/LLDP to map Layer 2/3 topology of Ukrainian ICS networks before destructive operations." },
          { name: "APT41", cls: "apt-cn", note: "Passive L2 enumeration post-initial-access to plan lateral movement paths." },
          { name: "Multi", cls: "apt-mul", note: "Post-compromise indicator — requires existing foothold." },
        ],
        cite: "MITRE ATT&CK T1590.003, ICS-CERT, industry reporting"
      },
      {
        sub: "T1590.004 — Network Topology",
        indicator: "Traceroute — TTL-exceeded ICMP mapping",
        arkime: `ip.src != $INTERNAL
&& protocols == icmp
&& icmp.type == 11
&& icmp.code == 0
&& packets.src > 5`,
        kibana: `NOT source.ip: $INTERNAL
AND network.transport: icmp
AND icmp.type: 11
AND icmp.code: 0`,
        suricata: `alert icmp $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1590.004 Traceroute
    ICMP TTL-exceeded mapping";
  itype:11; icode:0;
  threshold:type both,
    track by_src, count 5,
    seconds 15;
  classtype:attempted-recon;
  sid:9159005; rev:1;)`,
        notes: "ICMP type 11 code 0 = 'TTL exceeded in transit' from your routers in response to probes with incrementing TTL. Maps hop-by-hop topology including internal routing infrastructure. Also watch UDP traceroute (ports 33434–33534) and tcptraceroute.",
        apt: [
          { name: "Sandworm", cls: "apt-ru", note: "Traceroute-based topology mapping of Ukrainian power grid/government networks prior to 2015–2016 destructive attacks." },
          { name: "APT40", cls: "apt-cn", note: "Traceroute-based mapping of maritime and government target perimeters." },
          { name: "APT33", cls: "apt-ir", note: "Network topology mapping to identify IT/OT boundary routers at energy sector targets." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Mapped routing infrastructure to understand network paths to OT systems." },
        ],
        cite: "MITRE ATT&CK T1590.004, CISA AA22-076A, industry reporting"
      },
      {
        sub: "T1590.004 — Network Topology",
        indicator: "UDP traceroute — high-port probing (33434–33534)",
        arkime: `ip.src != $INTERNAL
&& protocols == udp
&& port.dst >= 33434
&& port.dst <= 33534
&& databytes.src == 0`,
        kibana: `NOT source.ip: $INTERNAL
AND network.transport: udp
AND destination.port:
  [33434 TO 33534]
AND destination.bytes: 0`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 33434:33534
  (msg:"RECON T1590.004 UDP
    traceroute high-port probe";
  dsize:0;
  threshold:type both,
    track by_src, count 5,
    seconds 15;
  classtype:attempted-recon;
  sid:9159006; rev:1;)`,
        notes: "Classic Unix traceroute uses UDP 33434+ with incrementing TTL. Zero-byte payload distinguishes traceroute probes from legitimate UDP services. Windows traceroute uses ICMP echo by default — cover both. tcptraceroute (TCP SYN to 80/443) requires TTL pattern analysis.",
        apt: [
          { name: "Sandworm", cls: "apt-ru", note: "UDP traceroute in ICS network reconnaissance phases." },
          { name: "APT41", cls: "apt-cn", note: "Automated network mapping suites combining UDP and ICMP traceroute." },
          { name: "Multi", cls: "apt-mul", note: "Used broadly across CN/RU/IR actor toolkits as part of automated network enumeration." },
        ],
        cite: "MITRE ATT&CK T1590.004, industry reporting"
      },
      {
        sub: "T1590.004 — Network Topology",
        indicator: "SNMP community string enumeration — v1/v2c",
        arkime: `ip.src != $INTERNAL
&& port.dst == 161
&& protocols == udp
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 161
AND network.transport: udp`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 161
  (msg:"RECON T1590.004 External
    SNMP v1/v2c enumeration";
  content:"|30|"; offset:0;
  depth:1;
  classtype:attempted-recon;
  sid:9159007; rev:1;)`,
        notes: "Community strings (public, private, community, cisco, snmp) tried in bulk by onesixtyone and snmpwalk. Successful read exposes interface tables, ARP cache, routing table, CDP neighbors — complete internal topology map. Content '|30|' matches BER sequence tag opening every SNMP PDU. External UDP/161 reaching devices = misconfiguration finding.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "SNMP enumeration against MSP network devices — used harvested interface/ARP tables to map customer topology." },
          { name: "Dragonfly", cls: "apt-ru", note: "Systematic SNMP community string sweeps against energy sector IT/OT boundary devices prior to ICS targeting." },
          { name: "APT33", cls: "apt-ir", note: "SNMP enumeration against oil/gas sector network devices to identify OT segments." },
        ],
        cite: "MITRE ATT&CK T1590.004, CISA AA21-008A, ICS-CERT advisories"
      },
      {
        sub: "T1590.005 — IP Addresses",
        indicator: "Reverse DNS / PTR walking of your IP ranges",
        arkime: `ip.src != $INTERNAL
&& protocols == dns
&& dns.query-type == PTR
&& dns.host == *.in-addr.arpa
&& packets.src > 30`,
        kibana: `NOT source.ip: $INTERNAL
AND dns.question.type: "PTR"
AND dns.question.name:
  *.in-addr.arpa`,
        suricata: `alert dns $EXTERNAL_NET any
  -> $DNS_SERVERS any
  (msg:"RECON T1590.005 PTR sweep
    reverse DNS enumeration";
  dns.query;
  content:".in-addr.arpa";
  threshold:type both,
    track by_src,
    count 15, seconds 20;
  classtype:attempted-recon;
  sid:9159003; rev:1;)`,
        notes: "Sequential PTR queries map hostnames to IPs without touching hosts directly. Confirm sequential last-octet increments in Arkime to distinguish from legitimate resolver behavior. Walking a /24 in under 60 seconds with incrementing octets = near-certain automated enumeration.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Reverse DNS walking to map MSP customer IP allocations during Cloud Hopper." },
          { name: "Sandworm", cls: "apt-ru", note: "PTR enumeration against Ukrainian government and energy IP ranges to build target maps." },
          { name: "Multi", cls: "apt-mul", note: "Documented across multiple CISA and NSA advisories as a standard pre-exploitation technique." },
        ],
        cite: "MITRE ATT&CK T1590.005, CISA AA22-076A, industry reporting"
      },
      {
        sub: "T1590.005 — IP Addresses",
        indicator: "ASN / BGP enumeration via external looking glass — from internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *bgp.he.net*
  || *stat.ripe.net*
  || *bgpview.io*
  || *ipinfo.io*
  || *ipwhois.io*
  || *team-cymru.com*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "bgp.he.net"
  OR "stat.ripe.net"
  OR "bgpview.io"
  OR "ipinfo.io"
  OR "ipwhois.io"
  OR "team-cymru.com"
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1590.005 Internal
    host querying BGP/ASN service";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    bgp\\.he\\.net|
    stat\\.ripe\\.net|
    bgpview\\.io|ipinfo\\.io|
    ipwhois\\.io|
    team-cymru\\.com)/i";
  http.header;
  classtype:policy-violation;
  sid:9159009; rev:1;)`,
        notes: "Internal endpoints hitting BGP looking glasses = red team or adversary-in-network pre-lateral-movement recon. Legitimate NOC uses internal tooling. Enrich source host identity and cross-reference recent authentication events. Requires existing foothold.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Queried BGP/ASN data from compromised MSP hosts to map customer IP allocations during Cloud Hopper." },
          { name: "APT29", cls: "apt-ru", note: "Internal IP range mapping via external ASN lookup during dwell-time recon phases prior to SolarWinds lateral movement." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "IP and ASN enumeration to understand routing relationships between target orgs and ISPs." },
        ],
        cite: "MITRE ATT&CK T1590.005, industry reporting"
      },
      {
        sub: "T1590.005 — IP Addresses",
        indicator: "Shodan / Censys / BinaryEdge crawler IPs probing perimeter",
        arkime: `ip.src == [
  66.240.192.0/19
  || 198.20.69.0/24
  || 162.142.125.0/24
  || 71.6.135.0/24
  || 45.33.32.0/24
  || 93.120.27.62
]
&& port.dst != [80 || 443]`,
        kibana: `source.ip: (
  "66.240.0.0/14"
  OR "162.142.125.0/24"
  OR "71.6.135.0/24"
  OR "198.20.69.0/24"
  OR "45.33.32.0/24"
)`,
        suricata: `alert ip [
  66.240.192.0/19,
  198.20.69.0/24,
  162.142.125.0/24,
  71.6.135.0/24,
  45.33.32.0/24
] any -> $HOME_NET any
  (msg:"RECON T1590.005
    Shodan/Censys scanner IP";
  classtype:attempted-recon;
  sid:9159010; rev:1;)`,
        notes: "Shodan (66.240.x, 198.20.69.x), Censys (162.142.125.x), BinaryEdge (45.33.x). If these IPs reach anything beyond your public web tier, you have an exposure. Use GreyNoise API for dynamic enrichment — static CIDRs go stale. Your Shodan indexed exposure IS the adversary's target list.",
        apt: [
          { name: "APT40", cls: "apt-cn", note: "Reviews Shodan/Censys data to identify exposed services on maritime/defense/government targets prior to exploitation." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Queried Shodan for exposed management interfaces (RDP, VNC, OT protocols) on US critical infrastructure." },
          { name: "APT33", cls: "apt-ir", note: "Used Shodan to identify exposed ICS interfaces and VPN endpoints in energy sector targets." },
        ],
        cite: "MITRE ATT&CK T1590.005, T1596.005, CISA advisories, industry reporting"
      },
      {
        sub: "T1590.006 — Network Security Appliances",
        indicator: "VPN gateway IKE vendor-ID fingerprinting",
        arkime: `ip.src != $INTERNAL
&& port.dst == [500 || 4500]
&& protocols == udp
&& databytes.src > 28
&& databytes.src < 500`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: (500 OR 4500)
AND network.transport: udp
AND destination.bytes: [28 TO 500]`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET [500,4500]
  (msg:"RECON T1590.006 IKE VPN
    gateway fingerprint probe";
  dsize:28<>500;
  threshold:type both,
    track by_src, count 3,
    seconds 30;
  classtype:attempted-recon;
  sid:9159011; rev:1;)`,
        notes: "IKEv1 vendor-IDs uniquely identify VPN vendor and version (Cisco ASA, Palo Alto, Fortinet, Check Point, SonicWall). ike-scan enumerates in seconds. Version disclosure enables CVE selection — CVE-2024-21762 FortiOS, CVE-2023-46805 Ivanti both preceded by systematic IKE fingerprinting. IKEv2 less verbose but still fingerprintable via transform sets.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Systematic IKE VPN fingerprinting of US critical infrastructure prior to LOTL footholds per CISA AA23-144A." },
          { name: "APT33", cls: "apt-ir", note: "Fingerprinted Pulse Secure/Fortinet VPN gateways before CVE-2019-11510 and CVE-2018-13379 exploitation." },
          { name: "APT28", cls: "apt-ru", note: "Targeted Cisco ASA VPN gateways via IKE enumeration prior to CVE-2018-0101 exploitation." },
          { name: "Charming Kitten", cls: "apt-ir", note: "IKE fingerprinting to identify Fortinet and Citrix appliances in academic/government target networks." },
        ],
        cite: "MITRE ATT&CK T1590.006, CISA AA23-144A, CISA AA20-073A, industry reporting"
      },
      {
        sub: "T1590.006 — Network Security Appliances",
        indicator: "SSL-VPN portal path fingerprinting — vendor-deterministic URI probing",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  */dana-na/auth/*
  || */remote/logincheck*
  || */+CSCOE+/logon.html*
  || */global-protect/*
  || */sslvpn/Login/*
  || */my.policy*
  || */php/login.php*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  */dana-na/auth/*
  OR */remote/logincheck*
  OR */+CSCOE+/*
  OR */global-protect/*
  OR */sslvpn/Login/*
  OR */my.policy*
  OR */php/login.php*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1590.006 SSL-VPN
    portal path fingerprinting";
  flow:established,to_server;
  pcre:"/\\/(dana-na\\/auth|
    remote\\/logincheck|
    \\+CSCOE\\+\\/logon|
    global-protect|
    sslvpn\\/Login|
    my\\.policy|
    php\\/login)/ix";
  http.uri;
  classtype:attempted-recon;
  sid:9159012; rev:1;)`,
        notes: "/dana-na/auth/ = Ivanti/Pulse Secure, /remote/logincheck = Fortinet, /+CSCOE+/ = Cisco AnyConnect, /global-protect/ = Palo Alto GlobalProtect, /sslvpn/Login/ = SonicWall, /my.policy = F5 BIG-IP APM. Single GET uniquely identifies vendor. APT33 path probing preceded Pulse/Fortinet exploitation by 4–6 weeks in documented intrusions. 200 response = trigger patch verification immediately.",
        apt: [
          { name: "APT33", cls: "apt-ir", note: "Probed /dana-na/auth/ and /remote/logincheck paths at scale before mass exploitation of CVE-2019-11510 and CVE-2018-13379 — 4–6 weeks preceding exploitation." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Probed /global-protect/ and Cisco AnyConnect paths against US critical infrastructure per CISA AA23-144A." },
          { name: "APT29", cls: "apt-ru", note: "Probed Fortinet SSL-VPN paths prior to CVE-2022-42475 exploitation in government/defense targeting." },
          { name: "Lazarus", cls: "apt-kp", note: "SSL-VPN portal path probing against financial sector targets to identify exploitable remote access infrastructure." },
        ],
        cite: "MITRE ATT&CK T1590.006, CISA AA23-144A, CISA AA21-062A, industry reporting"
      },
      {
        sub: "T1590.006 — Network Security Appliances",
        indicator: "Security appliance vendor banner in HTTP response headers",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.statuscode == [403 || 400 || 407]
&& http.response-header == [
  *Fortinet* || *PAN-OS*
  || *Cisco* || *Check Point*
  || *F5* || *Juniper*
  || *SonicWall*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.response.status_code:
  (400 OR 403 OR 407)
AND http.response.headers.server: (
  *Fortinet* OR *PAN-OS*
  OR *Cisco* OR *F5*
  OR *Barracuda* OR *Juniper*
  OR *SonicWall*
)`,
        suricata: `alert http $HTTP_SERVERS any
  -> $EXTERNAL_NET any
  (msg:"RECON T1590.006 Appliance
    banner in egress response";
  flow:established,from_server;
  pcre:"/Server\\s*:\\s*[^\\r\\n]*(
    Fortinet|PAN-OS|Cisco|
    Check.?Point|Barracuda|
    F5|Juniper|SonicWall)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159013; rev:1;)`,
        notes: "This rule fires on egress — your own appliance advertising its identity. Remediate: suppress or genericize Server headers, customize block pages to remove product branding. Check Point, Fortinet, F5 all have suppression settings. Banner disclosure is passive intel — adversaries receive it without triggering any alert unless you instrument egress responses.",
        apt: [
          { name: "APT33", cls: "apt-ir", note: "Correlates HTTP Server header disclosures with Shodan data and SSL-VPN path probing to build confirmed target profiles." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Documented using banner disclosure correlated with internet scan data for target profiling." },
          { name: "Multi/IAB", cls: "apt-mul", note: "Initial access brokers harvest appliance banners to build commercial target lists sold to ransomware and nation-state operators." },
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
        sub: "T1591.001 — Physical Locations",
        indicator: "HR scraper bots hitting career / about / team pages",
        arkime: `ip.src != $INTERNAL
&& http.uri == [
  *careers* || *recruit*
  || *apply* || *about*
  || *team* || *join*
]
&& databytes.src > 50000
&& packets.src > 30`,
        kibana: `NOT source.ip: $INTERNAL
AND url.path: (
  *careers* OR *about*
  OR *team* OR *recruit*
  OR *apply* OR *join*
)
AND http.response.bytes > 50000`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1591 Org scrape
    HR page high volume";
  flow:established,to_server;
  content:"GET"; http.method;
  content:"/careers"; http.uri;
  threshold:type threshold,
    track by_src,
    count 20, seconds 60;
  classtype:web-application-activity;
  sid:9159101; rev:1;)`,
        notes: "High-volume GETs to /careers, /about, /team from single external IP in short window. Correlate UA — Python-requests, curl, headless browser UAs (HeadlessChrome, PhantomJS) common. Adversaries derive org chart, tech stack, and high-value target roles from job descriptions.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Used LLMs to gather information about satellite capabilities and org structure." },
          { name: "Lazarus", cls: "apt-kp", note: "Studied publicly available org info to tailor spearphishing against specific departments and individuals." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Conducted extensive pre-compromise recon to gather information about targeted organizations." },
          { name: "FIN7", cls: "apt-mul", note: "Compiled victim lists by filtering companies by revenue using Zoominfo." },
        ],
        cite: "MITRE ATT&CK T1591, industry reporting"
      },
      {
        sub: "T1591.001 — Physical Locations",
        indicator: "Bulk subsidiary / affiliate DNS enumeration",
        arkime: `ip.src != $INTERNAL
&& protocols == dns
&& dns.query-type == A
&& dns.host == *.corp.*
&& packets.src > 50`,
        kibana: `NOT source.ip: $INTERNAL
AND dns.question.type: "A"
AND dns.question.name: (
  *corp* OR *internal*
  OR *dev* OR *staging*
  OR *subsidiary*
)`,
        suricata: `alert dns $EXTERNAL_NET any
  -> $DNS_SERVERS any
  (msg:"RECON T1591 Subsidiary
    DNS bulk enum";
  dns.query;
  content:".corp.";
  threshold:type both,
    track by_src,
    count 15, seconds 30;
  classtype:attempted-recon;
  sid:9159102; rev:1;)`,
        notes: "External IPs resolving many internal subdomain patterns suggests org structure mapping. Pair with passive DNS to identify which names actually resolved vs NXDOMAIN flood. Watch NXDOMAIN ratio across all sources combined for slow-and-low variants.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Maps subsidiary and affiliate infrastructure to identify weakest-link entry points prior to supply chain operations." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Enumerated subsidiary DNS as part of pre-compromise mapping of US critical infrastructure." },
          { name: "Sandworm", cls: "apt-ru", note: "Targeted partner/subsidiary DNS to identify pivot paths into Ukrainian government and ICS networks." },
        ],
        cite: "MITRE ATT&CK T1591, industry reporting"
      },
      {
        sub: "T1591.001 — Physical Locations",
        indicator: "WHOIS / RDAP automated org and domain queries",
        arkime: `ip.src != $INTERNAL
&& port.dst == 43
&& protocols == tcp
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 43
AND network.transport: tcp`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 43
  (msg:"RECON T1591 Inbound
    WHOIS query port 43";
  flow:established,to_server;
  classtype:attempted-recon;
  sid:9159103; rev:1;)`,
        notes: "Port 43 TCP is WHOIS. Inbound to your authoritative server from external IPs is uncommon outside of automation or targeted recon tooling mapping registered domains and ASN contacts. RDAP (HTTP/443) is the modern replacement — watch for outbound internal hits to rdap.arin.net and rdap.ripe.net querying your own ASN.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Used WHOIS and domain registration data to map organizational relationships and identify MSP connections." },
          { name: "APT29", cls: "apt-ru", note: "Queried domain registration and RDAP data to map subsidiary relationships prior to SolarWinds." },
          { name: "Multi", cls: "apt-mul", note: "Standard early-phase technique across CN/RU/IR actors — typically automated tooling." },
        ],
        cite: "MITRE ATT&CK T1591, industry reporting"
      },
      {
        sub: "T1591.002 — Business Relationships",
        indicator: "Business relationship / third-party vendor enumeration via OSINT",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *zoominfo.com*
  || *dnb.com*
  || *opencorporates.com*
  || *crunchbase.com*
  || *pitchbook.com*
  || *sec.gov*
]
&& http.uri == [
  */company/* || */search*
  || */v2/organizations*
  || */filings*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "zoominfo.com"
  OR "dnb.com"
  OR "opencorporates.com"
  OR "crunchbase.com"
  OR "pitchbook.com"
  OR "sec.gov"
)
AND url.path: (
  */company/* OR *search*
  OR *organizations*
  OR *filings*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1591 Internal host
    business relationship OSINT";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    zoominfo\\.com|dnb\\.com|
    opencorporates\\.com|
    crunchbase\\.com|
    pitchbook\\.com)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159104; rev:1;)`,
        notes: "Internal hosts querying business intelligence platforms against your own org or vendors may indicate a compromised host mapping third-party relationships for supply chain targeting. Baseline expected use from BD/sales teams — anomalous volume from IT or security hosts is the flag.",
        apt: [
          { name: "FIN7", cls: "apt-mul", note: "Compiled victim lists by filtering companies by revenue using Zoominfo." },
          { name: "APT41", cls: "apt-cn", note: "Researches business relationships to identify supply chain access paths." },
          { name: "Cozy Bear", cls: "apt-ru", note: "Mapped partner and contractor relationships prior to SolarWinds supply chain compromise." },
        ],
        cite: "MITRE ATT&CK T1591.002, industry reporting"
      },
    ]
  },
  {
    id: "T1592",
    name: "Gather Victim Host Information",
    desc: ".001 Hardware · .002 Software · .003 Firmware · .004 Client Configurations",
    rows: [
      {
        sub: "T1592.001 — Hardware",
        indicator: "NetBIOS Name Service (NBNS) enumeration — external host querying your broadcast domain",
        arkime: `ip.src != $INTERNAL
&& port.dst == 137
&& protocols == udp
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 137
AND network.transport: udp`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 137
  (msg:"RECON T1592.001 External
    NBNS name query";
  content:"|00 00|";
  offset:2; depth:2;
  classtype:attempted-recon;
  sid:9159201; rev:1;)`,
        notes: "NBNS (UDP/137) resolves NetBIOS names to IPs and returns the NetBIOS name, workgroup/domain name, and MAC address. External NBNS should never reach internal hosts. Internally, watch for non-Windows hosts generating NBNS queries in bulk — Responder generates distinctive query patterns visible in Zeek nbns.log.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Used NetBIOS enumeration for MSP network host discovery during Cloud Hopper, mapping workstation and server names without touching AD." },
          { name: "APT28", cls: "apt-ru", note: "Used NBNS and SMB enumeration to identify host hardware configurations and domain membership in government network targeting." },
          { name: "Multi", cls: "apt-mul", note: "Documented in multiple CISA advisories as a standard network discovery technique used post-initial-access." },
        ],
        cite: "MITRE ATT&CK T1592.001, CISA advisories, industry reporting"
      },
      {
        sub: "T1592.001 — Hardware",
        indicator: "NBNS broadcast sweep — internal host performing name resolution sweep",
        arkime: `ip.src == $INTERNAL
&& port.dst == 137
&& protocols == udp
&& ip.dst == 255.255.255.255
&& packets.src > 20`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 137
AND network.transport: udp
AND destination.ip: "255.255.255.255"`,
        suricata: `alert udp $HOME_NET any
  -> 255.255.255.255 137
  (msg:"RECON T1592.001 Internal
    NBNS broadcast sweep";
  content:"|20|";
  offset:12; depth:1;
  threshold:type both,
    track by_src,
    count 20, seconds 30;
  classtype:attempted-recon;
  sid:9159202; rev:1;)`,
        notes: "An internal host broadcasting NBNS queries to 255.255.255.255 at high volume = scanner (nmap -sU, nbtscan, enum4linux) or host discovery tool. Content '|20|' at offset 12 matches NetBIOS encoded name wildcard. 20+ in 30 seconds from a single non-DC host is anomalous. Post-foothold indicator — combine with source host identity and off-hours timing.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Uses NBNS broadcast sweeps post-initial-access to enumerate workstation/server names without touching AD LDAP." },
          { name: "APT41", cls: "apt-cn", note: "Performs internal NBNS enumeration using nbtscan-equivalent tooling to build host inventory maps before lateral movement." },
          { name: "Multi", cls: "apt-mul", note: "Documented post-compromise discovery technique in multiple CISA and FBI ransomware/nation-state advisories." },
        ],
        cite: "MITRE ATT&CK T1592.001, T1016, CISA advisories"
      },
      {
        sub: "T1592.001 — Hardware",
        indicator: "UPnP SSDP M-SEARCH — device hardware discovery via multicast probe",
        arkime: `ip.src != $INTERNAL
&& port.dst == 1900
&& protocols == udp
&& http.method == M-SEARCH
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 1900
AND network.transport: udp`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 1900
  (msg:"RECON T1592.001 UPnP SSDP
    M-SEARCH device discovery";
  content:"M-SEARCH"; depth:8;
  content:"ssdp:discover";
  classtype:attempted-recon;
  sid:9159203; rev:1;)`,
        notes: "SSDP M-SEARCH to UDP/1900 discovers UPnP devices — printers, NAS, routers, IoT — and returns device type, model, manufacturer, and firmware version. External SSDP reaching internal devices = perimeter misconfiguration. Internally, SSDP M-SEARCH from non-IoT hosts is anomalous. Tools: Miranda, UPnP-Inspector, Metasploit UPnP scanner.",
        apt: [
          { name: "Sandworm", cls: "apt-ru", note: "Used UPnP enumeration to identify network-connected hardware in Ukrainian industrial environments." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Enumerated UPnP-capable devices in SOHO environments to identify hardware with exploitable UPnP implementations." },
          { name: "Multi", cls: "apt-mul", note: "Documented in CISA ICS advisories as a technique used to map hardware in OT-adjacent network segments." },
        ],
        cite: "MITRE ATT&CK T1592.001, CISA ICS advisories, industry reporting"
      },
      {
        sub: "T1592.001 — Hardware",
        indicator: "UPnP description XML fetch — hardware detail harvest post-SSDP discovery",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  */rootDesc.xml*
  || */upnp/desc*
  || */device.xml*
  || */DeviceDescription*
  || */igd.xml*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *rootDesc.xml*
  OR *upnp/desc*
  OR *device.xml*
  OR *DeviceDescription*
  OR *igd.xml*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1592.001 UPnP
    device description XML fetch";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(rootDesc\\.xml|
    upnp\\/desc|device\\.xml|
    DeviceDescription|
    igd\\.xml)/ix";
  http.uri;
  classtype:attempted-recon;
  sid:9159204; rev:1;)`,
        notes: "After SSDP discovery, adversaries fetch the UPnP device description XML containing the full hardware profile: manufacturer, model number, serial number, firmware version, and UPnP services. Two-step chain: SSDP discovers what's present, description XML retrieves details. A 200 response to rootDesc.xml from an external IP is both a misconfiguration and an active hardware disclosure event.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Fetched UPnP device description XML from SOHO routers to confirm device models for targeted firmware exploitation per CISA AA23-144A." },
          { name: "Sandworm", cls: "apt-ru", note: "Retrieved UPnP device descriptions from network-connected hardware in target environments." },
          { name: "Multi", cls: "apt-mul", note: "Well-documented technique in penetration testing and nation-state toolkits for hardware inventory collection." },
        ],
        cite: "MITRE ATT&CK T1592.001, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1592.001 — Hardware",
        indicator: "WMI remote queries — external or lateral WMI hardware enumeration (DCOM/RPC)",
        arkime: `ip.src != $INTERNAL
&& port.dst == [135 || 445]
&& protocols == [dce-rpc || smb]
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: (135 OR 445)
AND network.transport: tcp
AND source.bytes > 0
AND destination.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET [135,445]
  (msg:"RECON T1592.001 External
    WMI/DCOM hardware enum";
  flow:established,to_server;
  content:"|05 00|"; depth:2;
  threshold:type both,
    track by_src,
    count 3, seconds 30;
  classtype:attempted-recon;
  sid:9159205; rev:1;)`,
        notes: "WMI over DCOM (TCP/135 + dynamic high ports) allows remote hardware enumeration — Win32_ComputerSystem returns manufacturer/model/memory. External TCP/135 or TCP/445 should never reach internal hosts. Content '|05 00|' matches DCE/RPC bind header. Zeek dce_rpc.log captures operation names — look for IWbemServices::ExecQuery calls.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Uses remote WMI queries extensively post-initial-access to enumerate hardware configuration across target environments." },
          { name: "APT28", cls: "apt-ru", note: "Uses WMI remote enumeration against government/military targets, using hardware inventory to select architecture-appropriate payloads." },
          { name: "Lazarus", cls: "apt-kp", note: "Uses WMI remote queries in financial sector intrusions to profile workstation hardware before deploying tooling." },
        ],
        cite: "MITRE ATT&CK T1592.001, T1047, CISA advisories, industry reporting"
      },
      {
        sub: "T1592.001 — Hardware",
        indicator: "MAC address OUI harvesting via ARP sweep — hardware vendor identification",
        arkime: `ip.src == $INTERNAL
&& protocols == arp
&& packets.src > 30
&& node:*`,
        kibana: `source.ip: $INTERNAL
AND network.type: "ipv4"
AND network.transport: "arp"`,
        suricata: `alert arp $HOME_NET any
  -> any any
  (msg:"RECON T1592.001 ARP sweep
    MAC/OUI hardware enumeration";
  content:"|00 01|"; offset:6;
  depth:2;
  threshold:type both,
    track by_src,
    count 30, seconds 30;
  classtype:attempted-recon;
  sid:9159206; rev:1;)`,
        notes: "ARP responses include the MAC address of each responding host. The first three octets (OUI) identify the hardware vendor — Cisco, Dell, Fortinet, Raspberry Pi, VMware. An internal host generating 30+ ARP requests in 30 seconds is performing a sweep. Requires existing foothold (ARP is layer 2). Zeek arp.log captures all ARP activity including OUIs.",
        apt: [
          { name: "Sandworm", cls: "apt-ru", note: "Performed ARP-based hardware enumeration in Ukrainian network environments to identify Cisco, GE, and Siemens hardware on OT-adjacent segments." },
          { name: "APT41", cls: "apt-cn", note: "Uses ARP sweeps post-initial-access to identify hardware vendors and select appropriate exploitation paths." },
          { name: "Multi", cls: "apt-mul", note: "Post-compromise indicator — requires existing segment access." },
        ],
        cite: "MITRE ATT&CK T1592.001, T1018, industry reporting"
      },
      {
        sub: "T1592.002 — Software",
        indicator: "mDNS / Bonjour service browse — software and service inventory via multicast DNS",
        arkime: `ip.src != $INTERNAL
&& port.dst == 5353
&& protocols == udp
&& ip.dst == 224.0.0.251
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 5353
AND network.transport: udp
AND destination.ip: "224.0.0.251"`,
        suricata: `alert udp $EXTERNAL_NET any
  -> 224.0.0.251 5353
  (msg:"RECON T1592.002 mDNS
    Bonjour service enumeration";
  content:"|00 0c|"; offset:2;
  depth:2;
  classtype:attempted-recon;
  sid:9159207; rev:1;)`,
        notes: "mDNS (UDP/5353 to multicast 224.0.0.251) allows zero-config service discovery — any host can query for _http._tcp, _smb._tcp, _ssh._tcp, _printer._tcp and receive responses advertising software names, versions, and hostnames. External mDNS reaching internal segments = perimeter misconfiguration. Content '|00 0c|' matches PTR record type used for service browsing.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Used mDNS enumeration in SOHO environments to identify software services on network-connected devices." },
          { name: "Sandworm", cls: "apt-ru", note: "Used mDNS service browsing to enumerate software on network-connected devices in Ukrainian target environments." },
          { name: "Multi", cls: "apt-mul", note: "Included in Metasploit auxiliary scanner suite and multiple post-exploitation frameworks." },
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 — Software",
        indicator: "HTTP Server header software version disclosure in egress responses",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.statuscode == [
  200 || 301 || 302
  || 400 || 403 || 404
]
&& http.response-header == [
  *Apache/* || *nginx/*
  || *Microsoft-IIS/*
  || *PHP/* || *Tomcat/*
  || *Jetty/* || *Werkzeug/*
  || *OpenSSL/*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.response.status_code: (
  200 OR 301 OR 302
  OR 400 OR 403 OR 404
)
AND http.response.headers.server: (
  *Apache* OR *nginx*
  OR *Microsoft-IIS*
  OR *PHP* OR *Tomcat*
  OR *Jetty* OR *Werkzeug*
  OR *OpenSSL*
)`,
        suricata: `alert http $HTTP_SERVERS any
  -> $EXTERNAL_NET any
  (msg:"RECON T1592.002 HTTP Server
    header software version
    disclosure";
  flow:established,from_server;
  pcre:"/Server\\s*:\\s*[^\\r\\n]*(
    Apache\\/|nginx\\/|
    Microsoft-IIS\\/|PHP\\/|
    Tomcat\\/|Jetty\\/|
    Werkzeug\\/|OpenSSL\\/)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159209; rev:1;)`,
        notes: "HTTP Server headers advertising specific versions (Apache/2.4.49, nginx/1.18.0, PHP/7.4.3) give adversaries a precise CVE selection guide. This rule fires on egress — your own servers advertising their stack. Remediate: Apache: ServerTokens Prod; nginx: server_tokens off. Also watch X-Powered-By, X-Generator, X-AspNet-Version headers.",
        apt: [
          { name: "APT40", cls: "apt-cn", note: "Harvests HTTP Server header version strings from maritime/defense/government web infrastructure for CVE-targeted exploitation." },
          { name: "APT33", cls: "apt-ir", note: "Systematically collects HTTP Server header disclosures from energy sector web infrastructure to select exploitation paths." },
          { name: "Multi", cls: "apt-mul", note: "Passive intel — adversaries collect from normal web traffic without generating probe traffic." },
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 — Software",
        indicator: "X-Powered-By / X-Generator header — CMS and framework version disclosure",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.response-header == [
  *X-Powered-By*
  || *X-Generator*
  || *X-AspNet-Version*
  || *X-AspNetMvc-Version*
  || *X-Drupal-Cache*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.response.headers: (
  *X-Powered-By*
  OR *X-Generator*
  OR *X-AspNet-Version*
  OR *X-AspNetMvc-Version*
  OR *X-Drupal-Cache*
)`,
        suricata: `alert http $HTTP_SERVERS any
  -> $EXTERNAL_NET any
  (msg:"RECON T1592.002 CMS/framework
    version header disclosure";
  flow:established,from_server;
  pcre:"/X-(Powered-By|Generator|
    AspNet-Version|
    AspNetMvc-Version|
    Drupal-Cache)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159210; rev:1;)`,
        notes: "X-Powered-By exposes PHP/ASP.NET/Express version; X-Generator exposes WordPress/Drupal/Joomla version; X-AspNet-Version exposes .NET runtime. Default in most frameworks — requires explicit suppression. Combined with Server headers, gives adversaries a complete software stack fingerprint in a single HTTP response.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Collects framework/CMS version headers to identify WordPress plugin versions, PHP runtime, and .NET versions for CVE exploitation." },
          { name: "APT33", cls: "apt-ir", note: "Harvests X-Powered-By and X-AspNet-Version from energy sector and defense contractor web applications." },
          { name: "FIN7", cls: "apt-mul", note: "Uses CMS version disclosure from X-Generator headers to identify vulnerable WordPress/Drupal installations in POS/hospitality targeting." },
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 — Software",
        indicator: "SMB protocol negotiation — OS and software version fingerprinting",
        arkime: `ip.src != $INTERNAL
&& port.dst == 445
&& protocols == smb
&& databytes.src > 0
&& databytes.dst > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 445
AND network.transport: tcp
AND source.bytes > 0
AND destination.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 445
  (msg:"RECON T1592.002 SMB
    negotiate software fingerprint";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  classtype:attempted-recon;
  sid:9159211; rev:1;)`,
        notes: "SMB protocol negotiation reveals OS version, SMB dialect (SMB1/2/3), and build number — enough to identify Windows version down to patch level without authentication. Content '|ff 53 4d 42|' = SMB1 header magic; SMB2 uses '|fe 53 4d 42|'. External TCP/445 should never reach internal hosts. Zeek smb.log captures dialect negotiation details.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Uses SMB negotiation fingerprinting to identify Windows versions and SMB dialect support, selecting CVEs like EternalBlue and PrintNightmare." },
          { name: "APT10", cls: "apt-cn", note: "Used SMB negotiation fingerprinting against MSP environments to identify Windows versions across customer workstation fleets." },
          { name: "Lazarus", cls: "apt-kp", note: "Used SMB software fingerprinting to identify systems running vulnerable SMB before lateral movement via EternalBlue." },
        ],
        cite: "MITRE ATT&CK T1592.002, industry reporting"
      },
      {
        sub: "T1592.002 — Software",
        indicator: "RDP protocol negotiation — software version and NLA configuration fingerprinting",
        arkime: `ip.src != $INTERNAL
&& port.dst == 3389
&& protocols == rdp
&& databytes.src > 0
&& databytes.dst > 0
&& packets.src < 5`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 3389
AND network.transport: tcp
AND source.bytes > 0
AND destination.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET 3389
  (msg:"RECON T1592.002 RDP
    software/NLA config fingerprint";
  flow:established,to_server;
  content:"|03 00|"; depth:2;
  classtype:attempted-recon;
  sid:9159212; rev:1;)`,
        notes: "RDP connection negotiation reveals whether NLA is enforced, RDP protocol version, and supported encryption levels — before any authentication. Connect-and-disconnect with low packet count (<5) from external IP is the classic RDP fingerprint pattern. Content '|03 00|' matches TPKT header. Tools: rdp-sec-check, nmap RDP scripts. NLA disabled = pre-auth attack surface (BlueKeep CVE-2019-0708).",
        apt: [
          { name: "Lazarus", cls: "apt-kp", note: "Fingerprints RDP NLA configuration and version on financial sector targets to identify systems vulnerable to credential spray or CVE exploitation." },
          { name: "APT28", cls: "apt-ru", note: "Uses RDP protocol negotiation fingerprinting against government targets to identify Windows versions before RDP-based lateral movement." },
          { name: "Multi", cls: "apt-mul", note: "Documented in multiple CISA ransomware advisories as pre-exploitation recon used by IABs to build lists of exposed vulnerable RDP endpoints." },
        ],
        cite: "MITRE ATT&CK T1592.002, CISA ransomware advisories, industry reporting"
      },
      {
        sub: "T1592.003 — Firmware",
        indicator: "SNMP sysDescr OID walk — firmware version string harvest from network devices",
        arkime: `ip.src != $INTERNAL
&& port.dst == 161
&& protocols == udp
&& databytes.src > 0
&& databytes.src < 200`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 161
AND network.transport: udp
AND destination.bytes: [1 TO 200]`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 161
  (msg:"RECON T1592.003 SNMP
    sysDescr firmware harvest";
  content:"|30|"; depth:1;
  content:"|06 09 2b 06 01 02 01
    01 01 00|";
  classtype:attempted-recon;
  sid:9159213; rev:1;)`,
        notes: "SNMP sysDescr OID (1.3.6.1.2.1.1.1.0) returns full device description including OS version, firmware version, hardware model, and build date. Content '|06 09 2b 06 01 02 01 01 01 00|' is the BER-encoded OID for sysDescr. A single successful read from an external IP = CVE selection guide. Correlate with T1590.004 SNMP community string enumeration — the community string brute is the precursor.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Used SNMP sysDescr queries against MSP network devices to enumerate Cisco IOS and Juniper JUNOS firmware versions." },
          { name: "Dragonfly", cls: "apt-ru", note: "Performed systematic SNMP sysDescr harvesting against energy sector network equipment per CISA ICS-CERT advisories." },
          { name: "APT33", cls: "apt-ir", note: "Queried SNMP sysDescr on oil and gas sector network infrastructure to identify Cisco, Fortinet, and Juniper firmware versions." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Used SNMP firmware version enumeration against US critical infrastructure network equipment during pre-positioning." },
        ],
        cite: "MITRE ATT&CK T1592.003, CISA ICS-CERT, CISA AA23-144A"
      },
      {
        sub: "T1592.003 — Firmware",
        indicator: "SNMP bulk walk — full MIB firmware and configuration harvest",
        arkime: `ip.src != $INTERNAL
&& port.dst == 161
&& protocols == udp
&& databytes.src > 200
&& packets.src > 10`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 161
AND network.transport: udp
AND destination.bytes > 200
AND network.packets > 10`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 161
  (msg:"RECON T1592.003 SNMP bulk
    MIB walk firmware harvest";
  content:"|30|"; depth:1;
  content:"|a5|"; offset:5;
  depth:1;
  threshold:type both,
    track by_src,
    count 10, seconds 30;
  classtype:attempted-recon;
  sid:9159214; rev:1;)`,
        notes: "SNMP GetBulkRequest (PDU type 0xa5) retrieves multiple OIDs in a single request. A full MIB walk returns sysDescr, interfaces, ARP tables, routing tables, CDP neighbor data, and proprietary MIBs containing running config hashes and boot image names — a complete device profile. High packet count + large payload from external IP to UDP/161 = active bulk walk.",
        apt: [
          { name: "Dragonfly", cls: "apt-ru", note: "Performed full SNMP MIB walks against energy sector network devices, harvesting complete device profiles including firmware versions and running config hashes." },
          { name: "APT10", cls: "apt-cn", note: "Conducted bulk SNMP walks against MSP-managed network devices to extract full device profiles for customer environments." },
          { name: "Multi", cls: "apt-mul", note: "Documented in CISA ICS-CERT advisories — a single successful community string enables complete device state visibility." },
        ],
        cite: "MITRE ATT&CK T1592.003, CISA ICS-CERT advisories, industry reporting"
      },
      {
        sub: "T1592.003 — Firmware",
        indicator: "Network device HTTP management interface — firmware version page probing",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  */firmware* || */version*
  || */cgi-bin/luci*
  || */webui/login*
  || */admin/status.php*
  || */system/device-info*
  || */api/v1/system/info*
  || */rest/system/info*
]
&& http.host != $KNOWN_GOOD`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *firmware* OR *version*
  OR */cgi-bin/luci*
  OR */webui/login*
  OR */admin/status.php*
  OR */system/device-info*
  OR */api/v1/system/info*
  OR */rest/system/info*
)
AND NOT url.domain: $KNOWN_GOOD`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1592.003 Device mgmt
    firmware version page probe";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(firmware|version|
    cgi-bin\\/luci|webui\\/login|
    admin\\/status\\.php|
    system\\/device-info|
    api\\/v1\\/system\\/info|
    rest\\/system\\/info)/ix";
  http.uri;
  classtype:attempted-recon;
  sid:9159215; rev:1;)`,
        notes: "Network devices expose firmware version information on management web interface pages — often without authentication on the version/status/about page. Path signatures: /cgi-bin/luci = OpenWRT/LEDE, /webui/login = UTM appliances, /api/v1/system/info = Ubiquiti/Aruba/Ruckus. A 200 response disclosing a firmware version = immediate patch status check. Cross-reference response body against CVE database.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Probed network device HTTP management interfaces to enumerate firmware versions on SOHO routers and enterprise network equipment per CISA AA23-144A." },
          { name: "APT33", cls: "apt-ir", note: "Queried HTTP management interfaces of network appliances in energy sector environments." },
          { name: "Sandworm", cls: "apt-ru", note: "Probed management interface firmware version pages on Ukrainian network infrastructure equipment." },
        ],
        cite: "MITRE ATT&CK T1592.003, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1592.003 — Firmware",
        indicator: "TFTP read request — firmware image or config file retrieval attempt",
        arkime: `ip.src != $INTERNAL
&& port.dst == 69
&& protocols == udp
&& databytes.src > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: 69
AND network.transport: udp
AND destination.bytes > 0`,
        suricata: `alert udp $EXTERNAL_NET any
  -> $HOME_NET 69
  (msg:"RECON T1592.003 TFTP read
    request firmware enumeration";
  content:"|00 01|"; depth:2;
  classtype:attempted-recon;
  sid:9159216; rev:1;)`,
        notes: "TFTP (UDP/69) used by network devices for firmware updates and config backup — an exposed TFTP server may serve firmware images and running configs without any authentication. Content '|00 01|' is the TFTP Read Request opcode. External UDP/69 reaching your network = critical misconfiguration. Cisco devices historically stored running-config via TFTP. Zeek tftp.log captures filenames requested.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Exploited exposed TFTP servers in MSP environments to retrieve Cisco running configurations and firmware images without authentication." },
          { name: "Dragonfly", cls: "apt-ru", note: "Targeted TFTP servers on energy sector networks to retrieve network device configurations and firmware images per CISA ICS-CERT advisories." },
          { name: "Multi", cls: "apt-mul", note: "External UDP/69 is cited in multiple NSA and CISA hardening guides as a high-priority remediation item." },
        ],
        cite: "MITRE ATT&CK T1592.003, CISA ICS-CERT, NSA hardening guides"
      },
      {
        sub: "T1592.003 — Firmware",
        indicator: "TLS certificate CN / SAN — device firmware version and model disclosure",
        arkime: `ip.src != $INTERNAL
&& protocols == tls
&& tls.cert-cn == [
  *FortiGate* || *SonicWall*
  || *pfSense* || *OPNsense*
  || *Cisco* || *Juniper*
  || *Ubiquiti* || *MikroTik*
  || *Synology* || *QNAP*
  || *router* || *firewall*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND tls.server.x509.subject.common_name: (
  *FortiGate* OR *SonicWall*
  OR *pfSense* OR *OPNsense*
  OR *Cisco* OR *Juniper*
  OR *Ubiquiti* OR *MikroTik*
  OR *Synology* OR *QNAP*
  OR *router* OR *firewall*
)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1592.003 TLS cert
    device model/firmware disclose";
  flow:established,from_server;
  tls.cert_subject;
  pcre:"/CN=[^,]*(FortiGate|
    SonicWall|pfSense|OPNsense|
    Cisco|Juniper|Ubiquiti|
    MikroTik|Synology|QNAP|
    router|firewall)/ix";
  classtype:policy-violation;
  sid:9159217; rev:1;)`,
        notes: "Network devices generating self-signed TLS certs often include device model, hostname, and sometimes firmware version in the CN or SAN fields. A FortiGate self-signed cert with CN=FortiGate-100F reveals exact hardware model — adversaries correlate with Shodan to track firmware update history. Remediate: replace self-signed certs with CA-issued certs with generic CNs.",
        apt: [
          { name: "APT33", cls: "apt-ir", note: "Collects TLS certificate CN/SAN data from network device management interfaces to identify device models and correlate with Shodan data." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Harvests TLS certificate metadata from network device management interfaces to identify hardware models and correlate against CVE-vulnerable firmware versions." },
          { name: "Multi", cls: "apt-mul", note: "Passive intelligence source — adversaries collect from Shodan indexed scans without generating probe traffic." },
        ],
        cite: "MITRE ATT&CK T1592.003, industry reporting"
      },
      {
        sub: "T1592.004 — Client Configurations",
        indicator: "JA3 / JA4 known scanner TLS fingerprint — tool identification via ClientHello",
        arkime: `ip.src != $INTERNAL
&& protocols == tls
&& tls.ja3 == [
  "e7d705a3286e19ea42f587b344ee6865"
  || "6734f37431670b3ab4292b8f60f29984"
  || "4d7a28d6f2263ed61de88ca66eb011e3"
  || "b386946a5a44d1ddcc843bc75336dfce"
  || "a0e9f5d64349fb13191bc781f81f42e1"
]`,
        kibana: `NOT source.ip: $INTERNAL
AND tls.client.ja3: (
  "e7d705a3286e19ea42f587b344ee6865"
  OR "6734f37431670b3ab4292b8f60f29984"
  OR "4d7a28d6f2263ed61de88ca66eb011e3"
  OR "b386946a5a44d1ddcc843bc75336dfce"
  OR "a0e9f5d64349fb13191bc781f81f42e1"
)`,
        suricata: `alert tls $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1592.004 Known
    scanner JA3 fingerprint";
  ja3.hash;
  content:"e7d705a3286e19ea42f587b344ee6865";
  classtype:attempted-recon;
  sid:9159218; rev:1;)`,
        notes: "Known scanner JA3 hashes (maintain a current blocklist — these rotate with tool updates): e7d705a3 = Metasploit, 6734f374 = zgrab2 default, 4d7a28d6 = Nmap SSL probe, b386946a = Masscan TLS, a0e9f5d6 = curl/7 default. Evasion: cipher reordering changes the hash. Pair with JA4 (more stable) and behavioral heuristics. Maintain a living blocklist from SSLBL (abuse.ch).",
        apt: [
          { name: "Multi", cls: "apt-mul", note: "JA3 scanner fingerprint matches primarily catch unsophisticated actors and automated tooling — nation-state actors rotate TLS parameters to evade JA3." },
          { name: "IAB", cls: "apt-mul", note: "Initial access brokers running bulk scanning frequently use default tool configurations generating known JA3 hashes." },
        ],
        cite: "MITRE ATT&CK T1592.004, abuse.ch SSLBL, industry reporting"
      },
      {
        sub: "T1592.004 — Client Configurations",
        indicator: "JA4 fingerprint anomaly — tool TLS stack versus claimed browser UA mismatch",
        arkime: `ip.src != $INTERNAL
&& protocols == tls
&& tls.ja4 != $BROWSER_JA4_BASELINE
&& http.user-agent == [
  *Mozilla* || *Chrome*
  || *Firefox* || *Safari*
  || *Edge*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND tls.client.ja4: *
AND NOT tls.client.ja4:
  $BROWSER_JA4_BASELINE
AND user_agent.original: (
  *Mozilla* OR *Chrome*
  OR *Firefox* OR *Safari*
  OR *Edge*
)`,
        suricata: `alert tls $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1592.004 JA4
    mismatch - tool spoofing
    browser UA";
  flow:established,to_server;
  ja3.hash; content:!"";
  classtype:attempted-recon;
  sid:9159219; rev:1;)`,
        notes: "A tool claiming to be Chrome but generating a non-Chrome JA4 hash is spoofing its UA — the TLS ClientHello doesn't lie. Chrome, Firefox, and Edge have stable, well-documented JA4 fingerprints. Build a baseline of expected JA4 values and alert on deviations paired with browser UA strings. This catches adversaries who rotate UA strings but don't implement browser-accurate TLS stacks. Requires Zeek JA4 package.",
        apt: [
          { name: "Midnight Blizzard", cls: "apt-ru", note: "Uses custom tooling with spoofed browser UA strings that generate non-browser JA4 fingerprints — mismatch detectable via JA4 analysis." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Deploys credential harvesting infrastructure with browser-mimicking UA strings but Python/Go TLS stacks — JA4 catches the mismatch." },
          { name: "Scattered Spider", cls: "apt-mul", note: "Uses browser-mimicking UA strings but non-browser TLS stacks in AiTM phishing infrastructure." },
        ],
        cite: "MITRE ATT&CK T1592.004, industry reporting"
      },
      {
        sub: "T1592.004 — Client Configurations",
        indicator: "JA4S — server TLS response fingerprinting for rogue/AiTM infrastructure detection",
        arkime: `ip.dst == $INTERNAL
&& protocols == tls
&& tls.ja3s != $KNOWN_GOOD_SERVERS
&& tls.cert-notbefore >= now-14d`,
        kibana: `destination.ip: $INTERNAL
AND NOT tls.server.ja3s:
  $KNOWN_GOOD_SERVERS
AND tls.server.not_before:
  [now-14d TO now]`,
        suricata: `alert tls $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1592.004 JA4S
    unknown server TLS config";
  flow:established,from_server;
  ja3.hash; content:!"";
  classtype:policy-violation;
  sid:9159220; rev:1;)`,
        notes: "JA4S fingerprints the server-side TLS response (ServerHello). Known-good server JA4S values are stable for your infrastructure — a newly appearing JA4S that doesn't match any known server = rogue service or adversary infrastructure. AiTM proxies have characteristic JA4S values distinct from legitimate IdP servers (Okta, Azure AD, Google). Build a JA4S allowlist for your servers and alert on deviations.",
        apt: [
          { name: "Midnight Blizzard", cls: "apt-ru", note: "AiTM infrastructure generates JA4S values distinct from legitimate Microsoft and Okta TLS server responses." },
          { name: "Scattered Spider", cls: "apt-mul", note: "AiTM proxy infrastructure has documented JA4S values differing from legitimate IdP servers." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Credential harvesting pages generate JA4S values inconsistent with the legitimate Google/Microsoft servers they mimic." },
        ],
        cite: "MITRE ATT&CK T1592.004, T1598, industry reporting"
      },
      {
        sub: "T1592.004 — Client Configurations",
        indicator: "Passive OS fingerprinting — TCP stack anomaly indicating scanner or non-standard OS",
        arkime: `ip.src != $INTERNAL
&& protocols == tcp
&& tcpflags.syn == 1
&& tcpflags.ack == 0
&& ip.ttl == [255 || 64 || 128]
&& tcp.window-size == [
  1024 || 2048 || 65535 || 0
]`,
        kibana: `NOT source.ip: $INTERNAL
AND tcp.flags: "S"
AND NOT tcp.flags: "A"
AND network.transport: tcp`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1592.004 Passive OS
    fingerprint TCP anomaly";
  flags:S,12;
  flow:stateless;
  ttl:255;
  window:1024;
  classtype:attempted-recon;
  sid:9159221; rev:1;)`,
        notes: "TCP SYN packets contain OS fingerprinting data in IP TTL, TCP window size, MSS, and options order. Baseline values: Linux = TTL 64, window ~29200; Windows = TTL 128, window 65535; Cisco IOS = TTL 255, window 4128; Masscan = TTL 255, window 1024; Zmap = TTL 255, window 65535. Integrate p0f or Zeek OS fingerprinting for passive identification. Arkime community fingerprint plugin surfaces p0f data in session records.",
        apt: [
          { name: "APT40", cls: "apt-cn", note: "Uses Masscan-equivalent tooling with characteristic TCP stack (TTL=255, window=1024) for large-scale port sweeps — passive TCP fingerprinting identifies this even when UAs are customized." },
          { name: "APT28", cls: "apt-ru", note: "Network scanning tooling generates distinctive TCP stack signatures detectable via passive OS fingerprinting per NSA/CISA AA20-296A." },
          { name: "Multi", cls: "apt-mul", note: "Most evasion-resistant scanning detection method — TCP stack parameters require OS-level changes to spoof convincingly." },
        ],
        cite: "MITRE ATT&CK T1592.004, NSA/CISA AA20-296A, industry reporting"
      },
      {
        sub: "T1592.004 — Client Configurations",
        indicator: "JA4H mismatch — HTTP header order inconsistent with claimed browser",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.user-agent == [
  *Chrome* || *Firefox*
  || *Safari* || *Edge*
]
&& http.header-order != $BROWSER_HEADER_BASELINE`,
        kibana: `NOT source.ip: $INTERNAL
AND user_agent.original: (
  *Chrome* OR *Firefox*
  OR *Safari* OR *Edge*
)
AND NOT http.request.headers.order:
  $BROWSER_HEADER_BASELINE`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1592.004 JA4H
    header order browser UA
    mismatch";
  flow:established,to_server;
  content:"Mozilla/5.0"; http.header;
  pcre:"/^(?!.*(Host|User-Agent|
    Accept|Accept-Language|
    Accept-Encoding|Connection))/x";
  http.header;
  classtype:attempted-recon;
  sid:9159222; rev:1;)`,
        notes: "JA4H fingerprints HTTP clients by header order, count, accept-language, and cookie/referer presence. Chrome, Firefox, Edge each have stable header orders. Known orders: Chrome = Host, Connection, Accept, User-Agent, Accept-Encoding, Accept-Language; Python-requests = Host, User-Agent, Accept-Encoding, Accept, Connection (no Accept-Language). Effective for catching web scanner and phishing kit traffic spoofing browser UAs. Requires Zeek JA4 package.",
        apt: [
          { name: "Charming Kitten", cls: "apt-ir", note: "Uses browser-mimicking UA strings but Python-requests or Go http.Client header orders detectable via JA4H analysis." },
          { name: "Kimsuky", cls: "apt-kp", note: "Automated reconnaissance tooling with spoofed browser UAs but scripting library header orders, detectable via JA4H." },
          { name: "Multi", cls: "apt-mul", note: "Particularly effective against phishing kits — kits written in PHP/Python/Go rarely implement accurate browser header ordering." },
        ],
        cite: "MITRE ATT&CK T1592.004, industry reporting"
      },
      {
        sub: "T1592.004 — Client Configurations",
        indicator: "WPAD / PAC file request — network proxy configuration disclosure",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  */wpad.dat*
  || */proxy.pac*
  || */wpad/wpad.dat*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *wpad.dat*
  OR *proxy.pac*
  OR *wpad/wpad.dat*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1592.004 WPAD PAC
    proxy config disclosure";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(wpad\\.dat|
    proxy\\.pac|
    wpad\\/wpad\\.dat)/ix";
  http.uri;
  classtype:attempted-recon;
  sid:9159223; rev:1;)`,
        notes: "WPAD requests reveal that the client uses automatic proxy detection — and if your PAC file is served, it discloses internal proxy hostnames, IP ranges, and bypass lists. External requests for wpad.dat should never reach your web servers. WPAD poisoning via Responder is a documented credential harvesting technique — internal clients broadcasting WPAD requests are vulnerable. Disable WPAD on all clients or configure proxy settings explicitly.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Exploited WPAD broadcast requests using Responder-equivalent tooling to serve malicious PAC files, redirecting traffic through adversary-controlled proxies." },
          { name: "Multi", cls: "apt-mul", note: "WPAD poisoning via NBNS/mDNS is documented in multiple penetration testing frameworks and commonly observed in post-compromise lateral movement." },
        ],
        cite: "MITRE ATT&CK T1592.004, T1557, industry reporting"
      },
    ]
  },
  {
    id: "T1593",
    name: "Search Open Websites / Domains",
    desc: ".001 Social Media · .002 Search Engines · .003 Code Repositories",
    rows: [
      {
        sub: "T1593.001 — Social Media",
        indicator: "LinkedIn bulk profile / company scraping from internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == *linkedin.com*
&& http.method == GET
&& http.uri == [
  */search/results/people*
  || */company/*
  || */in/*
  || */posts/*
]
&& databytes.src > 20000
&& packets.src > 20`,
        kibana: `source.ip: $INTERNAL
AND url.domain: "linkedin.com"
AND http.request.method: GET
AND url.path: (
  *search/results/people*
  OR */company/*
  OR */in/*
  OR */posts/*
)
AND http.response.bytes > 20000`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1593.001 Internal
    LinkedIn bulk profile scrape";
  flow:established,to_server;
  content:"GET"; http.method;
  content:"linkedin.com"; http.host;
  pcre:"/(search\\/results\\/people|
    \\/company\\/|
    \\/in\\/[a-z0-9\\-]+\\/)/ix";
  http.uri;
  threshold:type both,
    track by_src,
    count 20, seconds 60;
  classtype:policy-violation;
  sid:9159301; rev:1;)`,
        notes: "High-volume LinkedIn profile and company page fetches from single internal host = automated scraping. Legitimate LinkedIn use is interactive — 20+ profile GETs in 60 seconds from one endpoint is anomalous. LinkedIn rate limiting generates 429 responses visible in proxy logs — a 429 from LinkedIn is itself an indicator. Baseline sales/recruiting team use first.",
        apt: [
          { name: "Charming Kitten", cls: "apt-ir", note: "Uses LinkedIn profile scraping to identify high-value targets at academic, NGO, and government organizations before spearphishing." },
          { name: "Kimsuky", cls: "apt-kp", note: "Scrapes LinkedIn profiles of South Korean government and US policy organization staff to identify personnel with access to target information." },
          { name: "APT10", cls: "apt-cn", note: "Scraped LinkedIn profiles of MSP employees to identify system administrators during Cloud Hopper." },
        ],
        cite: "MITRE ATT&CK T1593.001, T1589.003, industry reporting"
      },
      {
        sub: "T1593.001 — Social Media",
        indicator: "Social platform bulk org mention queries from internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *twitter.com* || *x.com*
  || *reddit.com*
  || *glassdoor.com*
  || *facebook.com*
]
&& http.uri == [
  */search* || */query*
  || */api/search*
  || */graphql*
]
&& databytes.src > 10000
&& packets.src > 15`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "twitter.com" OR "x.com"
  OR "reddit.com"
  OR "glassdoor.com"
  OR "facebook.com"
)
AND url.path: (
  *search* OR *query*
  OR *api/search*
  OR *graphql*
)
AND http.response.bytes > 10000`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1593.001 Internal
    social platform bulk search";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    twitter\\.com|x\\.com|
    reddit\\.com|glassdoor\\.com|
    facebook\\.com)/ix";
  http.header;
  threshold:type both,
    track by_src,
    count 15, seconds 60;
  classtype:policy-violation;
  sid:9159302; rev:1;)`,
        notes: "Adversaries query social platforms for mentions of your org, employee names, and internal tool names. Reddit contains employee posts mentioning internal tools and outages. Glassdoor reviews often disclose internal technology stacks in detail. GraphQL endpoints on Twitter/X and Facebook are used by automated tools to bulk-harvest org-related content.",
        apt: [
          { name: "Kimsuky", cls: "apt-kp", note: "Conducts social media reconnaissance across multiple platforms to build target profiles of government and policy organization employees." },
          { name: "Cozy Bear", cls: "apt-ru", note: "Used social media intelligence gathering to identify and profile targets prior to spearphishing." },
          { name: "Multi", cls: "apt-mul", note: "Social media platform searches for org-specific content from internal hosts is a documented post-compromise reconnaissance behavior." },
        ],
        cite: "MITRE ATT&CK T1593.001, industry reporting"
      },
      {
        sub: "T1593.002 — Search Engines",
        indicator: "Google / Bing dork queries targeting your own domain from internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *google.com*
  || *bing.com*
  || *duckduckgo.com*
]
&& http.uri == [
  *site:yourdomain.com*
  || *inurl:yourdomain*
  || *filetype:*
  || *intitle:index.of*
  || *"internal use only"*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "google.com" OR "bing.com"
  OR "duckduckgo.com"
)
AND url.query: (
  *site:yourdomain* OR *inurl:*
  OR *filetype:* OR *intitle:*
  OR *"internal use only"*
  OR *confidential*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1593.002 Internal
    host Google dorking own domain";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    google\\.com|bing\\.com|
    duckduckgo\\.com)/ix";
  http.header;
  pcre:"/(site%3A|inurl%3A|
    filetype%3A|intitle%3A|
    internal.use.only|
    confidential)/ix";
  http.uri;
  classtype:policy-violation;
  sid:9159303; rev:1;)`,
        notes: "Google dork operators (site:, inurl:, filetype:, intitle:) allow targeted searches for exposed files and sensitive content. An internal host running dork queries against your own domain is either red team activity (document it) or a compromised host performing pre-exfil intelligence gathering. URL-encoded operators (%3A = :) used by automated tools — the Suricata PCRE matches both encoded and decoded forms.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Used Google dorking to identify exposed files, login pages, and sensitive content on target organization websites." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Uses targeted Google dork queries to find publicly accessible documents containing employee information and technology details on target websites." },
          { name: "Kimsuky", cls: "apt-kp", note: "Uses search engine dorking to identify exposed documents on government and research organization websites prior to targeted phishing." },
        ],
        cite: "MITRE ATT&CK T1593.002, industry reporting"
      },
      {
        sub: "T1593.002 — Search Engines",
        indicator: "Shodan / Censys / FOFA search API queries from internal host — own org lookup",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *shodan.io*
  || *censys.io*
  || *zoomeye.org*
  || *fofa.info*
  || *binaryedge.io*
]
&& http.uri == [
  */shodan/host/search*
  || */api/v2/hosts/search*
  || */search*
]
&& http.method == GET`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "shodan.io" OR "censys.io"
  OR "zoomeye.org"
  OR "fofa.info"
  OR "binaryedge.io"
)
AND url.path: (
  *search* OR *hosts/search*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1593.002 Internal
    host Shodan/Censys/FOFA
    own-org search";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    shodan\\.io|censys\\.io|
    zoomeye\\.org|fofa\\.info|
    binaryedge\\.io)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159304; rev:1;)`,
        notes: "Internal hosts querying Shodan or Censys API against your own org's IP ranges = either security team exposure assessment (document and baseline) or a compromised host mapping your internet-facing attack surface. FOFA (fofa.info) and ZoomEye (zoomeye.org) are Chinese internet-wide scan databases — internal hits from non-security-team endpoints are a strong indicator of CN-attributed adversarial tooling.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Uses FOFA and ZoomEye (Chinese internet scan databases) to search for exposed services — internal hits indicate adversary tooling performing attack surface mapping." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Queried Shodan and Censys for exposed management interfaces on US critical infrastructure during pre-positioning operations." },
          { name: "APT33", cls: "apt-ir", note: "Used Shodan API queries to map exposed services on energy sector targets." },
        ],
        cite: "MITRE ATT&CK T1593.002, T1596.005, industry reporting"
      },
      {
        sub: "T1593.003 — Code Repositories",
        indicator: "GitHub API search for org secrets / internal naming from internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *github.com*
  || *api.github.com*
]
&& http.uri == [
  */search/code*
  || */search?q=*
]
&& http.uri == [
  *password* || *secret*
  || *api_key* || *token*
  || *yourdomain* || *internal*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "github.com"
  OR "api.github.com"
)
AND url.path: (
  *search/code*
  OR *search/repositories*
)
AND url.query: (
  *yourdomain* OR *internal*
  OR *password* OR *secret*
  OR *api_key* OR *token*
  OR *BEGIN+RSA*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1593.003 Internal
    GitHub code search secret
    exposure hunting";
  flow:established,to_server;
  content:"api.github.com"; http.host;
  content:"/search/code"; http.uri;
  pcre:"/(password|secret|
    api_key|token|BEGIN.RSA|
    BEGIN.PGP|internal|corp)/ix";
  http.uri;
  classtype:policy-violation;
  sid:9159305; rev:1;)`,
        notes: "GitHub code search API queries targeting your org's domain, internal naming conventions, or credential keywords from internal hosts = security team secret scanning (document it) or compromised host hunting for accidentally committed credentials. GitHub API rate-limits at 10 req/min for authenticated users — 403 responses in proxy logs indicate automated tooling hitting rate limits.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Searches GitHub for accidentally committed credentials, API keys, and internal configuration data from target organizations." },
          { name: "Cozy Bear", cls: "apt-ru", note: "Searched code repositories for credentials and configuration files related to target organizations." },
          { name: "APT33", cls: "apt-ir", note: "Used GitHub secret scanning techniques against energy sector and defense contractor repositories to identify accidentally committed credentials." },
        ],
        cite: "MITRE ATT&CK T1593.003, CISA advisories, industry reporting"
      },
      {
        sub: "T1593.003 — Code Repositories",
        indicator: "git clone over HTTPS — bulk repository cloning from suspicious endpoint",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.host == [
  *github.com*
  || *gitlab.com*
  || *bitbucket.org*
]
&& http.user-agent == *git/*
&& http.uri == [
  */info/refs*
  || */git-upload-pack*
]
&& databytes.dst > 100000`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "github.com" OR "gitlab.com"
  OR "bitbucket.org"
)
AND user_agent.original: *git/*
AND url.path: (
  *info/refs*
  OR *git-upload-pack*
)
AND destination.bytes > 100000`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1593.003 Git clone
    bulk repo download";
  flow:established,to_server;
  content:"git/"; http.header;
  content:"/info/refs"; http.uri;
  threshold:type both,
    track by_src,
    count 5, seconds 300;
  classtype:policy-violation;
  sid:9159306; rev:1;)`,
        notes: "Git clone over HTTPS generates a two-step HTTP exchange: GET /repo.git/info/refs?service=git-upload-pack (discovery) followed by POST /repo.git/git-upload-pack (pack download). User-Agent is always git/[version] — unforgeable without breaking git protocol. Bulk cloning of multiple repos from your org's namespace from an endpoint that isn't a known CI/CD system is anomalous. Large databytes.dst reflects repository size.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Has cloned target organization code repositories to harvest credentials, API keys, and internal infrastructure details." },
          { name: "APT29", cls: "apt-ru", note: "Cloned repositories related to target organizations during pre-compromise intelligence gathering." },
          { name: "Multi", cls: "apt-mul", note: "Git clone activity against your org's repos from non-CI/CD endpoints is a documented post-compromise data staging behavior." },
        ],
        cite: "MITRE ATT&CK T1593.003, industry reporting"
      },
      {
        sub: "T1593.003 — Code Repositories",
        indicator: "Self-hosted GitLab / Bitbucket SCM API enumeration — external repository listing",
        arkime: `ip.src != $INTERNAL
&& http.host == [
  *gitlab.yourdomain.com*
  || *bitbucket.yourdomain.com*
  || *git.yourdomain.com*
]
&& http.method == GET
&& http.uri == [
  */api/v4/projects*
  || */rest/api/1.0/repos*
  || */explore/repos*
  || */api/v4/users*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND url.domain: (
  *gitlab.yourdomain*
  OR *bitbucket.yourdomain*
  OR *git.yourdomain*
)
AND url.path: (
  */api/v4/projects*
  OR */rest/api/1.0/repos*
  OR */explore/repos*
  OR */api/v4/users*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1593.003 External
    internal SCM API enumeration";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(api\\/v4\\/projects|
    rest\\/api\\/1\\.0\\/repos|
    explore\\/repos|
    api\\/v4\\/users)/ix";
  http.uri;
  classtype:attempted-recon;
  sid:9159307; rev:1;)`,
        notes: "Self-hosted GitLab and Bitbucket expose REST APIs that list all repositories and users — even without authentication if misconfigured with public visibility. /api/v4/projects returns all repositories an unauthenticated user can see. External access to these endpoints from unknown IPs = repository enumeration. A 200 response with a large JSON payload from an external IP = critical misconfiguration — your repo list is public.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Enumerated self-hosted GitLab and Bitbucket instances via unauthenticated API endpoints per FBI and CISA advisories." },
          { name: "APT33", cls: "apt-ir", note: "Targeted self-hosted SCM instances at defense contractor and energy sector organizations to enumerate repositories." },
          { name: "Multi", cls: "apt-mul", note: "Unauthenticated SCM API access is a critical misconfiguration — remediate before tuning detection." },
        ],
        cite: "MITRE ATT&CK T1593.003, FBI/CISA advisories, industry reporting"
      },
    ]
  },
  {
    id: "T1595",
    name: "Active Scanning",
    desc: ".001 IP Blocks · .002 Vulnerability Scanning · .003 Wordlist Scanning",
    rows: [
      {
        sub: "T1595.001 — Scanning IP Blocks",
        indicator: "SYN scan pattern — single packet each direction, no data exchange",
        arkime: `ip.src != $INTERNAL
&& packets.src == 1
&& packets.dst == 1
&& databytes.src == 0
&& databytes.dst == 0
&& tcpflags.syn == 1
&& tcpflags.ack == 0`,
        kibana: `NOT source.ip: $INTERNAL
AND tcp.flags: "S"
AND NOT tcp.flags: "A"
AND network.packets: 2
AND source.bytes: 0
AND destination.bytes: 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1595 SYN scan";
  flags:S,12; flow:stateless;
  threshold:type both,
    track by_src,
    count 20, seconds 10;
  classtype:attempted-recon;
  sid:9159501; rev:1;)`,
        notes: "flags:S,12 matches SYN only, ignoring RST/ACK/FIN. Exactly 1 pkt each direction with 0 databytes is the SYN→SYN-ACK→RST fingerprint. High count threshold avoids false positives on slow apps.",
        ja4: `# JA4T — TCP fingerprint (TTL, window size, MSS, TCP options order)
# Zeek (ja4 package): ja4t.log
# Format: TTL_WindowSize_MSS_Options

# Masscan characteristic JA4T (TTL=255, tiny window, no options):
ja4t == "255_0064_0000_00"

# Nmap SYN scan JA4T (TTL=64, window=1024, MSS=1460):
ja4t == "064_0400_05b4_mss"

# Zmap default JA4T (TTL=255, window=65535):
ja4t == "255_ffff_0000_00"

# Arkime field (requires ja4 plugin):
ja4t == "255_0064_0000_00"

# Kibana (ECS with ja4 enrichment):
ja4t: "255_0064_0000_00"

# Key: legitimate OS TCP stacks have consistent JA4T values.
# Linux: TTL=64, Win=~29200, MSS=1460
# Windows: TTL=128, Win=~65535, MSS=1460
# Scanner anomalies: TTL=255, zero/tiny window, no SACK`,
        apt: [
          { name: "APT40", cls: "apt-cn", note: "Systematic port sweeps of maritime/gov targets prior to exploitation." },
          { name: "APT28", cls: "apt-ru", note: "Broad port surveys pre-operation documented against NATO targets." },
          { name: "Sandworm", cls: "apt-ru", note: "Mass pre-exploitation scanning of Ukrainian infrastructure." },
          { name: "Multi/IAB", cls: "apt-mul", note: "Mass pre-exploitation scanning. Default tool UAs primarily seen from opportunistic actors and initial access brokers." },
        ],
        cite: "MITRE ATT&CK T1595.001, industry reporting"
      },
      {
        sub: "T1595.001 — Scanning IP Blocks",
        indicator: "External hosts touching common ports — 0 payload",
        arkime: `ip.src != $INTERNAL
&& databytes.dst == 0
&& port.dst == [21,22,23,25,53,
80,110,135,139,143,
443,445,1433,1521,
3306,3389,5900,
8080,8443,8888]`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: (21 OR 22
  OR 23 OR 25 OR 53 OR 80
  OR 110 OR 135 OR 139 OR 143
  OR 443 OR 445 OR 1433 OR 1521
  OR 3306 OR 3389 OR 5900
  OR 8080 OR 8443 OR 8888)
AND destination.bytes: 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET [21,22,23,25,53,
   80,110,135,139,143,
   443,445,1433,1521,3306,
   3389,5900,8080,8443,8888]
  (msg:"RECON T1595 Zero-payload
    probe common ports";
  flags:S,12; dsize:0;
  threshold:type both,
    track by_src,
    count 10, seconds 30;
  classtype:attempted-recon;
  sid:9159502; rev:1;)`,
        notes: "DB ports (1433 MSSQL, 1521 Oracle, 3306 MySQL), VNC (5900), alt-HTTP included. Zero databytes.dst confirms knock with no follow-through. Enrich with GeoIP — RDP from Eastern Europe at 03:00 UTC is a tier-1 alert.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Cloud Hopper targeted RDP/SMB extensively against MSP environments." },
          { name: "Lazarus", cls: "apt-kp", note: "Probes DB/RDP ports against financial targets." },
          { name: "APT28", cls: "apt-ru", note: "Broad port surveys pre-operation." },
        ],
        cite: "MITRE ATT&CK T1595.001, industry reporting"
      },
      {
        sub: "T1595.001 — Scanning IP Blocks",
        indicator: "ICMP ping sweep — external host sweeping your address space",
        arkime: `ip.src != $INTERNAL
&& protocols == icmp
&& icmp.type == 8
&& icmp.code == 0
&& ip.dst == $INTERNAL
&& packets.src > 10
&& node:*`,
        kibana: `NOT source.ip: $INTERNAL
AND network.transport: icmp
AND icmp.type: 8
AND icmp.code: 0
AND destination.ip: $INTERNAL`,
        suricata: `alert icmp $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1595.001 ICMP ping
    sweep host discovery";
  itype:8; icode:0;
  threshold:type both,
    track by_src,
    count 10, seconds 10;
  classtype:attempted-recon;
  sid:9159505; rev:1;)`,
        notes: "ICMP type 8 code 0 = echo request. Burst of pings to sequential IPs from a single external source = host discovery sweep before port scanning. Check ip.dst for sequential increment pattern in Arkime. Many orgs block inbound ICMP at perimeter — adversaries fall back to TCP SYN host discovery instead.",
        apt: [
          { name: "APT40", cls: "apt-cn", note: "ICMP host discovery sweeps as standard first step in network enumeration of maritime/defense/gov IP ranges." },
          { name: "Sandworm", cls: "apt-ru", note: "ICMP sweep-based host discovery against Ukrainian government and energy sector IP allocations prior to destructive operations." },
          { name: "APT28", cls: "apt-ru", note: "Automated pre-scan ICMP sweeps in network reconnaissance toolkits against NATO member networks." },
          { name: "Volt Typhoon", cls: "apt-cn", note: "Host discovery including ICMP sweeps to enumerate live systems in US critical infrastructure IP ranges." },
        ],
        cite: "MITRE ATT&CK T1595.001, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1595.002 — Vulnerability Scanning",
        indicator: "Web recon / directory enumeration — sensitive path probing",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  *robots.txt* || *sitemap*
  || *.env* || */.git/*
  || */.svn/* || */wp-config*
  || */config.php* || */web.config*
  || */phpinfo* || */server-status*
  || */admin/* || */actuator/*
  || */swagger* || */api-docs*
  || */.aws/credentials*
  || */backup* || */.htpasswd*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *robots.txt* OR *sitemap*
  OR *.env* OR *.git*
  OR *.svn* OR *wp-config*
  OR *phpinfo* OR *server-status*
  OR */admin/* OR */actuator/*
  OR *swagger* OR *api-docs*
  OR *.aws/credentials*
  OR *backup* OR *.htpasswd*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1595 Dir enum
    sensitive path probe";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/\\/(robots\\.txt|sitemap|
    \\.env|\\.git|\\.svn|wp-config|
    phpinfo|server-status|admin|
    actuator|swagger|api-docs|
    backup|\\.htpasswd|\\.aws)/ix";
  http.uri;
  threshold:type both,
    track by_src, count 5,
    seconds 60;
  classtype:web-application-activity;
  sid:9159503; rev:1;)`,
        notes: "Path list covers: source control leaks (.git, .svn), cloud cred leaks (.aws/credentials), Spring Boot (actuator), REST API discovery (swagger, api-docs), Apache internals (server-status). Any 200 response to these paths is a critical finding regardless of scanning intent.",
        apt: [
          { name: "APT33", cls: "apt-ir", note: "Heavily targets exposed cloud credentials and config files against energy/defense sector targets." },
          { name: "APT41", cls: "apt-cn", note: "Probes web apps pre-supply-chain compromise." },
          { name: "FIN7", cls: "apt-mul", note: "Directory enum for POS/hospitality targeting." },
        ],
        cite: "MITRE ATT&CK T1595.002, industry reporting"
      },
      {
        sub: "T1595.002 — Vulnerability Scanning",
        indicator: "CVE-specific exploit probe patterns — known-exploited path fingerprinting",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  *jndi:ldap* || *jndi:rmi*
  || */owa/auth/x.js*
  || */vpns/portal/scripts/*
  || */mgmt/tm/util/bash*
  || */mgmt/tm/sys/config*
  || */solr/admin/cores*
  || */actuator/heapdump*
  || */actuator/env*
  || */wp-json/wp/v2/users*
  || */telescope/requests*
  || */dana-na/auth/saml-sso*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *jndi:ldap* OR *jndi:rmi*
  OR */owa/auth/x.js*
  OR */vpns/portal/scripts/*
  OR */mgmt/tm/util/bash*
  OR */mgmt/tm/sys/config*
  OR */solr/admin/cores*
  OR */actuator/heapdump*
  OR */actuator/env*
  OR */wp-json/wp/v2/users*
  OR */telescope/requests*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1595.002 CVE-specific
    exploit path probe";
  flow:established,to_server;
  pcre:"/(\\$\\{jndi:|
    \\/owa\\/auth\\/x\\.js|
    \\/vpns\\/portal\\/scripts|
    \\/mgmt\\/tm\\/util\\/bash|
    \\/solr\\/admin\\/cores|
    \\/actuator\\/(heapdump|env)|
    \\/wp-json\\/wp\\/v2\\/users|
    \\/telescope\\/requests)/ix";
  http.uri;
  classtype:web-application-activity;
  sid:9159506; rev:1;)`,
        notes: "CVE mapping: jndi:ldap/rmi = Log4Shell (CVE-2021-44228), /owa/auth/x.js = ProxyLogon (CVE-2021-26855), /vpns/portal/scripts/ = Citrix ADC (CVE-2019-19781), /mgmt/tm/util/bash = F5 iControl (CVE-2021-22986), /solr/admin/cores = Apache Solr RCE, /actuator/heapdump = Spring Boot. A single hit on any of these from an external IP is P1 — maintain a living list updated against CISA KEV additions.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Probed F5 iControl and Citrix paths weeks before exploitation per CISA AA23-144A." },
          { name: "APT33", cls: "apt-ir", note: "Log4Shell path probing within 48 hours of public disclosure against energy/defense web infrastructure." },
          { name: "Lazarus", cls: "apt-kp", note: "ProxyLogon path probing (/owa/auth/x.js) against financial sector Exchange infrastructure." },
          { name: "Multi", cls: "apt-mul", note: "CVE-specific path probing documented across all major nation-state actors following high-profile vulnerability disclosures." },
        ],
        cite: "MITRE ATT&CK T1595.002, CISA KEV, CISA AA23-144A, industry reporting"
      },
      {
        sub: "T1595.002 — Vulnerability Scanning",
        indicator: "Banner grabbing — service version harvest via connect-and-RST",
        arkime: `ip.src != $INTERNAL
&& port.dst == [
  21,22,23,25,110,
  143,389,445,3306,
  3389,5432,5900,8080
]
&& packets.src == 1
&& packets.dst >= 1
&& databytes.src == 0
&& databytes.dst > 0`,
        kibana: `NOT source.ip: $INTERNAL
AND destination.port: (
  21 OR 22 OR 23 OR 25
  OR 110 OR 143 OR 389
  OR 445 OR 3306 OR 3389
  OR 5432 OR 5900 OR 8080
)
AND source.packets: 1
AND destination.packets >= 1
AND source.bytes: 0
AND destination.bytes > 0`,
        suricata: `alert tcp $EXTERNAL_NET any
  -> $HOME_NET
  [21,22,23,25,110,143,
   389,445,3306,3389,
   5432,5900,8080]
  (msg:"RECON T1595.002 Banner
    grab connect-and-RST";
  flow:established,to_server;
  dsize:0;
  threshold:type both,
    track by_src,
    count 5, seconds 30;
  classtype:attempted-recon;
  sid:9159507; rev:1;)`,
        notes: "Client connects, server sends banner, client immediately RSTs without sending data. Zero databytes.src with non-zero databytes.dst across multiple service ports from same source IP. SSH banners reveal OpenSSH version; FTP reveals server software; SMTP reveals MTA and version. Zeek service.log provides cleaner banner capture for post-incident analysis.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Banner grabbing as standard service enumeration step in MSP network reconnaissance during Cloud Hopper." },
          { name: "APT40", cls: "apt-cn", note: "Service banner grabbing against maritime/government perimeters to build software inventory before CVE selection." },
          { name: "Dragonfly", cls: "apt-ru", note: "Banner grabbing against energy sector exposed services to identify unpatched software at IT/OT boundaries." },
        ],
        cite: "MITRE ATT&CK T1595.002, T1592.002, NSA/CISA advisories, industry reporting"
      },
      {
        sub: "T1595.002 — Vulnerability Scanning",
        indicator: "Known scanner user-agents hitting infrastructure",
        arkime: `ip.src != $INTERNAL
&& http.user-agent == [
  *nmap* || *nikto*
  || *masscan* || *zgrab*
  || *gobuster* || *nuclei*
  || *sqlmap* || *ffuf*
  || *feroxbuster* || *wpscan*
  || *acunetix* || *nessus*
  || *metasploit* || *hydra*
  || *python-requests*
  || *go-http-client*
  || *libwww-perl*
]`,
        kibana: `NOT source.ip: $INTERNAL
AND user_agent.original: (
  *nmap* OR *nikto*
  OR *masscan* OR *zgrab*
  OR *gobuster* OR *nuclei*
  OR *sqlmap* OR *ffuf*
  OR *feroxbuster* OR *wpscan*
  OR *acunetix* OR *nessus*
  OR *metasploit* OR *hydra*
  OR *python-requests*
  OR *go-http-client*
  OR *libwww-perl*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1595 Scanner UA";
  flow:established,to_server;
  pcre:"/User-Agent\\s*:\\s*
    [^\\r\\n]*(nmap|nikto|masscan|
    zgrab|gobuster|nuclei|sqlmap|
    ffuf|feroxbuster|wpscan|
    acunetix|nessus|metasploit|
    hydra|python-requests|
    go-http-client|
    libwww-perl)/ix";
  http.header;
  classtype:web-application-activity;
  sid:9159504; rev:1;)`,
        notes: "Includes modern wordlist fuzzers (ffuf, feroxbuster, wfuzz), CMS scanners (wpscan, joomscan), commercial scanners (Acunetix, Nessus, Qualys), exploitation frameworks (Metasploit, Hydra), scripting defaults (python-requests, go-http-client, libwww-perl). Skilled adversaries spoof UAs — absence does NOT clear a session. Pair with JA3/JA4.",
        apt: [
          { name: "Multi/IAB", cls: "apt-mul", note: "Default tool UAs primarily from opportunistic actors and initial access brokers. Nation-state actors typically customize UA strings." },
        ],
        cite: "MITRE ATT&CK T1595.002, industry reporting"
      },
      {
        sub: "T1595.003 — Wordlist Scanning",
        indicator: "High 4xx response ratio from single external IP — wordlist exhaustion",
        arkime: `ip.src != $INTERNAL
&& protocols == http
&& http.statuscode == [
  400 || 403 || 404 || 405
]
&& packets.src > 50`,
        kibana: `NOT source.ip: $INTERNAL
AND http.response.status_code: (
  400 OR 403 OR 404 OR 405
)
| stats count by source.ip
| where count > 50`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1595.003 High 4xx
    ratio wordlist exhaustion";
  flow:established,to_server;
  content:"GET"; http.method;
  http.stat_code;
  content:"404";
  threshold:type both,
    track by_src,
    count 50, seconds 60;
  classtype:web-application-activity;
  sid:9159508; rev:1;)`,
        notes: "Wordlist scanners (gobuster, ffuf, feroxbuster) generate characteristic 404/403/400 bursts regardless of UA string. Single external IP generating 50+ 4xx responses across varied URI paths in 60 seconds = near-certain wordlist scanning. UA-spoof-resistant companion to the scanner UA row. Use bucket aggregation in Kibana (source.ip + status_code) — signal is in the volume, not individual requests.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Wordlist-based web enumeration with custom UA strings as standard pre-compromise step — 4xx ratio catches this where UA matching fails." },
          { name: "APT33", cls: "apt-ir", note: "Directory brute-forcing with rotated UA strings against energy/defense web apps." },
          { name: "FIN7", cls: "apt-mul", note: "ffuf and feroxbuster with custom UAs in POS/hospitality sector web app recon." },
          { name: "IAB", cls: "apt-mul", note: "Initial access brokers run ffuf/feroxbuster with spoofed UAs against bulk target lists — 4xx ratio is the only reliable indicator when UA rotation is in play." },
        ],
        cite: "MITRE ATT&CK T1595.003, industry reporting"
      },
    ]
  },
  {
    id: "T1596",
    name: "Search Technical Databases",
    desc: ".001/.002 WHOIS & History · .003 Passive DNS · .004 Certificate Transparency · .005 Scan Databases",
    rows: [
      {
        sub: "T1596.001 — WHOIS / .002 WHOIS History",
        indicator: "RDAP / WHOIS API query — internal host querying registration data for own domain",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *rdap.arin.net*
  || *rdap.ripe.net*
  || *rdap.apnic.net*
  || *whois.domaintools.com*
  || *whoisxmlapi.com*
  || *whoisfreaks.com*
]
&& http.method == GET
&& http.uri == [
  */ip/* || */domain/*
  || */autnum/*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "rdap.arin.net"
  OR "rdap.ripe.net"
  OR "rdap.apnic.net"
  OR "whois.domaintools.com"
  OR "whoisxmlapi.com"
  OR "whoisfreaks.com"
)
AND url.path: (
  */ip/* OR */domain/*
  OR */autnum/*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.001 Internal
    host RDAP/WHOIS API query";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    rdap\\.arin\\.net|
    rdap\\.ripe\\.net|
    rdap\\.apnic\\.net|
    whois\\.domaintools\\.com|
    whoisxmlapi\\.com|
    whoisfreaks\\.com)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159401; rev:1;)`,
        notes: "Internal hosts querying RDAP or commercial WHOIS APIs against your own domain or IP ranges = NOC/security team activity (baseline and document) or a compromised host mapping registration data. Automated bulk queries from endpoints are anomalous. Port 43 TCP (legacy WHOIS) is covered in T1590.001 — this row covers the modern RDAP/HTTP equivalent.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Queried RDAP and WHOIS data to map organizational relationships between target organizations and their ISPs, identifying OT-segment IP ranges." },
          { name: "APT29", cls: "apt-ru", note: "Queried domain registration and RDAP data to map subsidiary and partner relationships during pre-SolarWinds reconnaissance." },
          { name: "Multi", cls: "apt-mul", note: "Post-compromise indicator — adversaries map your registered IP space to plan lateral movement and identify overlooked internet-exposed ranges." },
        ],
        cite: "MITRE ATT&CK T1596.001, industry reporting"
      },
      {
        sub: "T1596.001 — WHOIS / .002 WHOIS History",
        indicator: "WHOIS history / DomainTools API — historical registration data query from internal host",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *domaintools.com*
  || *whoisology.com*
  || *whoxy.com*
  || *whoishistory.com*
  || *completedns.com*
]
&& http.method == GET
&& http.uri == [
  */history/* || */reverse/*
  || */hosting-history/*
  || */whois-history/*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "domaintools.com"
  OR "whoisology.com"
  OR "whoxy.com"
  OR "whoishistory.com"
)
AND url.path: (
  *history* OR *reverse*
  OR *hosting-history*
  OR *whois-history*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.002 Internal
    host WHOIS history query";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    domaintools\\.com|
    whoisology\\.com|
    whoxy\\.com|
    whoishistory\\.com|
    completedns\\.com)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159402; rev:1;)`,
        notes: "WHOIS history services reveal historical registrant data, previous name servers, past IP associations, and ownership changes. Adversaries use this to identify previously used infrastructure and overlooked decommissioned services. DomainTools reverse WHOIS (find all domains registered to the same email/org) maps your entire domain portfolio — extremely high intelligence value.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Uses WHOIS history data to map target organization domain registration history and identify the full domain portfolio." },
          { name: "APT33", cls: "apt-ir", note: "Queries WHOIS history services to identify historically registered domains associated with target organizations." },
          { name: "Multi", cls: "apt-mul", note: "WHOIS history queries from internal hosts against your own domain portfolio are a documented post-compromise intelligence gathering technique." },
        ],
        cite: "MITRE ATT&CK T1596.002, industry reporting"
      },
      {
        sub: "T1596.003 — Passive DNS",
        indicator: "Passive DNS database query — internal host querying pDNS for own infrastructure history",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *passivetotal.org*
  || *api.passivetotal.org*
  || *virustotal.com*
  || *robtex.com*
  || *dnsdb.info*
  || *farsightsecurity.com*
  || *community.riskiq.com*
]
&& http.method == GET
&& http.uri == [
  */dns/passive*
  || */resolutions*
  || */pdns*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "passivetotal.org"
  OR "virustotal.com"
  OR "robtex.com"
  OR "dnsdb.info"
  OR "farsightsecurity.com"
  OR "community.riskiq.com"
)
AND url.path: (
  *dns/passive* OR *resolutions*
  OR *pdns* OR *domain*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.003 Internal
    host passive DNS query own
    infrastructure";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    passivetotal\\.org|
    api\\.passivetotal\\.org|
    virustotal\\.com|robtex\\.com|
    dnsdb\\.info|
    farsightsecurity\\.com|
    community\\.riskiq\\.com)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159403; rev:1;)`,
        notes: "Passive DNS databases record historical DNS resolutions — what IPs a hostname resolved to over time. Internal hosts querying pDNS for your own hostnames map your historical DNS footprint, potentially exposing decommissioned services still in DNS and past infrastructure still accessible. Farsight DNSDB is extremely comprehensive. These queries also create intelligence-leakage risk on top of the detection signal.",
        apt: [
          { name: "APT10", cls: "apt-cn", note: "Queried passive DNS databases to map historical DNS resolutions for MSP customer infrastructure, locating decommissioned but still-accessible services." },
          { name: "APT29", cls: "apt-ru", note: "Used passive DNS data to map infrastructure relationships between target organizations and hosting providers during pre-SolarWinds reconnaissance." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Queries passive DNS databases to track target organization infrastructure changes over time, identifying new services and decommissioned endpoints." },
        ],
        cite: "MITRE ATT&CK T1596.003, industry reporting"
      },
      {
        sub: "T1596.004 — Certificate Transparency",
        indicator: "Certificate Transparency log query — CT log scraping for org subdomain enumeration",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *crt.sh*
  || *certspotter.com*
  || *sslmate.com*
  || *transparencyreport.google.com*
  || *censys.io*
]
&& http.method == GET
&& http.uri == [
  */?q=* || */search*
  || */api/v1/certs*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "crt.sh" OR "certspotter.com"
  OR "sslmate.com"
  OR "censys.io"
  OR "ct.googleapis.com"
)
AND url.path: (
  *?q=* OR *search*
  OR *api/v1/certs*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.004 Internal
    host CT log subdomain query";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    crt\\.sh|certspotter\\.com|
    sslmate\\.com|
    ct\\.googleapis\\.com|
    censys\\.io)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159404; rev:1;)`,
        notes: "Certificate Transparency logs record every TLS certificate issued for your domain — including wildcard certs revealing subdomain patterns, SAN entries listing internal hostnames, and certs for decommissioned services. A crt.sh query for %.yourdomain.com returns every cert ever issued. CT logs are public and queryable without authentication — adversaries use this as a zero-noise subdomain enumeration technique that never touches your infrastructure.",
        apt: [
          { name: "APT41", cls: "apt-cn", note: "Queries CT logs to enumerate subdomains of target organizations before active scanning, identifying dev/staging/internal services with public certs." },
          { name: "APT28", cls: "apt-ru", note: "Uses CT log queries to identify target organization subdomains and map infrastructure scope prior to exploitation." },
          { name: "APT33", cls: "apt-ir", note: "Queries CT logs to identify TLS certificates for energy sector and defense contractor subdomains without any active probing." },
        ],
        cite: "MITRE ATT&CK T1596.004, industry reporting"
      },
      {
        sub: "T1596.004 — Certificate Transparency",
        indicator: "CT stream monitoring — real-time WebSocket feed for newly issued cert tracking",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *certstream.calidog.io*
  || *ct.cloudflare.com*
  || *mammoth.ct.comodo.com*
]
&& protocols == wss
&& databytes.dst > 0`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "certstream.calidog.io"
  OR "ct.cloudflare.com"
  OR "mammoth.ct.comodo.com"
)
AND network.protocol: "websocket"`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.004 Internal
    host CT stream monitoring
    websocket";
  flow:established,to_server;
  content:"certstream"; http.uri;
  content:"Upgrade: websocket";
  http.header;
  classtype:policy-violation;
  sid:9159405; rev:1;)`,
        notes: "CertStream provides a real-time WebSocket feed of all newly issued CT log certificates. A persistent WebSocket connection to certstream.calidog.io from an endpoint that isn't a known security monitoring system is anomalous — it's a running process. Adversaries can use this feed to monitor when you issue new certificates, revealing new services and infrastructure as they come online. Relatively niche but high-signal when it fires from unexpected endpoints.",
        apt: [
          { name: "Multi", cls: "apt-mul", note: "CT stream monitoring from internal hosts is primarily observed in security operations contexts — from unexpected endpoints it indicates adversary automation tracking newly issued infrastructure certificates." },
        ],
        cite: "MITRE ATT&CK T1596.004, industry reporting"
      },
      {
        sub: "T1596.005 — Scan Databases",
        indicator: "Shodan / Censys historical host data API — own infrastructure exposure query",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *api.shodan.io*
  || *search.censys.io*
  || *api.censys.io*
  || *app.binaryedge.io*
]
&& http.method == GET
&& http.uri == [
  */shodan/host/*
  || */v2/hosts/*
  || */api/v2/hosts/search*
  || */v1/query/ip*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "api.shodan.io"
  OR "search.censys.io"
  OR "api.censys.io"
  OR "app.binaryedge.io"
)
AND url.path: (
  *shodan/host*
  OR *v2/hosts*
  OR *hosts/search*
  OR *query/ip*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.005 Internal
    host Shodan/Censys historical
    data query own IP";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    api\\.shodan\\.io|
    search\\.censys\\.io|
    api\\.censys\\.io|
    app\\.binaryedge\\.io)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159406; rev:1;)`,
        notes: "Shodan and Censys host APIs return historical scan data for a specific IP — all open ports ever observed, banners captured, TLS certificates indexed. An internal host querying these APIs for your own IP ranges retrieves exactly what adversaries see when they look you up. Legitimate security team activity — document and baseline it. From unexpected endpoints = compromised host or insider reconnaissance.",
        apt: [
          { name: "Volt Typhoon", cls: "apt-cn", note: "Queried Shodan and Censys host APIs for US critical infrastructure IP ranges to identify historically exposed management interfaces." },
          { name: "APT33", cls: "apt-ir", note: "Used Shodan historical host data to monitor energy sector target infrastructure for new service exposures and version changes." },
          { name: "APT40", cls: "apt-cn", note: "Queries Censys and Shodan APIs for maritime and government target IP ranges to build comprehensive historical exposure profiles." },
        ],
        cite: "MITRE ATT&CK T1596.005, CISA advisories, industry reporting"
      },
      {
        sub: "T1596.005 — Scan Databases",
        indicator: "VirusTotal / OTX / URLScan — own infrastructure submitted to threat intel platform",
        arkime: `ip.src == $INTERNAL
&& http.host == [
  *virustotal.com*
  || *otx.alienvault.com*
  || *urlscan.io*
  || *urlvoid.com*
]
&& http.method == [GET || POST]
&& http.uri == [
  */api/v3/domains/*
  || */api/v3/ip_addresses/*
  || */api/v1/indicators/*
  || */result/* || */scan*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  "virustotal.com"
  OR "otx.alienvault.com"
  OR "urlscan.io"
  OR "urlvoid.com"
)
AND url.path: (
  *api/v3/domains*
  OR *api/v3/ip_addresses*
  OR *api/v1/indicators*
  OR *result* OR *scan*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1596.005 Internal
    host submitting own infra to
    threat intel platform";
  flow:established,to_server;
  pcre:"/Host\\s*:\\s*(
    virustotal\\.com|
    otx\\.alienvault\\.com|
    urlscan\\.io|
    urlvoid\\.com)/ix";
  http.header;
  classtype:policy-violation;
  sid:9159407; rev:1;)`,
        notes: "Submitting your own domain or IP to VirusTotal from an internal host leaks intelligence — VT results are visible to all paid subscribers. A compromised host checking if infrastructure is flagged = adversary verifying C2 isn't burned. URLScan.io takes public screenshots of submitted URLs — submitting an internal URL creates a permanent public screenshot of your internal web applications. Critical OPSEC failure if observed from unexpected endpoints.",
        apt: [
          { name: "Lazarus", cls: "apt-kp", note: "Submitted infrastructure components to threat intel platforms from compromised hosts to verify detection status before deploying additional tooling." },
          { name: "Multi", cls: "apt-mul", note: "Adversaries inside target networks have been documented submitting infrastructure to VT and OTX to verify whether C2 domains and payloads are flagged." },
        ],
        cite: "MITRE ATT&CK T1596.005, industry reporting"
      },
    ]
  },
  {
    id: "T1598",
    name: "Phishing for Information",
    desc: ".001 Spearphishing Service · .002 Spearphishing Attachment · .003 Spearphishing Link",
    rows: [
      {
        sub: "T1598.003 — Spearphishing Link",
        indicator: "Spearphishing link — internal host clicking newly registered suspicious domain",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& tls.cert-notbefore >= now-30d
&& http.host != $KNOWN_GOOD
&& http.host == [
  *login* || *verify*
  || *secure* || *account*
  || *signin* || *auth*
  || *microsoft* || *office365*
]`,
        kibana: `source.ip: $INTERNAL
AND NOT url.domain: $KNOWN_GOOD
AND url.path: (
  *login* OR *verify*
  OR *secure* OR *account*
  OR *update* OR *confirm*
  OR *signin* OR *auth*
)
AND tls.server.not_before:
  [now-30d TO now]`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1598.003 Click to
    suspicious login domain";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/(login|verify|secure|
    account|update|confirm|
    signin|auth)/i";
  http.uri;
  classtype:social-engineering;
  sid:9159801; rev:1;)`,
        notes: "Correlate domain age via threat intel (WHOIS, PassiveDNS). Domains registered within 30 days containing auth-themed keywords are high-risk. Typosquats (micros0ft, g00gle, rn-icrosoft) require fuzzy matching against your known-good list.",
        apt: [
          { name: "APT28", cls: "apt-ru", note: "Used spearphishing links to compromise credentials." },
          { name: "Kimsuky", cls: "apt-kp", note: "Tailored spearphishing emails to gather victim information including contact lists." },
          { name: "ZIRCONIUM", cls: "apt-cn", note: "Targeted presidential campaign staffers with credential phishing emails." },
          { name: "Moonstone Sleet", cls: "apt-kp", note: "Interacted with victims via email to gather information." },
        ],
        cite: "MITRE ATT&CK T1598.003, industry reporting"
      },
      {
        sub: "T1598.003 — Spearphishing Link",
        indicator: "Internal host POSTing credentials to external harvester page",
        arkime: `ip.src == $INTERNAL
&& http.method == POST
&& http.host != $KNOWN_GOOD
&& http.uri == [
  *login* || *signin*
  || *verify* || *auth*
  || *password* || *credential*
]
&& databytes.src > 50
&& databytes.src < 500`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: POST
AND NOT url.domain: $KNOWN_GOOD
AND url.path: (
  *login* OR *signin*
  OR *verify* OR *auth*
  OR *account* OR *password*
)
AND http.request.body.bytes > 50
AND http.request.body.bytes < 500`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1598 Cred POST
    to external URI";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(login|signin|verify|
    auth|account|confirm|
    password|credential)/i";
  http.uri;
  content:"password=";
  http.request_body;
  classtype:social-engineering;
  sid:9159802; rev:1;)`,
        notes: "POST body 50–500 bytes is the sweet spot for a username+password submission. Also match 'passwd=', 'pwd=', 'pass=', 'credential=' variants. Pair with proxy category for the destination domain.",
        apt: [
          { name: "APT33", cls: "apt-ir", note: "Dedicated credential harvesting infrastructure targeting energy/aviation via fake O365/OWA portals." },
          { name: "Charming Kitten", cls: "apt-ir", note: "HYPERSCRAPE tool collects credentials from fake Gmail and Yahoo portals." },
          { name: "APT29", cls: "apt-ru", note: "Used credential harvesting pages as initial access in multiple government intrusions." },
          { name: "Kimsuky", cls: "apt-kp", note: "Deploys credential harvesting pages mimicking Korean government and academic portals." },
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
      {
        sub: "T1598.003 — Spearphishing Link",
        indicator: "AiTM / Evilginx proxy — session cookie harvest post-MFA",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host != $KNOWN_GOOD
&& http.response-header.set-cookie == *
&& tls.cert-cn != $KNOWN_GOOD
&& tls.cert-notbefore >= now-14d`,
        kibana: `source.ip: $INTERNAL
AND NOT tls.server.name: $KNOWN_GOOD
AND http.response.headers.set_cookie: *
AND tls.server.not_before:
  [now-14d TO now]
AND NOT url.domain: $KNOWN_GOOD`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"RECON T1598 AiTM proxy
    Set-Cookie unknown domain";
  flow:established,from_server;
  content:"Set-Cookie:"; http.header;
  content:"Secure"; http.header;
  content:"HttpOnly"; http.header;
  threshold:type both,
    track by_dst, count 2,
    seconds 10;
  classtype:social-engineering;
  sid:9159803; rev:1;)`,
        notes: "AiTM frameworks (Evilginx2, Modlishka, Muraena) proxy the real IdP — MFA succeeds but session token is captured. Look for Secure+HttpOnly cookies set by domains NOT in your IdP list (Okta, Azure AD, Duo). Follow up in identity logs: successful MFA + new device or impossible travel = confirmed incident.",
        apt: [
          { name: "Midnight Blizzard", cls: "apt-ru", note: "Used AiTM phishing against Microsoft corporate and government targets 2023–2024." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Deployed Evilginx2 infrastructure targeting academic and government O365 tenants." },
          { name: "Scattered Spider", cls: "apt-mul", note: "Deployed EvilProxy at scale against MGM Resorts and Caesars Entertainment." },
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
      {
        sub: "T1598.003 — Spearphishing Link",
        indicator: "MFA token harvesting — rapid sequential TOTP/OTP submission",
        arkime: `ip.src != $INTERNAL
&& http.method == POST
&& http.uri == [
  *mfa* || *otp* || *totp*
  || *2fa* || *verify*
  || *code* || *challenge*
]
&& packets.src > 5
&& http.statuscode == [
  200 || 302 || 401
]`,
        kibana: `NOT source.ip: $INTERNAL
AND http.request.method: POST
AND url.path: (
  *mfa* OR *otp* OR *totp*
  OR *2fa* OR *verify*
  OR *code* OR *challenge*
)
AND http.response.status_code:
  (200 OR 302 OR 401)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HTTP_SERVERS any
  (msg:"RECON T1598 MFA OTP
    brute/harvest attempt";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(mfa|otp|totp|2fa|
    verify|challenge|token)/i";
  http.uri;
  threshold:type both,
    track by_src, count 5,
    seconds 30;
  classtype:attempted-user;
  sid:9159804; rev:1;)`,
        notes: "Real-time kits (EvilProxy) relay OTP within the 30s TOTP window — creates a burst of POSTs to /mfa or /verify endpoints. Also watch for MFA fatigue: repeated push notifications to the same account in short window — visible in IdP logs, not network traffic.",
        apt: [
          { name: "Scattered Spider", cls: "apt-mul", note: "Pioneered MFA fatigue (push bombing) attacks at scale." },
          { name: "Midnight Blizzard", cls: "apt-ru", note: "MFA bypass operations against Microsoft corporate using real-time relay." },
          { name: "Lazarus", cls: "apt-kp", note: "OTP relay against cryptocurrency exchange staff to bypass 2FA." },
          { name: "Kimsuky", cls: "apt-kp", note: "Real-time phishing kits relaying OTP codes during government/policy targeting." },
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
      {
        sub: "T1598.002 — Spearphishing Attachment",
        indicator: "DNS OOB callback — encoded subdomain from phishing document",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.query-type == [A || AAAA || TXT]
&& dns.host != $KNOWN_GOOD
&& dns.host == /[0-9a-f]{8,}\\./
|| dns.host == /[A-Za-z0-9+]{16,}\\./`,
        kibana: `source.ip: $INTERNAL
AND dns.question.type: (
  "A" OR "AAAA" OR "TXT"
)
AND dns.question.name: /
  [0-9a-f]{8,}\\.|
  [A-Za-z0-9]{20,}\\.
/`,
        suricata: `alert dns $HOME_NET any
  -> any any
  (msg:"RECON T1598 OOB DNS
    encoded subdomain callback";
  dns.query;
  pcre:"/^([0-9a-f]{8,}|
    [A-Za-z0-9+\\/]{16,})\\./i";
  classtype:attempted-recon;
  sid:9159805; rev:1;)`,
        notes: "DOCX remote templates, OLE links, XXE, SVG/CSS imports fire DNS lookups encoding victim hostname/user/IP in the subdomain. TXT queries used for data exfil. Flag any internal host resolving a subdomain with 8+ consecutive hex chars or 16+ base64 chars.",
        apt: [
          { name: "APT40", cls: "apt-cn", note: "Remote template injection with OOB DNS callbacks to confirm document opens in maritime/government targeting." },
          { name: "APT28", cls: "apt-ru", note: "DNS OOB extensively in spearphishing document delivery for victim profiling." },
          { name: "APT35", cls: "apt-ir", note: "Burp Collaborator-style callbacks in credential harvesting campaigns." },
          { name: "Kimsuky", cls: "apt-kp", note: "OOB DNS callbacks in documents targeting South Korean government and US think tanks." },
        ],
        cite: "MITRE ATT&CK T1598.002, industry reporting"
      },
      {
        sub: "T1598.002 — Spearphishing Attachment",
        indicator: "Remote template fetch — post-email open outbound connection",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.uri == [
  *.dotx* || *.dot*
  || *.xltx* || *.potx*
  || *.sct* || *.hta*
  || *.wsdl*
]
&& http.host != $KNOWN_GOOD
&& http.referrer == [
  *outlook* || *mail*
  || *webmail* || *owa*
]`,
        kibana: `source.ip: $INTERNAL
AND NOT url.domain: $KNOWN_GOOD
AND url.path: (
  *.dotx* OR *.dot*
  OR *.xltx* OR *.potx*
  OR *.sct* OR *.hta*
  OR *.wsdl*
)
AND http.request.referrer: (
  *outlook* OR *mail*
  OR *webmail* OR *owa*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"RECON T1598.002 Remote
    template fetch post-email";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/\\.(dotx?|xltx|potx|
    sct|hta|wsdl)(\\?|$)/i";
  http.uri;
  classtype:social-engineering;
  sid:9159806; rev:1;)`,
        notes: "Clean document fetches malicious template on open (T1221). Outlook/OWA referrer + .dotx from unknown external host is strong correlation. UNC path triggers (SMB to external IP) won't appear in HTTP logs — catch in Zeek conn.log. The document itself evades AV; the network fetch is the only detection opportunity.",
        apt: [
          { name: "APT40", cls: "apt-cn", note: "Remote template injection in spearphishing docs targeting maritime/defense/government sectors." },
          { name: "APT41", cls: "apt-cn", note: "Remote template injection as supply chain pre-positioning — clean doc passes email gateway scanning." },
          { name: "APT28", cls: "apt-ru", note: "Used .dotx remote templates in election-related targeting of campaign and government staff." },
          { name: "Charming Kitten", cls: "apt-ir", note: "Remote template injection targeting academic and research institutions." },
        ],
        cite: "MITRE ATT&CK T1598.002, T1221, industry reporting"
      },
      {
        sub: "T1598.001 — Spearphishing Service",
        indicator: "Inbound phishing infrastructure — newly registered MX hitting mail gateway",
        arkime: `ip.dst == $MAIL_SERVERS
&& port.dst == [25 || 587]
&& protocols == smtp
&& ip.src != $KNOWN_MX
&& ip.src != $KNOWN_GOOD
&& tls.cert-notbefore >= now-30d`,
        kibana: `destination.ip: $MAIL_SERVERS
AND destination.port: (25 OR 587)
AND NOT source.ip: $KNOWN_MX
AND NOT source.ip: $KNOWN_GOOD
AND tls.server.not_before:
  [now-30d TO now]`,
        suricata: `alert smtp $EXTERNAL_NET any
  -> $SMTP_SERVERS [25,587]
  (msg:"RECON T1598 Inbound SMTP
    unknown/new sending IP";
  flow:established,to_server;
  content:"EHLO"; nocase;
  threshold:type both,
    track by_src, count 3,
    seconds 60;
  classtype:social-engineering;
  sid:9159807; rev:1;)`,
        notes: "Pair with SPF/DKIM/DMARC fail tags. New sending IP + DMARC fail + auth-themed subject = near-certain spearphish. Enrich against GreyNoise, Spamhaus, AbuseIPDB. Cross-reference vendor email allowlist — legitimate vendors do sometimes send from new IPs.",
        apt: [
          { name: "Charming Kitten", cls: "apt-ir", note: "Rotates dedicated phishing infrastructure per campaign with newly registered domains and fresh IPs." },
          { name: "Kimsuky", cls: "apt-kp", note: "Newly registered domains and fresh IPs for spearphishing against policy orgs and government contractors." },
          { name: "APT29", cls: "apt-ru", note: "Dedicated purpose-built phishing infrastructure in SolarWinds pre-compromise campaign." },
          { name: "Moonstone Sleet", cls: "apt-kp", note: "Interacted with victims via email to gather information and build rapport prior to malicious activity." },
        ],
        cite: "MITRE ATT&CK T1598, industry reporting"
      },
    ]
  }
];
