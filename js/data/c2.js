// TA0011 - Command & Control
// 10 techniques · 74 indicators · network-visible detection focus

const DATA = [
  {
    id: "T1071",
    name: "Application Layer Protocol",
    desc: ".001 Web · .002 File Transfer · .003 Mail · .004 DNS",
    rows: [
      {
        sub: "T1071.001 - Web Protocols",
        indicator: "HTTP beacon - periodic GET to same URI with low jitter, characteristic of Cobalt Strike, Sliver, Mythic, Havoc",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == GET
&& http.uri == [
  */ca || */dpixel
  || */fwlink || */pixel
  || */__utm.gif
  || */jquery-3.3.1.min.js
  || */load || */api/x
]
&& session.duration > 60
&& packets.src < 50
&& session-count groupby
  ip.src,ip.dst > 5
  within 3600s`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  */ca OR */dpixel
  OR */fwlink OR */pixel
  OR */__utm.gif
  OR */jquery-3.3.1.min.js
  OR */load OR */api/x
)
AND network.packets < 50`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1071.001 HTTP
    beacon Cobalt Strike default
    profile URI";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/^\\/(ca|dpixel|fwlink|
    pixel|__utm\\.gif|
    jquery-3\\.3\\.1\\.min\\.js|
    load|api\\/x)(\\?|$)/i";
  http.uri;
  threshold:type both,
    track by_src,
    count 5, seconds 3600;
  classtype:trojan-activity;
  sid:9107101; rev:1;)`,
        notes: "Default Cobalt Strike malleable profiles use predictable URIs - /ca, /dpixel, /fwlink, /pixel, /__utm.gif (mimics Google Analytics), /jquery-3.3.1.min.js (mimics CDN). Customized profiles change these but most operators don't. Beacon periodicity is the more general signal: same internal-to-external pair with low jitter (sleep + small jitter window) over hours. Build per-pair session timing histograms in Kibana - periodic patterns stick out clearly. Pair with low databytes.src (beacon check-in is usually a few hundred bytes max) and low databytes.dst (no commands queued = small response).",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses Cobalt Strike extensively, documented in CISA and NSA advisories on Russian SVR operations." },
          { cls: "apt-cn", name: "APT41", note: "Uses Cobalt Strike with custom malleable profiles in operations against technology, healthcare, and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses Cobalt Strike alongside custom implants in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Cobalt Strike is the most widely abused commercial C2 framework - leaked and cracked versions are used by the majority of ransomware affiliates." }
        ],
        cite: "MITRE ATT&CK T1071.001, S0154 Cobalt Strike, industry reporting"
      },
      {
        sub: "T1071.001 - Web Protocols",
        indicator: "HTTP POST beacon - outbound POST with small body, characteristic of beacon check-in / task response",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == POST
&& databytes.src < 5000
&& databytes.dst < 1000
&& http.uri == [
  */submit.php
  || */api/v1/upload
  || */upload/file
  || */push || */report
]
&& ip.dst != $KNOWN_GOOD
&& session-count groupby
  ip.src,ip.dst > 3
  within 1800s`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: POST
AND http.request.body.bytes < 5000
AND http.response.body.bytes < 1000
AND url.path: (
  *submit.php* OR *api/v1/upload*
  OR *upload/file*
  OR *push* OR *report*
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1071.001 HTTP
    POST beacon small body
    periodic checkin";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/(submit\\.php|api\\/v1\\/
    upload|upload\\/file|push|
    report)/i";
  http.uri;
  threshold:type both,
    track by_src,
    count 3, seconds 1800;
  classtype:trojan-activity;
  sid:9107102; rev:1;)`,
        notes: "POST-based beacons send results back to C2 - typically small encrypted/encoded payloads (a few KB) at regular intervals. Cobalt Strike default profile uses /submit.php; Sliver uses configurable URIs (often /api/...); custom implants use generic-looking endpoints. POST size 1-5KB combined with periodic timing is characteristic. Distinguish from legitimate API traffic by domain reputation and JA3/JA4 fingerprint. Watch for paired GET (task fetch) and POST (result return) sequences from same source-destination pair within seconds of each other - classic beacon RPC pattern.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses HTTPS POST beacons in Cobalt Strike and custom implant operations." },
          { cls: "apt-cn", name: "APT10", note: "Uses POST-based C2 in MSP-targeting operations during Cloud Hopper." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses POST beacons in custom implants targeting financial and cryptocurrency exchange organizations." }
        ],
        cite: "MITRE ATT&CK T1071.001, industry reporting"
      },
      {
        sub: "T1071.001 - Web Protocols",
        indicator: "HTTPS beacon - periodic TLS sessions to same destination with low jitter and small data volumes",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& port.dst == 443
&& packets.src < 30
&& packets.dst < 30
&& databytes.src < 10000
&& session.duration < 5
&& session-count groupby
  ip.src,ip.dst > 10
  within 3600s
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND network.transport: tcp
AND network.packets < 30
AND network.bytes < 10000
AND event.duration < 5000000
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1071.001 HTTPS
    periodic short beacon possible
    C2 checkin";
  flow:established,to_server;
  content:"|16 03|"; depth:2;
  threshold:type both,
    track by_src,
    count 10, seconds 3600;
  classtype:trojan-activity;
  sid:9107103; rev:1;)`,
        notes: "HTTPS beacons are the dominant modern C2 channel. The signal isn't in the encrypted payload - it's in the connection metadata: short sessions (under 5s), low packet count (under 30 each way), small data volume (under 10KB), regular timing to same destination. Build a beacon detection model on flow records: same src-dst pair, sessions within 10% of a fixed interval, low data volumes, sustained over 1+ hour. Open-source: RITA (Real Intelligence Threat Analytics) and AC-Hunter implement this analysis on Zeek conn.log. False positives: software update checks, telemetry, push notification keepalives - baseline these with allowlist and high-volume known endpoints first.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Uses HTTPS C2 with Cobalt Strike, BEACON, and custom .NET implants." },
          { cls: "apt-cn", name: "APT41", note: "Uses HTTPS C2 with Cobalt Strike and custom implants." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses HTTPS C2 with custom implants in financial sector targeting." },
          { cls: "apt-ir", name: "APT33", note: "Uses HTTPS C2 with custom implants in energy sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Periodic beacon timing analysis is documented as a primary network-layer C2 detection method in MITRE D3FEND and Active Countermeasures (RITA) research." }
        ],
        cite: "MITRE ATT&CK T1071.001, MITRE D3FEND, industry research"
      },
      {
        sub: "T1071.001 - Web Protocols",
        indicator: "HTTP User-Agent anomaly - non-browser UA on browser-like traffic, missing UA, or known-malicious UA",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.user-agent == [
  *python-requests*
  || *Go-http-client*
  || *curl/* || *Wget/*
  || *PowerShell*
  || *Microsoft BITS*
  || *WinHTTP*
  || *Mozilla/4.0*
]
&& ip.dst != $KNOWN_GOOD
&& port.dst == [80 || 443]`,
        kibana: `source.ip: $INTERNAL
AND user_agent.original: (
  *python-requests*
  OR *Go-http-client*
  OR *curl/* OR *Wget/*
  OR *PowerShell*
  OR *Microsoft BITS*
  OR *WinHTTP*
  OR *Mozilla/4.0*
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1071.001 Non
    browser User-Agent suspicious
    HTTP client";
  flow:established,to_server;
  content:"User-Agent|3a|";
  http.header;
  pcre:"/User-Agent:\\s*
    (python-requests|
    Go-http-client|curl\\/|
    Wget\\/|PowerShell|
    Microsoft BITS|WinHTTP|
    Mozilla\\/4\\.0)/i";
  http.header;
  classtype:trojan-activity;
  sid:9107104; rev:1;)`,
        notes: "User-Agent strings reveal the HTTP library used - python-requests, Go-http-client, curl, wget, PowerShell, WinHTTP, BITS - which from end-user workstations browsing the web is anomalous. Mozilla/4.0 (no version after) is a hardcoded UA in many implants and old Cobalt Strike profiles. Empty or missing User-Agent on outbound HTTP is also suspicious - every legitimate browser sets one. Custom UAs containing only the OS name or a single word are common implant signatures. False positives: actual scripts, package managers (pip, npm), update agents - baseline these by pairing UA with destination domain (pip + pypi.org = legit; pip + unknown-domain = suspicious).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Uses custom Go-based implants generating Go-http-client User-Agent strings." },
          { cls: "apt-ru", name: "APT28", note: "Uses PowerShell-based payloads with characteristic PowerShell UA." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses custom Windows implants with WinHTTP and BITS user agents." },
          { cls: "apt-mul", name: "Multi", note: "Mozilla/4.0 hardcoded UA is documented in numerous threat intel reports as an indicator of older Cobalt Strike profiles and custom implants." }
        ],
        cite: "MITRE ATT&CK T1071.001, industry reporting"
      },
      {
        sub: "T1071.002 - File Transfer Protocols",
        indicator: "Outbound FTP from non-file-server host - interactive FTP session for C2 or staging",
        arkime: `ip.src == $INTERNAL
&& ip.src != $FILE_SERVERS
&& protocols == ftp
&& port.dst == 21
&& ip.dst != $KNOWN_GOOD
&& session.duration > 30`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $FILE_SERVERS
AND destination.port: 21
AND network.protocol: ftp
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 21
  (msg:"TA0011 T1071.002 Outbound
    FTP from non-file-server host
    possible C2";
  flow:established,to_server;
  content:"USER "; depth:5;
  classtype:trojan-activity;
  sid:9107105; rev:1;)`,
        notes: "FTP (TCP/21) is largely deprecated for legitimate use - SFTP, FTPS, and HTTPS file transfer have replaced it. End-user workstations and application servers shouldn't initiate outbound FTP. When they do, it's often legacy systems pulling from internal mirrors (legitimate but should be on internal IPs only) or implants using FTP as a low-sophistication C2/exfil channel. The USER command at the start of the session reveals the username being used - adversary credentials often appear here in cleartext. Zeek ftp.log captures the full transaction including filenames transferred. FTP data channel uses dynamic ports (passive mode) - the control channel on 21 is what's reliably visible.",
        apt: [
          { cls: "apt-ir", name: "APT33", note: "Has used FTP for C2 and exfiltration in operations against energy sector targets." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used FTP-based exfiltration in financial sector operations." },
          { cls: "apt-mul", name: "Multi", note: "FTP-based C2 is documented in older campaign reporting and remains in use by some criminal actors as a low-sophistication channel." }
        ],
        cite: "MITRE ATT&CK T1071.002, industry reporting"
      },
      {
        sub: "T1071.002 - File Transfer Protocols",
        indicator: "SMB outbound to internet - C2 channel abusing SMB protocol over external connection",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& ip.dst != $INTERNAL
&& ip.dst != $KNOWN_PARTNERS`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND network.protocol: smb
AND NOT destination.ip: $INTERNAL
AND NOT destination.ip: $KNOWN_PARTNERS`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 445
  (msg:"TA0011 T1071.002 Outbound
    SMB to internet possible C2
    or hash relay";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  classtype:trojan-activity;
  sid:9107106; rev:1;)`,
        notes: "SMB to external destinations is essentially never legitimate - outbound TCP/445 to the internet should be blocked at the perimeter as a basic hygiene control. When it bypasses controls (egress firewall misconfiguration), implants can use SMB for both C2 and credential theft (responder-style hash capture against attacker-controlled SMB servers). The classic indicator: a UNC path injection (\\\\attacker.com\\share) in an Office document or browser that triggers an outbound SMB authentication attempt, leaking the user's NTLM hash to the adversary. Block outbound 445 at the perimeter and alert on any attempt - there's no legitimate reason to allow it.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Has used outbound SMB for credential theft via UNC path injection in document-based phishing operations." },
          { cls: "apt-cn", name: "APT10", note: "Used outbound SMB for credential capture in MSP targeting during Cloud Hopper." },
          { cls: "apt-mul", name: "Multi", note: "Outbound SMB exploitation for credential theft and C2 is documented in CISA and NSA advisories on AD security." }
        ],
        cite: "MITRE ATT&CK T1071.002, T1187, CISA advisories"
      },
      {
        sub: "T1071.003 - Mail Protocols",
        indicator: "Outbound SMTP from non-mail server - C2 or exfil via mail protocol",
        arkime: `ip.src == $INTERNAL
&& ip.src != $MAIL_SERVERS
&& port.dst == [25 || 587 || 465]
&& protocols == smtp
&& ip.dst != $KNOWN_MAIL_PROVIDERS`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $MAIL_SERVERS
AND destination.port: (
  25 OR 587 OR 465
)
AND network.protocol: smtp
AND NOT destination.ip: $KNOWN_MAIL_PROVIDERS`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET [25,465,587]
  (msg:"TA0011 T1071.003 Outbound
    SMTP from non-mail server
    possible C2 or exfil";
  flow:established,to_server;
  content:"EHLO"; depth:4;
  classtype:trojan-activity;
  sid:9107107; rev:1;)`,
        notes: "End-user workstations shouldn't initiate outbound SMTP - mail flows through your authenticated mail relay (Exchange, O365, Google Workspace). Any non-mail-server host initiating outbound SMTP is anomalous. C2-via-email implants (Hammertoss, custom Lazarus implants) use Gmail/Outlook drafts as a dead-drop channel - see T1102.001 for that variant. Direct SMTP to attacker-controlled mail server is more obvious. Watch for outbound 587 (submission) and 465 (SMTPS) in addition to legacy 25 - modern implants typically use the encrypted submission ports. Zeek smtp.log captures HELO/EHLO, MAIL FROM, RCPT TO, and message subject lines.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Has used mail-based C2 channels including Hammertoss-class implants." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used SMTP-based exfiltration in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Mail protocol abuse for C2 is documented in MITRE ATT&CK and is a classic technique for blending into legitimate traffic." }
        ],
        cite: "MITRE ATT&CK T1071.003, industry reporting"
      },
      {
        sub: "T1071.004 - DNS",
        indicator: "DNS tunneling - high volume of long subdomain queries to single domain",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.host =~ /^[a-zA-Z0-9]
  {30,}\\..+/
&& dns.query-count groupby
  dns.host > 50 within 600s`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: dns
AND dns.question.name: /[a-zA-Z0-9]{30,}\\..+/`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0011 T1071.004 DNS
    tunneling long subdomain
    high volume to single domain";
  flow:stateless;
  dns.query;
  pcre:"/^[a-zA-Z0-9]{30,}\\./";
  threshold:type both,
    track by_src,
    count 50, seconds 600;
  classtype:trojan-activity;
  sid:9107108; rev:1;)`,
        notes: "DNS tunneling tools (iodine, dnscat2, DNSExfiltrator, custom implants) encode data in subdomain labels - typically base32 or base64 encoded into 30-63 character subdomain segments. The signal is high query volume to a single registered domain with very long, high-entropy subdomain labels. Iodine specifically uses the format <encoded-data>.tunnel.attacker.com. Calculate Shannon entropy on subdomain strings - encoded data has near-uniform character distribution (entropy >4.5 for base32, >4.8 for base64); legitimate subdomains have lower entropy due to dictionary patterns. False positives: some CDNs use long hash-based subdomains (Akamai, CloudFront) - exclude known CDN domains.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Has used DNS tunneling for C2 and exfiltration in long-running espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Uses DNS-based C2 in custom implants." },
          { cls: "apt-ir", name: "OilRig", note: "Extensively uses DNS tunneling - DNSpionage and Karkoff malware families use DNS as primary C2 against Middle East government and energy targets." }
        ],
        cite: "MITRE ATT&CK T1071.004, CISA advisories"
      },
      {
        sub: "T1071.004 - DNS",
        indicator: "DNS TXT record query volume - TXT-based C2 channel",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.query-type == TXT
&& dns.host != [
  *_dmarc* || *_spf*
  || *_acme-challenge*
  || *_domainkey*
]
&& dns.query-count groupby
  ip.src > 20 within 600s`,
        kibana: `source.ip: $INTERNAL
AND dns.question.type: "TXT"
AND NOT dns.question.name: (
  *_dmarc* OR *_spf*
  OR *_acme-challenge*
  OR *_domainkey*
)`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0011 T1071.004 High
    volume TXT queries to non
    standard targets DNS C2";
  flow:stateless;
  dns.query;
  byte_test:2,=,16,2,relative,big;
  threshold:type both,
    track by_src,
    count 20, seconds 600;
  classtype:trojan-activity;
  sid:9107109; rev:1;)`,
        notes: "DNS TXT records are designed for arbitrary text data - perfect for embedding C2 commands and exfiltrated data. Legitimate TXT queries are rare in normal user traffic - they're typically email validation (SPF, DMARC, DKIM, _domainkey), Let's Encrypt challenges (_acme-challenge), and verification records (_github-challenge, etc). High-volume TXT queries from a workstation to non-validation subdomains is anomalous. Cobalt Strike's DNS C2 mode uses TXT records to tunnel beacon traffic; dnscat2 uses TXT/CNAME/MX. DNS over HTTPS (DoH) bypasses on-network DNS detection - block known DoH endpoints at the firewall and force traffic through your enterprise resolver.",
        apt: [
          { cls: "apt-ir", name: "OilRig", note: "Uses DNS TXT records for C2 in DNSpionage operations against Middle East targets." },
          { cls: "apt-ru", name: "APT29", note: "Has used DNS TXT-based C2 channels." },
          { cls: "apt-cn", name: "APT41", note: "Uses DNS-based C2 with TXT records in custom implants." }
        ],
        cite: "MITRE ATT&CK T1071.004, industry reporting"
      },
      {
        sub: "T1071.004 - DNS",
        indicator: "DNS NULL / CNAME chain abuse - non-standard record type C2",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.query-type == [
  NULL || CNAME
  || PTR || MX
]
&& dns.host != $KNOWN_GOOD_DOMAINS
&& dns.response-size > 200
&& dns.query-count groupby
  ip.src > 30 within 600s`,
        kibana: `source.ip: $INTERNAL
AND dns.question.type: (
  "NULL" OR "CNAME"
  OR "PTR" OR "MX"
)
AND NOT dns.question.name:
  $KNOWN_GOOD_DOMAINS
AND dns.answer.bytes > 200`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0011 T1071.004 DNS NULL
    record query unusual record
    type C2";
  flow:stateless;
  dns.query;
  byte_test:2,=,10,2,relative,big;
  threshold:type both,
    track by_src,
    count 30, seconds 600;
  classtype:trojan-activity;
  sid:9107110; rev:1;)`,
        notes: "DNS NULL records (type 10) are rarely used legitimately - they were intended for experimental data and are essentially unused outside C2 abuse. Iodine uses NULL records in default mode because they can carry the most data (no formatting restrictions). Any NULL query from a workstation is highly suspicious. CNAME chain abuse - many CNAME records resolved in sequence - can encode data in the chain. MX record queries from workstations are also anomalous (mail clients query MX for the destination domain, but workstations don't normally do this). Build per-host DNS query type baselines: a workstation querying types other than A/AAAA in volume = anomaly worth investigating.",
        apt: [
          { cls: "apt-ir", name: "OilRig", note: "Has used non-standard DNS record types in DNSpionage and Karkoff malware C2 channels." },
          { cls: "apt-ru", name: "APT29", note: "Has demonstrated capability for advanced DNS-based C2 across multiple operations." },
          { cls: "apt-mul", name: "Multi", note: "NULL record and CNAME chain abuse for C2 is documented in academic research on DNS tunneling tools (iodine, dnscat2)." }
        ],
        cite: "MITRE ATT&CK T1071.004, academic research"
      },
      {
        sub: "T1071.004 - DNS",
        indicator: "DNS query to newly registered or low-reputation domain - first-seen C2 lookup",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.host != $KNOWN_GOOD
&& dns.host-age < 7d
&& dns.query-count groupby
  dns.host > 5 within 3600s`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: dns
AND dns.question.name:
  $NEWLY_REGISTERED_DOMAINS`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0011 T1071.004 DNS
    query to newly registered
    domain possible C2 lookup";
  flow:stateless;
  dns.query;
  classtype:trojan-activity;
  sid:9107111; rev:1;)`,
        notes: "Repeated DNS queries from a workstation to a domain registered in the last 7 days is a high-confidence C2 indicator. Most legitimate domains accessed by enterprise users have been around for years. Newly registered domain (NRD) data is available from threat intel feeds (DomainTools, Whoisxml, SecurityTrails). Integrate with Suricata rule sets via lua scripts or with Kibana via threat intel enrichment. Pair with low-reputation TLD (.xyz, .top, .pw, .tk, .ml, .ga, .cf) detection - combination of NRD + low-rep TLD is near-certain malicious infrastructure. Zeek dns.log + passive DNS database (CIRCL, DomainTools, VirusTotal) makes this a powerful retro-hunt capability.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Routinely registers domains days before campaigns and burns them after operations." },
          { cls: "apt-cn", name: "APT41", note: "Rotates C2 infrastructure on newly registered domains." },
          { cls: "apt-ru", name: "APT28", note: "Uses NRD-based C2 infrastructure rotation." },
          { cls: "apt-mul", name: "Multi", note: "Newly registered domain detection is a primary threat hunting technique documented in SANS, CISA, and industry threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1071.004, T1583.001, industry reporting"
      }
    ]
  },
  {
    id: "T1568",
    name: "Dynamic Resolution",
    desc: ".001 Fast Flux · .002 DGA · .003 DNS Calculation",
    rows: [
      {
        sub: "T1568.002 - Domain Generation Algorithms",
        indicator: "High NXDOMAIN response rate from single internal host - DGA cycling through generated domains",
        arkime: `ip.dst == $INTERNAL
&& protocols == dns
&& dns.response-code == NXDOMAIN
&& dns.host != $KNOWN_GOOD
&& dns.query-count groupby
  ip.dst > 30 within 600s`,
        kibana: `destination.ip: $INTERNAL
AND network.protocol: dns
AND dns.response_code: "NXDOMAIN"
AND NOT dns.question.name: $KNOWN_GOOD`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0011 T1568.002 High
    NXDOMAIN response rate
    possible DGA cycling";
  flow:stateless;
  dns.response;
  byte_test:1,&,3,3,relative;
  threshold:type both,
    track by_dst,
    count 30, seconds 600;
  classtype:trojan-activity;
  sid:9156801; rev:1;)`,
        notes: "DGA implants generate hundreds to thousands of pseudo-random domains daily and try to resolve them - only the few that the operator has registered will succeed; the rest return NXDOMAIN. The signal is a workstation generating an anomalously high NXDOMAIN rate. Baseline normal NXDOMAIN rates per host (typo'd URLs, expired domains, internal lookup misses) - typically a few per hour at most. A workstation generating 30+ NXDOMAINs in 10 minutes is a strong DGA indicator. Conficker famously generated 50,000 candidate domains daily, of which only ~500 were registered. Modern DGAs (Necurs, Emotet, Qakbot, Murofet) generate 1000-10000 daily candidates. Combine with subdomain entropy analysis on the queried domains.",
        apt: [
          { cls: "apt-mul", name: "Conficker", note: "DGA generated 50,000 candidate domains daily, with the worm reaching ~9 million infected hosts at peak." },
          { cls: "apt-mul", name: "Emotet", note: "Uses DGA for C2 resilience across banking trojan operations." },
          { cls: "apt-mul", name: "Qakbot", note: "Uses DGA for C2 resilience in banking trojan operations." },
          { cls: "apt-ru", name: "APT29", note: "Used DGA-style domain generation in custom implants including the SUNBURST DGA observed in the SolarWinds compromise." }
        ],
        cite: "MITRE ATT&CK T1568.002, industry reporting"
      },
      {
        sub: "T1568.002 - Domain Generation Algorithms",
        indicator: "High-entropy domain queries - algorithmically generated subdomain or domain string",
        arkime: `ip.src == $INTERNAL
&& protocols == dns
&& dns.host =~ /^[a-z0-9]
  {12,30}\\.(com|net|org|info|
  biz|us|ru|cn|tk|ml|ga|cf|
  xyz|top|online|site)$/
&& dns.host != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND dns.question.name: /[a-z0-9]{12,30}\\.(com|net|org|info|biz|tk|ml|xyz|top)/
AND NOT dns.question.name: $KNOWN_GOOD`,
        suricata: `alert dns $HOME_NET any
  -> any 53
  (msg:"TA0011 T1568.002 High
    entropy domain query possible
    DGA";
  flow:stateless;
  dns.query;
  pcre:"/^[a-z0-9]{12,30}\\.
    (com|net|org|info|biz|us|
    ru|cn|tk|ml|ga|cf|xyz|top|
    online|site)$/i";
  classtype:trojan-activity;
  sid:9156802; rev:1;)`,
        notes: "DGA-generated domains have characteristic structure: 12-30 character base label with high character entropy (no dictionary words, near-uniform character distribution). Most DGAs target common TLDs (.com, .net, .org) with some variation in cheap TLDs. Calculate Shannon entropy on the second-level domain - DGA domains score >3.5; legitimate domains usually <3.0 due to dictionary words and brand patterns. Build word-list filters: domains where >30% of characters form recognizable English (or target-language) substrings are likely legitimate. False positives: hash-named CDN endpoints (CloudFront, Akamai), some shorteners (bit.ly looks DGA-like). Maintain an exclusion list of known high-entropy legitimate domains.",
        apt: [
          { cls: "apt-mul", name: "Conficker", note: "Generated high-entropy DGA domains across many TLDs." },
          { cls: "apt-mul", name: "Necurs", note: "Used DGA-based C2 across long-running spam botnet operations." },
          { cls: "apt-mul", name: "Emotet", note: "Used DGA in banking trojan and dropper operations." },
          { cls: "apt-ru", name: "APT29", note: "SUNBURST malware used DGA-generated subdomains under avsvmcloud.com encoding victim domain identifiers." }
        ],
        cite: "MITRE ATT&CK T1568.002, academic research"
      },
      {
        sub: "T1568.002 - Domain Generation Algorithms",
        indicator: "Sequential failed DNS lookups followed by single successful query - DGA round successful resolution",
        arkime: `ip.dst == $INTERNAL
&& protocols == dns
&& dns.response-code == NXDOMAIN
&& session-count groupby
  ip.dst > 10 within 60s
&& subsequent.dns.response-code
  == NOERROR
&& subsequent.dns.host
  =~ /^[a-z0-9]{10,}\\..+/`,
        kibana: `destination.ip: $INTERNAL
AND network.protocol: dns
AND ((dns.response_code: "NXDOMAIN" AND _exists_: dns.question.name)
  OR (dns.response_code: "NOERROR" AND dns.question.name: /[a-z0-9]{10,}\\..+/))`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0011 T1568.002 NXDOMAIN
    burst followed by successful
    high-entropy resolution DGA
    success";
  flow:stateless;
  dns.response;
  threshold:type both,
    track by_dst,
    count 10, seconds 60;
  classtype:trojan-activity;
  sid:9156803; rev:1;)`,
        notes: "The DGA successful resolution pattern: a flurry of NXDOMAIN responses (the implant trying generated domains) followed by a single NOERROR response (the operator's registered domain). The successful domain is the actual C2 endpoint. Capture this domain immediately - it's an active C2 IOC for the campaign. Build SIEM correlation rules that join NXDOMAIN bursts with subsequent successful queries from the same source within 60 seconds. The successful resolution IP is also a high-value IOC for blocklist propagation. False positive reduction: exclude resolutions to known CDN ranges (CloudFlare, Akamai, AWS) which sometimes appear in DGA-style patterns due to load balancing.",
        apt: [
          { cls: "apt-mul", name: "Conficker", note: "Generated NXDOMAIN-burst-then-success patterns observable across millions of infected hosts." },
          { cls: "apt-mul", name: "Emotet", note: "Banking trojan DGA produced this pattern across criminal operations." },
          { cls: "apt-mul", name: "Qakbot", note: "DGA produced NXDOMAIN burst followed by successful resolution." },
          { cls: "apt-ru", name: "APT29", note: "SUNBURST followed this pattern with avsvmcloud.com subdomain resolution after victim profiling." }
        ],
        cite: "MITRE ATT&CK T1568.002, CISA ED-21-01"
      },
      {
        sub: "T1568.001 - Fast Flux DNS",
        indicator: "Single domain resolving to many IPs across many ASNs in short time - fast flux infrastructure",
        arkime: `protocols == dns
&& dns.response-code == NOERROR
&& dns.host != $KNOWN_CDNS
&& unique-ip-count groupby
  dns.host > 10 within 3600s
&& unique-asn-count groupby
  dns.host > 5 within 3600s`,
        kibana: `network.protocol: dns
AND dns.response_code: "NOERROR"
AND NOT dns.question.name: $KNOWN_CDNS`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0011 T1568.001 Domain
    resolving to many IPs across
    ASNs possible fast flux";
  flow:stateless;
  dns.response;
  threshold:type both,
    track by_src,
    count 10, seconds 3600;
  classtype:trojan-activity;
  sid:9156804; rev:1;)`,
        notes: "Fast flux DNS rapidly rotates A records for a single domain across a pool of compromised hosts (typically residential broadband, IoT devices, or hosting nodes the operator controls). The domain resolves to a different IP every few minutes. Detection signal: a single domain that resolves to many distinct IPs across many distinct ASNs over a short time window. Legitimate use case: large CDNs (CloudFlare, Akamai, AWS) - but these stay within the CDN's own ASN. Fast flux infrastructure spans many unrelated ASNs (residential ISPs from many countries). Maintain a $KNOWN_CDNS exclusion list. Aggregate by registered domain, not just FQDN - fast flux often uses many subdomains under a single registered domain.",
        apt: [
          { cls: "apt-mul", name: "Storm Worm", note: "Pioneered fast flux infrastructure in early criminal botnet operations." },
          { cls: "apt-mul", name: "Avalanche", note: "Operated massive fast flux infrastructure taken down 2016 in international law enforcement operation." },
          { cls: "apt-ru", name: "Sandworm", note: "Has used fast flux infrastructure in operations against Ukrainian targets." },
          { cls: "apt-mul", name: "Multi", note: "Fast flux remains in use by phishing kit operators, exploit kits, and ransomware affiliates." }
        ],
        cite: "MITRE ATT&CK T1568.001, FBI/CISA AA25-093A advisory"
      },
      {
        sub: "T1568.001 - Fast Flux DNS",
        indicator: "Anomalously low DNS TTL on non-CDN domain - fast flux indicator",
        arkime: `protocols == dns
&& dns.response == true
&& dns.ttl < 300
&& dns.host != $KNOWN_CDNS
&& dns.host != $KNOWN_LB`,
        kibana: `network.protocol: dns
AND dns.type: response
AND dns.answers.ttl: [0 TO 300]
AND NOT dns.answers.name: (
  $KNOWN_CDNS OR $KNOWN_LB
)`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0011 T1568.001 Low DNS
    TTL on non-CDN domain
    possible fast flux";
  flow:stateless;
  dns.response;
  byte_test:4,<,300,
    8,relative,big;
  classtype:trojan-activity;
  sid:9156805; rev:1;)`,
        notes: "Fast flux requires very low TTLs (typically 60-300 seconds) so resolvers don't cache stale IPs while the operator rotates the pool. Legitimate low TTLs occur on CDNs and DNS-based load balancers - these need to be in your $KNOWN_CDNS / $KNOWN_LB exclusion lists. After exclusions, low-TTL responses on non-CDN domains are a strong fast flux indicator, especially when combined with high IP/ASN diversity (sid 9156804). Pair these two indicators in your SIEM for high-confidence fast flux identification. Some legitimate websites use low TTLs for rapid failover - most enterprise and small business sites don't.",
        apt: [
          { cls: "apt-mul", name: "Avalanche", note: "Used 60-300 second TTLs across hundreds of thousands of compromised proxy nodes." },
          { cls: "apt-mul", name: "Storm Worm", note: "Used low TTLs for fast flux infrastructure rotation." },
          { cls: "apt-ru", name: "Sandworm", note: "Has used low-TTL fast flux infrastructure in operations against Ukrainian targets." }
        ],
        cite: "MITRE ATT&CK T1568.001, FBI/CISA AA25-093A"
      },
      {
        sub: "T1568.001 - Fast Flux DNS",
        indicator: "NS records changing frequently for same domain - double-flux infrastructure",
        arkime: `protocols == dns
&& dns.query-type == NS
&& dns.host != $KNOWN_GOOD
&& unique-ns-count groupby
  dns.host > 5 within 86400s`,
        kibana: `network.protocol: dns
AND dns.question.type: "NS"
AND NOT dns.question.name: $KNOWN_GOOD`,
        suricata: `alert dns any 53
  -> $HOME_NET any
  (msg:"TA0011 T1568.001 NS
    records frequently changing
    possible double flux";
  flow:stateless;
  dns.response;
  classtype:trojan-activity;
  sid:9156806; rev:1;)`,
        notes: "Double-flux is fast flux taken further - both A records AND NS records for the domain rotate, with the authoritative nameservers themselves running on compromised hosts. This makes takedown extremely difficult because there's no single registrar or hosting provider to contact. The signal: NS records for a domain change multiple times in a 24-hour window. Most legitimate domains have stable NS records for years. Track NS record changes via passive DNS - historical NS data shows whether a domain's nameservers are stable (legitimate) or rotating (double flux). Less common than single-flux but very high-confidence indicator when observed.",
        apt: [
          { cls: "apt-mul", name: "Avalanche", note: "Used double-flux infrastructure with rotating NS records to defeat takedown attempts." },
          { cls: "apt-mul", name: "Storm Worm", note: "Used double-flux for resilient C2 infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Double-flux remains in use by sophisticated phishing kit operators and some criminal C2 infrastructure." }
        ],
        cite: "MITRE ATT&CK T1568.001, academic research"
      },
      {
        sub: "T1568.003 - DNS Calculation",
        indicator: "Internal host querying legitimate service for IP/port calculation seed - DNS calculation precursor",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *icanhazip.com*
  || *ifconfig.me*
  || *api.ipify.org*
  || *checkip.amazonaws.com*
  || *ipinfo.io*
  || *iplogger.org*
  || *worldtimeapi.org*
  || *time.is*
]
&& process != $KNOWN_GOOD_PROCS`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *icanhazip.com*
  OR *ifconfig.me*
  OR *api.ipify.org*
  OR *checkip.amazonaws.com*
  OR *ipinfo.io*
  OR *iplogger.org*
  OR *worldtimeapi.org*
  OR *time.is*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1568.003 IP/time
    lookup possible DNS calculation
    seed";
  flow:established,to_server;
  pcre:"/Host:\\s*(icanhazip|
    ifconfig\\.me|api\\.ipify|
    checkip\\.amazonaws|
    ipinfo\\.io|iplogger\\.org|
    worldtimeapi\\.org|
    time\\.is)/i";
  http.header;
  threshold:type both,
    track by_src,
    count 5, seconds 3600;
  classtype:trojan-activity;
  sid:9156807; rev:1;)`,
        notes: "DNS Calculation derives the C2 endpoint from external data - most commonly the implant queries a legitimate IP-lookup service (icanhazip, ifconfig.me, ipify) or time service (worldtimeapi, time.is) and uses the response in an algorithm to compute the actual C2 IP/port/domain. The lookup itself is benign; the inference comes from process correlation (workstation querying ipify isn't a typical user action) and behavioral context (followed by anomalous outbound connection to a calculated destination). Many implants also use these services just for self-IP discovery (more T1016 Discovery than C2). Combine with subsequent outbound connection analysis: lookup followed quickly by connection to previously-unseen IP = high suspicion.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Has used IP/time lookup services in implant operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used lookup services in self-discovery and DNS calculation." },
          { cls: "apt-cn", name: "APT41", note: "Has used IP lookup services in implant operations." },
          { cls: "apt-mul", name: "Multi", note: "The lookup-service technique is documented in numerous threat intel reports - distinguishing legitimate lookups from C2 calculation requires process correlation." }
        ],
        cite: "MITRE ATT&CK T1568.003, T1016, industry reporting"
      }
    ]
  },
  {
    id: "T1102",
    name: "Web Service",
    desc: ".001 Dead Drop · .002 Bidirectional · .003 One-Way",
    rows: [
      {
        sub: "T1102.001 - Dead Drop Resolver",
        indicator: "Internal host fetching paste from Pastebin / Ghostbin / Hastebin / Rentry - dead drop C2 endpoint resolution",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *pastebin.com*
  || *paste.ee*
  || *hastebin.com*
  || *ghostbin.com*
  || *rentry.co*
  || *ix.io*
  || *0bin.net*
  || *privatebin.info*
]
&& http.method == GET
&& http.uri == [
  */raw/* || */paste/*
  || *.txt
]
&& process != [
  *chrome* || *firefox*
  || *edge* || *safari*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *pastebin.com*
  OR *paste.ee*
  OR *hastebin.com*
  OR *ghostbin.com*
  OR *rentry.co*
  OR *0bin.net*
)
AND http.request.method: GET
AND url.path: (
  */raw/* OR */paste/*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.001 Pastebin
    raw paste fetch possible
    dead drop resolver";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*(pastebin|paste\\.ee
    |hastebin|ghostbin|rentry|
    ix\\.io|0bin|privatebin)/i";
  http.header;
  pcre:"/(\\/raw\\/|\\/paste\\/|\\.txt$)/";
  http.uri;
  classtype:trojan-activity;
  sid:9110201; rev:1;)`,
        notes: "Dead drop resolvers are paste-style services where the adversary publishes the actual C2 endpoint (IP, domain, key, configuration) as a public paste. The implant fetches the paste, parses out the C2 details, and connects to the resolved infrastructure. The paste itself looks like random text or code. Detection signal: workstation processes (non-browsers) fetching raw pastes from paste.ee, pastebin, ghostbin, rentry, etc. Browser fetches are usually a developer or legitimate user; non-browser process fetches via WinHTTP, BITS, PowerShell, curl, python-requests are anomalous. Pair with EDR process telemetry. Block paste sites at proxy if your environment has no legitimate developer use case for them.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Has used pastebin and similar services as dead drop resolvers in custom implants." },
          { cls: "apt-cn", name: "APT41", note: "Uses paste services for C2 endpoint resolution in operations against technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses dead drop resolvers in financial sector targeting." },
          { cls: "apt-ir", name: "OilRig", note: "Has used Pastebin in DNSpionage-related operations." }
        ],
        cite: "MITRE ATT&CK T1102.001, industry reporting"
      },
      {
        sub: "T1102.001 - Dead Drop Resolver",
        indicator: "GitHub Gist or raw repository content fetch from non-developer host - dead drop via GitHub",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *gist.githubusercontent.com*
  || *raw.githubusercontent.com*
  || *gist.github.com*
]
&& http.method == GET
&& process != [
  *git* || *code* || *idea*
  || *vscode* || *chrome*
  || *firefox* || *npm*
  || *pip* || *brew*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *gist.githubusercontent.com*
  OR *raw.githubusercontent.com*
  OR *gist.github.com*
)
AND http.request.method: GET`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.001 GitHub
    raw content fetch from non
    developer host dead drop";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*(gist\\.github|
    raw\\.githubusercontent)/i";
  http.header;
  classtype:trojan-activity;
  sid:9110202; rev:1;)`,
        notes: "GitHub Gists and raw repository content are commonly abused as dead drops because GitHub is essentially impossible to block in modern enterprises. The adversary publishes a gist containing the C2 endpoint configuration, and the implant fetches the raw URL. Detection requires distinguishing legitimate developer activity (git clone, IDE syncing, package managers fetching from GitHub) from anomalous fetches by other processes. EDR process correlation is essential. Build per-host baselines: developer workstations have heavy legitimate GitHub traffic; finance / HR / production server access to gist.githubusercontent.com is highly anomalous. Filter on URL patterns too - implants typically fetch /username/gist-id/raw paths, not browsing patterns.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Has used GitHub Gists as dead drop resolvers in espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses GitHub for C2 configuration and payload hosting in financial sector operations including the 3CX supply chain compromise." },
          { cls: "apt-cn", name: "APT41", note: "Uses GitHub for dead drop and payload hosting." }
        ],
        cite: "MITRE ATT&CK T1102.001, Microsoft MSTIC"
      },
      {
        sub: "T1102.001 - Dead Drop Resolver",
        indicator: "Twitter/X profile or post fetch from non-browser process - social media dead drop",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *twitter.com*
  || *x.com*
  || *api.twitter.com*
  || *nitter.net*
]
&& http.method == GET
&& process != [
  *chrome* || *firefox*
  || *edge* || *safari*
  || *teams* || *outlook*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *twitter.com*
  OR *x.com*
  OR *api.twitter.com*
  OR *nitter.net*
)
AND http.request.method: GET`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.001 Twitter
    fetch from non-browser process
    possible dead drop";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*(twitter\\.com|
    x\\.com|api\\.twitter\\.com|
    nitter\\.net)/i";
  http.header;
  classtype:trojan-activity;
  sid:9110203; rev:1;)`,
        notes: "Hammertoss-class implants (APT29) and similar use Twitter/X as dead drops - the implant fetches a specific Twitter handle's profile or tweets, parses encoded data from the tweet content (often steganographically embedded in images), and uses it to identify the actual C2 endpoint. The technique is OPSEC-optimized: even if the adversary's Twitter account is taken down, the implant continues trying. Detection requires process correlation - non-browser processes fetching twitter.com or x.com are anomalous. Modern variants may use Mastodon, Bluesky, or other federated platforms with similar API patterns.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Hammertoss malware (FireEye/Mandiant 2015) used Twitter as a dead drop resolver - implant queried specific Twitter handles based on a daily algorithm, parsed encoded URLs from tweet content." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used social media platforms for C2 configuration in some operations." },
          { cls: "apt-mul", name: "Multi", note: "Hammertoss influenced subsequent generations of social-media dead drop implants." }
        ],
        cite: "MITRE ATT&CK T1102.001, Mandiant Hammertoss reporting"
      },
      {
        sub: "T1102.002 - Bidirectional Communication",
        indicator: "Discord webhook POST from non-Discord-client process - Discord-based C2 channel",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *discord.com*
  || *discordapp.com*
]
&& http.method == POST
&& http.uri == [
  */api/webhooks/*
  || */api/v*/channels/*/messages*
]
&& process != [
  *Discord* || *chrome*
  || *firefox*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *discord.com*
  OR *discordapp.com*
)
AND http.request.method: POST
AND url.path: (
  */api/webhooks/*
  OR */api/v*/channels/*/messages*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.002 Discord
    webhook POST possible C2
    or exfil channel";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/Host:\\s*(discord(app)?\\.com)/i";
  http.header;
  pcre:"/\\/api\\/(webhooks\\/|v[0-9]+\\/
    channels\\/.+\\/messages)/i";
  http.uri;
  classtype:trojan-activity;
  sid:9110204; rev:1;)`,
        notes: "Discord webhooks (POST to /api/webhooks/{id}/{token}) are extensively abused for C2 and exfiltration - they require no authentication, accept arbitrary message content and file attachments, and the destination URL contains both the channel and credentials in a single string. Stealer malware (Redline, Vidar, Raccoon, Lumma) almost universally uses Discord webhooks for stolen credential exfiltration. Bot API endpoints (/api/v{N}/channels/{id}/messages) provide bidirectional C2. Detection: any non-Discord-client process POSTing to discord.com is suspicious. Many enterprise environments have no legitimate Discord use case - block at proxy.",
        apt: [
          { cls: "apt-mul", name: "Stealer Malware", note: "Discord webhook abuse for credential exfiltration is documented in essentially every modern stealer family (Redline, Vidar, Raccoon, Lumma, Mars Stealer)." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used Discord for C2 infrastructure in some operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Discord-based C2 is documented in numerous criminal operations." }
        ],
        cite: "MITRE ATT&CK T1102.002, industry reporting"
      },
      {
        sub: "T1102.002 - Bidirectional Communication",
        indicator: "Telegram Bot API POST from non-Telegram-client process - Telegram-based C2 channel",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *api.telegram.org*
]
&& http.method == [POST || GET]
&& http.uri == [
  */bot*/sendMessage*
  || */bot*/sendDocument*
  || */bot*/getUpdates*
  || */bot*/sendPhoto*
]
&& process != [
  *Telegram* || *chrome*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: *api.telegram.org*
AND url.path: (
  */bot*/sendMessage*
  OR */bot*/sendDocument*
  OR */bot*/getUpdates*
  OR */bot*/sendPhoto*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.002 Telegram
    Bot API call possible C2 or
    exfil channel";
  flow:established,to_server;
  content:"api.telegram.org";
  http.header;
  pcre:"/\\/bot[0-9]+:[A-Za-z0-9_-]+\\/
    (sendMessage|sendDocument|
    sendPhoto|getUpdates)/";
  http.uri;
  classtype:trojan-activity;
  sid:9110205; rev:1;)`,
        notes: "Telegram Bot API uses URLs of the form /bot{bot_id}:{bot_token}/{method} - the bot ID and token are embedded in the URL itself, making detection straightforward at the URL pattern level. /sendMessage and /sendDocument are exfil endpoints; /getUpdates polls for incoming commands (the bidirectional C2 pattern). Telegram is heavily abused by Russian-speaking criminal actors for C2 and stealer exfiltration. Like Discord, Telegram is allowlisted in many environments - block api.telegram.org if no legitimate business use case exists.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Extensively uses Telegram for C2 and exfiltration in operations against Ukrainian and European targets." },
          { cls: "apt-mul", name: "Stealer Malware", note: "Stealer malware families (Redline, Lumma, Mars, Raccoon) commonly use Telegram Bot API as an exfiltration channel." },
          { cls: "apt-mul", name: "Ransomware", note: "Telegram-based C2 is documented in CISA and CERT-UA advisories on Russian state-sponsored and criminal operations." }
        ],
        cite: "MITRE ATT&CK T1102.002, CERT-UA advisories"
      },
      {
        sub: "T1102.002 - Bidirectional Communication",
        indicator: "Slack webhook POST from non-Slack-client process - corporate Slack abuse for C2",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *hooks.slack.com*
  || *slack.com*
]
&& http.method == POST
&& http.uri == [
  */services/T*/B*/*
  || */api/chat.postMessage*
  || */api/files.upload*
]
&& process != [
  *Slack* || *chrome*
  || *firefox*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *hooks.slack.com*
  OR *slack.com*
)
AND http.request.method: POST
AND url.path: (
  */services/T*/B*/*
  OR */api/chat.postMessage*
  OR */api/files.upload*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.002 Slack
    webhook POST possible C2 or
    exfil channel";
  flow:established,to_server;
  content:"POST"; http.method;
  pcre:"/Host:\\s*(hooks\\.slack|
    slack)\\.com/i";
  http.header;
  pcre:"/(\\/services\\/T[A-Z0-9]+\\/
    B[A-Z0-9]+|\\/api\\/(chat\\.
    postMessage|files\\.upload))/";
  http.uri;
  classtype:trojan-activity;
  sid:9110206; rev:1;)`,
        notes: "Slack incoming webhooks (https://hooks.slack.com/services/T{team}/B{bot}/{token}) are abused for C2 and exfil similarly to Discord webhooks - no authentication required beyond knowing the URL, accepts arbitrary text and file content. Slack API endpoints (chat.postMessage, files.upload) provide bidirectional C2 with bot token authentication. Detection challenge: Slack is heavily used in enterprises, so blocking is not feasible. Focus on process correlation: legitimate Slack traffic comes from the Slack desktop app, browser tabs, or sanctioned integrations (Jira, GitHub, PagerDuty, Datadog). Anything else POSTing to Slack endpoints is suspicious. Maintain inventory of approved Slack integrations.",
        apt: [
          { cls: "apt-mul", name: "Stealer Malware", note: "Slack webhook abuse documented in security research on cloud-native attack surfaces." },
          { cls: "apt-mul", name: "Insider", note: "The technique is particularly relevant for insider threat scenarios where an authorized user has legitimate Slack access." },
          { cls: "apt-mul", name: "Multi", note: "Stealer malware operators have begun adopting Slack alongside Discord and Telegram." }
        ],
        cite: "MITRE ATT&CK T1102.002, industry reporting"
      },
      {
        sub: "T1102.003 - One-Way Communication",
        indicator: "Cloud storage POST/PUT from non-storage-client process - exfil to Dropbox / OneDrive / Google Drive / Mega",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *content.dropboxapi.com*
  || *graph.microsoft.com*
  || *graph.live.com*
  || *www.googleapis.com*
  || *uploads.mega.nz*
  || *api.box.com*
]
&& http.method == [POST || PUT]
&& process != [
  *Dropbox* || *OneDrive*
  || *Google Drive* || *MEGA*
  || *Box* || *chrome*
]
&& databytes.src > 100000`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *content.dropboxapi.com*
  OR *graph.microsoft.com*
  OR *graph.live.com*
  OR *uploads.mega.nz*
  OR *api.box.com*
)
AND http.request.method: (POST OR PUT)
AND source.bytes > 100000`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.003 Cloud
    storage upload from non-client
    process possible exfil";
  flow:established,to_server;
  pcre:"/(POST|PUT)/"; http.method;
  pcre:"/Host:\\s*(content\\.
    dropboxapi|graph\\.(microsoft|
    live)|www\\.googleapis|
    uploads\\.mega|api\\.box)\\./i";
  http.header;
  classtype:trojan-activity;
  sid:9110207; rev:1;)`,
        notes: "Cloud storage services are heavily abused for exfiltration (T1567 Exfiltration Over Web Service) but also for one-way C2 - implants upload status reports and harvested data to attacker-controlled cloud storage accounts. The detection challenge mirrors Slack: cloud storage clients are legitimate, so process correlation is essential. Focus on the API endpoints (content.dropboxapi.com, graph.microsoft.com, uploads.mega.nz) which are used by the sync clients but also by any custom HTTP code. Mega.nz is particularly favored by criminal actors due to its strong client-side encryption (which also defeats DLP inspection). For Microsoft 365 tenants, audit OAuth grants regularly.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Has used cloud storage services including Dropbox and OneDrive for exfiltration in operations against government and military targets." },
          { cls: "apt-ru", name: "APT29", note: "Has used cloud storage for staging and exfil including via OAuth-granted access to compromised Microsoft 365 tenants." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses cloud storage for exfiltration in financial sector operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Mega.nz is documented as a preferred exfil destination for ransomware affiliates and stealer operators." }
        ],
        cite: "MITRE ATT&CK T1102.003, T1567.002, CISA advisories"
      },
      {
        sub: "T1102.003 - One-Way Communication",
        indicator: "Google Docs / Drive API POST from non-Google-client process - document-based C2 or exfil",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *docs.google.com*
  || *drive.google.com*
  || *www.googleapis.com*
]
&& http.uri == [
  */drive/v*/files*
  || */upload/drive/v*/files*
  || */feeds/*
]
&& process != [
  *Drive* || *chrome*
  || *firefox* || *Backup*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *docs.google.com*
  OR *drive.google.com*
  OR *www.googleapis.com*
)
AND url.path: (
  */drive/v*/files*
  OR */upload/drive/v*/files*
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1102.003 Google
    Drive API call from non-client
    process possible C2";
  flow:established,to_server;
  pcre:"/Host:\\s*(docs|drive)\\.
    google\\.com|www\\.googleapis\\.com/i";
  http.header;
  pcre:"/(\\/drive\\/v[0-9]+\\/files|
    \\/upload\\/drive\\/v[0-9]+\\/
    files|\\/feeds\\/)/";
  http.uri;
  classtype:trojan-activity;
  sid:9110208; rev:1;)`,
        notes: "Google Workspace is one of the most-abused web services for C2 by Iranian and North Korean actors. Charming Kitten (APT35) has used Google Docs/Drive extensively for both C2 and exfiltration - implants read commands from a Google Doc, write results back to it, and upload exfil to Drive. The Google Drive API endpoints (/drive/v3/files, /upload/drive/v3/files) are visible in URL paths even over HTTPS via SNI and request URI inspection. Process correlation: legitimate Drive sync comes from Google Drive client, browsers, or sanctioned backup tools. Audit OAuth grants in your Google Workspace admin console.",
        apt: [
          { cls: "apt-ir", name: "Charming Kitten", note: "(APT35) extensively uses Google Docs and Drive for C2 and exfiltration in operations against academic, NGO, and human rights sector targets." },
          { cls: "apt-kp", name: "Kimsuky", note: "Uses Google Drive for C2 in operations against South Korean government and policy targets." },
          { cls: "apt-ir", name: "APT35", note: "Documented Google Workspace abuse in Google TAG and Microsoft MSTIC reporting." },
          { cls: "apt-mul", name: "Multi", note: "Favored by Iranian and DPRK actors targeting Google-Workspace-heavy organizations." }
        ],
        cite: "MITRE ATT&CK T1102.003, Google TAG reporting"
      }
    ]
  },
  {
    id: "T1573",
    name: "Encrypted Channel",
    desc: ".001 Symmetric Cryptography · .002 Asymmetric Cryptography · TLS fingerprinting and certificate analysis",
    rows: [
      {
        sub: "T1573 - JA3/JA4 Client Fingerprint",
        indicator: "Outbound TLS with known-malicious JA3 / JA4 client fingerprint - implant TLS handshake match",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.ja3 == $MALICIOUS_JA3
|| tls.ja4 == $MALICIOUS_JA4`,
        kibana: `source.ip: $INTERNAL
AND (tls.client.ja3: $MALICIOUS_JA3
  OR tls.client.ja4: $MALICIOUS_JA4)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1573 Known
    malicious JA3 or JA4 client
    fingerprint";
  flow:established,to_server;
  ja3.hash;
  classtype:trojan-activity;
  sid:9157301; rev:1;)`,
        notes: "JA3 (and modern replacement JA4) hashes the client TLS handshake parameters - cipher suites, extensions, elliptic curves, point formats - into a fingerprint that identifies the client implementation. Different TLS libraries produce different fingerprints: Chrome on Windows is one fingerprint; Firefox is another; the Python requests library is another; custom Go implants produce a Go-specific fingerprint. Maintain $MALICIOUS_JA3 and $MALICIOUS_JA4 from threat intel feeds - abuse.ch SSLBL, FoxIO JA4 database, Mandiant fingerprints. JA4 is preferred over JA3 because it includes more handshake elements and is more stable across TLS library versions. Some classic Cobalt Strike default JA3 hashes: 72a589da586844d7f0818ce684948eea, a0e9f5d64349fb13191bc781f81f42e1.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Cobalt Strike JA3 fingerprints documented across SVR operations including SolarWinds compromise." },
          { cls: "apt-cn", name: "APT41", note: "Custom implant JA3 fingerprints documented in technology and gaming sector operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Custom implant TLS fingerprints documented in financial sector operations." },
          { cls: "apt-mul", name: "Multi", note: "JA3 / JA4 fingerprinting is documented as a primary network layer detection method by Salesforce, FoxIO, and Mandiant. The technique scales across all TLS-based C2." }
        ],
        cite: "MITRE ATT&CK T1573, Salesforce JA3, FoxIO JA4"
      },
      {
        sub: "T1573 - JA3/JA4 Client Fingerprint",
        indicator: "JA4 fingerprint anomaly - client fingerprint never seen on this host or VLAN before",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.ja4 != $BASELINE_JA4_BY_HOST
&& session.duration > 30`,
        kibana: `source.ip: $INTERNAL
AND _exists_: tls.client.ja4
AND NOT tls.client.ja4: $HOST_JA4_BASELINE`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1573 First-seen
    JA4 fingerprint on host
    possible new TLS client";
  flow:established,to_server;
  ja3.hash;
  classtype:trojan-activity;
  sid:9157302; rev:1;)`,
        notes: "Per-host JA4 baselining is one of the most powerful TLS-layer detection patterns. Most workstations have a small set of TLS clients in active use: Chrome, Edge, Firefox, the Outlook desktop client, Teams, OneDrive, Slack, a few system utilities. The set of JA4 fingerprints observed on a host is stable. A new JA4 fingerprint appearing on a host - especially making outbound connections to first-seen destinations - is a strong indicator of new code running. Implants written in Go, Rust, Python, or .NET produce distinctive JA4 fingerprints. Build the baseline in Kibana via aggregation: count distinct JA4s per source.ip, alert when new one appears. Worth investigating even when destination is benign - the new TLS client itself is the signal.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Custom Go implants produce Go-specific JA4 fingerprints distinct from any normal user TLS client." },
          { cls: "apt-ru", name: "APT29", note: "Custom .NET implants produce distinctive JA4 fingerprints." },
          { cls: "apt-kp", name: "Lazarus", note: "Custom implant TLS fingerprints documented in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Per-host JA4 baselining is documented in FoxIO and Corelight research as a primary detection method for novel implants." }
        ],
        cite: "MITRE ATT&CK T1573, FoxIO research"
      },
      {
        sub: "T1573 - JA3/JA4 Client Fingerprint",
        indicator: "JA4 fingerprint inconsistent with claimed User-Agent - TLS client lying about browser identity",
        arkime: `ip.src == $INTERNAL
&& protocols == [tls && http]
&& http.user-agent =~ /Mozilla/
&& tls.ja4 != $BROWSER_JA4_RANGE`,
        kibana: `source.ip: $INTERNAL
AND user_agent.original: *Mozilla*
AND _exists_: tls.client.ja4
AND NOT tls.client.ja4: $BROWSER_JA4_RANGE`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1573 JA4 / UA
    mismatch claimed browser TLS
    fingerprint inconsistent";
  flow:established,to_server;
  ja3.hash;
  classtype:trojan-activity;
  sid:9157303; rev:1;)`,
        notes: "Many implants spoof their User-Agent to look like a browser (Mozilla/5.0 with realistic browser version strings) but use a non-browser TLS library underneath, producing a JA4 fingerprint that doesn't match any real browser. The mismatch - claimed Chrome UA + non-Chrome JA4 - is a strong signal. Build $BROWSER_JA4_RANGE from current major browser fingerprints (Chrome, Firefox, Safari, Edge by version) - FoxIO publishes these. Then alert on any host claiming a browser UA but presenting a JA4 outside that range. Especially powerful against Python requests, Go http, and curl-based implants that try to blend in with browser-style UAs.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Documented use of spoofed browser UAs combined with non-browser TLS clients." },
          { cls: "apt-mul", name: "Stealer", note: "Many stealer families use Python or Go HTTP libraries with spoofed Chrome UAs." },
          { cls: "apt-mul", name: "Multi", note: "JA3/JA4-vs-UA correlation is documented in Mandiant, Corelight, and FoxIO threat hunting research." }
        ],
        cite: "MITRE ATT&CK T1573, T1071, FoxIO research"
      },
      {
        sub: "T1573 - JA3S/JA4S Server Fingerprint",
        indicator: "Cobalt Strike team server JA3S / JA4S - server-side TLS fingerprint match",
        arkime: `ip.dst == $INTERNAL
&& protocols == tls
&& tls.ja3s == [
  ec74a5c51106f0419184d0dd08fb05bc
  || 4d2bd7c1c1c1f3e3a6e4dc1b9a8c1234
]
|| tls.ja4s == $CS_JA4S_HASHES`,
        kibana: `_exists_: tls.server.ja3s
AND tls.server.ja3s: (
  "ec74a5c51106f0419184d0dd08fb05bc"
)`,
        suricata: `alert tls $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0011 T1573 Cobalt Strike
    team server JA3S fingerprint";
  flow:established,from_server;
  ja3s.hash;
  classtype:trojan-activity;
  sid:9157304; rev:1;)`,
        notes: "JA3S / JA4S fingerprints the server-side of the TLS handshake - selected cipher suite, extensions chosen, etc. Cobalt Strike team servers running default profiles produce identifiable JA3S hashes that have been documented and tracked. Modern Cobalt Strike operators customize the malleable C2 profile to randomize TLS server behavior, but many don't. Combine JA3 (client) + JA3S (server) for highest confidence - both fingerprints matching known-bad indicates the TLS session is between a known-bad client and known-bad server, which is essentially proof of C2 traffic. Sources for current Cobalt Strike server fingerprints: abuse.ch, Mandiant, ThreatFox.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Cobalt Strike team server fingerprints documented across SVR operations." },
          { cls: "apt-cn", name: "APT41", note: "Cobalt Strike used in operations against technology and gaming sectors." },
          { cls: "apt-mul", name: "Ransomware", note: "Cobalt Strike is the dominant C2 framework in ransomware operations - JA3S hashes documented across ALPHV, LockBit, BlackBasta, Conti operations." },
          { cls: "apt-mul", name: "Multi", note: "Cobalt Strike server fingerprints are tracked by abuse.ch ThreatFox, Mandiant, and Microsoft MSTIC." }
        ],
        cite: "MITRE ATT&CK T1573, abuse.ch ThreatFox, S0154"
      },
      {
        sub: "T1573 - Server Fingerprinting",
        indicator: "Active jARM fingerprint match against known C2 framework - server probing identifies framework",
        arkime: `[Active scanning required - jARM
fingerprint of suspicious external
IPs against database of known
Cobalt Strike, Sliver, Mythic,
Brute Ratel, Havoc team server
fingerprints]
N/A passive Arkime`,
        kibana: `_exists_: jarm.fingerprint
AND jarm.fingerprint: $C2_FRAMEWORK_JARM`,
        suricata: `[Suricata is passive - jARM
requires active probing. Use
companion tool like jarm.py to
fingerprint candidate C2 IPs
identified by other detections]`,
        notes: "jARM (by Salesforce) is an active TLS server fingerprinting tool - sends 10 specifically crafted TLS Client Hellos to a target server, observes the server's responses, and builds a 62-character fingerprint. Different C2 frameworks have characteristic jARM fingerprints due to their default TLS implementations. Workflow: identify candidate C2 IPs from passive detection (beacon timing, JA3 anomaly, certificate analysis); use jARM.py to actively fingerprint them; compare against known C2 framework fingerprints. Cobalt Strike default jARM has been published, as have Sliver, Mythic, Havoc, Brute Ratel defaults. This is an investigation tool, not a real-time alert mechanism - but it's powerful for confirming that a suspicious external IP is running a known C2 framework.",
        apt: [
          { cls: "apt-mul", name: "Cobalt Strike Operators", note: "Default jARM fingerprint published, allowing identification of unmodified team servers." },
          { cls: "apt-mul", name: "Sliver Operators", note: "Default jARM fingerprint published - Sliver-based operations including some criminal and red team activity." },
          { cls: "apt-mul", name: "Multi", note: "jARM is documented as a primary infrastructure attribution tool by Salesforce, Mandiant, and Recorded Future." }
        ],
        cite: "MITRE ATT&CK T1573, Salesforce jARM"
      },
      {
        sub: "T1573 - Certificate Anomalies",
        indicator: "Self-signed TLS certificate on connection to external host - implant team server",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.cert-issuer == tls.cert-subject
&& port.dst == 443
&& ip.dst != $INTERNAL`,
        kibana: `source.ip: $INTERNAL
AND tls.server.x509.issuer.distinguished_name:
  tls.server.x509.subject.distinguished_name
AND destination.port: 443
AND NOT destination.ip: $INTERNAL`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1573 Self-signed
    TLS certificate on external
    connection";
  flow:established,from_server;
  tls.cert_issuer;
  tls.cert_subject;
  classtype:trojan-activity;
  sid:9157306; rev:1;)`,
        notes: "Modern public-internet TLS uses certificates signed by trusted CAs (Let's Encrypt, DigiCert, Sectigo, GoDaddy, etc). A self-signed certificate on an external HTTPS connection is a strong anomaly - operators sometimes deploy self-signed certs on team servers to avoid the work of getting a real cert, or for short-lived infrastructure. Detection: issuer == subject in the certificate chain. Internal services (development environments, IoT devices, internal CAs) legitimately use self-signed certs - exclude internal traffic. The remaining external self-signed traffic is essentially always either misconfigured legitimate infrastructure (rare) or implant infrastructure (common).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used self-signed certs on team server infrastructure." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used self-signed certs in some operations." },
          { cls: "apt-mul", name: "Red Team", note: "Self-signed certificates are common in red team and lower-sophistication criminal operations." }
        ],
        cite: "MITRE ATT&CK T1573, T1583.005"
      },
      {
        sub: "T1573 - Certificate Anomalies",
        indicator: "TLS certificate with default framework subject - Cobalt Strike 'Major Cobalt Strike' or other default cert subjects",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.cert-subject == [
  *Major Cobalt Strike*
  || *cobaltstrike.com*
  || *MetaSploit*
  || *Burp Suite*
  || *empire-server*
]`,
        kibana: `_exists_: tls.server.x509.subject.common_name
AND tls.server.x509.subject.common_name: (
  *Major Cobalt Strike*
  OR *cobaltstrike.com*
  OR *MetaSploit*
  OR *Burp Suite*
  OR *empire-server*
)`,
        suricata: `alert tls $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0011 T1573 Default
    framework certificate subject
    Cobalt Strike or similar";
  flow:established,from_server;
  tls.cert_subject;
  pcre:"/(Major Cobalt Strike|
    cobaltstrike\\.com|MetaSploit|
    Burp Suite|empire-server)/i";
  classtype:trojan-activity;
  sid:9157307; rev:1;)`,
        notes: "Cobalt Strike's default keystore (cobaltstrike.store) contained a self-signed certificate with CN 'Major Cobalt Strike' - this exact string in TLS certificate subjects across thousands of compromised networks is one of the most famously documented C2 indicators. Modern operators replace this default certificate, but a surprising number don't. Other framework default certs to watch for: Metasploit's default 'MetaSploit' subject, Burp Suite's CA cert (sometimes used as a C2 cert by lazy operators), Empire framework defaults. This is a near-zero-FP detection - no legitimate organization would have these strings in their certificate subjects. Worth deploying as a permanent baseline detection.",
        apt: [
          { cls: "apt-mul", name: "Cobalt Strike Operators", note: "'Major Cobalt Strike' default certificate appears in numerous incident reports and ransomware investigations." },
          { cls: "apt-mul", name: "Ransomware", note: "Default Cobalt Strike certificates documented in many ransomware operations including Conti, LockBit, BlackCat affiliate operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented as one of the most reliable Cobalt Strike infrastructure indicators by Mandiant, CrowdStrike, and Microsoft MSTIC." }
        ],
        cite: "MITRE ATT&CK T1573, Cobalt Strike documentation"
      },
      {
        sub: "T1573 - Certificate Anomalies",
        indicator: "Recently-issued Let's Encrypt certificate on connection to first-seen destination",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.cert-issuer == [
  *Let's Encrypt*
]
&& tls.cert-age < 7d
&& ip.dst != $KNOWN_GOOD
&& tls.sni-first-seen == true`,
        kibana: `source.ip: $INTERNAL
AND tls.server.x509.issuer.common_name: *Let's Encrypt*
AND tls.server.x509.not_before: [now-7d TO now]
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1573 Recently
    issued Lets Encrypt cert
    on first contact destination";
  flow:established,from_server;
  tls.cert_issuer;
  content:"Let's Encrypt";
  classtype:trojan-activity;
  sid:9157308; rev:1;)`,
        notes: "Let's Encrypt issues free 90-day TLS certificates with minimal validation - they're heavily used by adversaries for C2 infrastructure because they're free, fast, and provide the same green-padlock UX as commercial certs. The detection signal isn't 'Let's Encrypt cert' (which has many legitimate users) but 'Let's Encrypt cert issued in the last 7 days on a first-contact destination'. Combine with NRD detection (destination is a newly registered domain) for very high confidence. Build per-host destination history; alert when a host establishes its first connection to a destination AND that destination has a recently-issued Let's Encrypt cert AND is a low-reputation domain. This stacked signal is near-certain malicious.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Routinely uses Let's Encrypt certificates on rapidly-rotated C2 infrastructure." },
          { cls: "apt-kp", name: "Lazarus", note: "Uses Let's Encrypt certs across financial sector targeting infrastructure." },
          { cls: "apt-ir", name: "APT33", note: "Documented use of Let's Encrypt for C2 infrastructure." },
          { cls: "apt-mul", name: "Ransomware", note: "Let's Encrypt certs are essentially universal in modern ransomware infrastructure due to free, fast issuance." }
        ],
        cite: "MITRE ATT&CK T1573, T1583.005"
      },
      {
        sub: "T1573 - Custom Cryptography",
        indicator: "High-entropy payload in cleartext protocol - non-TLS encrypted C2 channel",
        arkime: `ip.src == $INTERNAL
&& protocols == [tcp || udp]
&& port.dst != [443 || 22 || 8443]
&& payload-entropy > 7.5
&& session.duration > 60
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND NOT destination.port: (
  443 OR 22 OR 8443
)
AND _exists_: payload.entropy
AND payload.entropy: [7.5 TO 8.0]
AND event.duration > 60000000`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1573.001 High
    entropy payload in cleartext
    protocol custom encryption";
  flow:established,to_server;
  byte_test:1,>,0xFA,0;
  classtype:trojan-activity;
  sid:9157309; rev:1;)`,
        notes: "Some implants use custom symmetric encryption rather than TLS for C2 - RC4, AES with hardcoded keys, XOR-with-rotating-key. The traffic flows over TCP/UDP without TLS handshake but the payload is still encrypted, producing high entropy (close to 8 bits per byte, the maximum). Detection requires payload entropy analysis - Zeek's entropy script (corelight/zeek-spicy-entropy or custom analyzer) calculates Shannon entropy per session. Encrypted traffic without TLS markers (no 16 03 0X TLS record header) on non-standard ports is a strong custom-crypto C2 indicator. T1573.001 specifically covers symmetric crypto; the same indicator catches RC4-based implants from older malware families.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Custom crypto in some implant families documented across operations against financial and cryptocurrency sectors." },
          { cls: "apt-cn", name: "APT41", note: "Custom symmetric encryption in older custom implants." },
          { cls: "apt-ru", name: "Turla", note: "Sophisticated custom encryption in long-running espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Custom-crypto C2 is a hallmark of older and more sophisticated implant families that predate widespread TLS adoption." }
        ],
        cite: "MITRE ATT&CK T1573.001, industry reporting"
      }
    ]
  },
  {
    id: "T1095",
    name: "Non-Application Layer Protocol",
    desc: "ICMP tunneling, raw TCP/UDP shells, abuse of L3/L4 protocols for C2",
    rows: [
      {
        sub: "T1095 - ICMP Tunneling",
        indicator: "ICMP echo with anomalously large payload - tunneled data in ping packets",
        arkime: `ip.src == $INTERNAL
&& protocols == icmp
&& icmp.type == 8
&& packet.size > 100
&& packet-count groupby
  ip.src,ip.dst > 50
  within 600s`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: icmp
AND icmp.type: 8
AND network.bytes > 100`,
        suricata: `alert icmp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1095 Large ICMP
    echo payload possible tunnel";
  itype:8;
  dsize:>100;
  threshold:type both,
    track by_src,
    count 50, seconds 600;
  classtype:trojan-activity;
  sid:9109501; rev:1;)`,
        notes: "Standard ICMP echo (ping) packets carry small payloads - typically 32-64 bytes, all printable ASCII or sequential bytes. ICMP tunnels (ptunnel, icmpsh, custom implants) carry hundreds to thousands of bytes per packet, often encrypted. Detection: ICMP echo packets with payload >100 bytes from internal hosts to external destinations. Pair with high packet rate (50+ pings to same destination in 10 minutes) - legitimate ping rarely sustains this. The tunnel pattern: internal host pinging external IP frequently with full-MTU ICMP payloads = essentially always a tunnel. Block ICMP echo to/from internet at perimeter as basic hygiene.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "ICMP tunneling documented in operations against industrial control system targets in Ukraine." },
          { cls: "apt-cn", name: "APT41", note: "Has used ICMP tunneling in some custom implant operations." },
          { cls: "apt-mul", name: "Multi", note: "ICMP tunneling tools (ptunnel, icmpsh, hans, icmptunnel) are widely available and documented in MITRE ATT&CK and SANS threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1095, SANS threat hunting"
      },
      {
        sub: "T1095 - ICMP Tunneling",
        indicator: "ICMP echo with high-entropy payload - encrypted data in ping",
        arkime: `ip.src == $INTERNAL
&& protocols == icmp
&& icmp.type == 8
&& payload-entropy > 6.5
&& packet.size > 60`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: icmp
AND icmp.type: 8
AND _exists_: payload.entropy
AND payload.entropy: [6.5 TO 8.0]`,
        suricata: `alert icmp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1095 ICMP echo
    with high entropy payload
    encrypted tunnel";
  itype:8;
  dsize:>60;
  classtype:trojan-activity;
  sid:9109502; rev:1;)`,
        notes: "Standard ping payloads have low entropy (sequential bytes, ASCII strings, predictable patterns). Encrypted ICMP tunnel data has near-maximum entropy (>6.5 bits per byte for the data portion). Combine with sid 9109501 (large payload size) for stronger signal. The Zeek ICMP analyzer combined with an entropy script can produce this metric. Most implants don't bother with custom encryption inside ICMP tunnels - XOR or RC4 is common - but the entropy is still elevated above legitimate ping patterns. False positives: some monitoring tools use larger ICMP payloads for testing, but they typically use predictable patterns (entropy <4).",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "ICMP-based C2 with encrypted payloads documented in Ukraine-targeting operations." },
          { cls: "apt-mul", name: "Multi", note: "Entropy-based payload analysis is documented in academic security research and Active Countermeasures (RITA) tooling." }
        ],
        cite: "MITRE ATT&CK T1095, RITA documentation"
      },
      {
        sub: "T1095 - ICMP Tunneling",
        indicator: "Sustained ICMP echo session - long-running ping pattern indicating active tunnel",
        arkime: `ip.src == $INTERNAL
&& protocols == icmp
&& icmp.type == 8
&& packet-count groupby
  ip.src,ip.dst > 100
  within 1800s
&& ip.dst != $INTERNAL
&& ip.dst != $MONITORING_TARGETS`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: icmp
AND icmp.type: 8
AND NOT destination.ip: ($INTERNAL OR $MONITORING_TARGETS)`,
        suricata: `alert icmp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1095 Sustained
    ICMP echo session possible
    active tunnel";
  itype:8;
  threshold:type both,
    track by_src,
    count 100, seconds 1800;
  classtype:trojan-activity;
  sid:9109503; rev:1;)`,
        notes: "Active ICMP tunnels show as sustained ping patterns - hundreds of echo packets over half-hour windows. Legitimate ping use is bursty and short-lived (a few packets to test connectivity, then stops). Continuous ping flow over 30+ minutes from a workstation to an external destination is essentially never legitimate. Build a $MONITORING_TARGETS exclusion for sanctioned ping monitoring (Smokeping, internal monitoring sources pinging known-good targets). After exclusions, this is a near-zero-FP detection. Combine with payload analysis (sid 9109501, 9109502) for definitive identification.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Sustained ICMP C2 documented in operations against industrial control system targets." },
          { cls: "apt-mul", name: "Multi", note: "Sustained ICMP patterns documented as primary tunneling indicator in MITRE ATT&CK and academic research." }
        ],
        cite: "MITRE ATT&CK T1095"
      },
      {
        sub: "T1095 - Raw TCP / UDP Shells",
        indicator: "Outbound connection to known offensive tooling default ports - netcat, msfvenom listener defaults",
        arkime: `ip.src == $INTERNAL
&& port.dst == [
  4444 || 4443 || 1337
  || 31337 || 5555 || 6666
  || 7777 || 8888 || 9999
  || 4242 || 1234 || 12345
]
&& session.duration > 30
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (
  4444 OR 4443 OR 1337
  OR 31337 OR 5555 OR 6666
  OR 7777 OR 8888 OR 9999
  OR 4242 OR 1234 OR 12345
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET
  [4444,4443,1337,31337,5555,
   6666,7777,8888,9999,4242,
   1234,12345]
  (msg:"TA0011 T1095 Outbound
    to known offensive tool
    default port";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9109504; rev:1;)`,
        notes: "Default ports for offensive tools: msfvenom default reverse shell port is 4444, Metasploit handler defaults to 4444, netcat tutorials universally use 4444 or 1337, '31337' (eleet) is a hacker culture port. Sophisticated operators don't use these - but unsophisticated operators, red teams running un-customized tools, and commodity malware do. Worth deploying as low-cost coverage for amateur tradecraft. Production environments should never have legitimate outbound traffic to these ports; if you find any in baseline, investigate immediately. Adding more ports based on your environment's specific exposure is appropriate.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Default Metasploit and netcat ports widely seen in red team and pen test operations." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Default ports common in commodity malware and lower-sophistication criminal operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented as low-precision but useful coverage in MITRE ATT&CK and SANS threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1095, SANS hunting"
      },
      {
        sub: "T1095 - Raw TCP / UDP Shells",
        indicator: "Raw TCP on common web ports without HTTP/TLS - protocol mismatch indicating bind shell",
        arkime: `ip.src == $INTERNAL
&& port.dst == [80 || 443 || 8080 || 8443]
&& protocols != [http || tls]
&& session.duration > 60
&& packets.src > 10
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (
  80 OR 443 OR 8080 OR 8443
)
AND NOT network.protocol: (http OR tls)
AND event.duration > 60000000
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET [80,443,8080,8443]
  (msg:"TA0011 T1095 Raw TCP
    on web port no HTTP/TLS
    possible bind shell";
  flow:established,to_server;
  app-layer-protocol:!http;
  app-layer-protocol:!tls;
  threshold:type both,
    track by_src,
    count 1, seconds 600;
  classtype:trojan-activity;
  sid:9109505; rev:1;)`,
        notes: "Adversaries often use ports 80, 443, 8080, 8443 for raw TCP shells because these ports are universally allowed outbound - but the traffic is raw command/response, not HTTP or TLS. Zeek's Dynamic Protocol Detection (DPD) identifies the actual protocol regardless of port. Raw TCP on a web port = strong indicator. Suricata's app-layer-protocol negation works similarly. The detection catches bind shells, custom binary protocols, encrypted-but-not-TLS payloads, and raw netcat-style channels. False positives: some custom internal applications use raw TCP on web ports (this should be on internal IPs only); some IoT devices use unusual protocols on standard ports.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used raw TCP shells on port 443 to evade content inspection." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used custom protocols on web ports in implant operations." },
          { cls: "apt-mul", name: "Multi", note: "Raw TCP on web ports is a classic evasion technique documented across red team training and threat actor operations." }
        ],
        cite: "MITRE ATT&CK T1095, T1571"
      },
      {
        sub: "T1095 - Raw TCP / UDP Shells",
        indicator: "Raw UDP outbound on non-standard port - UDP-based C2 channel",
        arkime: `ip.src == $INTERNAL
&& protocols == udp
&& port.dst != [
  53 || 123 || 161 || 162
  || 500 || 514 || 1812
  || 1813 || 4500 || 51820
  || 5353 || 67 || 68
]
&& packet-count groupby
  ip.src,ip.dst > 20
  within 600s
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND network.transport: udp
AND NOT destination.port: (
  53 OR 123 OR 161 OR 162
  OR 500 OR 514 OR 1812
  OR 1813 OR 4500 OR 51820
  OR 5353
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert udp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1095 Raw UDP
    outbound on non-standard
    port possible UDP C2";
  flow:to_server;
  threshold:type both,
    track by_src,
    count 20, seconds 600;
  classtype:trojan-activity;
  sid:9109506; rev:1;)`,
        notes: "Outbound UDP traffic from internal hosts is mostly DNS (53), NTP (123), some VPN protocols (500/4500/51820), syslog (514), DHCP (67/68), and a small set of others. Custom UDP C2 channels stand out - high packet rate from internal hosts to external destinations on non-standard UDP ports. Build $KNOWN_GOOD_UDP allowlist for sanctioned UDP traffic (your DNS resolvers, NTP servers, sanctioned VPN endpoints). After exclusions, sustained UDP traffic to external destinations is anomalous. UDP-based C2 is less common than TCP because UDP doesn't provide reliability - but some sophisticated implants use it for stealth (no connection tracking).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used UDP-based custom protocols in some implant operations." },
          { cls: "apt-ru", name: "Sandworm", note: "Has used UDP-based C2 in operations against ICS targets." },
          { cls: "apt-mul", name: "Multi", note: "UDP-based C2 documented in academic security research and threat intelligence reporting." }
        ],
        cite: "MITRE ATT&CK T1095"
      },
      {
        sub: "T1095 - L3/L4 Protocol Abuse",
        indicator: "GRE / SCTP / AH / ESP outbound from non-router host - L3 protocol abuse",
        arkime: `ip.src == $INTERNAL
&& ip.src != $ROUTERS
&& ip.protocol == [
  47 || 132 || 50 || 51
]
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $ROUTERS
AND network.iana_number: (
  47 OR 132 OR 50 OR 51
)`,
        suricata: `alert ip $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1095 GRE SCTP
    AH ESP from non-router host
    L3 protocol abuse";
  ip_proto:47;
  classtype:trojan-activity;
  sid:9109507; rev:1;)`,
        notes: "GRE (protocol 47), SCTP (132), AH (50), and ESP (51) are L3/L4 protocols normally seen between routers and VPN concentrators - not from end-user workstations. When these protocols originate from a workstation IP, it's either a misconfigured tunnel client (rare) or an exotic C2 channel (also rare but very interesting). End-user hosts shouldn't speak GRE outbound. SCTP is occasionally used by SS7-related telecom applications but only on dedicated systems. Protocol abuse for C2 is uncommon but documented - adversaries occasionally use unusual L3 protocols specifically to evade network controls that only inspect TCP/UDP.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Has demonstrated capability with unusual protocols in operations against ICS targets." },
          { cls: "apt-mul", name: "Red Team", note: "Exotic protocol abuse documented in offensive security research." },
          { cls: "apt-mul", name: "Multi", note: "L3 protocol abuse is uncommon but documented in MITRE ATT&CK and academic research." }
        ],
        cite: "MITRE ATT&CK T1095"
      },
      {
        sub: "T1095 - L3/L4 Protocol Abuse",
        indicator: "Anomalous TCP flag combinations - covert channels in TCP header fields",
        arkime: `ip.src == $INTERNAL
&& protocols == tcp
&& tcp.flags == [
  *FIN+URG+PSH*
  || *NULL* || *XMAS*
  || *FIN-only*
]
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND tcp.flags: (
  "FIN+URG+PSH"
  OR "NULL"
  OR "FIN"
)`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1095 Anomalous
    TCP flag combination scan
    or covert channel";
  flags:FPU,12;
  classtype:bad-unknown;
  sid:9109508; rev:1;)`,
        notes: "TCP flag combinations like FIN+URG+PSH (Christmas tree scan), NULL (no flags set), or lone FIN are not used by legitimate TCP stacks - they're either scan attempts or covert channel signaling. Some advanced implants use unusual flag combinations or sequence number patterns for low-bandwidth covert C2 (each connection attempt encodes 1-2 bits of data). The detection catches both reconnaissance scans and the rare custom implant that uses TCP header fields as a covert channel. False positives: stack fingerprinting tools (nmap, masscan with custom options) - these should originate from sanctioned scan sources only. Outbound from a workstation = essentially always anomalous.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "TCP header covert channels are documented in academic security research and offensive security research, though rarely seen in real operations." },
          { cls: "apt-mul", name: "Recon", note: "Christmas tree scans (FIN+URG+PSH) are documented as a network reconnaissance technique." }
        ],
        cite: "MITRE ATT&CK T1095, academic research"
      }
    ]
  },
  {
    id: "T1090",
    name: "Proxy",
    desc: ".001 Internal · .002 External · .003 Multi-hop · .004 Domain Fronting",
    rows: [
      {
        sub: "T1090.001 - Internal Proxy",
        indicator: "Internal host receiving inbound connections from many other internal hosts - pivot / relay infrastructure",
        arkime: `ip.dst == $INTERNAL
&& ip.src == $INTERNAL
&& port.dst == [
  443 || 80 || 8080
  || 22 || 3128 || 1080
  || 8443 || 4444
]
&& unique-src-count groupby
  ip.dst > 5 within 3600s`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $INTERNAL
AND destination.port: (
  443 OR 80 OR 8080
  OR 22 OR 3128 OR 1080
  OR 8443 OR 4444
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET
  [80,443,1080,3128,4444,
   8080,8443,22]
  (msg:"TA0011 T1090.001 Internal
    host receiving from many
    sources possible pivot relay";
  flow:established,to_server;
  threshold:type both,
    track by_dst,
    count 5, seconds 3600;
  classtype:trojan-activity;
  sid:9109001; rev:1;)`,
        notes: "Internal proxies (compromised host used as a pivot for lateral C2 routing) generate a distinctive east-west pattern: a single internal IP receiving inbound connections from many other internal IPs to a single port. Workstations don't normally serve as connection targets for other workstations. Servers that legitimately receive many internal client connections (DCs, file servers, app servers) should be in your asset inventory and excluded from this detection. The remaining hosts that show this pattern - workstation, IoT device, printer, IP camera - receiving many internal connections are anomalous. Pair with EDR for definitive identification of which process is listening. Common Cobalt Strike pivot pattern: SMB beacon listening on \\\\.\\pipe\\beacon or named pipes, or HTTP listener on 8080.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Internal pivoting via Cobalt Strike SMB and HTTP beacons documented in SVR operations." },
          { cls: "apt-cn", name: "APT41", note: "Internal proxies in operations against technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Internal pivot patterns documented in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Internal pivoting via compromised hosts is foundational and used by virtually every advanced threat actor and ransomware affiliate." }
        ],
        cite: "MITRE ATT&CK T1090.001, MITRE D3FEND"
      },
      {
        sub: "T1090.001 - Internal Proxy",
        indicator: "SMB named pipe traffic between internal hosts on non-standard pipe names - Cobalt Strike SMB beacon",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.pipe-name == [
  *MSSE-* || *postex_*
  || *status_* || *msagent_*
  || *paw_* || *DserNamePipe*
  || *ntsvcs_* || *scerpc_*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $INTERNAL
AND destination.port: 445
AND smb.named_pipe: (
  *MSSE-* OR *postex_*
  OR *status_* OR *msagent_*
  OR *paw_* OR *DserNamePipe*
  OR *ntsvcs_* OR *scerpc_*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0011 T1090.001 Cobalt
    Strike SMB beacon named pipe";
  flow:established,to_server;
  content:"|ff 53 4d 42|"; depth:5;
  pcre:"/(MSSE-|postex_|status_|
    msagent_|paw_|DserNamePipe|
    ntsvcs_[0-9]+|
    scerpc_[a-f0-9]{4})/i";
  classtype:trojan-activity;
  sid:9109002; rev:1;)`,
        notes: "Cobalt Strike SMB beacons communicate over named pipes between compromised hosts - the parent beacon connects to the child beacon's named pipe to send commands and receive results. Default pipe names: MSSE-{number}-server (older versions), postex_{hex}, status_{hex}, msagent_{hex}. Operators should customize but many don't. The named pipe abuse is also used by other frameworks: Sliver uses configurable pipe names but defaults are documented. PowerShell Empire used \\\\.\\pipe\\empire-{id}. Detection: Zeek's smb_files.log or smb.log captures pipe names. Operators using completely custom pipe names evade this - but the pattern of internal SMB to non-standard pipes (anything not srvsvc, lsass, samr, netlogon, eventlog, etc.) is itself anomalous and worth alerting on.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Cobalt Strike SMB beacons in lateral movement operations." },
          { cls: "apt-cn", name: "APT41", note: "Cobalt Strike SMB beacons in operations against technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Cobalt Strike SMB beacons in financial sector targeting." },
          { cls: "apt-mul", name: "Ransomware", note: "Default Cobalt Strike pipe names appear in numerous ransomware incident reports across affiliate operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in extensive Mandiant, CrowdStrike, and Microsoft MSTIC research." }
        ],
        cite: "MITRE ATT&CK T1090.001, T1573, S0154"
      },
      {
        sub: "T1090.002 - External Proxy",
        indicator: "Outbound connection to known commercial proxy / VPS provider - adversary infrastructure rental",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $KNOWN_VPS_RANGES
&& port.dst == [
  443 || 80 || 8080 || 22
  || 1080 || 3128 || 4444
]
&& session.duration > 300
&& databytes.src > 10000
&& process != $KNOWN_GOOD_PROCS`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $KNOWN_VPS_RANGES
AND destination.port: (
  443 OR 80 OR 8080 OR 22
  OR 1080 OR 3128 OR 4444
)
AND event.duration > 300000000
AND source.bytes > 10000`,
        suricata: `alert tcp $HOME_NET any
  -> $KNOWN_VPS_RANGES
  [22,80,443,1080,3128,4444,8080]
  (msg:"TA0011 T1090.002 Sustained
    outbound to commercial VPS
    provider possible C2 proxy";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 1, seconds 600;
  classtype:trojan-activity;
  sid:9109003; rev:1;)`,
        notes: "Adversaries rent VPS infrastructure from commercial providers (DigitalOcean, Vultr, Linode, Hetzner, Contabo, AWS, Azure) as proxy/relay nodes. The IPs are legitimate hosting infrastructure but the use case is malicious. Maintain $KNOWN_VPS_RANGES from threat intel feeds (GreyNoise, Censys, ASN-based lists) - note this is NOT a blocklist (legitimate cloud workloads come from these ASNs too) but rather a watchlist for behavioral anomalies. Sustained connections (>5 minutes) carrying meaningful data (>10KB) from end-user workstations to bare-IP VPS endpoints are anomalous - legitimate cloud usage flows through DNS-named services, not random hosting IPs. Combine with destination-IP age (when did your network first see this IP), JA4 fingerprint, and process correlation.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Uses DigitalOcean, Vultr, and other VPS providers extensively for cryptocurrency exchange targeting." },
          { cls: "apt-cn", name: "APT41", note: "Uses commercial VPS for C2 staging." },
          { cls: "apt-ru", name: "APT28", note: "Has used hosting providers across multiple regions." },
          { cls: "apt-ir", name: "APT33", note: "Uses commercial VPS infrastructure in energy sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Commercial VPS rental for C2 is essentially universal across nation-state and criminal threat actors. Documented by Recorded Future, Mandiant, CrowdStrike." }
        ],
        cite: "MITRE ATT&CK T1090.002, industry reporting"
      },
      {
        sub: "T1090.002 - External Proxy",
        indicator: "HTTP CONNECT method outbound - open proxy abuse for tunneling",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == CONNECT
&& ip.dst != $INTERNAL_PROXIES
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: CONNECT
AND NOT destination.ip: $INTERNAL_PROXIES
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1090.002 HTTP
    CONNECT method to external
    open proxy abuse";
  flow:established,to_server;
  content:"CONNECT "; depth:8;
  classtype:trojan-activity;
  sid:9109004; rev:1;)`,
        notes: "HTTP CONNECT is used by web proxies to establish tunnels (typically HTTPS through a forward proxy). Legitimate use: clients configured with $INTERNAL_PROXIES tunneling out via your sanctioned forward proxy. Anomalous use: a workstation issuing CONNECT to an external IP that isn't your proxy - indicates either misconfigured client or implant using an external open proxy as a relay. Open proxies (free, anonymous proxy lists) are heavily abused for adversary anonymization. The CONNECT method is rarely seen in normal HTTP traffic; when it appears outbound to non-corporate-proxy destinations it's a strong signal. Zeek http.log captures the method explicitly.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used open proxy infrastructure in operations." },
          { cls: "apt-ru", name: "APT28", note: "Has used proxy chains in espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Open proxy abuse is documented in numerous threat intel reports - public proxy lists are routinely used by criminal actors and some nation-state operations." }
        ],
        cite: "MITRE ATT&CK T1090.002, industry reporting"
      },
      {
        sub: "T1090.003 - Multi-hop Proxy",
        indicator: "Outbound connection to Tor entry node - first hop into Tor network",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $TOR_NODES
&& port.dst == [
  9001 || 9030 || 9050
  || 9051 || 443 || 80
]
&& session.duration > 30`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $TOR_NODES
AND destination.port: (
  9001 OR 9030 OR 9050
  OR 9051 OR 443 OR 80
)`,
        suricata: `alert tcp $HOME_NET any
  -> $TOR_NODES any
  (msg:"TA0011 T1090.003 Connection
    to Tor entry node multi-hop
    anonymization";
  flow:established,to_server;
  classtype:policy-violation;
  sid:9109005; rev:1;)`,
        notes: "Tor (The Onion Router) routes traffic through 3+ hops with layered encryption - the entry node sees the originating IP but not the destination; the exit node sees the destination but not the originator. From a defender's perspective, you can identify connections to the Tor entry node list (published continuously at check.torproject.org/torbulkexitlist and via the Tor consensus). $TOR_NODES should be auto-updated daily from these sources. Tor is sometimes used legitimately by privacy-conscious users, journalists, and researchers - but in most enterprise environments it's a strong policy violation indicator. Tor browser uses ports 9001, 9030 for relay traffic, 9050 for SOCKS, and increasingly 443/80 for traffic that passes through obfs4 bridges (which themselves require additional detection - see next indicator).",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Has used Tor for C2 and exfiltration in financial sector operations." },
          { cls: "apt-ir", name: "APT33", note: "Has used Tor in operations against energy sector targets." },
          { cls: "apt-mul", name: "Ransomware", note: "BlackCat/ALPHV explicitly markets Tor-based negotiation portals; widely used by ransomware operators." },
          { cls: "apt-mul", name: "Insider", note: "Tor entry node detection is a standard policy enforcement point in enterprise environments for insider threat monitoring." },
          { cls: "apt-mul", name: "Multi", note: "Tor Project maintains public lists of relay and exit nodes for both research and operational defense purposes." }
        ],
        cite: "MITRE ATT&CK T1090.003, T1571, Tor Project documentation"
      },
      {
        sub: "T1090.003 - Multi-hop Proxy",
        indicator: "obfs4 / meek bridge traffic - Tor obfuscation pluggable transport",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.ja3 == [
  e7d705a3286e19ea42f587b344ee6865
  || 7dd50e112cd23734a310b90f6f44a7cd
]
|| tls.cert-subject =~
  /CN=[a-f0-9]{16,}/
&& port.dst == [443 || 80]`,
        kibana: `source.ip: $INTERNAL
AND tls.client.ja3: (
  "e7d705a3286e19ea42f587b344ee6865"
  OR "7dd50e112cd23734a310b90f6f44a7cd"
)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET [80,443]
  (msg:"TA0011 T1090.003 Tor
    pluggable transport obfs4 or
    meek bridge";
  flow:established,to_server;
  ja3.hash;
  classtype:policy-violation;
  sid:9109006; rev:1;)`,
        notes: "Tor pluggable transports (obfs4, meek-azure, snowflake) disguise Tor traffic to bypass network-level Tor blocking. obfs4 uses a custom obfuscated protocol that doesn't match TLS or any standard application protocol - Zeek's protocol detection logs these as 'unknown' protocol on TCP. meek wraps Tor traffic in TLS to legitimate CDN endpoints (Azure CDN, AWS CloudFront historically) - the SNI looks legitimate but the traffic is Tor. Snowflake uses WebRTC over TURN servers. Each has characteristic JA3/JA4 fingerprints because they use custom TLS implementations. Detection on these is harder than entry node lookup but possible with current TLS fingerprint feeds (FoxIO maintains JA4 fingerprints for major pluggable transports). Most enterprise environments should block all pluggable transport traffic.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Has used Tor pluggable transports in some operations." },
          { cls: "apt-mul", name: "Insider", note: "Pluggable transports are commonly used by insiders attempting to evade network-level Tor detection." },
          { cls: "apt-mul", name: "Multi", note: "JA3/JA4 fingerprints for pluggable transport implementations are tracked by FoxIO and other TLS fingerprint research projects." }
        ],
        cite: "MITRE ATT&CK T1090.003, Tor Project documentation"
      },
      {
        sub: "T1090.003 - Multi-hop Proxy",
        indicator: "Residential proxy network endpoint - connection to known consumer-IP proxy services",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $RESIDENTIAL_PROXY_RANGES
&& port.dst == [
  443 || 80 || 8080
  || 1080 || 3128
]
&& session.duration > 60`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: $RESIDENTIAL_PROXY_RANGES
AND destination.port: (
  443 OR 80 OR 8080
  OR 1080 OR 3128
)`,
        suricata: `alert tcp $HOME_NET any
  -> $RESIDENTIAL_PROXY_RANGES
  [80,443,1080,3128,8080]
  (msg:"TA0011 T1090.003 Connection
    to residential proxy network
    endpoint anonymization";
  flow:established,to_server;
  classtype:policy-violation;
  sid:9109007; rev:1;)`,
        notes: "Residential proxy networks (Bright Data formerly Luminati, Oxylabs, Smartproxy, NetNut, IPRoyal) route traffic through real consumer IP addresses - devices owned by users who installed an SDK in exchange for free apps or VPN services. Adversaries use these networks because each request appears to originate from a different residential ISP IP, defeating IP reputation, geolocation analysis, and rate limiting. The destination IPs of these networks change rapidly as the proxy pool rotates. Detection requires threat intel feeds that track residential proxy network IPs. Spur.us specializes in this - both reactive (lookup) and bulk feeds. Residential proxies are also legitimately used by competitive intelligence, ad verification, and price comparison services. Block where no legitimate business case exists.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Uses residential proxies extensively to log into compromised cloud tenants from IPs that match the victim's geographic profile, defeating impossible-travel detection." },
          { cls: "apt-ru", name: "Midnight Blizzard", note: "Documented residential proxy abuse in espionage operations." },
          { cls: "apt-mul", name: "Stealer", note: "Residential proxies used for stealer credential testing and account takeover operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented as an emerging high-priority threat in 2023-2024 threat intelligence reporting from CISA, FBI, and Microsoft MSTIC." }
        ],
        cite: "MITRE ATT&CK T1090.003, CISA AA23-320A"
      },
      {
        sub: "T1090.004 - Domain Fronting",
        indicator: "SNI / Host header mismatch on HTTPS connection - canonical domain fronting signature",
        arkime: `ip.src == $INTERNAL
&& protocols == [tls && http]
&& tls.sni != http.host
&& port.dst == 443
&& tls.sni == [
  *cloudfront.net*
  || *azureedge.net*
  || *fastly.net*
  || *akamaihd.net*
  || *appspot.com*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND _exists_: tls.client.server_name
AND _exists_: http.request.headers.host
AND tls.client.server_name: NOT http.request.headers.host`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1090.004 SNI Host
    header mismatch domain fronting";
  flow:established,to_server;
  tls.sni;
  pcre:"/(cloudfront\\.net|
    azureedge\\.net|fastly\\.net|
    akamaihd\\.net|appspot\\.com)/i";
  classtype:trojan-activity;
  sid:9109008; rev:1;)`,
        notes: "Domain fronting works by presenting one domain in the TLS SNI (the only domain visible to network observers) while sending a different Host header inside the encrypted HTTPS request. CDN edge servers use the SNI to terminate TLS but route based on the inner Host header - meaning the SNI says 'images.bigcorp.com' (legitimate) but the Host header routes to 'attackerc2.com' (also hosted on the same CDN). The mismatch IS the detection. Requires either egress TLS inspection (to see the Host header) or a CDN egress policy enforcing SNI=Host. CloudFront and Google Cloud blocked domain fronting in 2018 by enforcing SNI=Host at the edge - Azure CDN and Fastly didn't fully follow until 2022. Variants persist on smaller CDNs and via SNI manipulation in newer techniques (ESNI, Encrypted ClientHello). Maintain detection coverage even though the technique has been partially mitigated upstream.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Used domain fronting via Google App Engine in operations against US political targets in 2016." },
          { cls: "apt-cn", name: "APT41", note: "Used domain fronting via CloudFront in operations against gaming and technology sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Used domain fronting via Azure CDN in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Documented as a primary CDN-abuse C2 technique in research from FireEye, CrowdStrike, and Microsoft MSTIC." }
        ],
        cite: "MITRE ATT&CK T1090.004, Microsoft MSTIC"
      },
      {
        sub: "T1090.004 - Domain Fronting",
        indicator: "Outbound TLS to high-volume CDN domain on first contact - possible domain fronting endpoint",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.sni == [
  *cloudfront.net*
  || *azureedge.net*
  || *fastly.net*
  || *akamaihd.net*
  || *appspot.com*
  || *cloudfunctions.net*
]
&& tls.sni.first-seen-by-host
  == true
&& session.duration > 60`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND tls.client.server_name: (
  *cloudfront.net*
  OR *azureedge.net*
  OR *fastly.net*
  OR *akamaihd.net*
  OR *appspot.com*
  OR *cloudfunctions.net*
)
AND event.duration > 60000000`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1090.004 First
    contact CDN endpoint sustained
    session possible fronting";
  flow:established,to_server;
  tls.sni;
  pcre:"/(cloudfront\\.net|
    azureedge\\.net|fastly\\.net|
    akamaihd\\.net|appspot\\.com|
    cloudfunctions\\.net)/i";
  classtype:trojan-activity;
  sid:9109009; rev:1;)`,
        notes: "CDN-hosted endpoints carry massive volumes of legitimate traffic - most large websites use CloudFront, Akamai, Fastly, or Azure CDN. The challenge is distinguishing legitimate CDN-fronted services from C2 infrastructure on the same CDN. Per-host first-contact analysis helps: a workstation establishing a sustained connection to a never-before-seen CDN endpoint subdomain is more suspicious than connecting to a popular SaaS service's CDN. Build per-host CDN endpoint history. Pair with destination certificate examination - domain-fronted C2 often uses cloudfront.net wildcard certs while legitimate services use brand-specific certs. Cloud Functions URLs (cloudfunctions.net, *.run.app) are increasingly abused - these are dynamically allocated and trivial for adversaries to register.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "CDN abuse for C2 documented in SVR operations." },
          { cls: "apt-cn", name: "APT41", note: "CDN-fronted C2 documented in operations against technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "CDN-fronted C2 documented in financial sector operations." },
          { cls: "apt-mul", name: "Multi", note: "CDN abuse remains effective because blocking at the CDN-domain level breaks legitimate web access. Per-host first-contact analysis is the defensive operations approach." }
        ],
        cite: "MITRE ATT&CK T1090.004, industry reporting"
      }
    ]
  },
  {
    id: "T1572",
    name: "Protocol Tunneling",
    desc: "SSH tunneling, HTTPS tunneling/WebSocket, layered protocol tunneling (DoH, VPN protocols)",
    rows: [
      {
        sub: "T1572 - SSH Tunneling",
        indicator: "Outbound SSH from non-admin host - workstation or server initiating SSH where it shouldn't",
        arkime: `ip.src == $USER_VLAN
&& ip.src != $ADMIN_HOSTS
&& port.dst == [22 || 2222]
&& protocols == ssh
&& ip.dst != $INTERNAL
&& ip.dst != $KNOWN_GOOD
&& session.duration > 60`,
        kibana: `source.ip: $USER_VLAN
AND NOT source.ip: $ADMIN_HOSTS
AND destination.port: (22 OR 2222)
AND network.protocol: ssh
AND NOT destination.ip: $INTERNAL
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tcp $USER_VLAN any
  -> $EXTERNAL_NET [22,2222]
  (msg:"TA0011 T1572 Outbound SSH
    from non-admin user VLAN
    possible tunnel";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  threshold:type both,
    track by_src,
    count 1, seconds 600;
  classtype:trojan-activity;
  sid:9157201; rev:1;)`,
        notes: "End-user workstations don't typically initiate outbound SSH. When they do, it's usually a developer workflow (which should be allowlisted by host) or a tunneled C2 channel. Build $ADMIN_HOSTS as the explicit allowlist of hosts permitted to initiate outbound SSH. Everything else from $USER_VLAN going to TCP/22 is anomalous. Port 2222 is a common alternative SSH port - adversaries use it because some egress firewalls allow it as 'developer access'. Pair with destination IP reputation and session-duration analysis: long sustained SSH sessions (hours) with bidirectional data transfer are tunnel indicators, not interactive admin sessions which are typically shorter and bursty.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used SSH for C2 in operations targeting Linux infrastructure in technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used SSH tunneling for both C2 and exfiltration in financial sector operations." },
          { cls: "apt-ir", name: "APT33", note: "Documented SSH-based C2 capability." },
          { cls: "apt-mul", name: "Insider", note: "SSH tunneling is also a primary insider-threat exfiltration vector - credentialed users with legitimate SSH access can tunnel arbitrary traffic out." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK T1572 and industry threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1572, industry reporting"
      },
      {
        sub: "T1572 - SSH Tunneling",
        indicator: "SSH session with sustained bidirectional data - long-lived tunnel rather than interactive shell",
        arkime: `protocols == ssh
&& session.duration > 1800
&& databytes.src > 100000
&& databytes.dst > 100000
&& ip.src == $INTERNAL`,
        kibana: `network.protocol: ssh
AND event.duration > 1800000000
AND source.bytes > 100000
AND destination.bytes > 100000
AND source.ip: $INTERNAL`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET [22,2222]
  (msg:"TA0011 T1572 Long-lived
    SSH session sustained data
    transfer possible tunnel";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  threshold:type both,
    track by_src,
    count 1, seconds 1800;
  classtype:trojan-activity;
  sid:9157202; rev:1;)`,
        notes: "Interactive SSH sessions are typically: short bursts of input from the user, larger response from the server (command output), with idle gaps. Tunneled SSH (ssh -L for local port forward, ssh -R for reverse forward, ssh -D for SOCKS proxy) shows sustained bidirectional data flow because real application traffic is flowing through the encrypted tunnel. Build SSH session profiles: ratio of source-to-destination bytes, packet timing distribution, session duration. A 30+ minute session with substantial bidirectional data (>100KB each way) is essentially never an interactive shell - it's a tunnel carrying file transfers, RDP sessions, or other application traffic. Zeek ssh.log captures connection metadata; ssh.log + conn.log together provide the timing and volume analysis surface.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Long-lived SSH tunnels for C2 documented in technology sector operations." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH tunnels for C2 and exfiltration in financial sector." },
          { cls: "apt-mul", name: "Insider", note: "Insider threat exfiltration via SSH tunnels documented in CISA insider threat advisories." },
          { cls: "apt-mul", name: "Ransomware", note: "Long-lived SSH tunnels documented in ransomware operations against Linux infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Volume-and-duration analysis approach documented in research from Active Countermeasures (RITA) and academic security research." }
        ],
        cite: "MITRE ATT&CK T1572, RITA documentation"
      },
      {
        sub: "T1572 - SSH Tunneling",
        indicator: "SSH client banner anomaly - non-OpenSSH client or modified version string",
        arkime: `protocols == ssh
&& ssh.client-banner != [
  *OpenSSH_*
  || *PuTTY_*
  || *libssh*
  || *Cisco-* || *dropbear*
]
&& ip.src == $INTERNAL`,
        kibana: `network.protocol: ssh
AND source.ip: $INTERNAL
AND ssh.client: NOT (
  *OpenSSH* OR *PuTTY*
  OR *libssh* OR *Cisco-*
  OR *dropbear*
)`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 22
  (msg:"TA0011 T1572 Non-standard
    SSH client banner possible
    custom tunnel tool";
  flow:established,from_client;
  content:"SSH-"; depth:4;
  pcre:!"/^SSH-2\\.0-(OpenSSH|
    PuTTY|libssh|Cisco|dropbear)/";
  classtype:trojan-activity;
  sid:9157203; rev:1;)`,
        notes: "SSH client banners (sent in cleartext during handshake before encryption begins) reveal the implementation: OpenSSH_8.9p1, PuTTY_Release_0.78, libssh_0.10.4, Cisco-1.25, dropbear_2022.83. Custom tunneling tools (Chisel, FRP, ngrok-style tunnels using SSH transport) often have characteristic banners or modified versions. Some tunneling tools mimic OpenSSH banners exactly to evade this detection - but many don't. Zeek ssh.log captures both client and server banners. Build a $KNOWN_GOOD_SSH_CLIENTS allowlist of banners observed legitimately in your environment and alert on first-seen banners. New SSH tunneling tools appear regularly - Hexshell, Chisel, Wireguard-over-SSH, Cloudflare Tunnel - keep the allowlist tight and investigate new banners.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used custom SSH-based tunneling tools." },
          { cls: "apt-mul", name: "Red Team", note: "Custom SSH-based tunneling tools (Chisel, FRP, ngrok) are documented red team and threat actor tooling." },
          { cls: "apt-mul", name: "Multi", note: "Banner-based detection documented in offensive security training and Corelight Zeek SSH analyzer documentation." }
        ],
        cite: "MITRE ATT&CK T1572, Corelight documentation"
      },
      {
        sub: "T1572 - HTTPS Tunneling / WebSocket",
        indicator: "HTTP CONNECT method to non-corporate-proxy destination - open tunnel via legitimate proxy",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.method == CONNECT
&& ip.dst != $CORPORATE_PROXIES
&& ip.dst != $KNOWN_GOOD
&& session.duration > 60`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: CONNECT
AND NOT destination.ip: $CORPORATE_PROXIES
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1572 HTTP CONNECT
    to non-corporate proxy
    tunnel attempt";
  flow:established,to_server;
  content:"CONNECT "; depth:8;
  classtype:trojan-activity;
  sid:9157204; rev:1;)`,
        notes: "HTTP CONNECT is the standard mechanism for establishing tunnels through forward proxies. Legitimate use: clients tunneling HTTPS traffic through your corporate forward proxy. Anomalous use: workstation issuing CONNECT to an external endpoint that isn't your sanctioned proxy. The CONNECT target reveals the actual destination - 'CONNECT attackerc2.com:443 HTTP/1.1' shows the target host:port even before the tunnel encrypts. After CONNECT succeeds, the proxy relays raw bytes between client and target (typically TLS); the proxy doesn't see the encrypted content but does see the connection metadata. Detection at the proxy layer is the cleanest place - your corporate forward proxy should log all CONNECT targets and alert on non-allowlisted destinations.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used CONNECT-based tunneling in some operations." },
          { cls: "apt-ru", name: "APT28", note: "Documented use of proxy-based tunneling in espionage operations." },
          { cls: "apt-mul", name: "Insider", note: "CONNECT method abuse is particularly relevant for insider threat scenarios." },
          { cls: "apt-mul", name: "Multi", note: "Documented in offensive security tooling (Squid, 3proxy as relay infrastructure) and in nation-state operations." }
        ],
        cite: "MITRE ATT&CK T1572, T1090, industry reporting"
      },
      {
        sub: "T1572 - HTTPS Tunneling / WebSocket",
        indicator: "WebSocket upgrade on HTTP - long-lived bidirectional channel inside HTTP/HTTPS",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.request-header == [
  *Upgrade: websocket*
  || *Connection: Upgrade*
]
&& session.duration > 600
&& ip.dst != $KNOWN_GOOD
&& process != $KNOWN_GOOD_PROCS`,
        kibana: `source.ip: $INTERNAL
AND http.request.headers.upgrade: "websocket"
AND http.request.headers.connection: *Upgrade*
AND event.duration > 600000000
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1572 WebSocket
    upgrade long-lived channel
    possible tunnel";
  flow:established,to_server;
  content:"Upgrade|3a| websocket";
  http.header; nocase;
  threshold:type both,
    track by_src,
    count 1, seconds 600;
  classtype:trojan-activity;
  sid:9157205; rev:1;)`,
        notes: "WebSocket (RFC 6455) starts as an HTTP/HTTPS request with 'Upgrade: websocket' and 'Connection: Upgrade' headers, then upgrades to a persistent bidirectional channel that bypasses request-response HTTP semantics entirely. Once upgraded, the connection carries arbitrary binary or text data - perfect for C2 tunnels. Legitimate WebSocket use: real-time web applications (Slack, Discord webapp, trading platforms, messaging apps, video conferencing signaling). Detection challenge: distinguishing legitimate WebSocket use from C2 tunnels. Process correlation is the strongest signal - non-browser processes initiating WebSocket connections are highly anomalous. Sustained connections (>10 minutes) to first-seen destinations are anomalous regardless of process. The Upgrade headers are visible in cleartext HTTP and in the cleartext portion of HTTPS (Zeek http.log captures them when decrypting).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Has used WebSocket-based C2 in custom implants." },
          { cls: "apt-kp", name: "Lazarus", note: "Has used WebSocket transport in some implant operations." },
          { cls: "apt-mul", name: "Multi", note: "WebSocket-based C2 documented in modern implant frameworks including Mythic, Sliver (configurable transport), and Havoc. Increasingly common as legitimate WebSocket use is heavy in modern web apps." }
        ],
        cite: "MITRE ATT&CK T1572, T1071.001, industry reporting"
      },
      {
        sub: "T1572 - HTTPS Tunneling / WebSocket",
        indicator: "HTTPS connection with sustained bidirectional flow - tunneled session inside TLS",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& port.dst == 443
&& session.duration > 1800
&& databytes.src > 500000
&& databytes.dst > 500000
&& packets.src > 500
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND network.transport: tcp
AND event.duration > 1800000000
AND source.bytes > 500000
AND destination.bytes > 500000
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1572 Long sustained
    HTTPS heavy bidirectional
    possible tunnel";
  flow:established,to_server;
  content:"|16 03|"; depth:2;
  threshold:type both,
    track by_src,
    count 1, seconds 1800;
  classtype:trojan-activity;
  sid:9157206; rev:1;)`,
        notes: "Most legitimate HTTPS sessions are short - a request, a response, the connection closes (or HTTP/2 multiplexes briefly). Tunneled HTTPS (ngrok, Cloudflare Tunnel, custom tools using HTTPS transport) generates sustained sessions with substantial bidirectional traffic - minutes to hours of session duration with hundreds of KB to MB transferred each way. Build per-host HTTPS session profiles: most workstations have many short sessions; one or two hosts with sustained heavy-bidirectional sessions to first-seen destinations are anomalous. Tools to know: ngrok generates client connections to ngrok.io endpoints; Cloudflare Tunnel uses cloudflared client connecting to *.cloudflareaccess.com or *.argotunnel.com; tailscale uses *.tailscale.com. These are increasingly used for legitimate purposes (development, remote access) - process correlation distinguishes legitimate tool use from implant abuse.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Tunneling tool abuse documented in CISA AA23-320A on operations against hospitality and technology sector targets." },
          { cls: "apt-cn", name: "APT41", note: "Has used tunneling tools in operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Ransomware operators have abused legitimate tunnel services for data staging and C2." },
          { cls: "apt-mul", name: "Multi", note: "CISA and FBI advisories document the trend toward tunneling-tool abuse as a primary alternative to Cobalt Strike - particularly after 2022." }
        ],
        cite: "MITRE ATT&CK T1572, CISA AA23-320A"
      },
      {
        sub: "T1572 - Layered Protocol Tunneling",
        indicator: "DNS-over-HTTPS (DoH) endpoint - bypass of on-network DNS inspection",
        arkime: `ip.src == $INTERNAL
&& protocols == https
&& http.host == [
  *cloudflare-dns.com*
  || *dns.google*
  || *dns.quad9.net*
  || *doh.opendns.com*
  || *dns.adguard.com*
  || *mozilla.cloudflare-dns.com*
]
&& port.dst == 443
&& process != [
  *firefox* || *chrome*
]`,
        kibana: `source.ip: $INTERNAL
AND url.domain: (
  *cloudflare-dns.com*
  OR *dns.google*
  OR *dns.quad9.net*
  OR *doh.opendns.com*
  OR *dns.adguard.com*
)
AND destination.port: 443`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1572 DNS over
    HTTPS DoH endpoint bypass
    of on-network DNS";
  flow:established,to_server;
  tls.sni;
  pcre:"/(cloudflare-dns\\.com|
    dns\\.google|dns\\.quad9\\.net|
    doh\\.opendns\\.com|
    dns\\.adguard\\.com|mozilla\\.
    cloudflare-dns\\.com)/i";
  classtype:policy-violation;
  sid:9157207; rev:1;)`,
        notes: "DNS-over-HTTPS sends DNS queries inside HTTPS to public resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8 via dns.google, Quad9, OpenDNS DoH, AdGuard). When clients use DoH, on-network DNS inspection is bypassed entirely - your enterprise resolver, your DNS-based security tools, and your DNS query telemetry are all blind. Browsers (Firefox by default since 2020, Chrome opt-in) use DoH legitimately, which is itself a problem for defenders. Non-browser processes connecting to DoH endpoints are highly anomalous - there's no legitimate reason for a generic application to bypass system DNS resolution. Block known DoH endpoints at the firewall (the SNI is visible) and force DNS through your enterprise resolver. This is essential hygiene for environments with serious DNS-based detection (DGA, NRD, tunnel detection from T1568 and T1071.004 - all bypassed by DoH).",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Has used DoH-capable implants for DNS-based C2 evading on-network detection." },
          { cls: "apt-cn", name: "APT41", note: "Implants increasingly support DoH transport." },
          { cls: "apt-kp", name: "Lazarus", note: "DoH-capable implants documented in financial sector operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented as a high-priority defensive concern in NSA, CISA, and SANS network defense guidance." }
        ],
        cite: "MITRE ATT&CK T1572, T1071.004, NSA DoH guidance"
      },
      {
        sub: "T1572 - Layered Protocol Tunneling",
        indicator: "Wireguard / OpenVPN UDP traffic from non-VPN-client host - VPN protocol as covert tunnel",
        arkime: `ip.src == $INTERNAL
&& protocols == udp
&& port.dst == [
  51820 || 1194 || 4500
  || 500
]
&& ip.dst != $CORPORATE_VPN
&& ip.dst != $KNOWN_GOOD
&& process != [
  *VPN* || *OpenVPN*
  || *Wireguard* || *Tunnelblick*
]`,
        kibana: `source.ip: $INTERNAL
AND network.transport: udp
AND destination.port: (
  51820 OR 1194 OR 4500 OR 500
)
AND NOT destination.ip: $CORPORATE_VPN
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert udp $HOME_NET any
  -> $EXTERNAL_NET
  [500,1194,4500,51820]
  (msg:"TA0011 T1572 VPN protocol
    UDP from non-VPN-client host
    possible covert tunnel";
  flow:to_server;
  threshold:type both,
    track by_src,
    count 5, seconds 60;
  classtype:trojan-activity;
  sid:9157208; rev:1;)`,
        notes: "Wireguard (UDP/51820), OpenVPN (UDP/1194), IPsec (UDP/500 IKE, UDP/4500 NAT-T) are legitimate VPN protocols used by VPN client software. When a workstation initiates these protocols to a destination that isn't your corporate VPN concentrator, it's either a personal VPN service (consumer policy violation) or an adversary-controlled tunnel endpoint. Personal VPN use cases: Mullvad, ProtonVPN, NordVPN - these have known endpoint ranges that can be added to a watchlist. Wireguard is increasingly used by adversaries because it's simple, fast, and produces lightweight UDP traffic that's easy to confuse with QUIC. Process correlation: only sanctioned VPN clients should be using these protocols; everything else is anomalous. Personal VPN policy enforcement: most enterprises should block consumer VPN endpoints at egress.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Wireguard-based tunneling documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Insider", note: "Personal VPN abuse for exfiltration documented in CISA insider threat guidance." },
          { cls: "apt-mul", name: "Ransomware", note: "VPN-protocol-based persistence documented in ransomware operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA and FBI advisories." }
        ],
        cite: "MITRE ATT&CK T1572, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    desc: "Post-exploitation tool downloads - LOLBin user agents, suspicious payload sources, encoded payloads",
    rows: [
      {
        sub: "T1105 - LOLBin User-Agent Fetches",
        indicator: "certutil.exe outbound HTTP - Windows certificate utility used as downloader",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.user-agent == [
  *CertUtil*
  || *Microsoft-CryptoAPI*
]
&& ip.dst != $WINDOWS_UPDATE_INFRA
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND user_agent.original: (
  *CertUtil*
  OR *Microsoft-CryptoAPI*
)
AND NOT destination.ip: $WINDOWS_UPDATE_INFRA`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1105 certutil
    download User-Agent LOLBin
    abuse";
  flow:established,to_server;
  content:"User-Agent|3a|"; http.header;
  pcre:"/User-Agent:\\s*(CertUtil|
    Microsoft-CryptoAPI)/i";
  http.header;
  classtype:trojan-activity;
  sid:9110501; rev:1;)`,
        notes: "certutil.exe is a Windows certificate management utility that can also download files via 'certutil -urlcache -split -f http://...' - extensively abused by adversaries because it's signed Microsoft code that bypasses application allowlisting. The User-Agent string 'CertUtil' (or sometimes 'Microsoft-CryptoAPI') is sent with the HTTP request and is highly distinctive. Legitimate certutil usage is internal CRL/OCSP fetches to PKI infrastructure - outbound certutil to internet hosts is essentially never legitimate. The technique is documented in MITRE LOLBAS project and remains in active use because many environments don't audit certutil usage. Pair with EDR process correlation: certutil.exe spawned by an unusual parent (cmd.exe via macro, PowerShell, anything other than admin context) is the strongest signal.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Uses certutil extensively for second-stage payload retrieval." },
          { cls: "apt-ir", name: "APT33", note: "Uses certutil in energy sector targeting." },
          { cls: "apt-kp", name: "Lazarus", note: "Documented certutil abuse in financial sector operations." },
          { cls: "apt-ru", name: "APT29", note: "Documented certutil abuse in espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all major nation-state and criminal threat actor profiles. Documented in MITRE ATT&CK, MITRE LOLBAS, and CISA living-off-the-land guidance." }
        ],
        cite: "MITRE ATT&CK T1105, MITRE LOLBAS, CISA advisories"
      },
      {
        sub: "T1105 - LOLBin User-Agent Fetches",
        indicator: "bitsadmin.exe / BITS service download - background transfer service abuse",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.user-agent == [
  *Microsoft BITS*
]
&& ip.dst != $WINDOWS_UPDATE_INFRA
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND user_agent.original: *Microsoft BITS*
AND NOT destination.ip: $WINDOWS_UPDATE_INFRA`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1105 BITS service
    download to non-WU destination
    LOLBin abuse";
  flow:established,to_server;
  content:"User-Agent|3a| Microsoft BITS";
  http.header;
  classtype:trojan-activity;
  sid:9110502; rev:1;)`,
        notes: "Background Intelligent Transfer Service (BITS) is the Windows service that handles Windows Update, WSUS, and similar background downloads. Its User-Agent is 'Microsoft BITS/{version}' and is highly distinctive. Adversaries abuse BITS via 'bitsadmin /transfer' or PowerShell's Start-BitsTransfer to download payloads with administrative tooling that's signed and trusted. BITS to non-Microsoft-Update destinations is anomalous. Build $WINDOWS_UPDATE_INFRA allowlist (Microsoft published ranges, your WSUS server). Anything else from BITS is suspicious. The technique is documented across many APTs because BITS downloads run in the background, persist across reboots, and don't require an interactive user session. EDR correlation with bitsadmin.exe process or PowerShell Start-BitsTransfer cmdlet provides definitive identification.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "BITS abuse for second-stage payload retrieval." },
          { cls: "apt-ir", name: "OilRig", note: "BITS abuse documented in Middle East government targeting." },
          { cls: "apt-ru", name: "APT29", note: "BITS abuse in espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "BITS abuse in financial sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK T1197 (BITS Jobs), MITRE LOLBAS, and CISA living-off-the-land guidance." }
        ],
        cite: "MITRE ATT&CK T1105, T1197, MITRE LOLBAS"
      },
      {
        sub: "T1105 - LOLBin User-Agent Fetches",
        indicator: "PowerShell HTTP download - Invoke-WebRequest / DownloadString outbound fetch",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.user-agent == [
  *WindowsPowerShell*
  || *PowerShell*
  || *Mozilla/5.0 (Windows NT*
    *WindowsPowerShell*
]
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND user_agent.original: (
  *WindowsPowerShell*
  OR *PowerShell*
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1105 PowerShell
    HTTP download Invoke-
    WebRequest or DownloadString";
  flow:established,to_server;
  content:"User-Agent|3a|"; http.header;
  pcre:"/User-Agent:\\s*(.*?)
    (WindowsPowerShell|PowerShell)/i";
  http.header;
  classtype:trojan-activity;
  sid:9110503; rev:1;)`,
        notes: "PowerShell's Invoke-WebRequest, Invoke-RestMethod, and (New-Object Net.WebClient).DownloadString send a default User-Agent containing 'WindowsPowerShell' or 'Mozilla/5.0 (Windows NT 10.0; ...; WindowsPowerShell/...)'. PowerShell HTTP downloads are rare in normal user activity (sometimes legitimate for IT automation scripts, package managers like Chocolatey) but very common in adversary tooling. Detection: any PowerShell HTTP UA from a host that doesn't legitimately use PowerShell for HTTP. Build per-host allowlists for sanctioned PowerShell HTTP patterns. The Empire and PowerSploit frameworks use PowerShell HTTP downloads extensively; modern Cobalt Strike powerpick and execute-assembly use in-memory loading that doesn't always cross the network. Pair with PowerShell logging (Event ID 4104) for definitive correlation.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "PowerShell-based payload download in operations against government targets." },
          { cls: "apt-cn", name: "APT41", note: "PowerShell HTTP downloads in technology sector operations." },
          { cls: "apt-ir", name: "APT33", note: "PowerShell-based payload download in energy sector operations." },
          { cls: "apt-kp", name: "Kimsuky", note: "PowerShell-based payload download in operations against South Korean government and policy targets." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK T1059.001, NSA PowerShell hardening guidance, and CISA living-off-the-land advisories." }
        ],
        cite: "MITRE ATT&CK T1105, T1059.001, NSA PowerShell guidance"
      },
      {
        sub: "T1105 - LOLBin User-Agent Fetches",
        indicator: "WinHTTP / wininet / curl / wget User-Agent - non-browser HTTP libraries downloading executables",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.user-agent == [
  *WinHttp* || *Wininet*
  || *curl/* || *Wget/*
  || *python-requests*
  || *Go-http-client*
]
&& http.uri == [
  *.exe || *.dll || *.ps1
  || *.vbs || *.bat
  || *.hta || *.scr
  || *.bin || *.dat
]
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND user_agent.original: (
  *WinHttp* OR *Wininet*
  OR *curl/* OR *Wget/*
  OR *python-requests*
  OR *Go-http-client*
)
AND url.path: (
  *.exe OR *.dll OR *.ps1
  OR *.vbs OR *.bat
  OR *.hta OR *.scr
)
AND NOT destination.ip: $KNOWN_GOOD`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1105 Non-browser
    HTTP library downloading
    executable";
  flow:established,to_server;
  pcre:"/User-Agent:\\s*(WinHttp|
    Wininet|curl\\/|Wget\\/|
    python-requests|
    Go-http-client)/i";
  http.header;
  pcre:"/\\.(exe|dll|ps1|vbs|bat|
    hta|scr|bin|dat)(\\?|$)/i";
  http.uri;
  classtype:trojan-activity;
  sid:9110504; rev:1;)`,
        notes: "Non-browser HTTP libraries (WinHTTP, WinINet, curl, wget, python-requests, Go-http-client) downloading executable file types (.exe, .dll, .ps1, .vbs, .bat, .hta, .scr) is one of the highest-confidence indicators of post-exploitation tool transfer. Each individual signal has noise (legitimate scripts use these libraries; legitimate updates download executables), but the combination of non-browser UA + executable extension + unknown destination is near-zero false positive. Custom implants written in Go produce 'Go-http-client/1.1' UA. Python-based stagers produce 'python-requests/{version}'. Curl and wget are obvious. WinHTTP and WinINet are common Windows API patterns. Pair with destination domain age (NRD) and reputation for highest-confidence alerting.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Custom Go-based implants generating Go-http-client UA in operations against technology and gaming sectors." },
          { cls: "apt-ru", name: "APT28", note: "WinHTTP-based downloaders documented in espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Custom Windows implants with WinHTTP and BITS user agents." },
          { cls: "apt-ir", name: "APT33", note: "WinHTTP-based payload downloads in energy sector targeting." },
          { cls: "apt-mul", name: "Multi", note: "Combination of UA pattern and executable extension is one of the most-cited high-precision detections in threat hunting guidance." }
        ],
        cite: "MITRE ATT&CK T1105, industry threat hunting guidance"
      },
      {
        sub: "T1105 - Payload Source Anomalies",
        indicator: "Executable download from low-reputation TLD or newly registered domain",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.uri == [
  *.exe || *.dll || *.ps1
  || *.vbs || *.hta
  || *.bat || *.scr
]
&& dns.host =~ /\\.(xyz|top|club|
  online|site|live|fun|pw|cc|
  tk|ml|ga|cf)$/
|| dns.host-age < 14d`,
        kibana: `source.ip: $INTERNAL
AND http.request.method: GET
AND url.path: (
  *.exe OR *.dll OR *.ps1
  OR *.vbs OR *.hta
)
AND url.domain: /.+\\.(xyz|top|club|online|site|tk|ml|ga|cf)$/`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1105 Executable
    download from low-reputation
    TLD";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*[^\\r\\n]+\\.(xyz|
    top|club|online|site|live|
    fun|pw|cc|tk|ml|ga|cf)/i";
  http.header;
  pcre:"/\\.(exe|dll|ps1|vbs|hta|
    bat|scr)(\\?|$)/i";
  http.uri;
  classtype:trojan-activity;
  sid:9110505; rev:1;)`,
        notes: "Low-reputation TLDs (.xyz, .top, .tk, .ml, .ga, .cf, .cc, .pw) are heavily abused for adversary infrastructure because they're cheap, easy to register anonymously, and have minimal abuse response from registrars. Most enterprise software and legitimate updates do NOT come from these TLDs. An executable file download from one of these TLDs is a strong adversary indicator. Pair with NRD detection (sid 9110506) - a brand-new domain on a low-rep TLD serving an .exe = essentially certain malicious. Build a $LEGITIMATE_LOW_REP_DOMAINS allowlist for the rare exception (some legitimate services do use these TLDs) and alert on everything else.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Routinely uses low-reputation TLDs for payload hosting infrastructure." },
          { cls: "apt-cn", name: "APT41", note: "Documented use of low-rep TLDs for short-lived staging infrastructure." },
          { cls: "apt-ir", name: "APT33", note: "Uses low-rep TLDs in energy sector targeting infrastructure." },
          { cls: "apt-mul", name: "Ransomware", note: "Low-rep TLD abuse universal across ransomware operator infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Documented in research from Spamhaus, Cisco Talos, and threat intel vendors." }
        ],
        cite: "MITRE ATT&CK T1105, T1583.001, industry reporting"
      },
      {
        sub: "T1105 - Payload Source Anomalies",
        indicator: "Executable downloaded from IP address rather than domain - direct-IP fetch bypassing DNS reputation",
        arkime: `ip.src == $INTERNAL
&& protocols == http
&& http.host =~ /^[0-9]+\\.[0-9]+
  \\.[0-9]+\\.[0-9]+$/
&& http.uri == [
  *.exe || *.dll || *.ps1
  || *.vbs || *.hta
  || *.bat || *.scr
]
&& ip.dst != $KNOWN_GOOD`,
        kibana: `source.ip: $INTERNAL
AND url.domain: /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/
AND url.path: (
  *.exe OR *.dll OR *.ps1
  OR *.vbs OR *.hta
)`,
        suricata: `alert http $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1105 Executable
    fetched via direct IP no
    DNS resolution";
  flow:established,to_server;
  content:"GET"; http.method;
  pcre:"/Host:\\s*[0-9]+\\.[0-9]+\\.
    [0-9]+\\.[0-9]+/";
  http.header;
  pcre:"/\\.(exe|dll|ps1|vbs|hta|
    bat|scr)(\\?|$)/i";
  http.uri;
  classtype:trojan-activity;
  sid:9110506; rev:1;)`,
        notes: "Direct-IP HTTP requests (Host header is an IPv4 or IPv6 address rather than a domain) bypass DNS reputation, NRD detection, and threat intel domain feeds. Adversaries use this when their domain has been burned or to avoid creating DNS infrastructure entirely. Most legitimate web traffic uses domain names - direct-IP fetches are unusual and direct-IP fetches OF executables are essentially never legitimate. The pattern shows up in stager scripts and second-stage payload retrieval. Combine with destination IP being on a commercial VPS range (sid 9109003 from T1090) for very high confidence. Zeek http.log captures the Host header explicitly. Detection is a near-zero-FP pattern.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Direct-IP payload fetches in operations where domain infrastructure has been disrupted." },
          { cls: "apt-kp", name: "Lazarus", note: "Direct-IP staging documented in financial sector operations." },
          { cls: "apt-ir", name: "APT33", note: "Direct-IP fetches in operations against energy sector targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Widely observed in ransomware affiliate operations and commodity malware." },
          { cls: "apt-mul", name: "Multi", note: "Documented in numerous incident reports, particularly where adversary uses ephemeral VPS infrastructure." }
        ],
        cite: "MITRE ATT&CK T1105, industry reporting"
      },
      {
        sub: "T1105 - Payload Source Anomalies",
        indicator: "Encoded payload in HTTP response - base64 or hex-encoded executable in plain HTTP body",
        arkime: `ip.dst == $INTERNAL
&& protocols == http
&& http.statuscode == 200
&& http.response-body =~
  /TVqQAAMAAAAEAAAA/
|| http.response-body =~
  /4d5a900003000000/`,
        kibana: `destination.ip: $INTERNAL
AND http.response.status_code: 200
AND http.response.body: (
  *TVqQAAMAAAAEAAAA*
  OR *4d5a90000300*
)`,
        suricata: `alert http $EXTERNAL_NET any
  -> $HOME_NET any
  (msg:"TA0011 T1105 Base64 or
    hex encoded PE in HTTP body
    payload delivery";
  flow:established,from_server;
  content:"200"; http.stat_code;
  file_data;
  pcre:"/(TVqQAAMAAAAEAAAA|
    4d5a900003000000)/";
  classtype:trojan-activity;
  sid:9110507; rev:1;)`,
        notes: "PE files (.exe, .dll) start with magic bytes 'MZ' (0x4D 0x5A) followed by a DOS stub. When base64-encoded, this produces 'TVqQAAMAAAAEAAAA' as a recognizable prefix in the encoded output. When hex-encoded, '4d5a900003000000' appears at the start. Adversaries deliver PE payloads encoded in HTTP response bodies to bypass content inspection that's looking for raw PE files - the encoded version doesn't trigger PE-detection signatures, but the implant decodes it client-side. Detection: scan HTTP response bodies for these distinctive encoded-PE patterns. Catches PowerShell stagers that fetch and decode payloads, .NET assembly loaders, custom implant download patterns. Suricata's file_data keyword inspects HTTP response payloads. False positives: some legitimate software distribution systems use base64-encoded binaries in response bodies - baseline these by destination domain.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Encoded PE payload delivery in custom .NET implant operations." },
          { cls: "apt-ru", name: "APT28", note: "Encoded payload delivery in espionage operations against government targets." },
          { cls: "apt-kp", name: "Lazarus", note: "Encoded payload delivery in financial sector operations." },
          { cls: "apt-mul", name: "Multi", note: "Base64 prefix 'TVqQAAMAAAAEAAAA' is widely used as a detection indicator in industry threat hunting guidance. Documented in research from Mandiant, CrowdStrike, and Microsoft MSTIC." }
        ],
        cite: "MITRE ATT&CK T1105, T1027, industry reporting"
      }
    ]
  },
  {
    id: "T1571",
    name: "Non-Standard Port",
    desc: "C2 traffic on ports that don't match expected protocol - port-protocol mismatch detection",
    rows: [
      {
        sub: "T1571 - TLS on Non-Standard Port",
        indicator: "TLS handshake on non-standard port - HTTPS-style traffic on port other than 443/8443",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& port.dst != [
  443 || 8443 || 4443
  || 465 || 587 || 636
  || 853 || 989 || 990
  || 993 || 995 || 8883
  || 6697 || 5223
]
&& ip.dst != $INTERNAL
&& session.duration > 60`,
        kibana: `source.ip: $INTERNAL
AND network.protocol: tls
AND NOT destination.port: (
  443 OR 8443 OR 4443
  OR 465 OR 587 OR 636
  OR 853 OR 989 OR 990
  OR 993 OR 995 OR 8883
)
AND NOT destination.ip: $INTERNAL`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET ![
  443,8443,4443,465,587,
  636,853,989,990,993,995,8883]
  (msg:"TA0011 T1571 TLS handshake
    on non-standard port";
  flow:established,to_server;
  content:"|16 03|"; depth:2;
  classtype:trojan-activity;
  sid:9157101; rev:1;)`,
        notes: "TLS legitimately runs on a small set of ports: 443 (HTTPS), 8443 (alternative HTTPS), 4443 (alternative), 465/587 (SMTPS submission), 636 (LDAPS), 853 (DNS-over-TLS), 989/990 (FTPS), 993 (IMAPS), 995 (POP3S), 8883 (MQTTS). TLS on other ports is anomalous - often C2 servers configured on non-standard ports for stealth (4433, 5443, 8081, etc). The Suricata content '|16 03|' matches the TLS record header (version 03 = TLSv1.x). Some legitimate corner cases exist: development environments, custom enterprise applications using TLS on bespoke ports - these should be in $KNOWN_GOOD_INTERNAL or have well-defined destination IPs to exclude. Outbound to internet on TLS-non-standard port is rarely legitimate.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "TLS C2 on non-standard ports including 4443, 8081, and others in operations against technology and gaming sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Non-standard TLS ports documented in financial sector operations." },
          { cls: "apt-ru", name: "APT29", note: "Non-standard TLS ports in espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and threat hunting guidance from Corelight and SANS." }
        ],
        cite: "MITRE ATT&CK T1571, industry reporting"
      },
      {
        sub: "T1571 - Port-Protocol Mismatch",
        indicator: "Protocol-port mismatch - Zeek-detected protocol differs from port's standard assignment",
        arkime: `protocols == zeek-dpd
&& zeek.detected-proto !=
  service-by-port(port.dst)
&& ip.src == $INTERNAL
&& session.duration > 30`,
        kibana: `source.ip: $INTERNAL
AND _exists_: zeek.dpd
AND zeek.dpd.protocol: NOT zeek.dpd.expected_protocol`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1571 Protocol port
    mismatch DPD detection
    needed";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9157102; rev:1;)`,
        notes: "Zeek's Dynamic Protocol Detection (DPD) identifies the actual protocol being spoken in a TCP session by content inspection, regardless of the port number. When the detected protocol differs from the port's standard assignment, that's a port-protocol mismatch - strong indicator of either misconfigured legitimate service or adversary using non-standard ports for known protocols. Examples: SSH on TCP/443, HTTP on TCP/22, custom binary protocol on TCP/80. The dpd.log captures these mismatches explicitly. This is the most general detection for non-standard port abuse and complements signature-based detections - it catches cases where neither the port nor a JA3/JA4 fingerprint match expectations. Suricata can produce similar signals via its app-layer protocol detection (`app-layer-protocol:!http` on port 80, etc).",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Documented use of port-protocol mismatch in some implant operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Port-protocol mismatch documented in custom implant operations." },
          { cls: "apt-mul", name: "Insider", note: "Port-protocol mismatch is also a common insider threat exfiltration indicator." },
          { cls: "apt-mul", name: "Multi", note: "Documented in Zeek/Bro documentation and Corelight (commercial Zeek vendor) research as a primary detection for novel C2 frameworks." }
        ],
        cite: "MITRE ATT&CK T1571, Corelight documentation"
      },
      {
        sub: "T1571 - High Port Outbound",
        indicator: "Outbound to high random port - sustained connection to port above 10000 not in known-app range",
        arkime: `ip.src == $INTERNAL
&& port.dst > 10000
&& port.dst != [
  10050 || 10051 || 11211
  || 27017 || 27018 || 27019
  || 50000 || 50443 || 51820
  || 6443
]
&& ip.dst != $KNOWN_GOOD
&& ip.dst != $INTERNAL
&& session.duration > 60
&& databytes.src > 5000`,
        kibana: `source.ip: $INTERNAL
AND destination.port: [10000 TO 65535]
AND NOT destination.port: (
  10050 OR 10051 OR 11211
  OR 27017 OR 27018 OR 27019
  OR 50000 OR 50443 OR 51820
  OR 6443
)
AND NOT destination.ip: ($KNOWN_GOOD OR $INTERNAL)`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 10000:65535
  (msg:"TA0011 T1571 Outbound to
    high random port sustained
    session";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 1, seconds 600;
  classtype:trojan-activity;
  sid:9157103; rev:1;)`,
        notes: "Most enterprise outbound traffic concentrates on well-known ports (80, 443, 53, 22, 25, 587, etc). Outbound to high-numbered random ports (>10000) is statistically rare except for specific applications: Zabbix agents (10050/10051), MongoDB (27017-27019), Wireguard (51820), Kubernetes API (6443), some game servers, BitTorrent, and certain SaaS platforms. Build $KNOWN_GOOD_HIGH_PORTS as the explicit allowlist of permitted high-port destinations. Sustained sessions to other high ports from internal hosts are anomalous. The detection has noise - gaming, P2P, some cloud apps - but in production server VLANs and standard user environments, the false positive rate is low. Combine with destination IP reputation for higher confidence.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "High random port C2 documented in custom implant operations." },
          { cls: "apt-kp", name: "Lazarus", note: "High port C2 in financial sector operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented in MITRE ATT&CK and threat hunting guidance focused on egress traffic anomaly detection." }
        ],
        cite: "MITRE ATT&CK T1571, industry reporting"
      }
    ]
  },
  {
    id: "T1219",
    name: "Remote Access Software",
    desc: "Legitimate RMM tools (TeamViewer, AnyDesk, ConnectWise, etc) abused for C2 and remote access",
    rows: [
      {
        sub: "T1219 - TeamViewer",
        indicator: "TeamViewer connection - host connecting to TeamViewer infrastructure",
        arkime: `ip.src == $INTERNAL
&& protocols == [tls || tcp]
&& tls.sni == [
  *teamviewer.com*
  || *.teamviewer.com*
]
|| port.dst == [5938 || 5939]
|| ip.dst == $TEAMVIEWER_RANGES`,
        kibana: `source.ip: $INTERNAL
AND (tls.client.server_name: (
  *teamviewer.com*
)
OR destination.port: (5938 OR 5939)
OR destination.ip: $TEAMVIEWER_RANGES)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1219 TeamViewer
    connection";
  flow:established,to_server;
  tls.sni;
  pcre:"/teamviewer\\.com/i";
  classtype:policy-violation;
  sid:9121901; rev:1;)`,
        notes: "TeamViewer connects to *.teamviewer.com endpoints, primarily via TCP/5938 (default) and TCP/5939 (HTTPS fallback), with HTTPS traffic to the SaaS platform. Maintain $TEAMVIEWER_RANGES from TeamViewer's published infrastructure ranges. TeamViewer is widely allowed in some environments (consultants, IT support) but should NOT be running on production servers, finance/HR workstations, or generic end-user systems unless specifically sanctioned. Build per-host policy: TeamViewer permitted on $TEAMVIEWER_AUTHORIZED_HOSTS, alerted everywhere else. The technique is a primary CISA-flagged threat in advisories on Scattered Spider, RMM tool abuse, and tech support scams. Block TeamViewer at the proxy/firewall in environments without legitimate use.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "TeamViewer abuse documented in CISA AA23-320A operations against hospitality and technology sector targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Documented in numerous ransomware incident reports as an initial access and persistence mechanism." },
          { cls: "apt-mul", name: "Tech Support Scams", note: "TeamViewer is the dominant tool used in tech support scam operations against consumers and enterprises." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA AA23-320A on Scattered Spider, FBI/CISA advisories on RMM abuse, and ransomware incident reports." }
        ],
        cite: "MITRE ATT&CK T1219, CISA AA23-320A, FBI advisories"
      },
      {
        sub: "T1219 - AnyDesk",
        indicator: "AnyDesk connection - host connecting to AnyDesk infrastructure",
        arkime: `ip.src == $INTERNAL
&& protocols == [tls || tcp]
&& tls.sni == [
  *anydesk.com*
  || *.anydesk.com*
  || *.net.anydesk.com*
]
|| port.dst == [6568 || 7070]
|| ip.dst == $ANYDESK_RANGES`,
        kibana: `source.ip: $INTERNAL
AND (tls.client.server_name: (
  *anydesk.com*
)
OR destination.port: (6568 OR 7070)
OR destination.ip: $ANYDESK_RANGES)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET any
  (msg:"TA0011 T1219 AnyDesk
    connection";
  flow:established,to_server;
  tls.sni;
  pcre:"/anydesk\\.com/i";
  classtype:policy-violation;
  sid:9121902; rev:1;)`,
        notes: "AnyDesk connects to *.net.anydesk.com endpoints with HTTPS on TCP/443 primarily, with fallback TCP/6568 and TCP/7070 for direct connections. AnyDesk is heavily abused by ransomware affiliates and Scattered Spider - particularly because it's portable (single executable, no installation required) which makes it perfect for adversary deployment. The portable executable produces distinctive process behavior (anydesk.exe in non-standard locations, often %TEMP% or user-writeable paths). Network detection per the SNI patterns above; pair with EDR for portable-AnyDesk-deployment indicators (file path of the binary).",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "AnyDesk abuse documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Documented in numerous ransomware incident reports including Conti, LockBit, BlackCat/ALPHV operations." },
          { cls: "apt-mul", name: "Conti", note: "AnyDesk used in Conti ransomware operations." },
          { cls: "apt-mul", name: "LockBit", note: "AnyDesk used in LockBit ransomware affiliate operations." },
          { cls: "apt-mul", name: "Multi", note: "Portable variant documented in research from Sophos, Mandiant, and CrowdStrike." }
        ],
        cite: "MITRE ATT&CK T1219, CISA AA23-320A, ransomware incident reporting"
      },
      {
        sub: "T1219 - RMM Platforms",
        indicator: "ConnectWise ScreenConnect / NinjaRMM / Atera / Splashtop - RMM platform connections",
        arkime: `ip.src == $INTERNAL
&& protocols == [tls || tcp]
&& tls.sni == [
  *.screenconnect.com*
  || *.ninjarmm.com*
  || *.atera.com*
  || *.splashtop.com*
  || *.logmein.com*
  || *.rustdesk.com*
  || *.netsupportsoftware.com*
  || *.parsecgaming.com*
]`,
        kibana: `source.ip: $INTERNAL
AND tls.client.server_name: (
  *.screenconnect.com*
  OR *.ninjarmm.com*
  OR *.atera.com*
  OR *.splashtop.com*
  OR *.logmein.com*
  OR *.rustdesk.com*
  OR *.netsupportsoftware.com*
  OR *.parsecgaming.com*
)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1219 RMM platform
    connection ConnectWise Ninja
    Atera Splashtop";
  flow:established,to_server;
  tls.sni;
  pcre:"/(screenconnect\\.com|
    ninjarmm\\.com|atera\\.com|
    splashtop\\.com|logmein\\.com|
    rustdesk\\.com|netsupport
    software\\.com|parsecgaming
    \\.com)/i";
  classtype:policy-violation;
  sid:9121903; rev:1;)`,
        notes: "ConnectWise Control (formerly ScreenConnect), Splashtop, NinjaRMM, Atera, LogMeIn, RustDesk, NetSupport Manager, and Parsec are remote management platforms heavily abused by adversaries. ScreenConnect specifically had a critical vulnerability (CVE-2024-1709, ConnectWise authentication bypass) exploited at scale in 2024 - adversaries with access to a ScreenConnect instance can deploy persistent agents to all managed endpoints. Each platform has distinct SNI patterns. RustDesk is an open-source self-hosted alternative that's increasingly seen in adversary operations because the operator can host the rendezvous server themselves. Block these at proxy/firewall unless your organization specifically uses one of them - and if you do use one, allowlist that vendor's SNI and alert on every other RMM tool's traffic.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "RMM tool abuse documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Black Basta", note: "ConnectWise CVE-2024-1709 exploitation by Black Basta documented in CISA emergency advisories." },
          { cls: "apt-mul", name: "Ransomware", note: "RMM platform abuse documented in numerous ransomware incident reports." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA AA23-320A, CISA AA24-038A, and CISA emergency advisories on ConnectWise vulnerabilities. Fastest-growing initial access and persistence category." }
        ],
        cite: "MITRE ATT&CK T1219, CISA AA23-320A, CISA emergency advisories"
      },
      {
        sub: "T1219 - Tunneling Tools",
        indicator: "Tunneling tool infrastructure - ngrok, Cloudflare Tunnel, FRP, Chisel endpoints",
        arkime: `ip.src == $INTERNAL
&& protocols == tls
&& tls.sni == [
  *.ngrok.io*
  || *.ngrok-free.app*
  || *.argotunnel.com*
  || *.cloudflareaccess.com*
  || *.try.cloudflare.com*
  || *.tailscale.com*
  || *.zerotier.com*
]
&& process != $KNOWN_GOOD_PROCS`,
        kibana: `source.ip: $INTERNAL
AND tls.client.server_name: (
  *.ngrok.io*
  OR *.ngrok-free.app*
  OR *.argotunnel.com*
  OR *.cloudflareaccess.com*
  OR *.try.cloudflare.com*
  OR *.tailscale.com*
  OR *.zerotier.com*
)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0011 T1219 Tunneling
    tool infrastructure ngrok
    Cloudflare Tunnel Tailscale";
  flow:established,to_server;
  tls.sni;
  pcre:"/(ngrok\\.io|ngrok-free
    \\.app|argotunnel\\.com|
    cloudflareaccess\\.com|try\\.
    cloudflare\\.com|tailscale
    \\.com|zerotier\\.com)/i";
  classtype:policy-violation;
  sid:9121904; rev:1;)`,
        notes: "Modern tunneling and overlay-network tools - ngrok (consumer-facing localhost-tunnel service), Cloudflare Tunnel (cloudflared client), Tailscale (mesh VPN), ZeroTier (mesh VPN) - are heavily abused for adversary remote access and C2 staging. Cloudflare Tunnel is particularly common in modern adversary operations because the cloudflared binary can be deployed without admin rights and the connection looks like ordinary HTTPS to Cloudflare. Tailscale has been documented in Scattered Spider operations as a way to establish persistent network access without VPN credentials. ngrok is used to expose internal services for adversary access. These tools have legitimate development and IT use cases - process correlation distinguishes legitimate from abusive use. Block at proxy unless the organization has specific approved use, and if approved, restrict to specific authorized hosts.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Cloudflare Tunnel and Tailscale abuse documented in CISA AA23-320A operations." },
          { cls: "apt-cn", name: "APT41", note: "Tunneling tool abuse documented in operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Cloudflare Tunnel abuse documented in ransomware operations." },
          { cls: "apt-mul", name: "Multi", note: "Cloudflare Tunnel and Tailscale specifically called out as primary alternatives to traditional VPN-based persistence in CISA and Microsoft MSTIC research." }
        ],
        cite: "MITRE ATT&CK T1219, T1572, CISA AA23-320A, Microsoft MSTIC"
      }
    ]
  }
];
