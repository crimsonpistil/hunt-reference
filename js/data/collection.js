// TA0009 - Collection
// 12 techniques · 16 indicators · SMB, EWS/Graph, HTTP, SNMP detection

const DATA = [
  {
    id: "T1039",
    name: "Data from Network Shared Drive",
    desc: "SMB bulk reads, admin share enumeration, high-sensitivity filename targeting",
    rows: [
      {
        sub: "T1039 - Bulk Read Patterns",
        indicator: "SMB read burst - single source reading many files across many directories",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == read
&& unique-path-count groupby
  ip.src > 50 within 300s
&& unique-directory-count > 10`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "read"
AND _exists_: file.path`,
        suricata: `alert tcp $HOME_NET any
  -> $FILE_SERVERS 445
  (msg:"TA0009 T1039 SMB bulk read
    burst single source many files
    network share collection";
  flow:established,to_server;
  content:"|fe|SMB"; depth:4;
  content:"|08 00|"; offset:12;
  threshold:type both,
    track by_src,
    count 50, seconds 300;
  classtype:trojan-activity;
  sid:9103901; rev:1;)`,
        notes: "Normal user file access patterns are characterized by depth, not breadth - they open a project folder, read 5-10 related files, work for a while, occasionally open another related folder. Adversary collection is the inverse: shallow but wide reads across many directories within minutes. Detection: count unique file paths AND unique parent directories per source IP per 5-minute window. Threshold of 50 files across 10+ directories is a starting point - tune based on your environment (developers and analysts may legitimately hit higher baselines for code/data folders). Build per-role baselines if you can: HR users access HR shares, finance users access finance shares; cross-role access is highly anomalous. Zeek's smb_files.log is the primary data source; pair with smb_mapping.log to see which shares the source first connected to.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Bulk SMB reads universal in ransomware double-extortion (read-then-encrypt) operations." },
          { cls: "apt-cn", name: "APT41", note: "Documented in operations against tech sector and gaming companies." },
          { cls: "apt-ru", name: "APT29", note: "Heavy file server collection in SolarWinds and ongoing operations." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all data theft operations." }
        ],
        cite: "MITRE ATT&CK T1039, CISA AA23-320A"
      },
      {
        sub: "T1039 - Admin Share Access",
        indicator: "SMB tree connect to administrative or hidden shares from non-admin source - share enumeration",
        arkime: `ip.src == $INTERNAL
&& ip.src != $ADMIN_HOSTS
&& port.dst == 445
&& protocols == smb
&& smb.tree =~ /\\\\\\\\.+\\\\(C\\$|ADMIN\\$|IPC\\$|.+\\$)/i`,
        kibana: `source.ip: $INTERNAL
AND NOT source.ip: $ADMIN_HOSTS
AND destination.port: 445
AND smb.tree: (*$\\C$ OR *$\\ADMIN$ OR *\\*$)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0009 T1039 SMB tree
    connect to admin share from
    non-admin source";
  flow:established,to_server;
  content:"|fe|SMB"; depth:4;
  content:"|03 00|"; offset:12;
  pcre:"/\\\\(C|ADMIN|IPC)\\$/i";
  classtype:trojan-activity;
  sid:9103902; rev:1;)`,
        notes: "Hidden administrative shares (C$, ADMIN$, IPC$) and ad-hoc dollar-suffixed shares are rarely accessed legitimately by end-user workstations - they're admin tooling endpoints. Adversaries connect to them for two reasons: (1) lateral movement preparation (already covered under T1021.002), and (2) collection - file servers often have full-disk shares (D$, E$) that expose entire data volumes. Detection: SMB tree connect requests targeting any \\\\host\\X$ pattern from sources that aren't on your $ADMIN_HOSTS allowlist. Zeek's smb_mapping.log captures every tree connect. Investigate which user account performed the connect (via the prior NTLMSSP_AUTHENTICATE or Kerberos AP-REQ) - admin shares accessed by service accounts during off-hours are particularly suspicious. Pair with subsequent file read volume from the same connection.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Admin share access for collection of full-disk shares on file servers." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Used to access full-disk shares on file servers during data theft preparation." }
        ],
        cite: "MITRE ATT&CK T1039"
      },
      {
        sub: "T1039 - High-Sensitivity Filenames",
        indicator: "SMB read of high-sensitivity filename patterns - credentials, financials, secrets in file paths",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.filename =~
  /password|passwd|secret|credential|
   confidential|payroll|salary|ssn|
   tax|merger|acquisition|
   financial.{0,10}statement/i`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND file.name: (*password* OR *passwd* OR *secret* OR *credential* OR *confidential* OR *payroll* OR *salary* OR *ssn* OR *tax* OR *merger* OR *acquisition*)`,
        suricata: `alert tcp $HOME_NET any
  -> $FILE_SERVERS 445
  (msg:"TA0009 T1039 SMB access
    high-sensitivity filename
    collection target";
  flow:established,to_server;
  pcre:"/(password|passwd|secret|
    credential|confidential|
    payroll|salary|ssn|tax|
    merger|acquisition)/i";
  classtype:trojan-activity;
  sid:9103903; rev:1;)`,
        notes: "Adversaries doing targeted collection often grep filename listings for high-value keywords before bulk reading. Filename patterns containing 'password', 'secret', 'credential', 'confidential', 'payroll', 'salary', 'ssn', 'tax', 'merger', 'acquisition' are common collection targets. False positives: legitimate access by users whose job involves these files (HR, finance, M&A teams). Build $FINANCE_USERS / $HR_USERS allowlists or scope detection to off-role access. Particularly high-confidence when the source is a developer or sales workstation accessing finance share filenames. Pair with the bulk read pattern (sid 9103901) - bulk reads PLUS high-sensitivity filename matches is essentially diagnostic of collection. Note: this catches naive collection; sophisticated operators stage less obviously named files. Treat absence of these hits as 'we didn't catch them this way' rather than 'they didn't collect.'",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Filename targeting universal in ransomware double-extortion operations." },
          { cls: "apt-cn", name: "APT41", note: "Documented in operations targeting tech and finance sectors." },
          { cls: "apt-mul", name: "Industrial espionage", note: "Targeted filename access for M&A and strategic data." },
          { cls: "apt-mul", name: "Multi", note: "Documented across data-theft operations targeting financial/M&A data." }
        ],
        cite: "MITRE ATT&CK T1039, T1083"
      }
    ]
  },
  {
    id: "T1213.001",
    name: "Data from Information Repositories: Confluence",
    desc: "REST API search bursts and bulk content retrieval",
    rows: [
      {
        sub: "T1213.001 - Confluence Search Burst",
        indicator: "Confluence REST API search burst - single user, many distinct queries",
        arkime: `ip.src == $INTERNAL
&& port.dst == [80 || 443 || 8090]
&& http.uri =~
  /\\/rest\\/api\\/content\\/search/i
&& unique-query-count groupby
  ip.src > 20 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (80 OR 443 OR 8090)
AND url.path: */rest/api/content/search*`,
        suricata: `alert tcp $HOME_NET any
  -> $CONFLUENCE_HOSTS [80,443,8090]
  (msg:"TA0009 T1213.001 Confluence
    REST API search burst single
    user many queries collection";
  flow:established,to_server;
  content:"/rest/api/content/search";
  http_uri;
  threshold:type both,
    track by_src,
    count 20, seconds 600;
  classtype:trojan-activity;
  sid:9121301; rev:1;)`,
        notes: "Confluence's REST API at /rest/api/content/search accepts CQL (Confluence Query Language) queries - adversaries use this to grep across all spaces for keywords like 'password', 'api_key', 'credentials', 'AWS', 'jenkins'. Tools: confluence-dump, internal pentesting frameworks, custom scripts. Pattern: 20+ distinct search queries from one source within 10 minutes. The Confluence web UI does periodic search but humans rarely fire 20+ distinct CQL queries in a short window. The REST endpoint pattern is high-confidence - UI search uses different paths. Pair with bulk content downloads (/rest/api/content/{id}?expand=body) for full collection chain. If Confluence is hosted internally, build $CONFLUENCE_HOSTS allowlist; if cloud (Atlassian Cloud), this detection moves to cloud-side audit logs (Atlassian Audit API).",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Confluence enumeration is a standard red team data-discovery step in modern engagements." },
          { cls: "apt-cn", name: "APT41", note: "Wiki/Confluence collection in operations targeting tech sector." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations against SaaS environments." },
          { cls: "apt-mul", name: "Multi", note: "Particularly heavy in operations targeting tech sector companies." }
        ],
        cite: "MITRE ATT&CK T1213.001"
      }
    ]
  },
  {
    id: "T1213.002",
    name: "Data from Information Repositories: SharePoint",
    desc: "Search API and document library enumeration patterns",
    rows: [
      {
        sub: "T1213.002 - SharePoint Search Burst",
        indicator: "SharePoint search API burst - bulk site enumeration and document discovery",
        arkime: `ip.src == $INTERNAL
&& port.dst == [80 || 443]
&& http.uri =~
  /\\/_api\\/search\\/query|
   \\/_api\\/web\\/lists|
   \\/_vti_bin\\/search\\.asmx/i
&& unique-uri-count groupby
  ip.src > 30 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (80 OR 443)
AND url.path: (*/_api/search/query* OR */_api/web/lists* OR */_vti_bin/search*)`,
        suricata: `alert tcp $HOME_NET any
  -> $SHAREPOINT_HOSTS [80,443]
  (msg:"TA0009 T1213.002 SharePoint
    search API burst bulk discovery
    collection";
  flow:established,to_server;
  pcre:"/(\\/_api\\/search\\/query|
    \\/_api\\/web\\/lists|
    \\/_vti_bin\\/search)/i";
  threshold:type both,
    track by_src,
    count 30, seconds 600;
  classtype:trojan-activity;
  sid:9121302; rev:1;)`,
        notes: "SharePoint's REST API at /_api/search/query accepts KQL (Keyword Query Language) for site-wide content search. /_api/web/lists enumerates document libraries; /_vti_bin/search.asmx is the legacy SOAP search interface. Adversaries use these for bulk document discovery before downloading. Tools: SharpHound (BloodHound has SharePoint enumeration support), custom scripts, Microsoft Graph API for M365 SharePoint. The 30-query threshold accounts for SharePoint's chattier baseline (search-as-you-type, autocomplete) - adjust based on your environment. Internal SharePoint = $SHAREPOINT_HOSTS allowlist; M365 SharePoint Online detection moves to Microsoft 365 audit logs (UAL). Sysmon/PowerShell logging on workstations catches the user-side script execution that performed the queries.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SharePoint/M365 SharePoint targeting documented in operations against government and tech." },
          { cls: "apt-cn", name: "APT41", note: "Documented in operations against multiple sectors." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A SaaS-focused operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Heavy ransomware double-extortion targeting." },
          { cls: "apt-mul", name: "Multi", note: "Common across espionage and cybercrime operations targeting M365 environments." }
        ],
        cite: "MITRE ATT&CK T1213.002"
      }
    ]
  },
  {
    id: "T1213.003",
    name: "Data from Information Repositories: Code Repositories",
    desc: "GitLab/Gitea/Bitbucket bulk clone - git-upload-pack handshake bursts",
    rows: [
      {
        sub: "T1213.003 - Bulk Clone",
        indicator: "Git clone burst - single source cloning many repositories",
        arkime: `ip.src == $INTERNAL
&& port.dst == [22 || 80 || 443 || 9418]
&& (http.uri =~ /\\/info\\/refs\\?service=git-upload-pack/
    || protocols == ssh)
&& unique-repo-count groupby
  ip.src > 5 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: (22 OR 80 OR 443 OR 9418)
AND url.path: */info/refs?service=git-upload-pack*`,
        suricata: `alert tcp $HOME_NET any
  -> $GIT_HOSTS [80,443]
  (msg:"TA0009 T1213.003 Git clone
    burst many repositories
    code repository collection";
  flow:established,to_server;
  content:"/info/refs?service=git-upload-pack";
  http_uri;
  threshold:type both,
    track by_src,
    count 5, seconds 600;
  classtype:trojan-activity;
  sid:9121303; rev:1;)`,
        notes: "Internal code repos (GitLab, Gitea, Bitbucket Server, GitHub Enterprise) frequently contain hardcoded credentials, infrastructure secrets, business logic, customer data references. After credential compromise, adversaries clone many repos to grep offline for secrets. The git HTTP protocol uses /info/refs?service=git-upload-pack as the initial handshake - every clone hits this. Pattern: 5+ distinct repos cloned from one source in 10 minutes. Threshold lower than other bursts because legitimate developer behavior rarely involves cloning many distinct repos in rapid succession. Tools: gitleaks, trufflehog, or custom scripts run AFTER the clone - the network signal is the clone burst, the offline grep happens locally. Pair with subsequent outbound transfers of the cloned data (T1041 / T1567). For SSH-protocol git access (port 22), Zeek conn.log shows the connections but file paths aren't visible - fall back to volume-based detection.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Source code theft documented heavily in operations against tech sector and gaming companies." },
          { cls: "apt-kp", name: "Lazarus", note: "Targeted code repos for cryptocurrency-related projects." },
          { cls: "apt-mul", name: "Insider Threat", note: "Departing developers cloning entire repo collections - common insider threat scenario." },
          { cls: "apt-mul", name: "Industrial espionage", note: "Source code theft for IP and competitive intelligence." },
          { cls: "apt-mul", name: "Multi", note: "Documented across espionage and insider threat operations." }
        ],
        cite: "MITRE ATT&CK T1213.003"
      }
    ]
  },
  {
    id: "T1114.001",
    name: "Email Collection: Local Email Collection",
    desc: "PST/OST/NST file exfiltration via SMB - Outlook offline storage theft",
    rows: [
      {
        sub: "T1114.001 - PST/OST Exfiltration",
        indicator: "SMB read of .pst / .ost / .nst files - Outlook offline storage exfiltration",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.filename =~
  /\\.pst$|\\.ost$|\\.nst$|
   archive\\.pst|backup\\.pst/i
&& smb.filesize > 52428800`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND file.name: (*.pst OR *.ost OR *.nst)
AND file.size > 52428800`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0009 T1114.001 SMB read
    of large PST OST file Outlook
    storage exfiltration";
  flow:established,to_server;
  pcre:"/(\\.pst|\\.ost|\\.nst)/i";
  classtype:trojan-activity;
  sid:9111401; rev:1;)`,
        notes: "Outlook stores email locally in .pst (Personal Storage Table - archives, exports), .ost (Offline Storage Table - cached Exchange data), .nst (group calendar caches). PST/OST files often contain years of email and can exceed 50GB. Adversaries who gain access to a workstation often exfiltrate the OST file directly - it's a complete email archive without needing EWS bulk reads. Detection: SMB transfer of PST/OST files larger than 50MB (real archives are usually 1-50GB; tiny PSTs are typically templates or test files). False positives: legitimate IT migration of user mailboxes during platform changes - should originate from $IT_ADMINS hosts. After exclusions, large PST/OST movement is highly suspicious. Pair with subsequent outbound transfer of files matching the same size profile.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "PST/OST exfiltration in espionage operations targeting executives and knowledge workers." },
          { cls: "apt-cn", name: "APT41", note: "Email archive theft in operations across multiple sectors." },
          { cls: "apt-mul", name: "Insider Threat", note: "Common in insider-threat departures - entire mailbox archives." },
          { cls: "apt-mul", name: "Multi", note: "Documented across espionage operations and insider threat scenarios." }
        ],
        cite: "MITRE ATT&CK T1114.001"
      }
    ]
  },
  {
    id: "T1114.002",
    name: "Email Collection: Remote Email Collection",
    desc: "EWS / Graph API bulk email enumeration - FindItem/GetItem/ExportItems bursts",
    rows: [
      {
        sub: "T1114.002 - EWS Bulk Enumeration",
        indicator: "EWS FindItem / GetItem burst - bulk email enumeration via Exchange Web Services",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& http.uri =~ /\\/EWS\\/Exchange\\.asmx/i
&& http.method == POST
&& http.body =~
  /<.*FindItem|<.*GetItem|<.*ExportItems/i
&& count groupby ip.src > 100 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND url.path: */EWS/Exchange.asmx*
AND http.request.method: "POST"
AND http.request.body: (*FindItem* OR *GetItem* OR *ExportItems*)`,
        suricata: `alert tcp $HOME_NET any
  -> $EXCHANGE_HOSTS 443
  (msg:"TA0009 T1114.002 EWS bulk
    item enumeration email
    collection burst";
  flow:established,to_server;
  content:"/EWS/Exchange.asmx";
  http_uri;
  pcre:"/(<m:FindItem|<m:GetItem|
    <t:ExportItems)/i";
  threshold:type both,
    track by_src,
    count 100, seconds 600;
  classtype:trojan-activity;
  sid:9111402; rev:1;)`,
        notes: "Exchange Web Services (EWS) at /EWS/Exchange.asmx is the SOAP API used by Outlook for Mac, mobile clients, and many third-party tools. It's also the API used by adversary tools like MailSniper, FireEye's RuleSnoop, and custom Python/PowerShell scripts. FindItem enumerates mailbox contents; GetItem retrieves specific items; ExportItems pulls items in bulk. The high-volume detection threshold (100 calls in 10 min) tunes for normal heavy mail clients; adjust per environment. Particularly important for on-prem Exchange or hybrid deployments. For M365 Exchange Online, much of this traffic terminates at outlook.office365.com - detection moves to M365 audit logs (mailbox audit, particularly MailItemsAccessed events for E5 licenses). Graph API equivalents at graph.microsoft.com/v1.0/me/messages produce similar network patterns.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Bulk email collection via EWS heavily documented in operations against government and tech targets." },
          { cls: "apt-ir", name: "APT34", note: "MailSniper-like tooling against Exchange in Middle East operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Executive email targeting for financial intelligence." },
          { cls: "apt-mul", name: "Multi", note: "Documented across espionage operations targeting Exchange/M365 environments." }
        ],
        cite: "MITRE ATT&CK T1114.002"
      }
    ]
  },
  {
    id: "T1114.003",
    name: "Email Collection: Email Forwarding Rule",
    desc: "Mailbox rule creation for automated email exfiltration - EWS, Graph, Set-InboxRule patterns",
    rows: [
      {
        sub: "T1114.003 - Forwarding Rule Creation",
        indicator: "EWS UpdateInboxRules / Set-InboxRule - forwarding rule creation pattern",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& http.uri =~ /\\/EWS\\/Exchange\\.asmx|
   \\/PowerShell|\\/v1\\.0\\/me\\/mailFolders/i
&& http.body =~
  /UpdateInboxRules|Set-InboxRule|
   ForwardAsAttachmentToRecipients|
   ForwardToRecipients|
   "forwardingSmtpAddress"/i`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND url.path: (*/EWS/Exchange.asmx* OR */PowerShell* OR */v1.0/me/mailFolders*)
AND http.request.body: (*UpdateInboxRules* OR *Set-InboxRule* OR *ForwardToRecipients* OR *forwardingSmtpAddress*)`,
        suricata: `alert tcp $HOME_NET any
  -> $EXCHANGE_HOSTS 443
  (msg:"TA0009 T1114.003 Email
    forwarding rule creation
    via EWS or Graph API";
  flow:established,to_server;
  pcre:"/(UpdateInboxRules|
    Set-InboxRule|
    ForwardToRecipients|
    forwardingSmtpAddress)/i";
  classtype:trojan-activity;
  sid:9111403; rev:1;)`,
        notes: "Email forwarding rules persist after the adversary loses session access - set a rule to forward all incoming mail to an attacker-controlled address, and email exfiltration continues automatically. Common patterns: (1) BEC-style external forwarding (rule forwards to attacker@gmail.com), (2) deletion-after-forward to hide evidence, (3) keyword-triggered rules ('forward only emails matching invoice OR wire OR payment'). Detection points: EWS UpdateInboxRules SOAP body, Graph API mailFolders/inbox/messageRules POST, Exchange Online PowerShell Set-InboxRule cmdlet (visible in remote PowerShell sessions). Once you have hits, examine RULE BODY: rules forwarding outside the org are highest priority, rules with deletion enabled are next, rules matching financial keywords are next. M365 environments: Exchange Online audit logs (UnifiedAuditLog 'New-InboxRule' / 'Set-InboxRule' events) provide cleaner detection than network - but network catches it before logs are reviewed. Modern best practice: disable auto-forwarding to external recipients via tenant policy.",
        apt: [
          { cls: "apt-mul", name: "BEC Actors", note: "Forwarding rules are the signature persistence technique in BEC - documented across FBI IC3 reports." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Forwarding rule creation documented in CISA AA23-320A operations targeting M365." },
          { cls: "apt-ru", name: "APT29", note: "Forwarding rules in long-term espionage persistence." },
          { cls: "apt-mul", name: "Multi", note: "Universal across cybercrime operations targeting cloud email." }
        ],
        cite: "MITRE ATT&CK T1114.003"
      }
    ]
  },
  {
    id: "T1530",
    name: "Data from Cloud Storage",
    desc: "Bulk access to S3 / Azure Blob / GCS via stolen IAM credentials or SAS tokens",
    rows: [
      {
        sub: "T1530 - Cloud Storage Bulk Download",
        indicator: "S3 ListObjects / GetObject burst - bulk bucket enumeration and download",
        arkime: `ip.src == $INTERNAL
&& port.dst == 443
&& host.dst =~ /\\.s3.*\\.amazonaws\\.com$|
   \\.blob\\.core\\.windows\\.net$|
   storage\\.googleapis\\.com$/i
&& http.method == GET
&& count groupby ip.src > 200 within 600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 443
AND destination.domain: (*.s3*.amazonaws.com OR *.blob.core.windows.net OR storage.googleapis.com)`,
        suricata: `alert tls $HOME_NET any
  -> $EXTERNAL_NET 443
  (msg:"TA0009 T1530 S3 or Azure
    Blob bulk download cloud
    storage collection";
  flow:established,to_server;
  tls.sni; pcre:"/\\.(s3.*\\.amazonaws\\.com|
    blob\\.core\\.windows\\.net|
    storage\\.googleapis\\.com)$/i";
  threshold:type both,
    track by_src,
    count 200, seconds 600;
  classtype:trojan-activity;
  sid:9153001; rev:1;)`,
        notes: "Cloud storage providers each have distinctive SNI patterns: AWS S3 uses bucket.s3.region.amazonaws.com or s3.amazonaws.com, Azure Blob uses account.blob.core.windows.net, GCS uses storage.googleapis.com. Bulk download attacks: adversaries with stolen IAM credentials/SAS tokens enumerate buckets and download contents. Pattern: 200+ HTTPS requests to cloud storage SNI from one source within 10 minutes is well above normal application baseline. Tools: AWS CLI s3 sync/cp, rclone, custom boto3/azure-sdk scripts. Cloud-side detection is more precise (CloudTrail, Azure Activity Log, GCS audit logs) and SHOULD be your primary detection - but network-side catches the egress side and can fire before cloud audit logs are reviewed. Build $CLOUD_USERS allowlist of known sources that legitimately access cloud storage at scale (CI/CD runners, backup services, data pipelines). After exclusions, this signature catches adversaries operating with stolen tokens from compromised workstations.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Cloud storage targeting documented heavily in CISA AA23-320A - particularly AWS S3 buckets containing customer data." },
          { cls: "apt-mul", name: "Cybercrime", note: "S3 buckets targeted across cybercrime ransomware operations targeting cloud-native organizations." },
          { cls: "apt-cn", name: "APT41", note: "Cloud-hosted data targeted in operations against tech companies." },
          { cls: "apt-mul", name: "Multi", note: "Increasingly common as enterprises move data to cloud object stores." }
        ],
        cite: "MITRE ATT&CK T1530, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1602.002",
    name: "Data from Configuration Repository: Network Device Configuration Dump",
    desc: "SNMP CISCO-CONFIG-COPY-MIB walks and TFTP/SCP config exfiltration patterns",
    rows: [
      {
        sub: "T1602.002 - SNMP Config Walk",
        indicator: "SNMP bulk walk of CISCO-CONFIG-COPY-MIB - config dump via SNMP",
        arkime: `ip.src == $INTERNAL
&& port.dst == 161
&& protocols == snmp
&& snmp.oid =~
  /1\\.3\\.6\\.1\\.4\\.1\\.9\\.9\\.96|
   1\\.3\\.6\\.1\\.4\\.1\\.9\\.2\\.1\\.55/
&& snmp.command == [getbulk || getnext]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 161
AND snmp.oid: (1.3.6.1.4.1.9.9.96.* OR 1.3.6.1.4.1.9.2.1.55.*)`,
        suricata: `alert udp $HOME_NET any
  -> $NETWORK_DEVICES 161
  (msg:"TA0009 T1602.002 SNMP
    CISCO-CONFIG-COPY-MIB walk
    config dump";
  content:"|2b 06 01 04 01 09 09 60|";
  classtype:trojan-activity;
  sid:9160202; rev:1;)`,
        notes: "CISCO-CONFIG-COPY-MIB (1.3.6.1.4.1.9.9.96) and OLD-CISCO-SYSTEM-MIB (1.3.6.1.4.1.9.2.1.55) both allow remote dumping of running and startup configurations via SNMP - typically to a TFTP server. Adversaries with SNMP write community strings (or read-only on misconfigured devices) can pull configs containing: enable secrets (often weakly hashed), VPN preshared keys, BGP/OSPF auth keys, ACL contents, NAT rules. Volt Typhoon and other infrastructure-focused threats heavily target Cisco IOS, Juniper, Fortinet config extraction. Detection: SNMP getbulk/getnext walks of these specific OIDs, particularly from sources outside the $NETWORK_ADMINS allowlist. Pair with subsequent TFTP transfer (UDP/69) or SCP from network device to attacker - the config copy operation often uses TFTP put. Modern best practice: SNMPv3 with auth/priv (replacing SNMPv1/v2c community strings), restrict SNMP source IPs at device ACL, monitor SNMP set operations.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Network device config theft documented heavily in CISA AA23-144A targeting US critical infrastructure." },
          { cls: "apt-cn", name: "APT41", note: "Network device targeting in operations against telecom and ISP targets." },
          { cls: "apt-ru", name: "APT28", note: "Historical targeting of network device configs in espionage operations." },
          { cls: "apt-mul", name: "Network-focused threats", note: "Living-off-the-land approach using device's own config-copy mechanisms." },
          { cls: "apt-mul", name: "Multi", note: "Configs reveal architecture, secrets, and ACLs for follow-on operations." }
        ],
        cite: "MITRE ATT&CK T1602.002, CISA AA23-144A"
      },
      {
        sub: "T1602.002 - Config File Transfer",
        indicator: "TFTP / SCP transfer of config-shaped files from network device",
        arkime: `ip.src == $NETWORK_DEVICES
&& port.dst == [69 || 22]
&& (protocols == tftp
    || (protocols == ssh && bytes-out > 5000))
&& filename =~
  /running-config|startup-config|
   \\.cfg$|\\.conf$|config\\.txt/i`,
        kibana: `source.ip: $NETWORK_DEVICES
AND destination.port: (69 OR 22)
AND file.name: (running-config* OR startup-config* OR *.cfg OR *.conf)`,
        suricata: `alert udp $NETWORK_DEVICES any
  -> $HOME_NET 69
  (msg:"TA0009 T1602.002 TFTP
    transfer of config-shaped
    file from network device";
  pcre:"/(running-config|
    startup-config|\\.cfg|\\.conf|
    config\\.txt)/i";
  classtype:trojan-activity;
  sid:9160203; rev:1;)`,
        notes: "After triggering the SNMP config copy (or via direct SSH show running-config | redirect), network devices send the config file via TFTP (UDP/69) or SCP (TCP/22) to a destination. Filename patterns: running-config, startup-config, hostname-confg, *.cfg, *.conf. Detection: file transfers from network devices with these naming patterns. Particularly anomalous when destination is NOT the configured TACACS+/syslog/management server (build $NETWORK_MGMT_HOSTS allowlist). TFTP is unencrypted and trivially captured - passive attackers on the segment can grab configs from legitimate TACACS push operations as well. Modern best practice: disable TFTP entirely, use SCP with key-based auth, or SFTP, or vendor-specific encrypted config transfer. Volt Typhoon-style living-off-the-land operations use the device's own config-copy mechanisms to avoid dropping tools.",
        apt: [
          { cls: "apt-cn", name: "Volt Typhoon", note: "Documented exfiltrating router configs from US infrastructure targets per CISA AA23-144A." },
          { cls: "apt-cn", name: "APT41", note: "Network device targeting in telecom/ISP operations." },
          { cls: "apt-ru", name: "APT28", note: "Historical config theft in espionage." },
          { cls: "apt-mul", name: "Multi", note: "Used for reconnaissance/collection before subsequent operations." }
        ],
        cite: "MITRE ATT&CK T1602.002, CISA AA23-144A"
      }
    ]
  },
  {
    id: "T1074.001",
    name: "Data Staged: Local Data Staging",
    desc: "Staging in non-standard local directories - Recycle Bin, Temp, ProgramData, Public",
    rows: [
      {
        sub: "T1074.001 - Local Staging Directories",
        indicator: "SMB write to staging directory patterns - Recycle Bin, ProgramData, temp paths",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == write
&& smb.path =~
  /\\$Recycle\\.Bin|\\\\Windows\\\\Temp|
   \\\\ProgramData|\\\\Users\\\\Public|
   PerfLogs|Intel\\\\Logs/i`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "write"
AND file.path: (*$Recycle.Bin* OR *Windows\\Temp* OR *ProgramData* OR *Users\\Public* OR *PerfLogs*)`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0009 T1074.001 SMB write
    to staging directory pattern
    data staging";
  flow:established,to_server;
  pcre:"/(\\$Recycle\\.Bin|
    \\\\Windows\\\\Temp|
    \\\\ProgramData|
    \\\\Users\\\\Public|PerfLogs)/i";
  classtype:trojan-activity;
  sid:9107401; rev:1;)`,
        notes: "Staging locations are chosen because they're: writeable by most users (including service accounts), often excluded from EDR/AV scanning, large enough for big archives, unlikely to be reviewed by users. Common patterns: C:\\$Recycle.Bin\\... (looks like deleted files; rarely browsed), C:\\Windows\\Temp (generic temp; massive baseline of writes), C:\\ProgramData\\... (hidden by default; service-account writeable), C:\\Users\\Public\\... (legitimately writeable by all users), C:\\PerfLogs (often empty; always present), C:\\Intel\\Logs (looks like driver logs). Detection focuses on UNUSUAL files appearing in these locations: .zip/.rar/.7z archives, .dat/.bin generic blobs, oddly-named files. Pair with file SIZE thresholds - staged archives are typically >50MB. Also pair with subsequent SMB read of the same files (preparation for exfil pulls them out) or outbound transfer matching the file size profile.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Staging in non-standard directories universal across ransomware double-extortion." },
          { cls: "apt-cn", name: "APT41", note: "Documented in operations against tech sector." },
          { cls: "apt-ru", name: "APT29", note: "Used in long-term espionage operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all data-theft operations." }
        ],
        cite: "MITRE ATT&CK T1074.001"
      }
    ]
  },
  {
    id: "T1074.002",
    name: "Data Staged: Remote Data Staging",
    desc: "Aggregation of large files at internal staging host - multi-source collection patterns",
    rows: [
      {
        sub: "T1074.002 - Remote Staging Aggregation",
        indicator: "SMB write to internal staging share - large file collection at central host",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == write
&& smb.filesize > 104857600
&& destination-ip-write-volume groupby
  ip.dst > 1073741824 within 3600s`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "write"
AND file.size > 104857600`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0009 T1074.002 SMB write
    of large file 100MB+ remote
    staging activity";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9107402; rev:1;)`,
        notes: "Remote staging consolidates collection across many source hosts to one staging host inside the network - typically the host with the best outbound egress path. Pattern: multiple internal source IPs writing large files (>100MB) to one destination over short time window, accumulating to 1GB+ of inbound data at the destination. Common staging hosts: file servers (already trusted to receive bulk data), jump hosts (often have egress for legit reasons), forgotten dev servers (low monitoring). Detection: aggregate write volume per destination IP per hour; alert when total inbound writes exceed 1GB from multiple distinct sources. False positives: legitimate backup operations (allowlist $BACKUP_HOSTS), file server consolidation (allowlist $FILE_SERVERS - though those usually have outbound restrictions). Pair with subsequent outbound traffic from the staging host - the staging-then-exfil pattern is essentially diagnostic. Modern best practice: data exfiltration prevention via DLP at egress, but network-side staging detection catches the activity before egress.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Standard pattern in ransomware double-extortion before exfiltration." },
          { cls: "apt-ru", name: "APT29", note: "Remote staging in long-term espionage operations including SolarWinds." },
          { cls: "apt-cn", name: "APT41", note: "Multi-source data aggregation before exfiltration." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all data-theft operations." }
        ],
        cite: "MITRE ATT&CK T1074.002"
      }
    ]
  },
  {
    id: "T1560.001",
    name: "Archive Collected Data: Archive via Utility",
    desc: "Compression via 7-Zip / WinRAR / tar - archive file creation and password-protected archive patterns",
    rows: [
      {
        sub: "T1560.001 - Archive Files",
        indicator: "SMB write of archive files with adversary-typical naming - .zip/.rar/.7z bursts",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == write
&& smb.filename =~
  /\\.zip$|\\.rar$|\\.7z$|\\.tar\\.gz$|
   \\.tgz$|\\.tar$/i
&& smb.filesize > 10485760`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "write"
AND file.name: (*.zip OR *.rar OR *.7z OR *.tar.gz OR *.tgz OR *.tar)
AND file.size > 10485760`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0009 T1560.001 SMB write
    of archive file 10MB+ archive
    collected data";
  flow:established,to_server;
  pcre:"/\\.(zip|rar|7z|tar\\.gz|
    tgz|tar)/i";
  classtype:trojan-activity;
  sid:9156001; rev:1;)`,
        notes: "Archive creation as part of collection: 7-Zip, WinRAR, tar+gzip on Linux. Typical archives are 10MB-10GB depending on data volume. Detection: SMB write of files with archive extensions exceeding 10MB threshold. Adversary-typical naming patterns: random short names (a.zip, x.rar), date-stamped (2025-04-30.zip), location-named (data.zip, files.rar, backup.7z). Sophisticated adversaries password-protect archives - visible at archive header level: ZIP central directory, RAR header, 7z header all reveal encryption flags without revealing contents. False positives: legitimate backup archives, software distribution packages, IT operations. Build $BACKUP_HOSTS allowlist. The 10MB threshold filters out most legitimate small archives (installer .zips, log bundles) while catching realistic data-theft archives. Pair with subsequent outbound transfer of files matching the size profile and with staging-directory writes (sid 9107401).",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Universal in ransomware double-extortion: collect, archive, exfiltrate, then encrypt." },
          { cls: "apt-ru", name: "APT29", note: "Archive creation in long-term espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Documented in operations across multiple sectors." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Documented in CISA AA23-320A operations." },
          { cls: "apt-mul", name: "Multi", note: "Universally documented across data-theft operations." }
        ],
        cite: "MITRE ATT&CK T1560.001, CISA AA23-320A"
      },
      {
        sub: "T1560.001 - Encrypted Archives",
        indicator: "SMB write of password-protected archive - encryption header in file content",
        arkime: `ip.src == $INTERNAL
&& port.dst == 445
&& protocols == smb
&& smb.command == write
&& smb.filename =~ /\\.zip$|\\.rar$|\\.7z$/i
&& file-content-bytes-1to8 ==
  [PK signature with encrypt flag
   || RAR! signature
   || 7z BCAF271C signature]`,
        kibana: `source.ip: $INTERNAL
AND destination.port: 445
AND smb.command: "write"
AND file.name: (*.zip OR *.rar OR *.7z)
AND file.encrypted: true`,
        suricata: `alert tcp $HOME_NET any
  -> $HOME_NET 445
  (msg:"TA0009 T1560.001 SMB write
    of password-protected archive
    encrypted archive collection";
  flow:established,to_server;
  content:"PK"; depth:2;
  content:"|01 00|"; offset:6; depth:2;
  classtype:trojan-activity;
  sid:9156002; rev:1;)`,
        notes: "Password-protected archives are a strong adversary signal - legitimate enterprise file sharing rarely uses password-protected ZIPs (people use proper file sharing platforms instead). When they DO appear, it's often: (1) DLP-evading exfil prep (encrypted archive defeats simple DLP keyword scanning), (2) ransomware staging before exfil (archives are encrypted to prevent recovery), (3) insider data theft. Detection: ZIP files with general-purpose-bit-flag bit 0 set (encrypted), RAR files with HEAD_FLAGS encrypted bit, 7z files with header encryption. Zeek's file analyzer can extract these flags. The signature shown is simplified; full implementation needs file-format-aware parsing. Particularly investigate when password-protected archives appear in staging directories (combine with sid 9107401). Treat as high-priority alert: encrypted-archive-on-network is one of the highest-fidelity collection-prep signals.",
        apt: [
          { cls: "apt-mul", name: "Ransomware", note: "Password-protected archives to evade DLP scanning before exfiltration." },
          { cls: "apt-ru", name: "APT29", note: "Encrypted archives in espionage operations." },
          { cls: "apt-mul", name: "Insider Threat", note: "Common in insider data theft to defeat content inspection." },
          { cls: "apt-mul", name: "Multi", note: "Documented across advanced operations using DLP-evading techniques." }
        ],
        cite: "MITRE ATT&CK T1560.001"
      }
    ]
  }
];
