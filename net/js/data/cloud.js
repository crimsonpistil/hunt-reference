// TA0006/TA0004/TA0005/TA0010 (cloud) - Cloud Control Plane Hunt Reference
// Identity is the perimeter. Detection layer is the cloud audit log
// (AWS CloudTrail, Azure Activity/Entra sign-in, GCP Cloud Audit Logs),
// ingested into Elastic. KQL below assumes ECS-normalized cloud fields
// (event.provider, cloud.*, aws.cloudtrail.*, azure.*). Network egress
// correlation (Arkime/Suricata) is provided where a real wire-side angle
// exists; where detection is cloud-side only, the note says so plainly.
//
// Variables: $CLOUD_ADMINS (sanctioned admin principals), $CI_PRINCIPALS
// (CI/CD + automation identities), $CORP_CIDR (corporate egress ranges),
// $KNOWN_REGIONS (regions you operate in), $BREAKGLASS (emergency accounts).

const DATA = [
  {
    id: "T1078.004",
    name: "Valid Accounts: Cloud Accounts",
    desc: "Abuse of legitimate cloud identities - stolen keys, session hijack, impossible travel, unused-credential reactivation",
    rows: [
      {
        sub: "T1078.004 - Impossible Travel / Geo-Velocity",
        indicator: "Successful console or API auth for one principal from two geographically impossible locations within a short window",
        kibana: "event.provider: (\"signin.amazonaws.com\" OR \"AzureActiveDirectory\")\nAND event.outcome: \"success\"\nAND event.action: (\"ConsoleLogin\" OR \"UserLoggedIn\")\n// aggregate by user.name over source.geo.country_name\n// alert when >1 country per principal within 60m",
        suricata: "[Cloud-side detection only. Impossible\ntravel is computed by aggregating\nauth events by principal across\nsource.geo over time - this is a SIEM\naggregation / Entra risk-detection\njob, not a packet signature. Feed\nCloudTrail + Entra sign-in logs to\nElastic and run a geo-velocity rule.]",
        notes: "Classic stolen-credential tell. One identity authenticates from two locations whose distance exceeds any plausible travel speed inside the time gap. AWS: ConsoleLogin + AssumeRole events in CloudTrail carry sourceIPAddress; enrich to geo. Azure/Entra: sign-in logs already emit a risk detection for this (riskEventType: impossibleTravel) - ingest and alert on it rather than rebuilding it. FALSE POSITIVES: corporate VPN egress that lands in a different region than the user, mobile carriers using distant CGNAT egress, and cloud-shell/API calls that appear to originate from the provider's own ranges. Build $CORP_CIDR and VPN concentrator allowlists first. Pair with: MFA state (was the second login MFA-satisfied or was it a session-token replay?), user-agent change, and whether the second location performed sensitive actions (IAM changes, key creation). Impossible travel alone is a lead; impossible travel followed by privilege enumeration is an incident.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Cloud identity abuse and session/token theft documented across O365/Entra intrusions (CISA AA24-057A)." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Session hijack + SIM-swap MFA bypass to ride valid cloud identities (CISA AA23-320A)." },
          { cls: "apt-mul", name: "Multi", note: "Universal for stolen-credential cloud access." }
        ],
        cite: "MITRE ATT&CK T1078.004, CISA AA24-057A, AA23-320A"
      },
      {
        sub: "T1078.004 - Access Key Used From New ASN",
        indicator: "Long-lived IAM access key suddenly used from an ASN / hosting provider it has never used before",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND aws.cloudtrail.user_identity.access_key_id: *\nAND NOT source.ip: $CORP_CIDR\n// baseline (principal -> historical ASN set)\n// alert on first-seen ASN, esp. VPS/hosting ASNs",
        arkime: "// Correlation only: if the key was used\n// from inside your own egress, you may\n// see the outbound API call to the\n// cloud endpoint in capture:\nip.src == $CORP_CIDR\n&& host.dns == *.amazonaws.com\n&& port.dst == 443",
        suricata: "[Primary detection is CloudTrail-side.\nNetwork capture only helps if the API\ncall egressed through your sensors.\nUse the KQL baseline for the real\ndetection; wire-side is corroboration.]",
        notes: "Programmatic access keys (AKIA...) are the cloud equivalent of a reusable password and are the most commonly leaked cloud secret (git commits, CI logs, public S3, laptop theft). A key that has only ever been used from your CI runners or corporate egress suddenly calling from a VPS provider (DigitalOcean, OVH, Hetzner, a residential-proxy ASN) is high-signal. Detection: baseline each access_key_id to its historical set of source ASNs / IPs, alert on first-seen. FALSE POSITIVES: legitimately new CI regions, a developer traveling, a new SaaS integration using the key. Build $CI_PRINCIPALS and known-integration allowlists. The strongest chain is new-ASN key use FOLLOWED BY discovery calls (GetCallerIdentity, ListBuckets, ListUsers) - stolen-key operators orient themselves immediately. AWS best practice this feeds: prefer short-lived role credentials over long-lived keys; this hunt also inventories which keys are still long-lived.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Cloud key abuse against tech/cloud-native targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Access-broker key theft precedes cloud data theft and extortion." },
          { cls: "apt-mul", name: "Multi", note: "Leaked-key abuse is ubiquitous." }
        ],
        cite: "MITRE ATT&CK T1078.004, T1552.001"
      },
      {
        sub: "T1078.004 - Dormant Account Reactivation",
        indicator: "A cloud identity with no activity for an extended period suddenly authenticates and acts",
        kibana: "event.provider: (\"signin.amazonaws.com\" OR \"AzureActiveDirectory\")\nAND event.outcome: \"success\"\n// compare event timestamp to last-seen\n// per principal; alert if gap > 90d\n// AND next actions are sensitive",
        suricata: "[Cloud-side detection only. Dormancy is\na per-principal last-seen aggregation\nover audit logs - SIEM job, not a\npacket signature.]",
        notes: "Attackers love accounts nobody watches: former employees not fully deprovisioned, service accounts for a retired project, break-glass accounts. A principal silent for 90+ days that logs in and starts doing things is worth a look, especially if it skips normal onboarding patterns (no prior MFA registration event, first action is high-value). Detection: maintain per-principal last-seen; alert on reactivation past a threshold gap. FALSE POSITIVES: seasonal/contractor accounts, quarterly audit logins, DR test accounts, $BREAKGLASS during a real incident (correlate with change tickets). This hunt doubles as hygiene: the dormant-account inventory it produces is exactly what IAM should be deprovisioning.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Targets under-monitored identities and service principals in cloud tenants." },
          { cls: "apt-mul", name: "Multi", note: "Dormant/orphaned account abuse is a standard access-persistence play." }
        ],
        cite: "MITRE ATT&CK T1078.004"
      }
    ]
  },
  {
    id: "T1098.001",
    name: "Account Manipulation: Cloud Credentials",
    desc: "Persistence via new keys, added credentials to principals/service accounts, and federation tampering",
    rows: [
      {
        sub: "T1098.001 - New Access Key On Existing User",
        indicator: "CreateAccessKey / add credential to a principal, especially by a different principal or onto a privileged user",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: \"CreateAccessKey\"\nAND NOT aws.cloudtrail.user_identity.arn: $CI_PRINCIPALS\n// flag when actor != target user\n// or target user is in $CLOUD_ADMINS",
        suricata: "[Cloud-side detection only. This is a\ncontrol-plane API event in CloudTrail /\nAzure Activity Log; no wire signature.]",
        notes: "A durable persistence primitive: an attacker who compromises one identity mints a second access key so they keep access even if the first credential is rotated. High-signal variants: (1) actor principal differs from the user the key is created ON - lateral credential planting; (2) key created on a $CLOUD_ADMINS member; (3) key created immediately after a suspicious login. Azure/Entra equivalents: addKey / addPassword to a service principal or application (watch Add service principal credentials in the audit log) - a heavily abused APT29 technique for tenant persistence. FALSE POSITIVES: legitimate key rotation (usually paired with a DeleteAccessKey shortly after and performed by the user themselves or IAM automation), onboarding. Build $CI_PRINCIPALS and rotation-automation allowlists. Chain to watch: CreateAccessKey -> the new key used from a new ASN within minutes.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Adds credentials to service principals/apps for durable Entra tenant persistence (CISA AA24-057A)." },
          { cls: "apt-mul", name: "Scattered Spider", note: "Creates additional access paths after initial cloud compromise." },
          { cls: "apt-mul", name: "Multi", note: "Standard cloud persistence." }
        ],
        cite: "MITRE ATT&CK T1098.001, T1098.003, CISA AA24-057A"
      },
      {
        sub: "T1098.001 - Federation / Identity Provider Tampering",
        indicator: "Changes to trust: new SAML/OIDC IdP, added federation, or updated trust policy allowing external principals",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: (\"CreateSAMLProvider\" OR \"UpdateSAMLProvider\"\n  OR \"UpdateAssumeRolePolicy\" OR \"UpdateOpenIDConnectProviderThumbprint\")\n// Entra: \"Set federation settings on domain\",\n// \"Add unverified domain\", \"Set domain authentication\"",
        suricata: "[Cloud-side detection only. Federation\nchanges are control-plane events; the\ndetection lives in CloudTrail / Entra\naudit logs.]",
        notes: "The apex cloud-persistence move. If an attacker can add a federated identity provider or alter a role trust policy, they can mint valid tokens for ANY identity without touching a password again - the cloud version of a Golden SAML / Golden Ticket. AWS: CreateSAMLProvider, UpdateAssumeRolePolicy widening a role to trust an external account or '*'. Azure/Entra: adding a federated domain, changing domain authentication to federated, or altering token-signing configuration (the AADInternals-style attack APT29 used in SolarWinds follow-on activity). These events are RARE in a stable tenant, which makes them excellent detections: alert on essentially every occurrence and verify against a change ticket. FALSE POSITIVES: genuine SSO onboarding, M&A tenant work, planned IdP migration - all of which should have change records. There is almost no benign high-frequency source for these events; treat unexplained ones as priority-1.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Golden SAML / federated trust manipulation for tenant-wide token forgery (SolarWinds follow-on, CISA AA24-057A)." },
          { cls: "apt-mul", name: "Multi", note: "Federation tampering is the highest-impact cloud persistence class." }
        ],
        cite: "MITRE ATT&CK T1098.001, T1484.002, CISA AA24-057A"
      }
    ]
  },
  {
    id: "T1580",
    name: "Cloud Infrastructure Discovery",
    desc: "Post-access orientation - enumeration bursts across IAM, storage, compute, and account metadata",
    rows: [
      {
        sub: "T1580 - Enumeration Burst After First Access",
        indicator: "Many distinct List*/Describe*/Get* read calls from one principal in a short window shortly after auth",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: (List* OR Describe* OR Get*)\nAND aws.cloudtrail.read_only: true\n// alert when distinct action count per\n// principal > 30 within 10m, esp. if the\n// principal is newly authed or new-ASN",
        suricata: "[Cloud-side detection only. Enumeration\nis a rate/variety pattern over read-only\nAPI events - a SIEM aggregation, not a\npacket signature.]",
        notes: "Stolen-credential operators don't know the environment, so their first move is to orient: who am I (GetCallerIdentity), what can I touch (ListBuckets, ListUsers, ListRoles, DescribeInstances, GetAccountAuthorizationDetails). The tell is VARIETY and RATE - dozens of distinct read-only actions from one principal in minutes, often ones that principal has never called before. Detection: per-principal distinct read-only action count in a sliding window; weight higher if the principal was flagged by any T1078.004 hunt. FALSE POSITIVES: cloud security posture tools (Prowler, ScoutSuite, Wiz, Steampipe), infra-as-code plan/refresh (Terraform), backup and inventory jobs - these enumerate broadly by design. Build $CI_PRINCIPALS and scanner-identity allowlists; those are exactly the identities that legitimately enumerate. After exclusions, an interactive human principal enumerating broadly is a strong lead. GetAccountAuthorizationDetails specifically (dumps the entire IAM graph) is a favorite of attackers mapping privilege-escalation paths - alert on it outside known posture tooling.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Rapid cloud enumeration after identity compromise (CISA AA23-320A)." },
          { cls: "apt-cn", name: "APT41", note: "Systematic cloud resource discovery in intrusions." },
          { cls: "apt-mul", name: "Multi", note: "Enumeration precedes nearly all cloud attacker objectives." }
        ],
        cite: "MITRE ATT&CK T1580, T1526, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1548.005",
    name: "Abuse Elevation Control: Temporary Cloud Credentials",
    desc: "Privilege escalation through IAM policy abuse, role assumption chains, and permission self-grants",
    rows: [
      {
        sub: "T1548.005 - IAM Privilege Self-Escalation",
        indicator: "A principal grants itself or a controlled principal more permissions: attach admin policy, PutUserPolicy, PassRole into a privileged role",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: (\"AttachUserPolicy\" OR \"AttachRolePolicy\"\n  OR \"PutUserPolicy\" OR \"PutRolePolicy\" OR \"CreatePolicyVersion\"\n  OR \"AddUserToGroup\")\n// flag when policy grants \"*\":\"*\" or\n// AdministratorAccess, or actor == target",
        suricata: "[Cloud-side detection only. Policy\nmutations are control-plane events in\nCloudTrail / Azure Activity Log.]",
        notes: "Cloud priv-esc is usually not an exploit - it's IAM being used as designed by someone who shouldn't. Known escalation primitives to hunt: attaching AdministratorAccess or a wildcard policy to a controlled principal; CreatePolicyVersion + SetDefaultPolicyVersion to quietly widen an existing policy; iam:PassRole combined with a service (Lambda/EC2/Glue) to run code as a more privileged role; AddUserToGroup into an admin group. Azure: role assignment changes granting Owner/Contributor/User Access Administrator; adding to privileged Entra roles (Global Administrator, Privileged Role Administrator). Detection: alert on policy/role mutations whose RESULT is broad privilege, weight higher when actor == target (self-escalation) or actor was flagged upstream. FALSE POSITIVES: IAM/platform teams doing legitimate grants, IaC applying policy - all of which should come from $CI_PRINCIPALS or known admin principals with change records. The dangerous chain: compromised low-priv identity -> PassRole/policy attach -> now admin -> data access. Detecting the middle step is the intervention point.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "IAM manipulation to escalate within compromised cloud tenants (CISA AA23-320A)." },
          { cls: "apt-mul", name: "Ransomware", note: "Privilege escalation before cloud data theft/destruction." },
          { cls: "apt-mul", name: "Multi", note: "IAM-native escalation is the dominant cloud priv-esc path." }
        ],
        cite: "MITRE ATT&CK T1548.005, T1098, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1562.008",
    name: "Impair Defenses: Disable Cloud Logging",
    desc: "Blinding the defender - stopping/deleting audit trails and altering log delivery",
    rows: [
      {
        sub: "T1562.008 - CloudTrail / Audit Log Tampering",
        indicator: "StopLogging, DeleteTrail, UpdateTrail, or delete/alter of the audit-log delivery pipeline",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: (\"StopLogging\" OR \"DeleteTrail\"\n  OR \"UpdateTrail\" OR \"PutEventSelectors\")\n// Azure: \"Delete diagnostic setting\",\n// \"Update diagnostic setting\"\n// GCP: \"UpdateSink\" / \"DeleteSink\"",
        suricata: "[Cloud-side detection only - and note the\nirony: the log source you'd detect this\nin is the one being disabled. Ship audit\nlogs OFF the account in near-real-time so\ntampering can't erase the evidence of\ntampering.]",
        notes: "A defense-evasion move with a built-in paradox: the attacker disables the very log that would record the disabling - so the LAST event before the gap is your detection. StopLogging (AWS), deleting/updating a trail to stop capturing management events, narrowing event selectors, or on Azure/GCP deleting diagnostic settings / log sinks. Detection: alert on ANY of these actions immediately (they are rare and almost never benign at speed), and separately alert on a LOGGING GAP - the absence of expected CloudTrail heartbeat is itself a signal. CRITICAL ARCHITECTURE: forward cloud audit logs to a separate, tightly-controlled logging account / external SIEM in near-real-time, so a tenant compromise can't retroactively erase the trail. FALSE POSITIVES: legitimate trail reconfiguration during platform work (should have a change ticket), region decommissioning. Given the stakes, treat unexplained log-tampering as priority-1 and assume it brackets other activity.",
        apt: [
          { cls: "apt-mul", name: "Scattered Spider", note: "Disables cloud logging/security tooling to operate unobserved (CISA AA23-320A)." },
          { cls: "apt-cn", name: "APT41", note: "Defense evasion including log manipulation in sustained intrusions." },
          { cls: "apt-mul", name: "Multi", note: "Log tampering is a near-universal pre-objective step." }
        ],
        cite: "MITRE ATT&CK T1562.008, CISA AA23-320A"
      }
    ]
  },
  {
    id: "T1537",
    name: "Transfer Data to Cloud Account",
    desc: "Exfil that never leaves the provider - snapshot sharing, bucket policy opening, cross-account replication",
    rows: [
      {
        sub: "T1537 - Snapshot / Image Shared to External Account",
        indicator: "EBS/RDS snapshot or AMI attribute changed to share with an unknown external account, or made public",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: (\"ModifySnapshotAttribute\"\n  OR \"ModifyImageAttribute\" OR \"ModifyDBSnapshotAttribute\"\n  OR \"ShareDirectory\")\n// alert when target account NOT in your\n// org account list, or 'all' (public)",
        suricata: "[Cloud-side detection only. The data\nnever traverses your network - it moves\nprovider-internally to the attacker's\naccount. Only the control-plane API call\nis visible, in CloudTrail.]",
        notes: "The stealthiest cloud exfil: the attacker never downloads anything through your egress, so network monitoring sees nothing. Instead they snapshot a volume/database and SHARE the snapshot with an AWS account they control, or replicate a bucket cross-account, then read it from their side. Detection is entirely control-plane: ModifySnapshotAttribute / ModifyImageAttribute adding an external account ID or 'all' (public); CreateDBSnapshot followed by a share; PutBucketPolicy / PutBucketAcl opening a bucket to an external principal or public; S3 replication configured to an external-account bucket. Maintain your org's known account-ID list; alert on any share to an ID outside it and on any public grant. FALSE POSITIVES: legitimate cross-account sharing within your org, sanctioned data-partner accounts (allowlist them), public buckets that are public by design (static sites - inventory these so the alert is meaningful). This is a top hunt for cloud data-theft precisely because it defeats network-centric detection - it belongs in every cloud hunt program.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Cloud-native data theft techniques against cloud-hosted targets." },
          { cls: "apt-mul", name: "Ransomware", note: "Snapshot/bucket exfil for double-extortion before destruction." },
          { cls: "apt-mul", name: "Multi", note: "Provider-internal transfer is the emerging cloud exfil standard." }
        ],
        cite: "MITRE ATT&CK T1537"
      },
      {
        sub: "T1537 - Resource Hijack / Unusual Region Spin-Up",
        indicator: "Compute launched in an unused region or at anomalous scale - resource hijack / staging",
        kibana: "event.dataset: \"aws.cloudtrail\"\nAND event.action: (\"RunInstances\" OR \"CreateCluster\"\n  OR \"StartInstances\")\nAND NOT cloud.region: $KNOWN_REGIONS\n// or instance count / size far above\n// baseline for the principal",
        suricata: "[Cloud-side detection only for the launch\nevent. If hijacked instances then beacon\nor mine, THAT egress may cross sensors -\nsee C2 (TA0011) and the cryptomining\nSNI/pool patterns there.]",
        notes: "Two motives share one signature: (1) resource hijack for cryptomining/proxyware - attackers spin up expensive GPU/compute in regions you don't use, hoping it hides in the billing noise; (2) staging - attackers stand up their own instances inside your account as a foothold or exfil relay. Detection: RunInstances / CreateCluster in a region outside $KNOWN_REGIONS, or instance type/count far above the launching principal's baseline (a dev who launches t3.micros suddenly launching GPU instances). FALSE POSITIVES: legitimate expansion into a new region (should have change records), DR drills, data-science workloads that genuinely need big instances - baseline per team. Pair with downstream signals: hijacked miners connect to mining pools (catch on the network side via SNI/pool ports in C2), and staging instances make outbound connections that don't fit normal patterns. Cost anomaly alerts from billing are a useful independent corroborator.",
        apt: [
          { cls: "apt-mul", name: "Multi", note: "Cloud resource hijack for mining/proxyware is widespread and financially motivated." },
          { cls: "apt-ir", name: "APT35", note: "Cloud resource abuse observed in operations." }
        ],
        cite: "MITRE ATT&CK T1537, T1496"
      }
    ]
  }
];
