# TONK • Threat Observation & Network Kill-chain

TONK is a single, self-contained static-web kit that bundles four threat-hunting surfaces behind one landing page, served from one origin so they share a single evidence list:

- **NET** (`net`): a MITRE ATT&CK-mapped *network* detection reference, with Arkime / Kibana / Suricata queries, APT attribution, and a global actor/IOC/technique search.
- **HOST** (`host`): the *host-side* companion, mapping endpoint detections (Sysmon, Windows events, PowerShell, registry/file artifacts) across the attack lifecycle, with the same attribution model and open-source detection references.
- **ATTRIB** (`attribution`): an evidence-driven adversary attribution engine that reads the indicators you starred in NET and HOST and ranks the likely threat actors, cross-nation, with continuity save/load so a hunt survives a session reset or moves between machines.
- **PLAYBOOKS** (`playbooks`): curated hunt sequences organized by threat actor, environment, exploit reference, and incident triage scenario, plus a scan importer that turns an nmap or Henmap export into a generated hunt plan. Each playbook is a prioritized checklist linking into the NET and HOST detection references.

Because all four live under one origin, the **My Hunts** evidence list is shared across them: star an indicator on NET or HOST and it lands in the same list, and ATTRIB scores all of it together. The same origin sharing carries the **environment profile**, so `$MPNET` and friends are mapped once per deployment and every surface picks them up. PLAYBOOKS provides the operational context: when intel drops an actor name or a detection fires, the playbook tells you what to look for next.

---

## Overview

TONK is meant to live somewhere an analyst can actually reach it: a hardened jump host, a lab VM, an air-gapped box. NET is the reference you reach for when you have an indicator on the wire and need the query, the context, and the threat-actor association. HOST is the same idea moved onto the endpoint: what the adversary does *inside* the box, and where to hunt it. ATTRIB is the analysis layer: once you have evidence on the board from either surface, it works backward from what you found to who is likely behind it. PLAYBOOKS is the operational layer: when intel names an actor or a detection fires, the playbook gives you the prioritized hunt sequence with cross-links into NET and HOST for each step. Together they cover "look it up fast on the wire," "look it up fast on the host," "figure out who it is," and "here is the checklist for what to do about it."

Everything is plain HTML, CSS, and vanilla JavaScript. There is no transpiler, bundler, package manager, or runtime dependency.

---

## Repository layout

```
hunt-reference/             # served at hunt.6b74.dev (one origin)
  index.html                # landing / chooser (NET · HOST · ATTRIB · PLAYBOOKS)
  CNAME                     # hunt.6b74.dev
  .nojekyll                 # disables Jekyll so js/ folders serve untouched
  net/                      # network detection reference - 9 tactic pages
    index.html              # matrix landing + global actor/keyword search
    recon.html              # one page per ATT&CK tactic
    initial_access.html
    discovery.html
    lateral.html
    credential.html
    collection.html
    c2.html
    exfil.html
    cloud.html              # cross-tactic: cloud control plane / identity
    css/style.css           # shared terminal theme + matrix styles
    js/
      env.js                # environment profile: $VARIABLE mapping + substitution
      core.js               # renders a tactic page, filters, the hunt list/export
      index.js              # landing-page tactic-card filter
      search.js             # global APT/keyword search (alias-aware)
      actors.js             # canonical actor reference: names, MITRE G-IDs, aliases
      data/                 # one DATA file per tactic (techniques + indicators)
        recon.js  initial_access.js  discovery.js  lateral.js
        credential.js  collection.js  c2.js  exfil.js  cloud.js
  host/                     # host-side detection reference - 8 tactic pages
    index.html              # host matrix landing
    execution.html          # one page per host ATT&CK tactic
    persistence.html
    privilege_escalation.html
    defense_evasion.html
    credential_access.html
    discovery.html
    lateral_movement.html
    impact.html
    css/style.css
    js/
      env.js  core.js  index.js  actors.js
      data/                 # execution.js  persistence.js  privilege_escalation.js
                            # defense_evasion.js  credential_access.js  discovery.js
                            # lateral_movement.js  impact.js
  attribution/
    index.html              # adversary attribution engine - single-file app
  playbooks/                # curated hunt playbooks - 45 index cards, 44 pages
    index.html              # playbook index
    generate.html           # scan importer: nmap XML / Henmap CSV -> hunt plan
    scan-correlation.js     # service/port/product -> technique, exploit, role table
    sample-nmap-scan.xml    # test fixture for the importer
    actors/                 # 13 threat actor playbooks
    environments/           # 10 environment playbooks
    exploits/               # 10 exploit reference playbooks
    triage/                 # 11 incident triage playbooks (3 tiers)
  .tools/                   # maintenance scripts (not served)
    lint-data.py            # data integrity checks for the indicator files
    sigma-export.py         # optional Sigma ruleset export (see Maintenance tooling)
```

---

## Running it
Access the live site at `hunt.6b74.dev` or serve the repo root over HTTP and open the landing page:

```
cd hunt-reference
python3 -m http.server 8000
```

Then browse to `http://localhost:8000/`. From the landing page, choose NET, HOST, ATTRIB, or PLAYBOOKS; the switcher in each header moves between all four.

Serving over HTTP matters: the NET global search uses `fetch()` to read the tactic data files, and browsers block `fetch()` under the `file://` scheme. It also matters for the environment profile and My Hunts, since `localStorage` is unavailable on an opaque `file://` origin. If you open `index.html` directly off disk, the search shows a hint explaining this, but the rest of the kit still works. ATTRIB is self-contained and runs fine either way, and the scan importer (`playbooks/generate.html`) is deliberately built to work under `file://` too.

**One origin, one evidence list.** Serving all four surfaces from the same origin is not incidental - it is what lets My Hunts and the environment profile span NET and HOST. `localStorage` is partitioned per origin, so if these surfaces were split across separate subdomains they would each keep their own, separate hunt list and their own variable mapping, and ATTRIB would only ever see one of them. Keeping them under `hunt.6b74.dev/...` is what makes the shared evidence flow work.

---

## NET (the network hunt reference)

A MITRE ATT&CK-organized matrix of network-observable detections.

**Coverage.** 9 tactics, 87 techniques, 358 indicators. Tactics: Reconnaissance, Initial Access, Discovery, Lateral Movement, Credential Access, Collection, Command and Control, Exfiltration, and Cloud Control Plane.

**Per-indicator content.** Each indicator row provides a plain-language description, copy-ready Arkime / Kibana / Suricata detections, an analyst note (hunt method, false-positive guidance, remediation), and a citation. Attribution lives in the expanded card's APT tab (not crowded onto the list rows), organized into three clearly separated sections: **Actors** (named threat groups), **Malware & Tooling** (named malware/frameworks like Emotet, Cobalt Strike), and **Activity & Roles** (categories like Red Team, Insider, IAB). Keeping malware and activity out of the actor field means a worm or a red-team note is never mistaken for threat-group attribution. Notes flag air-gap and off-network tripwires where relevant.

**Cloud control plane.** The CLOUD page is cross-tactic by design, because cloud intrusion does not respect the on-prem kill chain: identity is the perimeter and the detection layer is the audit log, not the wire. It covers valid-account abuse (impossible travel, access keys used from a new ASN, dormant account reactivation), credential and federation persistence including Golden SAML, post-access enumeration bursts, IAM privilege escalation, disabling cloud logging, and provider-internal exfiltration such as snapshot sharing to an external account. Queries target CloudTrail, Azure Activity and Entra sign-in logs, and GCP Cloud Audit Logs as normalized into Elastic. Where a detection is genuinely cloud-side only, the Suricata tab says so plainly rather than inventing a packet signature.

**Data model.** Each indicator row carries three sibling association arrays: `apt[]` (named threat actors, the single source of truth the ATTRIB engine scores against), `malware[]` (named malware and tooling), and `activity[]` (operator categories and roles). Only `apt[]` feeds attribution; the other two are context.

**Multi-query indicators.** Many indicators carry several independent queries in one field, each introduced by a `// label` header. These render as separate labelled blocks, each with its own Copy button, plus a Copy-all. This matters because copying a four-query field as one string produces something that is not valid as a single query. Three comment roles are recognized: a header that opens a block, a continuation line before any query content, and a trailing annotation that explains the clause above it and stays attached to that block.

**APT attribution.** Actor tags are color-coded by origin (`apt-cn`, `apt-ru`, `apt-kp`, `apt-ir`, and `apt-mul` for multi-actor / commodity). Coverage emphasizes infrastructure-focused actors that network hunters are well-placed to catch, including deep Volt Typhoon coverage and Salt Typhoon (Cisco Smart Install / CVE-2018-0171, network-device config dumps, GRE tunnels via device config, loopback-sourced SSH for ACL bypass, and FTP/TFTP config exfil), alongside APT41, APT29, Lazarus, Scattered Spider, APT28, Sandworm, APT10, Charming Kitten, Kimsuky, and many more.

**Actor reference and aliases.** A canonical actor reference (`net/js/actors.js`) maps each tracked actor to its MITRE ATT&CK group ID (Gxxxx) and known aliases, generated from the MITRE ATT&CK Groups export. Where the data used multiple names for one group, they collapse to a single canonical (so APT29 / Cozy Bear / Midnight Blizzard resolve to one actor, anchored by its G-number). This drives alias resolution in NET search, HOST, and ATTRIB. This reference is shared: ATTRIB loads it from `../net/js/actors.js`.

**Global search (NET landing page).** The NET landing page can search every tactic data file at once. Type an actor (for example `Salt Typhoon`) to see every indicator tagged with that actor, grouped by tactic, each linking straight to the technique on its tactic page. Search is alias-aware: it resolves any known name or alias to its canonical actor through `actors.js`, so `Cozy Bear`, `Midnight Blizzard`, and `APT29` all return the same indicators, and a reporting name that never appears in the data (for example `Vanguard Panda`) still finds its actor's rows (Volt Typhoon). Non-actor queries fall back to keyword matching across technique IDs/names, indicator text, notes, and citations (so `portproxy`, `GRE`, `T1090`, `TFTP` all resolve). Quick-actor chips surface the most-referenced named actors, merged by canonical name so aliases do not split into duplicate chips. Mechanically, the search fetches each data file as text and evaluates it in an isolated scope, which sidesteps the fact that every data file declares its own `const DATA` and avoids any changes to the data files themselves.

**Per-tactic filtering.** Each tactic page has its own search box and APT filter buttons to narrow the indicator list in place.

---

## HOST (the host-side hunt reference)

The endpoint companion to NET: where NET covers what adversaries do across the wire, HOST covers what they do inside the box.

**Coverage.** 8 tactics, 101 techniques, 182 indicators, spanning Windows and Linux. Tactics: Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, and Impact.

**Per-indicator content.** Each host indicator carries detection telemetry tuned to the endpoint: key Sysmon / Windows Event signatures, paste-ready Kibana KQL, PowerShell hunt snippets, registry and file artifacts, adversary tool attribution, and references to open-source detection projects (Sigma, Velociraptor, Hayabusa, Falco, and similar). Each row is tagged with the OS it applies to (Windows, Linux). Host indicators frequently pack several independent queries per field, so the multi-query block rendering described under NET applies here especially.

**Same attribution model.** HOST uses the same `apt[]` / `malware[]` / `activity[]` association model and the same origin classes as NET, so a host indicator's actor tags feed ATTRIB exactly like a network one. A hunt that combines host and network evidence is scored as a single body of evidence. HOST now loads the shared `actors.js`, so alias collapsing applies to HOST in-page filtering as well as to NET search and ATTRIB scoring.

**Note on variables.** HOST indicators use no `$VARIABLE` placeholders. This is not an omission: host detection is categorical (process names, registry paths, command lines) while network detection is topological (subnets, server roles, VLANs). The environment profile is therefore effectively a NET-surface feature, and the panel on a HOST page will honestly report zero variables to map.

---

## Environment profile (mapping `$VARIABLES` to your network)

Indicator queries are written against placeholders (`$MPNET`, `$DOMAIN_CONTROLLERS`, `$ALLOWED_DEFAULTS`) so the reference stays portable across deployments. The environment profile is where those placeholders get bound to a real network, once, instead of being hand-edited on every copy.

Open it from the **Environment** button in any tactic page header. The profile is stored in `localStorage` under `tonk_env_v1` and, like My Hunts, is shared across every surface on the origin.

**Three classes of variable, deliberately treated differently.**

- **Observable.** Things a network scan could legitimately tell you: subnets, server roles, VLANs. `$MPNET`, `$DOMAIN_CONTROLLERS`, `$DNS_SERVERS`, `$FILE_SERVERS`.
- **Policy.** Things that encode what is *permitted*, not what exists: `$ALLOWED_DEFAULTS`, `$SANCTIONED_SSH_DESTS`, `$APPROVED_OUI_PREFIXES`, `$SSH_ADMINS`. These are analyst-defined only, and the panel says why: if you fill an allowlist from observed traffic, the allowlist becomes a description of reality and the detection can never fire. Any variable the profile does not recognize defaults to policy, so nothing new is ever silently auto-populated.
- **Suricata built-ins.** `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_SERVERS` and friends are resolved by Suricata itself from `suricata.yaml`. TONK leaves them untouched in rules and instead offers a downloadable `vars: address-groups:` block generated from your profile, which is the correct place to define non-built-in variables like `$MPNET` for Suricata.

**Where substitution applies.** Arkime and Kibana fields only, because those are the ones you paste into a search bar. Suricata rules keep their variables, and the Sysmon / PowerShell / auditd script fields are left untouched on purpose: those contain local shell variables (`$BASELINE`, `$HAVE_RPM`, `$BINS`, `$LASTEXITCODE`) that substitution would corrupt. Substitution reaches the rendered query, every Copy button (per-block, copy-all, and the header quick-copy), and the My Hunts TXT / CSV / CMS exports, so a package handed to TheHive is not still full of `$MPNET`.

**Unmapped variables are loud on purpose.** Any query panel with unresolved variables shows an amber `N unmapped` badge listing them. This is the failure mode the feature exists to prevent: a query pasted with `$MPNET` still in it returns zero hits, and zero hits reads as a clean network.

**Portability.** Export the profile as JSON and ship it inside the kit, so every analyst on that network opens to a mapped reference instead of filling the form themselves. Import restores it. This is also how a profile moves between the offline kit and the online site, which are different origins and therefore different `localStorage`, and how it survives a browser profile reset on a locked-down workstation.

**Two-tier use.** A senior analyst authors the profile, especially the policy variables, which encode environment intent that no tool can infer. A junior inherits it as shipped JSON and never hand-fills a variable. Same artifact, opposite relationship to it.

The panel shows a live coverage readout ("N of M variables mapped, X of Y indicators fully resolved") and a per-variable usage count, so you can see which mappings buy the most. The distribution is lopsided: mapping `$MPNET`, `$EXTERNAL`, `$ALLOWED_DEFAULTS`, and `$DOMAIN_CONTROLLERS` clears the majority of queries.

---

## ATTRIB (adversary attribution)

A single-file app (`attribution/index.html`) that answers the working analyst's question: *given what I have found, who is likely behind it?* It is evidence-driven and assumes no adversary up front, and it scores network and host evidence together.

**Reads your hunt evidence.** On load, ATTRIB reads the indicators you starred in NET and HOST (`localStorage` key `hunt_reference_hunts_v1`) directly. No re-entry, no jumping between tools. Because all three surfaces share one origin, this is the same list the hunt surfaces write to. A source badge shows where the current evidence came from (live hunt tool, a loaded state file, or a CSV import).

**Scoring.** For every indicator in the evidence set, the engine walks that indicator's `apt` attribution array and ranks the named actors. Actor names are resolved to canonical through `actors.js`, so aliases collapse into one ranked actor (APT29 / Cozy Bear / Midnight Blizzard count together, not as three), with same-group aliases on a single indicator de-duplicated so they are not double-counted. Scoring is cross-nation with no hardcoded roster: it ranks whatever actors the evidence points to, so adding new indicators (network or host, for any actor, any nation) enriches attribution automatically. The default model is **distinctiveness + corroboration**: an indicator that names one actor gives that actor full credit, while one that names eight splits the credit eight ways, so distinctive indicators outweigh crowd-tagged ones; an actor seen across several distinct techniques earns a gentle corroboration bonus on top. A **FLAT** scoring toggle is available for comparison, where every named actor scores equally per indicator. Generic / commodity tags (`apt-mul`, "Multi", "Ransomware", and similar) are excluded from the named ranking entirely and surfaced separately.

**Confidence margin.** Because absolute scores are arbitrary, the engine leads with the **separation** between the top two candidates, which is the real analytic product. The margin is classified plainly: STRONG LEAN, MODERATE LEAN, WEAK LEAN, or TOSS-UP, so the readout tells you not just who ranks first but how much daylight there is to second.

**Honest about ambiguity.** Generic / commodity attribution is surfaced as its own line rather than hidden. When a large share of the evidence is commodity tradecraft, ATTRIB says so plainly ("not strongly attributable to a single named actor") so a weak signal is never dressed up as a confident call. Analyst-set severity is displayed alongside each indicator but does not affect the score; presence of the technique is what counts.

**Lens.** A nation lens (ALL / CHINA / RUSSIA / IRAN / DPRK) filters the ranking to one origin class or shows everything. It is a view over one engine, not separate walled-off pages.

**Continuity.** Because `localStorage` alone is fragile (a cleared browser or reset box loses an in-progress hunt), ATTRIB treats a file as the system of record:
- *Save state* downloads the full evidence set as a timestamped, schema-versioned `.json` (every indicator, severity, and timestamp; not just the CSV view).
- *Load state* restores a saved `.json` back into the engine. Load is **replace-with-guard**: if you have unsaved evidence loaded, it warns and offers to save the current state before overwriting.
- *CSV import* ingests a `hunt_package.csv` export as a fallback for a hunt that happened on another machine. The CSV has no attribution column, so ATTRIB recovers attribution from live hunt data where it can and reports honestly when it cannot.
- *Autosave checkpoint* periodically serializes the working set to `localStorage` (`attribution_autosave_v1`) and recovers from it on load, shrinking the worst-case loss window to minutes.

---

## PLAYBOOKS (curated hunt sequences)

Operational playbooks organized by threat actor, environment, exploit reference, and incident triage scenario. Each playbook is a prioritized checklist that an analyst can work through when intel drops an actor name, a detection fires, or they need to scope an environment. Playbook steps cross-link into the NET and HOST detection references so each step has the corresponding query and detection telemetry behind it.

**Coverage.** 45 index cards backed by 44 playbook pages. Sourced from CrowdStrike 2026 Global Threat Report, Dragos 2026 OT Year in Review, Mandiant M-Trends 2026, CISA advisories, and ongoing threat intelligence reporting.

**Threat actors (13 playbooks).** Nation-state actors organized by country: China (Volt Typhoon, Salt Typhoon, APT41), Russia (APT28, APT29, Sandworm), Iran (APT35/Charming Kitten, MuddyWater, APT42), and DPRK (Lazarus). eCrime: Scattered Spider and the RaaS Ecosystem (the ransomware supply chain model). Hacktivists: a 3-tier spectrum from script kiddies to state-aligned pseudo-hacktivists. Each actor playbook includes an operational profile, documented TTPs, a prioritized hunt checklist with detection references, custom tooling inventory, and cross-links to related triage playbooks.

**Environments (10 playbooks).** Quick Start, Air-Gapped OT/ICS (Purdue Level 2-3, no cloud EDR, Zeek/Suricata/Sysmon-based detection, control-loop mapping by VOLTZITE and KAMACITE), Air-Gapped IT, Hybrid AD Enterprise (on-prem to Entra ID attack paths), Cloud Control Plane, Kubernetes, Linux Server Fleet, macOS Fleet, SOHO Router, and AI/LLM infrastructure.

**Exploit reference (10 playbooks).** EternalBlue/MS17-010, the SharePoint CVE chain, Log4Shell, ProxyLogon, PrintNightmare, PetitPotam/ADCS, Citrix Bleed, the Ivanti chain, the ESXi chain, and PAN-OS/FortiGate edge device exploitation. Each carries detection signatures across Suricata, Zeek, and Arkime plus sector-specific impact analysis.

**Incident triage (11 playbooks, 3 tiers).**
- *Tier 1 (you will see these):* Ransomware Detected, Compromised Credentials, C2 Beacon Found, Business Email Compromise.
- *Tier 2 (common and growing):* Edge Device Compromised, Supply Chain Indicator, Data Exfiltration Detected, SaaS Account Hijack.
- *Tier 3 (specialized, high-impact):* Living-off-the-Land Activity, Infostealer Infection, Insider Threat.

**Scan importer (`generate.html`).** Drop an nmap XML or a host-port CSV export and the page correlates it in-browser into a generated hunt playbook: ICS/OT protocol exposure first, then ranked exploit leads with CVE and affected hosts, then hunt leads grouped by tactic with links into the detection references, then role deviations and version findings that cleared. The correlation table (`scan-correlation.js`) maps service and port to ATT&CK technique, product and version to exploit reference, and OS match to a device role hint with deviation flagging. nmap XML is the preferred input because it carries the scan metadata (real command line, scan start time, nmap version) that renders in the generated playbook's provenance stamp.

Generated output is deliberately fenced: a distinct identity, a timestamp, the scan source, and a banner stating it is a plan and not a finding, so it can never be mistaken for an authored and vetted playbook. Every exploit lead is `verified:false` by design, because a reported version is not a confirmed compromise, and version gating actively clears hosts whose versions are not vulnerable. For ICS protocols the principle encoded is that these protocols have no native authentication, so reachability implies controllability: reachable *is* the finding, and every entry names the Purdue zone-boundary check and hands it to the operator.

The importer runs entirely client-side (FileReader and DOMParser, no fetch, no storage, no telemetry) and works under `file://` as well as over HTTP.

**Card format.** Each index card uses a structured description format: actor cards show Operational Profile and Key TTPs; triage cards show Trigger and Priority Actions; environment cards show Environment and Key Attack Paths; exploit cards show Vulnerability and Impact. The format gives a defender three things at a glance: what this is, what they do, and what you should do right now.

**Deep-link handler.** NET and HOST `core.js` include a `handleHash()` function that reads URL hashes from playbook cross-links, finds the matching technique section, clears filters, expands the first indicator, and smooth-scrolls to it. A link like `/net/lateral.html#T1021.002` opens the lateral movement page and jumps straight to the SMB/Windows Admin Shares technique.

**Static HTML.** Like the rest of TONK, playbooks are plain HTML with inline CSS. Each playbook page is self-contained and works offline.

---

## My Hunts (shared evidence across NET + HOST)

Both NET and HOST let you star any indicator into a running hunt list (a star toggle on each row). The list persists in `localStorage` under `hunt_reference_hunts_v1`, syncs across open tabs in real time, lets you set a per-indicator severity, and exports as TXT or CSV in a CMS-ready package for import into TheHive. Exports run through the environment profile, so the queries in a hunt package are substituted rather than shipped with raw placeholders. Each starred item stores its full row data, including the `apt` attribution array, which is what makes downstream attribution possible without re-entering anything. Because NET, HOST, ATTRIB, and PLAYBOOKS share one origin, this is a single list across all four: star on the wire and on the host, attribute both together, and use the playbooks to guide where to look next.

---

## Maintenance tooling (`.tools/`)

These are developer scripts, not part of the served site.

**`lint-data.py`** checks the indicator data files for defects that are invisible in the browser but break downstream consumers. It catches stray double commas that create JavaScript sparse-array holes (`forEach` skips holes, so the page looks fine while `DATA.length` is wrong and `for...of` throws), regex literals that do not compile after JS string unescaping (usually one backslash short, which fails silently in Kibana too), queries accidentally written inside their own comment and therefore not pasteable, a missing blank line before a block header which causes the query beneath it to be swallowed as an annotation, and raw control bytes in source. It exits non-zero on findings, so it slots into a pre-commit hook. Run it before committing data changes:

```
python3 .tools/lint-data.py
```

**`sigma-export.py`** converts the indicator set into a Sigma ruleset, grading every rule as `full`, `partial`, or `metadata` and recording each approximated or dropped clause per rule. It is optional and is not part of the hunting workflow: with a single Elastic backend, Sigma's cross-backend portability buys little day to day. It is retained as an interchange format and is a candidate to move into its own repository.

---

## Browser and serving notes

- Serve over HTTP (for example `python3 -m http.server`). The NET global search's `fetch()` is blocked under `file://`, and `localStorage` (My Hunts, the environment profile, the air-gap mode toggle) is unavailable on an opaque `file://` origin.
- **Script order matters.** `env.js` must load *before* `core.js` on every tactic page. `core.js` renders at script-eval time rather than on `DOMContentLoaded`, so loading `env.js` after it silently disables all variable substitution with no error. The page init line goes after both.
- There is currently no Content-Security-Policy set. The NET search parses data files with `new Function(...)`, which a strict CSP would block. If you add a CSP later, either allow `'unsafe-eval'` or switch the parser to a registry approach.
- `.nojekyll` is present at the repo root so GitHub Pages serves the `js/` folders untouched (Jekyll can otherwise mangle files and folders it does not expect).
- `CNAME` binds the repo to `hunt.6b74.dev`. There is exactly one, at the repo root.
