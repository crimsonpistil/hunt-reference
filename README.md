# TONK • Threat Observation & Network Kill-chain

TONK is a single, self-contained static-web kit that bundles four threat-hunting surfaces behind one landing page, served from one origin so they share a single evidence list:

- **NET** (`net`): a MITRE ATT&CK-mapped *network* detection reference, with Arkime / Kibana / Suricata queries, APT attribution, and a global actor/IOC/technique search.
- **HOST** (`host`): the *host-side* companion, mapping endpoint detections (Sysmon, Windows events, PowerShell, registry/file artifacts) across the attack lifecycle, with the same attribution model and open-source detection references.
- **ATTRIB** (`attribution`): an evidence-driven adversary attribution engine that reads the indicators you starred in NET and HOST and ranks the likely threat actors, cross-nation, with continuity save/load so a hunt survives a session reset or moves between machines.
- **PLAYBOOKS** (`playbooks`): curated hunt sequences organized by threat actor, environment, exploit reference, and incident triage scenario. Each playbook is a prioritized checklist linking into the NET and HOST detection references, sourced from CrowdStrike, Dragos, Mandiant, and CISA reporting.

Because all four live under one origin, the **My Hunts** evidence list is shared across them: star an indicator on NET or HOST and it lands in the same list, and ATTRIB scores all of it together. PLAYBOOKS provides the operational context: when intel drops an actor name or a detection fires, the playbook tells you what to look for next.

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
  net/                      # network detection reference
    index.html              # matrix landing + global actor/keyword search
    recon.html              # one page per ATT&CK tactic
    initial_access.html
    discovery.html
    lateral.html
    credential.html
    collection.html
    c2.html
    exfil.html
    css/style.css           # shared terminal theme + matrix styles
    js/
      core.js               # renders a tactic page, filters, the hunt list/export
      index.js              # landing-page tactic-card filter
      search.js             # global APT/keyword search (alias-aware)
      actors.js             # canonical actor reference: names, MITRE G-IDs, aliases
      data/                 # one DATA file per tactic (techniques + indicators)
        recon.js  initial_access.js  discovery.js  lateral.js
        credential.js  collection.js  c2.js  exfil.js
  host/                     # host-side detection reference
    index.html              # host matrix landing
    execution.html          # one page per host ATT&CK tactic
    persistence.html
    privilege_escalation.html
    defense_evasion.html
    css/style.css
    js/
      core.js  index.js
      data/                 # execution.js  persistence.js
                            # privilege_escalation.js  defense_evasion.js
  attribution/
    index.html              # adversary attribution engine - single-file app
  playbooks/                # curated hunt playbooks
    index.html              # playbook index - 28 cards across 8 sections
    actors/                 # 13 threat actor playbooks
      apt28.html            # Russia GRU 26165 / Fancy Bear
      apt29.html            # Russia SVR / Cozy Bear
      apt35.html            # Iran IRGC / Charming Kitten
      apt41.html            # China MSS / Winnti
      apt42.html            # Iran IRGC-IO / individual surveillance
      hacktivist-ops.html   # 3-tier hacktivist spectrum
      lazarus.html          # DPRK RGB / HIDDEN COBRA
      muddywater.html       # Iran MOIS / Mango Sandstorm
      raas-ecosystem.html   # ransomware supply chain model
      salt-typhoon.html     # China PRC / telecom compromise
      sandworm.html         # Russia GRU 74455 / APT44
      scattered-spider.html # eCrime / UNC3944 / Octo Tempest
      volt-typhoon.html     # China PLA / VOLTZITE / LOTL pre-positioning
    environments/           # 3 environment playbooks
      airgap-ot.html        # air-gapped OT/ICS (Purdue Level 2-3)
      hybrid-ad.html        # on-prem AD synced to Entra ID
      linux-fleet.html      # all-Linux infrastructure
    exploits/               # 2 exploit reference playbooks
      eternalblue.html      # MS17-010 / CVE-2017-0144 / SMBv1
      sharepoint-chain.html # CVE-2026-32201 + 45659 + 56164 (July 2026)
    triage/                 # 10 incident triage playbooks (3 tiers)
      ransomware.html       # tier 1
      compromised-credentials.html
      c2-beacon.html
      bec.html
      edge-device.html      # tier 2
      supply-chain.html
      data-exfil.html
      lotl.html             # tier 3
      infostealer.html
      insider-threat.html
```

---

## Running it
Access the live site at `hunt.6b74.dev` or serve the repo root over HTTP and open the landing page:

```
cd hunt-reference
python3 -m http.server 8000
```

Then browse to `http://localhost:8000/`. From the landing page, choose NET, HOST, ATTRIB, or PLAYBOOKS; the switcher in each header moves between all four.

Serving over HTTP matters: the NET global search uses `fetch()` to read the tactic data files, and browsers block `fetch()` under the `file://` scheme. If you open `index.html` directly off disk, the search shows a hint explaining this, but the rest of the kit still works. ATTRIB is self-contained and runs fine either way.

**One origin, one evidence list.** Serving all four surfaces from the same origin is not incidental - it is what lets My Hunts span NET and HOST. `localStorage` is partitioned per origin, so if these surfaces were split across separate subdomains they would each keep their own, separate hunt list and ATTRIB would only ever see one of them. Keeping them under `hunt.6b74.dev/...` is what makes the shared evidence flow work.

---

## NET (the network hunt reference)

A MITRE ATT&CK-organized matrix of network-observable detections.

**Coverage.** 8 tactics, 81 techniques, 348 indicators. Tactics: Reconnaissance, Initial Access, Discovery, Lateral Movement, Credential Access, Collection, Command and Control, and Exfiltration.

**Per-indicator content.** Each indicator row provides a plain-language description, copy-ready Arkime / Kibana / Suricata detections, an analyst note (hunt method, false-positive guidance, remediation), and a citation. Attribution lives in the expanded card's APT tab (not crowded onto the list rows), organized into three clearly separated sections: **Actors** (named threat groups), **Malware & Tooling** (named malware/frameworks like Emotet, Cobalt Strike), and **Activity & Roles** (categories like Red Team, Insider, IAB). Keeping malware and activity out of the actor field means a worm or a red-team note is never mistaken for threat-group attribution. Notes flag air-gap and off-network tripwires where relevant.

**Data model.** Each indicator row carries three sibling association arrays: `apt[]` (named threat actors, the single source of truth the ATTRIB engine scores against), `malware[]` (named malware and tooling), and `activity[]` (operator categories and roles). Only `apt[]` feeds attribution; the other two are context.

**APT attribution.** Actor tags are color-coded by origin (`apt-cn`, `apt-ru`, `apt-kp`, `apt-ir`, and `apt-mul` for multi-actor / commodity). Coverage emphasizes infrastructure-focused actors that network hunters are well-placed to catch, including deep Volt Typhoon coverage and Salt Typhoon (Cisco Smart Install / CVE-2018-0171, network-device config dumps, GRE tunnels via device config, loopback-sourced SSH for ACL bypass, and FTP/TFTP config exfil), alongside APT41, APT29, Lazarus, Scattered Spider, APT28, Sandworm, APT10, Charming Kitten, Kimsuky, and many more.

**Actor reference and aliases.** A canonical actor reference (`net/js/actors.js`) maps each tracked actor to its MITRE ATT&CK group ID (Gxxxx) and known aliases, generated from the MITRE ATT&CK Groups export. Where the data used multiple names for one group, they collapse to a single canonical (so APT29 / Cozy Bear / Midnight Blizzard resolve to one actor, anchored by its G-number). This drives alias resolution in both NET search and ATTRIB. This reference is shared: ATTRIB loads it from `../net/js/actors.js`.

**Global search (NET landing page).** The NET landing page can search every tactic data file at once. Type an actor (for example `Salt Typhoon`) to see every indicator tagged with that actor, grouped by tactic, each linking straight to the technique on its tactic page. Search is alias-aware: it resolves any known name or alias to its canonical actor through `actors.js`, so `Cozy Bear`, `Midnight Blizzard`, and `APT29` all return the same indicators, and a reporting name that never appears in the data (for example `Vanguard Panda`) still finds its actor's rows (Volt Typhoon). Non-actor queries fall back to keyword matching across technique IDs/names, indicator text, notes, and citations (so `portproxy`, `GRE`, `T1090`, `TFTP` all resolve). Quick-actor chips surface the most-referenced named actors, merged by canonical name so aliases do not split into duplicate chips. Mechanically, the search fetches each data file as text and evaluates it in an isolated scope, which sidesteps the fact that every data file declares its own `const DATA` and avoids any changes to the data files themselves.

**Per-tactic filtering.** Each tactic page has its own search box and APT filter buttons to narrow the indicator list in place.

---

## HOST (the host-side hunt reference)

The endpoint companion to NET: where NET covers what adversaries do across the wire, HOST covers what they do inside the box - process execution, persistence, privilege escalation, and defense evasion.

**Coverage.** 4 tactics, 69 techniques, 129 indicators, spanning Windows and Linux. Tactics: Execution, Persistence, Privilege Escalation, and Defense Evasion.

**Per-indicator content.** Each host indicator carries detection telemetry tuned to the endpoint: key Sysmon / Windows Event signatures, paste-ready Kibana KQL, PowerShell hunt snippets, registry and file artifacts, adversary tool attribution, and references to open-source detection projects (Sigma, Velociraptor, Hayabusa, Falco, and similar). Each row is tagged with the OS it applies to (Windows, Linux).

**Same attribution model.** HOST uses the same `apt[]` / `malware[]` / `activity[]` association model and the same origin classes as NET, so a host indicator's actor tags feed ATTRIB exactly like a network one. A hunt that combines host and network evidence is scored as a single body of evidence.

**Note on parity.** HOST currently does not load `actors.js`, so alias collapsing applies to NET search and to ATTRIB scoring, but not yet to HOST's own in-page filtering. Folding the shared actor reference into HOST is a natural follow-on.

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

**Coverage.** 28 cards across 8 sections, backed by 29 playbook pages. Sourced from CrowdStrike 2026 Global Threat Report, Dragos 2026 OT Year in Review, Mandiant M-Trends 2026, CISA advisories, and ongoing threat intelligence reporting.

**Threat actors (13 playbooks).** Nation-state actors organized by country: China (Volt Typhoon, Salt Typhoon, APT41), Russia (APT28, APT29, Sandworm), Iran (APT35/Charming Kitten, MuddyWater, APT42), and DPRK (Lazarus). eCrime: Scattered Spider and the RaaS Ecosystem (the ransomware supply chain model). Hacktivists: a 3-tier spectrum from script kiddies to state-aligned pseudo-hacktivists. Each actor playbook includes an operational profile, documented TTPs, a prioritized hunt checklist with detection references, custom tooling inventory, and cross-links to related triage playbooks.

**Environments (3 playbooks).** Air-Gapped OT/ICS (Purdue Level 2-3, no cloud EDR, Zeek/Suricata/Sysmon-based detection, ICS-specific attack tools, control-loop mapping by VOLTZITE and KAMACITE), Hybrid AD Enterprise (on-prem to Azure AD/Entra ID attack paths, 6 trust boundaries), and Linux Server Fleet (auditd/Sysmon for Linux, SSH lateral, container escape, rootkit detection).

**Exploit reference (2 playbooks).** EternalBlue/MS17-010 (the CVE-2017-0144 family, 6 related CVEs, Suricata/Zeek/Arkime detection signatures, sector-specific impact analysis across healthcare, shipping, pharma, energy, telecom, and government) and the SharePoint CVE Chain of July 2026 (CVE-2026-32201 + CVE-2026-45659 + CVE-2026-56164, IIS machine key theft, LeakFang backdoor, air-gap-specific initial access vectors and post-exploitation, CISA KEV).

**Incident triage (10 playbooks, 3 tiers).**
- *Tier 1 (you will see these):* Ransomware Detected, Compromised Credentials, C2 Beacon Found, Business Email Compromise.
- *Tier 2 (common and growing):* Edge Device Compromised, Supply Chain Indicator, Data Exfiltration Detected.
- *Tier 3 (specialized, high-impact):* Living-off-the-Land Activity, Infostealer Infection, Insider Threat.

**Card format.** Each index card uses a structured description format: actor cards show Operational Profile and Key TTPs; triage cards show Trigger and Priority Actions; environment cards show Environment and Key Attack Paths; exploit cards show Vulnerability and Impact. The format gives a defender three things at a glance: what this is, what they do, and what you should do right now.

**Intel sourcing.** Playbooks integrate findings from CrowdStrike 2026 GTR (82% malware-free detections, 29-minute breakout, ClickFix +563%, vishing +442%, FAMOUS CHOLLIMA, LAMEHUG), Dragos 2026 OT Year in Review (VOLTZITE Stage 2, KAMACITE US ICS scanning, SYLVANITE, AZURITE, PYROXENE, PLC_Controller.exe, Modbus PowerShell tools, hacktivist ICS evolution), and ongoing CISA/allied advisories. Updated as reporting drops.

**Deep-link handler.** NET and HOST core.js include a `handleHash()` function that reads URL hashes from playbook cross-links, finds the matching technique section, clears filters, expands the first indicator, and smooth-scrolls to it. This makes playbook-to-detection-reference navigation seamless: a link like `/net/lateral.html#T1021.002` opens the lateral movement page and jumps straight to the SMB/Windows Admin Shares technique.

**Static HTML.** Like the rest of TONK, playbooks are plain HTML with inline CSS. No JavaScript dependencies, no build step, no runtime. Each playbook page is self-contained and works offline.

---

## My Hunts (shared evidence across NET + HOST)

Both NET and HOST let you star any indicator into a running hunt list (a star toggle on each row). The list persists in `localStorage` under `hunt_reference_hunts_v1`, syncs across open tabs in real time, lets you set a per-indicator severity, and exports as TXT or CSV in a CMS-ready package for import into TheHive. Each starred item stores its full row data, including the `apt` attribution array, which is what makes downstream attribution possible without re-entering anything. Because NET, HOST, ATTRIB, and PLAYBOOKS share one origin, this is a single list across all four: star on the wire and on the host, attribute both together, and use the playbooks to guide where to look next.

---

## Browser and serving notes

- Serve over HTTP (for example `python3 -m http.server`); the NET global search's `fetch()` is blocked under `file://`.
- There is currently no Content-Security-Policy set. The NET search parses data files with `new Function(...)`, which a strict CSP would block. If you add a CSP later, either allow `'unsafe-eval'` or switch the parser to a registry approach.
- `.nojekyll` is present at the repo root so GitHub Pages serves the `js/` folders untouched (Jekyll can otherwise mangle files and folders it does not expect).
- `CNAME` binds the repo to `hunt.6b74.dev`. There is exactly one, at the repo root.
