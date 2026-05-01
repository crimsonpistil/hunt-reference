# MITRE ATT&CK Hunt Reference

An offline-first, single-page network threat hunting reference. Each MITRE ATT&CK tactic page lists indicators with paste-ready query syntax for **Arkime**, **Kibana (KQL)**, and **Suricata**, plus operational notes and APT attribution context for each.

Built for network analysts who want a fast lookup tool on isolated workstations.

## Live demo

https://crimsonpistil.github.io/hunt-reference/

## Coverage

| Tactic | ID | Techniques | Indicators |
|---|---|---|---|
| Reconnaissance | TA0043 | 10 | 80 |
| Initial Access | TA0001 | 9 | 65 |
| Command & Control | TA0011 | 10 | 74 |
| Credential Access | TA0006 | — | planned |
| Discovery | TA0007 | 10 | 42 |
| Lateral Movement | TA0008 | — | planned |
| Collection | TA0009 | — | planned |
| Exfiltration | TA0010 | — | planned |

Each indicator includes:

- **Arkime** session query syntax
- **Kibana** KQL query
- **Suricata** rule (with SID, classtype, and threshold tuning where relevant)
- **Operational notes** — why the indicator works, what the false positive sources are, what to baseline
- **APT attribution** — which actor groups are documented using the technique, with country-of-origin tags
- **Citations** to MITRE, CISA advisories, and industry reporting

## Features

- **Search** — across indicators, query syntax, notes, and APT actors
- **Filter** — by technique ID or by APT origin (CN / RU / IR / KP)
- **Hunt picker** — star (★) any row to add it to a hunt package, then export to TXT or CSV with a CMS-ready template
- **Persistent hunts** — your hunt list survives tab closes, browser restarts, and is shared across all tactic pages via `localStorage`. Hunts are timestamped and ordered chronologically so the export reads as a hunt timeline.
- **Cross-tab sync** — adding an indicator in one tab updates any other open tabs immediately
- **Sidebar TOC** — jump to any technique on the page
- **Fully offline** — no external assets, no fetch calls, no fonts pulled remotely

### Data storage

Hunt data lives in `localStorage` under the key `hunt_reference_hunts_v1`. Storage is plain text scoped to the page's origin (so `localhost:8000` and `crimsonpistil.github.io` are separate buckets). To clear all hunts, use the **Clear All** button in the hunt panel, or run `localStorage.removeItem('hunt_reference_hunts_v1')` in the browser console. Note that `localStorage` is not encrypted on disk — for shared workstations or sensitive engagements, clear hunts when you're done.

## Use

```
git clone https://github.com/crimsonpistil/hunt-reference.git
cd hunt-reference
# open index.html in any browser
```

Or download the repo as a ZIP and double-click `index.html`.

For analyst workstations on isolated networks: drop the folder onto the system, open the HTML, done.

## Architecture

Three layers:

```
HTML (skeleton)  →  js/data/*.js (content)  →  js/core.js (renders + UI)
```

Each tactic page (`recon.html`, `initial_access.html`, etc.) is an empty shell that loads its tactic-specific data file (`js/data/recon.js`, `js/data/initial_access.js`) plus the shared `js/core.js`. The core script reads the global `DATA` array and builds all tables, the sidebar TOC, search, filters, and the hunt picker.

Adding a new tactic means: write the data file, copy an HTML stub, swap the data script tag. The CSS in `css/style.css` is shared across all pages.

State (selected rows, hunt picker contents) is held in memory only — refreshing clears it. This is intentional for an offline analyst tool. Swapping in `localStorage` would be straightforward if persistence is wanted.

## Data format

Each indicator is a JS object:

```javascript
{
  sub: "T1190 — Web App Injection",
  indicator: "SQL injection attempt — classic and blind patterns in HTTP request parameters",
  arkime: `ip.src != $INTERNAL && http.uri == [*UNION+SELECT* || *SLEEP(*]`,
  kibana: `NOT source.ip: $INTERNAL AND url.query: (*UNION+SELECT* OR *SLEEP(*)`,
  suricata: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (...)`,
  notes: "Operational context, FP sources, baselining advice...",
  apt: [
    { cls: "apt-cn", name: "APT41", note: "Attribution context..." }
  ],
  cite: "MITRE ATT&CK T1190, OWASP, industry reporting"
}
```

This structure is deliberately portable — if you ever want to migrate to a different rendering tool, ingest into a SIEM as detection-as-code, or feed into a Sigma converter, the data is already structured for it.

## Customization

Variables like `$INTERNAL`, `$VPN_SERVERS`, `$KNOWN_GOOD`, etc. in the query syntax are placeholders. Replace these with values from your environment before running queries against your own data sources.

The query syntax is generic and not tied to any specific Arkime/Kibana/Suricata version — adjust field names if you've customized your Zeek log mapping or Suricata classification config.

## Contributing / forking

Forks welcome. If you extend with additional tactics or indicators that are non-environment-specific, PRs are welcome too. Please don't submit indicators that contain real internal IPs, real customer data, or proprietary detection logic — keep the public version generic.

## Disclaimer

This is a reference tool, not a turnkey detection package. Indicators are starting points — every detection needs to be tuned against your specific environment's baseline traffic, log schema, and false positive tolerance. The Suricata SIDs use a private range (9XXXXXX) chosen to avoid collisions with ET, ETPRO, and Snort community rule sets, but verify they don't conflict with your existing rule corpus before deploying.

Built as a personal reference. Not affiliated with MITRE, CISA, or any vendor mentioned.

## License

MIT
