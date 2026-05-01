// ── HUNT REFERENCE — core.js ──
// Shared UI logic for all tactic pages.
// DATA must be loaded before this file via a tactic-specific data/*.js script tag.

// ── CMS TEMPLATES ──
const CMS_TEMPLATES = {
  T1595: { title:'T1595 — Active Scanning', body:`## TAG - RECON\n### Technique: Active Scanning, T1595\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n\nNotes:` },
  T1589: { title:'T1589 — Gather Victim Identity Information', body:`## TAG - RECON\n### Technique: Gather Victim Identity Information, T1589\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Usernames, Emails, Employee Names, Credentials, etc.)\n\nNotes:` },
  T1590: { title:'T1590 — Gather Victim Network Information', body:`## TAG - RECON\n### Technique: Gather Victim Network Information, T1590\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Domains, Topology, IPs, ASN, VPN Vendor, etc.)\n\nNotes:` },
  T1591: { title:'T1591 — Gather Victim Org Information', body:`## TAG - RECON\n### Technique: Gather Victim Org Information, T1591\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Departments, Divisions, Roles, Vendors, etc.)\n\nNotes:` },
  T1592: { title:'T1592 — Gather Victim Host Information', body:`## TAG - RECON\n### Technique: Gather Victim Host Information, T1592\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Hardware, Software Version, Firmware, OS, etc.)\n\nNotes:` },
  T1593: { title:'T1593 — Search Open Websites / Domains', body:`## TAG - RECON\n### Technique: Search Open Websites / Domains, T1593\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Employee Profiles, Credentials, Source Code, etc.)\n\nNotes:` },
  T1594: { title:'T1594 — Search Victim-Owned Websites', body:`## TAG - RECON\n### Technique: Search Victim-Owned Websites, T1594\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Tech Stack, Exposed Files, CMS Version, etc.)\n\nNotes:` },
  T1596: { title:'T1596 — Search Technical Databases', body:`## TAG - RECON\n### Technique: Search Technical Databases, T1596\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (WHOIS, Passive DNS, Cert History, Scan Data, etc.)\n\nNotes:` },
  T1597: { title:'T1597 — Search Closed Sources', body:`## TAG - RECON\n### Technique: Search Closed Sources, T1597\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Credentials, Breach Data, Purchased Info, etc.)\n\nNotes:` },
  T1598: { title:'T1598 — Phishing for Information', body:`## TAG - RECON\n### Technique: Phishing for Information, T1598\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Type of Info Gathered: (Credentials, MFA Tokens, Employee Info, etc.)\n\nNotes:` },
  T1078: { title:'T1078 — Valid Accounts', body:`## TAG - INITIAL ACCESS\n### Technique: Valid Accounts, T1078\n- Time:\n- Source IP:\n- Destination IP(s):\n- Port(s):\n- Account Type: (Default / Domain / Local / Cloud)\n- Username Observed:\n- Auth Result: (Success / Failure)\n- MFA Status:\n\nNotes:` },
  T1091: { title:'T1091 — Replication Through Removable Media', body:`## TAG - INITIAL ACCESS\n### Technique: Replication Through Removable Media, T1091\n- Time:\n- Source Host:\n- USB Event Time (if known):\n- Destination IP(s):\n- Port(s):\n- Propagation Method: (SMB / HTTP fetch / Air-gap bridge)\n- Payload Observed:\n\nNotes:` },
  T1133: { title:'T1133 — External Remote Services', body:`## TAG - INITIAL ACCESS\n### Technique: External Remote Services, T1133\n- Time:\n- Source IP / Geo / ASN:\n- Destination IP(s):\n- Port(s):\n- Service: (VPN / RDP / SSH / Citrix / Cloud)\n- Username Observed:\n- Auth Result:\n- Anomaly: (New geo / Off hours / Brute / Tor)\n\nNotes:` },
  T1189: { title:'T1189 — Drive-by Compromise', body:`## TAG - INITIAL ACCESS\n### Technique: Drive-by Compromise, T1189\n- Time:\n- Internal Host:\n- Browsed URL / Domain:\n- Redirect Chain:\n- Final Destination IP:\n- Payload Type: (Exploit / Document / PE)\n- Post-exploit C2:\n\nNotes:` },
  T1190: { title:'T1190 — Exploit Public-Facing Application', body:`## TAG - INITIAL ACCESS\n### Technique: Exploit Public-Facing Application, T1190\n- Time:\n- Source IP:\n- Target Server:\n- Port(s):\n- Application / CVE:\n- Exploit Type: (SQLi / Cmd Inj / LFI / Deserialization / Log4Shell / VPN CVE)\n- HTTP Response Code:\n- Post-exploit Callback:\n\nNotes:` },
  T1195: { title:'T1195 — Supply Chain Compromise', body:`## TAG - INITIAL ACCESS\n### Technique: Supply Chain Compromise, T1195\n- Time:\n- Affected Host / Build Server:\n- Destination IP(s) / Domain:\n- Compromise Type: (Dependency / Software / Hardware)\n- Package or Vendor:\n- C2 Pattern Observed:\n\nNotes:` },
  T1200: { title:'T1200 — Hardware Additions', body:`## TAG - INITIAL ACCESS\n### Technique: Hardware Additions, T1200\n- Time:\n- Switch Port / VLAN:\n- MAC Address / OUI:\n- Device Type: (Rogue switch / USB-Eth / Implant / Rogue AP / BMC)\n- DHCP Hostname:\n- Outbound Activity:\n\nNotes:` },
  T1566: { title:'T1566 — Phishing', body:`## TAG - INITIAL ACCESS\n### Technique: Phishing, T1566\n- Time:\n- Sender / From Domain:\n- Recipient(s):\n- Delivery: (Attachment / Link / Service)\n- Attachment Filename / Hash:\n- Click Destination URL:\n- Credential POST Observed:\n- AiTM / MFA Bypass:\n\nNotes:` },
  T1659: { title:'T1659 — Content Injection', body:`## TAG - INITIAL ACCESS\n### Technique: Content Injection, T1659\n- Time:\n- Source IP / Server:\n- Internal Victim:\n- Injection Type: (HTTP Response / DNS / BGP / TLS Downgrade)\n- Injected Content / Domain:\n- Affected Domain / Prefix:\n\nNotes:` },
  T1071: { title:'T1071 — Application Layer Protocol', body:`## TAG - C2\n### Technique: Application Layer Protocol, T1071\n- Time:\n- Source IP:\n- Destination IP / Domain:\n- Port(s):\n- Protocol: (HTTP / HTTPS / FTP / SMB / SMTP / DNS)\n- Beacon Interval (s):\n- URI Pattern:\n- User-Agent:\n- JA3/JA4:\n\nNotes:` },
  T1568: { title:'T1568 — Dynamic Resolution', body:`## TAG - C2\n### Technique: Dynamic Resolution, T1568\n- Time:\n- Source IP:\n- DNS Query Pattern:\n- Resolution Type: (DGA / Fast Flux / DNS Calculation)\n- NXDOMAIN Rate:\n- Successful Resolution Domain:\n- Resolved IP(s):\n- TTL Observed:\n\nNotes:` },
  T1102: { title:'T1102 — Web Service', body:`## TAG - C2\n### Technique: Web Service, T1102\n- Time:\n- Source IP:\n- Service: (Pastebin / GitHub / Discord / Telegram / Slack / Cloud Storage)\n- Endpoint URI:\n- HTTP Method:\n- Process:\n- Direction: (Dead Drop / Bidirectional / One-Way Exfil)\n\nNotes:` },
  T1573: { title:'T1573 — Encrypted Channel', body:`## TAG - C2\n### Technique: Encrypted Channel, T1573\n- Time:\n- Source IP:\n- Destination IP:\n- TLS Version:\n- JA3 / JA3S:\n- JA4 / JA4S:\n- Cert Issuer:\n- Cert Subject:\n- Cert Issued (Date):\n- Crypto Type: (Symmetric / Asymmetric / Custom)\n\nNotes:` },
  T1095: { title:'T1095 — Non-Application Layer Protocol', body:`## TAG - C2\n### Technique: Non-Application Layer Protocol, T1095\n- Time:\n- Source IP:\n- Destination IP:\n- Protocol: (ICMP / Raw TCP / Raw UDP / GRE / SCTP)\n- Port (if applicable):\n- Payload Size:\n- Payload Entropy:\n- Packet Count / Duration:\n\nNotes:` },
  T1090: { title:'T1090 — Proxy', body:`## TAG - C2\n### Technique: Proxy, T1090\n- Time:\n- Source IP:\n- Destination IP:\n- Proxy Type: (.001 Internal / .002 External / .003 Multi-hop / .004 Domain Fronting)\n- Port(s):\n- SNI:\n- Host Header:\n- ASN / Provider:\n\nNotes:` },
  T1572: { title:'T1572 — Protocol Tunneling', body:`## TAG - C2\n### Technique: Protocol Tunneling, T1572\n- Time:\n- Source IP:\n- Destination IP:\n- Tunnel Protocol: (SSH / HTTPS / WebSocket / DoH / VPN)\n- Port:\n- Session Duration:\n- Bytes (src/dst):\n- SSH Banner / SNI:\n\nNotes:` },
  T1105: { title:'T1105 — Ingress Tool Transfer', body:`## TAG - C2\n### Technique: Ingress Tool Transfer, T1105\n- Time:\n- Source Host:\n- Destination IP / Domain:\n- LOLBin: (certutil / bitsadmin / PowerShell / curl / wget)\n- User-Agent:\n- File Type Downloaded:\n- File Hash (if known):\n- Encoded Payload (Y/N):\n\nNotes:` },
  T1571: { title:'T1571 — Non-Standard Port', body:`## TAG - C2\n### Technique: Non-Standard Port, T1571\n- Time:\n- Source IP:\n- Destination IP:\n- Port:\n- Detected Protocol (Zeek DPD):\n- Expected Protocol for Port:\n- Session Duration:\n\nNotes:` },
  T1219: { title:'T1219 — Remote Access Software', body:`## TAG - C2\n### Technique: Remote Access Software, T1219\n- Time:\n- Source Host:\n- Destination IP / SNI:\n- RMM Tool: (TeamViewer / AnyDesk / ConnectWise / Splashtop / RustDesk / ngrok / Cloudflare Tunnel / Tailscale)\n- Process Path:\n- Authorized for Host (Y/N):\n\nNotes:` },
  T1018: { title:'T1018 — Remote System Discovery', body:`## TAG - DISCOVERY\n### Technique: Remote System Discovery, T1018\n- Time:\n- Source IP:\n- Destination IP / Subnet:\n- Discovery Method: (ICMP sweep / ARP scan / NBNS / DNS-PTR / SMB probe / AXFR)\n- Hosts Identified:\n- Subnets Touched:\n\nNotes:` },
  T1046: { title:'T1046 — Network Service Discovery', body:`## TAG - DISCOVERY\n### Technique: Network Service Discovery, T1046\n- Time:\n- Source IP:\n- Target Range / Hosts:\n- Scan Type: (TCP SYN / Horizontal sweep / Banner grab / SNMP / masscan)\n- Ports Probed:\n- Tool Inferred: (nmap / masscan / zmap / nikto / custom)\n\nNotes:` },
  T1135: { title:'T1135 — Network Share Discovery', body:`## TAG - DISCOVERY\n### Technique: Network Share Discovery, T1135\n- Time:\n- Source IP:\n- Target Server(s):\n- RPC Interface: (srvsvc NetShareEnum / IPC$ / DFS referral)\n- Shares Discovered:\n- Auth Context: (Anonymous / Authenticated user / Domain admin)\n\nNotes:` },
  T1087: { title:'T1087 — Account Discovery', body:`## TAG - DISCOVERY\n### Technique: Account Discovery, T1087\n- Time:\n- Source IP:\n- Target DC:\n- Method: (LDAP filter / SAMR RPC / Kerberos AS-REQ enum / BloodHound)\n- Filter / Opnum:\n- Accounts Enumerated:\n- Sub-technique: (.001 Local / .002 Domain / .003 Email / .004 Cloud)\n\nNotes:` },
  T1069: { title:'T1069 — Permission Groups Discovery', body:`## TAG - DISCOVERY\n### Technique: Permission Groups Discovery, T1069\n- Time:\n- Source IP:\n- Target DC:\n- Group Queried: (Domain Admins / Enterprise Admins / Schema Admins / adminCount=1 / gMSA)\n- Method: (LDAP / LDAP_MATCHING_RULE_IN_CHAIN / SAMR / net.exe RPC)\n- Members Enumerated:\n\nNotes:` },
  T1482: { title:'T1482 — Domain Trust Discovery', body:`## TAG - DISCOVERY\n### Technique: Domain Trust Discovery, T1482\n- Time:\n- Source IP:\n- Target DC:\n- Trust Direction Discovered:\n- Trust Type: (Parent-child / External / Forest / Realm)\n- Method: (LDAP trustedDomain / LSARPC / nltest / RootDSE / cross-trust DNS SRV)\n\nNotes:` },
  T1083: { title:'T1083 — File and Directory Discovery', body:`## TAG - DISCOVERY\n### Technique: File and Directory Discovery, T1083\n- Time:\n- Source Host:\n- Target Share / Path:\n- File Patterns Searched: (web.config / *.kdbx / id_rsa / unattend.xml / etc.)\n- Tool: (Snaffler / PowerShell Get-ChildItem / robocopy /L / custom)\n- Files Identified:\n\nNotes:` },
  T1016: { title:'T1016 — System Network Configuration Discovery', body:`## TAG - DISCOVERY\n### Technique: System Network Configuration Discovery, T1016\n- Time:\n- Source Host:\n- Service Queried: (icanhazip / ifconfig.me / IMDS 169.254.169.254 / ipinfo.io)\n- Process:\n- Discovery Type: (External IP / Cloud metadata / Network interfaces)\n\nNotes:` },
  T1049: { title:'T1049 — System Network Connections Discovery', body:`## TAG - DISCOVERY\n### Technique: System Network Connections Discovery, T1049\n- Time:\n- Source IP:\n- Target Host:\n- RPC Interface: (svcctl / WMI / netstat-equivalent)\n- Services Enumerated:\n- Reason Inferred: (Defense evasion / Privilege escalation / Lateral movement)\n\nNotes:` },
  T1033: { title:'T1033 — System Owner / User Discovery', body:`## TAG - DISCOVERY\n### Technique: System Owner / User Discovery, T1033\n- Time:\n- Source IP:\n- Target DC:\n- SIDs Looked Up:\n- Method: (LSARPC LsaLookupSids / whoami / LDAP self-query / SAMR)\n- Resolved Usernames:\n\nNotes:` },
};

// ── STATE ──
let activeTech = 'all';
let activeApt  = null;
let huntOpen   = false;
let totalRows  = 0;
let selectedRows = new Set();
let huntItems  = {};     // rowId -> { indicator, techId, severity, addedAt, row }
let rowRegistry = {};    // rowId -> { row, techId }

// ── PERSISTENCE ──
// Hunt items survive across tabs and browser sessions via localStorage.
// Schema versioning lets us migrate or discard incompatible saved data.
const HUNT_STORAGE_KEY = 'hunt_reference_hunts_v1';
const HUNT_SCHEMA_VERSION = 1;

function loadHunts() {
  try {
    const raw = localStorage.getItem(HUNT_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed._v !== HUNT_SCHEMA_VERSION) {
      console.warn('Hunt storage schema mismatch; discarding old data.');
      localStorage.removeItem(HUNT_STORAGE_KEY);
      return;
    }
    huntItems = parsed.items || {};
  } catch (e) {
    console.error('Failed to load hunts from localStorage:', e);
    huntItems = {};
  }
}

function saveHunts() {
  try {
    const payload = { _v: HUNT_SCHEMA_VERSION, items: huntItems };
    localStorage.setItem(HUNT_STORAGE_KEY, JSON.stringify(payload));
  } catch (e) {
    // QuotaExceededError is the realistic failure mode.
    console.error('Failed to save hunts to localStorage:', e);
  }
}

// Cross-tab sync: when another tab modifies the hunt list, refresh ours.
window.addEventListener('storage', e => {
  if (e.key !== HUNT_STORAGE_KEY) return;
  loadHunts();
  renderHunt();
  // Refresh star button states for indicators on the current page.
  document.querySelectorAll('.ind-row').forEach(rowEl => {
    const rowId = rowEl.dataset.rowId;
    const star = rowEl.querySelector('.star-btn');
    if (!star) return;
    if (huntItems[rowId]) {
      star.innerHTML = '&#9733;';
      star.classList.add('starred');
    } else {
      star.innerHTML = '&#9734;';
      star.classList.remove('starred');
    }
  });
});

// ── HELPERS ──
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function aptOrigins(apt) {
  return apt.map(a => {
    if (a.cls === 'apt-cn') return 'CN';
    if (a.cls === 'apt-ru') return 'RU';
    if (a.cls === 'apt-ir') return 'IR';
    if (a.cls === 'apt-kp') return 'KP';
    return '';
  }).join(' ');
}

function copyText(text, btn, label) {
  navigator.clipboard.writeText(text.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = label || 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
  });
}

// ── BUILD ROW ──
function buildRow(row, techId, rowId) {
  const aptBadges = row.apt.map(a =>
    `<span class="apt-badge ${a.cls}">${a.name}</span>`
  ).join('');

  const searchText = [
    row.indicator, row.notes, row.arkime, row.kibana, row.suricata,
    row.apt.map(a => a.name + ' ' + (a.note||'')).join(' '),
    row.cite || '', techId
  ].join(' ').toLowerCase();

  const el = document.createElement('div');
  el.className = 'ind-row';
  el.dataset.tech = techId;
  el.dataset.apt  = aptOrigins(row.apt);
  el.dataset.text = searchText;
  el.dataset.rowId = rowId;
  el.dataset.techId = techId;

  // ── collapsed bar ──
  const bar = document.createElement('div');
  bar.className = 'ind-collapsed';
  const isStarred = !!huntItems[rowId];
  bar.innerHTML = `
    <input type="checkbox" class="row-check" title="Select for export">
    <button class="star-btn${isStarred ? ' starred' : ''}" title="Add to hunt">${isStarred ? '&#9733;' : '&#9734;'}</button>
    <span class="ind-name">${esc(row.indicator)}</span>
    <div class="apt-badges">${aptBadges}</div>
    <div class="quick-tools">
      <button class="qtool qt-a" title="Copy Arkime">ARK</button>
      <button class="qtool qt-k" title="Copy Kibana">KQL</button>
      <button class="qtool qt-s" title="Copy Suricata">SUR</button>
    </div>
    <span class="expand-icon">&#9662;</span>`;

  bar.querySelector('.row-check').addEventListener('click', e => {
    e.stopPropagation();
    toggleSelect(rowId, e.target);
  });
  bar.querySelector('.star-btn').addEventListener('click', e => {
    e.stopPropagation();
    toggleHuntItem(rowId, e.target);
  });
  bar.querySelector('.qt-a').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.arkime, e.target);
  });
  bar.querySelector('.qt-k').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.kibana, e.target);
  });
  bar.querySelector('.qt-s').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.suricata, e.target);
  });
  bar.addEventListener('click', () => el.classList.toggle('open'));

  // ── detail panel ──
  const detail = document.createElement('div');
  detail.className = 'ind-detail';

  // tab bar
  const tabs = [
    ['t-ark', 'Arkime'],
    ['t-kib', 'Kibana'],
    ['t-sur', 'Suricata'],
    ['t-not', 'Notes'],
    ['t-apt', 'APT'],
    ['t-cms', 'CMS Template'],
  ];
  const tabBar = document.createElement('div');
  tabBar.className = 'tab-bar';
  tabs.forEach(([cls, label], i) => {
    const btn = document.createElement('button');
    btn.className = 'dtab ' + cls + (i === 0 ? ' active' : '');
    btn.textContent = label;
    btn.addEventListener('click', () => switchTab(detail, btn, cls));
    tabBar.appendChild(btn);
  });
  detail.appendChild(tabBar);

  // code panels
  function codePanel(langCls, langLabel, content) {
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyText(content, copyBtn));
    wrap.innerHTML = `<div class="code-hdr"><span class="code-lang ${langCls}">${langLabel}</span></div>`;
    wrap.querySelector('.code-hdr').appendChild(copyBtn);
    const pre = document.createElement('pre');
    pre.className = 'code-body';
    pre.textContent = content;
    wrap.appendChild(pre);
    return wrap;
  }

  // panels
  const panels = {
    'ark': codePanel('l-ark', 'Arkime SPI/Search', row.arkime),
    'kib': codePanel('l-kib', 'Kibana KQL',        row.kibana),
    'sur': codePanel('l-sur', 'Suricata Rule',     row.suricata),
    'not': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.notes; return d; })(),
    'apt': (() => {
      const d = document.createElement('div');
      row.apt.forEach(a => {
        const item = document.createElement('div');
        item.className = 'apt-item';
        item.innerHTML = `<span class="apt-badge ${a.cls}" style="font-size:11px">${esc(a.name)}</span>`;
        if (a.note) {
          const note = document.createElement('div');
          note.className = 'apt-item-note';
          note.textContent = a.note;
          item.appendChild(note);
        }
        d.appendChild(item);
      });
      if (row.cite) {
        const cite = document.createElement('div');
        cite.className = 'apt-cite';
        cite.textContent = row.cite;
        d.appendChild(cite);
      }
      return d;
    })(),
    'cms': (() => {
      const d = document.createElement('div');
      const tpl = CMS_TEMPLATES[techId];
      if (tpl) {
        const hdr = document.createElement('div');
        hdr.className = 'cms-hdr';
        const title = document.createElement('span');
        title.className = 'cms-title';
        title.textContent = tpl.title;
        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.style.borderColor = 'var(--teal)';
        copyBtn.textContent = 'Copy Template';
        copyBtn.addEventListener('click', () => copyText(tpl.body, copyBtn, 'Copied!'));
        hdr.appendChild(title);
        hdr.appendChild(copyBtn);
        const pre = document.createElement('pre');
        pre.className = 'cms-body-pre';
        pre.textContent = tpl.body;
        d.appendChild(hdr);
        d.appendChild(pre);
      } else {
        d.innerHTML = '<span style="color:var(--text3);font-size:12px">No CMS template for this technique yet.</span>';
      }
      return d;
    })(),
  };

  const panelKeys = ['ark','kib','sur','not','apt','cms'];
  panelKeys.forEach((key, i) => {
    const wrap = document.createElement('div');
    wrap.className = 'tab-panel' + (i === 0 ? ' active' : '');
    wrap.appendChild(panels[key]);
    detail.appendChild(wrap);
  });

  el.appendChild(bar);
  el.appendChild(detail);
  rowRegistry[rowId] = { row, techId };
  return el;
}

function switchTab(detail, activeBtn, activeCls) {
  detail.querySelectorAll('.dtab').forEach(b => b.classList.remove('active'));
  detail.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  activeBtn.classList.add('active');
  const idx = ['ark','kib','sur','not','apt','cms'].indexOf(activeCls.replace('t-',''));
  const panels = detail.querySelectorAll('.tab-panel');
  if (panels[idx]) panels[idx].classList.add('active');
}

// ── RENDER ──
function render() {
  const content = document.getElementById('content');
  const toc     = document.getElementById('toc');
  const sidebarStats = document.getElementById('sidebar-stats');
  if (!content) return;

  DATA.forEach(tech => {
    // TOC
    const tocItem = document.createElement('div');
    tocItem.className = 'toc-item';
    tocItem.dataset.tech = tech.id;
    tocItem.innerHTML = `<span class="toc-id">${tech.id}</span><span class="toc-name">${tech.name.split(' ').slice(0,3).join(' ')}</span><span class="toc-count">${tech.rows.length}</span>`;
    tocItem.addEventListener('click', () => {
      document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
      const btn = document.querySelector(`.fbtn[data-tech="${tech.id}"]`);
      if (btn) { btn.classList.add('active'); activeTech = tech.id; applyFilters(); }
      document.getElementById('tech-' + tech.id)?.scrollIntoView({ behavior:'smooth', block:'start' });
    });
    if (toc) toc.appendChild(tocItem);

    // Section
    const section = document.createElement('div');
    section.className = 'technique-section';
    section.id = 'tech-' + tech.id;
    section.dataset.tech = tech.id;

    const hdr = document.createElement('div');
    hdr.className = 'tech-header';
    hdr.innerHTML = `<span class="tech-id">${tech.id}</span><span class="tech-name">${tech.name}</span><span class="tech-count">${tech.rows.length}</span><span class="tech-desc">${tech.desc || ''}</span><span class="tech-toggle">&#9662;</span>`;
    hdr.addEventListener('click', () => section.classList.toggle('collapsed'));
    section.appendChild(hdr);

    const wrap = document.createElement('div');
    wrap.className = 'rows-wrap';

    let lastSub = '';
    tech.rows.forEach((row, i) => {
      if (row.sub && row.sub !== lastSub) {
        const div = document.createElement('div');
        div.className = 'sub-divider';
        div.textContent = row.sub;
        wrap.appendChild(div);
        lastSub = row.sub;
      }
      const rowId = tech.id + '_' + i;
      wrap.appendChild(buildRow(row, tech.id, rowId));
      totalRows++;
    });

    section.appendChild(wrap);
    content.appendChild(section);
  });

  if (sidebarStats) {
    sidebarStats.innerHTML = DATA.map(t =>
      `<div><span style="color:var(--accent);font-family:var(--mono)">${t.id}</span> — ${t.rows.length}</div>`
    ).join('') + `<div style="margin-top:6px;color:var(--text2)">Total: <strong>${totalRows}</strong></div>`;
  }

  updateStats(totalRows, totalRows);
}

// ── SELECT / EXPORT SELECTED ──
function toggleSelect(rowId, cb) {
  if (cb.checked) selectedRows.add(rowId);
  else selectedRows.delete(rowId);
  const btn = document.getElementById('export-selected-btn');
  if (btn) btn.style.display = selectedRows.size > 0 ? 'flex' : 'none';
}

function exportSelected() {
  if (!selectedRows.size) return;
  let out = `Hunt Reference — Selected Indicators\nExported: ${new Date().toLocaleString()}\n${'='.repeat(60)}\n\n`;
  selectedRows.forEach(rowId => {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    const { row, techId } = entry;
    out += `[${techId}] ${row.indicator}\n${'-'.repeat(50)}\nARKIME:\n${row.arkime}\n\nKIBANA:\n${row.kibana}\n\nSURICATA:\n${row.suricata}\n\nNOTES:\n${row.notes}\n\n${'='.repeat(60)}\n\n`;
  });
  download(out, 'selected_indicators.txt', 'text/plain');
}

// ── HUNT ──
function toggleHunt() {
  huntOpen = !huntOpen;
  document.getElementById('hunt-panel').classList.toggle('open', huntOpen);
}

function toggleHuntItem(rowId, starBtn) {
  if (huntItems[rowId]) {
    delete huntItems[rowId];
    starBtn.innerHTML = '&#9734;';
    starBtn.classList.remove('starred');
  } else {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    huntItems[rowId] = {
      indicator: entry.row.indicator,
      techId: entry.techId,
      severity: 'high',
      addedAt: Date.now(),
      row: entry.row  // full row data — enables cross-tactic export from any page
    };
    starBtn.innerHTML = '&#9733;';
    starBtn.classList.add('starred');
    if (!huntOpen) { huntOpen = true; document.getElementById('hunt-panel').classList.add('open'); }
  }
  saveHunts();
  renderHunt();
}

function renderHunt() {
  const list = document.getElementById('hunt-list');
  const countEl = document.getElementById('hunt-count');
  const keys = Object.keys(huntItems);

  if (!keys.length) {
    list.innerHTML = '<div class="hunt-empty">No indicators added. Click &#9734; on any row.</div>';
    if (countEl) countEl.style.display = 'none';
    return;
  }

  if (countEl) { countEl.textContent = keys.length; countEl.style.display = 'inline'; }

  // Sort by addedAt ascending — oldest first, building a hunt timeline.
  // Items added before persistence existed have no addedAt and sort as 0 (top).
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Group consecutive items by techId and insert a small header before each new group.
  let html = '';
  let lastTech = null;
  sortedKeys.forEach(rowId => {
    const item = huntItems[rowId];
    if (item.techId !== lastTech) {
      html += `<div class="hunt-group-header">${item.techId}</div>`;
      lastTech = item.techId;
    }
    const ts = item.addedAt
      ? new Date(item.addedAt).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' })
      : '';
    html += `<div class="hunt-item">
      <span class="hunt-item-tech">${item.techId}</span>
      <span class="hunt-item-name">${esc(item.indicator)}</span>
      ${ts ? `<span class="hunt-item-ts" title="Added">${ts}</span>` : ''}
      <select class="sev-sel sev-${item.severity}" onchange="setSev('${rowId}',this)">
        <option value="critical" ${item.severity==='critical'?'selected':''}>CRITICAL</option>
        <option value="high"     ${item.severity==='high'    ?'selected':''}>HIGH</option>
        <option value="medium"   ${item.severity==='medium'  ?'selected':''}>MEDIUM</option>
        <option value="low"      ${item.severity==='low'     ?'selected':''}>LOW</option>
      </select>
      <button class="hunt-remove" onclick="removeHunt('${rowId}')">&#10005;</button>
    </div>`;
  });
  list.innerHTML = html;
}

function setSev(rowId, sel) {
  if (huntItems[rowId]) {
    huntItems[rowId].severity = sel.value;
    sel.className = 'sev-sel sev-' + sel.value;
    saveHunts();
  }
}

function removeHunt(rowId) {
  delete huntItems[rowId];
  const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
  if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  saveHunts();
  renderHunt();
}

function clearHunt() {
  Object.keys(huntItems).forEach(rowId => {
    const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
    if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  });
  huntItems = {};
  saveHunts();
  renderHunt();
}

function exportHunt(fmt) {
  const keys = Object.keys(huntItems);
  if (!keys.length) return;

  // Sort by addedAt to preserve hunt timeline order in exports.
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Use stored row data first; fall back to rowRegistry for items added before
  // persistence existed, or that for some reason lack the .row field.
  const getRow = rowId => huntItems[rowId].row || (rowRegistry[rowId] && rowRegistry[rowId].row);

  if (fmt === 'csv') {
    const q = s => '"' + String(s||'').replace(/"/g,'""').replace(/\n/g,' ') + '"';
    let csv = 'Order,Added,Severity,Technique,Indicator,Arkime,Kibana,Suricata,Notes\n';
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toISOString() : '';
      csv += [i+1, ts, item.severity.toUpperCase(), item.techId, r.indicator, r.arkime, r.kibana, r.suricata, r.notes].map(q).join(',') + '\n';
    });
    download(csv, 'hunt_package.csv', 'text/csv');
  } else {
    let out = `Hunt Package\nExported: ${new Date().toLocaleString()}\nIndicators: ${sortedKeys.length}\n${'='.repeat(60)}\n\n`;
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toLocaleString() : 'unknown';
      out += `[${i+1}] [${item.severity.toUpperCase()}] ${item.techId} — ${r.indicator}\nAdded: ${ts}\n${'-'.repeat(50)}\nARKIME:\n${r.arkime}\n\nKIBANA:\n${r.kibana}\n\nSURICATA:\n${r.suricata}\n\nNOTES:\n${r.notes}\n\n${'='.repeat(60)}\n\n`;
    });
    download(out, 'hunt_package.txt', 'text/plain');
  }
}

function download(content, filename, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── SEARCH + FILTER ──
function highlight(text, terms) {
  let result = esc(text);
  terms.forEach(t => {
    if (!t) return;
    const re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')', 'gi');
    result = result.replace(re, '<mark>$1</mark>');
  });
  return result;
}

function applyFilters() {
  const q   = (document.getElementById('search')?.value || '').toLowerCase().trim();
  const aq  = (document.getElementById('apt-search')?.value || '').toLowerCase().trim();
  const terms = q ? q.split(/\s+/).filter(Boolean) : [];
  let visible = 0;

  document.querySelectorAll('.ind-row').forEach(row => {
    const techMatch = activeTech === 'all' || row.dataset.tech === activeTech;
    const aptMatch  = !activeApt  || row.dataset.apt.includes(activeApt);
    const textMatch = !terms.length || terms.every(t => row.dataset.text.includes(t));
    const aptTxt    = !aq || row.dataset.text.includes(aq);

    if (techMatch && aptMatch && textMatch && aptTxt) {
      row.classList.remove('hidden');
      visible++;
      const nameEl = row.querySelector('.ind-name');
      if (nameEl) {
        const orig = row.querySelector('[data-row-id]')?.dataset.rowId
          ? rowRegistry[row.dataset.rowId]?.row.indicator
          : nameEl.textContent;
        if (orig) nameEl.innerHTML = highlight(orig, [...terms, aq].filter(Boolean));
      }
    } else {
      row.classList.add('hidden');
    }
  });

  document.querySelectorAll('.technique-section').forEach(sec => {
    sec.style.display = sec.querySelectorAll('.ind-row:not(.hidden)').length ? '' : 'none';
    const tocItem = document.querySelector(`.toc-item[data-tech="${sec.dataset.tech}"]`);
    if (tocItem) tocItem.classList.toggle('active', sec.dataset.tech === activeTech);
  });

  document.getElementById('no-results').style.display = visible ? 'none' : 'block';
  updateStats(visible, totalRows);
}

function updateStats(visible, total) {
  const el = document.getElementById('stats');
  if (el) el.textContent = `${visible} / ${total} indicators`;
}

// ── EVENT LISTENERS ──
document.getElementById('search')?.addEventListener('input', applyFilters);
document.getElementById('apt-search')?.addEventListener('input', applyFilters);

document.querySelectorAll('.fbtn[data-tech]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTech = btn.dataset.tech;
    applyFilters();
  });
});

document.querySelectorAll('.fbtn[data-apt]').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.apt;
    if (activeApt === key) {
      activeApt = null;
      btn.className = 'fbtn';
    } else {
      document.querySelectorAll('.fbtn[data-apt]').forEach(b => b.className = 'fbtn');
      activeApt = key;
      btn.classList.add('apt-' + key.toLowerCase());
    }
    applyFilters();
  });
});

// ── INIT ──
loadHunts();
render();
applyFilters();
renderHunt();
