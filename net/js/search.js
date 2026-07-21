// ===========================================================================
// TONK hunt reference - global matrix search (index page)
//
// Each tactic data file declares `const DATA = [...]`, so they cannot all be
// loaded with <script> tags on one page (duplicate `const DATA` throws).
// Instead we fetch each file as text and evaluate it in an isolated function
// scope, capturing its DATA without touching the global namespace. This needs
// zero changes to the data files or core.js. Served over http (python3 -m
// http.server) fetch works fine; under file:// fetch is blocked and we show a
// friendly hint.
// ===========================================================================

(function () {
  'use strict';

  // Tactic metadata - file, destination page, label, accent, ATT&CK id.
  const TACTICS = [
    { file: 'js/data/recon.js',          page: 'recon.html',          label: 'Reconnaissance',    id: 'TA0043', color: '#58a6ff' },
    { file: 'js/data/initial_access.js', page: 'initial_access.html', label: 'Initial Access',    id: 'TA0001', color: '#3fb950' },
    { file: 'js/data/discovery.js',      page: 'discovery.html',      label: 'Discovery',         id: 'TA0007', color: '#58a6ff' },
    { file: 'js/data/lateral.js',        page: 'lateral.html',        label: 'Lateral Movement',  id: 'TA0008', color: '#d29922' },
    { file: 'js/data/credential.js',     page: 'credential.html',     label: 'Credential Access', id: 'TA0006', color: '#f85149' },
    { file: 'js/data/collection.js',     page: 'collection.html',     label: 'Collection',        id: 'TA0009', color: '#bc8cff' },
    { file: 'js/data/c2.js',             page: 'c2.html',             label: 'Command & Control', id: 'TA0011', color: '#ff7b72' },
    { file: 'js/data/exfil.js',          page: 'exfil.html',          label: 'Exfiltration',      id: 'TA0010', color: '#7ee787' },
    { file: 'js/data/cloud.js',          page: 'cloud.html',          label: 'Cloud Control Plane', id: 'CLOUD', color: '#56d4dd' }
  ];

  let INDEX = [];          // flat list of every indicator row
  let APT_NAMES = [];      // unique APT names (original casing)
  let APT_META = {};       // lowercased name -> { name, cls, count }
  let ready = false;
  let loadError = false;

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Canonical actor resolution. Uses actors.js (resolveActor) when present so
  // aliases collapse to one canonical name (Cozy Bear -> APT29). Degrades to
  // identity if actors.js is not loaded, so search never hard-depends on it.
  const canon = (name) => {
    if (typeof resolveActor === 'function') return resolveActor(name);
    return name;
  };
  const canonKey = (name) => canon(name).toLowerCase();

  // Parse one data file's text into its DATA array, isolated from globals.
  function parseData(text) {
    // The file body ends with `const DATA = [...];` - run it in a private
    // scope and hand back DATA. new Function keeps it out of window.
    return (new Function(text + '\n;return (typeof DATA !== "undefined") ? DATA : [];'))();
  }

  async function loadAll() {
    const flat = [];
    for (const t of TACTICS) {
      try {
        const res = await fetch(t.file, { cache: 'no-store' });
        if (!res.ok) throw new Error(res.status);
        const data = parseData(await res.text());
        (data || []).forEach((tech) => {
          (tech.rows || []).forEach((row) => {
            flat.push({
              tactic: t,
              techId: tech.id,
              techName: tech.name,
              sub: row.sub || '',
              indicator: row.indicator || '',
              notes: row.notes || '',
              cite: row.cite || '',
              apt: Array.isArray(row.apt) ? row.apt : []
            });
          });
        });
      } catch (e) {
        loadError = true;
        // keep going - a single missing file should not kill the whole index
      }
    }
    INDEX = flat;

    // Build the APT registry, keyed by CANONICAL name so aliases merge
    // (Cozy Bear + APT29 + Midnight Blizzard -> one APT29 entry, counts summed).
    const meta = {};
    flat.forEach((r) => r.apt.forEach((a) => {
      if (!a || !a.name) return;
      const display = canon(a.name);
      const k = display.toLowerCase();
      if (!meta[k]) meta[k] = { name: display, cls: a.cls || 'apt-mul', count: 0 };
      meta[k].count++;
    }));
    APT_META = meta;
    APT_NAMES = Object.values(meta).map((m) => m.name);
    ready = true;
  }

  // ---- rendering ----------------------------------------------------------

  // Generic catch-all labels that are not specific named actors. They stay
  // searchable if typed, but should not crowd the quick-actor chips.
  const GENERIC_ACTOR = /^(multi|ransomware|red team|commodity|.*threats|older malware families|cybercriminals?|various|unknown)$/i;

  function renderChips() {
    const wrap = $('repo-search-chips');
    if (!wrap) return;
    // Feature the most-referenced actors; surface the Typhoons first if present.
    const featured = ['Salt Typhoon', 'Volt Typhoon'];
    const ranked = Object.values(APT_META)
      .filter((m) => !GENERIC_ACTOR.test(m.name))
      .sort((a, b) => b.count - a.count);
    const seen = new Set();
    const chips = [];
    featured.forEach((name) => {
      const m = APT_META[name.toLowerCase()];
      if (m) { chips.push(m); seen.add(m.name.toLowerCase()); }
    });
    ranked.forEach((m) => {
      if (chips.length >= 12) return;
      if (seen.has(m.name.toLowerCase())) return;
      chips.push(m); seen.add(m.name.toLowerCase());
    });
    wrap.innerHTML = '<span class="rs-chip-label">Jump to an actor:</span>' +
      chips.map((m) =>
        `<button type="button" class="rs-chip ${esc(m.cls)}" data-apt="${esc(m.name)}">${esc(m.name)} <span class="rs-chip-n">${m.count}</span></button>`
      ).join('');
    wrap.querySelectorAll('.rs-chip').forEach((b) => {
      b.addEventListener('click', () => {
        const v = b.dataset.apt;
        const input = $('repo-search-input');
        if (input) input.value = v;
        runSearch(v);
      });
    });
  }

  function aptBadges(apt, highlightSet) {
    return apt.map((a) => {
      const hot = highlightSet && highlightSet.has(canonKey(a.name || ''));
      return `<span class="rs-apt ${esc(a.cls || 'apt-mul')}${hot ? ' rs-apt-hot' : ''}">${esc(a.name)}</span>`;
    }).join('');
  }

  function render(rows, q, mode, matchedAptSet) {
    const out = $('repo-search-results');
    if (!out) return;

    if (loadError && INDEX.length === 0) {
      out.innerHTML = `<div class="rs-empty">Could not load the data files. This search needs the kit to be served over http (for example <code>python3 -m http.server</code>); opening index.html directly from disk blocks the fetch.</div>`;
      return;
    }
    if (!rows.length) {
      out.innerHTML = `<div class="rs-empty">No matches for <strong>${esc(q)}</strong>. Try an actor name (Salt Typhoon), a technique (T1090), or a keyword (portproxy, GRE, TFTP).</div>`;
      return;
    }

    // Group by tactic, preserving the TACTICS order.
    const byTactic = new Map();
    rows.forEach((r) => {
      if (!byTactic.has(r.tactic.label)) byTactic.set(r.tactic.label, { tactic: r.tactic, rows: [] });
      byTactic.get(r.tactic.label).rows.push(r);
    });

    const header = mode === 'apt'
      ? `<div class="rs-summary"><strong>${esc(q)}</strong> appears in <strong>${rows.length}</strong> indicator${rows.length === 1 ? '' : 's'} across <strong>${byTactic.size}</strong> tactic${byTactic.size === 1 ? '' : 's'}</div>`
      : `<div class="rs-summary"><strong>${rows.length}</strong> indicator${rows.length === 1 ? '' : 's'} match <strong>${esc(q)}</strong></div>`;

    const groups = TACTICS.map((t) => byTactic.get(t.label)).filter(Boolean);

    out.innerHTML = header + groups.map((g) => {
      const t = g.tactic;
      const items = g.rows.map((r) => {
        let note = '';
        if (mode === 'apt' && matchedAptSet) {
          const hit = r.apt.find((a) => matchedAptSet.has(canonKey(a.name || '')));
          if (hit && hit.note) note = `<div class="rs-note">${esc(hit.note)}</div>`;
        }
        const anchor = `${t.page}#tech-${r.techId}`;
        return `
          <a class="rs-row" href="${esc(anchor)}">
            <div class="rs-row-top">
              <span class="rs-tech">${esc(r.techId)} · ${esc(r.techName)}</span>
              <span class="rs-aptwrap">${aptBadges(r.apt, matchedAptSet)}</span>
            </div>
            <div class="rs-ind">${esc(r.sub)}${r.sub ? ' · ' : ''}${esc(r.indicator)}</div>
            ${note}
          </a>`;
      }).join('');
      return `
        <div class="rs-group">
          <div class="rs-group-head" style="color:${t.color}">
            <span class="rs-tac-id">${esc(t.id)}</span>
            <span class="rs-tac-label">${esc(t.label)}</span>
            <span class="rs-tac-count">${g.rows.length}</span>
          </div>
          ${items}
        </div>`;
    }).join('');
  }

  // ---- search -------------------------------------------------------------

  function runSearch(raw) {
    const q = (raw || '').trim();
    const out = $('repo-search-results');
    if (!ready) {
      if (out) out.innerHTML = `<div class="rs-empty">Indexing the matrix...</div>`;
      // retry shortly once loading finishes
      setTimeout(() => runSearch(raw), 150);
      return;
    }
    if (q.length < 2) { if (out) out.innerHTML = ''; return; }

    const ql = q.toLowerCase();

    // APT-name match takes priority (the headline use case). Resolve the query
    // through canonical names so an alias (Cozy Bear) matches indicators tagged
    // with any sibling name (APT29, Midnight Blizzard) and vice versa.
    // Match canonical-to-canonical: resolve the query AND each actor name.
    const qCanon = canonKey(q);
    const matchedNames = APT_NAMES.filter((n) => {
      const nl = n.toLowerCase();
      // direct substring match on the (canonical) registry name, OR the typed
      // query resolves to this canonical actor (handles alias input).
      return nl.includes(ql) || (qCanon && nl === qCanon);
    });
    if (matchedNames.length) {
      // Build the canonical set we are matching against.
      const set = new Set(matchedNames.map((n) => n.toLowerCase()));
      // A row matches if ANY of its actors, resolved to canonical, is in the set.
      const rows = INDEX.filter((r) => r.apt.some((a) => set.has(canonKey(a.name || ''))));
      render(rows, matchedNames.length === 1 ? matchedNames[0] : q, 'apt', set);
      return;
    }

    // Fallback: keyword match across technique id/name, indicator, notes, cite.
    const rows = INDEX.filter((r) =>
      (r.techId + ' ' + r.techName + ' ' + r.sub + ' ' + r.indicator + ' ' + r.notes + ' ' + r.cite)
        .toLowerCase().includes(ql)
    );
    render(rows, q, 'kw', null);
  }

  // ---- wire up ------------------------------------------------------------

  function init() {
    const input = $('repo-search-input');
    const btn = $('repo-search-btn');
    if (!input && !btn) return; // markup not present on this page

    let t = null;
    if (input) {
      input.addEventListener('input', () => {
        clearTimeout(t);
        t = setTimeout(() => runSearch(input.value), 160);
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { clearTimeout(t); runSearch(input.value); }
      });
    }
    if (btn) btn.addEventListener('click', () => runSearch(input ? input.value : ''));

    loadAll().then(() => {
      renderChips();
      if (input && input.value.trim().length >= 2) runSearch(input.value);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
