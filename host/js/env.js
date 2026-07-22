/* ===========================================================================
   TONK environment profile  (tonk_env_v1)

   One profile per deployment, shared by every surface on the origin, exactly
   like the My Hunts list. A senior analyst authors it; juniors inherit it.

   Three classes of $VARIABLE, treated differently on purpose:

     observable  a scan can propose a value (DOMAIN_CONTROLLERS, DNS_SERVERS).
                 Proposals always carry their evidence and are never applied
                 without confirmation.
     policy      encodes what is PERMITTED, not what exists (ALLOWED_*,
                 SANCTIONED_*, *_ADMINS). A scan must never populate these:
                 filling an allowlist from observed traffic defines the
                 allowlist as reality, and the detection can never fire.
                 Unknown variables default to policy for exactly this reason.
     suricata    Suricata's own built-ins ($HOME_NET, $EXTERNAL_NET ...).
                 Suricata resolves these from suricata.yaml, so TONK leaves
                 them alone and instead can emit a vars: block to paste there.

   Substitution applies to Arkime and Kibana (the copy-into-a-search-bar
   fields). Suricata rules keep their variables.
   =========================================================================== */
(function (global) {
  'use strict';

  var KEY = 'tonk_env_v1';
  var SCHEMA = 1;

  // A TONK variable is ALL-CAPS, 4+ chars, not followed by more word chars.
  // The trailing guard stops `$Recycle.Bin` from being read as `$R`.
  var VAR_RE = /\$[A-Z][A-Z0-9_]{2,}(?![A-Za-z0-9_])/g;

  // Shell / OS variables that appear inside detection CONTENT, not TONK vars.
  var IGNORE = ['$IFS', '$PATH', '$HOME', '$USER', '$PWD', '$SHELL', '$RANDOM',
    '$COMSPEC', '$TEMP', '$TMP', '$APPDATA', '$SYSTEMROOT', '$WINDIR',
    '$USERPROFILE', '$PROGRAMDATA', '$LD_PRELOAD', '$PS1', '$HISTFILE',
    '$UID', '$EUID', '$OLDPWD', '$SECONDS'];

  // Resolved by Suricata itself from suricata.yaml.
  var SURICATA = ['$HOME_NET', '$EXTERNAL_NET', '$HTTP_SERVERS', '$SMTP_SERVERS',
    '$SQL_SERVERS', '$TELNET_SERVERS', '$AIM_SERVERS', '$DC_SERVERS',
    '$DNP3_SERVER', '$DNP3_CLIENT', '$MODBUS_SERVER', '$MODBUS_CLIENT',
    '$ENIP_SERVER', '$ENIP_CLIENT', '$HTTP_PORTS', '$SHELLCODE_PORTS',
    '$ORACLE_PORTS', '$SSH_PORTS', '$FTP_PORTS', '$FILE_DATA_PORTS'];

  // Variables a network scan can legitimately propose a value for.
  var OBSERVABLE = ['$MPNET', '$EXTERNAL', '$CORP_CIDR', '$DOMAIN_CONTROLLERS',
    '$DC_SUBNET', '$DNS_SERVERS', '$FILE_SERVERS', '$MAIL_SERVERS',
    '$EXCHANGE_HOSTS', '$VPN_SERVERS', '$NETWORK_DEVICES', '$ROUTERS',
    '$WORKSTATIONS', '$SERVERS', '$DMZ_SERVERS', '$BUILD_SERVERS',
    '$CONFLUENCE_HOSTS', '$SHAREPOINT_HOSTS', '$GIT_HOSTS', '$ADFS_SERVER',
    '$OWA_SERVER', '$RDP_GATEWAYS', '$RDP_JUMP_HOSTS', '$MPNET_WEB_APPS',
    '$MONITORING_HOSTS', '$PRINTER_VLAN', '$ADMIN_VLAN', '$MGMT_VLAN',
    '$LOCAL_DOMAIN', '$LOCAL_DOMAIN_SRV', '$MPNET_PROXIES',
    '$MPNET_PACKAGE_REGISTRY', '$LEGACY_INTERNAL', '$WEB_CLIENTS'];

  var POLICY_PREFIX = /^(ALLOWED|SANCTIONED|APPROVED|AUTHORIZED|KNOWN|BASELINE|MALICIOUS|THREAT_INTEL|NEWLY|CORP_SSIDS|SCAN_SOURCES)/;
  var POLICY_SUFFIX = /_(ADMINS|ALLOWLIST|BASELINE|RANGE|RANGES|GEOS|OUIS|PREFIXES|BSSIDS|SSIDS|CLIENTS|IPS|DESTS|PEERS|PARTNERS)$/;

  function has(arr, v) { return arr.indexOf(v) !== -1; }

  function classify(name) {
    if (has(IGNORE, name)) return 'ignore';
    if (has(SURICATA, name)) return 'suricata';
    var bare = name.slice(1);
    if (POLICY_PREFIX.test(bare) || POLICY_SUFFIX.test(bare)) return 'policy';
    if (has(OBSERVABLE, name)) return 'observable';
    return 'policy';   // safe default: never auto-fill something unclassified
  }

  // ---- state -------------------------------------------------------------

  var state = null;

  function blank() {
    return { _v: SCHEMA, name: '', vars: {}, meta: {} };
  }

  function load() {
    if (state) return state;
    try {
      var raw = global.localStorage.getItem(KEY);
      state = raw ? JSON.parse(raw) : blank();
      if (!state || state._v !== SCHEMA) state = blank();
      if (!state.vars) state.vars = {};
    } catch (e) {
      state = blank();
    }
    return state;
  }

  function save() {
    try {
      global.localStorage.setItem(KEY, JSON.stringify(load()));
    } catch (e) { /* private mode / quota - substitution still works in-session */ }
    notify();
  }

  var listeners = [];
  function onChange(fn) { listeners.push(fn); }
  function notify() { listeners.forEach(function (f) { try { f(); } catch (e) {} }); }

  function isOn() { return load().enabled !== false; }
  function setOn(v) { load().enabled = !!v; save(); }

  function get(name) {
    var e = load().vars[name];
    return e && e.value ? e.value : null;
  }

  function set(name, value, source, evidence) {
    var s = load();
    if (!value) { delete s.vars[name]; }
    else {
      s.vars[name] = {
        value: String(value).trim(),
        source: source || 'manual',
        evidence: evidence || '',
        ts: new Date().toISOString()
      };
    }
    save();
  }

  // ---- discovery ---------------------------------------------------------

  /* Walk a DATA array and count how many indicator rows use each variable. */
  function discover(DATA, fields) {
    fields = fields || ['arkime', 'kibana', 'suricata'];
    var counts = {};
    (DATA || []).forEach(function (tech) {
      (tech.rows || []).forEach(function (row) {
        var seen = {};
        fields.forEach(function (f) {
          var v = row[f];
          if (typeof v !== 'string') return;
          var m = v.match(VAR_RE) || [];
          m.forEach(function (name) { seen[name] = true; });
        });
        Object.keys(seen).forEach(function (n) {
          if (classify(n) === 'ignore') return;
          counts[n] = (counts[n] || 0) + 1;
        });
      });
    });
    return counts;
  }

  // ---- substitution ------------------------------------------------------

  /*
     Replace mapped variables in a query. Returns the rewritten text plus the
     list of variables that are still unmapped, so the UI can warn. An
     unmapped variable pasted into Kibana returns zero hits, which reads as a
     clean network - the single worst failure mode this feature can have.
  */
  /*
     Fields that are genuinely queries pasted into a search bar. Everything
     else (Suricata rules, Sysmon config, PowerShell/bash hunt scripts) is
     left untouched: Suricata resolves its own variables, and the script
     fields contain LOCAL shell variables ($BASELINE, $HAVE_RPM, $BINS,
     $LASTEXITCODE ...) that would be corrupted by substitution.
  */
  var SUBSTITUTABLE = ['arkime', 'kibana'];

  function substitute(text, field) {
    var out = { text: text, unmapped: [], mapped: [] };
    if (typeof text !== 'string' || !text) return out;
    if (field && SUBSTITUTABLE.indexOf(field) === -1) return out;
    if (!isOn()) {
      (text.match(VAR_RE) || []).forEach(function (n) {
        if (classify(n) === 'ignore') return;
        if (out.unmapped.indexOf(n) === -1 && !get(n)) out.unmapped.push(n);
      });
      return out;
    }
    out.text = text.replace(VAR_RE, function (name) {
      if (classify(name) === 'ignore') return name;
      var val = get(name);
      if (val) {
        if (out.mapped.indexOf(name) === -1) out.mapped.push(name);
        return val;
      }
      if (out.unmapped.indexOf(name) === -1) out.unmapped.push(name);
      return name;
    });
    return out;
  }

  // ---- portability -------------------------------------------------------

  function exportJSON() {
    var s = load();
    return JSON.stringify({
      _v: SCHEMA,
      name: s.name || '',
      exported: new Date().toISOString(),
      meta: s.meta || {},
      vars: s.vars
    }, null, 2);
  }

  function importJSON(text) {
    var incoming = JSON.parse(text);
    if (!incoming || !incoming.vars) throw new Error('not a TONK env profile');
    var s = load();
    s.name = incoming.name || s.name;
    s.meta = incoming.meta || s.meta;
    Object.keys(incoming.vars).forEach(function (k) { s.vars[k] = incoming.vars[k]; });
    save();
    return Object.keys(incoming.vars).length;
  }

  /* Suricata resolves its own variables, so hand the analyst a vars: block
     for suricata.yaml rather than rewriting the rules. */
  function suricataVars() {
    var s = load(), lines = ['vars:', '  address-groups:'];
    Object.keys(s.vars).sort().forEach(function (k) {
      if (classify(k) === 'suricata') return;
      var v = s.vars[k].value;
      if (!/^[\d.,:\/\[\]\s$!a-fA-F]+$/.test(v)) return;   // address-like only
      lines.push('    ' + k.slice(1) + ': "' + v + '"');
    });
    return lines.join('\n');
  }

  global.TonkEnv = {
    KEY: KEY, VAR_RE: VAR_RE,
    classify: classify, discover: discover, substitute: substitute,
    load: load, save: save, get: get, set: set,
    isOn: isOn, setOn: setOn, onChange: onChange,
    exportJSON: exportJSON, importJSON: importJSON, suricataVars: suricataVars,
    _classes: { IGNORE: IGNORE, SURICATA: SURICATA, OBSERVABLE: OBSERVABLE }
  };
})(typeof window !== 'undefined' ? window : globalThis);

/* ===========================================================================
   Panel UI. Mirrors the My Hunts slide-down so the interaction is familiar.
   Injected by env-panel.init(DATA) from each page after core.js runs.
   =========================================================================== */
(function (global) {
  'use strict';
  var E = global.TonkEnv;
  if (!E) return;

  var LABEL = {
    observable: 'Observable  (a scan can propose these)',
    policy: 'Policy  (you define these - a scan must not)',
    suricata: 'Suricata built-ins  (resolved by suricata.yaml)'
  };
  var HINT = {
    observable: 'Derived from what is on the wire: subnets, server roles, VLANs.',
    policy: 'These encode what is PERMITTED. Filling an allowlist from observed traffic makes the allowlist a description of reality, and the detection can never fire.',
    suricata: 'Left untouched in Suricata rules. Use "suricata.yaml vars" below to define them there.'
  };

  function el(tag, cls, text) {
    var d = document.createElement(tag);
    if (cls) d.className = cls;
    if (text != null) d.textContent = text;
    return d;
  }

  function init(DATA) {
    if (document.querySelector('.env-btn')) return;   // already initialised
    var counts = E.discover(DATA);
    var names = Object.keys(counts).sort(function (a, b) {
      return counts[b] - counts[a] || a.localeCompare(b);
    });

    var header = document.querySelector('.header-right') || document.querySelector('header');
    if (!header) return;

    var btn = el('button', 'env-btn');
    var badge = el('span', 'env-badge');
    btn.textContent = '\u2699 Environment ';
    btn.appendChild(badge);
    header.appendChild(btn);

    var panel = el('div', 'env-panel');
    panel.id = 'env-panel';
    document.body.appendChild(panel);
    btn.addEventListener('click', function () { panel.classList.toggle('open'); });

    function totals() {
      var mapped = 0, covered = 0, total = 0;
      names.forEach(function (n) {
        if (E.classify(n) === 'suricata') return;
        total++;
        if (E.get(n)) mapped++;
      });
      // rows fully satisfied = rows whose every non-suricata var is mapped
      (DATA || []).forEach(function (t) {
        (t.rows || []).forEach(function (r) {
          var need = {}, any = false;
          ['arkime', 'kibana'].forEach(function (f) {
            var v = r[f];
            if (typeof v !== 'string') return;
            (v.match(E.VAR_RE) || []).forEach(function (n) {
              var c = E.classify(n);
              if (c === 'ignore' || c === 'suricata') return;
              need[n] = true; any = true;
            });
          });
          if (!any) { covered++; return; }
          var ok = Object.keys(need).every(function (n) { return !!E.get(n); });
          if (ok) covered++;
        });
      });
      var rows = 0;
      (DATA || []).forEach(function (t) { rows += (t.rows || []).length; });
      return { mapped: mapped, total: total, covered: covered, rows: rows };
    }

    function render() {
      var t = totals();
      badge.textContent = t.mapped + '/' + t.total;
      badge.className = 'env-badge' + (t.mapped ? ' on' : '');
      panel.innerHTML = '';
      var inner = el('div', 'env-inner');

      var top = el('div', 'env-top');
      top.appendChild(el('div', 'env-title', 'Environment profile'));
      var stat = el('div', 'env-stat');
      stat.textContent = t.mapped + ' of ' + t.total + ' variables mapped \u00b7 '
        + t.covered + ' of ' + t.rows + ' indicators fully resolved';
      top.appendChild(stat);

      var subWrap = el('label', 'env-toggle');
      var sub = document.createElement('input');
      sub.type = 'checkbox'; sub.checked = E.isOn();
      sub.addEventListener('change', function () { E.setOn(sub.checked); });
      subWrap.appendChild(sub);
      subWrap.appendChild(el('span', null, 'Substitute values in queries'));
      top.appendChild(subWrap);
      inner.appendChild(top);

      ['observable', 'policy', 'suricata'].forEach(function (cls) {
        var group = names.filter(function (n) { return E.classify(n) === cls; });
        if (!group.length) return;
        var sec = el('div', 'env-sec env-sec-' + cls);
        sec.appendChild(el('div', 'env-sec-head', LABEL[cls]));
        sec.appendChild(el('div', 'env-sec-hint', HINT[cls]));
        group.forEach(function (name) {
          var row = el('div', 'env-row');
          var lab = el('div', 'env-var');
          lab.appendChild(el('span', 'env-var-name', name));
          lab.appendChild(el('span', 'env-var-use', counts[name] + (counts[name] === 1 ? ' indicator' : ' indicators')));
          row.appendChild(lab);
          if (cls === 'suricata') {
            row.appendChild(el('div', 'env-suri', 'defined in suricata.yaml'));
          } else {
            var input = document.createElement('input');
            input.type = 'text';
            input.className = 'env-input';
            input.placeholder = cls === 'policy' ? 'analyst-defined value' : 'e.g. 10.10.0.0/16';
            var cur = E.load().vars[name];
            input.value = cur ? cur.value : '';
            input.addEventListener('change', function () {
              E.set(name, input.value, 'manual');
              render();
            });
            row.appendChild(input);
            if (cur && cur.source && cur.source !== 'manual') {
              var src = el('span', 'env-src', cur.source);
              if (cur.evidence) src.title = cur.evidence;
              row.appendChild(src);
            }
          }
          sec.appendChild(row);
        });
        inner.appendChild(sec);
      });

      var actions = el('div', 'env-actions');
      function act(label, fn, cls) {
        var b = el('button', 'env-act' + (cls ? ' ' + cls : ''), label);
        b.addEventListener('click', fn);
        actions.appendChild(b);
        return b;
      }
      act('\u2193 Export profile', function () {
        dl('tonk-env-profile.json', E.exportJSON(), 'application/json');
      });
      var file = document.createElement('input');
      file.type = 'file'; file.accept = '.json'; file.style.display = 'none';
      file.addEventListener('change', function () {
        var f = file.files[0]; if (!f) return;
        var rd = new FileReader();
        rd.onload = function () {
          try {
            var n = E.importJSON(rd.result);
            render();
            alert('Imported ' + n + ' variables.');
          } catch (err) { alert('Import failed: ' + err.message); }
        };
        rd.readAsText(f); file.value = '';
      });
      actions.appendChild(file);
      act('\u2191 Import profile', function () { file.click(); });
      act('suricata.yaml vars', function () {
        dl('tonk-suricata-vars.yaml', E.suricataVars(), 'text/yaml');
      });
      act('\u2715 Clear all', function () {
        if (!confirm('Clear every mapped variable in this profile?')) return;
        E.load().vars = {}; E.save(); render();
      }, 'env-danger');
      inner.appendChild(actions);
      panel.appendChild(inner);
    }

    function dl(name, text, mime) {
      var b = new Blob([text], { type: mime });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(b); a.download = name;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    }

    E.onChange(function () {
      var t = totals();
      badge.textContent = t.mapped + '/' + t.total;
    });
    render();
    global.addEventListener('storage', function (e) {
      if (e.key === E.KEY) { E.load.state = null; render(); }
    });
  }

  E.initPanel = init;
})(typeof window !== 'undefined' ? window : globalThis);
