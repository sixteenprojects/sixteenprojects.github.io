/**
 * export.js — IOC-centric export: CSV, JSON, YARA rules, Suricata rules.
 *
 * For malware / actors / ransomware: collects real IOCs from ThreatFox,
 * OTX (ioc.json), and FeodoTracker, then converts them to detection content.
 * For victims: exports metadata as plain CSV/JSON.
 *
 * IOC sources per entity type:
 *   malware    → threatfox.malware[id].iocs  +  .samples (MalwareBazaar hashes)
 *   actors     → ioc.actors[id].indicators (OTX)  +  ThreatFox for linked malware
 *   ransomware → feodo.c2s filtered by group name  +  linked actor OTX indicators
 */

import Security from './security.js';
import Api      from './api.js';

const Export = (() => {
  'use strict';

  // ── IOC collection ─────────────────────────────────────────────────────────

  /**
   * Collect normalized IOCs for the given entity type and items array.
   * Returns [{type, value, port, malware, actor, source, confidence, date, threat_type}]
   */
  function collectIOCs(type, items) {
    const cache     = Api.getAll();
    const tfMalware = (cache.threatfox || {}).malware       || {};
    const tfFeodo   = ((cache.threatfox || {}).feodo || {}).c2s || [];
    const iocActors = ((cache.ioc || {}).actors || cache.ioc) || {};
    const iocs      = [];

    if (type === 'malware') {
      for (const item of items) {
        const tf = tfMalware[item.id] || {};

        for (const ioc of (tf.iocs || [])) {
          const raw = ioc.value || '';
          let value = raw, port = null;
          if ((ioc.type || '').toLowerCase().includes('ip') && raw.includes(':')) {
            [value, port] = raw.split(':');
          }
          iocs.push({
            type:        _normalizeType(ioc.type || ''),
            value,
            port,
            malware:     item.name || item.id,
            actor:       '',
            source:      'ThreatFox',
            confidence:  ioc.confidence || 0,
            date:        (ioc.first_seen || '').slice(0, 10),
            threat_type: ioc.threat_type || '',
          });
        }

        for (const s of (tf.samples || [])) {
          const base = { port: null, malware: item.name || item.id, actor: '', source: 'MalwareBazaar', confidence: 100, date: (s.first_seen || '').slice(0, 10), threat_type: '' };
          if (s.sha256) iocs.push({ type: 'sha256', value: s.sha256, file_name: s.file_name || '', ...base });
          if (s.md5)    iocs.push({ type: 'md5',    value: s.md5,    file_name: s.file_name || '', ...base });
        }
      }
    }

    if (type === 'actors') {
      for (const item of items) {
        // OTX indicators for this actor
        const entry = iocActors[item.id] || {};
        const ind   = entry.indicators || {};
        for (const [iocType, values] of Object.entries(ind)) {
          for (const val of (values || [])) {
            iocs.push({
              type:        iocType,
              value:       val,
              port:        null,
              malware:     '',
              actor:       item.name || item.id,
              source:      'OTX AlienVault',
              confidence:  75,
              date:        (entry.updated || '').slice(0, 10),
              threat_type: '',
            });
          }
        }

        // ThreatFox data for each malware family used by this actor (capped)
        for (const mId of (item.malware || []).slice(0, 10)) {
          const tf = tfMalware[mId] || {};
          for (const ioc of (tf.iocs || []).slice(0, 30)) {
            const raw = ioc.value || '';
            let value = raw, port = null;
            if ((ioc.type || '').toLowerCase().includes('ip') && raw.includes(':')) {
              [value, port] = raw.split(':');
            }
            iocs.push({
              type:        _normalizeType(ioc.type || ''),
              value, port,
              malware:     mId,
              actor:       item.name || item.id,
              source:      'ThreatFox',
              confidence:  ioc.confidence || 0,
              date:        (ioc.first_seen || '').slice(0, 10),
              threat_type: ioc.threat_type || '',
            });
          }
          for (const s of (tf.samples || []).slice(0, 15)) {
            const base = { port: null, malware: mId, actor: item.name || item.id, source: 'MalwareBazaar', confidence: 100, date: (s.first_seen||'').slice(0,10), threat_type:'' };
            if (s.sha256) iocs.push({ type: 'sha256', value: s.sha256, file_name: s.file_name||'', ...base });
            if (s.md5)    iocs.push({ type: 'md5',    value: s.md5,    file_name: s.file_name||'', ...base });
          }
        }
      }
    }

    if (type === 'ransomware') {
      for (const item of items) {
        const name = (item.name || '').toLowerCase();
        for (const c2 of tfFeodo) {
          const c2name = (c2.malware || '').toLowerCase();
          if (!c2name || !name) continue;
          if (c2name === name || c2name.includes(name) || name.includes(c2name)) {
            iocs.push({
              type:        'ip',
              value:       c2.ip,
              port:        c2.port ? String(c2.port) : null,
              malware:     c2.malware || item.name,
              actor:       '',
              source:      'FeodoTracker',
              confidence:  90,
              date:        (c2.last_online || c2.first_seen || '').slice(0, 10),
              threat_type: 'botnet_cc',
            });
          }
        }
      }
    }

    // Deduplicate by type:value
    const seen = new Set();
    return iocs.filter(ioc => {
      if (!ioc.value) return false;
      const key = `${ioc.type}:${ioc.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function _normalizeType(raw) {
    const map = {
      'IPv4': 'ip', 'IPv6': 'ip', 'ip:port': 'ip',
      'domain': 'domain', 'hostname': 'domain',
      'URL': 'url',
      'FileHash-MD5': 'md5', 'FileHash-SHA256': 'sha256', 'FileHash-SHA1': 'sha1',
    };
    return map[raw] || (raw || 'unknown').toLowerCase();
  }

  // ── IOC download functions ─────────────────────────────────────────────────

  function toIOCcsv(iocs, filename = 'iocs.csv') {
    if (!iocs.length) return;
    const cols = ['type', 'value', 'port', 'malware', 'actor', 'source', 'confidence', 'date', 'threat_type'];
    const header = cols.join(',');
    const rows   = iocs.map(ioc => cols.map(k => _csvCell(ioc[k])).join(','));
    _download([header, ...rows].join('\r\n'), filename, 'text/csv;charset=utf-8');
  }

  function toIOCjson(iocs, label, filename = 'iocs.json') {
    if (!iocs.length) return;
    _download(
      JSON.stringify({
        generated: new Date().toISOString(),
        source: 'TI-Hub / The Sixteen Project',
        entity: label,
        count: iocs.length,
        iocs,
      }, null, 2),
      filename,
      'application/json'
    );
  }

  function toIOCyara(iocs, label, filename = 'tihub.yar') {
    if (!iocs.length) return;
    const rules = _buildYARAfromIOCs(iocs, label);
    if (!rules.length) return;
    const header = [
      `/*`,
      ` * TI-Hub IOC YARA Rules`,
      ` * Entity: ${_safeStr(label)}`,
      ` * Generated: ${new Date().toISOString()}`,
      ` * IOC count: ${iocs.length} | Rules: ${rules.length}`,
      ` * Source: TI-Hub / ThreatFox · MalwareBazaar · OTX AlienVault`,
      ` * WARNING: Review and tune before production deployment.`,
      ` */`,
      '',
    ].join('\n');
    _download(header + rules.join('\n\n'), filename, 'text/plain');
  }

  function toIOCSuricata(iocs, label, filename = 'tihub.rules') {
    if (!iocs.length) return;
    const rules = _buildSuricataFromIOCs(iocs, label);
    if (!rules.length) return;
    const header = [
      `# TI-Hub Suricata IOC Rules`,
      `# Entity: ${label}`,
      `# Generated: ${new Date().toISOString()}`,
      `# Rules: ${rules.length}`,
      `# Source: TI-Hub / ThreatFox · FeodoTracker · OTX AlienVault`,
      `# WARNING: Review before deploying in production.`,
      ``,
    ].join('\n');
    _download(header + rules.join('\n'), filename, 'text/plain');
  }

  // ── YARA rule builder ──────────────────────────────────────────────────────

  function _buildYARAfromIOCs(iocs, label) {
    const rules = [];
    const name  = _yaraName(label);
    const today = new Date().toISOString().slice(0, 10);

    // 1. Hash rule (YARA hash module)
    const sha256s = iocs.filter(i => i.type === 'sha256' && /^[0-9a-fA-F]{64}$/.test(i.value)).slice(0, 60);
    const md5s    = iocs.filter(i => i.type === 'md5'    && /^[0-9a-fA-F]{32}$/.test(i.value)).slice(0, 60);
    if (sha256s.length || md5s.length) {
      const conditions = [
        ...sha256s.map(h => `        hash.sha256(0, filesize) == "${h.value.toLowerCase()}"`),
        ...md5s.map(h    => `        hash.md5(0, filesize) == "${h.value.toLowerCase()}"`),
      ];
      rules.push(
        `import "hash"\n\n` +
        `rule ${name}_FileHash {\n` +
        `    meta:\n` +
        `        description = "${_safeStr(label)} malware samples — file hash detection"\n` +
        `        source = "TI-Hub / MalwareBazaar"\n` +
        `        date = "${today}"\n` +
        `        sample_count = "${sha256s.length + md5s.length}"\n` +
        `    condition:\n` +
        conditions.join(' or\n') +
        `\n}`
      );
    }

    // 2. Domain / URL string rule
    const domains = iocs.filter(i => i.type === 'domain' && _validDomain(i.value)).slice(0, 40);
    const urls    = iocs.filter(i => i.type === 'url').slice(0, 20);
    const netStrings = [
      ...domains.map((d, i) => `        $d${i+1} = "${_safeStr(d.value)}" nocase ascii wide`),
      ...urls.flatMap((u, i) => {
        try {
          const path = new URL(u.value).pathname;
          if (path && path !== '/') return [`        $u${i+1} = "${_safeStr(path)}" nocase ascii`];
        } catch {}
        return [];
      }),
    ];
    if (netStrings.length) {
      rules.push(
        `rule ${name}_Network {\n` +
        `    meta:\n` +
        `        description = "${_safeStr(label)} C2 domains and malicious URLs"\n` +
        `        source = "TI-Hub / ThreatFox + OTX AlienVault"\n` +
        `        date = "${today}"\n` +
        `    strings:\n` +
        netStrings.join('\n') + '\n' +
        `    condition:\n` +
        `        any of them\n` +
        `}`
      );
    }

    // 3. IP address string rule
    const ips = iocs.filter(i => i.type === 'ip' && _validIP(i.value)).slice(0, 40);
    if (ips.length) {
      const ipStrings = ips.map((ip, i) => `        $ip${i+1} = "${ip.value}" ascii`);
      rules.push(
        `rule ${name}_IP {\n` +
        `    meta:\n` +
        `        description = "${_safeStr(label)} known C2 IP addresses"\n` +
        `        source = "TI-Hub / ThreatFox + FeodoTracker + OTX"\n` +
        `        date = "${today}"\n` +
        `        note = "String-based — use Suricata rules for network detection"\n` +
        `    strings:\n` +
        ipStrings.join('\n') + '\n' +
        `    condition:\n` +
        `        any of ($ip*)\n` +
        `}`
      );
    }

    return rules;
  }

  // ── Suricata rule builder ──────────────────────────────────────────────────

  function _buildSuricataFromIOCs(iocs, label) {
    const rules   = [];
    let   sid     = 9100001;
    const today   = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const safeLbl = label.replace(/[^a-zA-Z0-9_. -]/g, '_').slice(0, 40);

    // IP → alert ip
    for (const ioc of iocs.filter(i => i.type === 'ip' && _validIP(i.value))) {
      const dstPort = ioc.port || 'any';
      rules.push(
        `alert ip $HOME_NET any -> ${ioc.value} ${dstPort} ` +
        `(msg:"TIHub ${safeLbl} C2 IP ${ioc.value}"; ` +
        `classtype:trojan-activity; sid:${sid}; rev:1; ` +
        `metadata:affected_product Any,attack_target Client_Endpoint,` +
        `created_at ${today},confidence ${ioc.confidence || 0},` +
        `source_feed ${(ioc.source || '').replace(/\s+/g, '_')},tihub true;)`
      );
      sid++;
      if (rules.length >= 600) break;
    }

    // Domain → alert dns
    for (const ioc of iocs.filter(i => i.type === 'domain' && _validDomain(i.value))) {
      rules.push(
        `alert dns $HOME_NET any -> any 53 ` +
        `(msg:"TIHub ${safeLbl} C2 domain ${ioc.value}"; ` +
        `dns.query; content:"${ioc.value}"; nocase; ` +
        `classtype:trojan-activity; sid:${sid}; rev:1; ` +
        `metadata:created_at ${today},confidence ${ioc.confidence || 0},` +
        `source_feed ${(ioc.source || '').replace(/\s+/g, '_')},tihub true;)`
      );
      sid++;
      if (rules.length >= 600) break;
    }

    // URL → alert http
    for (const ioc of iocs.filter(i => i.type === 'url')) {
      try {
        const u    = new URL(ioc.value);
        const host = u.hostname;
        const path = (u.pathname + (u.search || '')).slice(0, 80);
        if (!_validDomain(host)) continue;
        rules.push(
          `alert http $HOME_NET any -> any any ` +
          `(msg:"TIHub ${safeLbl} malicious URL ${host}"; ` +
          `flow:established,to_server; ` +
          `http.host; content:"${host}"; nocase; ` +
          `http.uri; content:"${_safeStr(path)}"; nocase; ` +
          `classtype:trojan-activity; sid:${sid}; rev:1; ` +
          `metadata:created_at ${today},confidence ${ioc.confidence || 0},` +
          `source_feed ${(ioc.source || '').replace(/\s+/g, '_')},tihub true;)`
        );
        sid++;
        if (rules.length >= 600) break;
      } catch { continue; }
    }

    return rules;
  }

  // ── Toolbar ────────────────────────────────────────────────────────────────

  /** Build download toolbar. For IOC-capable types, exports actual IOCs. */
  function buildToolbar(items, type, label = '') {
    const bar  = document.createElement('div');
    bar.className = 'export-toolbar';
    const slug = (label || type).toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    const ts   = new Date().toISOString().slice(0, 10);

    const iocTypes = ['malware', 'actors', 'ransomware'];

    if (iocTypes.includes(type)) {
      const lbl = document.createElement('span');
      lbl.className = 'export-label';
      lbl.textContent = 'Export IOCs:';
      bar.appendChild(lbl);

      [
        { label: 'CSV',      fmt: 'csv'      },
        { label: 'JSON',     fmt: 'json'     },
        { label: 'YARA',     fmt: 'yara'     },
        { label: 'Suricata', fmt: 'suricata' },
      ].forEach(({ label: fmtLabel, fmt }) => {
        const btn = document.createElement('button');
        btn.className = 'btn btn-ghost btn-sm';
        btn.innerHTML = _dlIcon() + fmtLabel;
        btn.addEventListener('click', () => {
          const iocs = collectIOCs(type, items);
          if (!iocs.length) {
            _flashBtn(btn, 'No IOCs yet', fmtLabel);
            return;
          }
          switch (fmt) {
            case 'csv':      toIOCcsv(iocs,              `tihub_ioc_${slug}_${ts}.csv`);   break;
            case 'json':     toIOCjson(iocs, label,      `tihub_ioc_${slug}_${ts}.json`);  break;
            case 'yara':     toIOCyara(iocs, label,      `tihub_ioc_${slug}_${ts}.yar`);   break;
            case 'suricata': toIOCSuricata(iocs, label,  `tihub_ioc_${slug}_${ts}.rules`); break;
          }
        });
        bar.appendChild(btn);
      });

    } else {
      // Victims / generic: metadata export
      const lbl = document.createElement('span');
      lbl.className = 'export-label';
      lbl.textContent = 'Export:';
      bar.appendChild(lbl);

      [{ label: 'CSV', fmt: 'csv' }, { label: 'JSON', fmt: 'json' }].forEach(({ label: fmtLabel, fmt }) => {
        const btn = document.createElement('button');
        btn.className = 'btn btn-ghost btn-sm';
        btn.innerHTML = _dlIcon() + fmtLabel;
        btn.addEventListener('click', () => {
          if (fmt === 'csv')  toCSV(items,  `tihub_${slug}_${ts}.csv`);
          if (fmt === 'json') toJSON(items, `tihub_${slug}_${ts}.json`);
        });
        bar.appendChild(btn);
      });
    }

    return bar;
  }

  // ── Legacy metadata export (victims) ──────────────────────────────────────

  function toCSV(items, filename = 'export.csv') {
    if (!items?.length) return;
    const cols = Object.keys(items[0]).filter(k => !Array.isArray(items[0][k]) && typeof items[0][k] !== 'object');
    const header = cols.join(',');
    const rows   = items.map(item => cols.map(k => _csvCell(item[k])).join(','));
    _download([header, ...rows].join('\r\n'), filename, 'text/csv;charset=utf-8');
  }

  function toJSON(items, filename = 'export.json') {
    _download(JSON.stringify(items, null, 2), filename, 'application/json');
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function _validIP(val) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(val || '');
  }

  function _validDomain(val) {
    return /^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$/.test(val || '') && !_validIP(val);
  }

  function _yaraName(str) {
    if (!str) return 'TIHub_Unknown';
    return 'TIHub_' + str.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^(\d)/, '_$1').slice(0, 80);
  }

  function _safeStr(str) {
    return String(str || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\x00-\x1f]/g, ' ');
  }

  function _csvCell(val) {
    if (val === null || val === undefined) return '';
    const str = Array.isArray(val) ? val.join('; ') : String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  }

  function _download(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename; a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function _dlIcon() {
    return `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12" style="margin-right:4px"><path d="M8 1v9M4 7l4 4 4-4M2 13h12"/></svg>`;
  }

  function _flashBtn(btn, msg, original) {
    btn.textContent = msg;
    setTimeout(() => { btn.innerHTML = _dlIcon() + original; }, 2000);
  }

  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.cssText = 'position:fixed;opacity:0;';
      document.body.appendChild(ta); ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    }
  }

  return {
    collectIOCs,
    toCSV, toJSON,
    toIOCcsv, toIOCjson, toIOCyara, toIOCSuricata,
    copyToClipboard,
    buildToolbar,
  };
})();

export default Export;
