/**
 * export.js — Export utilities: CSV, JSON, YARA rules, Suricata rules.
 * Accepts raw data arrays and a type descriptor.
 * All exports trigger browser download via Blob + anchor.
 */

import Security from './security.js';

const Export = (() => {
  'use strict';

  // ── Public API ─────────────────────────────────────────────────────────

  /** Download an array of objects as CSV */
  function toCSV(items, filename = 'export.csv') {
    if (!items?.length) return;
    const cols = Object.keys(items[0]).filter(k => !Array.isArray(items[0][k]) && typeof items[0][k] !== 'object');
    const header = cols.join(',');
    const rows = items.map(item =>
      cols.map(k => _csvCell(item[k])).join(',')
    );
    _download([header, ...rows].join('\r\n'), filename, 'text/csv;charset=utf-8');
  }

  /** Download data as JSON */
  function toJSON(items, filename = 'export.json') {
    _download(JSON.stringify(items, null, 2), filename, 'application/json');
  }

  /**
   * Generate YARA rules from malware data.
   * Creates one rule per malware family using available metadata.
   * items: array of malware objects from malware.json
   */
  function toYARA(items, filename = 'tihub_export.yar') {
    if (!items?.length) return;
    const rules = items.map(item => _buildYARARule(item)).filter(Boolean);
    if (!rules.length) return;
    const header = _yaraHeader(items.length);
    _download(header + rules.join('\n\n'), filename, 'text/plain');
  }

  /**
   * Generate Suricata rules from malware/victim data.
   * Creates alert rules using known domain indicators.
   * items: array of victim or malware objects
   */
  function toSuricata(items, filename = 'tihub_export.rules') {
    if (!items?.length) return;
    const rules = _buildSuricataRules(items);
    if (!rules.length) return;
    const header = `# TI-Hub Suricata Rules\n# Generated: ${new Date().toISOString()}\n# Count: ${rules.length}\n\n`;
    _download(header + rules.join('\n'), filename, 'text/plain');
  }

  /** Copy text to clipboard */
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fallback for older browsers
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    }
  }

  /** Build a download toolbar element (returns a DOM element) */
  function buildToolbar(items, type, label = '') {
    const bar = document.createElement('div');
    bar.className = 'export-toolbar';

    const lbl = document.createElement('span');
    lbl.className = 'export-label';
    lbl.textContent = 'Export:';
    bar.appendChild(lbl);

    const formats = _getFormats(type);

    formats.forEach(fmt => {
      const btn = document.createElement('button');
      btn.className = 'btn btn-ghost btn-sm';
      btn.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12"><path d="M8 1v9M4 7l4 4 4-4M2 13h12"/></svg> ${fmt.label}`;
      btn.addEventListener('click', () => _handleExport(fmt.format, items, label || type));
      bar.appendChild(btn);
    });

    return bar;
  }

  // ── Format dispatch ────────────────────────────────────────────────────

  function _getFormats(type) {
    const base = [
      { label: 'CSV',  format: 'csv'  },
      { label: 'JSON', format: 'json' },
    ];
    if (type === 'malware') {
      return [...base, { label: 'YARA', format: 'yara' }];
    }
    if (type === 'victims') {
      return [...base, { label: 'Suricata', format: 'suricata' }];
    }
    if (type === 'ransomware') {
      return [...base, { label: 'YARA', format: 'yara' }, { label: 'Suricata', format: 'suricata' }];
    }
    return base;
  }

  function _handleExport(format, items, name) {
    const slug = name.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    const ts   = new Date().toISOString().slice(0, 10);
    switch (format) {
      case 'csv':      toCSV(items,     `tihub_${slug}_${ts}.csv`);  break;
      case 'json':     toJSON(items,    `tihub_${slug}_${ts}.json`); break;
      case 'yara':     toYARA(items,    `tihub_${slug}_${ts}.yar`);  break;
      case 'suricata': toSuricata(items,`tihub_${slug}_${ts}.rules`);break;
    }
  }

  // ── YARA generation ────────────────────────────────────────────────────

  function _buildYARARule(item) {
    const name = _yaraName(item.name || item.id);
    if (!name) return null;

    const aliases  = (item.aliases || []).map(a => `"${_safeStr(a)}"`).slice(0, 5);
    const strLines = aliases.length
      ? aliases.map((a, i) => `        $alias${i} = ${a} nocase ascii wide`).join('\n')
      : `        $name = "${_safeStr(item.name || item.id)}" nocase ascii wide`;

    const condition = aliases.length
      ? `any of ($alias*)`
      : `$name`;

    const meta = [
      `        description = "${_safeStr(Security.truncate(item.description || '', 200))}"`,
      `        malware_type = "${_safeStr(item.type || 'unknown')}"`,
      `        platform = "${_safeStr((item.platform || []).join(','))}"`,
      `        uuid = "${_safeStr(item.uuid || '')}"`,
      `        source = "TI-Hub/Malpedia"`,
      `        date = "${new Date().toISOString().slice(0,10)}"`,
    ].join('\n');

    return [
      `rule ${name} {`,
      `    meta:`,
      meta,
      `    strings:`,
      strLines,
      `    condition:`,
      `        ${condition}`,
      `}`,
    ].join('\n');
  }

  function _yaraName(str) {
    if (!str) return '';
    return 'TIHub_' + str.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&').slice(0, 100);
  }

  function _safeStr(str) {
    return String(str || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\x00-\x1f]/g, ' ');
  }

  function _yaraHeader(count) {
    return [
      `/*`,
      ` * TI-Hub YARA Rules`,
      ` * Generated: ${new Date().toISOString()}`,
      ` * Rules: ${count}`,
      ` * Source: Malpedia via The Sixteen Project TI-Hub`,
      ` * WARNING: These are detection signatures based on name/alias strings.`,
      ` *          Review and tune before production deployment.`,
      ` */`,
      '',
    ].join('\n');
  }

  // ── Suricata generation ────────────────────────────────────────────────

  function _buildSuricataRules(items) {
    const rules  = [];
    let   sid    = 9100001;
    const today  = new Date().toISOString().slice(0,10).replace(/-/g, '');

    for (const item of items) {
      const domain = item.domain || item.url || '';
      if (!domain) continue;

      const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
      if (!cleanDomain || !/^[a-zA-Z0-9._-]+$/.test(cleanDomain)) continue;

      const name = Security.truncate((item.victim || item.name || item.group || ''), 40)
        .replace(/[^a-zA-Z0-9_. -]/g, '_');
      const group = (item.group || 'ransomware').replace(/[^a-zA-Z0-9_]/g, '_');

      rules.push(
        `alert dns $HOME_NET any -> any 53 (msg:"TIHub ${group} domain ${cleanDomain}"; ` +
        `dns.query; content:"${cleanDomain}"; nocase; ` +
        `classtype:trojan-activity; sid:${sid}; rev:1; metadata:created_at ${today}, tihub true;)`
      );
      sid++;

      if (rules.length >= 500) break;
    }

    return rules;
  }

  // ── CSV helpers ────────────────────────────────────────────────────────

  function _csvCell(val) {
    if (val === null || val === undefined) return '';
    const str = Array.isArray(val) ? val.join('; ') : String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  }

  // ── Download helper ────────────────────────────────────────────────────

  function _download(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  return { toCSV, toJSON, toYARA, toSuricata, copyToClipboard, buildToolbar };
})();

export default Export;
