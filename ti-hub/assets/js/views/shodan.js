/**
 * shodan.js — Shodan Internet Exposure Intelligence dashboard.
 * Indonesia-focused: top products, OS, CVEs, critical ports, org exposure.
 * All data sourced from free Shodan /host/count facet queries (zero credits).
 */

import Security from '../security.js';

const ShodanView = (() => {
  'use strict';

  const RISK = n =>
    n > 100000 ? { color: '#ef4444', label: 'Critical', bg: '#ef444422' } :
    n > 10000  ? { color: '#f59e0b', label: 'High',     bg: '#f59e0b22' } :
    n > 1000   ? { color: '#3b82f6', label: 'Medium',   bg: '#3b82f622' } :
    n > 0      ? { color: '#22c55e', label: 'Low',       bg: '#22c55e22' } :
                 { color: '#6b7280', label: 'None',      bg: '#6b728022' };

  function render(container, data) {
    const shodan    = data.shodan    || {};
    const landscape = shodan.landscape || {};
    const indo      = landscape.indonesia      || {};
    const indoVuln  = landscape.indonesia_vuln || {};
    const indoPorts = landscape.indonesia_ports || {};
    const global_   = landscape.global         || {};
    const globalVuln= landscape.global_vuln    || {};
    const cveExp    = shodan.cve_exposure       || {};

    container.innerHTML = '';

    // ── Page header ──────────────────────────────────────────────────────────
    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Shodan Exposure Intelligence</h1>
          <p class="page-subtitle">
            Internet-facing systems · Vulnerability exposure · Critical risk radar
            ${landscape.updated ? `<span style="opacity:.6">· ${landscape.updated.slice(0,10)}</span>` : ''}
          </p>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <span class="badge badge-yellow" style="font-size:11px;">⬡ Shodan</span>
          ${indo.total ? `<span class="badge badge-red" style="font-size:11px;">${_fmt(indo.total)} ID hosts</span>` : ''}
          ${indoVuln.total ? `<span class="badge badge-orange" style="font-size:11px;">⚠ ${_fmt(indoVuln.total)} vulnerable</span>` : ''}
        </div>
      </div>`;
    container.appendChild(hdr);

    if (!indo.total && !Object.keys(indoPorts).length) {
      container.appendChild(_emptyState());
      return;
    }

    // ── Indonesia KPI hero ───────────────────────────────────────────────────
    container.appendChild(_buildKPIs(indo, indoVuln, indoPorts));

    // ── Critical port risk matrix ─────────────────────────────────────────────
    container.appendChild(_buildPortMatrix(indoPorts, indo.total || 0));

    // ── Products + OS ────────────────────────────────────────────────────────
    const row1 = _el('div', 'grid-2');
    row1.style.marginBottom = 'var(--space-4)';
    row1.appendChild(_buildRankList('Top Products — Indonesia', (indo.facets || {}).product || [], '#f59e0b', 'software & services exposed to internet'));
    row1.appendChild(_buildRankList('Top OS Distribution — Indonesia', (indo.facets || {}).os || [], '#3b82f6', 'operating systems of internet-facing hosts'));
    container.appendChild(row1);

    // ── CVEs Indonesia (facet) + CISA KEV (global count) ─────────────────────
    const indoCVEFacets = (indoVuln.facets || {}).vuln || [];
    const row2 = _el('div', 'grid-2');
    row2.style.marginBottom = 'var(--space-4)';
    row2.appendChild(_buildCVEFacets('Top CVEs by Exposure — Indonesia', indoCVEFacets));
    row2.appendChild(_buildCVEKev(cveExp));
    container.appendChild(row2);

    // ── Orgs + ASNs ──────────────────────────────────────────────────────────
    const orgFacets = indo.facets || {};
    if ((orgFacets.org || []).length) {
      const row3 = _el('div', 'grid-2');
      row3.style.marginBottom = 'var(--space-4)';
      row3.appendChild(_buildRankList('Top Organizations Exposed — Indonesia', orgFacets.org || [], '#7c3aed', 'organizations with most internet-facing hosts'));
      row3.appendChild(_buildRankList('Top ASNs — Indonesia', orgFacets.asn || [], '#0891b2', 'autonomous systems by exposure count'));
      container.appendChild(row3);
    }

    // ── Vulnerable products Indonesia ─────────────────────────────────────────
    const vulnProds = (indoVuln.facets || {}).product || [];
    if (vulnProds.length) {
      container.appendChild(_buildRankList(
        'Vulnerable Products — Indonesia (hosts with known CVEs)',
        vulnProds, '#ef4444',
        'products running on hosts with at least one unpatched CVE'
      ));
    }

    // ── Indonesia vs Global comparison ────────────────────────────────────────
    const globalProds = (global_.facets || {}).product || [];
    const indoProds   = (indo.facets   || {}).product || [];
    if (globalProds.length && indoProds.length) {
      container.appendChild(_buildComparison(indoProds, globalProds));
    }

    // ── Country ranking (where Indonesia sits globally) ───────────────────────
    const countries = (global_.facets || {}).country || [];
    if (countries.length) {
      container.appendChild(_buildCountryRank(countries));
    }

    // ── Attribution ───────────────────────────────────────────────────────────
    const footer = _el('div');
    footer.style.cssText = 'text-align:center;padding:20px;font-size:10px;color:var(--text-muted);border-top:1px solid var(--border-color);margin-top:8px;line-height:1.6;';
    footer.innerHTML = `
      Data via <a href="https://www.shodan.io" target="_blank" rel="noopener noreferrer" style="color:#f59e0b;text-decoration:none;font-weight:600;">Shodan</a>
      · <code>/host/count</code> facet queries — <strong>zero query credits consumed</strong>
      · CISA Known Exploited Vulnerabilities catalog for KEV data<br>
      <span style="opacity:.7;">All queries use <code>country:id</code> filter for Indonesia-specific data</span>`;
    container.appendChild(footer);
  }

  // ── KPI Hero strip ────────────────────────────────────────────────────────

  function _buildKPIs(indo, indoVuln, ports) {
    const wrap = _el('div');
    wrap.style.marginBottom = 'var(--space-4)';

    const section = _el('div');
    section.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:12px;';
    section.innerHTML = `
      <div style="width:3px;height:18px;background:#ef4444;border-radius:2px;flex-shrink:0;"></div>
      <span style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;">Indonesia Internet Exposure Snapshot</span>`;
    wrap.appendChild(section);

    const total = indo.total || 0;
    const vuln  = indoVuln.total || 0;
    const db    = (ports.mysql||0)+(ports.mssql||0)+(ports.mongo||0)+(ports.redis||0)+(ports.elastic||0);

    const cards = [
      { icon: '🌐', label: 'Total Exposed', value: _fmt(total),          sub: 'internet-facing systems in ID',    color: '#3b82f6' },
      { icon: '🔴', label: 'Vulnerable Hosts', value: _fmt(vuln),        sub: `${total?((vuln/total)*100).toFixed(1):0}% of total exposed`, color: '#ef4444' },
      { icon: '🖥️', label: 'RDP Exposed',    value: _fmt(ports.rdp||0),  sub: 'port 3389 — ransomware vector',   color: RISK(ports.rdp||0).color },
      { icon: '🗄️', label: 'DB Internet',    value: _fmt(db),            sub: 'MySQL/MSSQL/Mongo/Redis/Elastic',  color: RISK(db).color },
      { icon: '📁', label: 'SMB Exposed',     value: _fmt(ports.smb||0),  sub: 'port 445 — WannaCry vector',      color: RISK(ports.smb||0).color },
      { icon: '⚡', label: 'ICS / SCADA',     value: _fmt(ports.ics||0),  sub: 'industrial control systems',       color: RISK(ports.ics||0).color },
      { icon: '📟', label: 'Telnet Open',     value: _fmt(ports.telnet||0),sub: 'port 23 — plaintext protocol',   color: RISK(ports.telnet||0).color },
      { icon: '🔒', label: 'SSH Exposed',     value: _fmt(ports.ssh||0),  sub: 'port 22 — brute force target',    color: RISK(ports.ssh||0).color },
    ];

    const grid = _el('div');
    grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;';

    for (const c of cards) {
      const card = _el('div');
      card.style.cssText = `
        padding:14px 16px;background:var(--bg-surface);border:1px solid var(--border-color);
        border-radius:var(--radius-lg);border-left:3px solid ${c.color};
        display:flex;flex-direction:column;gap:4px;`;
      card.innerHTML = `
        <div style="font-size:16px;">${c.icon}</div>
        <div style="font-size:20px;font-weight:800;color:${c.color};font-variant-numeric:tabular-nums;line-height:1;">${Security.escapeHtml(c.value)}</div>
        <div style="font-size:11px;font-weight:600;color:var(--text-primary);">${Security.escapeHtml(c.label)}</div>
        <div style="font-size:10px;color:var(--text-muted);line-height:1.3;">${Security.escapeHtml(c.sub)}</div>`;
      grid.appendChild(card);
    }
    wrap.appendChild(grid);
    return wrap;
  }

  // ── Port risk matrix ──────────────────────────────────────────────────────

  function _buildPortMatrix(ports, totalHosts) {
    const wrap = _sectionCard('Critical Port Risk Matrix — Indonesia', '⚠');
    const body = wrap.querySelector('.section-card-body');

    const defs = [
      { key:'rdp',     port:'3389',     label:'RDP',           desc:'Remote Desktop Protocol — primary ransomware delivery path, brute force target' },
      { key:'smb',     port:'445',      label:'SMB',           desc:'File sharing — EternalBlue / WannaCry / NotPetya lateral movement vector' },
      { key:'telnet',  port:'23',       label:'Telnet',        desc:'Cleartext remote access — credentials transmitted in plaintext, IoT botnet infection' },
      { key:'ftp',     port:'21',       label:'FTP',           desc:'File transfer — credential sniffing, bounce attack, data exfiltration channel' },
      { key:'mysql',   port:'3306',     label:'MySQL',         desc:'Database — unauthenticated access, SQL injection to RCE, data breach risk' },
      { key:'mongo',   port:'27017',    label:'MongoDB',       desc:'NoSQL database — frequently exposed without auth, major ransomware target' },
      { key:'redis',   port:'6379',     label:'Redis',         desc:'In-memory cache — no default auth, SSH key injection, cryptomining deployment' },
      { key:'elastic', port:'9200',     label:'Elasticsearch', desc:'Search engine — open index data leakage, mass breach vector for medical/financial data' },
      { key:'mssql',   port:'1433',     label:'MSSQL',         desc:'SQL Server — brute force, sa account exploitation, xp_cmdshell RCE' },
      { key:'ics',     port:'502/102+', label:'ICS / SCADA',   desc:'Industrial control systems — Modbus, S7, DNP3 — critical infrastructure at risk' },
      { key:'ssh',     port:'22',       label:'SSH',           desc:'Secure Shell — brute force, weak key exploitation, supply chain pivot point' },
      { key:'http',    port:'80/8080',  label:'HTTP',          desc:'Unencrypted web — credential interception, malicious injection, phishing hosting' },
    ];

    const grid = _el('div');
    grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px;';

    for (const d of defs) {
      const count = ports[d.key] || 0;
      const risk  = RISK(count);
      const pct   = totalHosts ? Math.min((count / totalHosts) * 100, 100) : 0;

      const row = _el('div');
      row.style.cssText = `
        display:flex;align-items:flex-start;gap:10px;padding:10px 12px;
        background:var(--bg-surface-2);border-radius:8px;
        border-left:3px solid ${risk.color};`;

      const leftCol = _el('div');
      leftCol.style.cssText = 'min-width:78px;flex-shrink:0;';
      leftCol.innerHTML = `
        <div style="font-size:12px;font-weight:700;color:var(--text-primary);">${Security.escapeHtml(d.label)}</div>
        <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">:${Security.escapeHtml(d.port)}</div>`;

      const rightCol = _el('div');
      rightCol.style.cssText = 'flex:1;min-width:0;';
      rightCol.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <span style="font-size:14px;font-weight:800;color:${risk.color};font-variant-numeric:tabular-nums;">${_fmt(count)}</span>
          <span style="font-size:9px;font-weight:700;padding:1px 5px;background:${risk.bg};color:${risk.color};border-radius:3px;letter-spacing:.04em;">${risk.label.toUpperCase()}</span>
        </div>
        <div style="height:4px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;margin-bottom:5px;">
          <div style="height:100%;width:${pct.toFixed(1)}%;background:${risk.color};opacity:.8;border-radius:2px;"></div>
        </div>
        <div style="font-size:10px;color:var(--text-muted);line-height:1.4;">${Security.escapeHtml(d.desc)}</div>`;

      row.appendChild(leftCol);
      row.appendChild(rightCol);
      grid.appendChild(row);
    }
    body.appendChild(grid);
    return wrap;
  }

  // ── Generic ranked list ───────────────────────────────────────────────────

  function _buildRankList(title, items, color, subtitle) {
    const wrap = _sectionCard(title, '▸');
    const body = wrap.querySelector('.section-card-body');

    if (subtitle) {
      const sub = _el('div');
      sub.style.cssText = 'font-size:10px;color:var(--text-muted);margin-bottom:10px;font-style:italic;';
      sub.textContent = subtitle;
      body.appendChild(sub);
    }

    if (!items.length) {
      body.innerHTML += '<p class="text-muted" style="padding:8px 0;">No data yet — run workflow with Shodan enabled.</p>';
      return wrap;
    }

    const max = items[0]?.count || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    items.slice(0, 20).forEach((item, i) => {
      const pct = (item.count / max * 100).toFixed(1);
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary);"
              title="${Security.escapeHtml(item.value||'')}">${Security.escapeHtml(Security.truncate(item.value||'Unknown',34))}</span>
        <div style="width:80px;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${pct}%;background:${color};opacity:.75;border-radius:2px;transition:width .4s;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:54px;text-align:right;color:var(--text-primary);font-variant-numeric:tabular-nums;">${_fmt(item.count)}</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── CVE facets (from Shodan query vuln:* country:id) ─────────────────────

  function _buildCVEFacets(title, items) {
    const wrap = _sectionCard(title, '🔥');
    const body = wrap.querySelector('.section-card-body');

    if (!items.length) {
      body.innerHTML = '<p class="text-muted" style="padding:8px 0;">No CVE facet data yet — run Shodan fetch.</p>';
      return wrap;
    }

    const max = items[0]?.count || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    items.slice(0, 20).forEach((item, i) => {
      const cve   = item.value || '';
      const count = item.count || 0;
      const risk  = RISK(count);
      const pct   = (count / max * 100).toFixed(1);

      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <a href="https://nvd.nist.gov/vuln/detail/${Security.escapeHtml(cve)}" target="_blank" rel="noopener noreferrer"
           style="font-family:var(--font-mono);font-size:11px;font-weight:700;min-width:136px;color:${risk.color};text-decoration:none;"
           title="View on NVD">${Security.escapeHtml(cve)}</a>
        <div style="flex:1;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${risk.color};opacity:.7;border-radius:2px;transition:width .4s;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:52px;text-align:right;color:${risk.color};font-variant-numeric:tabular-nums;">${_fmt(count)}</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);

    const note = _el('div');
    note.style.cssText = 'margin-top:8px;font-size:10px;color:var(--text-muted);';
    note.textContent = 'Source: Shodan vuln:* country:id — systems with at least one unpatched CVE in Indonesia';
    body.appendChild(note);
    return wrap;
  }

  // ── CISA KEV global count ─────────────────────────────────────────────────

  function _buildCVEKev(cveExp) {
    const wrap = _sectionCard('CISA Known Exploited Vulnerabilities — Global Exposure', '🛡');
    const body = wrap.querySelector('.section-card-body');

    const sorted = Object.entries(cveExp)
      .filter(([, c]) => c > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20);

    if (!sorted.length) {
      body.innerHTML = '<p class="text-muted" style="padding:8px 0;">No CISA KEV data yet — run Shodan fetch (--cve-only).</p>';
      return wrap;
    }

    const max = sorted[0][1] || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    sorted.forEach(([cve, count], i) => {
      const risk = RISK(count);
      const pct  = (count / max * 100).toFixed(1);
      const row  = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <a href="https://nvd.nist.gov/vuln/detail/${Security.escapeHtml(cve)}" target="_blank" rel="noopener noreferrer"
           style="font-family:var(--font-mono);font-size:11px;font-weight:700;min-width:136px;color:${risk.color};text-decoration:none;">${Security.escapeHtml(cve)}</a>
        <div style="flex:1;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${risk.color};opacity:.7;border-radius:2px;transition:width .4s;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:52px;text-align:right;color:${risk.color};font-variant-numeric:tabular-nums;">${_fmt(count)}</span>
        <span style="font-size:10px;color:var(--text-muted);min-width:36px;">systems</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);

    const note = _el('div');
    note.style.cssText = 'margin-top:8px;font-size:10px;color:var(--text-muted);';
    note.textContent = 'Source: Shodan /host/count per CISA KEV CVE — global internet-facing systems with unpatched known exploited vuln';
    body.appendChild(note);
    return wrap;
  }

  // ── Indonesia vs Global product comparison ────────────────────────────────

  function _buildComparison(indoProds, globalProds) {
    const wrap = _sectionCard('Product Exposure: Indonesia vs Global Rank', '⟺');
    const body = wrap.querySelector('.section-card-body');

    const globalRank = {};
    globalProds.forEach((p, i) => { globalRank[p.value] = i + 1; });
    const maxIndo = indoProds[0]?.count || 1;

    const hdrRow = _el('div');
    hdrRow.style.cssText = 'display:grid;grid-template-columns:22px 1fr 80px 50px 70px;gap:8px;padding:0 0 6px;font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border-color);margin-bottom:8px;';
    hdrRow.innerHTML = '<span>#</span><span>Product</span><span style="text-align:right">ID Count</span><span style="text-align:center">ID Rank</span><span style="text-align:center">Global Rank</span>';
    body.appendChild(hdrRow);

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    indoProds.slice(0, 20).forEach((item, i) => {
      const gRank = globalRank[item.value];
      const diff  = gRank ? (gRank - (i + 1)) : null;
      const dColor = diff === null ? '#6b7280' : diff > 0 ? '#ef4444' : diff < 0 ? '#22c55e' : '#6b7280';
      const dText  = diff === null ? '—' : diff > 0 ? `▲${diff}` : diff < 0 ? `▼${Math.abs(diff)}` : '=';
      const pct    = (item.count / maxIndo * 100).toFixed(1);

      const row = _el('div');
      row.style.cssText = 'display:grid;grid-template-columns:22px 1fr 80px 50px 70px;gap:8px;align-items:center;';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);font-weight:700;text-align:right;">${i+1}</span>
        <div>
          <div style="font-size:11px;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
               title="${Security.escapeHtml(item.value||'')}">${Security.escapeHtml(Security.truncate(item.value||'Unknown',30))}</div>
          <div style="height:3px;background:var(--bg-surface-3);border-radius:1px;margin-top:3px;overflow:hidden;">
            <div style="height:100%;width:${pct}%;background:#f59e0b;opacity:.7;border-radius:1px;"></div>
          </div>
        </div>
        <span style="font-size:11px;font-weight:700;color:var(--text-primary);text-align:right;font-variant-numeric:tabular-nums;">${_fmt(item.count)}</span>
        <span style="font-size:11px;font-weight:700;text-align:center;color:var(--text-muted);">#${i+1}</span>
        <span style="font-size:11px;font-weight:700;text-align:center;color:${dColor};">${gRank?`#${gRank}`:'—'} <span style="font-size:9px;">${dText}</span></span>`;
      list.appendChild(row);
    });
    body.appendChild(list);

    const note = _el('div');
    note.style.cssText = 'margin-top:10px;font-size:10px;color:var(--text-muted);';
    note.textContent = '▲ = ranked higher globally than in Indonesia  ▼ = ranked lower globally  Red = more prominent in ID relative to global';
    body.appendChild(note);
    return wrap;
  }

  // ── Where Indonesia ranks among countries ─────────────────────────────────

  function _buildCountryRank(countries) {
    const wrap = _sectionCard('Global Country Exposure Ranking', '🌏');
    const body = wrap.querySelector('.section-card-body');

    const idIdx = countries.findIndex(c => (c.value||'').toUpperCase() === 'ID');
    const max   = countries[0]?.count || 1;

    const hdr = _el('div');
    hdr.style.cssText = 'display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;';
    if (idIdx >= 0) {
      const idEntry = countries[idIdx];
      hdr.innerHTML = `
        <div style="padding:10px 16px;background:var(--bg-surface-2);border:2px solid #f59e0b;border-radius:8px;text-align:center;">
          <div style="font-size:24px;font-weight:800;color:#f59e0b;">#${idIdx+1}</div>
          <div style="font-size:10px;color:var(--text-muted);font-weight:600;">Indonesia Global Rank</div>
          <div style="font-size:12px;font-weight:700;color:var(--text-primary);margin-top:2px;">${_fmt(idEntry.count)} hosts</div>
        </div>
        <div style="font-size:12px;color:var(--text-secondary);max-width:320px;line-height:1.5;">
          Indonesia ranks <strong>#${idIdx+1}</strong> globally by number of internet-facing systems.
          ${idIdx < 10 ? '⚠ Top 10 exposure globally — high attack surface.' : ''}
        </div>`;
    }
    body.appendChild(hdr);

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';
    const COUNTRY_NAMES = {
      US:'United States',CN:'China',IN:'India',BR:'Brazil',DE:'Germany',RU:'Russia',
      JP:'Japan',GB:'United Kingdom',KR:'South Korea',FR:'France',ID:'Indonesia',
      VN:'Vietnam',AU:'Australia',CA:'Canada',IT:'Italy',NL:'Netherlands',
      TH:'Thailand',ES:'Spain',TR:'Turkey',SG:'Singapore',
    };

    countries.slice(0, 20).forEach((c, i) => {
      const isIndo = (c.value||'').toUpperCase() === 'ID';
      const pct    = (c.count / max * 100).toFixed(1);
      const name   = COUNTRY_NAMES[(c.value||'').toUpperCase()] || c.value || '?';
      const row    = _el('div');
      row.style.cssText = `display:flex;align-items:center;gap:8px;${isIndo?'background:var(--bg-surface-2);padding:4px 8px;border-radius:6px;border-left:3px solid #f59e0b;':''}`;
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <span style="font-size:10px;font-weight:800;font-family:var(--font-mono);min-width:24px;color:${isIndo?'#f59e0b':'var(--text-muted)'};">${Security.escapeHtml((c.value||'?').toUpperCase())}</span>
        <span style="font-size:11px;flex:1;color:${isIndo?'var(--text-primary)':'var(--text-secondary)'};">${Security.escapeHtml(name)}</span>
        <div style="width:100px;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${pct}%;background:${isIndo?'#f59e0b':'var(--color-danger)'};opacity:${isIndo?'1':'.6'};border-radius:2px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:52px;text-align:right;color:${isIndo?'#f59e0b':'var(--text-primary)'};font-variant-numeric:tabular-nums;">${_fmt(c.count)}</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── Empty state ───────────────────────────────────────────────────────────

  function _emptyState() {
    const wrap = _el('div');
    wrap.style.cssText = 'text-align:center;padding:80px 20px;color:var(--text-muted);';
    wrap.innerHTML = `
      <div style="font-size:52px;margin-bottom:16px;">📡</div>
      <h3 style="font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:8px;">No Shodan Data Yet</h3>
      <p style="font-size:13px;max-width:480px;margin:0 auto 12px;line-height:1.6;">
        Run the workflow with <code style="background:var(--bg-surface-2);padding:2px 6px;border-radius:4px;">with_shodan=true</code>
        to collect Indonesia and global internet exposure statistics.
      </p>
      <p style="font-size:11px;color:var(--text-muted);">
        All landscape queries use <strong>/host/count with facets</strong> — zero Shodan query credits consumed.<br>
        Data collected: top products, OS, ports, CVEs, organizations, ASNs per country.
      </p>`;
    return wrap;
  }

  // ── Shared helpers ─────────────────────────────────────────────────────────

  function _fmt(n) {
    if (!n && n !== 0) return '—';
    if (n >= 1000000) return `${(n/1000000).toFixed(1)}M`;
    if (n >= 1000)    return `${(n/1000).toFixed(1)}K`;
    return n.toLocaleString();
  }

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  function _sectionCard(title, icon) {
    const wrap = _el('div', 'section-card');
    wrap.style.marginBottom = 'var(--space-4)';
    const hdr  = _el('div', 'section-card-header');
    hdr.innerHTML = `<span class="section-card-title">
      <span style="margin-right:6px;">${icon}</span>${Security.escapeHtml(title)}
    </span>`;
    const body = _el('div', 'section-card-body');
    wrap.appendChild(hdr);
    wrap.appendChild(body);
    return wrap;
  }

  return { render };
})();

export default ShodanView;
