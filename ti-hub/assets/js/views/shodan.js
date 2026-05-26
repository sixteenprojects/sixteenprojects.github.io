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

  // ── Port threat intelligence database ────────────────────────────────────
  const PORT_THREATS = {
    rdp:     { malware:['Ryuk','Conti','REvil','Dharma','LockBit'], cves:['CVE-2019-0708 BlueKeep','CVE-2019-1181 DejaBlue','CVE-2022-21990'], vectors:['Credential brute force','BlueKeep exploit (no auth RCE)','Pass-the-hash / NTLM relay','Credential stuffing from dark web leaks'], mitre:['T1021.001 Remote Services: RDP','T1110 Brute Force','T1078 Valid Accounts'], advice:'Disable public exposure. Require VPN + MFA. Restrict to IP allowlist. Enable NLA.' },
    smb:     { malware:['WannaCry','NotPetya','Petya','Emotet','Conti'], cves:['CVE-2017-0144 EternalBlue/WannaCry','CVE-2021-1675 PrintNightmare','CVE-2020-0796 SMBGhost'], vectors:['EternalBlue MS17-010 exploit','NTLM relay attacks','Lateral movement pivoting','PrintNightmare privilege escalation'], mitre:['T1021.002 SMB/Windows Admin Shares','T1570 Lateral Tool Transfer','T1110 Brute Force'], advice:'Block port 445 at perimeter. Disable SMBv1. Apply MS17-010 patch. Disable NTLM relay.' },
    telnet:  { malware:['Mirai','Mozi','Gafgyt','BotenaGo','Hajime'], cves:['CVE-2023-1389 TP-Link RCE','CVE-2018-10562 Dasan GPON'], vectors:['Default credential exploitation','Cleartext credential sniffing','IoT botnet recruitment for DDoS'], mitre:['T1110 Brute Force','T1040 Network Sniffing'], advice:'Disable entirely — replace with SSH. Change all default IoT credentials.' },
    ftp:     { malware:['DarkSide','APT28','Banking trojans'], cves:['CVE-2010-4221 ProFTPD buffer overflow'], vectors:['Anonymous login exploitation','Credential brute force','FTP bounce attack','Data exfiltration channel'], mitre:['T1071.002 File Transfer Protocols','T1020 Automated Exfiltration','T1110 Brute Force'], advice:'Disable anonymous login. Upgrade to SFTP/FTPS. Restrict access by IP allowlist.' },
    mysql:   { malware:['Ransomware groups','Cryptominers','Data stealers'], cves:['CVE-2023-21912','CVE-2012-2122 auth bypass'], vectors:['Unauthenticated root access','SQL injection to RCE','Credential brute force','Mass data exfiltration'], mitre:['T1190 Exploit Public-Facing Application','T1005 Data from Local System'], advice:'Never expose to internet. Bind to 127.0.0.1. Use DB proxy. Apply strict user privileges.' },
    mongo:   { malware:['Meow ransomware','R2R2','Cryptominers','Data extortionists'], cves:['CVE-2021-32030','CVE-2019-2392'], vectors:['No default auth (old versions)','Database wipe + ransom demand','Data dump and dark web sale'], mitre:['T1190 Exploit Public-Facing Application','T1485 Data Destruction'], advice:'Enable authentication. Bind to localhost. Never expose without auth + TLS.' },
    redis:   { malware:['Kinsing cryptominer','TeamTNT','Hildegard'], cves:['CVE-2022-0543 Lua sandbox escape','CVE-2023-28856'], vectors:['No default auth → SSH key injection','Cron job injection for persistence','Cryptomining deployment via CONFIG SET'], mitre:['T1190 Exploit Public-Facing','T1053 Scheduled Task','T1098 Account Manipulation'], advice:'Set requirepass. Bind to localhost. Rename/disable CONFIG, FLUSHALL commands.' },
    elastic: { malware:['Ransomware groups','Nation-state APTs','Data harvesters'], cves:['CVE-2015-1427 Groovy sandbox bypass'], vectors:['Open index data exfiltration','No default auth (old versions)','Medical/financial records breach','Ransom + destroy attacks'], mitre:['T1530 Data from Cloud Storage','T1485 Data Destruction'], advice:'Enable X-Pack security. Firewall restrict. Never expose without auth + TLS.' },
    mssql:   { malware:['Cl0p','LockBit','Various RATs'], cves:['CVE-2022-35840','CVE-2023-21566','CVE-2021-1636'], vectors:['SA account brute force','xp_cmdshell OS command execution','Linked server privilege escalation'], mitre:['T1190 Exploit Public-Facing','T1059 Command and Scripting Interpreter'], advice:'Disable SA account. Disable xp_cmdshell. Use Windows Auth. Restrict network access.' },
    ics:     { malware:['TRITON/TRISIS','Industroyer','BlackEnergy','Sandworm'], cves:['CVE-2022-34151 Mitsubishi MELSEC','CVE-2021-33012 Modicon'], vectors:['No authentication in Modbus/DNP3 protocols','Direct industrial equipment control','Physical damage potential (power, water)'], mitre:['T0855 Unauthorized Command Message','T0829 Loss of View','T0884 Connection Proxy'], advice:'CRITICAL: Air-gap from internet. Use data diodes. Deploy ICS-specific IDS (Dragos/Claroty).' },
    ssh:     { malware:['Various APTs','Cryptominers','Botnets'], cves:['CVE-2023-38408 OpenSSH agent','CVE-2023-25136 OpenSSH pre-auth'], vectors:['Password brute force','Weak key exploitation','Supply chain credential leak','Backdoored SSH configs'], mitre:['T1021.004 SSH','T1110 Brute Force','T1098.004 SSH Authorized Keys'], advice:'Disable password auth. Use key-only. Use Fail2ban. Restrict to VPN/allowlist.' },
    http:    { malware:['Web shells','DDoS botnets','SEO spam'], cves:['Multiple web framework CVEs','CMS vulnerabilities'], vectors:['Credential interception (MITM)','Malicious JS injection','Phishing page hosting','Web shell deployment'], mitre:['T1071.001 Web Protocols','T1189 Drive-by Compromise'], advice:'Force redirect to HTTPS. Enable HSTS. Keep web software patched.' },
  };

  // ── Slide-in detail panel ────────────────────────────────────────────────
  let _panel = null;

  function _initPanel() {
    if (_panel) return _panel;
    _panel = document.createElement('div');
    _panel.style.cssText = [
      'position:fixed;top:0;right:0;height:100vh;width:440px;max-width:92vw;',
      'background:var(--bg-surface);border-left:1px solid var(--border-color);',
      'box-shadow:-8px 0 32px rgba(0,0,0,.25);z-index:1000;overflow-y:auto;',
      'transform:translateX(100%);transition:transform .25s ease;display:flex;flex-direction:column;',
    ].join('');
    _panel.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;padding:16px 20px;
                  border-bottom:1px solid var(--border-color);position:sticky;top:0;
                  background:var(--bg-surface);z-index:1;flex-shrink:0;">
        <div id="sdp-title" style="font-size:13px;font-weight:700;color:var(--text-primary);flex:1;margin-right:8px;line-height:1.4;"></div>
        <button id="sdp-close" style="background:none;border:none;cursor:pointer;color:var(--text-muted);font-size:22px;padding:0 4px;line-height:1;flex-shrink:0;" aria-label="Close">×</button>
      </div>
      <div id="sdp-body" style="padding:16px 20px;font-size:13px;"></div>`;
    document.body.appendChild(_panel);
    document.getElementById('sdp-close').addEventListener('click', _hidePanel);
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && _panel.style.transform !== 'translateX(100%)') _hidePanel();
    });
    return _panel;
  }

  function _showPanel(title, html) {
    const p = _initPanel();
    document.getElementById('sdp-title').textContent = title;
    document.getElementById('sdp-body').innerHTML = html;
    p.style.transform = 'translateX(0%)';
    p.scrollTop = 0;
  }

  function _hidePanel() {
    if (_panel) _panel.style.transform = 'translateX(100%)';
  }

  function _shodanUrl(q) {
    return `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;
  }

  // ── Detail content: port ──────────────────────────────────────────────────
  function _portDetailHtml(def, count, pct) {
    const t    = PORT_THREATS[def.key] || {};
    const risk = RISK(count);
    const q    = `country:id port:${def.port.split('/')[0]}`;

    const malwareChips = (t.malware || []).map(m =>
      `<span style="display:inline-block;background:#ef444418;border:1px solid #ef444440;border-radius:4px;padding:1px 7px;font-size:11px;color:#ef4444;margin:2px;">${Security.escapeHtml(m)}</span>`
    ).join('');

    const cveChips = (t.cves || []).map(c =>
      `<span style="display:inline-block;background:#f59e0b18;border:1px solid #f59e0b40;border-radius:4px;padding:1px 7px;font-size:11px;color:#f59e0b;margin:2px;">${Security.escapeHtml(c)}</span>`
    ).join('');

    const vectors = (t.vectors || []).map(v =>
      `<li style="margin-bottom:5px;">${Security.escapeHtml(v)}</li>`
    ).join('');

    const mitre = (t.mitre || []).map(m =>
      `<li style="margin-bottom:3px;font-size:11px;font-family:var(--font-mono);">${Security.escapeHtml(m)}</li>`
    ).join('');

    return `
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:16px;">
        <div style="font-size:30px;font-weight:900;color:${risk.color};font-variant-numeric:tabular-nums;">${_fmt(count)}</div>
        <div>
          <span style="font-size:11px;font-weight:700;padding:2px 8px;background:${risk.bg};color:${risk.color};border-radius:4px;">${risk.label}</span>
          <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">${pct.toFixed(2)}% of Indonesian internet-facing hosts</div>
        </div>
      </div>
      <a href="${_shodanUrl(q)}" target="_blank" rel="noopener noreferrer"
         style="display:block;background:#f59e0b;color:#000;text-align:center;padding:9px;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;margin-bottom:16px;">
        🔍 Search on Shodan · <code style="font-size:11px;">${Security.escapeHtml(q)}</code>
      </a>
      ${malwareChips ? `<div style="margin-bottom:14px;"><div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Known Malware / Threat Actors</div><div>${malwareChips}</div></div>` : ''}
      <div style="margin-bottom:14px;">
        <div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Attack Vectors</div>
        <ul style="margin:0;padding-left:18px;color:var(--text-secondary);line-height:1.6;">${vectors}</ul>
      </div>
      ${cveChips ? `<div style="margin-bottom:14px;"><div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Key CVEs</div><div>${cveChips}</div></div>` : ''}
      ${mitre ? `<div style="margin-bottom:14px;"><div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">MITRE ATT&amp;CK</div><ul style="margin:0;padding-left:18px;color:var(--text-secondary);">${mitre}</ul></div>` : ''}
      <div style="background:var(--bg-surface-2);border:1px solid var(--border-color);border-radius:8px;padding:12px;">
        <div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Mitigation</div>
        <div style="font-size:12px;color:var(--text-secondary);line-height:1.5;">${Security.escapeHtml(t.advice || 'Review and restrict access.')}</div>
      </div>`;
  }

  // ── Detail content: generic rank item ─────────────────────────────────────
  function _rankDetailHtml(type, value, count, rank, extraHtml) {
    const QUERIES = {
      product:  `country:id product:"${value}"`,
      os:       `country:id os:"${value}"`,
      org:      `country:id org:"${value}"`,
      asn:      `asn:${value}`,
      country:  `country:${value}`,
      vuln_id:  `vuln:${value} country:id`,
    };
    const q    = QUERIES[type] || `country:id "${value}"`;
    const risk = RISK(count);

    return `
      <div style="font-size:28px;font-weight:900;color:${risk.color};margin-bottom:4px;font-variant-numeric:tabular-nums;">${_fmt(count)}</div>
      ${rank > 0 ? `<div style="font-size:11px;color:var(--text-muted);margin-bottom:16px;">Rank #${rank} · ${risk.label} exposure level</div>` : `<div style="font-size:11px;color:var(--text-muted);margin-bottom:16px;">Exposure level: ${risk.label}</div>`}
      <a href="${_shodanUrl(q)}" target="_blank" rel="noopener noreferrer"
         style="display:block;background:#f59e0b;color:#000;text-align:center;padding:9px;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;margin-bottom:16px;">
        🔍 Search on Shodan · <code style="font-size:11px;">${Security.escapeHtml(q)}</code>
      </a>
      ${extraHtml || ''}
      <div style="margin-top:12px;padding:10px;background:var(--bg-surface-2);border-radius:6px;font-size:11px;color:var(--text-muted);">
        Click the Shodan link to see individual hosts, banners, open ports, and detailed scan data.
      </div>`;
  }

  // ── Detail content: CVE ───────────────────────────────────────────────────
  function _cveDetailHtml(cve, count, isKev) {
    const risk     = RISK(count);
    const nvdUrl   = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
    const qGlobal  = `vuln:${cve}`;
    const qIndo    = `vuln:${cve} country:id`;

    return `
      <div style="font-family:var(--font-mono);font-size:16px;font-weight:900;color:${risk.color};margin-bottom:8px;">${Security.escapeHtml(cve)}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px;">
        <span style="background:${risk.bg};color:${risk.color};font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;">${risk.label}</span>
        ${isKev ? '<span style="background:#ef444420;color:#ef4444;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;">⚠ CISA KEV</span>' : ''}
        <span style="background:var(--bg-surface-2);color:var(--text-muted);font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;">${_fmt(count)} systems</span>
      </div>
      <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer"
         style="display:block;background:var(--bg-surface-2);border:1px solid var(--border-color);color:var(--text-primary);text-align:center;padding:9px;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;margin-bottom:8px;">
        📋 View on NVD — National Vulnerability Database
      </a>
      <a href="${_shodanUrl(qGlobal)}" target="_blank" rel="noopener noreferrer"
         style="display:block;background:#f59e0b;color:#000;text-align:center;padding:9px;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;margin-bottom:8px;">
        🌐 Search Globally · <code style="font-size:11px;">${Security.escapeHtml(qGlobal)}</code>
      </a>
      <a href="${_shodanUrl(qIndo)}" target="_blank" rel="noopener noreferrer"
         style="display:block;background:var(--bg-surface-2);border:1px solid var(--border-color);color:var(--text-secondary);text-align:center;padding:9px;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;margin-bottom:16px;">
        🇮🇩 Search in Indonesia · <code style="font-size:11px;">${Security.escapeHtml(qIndo)}</code>
      </a>
      ${isKev ? `<div style="background:#ef444410;border:1px solid #ef444430;border-radius:8px;padding:12px;font-size:12px;color:var(--text-secondary);line-height:1.5;">
        <strong style="color:#ef4444;">CISA Known Exploited Vulnerability</strong><br>
        This CVE is actively exploited in the wild. CISA mandates federal agencies patch within 2 weeks of KEV listing. Treat as urgent.
      </div>` : ''}`;
  }

  // ── Main render ───────────────────────────────────────────────────────────
  function render(container, data) {
    _hidePanel();

    const shodan    = data.shodan     || {};
    const landscape = shodan.landscape || {};
    const indo      = landscape.indonesia      || {};
    const indoVuln  = landscape.indonesia_vuln || {};
    const indoPorts = landscape.indonesia_ports || {};
    const global_   = landscape.global          || {};
    const cveExp    = shodan.cve_exposure        || {};

    container.innerHTML = '';

    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Shodan Exposure Intelligence</h1>
          <p class="page-subtitle">Internet-facing systems · Vulnerability exposure · Critical risk radar
            ${landscape.updated ? `<span style="opacity:.6"> · ${landscape.updated.slice(0,10)}</span>` : ''}
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

    container.appendChild(_buildKPIs(indo, indoVuln, indoPorts));
    container.appendChild(_buildPortMatrix(indoPorts, indo.total || 0));

    const row1 = _el('div', 'grid-2');
    row1.style.marginBottom = 'var(--space-4)';
    row1.appendChild(_buildRankList('Top Products — Indonesia', (indo.facets||{}).product||[], '#f59e0b', 'product', 'software & services exposed to internet'));
    row1.appendChild(_buildRankList('Top OS Distribution — Indonesia', (indo.facets||{}).os||[], '#3b82f6', 'os', 'operating systems of internet-facing hosts'));
    container.appendChild(row1);

    const indoCVEFacets = (indoVuln.facets||{}).vuln || [];
    const row2 = _el('div', 'grid-2');
    row2.style.marginBottom = 'var(--space-4)';
    row2.appendChild(_buildCVEFacets('Top CVEs by Exposure — Indonesia', indoCVEFacets, cveExp));
    row2.appendChild(_buildCVEKev(cveExp));
    container.appendChild(row2);

    const orgFacets = indo.facets || {};
    if ((orgFacets.org||[]).length) {
      const row3 = _el('div', 'grid-2');
      row3.style.marginBottom = 'var(--space-4)';
      row3.appendChild(_buildRankList('Top Organizations Exposed — Indonesia', orgFacets.org||[], '#7c3aed', 'org', 'organizations with most internet-facing hosts'));
      row3.appendChild(_buildRankList('Top ASNs — Indonesia', orgFacets.asn||[], '#0891b2', 'asn', 'autonomous systems by exposure count'));
      container.appendChild(row3);
    }

    const vulnProds = (indoVuln.facets||{}).product || [];
    if (vulnProds.length) {
      container.appendChild(_buildRankList('Vulnerable Products — Indonesia', vulnProds, '#ef4444', 'product', 'products running on hosts with at least one unpatched CVE'));
    }

    const globalProds = (global_.facets||{}).product || [];
    const indoProds   = (indo.facets||{}).product   || [];
    if (globalProds.length && indoProds.length) {
      container.appendChild(_buildComparison(indoProds, globalProds));
    }

    const countries = (global_.facets||{}).country || [];
    if (countries.length) {
      container.appendChild(_buildCountryRank(countries));
    }

    const footer = _el('div');
    footer.style.cssText = 'text-align:center;padding:20px;font-size:10px;color:var(--text-muted);border-top:1px solid var(--border-color);margin-top:8px;line-height:1.6;';
    footer.innerHTML = `Data via <a href="https://www.shodan.io" target="_blank" rel="noopener noreferrer" style="color:#f59e0b;text-decoration:none;font-weight:600;">Shodan</a>
      &nbsp;·&nbsp;<code>/host/count</code> facet queries — <strong>zero query credits consumed</strong>
      &nbsp;·&nbsp;CISA KEV catalog<br>
      <span style="opacity:.7;">Click any port card, row, or CVE to see threat details and Shodan search links</span>`;
    container.appendChild(footer);
  }

  // ── KPI hero strip ────────────────────────────────────────────────────────
  function _buildKPIs(indo, indoVuln, ports) {
    const wrap = _el('div');
    wrap.style.marginBottom = 'var(--space-4)';

    const label = _el('div');
    label.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:12px;';
    label.innerHTML = `<div style="width:3px;height:18px;background:#ef4444;border-radius:2px;"></div>
      <span style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;">Indonesia Internet Exposure Snapshot</span>`;
    wrap.appendChild(label);

    const total = indo.total || 0;
    const vuln  = indoVuln.total || 0;
    const db    = (ports.mysql||0)+(ports.mssql||0)+(ports.mongo||0)+(ports.redis||0)+(ports.elastic||0);

    const portDefs = {
      rdp:    { key:'rdp',    port:'3389',     label:'RDP'    },
      smb:    { key:'smb',    port:'445',      label:'SMB'    },
      ics:    { key:'ics',    port:'502/102+', label:'ICS'    },
      telnet: { key:'telnet', port:'23',       label:'Telnet' },
      ssh:    { key:'ssh',    port:'22',       label:'SSH'    },
    };

    const dbBreakdown = `
      <div style="font-size:12px;color:var(--text-secondary);line-height:1.8;margin-bottom:12px;">
        <div><strong>MySQL (3306):</strong> ${_fmt(ports.mysql||0)}</div>
        <div><strong>MSSQL (1433):</strong> ${_fmt(ports.mssql||0)}</div>
        <div><strong>MongoDB (27017):</strong> ${_fmt(ports.mongo||0)}</div>
        <div><strong>Redis (6379):</strong> ${_fmt(ports.redis||0)}</div>
        <div><strong>Elasticsearch (9200):</strong> ${_fmt(ports.elastic||0)}</div>
      </div>
      <div style="padding:10px;background:var(--bg-surface-2);border-radius:6px;font-size:11px;color:var(--text-muted);">Database ports exposed to the internet represent critical data breach risk. Each should be firewalled from public access.</div>`;

    const cards = [
      { icon:'🌐', label:'Total Exposed',    value:_fmt(total),         sub:'internet-facing systems in ID',    color:'#3b82f6',
        action:() => _showPanel('Indonesia — All Internet-Facing Hosts', _rankDetailHtml('country','id',total,0,'')) },
      { icon:'🔴', label:'Vulnerable Hosts', value:_fmt(vuln),          sub:`${total?((vuln/total)*100).toFixed(1):0}% of total exposed`, color:'#ef4444',
        action:() => _showPanel('Vulnerable Hosts — Indonesia', _rankDetailHtml('vuln_id','*',vuln,0,'<div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Hosts with at least one unpatched CVE detected by Shodan scanner</div>')) },
      { icon:'🖥️', label:'RDP Exposed',     value:_fmt(ports.rdp||0),  sub:'port 3389 — ransomware vector',   color:RISK(ports.rdp||0).color,   portKey:'rdp'    },
      { icon:'🗄️', label:'DB Internet',     value:_fmt(db),            sub:'MySQL/MSSQL/Mongo/Redis/Elastic',  color:RISK(db).color,
        action:() => _showPanel('Database Ports Exposed — Indonesia', dbBreakdown) },
      { icon:'📁', label:'SMB Exposed',      value:_fmt(ports.smb||0),  sub:'port 445 — WannaCry vector',      color:RISK(ports.smb||0).color,   portKey:'smb'    },
      { icon:'⚡', label:'ICS / SCADA',      value:_fmt(ports.ics||0),  sub:'industrial control systems',       color:RISK(ports.ics||0).color,   portKey:'ics'    },
      { icon:'📟', label:'Telnet Open',      value:_fmt(ports.telnet||0),sub:'port 23 — plaintext protocol',   color:RISK(ports.telnet||0).color, portKey:'telnet' },
      { icon:'🔒', label:'SSH Exposed',      value:_fmt(ports.ssh||0),  sub:'port 22 — brute force target',    color:RISK(ports.ssh||0).color,   portKey:'ssh'    },
    ];

    const grid = _el('div');
    grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;';

    for (const c of cards) {
      const action = c.action || (c.portKey ? () => {
        const d   = portDefs[c.portKey];
        const cnt = ports[c.portKey] || 0;
        const pct = total ? (cnt / total) * 100 : 0;
        _showPanel(`${d.label} (Port ${d.port}) — Indonesia`, _portDetailHtml(d, cnt, pct));
      } : null);

      const card = _el('div');
      card.style.cssText = `padding:14px 16px;background:var(--bg-surface);border:1px solid var(--border-color);border-radius:var(--radius-lg);border-left:3px solid ${c.color};display:flex;flex-direction:column;gap:4px;${action ? 'cursor:pointer;transition:filter .15s;' : ''}`;
      card.innerHTML = `
        <div style="font-size:16px;">${c.icon}</div>
        <div style="font-size:20px;font-weight:800;color:${c.color};font-variant-numeric:tabular-nums;line-height:1;">${Security.escapeHtml(c.value)}</div>
        <div style="font-size:11px;font-weight:600;color:var(--text-primary);">${Security.escapeHtml(c.label)}</div>
        <div style="font-size:10px;color:var(--text-muted);line-height:1.3;">${Security.escapeHtml(c.sub)}</div>`;

      if (action) {
        card.addEventListener('click', action);
        card.addEventListener('mouseenter', () => { card.style.filter = 'brightness(1.06)'; });
        card.addEventListener('mouseleave', () => { card.style.filter = ''; });
        card.title = 'Click for threat details';
      }
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
      { key:'rdp',     port:'3389',     label:'RDP',           desc:'Remote Desktop Protocol — primary ransomware delivery path' },
      { key:'smb',     port:'445',      label:'SMB',           desc:'File sharing — EternalBlue / WannaCry / NotPetya vector' },
      { key:'telnet',  port:'23',       label:'Telnet',        desc:'Cleartext remote access — IoT botnet infection, credential sniffing' },
      { key:'ftp',     port:'21',       label:'FTP',           desc:'File transfer — credential sniffing, bounce attack, exfiltration' },
      { key:'mysql',   port:'3306',     label:'MySQL',         desc:'Database — unauthenticated access, mass data breach risk' },
      { key:'mongo',   port:'27017',    label:'MongoDB',       desc:'NoSQL — frequently exposed without auth, ransomware wipe target' },
      { key:'redis',   port:'6379',     label:'Redis',         desc:'In-memory cache — SSH key injection, cryptomining deployment' },
      { key:'elastic', port:'9200',     label:'Elasticsearch', desc:'Search engine — open data leakage, medical/financial breach' },
      { key:'mssql',   port:'1433',     label:'MSSQL',         desc:'SQL Server — sa account exploitation, xp_cmdshell RCE' },
      { key:'ics',     port:'502/102+', label:'ICS / SCADA',   desc:'Industrial control — Modbus, S7, DNP3 — critical infrastructure' },
      { key:'ssh',     port:'22',       label:'SSH',           desc:'Secure Shell — brute force, weak key exploitation' },
      { key:'http',    port:'80/8080',  label:'HTTP',          desc:'Unencrypted web — credential interception, malicious injection' },
    ];

    const grid = _el('div');
    grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px;';

    for (const d of defs) {
      const count = ports[d.key] || 0;
      const risk  = RISK(count);
      const pct   = totalHosts ? Math.min((count / totalHosts) * 100, 100) : 0;

      const row = _el('div');
      row.style.cssText = `display:flex;align-items:flex-start;gap:10px;padding:10px 12px;background:var(--bg-surface-2);border-radius:8px;border-left:3px solid ${risk.color};cursor:pointer;transition:filter .15s;`;
      row.title = 'Click for threat details';

      const leftCol = _el('div');
      leftCol.style.cssText = 'min-width:78px;flex-shrink:0;pointer-events:none;';
      leftCol.innerHTML = `
        <div style="font-size:12px;font-weight:700;color:var(--text-primary);">${Security.escapeHtml(d.label)}</div>
        <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">:${Security.escapeHtml(d.port)}</div>`;

      const rightCol = _el('div');
      rightCol.style.cssText = 'flex:1;min-width:0;pointer-events:none;';
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
      row.addEventListener('click', () => {
        const cnt = ports[d.key] || 0;
        const p   = totalHosts ? (cnt / totalHosts) * 100 : 0;
        _showPanel(`${d.label} (Port ${d.port}) — Indonesia`, _portDetailHtml(d, cnt, p));
      });
      row.addEventListener('mouseenter', () => { row.style.filter = 'brightness(1.06)'; });
      row.addEventListener('mouseleave', () => { row.style.filter = ''; });
      grid.appendChild(row);
    }
    body.appendChild(grid);
    return wrap;
  }

  // ── Generic ranked list ───────────────────────────────────────────────────
  function _buildRankList(title, items, color, type, subtitle) {
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

    const max  = items[0]?.count || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    items.slice(0, 20).forEach((item, i) => {
      const pct = (item.count / max * 100).toFixed(1);
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;cursor:pointer;border-radius:4px;padding:2px 4px;transition:background .1s;';
      row.title = 'Click for Shodan search';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary);"
              title="${Security.escapeHtml(item.value||'')}">${Security.escapeHtml(Security.truncate(item.value||'Unknown', 34))}</span>
        <div style="width:80px;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${pct}%;background:${color};opacity:.75;border-radius:2px;transition:width .4s;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:54px;text-align:right;color:var(--text-primary);font-variant-numeric:tabular-nums;">${_fmt(item.count)}</span>`;

      row.addEventListener('click', () => _showPanel(`${item.value || 'Unknown'} — Shodan`, _rankDetailHtml(type, item.value || '', item.count, i + 1, '')));
      row.addEventListener('mouseenter', () => { row.style.background = 'var(--bg-surface-2)'; });
      row.addEventListener('mouseleave', () => { row.style.background = ''; });
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── CVE facets list ───────────────────────────────────────────────────────
  function _buildCVEFacets(title, items, cveExp) {
    const wrap = _sectionCard(title, '🔥');
    const body = wrap.querySelector('.section-card-body');

    if (!items.length) {
      body.innerHTML = '<p class="text-muted" style="padding:8px 0;">No CVE facet data yet — run workflow with <code>with_shodan=true</code> to collect vulnerability data.</p>';
      return wrap;
    }

    const max  = items[0]?.count || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    items.slice(0, 20).forEach((item, i) => {
      const cve   = item.value || '';
      const count = item.count || 0;
      const risk  = RISK(count);
      const pct   = (count / max * 100).toFixed(1);
      const isKev = cve in cveExp;

      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;cursor:pointer;border-radius:4px;padding:2px 4px;transition:background .1s;';
      row.title = 'Click for CVE details and Shodan search';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <span style="font-family:var(--font-mono);font-size:11px;font-weight:700;min-width:136px;color:${risk.color};">${Security.escapeHtml(cve)}</span>
        ${isKev ? '<span style="font-size:9px;font-weight:700;color:#ef4444;flex-shrink:0;min-width:28px;">KEV</span>' : '<span style="min-width:28px;"></span>'}
        <div style="flex:1;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${risk.color};opacity:.7;border-radius:2px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:52px;text-align:right;color:${risk.color};font-variant-numeric:tabular-nums;">${_fmt(count)}</span>`;

      row.addEventListener('click', () => _showPanel(`${cve} — Vulnerability Detail`, _cveDetailHtml(cve, count, isKev)));
      row.addEventListener('mouseenter', () => { row.style.background = 'var(--bg-surface-2)'; });
      row.addEventListener('mouseleave', () => { row.style.background = ''; });
      list.appendChild(row);
    });
    body.appendChild(list);

    const note = _el('div');
    note.style.cssText = 'margin-top:8px;font-size:10px;color:var(--text-muted);';
    note.textContent = 'Source: Shodan vuln:* country:id  ·  KEV = CISA Known Exploited Vulnerability  ·  Click any row for details';
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

    const max  = sorted[0][1] || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    sorted.forEach(([cve, count], i) => {
      const risk = RISK(count);
      const pct  = (count / max * 100).toFixed(1);
      const row  = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;cursor:pointer;border-radius:4px;padding:2px 4px;transition:background .1s;';
      row.title = 'Click for CVE details and Shodan search';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <span style="font-family:var(--font-mono);font-size:11px;font-weight:700;min-width:136px;color:${risk.color};">${Security.escapeHtml(cve)}</span>
        <div style="flex:1;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${risk.color};opacity:.7;border-radius:2px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:52px;text-align:right;color:${risk.color};font-variant-numeric:tabular-nums;">${_fmt(count)}</span>
        <span style="font-size:10px;color:var(--text-muted);min-width:36px;">systems</span>`;

      row.addEventListener('click', () => _showPanel(`${cve} — CISA KEV`, _cveDetailHtml(cve, count, true)));
      row.addEventListener('mouseenter', () => { row.style.background = 'var(--bg-surface-2)'; });
      row.addEventListener('mouseleave', () => { row.style.background = ''; });
      list.appendChild(row);
    });
    body.appendChild(list);

    const note = _el('div');
    note.style.cssText = 'margin-top:8px;font-size:10px;color:var(--text-muted);';
    note.textContent = 'Source: Shodan /host/count per CISA KEV CVE — global internet-facing systems with unpatched known exploited vuln  ·  Click any row';
    body.appendChild(note);
    return wrap;
  }

  // ── Indonesia vs Global comparison ────────────────────────────────────────
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
      const gRank  = globalRank[item.value];
      const diff   = gRank ? (gRank - (i + 1)) : null;
      const dColor = diff === null ? '#6b7280' : diff > 0 ? '#ef4444' : diff < 0 ? '#22c55e' : '#6b7280';
      const dText  = diff === null ? '—' : diff > 0 ? `▲${diff}` : diff < 0 ? `▼${Math.abs(diff)}` : '=';
      const pct    = (item.count / maxIndo * 100).toFixed(1);

      const row = _el('div');
      row.style.cssText = 'display:grid;grid-template-columns:22px 1fr 80px 50px 70px;gap:8px;align-items:center;cursor:pointer;border-radius:4px;padding:2px 4px;transition:background .1s;';
      row.title = 'Click for Shodan search';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);font-weight:700;text-align:right;">${i+1}</span>
        <div>
          <div style="font-size:11px;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
               title="${Security.escapeHtml(item.value||'')}">${Security.escapeHtml(Security.truncate(item.value||'Unknown', 30))}</div>
          <div style="height:3px;background:var(--bg-surface-3);border-radius:1px;margin-top:3px;overflow:hidden;">
            <div style="height:100%;width:${pct}%;background:#f59e0b;opacity:.7;border-radius:1px;"></div>
          </div>
        </div>
        <span style="font-size:11px;font-weight:700;color:var(--text-primary);text-align:right;font-variant-numeric:tabular-nums;">${_fmt(item.count)}</span>
        <span style="font-size:11px;font-weight:700;text-align:center;color:var(--text-muted);">#${i+1}</span>
        <span style="font-size:11px;font-weight:700;text-align:center;color:${dColor};">${gRank ? `#${gRank}` : '—'} <span style="font-size:9px;">${dText}</span></span>`;

      row.addEventListener('click', () => {
        const extra = gRank
          ? `<div style="background:var(--bg-surface-2);border-radius:6px;padding:10px;margin-bottom:12px;font-size:12px;color:var(--text-secondary);">
               <strong>Indonesia rank:</strong> #${i+1} &nbsp;·&nbsp; <strong>Global rank:</strong> #${gRank}<br>
               Delta: <span style="color:${dColor};font-weight:700;">${dText}</span>
               ${diff > 0 ? ' — more prominent in Indonesia vs global' : diff < 0 ? ' — less prominent globally' : ''}
             </div>` : '';
        _showPanel(`${item.value || 'Unknown'} — Product Exposure`, _rankDetailHtml('product', item.value || '', item.count, i + 1, extra));
      });
      row.addEventListener('mouseenter', () => { row.style.background = 'var(--bg-surface-2)'; });
      row.addEventListener('mouseleave', () => { row.style.background = ''; });
      list.appendChild(row);
    });
    body.appendChild(list);

    const note = _el('div');
    note.style.cssText = 'margin-top:10px;font-size:10px;color:var(--text-muted);';
    note.textContent = '▲ = ranked higher globally than in Indonesia  ▼ = ranked lower globally  ·  Click any row for Shodan search';
    body.appendChild(note);
    return wrap;
  }

  // ── Country ranking ───────────────────────────────────────────────────────
  function _buildCountryRank(countries) {
    const wrap = _sectionCard('Global Country Exposure Ranking', '🌏');
    const body = wrap.querySelector('.section-card-body');

    const COUNTRY_NAMES = {
      US:'United States',CN:'China',IN:'India',BR:'Brazil',DE:'Germany',RU:'Russia',
      JP:'Japan',GB:'United Kingdom',KR:'South Korea',FR:'France',ID:'Indonesia',
      VN:'Vietnam',AU:'Australia',CA:'Canada',IT:'Italy',NL:'Netherlands',
      TH:'Thailand',ES:'Spain',TR:'Turkey',SG:'Singapore',PK:'Pakistan',
    };

    const idIdx = countries.findIndex(c => (c.value||'').toUpperCase() === 'ID');
    const max   = countries[0]?.count || 1;

    if (idIdx >= 0) {
      const idEntry = countries[idIdx];
      const hdr = _el('div');
      hdr.style.cssText = 'display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;';
      hdr.innerHTML = `
        <div style="padding:10px 16px;background:var(--bg-surface-2);border:2px solid #f59e0b;border-radius:8px;text-align:center;">
          <div style="font-size:24px;font-weight:800;color:#f59e0b;">#${idIdx+1}</div>
          <div style="font-size:10px;color:var(--text-muted);font-weight:600;">Indonesia Global Rank</div>
          <div style="font-size:12px;font-weight:700;color:var(--text-primary);margin-top:2px;">${_fmt(idEntry.count)} hosts</div>
        </div>
        <div style="font-size:12px;color:var(--text-secondary);max-width:300px;line-height:1.5;">
          Indonesia ranks <strong>#${idIdx+1}</strong> globally by number of internet-facing systems.
          ${idIdx < 10 ? '<br>⚠ <strong>Top 10 globally</strong> — very high attack surface.' : ''}
        </div>`;
      body.appendChild(hdr);
    }

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:5px;';

    countries.slice(0, 20).forEach((c, i) => {
      const isIndo = (c.value||'').toUpperCase() === 'ID';
      const code   = (c.value||'?').toUpperCase();
      const name   = COUNTRY_NAMES[code] || c.value || '?';
      const pct    = (c.count / max * 100).toFixed(1);

      const row = _el('div');
      row.style.cssText = `display:flex;align-items:center;gap:8px;cursor:pointer;border-radius:4px;padding:2px 4px;transition:background .1s;${isIndo ? 'background:var(--bg-surface-2);border-left:3px solid #f59e0b;padding-left:8px;' : ''}`;
      row.title = 'Click for Shodan search';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:20px;text-align:right;font-weight:700;">${i+1}</span>
        <span style="font-size:10px;font-weight:800;font-family:var(--font-mono);min-width:24px;color:${isIndo ? '#f59e0b' : 'var(--text-muted)'};">${Security.escapeHtml(code)}</span>
        <span style="font-size:11px;flex:1;color:${isIndo ? 'var(--text-primary)' : 'var(--text-secondary)'};">${Security.escapeHtml(name)}</span>
        <div style="width:100px;height:10px;background:var(--bg-surface-3);border-radius:2px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${pct}%;background:${isIndo ? '#f59e0b' : 'var(--color-danger)'};opacity:${isIndo ? '1' : '.6'};border-radius:2px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:52px;text-align:right;color:${isIndo ? '#f59e0b' : 'var(--text-primary)'};font-variant-numeric:tabular-nums;">${_fmt(c.count)}</span>`;

      row.addEventListener('click', () => _showPanel(`${name} (${code}) — Country Exposure`, _rankDetailHtml('country', code.toLowerCase(), c.count, i + 1, '')));
      row.addEventListener('mouseenter', () => { if (!isIndo) row.style.background = 'var(--bg-surface-2)'; });
      row.addEventListener('mouseleave', () => { if (!isIndo) row.style.background = ''; });
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
        All landscape queries use <strong>/host/count with facets</strong> — zero Shodan query credits consumed.
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
    hdr.innerHTML = `<span class="section-card-title"><span style="margin-right:6px;">${icon}</span>${Security.escapeHtml(title)}</span>`;
    const body = _el('div', 'section-card-body');
    wrap.appendChild(hdr);
    wrap.appendChild(body);
    return wrap;
  }

  return { render };
})();

export default ShodanView;
