/**
 * detail.js — Slide-in detail panel for malware, actors, ransomware, victims.
 * Phase 6: cross-links + MITRE ATT&CK heatmap embedded in ransomware detail.
 */

import Security    from '../security.js';
import Export      from '../export.js';
import Api         from '../api.js';
import MitreMatrix from '../components/mitre.js';

const DetailView = (() => {
  'use strict';

  let _panel    = null;
  let _backdrop = null;
  let _titleEl  = null;
  let _badgeEl  = null;
  let _bodyEl   = null;
  let _isOpen   = false;

  function _getEls() {
    if (_panel) return;
    _panel    = document.getElementById('detail-panel');
    _backdrop = document.getElementById('detail-backdrop');
    _titleEl  = document.getElementById('detail-panel-title');
    _badgeEl  = document.getElementById('detail-panel-badge');
    _bodyEl   = document.getElementById('detail-panel-body');
    if (_backdrop) _backdrop.addEventListener('click', close);
  }

  // ── Public ─────────────────────────────────────────────────────────────

  function open(type, item) {
    _getEls();
    if (!_panel || !item) return;

    _panel.hidden = false;
    _isOpen = true;
    requestAnimationFrame(() => {
      _panel.classList.add('open');
      if (_backdrop) _backdrop.classList.add('visible');
    });

    _renderHeader(type, item);
    _renderBody(type, item);
  }

  function close() {
    _getEls();
    if (!_panel) return;
    _panel.classList.remove('open');
    if (_backdrop) _backdrop.classList.remove('visible');
    _isOpen = false;
    setTimeout(() => { if (!_isOpen && _panel) _panel.hidden = true; }, 300);
  }

  function isOpen() { return _isOpen; }

  // ── Header ─────────────────────────────────────────────────────────────

  const _BADGE_CLASS = {
    malware: 'badge-blue', actor: 'badge-red',
    ransomware: 'badge-yellow', victim: 'badge-gray',
  };
  const _BADGE_LABEL = {
    malware: 'Malware', actor: 'Threat Actor',
    ransomware: 'Ransomware', victim: 'Victim',
  };

  function _renderHeader(type, item) {
    const label = _BADGE_LABEL[type] || type;
    const cls   = _BADGE_CLASS[type] || 'badge-gray';
    if (_badgeEl) { _badgeEl.className = `badge ${cls}`; Security.setText(_badgeEl, label); }
    if (_titleEl) { Security.setText(_titleEl, item.name || item.victim || item.id || 'Unknown'); }
  }

  // ── Body dispatch ──────────────────────────────────────────────────────

  function _renderBody(type, item) {
    if (!_bodyEl) return;
    _bodyEl.innerHTML = '';
    switch (type) {
      case 'malware':    _renderMalware(item);    break;
      case 'actor':      _renderActor(item);      break;
      case 'ransomware': _renderRansomware(item); break;
      case 'victim':     _renderVictim(item);     break;
      default:           _renderGeneric(item);    break;
    }
  }

  // ── Malware detail ─────────────────────────────────────────────────────

  function _renderMalware(item) {
    _bodyEl.appendChild(_infoGrid([
      { label: 'ID',       value: item.id },
      { label: 'Type',     value: item.type },
      { label: 'Platform', value: (item.platform || []).join(', ') || '—' },
      { label: 'Aliases',  value: (item.aliases || []).join(', ') || '—' },
      { label: 'Updated',  value: Security.formatDate(item.updated) },
    ]));

    // Cross-link: clickable actors
    if ((item.actors || []).length) {
      const sec = _el('div', 'detail-refs');
      const h = _el('h4'); h.textContent = 'Associated Actors';
      const tags = _el('div', 'cell-tags');
      tags.style.cssText = 'padding:4px 0 8px;';
      for (const name of (item.actors || [])) {
        const chip = _crossChip(name, 'actor-chip');
        chip.addEventListener('click', () => _openRelated('actor', name));
        tags.appendChild(chip);
      }
      sec.appendChild(h);
      sec.appendChild(tags);
      _bodyEl.appendChild(sec);
    }

    if (item.description) _bodyEl.appendChild(_descBlock(item.description));
    if (item.references?.length) _bodyEl.appendChild(_refList(item.references));
    _bodyEl.appendChild(Export.buildToolbar([item], 'malware', item.name || item.id));
  }

  // ── Actor detail ────────────────────────────────────────────────────────

  function _renderActor(item) {
    _bodyEl.appendChild(_infoGrid([
      { label: 'ID',      value: item.id },
      { label: 'Country', value: item.country_iso || item.country || '—' },
      { label: 'Aliases', value: (item.aliases || []).join(', ') || '—' },
      { label: 'Updated', value: Security.formatDate(item.updated) },
    ]));

    // Cross-link: clickable malware families
    if ((item.malware || []).length) {
      const sec = _el('div', 'detail-refs');
      const h = _el('h4'); h.textContent = `Malware Families (${item.malware.length})`;
      const tags = _el('div', 'cell-tags');
      tags.style.cssText = 'padding:4px 0 8px;';
      for (const mId of (item.malware || []).slice(0, 30)) {
        const chip = _crossChip(mId, 'malware-chip');
        chip.addEventListener('click', () => _openRelated('malware', mId));
        tags.appendChild(chip);
      }
      if (item.malware.length > 30) {
        const more = _el('span', 'text-muted');
        more.style.fontSize = '11px';
        more.textContent = `+${item.malware.length - 30} more`;
        tags.appendChild(more);
      }
      sec.appendChild(h);
      sec.appendChild(tags);
      _bodyEl.appendChild(sec);
    }

    if (item.description) _bodyEl.appendChild(_descBlock(item.description));
    if (item.references?.length) _bodyEl.appendChild(_refList(item.references));
    _bodyEl.appendChild(Export.buildToolbar([item], 'actors', item.name || item.id));
  }

  // ── Ransomware detail ───────────────────────────────────────────────────

  function _renderRansomware(item) {
    const infoRows = [
      { label: 'Status',     value: item.status || '—' },
      { label: 'First Seen', value: Security.formatDate(item.first_seen) || '—' },
      { label: 'Victims',    value: (item.victim_count || 0).toLocaleString() },
      { label: 'RaaS',       value: item.is_raas ? 'Yes' : 'No' },
      { label: 'TTPs',       value: (item.ttps || []).length + ' techniques' },
    ];
    if (item.jabber)   infoRows.push({ label: 'Jabber',   value: item.jabber });
    if (item.mail)     infoRows.push({ label: 'Email',    value: item.mail });
    if (item.telegram) infoRows.push({ label: 'Telegram', value: item.telegram });
    _bodyEl.appendChild(_infoGrid(infoRows));

    if (item.description) _bodyEl.appendChild(_descBlock(item.description));

    // Affiliates
    const affiliates = item.affiliates || [];
    if (affiliates.length) {
      const sec = _el('div', 'detail-refs');
      const h = _el('h4'); h.textContent = `Affiliates / Partners (${affiliates.length})`;
      const tags = _el('div', 'cell-tags');
      tags.style.cssText = 'padding:4px 0 8px;';
      affiliates.slice(0, 20).forEach(a => {
        const chip = _el('span', 'badge badge-orange');
        chip.style.fontSize = '10px';
        chip.textContent = Security.truncate(String(a), 24);
        tags.appendChild(chip);
      });
      sec.appendChild(h);
      sec.appendChild(tags);
      _bodyEl.appendChild(sec);
    }

    // Tools (structured by category if object, or flat list)
    const tools = item.tools || [];
    if (tools.length) {
      const sec = _el('div', 'detail-refs');
      const h = _el('h4'); h.textContent = 'Tools Used';
      const tags = _el('div', 'cell-tags');
      tags.style.cssText = 'padding:4px 0 8px;';
      const toolList = typeof tools === 'object' && !Array.isArray(tools)
        ? Object.values(tools).flat()
        : tools;
      toolList.slice(0, 25).forEach(t => {
        const chip = _el('span', 'badge badge-gray');
        chip.style.fontSize = '10px';
        chip.textContent = Security.truncate(String(t), 20);
        tags.appendChild(chip);
      });
      sec.appendChild(h);
      sec.appendChild(tags);
      _bodyEl.appendChild(sec);
    }

    // MITRE ATT&CK heatmap
    if ((item.ttps || []).length) {
      const sec = _el('div', 'mitre-detail-section');
      const h = _el('h4'); h.textContent = 'MITRE ATT&CK TTPs';
      sec.appendChild(h);
      MitreMatrix.renderForGroup(sec, item.ttps);
      _bodyEl.appendChild(sec);
    }

    if (item.locations?.length) _bodyEl.appendChild(_locList(item.locations));

    // Cross-link: link to victims view filtered by group
    if (item.victim_count) {
      const row = _el('div');
      row.style.cssText = 'padding:8px 20px;';
      const btn = _el('button', 'btn btn-ghost btn-sm');
      btn.textContent = `View ${item.victim_count} victim${item.victim_count !== 1 ? 's' : ''} →`;
      btn.addEventListener('click', () => {
        close();
        window.location.hash = '/victims';
      });
      row.appendChild(btn);
      _bodyEl.appendChild(row);
    }

    _bodyEl.appendChild(Export.buildToolbar([item], 'ransomware', item.name || item.id));
  }

  // ── Victim detail ────────────────────────────────────────────────────────

  function _renderVictim(item) {
    const rows = [
      { label: 'Domain',     value: item.domain || '—' },
      { label: 'Country',    value: item.country || '—' },
      { label: 'Sector',     value: item.sector || '—' },
      { label: 'Attack',     value: Security.formatDate(item.attack_date) || '—' },
      { label: 'Discovered', value: Security.formatDate(item.discovered)  || '—' },
    ];
    if (item.data_size) rows.push({ label: 'Data Size', value: String(item.data_size) });
    if (item.ransom)    rows.push({ label: 'Ransom',    value: String(item.ransom) });
    rows.push({ label: 'Source', value: item.source || '—' });
    _bodyEl.appendChild(_infoGrid(rows));

    // Cross-link: clickable group name
    if (item.group) {
      const row = _el('div');
      row.style.cssText = 'padding:0 20px 12px;display:flex;align-items:center;gap:8px;';
      const lbl = _el('span', 'filter-label'); lbl.textContent = 'Group:';
      const chip = _crossChip(item.group, 'ransomware-chip');
      chip.addEventListener('click', () => _openRelated('ransomware', item.group));
      row.appendChild(lbl);
      row.appendChild(chip);
      _bodyEl.appendChild(row);
    }

    if (item.description) _bodyEl.appendChild(_descBlock(item.description));

    // Infostealer data block
    const is = item.infostealer || {};
    const stealers = is.stealers || {};
    if (typeof stealers === 'object' && Object.keys(stealers).length) {
      const block = _el('div', 'detail-desc');
      block.innerHTML = `<h4>Infostealer Data</h4>`;
      const info = _el('div');
      info.style.cssText = 'display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-secondary);';
      if (is.employees) info.innerHTML += `<span>Employees exposed: <strong>${Number(is.employees).toLocaleString()}</strong></span>`;
      if (is.users)     info.innerHTML += `<span>Users exposed: <strong>${Number(is.users).toLocaleString()}</strong></span>`;
      const stealerList = Object.entries(stealers).map(([k, v]) => `${k} (${v})`).join(', ');
      info.innerHTML += `<span>Stealers: <strong>${Security.escapeHtml(stealerList)}</strong></span>`;
      block.appendChild(info);
      _bodyEl.appendChild(block);
    }

    // Links row
    const linksRow = _el('div');
    linksRow.style.cssText = 'padding:8px 20px;display:flex;gap:8px;flex-wrap:wrap;';
    if (item.claim_url) {
      const a = _el('a', 'btn btn-ghost btn-sm');
      a.href = Security.sanitizeUrl(item.claim_url) || '#';
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.textContent = 'Claim ↗';
      linksRow.appendChild(a);
    }
    if (item.url) {
      const a = _el('a', 'btn btn-ghost btn-sm');
      a.href = Security.sanitizeUrl(item.url) || '#';
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.textContent = 'Original post ↗';
      linksRow.appendChild(a);
    }
    if (item.press) {
      const a = _el('a', 'btn btn-ghost btn-sm');
      a.href = Security.sanitizeUrl(item.press) || '#';
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.textContent = 'Press coverage ↗';
      linksRow.appendChild(a);
    }
    if (linksRow.children.length) _bodyEl.appendChild(linksRow);

    _bodyEl.appendChild(Export.buildToolbar([item], 'victims', item.victim || item.id));
  }

  // ── Generic fallback ─────────────────────────────────────────────────────

  function _renderGeneric(item) {
    const rows = Object.entries(item)
      .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
      .slice(0, 10)
      .map(([k, v]) => ({ label: k, value: String(v) }));
    _bodyEl.appendChild(_infoGrid(rows));
  }

  // ── Cross-link helpers ─────────────────────────────────────────────────

  function _crossChip(label, extraCls = '') {
    const chip = _el('span', `badge badge-blue cross-link-chip ${extraCls}`);
    chip.textContent = Security.truncate(label, 28);
    chip.title = label;
    chip.style.cursor = 'pointer';
    return chip;
  }

  function _openRelated(type, nameOrId) {
    const data = Api.getAll();
    let item = null;

    if (type === 'actor') {
      item = (data.actors || []).find(a =>
        a.id === nameOrId || a.name === nameOrId ||
        (a.aliases || []).includes(nameOrId));
    } else if (type === 'malware') {
      item = (data.malware || []).find(m =>
        m.id === nameOrId || m.name === nameOrId ||
        (m.aliases || []).includes(nameOrId));
    } else if (type === 'ransomware') {
      item = (data.ransomware || []).find(r =>
        r.id === nameOrId || r.name === nameOrId);
    }

    if (item) open(type, item);
  }

  // ── Shared sub-components ─────────────────────────────────────────────

  function _infoGrid(rows) {
    const grid = _el('dl', 'detail-info-grid');
    for (const { label, value } of rows) {
      const dt = _el('dt'); Security.setText(dt, label);
      const dd = _el('dd'); Security.setText(dd, String(value || '—'));
      grid.appendChild(dt);
      grid.appendChild(dd);
    }
    return grid;
  }

  function _descBlock(text) {
    const wrap = _el('div', 'detail-desc');
    const h = _el('h4'); h.textContent = 'Description';
    const p = _el('p'); Security.setText(p, Security.truncate(text, 800));
    wrap.appendChild(h);
    wrap.appendChild(p);
    return wrap;
  }

  function _refList(refs) {
    const wrap = _el('div', 'detail-refs');
    const h = _el('h4'); h.textContent = 'References';
    const ul = _el('ul');
    for (const ref of refs.slice(0, 8)) {
      const url = typeof ref === 'string' ? ref : (ref.url || ref.link || '');
      if (!url) continue;
      const safeUrl = Security.sanitizeUrl(url);
      if (!safeUrl) continue;
      const li = _el('li');
      li.innerHTML = `<a href="${Security.escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer" class="ref-link">${Security.escapeHtml(Security.truncate(safeUrl, 60))}</a>`;
      ul.appendChild(li);
    }
    wrap.appendChild(h);
    wrap.appendChild(ul);
    return wrap;
  }

  function _locList(locations) {
    const wrap = _el('div', 'detail-refs');
    const h = _el('h4'); h.textContent = 'Known Locations';
    const ul = _el('ul');
    for (const loc of locations.slice(0, 5)) {
      const li = _el('li');
      const url = loc.url || loc.fqdn || '';
      const avail = loc.available ? '🟢' : '🔴';
      li.textContent = `${avail} ${Security.truncate(url, 60)}`;
      ul.appendChild(li);
    }
    wrap.appendChild(h);
    wrap.appendChild(ul);
    return wrap;
  }

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  return { open, close, isOpen };
})();

export default DetailView;
