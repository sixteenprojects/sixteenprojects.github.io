/**
 * detail.js — Slide-in detail panel for malware, actors, ransomware, victims.
 * Phase 2: basic info rendering. Phase 3 will add full tabbed content.
 */

import Security from '../security.js';

const DetailView = (() => {
  'use strict';

  let _panel    = null;
  let _titleEl  = null;
  let _badgeEl  = null;
  let _bodyEl   = null;
  let _closeBtn = null;
  let _isOpen   = false;

  function _getEls() {
    if (_panel) return;
    _panel    = document.getElementById('detail-panel');
    _titleEl  = document.getElementById('detail-panel-title');
    _badgeEl  = document.getElementById('detail-panel-badge');
    _bodyEl   = document.getElementById('detail-panel-body');
    _closeBtn = document.getElementById('detail-panel-close');
  }

  // ── Public ─────────────────────────────────────────────────────────────

  function open(type, item) {
    _getEls();
    if (!_panel || !item) return;

    _panel.hidden = false;
    _isOpen = true;
    requestAnimationFrame(() => _panel.classList.add('open'));

    _renderHeader(type, item);
    _renderBody(type, item);
  }

  function close() {
    _getEls();
    if (!_panel) return;
    _panel.classList.remove('open');
    _isOpen = false;
    setTimeout(() => { if (!_isOpen && _panel) _panel.hidden = true; }, 300);
  }

  function isOpen() { return _isOpen; }

  // ── Header ─────────────────────────────────────────────────────────────

  const _BADGE_CLASS = {
    malware:    'badge-blue',
    actor:      'badge-red',
    ransomware: 'badge-yellow',
    victim:     'badge-gray',
  };

  const _BADGE_LABEL = {
    malware:    'Malware',
    actor:      'Threat Actor',
    ransomware: 'Ransomware',
    victim:     'Victim',
  };

  function _renderHeader(type, item) {
    const label = _BADGE_LABEL[type] || type;
    const cls   = _BADGE_CLASS[type] || 'badge-gray';

    if (_badgeEl) {
      _badgeEl.className = `badge ${cls}`;
      Security.setText(_badgeEl, label);
    }
    if (_titleEl) {
      Security.setText(_titleEl, item.name || item.victim || item.id || 'Unknown');
    }
  }

  // ── Body dispatch ──────────────────────────────────────────────────────

  function _renderBody(type, item) {
    if (!_bodyEl) return;
    _bodyEl.innerHTML = '';

    switch (type) {
      case 'malware':    _renderMalware(item); break;
      case 'actor':      _renderActor(item);   break;
      case 'ransomware': _renderRansomware(item); break;
      case 'victim':     _renderVictim(item);  break;
      default:           _renderGeneric(item); break;
    }
  }

  // ── Malware detail ─────────────────────────────────────────────────────

  function _renderMalware(item) {
    const rows = [
      { label: 'ID',          value: item.id },
      { label: 'Type',        value: item.type },
      { label: 'Platform',    value: (item.platform || []).join(', ') || '—' },
      { label: 'Aliases',     value: (item.aliases || []).join(', ') || '—' },
      { label: 'Actors',      value: (item.actors || []).join(', ') || '—' },
      { label: 'Updated',     value: Security.formatDate(item.updated) },
    ];
    _bodyEl.appendChild(_infoGrid(rows));
    if (item.description) _bodyEl.appendChild(_descBlock(item.description));
    if (item.references?.length) _bodyEl.appendChild(_refList(item.references));
    _bodyEl.appendChild(_phaseNote('Full malware detail — yara rules, actor links, IOC export — coming in Phase 3'));
  }

  // ── Actor detail ────────────────────────────────────────────────────────

  function _renderActor(item) {
    const rows = [
      { label: 'ID',        value: item.id },
      { label: 'Country',   value: item.country_iso || item.country || '—' },
      { label: 'Aliases',   value: (item.aliases || []).join(', ') || '—' },
      { label: 'Malware',   value: (item.malware || []).length + ' families' },
      { label: 'Updated',   value: Security.formatDate(item.updated) },
    ];
    _bodyEl.appendChild(_infoGrid(rows));
    if (item.description) _bodyEl.appendChild(_descBlock(item.description));
    if (item.references?.length) _bodyEl.appendChild(_refList(item.references));
    _bodyEl.appendChild(_phaseNote('Full actor profile — TTP matrix, associated malware, victim list — coming in Phase 3'));
  }

  // ── Ransomware detail ───────────────────────────────────────────────────

  function _renderRansomware(item) {
    const rows = [
      { label: 'Status',      value: item.status || '—' },
      { label: 'First Seen',  value: Security.formatDate(item.first_seen) || '—' },
      { label: 'Victims',     value: (item.victim_count || 0).toLocaleString() },
      { label: 'RaaS',        value: item.is_raas ? 'Yes' : 'No' },
      { label: 'Tools',       value: (item.tools || []).slice(0, 5).join(', ') || '—' },
      { label: 'TTPs',        value: (item.ttps || []).length + ' techniques' },
    ];
    _bodyEl.appendChild(_infoGrid(rows));
    if (item.description) _bodyEl.appendChild(_descBlock(item.description));
    if (item.locations?.length) _bodyEl.appendChild(_locList(item.locations));
    _bodyEl.appendChild(_phaseNote('Full ransomware profile — MITRE TTPs, victim list, location history — coming in Phase 4'));
  }

  // ── Victim detail ────────────────────────────────────────────────────────

  function _renderVictim(item) {
    const rows = [
      { label: 'Domain',     value: item.domain || '—' },
      { label: 'Group',      value: item.group  || '—' },
      { label: 'Country',    value: item.country || '—' },
      { label: 'Sector',     value: item.sector || '—' },
      { label: 'Attack',     value: Security.formatDate(item.attack_date) || '—' },
      { label: 'Discovered', value: Security.formatDate(item.discovered)  || '—' },
      { label: 'Source',     value: item.source || '—' },
    ];
    _bodyEl.appendChild(_infoGrid(rows));
    if (item.description) _bodyEl.appendChild(_descBlock(item.description));
    if (item.claim_url) {
      const row = document.createElement('div');
      row.style.cssText = 'padding:12px 20px;';
      const a = document.createElement('a');
      a.className = 'btn btn-ghost btn-sm';
      a.href = Security.sanitizeUrl(item.claim_url) || '#';
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'View claim page ↗';
      row.appendChild(a);
      _bodyEl.appendChild(row);
    }
  }

  // ── Generic fallback ─────────────────────────────────────────────────────

  function _renderGeneric(item) {
    const rows = Object.entries(item)
      .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
      .slice(0, 10)
      .map(([k, v]) => ({ label: k, value: String(v) }));
    _bodyEl.appendChild(_infoGrid(rows));
  }

  // ── Shared sub-components ─────────────────────────────────────────────

  function _infoGrid(rows) {
    const grid = document.createElement('dl');
    grid.className = 'detail-info-grid';
    for (const { label, value } of rows) {
      const dt = document.createElement('dt');
      Security.setText(dt, label);
      const dd = document.createElement('dd');
      Security.setText(dd, String(value || '—'));
      grid.appendChild(dt);
      grid.appendChild(dd);
    }
    return grid;
  }

  function _descBlock(text) {
    const wrap = document.createElement('div');
    wrap.className = 'detail-desc';
    const h = document.createElement('h4');
    h.textContent = 'Description';
    const p = document.createElement('p');
    Security.setText(p, Security.truncate(text, 800));
    wrap.appendChild(h);
    wrap.appendChild(p);
    return wrap;
  }

  function _refList(refs) {
    const wrap = document.createElement('div');
    wrap.className = 'detail-refs';
    const h = document.createElement('h4');
    h.textContent = 'References';
    wrap.appendChild(h);
    const ul = document.createElement('ul');
    for (const ref of refs.slice(0, 8)) {
      const li = document.createElement('li');
      const url = typeof ref === 'string' ? ref : (ref.url || ref.link || '');
      if (!url) continue;
      const safeUrl = Security.sanitizeUrl(url);
      if (!safeUrl) continue;
      li.innerHTML = `<a href="${Security.escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer" class="ref-link">${Security.escapeHtml(Security.truncate(safeUrl, 60))}</a>`;
      ul.appendChild(li);
    }
    wrap.appendChild(ul);
    return wrap;
  }

  function _locList(locations) {
    const wrap = document.createElement('div');
    wrap.className = 'detail-refs';
    const h = document.createElement('h4');
    h.textContent = 'Known Locations';
    wrap.appendChild(h);
    const ul = document.createElement('ul');
    for (const loc of locations.slice(0, 5)) {
      const li = document.createElement('li');
      const url = loc.url || loc.fqdn || '';
      const avail = loc.available ? '🟢' : '🔴';
      li.textContent = `${avail} ${Security.truncate(url, 60)}`;
      ul.appendChild(li);
    }
    wrap.appendChild(ul);
    return wrap;
  }

  function _phaseNote(msg) {
    const note = document.createElement('div');
    note.className = 'detail-phase-note';
    note.textContent = `ℹ ${msg}`;
    return note;
  }

  return { open, close, isOpen };
})();

export default DetailView;
