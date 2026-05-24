/**
 * search.js — Global search across all TI-Hub datasets.
 * Searches malware, actors, ransomware groups, and victims.
 * Keyboard shortcut: Ctrl+K or type in sidebar search box.
 */

import Security from './security.js';

const Search = (() => {
  'use strict';

  const MAX_RESULTS = 50;
  const DEBOUNCE_MS = 180;

  let _data = { malware: [], actors: [], ransomware: [], victims: [] };
  let _overlay = null;
  let _resultsEl = null;
  let _searchInput = null;
  let _debounceTimer = null;
  let _activeIndex = -1;
  let _resultRows = [];

  // ── Public API ─────────────────────────────────────────────────────────

  function init(data) {
    _data = data || _data;
    _overlay     = document.getElementById('search-overlay');
    _resultsEl   = document.getElementById('search-results');
    _searchInput = document.getElementById('global-search');

    _bindInput();
    _bindOverlay();
    _bindGlobalShortcut();
  }

  function updateData(data) {
    _data = data || _data;
  }

  function open() {
    if (_searchInput) { _searchInput.focus(); _searchInput.select(); }
    if (_overlay) _overlay.hidden = false;
  }

  function close() {
    if (_overlay) _overlay.hidden = true;
    if (_searchInput) _searchInput.value = '';
    if (_resultsEl) _resultsEl.innerHTML = '';
    _activeIndex = -1;
    _resultRows = [];
  }

  // ── Input binding ──────────────────────────────────────────────────────

  function _bindInput() {
    if (!_searchInput) return;

    _searchInput.addEventListener('input', () => {
      clearTimeout(_debounceTimer);
      _debounceTimer = setTimeout(() => _performSearch(_searchInput.value), DEBOUNCE_MS);
    });

    _searchInput.addEventListener('keydown', e => {
      switch (e.key) {
        case 'Escape':   close(); break;
        case 'ArrowDown': e.preventDefault(); _moveActive(1); break;
        case 'ArrowUp':   e.preventDefault(); _moveActive(-1); break;
        case 'Enter':     e.preventDefault(); _activateSelected(); break;
      }
    });

    _searchInput.addEventListener('focus', () => {
      if ((_searchInput.value || '').trim().length >= 2 && _overlay) {
        _overlay.hidden = false;
      }
    });
  }

  function _bindOverlay() {
    if (!_overlay) return;
    _overlay.addEventListener('click', e => {
      if (e.target === _overlay) close();
    });
  }

  function _bindGlobalShortcut() {
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        open();
      }
    });
  }

  // ── Keyboard navigation ────────────────────────────────────────────────

  function _moveActive(delta) {
    if (!_resultRows.length) return;
    _resultRows[_activeIndex]?.classList.remove('active');
    _activeIndex = Math.max(0, Math.min(_resultRows.length - 1, _activeIndex + delta));
    const row = _resultRows[_activeIndex];
    if (row) {
      row.classList.add('active');
      row.scrollIntoView({ block: 'nearest' });
    }
  }

  function _activateSelected() {
    if (_activeIndex >= 0 && _resultRows[_activeIndex]) {
      _resultRows[_activeIndex].click();
    }
  }

  // ── Search logic ───────────────────────────────────────────────────────

  function _performSearch(query) {
    const q = (query || '').trim().toLowerCase();
    if (q.length < 2) {
      if (_overlay) _overlay.hidden = true;
      return;
    }
    const results = _runQuery(q);
    _renderResults(results, q);
    if (_overlay) _overlay.hidden = false;
  }

  function _runQuery(q) {
    const results = [];

    for (const m of (_data.malware || [])) {
      if (results.length >= MAX_RESULTS) break;
      if (_match(m.name, q) || _matchArr(m.aliases, q) || _match(m.type, q)) {
        results.push({
          type: 'malware',
          label: m.name || m.id,
          sub: [m.type, m.platform?.slice(0, 2).join('/')].filter(Boolean).join(' · '),
          view: 'malware', id: m.id
        });
      }
    }

    for (const a of (_data.actors || [])) {
      if (results.length >= MAX_RESULTS) break;
      if (_match(a.name, q) || _matchArr(a.aliases, q) || _match(a.country_iso, q)) {
        results.push({
          type: 'actor',
          label: a.name || a.id,
          sub: [a.country_iso, _matchArr(a.aliases, q) ? _firstMatch(a.aliases, q) : ''].filter(Boolean).join(' · '),
          view: 'actors', id: a.id
        });
      }
    }

    for (const r of (_data.ransomware || [])) {
      if (results.length >= MAX_RESULTS) break;
      if (_match(r.name, q) || _match(r.id, q)) {
        results.push({
          type: 'ransomware',
          label: r.name || r.id,
          sub: (r.status || 'unknown') + (r.victim_count ? ` · ${r.victim_count} victims` : ''),
          view: 'ransomware', id: r.id
        });
      }
    }

    for (const v of (_data.victims || [])) {
      if (results.length >= MAX_RESULTS) break;
      if (_match(v.victim, q) || _match(v.domain, q) || _match(v.group, q)) {
        results.push({
          type: 'victim',
          label: v.victim,
          sub: [v.group, v.country, Security.formatDate(v.attack_date)].filter(Boolean).join(' · '),
          view: 'victims', id: v.id
        });
      }
    }

    return results;
  }

  function _match(str, q) {
    return !!str && String(str).toLowerCase().includes(q);
  }

  function _matchArr(arr, q) {
    return Array.isArray(arr) && arr.some(s => !!s && String(s).toLowerCase().includes(q));
  }

  function _firstMatch(arr, q) {
    return (Array.isArray(arr) ? arr.find(s => !!s && String(s).toLowerCase().includes(q)) : '') || '';
  }

  // ── Result rendering ───────────────────────────────────────────────────

  const _TYPE_LABEL = { malware: 'Malware', actor: 'Actor', ransomware: 'Ransomware', victim: 'Victim' };
  const _TYPE_BADGE = { malware: 'badge-blue', actor: 'badge-red', ransomware: 'badge-yellow', victim: 'badge-gray' };

  function _renderResults(results, query) {
    if (!_resultsEl) return;
    _resultsEl.innerHTML = '';
    _activeIndex = -1;
    _resultRows = [];

    if (!results.length) {
      const empty = document.createElement('p');
      empty.className = 'search-empty';
      empty.textContent = `No results for "${Security.truncate(query, 40)}"`;
      _resultsEl.appendChild(empty);
      return;
    }

    const groups = {};
    for (const r of results) {
      (groups[r.type] = groups[r.type] || []).push(r);
    }

    for (const [type, items] of Object.entries(groups)) {
      const section = document.createElement('div');
      section.className = 'search-result-section';

      const label = document.createElement('div');
      label.className = 'search-result-label';
      label.textContent = (_TYPE_LABEL[type] || type) + ' (' + items.length + ')';
      section.appendChild(label);

      for (const item of items) {
        const row = document.createElement('div');
        row.className = 'search-result-row';
        row.setAttribute('role', 'option');
        row.setAttribute('tabindex', '-1');

        const badge = document.createElement('span');
        badge.className = `badge ${_TYPE_BADGE[type] || 'badge-gray'}`;
        badge.style.cssText = 'font-size:10px;flex-shrink:0;min-width:60px;text-align:center;';
        badge.textContent = _TYPE_LABEL[type] || type;

        const nameEl = document.createElement('span');
        nameEl.className = 'search-result-name';
        nameEl.innerHTML = _highlight(item.label, query);

        const subEl = document.createElement('span');
        subEl.className = 'search-result-sub';
        subEl.textContent = Security.truncate(item.sub || '', 50);

        row.appendChild(badge);
        row.appendChild(nameEl);
        row.appendChild(subEl);

        row.addEventListener('click', () => {
          close();
          window.location.hash = `#/${item.view}`;
        });
        row.addEventListener('mouseenter', () => {
          _resultRows.forEach(r => r.classList.remove('active'));
          _activeIndex = _resultRows.indexOf(row);
          row.classList.add('active');
        });

        section.appendChild(row);
        _resultRows.push(row);
      }

      _resultsEl.appendChild(section);
    }

    const footer = document.createElement('div');
    footer.className = 'search-result-footer';
    footer.textContent = `${results.length} result${results.length !== 1 ? 's' : ''} — ↑↓ navigate · Enter select · Esc close`;
    _resultsEl.appendChild(footer);
  }

  function _highlight(text, query) {
    if (!text) return '';
    const safe  = Security.escapeHtml(text);
    const safeQ = Security.escapeHtml(query);
    const idx   = safe.toLowerCase().indexOf(safeQ.toLowerCase());
    if (idx < 0) return safe;
    return (
      safe.slice(0, idx) +
      `<mark class="search-highlight">${safe.slice(idx, idx + safeQ.length)}</mark>` +
      safe.slice(idx + safeQ.length)
    );
  }

  return { init, updateData, open, close };
})();

export default Search;
