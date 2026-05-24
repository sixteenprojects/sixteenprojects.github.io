/**
 * actors.js — Threat Actors view.
 * Shows all threat actors with filters: country, associated malware.
 * Clicking a row opens the detail panel.
 */

import Security  from '../security.js';
import Table     from '../components/table.js';
import DetailView from './detail.js';
import Export    from '../export.js';

const ActorsView = (() => {
  'use strict';

  let _tableInstance = null;
  let _currentData   = [];
  let _filters       = { search: '', country: '', malware: '' };

  function render(container, data, refs) {
    const actors = data.actors || [];
    _currentData = actors;
    _filters = { search: '', country: '', malware: '' };

    container.innerHTML = '';

    // ── Page header ──
    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Threat Actors</h1>
          <p class="page-subtitle">${actors.length.toLocaleString()} actors from Malpedia</p>
        </div>
      </div>`;
    container.appendChild(hdr);

    // ── Stats strip ──
    container.appendChild(_buildActorStats(actors));

    // ── Main card ──
    const card = _el('div', 'section-card');
    container.appendChild(card);

    card.appendChild(_buildToolbar(actors));

    const tableContainer = _el('div');
    card.appendChild(tableContainer);

    _tableInstance = Table.create(tableContainer, {
      data: actors,
      pageSize: 50,
      emptyText: 'No threat actors found.',
      defaultSort: 'name',
      columns: _getColumns(),
      onRowClick: item => DetailView.open('actor', item),
    });
  }

  // ── Stats strip ───────────────────────────────────────────────────────

  function _buildActorStats(actors) {
    const countries = new Set(actors.map(a => a.country_iso).filter(Boolean));
    const withMalware = actors.filter(a => (a.malware || []).length > 0).length;

    const strip = _el('div', 'stats-grid');
    strip.style.marginBottom = 'var(--space-4)';

    const defs = [
      { label: 'Total Actors',      value: actors.length, color: 'red' },
      { label: 'Countries',         value: countries.size, color: 'blue' },
      { label: 'With Known Malware',value: withMalware,    color: 'yellow' },
      { label: 'Avg Malware/Actor', value: actors.length
          ? (actors.reduce((s, a) => s + (a.malware?.length || 0), 0) / actors.length).toFixed(1)
          : 0,
        color: 'cyan' },
    ];

    for (const d of defs) {
      const card = _el('div', 'stat-card');
      card.innerHTML = `
        <div class="stat-card-icon ${d.color}">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="8" cy="5" r="3"/>
            <path d="M2 14c0-3 2.7-5 6-5s6 2 6 5"/>
          </svg>
        </div>
        <div class="stat-card-value">${String(d.value).toLocaleString()}</div>
        <div class="stat-card-label">${d.label}</div>`;
      strip.appendChild(card);
    }
    return strip;
  }

  // ── Toolbar ────────────────────────────────────────────────────────────

  function _buildToolbar(actors) {
    const bar = _el('div', 'table-toolbar');

    // Search
    const searchWrap = _el('div', 'table-search-wrap');
    searchWrap.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6.5" cy="6.5" r="5"/><path d="M11 11l3 3"/></svg>`;
    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.className = 'table-search';
    searchInput.placeholder = 'Search actor name, alias, country…';
    searchInput.setAttribute('aria-label', 'Search actors');
    searchWrap.appendChild(searchInput);
    bar.appendChild(searchWrap);

    // Country filter (top 30 countries by count)
    const countryCounts = {};
    actors.forEach(a => { if (a.country_iso) countryCounts[a.country_iso] = (countryCounts[a.country_iso] || 0) + 1; });
    const countries = Object.entries(countryCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([c]) => c)
      .slice(0, 40);

    bar.appendChild(_filterSelect('Country', countries, val => {
      _filters.country = val;
      _applyFilters();
    }));

    // Clear
    const clearBtn = document.createElement('button');
    clearBtn.className = 'btn btn-ghost btn-sm';
    clearBtn.textContent = 'Clear';
    clearBtn.addEventListener('click', () => {
      _filters = { search: '', country: '', malware: '' };
      searchInput.value = '';
      bar.querySelectorAll('select').forEach(s => { s.value = ''; });
      _applyFilters();
    });
    bar.appendChild(clearBtn);

    const countEl = _el('span', 'text-muted text-sm');
    countEl.id = 'actors-count';
    countEl.style.marginLeft = 'auto';
    countEl.textContent = `${actors.length.toLocaleString()} actors`;
    bar.appendChild(countEl);

    const exportLbl = _el('span', 'filter-label');
    exportLbl.style.marginLeft = '8px';
    exportLbl.textContent = 'Export:';
    bar.appendChild(exportLbl);
    [['CSV','csv'],['JSON','json']].forEach(([label, fmt]) => {
      const btn = document.createElement('button');
      btn.className = 'btn btn-ghost btn-sm';
      btn.textContent = label;
      btn.addEventListener('click', () => {
        const data = _tableInstance?.getFiltered() || actors;
        const ts   = new Date().toISOString().slice(0,10);
        if (fmt === 'csv')  Export.toCSV(data,  `tihub_actors_${ts}.csv`);
        if (fmt === 'json') Export.toJSON(data, `tihub_actors_${ts}.json`);
      });
      bar.appendChild(btn);
    });

    let _debounce = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(_debounce);
      _debounce = setTimeout(() => {
        _filters.search = searchInput.value.trim().toLowerCase();
        _applyFilters();
      }, 200);
    });

    return bar;
  }

  function _filterSelect(label, options, onChange) {
    const wrap = _el('div', 'filter-group');
    const lbl  = _el('span', 'filter-label');
    lbl.textContent = label + ':';
    const sel = document.createElement('select');
    sel.className = 'filter-select';
    sel.innerHTML = `<option value="">All</option>`;
    options.forEach(opt => {
      const o = document.createElement('option');
      o.value = opt;
      o.textContent = opt;
      sel.appendChild(o);
    });
    sel.addEventListener('change', () => onChange(sel.value));
    wrap.appendChild(lbl);
    wrap.appendChild(sel);
    return wrap;
  }

  // ── Filtering ──────────────────────────────────────────────────────────

  function _applyFilters() {
    const { search, country } = _filters;

    _tableInstance?.filter(a => {
      if (country && a.country_iso !== country) return false;
      if (search) {
        const hay = [a.name, ...(a.aliases || []), a.country_iso, a.id].join(' ').toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const count = _tableInstance?.getFiltered().length ?? _currentData.length;
    const countEl = document.getElementById('actors-count');
    if (countEl) countEl.textContent = `${count.toLocaleString()} actors`;
  }

  // ── Table columns ──────────────────────────────────────────────────────

  function _getColumns() {
    return [
      {
        key: 'name',
        label: 'Actor',
        className: 'cell-name',
        width: '220px',
        render: item => {
          const wrap = _el('div');
          wrap.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
          const name = _el('span');
          name.style.fontWeight = '600';
          name.textContent = item.name || item.id;
          wrap.appendChild(name);
          if (item.aliases?.length) {
            const alias = _el('span', 'text-muted');
            alias.style.fontSize = '11px';
            alias.textContent = item.aliases.slice(0, 3).join(', ');
            wrap.appendChild(alias);
          }
          return wrap;
        }
      },
      {
        key: 'country_iso',
        label: 'Country',
        width: '100px',
        render: item => {
          const iso = item.country_iso || item.country || '??';
          const badge = _el('span', 'badge badge-gray');
          badge.textContent = iso;
          return badge;
        }
      },
      {
        key: 'malware',
        label: 'Malware Families',
        sortable: false,
        render: item => {
          const families = item.malware || [];
          if (!families.length) return _muted('—');
          const wrap = _el('div', 'cell-tags');
          families.slice(0, 4).forEach(m => {
            const badge = _el('span', 'badge badge-blue');
            badge.style.fontSize = '10px';
            badge.textContent = Security.truncate(m, 20);
            wrap.appendChild(badge);
          });
          if (families.length > 4) {
            const more = _el('span', 'text-muted');
            more.style.fontSize = '11px';
            more.textContent = `+${families.length - 4}`;
            wrap.appendChild(more);
          }
          return wrap;
        }
      },
      {
        key: 'malware_count',
        label: '#',
        width: '60px',
        className: 'cell-number',
        render: item => {
          const count = (item.malware || []).length;
          const el = _el('span', count > 0 ? 'text-accent' : 'text-muted');
          el.style.fontWeight = '700';
          el.textContent = count || '0';
          return el;
        }
      },
      {
        key: 'description',
        label: 'Description',
        sortable: false,
        render: item => {
          const el = _el('span', 'text-muted');
          el.style.fontSize = '11px';
          el.textContent = Security.truncate(item.description || '—', 100);
          return el;
        }
      },
      {
        key: 'updated',
        label: 'Updated',
        width: '110px',
        className: 'cell-nowrap',
        render: item => {
          const el = _el('span', 'text-muted');
          el.textContent = Security.formatDate(item.updated);
          return el;
        }
      }
    ];
  }

  // ── Helpers ────────────────────────────────────────────────────────────

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  function _muted(text) {
    const el = _el('span', 'text-muted');
    el.textContent = text;
    return el;
  }

  return { render };
})();

export default ActorsView;
