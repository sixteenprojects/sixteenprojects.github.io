/**
 * victims.js — Victims Feed view.
 * Filters: country, sector, group, date range. Clicking a row opens detail.
 */

import Security  from '../security.js';
import Table     from '../components/table.js';
import DetailView from './detail.js';
import Export    from '../export.js';

const VictimsView = (() => {
  'use strict';

  let _tableInstance = null;
  let _currentData   = [];
  let _filters       = { search: '', country: '', sector: '', group: '', dateFrom: '', dateTo: '' };

  function render(container, data, refs) {
    const victims = data.victims || [];
    _currentData = victims;
    _filters = { search: '', country: '', sector: '', group: '', dateFrom: '', dateTo: '' };

    container.innerHTML = '';

    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Victims Feed</h1>
          <p class="page-subtitle">${victims.length.toLocaleString()} recorded attacks from Ransomware.live</p>
        </div>
      </div>`;
    container.appendChild(hdr);

    container.appendChild(_buildStats(victims));

    const card = _el('div', 'section-card');
    container.appendChild(card);
    card.appendChild(_buildToolbar(victims));

    const tableContainer = _el('div');
    card.appendChild(tableContainer);

    _tableInstance = Table.create(tableContainer, {
      data: victims,
      pageSize: 50,
      emptyText: 'No victims found.',
      defaultSort: 'attack_date',
      defaultSortDir: 'desc',
      columns: _getColumns(),
      onRowClick: item => DetailView.open('victim', item),
    });
  }

  function _buildStats(victims) {
    const countries = new Set(victims.map(v => v.country).filter(Boolean)).size;
    const sectors   = new Set(victims.map(v => v.sector).filter(Boolean)).size;
    const groups    = new Set(victims.map(v => v.group).filter(Boolean)).size;

    const strip = _el('div', 'stats-grid');
    strip.style.marginBottom = 'var(--space-4)';

    [
      { label: 'Total Victims',    value: victims.length, color: 'red'    },
      { label: 'Countries Hit',    value: countries,       color: 'yellow' },
      { label: 'Sectors Targeted', value: sectors,         color: 'blue'   },
      { label: 'Active Groups',    value: groups,          color: 'cyan'   },
    ].forEach(d => {
      const c = _el('div', 'stat-card');
      c.innerHTML = `
        <div class="stat-card-icon ${d.color}">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M8 1L2 4v5c0 3.5 2.5 6.3 6 7 3.5-.7 6-3.5 6-7V4L8 1z"/>
          </svg>
        </div>
        <div class="stat-card-value">${String(d.value).toLocaleString()}</div>
        <div class="stat-card-label">${d.label}</div>`;
      strip.appendChild(c);
    });
    return strip;
  }

  function _buildToolbar(victims) {
    const bar = _el('div', 'table-toolbar');
    bar.style.flexWrap = 'wrap';
    bar.style.gap = '8px';

    // Search
    const searchWrap = _el('div', 'table-search-wrap');
    searchWrap.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6.5" cy="6.5" r="5"/><path d="M11 11l3 3"/></svg>`;
    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.className = 'table-search';
    searchInput.placeholder = 'Search victim, domain, group…';
    searchWrap.appendChild(searchInput);
    bar.appendChild(searchWrap);

    // Country
    const countryCounts = {};
    victims.forEach(v => { if (v.country) countryCounts[v.country] = (countryCounts[v.country] || 0) + 1; });
    const countries = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).map(([c]) => c).slice(0, 50);
    bar.appendChild(_filterSelect('Country', countries, val => { _filters.country = val; _applyFilters(); }));

    // Sector
    const sectorCounts = {};
    victims.forEach(v => { if (v.sector) sectorCounts[v.sector] = (sectorCounts[v.sector] || 0) + 1; });
    const sectors = Object.entries(sectorCounts).sort((a, b) => b[1] - a[1]).map(([s]) => s).slice(0, 50);
    bar.appendChild(_filterSelect('Sector', sectors, val => { _filters.sector = val; _applyFilters(); }));

    // Group
    const groupCounts = {};
    victims.forEach(v => { if (v.group) groupCounts[v.group] = (groupCounts[v.group] || 0) + 1; });
    const groups = Object.entries(groupCounts).sort((a, b) => b[1] - a[1]).map(([g]) => g).slice(0, 60);
    bar.appendChild(_filterSelect('Group', groups, val => { _filters.group = val; _applyFilters(); }));

    // Date from/to
    const dateWrap = _el('div', 'filter-group');
    const dateLbl  = _el('span', 'filter-label');
    dateLbl.textContent = 'From:';
    const dateFrom = document.createElement('input');
    dateFrom.type = 'date';
    dateFrom.className = 'filter-select';
    dateFrom.style.width = '130px';
    dateFrom.addEventListener('change', () => { _filters.dateFrom = dateFrom.value; _applyFilters(); });
    const dateLbl2 = _el('span', 'filter-label');
    dateLbl2.textContent = 'To:';
    const dateTo = document.createElement('input');
    dateTo.type = 'date';
    dateTo.className = 'filter-select';
    dateTo.style.width = '130px';
    dateTo.addEventListener('change', () => { _filters.dateTo = dateTo.value; _applyFilters(); });
    dateWrap.appendChild(dateLbl);
    dateWrap.appendChild(dateFrom);
    dateWrap.appendChild(dateLbl2);
    dateWrap.appendChild(dateTo);
    bar.appendChild(dateWrap);

    // Clear
    const clearBtn = document.createElement('button');
    clearBtn.className = 'btn btn-ghost btn-sm';
    clearBtn.textContent = 'Clear';
    clearBtn.addEventListener('click', () => {
      _filters = { search: '', country: '', sector: '', group: '', dateFrom: '', dateTo: '' };
      searchInput.value = '';
      dateFrom.value = '';
      dateTo.value = '';
      bar.querySelectorAll('select').forEach(s => { s.value = ''; });
      _applyFilters();
    });
    bar.appendChild(clearBtn);

    const countEl = _el('span', 'text-muted text-sm');
    countEl.id = 'victims-count';
    countEl.style.marginLeft = 'auto';
    countEl.textContent = `${victims.length.toLocaleString()} victims`;
    bar.appendChild(countEl);

    const exportLbl = _el('span', 'filter-label');
    exportLbl.style.marginLeft = '8px';
    exportLbl.textContent = 'Export:';
    bar.appendChild(exportLbl);
    [['CSV','csv'],['JSON','json'],['Suricata','suricata']].forEach(([label, fmt]) => {
      const btn = document.createElement('button');
      btn.className = 'btn btn-ghost btn-sm';
      btn.textContent = label;
      btn.addEventListener('click', () => {
        const data = _tableInstance?.getFiltered() || victims;
        const ts   = new Date().toISOString().slice(0,10);
        if (fmt === 'csv')      Export.toCSV(data,      `tihub_victims_${ts}.csv`);
        if (fmt === 'json')     Export.toJSON(data,     `tihub_victims_${ts}.json`);
        if (fmt === 'suricata') Export.toSuricata(data, `tihub_victims_${ts}.rules`);
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

  function _applyFilters() {
    const { search, country, sector, group, dateFrom, dateTo } = _filters;
    const fromMs = dateFrom ? new Date(dateFrom).getTime() : 0;
    const toMs   = dateTo   ? new Date(dateTo).getTime()   : Infinity;

    _tableInstance?.filter(v => {
      if (country && v.country !== country) return false;
      if (sector  && v.sector  !== sector)  return false;
      if (group   && v.group   !== group)   return false;
      if (fromMs || toMs < Infinity) {
        const d = new Date(v.attack_date || v.discovered || '').getTime();
        if (isNaN(d) || d < fromMs || d > toMs) return false;
      }
      if (search) {
        const hay = [v.victim, v.domain, v.group, v.sector].join(' ').toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const count = _tableInstance?.getFiltered().length ?? _currentData.length;
    const el = document.getElementById('victims-count');
    if (el) el.textContent = `${count.toLocaleString()} victims`;
  }

  function _getColumns() {
    return [
      {
        key: 'victim',
        label: 'Victim',
        className: 'cell-name',
        width: '220px',
        render: item => {
          const wrap = _el('div');
          wrap.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
          const name = _el('span');
          name.style.fontWeight = '600';
          name.textContent = Security.truncate(item.victim, 40);
          wrap.appendChild(name);
          if (item.domain) {
            const dom = _el('span', 'text-muted');
            dom.style.cssText = 'font-size:11px;font-family:var(--font-mono);';
            dom.textContent = item.domain;
            wrap.appendChild(dom);
          }
          return wrap;
        }
      },
      {
        key: 'group',
        label: 'Group',
        width: '140px',
        render: item => {
          const badge = _el('span', 'badge badge-red');
          badge.textContent = Security.truncate(item.group || 'unknown', 20);
          return badge;
        }
      },
      {
        key: 'country',
        label: 'Country',
        width: '90px',
        render: item => {
          const el = _el('span', 'badge badge-gray');
          el.textContent = item.country || '??';
          return el;
        }
      },
      {
        key: 'sector',
        label: 'Sector',
        render: item => {
          const el = _el('span', 'text-muted');
          el.style.fontSize = '11px';
          el.textContent = Security.truncate(item.sector || 'Unknown', 25);
          return el;
        }
      },
      {
        key: 'attack_date',
        label: 'Attack Date',
        width: '110px',
        className: 'cell-nowrap',
        render: item => _muted(Security.formatDate(item.attack_date) || '—')
      },
      {
        key: 'source',
        label: 'Source',
        width: '90px',
        sortable: false,
        render: item => {
          const el = _el('span', 'badge badge-gray');
          el.style.fontSize = '10px';
          el.textContent = item.source || '—';
          return el;
        }
      }
    ];
  }

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

export default VictimsView;
