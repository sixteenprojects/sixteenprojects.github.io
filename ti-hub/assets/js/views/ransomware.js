/**
 * ransomware.js — Ransomware Groups view.
 * Filters: status, RaaS, TTP presence. Clicking a row opens detail panel.
 */

import Security  from '../security.js';
import Table     from '../components/table.js';
import DetailView from './detail.js';

const RansomwareView = (() => {
  'use strict';

  let _tableInstance = null;
  let _currentData   = [];
  let _filters       = { search: '', status: '', raas: '' };

  function render(container, data, refs) {
    const groups = data.ransomware || [];
    _currentData = groups;
    _filters = { search: '', status: '', raas: '' };

    container.innerHTML = '';

    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Ransomware Groups</h1>
          <p class="page-subtitle">${groups.length.toLocaleString()} groups from Ransomware.live · RansomLook</p>
        </div>
      </div>`;
    container.appendChild(hdr);

    // Stats
    container.appendChild(_buildStats(groups));

    const card = _el('div', 'section-card');
    container.appendChild(card);
    card.appendChild(_buildToolbar(groups));

    const tableContainer = _el('div');
    card.appendChild(tableContainer);

    _tableInstance = Table.create(tableContainer, {
      data: groups,
      pageSize: 50,
      emptyText: 'No ransomware groups found.',
      defaultSort: 'victim_count',
      defaultSortDir: 'desc',
      columns: _getColumns(),
      onRowClick: item => DetailView.open('ransomware', item),
    });
  }

  function _buildStats(groups) {
    const active   = groups.filter(g => g.status === 'active').length;
    const raas     = groups.filter(g => g.is_raas).length;
    const total    = groups.reduce((s, g) => s + (g.victim_count || 0), 0);

    const strip = _el('div', 'stats-grid');
    strip.style.marginBottom = 'var(--space-4)';

    [
      { label: 'Total Groups',    value: groups.length,           color: 'red' },
      { label: 'Active Groups',   value: active,                  color: 'yellow' },
      { label: 'RaaS Operations', value: raas,                    color: 'blue' },
      { label: 'Total Victims',   value: total.toLocaleString(),  color: 'cyan' },
    ].forEach(d => {
      const c = _el('div', 'stat-card');
      c.innerHTML = `
        <div class="stat-card-icon ${d.color}">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="7" width="10" height="8" rx="1"/>
            <path d="M5 7V5a3 3 0 016 0v2"/>
          </svg>
        </div>
        <div class="stat-card-value">${d.value}</div>
        <div class="stat-card-label">${d.label}</div>`;
      strip.appendChild(c);
    });
    return strip;
  }

  function _buildToolbar(groups) {
    const bar = _el('div', 'table-toolbar');

    const searchWrap = _el('div', 'table-search-wrap');
    searchWrap.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6.5" cy="6.5" r="5"/><path d="M11 11l3 3"/></svg>`;
    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.className = 'table-search';
    searchInput.placeholder = 'Search group name…';
    searchWrap.appendChild(searchInput);
    bar.appendChild(searchWrap);

    bar.appendChild(_filterSelect('Status', ['active', 'inactive', 'unknown'], val => {
      _filters.status = val;
      _applyFilters();
    }));

    bar.appendChild(_filterSelect('RaaS', ['Yes', 'No'], val => {
      _filters.raas = val;
      _applyFilters();
    }));

    const clearBtn = document.createElement('button');
    clearBtn.className = 'btn btn-ghost btn-sm';
    clearBtn.textContent = 'Clear';
    clearBtn.addEventListener('click', () => {
      _filters = { search: '', status: '', raas: '' };
      searchInput.value = '';
      bar.querySelectorAll('select').forEach(s => { s.value = ''; });
      _applyFilters();
    });
    bar.appendChild(clearBtn);

    const countEl = _el('span', 'text-muted text-sm');
    countEl.id = 'ransomware-count';
    countEl.style.marginLeft = 'auto';
    countEl.textContent = `${groups.length.toLocaleString()} groups`;
    bar.appendChild(countEl);

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
    const { search, status, raas } = _filters;

    _tableInstance?.filter(g => {
      if (status && g.status !== status) return false;
      if (raas === 'Yes' && !g.is_raas) return false;
      if (raas === 'No'  && g.is_raas)  return false;
      if (search && !g.name?.toLowerCase().includes(search) &&
                    !g.id?.toLowerCase().includes(search)) return false;
      return true;
    });

    const count = _tableInstance?.getFiltered().length ?? _currentData.length;
    const el = document.getElementById('ransomware-count');
    if (el) el.textContent = `${count.toLocaleString()} groups`;
  }

  function _getColumns() {
    return [
      {
        key: 'name',
        label: 'Group',
        className: 'cell-name',
        width: '200px',
        render: item => {
          const wrap = _el('div');
          wrap.style.cssText = 'display:flex;align-items:center;gap:8px;';
          const dot = _el('span', `status-dot ${item.status === 'active' ? 'active' : 'inactive'}`);
          dot.title = item.status || 'unknown';
          const name = _el('span');
          name.style.fontWeight = '600';
          name.textContent = item.name || item.id;
          wrap.appendChild(dot);
          wrap.appendChild(name);
          return wrap;
        }
      },
      {
        key: 'status',
        label: 'Status',
        width: '100px',
        render: item => {
          const cls = item.status === 'active' ? 'badge-green' : item.status === 'inactive' ? 'badge-gray' : 'badge-yellow';
          const badge = _el('span', `badge ${cls}`);
          badge.textContent = item.status || 'unknown';
          return badge;
        }
      },
      {
        key: 'is_raas',
        label: 'RaaS',
        width: '70px',
        render: item => {
          const el = _el('span', item.is_raas ? 'badge badge-red' : 'text-muted');
          el.textContent = item.is_raas ? 'RaaS' : '—';
          return el;
        }
      },
      {
        key: 'victim_count',
        label: 'Victims',
        width: '90px',
        className: 'cell-number',
        render: item => {
          const el = _el('span');
          el.style.fontWeight = '700';
          el.style.color = (item.victim_count || 0) > 100 ? 'var(--color-danger)' : 'var(--text-primary)';
          el.textContent = (item.victim_count || 0).toLocaleString();
          return el;
        }
      },
      {
        key: 'ttps',
        label: 'TTPs',
        width: '70px',
        sortable: false,
        render: item => {
          const count = (item.ttps || []).length;
          const el = _el('span', count ? 'badge badge-blue' : 'text-muted');
          el.textContent = count || '—';
          return el;
        }
      },
      {
        key: 'tools',
        label: 'Tools',
        sortable: false,
        render: item => {
          const tools = item.tools || [];
          if (!tools.length) return _muted('—');
          const wrap = _el('div', 'cell-tags');
          tools.slice(0, 3).forEach(t => {
            const badge = _el('span', 'badge badge-gray');
            badge.style.fontSize = '10px';
            badge.textContent = Security.truncate(t, 16);
            wrap.appendChild(badge);
          });
          if (tools.length > 3) {
            const more = _muted(` +${tools.length - 3}`);
            more.style.fontSize = '11px';
            wrap.appendChild(more);
          }
          return wrap;
        }
      },
      {
        key: 'first_seen',
        label: 'First Seen',
        width: '110px',
        className: 'cell-nowrap',
        render: item => _muted(Security.formatDate(item.first_seen) || '—')
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

export default RansomwareView;
