/**
 * table.js — Reusable sortable, paginated data table.
 * Usage: Table.create(container, config)
 * config: { columns, data, pageSize, onRowClick, emptyText }
 * column: { key, label, sortable, render, className, width }
 */

import Security from '../security.js';

const Table = (() => {
  'use strict';

  const DEFAULT_PAGE_SIZE = 50;

  /**
   * Create a table instance bound to a container element.
   * Returns { setData, filter, getFiltered, destroy }
   */
  function create(container, config = {}) {
    const cols      = config.columns || [];
    const onRowClick = config.onRowClick || null;
    const emptyText  = config.emptyText || 'No data found.';

    let _allData     = config.data || [];
    let _filtered    = [..._allData];
    let _sortKey     = config.defaultSort || '';
    let _sortDir     = config.defaultSortDir || 'asc';
    let _page        = 0;
    let _pageSize    = config.pageSize || DEFAULT_PAGE_SIZE;

    // ── Elements ───────────────────────────────────────────────────────

    const _wrap    = _el('div', 'data-table-wrap');
    const _table   = _el('table', 'data-table');
    const _thead   = _el('thead');
    const _tbody   = _el('tbody');
    const _pagEl   = _el('div', 'pagination');

    _table.setAttribute('role', 'grid');
    _table.appendChild(_thead);
    _table.appendChild(_tbody);
    _wrap.appendChild(_table);
    container.appendChild(_wrap);
    container.appendChild(_pagEl);

    // ── Initial render ─────────────────────────────────────────────────

    _buildHead();
    _applySort();
    _renderBody();
    _renderPagination();

    // ── Public API ─────────────────────────────────────────────────────

    function setData(data) {
      _allData   = data || [];
      _filtered  = [..._allData];
      _page      = 0;
      _applySort();
      _renderBody();
      _renderPagination();
    }

    function filter(predFn) {
      _filtered = typeof predFn === 'function' ? _allData.filter(predFn) : [..._allData];
      _page = 0;
      _applySort();
      _renderBody();
      _renderPagination();
    }

    function getFiltered() { return _filtered; }

    function setPage(p) {
      const pages = Math.ceil(_filtered.length / _pageSize);
      _page = Math.max(0, Math.min(pages - 1, p));
      _renderBody();
      _renderPagination();
    }

    function destroy() {
      _wrap.remove();
      _pagEl.remove();
    }

    // ── Head ───────────────────────────────────────────────────────────

    function _buildHead() {
      _thead.innerHTML = '';
      const tr = _el('tr');
      for (const col of cols) {
        const th = _el('th');
        if (col.sortable !== false) th.className = 'sortable';
        if (col.width) th.style.width = col.width;

        const label = document.createTextNode(col.label || '');
        th.appendChild(label);

        if (col.sortable !== false) {
          const icon = _el('span', 'sort-icon');
          icon.innerHTML = '⇅';
          icon.setAttribute('aria-hidden', 'true');
          th.appendChild(icon);
          th.addEventListener('click', () => _handleSort(col.key, th));
        }

        _applyThSort(th, col.key);
        tr.appendChild(th);
      }
      _thead.appendChild(tr);
    }

    function _applyThSort(th, key) {
      th.classList.remove('sorted-asc', 'sorted-desc');
      if (_sortKey === key) th.classList.add(_sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
    }

    function _handleSort(key, clickedTh) {
      if (_sortKey === key) {
        _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        _sortKey = key;
        _sortDir = 'asc';
      }
      _thead.querySelectorAll('th').forEach((th, i) => {
        _applyThSort(th, cols[i]?.key);
      });
      _page = 0;
      _applySort();
      _renderBody();
      _renderPagination();
    }

    // ── Sort ───────────────────────────────────────────────────────────

    function _applySort() {
      if (!_sortKey) return;
      _filtered = [..._filtered].sort((a, b) => {
        const av = a[_sortKey] ?? '';
        const bv = b[_sortKey] ?? '';
        const aStr = String(av).toLowerCase();
        const bStr = String(bv).toLowerCase();
        const aNum = parseFloat(av);
        const bNum = parseFloat(bv);
        let cmp;
        if (!isNaN(aNum) && !isNaN(bNum)) {
          cmp = aNum - bNum;
        } else {
          cmp = aStr.localeCompare(bStr, undefined, { numeric: true, sensitivity: 'base' });
        }
        return _sortDir === 'asc' ? cmp : -cmp;
      });
    }

    // ── Body ───────────────────────────────────────────────────────────

    function _renderBody() {
      _tbody.innerHTML = '';
      const start    = _page * _pageSize;
      const pageData = _filtered.slice(start, start + _pageSize);

      if (!pageData.length) {
        const tr  = _el('tr');
        const td  = _el('td');
        td.colSpan = cols.length;
        td.className = 'text-muted';
        td.style.cssText = 'text-align:center;padding:32px;';
        td.textContent = emptyText;
        tr.appendChild(td);
        _tbody.appendChild(tr);
        return;
      }

      for (const item of pageData) {
        const tr = _el('tr');
        tr.setAttribute('role', 'row');
        if (onRowClick) {
          tr.addEventListener('click', () => onRowClick(item));
        }

        for (const col of cols) {
          const td = _el('td', col.className || '');
          if (col.render) {
            const result = col.render(item);
            if (result instanceof Element) {
              td.appendChild(result);
            } else if (typeof result === 'string') {
              td.innerHTML = result; // col.render is responsible for XSS safety
            }
          } else {
            const val = item[col.key];
            td.textContent = (val === null || val === undefined) ? '—' : String(val);
          }
          tr.appendChild(td);
        }

        _tbody.appendChild(tr);
      }
    }

    // ── Pagination ─────────────────────────────────────────────────────

    function _renderPagination() {
      _pagEl.innerHTML = '';
      const total = _filtered.length;
      const pages = Math.ceil(total / _pageSize);
      const start = _page * _pageSize + 1;
      const end   = Math.min(start + _pageSize - 1, total);

      const info = _el('span', 'pagination-info');
      info.textContent = total
        ? `${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()}`
        : 'No results';
      _pagEl.appendChild(info);

      if (pages <= 1) return;

      const controls = _el('div', 'pagination-controls');

      const prevBtn = _pageBtn('←', _page === 0, () => { _page--; _renderBody(); _renderPagination(); });
      controls.appendChild(prevBtn);

      const rangeStart = Math.max(0, _page - 2);
      const rangeEnd   = Math.min(pages, rangeStart + 5);

      for (let i = rangeStart; i < rangeEnd; i++) {
        const btn = _pageBtn(String(i + 1), false, () => {
          _page = i;
          _renderBody();
          _renderPagination();
        });
        if (i === _page) btn.classList.add('active');
        controls.appendChild(btn);
      }

      const nextBtn = _pageBtn('→', _page >= pages - 1, () => { _page++; _renderBody(); _renderPagination(); });
      controls.appendChild(nextBtn);

      const sizeWrap = _el('div', 'pagination-size');
      sizeWrap.innerHTML = 'Rows: ';
      const sel = document.createElement('select');
      [25, 50, 100, 200].forEach(n => {
        const opt = document.createElement('option');
        opt.value = n;
        opt.textContent = n;
        if (n === _pageSize) opt.selected = true;
        sel.appendChild(opt);
      });
      sel.addEventListener('change', () => {
        _pageSize = parseInt(sel.value);
        _page = 0;
        _renderBody();
        _renderPagination();
      });
      sizeWrap.appendChild(sel);

      _pagEl.appendChild(controls);
      _pagEl.appendChild(sizeWrap);
    }

    function _pageBtn(label, disabled, onClick) {
      const btn = _el('button', 'page-btn');
      btn.textContent = label;
      btn.disabled = disabled;
      if (!disabled) btn.addEventListener('click', onClick);
      return btn;
    }

    return { setData, filter, getFiltered, setPage, destroy };
  }

  // ── Helpers ────────────────────────────────────────────────────────────

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  return { create };
})();

export default Table;
