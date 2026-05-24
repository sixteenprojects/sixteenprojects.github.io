/**
 * filters.js — Saved filter presets (localStorage).
 * Filters.buildSaveUI(viewId, getState, onLoad) → DOM element for toolbar.
 */

const Filters = (() => {
  'use strict';

  const KEY = 'tihub-saved-filters';

  function _read() {
    try { return JSON.parse(localStorage.getItem(KEY) || '{}'); }
    catch { return {}; }
  }
  function _write(data) {
    try { localStorage.setItem(KEY, JSON.stringify(data)); } catch {}
  }

  function save(viewId, name, state) {
    const all = _read();
    if (!all[viewId]) all[viewId] = {};
    all[viewId][name] = { state, savedAt: Date.now() };
    _write(all);
  }

  function loadAll(viewId) {
    return _read()[viewId] || {};
  }

  function remove(viewId, name) {
    const all = _read();
    if (all[viewId]) { delete all[viewId][name]; _write(all); }
  }

  /**
   * Build a small "Save / load preset" UI element for toolbar insertion.
   * @param {string}   viewId       — unique key per view (e.g. 'malware')
   * @param {function} getState     — returns current filter state (plain object)
   * @param {function} onLoad       — called with filter state when user loads a preset
   */
  function buildSaveUI(viewId, getState, onLoad) {
    const wrap = _el('div', 'filter-saved-wrap');
    wrap.style.cssText = 'display:flex;align-items:center;gap:6px;flex-wrap:wrap;';

    // Save button
    const saveBtn = _el('button', 'btn btn-ghost btn-sm');
    saveBtn.title = 'Save current filters as preset';
    saveBtn.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12">
      <path d="M2 3a1 1 0 011-1h7l4 4v7a1 1 0 01-1 1H3a1 1 0 01-1-1V3z"/>
      <rect x="5" y="10" width="6" height="4" rx=".5"/><rect x="4" y="2" width="5" height="3" rx=".5"/>
    </svg> Save`;
    saveBtn.addEventListener('click', () => {
      const name = prompt('Name for this filter preset:');
      if (!name?.trim()) return;
      save(viewId, name.trim(), getState());
      _refreshChips(wrap, viewId, onLoad, saveBtn);
    });
    wrap.appendChild(saveBtn);

    _refreshChips(wrap, viewId, onLoad, saveBtn);
    return wrap;
  }

  function _refreshChips(wrap, viewId, onLoad, saveBtn) {
    wrap.querySelectorAll('.saved-filter-chip').forEach(c => c.remove());
    const presets = loadAll(viewId);
    for (const [name, data] of Object.entries(presets)) {
      const chip = _el('span', 'badge badge-blue saved-filter-chip');
      chip.style.cssText = 'cursor:pointer;display:inline-flex;align-items:center;gap:4px;';
      chip.title = `Load "${name}"`;

      const lbl = _el('span');
      lbl.textContent = name;
      lbl.addEventListener('click', () => onLoad(data.state));

      const del = _el('span');
      del.textContent = '×';
      del.style.cssText = 'opacity:.7;font-size:11px;margin-left:2px;';
      del.title = 'Delete preset';
      del.addEventListener('click', e => {
        e.stopPropagation();
        remove(viewId, name);
        _refreshChips(wrap, viewId, onLoad, saveBtn);
      });

      chip.appendChild(lbl);
      chip.appendChild(del);
      wrap.appendChild(chip);
    }
  }

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  // apply() kept for API compatibility (legacy stub signature)
  function apply(data) { return data; }

  return { save, loadAll, remove, buildSaveUI, apply };
})();

export default Filters;
