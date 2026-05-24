/**
 * state.js — Global application state with observer pattern.
 * Single source of truth for all view data and UI state.
 */

const State = (() => {
  'use strict';

  const _state = {
    // Data
    malware:    [],
    actors:     [],
    ransomware: [],
    victims:    [],
    meta:       {},

    // UI
    currentView:   'overview',
    detailItem:    null,
    detailType:    null,
    sidebarPinned: false,
    isLoading:     true,
    searchQuery:   '',

    // Filters (per view)
    filters: {
      malware:    {},
      actors:     {},
      ransomware: {},
      victims:    {},
    },

    // Saved filters
    savedFilters: {},

    // Cross-reference indexes (built after data load)
    refs: null,
  };

  const _listeners = new Map(); // event → Set<fn>

  function _emit(event, payload) {
    const fns = _listeners.get(event);
    if (fns) fns.forEach(fn => { try { fn(payload); } catch(e) { console.error(e); } });
    // Also emit wildcard
    const all = _listeners.get('*');
    if (all) all.forEach(fn => { try { fn(event, payload); } catch(e) { console.error(e); } });
  }

  /** Get a state value by dot-path key */
  function get(key) {
    return key.split('.').reduce((obj, k) => obj?.[k], _state);
  }

  /** Set a state value and emit change event */
  function set(key, value) {
    const parts = key.split('.');
    let obj = _state;
    for (let i = 0; i < parts.length - 1; i++) {
      if (obj[parts[i]] === undefined) obj[parts[i]] = {};
      obj = obj[parts[i]];
    }
    const last = parts[parts.length - 1];
    const prev = obj[last];
    obj[last] = value;
    if (prev !== value) _emit(`change:${key}`, { key, value, prev });
    _emit('change', { key, value, prev });
  }

  /** Merge an object into state at a given key */
  function merge(key, partial) {
    const current = get(key) || {};
    set(key, { ...current, ...partial });
  }

  /** Subscribe to state change events */
  function on(event, fn) {
    if (!_listeners.has(event)) _listeners.set(event, new Set());
    _listeners.get(event).add(fn);
    return () => _listeners.get(event)?.delete(fn); // returns unsubscribe fn
  }

  /** Load all data into state */
  function loadData(data) {
    set('malware',    data.malware    || []);
    set('actors',     data.actors     || []);
    set('ransomware', data.ransomware || []);
    set('victims',    data.victims    || []);
    set('meta',       data.meta       || {});
    set('isLoading',  false);
    _emit('data:loaded', data);
  }

  /** Set the active view */
  function setView(viewName) {
    const prev = _state.currentView;
    set('currentView', viewName);
    if (prev !== viewName) _emit('view:change', { view: viewName, prev });
  }

  /** Open detail panel */
  function openDetail(item, type) {
    set('detailItem', item);
    set('detailType', type);
    _emit('detail:open', { item, type });
  }

  /** Close detail panel */
  function closeDetail() {
    set('detailItem', null);
    set('detailType', null);
    _emit('detail:close', {});
  }

  /** Set filter for a view */
  function setFilter(view, key, value) {
    const current = get(`filters.${view}`) || {};
    if (value === null || value === '' || value === undefined) {
      const { [key]: _, ...rest } = current;
      set(`filters.${view}`, rest);
    } else {
      set(`filters.${view}`, { ...current, [key]: value });
    }
    _emit(`filter:${view}`, get(`filters.${view}`));
  }

  /** Clear all filters for a view */
  function clearFilters(view) {
    set(`filters.${view}`, {});
    _emit(`filter:${view}`, {});
  }

  /** Save current filters under a name */
  function saveFilter(view, name) {
    const current = get(`filters.${view}`) || {};
    const key = `${view}:${name}`;
    const saved = { ...(_state.savedFilters || {}), [key]: current };
    set('savedFilters', saved);
    // Persist to localStorage
    try { localStorage.setItem('tihub-saved-filters', JSON.stringify(saved)); } catch {}
  }

  /** Load saved filters from localStorage */
  function loadSavedFilters() {
    try {
      const raw = localStorage.getItem('tihub-saved-filters');
      if (raw) set('savedFilters', JSON.parse(raw));
    } catch {}
  }

  /** Toggle sidebar pinned state */
  function toggleSidebarPin() {
    const next = !_state.sidebarPinned;
    set('sidebarPinned', next);
    try { localStorage.setItem('tihub-sidebar-pinned', next ? '1' : '0'); } catch {}
    return next;
  }

  /** Load sidebar preference from localStorage */
  function loadSidebarPref() {
    try {
      const v = localStorage.getItem('tihub-sidebar-pinned');
      if (v !== null) set('sidebarPinned', v === '1');
    } catch {}
  }

  return {
    get, set, merge, on, loadData, loadSavedFilters, loadSidebarPref,
    setView, openDetail, closeDetail,
    setFilter, clearFilters, saveFilter, toggleSidebarPin,
  };
})();

export default State;
