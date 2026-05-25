/**
 * api.js — Data loading, caching, and refresh logic.
 * All data is read from /ti-hub/data/*.json (built by GitHub Actions).
 * Manual refresh triggers GitHub Actions workflow dispatch.
 */

import Security from './security.js';

const Api = (() => {
  'use strict';

  const BASE_DATA = './data';
  const FILES = {
    malware:    `${BASE_DATA}/malware.json`,
    actors:     `${BASE_DATA}/actors.json`,
    ransomware: `${BASE_DATA}/ransomware.json`,
    victims:    `${BASE_DATA}/victims.json`,
    stats:      `${BASE_DATA}/stats.json`,
    recent:     `${BASE_DATA}/recent.json`,
    ioc:        `${BASE_DATA}/ioc.json`,
    meta:       `${BASE_DATA}/meta.json`,
    threatfox:  `${BASE_DATA}/threatfox.json`,
    shodan:     `${BASE_DATA}/shodan.json`,
  };

  // In-memory cache
  const _cache = {
    malware:    null,
    actors:     null,
    ransomware: null,
    victims:    null,
    stats:      null,
    recent:     null,
    ioc:        null,
    meta:       null,
    threatfox:  null,
    shodan:     null,
  };

  let _loading = false;
  let _loadListeners = [];
  let _errorListeners = [];

  /** Fetch a single JSON file with error handling */
  async function _fetchJSON(url) {
    const resp = await fetch(url + '?t=' + Date.now(), {
      cache: 'no-store',
      headers: { 'Accept': 'application/json' }
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
    const data = await resp.json();
    return data;
  }

  /** Load all data files into cache */
  async function loadAll() {
    if (_loading) return _cache;
    _loading = true;

    const results = await Promise.allSettled([
      _fetchJSON(FILES.malware).then(d => { _cache.malware = Array.isArray(d) ? d : []; }),
      _fetchJSON(FILES.actors).then(d  => { _cache.actors  = Array.isArray(d) ? d : []; }),
      _fetchJSON(FILES.ransomware).then(d=>{ _cache.ransomware = Array.isArray(d) ? d : []; }),
      _fetchJSON(FILES.victims).then(d => { _cache.victims  = Array.isArray(d) ? d : []; }),
      _fetchJSON(FILES.stats).then(d   => { _cache.stats    = typeof d === 'object' && !Array.isArray(d) ? d : {}; }),
      _fetchJSON(FILES.recent).then(d  => { _cache.recent   = Array.isArray(d) ? d : []; }),
      _fetchJSON(FILES.ioc).then(d      => { _cache.ioc       = typeof d === 'object' && !Array.isArray(d) ? d : {}; }).catch(() => { _cache.ioc = {}; }),
      _fetchJSON(FILES.meta).then(d     => { _cache.meta      = typeof d === 'object' ? d : {}; }),
      _fetchJSON(FILES.threatfox).then(d=> { _cache.threatfox = typeof d === 'object' && !Array.isArray(d) ? d : {}; }).catch(() => { _cache.threatfox = {}; }),
      _fetchJSON(FILES.shodan).then(d   => { _cache.shodan    = typeof d === 'object' && !Array.isArray(d) ? d : {}; }).catch(() => { _cache.shodan = {}; }),
    ]);

    const errors = results
      .filter(r => r.status === 'rejected')
      .map(r => r.reason?.message || 'Unknown error');

    _loading = false;

    if (errors.length) {
      console.warn('[Api] Some files failed to load:', errors);
      _errorListeners.forEach(fn => fn(errors));
    }

    _loadListeners.forEach(fn => fn(_cache));
    return _cache;
  }

  /** Get cached data (loads if not yet loaded) */
  async function get(key) {
    if (!_cache[key]) await loadAll();
    return _cache[key] || [];
  }

  /** Get all cached data */
  function getAll() { return _cache; }

  /** Get metadata (last updated, counts) */
  async function getMeta() {
    if (!_cache.meta) await loadAll();
    return _cache.meta || {};
  }

  /** Get last updated timestamp as formatted string */
  async function getLastUpdated() {
    const meta = await getMeta();
    return Security.formatDate(meta.last_updated) || 'Never';
  }

  /** Get counts summary */
  async function getCounts() {
    const meta = await getMeta();
    return meta.counts || { malware: 0, actors: 0, ransomware_groups: 0, victims: 0 };
  }

  /**
   * Manual refresh — triggers GitHub Actions workflow dispatch.
   * Requires a GitHub PAT stored in localStorage (set via settings panel).
   * Falls back to page reload if no token available.
   */
  async function triggerRefresh(opts = {}) {
    const token = opts.token || localStorage.getItem('tihub-gh-token');
    const repo  = opts.repo  || localStorage.getItem('tihub-gh-repo') || 'sixteenprojects/website';

    if (!token) {
      // No token — just reload data from existing JSON
      console.info('[Api] No GitHub token. Reloading data from JSON...');
      _cache.malware = null;
      _cache.actors  = null;
      _cache.ransomware = null;
      _cache.victims = null;
      _cache.meta    = null;
      return loadAll();
    }

    // Trigger GitHub Actions workflow dispatch
    const url = `https://api.github.com/repos/${repo}/actions/workflows/update_tihub_data.yml/dispatches`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ref: 'master' })
    });

    if (resp.ok || resp.status === 204) {
      return { triggered: true, message: 'Workflow dispatched. Data will update in ~10 minutes.' };
    }

    const err = await resp.json().catch(() => ({}));
    throw new Error(err.message || `GitHub API error: ${resp.status}`);
  }

  /** Force clear cache and reload */
  async function forceReload() {
    Object.keys(_cache).forEach(k => { _cache[k] = null; });
    return loadAll();
  }

  /** Register callback for when data loads */
  function onLoad(fn) {
    if (typeof fn === 'function') _loadListeners.push(fn);
  }

  /** Register callback for load errors */
  function onError(fn) {
    if (typeof fn === 'function') _errorListeners.push(fn);
  }

  /**
   * Build a lookup map from an array by a key field.
   * Useful for O(1) cross-referencing between datasets.
   */
  function buildIndex(arr, keyField = 'id') {
    const map = new Map();
    if (!Array.isArray(arr)) return map;
    for (const item of arr) {
      const k = item[keyField];
      if (k !== undefined && k !== null) map.set(String(k), item);
    }
    return map;
  }

  /**
   * Build cross-reference indexes between datasets.
   * Returns Maps for fast O(1) lookups in views.
   */
  function buildCrossRefs() {
    const { malware = [], actors = [], ransomware = [], victims = [] } = _cache;

    // malwareById, actorById, ransomwareById
    const malwareById    = buildIndex(malware);
    const actorById      = buildIndex(actors);
    const ransomwareById = buildIndex(ransomware);

    // victims grouped by group_id
    const victimsByGroup = new Map();
    for (const v of victims) {
      const gid = v.group_id || '';
      if (!victimsByGroup.has(gid)) victimsByGroup.set(gid, []);
      victimsByGroup.get(gid).push(v);
    }

    // actors grouped by malware id (reverse: which actors use this malware)
    const actorsByMalware = new Map();
    for (const actor of actors) {
      for (const mId of (actor.malware || [])) {
        if (!actorsByMalware.has(mId)) actorsByMalware.set(mId, []);
        actorsByMalware.get(mId).push(actor);
      }
    }

    return { malwareById, actorById, ransomwareById, victimsByGroup, actorsByMalware };
  }

  return {
    loadAll, get, getAll, getMeta,
    getLastUpdated, getCounts,
    triggerRefresh, forceReload,
    onLoad, onError,
    buildIndex, buildCrossRefs
  };
})();

export default Api;
