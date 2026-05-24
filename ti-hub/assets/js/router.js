/**
 * router.js — Hash-based client-side router.
 * Routes: #/overview, #/malware, #/actors, #/ransomware, #/victims, #/map, #/graph
 */

import State from './state.js';

const Router = (() => {
  'use strict';

  const ROUTES = {
    '/overview':   'overview',
    '/malware':    'malware',
    '/actors':     'actors',
    '/ransomware': 'ransomware',
    '/victims':    'victims',
    '/stats':      'stats',
    '/map':        'map',
    '/graph':      'graph',
  };

  const DEFAULT_ROUTE = '/overview';
  let _onNavigate = null;

  /** Parse current hash to route path */
  function _currentPath() {
    const hash = window.location.hash || '';
    const path = hash.replace(/^#/, '');
    return path || DEFAULT_ROUTE;
  }

  /** Navigate to a route, updating hash and state */
  function navigate(path) {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    window.location.hash = normalizedPath;
  }

  /** Handle hash change event */
  function _handleChange() {
    const path = _currentPath();
    const viewName = ROUTES[path] || ROUTES[DEFAULT_ROUTE];

    // Update sidebar active links
    document.querySelectorAll('.sidebar-link[data-view]').forEach(el => {
      el.classList.toggle('active', el.dataset.view === viewName);
      el.setAttribute('aria-current', el.dataset.view === viewName ? 'page' : 'false');
    });

    // Update breadcrumb
    const bc = document.getElementById('breadcrumb-current');
    if (bc) {
      const labels = {
        overview: 'Dashboard', malware: 'Malware Library', actors: 'Threat Actors',
        ransomware: 'Ransomware Groups', victims: 'Victims Feed',
        stats: 'Statistics', map: 'World Map', graph: 'Threat Graph',
      };
      bc.textContent = labels[viewName] || viewName;
    }

    State.setView(viewName);
    if (_onNavigate) _onNavigate(viewName, path);
  }

  /** Initialize router */
  function init(onNavigate) {
    _onNavigate = onNavigate;
    window.addEventListener('hashchange', _handleChange);
    // Handle initial load
    _handleChange();
  }

  /** Get current view name */
  function currentView() {
    const path = _currentPath();
    return ROUTES[path] || ROUTES[DEFAULT_ROUTE];
  }

  return { init, navigate, currentView };
})();

export default Router;
