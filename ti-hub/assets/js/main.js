/**
 * main.js — Application entry point. Boots the TI-Hub SPA.
 * Wires: Theme → State → Api → Router → Views → Sidebar → Header
 */

import Theme   from './theme.js';
import State   from './state.js';
import Api     from './api.js';
import Router  from './router.js';
import Toast   from './components/toast.js';
import Security from './security.js';
import Search   from './search.js';

import OverviewView   from './views/overview.js';
import MalwareView    from './views/malware.js';
import ActorsView     from './views/actors.js';
import RansomwareView from './views/ransomware.js';
import VictimsView    from './views/victims.js';
import StatsView      from './views/stats.js';
import ShodanView     from './views/shodan.js';
import DetailView     from './views/detail.js';
import MapView        from './components/map.js';
import GraphView      from './components/graph.js';

// ── Boot sequence ──────────────────────────────────────────────────────

(async function boot() {
  // 1. Theme (must be first — prevents FOUC)
  Theme.init();
  Theme.bindToggleButton(document.getElementById('theme-toggle-btn'));

  // 2. Load persistent preferences
  State.loadSavedFilters();
  State.loadSidebarPref();

  // 3. Wire sidebar + mobile hamburger
  _initSidebar();
  _initMobileMenu();

  // 4. Wire detail panel close + Escape
  _initDetailPanel();

  // 4b. Wire refresh button
  _initRefreshButton();

  // 5. Load data
  _showLoading(true);
  try {
    const data = await Api.loadAll();
    State.loadData(data);
    await _updateLastUpdated();
    _updateSidebarCounts(data);
    Search.init(data);
    Toast.success('Threat intelligence data loaded.', 3000);
  } catch (err) {
    console.error('[Boot] Data load failed:', err);
    Toast.error('Failed to load data. Some views may be empty.');
    State.loadData({ malware: [], actors: [], ransomware: [], victims: [], meta: {} });
  }

  // 6. Init router — triggers first render
  Router.init(_renderView);
})();

// ── View rendering ─────────────────────────────────────────────────────

function _renderView(viewName) {
  const container = document.getElementById('view-container');
  if (!container) return;

  const data = Api.getAll();
  const refs  = Api.buildCrossRefs();

  _showLoading(false);
  container.innerHTML = '';

  // Map view needs zero padding and no scroll
  container.classList.toggle('view-container--map', viewName === 'map');

  switch (viewName) {
    case 'overview':   OverviewView.render(container, data);            break;
    case 'malware':    MalwareView.render(container, data, refs);       break;
    case 'actors':     ActorsView.render(container, data, refs);        break;
    case 'ransomware': RansomwareView.render(container, data, refs);    break;
    case 'victims':    VictimsView.render(container, data, refs);       break;
    case 'stats':      StatsView.render(container, data);               break;
    case 'shodan':     ShodanView.render(container, data);             break;
    case 'map':        MapView.render(container, data);                 break;
    case 'graph':      GraphView.render(container, data, refs);         break;
    default:           OverviewView.render(container, data);
  }
}

// ── Detail panel ───────────────────────────────────────────────────────

function _initDetailPanel() {
  const closeBtn = document.getElementById('detail-panel-close');
  const panel    = document.getElementById('detail-panel');
  if (!panel) return;

  if (closeBtn) closeBtn.addEventListener('click', () => DetailView.close());

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !panel.hidden) DetailView.close();
  });
}

// ── Mobile hamburger menu ──────────────────────────────────────────────

function _initMobileMenu() {
  const btn      = document.getElementById('mobile-menu-btn');
  const sidebar  = document.getElementById('sidebar');
  const backdrop = document.getElementById('mobile-sidebar-backdrop');
  if (!btn || !sidebar) return;

  function _openMobile() {
    sidebar.classList.add('mobile-open');
    if (backdrop) backdrop.classList.add('visible');
  }
  function _closeMobile() {
    sidebar.classList.remove('mobile-open');
    if (backdrop) backdrop.classList.remove('visible');
  }

  btn.addEventListener('click', () => {
    if (sidebar.classList.contains('mobile-open')) _closeMobile();
    else _openMobile();
  });
  if (backdrop) backdrop.addEventListener('click', _closeMobile);

  // Close sidebar when a nav link is clicked on mobile
  document.querySelectorAll('.sidebar-link[data-view]').forEach(link => {
    link.addEventListener('click', () => {
      if (window.innerWidth <= 768) _closeMobile();
    });
  });
}

// ── Sidebar ────────────────────────────────────────────────────────────

function _initSidebar() {
  const pinBtn      = document.getElementById('sidebar-pin-btn');
  const collapseBtn = document.getElementById('sidebar-collapse-btn');
  const expandBtn   = document.getElementById('sidebar-expand-btn');

  // Sidebar always starts expanded (no saved state)
  _applySidebarCollapsed(false);

  function _toggle() {
    const collapsed = State.toggleSidebarCollapsed();
    _applySidebarCollapsed(collapsed);
  }

  if (pinBtn)      pinBtn.addEventListener('click', _toggle);
  if (collapseBtn) collapseBtn.addEventListener('click', _toggle);
  if (expandBtn)   expandBtn.addEventListener('click', _toggle);

  // Wire sidebar nav clicks
  document.querySelectorAll('.sidebar-link[data-view]').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      Router.navigate(link.dataset.view);
    });
  });
}

function _applySidebarCollapsed(collapsed) {
  const appShell = document.getElementById('app');
  if (appShell) {
    if (collapsed) appShell.classList.add('sidebar-collapsed');
    else           appShell.classList.remove('sidebar-collapsed');
  }
  const pinBtn = document.getElementById('sidebar-pin-btn');
  if (pinBtn) {
    pinBtn.title = collapsed ? 'Show sidebar' : 'Hide sidebar';
    pinBtn.setAttribute('aria-label', collapsed ? 'Show sidebar' : 'Hide sidebar');
  }
}

// ── Refresh button ─────────────────────────────────────────────────────

function _initRefreshButton() {
  const btn  = document.getElementById('refresh-btn');
  const icon = document.getElementById('refresh-icon');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    if (icon) icon.style.animation = 'spin 0.6s linear infinite';
    Toast.info('Refreshing data…', 0);

    try {
      await Api.forceReload();
      State.loadData(Api.getAll());
      await _updateLastUpdated();
      _updateSidebarCounts(Api.getAll());
      Search.updateData(Api.getAll());
      _renderView(Router.currentView());
      Toast.success('Data refreshed successfully.');
    } catch (err) {
      Toast.error('Refresh failed: ' + (err.message || 'Unknown error'));
    } finally {
      btn.disabled = false;
      if (icon) icon.style.animation = '';
    }
  });
}

// ── Header helpers ─────────────────────────────────────────────────────

async function _updateLastUpdated() {
  const el = document.getElementById('last-updated');
  if (!el) return;
  const ts = await Api.getLastUpdated();
  el.textContent = ts;
}

function _updateSidebarCounts(data) {
  const map = {
    'count-malware':    (data.malware    || []).length,
    'count-actors':     (data.actors     || []).length,
    'count-ransomware': (data.ransomware || []).length,
    'count-victims':    (data.victims    || []).length,
  };
  for (const [id, count] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (el) el.textContent = count.toLocaleString();
  }
}

function _showLoading(show) {
  const container = document.getElementById('view-container');
  if (!container) return;
  if (show) {
    container.innerHTML = `
      <div class="loading-overlay">
        <div class="spinner"></div>
        <p>Loading threat intelligence data…</p>
      </div>`;
  }
}

// ── Toast CSS injection (avoids extra file for Phase 1) ────────────────

const toastStyles = document.createElement('style');
toastStyles.textContent = `
.toast-container {
  position: fixed; bottom: 24px; right: 24px;
  display: flex; flex-direction: column; gap: 8px;
  z-index: var(--z-toast); pointer-events: none;
}
.toast {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 16px;
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  font-size: 13px; color: var(--text-primary);
  pointer-events: auto;
  max-width: 380px; min-width: 240px;
}
.toast-info    { border-left: 3px solid var(--color-info); }
.toast-success { border-left: 3px solid var(--color-success); }
.toast-warning { border-left: 3px solid var(--color-warning); }
.toast-error   { border-left: 3px solid var(--color-danger); }
.toast-icon { font-size: 12px; flex-shrink: 0; }
.toast-info .toast-icon    { color: var(--color-info); }
.toast-success .toast-icon { color: var(--color-success); }
.toast-warning .toast-icon { color: var(--color-warning); }
.toast-error .toast-icon   { color: var(--color-danger); }
.toast-message { flex: 1; line-height: 1.4; }
.toast-close {
  background: none; border: none; cursor: pointer;
  color: var(--text-muted); font-size: 12px; padding: 2px 4px;
  border-radius: 4px; flex-shrink: 0;
}
.toast-close:hover { color: var(--text-primary); background: var(--bg-surface-3); }
@keyframes toastIn  { from { opacity:0; transform:translateX(16px); } to { opacity:1; transform:none; } }
@keyframes toastOut { from { opacity:1; transform:none; } to { opacity:0; transform:translateX(16px); } }
.search-overlay { position:fixed; inset:0; z-index:var(--z-modal); background:rgba(0,0,0,.5); display:flex; align-items:flex-start; justify-content:center; padding-top:80px; }
.search-overlay-inner { background:var(--bg-surface); border:1px solid var(--border-color); border-radius:var(--radius-lg); width:100%; max-width:640px; max-height:65vh; overflow-y:auto; box-shadow:var(--shadow-lg); }
.search-results { padding:8px; }
.search-empty { padding:20px; color:var(--text-muted); font-size:13px; text-align:center; }
.search-result-section { margin-bottom:4px; }
.search-result-label { padding:8px 12px 4px; font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.06em; }
.search-result-row { display:flex; align-items:center; gap:8px; padding:8px 12px; border-radius:6px; cursor:pointer; transition:background .1s; }
.search-result-row:hover, .search-result-row.active { background:var(--bg-surface-2); }
.search-result-name { flex:1; font-size:13px; font-weight:500; color:var(--text-primary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.search-result-sub { font-size:11px; color:var(--text-muted); white-space:nowrap; flex-shrink:0; max-width:200px; overflow:hidden; text-overflow:ellipsis; }
.search-result-footer { padding:8px 12px; font-size:11px; color:var(--text-muted); border-top:1px solid var(--border-color); }
mark.search-highlight { background:var(--color-brand-accent); color:#fff; border-radius:2px; padding:0 2px; }
.detail-info-grid { display:grid; grid-template-columns:140px 1fr; gap:2px 12px; padding:16px 20px; font-size:13px; }
.detail-info-grid dt { color:var(--text-muted); font-weight:500; padding:4px 0; }
.detail-info-grid dd { color:var(--text-primary); padding:4px 0; word-break:break-word; margin:0; }
.detail-desc { padding:0 20px 16px; }
.detail-desc h4 { font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.06em; margin-bottom:8px; }
.detail-desc p { font-size:13px; color:var(--text-secondary); line-height:1.6; }
.detail-refs { padding:0 20px 16px; }
.detail-refs h4 { font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.06em; margin-bottom:8px; }
.detail-refs ul { list-style:none; padding:0; display:flex; flex-direction:column; gap:4px; }
.detail-refs li { font-size:12px; color:var(--text-secondary); word-break:break-all; }
.ref-link { color:var(--color-brand-accent); text-decoration:none; }
.ref-link:hover { text-decoration:underline; }
.detail-phase-note { margin:0 20px 20px; padding:10px 14px; background:var(--bg-surface-2); border:1px solid var(--border-color); border-radius:var(--radius-md); font-size:12px; color:var(--text-muted); }
.cross-link-chip { cursor:pointer; transition:filter .1s; }
.cross-link-chip:hover { filter:brightness(1.25); text-decoration:underline; }
.filter-saved-wrap { display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
.saved-filter-chip { cursor:pointer; display:inline-flex; align-items:center; gap:4px; }
`;
document.head.appendChild(toastStyles);
