/**
 * map.js — World Map view showing victims by country.
 * Uses Leaflet for the base map with CircleMarkers at country centroids.
 * Leaflet must be loaded globally before this module runs.
 */

import Security from '../security.js';

const MapView = (() => {
  'use strict';

  let _mapInstance = null;

  // Country centroids [lat, lng] — top 80 countries in ransomware data
  const CENTROIDS = {
    US:[38,-97],GB:[55.4,-3.4],DE:[51.2,10.5],FR:[46.2,2.2],IT:[42.8,12.8],
    ES:[40.5,-3.7],CA:[56.1,-106.3],AU:[-25.3,133.8],JP:[36.2,138.3],
    KR:[35.9,127.8],IN:[20.6,78.9],CN:[35.9,104.2],RU:[61.5,105.3],
    BR:[-14.2,-51.9],MX:[23.6,-102.6],AR:[-38.4,-63.6],ZA:[-30.6,22.9],
    NG:[9.1,8.7],EG:[26.8,30.8],TR:[38.9,35.2],IL:[31.0,35.0],
    SA:[23.9,45.1],AE:[23.4,53.8],PL:[51.9,19.1],NL:[52.1,5.3],
    SE:[60.1,18.6],NO:[60.5,8.5],DK:[56.3,9.5],FI:[64.0,26.0],
    CH:[46.8,8.2],AT:[47.5,14.5],BE:[50.5,4.5],PT:[39.4,-8.2],
    GR:[39.1,22.0],CZ:[49.8,15.5],HU:[47.2,19.5],RO:[45.9,24.9],
    SG:[1.3,103.8],HK:[22.4,114.2],TW:[23.7,121.0],TH:[15.9,100.9],
    ID:[-0.8,113.9],MY:[4.2,109.4],PH:[12.9,121.8],VN:[14.1,108.3],
    CL:[-35.7,-71.5],CO:[4.6,-74.3],PE:[-9.2,-75.0],UA:[48.4,31.2],
    PK:[30.4,69.3],BD:[23.7,90.4],NZ:[-40.9,174.9],LK:[7.9,80.8],
    SK:[48.7,19.7],SI:[46.2,14.9],HR:[45.1,15.2],RS:[44.0,21.0],
    BG:[42.7,25.5],BA:[43.9,17.7],LT:[55.2,23.9],LV:[56.9,24.6],
    EE:[58.6,25.0],CY:[35.1,33.4],QA:[25.4,51.2],KW:[29.3,47.5],
    JO:[30.6,36.2],MA:[31.8,-7.1],DZ:[28.0,2.6],TN:[33.9,9.6],
    KE:[-0.0,37.9],GH:[7.9,-1.0],TZ:[-6.4,34.9],ET:[9.1,40.5],
    ZW:[-19.0,29.9],UG:[1.4,32.3],IQ:[33.2,43.7],SY:[35.0,38.0],
    LB:[33.9,35.5],LY:[26.3,17.2],SD:[15.6,32.5],VE:[6.4,-66.6],
    EC:[-1.8,-78.2],BO:[-16.3,-63.6],PY:[-23.4,-58.4],UY:[-32.5,-55.8],
    CR:[9.7,-83.8],GT:[15.8,-90.2],PA:[8.5,-80.8],CU:[21.5,-79.5],
  };

  function render(container, data) {
    const victims = data.victims || [];

    container.innerHTML = '';

    // ── Page header ──
    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">World Map</h1>
          <p class="page-subtitle">Victim distribution across ${_countryCount(victims)} countries</p>
        </div>
        <div class="page-actions">
          <select id="map-group-filter" class="filter-select" style="min-width:160px;">
            <option value="">All Groups</option>
            ${_groupOptions(data.ransomware || [])}
          </select>
        </div>
      </div>`;
    container.appendChild(hdr);

    // ── Main layout: map + sidebar ──
    const layout = _el('div', 'grid-main-aside');
    container.appendChild(layout);

    // Map card
    const mapCard = _el('div', 'section-card');
    layout.appendChild(mapCard);

    const mapEl = _el('div', 'map-container');
    mapEl.id = 'ti-hub-leaflet-map';
    mapCard.appendChild(mapEl);

    // Sidebar: top countries table
    const sideCard = _el('div', 'section-card');
    layout.appendChild(sideCard);

    const sideHdr = _el('div', 'section-card-header');
    sideHdr.innerHTML = `<span class="section-card-title">Top Countries</span>`;
    sideCard.appendChild(sideHdr);

    const sideBody = _el('div', 'section-card-body');
    sideBody.id = 'map-side-list';
    sideCard.appendChild(sideBody);

    // Render map after DOM is ready
    requestAnimationFrame(() => {
      _initMap(mapEl, victims);
      _renderSideList(sideBody, victims);
    });

    // Wire group filter
    const groupFilter = document.getElementById('map-group-filter');
    if (groupFilter) {
      groupFilter.addEventListener('change', () => {
        const filtered = groupFilter.value
          ? victims.filter(v => v.group === groupFilter.value)
          : victims;
        _updateMap(filtered);
        _renderSideList(sideBody, filtered);
      });
    }
  }

  // ── Map setup ───────────────────────────────────────────────────────────

  function _initMap(mapEl, victims) {
    if (!window.L) {
      mapEl.innerHTML = '<p style="padding:40px;color:var(--text-muted);text-align:center">Leaflet not loaded</p>';
      return;
    }

    if (_mapInstance) {
      _mapInstance.remove();
      _mapInstance = null;
    }

    const map = L.map(mapEl, {
      center: [20, 10],
      zoom: 2,
      minZoom: 1,
      maxZoom: 8,
      zoomControl: true,
      attributionControl: false,
    });

    _mapInstance = map;

    // Tile layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '© OpenStreetMap',
    }).addTo(map);

    L.control.attribution({ prefix: '© <a href="https://openstreetmap.org">OSM</a>' }).addTo(map);

    // Legend control
    const legend = L.control({ position: 'bottomleft' });
    legend.onAdd = () => {
      const div = L.DomUtil.create('div', 'map-legend');
      div.innerHTML = `
        <div class="map-legend-title">Victims by Country</div>
        ${[['1–10','#fba4a4'],['11–50','#f56060'],['51–200','#ef2020'],['200+','#8b0000']].map(([l,c]) =>
          `<div class="map-legend-item"><div class="map-legend-color" style="background:${c}"></div><span>${l}</span></div>`
        ).join('')}`;
      return div;
    };
    legend.addTo(map);

    _updateMap(victims);
  }

  let _markerLayer = null;

  function _updateMap(victims) {
    if (!_mapInstance || !window.L) return;

    const counts = _buildCounts(victims);

    if (_markerLayer) {
      _mapInstance.removeLayer(_markerLayer);
      _markerLayer = null;
    }

    const markers = [];
    for (const [iso, count] of Object.entries(counts)) {
      const centroid = CENTROIDS[iso.toUpperCase()];
      if (!centroid) continue;

      const color = _countColor(count);
      const radius = Math.max(6, Math.min(40, 6 + Math.sqrt(count) * 3));

      const circle = L.circleMarker(centroid, {
        radius,
        fillColor: color,
        color: '#fff',
        weight: 1.5,
        opacity: 0.9,
        fillOpacity: 0.75,
      });

      circle.bindTooltip(
        `<div class="map-tooltip">
          <div class="country-name">${Security.escapeHtml(iso)}</div>
          <div class="victim-count">${count.toLocaleString()} victim${count !== 1 ? 's' : ''}</div>
         </div>`,
        { sticky: true, className: '', direction: 'top', opacity: 1 }
      );

      markers.push(circle);
    }

    _markerLayer = L.layerGroup(markers).addTo(_mapInstance);
  }

  // ── Side list ───────────────────────────────────────────────────────────

  function _renderSideList(container, victims) {
    const counts = _buildCounts(victims);
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 20);
    const max    = sorted[0]?.[1] || 1;

    container.innerHTML = '';
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:8px;';

    sorted.forEach(([country, count]) => {
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:11px;font-weight:700;min-width:32px;font-family:var(--font-mono);color:var(--text-secondary)">${Security.escapeHtml(country)}</span>
        <div style="flex:1;height:18px;background:var(--bg-surface-3);border-radius:4px;overflow:hidden;">
          <div style="height:100%;width:${(count/max*100).toFixed(1)}%;background:${_countColor(count)};opacity:.8;border-radius:4px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:36px;text-align:right;color:var(--text-primary)">${count.toLocaleString()}</span>`;
      list.appendChild(row);
    });

    container.appendChild(list);
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  function _buildCounts(victims) {
    const counts = {};
    for (const v of victims) {
      const c = (v.country || '').toUpperCase().trim();
      if (c && c.length === 2) counts[c] = (counts[c] || 0) + 1;
    }
    return counts;
  }

  function _countColor(n) {
    if (n <= 10)  return '#fba4a4';
    if (n <= 50)  return '#f56060';
    if (n <= 200) return '#ef2020';
    return '#8b0000';
  }

  function _countryCount(victims) {
    return new Set(victims.map(v => v.country).filter(Boolean)).size;
  }

  function _groupOptions(groups) {
    return groups
      .sort((a, b) => (b.victim_count || 0) - (a.victim_count || 0))
      .slice(0, 40)
      .map(g => `<option value="${Security.escapeHtml(g.name)}">${Security.escapeHtml(g.name)}</option>`)
      .join('');
  }

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  return { render };
})();

export default MapView;
