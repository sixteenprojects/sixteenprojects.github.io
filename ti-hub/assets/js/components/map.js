/**
 * map.js — Comprehensive Threat Intelligence Geo Map
 * CartoDB Dark Matter · GeoJSON choropleth · bubble markers · rich tooltips
 * Group/year filters · time animation · country detail panel · live KPIs
 */
import Security from '../security.js';

const MapView = (() => {
  'use strict';

  // ── Module state ───────────────────────────────────────────────────────────
  let _map = null, _geoLayer = null, _bubbleLayer = null, _geoData = null;
  let _allVictims = [], _filteredVictims = [];
  let _filters = { group: '', year: '' };
  let _mode = 'choropleth'; // 'choropleth' | 'bubbles' | 'both'
  let _playing = false, _playTimer = null, _years = [];
  let _countryRank = {}, _selectedIso = null;

  // ── Country display names ──────────────────────────────────────────────────
  const NAMES = {
    US:'United States',GB:'United Kingdom',DE:'Germany',FR:'France',CA:'Canada',
    AU:'Australia',IT:'Italy',ES:'Spain',NL:'Netherlands',PL:'Poland',
    BR:'Brazil',IN:'India',JP:'Japan',RU:'Russia',CN:'China',MX:'Mexico',
    AR:'Argentina',ZA:'South Africa',KR:'South Korea',TW:'Taiwan',SE:'Sweden',
    NO:'Norway',DK:'Denmark',FI:'Finland',CH:'Switzerland',AT:'Austria',
    BE:'Belgium',PT:'Portugal',GR:'Greece',CZ:'Czech Republic',HU:'Hungary',
    RO:'Romania',SG:'Singapore',HK:'Hong Kong',TH:'Thailand',ID:'Indonesia',
    MY:'Malaysia',PH:'Philippines',VN:'Vietnam',TR:'Turkey',IL:'Israel',
    SA:'Saudi Arabia',AE:'UAE',QA:'Qatar',KW:'Kuwait',NG:'Nigeria',EG:'Egypt',
    KE:'Kenya',ZW:'Zimbabwe',GH:'Ghana',UA:'Ukraine',PK:'Pakistan',
    BD:'Bangladesh',NZ:'New Zealand',CO:'Colombia',CL:'Chile',PE:'Peru',
    VE:'Venezuela',EC:'Ecuador',MA:'Morocco',DZ:'Algeria',TN:'Tunisia',
    LY:'Libya',IQ:'Iraq',SY:'Syria',LB:'Lebanon',JO:'Jordan',SK:'Slovakia',
    SI:'Slovenia',HR:'Croatia',RS:'Serbia',BG:'Bulgaria',BA:'Bosnia',
    LT:'Lithuania',LV:'Latvia',EE:'Estonia',CY:'Cyprus',LK:'Sri Lanka',
    MM:'Myanmar',KH:'Cambodia',LA:'Laos',IR:'Iran',KZ:'Kazakhstan',
    UZ:'Uzbekistan',KG:'Kyrgyzstan',TJ:'Tajikistan',TM:'Turkmenistan',
    AM:'Armenia',AZ:'Azerbaijan',GE:'Georgia',MD:'Moldova',BY:'Belarus',
    MK:'North Macedonia',AL:'Albania',ME:'Montenegro',XK:'Kosovo',
    AF:'Afghanistan',NP:'Nepal',PG:'Papua New Guinea',FJ:'Fiji',BN:'Brunei',
    BT:'Bhutan',GA:'Gabon',BO:'Bolivia',PY:'Paraguay',UY:'Uruguay',
    CR:'Costa Rica',GT:'Guatemala',PA:'Panama',CU:'Cuba',DO:'Dominican Rep.',
    HT:'Haiti',JM:'Jamaica',TT:'Trinidad & Tobago',SD:'Sudan',ET:'Ethiopia',
    TZ:'Tanzania',UG:'Uganda',RW:'Rwanda',AO:'Angola',MZ:'Mozambique',
    ZM:'Zambia',MW:'Malawi',NA:'Namibia',BW:'Botswana',SN:'Senegal',
    ML:'Mali',GN:'Guinea',CM:'Cameroon',SO:'Somalia',MG:'Madagascar',
    CD:'DR Congo',CG:'Congo',CF:'Central African Rep.',TD:'Chad',NE:'Niger',
    MR:'Mauritania',BJ:'Benin',TG:'Togo',BF:'Burkina Faso',SL:'Sierra Leone',
    LR:'Liberia',CI:"Côte d'Ivoire",GW:'Guinea-Bissau',GM:'Gambia',
    ER:'Eritrea',DJ:'Djibouti',SS:'South Sudan',GQ:'Equatorial Guinea',
    PS:'Palestine',TL:'East Timor',SZ:'Eswatini',LS:'Lesotho',
    KP:'North Korea',NC:'New Caledonia',BS:'Bahamas',GY:'Guyana',SR:'Suriname',
  };

  // ── Country centroids [lat, lng] ───────────────────────────────────────────
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
    IR:[32.4,53.7],KZ:[48.0,68.0],BY:[53.7,28.0],GE:[42.3,43.4],
    AM:[40.1,45.0],AZ:[40.1,47.6],UZ:[41.3,64.6],KG:[41.2,74.8],
    TJ:[38.9,71.3],TM:[39.0,58.4],AF:[33.9,67.7],MM:[19.2,96.6],
    KH:[12.6,104.9],LA:[18.0,102.5],NP:[28.4,84.1],MK:[41.6,21.7],
    AL:[41.2,20.2],ME:[42.7,19.4],DO:[18.7,-70.2],HT:[18.9,-72.7],
    JM:[18.1,-77.3],TT:[10.7,-61.2],CM:[5.7,12.7],SN:[14.5,-14.5],
    CI:[7.5,-5.6],NG:[9.1,8.7],KE:[-0.0,37.9],UG:[1.4,32.3],
    ZA:[-29.0,25.1],MZ:[-18.7,35.5],ZM:[-13.1,27.8],AO:[-11.2,17.9],
    SO:[5.2,45.3],MG:[-20.2,46.7],ML:[12.7,-3.0],NE:[16.0,7.9],
    TD:[15.5,18.7],CF:[6.6,20.9],CD:[-4.0,21.8],CG:[-0.2,15.8],
    GA:[-0.8,11.6],GN:[11.0,-10.9],SL:[8.5,-11.8],LR:[6.5,-9.4],
    BJ:[9.3,2.3],TG:[8.6,0.8],BF:[12.4,-1.6],GW:[12.0,-15.2],GM:[13.4,-15.3],
    ER:[15.2,39.8],DJ:[11.8,42.6],SS:[6.9,31.3],GQ:[1.7,10.3],
    PS:[31.9,35.2],TL:[-8.9,125.7],SZ:[-26.5,31.5],LS:[-29.6,28.2],
    KP:[40.3,127.5],BS:[25.0,-77.4],GY:[4.9,-59.0],SR:[3.9,-56.0],
    BN:[4.5,114.7],BT:[27.5,90.4],PG:[-6.3,143.9],
  };

  // ── Color scale ────────────────────────────────────────────────────────────
  function _color(n) {
    if (!n)       return '#1a2035';
    if (n <= 5)   return '#3d1515';
    if (n <= 20)  return '#6b1c1c';
    if (n <= 50)  return '#8b2020';
    if (n <= 100) return '#b52424';
    if (n <= 200) return '#d93030';
    if (n <= 500) return '#ef4444';
    return '#ff2222';
  }

  // ── render (entry point) ───────────────────────────────────────────────────
  async function render(container, data) {
    _allVictims = data.victims || [];
    _filteredVictims = [..._allVictims];
    _years = _getYears(_allVictims);
    _filters = { group: '', year: '' };
    _mode = 'choropleth';
    _selectedIso = null;
    _playing = false;
    clearTimeout(_playTimer);

    container.innerHTML = `<div class="map-page" id="map-page">
      ${_buildTopbar()}
      <div id="ti-map-el" class="map-canvas"></div>
      ${_buildSidePanel()}
      ${_buildLegend()}
      ${_buildKPIStrip()}
    </div>`;

    _populateSelects(data.ransomware || []);

    // Init map after DOM is painted
    requestAnimationFrame(async () => {
      _initLeaflet();
      if (_map) {
        _geoData = await _loadGeo();
        _renderAll();
        _wireEvents();
      }
    });
  }

  // ── HTML builders ──────────────────────────────────────────────────────────

  function _buildTopbar() {
    return `
    <div class="map-topbar" id="map-topbar">
      <div class="map-topbar-left">
        <svg class="map-topbar-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <circle cx="12" cy="12" r="10"/>
          <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
        </svg>
        <span class="map-topbar-title">Threat Intelligence Map</span>
        <span class="map-topbar-badge" id="map-year-badge" style="display:none"></span>
      </div>
      <div class="map-topbar-right">
        <select id="mf-group" class="map-select" title="Filter by ransomware group">
          <option value="">All Groups</option>
        </select>
        <select id="mf-year" class="map-select" title="Filter by year">
          <option value="">All Years</option>
        </select>
        <div class="map-mode-tabs" id="map-mode-tabs">
          <button class="map-tab active" data-mode="choropleth">Countries</button>
          <button class="map-tab" data-mode="bubbles">Hotspots</button>
          <button class="map-tab" data-mode="both">Both</button>
        </div>
        <button id="map-play-btn" class="map-action-btn" title="Animate through years">
          <svg viewBox="0 0 24 24" fill="currentColor" width="11" height="11"><polygon points="5,3 19,12 5,21"/></svg>
          <span>Play</span>
        </button>
        <button id="map-home-btn" class="map-action-btn" title="Reset zoom">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" width="13" height="13">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
            <polyline points="9 22 9 12 15 12 15 22"/>
          </svg>
        </button>
      </div>
    </div>`;
  }

  function _buildKPIStrip() {
    return `
    <div class="map-kpi-strip" id="map-kpi-strip">
      <div class="map-kpi">
        <span class="map-kpi-val danger" id="kpi-victims">—</span>
        <span class="map-kpi-label">Victims</span>
      </div>
      <div class="map-kpi-divider"></div>
      <div class="map-kpi">
        <span class="map-kpi-val" id="kpi-countries">—</span>
        <span class="map-kpi-label">Countries</span>
      </div>
      <div class="map-kpi-divider"></div>
      <div class="map-kpi">
        <span class="map-kpi-val" id="kpi-groups">—</span>
        <span class="map-kpi-label">Groups</span>
      </div>
      <div class="map-kpi-divider"></div>
      <div class="map-kpi">
        <span class="map-kpi-val warning" id="kpi-top">—</span>
        <span class="map-kpi-label">Most Hit</span>
      </div>
    </div>`;
  }

  function _buildLegend() {
    const steps = [
      ['No data', '#1a2035'],['1–5','#3d1515'],['6–20','#6b1c1c'],
      ['21–50','#8b2020'],['51–100','#b52424'],['101–200','#d93030'],['200+','#ef4444'],
    ];
    return `
    <div class="map-legend" id="map-legend">
      <div class="map-legend-head">Victim Count</div>
      ${steps.map(([l,c]) => `
        <div class="map-legend-row">
          <span class="map-legend-dot" style="background:${c}"></span>
          <span class="map-legend-lbl">${l}</span>
        </div>`).join('')}
      <div class="map-legend-src">
        <span>Source: ransomware.live</span>
      </div>
    </div>`;
  }

  function _buildSidePanel() {
    return `
    <div class="map-panel hidden" id="map-panel">
      <div class="map-panel-header">
        <span class="map-panel-title" id="map-panel-title">Country</span>
        <button class="map-panel-close" id="map-panel-close" title="Close">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="map-panel-body" id="map-panel-body">
        <p class="map-panel-empty">Select a country on the map</p>
      </div>
    </div>`;
  }

  // ── Leaflet init ───────────────────────────────────────────────────────────

  function _initLeaflet() {
    if (_map) {
      try { _map.remove(); } catch (e) { /* ignore */ }
      _map = null; _geoLayer = null; _bubbleLayer = null;
    }

    const el = document.getElementById('ti-map-el');
    if (!el || !window.L) return;

    // Explicitly set container height via JS (avoids CSS positioning race)
    const headerH = 56;
    el.style.width  = '100%';
    el.style.height = (window.innerHeight - headerH) + 'px';

    _map = L.map(el, {
      center: [20, 10], zoom: 2,
      minZoom: 1, maxZoom: 8,
      zoomControl: false,
      attributionControl: false,
      preferCanvas: true,
    });

    // CartoDB Dark Matter tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 20,
    }).addTo(_map);

    L.control.zoom({ position: 'bottomright' }).addTo(_map);
    L.control.attribution({ prefix: false, position: 'bottomright' }).addTo(_map);

    // Resize map when window resizes
    window.addEventListener('resize', () => {
      if (_map && el) {
        el.style.height = (window.innerHeight - headerH) + 'px';
        _map.invalidateSize();
      }
    });

    _map.invalidateSize();
  }

  async function _loadGeo() {
    try {
      const resp = await fetch('./data/geo.json');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      console.warn('[MapView] Failed to load geo.json:', e);
      return null;
    }
  }

  // ── Layer rendering ────────────────────────────────────────────────────────

  function _renderAll() {
    const counts = _buildCounts(_filteredVictims);
    _buildRanks(counts);

    // Remove stale layers based on mode
    if (_mode === 'bubbles' && _geoLayer)      { _map.removeLayer(_geoLayer);    _geoLayer = null; }
    if (_mode === 'choropleth' && _bubbleLayer) { _map.removeLayer(_bubbleLayer); _bubbleLayer = null; }

    if (_mode !== 'bubbles')    _renderChoropleth(counts);
    // Always show bubbles if no geo data (fallback) OR when mode includes bubbles
    if (_mode !== 'choropleth' || !_geoData)   _renderBubbles(counts);

    _updateKPIs(counts);
    if (_map) _map.invalidateSize();
  }

  function _renderChoropleth(counts) {
    if (_geoLayer) { _map.removeLayer(_geoLayer); _geoLayer = null; }
    if (!_geoData || !_map) return;

    _geoLayer = L.geoJSON(_geoData, {
      style: feat => {
        const iso = (feat.properties?.iso || '').toUpperCase();
        const n = counts[iso] || 0;
        return {
          fillColor: _color(n),
          fillOpacity: n ? 0.82 : 0.18,
          color: '#1b2540',
          weight: 0.7,
          opacity: 0.85,
        };
      },
      onEachFeature: (feat, layer) => {
        const iso = (feat.properties?.iso || '').toUpperCase();
        const name = feat.properties?.name || NAMES[iso] || iso;
        const n = counts[iso] || 0;

        layer.bindTooltip(
          _tooltipHTML(iso, name, n, counts),
          { sticky: true, className: 'map-tt', direction: 'top', opacity: 1, offset: [0, -4] }
        );

        layer.on({
          mouseover: e => {
            if (n > 0) e.target.setStyle({ fillOpacity: 1, weight: 1.8, color: '#4a6fa5' });
            e.target.bringToFront();
          },
          mouseout: e => {
            if (_geoLayer) _geoLayer.resetStyle(e.target);
          },
          click: () => _openPanel(iso, name, counts),
        });
      },
    }).addTo(_map);
  }

  function _renderBubbles(counts) {
    if (_bubbleLayer) { _map.removeLayer(_bubbleLayer); _bubbleLayer = null; }
    if (!_map) return;

    // Render smallest first so large bubbles appear on top
    const sorted = Object.entries(counts)
      .filter(([iso]) => CENTROIDS[iso])
      .sort((a, b) => a[1] - b[1]);

    const layers = [];
    for (const [iso, n] of sorted) {
      const c = CENTROIDS[iso];
      const name = NAMES[iso] || iso;
      const r = Math.max(4, Math.min(58, 4 + Math.sqrt(n) * 2.6));
      const col = _color(n);

      // Glow halo
      layers.push(L.circleMarker(c, {
        radius: r * 1.6,
        fillColor: col, color: 'transparent',
        fillOpacity: 0.1, interactive: false,
        className: 'map-halo',
      }));

      // Core bubble
      const bubble = L.circleMarker(c, {
        radius: r,
        fillColor: col,
        color: 'rgba(255,255,255,0.2)',
        weight: 1,
        fillOpacity: 0.88,
        className: 'map-bubble',
      });

      bubble.bindTooltip(
        _tooltipHTML(iso, name, n, counts),
        { sticky: true, className: 'map-tt', direction: 'top', opacity: 1 }
      );
      bubble.on({
        mouseover: e => { e.target.setStyle({ fillOpacity: 1, color: 'rgba(255,255,255,0.7)', weight: 1.5 }); e.target.bringToFront(); },
        mouseout:  e => { e.target.setStyle({ fillOpacity: 0.88, color: 'rgba(255,255,255,0.2)', weight: 1 }); },
        click: () => _openPanel(iso, name, counts),
      });
      layers.push(bubble);
    }

    _bubbleLayer = L.layerGroup(layers).addTo(_map);
  }

  // ── Tooltip ────────────────────────────────────────────────────────────────

  function _tooltipHTML(iso, name, n, counts) {
    const esc = Security.escapeHtml;
    if (!n) return `<div class="map-tt-inner"><span class="map-tt-name">${esc(name)}</span><span class="map-tt-zero">No victims recorded</span></div>`;

    const total = Object.values(counts).reduce((s, v) => s + v, 0);
    const pct = total ? ((n / total) * 100).toFixed(1) : '0';
    const rank = _countryRank[iso] || '—';
    const top = _topGroup(iso);
    const flag = _flag(iso);

    return `
    <div class="map-tt-inner">
      <div class="map-tt-head">
        <span class="map-tt-flag">${flag}</span>
        <span class="map-tt-name">${esc(name)}</span>
        <span class="map-tt-rank">#${rank}</span>
      </div>
      <div class="map-tt-rows">
        <div class="map-tt-row"><span>Victims</span><strong class="danger">${n.toLocaleString()}</strong></div>
        <div class="map-tt-row"><span>Global share</span><strong>${pct}%</strong></div>
        ${top ? `<div class="map-tt-row"><span>Top group</span><strong>${esc(_fmt(top))}</strong></div>` : ''}
      </div>
    </div>`;
  }

  // ── Country detail panel ───────────────────────────────────────────────────

  function _openPanel(iso, name, counts) {
    _selectedIso = iso;
    const panel = document.getElementById('map-panel');
    const title = document.getElementById('map-panel-title');
    const body  = document.getElementById('map-panel-body');
    if (!panel) return;

    const flag = _flag(iso);
    const n = counts[iso] || 0;
    const rank = _countryRank[iso] || '?';

    title.innerHTML = `${flag} ${Security.escapeHtml(name)}`;

    const victimsForCountry = _filteredVictims.filter(v => (v.country || '').toUpperCase() === iso);

    // Group breakdown
    const byGroup = {};
    for (const v of victimsForCountry) byGroup[v.group] = (byGroup[v.group] || 0) + 1;
    const topGroups = Object.entries(byGroup).sort((a,b)=>b[1]-a[1]).slice(0, 6);

    // Sector breakdown
    const bySector = {};
    for (const v of victimsForCountry) {
      const s = v.sector || 'Unknown';
      bySector[s] = (bySector[s] || 0) + 1;
    }
    const topSectors = Object.entries(bySector).sort((a,b)=>b[1]-a[1]).slice(0, 5);

    // Recent victims
    const recent = [...victimsForCountry]
      .sort((a,b) => (b.attack_date||'').localeCompare(a.attack_date||''))
      .slice(0, 12);

    body.innerHTML = `
      <div class="panel-hero">
        <div class="panel-stat">
          <span class="panel-stat-val danger">${n.toLocaleString()}</span>
          <span class="panel-stat-lbl">Victims</span>
        </div>
        <div class="panel-stat">
          <span class="panel-stat-val">#${rank}</span>
          <span class="panel-stat-lbl">Global Rank</span>
        </div>
      </div>

      ${topGroups.length ? `
      <div class="panel-section">
        <div class="panel-sec-title">Top Attacking Groups</div>
        ${topGroups.map(([g,c],i) => `
        <div class="panel-bar-row" ${i===0?'style="margin-bottom:6px"':''}>
          <span class="panel-bar-name">${Security.escapeHtml(_fmt(g))}</span>
          <div class="panel-bar-track">
            <div class="panel-bar-fill" style="width:${Math.round(c/topGroups[0][1]*100)}%"></div>
          </div>
          <span class="panel-bar-count">${c.toLocaleString()}</span>
        </div>`).join('')}
      </div>` : ''}

      ${topSectors.length ? `
      <div class="panel-section">
        <div class="panel-sec-title">Top Sectors</div>
        ${topSectors.map(([s,c]) => `
        <div class="panel-bar-row">
          <span class="panel-bar-name">${Security.escapeHtml(s)}</span>
          <div class="panel-bar-track">
            <div class="panel-bar-fill sector" style="width:${Math.round(c/topSectors[0][1]*100)}%"></div>
          </div>
          <span class="panel-bar-count">${c.toLocaleString()}</span>
        </div>`).join('')}
      </div>` : ''}

      <div class="panel-section">
        <div class="panel-sec-title">Recent Victims
          <span class="panel-sec-meta">(${recent.length} of ${n.toLocaleString()})</span>
        </div>
        ${recent.map(v => `
        <div class="panel-victim">
          <div class="panel-victim-name">${Security.escapeHtml(v.victim || '—')}</div>
          <div class="panel-victim-meta">
            <span class="panel-victim-group">${Security.escapeHtml(_fmt(v.group || ''))}</span>
            ${v.attack_date ? `<span class="panel-victim-date">${v.attack_date.slice(0,10)}</span>` : ''}
          </div>
        </div>`).join('')}
      </div>`;

    panel.classList.remove('hidden');
    panel.classList.add('open');
  }

  // ── KPI strip ──────────────────────────────────────────────────────────────

  function _updateKPIs(counts) {
    const total    = _filteredVictims.length;
    const nCtry    = Object.values(counts).filter(v => v > 0).length;
    const nGroups  = new Set(_filteredVictims.map(v => v.group).filter(Boolean)).size;
    const topEntry = Object.entries(counts).sort((a,b) => b[1]-a[1])[0];
    const topName  = topEntry ? (NAMES[topEntry[0]] || topEntry[0]) : '—';

    const s = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    s('kpi-victims',   total.toLocaleString());
    s('kpi-countries', nCtry.toLocaleString());
    s('kpi-groups',    nGroups.toLocaleString());
    s('kpi-top',       topName);
  }

  // ── Filtering ──────────────────────────────────────────────────────────────

  function _applyFilters() {
    _filteredVictims = _allVictims.filter(v => {
      if (_filters.group && v.group !== _filters.group) return false;
      if (_filters.year) {
        const d = v.attack_date || v.discovered || '';
        if (!d.startsWith(_filters.year)) return false;
      }
      return true;
    });
    _renderAll();

    // Refresh open panel with new filtered data
    if (_selectedIso && !document.getElementById('map-panel')?.classList.contains('hidden')) {
      const name = NAMES[_selectedIso] || _selectedIso;
      _openPanel(_selectedIso, name, _buildCounts(_filteredVictims));
    }
  }

  // ── Time animation ─────────────────────────────────────────────────────────

  function _startPlay() {
    if (!_years.length) return;
    _playing = true;
    _setPlayBtn(true);

    const sel = document.getElementById('mf-year');
    let idx = 0;

    const step = () => {
      if (!_playing) return;
      const yr = _years[idx];

      if (sel) sel.value = yr;
      _filters.year = yr;

      const badge = document.getElementById('map-year-badge');
      if (badge) { badge.textContent = yr; badge.style.display = 'inline-flex'; }

      _applyFilters();
      idx++;
      if (idx >= _years.length) { _stopPlay(); return; }
      _playTimer = setTimeout(step, 1400);
    };
    step();
  }

  function _stopPlay() {
    _playing = false;
    clearTimeout(_playTimer);
    _setPlayBtn(false);
  }

  function _setPlayBtn(playing) {
    const btn = document.getElementById('map-play-btn');
    if (!btn) return;
    if (playing) {
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="currentColor" width="11" height="11"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg><span>Pause</span>`;
    } else {
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="currentColor" width="11" height="11"><polygon points="5,3 19,12 5,21"/></svg><span>Play</span>`;
    }
  }

  // ── Event wiring ───────────────────────────────────────────────────────────

  function _wireEvents() {
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };

    on('mf-group', 'change', e => { _filters.group = e.target.value; _applyFilters(); });
    on('mf-year',  'change', e => {
      _filters.year = e.target.value;
      const badge = document.getElementById('map-year-badge');
      if (badge) {
        badge.textContent = e.target.value;
        badge.style.display = e.target.value ? 'inline-flex' : 'none';
      }
      _applyFilters();
    });

    on('map-play-btn', 'click', () => { if (_playing) _stopPlay(); else _startPlay(); });
    on('map-home-btn', 'click', () => { if (_map) _map.setView([20, 10], 2, { animate: true }); });

    on('map-panel-close', 'click', () => {
      const panel = document.getElementById('map-panel');
      if (panel) { panel.classList.remove('open'); panel.classList.add('hidden'); }
      _selectedIso = null;
    });

    document.querySelectorAll('#map-mode-tabs .map-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#map-mode-tabs .map-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        _mode = btn.dataset.mode;
        _renderAll();
      });
    });
  }

  // ── Populate selects ───────────────────────────────────────────────────────

  function _populateSelects(groups) {
    const gsel = document.getElementById('mf-group');
    if (gsel) {
      const sorted = [...groups]
        .filter(g => g.name && g.name.toLowerCase() !== 'unknown')
        .sort((a, b) => (b.victim_count || 0) - (a.victim_count || 0))
        .slice(0, 60);
      for (const g of sorted) {
        const opt = document.createElement('option');
        opt.value = g.name || g.id;
        opt.textContent = _fmt(g.name || g.id);
        gsel.appendChild(opt);
      }
    }

    const ysel = document.getElementById('mf-year');
    if (ysel) {
      for (const yr of [..._years].reverse()) {
        const opt = document.createElement('option');
        opt.value = yr; opt.textContent = yr;
        ysel.appendChild(opt);
      }
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function _buildCounts(victims) {
    const c = {};
    for (const v of victims) {
      const iso = (v.country || '').toUpperCase().trim();
      if (iso && iso.length === 2 && iso !== '??') c[iso] = (c[iso] || 0) + 1;
    }
    return c;
  }

  function _buildRanks(counts) {
    _countryRank = {};
    Object.entries(counts).sort((a,b) => b[1]-a[1]).forEach(([iso], i) => {
      _countryRank[iso] = i + 1;
    });
  }

  function _topGroup(iso) {
    const m = {};
    for (const v of _filteredVictims) {
      if ((v.country || '').toUpperCase() !== iso) continue;
      m[v.group] = (m[v.group] || 0) + 1;
    }
    return Object.entries(m).sort((a,b) => b[1]-a[1])[0]?.[0] || '';
  }

  function _getYears(victims) {
    const s = new Set();
    for (const v of victims) {
      const d = v.attack_date || v.discovered || '';
      if (d.length >= 4) s.add(d.slice(0, 4));
    }
    return [...s].sort();
  }

  function _flag(iso) {
    if (!iso || iso.length !== 2) return '🌐';
    try {
      return String.fromCodePoint(
        0x1F1E6 + iso.toUpperCase().charCodeAt(0) - 65,
        0x1F1E6 + iso.toUpperCase().charCodeAt(1) - 65,
      );
    } catch { return '🌐'; }
  }

  function _fmt(name) {
    if (!name) return '—';
    return name
      .replace(/([a-z])([A-Z0-9])/g, '$1 $2')
      .replace(/(^|[\s-])([a-z])/g, (_, s, c) => (s || '') + c.toUpperCase())
      .replace(/-/g, ' ');
  }

  return { render };
})();

export default MapView;
