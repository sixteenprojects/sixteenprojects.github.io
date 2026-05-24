/**
 * stats.js — Comprehensive Statistics view.
 * Shows: overview KPIs, victims timeline, sector breakdown, country heatmap,
 * top groups, infostealer analysis, year-over-year comparison, RansomLook stats.
 */

import Security from '../security.js';

const StatsView = (() => {
  'use strict';

  const SECTOR_COLORS = [
    '#1a6fff','#3b82f6','#0891b2','#2563eb','#4f46e5',
    '#7c3aed','#db2777','#e11d48','#ea580c','#d97706',
  ];
  const COUNTRY_NAMES = {
    US:'United States', GB:'United Kingdom', DE:'Germany', FR:'France', CA:'Canada',
    AU:'Australia', IT:'Italy', ES:'Spain', NL:'Netherlands', BR:'Brazil',
    IN:'India', JP:'Japan', RU:'Russia', CN:'China', MX:'Mexico',
    SE:'Sweden', CH:'Switzerland', BE:'Belgium', PL:'Poland', ZA:'South Africa',
    SG:'Singapore', HK:'Hong Kong', NO:'Norway', DK:'Denmark', FI:'Finland',
    AT:'Austria', PT:'Portugal', TR:'Turkey', KR:'South Korea', TW:'Taiwan',
  };

  function render(container, data) {
    const stats = data.stats || {};
    const victims = data.victims || [];
    const ransomware = data.ransomware || [];
    const recent = data.recent || [];

    container.innerHTML = '';

    // Page header
    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Global Ransomware Statistics</h1>
          <p class="page-subtitle">Aggregated from Ransomware.live · RansomLook · ${victims.length.toLocaleString()} recorded attacks</p>
        </div>
      </div>`;
    container.appendChild(hdr);

    // Use pre-computed stats if available, otherwise compute from victims
    const ov = stats.overview || _computeOverview(victims, ransomware);
    const sectors = stats.sectors || _computeSectors(victims);
    const countries = stats.countries || _computeCountries(victims);
    const monthly = stats.monthly || _computeMonthly(victims);
    const yearly = stats.yearly || _computeYearly(victims);
    const topGroups = stats.top_groups || _computeTopGroups(ransomware);
    const infostealerStats = stats.infostealer || _computeInfostealer(victims);
    const rlStats = stats.ransomlook || {};

    // ── Hero KPI row ──
    container.appendChild(_buildHeroKPIs(ov, rlStats));

    // ── Full-width timeline ──
    container.appendChild(_buildTimeline(monthly, yearly));

    // ── Mid row: Sectors + Countries ──
    const midRow = _el('div', 'grid-2');
    midRow.style.marginBottom = 'var(--space-4)';
    midRow.appendChild(_buildSectors(sectors));
    midRow.appendChild(_buildCountries(countries));
    container.appendChild(midRow);

    // ── Lower row: Top Groups + Infostealer ──
    const lowerRow = _el('div', 'grid-2');
    lowerRow.style.marginBottom = 'var(--space-4)';
    lowerRow.appendChild(_buildTopGroups(topGroups));
    lowerRow.appendChild(_buildInfostealer(infostealerStats));
    container.appendChild(lowerRow);

    // ── Year-over-year comparison ──
    container.appendChild(_buildYearlyComparison(yearly));

    // ── RansomLook live stats ──
    if (rlStats && rlStats.posts_total) container.appendChild(_buildRansomLookStats(rlStats));

    // ── Recent attacks feed ──
    const recentData = stats.recent_attacks || recent;
    if (recentData.length) container.appendChild(_buildRecentFeed(recentData.slice(0, 20)));
  }

  // ── Hero KPIs ─────────────────────────────────────────────────────────────

  function _buildHeroKPIs(ov, rlStats) {
    const grid = _el('div', 'stats-grid');
    grid.style.cssText = 'grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:var(--space-4);';

    const defs = [
      { label: 'Total Victims',     value: (ov.total_victims||0).toLocaleString(),      color:'red',    icon:_icoShield() },
      { label: 'Victims This Year', value: (ov.victims_this_year||0).toLocaleString(),   color:'yellow', icon:_icoCalendar() },
      { label: 'Victims This Month',value: (ov.victims_this_month||0).toLocaleString(),  color:'orange', icon:_icoClock() },
      { label: 'Countries Hit',     value: (ov.countries_hit||0).toLocaleString(),       color:'blue',   icon:_icoGlobe() },
      { label: 'Active Groups',     value: (ov.active_groups||0).toLocaleString(),       color:'cyan',   icon:_icoLock() },
      { label: 'With Infostealer',  value: (ov.victims_with_infostealer||0).toLocaleString(), color:'purple', icon:_icoEye() },
    ];

    for (const d of defs) {
      const card = _el('div', 'stat-card');
      card.innerHTML = `
        <div class="stat-card-icon ${d.color}">${d.icon}</div>
        <div class="stat-card-value" style="font-variant-numeric:tabular-nums">${Security.escapeHtml(d.value)}</div>
        <div class="stat-card-label">${Security.escapeHtml(d.label)}</div>`;
      grid.appendChild(card);
    }
    return grid;
  }

  // ── Timeline (monthly victims, full history) ───────────────────────────────

  function _buildTimeline(monthly, yearly) {
    const wrap = _sectionCard('Victims Over Time', _icoCalendar());
    const body = wrap.querySelector('.section-card-body');

    // Year selector tabs
    const allYears = Object.keys(yearly || {}).sort();
    const tabRow = _el('div');
    tabRow.style.cssText = 'display:flex;gap:4px;flex-wrap:wrap;padding:0 20px 12px;';

    let activeYear = 'All';
    const chartId = 'stats-timeline-chart';

    const chartDiv = _el('div');
    chartDiv.id = chartId;
    chartDiv.style.cssText = 'padding:4px 20px 4px;height:200px;';
    body.appendChild(chartDiv);

    function _renderChart(year) {
      const data = year === 'All'
        ? monthly
        : monthly.filter(m => m.month.startsWith(year));
      requestAnimationFrame(() => _drawTimelineChart(chartId, data));
    }

    const allTab = _tabBtn('All', true);
    allTab.addEventListener('click', () => {
      _setActiveTab(tabRow, allTab);
      _renderChart('All');
    });
    tabRow.appendChild(allTab);

    const recentYears = allYears.slice(-5);
    for (const y of recentYears) {
      const btn = _tabBtn(y, false);
      btn.addEventListener('click', () => {
        _setActiveTab(tabRow, btn);
        _renderChart(y);
      });
      tabRow.appendChild(btn);
    }

    body.insertBefore(tabRow, chartDiv);
    requestAnimationFrame(() => _renderChart('All'));
    return wrap;
  }

  function _drawTimelineChart(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el || !window.d3 || !data || !data.length) return;

    const rect = el.getBoundingClientRect();
    const W = rect.width || 700;
    const H = rect.height || 180;
    const margin = { top: 10, right: 16, bottom: 38, left: 44 };
    const iW = W - margin.left - margin.right;
    const iH = H - margin.top - margin.bottom;

    el.innerHTML = '';
    const svg = d3.select(el).append('svg').attr('width', W).attr('height', H);
    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    const style = getComputedStyle(document.documentElement);
    const accent  = style.getPropertyValue('--color-brand-accent').trim() || '#1a6fff';
    const danger  = style.getPropertyValue('--color-danger').trim() || '#ef4444';
    const muted   = style.getPropertyValue('--text-muted').trim() || '#9ca3af';
    const border  = style.getPropertyValue('--border-color').trim() || '#e5e7eb';

    const x = d3.scaleBand().domain(data.map(d => d.month)).range([0, iW]).padding(0.2);
    const maxVal = d3.max(data, d => d.count) || 1;
    const y = d3.scaleLinear().domain([0, maxVal * 1.1]).range([iH, 0]);

    // Grid
    g.append('g').call(d3.axisLeft(y).ticks(4).tickSize(-iW).tickFormat(d => d >= 1000 ? `${(d/1000).toFixed(0)}k` : d))
      .call(ax => {
        ax.select('.domain').remove();
        ax.selectAll('.tick line').attr('stroke', border).attr('stroke-dasharray', '3,3');
        ax.selectAll('.tick text').attr('fill', muted).attr('font-size', 10).attr('font-family', 'inherit');
      });

    // Gradient bars — colour by relative height
    const avgVal = d3.mean(data, d => d.count) || 1;
    g.selectAll('.bar').data(data).join('rect')
      .attr('class', 'bar')
      .attr('x', d => x(d.month))
      .attr('y', d => y(d.count))
      .attr('width', x.bandwidth())
      .attr('height', d => iH - y(d.count))
      .attr('fill', d => d.count > avgVal * 1.5 ? danger : accent)
      .attr('opacity', 0.82)
      .attr('rx', Math.min(x.bandwidth() / 3, 4))
      .on('mouseenter', function(e, d) {
        d3.select(this).attr('opacity', 1);
        _showTooltip(e, `${d.month}: ${d.count.toLocaleString()} victims`);
      })
      .on('mouseleave', function() { d3.select(this).attr('opacity', 0.82); _hideTooltip(); });

    // X axis (show every Nth label)
    const step = Math.ceil(data.length / 10);
    const visibleLabels = data.filter((_, i) => i % step === 0 || i === data.length - 1);
    g.append('g').attr('transform', `translate(0,${iH})`).call(
      d3.axisBottom(x)
        .tickValues(visibleLabels.map(d => d.month))
        .tickFormat(d => {
          const [yr, mo] = d.split('-');
          return `${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][+mo-1]} '${yr.slice(2)}`;
        })
    ).call(ax => {
      ax.select('.domain').remove();
      ax.selectAll('.tick line').remove();
      ax.selectAll('.tick text').attr('fill', muted).attr('font-size', 10).attr('font-family', 'inherit');
    });
  }

  // ── Sectors ───────────────────────────────────────────────────────────────

  function _buildSectors(sectors) {
    const wrap = _sectionCard('Top Targeted Sectors', _icoBusiness());
    const body = wrap.querySelector('.section-card-body');

    const entries = Object.entries(sectors).slice(0, 12);
    const max = entries[0]?.[1] || 1;
    const total = entries.reduce((s, [, v]) => s + v, 0);

    if (!entries.length) { body.innerHTML = '<p class="text-muted" style="padding:20px">No sector data.</p>'; return wrap; }

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:7px;';
    entries.forEach(([sector, count], i) => {
      const pct = (count / max * 100).toFixed(1);
      const share = total ? (count / total * 100).toFixed(1) : 0;
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="width:6px;height:6px;border-radius:50%;background:${SECTOR_COLORS[i % SECTOR_COLORS.length]};flex-shrink:0;"></span>
        <span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary)" title="${Security.escapeHtml(sector)}">${Security.escapeHtml(Security.truncate(sector, 24))}</span>
        <div style="width:90px;height:14px;background:var(--bg-surface-3);border-radius:3px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${pct}%;background:${SECTOR_COLORS[i % SECTOR_COLORS.length]};opacity:.85;border-radius:3px;transition:width .4s;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:46px;text-align:right;color:var(--text-primary)">${count.toLocaleString()}</span>
        <span style="font-size:10px;color:var(--text-muted);min-width:34px;text-align:right">${share}%</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── Countries ─────────────────────────────────────────────────────────────

  function _buildCountries(countries) {
    const wrap = _sectionCard('Most Targeted Countries', _icoGlobe());
    const body = wrap.querySelector('.section-card-body');

    const entries = Object.entries(countries).slice(0, 12);
    const max = entries[0]?.[1] || 1;

    if (!entries.length) { body.innerHTML = '<p class="text-muted" style="padding:20px">No country data.</p>'; return wrap; }

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:7px;';
    entries.forEach(([code, count]) => {
      const name = COUNTRY_NAMES[code] || code;
      const pct = (count / max * 100).toFixed(1);
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:12px;font-weight:800;min-width:26px;color:var(--text-muted);font-family:var(--font-mono)">${Security.escapeHtml(code)}</span>
        <span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary)">${Security.escapeHtml(name)}</span>
        <div style="width:90px;height:14px;background:var(--bg-surface-3);border-radius:3px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${pct}%;background:var(--color-danger);opacity:.75;border-radius:3px;transition:width .4s;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:46px;text-align:right;color:var(--text-primary)">${count.toLocaleString()}</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── Top Groups ───────────────────────────────────────────────────────────

  function _buildTopGroups(topGroups) {
    const wrap = _sectionCard('Top Ransomware Groups', _icoLock());
    const body = wrap.querySelector('.section-card-body');

    const sorted = topGroups.slice(0, 15);
    const max = sorted[0]?.count || sorted[0]?.victim_count || 1;

    if (!sorted.length) { body.innerHTML = '<p class="text-muted" style="padding:20px">No group data.</p>'; return wrap; }

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:7px;';
    sorted.forEach((g, i) => {
      const count = g.count || g.victim_count || 0;
      const isActive = g.status === 'active';
      const isRaas = g.is_raas;
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;cursor:pointer;';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:16px;text-align:right;font-weight:700">${i+1}</span>
        <span class="status-dot ${isActive?'active':'inactive'}" title="${isActive?'Active':'Inactive'}"></span>
        <span style="flex:1;font-size:12px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-primary)">${Security.escapeHtml(_fmtGroup(g.name||g.id))}</span>
        ${isRaas ? '<span class="badge badge-red" style="font-size:9px;flex-shrink:0">RaaS</span>' : ''}
        <div style="width:70px;height:14px;background:var(--bg-surface-3);border-radius:3px;overflow:hidden;flex-shrink:0;">
          <div style="height:100%;width:${(count/max*100).toFixed(1)}%;background:var(--color-warning);opacity:.85;border-radius:3px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:40px;text-align:right;color:var(--text-primary)">${count.toLocaleString()}</span>`;
      row.addEventListener('click', () => { window.location.hash = '#/ransomware'; });
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── Infostealer Analysis ──────────────────────────────────────────────────

  function _buildInfostealer(is) {
    const wrap = _sectionCard('Infostealer Analysis', _icoEye());
    const body = wrap.querySelector('.section-card-body');

    if (!is || !is.total) {
      body.innerHTML = '<p class="text-muted" style="padding:20px">No infostealer data.</p>';
      return wrap;
    }

    const pct = is.total ? ((is.with_stealer / is.total) * 100).toFixed(1) : 0;

    // Summary strip
    const strip = _el('div');
    strip.style.cssText = 'display:flex;gap:16px;padding:0 0 12px;flex-wrap:wrap;';
    [
      { label:'Victims w/ Data', value:(is.with_stealer||0).toLocaleString() },
      { label:'Coverage',        value:`${pct}%` },
      { label:'Employees Exposed',value:(is.total_employees||0).toLocaleString() },
      { label:'Users Exposed',   value:(is.total_users||0).toLocaleString() },
    ].forEach(d => {
      const item = _el('div');
      item.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
      item.innerHTML = `
        <span style="font-size:18px;font-weight:800;color:var(--text-primary);font-variant-numeric:tabular-nums">${Security.escapeHtml(d.value)}</span>
        <span style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em">${Security.escapeHtml(d.label)}</span>`;
      strip.appendChild(item);
    });
    body.appendChild(strip);

    // Stealer breakdown
    const stealers = Object.entries(is.stealers || {}).slice(0, 10);
    if (stealers.length) {
      const maxS = stealers[0][1] || 1;
      const lbl = _el('div');
      lbl.style.cssText = 'font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;';
      lbl.textContent = 'Top Stealers Used';
      body.appendChild(lbl);

      const list = _el('div');
      list.style.cssText = 'display:flex;flex-direction:column;gap:6px;';
      const stealerColors = ['#7c3aed','#6d28d9','#5b21b6','#4c1d95','#8b5cf6','#a78bfa','#c4b5fd','#ddd6fe','#7c3aed','#6d28d9'];
      stealers.forEach(([name, count], i) => {
        const row = _el('div');
        row.style.cssText = 'display:flex;align-items:center;gap:8px;';
        row.innerHTML = `
          <span style="width:6px;height:6px;border-radius:50%;background:${stealerColors[i]};flex-shrink:0;"></span>
          <span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary);font-family:var(--font-mono)">${Security.escapeHtml(Security.truncate(name, 20))}</span>
          <div style="width:80px;height:12px;background:var(--bg-surface-3);border-radius:3px;overflow:hidden;flex-shrink:0;">
            <div style="height:100%;width:${(count/maxS*100).toFixed(1)}%;background:${stealerColors[i]};border-radius:3px;"></div>
          </div>
          <span style="font-size:11px;font-weight:700;min-width:40px;text-align:right;color:var(--text-primary)">${Number(count).toLocaleString()}</span>`;
        list.appendChild(row);
      });
      body.appendChild(list);
    }
    return wrap;
  }

  // ── Year-over-year comparison ──────────────────────────────────────────────

  function _buildYearlyComparison(yearly) {
    const wrap = _sectionCard('Year-over-Year Victims', _icoCalendar());
    const body = wrap.querySelector('.section-card-body');

    const entries = Object.entries(yearly || {}).filter(([y]) => +y >= 2019).sort((a, b) => a[0] - b[0]);
    if (!entries.length) { return wrap; }

    const chartId = 'stats-yearly-chart';
    const chartDiv = _el('div');
    chartDiv.id = chartId;
    chartDiv.style.cssText = 'padding:4px 20px 4px;height:160px;';
    body.appendChild(chartDiv);

    // Growth badges
    const badges = _el('div');
    badges.style.cssText = 'display:flex;gap:12px;flex-wrap:wrap;padding:12px 0 0;';
    for (let i = 1; i < entries.length; i++) {
      const [yr, cnt] = entries[i];
      const prev = entries[i-1][1];
      const delta = prev ? ((cnt - prev) / prev * 100) : 0;
      const up = delta >= 0;
      const badge = _el('div');
      badge.style.cssText = 'display:flex;flex-direction:column;gap:2px;';
      badge.innerHTML = `
        <span style="font-size:16px;font-weight:800;color:var(--text-primary)">${Number(cnt).toLocaleString()}</span>
        <span style="font-size:10px;color:${up?'var(--color-danger)':'var(--color-success)'};font-weight:600">${up?'▲':'▼'} ${Math.abs(delta).toFixed(0)}%</span>
        <span style="font-size:10px;color:var(--text-muted)">${yr}</span>`;
      badges.appendChild(badge);
    }
    body.appendChild(badges);

    const data = entries.map(([year, count]) => ({ year, count }));
    requestAnimationFrame(() => _drawYearlyChart(chartId, data));
    return wrap;
  }

  function _drawYearlyChart(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el || !window.d3 || !data.length) return;

    const rect = el.getBoundingClientRect();
    const W = rect.width || 700;
    const H = rect.height || 140;
    const margin = { top: 8, right: 16, bottom: 28, left: 44 };
    const iW = W - margin.left - margin.right;
    const iH = H - margin.top - margin.bottom;

    el.innerHTML = '';
    const svg = d3.select(el).append('svg').attr('width', W).attr('height', H);
    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    const style = getComputedStyle(document.documentElement);
    const accent = style.getPropertyValue('--color-brand-accent').trim() || '#1a6fff';
    const muted  = style.getPropertyValue('--text-muted').trim() || '#9ca3af';
    const border = style.getPropertyValue('--border-color').trim() || '#e5e7eb';

    const x = d3.scaleBand().domain(data.map(d => d.year)).range([0, iW]).padding(0.3);
    const y = d3.scaleLinear().domain([0, d3.max(data, d => d.count) * 1.1]).range([iH, 0]);

    g.append('g').call(d3.axisLeft(y).ticks(3).tickSize(-iW).tickFormat(d => d >= 1000 ? `${(d/1000).toFixed(0)}k` : d))
      .call(ax => {
        ax.select('.domain').remove();
        ax.selectAll('.tick line').attr('stroke', border).attr('stroke-dasharray', '3,3');
        ax.selectAll('.tick text').attr('fill', muted).attr('font-size', 10).attr('font-family', 'inherit');
      });

    g.selectAll('.bar').data(data).join('rect')
      .attr('x', d => x(d.year))
      .attr('y', d => y(d.count))
      .attr('width', x.bandwidth())
      .attr('height', d => iH - y(d.count))
      .attr('fill', accent).attr('opacity', 0.85).attr('rx', 4)
      .on('mouseenter', function(e, d) {
        d3.select(this).attr('opacity', 1);
        _showTooltip(e, `${d.year}: ${d.count.toLocaleString()} victims`);
      })
      .on('mouseleave', function() { d3.select(this).attr('opacity', 0.85); _hideTooltip(); });

    g.append('g').attr('transform', `translate(0,${iH})`).call(
      d3.axisBottom(x).tickFormat(d => d)
    ).call(ax => {
      ax.select('.domain').remove();
      ax.selectAll('.tick line').remove();
      ax.selectAll('.tick text').attr('fill', muted).attr('font-size', 11).attr('font-family', 'inherit').attr('font-weight', '600');
    });
  }

  // ── RansomLook Global Stats ───────────────────────────────────────────────

  function _buildRansomLookStats(rl) {
    const wrap = _sectionCard('RansomLook Live Activity', _icoActivity());
    const body = wrap.querySelector('.section-card-body');

    const items = [
      { label:'Groups Tracked', value:(rl.groups||0).toLocaleString(),       color:'blue' },
      { label:'Posts (24h)',     value:(rl.posts_24h||0).toLocaleString(),    color:'green' },
      { label:'Posts (30d)',     value:(rl.posts_month||0).toLocaleString(),  color:'yellow' },
      { label:'Posts (90d)',     value:(rl.posts_90d||0).toLocaleString(),    color:'orange' },
      { label:'Posts (1yr)',     value:(rl.posts_year||0).toLocaleString(),   color:'red' },
      { label:'Total Posts',     value:(rl.posts_total||0).toLocaleString(),  color:'cyan' },
      { label:'Dark Markets',    value:(rl.markets||0).toLocaleString(),      color:'purple' },
    ];

    const grid = _el('div');
    grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;';
    for (const d of items) {
      const card = _el('div');
      card.style.cssText = 'padding:14px 16px;background:var(--bg-surface-2);border-radius:var(--radius-lg);border:1px solid var(--border-color);';
      card.innerHTML = `
        <div style="font-size:22px;font-weight:800;font-variant-numeric:tabular-nums;color:var(--text-primary)">${Security.escapeHtml(d.value)}</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:.05em">${Security.escapeHtml(d.label)}</div>`;
      grid.appendChild(card);
    }
    body.appendChild(grid);
    return wrap;
  }

  // ── Recent Attacks Feed ───────────────────────────────────────────────────

  function _buildRecentFeed(attacks) {
    const wrap = _sectionCard('Recent Attacks', _icoShield(), true);

    const hdr = wrap.querySelector('.section-card-header');
    const link = _el('a', 'btn btn-ghost btn-sm');
    link.href = '#/victims';
    link.textContent = 'All victims →';
    hdr.appendChild(link);

    const table = document.createElement('table');
    table.className = 'data-table';
    table.innerHTML = `<thead><tr>
      <th>Victim</th><th>Group</th><th>Country</th><th>Date</th><th>Summary</th>
    </tr></thead>`;
    const tbody = document.createElement('tbody');

    for (const a of attacks) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="cell-name" style="max-width:180px;font-weight:600">${Security.escapeHtml(Security.truncate(a.victim||'',35))}</td>
        <td><span class="badge badge-red">${Security.escapeHtml(Security.truncate(a.group||'',18))}</span></td>
        <td><span class="badge badge-gray">${Security.escapeHtml((a.country||'??').slice(0,2))}</span></td>
        <td class="cell-nowrap text-muted text-sm">${Security.escapeHtml(Security.formatDate(a.date||a.attack_date||a.published))}</td>
        <td class="text-muted" style="font-size:11px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${Security.escapeHtml(a.summary||a.description||'')}">${Security.escapeHtml(Security.truncate(a.summary||a.description||'',80))}</td>`;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);

    const tableWrap = _el('div', 'data-table-wrap');
    tableWrap.appendChild(table);
    wrap.appendChild(tableWrap);
    return wrap;
  }

  // ── Fallback computations (when stats.json not available) ─────────────────

  function _computeOverview(victims, ransomware) {
    const now = new Date();
    const thisYear = now.getFullYear();
    const thisMonth = `${thisYear}-${String(now.getMonth()+1).padStart(2,'0')}`;
    let thisYearCount = 0, thisMonthCount = 0, withStealer = 0;
    const countries = new Set();
    for (const v of victims) {
      const d = v.attack_date || v.discovered || '';
      if (d.startsWith(String(thisYear))) thisYearCount++;
      if (d.startsWith(thisMonth)) thisMonthCount++;
      if (v.country && v.country !== '??') countries.add(v.country);
      const is = v.infostealer || {};
      if (typeof is === 'object' && Object.keys(is.stealers||{}).length) withStealer++;
    }
    return {
      total_victims: victims.length,
      victims_this_year: thisYearCount,
      victims_this_month: thisMonthCount,
      countries_hit: countries.size,
      active_groups: ransomware.filter(g => g.status === 'active').length,
      victims_with_infostealer: withStealer,
    };
  }

  function _computeSectors(victims) {
    const counts = {};
    for (const v of victims) {
      const s = (v.sector || 'Unknown').trim() || 'Unknown';
      counts[s] = (counts[s] || 0) + 1;
    }
    return Object.fromEntries(Object.entries(counts).sort((a,b) => b[1]-a[1]));
  }

  function _computeCountries(victims) {
    const counts = {};
    for (const v of victims) {
      const c = (v.country || '').toUpperCase();
      if (c && c !== '??') counts[c] = (counts[c] || 0) + 1;
    }
    return Object.fromEntries(Object.entries(counts).sort((a,b) => b[1]-a[1]));
  }

  function _computeMonthly(victims) {
    const map = {};
    for (const v of victims) {
      const d = v.attack_date || v.discovered || '';
      if (!d) continue;
      const dt = new Date(d);
      if (isNaN(dt)) continue;
      const k = `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}`;
      map[k] = (map[k] || 0) + 1;
    }
    return Object.keys(map).sort().map(k => ({ month: k, count: map[k] }));
  }

  function _computeYearly(victims) {
    const map = {};
    for (const v of victims) {
      const d = v.attack_date || v.discovered || '';
      if (!d) continue;
      const dt = new Date(d);
      if (isNaN(dt)) continue;
      const y = String(dt.getFullYear());
      map[y] = (map[y] || 0) + 1;
    }
    return Object.fromEntries(Object.entries(map).sort((a,b) => a[0]-b[0]));
  }

  function _computeTopGroups(ransomware) {
    return [...ransomware]
      .filter(g => g.id !== 'unknown' && g.name.toLowerCase() !== 'unknown')
      .sort((a,b) => (b.victim_count||0)-(a.victim_count||0)).slice(0,15)
      .map(g => ({ name: g.name, id: g.id, count: g.victim_count||0, status: g.status, is_raas: g.is_raas }));
  }

  function _computeInfostealer(victims) {
    const stealers = {};
    let withStealer = 0, totalEmp = 0, totalUsers = 0;
    for (const v of victims) {
      const is = v.infostealer || {};
      if (typeof is !== 'object') continue;
      const s = is.stealers || {};
      if (typeof s === 'object' && Object.keys(s).length) {
        withStealer++;
        totalEmp += +(is.employees || 0);
        totalUsers += +(is.users || 0);
        for (const [name, cnt] of Object.entries(s)) {
          stealers[name] = (stealers[name] || 0) + +cnt;
        }
      }
    }
    return {
      with_stealer: withStealer,
      total: victims.length,
      stealers: Object.fromEntries(Object.entries(stealers).sort((a,b)=>b[1]-a[1]).slice(0,15)),
      total_employees: totalEmp,
      total_users: totalUsers,
    };
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  function _sectionCard(title, iconSvg, noBody = false) {
    const wrap = _el('div', 'section-card');
    wrap.style.marginBottom = 'var(--space-4)';
    const hdr = _el('div', 'section-card-header');
    hdr.innerHTML = `<span class="section-card-title">${iconSvg || ''}${Security.escapeHtml(title)}</span>`;
    wrap.appendChild(hdr);
    if (!noBody) {
      const body = _el('div', 'section-card-body');
      wrap.appendChild(body);
    }
    return wrap;
  }

  function _tabBtn(label, active) {
    const btn = _el('button', `btn btn-ghost btn-sm${active ? ' active' : ''}`);
    btn.textContent = label;
    btn.style.cssText = `font-size:11px;padding:3px 10px;${active?'background:var(--bg-surface-3);font-weight:700;':''}`;
    return btn;
  }

  function _setActiveTab(container, activeBtn) {
    container.querySelectorAll('button').forEach(b => {
      b.style.background = '';
      b.style.fontWeight = '';
    });
    activeBtn.style.background = 'var(--bg-surface-3)';
    activeBtn.style.fontWeight = '700';
  }

  let _tooltip = null;
  function _showTooltip(event, text) {
    if (!_tooltip) {
      _tooltip = _el('div');
      _tooltip.style.cssText = 'position:fixed;background:var(--bg-surface);border:1px solid var(--border-color);border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;z-index:9999;box-shadow:var(--shadow-md);color:var(--text-primary);white-space:nowrap;';
      document.body.appendChild(_tooltip);
    }
    _tooltip.textContent = text;
    _tooltip.style.display = 'block';
    _tooltip.style.left = (event.clientX + 12) + 'px';
    _tooltip.style.top  = (event.clientY - 8) + 'px';
  }
  function _hideTooltip() { if (_tooltip) _tooltip.style.display = 'none'; }

  function _fmtGroup(name) {
    if (!name) return '—';
    // Title-case hyphen/digit-separated group IDs (e.g. "lockbit3" → "LockBit3")
    return name.replace(/([a-z])([A-Z0-9])/g, '$1 $2')
      .replace(/(^|[\s-])([a-z])/g, (_, s, c) => (s || '') + c.toUpperCase())
      .replace(/-/g, ' ');
  }

  // SVG icon helpers
  function _icoShield()    { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><path d="M8 1L2 4v5c0 3.5 2.5 6.3 6 7 3.5-.7 6-3.5 6-7V4L8 1z"/></svg>'; }
  function _icoCalendar()  { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><rect x="1" y="2" width="14" height="12" rx="1"/><path d="M1 6h14M5 1v2M11 1v2"/></svg>'; }
  function _icoClock()     { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><circle cx="8" cy="8" r="7"/><path d="M8 4v4l3 3"/></svg>'; }
  function _icoGlobe()     { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><circle cx="8" cy="8" r="7"/><path d="M8 1c-2 2-3 4-3 7s1 5 3 7M8 1c2 2 3 4 3 7s-1 5-3 7M1 8h14"/></svg>'; }
  function _icoLock()      { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><rect x="3" y="7" width="10" height="8" rx="1"/><path d="M5 7V5a3 3 0 016 0v2"/></svg>'; }
  function _icoEye()       { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><path d="M1 8c1.5-3 3.5-5 7-5s5.5 2 7 5c-1.5 3-3.5 5-7 5S2.5 11 1 8z"/><circle cx="8" cy="8" r="2.5"/></svg>'; }
  function _icoBusiness()  { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><path d="M2 14V6l6-4 6 4v8"/><rect x="5" y="9" width="2" height="5"/><rect x="9" y="9" width="2" height="5"/></svg>'; }
  function _icoActivity()  { return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-right:6px"><path d="M1 8h3l2-5 3 10 2-7 2 2h2"/></svg>'; }

  return { render };
})();

export default StatsView;
