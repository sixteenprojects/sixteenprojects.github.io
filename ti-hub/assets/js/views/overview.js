/**
 * overview.js — Full dashboard with D3 charts and live data.
 * Sections: Stats → Timeline → Countries + Groups → Sectors + Platforms → Recent Victims
 */

import Security from '../security.js';

const OverviewView = (() => {
  'use strict';

  function render(container, data) {
    const { malware = [], actors = [], ransomware = [], victims = [], meta = {}, stats = {}, recent = [] } = data;
    const counts = meta.counts || {
      malware: malware.length, actors: actors.length,
      ransomware_groups: ransomware.length, victims: victims.length,
    };
    const ov = stats.overview || {};

    container.innerHTML = '';

    // ── Page header ──
    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Threat Intelligence Dashboard</h1>
          <p class="page-subtitle">Live data from Malpedia · Ransomware.live · RansomLook</p>
        </div>
        <a href="#/stats" class="btn btn-secondary btn-sm">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12">
            <path d="M1 13V10h2v3H1zM5 13V7h2v6H5zM9 13V4h2v9H9zM13 13V1h2v12h-2z" fill="currentColor" stroke="none"/>
          </svg>
          Full Statistics
        </a>
      </div>`;
    container.appendChild(hdr);

    // ── Stat cards ──
    container.appendChild(_buildStats(counts, ov));

    // ── Timeline chart (D3) ──
    if (victims.length) container.appendChild(_buildTimeline(victims));

    // ── Mid row: Top Countries + Top Groups ──
    const midRow = _el('div', 'grid-2');
    midRow.style.marginBottom = 'var(--space-4)';
    midRow.appendChild(_buildTopCountries(victims));
    midRow.appendChild(_buildTopGroups(ransomware));
    container.appendChild(midRow);

    // ── Lower row: Sectors + Platforms ──
    const lowerRow = _el('div', 'grid-2');
    lowerRow.style.marginBottom = 'var(--space-4)';
    const sectorData = stats.sectors || null;
    lowerRow.appendChild(_buildSectors(victims, sectorData));
    lowerRow.appendChild(_buildPlatforms(malware));
    container.appendChild(lowerRow);

    // ── Recent victims table ──
    const recentVics = recent.length
      ? recent.slice(0, 15).map(r => ({ victim: r.victim, group: r.group, country: r.country, sector: '', attack_date: r.date || r.published, source: r.source }))
      : victims.slice(0, 15);
    container.appendChild(_buildRecentVictims(recentVics));
  }

  // ── Stats cards ────────────────────────────────────────────────────────

  function _buildStats(counts, ov) {
    const grid = _el('div', 'stats-grid');
    const defs = [
      { label: 'Malware Families', value: counts.malware || 0,           view: 'malware',    color: 'blue',
        sub: null,
        icon: '<path d="M8 3C5.2 3 3 5.2 3 8s2.2 5 5 5 5-2.2 5-5-2.2-5-5-5zm0 9c-2.2 0-4-1.8-4-4s1.8-4 4-4 4 1.8 4 4-1.8 4-4 4z"/><circle cx="8" cy="8" r="1.5" fill="currentColor"/>' },
      { label: 'Threat Actors',    value: counts.actors || 0,            view: 'actors',     color: 'red',
        sub: null,
        icon: '<circle cx="8" cy="5" r="3" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5" stroke="currentColor" stroke-width="1.5" fill="none"/>' },
      { label: 'Ransomware Groups',value: counts.ransomware_groups || 0, view: 'ransomware', color: 'yellow',
        sub: ov.active_groups ? `${ov.active_groups} active` : null,
        icon: '<rect x="3" y="7" width="10" height="8" rx="1" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M5 7V5a3 3 0 016 0v2" stroke="currentColor" stroke-width="1.5" fill="none"/><circle cx="8" cy="11" r="1" fill="currentColor"/>' },
      { label: 'Recorded Victims', value: counts.victims || 0,           view: 'victims',    color: 'cyan',
        sub: ov.victims_this_year ? `${(ov.victims_this_year||0).toLocaleString()} this year` : null,
        icon: '<path d="M8 1L2 4v5c0 3.5 2.5 6.3 6 7 3.5-.7 6-3.5 6-7V4L8 1z" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M5.5 8l1.5 1.5 3-3" stroke="currentColor" stroke-width="1.5" fill="none"/>' },
    ];
    for (const d of defs) {
      const card = _el('div', 'stat-card');
      card.style.cursor = 'pointer';
      card.innerHTML = `
        <div class="stat-card-icon ${d.color}">
          <svg viewBox="0 0 16 16" fill="none">${d.icon}</svg>
        </div>
        <div class="stat-card-value" style="font-variant-numeric:tabular-nums">${d.value.toLocaleString()}</div>
        <div class="stat-card-label">${d.label}</div>
        ${d.sub ? `<div style="font-size:10px;color:var(--text-muted);margin-top:2px">${Security.escapeHtml(d.sub)}</div>` : ''}`;
      card.addEventListener('click', () => { window.location.hash = `#/${d.view}`; });
      grid.appendChild(card);
    }
    return grid;
  }

  // ── Victims timeline (D3 bar chart) ────────────────────────────────────

  function _buildTimeline(victims) {
    const wrap = _sectionCard('Victims by Month', `
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <rect x="1" y="1" width="14" height="14" rx="2"/>
        <path d="M1 6h14M5 1v5M11 1v5"/>
      </svg>`);

    const chartDiv = _el('div');
    chartDiv.style.cssText = 'padding:20px 20px 4px;';
    chartDiv.id = 'overview-timeline-chart';
    chartDiv.style.height = '180px';
    wrap.querySelector('.section-card-body').appendChild(chartDiv);

    // Build monthly data (last 18 months)
    const monthly = _groupByMonth(victims, 18);
    requestAnimationFrame(() => _drawBarChart('overview-timeline-chart', monthly));
    return wrap;
  }

  function _groupByMonth(victims, maxMonths) {
    const map = {};
    for (const v of victims) {
      const dateStr = v.attack_date || v.discovered || '';
      if (!dateStr) continue;
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) continue;
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      map[key] = (map[key] || 0) + 1;
    }
    const keys = Object.keys(map).sort().slice(-maxMonths);
    return keys.map(k => ({ month: k, count: map[k] }));
  }

  function _drawBarChart(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container || !window.d3 || !data.length) return;

    const rect   = container.getBoundingClientRect();
    const W      = rect.width  || 600;
    const H      = rect.height || 160;
    const margin = { top: 10, right: 10, bottom: 36, left: 36 };
    const iW     = W - margin.left - margin.right;
    const iH     = H - margin.top  - margin.bottom;

    container.innerHTML = '';
    const svg = d3.select(container).append('svg')
      .attr('width', W).attr('height', H).attr('role', 'img').attr('aria-label', 'Victims by month chart');

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    const x = d3.scaleBand().domain(data.map(d => d.month)).range([0, iW]).padding(0.25);
    const y = d3.scaleLinear().domain([0, d3.max(data, d => d.count) * 1.1]).range([iH, 0]);

    const style   = getComputedStyle(document.documentElement);
    const accent  = style.getPropertyValue('--color-brand-accent').trim() || '#1a6fff';
    const muted   = style.getPropertyValue('--text-muted').trim() || '#9ca3af';
    const border  = style.getPropertyValue('--border-color').trim() || '#e5e7eb';

    // Grid lines
    g.append('g').call(d3.axisLeft(y).ticks(4).tickSize(-iW).tickFormat(d => d))
      .call(ax => { ax.select('.domain').remove(); ax.selectAll('.tick line').attr('stroke', border).attr('stroke-dasharray', '3,3'); ax.selectAll('.tick text').attr('fill', muted).attr('font-size', 10).attr('font-family', 'inherit'); });

    // Bars
    g.selectAll('.bar').data(data).join('rect')
      .attr('class', 'bar')
      .attr('x', d => x(d.month))
      .attr('y', d => y(d.count))
      .attr('width', x.bandwidth())
      .attr('height', d => iH - y(d.count))
      .attr('fill', accent).attr('opacity', 0.85).attr('rx', 3)
      .on('mouseenter', function(e, d) {
        d3.select(this).attr('opacity', 1);
        _showTooltip(e, `${d.month}: ${d.count} victims`);
      })
      .on('mouseleave', function() { d3.select(this).attr('opacity', 0.85); _hideTooltip(); });

    // X axis (show every 3rd label)
    const labels = data.filter((_, i) => i % Math.ceil(data.length / 8) === 0);
    g.append('g').attr('transform', `translate(0,${iH})`).call(
      d3.axisBottom(x).tickValues(labels.map(d => d.month)).tickFormat(d => {
        const [y, m] = d.split('-');
        return `${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][+m-1]} ${y.slice(2)}`;
      })
    ).call(ax => { ax.select('.domain').remove(); ax.selectAll('.tick line').remove(); ax.selectAll('.tick text').attr('fill', muted).attr('font-size', 10).attr('font-family', 'inherit'); });
  }

  // ── Top Countries ────────────────────────────────────────────────────────

  function _buildTopCountries(victims) {
    const wrap = _sectionCard('Top Targeted Countries', `
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="8" cy="8" r="7"/><path d="M8 1c-2 2-3 4-3 7s1 5 3 7M8 1c2 2 3 4 3 7s-1 5-3 7M1 8h14"/>
      </svg>`);

    const body = wrap.querySelector('.section-card-body');
    const counts = {};
    for (const v of victims) {
      const c = (v.country || '??').toUpperCase();
      counts[c] = (counts[c] || 0) + 1;
    }
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const max = top[0]?.[1] || 1;

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:8px;';
    for (const [country, count] of top) {
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:11px;font-weight:700;min-width:30px;color:var(--text-secondary);font-family:var(--font-mono)">${Security.escapeHtml(country)}</span>
        <div style="flex:1;height:20px;background:var(--bg-surface-3);border-radius:4px;overflow:hidden;">
          <div style="height:100%;width:${(count/max*100).toFixed(1)}%;background:var(--color-danger);opacity:.75;border-radius:4px;transition:width .4s ease;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:36px;text-align:right;color:var(--text-primary)">${count.toLocaleString()}</span>`;
      list.appendChild(row);
    }
    body.appendChild(list);
    return wrap;
  }

  // ── Top Ransomware Groups ────────────────────────────────────────────────

  function _buildTopGroups(ransomware) {
    const wrap = _sectionCard('Top Ransomware Groups', `
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <rect x="3" y="7" width="10" height="8" rx="1"/><path d="M5 7V5a3 3 0 016 0v2"/>
      </svg>`);

    const body = wrap.querySelector('.section-card-body');
    const sorted = [...ransomware]
      .filter(g => g.id !== 'unknown' && (g.name||'').toLowerCase() !== 'unknown')
      .sort((a, b) => (b.victim_count || 0) - (a.victim_count || 0)).slice(0, 10);
    const max = sorted[0]?.victim_count || 1;

    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:8px;';
    sorted.forEach((g, i) => {
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;cursor:pointer;';
      const isActive = g.status === 'active';
      row.innerHTML = `
        <span style="font-size:10px;color:var(--text-muted);min-width:16px;text-align:right">${i + 1}</span>
        <span class="status-dot ${isActive ? 'active' : 'inactive'}" title="${g.status}"></span>
        <span style="flex:1;font-size:12px;font-weight:600;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${Security.escapeHtml(_fmtGroup(g.name||g.id))}</span>
        <div style="width:80px;height:16px;background:var(--bg-surface-3);border-radius:4px;overflow:hidden;">
          <div style="height:100%;width:${((g.victim_count||0)/max*100).toFixed(1)}%;background:var(--color-warning);opacity:.8;border-radius:4px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:36px;text-align:right;color:var(--text-primary)">${(g.victim_count||0).toLocaleString()}</span>`;
      row.addEventListener('click', () => { window.location.hash = '#/ransomware'; });
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── Sector distribution ──────────────────────────────────────────────────

  function _buildSectors(victims, sectorData) {
    const wrap = _sectionCard('Attacked Sectors', `
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M2 14V6l6-4 6 4v8"/><rect x="5" y="9" width="2" height="5"/><rect x="9" y="9" width="2" height="5"/>
      </svg>`);

    const body = wrap.querySelector('.section-card-body');

    // Prefer pre-computed sector data from stats.json (official ransomware.live counts)
    let top;
    if (sectorData && Object.keys(sectorData).length) {
      top = Object.entries(sectorData).slice(0, 8);
    } else {
      const counts = {};
      for (const v of victims) {
        const s = (v.sector || 'Unknown').trim() || 'Unknown';
        counts[s] = (counts[s] || 0) + 1;
      }
      top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    }

    const max = top[0]?.[1] || 1;
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:6px;';
    const colors = ['#1a6fff','#3b82f6','#0891b2','#2563eb','#4f46e5','#7c3aed','#db2777','#e11d48'];
    top.forEach(([sector, count], i) => {
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="font-size:11px;flex:1;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${Security.escapeHtml(sector)}">${Security.escapeHtml(Security.truncate(sector, 22))}</span>
        <div style="width:80px;height:14px;background:var(--bg-surface-3);border-radius:3px;overflow:hidden;">
          <div style="height:100%;width:${(count/max*100).toFixed(1)}%;background:${colors[i % colors.length]};opacity:.8;border-radius:3px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:36px;text-align:right;color:var(--text-primary)">${Number(count).toLocaleString()}</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);

    // Link to full stats
    const link = _el('a', 'btn btn-ghost btn-sm');
    link.href = '#/stats';
    link.style.cssText = 'margin-top:10px;font-size:11px;';
    link.textContent = 'View full statistics →';
    body.appendChild(link);

    return wrap;
  }

  // ── Platform distribution ────────────────────────────────────────────────

  function _buildPlatforms(malware) {
    const wrap = _sectionCard('Malware by Platform', `
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <rect x="1" y="3" width="14" height="9" rx="1"/><path d="M5 12v2M11 12v2M3 14h10"/>
      </svg>`);

    const body = wrap.querySelector('.section-card-body');
    const counts = {};
    for (const m of malware) {
      for (const p of (m.platform || ['Unknown'])) {
        counts[p] = (counts[p] || 0) + 1;
      }
    }
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const total = top.reduce((s, [, v]) => s + v, 0);

    const colors = ['#1a6fff','#ef4444','#f59e0b','#10b981','#8b5cf6','#06b6d4','#f97316','#64748b'];
    const list = _el('div');
    list.style.cssText = 'display:flex;flex-direction:column;gap:6px;';
    top.forEach(([platform, count], i) => {
      const pct = total ? (count / total * 100).toFixed(1) : 0;
      const row = _el('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;';
      row.innerHTML = `
        <span style="width:8px;height:8px;border-radius:50%;background:${colors[i]};flex-shrink:0;"></span>
        <span style="font-size:11px;flex:1;color:var(--text-secondary)">${Security.escapeHtml(platform)}</span>
        <div style="width:80px;height:14px;background:var(--bg-surface-3);border-radius:3px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${colors[i]};opacity:.8;border-radius:3px;"></div>
        </div>
        <span style="font-size:11px;font-weight:700;min-width:42px;text-align:right;color:var(--text-primary)">${count.toLocaleString()}</span>`;
      list.appendChild(row);
    });
    body.appendChild(list);
    return wrap;
  }

  // ── Recent victims table ─────────────────────────────────────────────────

  function _buildRecentVictims(victims) {
    const wrap = _sectionCard('Recent Victims', `
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="8" cy="8" r="7"/><path d="M8 4v4l3 3"/>
      </svg>`, true);

    const headerRight = wrap.querySelector('.section-card-header');
    const viewAll = _el('a', 'btn btn-ghost btn-sm');
    viewAll.href = '#/victims';
    viewAll.textContent = 'View all →';
    headerRight.appendChild(viewAll);

    if (!victims.length) {
      const empty = _el('div', 'empty-state');
      empty.innerHTML = '<p>No victim data loaded.</p>';
      wrap.appendChild(empty);
      return wrap;
    }

    const table = document.createElement('table');
    table.className = 'data-table';
    table.innerHTML = `<thead><tr>
      <th>Victim</th><th>Group</th><th>Country</th><th>Sector</th><th>Date</th>
    </tr></thead>`;
    const tbody = document.createElement('tbody');

    for (const v of victims) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="cell-name truncate" style="max-width:220px">${Security.escapeHtml(Security.truncate(v.victim, 40))}</td>
        <td><span class="badge badge-red">${Security.escapeHtml(Security.truncate(v.group, 20))}</span></td>
        <td><span class="badge badge-gray">${Security.escapeHtml(v.country || '??')}</span></td>
        <td class="text-muted text-sm truncate" style="max-width:140px">${Security.escapeHtml(Security.truncate(v.sector || 'Unknown', 20))}</td>
        <td class="cell-nowrap text-muted text-sm">${Security.formatDate(v.attack_date || v.discovered)}</td>`;
      tr.style.cursor = 'pointer';
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);

    const tableWrap = _el('div', 'data-table-wrap');
    tableWrap.appendChild(table);
    wrap.appendChild(tableWrap);
    return wrap;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _fmtGroup(name) {
    if (!name) return '—';
    return name.replace(/([a-z])([A-Z0-9])/g, '$1 $2')
      .replace(/(^|[\s-])([a-z])/g, (_, s, c) => (s || '') + c.toUpperCase())
      .replace(/-/g, ' ');
  }

  function _el(tag, className = '') {
    const el = document.createElement(tag);
    if (className) el.className = className;
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

  return { render };
})();

export default OverviewView;
