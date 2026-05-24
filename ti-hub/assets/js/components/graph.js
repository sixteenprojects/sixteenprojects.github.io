/**
 * graph.js — D3 force-directed threat network graph.
 * Shows relationships between threat actors and malware families.
 * D3 v7 must be loaded globally as window.d3.
 */

import Security  from '../security.js';
import DetailView from '../views/detail.js';

const GraphView = (() => {
  'use strict';

  const MAX_NODES  = 150;   // limit for performance
  const MIN_DEGREE = 2;     // minimum connections to show

  function render(container, data, refs) {
    const actors  = data.actors  || [];
    const malware = data.malware || [];

    container.innerHTML = '';

    // ── Page header ──
    const hdr = _el('div', 'page-header');
    hdr.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Threat Graph</h1>
          <p class="page-subtitle">Actor ↔ Malware relationship network (top ${MAX_NODES} nodes by connections)</p>
        </div>
        <div class="page-actions">
          <span class="text-muted text-sm" id="graph-node-count"></span>
        </div>
      </div>`;
    container.appendChild(hdr);

    // ── Legend ──
    const legend = _el('div', 'section-card');
    legend.style.cssText = 'padding:12px 20px;margin-bottom:12px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;';
    legend.innerHTML = `
      <span style="font-size:12px;font-weight:600;color:var(--text-muted)">Legend:</span>
      <span style="display:flex;align-items:center;gap:6px;font-size:12px;">
        <svg width="14" height="14"><circle cx="7" cy="7" r="6" fill="#ef4444"/></svg> Threat Actor
      </span>
      <span style="display:flex;align-items:center;gap:6px;font-size:12px;">
        <svg width="14" height="14"><circle cx="7" cy="7" r="6" fill="#1a6fff"/></svg> Malware Family
      </span>
      <span style="display:flex;align-items:center;gap:6px;font-size:12px;">
        <svg width="14" height="14"><line x1="0" y1="7" x2="14" y2="7" stroke="var(--border-color)" stroke-width="2"/></svg> Uses
      </span>
      <span class="text-muted text-sm" style="margin-left:auto">Click node to view details · Drag to reposition · Scroll to zoom</span>`;
    container.appendChild(legend);

    // ── Graph container ──
    const graphCard = _el('div', 'section-card');
    const graphEl   = _el('div');
    graphEl.id = 'ti-hub-graph';
    graphEl.style.cssText = 'width:100%;height:580px;position:relative;overflow:hidden;background:var(--bg-surface-2);border-radius:0 0 var(--radius-lg) var(--radius-lg);';
    graphCard.appendChild(graphEl);
    container.appendChild(graphCard);

    if (!window.d3) {
      graphEl.innerHTML = '<p style="padding:60px;text-align:center;color:var(--text-muted)">D3.js not loaded.</p>';
      return;
    }

    requestAnimationFrame(() => _buildGraph(graphEl, actors, malware, refs));
  }

  // ── Graph construction ─────────────────────────────────────────────────

  function _buildGraph(container, actors, malware, refs) {
    const { nodes, links } = _buildGraphData(actors, malware);

    const countEl = document.getElementById('graph-node-count');
    if (countEl) countEl.textContent = `${nodes.length} nodes · ${links.length} connections`;

    const W = container.clientWidth  || 900;
    const H = container.clientHeight || 580;

    const svg = d3.select(container).append('svg')
      .attr('width', W)
      .attr('height', H)
      .attr('aria-label', 'Threat actor malware network graph');

    // Zoom behavior
    const zoomG = svg.append('g');
    svg.call(d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', e => zoomG.attr('transform', e.transform))
    );

    // Force simulation
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(60).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide().radius(d => d.r + 4));

    // Draw links
    const link = zoomG.append('g').attr('class', 'graph-links')
      .selectAll('line').data(links).join('line')
      .attr('stroke', 'var(--border-color)')
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', 1.5);

    // Draw nodes
    const node = zoomG.append('g').attr('class', 'graph-nodes')
      .selectAll('g').data(nodes).join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (e, d) => {
        e.stopPropagation();
        const item = d._raw;
        const type = d.type === 'actor' ? 'actor' : 'malware';
        if (item) DetailView.open(type, item);
      });

    node.append('circle')
      .attr('r', d => d.r)
      .attr('fill', d => d.type === 'actor' ? '#ef4444' : '#1a6fff')
      .attr('fill-opacity', 0.85)
      .attr('stroke', '#fff')
      .attr('stroke-width', 1.5);

    node.append('text')
      .attr('dy', '0.35em')
      .attr('text-anchor', 'middle')
      .attr('font-size', d => Math.min(11, Math.max(8, d.r - 2)))
      .attr('font-family', 'var(--font-sans)')
      .attr('fill', '#fff')
      .attr('pointer-events', 'none')
      .text(d => _truncLabel(d.label, d.r));

    // Tooltip
    const tooltip = d3.select(container).append('div')
      .style('position', 'absolute')
      .style('background', 'var(--bg-surface)')
      .style('border', '1px solid var(--border-color)')
      .style('border-radius', '8px')
      .style('padding', '8px 12px')
      .style('font-size', '12px')
      .style('pointer-events', 'none')
      .style('z-index', '9999')
      .style('display', 'none')
      .style('max-width', '220px')
      .style('color', 'var(--text-primary)')
      .style('box-shadow', 'var(--shadow-md)');

    node
      .on('mouseenter', (e, d) => {
        const lines = [
          `<strong>${Security.escapeHtml(d.label)}</strong>`,
          `<span style="color:var(--text-muted)">${d.type === 'actor' ? 'Threat Actor' : 'Malware'}</span>`,
          d.degree > 0 ? `${d.degree} connection${d.degree !== 1 ? 's' : ''}` : '',
          d._raw?.country_iso ? `Country: ${d._raw.country_iso}` : '',
          d._raw?.type ? `Type: ${d._raw.type}` : '',
        ].filter(Boolean).join('<br>');
        tooltip.html(lines).style('display', 'block');
      })
      .on('mousemove', e => {
        const rect = container.getBoundingClientRect();
        tooltip
          .style('left', (e.clientX - rect.left + 12) + 'px')
          .style('top',  (e.clientY - rect.top  - 8)  + 'px');
      })
      .on('mouseleave', () => tooltip.style('display', 'none'));

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });
  }

  // ── Data preparation ───────────────────────────────────────────────────

  function _buildGraphData(actors, malware) {
    const malwareById = new Map(malware.map(m => [m.id, m]));

    // Collect all edges
    const rawEdges = [];
    for (const actor of actors) {
      for (const mId of (actor.malware || [])) {
        if (malwareById.has(mId)) rawEdges.push({ source: actor.id, target: mId });
      }
    }

    // Count degrees
    const degree = new Map();
    for (const e of rawEdges) {
      degree.set(e.source, (degree.get(e.source) || 0) + 1);
      degree.set(e.target, (degree.get(e.target) || 0) + 1);
    }

    // Select top N actors and malware by degree
    const topActors = actors
      .filter(a => (degree.get(a.id) || 0) >= MIN_DEGREE)
      .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))
      .slice(0, Math.floor(MAX_NODES * 0.4));

    const actorIds = new Set(topActors.map(a => a.id));
    const neededMalware = new Set();
    for (const e of rawEdges) {
      if (actorIds.has(e.source)) neededMalware.add(e.target);
    }

    const topMalware = [...neededMalware]
      .map(id => malwareById.get(id))
      .filter(Boolean)
      .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))
      .slice(0, MAX_NODES - topActors.length);

    const malwareIds = new Set(topMalware.map(m => m.id));

    // Build node list
    const nodes = [
      ...topActors.map(a => ({
        id: a.id, type: 'actor', label: a.name || a.id,
        r: Math.max(8, Math.min(28, 8 + (degree.get(a.id) || 0))),
        degree: degree.get(a.id) || 0, _raw: a,
      })),
      ...topMalware.map(m => ({
        id: m.id, type: 'malware', label: m.name || m.id,
        r: Math.max(6, Math.min(22, 6 + Math.sqrt(degree.get(m.id) || 1) * 4)),
        degree: degree.get(m.id) || 0, _raw: m,
      })),
    ];

    // Build link list (only between selected nodes)
    const links = rawEdges.filter(e => actorIds.has(e.source) && malwareIds.has(e.target));

    return { nodes, links };
  }

  function _truncLabel(text, r) {
    const maxChars = Math.floor(r / 3.5);
    return text.length > maxChars ? text.slice(0, maxChars) + '…' : text;
  }

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  return { render };
})();

export default GraphView;
