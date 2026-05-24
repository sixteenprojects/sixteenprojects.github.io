/**
 * mitre.js — MITRE ATT&CK heatmap component.
 * MitreMatrix.renderForGroup(container, ttps)   — single group
 * MitreMatrix.renderCrossGroup(container, groups) — all groups heat map
 */

const MitreMatrix = (() => {
  'use strict';

  const TACTIC_ORDER = [
    'TA0043','TA0042','TA0001','TA0002','TA0003','TA0004',
    'TA0005','TA0006','TA0007','TA0008','TA0009','TA0011',
    'TA0010','TA0040',
  ];

  const TACTIC_SHORT = {
    TA0043: 'Recon',      TA0042: 'Res Dev',    TA0001: 'Init Access',
    TA0002: 'Execution',  TA0003: 'Persistence', TA0004: 'Priv Esc',
    TA0005: 'Def Evasion',TA0006: 'Cred Access', TA0007: 'Discovery',
    TA0008: 'Lateral Mv', TA0009: 'Collection',  TA0011: 'C2',
    TA0010: 'Exfil',      TA0040: 'Impact',
  };

  /* ── Render for a single ransomware group ────────────────────────── */

  function renderForGroup(container, ttps) {
    if (!Array.isArray(ttps) || !ttps.length) {
      const note = _el('p', 'text-muted');
      note.style.cssText = 'padding:8px 0;font-size:12px;';
      note.textContent = 'No MITRE ATT&CK TTPs recorded for this group.';
      container.appendChild(note);
      return;
    }

    const byTactic = _groupByTactic(ttps);
    const tactics  = _sortTactics(byTactic);

    const wrap = _el('div', 'mitre-matrix');
    const scrollWrap = _el('div', 'mitre-scroll');
    const grid = _el('div', 'mitre-grid');
    grid.style.gridTemplateColumns = `repeat(${tactics.length}, minmax(110px, 1fr))`;

    for (const tactic of tactics) {
      const col = _buildCol(tactic, tech => {
        const cell = _el('div', 'mitre-cell mitre-cell-active');
        cell.title = `${tech.technique_id}: ${tech.technique_name}${tech.details ? '\n' + tech.details : ''}`;
        _fillCell(cell, tech);
        return cell;
      });
      grid.appendChild(col);
    }

    scrollWrap.appendChild(grid);
    wrap.appendChild(scrollWrap);
    container.appendChild(wrap);

    const summary = _el('p', 'text-muted');
    summary.style.cssText = 'font-size:11px;margin-top:6px;';
    summary.textContent = `${ttps.length} technique${ttps.length !== 1 ? 's' : ''} across ${tactics.length} tactic${tactics.length !== 1 ? 's' : ''}`;
    container.appendChild(summary);
  }

  /* ── Render cross-group heat map ─────────────────────────────────── */

  function renderCrossGroup(container, groups) {
    if (!Array.isArray(groups) || !groups.length) return;

    const techMap = new Map();
    for (const g of groups) {
      for (const t of (g.ttps || [])) {
        if (!t.technique_id) continue;
        if (!techMap.has(t.technique_id)) {
          techMap.set(t.technique_id, { ...t, count: 0 });
        }
        techMap.get(t.technique_id).count++;
      }
    }

    if (!techMap.size) {
      const note = _el('p', 'text-muted');
      note.style.cssText = 'padding:8px 0;font-size:12px;';
      note.textContent = 'No MITRE ATT&CK data available.';
      container.appendChild(note);
      return;
    }

    const allTtps  = [...techMap.values()];
    const byTactic = _groupByTactic(allTtps);
    const tactics  = _sortTactics(byTactic);

    // Legend
    const legend = _el('div', 'mitre-legend');
    legend.innerHTML = `<span class="mitre-legend-label">Groups:</span>
      <span class="mitre-legend-swatch mitre-cell-heat-1">1</span>
      <span class="mitre-legend-swatch mitre-cell-heat-2">2–5</span>
      <span class="mitre-legend-swatch mitre-cell-heat-3">6–15</span>
      <span class="mitre-legend-swatch mitre-cell-heat-4">16+</span>`;
    container.appendChild(legend);

    const wrap = _el('div', 'mitre-matrix');
    const scrollWrap = _el('div', 'mitre-scroll');
    const grid = _el('div', 'mitre-grid');
    grid.style.gridTemplateColumns = `repeat(${tactics.length}, minmax(110px, 1fr))`;

    for (const tactic of tactics) {
      const sorted = [...tactic.techniques].sort((a, b) => (b.count || 0) - (a.count || 0));
      const col = _buildCol({ ...tactic, techniques: sorted }, tech => {
        const cls  = _heatClass(tech.count || 1);
        const cell = _el('div', `mitre-cell ${cls}`);
        cell.title = `${tech.technique_id}: ${tech.technique_name}\nUsed by ${tech.count} group${tech.count !== 1 ? 's' : ''}`;
        _fillCell(cell, tech);
        return cell;
      });
      grid.appendChild(col);
    }

    scrollWrap.appendChild(grid);
    wrap.appendChild(scrollWrap);
    container.appendChild(wrap);
  }

  /* ── Internal helpers ─────────────────────────────────────────────── */

  function _groupByTactic(ttps) {
    const map = new Map();
    for (const t of ttps) {
      const tid = t.tactic_id || 'TA0000';
      if (!map.has(tid)) map.set(tid, { name: t.tactic_name || tid, techniques: [] });
      map.get(tid).techniques.push(t);
    }
    return map;
  }

  function _sortTactics(byTactic) {
    const ordered = TACTIC_ORDER.filter(id => byTactic.has(id))
      .map(id => ({ id, ...byTactic.get(id) }));
    for (const [id, data] of byTactic) {
      if (!TACTIC_ORDER.includes(id)) ordered.push({ id, ...data });
    }
    return ordered;
  }

  function _buildCol(tactic, cellBuilder) {
    const col = _el('div', 'mitre-col');
    const hdr = _el('div', 'mitre-tactic-hdr');
    const tid  = _el('span', 'mitre-tactic-id');
    tid.textContent = tactic.id;
    const tname = _el('span', 'mitre-tactic-name');
    tname.textContent = TACTIC_SHORT[tactic.id] || tactic.name;
    tname.title = tactic.name;
    hdr.appendChild(tid);
    hdr.appendChild(tname);
    col.appendChild(hdr);
    for (const tech of tactic.techniques) col.appendChild(cellBuilder(tech));
    return col;
  }

  function _fillCell(cell, tech) {
    const tid  = _el('span', 'mitre-tech-id');
    tid.textContent = tech.technique_id;
    const name = _el('span', 'mitre-tech-name');
    name.textContent = tech.technique_name;
    cell.appendChild(tid);
    cell.appendChild(name);
  }

  function _heatClass(n) {
    if (n >= 16) return 'mitre-cell-heat-4';
    if (n >= 6)  return 'mitre-cell-heat-3';
    if (n >= 2)  return 'mitre-cell-heat-2';
    return 'mitre-cell-heat-1';
  }

  function _el(tag, cls) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    return el;
  }

  return { renderForGroup, renderCrossGroup };
})();

export default MitreMatrix;
