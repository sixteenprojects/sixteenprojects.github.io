/**
 * overview.js — Dashboard home view.
 * Shows: stats cards, last updated, recent victims mini-feed, activity chart.
 * Populated in Phase 2 — stub for Phase 1 boot.
 */

import Security from '../security.js';

const OverviewView = (() => {
  'use strict';

  function render(container, data) {
    const { malware = [], actors = [], ransomware = [], victims = [], meta = {} } = data;

    const counts = meta.counts || {
      malware: malware.length,
      actors: actors.length,
      ransomware_groups: ransomware.length,
      victims: victims.length,
    };

    container.innerHTML = '';

    // Page header
    const header = document.createElement('div');
    header.className = 'page-header';
    header.innerHTML = `
      <h1 class="page-title">Threat Intelligence Dashboard</h1>
      <p class="page-subtitle">Aggregated data from Malpedia, Ransomware.live, and RansomLook</p>
    `;
    container.appendChild(header);

    // Stats grid
    const statsGrid = _buildStatsGrid(counts);
    container.appendChild(statsGrid);

    // Recent victims section
    const recentSection = _buildRecentVictims(victims.slice(0, 10));
    container.appendChild(recentSection);
  }

  function _buildStatsGrid(counts) {
    const grid = document.createElement('div');
    grid.className = 'stats-grid';

    const stats = [
      {
        label: 'Malware Families',
        value: counts.malware || 0,
        icon: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="8" cy="8" r="7"/><path d="M8 5v3l2 2"/>
        </svg>`,
        colorClass: 'blue',
        view: 'malware',
      },
      {
        label: 'Threat Actors',
        value: counts.actors || 0,
        icon: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="8" cy="5" r="3"/><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5"/>
        </svg>`,
        colorClass: 'red',
        view: 'actors',
      },
      {
        label: 'Ransomware Groups',
        value: counts.ransomware_groups || 0,
        icon: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="3" y="7" width="10" height="8" rx="1"/><path d="M5 7V5a3 3 0 016 0v2"/>
        </svg>`,
        colorClass: 'yellow',
        view: 'ransomware',
      },
      {
        label: 'Recorded Victims',
        value: counts.victims || 0,
        icon: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M8 1L2 4v5c0 3.5 2.5 6.3 6 7 3.5-.7 6-3.5 6-7V4L8 1z"/>
        </svg>`,
        colorClass: 'cyan',
        view: 'victims',
      },
    ];

    for (const s of stats) {
      const card = document.createElement('div');
      card.className = 'stat-card';
      card.style.cursor = 'pointer';
      card.dataset.view = s.view;

      const icon = document.createElement('div');
      icon.className = `stat-card-icon ${s.colorClass}`;
      icon.innerHTML = s.icon;

      const value = document.createElement('div');
      value.className = 'stat-card-value';
      value.textContent = s.value.toLocaleString();

      const label = document.createElement('div');
      label.className = 'stat-card-label';
      label.textContent = s.label;

      card.appendChild(icon);
      card.appendChild(value);
      card.appendChild(label);

      card.addEventListener('click', () => {
        window.location.hash = `#/${s.view}`;
      });

      grid.appendChild(card);
    }

    return grid;
  }

  function _buildRecentVictims(victims) {
    const section = document.createElement('div');
    section.className = 'section-card';

    const header = document.createElement('div');
    header.className = 'section-card-header';
    header.innerHTML = `
      <span class="section-card-title">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="8" cy="8" r="7"/><path d="M8 4v4l3 3"/>
        </svg>
        Recent Victims
      </span>
      <a href="#/victims" class="btn btn-ghost btn-sm">View all →</a>
    `;
    section.appendChild(header);

    if (!victims.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = `<p>No victim data loaded yet.</p>`;
      section.appendChild(empty);
      return section;
    }

    const list = document.createElement('div');
    list.style.cssText = 'padding: 0;';

    for (const v of victims) {
      const row = document.createElement('div');
      row.style.cssText = `
        display: flex; align-items: center; gap: 12px;
        padding: 12px 20px; border-bottom: 1px solid var(--border-color);
        cursor: pointer; transition: background 0.15s;
      `;
      row.addEventListener('mouseenter', () => row.style.background = 'var(--bg-surface-2)');
      row.addEventListener('mouseleave', () => row.style.background = '');

      const name = document.createElement('span');
      name.style.cssText = 'font-weight:600; font-size:13px; flex:1; min-width:0;';
      name.className = 'truncate';
      name.textContent = v.victim || 'Unknown';

      const group = document.createElement('span');
      group.className = 'badge badge-red';
      group.textContent = Security.truncate(v.group, 20);

      const country = document.createElement('span');
      country.className = 'badge badge-gray';
      country.textContent = v.country || '??';

      const date = document.createElement('span');
      date.className = 'text-sm text-muted';
      date.style.whiteSpace = 'nowrap';
      date.textContent = Security.formatDate(v.attack_date || v.discovered);

      row.appendChild(name);
      row.appendChild(group);
      row.appendChild(country);
      row.appendChild(date);
      list.appendChild(row);
    }

    section.appendChild(list);
    return section;
  }

  return { render };
})();

export default OverviewView;
