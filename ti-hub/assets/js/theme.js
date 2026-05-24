/**
 * theme.js — Dark/light mode toggle with localStorage persistence.
 */

const Theme = (() => {
  'use strict';

  const STORAGE_KEY = 'tihub-theme';
  const DARK  = 'dark';
  const LIGHT = 'light';

  let _current = DARK; // default to dark (professional tool feel)
  let _listeners = [];

  /** Read saved preference or system preference */
  function _getPreferred() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === DARK || saved === LIGHT) return saved;
    // Respect OS preference
    if (window.matchMedia?.('(prefers-color-scheme: light)').matches) return LIGHT;
    return DARK;
  }

  /** Apply theme to <html> element */
  function _apply(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    _current = mode;
    _listeners.forEach(fn => fn(mode));
  }

  /** Initialize — call once on app boot */
  function init() {
    _apply(_getPreferred());

    // Listen for OS preference changes
    window.matchMedia?.('(prefers-color-scheme: light)')
      .addEventListener('change', e => {
        if (!localStorage.getItem(STORAGE_KEY)) {
          _apply(e.matches ? LIGHT : DARK);
        }
      });
  }

  /** Toggle between dark and light */
  function toggle() {
    const next = _current === DARK ? LIGHT : DARK;
    localStorage.setItem(STORAGE_KEY, next);
    _apply(next);
    return next;
  }

  /** Set a specific theme */
  function set(mode) {
    if (mode !== DARK && mode !== LIGHT) return;
    localStorage.setItem(STORAGE_KEY, mode);
    _apply(mode);
  }

  /** Get current theme */
  function current() { return _current; }

  /** Register a change listener */
  function onChange(fn) {
    if (typeof fn === 'function') _listeners.push(fn);
  }

  /**
   * Wire up a toggle button element.
   * The button must have .icon-sun and .icon-moon children (controlled via CSS).
   */
  function bindToggleButton(btn) {
    if (!btn) return;
    btn.addEventListener('click', () => toggle());
    btn.setAttribute('title', 'Toggle theme');
    btn.setAttribute('aria-label', 'Toggle dark/light mode');
  }

  return { init, toggle, set, current, onChange, bindToggleButton };
})();

export default Theme;
