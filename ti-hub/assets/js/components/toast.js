/**
 * toast.js — Lightweight toast notification system.
 */

const Toast = (() => {
  'use strict';

  let _container = null;

  function _getContainer() {
    if (!_container) {
      _container = document.getElementById('toast-container');
    }
    return _container;
  }

  /**
   * Show a toast notification.
   * @param {string} message
   * @param {'info'|'success'|'warning'|'error'} type
   * @param {number} duration ms (0 = persistent)
   */
  function show(message, type = 'info', duration = 4000) {
    const container = _getContainer();
    if (!container) return;

    const icons = {
      info:    '●',
      success: '✓',
      warning: '⚠',
      error:   '✕',
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || '●'}</span>
      <span class="toast-message"></span>
      <button class="toast-close" aria-label="Dismiss">✕</button>
    `;
    // Safe text insertion
    toast.querySelector('.toast-message').textContent = message;

    // Add entrance animation class
    toast.style.animation = 'toastIn 0.2s ease forwards';

    // Close on button click
    toast.querySelector('.toast-close').addEventListener('click', () => dismiss(toast));

    container.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => dismiss(toast), duration);
    }

    return toast;
  }

  function dismiss(toast) {
    if (!toast || !toast.parentNode) return;
    toast.style.animation = 'toastOut 0.2s ease forwards';
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
  }

  const info    = (msg, dur) => show(msg, 'info', dur);
  const success = (msg, dur) => show(msg, 'success', dur);
  const warning = (msg, dur) => show(msg, 'warning', dur);
  const error   = (msg, dur) => show(msg, 'error', dur);

  return { show, dismiss, info, success, warning, error };
})();

export default Toast;
