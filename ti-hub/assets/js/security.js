/**
 * security.js — Input sanitization and XSS prevention utilities.
 * All data from external APIs must pass through these functions before DOM insertion.
 */

const Security = (() => {
  'use strict';

  const HTML_ESCAPE_MAP = {
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#x27;', '/': '&#x2F;',
    '`': '&#x60;', '=': '&#x3D;'
  };

  /**
   * Escape HTML special characters. Use this for ALL user/API data
   * inserted into innerHTML contexts (prefer textContent when possible).
   */
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"'`=/]/g, ch => HTML_ESCAPE_MAP[ch]);
  }

  /**
   * Sanitize a URL — only allow http/https schemes.
   * Returns empty string for anything suspicious.
   */
  function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim();
    // Only allow http and https
    if (!/^https?:\/\//i.test(trimmed)) return '';
    // Block dangerous patterns
    if (/javascript:|data:|vbscript:|file:/i.test(trimmed)) return '';
    return trimmed;
  }

  /**
   * Sanitize a plain text string — strips all HTML tags.
   */
  function sanitizeText(str) {
    if (!str) return '';
    return String(str)
      .replace(/<[^>]*>/g, '')   // strip tags
      .replace(/\s+/g, ' ')      // normalize whitespace
      .trim();
  }

  /**
   * Recursively sanitize all string values in an object/array.
   * Does NOT modify keys, only string values.
   */
  function sanitizeObject(obj, depth = 0) {
    if (depth > 10) return obj; // prevent infinite recursion
    if (Array.isArray(obj)) {
      return obj.map(item => sanitizeObject(item, depth + 1));
    }
    if (obj !== null && typeof obj === 'object') {
      const clean = {};
      for (const [key, val] of Object.entries(obj)) {
        clean[key] = sanitizeObject(val, depth + 1);
      }
      return clean;
    }
    if (typeof obj === 'string') {
      return sanitizeText(obj);
    }
    return obj; // number, boolean, null — pass through
  }

  /**
   * Create a text node safely (preferred over textContent in loops).
   */
  function safeText(str) {
    return document.createTextNode(str === null || str === undefined ? '' : String(str));
  }

  /**
   * Set element text content safely.
   */
  function setText(el, str) {
    if (!el) return;
    el.textContent = (str === null || str === undefined) ? '' : String(str);
  }

  /**
   * Create an anchor element with a sanitized href.
   * Returns a <span> if the URL is invalid.
   */
  function safeLink(text, url, opts = {}) {
    const safeUrl = sanitizeUrl(url);
    const el = safeUrl ? document.createElement('a') : document.createElement('span');
    el.textContent = text || '';
    if (safeUrl) {
      el.href = safeUrl;
      if (opts.external !== false) {
        el.target = '_blank';
        el.rel = 'noopener noreferrer';
      }
      if (opts.className) el.className = opts.className;
    }
    return el;
  }

  /**
   * Validate that a fetched data array matches expected shape.
   * Returns only entries that pass the check function.
   */
  function validateArray(data, checkFn, label = 'items') {
    if (!Array.isArray(data)) {
      console.warn(`[Security] Expected array for ${label}, got ${typeof data}`);
      return [];
    }
    const valid = data.filter(item => {
      try { return checkFn(item); }
      catch { return false; }
    });
    if (valid.length < data.length) {
      console.warn(`[Security] ${label}: ${data.length - valid.length} invalid entries filtered`);
    }
    return valid;
  }

  /**
   * Truncate a string to maxLen characters, adding ellipsis if needed.
   */
  function truncate(str, maxLen = 200) {
    if (!str) return '';
    const s = String(str);
    return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s;
  }

  /**
   * Clamp a number between min and max.
   */
  function clamp(n, min, max) {
    return Math.min(Math.max(Number(n) || 0, min), max);
  }

  /**
   * Parse and validate a date string. Returns ISO string or empty string.
   */
  function safeDate(str) {
    if (!str) return '';
    const d = new Date(str);
    if (isNaN(d.getTime())) return '';
    // Reject dates before year 2000 or far in the future
    const year = d.getFullYear();
    if (year < 2000 || year > 2100) return '';
    return d.toISOString();
  }

  /**
   * Format a date string for display.
   */
  function formatDate(str) {
    const iso = safeDate(str);
    if (!iso) return 'Unknown';
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric'
    });
  }

  return {
    escapeHtml,
    sanitizeUrl,
    sanitizeText,
    sanitizeObject,
    safeText,
    setText,
    safeLink,
    validateArray,
    truncate,
    clamp,
    safeDate,
    formatDate
  };
})();

export default Security;
