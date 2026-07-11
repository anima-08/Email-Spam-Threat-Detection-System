/**
 * config.js — Single source of truth for SpamShield configuration.
 * Change BACKEND_URL here when you deploy to production.
 */
const CONFIG = {
  BACKEND_URL: "http://localhost:5000",

  // Default settings (overridden by user choices stored in chrome.storage.sync)
  DEFAULTS: {
    autoScan: true,
    notifications: true,
    spamThreshold: 0.50,   // 0.0 – 1.0
  },

  MAX_HISTORY: 20,
};
