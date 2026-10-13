// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
// Mycelix Prism — Service Worker for offline-first PWA
// Caches core assets on install, serves from cache with network fallback.

const CACHE_NAME = 'mycelix-prism-v3';
const PRISM_CACHE_PREFIX = 'mycelix-prism-';
// Explicitly known legacy Prism cache from the previous service worker.
const LEGACY_CACHE_NAMES = new Set(['prism-v2']);

// Only cache assets with stable filenames.
// CSS, JS, and WASM have content-hashed names (e.g. prism-abc123.css)
// and are cached on first fetch via the fetch handler below.
const CORE_ASSETS = [
  '/',
  '/static/prism-loading.jpg',
  '/static/prism-hero.jpg',
  '/static/prism-icon-192.png',
  '/static/prism-icon.svg',
  '/static/prism-index-core.bin',
];

// Install: cache only stable-filename assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Prism SW] Caching core assets');
      return cache.addAll(CORE_ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names
          .filter((n) =>
            n !== CACHE_NAME &&
            (n.startsWith(PRISM_CACHE_PREFIX) || LEGACY_CACHE_NAMES.has(n))
          )
          .map((n) => caches.delete(n))
      )
    )
  );
  self.clients.claim();
});

// Fetch: cache-first for static assets, network-first for everything else
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Cache Storage is shared by the origin. Let cross-origin and mutating
  // requests use the browser's normal fetch path without Prism cache access.
  if (url.origin !== self.location.origin || request.method !== 'GET') {
    return;
  }

  // HTML: network-first with the cached app shell as the offline fallback.
  // Do not persist each navigation URL: routes may contain queries, and the
  // offline path always returns '/', so route-specific cache entries are unused.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(async () => {
        const cache = await caches.open(CACHE_NAME);
        return cache.match('/');
      })
    );
    return;
  }

  // Static assets and WASM: cache-first (immutable/static filenames).
  if (url.pathname.startsWith('/static/') ||
      url.pathname.endsWith('.wasm') ||
      url.pathname.endsWith('.js') ||
      url.pathname.endsWith('.css')) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(request);
      if (cached) return cached;

      const response = await fetch(request);
      if (response.ok) {
        try {
          await cache.put(request, response.clone());
        } catch (_) {
          // Storage quota or an uncacheable response must not break an online fetch.
        }
      }
      return response;
    })());
    return;
  }

  // Everything else: network with fallback to this app's cache only.
  event.respondWith((async () => {
    try {
      return await fetch(request);
    } catch (_) {
      const cache = await caches.open(CACHE_NAME);
      return cache.match(request);
    }
  })());
});
