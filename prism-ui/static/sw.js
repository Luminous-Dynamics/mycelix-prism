// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
// Mycelix Prism — Service Worker for offline-first PWA
// Caches core assets on install, serves from cache with network fallback.

const CACHE_NAME = 'mycelix-prism-v4';
const PRISM_CACHE_PREFIX = 'mycelix-prism-';
// Explicitly known legacy Prism cache from the previous service worker.
const LEGACY_CACHE_NAMES = new Set(['prism-v2']);

// Some generated CSS, JS, and WASM assets have content fingerprints.
// Cache-first is reserved for unambiguous fingerprint-like filenames; other
// assets use network-first so ordinary names cannot be mistaken for hashes.
const CORE_ASSETS = [
  '/',
  '/static/prism-loading.jpg',
  '/static/prism-hero.jpg',
  '/static/prism-icon-192.png',
  '/static/prism-icon.svg',
  '/static/prism-index-core.bin',
];

function cacheControlDirectives(value) {
  return (value || '')
    .split(',')
    .map((directive) => directive.trim().toLowerCase())
    .filter(Boolean);
}

// Fail closed on invalid, duplicated, or zero max-age values. Treat an unusable
// lifetime as non-cacheable rather than letting CacheStorage preserve it forever.
function hasUnusableMaxAge(directives) {
  const maxAge = directives.filter((directive) =>
    directive.split('=', 1)[0].trim() === 'max-age'
  );
  if (maxAge.length === 0) return false;
  if (maxAge.length !== 1) return true;

  const equals = maxAge[0].indexOf('=');
  if (equals === -1) return true;
  const value = maxAge[0].slice(equals + 1).trim().replace(/^"|"$/g, '');
  if (!/^\d+$/.test(value)) return true;
  const seconds = Number(value);
  return !Number.isSafeInteger(seconds) || seconds === 0;
}

// Cache Storage deliberately does not implement HTTP freshness/privacy policy
// for the application. Keep sensitive or explicitly non-cacheable requests out
// of both lookup and insertion, rather than relying on Cache-Control by itself.
function shouldBypassStaticCache(request, url) {
  const requestDirectives = cacheControlDirectives(
    request.headers?.get('Cache-Control'),
  );
  const pragma = (request.headers?.get('Pragma') || '').toLowerCase();

  return url.search !== '' ||
    Boolean(request.headers?.has('Authorization')) ||
    requestDirectives.some((directive) =>
      directive === 'no-store' || directive === 'no-cache'
    ) ||
    hasUnusableMaxAge(requestDirectives) ||
    ['no-store', 'no-cache', 'reload'].includes(request.cache) ||
    pragma.split(',').some((directive) => directive.trim() === 'no-cache');
}

function isContentAddressedStaticAsset(url) {
  const filename = url.pathname.split('/').pop() || '';
  // Prefer cache speed only for a fingerprint-like segment with both hex
  // letters and digits. Words such as "facade" are hexadecimal too, but are
  // not content hashes; false negatives cost performance, false positives serve stale code.
  const fingerprint = filename.match(/(?:^|[-_.])([a-f0-9]{8,})(?:[-_.]|$)/i)?.[1];
  return Boolean(fingerprint && /[a-f]/i.test(fingerprint) && /[0-9]/.test(fingerprint));
}

function shouldCacheStaticResponse(response, requestUrl) {
  if (!response.ok || response.type === 'opaque' || response.status === 206) return false;

  // The SPA fallback can return index.html with status 200 for a missing
  // asset path (for example /static/missing.js). Do not poison the static
  // cache with HTML stored under an asset URL; navigation/app-shell HTML is
  // eligible only at the root shell URL.
  const url = typeof requestUrl === 'string'
    ? new URL(requestUrl, self.location.origin)
    : requestUrl;
  const contentType = (response.headers?.get('Content-Type') || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
  const isHtml = contentType === 'text/html' || contentType === 'application/xhtml+xml';
  const isAppShellUrl = url.pathname === '/';
  if (isHtml && !isAppShellUrl) return false;

  const cacheControl = response.headers?.get('Cache-Control');
  const directives = cacheControlDirectives(cacheControl);

  // Older HTTP/1.0 origins may express this policy only with Pragma.
  if (!cacheControl && (response.headers?.get('Pragma') || '')
    .split(',')
    .some((directive) => directive.trim().toLowerCase() === 'no-cache')) {
    return false;
  }

  // Cache Storage does not expire entries automatically. When Cache-Control
  // does not provide an explicit lifetime, don't persist expired/invalid
  // Expires values as though they were fresh.
  // RFC 9111 §5.2.2.10 limits s-maxage to shared caches. This worker's
  // CacheStorage is per-user, so only max-age overrides legacy Expires here.
  const hasExplicitLifetime = directives.some((directive) => {
    const [name] = directive.split('=', 1);
    return name.trim() === 'max-age';
  });
  const expires = response.headers?.get('Expires');
  if (!hasExplicitLifetime && expires !== null && expires !== undefined) {
    const expiresAt = Date.parse(expires);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
  }

  const forbidden = new Set([
    'no-store',
    'no-cache',
    'private',
    'must-revalidate',
    'proxy-revalidate',
  ]);
  if (
    directives.some((directive) => {
      const [name] = directive.split('=', 1);
      return forbidden.has(name.trim());
    }) ||
    hasUnusableMaxAge(directives)
  ) {
    return false;
  }

  // A wildcard Vary makes a response unsuitable for Cache.put().
  const vary = response.headers?.get('Vary') || '';
  if (vary.split(',').some((name) => name.trim() === '*')) return false;

  return true;
}

// Use explicit puts instead of Cache.addAll(), which would persist responses
// without this worker applying Cache-Control, Vary, and status eligibility.
async function precacheCoreAssets(cache) {
  await Promise.all(CORE_ASSETS.map(async (asset) => {
    const response = await fetch(asset);
    if (!response.ok) {
      throw new Error(`Failed to fetch core asset: ${asset}`);
    }
    if (!shouldCacheStaticResponse(response, new URL(asset, self.location.origin))) return;
    await cache.put(asset, response.clone());
  }));
}

// Install: cache only stable-filename assets whose response policy permits storage.
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Prism SW] Caching core assets');
      return precacheCoreAssets(cache);
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
  // offline path always returns '/', so route-specific cached documents are unused.
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
    // A URL query may carry tokens or user data. Authorization-bearing requests
    // and explicit cache-bypass directives must not read from or write to cache.
    if (shouldBypassStaticCache(request, url)) {
      event.respondWith((async () => {
        // Remove any entry accidentally left by an older worker/version before
        // honoring a request that explicitly bypasses cache or carries secrets.
        const cache = await caches.open(CACHE_NAME);
        await cache.delete(request);
        return fetch(request);
      })());
      return;
    }

    // A content-addressed name can safely use cache-first: a different payload
    // should have a different URL. Mutable filenames must contact the origin so
    // changed content and newly restrictive cache headers take effect online.
    const cacheFirst = isContentAddressedStaticAsset(url);

    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      if (cacheFirst) {
        const cached = await cache.match(request);
        if (cached) return cached;
      }

      try {
        const response = await fetch(request);
        if (shouldCacheStaticResponse(response, url)) {
          try {
            await cache.put(request, response.clone());
          } catch (_) {
            // Storage quota or an uncacheable response must not break an online fetch.
          }
        } else {
          // Do not leave an old cacheable response behind after the origin opts
          // out of storage or serves a non-cacheable fallback for this URL.
          await cache.delete(request);
        }
        return response;
      } catch (error) {
        // Mutable assets retain offline support, but never use a cached result
        // while the origin is reachable.
        const cached = await cache.match(request);
        if (cached) return cached;
        throw error;
      }
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
