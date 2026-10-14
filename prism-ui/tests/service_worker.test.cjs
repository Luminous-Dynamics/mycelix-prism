const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const ORIGIN = 'https://prism.example';
const WORKER_SOURCE = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'sw.js'),
  'utf8',
);

function makeHeaders(values = {}) {
  const entries = new Map(
    Object.entries(values).map(([name, value]) => [name.toLowerCase(), String(value)]),
  );
  return {
    get(name) {
      return entries.get(String(name).toLowerCase()) ?? null;
    },
    has(name) {
      return entries.has(String(name).toLowerCase());
    },
  };
}

function makeResponse(label, ok = true, headerValues = {}, type = 'basic', status = 200) {
  return {
    label,
    ok,
    type,
    status,
    headers: makeHeaders(headerValues),
    clone() {
      return makeResponse(label, ok, headerValues, type, status);
    },
  };
}

function request(url, {
  method = 'GET',
  mode = 'cors',
  headers = {},
  cache = 'default',
} = {}) {
  return {
    url: new URL(url, ORIGIN).href,
    method,
    mode,
    headers: makeHeaders(headers),
    cache,
  };
}

function requestKey(input) {
  if (typeof input === 'string') return new URL(input, ORIGIN).href;
  return input.url;
}

function makeHarness({ initialCaches = {}, fetchImpl = async () => makeResponse('network') } = {}) {
  const listeners = new Map();
  const stores = new Map();
  for (const [name, entries] of Object.entries(initialCaches)) {
    const store = new Map();
    for (const [url, value] of Object.entries(entries)) {
      store.set(new URL(url, ORIGIN).href, value);
    }
    stores.set(name, store);
  }

  const deleted = [];
  const deletedEntries = [];
  const puts = [];
  const fetched = [];
  let globalMatchCalls = 0;

  const caches = {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      const store = stores.get(name);
      return {
        async addAll(urls) {
          for (const url of urls) {
            const key = new URL(url, ORIGIN).href;
            if (!store.has(key)) store.set(key, makeResponse('preloaded app shell'));
          }
        },
        async match(input) {
          return store.get(requestKey(input));
        },
        async put(input, response) {
          const key = requestKey(input);
          puts.push({ name, url: key });
          store.set(key, response.clone ? response.clone() : response);
        },
        async delete(input) {
          const key = requestKey(input);
          const existed = store.delete(key);
          deletedEntries.push({ name, url: key, existed });
          return existed;
        },
      };
    },
    async keys() {
      return [...stores.keys()];
    },
    async delete(name) {
      deleted.push(name);
      return stores.delete(name);
    },
    async match(input) {
      globalMatchCalls += 1;
      for (const store of stores.values()) {
        const value = store.get(requestKey(input));
        if (value) return value;
      }
      return undefined;
    },
  };

  const self = {
    location: { origin: ORIGIN },
    addEventListener(type, handler) {
      listeners.set(type, handler);
    },
    skipWaiting() {},
    clients: { async claim() {} },
  };

  vm.runInNewContext(WORKER_SOURCE, {
    self,
    caches,
    URL,
    fetch: async (input) => {
      fetched.push(requestKey(input));
      return fetchImpl(input);
    },
    console: { log() {}, warn() {}, error() {} },
  }, { filename: 'sw.js' });

  return { listeners, stores, deleted, deletedEntries, puts, fetched, caches, get globalMatchCalls() { return globalMatchCalls; } };
}

function dispatchFetch(harness, req) {
  let responded = false;
  let responsePromise;
  harness.listeners.get('fetch')({
    request: req,
    respondWith(value) {
      responded = true;
      responsePromise = Promise.resolve(value);
    },
  });
  return { responded, responsePromise };
}

test('activation deletes only known Prism cache namespaces', async () => {
  const harness = makeHarness({
    initialCaches: {
      'prism-v2': { '/old-route?q=secret': makeResponse('old prism data') },
      'mycelix-prism-v2': { '/old': makeResponse('older prism data') },
      'mycelix-prism-v4': { '/': makeResponse('current app shell') },
      'other-app-v1': { '/': makeResponse('other app shell') },
      'prism-other-app-cache': { '/': makeResponse('unrelated cache with similar prefix') },
    },
  });

  let pending;
  harness.listeners.get('activate')({ waitUntil(promise) { pending = promise; } });
  await pending;

  assert.deepEqual(harness.deleted.sort(), ['mycelix-prism-v2', 'prism-v2']);
  assert.ok(harness.stores.has('mycelix-prism-v4'));
  assert.ok(harness.stores.has('other-app-v1'));
  assert.ok(harness.stores.has('prism-other-app-cache'));
});

test('cache-first assets never read another app cache', async () => {
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': {},
      'other-app-v1': { '/static/shared.js': makeResponse('foreign cached response') },
    },
    fetchImpl: async () => makeResponse('network response'),
  });

  const event = dispatchFetch(harness, request('/static/shared.js'));
  assert.equal(event.responded, true);
  const response = await event.responsePromise;

  assert.equal(response.label, 'network response');
  assert.equal(harness.globalMatchCalls, 0);
  assert.deepEqual(harness.puts, [{
    name: 'mycelix-prism-v4',
    url: new URL('/static/shared.js', ORIGIN).href,
  }]);
});

test('successful navigation does not persist the full route or query string', async () => {
  const harness = makeHarness({
    initialCaches: { 'mycelix-prism-v4': { '/': makeResponse('app shell') } },
    fetchImpl: async () => makeResponse('online route'),
  });
  const url = '/search?q=personal%20query';
  const event = dispatchFetch(harness, request(url, { mode: 'navigate' }));

  assert.equal(event.responded, true);
  assert.equal((await event.responsePromise).label, 'online route');
  assert.equal(harness.puts.some((entry) => entry.url === new URL(url, ORIGIN).href), false);
  assert.equal(harness.stores.get('mycelix-prism-v4').has(new URL(url, ORIGIN).href), false);
});

test('offline navigation falls back to Prism app shell, not another cache', async () => {
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': { '/': makeResponse('Prism app shell') },
      'other-app-v1': { '/': makeResponse('different app shell') },
    },
    fetchImpl: async () => { throw new Error('offline'); },
  });
  const event = dispatchFetch(harness, request('/search?q=offline', { mode: 'navigate' }));

  assert.equal((await event.responsePromise).label, 'Prism app shell');
  assert.equal(harness.globalMatchCalls, 0);
});

test('cross-origin requests bypass the Prism cache strategy', () => {
  const harness = makeHarness();
  const event = dispatchFetch(harness, request('https://cdn.example/asset.js'));

  assert.equal(event.responded, false);
  assert.deepEqual(harness.fetched, []);
  assert.deepEqual(harness.puts, []);
});

test('non-GET requests bypass the Prism cache strategy', () => {
  const harness = makeHarness();
  const event = dispatchFetch(harness, request('/api/search', { method: 'POST', mode: 'cors' }));

  assert.equal(event.responded, false);
  assert.deepEqual(harness.fetched, []);
  assert.deepEqual(harness.puts, []);
});


test('static responses marked non-cacheable by HTTP policy are not persisted', async () => {
  const cases = [
    ['no-store', { 'Cache-Control': 'no-store' }],
    ['private', { 'Cache-Control': 'public, PRIVATE, max-age=600' }],
    ['no-cache', { 'Cache-Control': 'no-cache' }],
    ['must-revalidate', { 'Cache-Control': 'must-revalidate' }],
    ['zero-max-age', { 'Cache-Control': 'max-age=0' }],
    ['vary-wildcard', { Vary: 'Accept-Language, *' }],
    ['partial-content', {}, 'basic', true, 206],
    ['pragma-no-cache', { Pragma: 'no-cache' }],
    ['expired-expires', { Expires: 'Thu, 01 Jan 1970 00:00:00 GMT' }],
    ['invalid-expires', { Expires: '0' }],
  ];

  for (const [index, [name, headers, type = 'basic', ok = true, status = 200]] of cases.entries()) {
    const harness = makeHarness({
      initialCaches: { 'mycelix-prism-v4': {} },
      fetchImpl: async () => makeResponse(name, ok, headers, type, status),
    });
    const event = dispatchFetch(harness, request(`/static/policy-${index}.js`));

    assert.equal((await event.responsePromise).label, name);
    assert.deepEqual(harness.puts, [], `${name} response must not be persisted`);
  }
});

test('query-bearing static URLs bypass cache lookup and insertion', async () => {
  const queryUrl = '/static/app.js?token=secret';
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': {
        [queryUrl]: makeResponse('previously cached sensitive response'),
      },
    },
    fetchImpl: async () => makeResponse('fresh network response'),
  });

  const event = dispatchFetch(harness, request(queryUrl));
  assert.equal((await event.responsePromise).label, 'fresh network response');
  assert.deepEqual(harness.puts, []);
  assert.equal(
    harness.stores.get('mycelix-prism-v4').has(new URL(queryUrl, ORIGIN).href),
    false,
    'an old query-bearing cache entry is purged before the network response is returned',
  );
});

test('authorization and explicit cache-bypass directives skip existing entries', async () => {
  const cases = [
    ['authorization', { headers: { Authorization: 'Bearer secret' } }],
    ['request-no-store', { headers: { 'Cache-Control': 'no-store' } }],
    ['request-no-cache', { headers: { 'Cache-Control': 'no-cache' } }],
    ['request-max-age-zero', { headers: { 'Cache-Control': 'max-age=0' } }],
    ['pragma-no-cache', { headers: { Pragma: 'no-cache' } }],
    ['cache-reload', { cache: 'reload' }],
    ['cache-no-cache', { cache: 'no-cache' }],
    ['cache-no-store', { cache: 'no-store' }],
  ];

  for (const [index, [name, options]] of cases.entries()) {
    const path = `/static/bypass-${index}.js`;
    const harness = makeHarness({
      initialCaches: {
        'mycelix-prism-v4': {
          [path]: makeResponse('must not reuse cached response'),
        },
      },
      fetchImpl: async () => makeResponse(name),
    });
    const event = dispatchFetch(harness, request(path, options));

    assert.equal((await event.responsePromise).label, name);
    assert.deepEqual(harness.puts, [], `${name} request must not populate cache`);
    assert.equal(
      harness.stores.get('mycelix-prism-v4').has(new URL(path, ORIGIN).href),
      false,
      `${name} request must purge its prior cache entry`,
    );
  }
});


test('install does not persist core assets marked non-cacheable by HTTP policy', async () => {
  const harness = makeHarness({
    initialCaches: { 'mycelix-prism-v4': {} },
    fetchImpl: async (input) => {
      const path = new URL(requestKey(input), ORIGIN).pathname;
      if (path === '/') {
        return makeResponse('app shell marked no-store', true, { 'Cache-Control': 'no-store' });
      }
      return makeResponse(`core asset ${path}`, true, { 'Cache-Control': 'public, max-age=3600' });
    },
  });

  let installPromise;
  harness.listeners.get('install')({
    waitUntil(promise) { installPromise = promise; },
  });
  await installPromise;

  const installedCache = harness.stores.get('mycelix-prism-v4');
  assert.equal(installedCache.has(new URL('/', ORIGIN).href), false);
  assert.equal(installedCache.has(new URL('/static/prism-loading.jpg', ORIGIN).href), true);
});


test('SPA fallback HTML is never cached under a static asset URL', async () => {
  const paths = [
    '/static/missing.js',
    '/static/missing.css',
    '/static/missing.wasm',
    '/static/missing.bin',
    '/static/missing.js/',
    '/static/missing-directory/',
  ];

  for (const path of paths) {
    const harness = makeHarness({
      initialCaches: { 'mycelix-prism-v4': {} },
      fetchImpl: async () => makeResponse(
        'SPA index returned for missing asset',
        true,
        { 'Content-Type': 'text/html; charset=utf-8' },
      ),
    });

    const event = dispatchFetch(harness, request(path));
    assert.equal((await event.responsePromise).label, 'SPA index returned for missing asset');
    assert.deepEqual(harness.puts, [], `HTML fallback must not be stored for ${path}`);
  }
});

test('install still caches a cacheable app shell at the root URL', async () => {
  const harness = makeHarness({
    initialCaches: { 'mycelix-prism-v4': {} },
    fetchImpl: async (input) => {
      const path = new URL(requestKey(input), ORIGIN).pathname;
      if (path === '/') {
        return makeResponse('cacheable app shell', true, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
        });
      }
      return makeResponse(`core asset ${path}`, true, {
        'Cache-Control': 'public, max-age=3600',
      });
    },
  });

  let installPromise;
  harness.listeners.get('install')({
    waitUntil(promise) { installPromise = promise; },
  });
  await installPromise;

  const installedCache = harness.stores.get('mycelix-prism-v4');
  assert.equal(installedCache.get(new URL('/', ORIGIN).href).label, 'cacheable app shell');
});


test('mutable static assets refresh from origin and replace stale cache entries', async () => {
  const path = '/static/prism-hero.jpg';
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': {
        [path]: makeResponse('stale hero image', true, { 'Cache-Control': 'public, max-age=3600' }),
      },
    },
    fetchImpl: async () => makeResponse('updated hero image', true, {
      'Cache-Control': 'public, max-age=3600',
    }),
  });

  const event = dispatchFetch(harness, request(path));
  assert.equal((await event.responsePromise).label, 'updated hero image');
  assert.equal(harness.stores.get('mycelix-prism-v4').get(new URL(path, ORIGIN).href).label, 'updated hero image');
});

test('new no-store policy removes an older cached mutable asset', async () => {
  const path = '/static/prism-icon.svg';
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': {
        [path]: makeResponse('old cacheable icon', true, { 'Cache-Control': 'public, max-age=3600' }),
      },
    },
    fetchImpl: async () => makeResponse('fresh non-cacheable icon', true, {
      'Cache-Control': 'no-store',
    }),
  });

  const event = dispatchFetch(harness, request(path));
  assert.equal((await event.responsePromise).label, 'fresh non-cacheable icon');
  assert.equal(harness.stores.get('mycelix-prism-v4').has(new URL(path, ORIGIN).href), false);
});

test('mutable static assets fall back to cache only after network failure', async () => {
  const path = '/static/prism-hero.jpg';
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': {
        [path]: makeResponse('offline hero image'),
      },
    },
    fetchImpl: async () => { throw new Error('offline'); },
  });

  const event = dispatchFetch(harness, request(path));
  assert.equal((await event.responsePromise).label, 'offline hero image');
  assert.deepEqual(harness.fetched, [new URL(path, ORIGIN).href]);
});

test('content-addressed assets remain cache-first for performance', async () => {
  const path = '/static/app-a1b2c3d4.js';
  const harness = makeHarness({
    initialCaches: {
      'mycelix-prism-v4': {
        [path]: makeResponse('cached fingerprinted asset'),
      },
    },
    fetchImpl: async () => { throw new Error('network should not be required'); },
  });

  const event = dispatchFetch(harness, request(path));
  assert.equal((await event.responsePromise).label, 'cached fingerprinted asset');
  assert.deepEqual(harness.fetched, []);
});


test('explicit Cache-Control lifetime takes precedence over legacy Expires', async () => {
  const harness = makeHarness({
    initialCaches: { 'mycelix-prism-v4': {} },
    fetchImpl: async () => makeResponse('explicit lifetime wins', true, {
      'Cache-Control': 'public, max-age=600',
      Expires: 'Thu, 01 Jan 1970 00:00:00 GMT',
      Pragma: 'no-cache',
    }),
  });

  const event = dispatchFetch(harness, request('/static/app.js'));
  assert.equal((await event.responsePromise).label, 'explicit lifetime wins');
  assert.equal(harness.puts.length, 1);
});
