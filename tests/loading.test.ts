import { readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, type RequestOptions, type Server } from 'node:https';
import type { AddressInfo, LookupFunction } from 'node:net';
import { gzipSync } from 'node:zlib';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const network = vi.hoisted(() => ({
  port: 0,
  ca: '',
  options: [] as RequestOptions[],
  addresses: [] as string[],
  resolve: vi.fn(),
}));

vi.mock('node:dns/promises', () => ({ lookup: network.resolve }));
vi.mock('node:https', async (importOriginal) => {
  const native = await importOriginal<typeof import('node:https')>();
  return {
    ...native,
    request(url: URL, options: RequestOptions) {
      network.options.push(options);
      // Only the fixture's connection address is replaced. DNS policy checks,
      // pinned lookup invocation, TLS hostname verification and streams are real.
      const lookup: LookupFunction = (hostname, lookupOptions, callback) => {
        options.lookup?.(hostname, lookupOptions, (error, address, family) => {
          if (error) return callback(error, []);
          if (Array.isArray(address)) {
            network.addresses.push(...address.map((item) => item.address));
            callback(null, [{ address: '127.0.0.1', family: 4 }]);
          } else {
            network.addresses.push(address);
            callback(null, '127.0.0.1', family ?? 4);
          }
        });
      };
      const target = new URL(url);
      target.port = String(network.port);
      return native.request(target, { ...options, ca: network.ca, lookup });
    },
  };
});

import { HttpFetchError } from '../src/internal/http-fetch.js';
import { loadCatalogFromEntry } from '../src/loading.js';
import type { CatalogEntry, CatalogEntryWithData, CatalogEntryWithUrl } from '../src/types.js';
import { CatalogParseError } from '../src/types.js';
import { checkCatalogEntry, createDigest } from '../src/verification.js';

const url = 'https://publisher.example/catalog.json';
const catalogType = 'application/ai-catalog+json';
const urlEntry: CatalogEntryWithUrl = { identifier: 'catalog', type: catalogType, url };
const catalog = { specVersion: '1.0', entries: [] };
const body = ' {\n  "entries": [], "specVersion": "1.0"\n}\n';
const artifactBytes = new TextEncoder().encode(body);
const options = { resourceTimeoutMs: 2_000, maxResponseBytes: 16_384 };
let server: Server;
let respond: (request: IncomingMessage, response: ServerResponse) => void;
const requests: string[] = [];
const timers = new Set<ReturnType<typeof setTimeout>>();

function later(delay: number, callback: () => void): void {
  const timer = setTimeout(() => {
    timers.delete(timer);
    callback();
  }, delay);
  timers.add(timer);
}

beforeAll(async () => {
  const cert = readFileSync(new URL('./fixtures/transport-cert.pem', import.meta.url), 'utf8');
  const key = readFileSync(new URL('./fixtures/transport-key.pem', import.meta.url), 'utf8');
  network.ca = cert;
  server = createServer({ cert, key }, (request, response) => {
    const host = request.headers.host?.replace(/:\d+$/, '');
    requests.push(`https://${host}${request.url}`);
    respond(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  network.port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

afterEach(() => {
  for (const timer of timers) clearTimeout(timer);
  timers.clear();
  server.closeAllConnections();
});

beforeEach(() => {
  network.resolve.mockReset();
  network.resolve.mockResolvedValue([{ address: '8.8.8.8', family: 4 }]);
  network.options.length = 0;
  network.addresses.length = 0;
  requests.length = 0;
  respond = (_request, response) => response.end(body);
});

describe('loadCatalogFromEntry', () => {
  it('loads a URL directly and retains the exact bytes used for entry verification', async () => {
    const entry = { ...urlEntry, digest: createDigest(artifactBytes) };
    const result = await loadCatalogFromEntry(entry, options);
    expect(result).toMatchObject({ status: 'found', catalog, url });
    if (result.status !== 'found') throw new Error('Expected a loaded catalog.');
    expect([...result.bytes]).toEqual([...artifactBytes]);
    await expect(checkCatalogEntry(entry, result.bytes)).resolves.toEqual({ status: 'checked', manifests: [] });
    await expect(checkCatalogEntry(entry, new TextEncoder().encode(JSON.stringify(result.catalog))))
      .resolves.toEqual({ status: 'artifact_digest_mismatch' });
    expect(requests).toEqual([url]);
  });

  it('parses an inline catalog without network activity, URL metadata or manufactured bytes', async () => {
    const entry: CatalogEntryWithData = { identifier: 'inline', type: catalogType, data: catalog };
    const result = await loadCatalogFromEntry(entry);
    expect(result).toEqual({ status: 'found', catalog });
    await expect(checkCatalogEntry({ ...entry, digest: createDigest(entry.data) })).resolves.toEqual({
      status: 'checked', manifests: [],
    });
    expect(requests).toEqual([]);
    expect(network.resolve).not.toHaveBeenCalled();
  });

  it('preserves the supplied base URL unchanged for an inline catalog without fetching it', async () => {
    const baseUrl = 'https://PUBLISHER.example:443/releases/../root.json?edition=1#existing';
    const entry: CatalogEntryWithData = { identifier: 'inline', type: catalogType, data: catalog };
    const result = await loadCatalogFromEntry(entry, { baseUrl });
    expect(result).toEqual({ status: 'found', catalog, url: baseUrl });
    expect(requests).toEqual([]);
    expect(network.resolve).not.toHaveBeenCalled();
  });

  it('carries redirected URL context through inline catalogs during recursive loading', async () => {
    const finalUrl = 'https://other.example/releases/final.json';
    const grandchildUrl = 'https://other.example/releases/grandchild.json';
    const inlineEntry: CatalogEntryWithData = {
      identifier: 'inline', type: catalogType,
      data: {
        specVersion: '1.0',
        entries: [{ identifier: 'grandchild', type: catalogType, url: './grandchild.json' }],
      },
    };
    respond = (request, response) => {
      if (request.url === '/catalog.json') {
        response.writeHead(302, { location: finalUrl }).end();
      } else if (request.url === '/releases/final.json') {
        response.end(JSON.stringify({ specVersion: '1.0', entries: [inlineEntry] }));
      } else if (request.url === '/releases/grandchild.json') {
        response.end(body);
      } else {
        response.writeHead(404).end();
      }
    };
    const visitedUrls: (string | undefined)[] = [];
    async function visit(entry: CatalogEntry, baseUrl?: string): Promise<void> {
      const loaded = await loadCatalogFromEntry(entry, {
        ...options, ...(baseUrl === undefined ? {} : { baseUrl }),
      });
      if (loaded.status !== 'found') throw new Error('Expected a loaded catalog.');
      visitedUrls.push(loaded.url);
      for (const child of loaded.catalog.entries) {
        if (child.type === catalogType) await visit(child, loaded.url);
      }
    }
    await visit(urlEntry);
    expect(visitedUrls).toEqual([finalUrl, finalUrl, grandchildUrl]);
    expect(requests).toEqual([url, finalUrl, grandchildUrl]);
  });

  it.each([null, 'not a catalog', {}, { specVersion: '2.0', entries: [] }])(
    'reports invalid inline catalog data without treating it as an invalid invocation: %j', async (data) => {
      await expect(loadCatalogFromEntry({ identifier: 'inline', type: catalogType, data })).resolves.toEqual({
        status: 'invalid_catalog', error: expect.any(CatalogParseError),
      });
      expect(requests).toEqual([]);
    },
  );

  it('preserves unknown catalog fields and declarations for subsequent validation', async () => {
    const document = {
      specVersion: '1.1', future: { retained: true },
      entries: [{ identifier: 'not an AIR identifier', type: 'custom', url: './artifact', digest: 'invalid' }],
    };
    for (const entry of [urlEntry, { identifier: 'inline', type: catalogType, data: document }]) {
      respond = (_request, response) => response.writeHead(200, { 'content-type': 'text/plain' }).end(JSON.stringify(document));
      const result = await loadCatalogFromEntry(entry, options);
      expect(result).toMatchObject({ status: 'found', catalog: document });
    }
    expect(requests).toEqual([url]);
  });

  it('resolves a relative reference against the supplied base and returns the final URL', async () => {
    respond = (request, response) => {
      if (request.url === '/catalog.json') response.writeHead(302, { location: 'https://other.example/releases/final.json' }).end();
      else response.end(body);
    };
    const result = await loadCatalogFromEntry({ ...urlEntry, url: '../catalog.json' }, {
      ...options, baseUrl: 'https://publisher.example/pages/root.json',
    });
    expect(result).toMatchObject({ status: 'found', url: 'https://other.example/releases/final.json' });
    expect(requests).toEqual([url, 'https://other.example/releases/final.json']);
  });

  it.each(['./child.json', 'https://[malformed'])('reports an unresolvable entry URL as fetch_failed: %s', async (reference) => {
    const result = await loadCatalogFromEntry({ ...urlEntry, url: reference }, options);
    expect(result).toMatchObject({ status: 'fetch_failed', url: reference, error: expect.any(Error) });
    if (result.status === 'fetch_failed' && reference.startsWith('.')) {
      expect(result.error.message).toMatch(/base URL/i);
    }
    expect(requests).toEqual([]);
    expect(network.resolve).not.toHaveBeenCalled();
  });

  it.each([404, 410, 500])('reports explicit HTTP %s without discovery or fallback', async (status) => {
    respond = (_request, response) => response.writeHead(status, { link: '</other>; rel="ai-catalog"' }).end();
    await expect(loadCatalogFromEntry(urlEntry, options)).resolves.toMatchObject({ status: 'fetch_failed', url });
    expect(requests).toEqual([url]);
  });

  it.each(['{', '{"specVersion":"1.0","entries":[{}]}', Buffer.from([0xff, 0xfe])])(
    'reports malformed fetched catalogs without returning source bytes: %j', async (source) => {
      respond = (_request, response) => response.end(source);
      await expect(loadCatalogFromEntry(urlEntry, options)).resolves.toEqual({
        status: 'invalid_catalog', url, error: expect.any(CatalogParseError),
      });
    },
  );

  it('returns decoded artifact bytes after decompression', async () => {
    respond = (_request, response) => response.writeHead(200, { 'content-encoding': 'gzip' }).end(gzipSync(body));
    const result = await loadCatalogFromEntry(urlEntry, options);
    expect(result.status).toBe('found');
    if (result.status === 'found') expect([...result.bytes]).toEqual([...artifactBytes]);
  });

  it('enforces the decoded response size before catalog parsing', async () => {
    respond = (_request, response) => response.writeHead(200, { 'content-encoding': 'gzip' }).end(gzipSync(body));
    await expect(loadCatalogFromEntry(urlEntry, { ...options, maxResponseBytes: artifactBytes.length - 1 }))
      .resolves.toMatchObject({ status: 'fetch_failed', error: expect.any(HttpFetchError) });
  });

  it('does not follow private redirect destinations', async () => {
    respond = (_request, response) => response.writeHead(302, { location: 'https://127.0.0.1/private' }).end();
    await expect(loadCatalogFromEntry(urlEntry, options)).resolves.toMatchObject({
      status: 'fetch_failed', url,
    });
    expect(requests).toEqual([url]);
  });

  it('uses a single deadline for body consumption', async () => {
    respond = (_request, response) => response.write('{');
    await expect(loadCatalogFromEntry(urlEntry, { ...options, resourceTimeoutMs: 80 }))
      .resolves.toMatchObject({ status: 'fetch_failed', error: expect.any(HttpFetchError) });
  });

  it('rejects with the exact cancellation reason during body consumption', async () => {
    const controller = new AbortController();
    const reason = { stop: true };
    respond = (_request, response) => {
      response.write('{');
      later(10, () => controller.abort(reason));
    };
    await expect(loadCatalogFromEntry(urlEntry, { ...options, signal: controller.signal })).rejects.toBe(reason);
  });

  it.each([urlEntry, { identifier: 'inline', type: catalogType, data: catalog }])(
    'checks cancellation before processing either entry form', async (entry) => {
      const reason = new Error('stop');
      const controller = new AbortController();
      controller.abort(reason);
      await expect(loadCatalogFromEntry(entry, { signal: controller.signal })).rejects.toBe(reason);
      expect(requests).toEqual([]);
    },
  );

  it('captures the entry and options before asynchronous retrieval', async () => {
    let release: (() => void) | undefined;
    network.resolve.mockImplementationOnce(() => new Promise((resolve) => {
      release = () => resolve([{ address: '8.8.8.8', family: 4 }]);
    }));
    const entry = { ...urlEntry, url: './catalog.json' };
    const supplied = { ...options, baseUrl: 'https://publisher.example/root.json' };
    const pending = loadCatalogFromEntry(entry, supplied);
    entry.url = 'https://other.example/mutated';
    entry.type = 'custom';
    supplied.baseUrl = 'https://other.example/root.json';
    supplied.maxResponseBytes = 1;
    release?.();
    await expect(pending).resolves.toMatchObject({ status: 'found', url });
    expect(requests).toEqual([url]);
  });

  it.each([null, [], {}, { ...urlEntry, type: 'application/json' }, { ...urlEntry, data: catalog }])(
    'rejects invalid entry arguments before network activity: %j', async (entry) => {
      await expect(loadCatalogFromEntry(entry as never)).rejects.toBeInstanceOf(TypeError);
      expect(requests).toEqual([]);
    },
  );

  it.each([
    { baseUrl: './relative' }, { resourceTimeoutMs: 0 }, { maxResponseBytes: Infinity }, { signal: {} },
  ])('rejects invalid options before network activity: %j', async (supplied) => {
    await expect(loadCatalogFromEntry(urlEntry, supplied as never)).rejects.toBeInstanceOf(TypeError);
    expect(requests).toEqual([]);
  });

  it('does not invoke entry or option accessors while capturing inputs', async () => {
    const getter = vi.fn(() => url);
    const badEntry = { identifier: 'catalog', type: catalogType, get url() { return getter(); } };
    await expect(loadCatalogFromEntry(badEntry)).rejects.toBeInstanceOf(TypeError);
    const badOptions = { get baseUrl() { return getter(); } };
    await expect(loadCatalogFromEntry(urlEntry, badOptions)).rejects.toBeInstanceOf(TypeError);
    expect(getter).not.toHaveBeenCalled();
  });

  it('propagates unexpected parser backend exceptions', async () => {
    const reason = new RangeError('backend failure');
    const parse = vi.spyOn(JSON, 'parse').mockImplementation(() => { throw reason; });
    try {
      await expect(loadCatalogFromEntry(urlEntry, options)).rejects.toBe(reason);
    } finally {
      parse.mockRestore();
    }
  });
});
