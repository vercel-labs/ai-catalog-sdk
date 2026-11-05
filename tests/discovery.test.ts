import { readFileSync } from 'node:fs';
import { createServer, type RequestOptions, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo, LookupFunction } from 'node:net';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';

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

import { discoverCatalog } from '../src/discovery.js';
import { HttpFetchError } from '../src/internal/http-fetch.js';
import { CatalogParseError } from '../src/types.js';

const website = 'https://publisher.example/start';
const wellKnown = '/.well-known/ai-catalog.json';
const catalog = { specVersion: '1.0', entries: [] };
const body = JSON.stringify(catalog);
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
  respond = (request, response) => {
    if (request.url === '/start') response.end('website');
    else if (request.url === wellKnown) response.end(body);
    else response.writeHead(404).end();
  };
});

describe('native HTTPS catalog discovery', () => {
  it('follows the first advertised HTTP Link across header lines and relation tokens', async () => {
    respond = (request, response) => {
      if (request.url === '/start') {
        response.setHeader('link', [
          '</unrelated>; rel="alternate"; title="a,b"',
          '</selected>; rel="alternate ai-catalog"; title="first", </ignored>; rel="ai-catalog"',
        ]);
        response.end();
      } else response.end(body);
    };
    await expect(discoverCatalog(website, options)).resolves.toEqual({
      status: 'found', catalog, url: 'https://publisher.example/selected',
    });
    expect(requests).toEqual([website, 'https://publisher.example/selected']);
    expect(network.addresses).toEqual(['8.8.8.8', '8.8.8.8']);
    expect(network.options.every((value) => value.agent === false && value.rejectUnauthorized === true)).toBe(true);
  });

  it('reads an advertised Link even when the website returns HTTP 404', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.writeHead(404, { link: '</catalog>; rel="ai-catalog"' }).end();
      else response.end(body);
    };
    await expect(discoverCatalog(website, options)).resolves.toMatchObject({ status: 'found' });
    expect(requests).toEqual([website, 'https://publisher.example/catalog']);
  });

  it.each([true, false])('inspects redirect-status responses without Location (advertisement: %s)', async (advertised) => {
    respond = (request, response) => {
      if (request.url === '/start') {
        response.writeHead(302, advertised ? { link: '</catalog>; rel="ai-catalog"' } : {}).end();
      } else response.end(body);
    };
    await expect(discoverCatalog(website, options)).resolves.toEqual({
      status: 'found', catalog, url: advertised ? 'https://publisher.example/catalog' : `https://publisher.example${wellKnown}`,
    });
  });

  it.each([
    '<html><head><link rel="ai-catalog" href="/html-catalog"></head></html>',
    body,
  ])('ignores the initial website body and falls back to the well-known URL: %s', async (page) => {
    respond = (request, response) => response.end(request.url === '/start' ? page : body);
    await expect(discoverCatalog(website, options)).resolves.toEqual({
      status: 'found', catalog, url: `https://publisher.example${wellKnown}`,
    });
    expect(requests).toEqual([website, `https://publisher.example${wellKnown}`]);
  });

  it('discards a nonending website body immediately after receiving its headers', async () => {
    respond = (request, response) => {
      if (request.url === '/start') {
        response.writeHead(200, { link: '</catalog>; rel="ai-catalog"', 'content-encoding': 'unknown' });
        response.write('x'.repeat(100_000));
      } else response.end(body);
    };
    await expect(discoverCatalog(website, { ...options, maxResponseBytes: body.length })).resolves.toMatchObject({
      status: 'found', catalog,
    });
  });

  it('resolves a relative advertised link against the final website path and returns the final catalog URL', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.writeHead(302, { location: 'https://other.example/pages/home' }).end();
      else if (request.url === '/pages/home') response.writeHead(200, { link: '<../catalog>; rel="ai-catalog"' }).end();
      else if (request.url === '/catalog') response.writeHead(307, { location: '/catalog-final' }).end();
      else response.end(body);
    };
    await expect(discoverCatalog(website, options)).resolves.toEqual({
      status: 'found', catalog, url: 'https://other.example/catalog-final',
    });
    expect(requests).toEqual([
      website, 'https://other.example/pages/home', 'https://other.example/catalog', 'https://other.example/catalog-final',
    ]);
    expect(network.resolve.mock.calls.map(([host]) => host)).toEqual([
      'publisher.example', 'other.example', 'other.example', 'other.example',
    ]);
    expect(network.options.map((value) => value.servername)).toEqual([
      'publisher.example', 'other.example', 'other.example', 'other.example',
    ]);
  });

  it.each([404, 410, 500])('does not fall back after an advertised catalog returns HTTP %s', async (status) => {
    respond = (request, response) => {
      if (request.url === '/start') response.writeHead(200, { link: '</broken>; rel="ai-catalog"' }).end();
      else if (request.url === '/broken') response.writeHead(status).end();
      else response.end(body);
    };
    const result = await discoverCatalog(website, options);
    expect(result).toMatchObject({ status: 'fetch_failed', url: 'https://publisher.example/broken', error: expect.any(Error) });
    expect(requests).toEqual([website, 'https://publisher.example/broken']);
  });

  it('reports an advertised invalid catalog without trying the well-known URL', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.writeHead(200, { link: '</broken>; rel="ai-catalog"' }).end();
      else response.end('{"specVersion":"1.0","entries":[{}]}');
    };
    await expect(discoverCatalog(website, options)).resolves.toMatchObject({
      status: 'invalid_catalog', url: 'https://publisher.example/broken', error: expect.any(CatalogParseError),
    });
    expect(requests).toHaveLength(2);
  });

  it('classifies malformed UTF-8 as an invalid catalog', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else response.end(Buffer.from([0xff, 0xfe]));
    };
    const result = await discoverCatalog(website, options);
    expect(result).toMatchObject({
      status: 'invalid_catalog', error: { issues: [{ code: 'invalid_json' }] },
    });
  });

  it('reports a malformed selected URL without falling back', async () => {
    respond = (_request, response) => response.writeHead(200, {
      link: '<https://[malformed>; rel="ai-catalog"',
    }).end();
    await expect(discoverCatalog(website, options)).resolves.toMatchObject({
      status: 'fetch_failed', url: 'https://[malformed', error: expect.any(Error),
    });
    expect(requests).toEqual([website]);
  });

  it('does not fall back after an advertised destination is blocked by network policy', async () => {
    respond = (_request, response) => response.writeHead(200, {
      link: '<https://other.example/catalog>; rel="ai-catalog"',
    }).end();
    network.resolve
      .mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }])
      .mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);
    await expect(discoverCatalog(website, options)).resolves.toMatchObject({
      status: 'fetch_failed', url: 'https://other.example/catalog', error: expect.any(Error),
    });
    expect(requests).toEqual([website]);
    expect(network.resolve).toHaveBeenCalledTimes(2);
  });

  it('reports an initial private-address policy block as a fetch failure', async () => {
    const url = 'https://127.0.0.1/start';
    await expect(discoverCatalog(url, options)).resolves.toMatchObject({
      status: 'fetch_failed', url, error: expect.any(Error),
    });
    expect(requests).toHaveLength(0);
    expect(network.resolve).not.toHaveBeenCalled();
  });

  it('parses structures without imposing authoring validation, media-type checks or artifact retrieval', async () => {
    const document = {
      specVersion: '1.0',
      futureCatalogField: { retained: true },
      entries: [{ identifier: 'not an AIR identifier', type: 'custom', url: 'not an absolute URL', digest: 'invalid' }],
    };
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else response.writeHead(200, { 'content-type': 'text/plain' }).end(JSON.stringify(document));
    };
    await expect(discoverCatalog(website, options)).resolves.toEqual({
      status: 'found', catalog: document, url: `https://publisher.example${wellKnown}`,
    });
    expect(requests).toHaveLength(2);
  });

  it.each([404, 410])('treats a well-known HTTP %s as absence and tries a same-origin candidate only once', async (status) => {
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else response.writeHead(status).end();
    };
    await expect(discoverCatalog(website, options)).resolves.toEqual({ status: 'not_found' });
    expect(requests).toEqual([website, `https://publisher.example${wellKnown}`]);
  });

  it('reports a well-known HTTP 500 as a fetch failure', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else response.writeHead(500).end();
    };
    await expect(discoverCatalog(website, options)).resolves.toMatchObject({
      status: 'fetch_failed', url: `https://publisher.example${wellKnown}`, error: expect.any(Error),
    });
  });

  it.each(['absent', 'HTTP error', 'invalid JSON', 'timeout'])('tries the original origin after the final origin has %s', async (failure) => {
    respond = (request, response) => {
      const host = request.headers.host;
      if (request.url === '/start') response.writeHead(302, { location: 'https://other.example/home' }).end();
      else if (request.url === '/home') response.end();
      else if (host?.startsWith('publisher.example')) response.end(body);
      else if (failure === 'absent') response.writeHead(410).end();
      else if (failure === 'HTTP error') response.writeHead(500).end();
      else if (failure === 'invalid JSON') response.end('{');
      else response.write('{');
    };
    await expect(discoverCatalog(website, { ...options, resourceTimeoutMs: 200 })).resolves.toEqual({
      status: 'found', catalog, url: `https://publisher.example${wellKnown}`,
    });
    expect(requests).toEqual([
      website, 'https://other.example/home', `https://other.example${wellKnown}`, `https://publisher.example${wellKnown}`,
    ]);
  });

  it.each([
    [404, 410, 'not_found', undefined],
    [500, 404, 'fetch_failed', 'other.example'],
    [404, 500, 'fetch_failed', 'publisher.example'],
    [200, 500, 'invalid_catalog', 'other.example'],
    [500, 200, 'fetch_failed', 'other.example'],
  ] as const)('keeps the first nonabsence failure when final and original statuses are %s and %s', async (finalStatus, originalStatus, status, host) => {
    respond = (request, response) => {
      if (request.url === '/start') response.writeHead(302, { location: 'https://other.example/home' }).end();
      else if (request.url === '/home') response.end();
      else response.writeHead(request.headers.host?.startsWith('other.example') ? finalStatus : originalStatus).end('{');
    };
    const result = await discoverCatalog(website, options);
    expect(result.status).toBe(status);
    if (host) expect(result).toMatchObject({ url: `https://${host}${wellKnown}`, error: expect.any(Error) });
    expect(requests).toHaveLength(4);
  });

  it.each(['gzip', 'deflate', 'br'] as const)('caps decoded catalog bytes for %s responses', async (encoding) => {
    const document = { ...catalog, padding: 'x'.repeat(4_000) };
    const decoded = Buffer.from(JSON.stringify(document));
    const compressed = { gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync }[encoding](decoded);
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else response.writeHead(200, { 'content-encoding': encoding }).end(compressed);
    };
    await expect(discoverCatalog(website, { ...options, maxResponseBytes: decoded.length })).resolves.toMatchObject({
      status: 'found', catalog: document,
    });
    await expect(discoverCatalog(website, { ...options, maxResponseBytes: decoded.length - 1 })).resolves.toMatchObject({
      status: 'fetch_failed', error: expect.any(Error),
    });
  });

  it('bounds streamed catalog bodies without a Content-Length header', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else {
        response.write('{"specVersion":"1.0","entries":[],"padding":"');
        response.end(`${'x'.repeat(1_000)}"}`);
      }
    };
    await expect(discoverCatalog(website, { ...options, maxResponseBytes: 100 })).resolves.toMatchObject({
      status: 'fetch_failed', error: expect.any(Error),
    });
  });

  it('gives the website and selected catalog fresh resource deadlines', async () => {
    respond = (request, response) => later(160, () => {
      if (request.url === '/start') response.writeHead(200, { link: '</catalog>; rel="ai-catalog"' }).end();
      else response.end(body);
    });
    await expect(discoverCatalog(website, { ...options, resourceTimeoutMs: 280 })).resolves.toMatchObject({ status: 'found' });
  });

  it('does not reset a resource deadline when following redirects', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else later(90, () => response.writeHead(302, { location: `${request.url}/next` }).end());
    };
    await expect(discoverCatalog(website, { ...options, resourceTimeoutMs: 230 })).resolves.toMatchObject({
      status: 'fetch_failed', error: expect.any(Error),
    });
    expect(requests.length).toBeLessThanOrEqual(5);
  });

  it('includes DNS in the deadline and does not connect after a late answer', async () => {
    let finish: (value: unknown) => void = () => {};
    network.resolve.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await expect(discoverCatalog(website, { ...options, resourceTimeoutMs: 40 })).resolves.toMatchObject({
      status: 'fetch_failed', url: website, error: expect.any(Error),
    });
    finish([{ address: '8.8.8.8', family: 4 }]);
    await Promise.resolve();
    expect(network.options).toHaveLength(0);
  });

  it('does not reset the catalog deadline for arriving body chunks', async () => {
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else {
        response.write('{');
        later(70, () => response.write(' '));
        later(140, () => response.write(' '));
        later(210, () => response.end(body.slice(1)));
      }
    };
    await expect(discoverCatalog(website, { ...options, resourceTimeoutMs: 180 })).resolves.toMatchObject({
      status: 'fetch_failed', error: expect.any(Error),
    });
  });

  it.each([
    { operation: 'cancel' },
    new HttpFetchError('caller reason'),
    new CatalogParseError([]),
  ])('rejects with the original cancellation reason during catalog retrieval: %s', async (reason) => {
    const controller = new AbortController();
    respond = (request, response) => {
      if (request.url === '/start') response.end();
      else {
        response.write('{');
        later(20, () => controller.abort(reason));
      }
    };
    await expect(discoverCatalog(website, { ...options, signal: controller.signal })).rejects.toBe(reason);
  });

  it('does not start DNS for a previously aborted caller', async () => {
    const controller = new AbortController();
    controller.abort('stop');
    await expect(discoverCatalog(website, { ...options, signal: controller.signal })).rejects.toBe('stop');
    expect(network.resolve).not.toHaveBeenCalled();
  });

  it('uses native AbortSignal operations despite caller property overrides', async () => {
    const controller = new AbortController();
    for (const property of ['aborted', 'reason', 'addEventListener', 'removeEventListener']) {
      Object.defineProperty(controller.signal, property, { get() { throw new Error('Caller override invoked'); } });
    }
    await expect(discoverCatalog(website, { ...options, signal: controller.signal })).resolves.toMatchObject({ status: 'found' });
  });

  it('captures options before awaiting the website response', async () => {
    const mutableOptions = { ...options };
    network.resolve.mockImplementationOnce(async () => {
      mutableOptions.maxResponseBytes = 1;
      return [{ address: '8.8.8.8', family: 4 }];
    });
    await expect(discoverCatalog(website, mutableOptions)).resolves.toMatchObject({ status: 'found' });
  });

  it('rejects option accessors without invoking them or starting I/O', async () => {
    const getter = vi.fn(() => 100);
    const accessorOptions = Object.defineProperty({}, 'resourceTimeoutMs', { get: getter });
    await expect(discoverCatalog(website, accessorOptions)).rejects.toBeInstanceOf(TypeError);
    expect(getter).not.toHaveBeenCalled();
    expect(network.resolve).not.toHaveBeenCalled();
  });

  it('reports an initial DNS failure without attempting well-known retrieval', async () => {
    const cause = Object.assign(new Error('DNS failed'), { code: 'ENOTFOUND' });
    network.resolve.mockRejectedValueOnce(cause);
    await expect(discoverCatalog(website, options)).resolves.toMatchObject({ status: 'fetch_failed', url: website });
    expect(network.resolve).toHaveBeenCalledTimes(1);
    expect(requests).toHaveLength(0);
  });

  it('rejects unexpected DNS backend failures instead of treating them as discovery results', async () => {
    const cause = new RangeError('DNS resource unavailable');
    network.resolve.mockRejectedValueOnce(cause);
    await expect(discoverCatalog(website, options)).rejects.toBe(cause);
  });

  it('rejects unexpected decoder failures instead of classifying the catalog as invalid', async () => {
    const cause = new RangeError('Decoder resource unavailable');
    const decode = vi.spyOn(TextDecoder.prototype, 'decode').mockImplementation(() => { throw cause; });
    try {
      await expect(discoverCatalog(website, options)).rejects.toBe(cause);
    } finally {
      decode.mockRestore();
    }
  });

  it('rejects unexpected JSON backend failures instead of classifying the catalog as invalid', async () => {
    const cause = new RangeError('JSON backend unavailable');
    const parseJson = JSON.parse;
    const parse = vi.spyOn(JSON, 'parse').mockImplementation((text, reviver) => {
      if (text === body) throw cause;
      return parseJson(text, reviver);
    });
    try {
      await expect(discoverCatalog(website, options)).rejects.toBe(cause);
    } finally {
      parse.mockRestore();
    }
  });
});
