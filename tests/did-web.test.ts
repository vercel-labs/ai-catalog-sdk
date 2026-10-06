import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createServer, type RequestOptions, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo, LookupFunction } from 'node:net';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const network = vi.hoisted(() => ({
  port: 0,
  ca: '',
  options: [] as RequestOptions[],
  lookups: [] as string[],
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
      // The test network maps already-checked public destinations to the local
      // fixture server. Everything else uses native HTTPS, including socket
      // lookup invocation, SNI, certificate verification and stream decoding.
      const lookup: LookupFunction = (hostname, lookupOptions, callback) => {
        network.lookups.push(hostname);
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

import { resolveDidWeb } from '../src/internal/did-web.js';
import { IssuerCheckError } from '../src/internal/publisher-profile.js';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntryTrustManifest,
  createTrustManifestSignaturePayload,
} from '../src/verification.js';
import type { CatalogEntryWithData } from '../src/types.js';

const options = { timeoutMs: 2_000, maxResponseBytes: 1024 * 1024 };
const document = { id: 'did:web:publisher.example', assertionMethod: [] };
let server: Server;
let respond: (request: IncomingMessage, response: ServerResponse) => void;

beforeAll(async () => {
  const cert = readFileSync(new URL('./fixtures/transport-cert.pem', import.meta.url), 'utf8');
  const key = readFileSync(new URL('./fixtures/transport-key.pem', import.meta.url), 'utf8');
  network.ca = cert;
  server = createServer({ cert, key }, (request, response) => respond(request, response));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  network.port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

beforeEach(() => {
  network.resolve.mockReset();
  network.resolve.mockResolvedValue([{ address: '8.8.8.8', family: 4 }]);
  network.options.length = 0;
  network.lookups.length = 0;
  network.addresses.length = 0;
  respond = (request, response) => {
    expect(request.url).toBe('/.well-known/did.json');
    response.setHeader('content-type', 'application/did+json');
    response.end(JSON.stringify(document));
  };
});

describe('native did:web transport', () => {
  it('verifies a signed entry end to end through native HTTPS and rejects current key removal', async () => {
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const identity = 'did:web:publisher.example';
    const kid = `${identity}#release-key`;
    const data = { amount: 123, currency: 'USD' };
    const identifier = 'urn:air:publisher.example:finance:agent:billing';
    const type = 'application/json';
    const manifest = {
      identity,
      issuedAt: '2026-01-01T00:00:00Z',
      subject: {
        identifier,
        type,
        digest: `sha256:${createHash('sha256').update(canonicalizeJsonValueToBytes(data)).digest('hex')}`,
      },
    };
    const protectedSegment = Buffer.from(JSON.stringify({ alg: 'ES256', kid })).toString('base64url');
    const payloadSegment = Buffer.from(createTrustManifestSignaturePayload(manifest)).toString('base64url');
    const signature = sign('sha256', Buffer.from(`${protectedSegment}.${payloadSegment}`), {
      key: keys.privateKey, dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    const entry: CatalogEntryWithData = {
      identifier, type, data,
      trustManifest: { ...manifest, signature: `${protectedSegment}..${signature}` },
    };
    const did = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: identity,
      assertionMethod: [{
        id: kid, type: 'JsonWebKey2020', controller: identity,
        publicKeyJwk: keys.publicKey.export({ format: 'jwk' }),
      }],
    };
    respond = (_request, response) => response.end(JSON.stringify(did));
    await expect(checkCatalogEntryTrustManifest(entry)).resolves.toEqual({ status: 'valid' });
    did.assertionMethod = [];
    await expect(checkCatalogEntryTrustManifest(entry)).resolves.toMatchObject({ status: 'issuer_check_failed' });
    expect(network.options).toHaveLength(2);
  });

  it('uses checked addresses at the connection boundary and verifies the HTTPS hostname', async () => {
    await expect(resolveDidWeb('did:web:publisher.example', options)).resolves.toEqual(document);
    expect(network.resolve).toHaveBeenCalledExactlyOnceWith('publisher.example', { all: true, verbatim: true });
    expect(network.lookups).toEqual(['publisher.example']);
    expect(network.addresses).toEqual(['8.8.8.8']);
    expect(network.options[0]).toMatchObject({ agent: false, rejectUnauthorized: true, servername: 'publisher.example' });
    await expect(resolveDidWeb('did:web:wrong.example', options)).rejects.toMatchObject({
      name: 'IssuerCheckError', cause: { code: 'ERR_TLS_CERT_ALTNAME_INVALID' },
    });
  });

  it.each([
    '0.0.0.0', '10.20.30.40', '100.100.100.200', '127.9.8.7', '169.254.169.254',
    '172.16.0.1', '172.31.255.254', '192.168.0.1', '198.18.0.1', '224.0.0.1',
    '255.255.255.255', '168.63.129.16', '::', '::1', 'fc00::1', 'fd00:ec2::254',
    'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '64:ff9b::a00:1', '2002:a00:1::1',
  ])('rejects a nonpublic DNS destination %s without connecting', async (address) => {
    network.resolve.mockResolvedValue([{ address, family: address.includes(':') ? 6 : 4 }]);
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBeInstanceOf(IssuerCheckError);
    expect(network.options).toHaveLength(0);
  });

  it('rejects mixed public/private DNS answers, instead of falling back into a private network', async () => {
    network.resolve.mockResolvedValue([{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]);
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBeInstanceOf(IssuerCheckError);
    expect(network.options).toHaveLength(0);
  });

  it('keeps all validated address families available to the native connector', async () => {
    network.resolve.mockResolvedValue([{ address: '2606:4700:4700::1111', family: 6 }, { address: '8.8.8.8', family: 4 }]);
    await expect(resolveDidWeb('did:web:publisher.example', options)).resolves.toEqual(document);
    expect(network.addresses).toEqual(['2606:4700:4700::1111', '8.8.8.8']);
  });

  it('follows relative and cross-host HTTPS redirects with fresh address checks and preserved SNI', async () => {
    respond = (request, response) => {
      if (request.url === '/.well-known/did.json') response.writeHead(302, { location: '/document' }).end();
      else if (request.url === '/document') response.writeHead(307, { location: 'https://other.example/final' }).end();
      else response.end(JSON.stringify(document));
    };
    await expect(resolveDidWeb('did:web:publisher.example', options)).resolves.toEqual(document);
    expect(network.resolve.mock.calls.map(([host]) => host)).toEqual(['publisher.example', 'publisher.example', 'other.example']);
    expect(network.options.map((value) => value.servername)).toEqual(['publisher.example', 'publisher.example', 'other.example']);
  });

  it.each(['http://publisher.example/did', 'https://127.0.0.1/did', 'https://[::1]/did', 'https://user:secret@other.example/did'])('refuses disallowed redirect %s', async (location) => {
    respond = (_request, response) => response.writeHead(302, { location }).end();
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBeInstanceOf(IssuerCheckError);
    expect(network.options).toHaveLength(1);
  });

  it('rechecks a redirect hostname resolving privately', async () => {
    network.resolve.mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }]).mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);
    respond = (_request, response) => response.writeHead(302, { location: 'https://other.example/did' }).end();
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBeInstanceOf(IssuerCheckError);
    expect(network.options).toHaveLength(1);
  });

  it('bounds redirect loops', async () => {
    respond = (_request, response) => response.writeHead(302, { location: '/.well-known/did.json' }).end();
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toThrow('loop');
    expect(network.options).toHaveLength(1);
  });

  it.each(['gzip', 'deflate', 'br'] as const)('reads %s and applies the ceiling to decoded bytes', async (encoding) => {
    const body = Buffer.from(JSON.stringify({ ...document, padding: 'x'.repeat(4000) }));
    const compressed = { gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync }[encoding](body);
    respond = (_request, response) => {
      response.writeHead(200, { 'content-encoding': encoding });
      response.end(compressed);
    };
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, maxResponseBytes: body.length })).resolves.toMatchObject(document);
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, maxResponseBytes: body.length - 1 })).rejects.toThrow('maxResponseBytes');
  });

  it('does not trust Content-Length as a substitute for a streaming body limit', async () => {
    respond = (_request, response) => {
      response.write('{"padding":"');
      response.end(`${'x'.repeat(1024)}"}`);
    };
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, maxResponseBytes: 100 })).rejects.toThrow('maxResponseBytes');
  });

  it.each([
    [Buffer.from('not json'), undefined],
    [Buffer.from([0xff, 0xfe]), undefined],
    [Buffer.from('not gzip'), 'gzip'],
    [Buffer.from('{}'), 'unknown'],
  ] as const)('rejects invalid response bytes or encoding', async (body, encoding) => {
    respond = (_request, response) => {
      if (encoding) response.setHeader('content-encoding', encoding);
      response.end(body);
    };
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBeInstanceOf(IssuerCheckError);
  });

  it('returns meaningful expected DNS and HTTP failures', async () => {
    const cause = Object.assign(new Error('DNS failed'), { code: 'ENOTFOUND' });
    network.resolve.mockRejectedValueOnce(cause);
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toMatchObject({ cause });
    respond = (_request, response) => response.writeHead(404).end();
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toThrow('HTTP 404');
  });

  it('rejects unexpected decoder resource failures instead of classifying them as invalid documents', async () => {
    const cause = new RangeError('Decoder resource unavailable');
    const decode = vi.spyOn(TextDecoder.prototype, 'decode').mockImplementation(() => { throw cause; });
    try {
      await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBe(cause);
    } finally {
      decode.mockRestore();
    }
  });

  it('rejects unexpected DNS resource failures', async () => {
    const cause = new RangeError('DNS resource unavailable');
    network.resolve.mockRejectedValueOnce(cause);
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBe(cause);
    expect(network.options).toHaveLength(0);
  });

  it('enforces the deadline during DNS, and does not connect after a late answer', async () => {
    let finish: (addresses: unknown) => void = () => {};
    network.resolve.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, timeoutMs: 20 })).rejects.toThrow('timeoutMs');
    finish([{ address: '8.8.8.8', family: 4 }]);
    await Promise.resolve();
    expect(network.options).toHaveLength(0);
  });

  it('enforces one total deadline across a stalled decoded response', async () => {
    respond = (_request, response) => {
      response.writeHead(200);
      response.write('{');
    };
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, timeoutMs: 80 })).rejects.toThrow('timeoutMs');
  });

  it.each([undefined, 'gzip'])('handles an interrupted response with content encoding %s', async (encoding) => {
    respond = (_request, response) => {
      if (encoding) response.setHeader('content-encoding', encoding);
      response.setHeader('content-length', '1000');
      response.write(Buffer.from([0x1f, 0x8b]));
      setImmediate(() => response.destroy());
    };
    await expect(resolveDidWeb('did:web:publisher.example', options)).rejects.toBeInstanceOf(IssuerCheckError);
  });

  it('rejects cancellation with its original reason during body reading', async () => {
    const controller = new AbortController();
    const reason = { operation: 'cancel' };
    respond = (_request, response) => {
      response.writeHead(200);
      response.write('{');
      controller.abort(reason);
    };
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, signal: controller.signal })).rejects.toBe(reason);
  });

  it('does not connect when already cancelled', async () => {
    const controller = new AbortController();
    controller.abort('stop');
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, signal: controller.signal })).rejects.toBe('stop');
    expect(network.resolve).not.toHaveBeenCalled();
    expect(network.options).toHaveLength(0);
  });

  it('uses native AbortSignal operations even when caller properties are overridden', async () => {
    const controller = new AbortController();
    for (const property of ['aborted', 'reason', 'addEventListener', 'removeEventListener']) {
      Object.defineProperty(controller.signal, property, { get() { throw new Error('Caller override invoked'); } });
    }
    await expect(resolveDidWeb('did:web:publisher.example', { ...options, signal: controller.signal })).resolves.toEqual(document);
  });
});
