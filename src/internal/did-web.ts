import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import type { IncomingMessage } from 'node:http';
import { BlockList, isIP, type LookupFunction } from 'node:net';
import { performance } from 'node:perf_hooks';
import type { Readable, Transform } from 'node:stream';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

import { IssuerCheckError } from './publisher-profile.js';

interface ResolutionOptions {
  signal?: AbortSignal;
  timeoutMs: number;
  maxResponseBytes: number;
}

const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
const signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason')?.get;

const nonPublicAddresses = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) nonPublicAddresses.addSubnet(address, prefix, 'ipv4');
// Azure's platform virtual address is globally numbered but not a public endpoint.
nonPublicAddresses.addAddress('168.63.129.16', 'ipv4');
const globalIpv6 = new BlockList();
globalIpv6.addSubnet('2000::', 3, 'ipv6');
for (const [address, prefix] of [
  ['2001::', 32], // Teredo embeds an IPv4 destination.
  ['2001:2::', 48], // Benchmarking.
  ['2001:db8::', 32], // Documentation.
  ['2001:10::', 28], // ORCHID.
  ['2001:20::', 28], // ORCHIDv2.
  ['2002::', 16], // 6to4 embeds an IPv4 destination.
] as const) nonPublicAddresses.addSubnet(address, prefix, 'ipv6');

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !nonPublicAddresses.check(address, 'ipv4');
  // This also excludes mapped IPv4, NAT64, unique-local, link-local,
  // unspecified, loopback and multicast addresses.
  return family === 6 && !address.includes('%') &&
    globalIpv6.check(address, 'ipv6') &&
    !nonPublicAddresses.check(address, 'ipv6');
}

function assertPublicAddress(address: string): void {
  if (!isPublicAddress(address)) {
    throw new IssuerCheckError('DID resolution requires public network addresses.');
  }
}

function checkedUrl(url: URL): string {
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new IssuerCheckError('DID resolution requires an HTTPS URL without credentials.');
  }
  // WHATWG URLs retain brackets on IPv6 hosts; DNS and TLS do not use them.
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname)) assertPublicAddress(hostname);
  return hostname;
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        if (signal.aborted) reject(signal.reason);
        else resolve(value);
      },
      (cause) => {
        signal.removeEventListener('abort', onAbort);
        reject(signal.aborted ? signal.reason : cause);
      },
    );
  });
}

async function pinnedLookup(hostname: string, signal: AbortSignal): Promise<LookupFunction> {
  const addresses = isIP(hostname)
    ? [{ address: hostname, family: isIP(hostname) }]
    : await abortable(lookup(hostname, { all: true, verbatim: true }), signal)
      .catch((cause: unknown) => {
        if (signal.aborted) throw signal.reason;
        if (cause instanceof TypeError || cause instanceof RangeError) throw cause;
        throw new IssuerCheckError('The publisher DID hostname could not be resolved.', { cause });
      });
  signal.throwIfAborted();
  if (addresses.length === 0) {
    throw new IssuerCheckError('The publisher DID hostname has no network addresses.');
  }
  for (const { address } of addresses) assertPublicAddress(address);
  // Supply exactly the addresses just checked to the socket connector. There
  // is no second DNS lookup between validation and connection. Keep all of
  // them available for Node's native address-family fallback.
  return (_hostname, options, callback) => {
    if (signal.aborted) {
      callback(new Error('DID resolution was cancelled.', { cause: signal.reason }), []);
      return;
    }
    const eligible = addresses.filter(({ family }) => !options.family || family === options.family);
    if (eligible.length === 0) {
      callback(new Error('No resolved address has the requested family.'), []);
    } else if (options.all) {
      callback(null, eligible);
    } else {
      const first = eligible[0];
      if (first) callback(null, first.address, first.family);
    }
  };
}

async function getResponse(url: URL, signal: AbortSignal): Promise<IncomingMessage> {
  const hostname = checkedUrl(url);
  const connectLookup = await pinnedLookup(hostname, signal);
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      req.destroy();
      reject(signal.reason);
    };
    const req = request(url, {
      method: 'GET',
      // A fresh native agent avoids pooled sockets, global-agent overrides and
      // ambient proxy settings bypassing the checked connection boundary.
      agent: false,
      lookup: connectLookup,
      servername: isIP(hostname) ? '' : hostname,
      rejectUnauthorized: true,
      headers: {
        accept: 'application/did+json, application/did+ld+json, application/json',
        'accept-encoding': 'gzip, deflate, br',
      },
    });
    signal.addEventListener('abort', onAbort, { once: true });
    req.once('error', (cause) => {
      signal.removeEventListener('abort', onAbort);
      reject(signal.aborted ? signal.reason :
        cause instanceof TypeError || cause instanceof RangeError ? cause :
        new IssuerCheckError('The publisher DID HTTPS request failed.', { cause }));
    });
    req.once('response', (response) => {
      signal.removeEventListener('abort', onAbort);
      if (signal.aborted) {
        response.destroy();
        reject(signal.reason);
      } else resolve(response);
    });
    req.end();
  });
}

async function readDocument(
  response: IncomingMessage,
  signal: AbortSignal,
  maxResponseBytes: number,
): Promise<unknown> {
  const encoding = response.headers['content-encoding']?.trim().toLowerCase();
  let decoded: Readable = response;
  if (encoding && encoding !== 'identity') {
    let decoder: Transform;
    if (encoding === 'gzip') decoder = createGunzip();
    else if (encoding === 'deflate') decoder = createInflate();
    else if (encoding === 'br') decoder = createBrotliDecompress();
    else {
      response.destroy();
      throw new IssuerCheckError('The publisher DID response has an unsupported content encoding.');
    }
    decoded = decoder;
    response.once('error', (cause) => decoder.destroy(cause));
    response.pipe(decoder);
  }
  const onAbort = () => {
    response.destroy();
    decoded.destroy(new Error('DID resolution was cancelled.', { cause: signal.reason }));
  };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    signal.throwIfAborted();
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of decoded) {
      signal.throwIfAborted();
      length += chunk.length;
      if (length > maxResponseBytes) {
        throw new IssuerCheckError('The decoded publisher DID document exceeds maxResponseBytes.');
      }
      chunks.push(chunk);
    }
    signal.throwIfAborted();
    const bytes = Buffer.concat(chunks, length);
    let json: string;
    try {
      json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (cause) {
      if (!(cause instanceof TypeError) || !('code' in cause) ||
        cause.code !== 'ERR_ENCODING_INVALID_ENCODED_DATA') throw cause;
      throw new IssuerCheckError('The publisher DID document is not valid UTF-8.', { cause });
    }
    try {
      return JSON.parse(json);
    } catch (cause) {
      if (!(cause instanceof SyntaxError)) throw cause;
      throw new IssuerCheckError('The publisher DID document is not valid JSON.', { cause });
    }
  } catch (cause) {
    if (signal.aborted) throw signal.reason;
    if (cause instanceof IssuerCheckError) throw cause;
    if (cause instanceof TypeError || cause instanceof RangeError) throw cause;
    throw new IssuerCheckError('The publisher DID response could not be read or decoded.', { cause });
  } finally {
    signal.removeEventListener('abort', onAbort);
    response.destroy();
    if (decoded !== response) decoded.destroy();
  }
}

/** Resolves a validated root did:web issuer through a bounded native HTTPS request. */
export async function resolveDidWeb(identity: string, options: ResolutionOptions): Promise<unknown> {
  const controller = new AbortController();
  const deadline = performance.now() + options.timeoutMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Use the native signal operations rather than caller-overridden accessors
  // or methods. The public boundary has already checked the native brand.
  const onAbort = () => controller.abort(signalReason?.call(options.signal));
  if (options.signal !== undefined) {
    EventTarget.prototype.addEventListener.call(options.signal, 'abort', onAbort, { once: true });
    if (signalAborted?.call(options.signal)) onAbort();
  }
  const scheduleDeadline = () => {
    const remaining = deadline - performance.now();
    if (remaining <= 0) {
      controller.abort(new IssuerCheckError('Publisher DID resolution exceeded timeoutMs.'));
    } else timer = setTimeout(scheduleDeadline, Math.min(remaining, 2 ** 31 - 1));
  };
  scheduleDeadline();
  try {
    let url = new URL(`https://${identity.slice('did:web:'.length)}/.well-known/did.json`);
    const visited = new Set<string>();
    for (;;) {
      controller.signal.throwIfAborted();
      url.hash = '';
      if (visited.has(url.href)) {
        throw new IssuerCheckError('The publisher DID endpoint redirects in a loop.');
      }
      visited.add(url.href);
      const response = await getResponse(url, controller.signal);
      const status = response.statusCode;
      if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) {
        const location = response.headers.location;
        response.destroy();
        if (!location) throw new IssuerCheckError('The publisher DID redirect has no Location header.');
        try {
          url = new URL(location, url);
        } catch (cause) {
          throw new IssuerCheckError('The publisher DID redirect URL is invalid.', { cause });
        }
        // Every redirect, including one to a numeric host, is checked afresh.
        continue;
      }
      if (status !== 200) {
        response.destroy();
        throw new IssuerCheckError(`The publisher DID endpoint returned HTTP ${status}.`);
      }
      const document = await readDocument(response, controller.signal, options.maxResponseBytes);
      // Parsing is synchronous, so explicitly sample the monotonic deadline
      // rather than relying on a timer callback being able to run during it.
      if (performance.now() >= deadline) {
        throw new IssuerCheckError('Publisher DID resolution exceeded timeoutMs.');
      }
      controller.signal.throwIfAborted();
      return document;
    }
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (options.signal !== undefined) {
      EventTarget.prototype.removeEventListener.call(options.signal, 'abort', onAbort);
    }
  }
}
