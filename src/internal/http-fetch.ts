import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import { BlockList, isIP, type LookupFunction } from 'node:net';
import { performance } from 'node:perf_hooks';
import type { Readable, Transform } from 'node:stream';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

export class HttpFetchError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'HttpFetchError';
  }
}

export interface HttpsResource {
  readonly url: URL;
  readonly statusCode: number;
  readonly headers: IncomingHttpHeaders;
  readBody(): Promise<Uint8Array>;
}

export interface HttpsResourceOptions {
  signal?: AbortSignal;
  timeoutMs: number;
  maxResponseBytes: number;
  accept: string;
  timeoutLabel?: string;
}

const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
const signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason')?.get;

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal !== undefined && signalAborted?.call(signal)) throw signalReason?.call(signal);
}

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
    throw new HttpFetchError('HTTPS retrieval requires public network addresses.');
  }
}

function checkedUrl(url: URL): string {
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new HttpFetchError('HTTPS retrieval requires an HTTPS URL without credentials.');
  }
  // WHATWG URLs retain brackets on IPv6 hosts; DNS and TLS do not use them.
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname)) assertPublicAddress(hostname);
  return hostname;
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) {
      signal.removeEventListener('abort', onAbort);
      reject(signal.reason);
    }
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
        throw new HttpFetchError('The HTTPS resource hostname could not be resolved.', { cause });
      });
  signal.throwIfAborted();
  if (addresses.length === 0) {
    throw new HttpFetchError('The HTTPS resource hostname has no network addresses.');
  }
  for (const { address } of addresses) assertPublicAddress(address);
  // Supply exactly the addresses just checked to the socket connector. There
  // is no second DNS lookup between validation and connection. Keep all of
  // them available for Node's native address-family fallback.
  return (_hostname, options, callback) => {
    if (signal.aborted) {
      callback(new Error('HTTPS retrieval was cancelled.', { cause: signal.reason }), []);
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

async function getResponse(url: URL, signal: AbortSignal, accept: string): Promise<IncomingMessage> {
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
        accept,
        'accept-encoding': 'gzip, deflate, br',
      },
    });
    signal.addEventListener('abort', onAbort, { once: true });
    req.once('error', (cause) => {
      signal.removeEventListener('abort', onAbort);
      reject(signal.aborted ? signal.reason :
        cause instanceof TypeError || cause instanceof RangeError ? cause :
        new HttpFetchError('The HTTPS request failed.', { cause }));
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

async function readBody(
  response: IncomingMessage,
  signal: AbortSignal,
  maxResponseBytes: number,
): Promise<Uint8Array> {
  const encoding = response.headers['content-encoding']?.trim().toLowerCase();
  let decoded: Readable = response;
  if (encoding && encoding !== 'identity') {
    let decoder: Transform;
    if (encoding === 'gzip') decoder = createGunzip();
    else if (encoding === 'deflate') decoder = createInflate();
    else if (encoding === 'br') decoder = createBrotliDecompress();
    else {
      response.destroy();
      throw new HttpFetchError('The HTTPS resource response has an unsupported content encoding.');
    }
    decoded = decoder;
    response.once('error', (cause) => decoder.destroy(cause));
    response.pipe(decoder);
  }
  const onAbort = () => {
    response.destroy();
    decoded.destroy(new Error('HTTPS retrieval was cancelled.', { cause: signal.reason }));
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
        throw new HttpFetchError('The decoded HTTPS response exceeds maxResponseBytes.');
      }
      chunks.push(chunk);
    }
    signal.throwIfAborted();
    return Buffer.concat(chunks, length);
  } catch (cause) {
    if (signal.aborted) throw signal.reason;
    if (cause instanceof HttpFetchError) throw cause;
    if (cause instanceof TypeError || cause instanceof RangeError) throw cause;
    throw new HttpFetchError('The HTTPS resource response could not be read or decoded.', { cause });
  } finally {
    signal.removeEventListener('abort', onAbort);
    response.destroy();
    if (decoded !== response) decoded.destroy();
  }
}

/** Fetches one public HTTPS resource within a single DNS, redirect and consumption budget. */
export async function fetchHttpsResource<T>(
  initialUrl: URL,
  options: HttpsResourceOptions,
  consume: (response: HttpsResource) => T | Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const deadline = performance.now() + options.timeoutMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutError = () => new HttpFetchError(`HTTPS retrieval exceeded ${options.timeoutLabel ?? 'timeoutMs'}.`);
  // Use native signal operations rather than caller-overridden accessors or methods.
  const onAbort = () => controller.abort(signalReason?.call(options.signal));
  if (options.signal !== undefined) {
    EventTarget.prototype.addEventListener.call(options.signal, 'abort', onAbort, { once: true });
    if (signalAborted?.call(options.signal)) onAbort();
  }
  const scheduleDeadline = () => {
    const remaining = deadline - performance.now();
    if (remaining <= 0) controller.abort(timeoutError());
    else timer = setTimeout(scheduleDeadline, Math.min(remaining, 2 ** 31 - 1));
  };
  scheduleDeadline();
  let response: IncomingMessage | undefined;
  try {
    let url = new URL(initialUrl.href);
    const visited = new Set<string>();
    for (;;) {
      controller.signal.throwIfAborted();
      url.hash = '';
      if (visited.has(url.href)) {
        throw new HttpFetchError('The HTTPS endpoint redirects in a loop.');
      }
      visited.add(url.href);
      response = await getResponse(url, controller.signal, options.accept);
      const status = response.statusCode;
      const location = response.headers.location;
      if (location && (status === 301 || status === 302 || status === 303 || status === 307 || status === 308)) {
        response.destroy();
        try {
          url = new URL(location, url);
        } catch (cause) {
          throw new HttpFetchError('The HTTPS redirect URL is invalid.', { cause });
        }
        // Every redirect, including one to a numeric host, is checked afresh.
        continue;
      }
      const finalResponse = response;
      let body: Promise<Uint8Array> | undefined;
      const result = await abortable(Promise.resolve(consume({
        url,
        statusCode: status ?? 0,
        headers: finalResponse.headers,
        readBody: () => body ??= readBody(finalResponse, controller.signal, options.maxResponseBytes),
      })), controller.signal);
      // Synchronous consumption can keep the timer from firing, so explicitly
      // sample the monotonic deadline after parsing or other callback work.
      if (performance.now() >= deadline) throw timeoutError();
      controller.signal.throwIfAborted();
      return result;
    }
  } finally {
    response?.destroy();
    if (timer !== undefined) clearTimeout(timer);
    if (options.signal !== undefined) {
      EventTarget.prototype.removeEventListener.call(options.signal, 'abort', onAbort);
    }
  }
}
