import { types as utilTypes } from 'node:util';

import {
  fetchHttpsResource,
  HttpFetchError,
  throwIfAborted,
  type HttpsResourceOptions,
} from './internal/http-fetch.js';
import { firstCatalogLink } from './internal/link-header.js';
import { safeParseCatalogJson } from './internal/parser.js';
import { type AICatalog, CatalogParseError } from './types.js';

/** Controls cancellation and the bounds of each website or catalog request. */
export interface DiscoverCatalogOptions {
  /** Caller cancellation rejects with this signal's original abort reason. */
  signal?: AbortSignal;
  /** Per-resource timeout, including redirects and body processing; defaults to 120,000 ms. */
  resourceTimeoutMs?: number;
  /** Maximum decoded catalog body size; defaults to 64 MiB. */
  maxResponseBytes?: number;
}

/**
 * A structurally parsed catalog, an absent well-known catalog, or an expected failure.
 * `found` establishes neither cryptographic integrity nor publisher trust.
 * URLs identify the final response when available, otherwise the attempted URL
 * or advertised reference.
 */
export type CatalogDiscoveryResult =
  | { status: 'found'; catalog: AICatalog; url: string }
  | { status: 'not_found' }
  | { status: 'invalid_catalog'; url: string; error: CatalogParseError }
  | { status: 'fetch_failed'; url: string; error: Error };

interface CapturedOptions {
  signal?: AbortSignal;
  resourceTimeoutMs: number;
  maxResponseBytes: number;
}

function snapshotOptions(value: unknown): CapturedOptions {
  if (value === undefined)
    return { resourceTimeoutMs: 120_000, maxResponseBytes: 64 * 1024 * 1024 };
  if (
    value === null || typeof value !== 'object' ||
    utilTypes.isProxy(value) || Array.isArray(value)
  ) throw new TypeError('options must be an object.');
  const options: Record<string, unknown> = Object.create(null);
  for (const name of ['signal', 'resourceTimeoutMs', 'maxResponseBytes']) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) continue;
    if (!('value' in descriptor))
      throw new TypeError(`options.${name} must be an own data property.`);
    options[name] = descriptor.value;
  }
  const resourceTimeoutMs = options.resourceTimeoutMs === undefined ? 120_000 : options.resourceTimeoutMs;
  const maxResponseBytes = options.maxResponseBytes === undefined ? 64 * 1024 * 1024 : options.maxResponseBytes;
  if (
    typeof resourceTimeoutMs !== 'number' ||
    !Number.isFinite(resourceTimeoutMs) || resourceTimeoutMs <= 0
  ) throw new TypeError('resourceTimeoutMs must be a positive finite number.');
  if (
    typeof maxResponseBytes !== 'number' ||
    !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0
  ) throw new TypeError('maxResponseBytes must be a positive safe integer.');
  const signal = options.signal;
  if (signal !== undefined) {
    if (signal === null || typeof signal !== 'object' || utilTypes.isProxy(signal))
      throw new TypeError('signal must be an AbortSignal.');
    try {
      Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get?.call(signal);
    } catch {
      throw new TypeError('signal must be an AbortSignal.');
    }
  }
  return {
    resourceTimeoutMs,
    maxResponseBytes,
    ...(signal === undefined ? {} : { signal: signal as AbortSignal }),
  };
}

function snapshotWebsiteUrl(value: unknown): URL {
  if (typeof value !== 'string')
    throw new TypeError('websiteUrl must be an absolute HTTPS URL string without credentials.');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('websiteUrl must be an absolute HTTPS URL string without credentials.');
  }
  if (url.protocol !== 'https:' || url.username || url.password)
    throw new TypeError('websiteUrl must be an absolute HTTPS URL string without credentials.');
  return url;
}

function transportOptions(options: CapturedOptions, accept: string): HttpsResourceOptions {
  return {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    maxResponseBytes: options.maxResponseBytes,
    timeoutMs: options.resourceTimeoutMs,
    timeoutLabel: 'resourceTimeoutMs',
    accept,
  };
}

function catalogText(bytes: Uint8Array): string {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  try {
    return decoder.decode(bytes);
  } catch (cause) {
    if (!(cause instanceof TypeError) ||
      (cause as NodeJS.ErrnoException).code !== 'ERR_ENCODING_INVALID_ENCODED_DATA') throw cause;
    throw new CatalogParseError([
      { code: 'invalid_json', path: [], message: 'The catalog text is not valid UTF-8 JSON.' },
    ], cause);
  }
}

type CatalogLookup = {
  result: Exclude<CatalogDiscoveryResult, { status: 'not_found' }>;
  absent: boolean;
};

async function fetchCatalog(url: URL, options: CapturedOptions): Promise<CatalogLookup> {
  let responseUrl = url.href;
  let absent = false;
  try {
    const result = await fetchHttpsResource(
      url,
      transportOptions(options, 'application/ai-catalog+json, application/json'),
      async (response): Promise<CatalogLookup['result']> => {
        responseUrl = response.url.href;
        if (response.statusCode < 200 || response.statusCode >= 300) {
          absent = response.statusCode === 404 || response.statusCode === 410;
          throw new HttpFetchError(`Catalog request returned HTTP ${response.statusCode}.`);
        }
        const parsed = safeParseCatalogJson(catalogText(await response.readBody()));
        return parsed.success
          ? { status: 'found', catalog: parsed.data, url: responseUrl }
          : { status: 'invalid_catalog', url: responseUrl, error: parsed.error };
      },
    );
    throwIfAborted(options.signal);
    return { result, absent: false };
  } catch (error) {
    throwIfAborted(options.signal);
    if (error instanceof CatalogParseError)
      return { result: { status: 'invalid_catalog', url: responseUrl, error }, absent: false };
    if (!(error instanceof HttpFetchError)) throw error;
    return { result: { status: 'fetch_failed', url: responseUrl, error }, absent };
  }
}

/**
 * Retrieves one catalog advertised by a website's HTTP Link header, or tries
 * `/.well-known/ai-catalog.json` at its final and then original origin.
 * The first advertised ai-catalog link is authoritative; its failure is terminal.
 * Without an advertisement, the first parsed well-known candidate wins and
 * `not_found` means every candidate returned HTTP 404 or 410.
 * Reads website headers only, without HTML discovery or nested catalog traversal.
 * Inputs are captured before I/O. Invalid arguments reject with `TypeError`;
 * caller cancellation and unexpected failures reject rather than becoming results.
 */
export async function discoverCatalog(
  websiteUrl: string,
  options?: DiscoverCatalogOptions,
): Promise<CatalogDiscoveryResult> {
  const originalUrl = snapshotWebsiteUrl(websiteUrl);
  const captured = snapshotOptions(options);
  throwIfAborted(captured.signal);
  let page: { url: URL; target: string | undefined };
  try {
    page = await fetchHttpsResource(
      originalUrl,
      transportOptions(captured, '*/*'),
      (response) => ({
        url: new URL(response.url.href),
        target: firstCatalogLink(response.headers.link),
      }),
    );
    throwIfAborted(captured.signal);
  } catch (error) {
    throwIfAborted(captured.signal);
    if (!(error instanceof HttpFetchError)) throw error;
    return { status: 'fetch_failed', url: originalUrl.href, error };
  }
  if (page.target !== undefined) {
    let target: URL;
    try {
      target = new URL(page.target, page.url);
    } catch (cause) {
      if (!(cause instanceof TypeError) ||
        (cause as NodeJS.ErrnoException).code !== 'ERR_INVALID_URL') throw cause;
      return {
        status: 'fetch_failed',
        url: page.target,
        error: new HttpFetchError('The advertised catalog URL is invalid.', { cause }),
      };
    }
    const lookup = await fetchCatalog(target, captured);
    throwIfAborted(captured.signal);
    return lookup.result;
  }
  const origins = [...new Set([page.url.origin, originalUrl.origin])];
  let firstFailure: CatalogLookup['result'] | undefined;
  for (const origin of origins) {
    const lookup = await fetchCatalog(new URL('/.well-known/ai-catalog.json', origin), captured);
    throwIfAborted(captured.signal);
    if (lookup.result.status === 'found') return lookup.result;
    if (!lookup.absent && firstFailure === undefined) firstFailure = lookup.result;
  }
  return firstFailure ?? { status: 'not_found' };
}
