import {
  type CapturedCatalogResourceOptions,
  catalogTransportOptions,
  fetchCatalogResource,
  snapshotCatalogResourceOptions,
} from './internal/catalog-resource.js';
import {
  fetchHttpsResource,
  HttpFetchError,
  normalizeHttpFetchError,
  throwIfAborted,
} from './internal/http-fetch.js';
import { firstCatalogLink } from './internal/link-header.js';
import type { AICatalog, CatalogParseError } from './types.js';

/** Controls cancellation and the bounds of each website or catalog request. */
export interface DiscoverCatalogOptions {
  /** `well-known` skips website advertisements and requests only the input origin's well-known catalog. */
  strategy?: 'auto' | 'well-known';
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
 * `found` and `invalid_catalog` URLs identify the final response. Retrieval
 * failures identify the final response URL when available, or the attempted URL
 * or advertised reference otherwise.
 */
export type CatalogDiscoveryResult =
  | { status: 'found'; catalog: AICatalog; url: string }
  | { status: 'not_found' }
  | { status: 'invalid_catalog'; url: string; error: CatalogParseError }
  | { status: 'fetch_failed'; url: string; error: Error };

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

async function fetchCatalog(url: URL, options: CapturedCatalogResourceOptions) {
  const lookup = await fetchCatalogResource(url, options);
  // Discovery exposes the parsed catalog and location; entry loading also
  // needs the exact artifact bytes for caller-controlled entry verification.
  const result = lookup.result.status === 'found'
    ? { status: 'found' as const, catalog: lookup.result.catalog, url: lookup.result.url }
    : lookup.result;
  return { result, absent: lookup.absent };
}

/**
 * Retrieves one catalog advertised by a website's HTTP Link header, or tries
 * `/.well-known/ai-catalog.json` at its final and then original origin.
 * The first advertised ai-catalog link is authoritative; its failure is terminal.
 * Without an advertisement, the first parsed well-known candidate wins and
 * `not_found` means every candidate returned HTTP 404 or 410.
 * `strategy: 'well-known'` skips the website request and uses only the input origin.
 * Reads website headers only, without HTML discovery or nested catalog traversal.
 * Inputs are captured before I/O. Invalid arguments reject with `TypeError`;
 * caller cancellation and unexpected failures reject rather than becoming results.
 */
export async function discoverCatalog(
  websiteUrl: string,
  options?: DiscoverCatalogOptions,
): Promise<CatalogDiscoveryResult> {
  const originalUrl = snapshotWebsiteUrl(websiteUrl);
  const captured = snapshotCatalogResourceOptions(options);
  const descriptor = options === undefined ? undefined : Object.getOwnPropertyDescriptor(options, 'strategy');
  if (descriptor && !('value' in descriptor))
    throw new TypeError('options.strategy must be an own data property.');
  const strategy: unknown = descriptor?.value === undefined ? 'auto' : descriptor.value;
  if (strategy !== 'auto' && strategy !== 'well-known')
    throw new TypeError('strategy must be auto or well-known.');
  throwIfAborted(captured.signal);
  if (strategy === 'well-known') {
    const lookup = await fetchCatalog(new URL('/.well-known/ai-catalog.json', originalUrl), captured);
    return lookup.absent ? { status: 'not_found' } : lookup.result;
  }
  let page: { url: URL; target: string | undefined };
  try {
    page = await fetchHttpsResource(
      originalUrl,
      { ...catalogTransportOptions(captured, '*/*'), requireLinkExposure: true },
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
      if (!(cause instanceof TypeError)) throw cause;
      return {
        status: 'fetch_failed',
        url: page.target,
        error: normalizeHttpFetchError(new HttpFetchError('The advertised catalog URL is invalid.', { cause }), captured),
      };
    }
    const lookup = await fetchCatalog(target, captured);
    throwIfAborted(captured.signal);
    return lookup.result;
  }
  const origins = [...new Set([page.url.origin, originalUrl.origin])];
  let firstFailure: Exclude<CatalogDiscoveryResult, { status: 'not_found' }> | undefined;
  for (const origin of origins) {
    const lookup = await fetchCatalog(new URL('/.well-known/ai-catalog.json', origin), captured);
    throwIfAborted(captured.signal);
    if (lookup.result.status === 'found') return lookup.result;
    if (!lookup.absent && firstFailure === undefined) firstFailure = lookup.result;
  }
  return firstFailure ?? { status: 'not_found' };
}
