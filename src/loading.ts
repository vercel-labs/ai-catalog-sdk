import { types as utilTypes } from 'node:util';

import { mediaTypes } from './entry-types.js';
import {
  fetchCatalogResource,
  snapshotCatalogResourceOptions,
} from './internal/catalog-resource.js';
import { HttpFetchError, throwIfAborted } from './internal/http-fetch.js';
import { preflightJsonValue } from './internal/json-value.js';
import { safeParseCatalog, safeParseCatalogEntry } from './internal/parser.js';
import {
  type AICatalog,
  type CatalogEntry,
  type CatalogEntryWithData,
  type CatalogEntryWithUrl,
  CatalogParseError,
} from './types.js';

/** Resolution context, cancellation, and bounds for loading one catalog entry. */
export interface LoadCatalogFromEntryOptions {
  /**
   * Absolute URL used to resolve relative `entry.url` values; without it, a
   * relative reference returns `fetch_failed`. Successful inline loads preserve
   * it as their result's `url`.
   */
  baseUrl?: string;
  /** Caller cancellation rejects with this signal's original reason. */
  signal?: AbortSignal;
  /** Per-retrieval deadline, including DNS, redirects and body processing; defaults to 120,000 ms. */
  resourceTimeoutMs?: number;
  /** Maximum decoded response body; defaults to 64 MiB. */
  maxResponseBytes?: number;
}

/**
 * The result of loading a catalog from a URL entry.
 * `found` contains the final response URL and decoded body bytes before text or
 * JSON parsing, suitable for `checkCatalogEntry(entry, bytes)`.
 * Failure URLs identify the final response when available, otherwise the
 * attempted URL or original reference. Failure results do not retain body bytes.
 */
export type UrlCatalogLoadResult =
  | { status: 'found'; catalog: AICatalog; url: string; bytes: Uint8Array }
  | { status: 'invalid_catalog'; url: string; error: CatalogParseError }
  | { status: 'fetch_failed'; url: string; error: Error };

/**
 * The result of parsing the complete catalog embedded in an entry's `data`.
 * On success, `url` preserves the supplied `baseUrl`, when present, as context
 * for relative references in the catalog. It does not identify a separate fetch.
 */
export type InlineCatalogLoadResult =
  | { status: 'found'; catalog: AICatalog; url?: string }
  | { status: 'invalid_catalog'; error: CatalogParseError };

/** A parsed, unverified catalog or an expected retrieval/parsing failure. */
export type CatalogLoadResult = UrlCatalogLoadResult | InlineCatalogLoadResult;

function snapshotBaseUrl(options: LoadCatalogFromEntryOptions | undefined): string | undefined {
  const descriptor = options === undefined ? undefined : Object.getOwnPropertyDescriptor(options, 'baseUrl');
  if (!descriptor) return undefined;
  if (!('value' in descriptor)) throw new TypeError('options.baseUrl must be an own data property.');
  if (descriptor.value === undefined) return undefined;
  if (typeof descriptor.value !== 'string') throw new TypeError('baseUrl must be an absolute URL string.');
  try {
    new URL(descriptor.value);
    return descriptor.value;
  } catch (cause) {
    if (!(cause instanceof TypeError) ||
      (cause as NodeJS.ErrnoException).code !== 'ERR_INVALID_URL') throw cause;
    throw new TypeError('baseUrl must be an absolute URL string.', { cause });
  }
}

type CapturedEntry = { url: string } | { data: unknown };

function snapshotEntry(value: unknown): CapturedEntry {
  if (
    value === null || typeof value !== 'object' ||
    utilTypes.isProxy(value) || Array.isArray(value)
  ) throw new TypeError('entry must be a catalog entry object.');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new TypeError('entry must be a plain catalog entry object.');

  const envelope: Record<string, unknown> = Object.create(null);
  let data: unknown;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new TypeError('entry must contain only JSON properties.');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
      throw new TypeError('entry fields must be enumerable own data properties.');
    if (key === 'data') data = descriptor.value;
    Object.defineProperty(envelope, key, {
      value: key === 'data' ? null : descriptor.value,
      enumerable: true,
    });
  }
  const issue = preflightJsonValue(envelope, {
    allowOwnProtoMember: false,
    isDisallowedObject: utilTypes.isProxy,
    requireIJsonStrings: false,
  });
  if (issue) throw new TypeError('entry must be a bounded JSON catalog entry.');
  const parsed = safeParseCatalogEntry(envelope);
  if (!parsed.success || parsed.data.type !== mediaTypes.aiCatalog)
    throw new TypeError('entry must have type application/ai-catalog+json and exactly one of url or data.');
  return 'url' in parsed.data ? { url: parsed.data.url } : { data };
}

/**
 * Loads exactly the catalog represented by a catalog-typed entry.
 * URL entries use public HTTPS retrieval; inline entries use ordinary catalog
 * parsing. Relative URLs are resolved against `options.baseUrl`; without a
 * base, they return `fetch_failed`. On success, `url` supplies context for the
 * returned catalog's relative references: the final response URL for URL entries,
 * or the unchanged supplied base for inline entries. No discovery fallback,
 * traversal, authoring assertion, or verification is performed.
 *
 * Inputs are captured before I/O. Malformed entries, other entry types, and
 * invalid options reject with `TypeError`. Cancellation rejects with its exact
 * reason; unexpected backend errors also reject. Expected URL resolution,
 * retrieval and catalog parsing failures are returned as results.
 */
export function loadCatalogFromEntry(
  entry: CatalogEntryWithUrl,
  options?: LoadCatalogFromEntryOptions,
): Promise<UrlCatalogLoadResult>;
export function loadCatalogFromEntry(
  entry: CatalogEntryWithData,
  options?: LoadCatalogFromEntryOptions,
): Promise<InlineCatalogLoadResult>;
export function loadCatalogFromEntry(
  entry: CatalogEntry,
  options?: LoadCatalogFromEntryOptions,
): Promise<CatalogLoadResult>;
export async function loadCatalogFromEntry(
  entry: CatalogEntry,
  options?: LoadCatalogFromEntryOptions,
): Promise<CatalogLoadResult> {
  const capturedOptions = snapshotCatalogResourceOptions(options);
  const baseUrl = snapshotBaseUrl(options);
  throwIfAborted(capturedOptions.signal);
  const captured = snapshotEntry(entry);
  if ('data' in captured) {
    const issue = preflightJsonValue(captured.data, {
      allowOwnProtoMember: false,
      isDisallowedObject: utilTypes.isProxy,
      requireIJsonStrings: false,
    });
    const parsed = issue
      ? { success: false as const, error: new CatalogParseError([issue]) }
      : safeParseCatalog(captured.data);
    throwIfAborted(capturedOptions.signal);
    return parsed.success
      ? { status: 'found', catalog: parsed.data, ...(baseUrl === undefined ? {} : { url: baseUrl }) }
      : { status: 'invalid_catalog', error: parsed.error };
  }
  let url: URL;
  try {
    url = new URL(captured.url, baseUrl);
  } catch (cause) {
    if (!(cause instanceof TypeError) ||
      (cause as NodeJS.ErrnoException).code !== 'ERR_INVALID_URL') throw cause;
    return {
      status: 'fetch_failed',
      url: captured.url,
      error: new HttpFetchError(
        'The catalog entry URL is invalid or cannot be resolved without a base URL.',
        { cause },
      ),
    };
  }
  const lookup = await fetchCatalogResource(url, capturedOptions);
  throwIfAborted(capturedOptions.signal);
  return lookup.result;
}
