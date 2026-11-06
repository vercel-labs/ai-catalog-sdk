import { types as utilTypes } from 'node:util';

import { type AICatalog, CatalogParseError } from '../types.js';
import {
  fetchHttpsResource,
  HttpFetchError,
  type HttpsResourceOptions,
  throwIfAborted,
} from './http-fetch.js';
import { safeParseCatalogJson } from './parser.js';

export interface CapturedCatalogResourceOptions {
  signal?: AbortSignal;
  resourceTimeoutMs: number;
  maxResponseBytes: number;
}

export function snapshotCatalogResourceOptions(value: unknown): CapturedCatalogResourceOptions {
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

export function catalogTransportOptions(
  options: CapturedCatalogResourceOptions,
  accept: string,
): HttpsResourceOptions {
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

export type CatalogResourceResult =
  | { status: 'found'; catalog: AICatalog; url: string; bytes: Uint8Array }
  | { status: 'invalid_catalog'; url: string; error: CatalogParseError }
  | { status: 'fetch_failed'; url: string; error: Error };

export interface CatalogResourceLookup {
  result: CatalogResourceResult;
  absent: boolean;
}

/** Retrieves and parses one explicit catalog, retaining the decoded artifact bytes on success. */
export async function fetchCatalogResource(
  url: URL,
  options: CapturedCatalogResourceOptions,
): Promise<CatalogResourceLookup> {
  let responseUrl = url.href;
  let absent = false;
  try {
    const result = await fetchHttpsResource(
      url,
      catalogTransportOptions(options, 'application/ai-catalog+json, application/json'),
      async (response): Promise<CatalogResourceResult> => {
        responseUrl = response.url.href;
        if (response.statusCode < 200 || response.statusCode >= 300) {
          absent = response.statusCode === 404 || response.statusCode === 410;
          throw new HttpFetchError(`Catalog request returned HTTP ${response.statusCode}.`);
        }
        const bytes = await response.readBody();
        const parsed = safeParseCatalogJson(catalogText(bytes));
        return parsed.success
          ? { status: 'found', catalog: parsed.data, url: responseUrl, bytes }
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
