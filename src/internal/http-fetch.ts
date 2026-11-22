import { hasPublicAccessHeaders } from './response-contract.js';

export { fetchHttpsResource } from '#transport';

export class HttpFetchError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'HttpFetchError';
  }
}

export const HTTP_FETCH_FAILURE_MESSAGE = 'The HTTPS resource could not be retrieved.';

export interface HttpsResource {
  readonly url: URL;
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readBody(): Promise<Uint8Array>;
}

export interface HttpsResourceOptions {
  signal?: AbortSignal;
  timeoutMs: number;
  maxResponseBytes: number;
  accept: string;
  timeoutLabel?: string;
  requirePublicAccessHeaders?: boolean;
  requireLinkExposure?: boolean;
}

export function validateResponseContract(response: HttpsResource, options: HttpsResourceOptions): void {
  if (options.requirePublicAccessHeaders &&
    !hasPublicAccessHeaders(response.headers, options.requireLinkExposure)) {
    throw new HttpFetchError('The HTTPS response does not satisfy the public-access header requirements.');
  }
}

export function normalizeHttpFetchError(
  error: HttpFetchError,
  options: Pick<HttpsResourceOptions, 'requirePublicAccessHeaders'>,
): HttpFetchError {
  if (!options.requirePublicAccessHeaders || error.message === HTTP_FETCH_FAILURE_MESSAGE) return error;
  return new HttpFetchError(HTTP_FETCH_FAILURE_MESSAGE, { cause: error });
}

const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
const signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason')?.get;

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal !== undefined && signalAborted?.call(signal)) throw signalReason?.call(signal);
}

export function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
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
