import {
  abortable,
  HttpFetchError,
  type HttpsResource,
  type HttpsResourceOptions,
  normalizeHttpFetchError,
  throwIfAborted,
  validateResponseContract,
} from './http-fetch.js';

const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
const signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason')?.get;

function checkedUrl(url: URL): URL {
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new HttpFetchError('HTTPS retrieval requires an HTTPS URL without credentials.');
  }
  const result = new URL(url.href);
  result.hash = '';
  return result;
}

async function getResponse(url: URL, signal: AbortSignal, accept: string): Promise<Response> {
  try {
    return await fetch(url, {
      method: 'GET',
      headers: { accept },
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      signal,
    });
  } catch (cause) {
    signal.throwIfAborted();
    if (!(cause instanceof TypeError)) throw cause;
    throw new HttpFetchError('The HTTPS request failed.', { cause });
  }
}

async function readBody(
  response: Response,
  signal: AbortSignal,
  maxResponseBytes: number,
): Promise<Uint8Array> {
  signal.throwIfAborted();
  const reader = response.body?.getReader();
  if (reader === undefined) return new Uint8Array();
  try {
    const chunks: Uint8Array[] = [];
    let length = 0;
    for (;;) {
      const chunk = await reader.read().catch((cause: unknown) => {
        signal.throwIfAborted();
        if (!(cause instanceof TypeError) && !(cause instanceof DOMException)) throw cause;
        throw new HttpFetchError('The HTTPS resource response could not be read or decoded.', { cause });
      });
      signal.throwIfAborted();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > maxResponseBytes) {
        throw new HttpFetchError('The decoded HTTPS response exceeds maxResponseBytes.');
      }
      chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    reader.releaseLock();
  }
}

export async function fetchHttpsResource<T>(
  initialUrl: URL,
  options: HttpsResourceOptions,
  consume: (response: HttpsResource) => T | Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const deadline = performance.now() + options.timeoutMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutError = () => new HttpFetchError(`HTTPS retrieval exceeded ${options.timeoutLabel ?? 'timeoutMs'}.`);
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
  try {
    controller.signal.throwIfAborted();
    const response = await getResponse(checkedUrl(initialUrl), controller.signal, options.accept);
    controller.signal.throwIfAborted();
    const url = checkedUrl(new URL(response.url || initialUrl.href));
    const headers: Record<string, string | undefined> = Object.create(null);
    response.headers.forEach((value, name) => { headers[name] = value; });
    let body: Promise<Uint8Array> | undefined;
    const resource: HttpsResource = {
      url,
      statusCode: response.status,
      headers,
      readBody: () => body ??= readBody(response, controller.signal, options.maxResponseBytes),
    };
    validateResponseContract(resource, options);
    const result = await abortable(Promise.resolve(consume(resource)), controller.signal);
    // Parsing can keep the event loop busy past the timer's scheduled deadline.
    if (performance.now() >= deadline) throw timeoutError();
    controller.signal.throwIfAborted();
    return result;
  } catch (cause) {
    throwIfAborted(options.signal);
    if (cause instanceof HttpFetchError) throw normalizeHttpFetchError(cause, options);
    throw cause;
  } finally {
    controller.abort();
    if (timer !== undefined) clearTimeout(timer);
    if (options.signal !== undefined) {
      EventTarget.prototype.removeEventListener.call(options.signal, 'abort', onAbort);
    }
  }
}
