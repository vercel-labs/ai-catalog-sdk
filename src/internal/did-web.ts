import { captureSdkConfiguration } from '../configure.js';
import { fetchHttpsResource, HttpFetchError, throwIfAborted } from './http-fetch.js';
import { IssuerCheckError } from './publisher-profile.js';

interface ResolutionOptions {
  signal?: AbortSignal;
  resolutionTimeoutMs: number;
  maxResponseBytes: number;
  requirePublicAccessHeaders?: boolean;
}

/** Resolves a validated root did:web issuer through a bounded HTTPS request. */
export async function resolveDidWeb(identity: string, options: ResolutionOptions): Promise<unknown> {
  const requirePublicAccessHeaders = options.requirePublicAccessHeaders ?? captureSdkConfiguration().requirePublicAccessHeaders;
  try {
    return await fetchHttpsResource(
      new URL(`https://${identity.slice('did:web:'.length)}/.well-known/did.json`),
      {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        timeoutMs: options.resolutionTimeoutMs,
        timeoutLabel: 'resolutionTimeoutMs',
        maxResponseBytes: options.maxResponseBytes,
        accept: 'application/did+json, application/did+ld+json, application/json',
        requirePublicAccessHeaders,
      },
      async (response) => {
        if ([301, 302, 303, 307, 308].includes(response.statusCode) && !response.headers.location) {
          throw new HttpFetchError('The publisher DID redirect has no Location header.');
        }
        if (response.statusCode !== 200) {
          throw new HttpFetchError(`The publisher DID endpoint returned HTTP ${response.statusCode}.`);
        }
        const bytes = await response.readBody();
        let json: string;
        try {
          json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (cause) {
          if (!(cause instanceof TypeError)) throw cause;
          throw new IssuerCheckError('The publisher DID document is not valid UTF-8.', { cause });
        }
        try {
          return JSON.parse(json);
        } catch (cause) {
          if (!(cause instanceof SyntaxError)) throw cause;
          throw new IssuerCheckError('The publisher DID document is not valid JSON.', { cause });
        }
      },
    );
  } catch (cause) {
    throwIfAborted(options.signal);
    if (!(cause instanceof HttpFetchError)) throw cause;
    throw new IssuerCheckError(cause.message, 'cause' in cause ? { cause: cause.cause } : undefined);
  }
}
