import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { DIGEST_PATTERN } from './internal/digest.js';

const digestImplementations = {
  sha256: {
    nodeName: 'sha256',
    hexLength: 64,
  },
} as const;

type ImplementedDigestAlgorithm = keyof typeof digestImplementations;

function isImplementedDigestAlgorithm(
  algorithm: string,
): algorithm is ImplementedDigestAlgorithm {
  return Object.hasOwn(digestImplementations, algorithm);
}

function assertStableBytes(bytes: unknown): asserts bytes is Uint8Array {
  if (!utilTypes.isUint8Array(bytes)) {
    throw new TypeError('bytes must be a Uint8Array.');
  }
  if (utilTypes.isSharedArrayBuffer(bytes.buffer)) {
    throw new TypeError(
      'bytes must not be backed by a SharedArrayBuffer.',
    );
  }
  try {
    Uint8Array.prototype.subarray.call(bytes, 0, 0);
  } catch {
    throw new TypeError('bytes must not have a detached ArrayBuffer.');
  }
}

/** The outcome of comparing bytes with a declared AI Catalog digest. */
export type DigestCheckResult =
  | { status: 'match' }
  | { status: 'mismatch' }
  | { status: 'invalid_digest' }
  | { status: 'algorithm_not_implemented'; algorithm: string };

/**
 * Indicates that the runtime could not execute a digest algorithm implemented
 * by this SDK.
 */
export class DigestAlgorithmUnavailableError extends Error {
  /** The exact AI Catalog algorithm token that could not be executed. */
  readonly algorithm: string;

  constructor(algorithm: string, cause?: unknown) {
    super(
      `The ${JSON.stringify(algorithm)} digest algorithm is unavailable in this runtime.`,
      cause === undefined ? undefined : { cause },
    );
    this.name = 'DigestAlgorithmUnavailableError';
    this.algorithm = algorithm;
  }
}

/**
 * Compares caller-supplied bytes with an AI Catalog digest.
 *
 * The exact byte range represented by `bytes` is hashed without fetching,
 * decoding, serialization, or JCS canonicalization. A matching digest proves
 * only that those bytes match the declaration; it does not establish that the
 * declaration is authentic or that the content is trustworthy.
 *
 * This SDK currently implements only the exact, case-sensitive `sha256`
 * algorithm token. Other syntactically valid tokens produce an
 * `algorithm_not_implemented` result rather than a judgment about whether the
 * AI Catalog specification permits them.
 *
 * @throws {TypeError} If an argument has the wrong runtime type or `bytes` is
 * backed by a shared or detached buffer.
 * @throws {DigestAlgorithmUnavailableError} If the runtime cannot execute a
 * digest algorithm implemented by this SDK.
 */
export function checkDigest(
  bytes: Uint8Array,
  expectedDigest: string,
): DigestCheckResult {
  assertStableBytes(bytes);
  if (typeof expectedDigest !== 'string') {
    throw new TypeError('expectedDigest must be a string.');
  }

  if (!DIGEST_PATTERN.test(expectedDigest)) return { status: 'invalid_digest' };

  const separator = expectedDigest.indexOf(':');
  const algorithm = expectedDigest.slice(0, separator);
  const expectedHex = expectedDigest.slice(separator + 1);
  if (!isImplementedDigestAlgorithm(algorithm)) {
    return { status: 'algorithm_not_implemented', algorithm };
  }

  const implementation = digestImplementations[algorithm];
  if (expectedHex.length !== implementation.hexLength) {
    return { status: 'invalid_digest' };
  }

  let actualHex: string;
  try {
    actualHex = createHash(implementation.nodeName)
      .update(bytes)
      .digest('hex');
  } catch (cause) {
    throw new DigestAlgorithmUnavailableError(algorithm, cause);
  }

  return { status: actualHex === expectedHex ? 'match' : 'mismatch' };
}
