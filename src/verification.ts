import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import canonicalize from 'canonicalize';

import { DIGEST_PATTERN } from './internal/digest.js';
import { preflightJsonValue } from './internal/json-value.js';
import type { JsonValue, TrustManifest } from './types.js';

const utf8Encoder = new TextEncoder();

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

function assertCanonicalizableJsonValue(
  value: unknown,
): asserts value is JsonValue {
  const preflightIssue = preflightJsonValue(value, {
    allowOwnProtoMember: true,
    isDisallowedObject: utilTypes.isProxy,
    requireIJsonStrings: true,
  });
  if (preflightIssue) {
    const ErrorClass =
      preflightIssue.code === 'resource_limit' ? RangeError : TypeError;
    throw new ErrorClass(preflightIssue.message);
  }
}

function assertCanonicalizableJsonObject(
  value: unknown,
): asserts value is Record<string, JsonValue> {
  if (
    value === null ||
    typeof value !== 'object' ||
    utilTypes.isProxy(value) ||
    Array.isArray(value)
  ) {
    throw new TypeError('manifest must be a plain JSON object.');
  }
  assertCanonicalizableJsonValue(value);
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
 * Encodes a logical JSON value as RFC 8785 JSON Canonicalization Scheme (JCS)
 * bytes.
 *
 * The input is an already-materialized JSON value, not JSON source text. The
 * function preserves array order and Unicode normalization form, sorts object
 * properties as required by RFC 8785, and returns a fresh UTF-8 byte array.
 * It does not parse JSON, detect duplicate member names erased by a previous
 * parse, remove signature fields, or hash the result.
 *
 * @throws {TypeError} If `value` is not a plain I-JSON value, including when
 * it contains non-finite numbers, forbidden Unicode code points, cycles,
 * sparse arrays, accessors, proxies, or exotic objects.
 * @throws {RangeError} If `value` exceeds the SDK's supported node or nesting
 * depth limit.
 */
export function canonicalizeJsonValueToBytes(value: JsonValue): Uint8Array {
  assertCanonicalizableJsonValue(value);

  let canonicalJson: string | undefined;
  try {
    canonicalJson = canonicalize(value);
  } catch (cause) {
    throw new TypeError('The value could not be canonicalized as JSON.', {
      cause,
    });
  }
  if (typeof canonicalJson !== 'string') {
    throw new TypeError('The value could not be canonicalized as JSON.');
  }
  return utf8Encoder.encode(canonicalJson);
}

/**
 * Creates the RFC 8785 payload covered by a Trust Manifest's detached JWS.
 *
 * The input is an already-materialized Trust Manifest. The function omits
 * exactly its own, top-level, case-sensitive `signature` member and preserves
 * every other JSON member, including unknown members and nested members named
 * `signature`. It does not mutate the manifest or validate its schema.
 * The entire input, including the omitted member, must be plain I-JSON data.
 *
 * The returned bytes are the detached JWS payload, not a base64url encoding or
 * complete JWS signing input. This function does not parse, create, or verify a
 * JWS, select keys or algorithms, or establish trust.
 *
 * @throws {TypeError} If `manifest` is not a plain I-JSON object, including when
 * it contains non-finite numbers, forbidden Unicode code points, cycles,
 * sparse arrays, accessors, proxies, or exotic objects.
 * @throws {RangeError} If `manifest` exceeds the SDK's supported node or
 * nesting depth limit.
 */
export function createTrustManifestSignaturePayload(
  manifest: TrustManifest,
): Uint8Array {
  assertCanonicalizableJsonObject(manifest);

  const descriptors = Object.getOwnPropertyDescriptors(manifest);
  delete descriptors.signature;
  const payload = Object.defineProperties(
    Object.create(null),
    descriptors,
  ) as Record<string, JsonValue>;

  return canonicalizeJsonValueToBytes(payload);
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
