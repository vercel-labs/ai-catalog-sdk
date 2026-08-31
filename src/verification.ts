import { Buffer } from 'node:buffer';
import {
  createHash,
  type KeyObject,
  type webcrypto,
} from 'node:crypto';
import { types as utilTypes } from 'node:util';
import canonicalize from 'canonicalize';
import { flattenedVerify } from 'jose/jws/flattened/verify';
import * as joseErrors from 'jose/errors';

import { DIGEST_PATTERN } from './internal/digest.js';
import { preflightJsonValue } from './internal/json-value.js';
import type { JsonValue, TrustManifest } from './types.js';

const utf8Encoder = new TextEncoder();
const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true });

const registeredJoseHeaderParameters = new Set([
  'alg',
  'jku',
  'jwk',
  'kid',
  'x5u',
  'x5c',
  'x5t',
  'x5t#S256',
  'typ',
  'cty',
  'crit',
]);

const digestImplementations = {
  sha256: {
    nodeName: 'sha256',
    hexLength: 64,
  },
} as const;

type ImplementedDigestAlgorithm = keyof typeof digestImplementations;

interface ParsedDetachedJws {
  protectedSegment: string;
  signatureSegment: string;
}

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

function readOwnDataProperty(
  value: object,
  name: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (!descriptor || !('value' in descriptor)) return undefined;
  return descriptor.value;
}

function assertEs256PublicKey(
  publicKey: unknown,
): asserts publicKey is webcrypto.CryptoKey | KeyObject {
  if (utilTypes.isCryptoKey(publicKey)) {
    const algorithm = publicKey.algorithm;
    if (
      publicKey.type !== 'public' ||
      algorithm.name !== 'ECDSA' ||
      !('namedCurve' in algorithm) ||
      algorithm.namedCurve !== 'P-256' ||
      !publicKey.usages.includes('verify')
    ) {
      throw new TypeError(
        'publicKey must be a public P-256 CryptoKey usable for verification.',
      );
    }
    return;
  }

  if (utilTypes.isKeyObject(publicKey)) {
    if (
      publicKey.type !== 'public' ||
      publicKey.asymmetricKeyType !== 'ec' ||
      publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    ) {
      throw new TypeError('publicKey must be a public P-256 KeyObject.');
    }
    return;
  }

  throw new TypeError('publicKey must be a CryptoKey or KeyObject.');
}

function snapshotSignatureCheckOptions(
  options: unknown,
): TrustManifestSignatureCheckOptions {
  if (
    options === null ||
    typeof options !== 'object' ||
    utilTypes.isProxy(options)
  ) {
    throw new TypeError('options must be an object.');
  }

  const expectedAlgorithm = readOwnDataProperty(options, 'expectedAlgorithm');
  if (expectedAlgorithm !== 'ES256') {
    throw new TypeError('expectedAlgorithm must be "ES256".');
  }

  const publicKey = readOwnDataProperty(options, 'publicKey');
  assertEs256PublicKey(publicKey);
  return { expectedAlgorithm, publicKey };
}

function base64UrlValue(code: number): number | undefined {
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 71;
  if (code >= 48 && code <= 57) return code + 4;
  if (code === 45) return 62;
  if (code === 95) return 63;
  return undefined;
}

function hasCanonicalBase64UrlSyntax(
  value: string,
  start: number,
  end: number,
): boolean {
  const length = end - start;
  if (length % 4 === 1) return false;

  let lastValue = 0;
  for (let index = start; index < end; index += 1) {
    const current = base64UrlValue(value.charCodeAt(index));
    if (current === undefined) return false;
    lastValue = current;
  }

  if (length % 4 === 2) return (lastValue & 0b1111) === 0;
  if (length % 4 === 3) return (lastValue & 0b11) === 0;
  return true;
}

function inspectDetachedJws(
  value: string,
  expectedAlgorithm: 'ES256',
): ParsedDetachedJws | TrustManifestSignatureCheckResult {
  const firstSeparator = value.indexOf('.');
  const secondSeparator = value.indexOf('.', firstSeparator + 1);
  if (
    firstSeparator < 0 ||
    secondSeparator !== firstSeparator + 1 ||
    value.indexOf('.', secondSeparator + 1) !== -1
  ) {
    return { status: 'invalid_jws' };
  }

  const signatureStart = secondSeparator + 1;
  if (
    !hasCanonicalBase64UrlSyntax(value, 0, firstSeparator) ||
    !hasCanonicalBase64UrlSyntax(value, signatureStart, value.length)
  ) {
    return { status: 'invalid_jws' };
  }

  const protectedSegment = value.slice(0, firstSeparator);
  const protectedBytes = Buffer.from(protectedSegment, 'base64url');

  let protectedHeader: unknown;
  try {
    protectedHeader = JSON.parse(strictUtf8Decoder.decode(protectedBytes));
  } catch {
    return { status: 'invalid_jws' };
  }
  if (
    protectedHeader === null ||
    typeof protectedHeader !== 'object' ||
    Array.isArray(protectedHeader)
  ) {
    return { status: 'invalid_jws' };
  }

  const critical = readOwnDataProperty(protectedHeader, 'crit');
  let unsupportedCriticalFeature = false;
  if (critical !== undefined) {
    if (
      !Array.isArray(critical) ||
      critical.length === 0 ||
      critical.some((name) => typeof name !== 'string' || name.length === 0) ||
      new Set(critical).size !== critical.length
    ) {
      return { status: 'invalid_jws' };
    }

    for (const name of critical) {
      if (!Object.hasOwn(protectedHeader, name)) {
        return { status: 'invalid_jws' };
      }
      if (registeredJoseHeaderParameters.has(name)) {
        return { status: 'invalid_jws' };
      }
      if (name !== 'b64') unsupportedCriticalFeature = true;
    }
  }

  const b64 = readOwnDataProperty(protectedHeader, 'b64');
  if (b64 !== undefined) {
    if (
      typeof b64 !== 'boolean' ||
      !Array.isArray(critical) ||
      !critical.includes('b64')
    ) {
      return { status: 'invalid_jws' };
    }
    if (!b64) unsupportedCriticalFeature = true;
  }

  const algorithm = readOwnDataProperty(protectedHeader, 'alg');
  if (typeof algorithm !== 'string' || algorithm.length === 0) {
    return { status: 'invalid_jws' };
  }
  if (algorithm !== expectedAlgorithm) {
    return { status: 'algorithm_mismatch', algorithm };
  }
  if (unsupportedCriticalFeature) {
    return { status: 'jws_feature_not_implemented' };
  }
  if (value.length - signatureStart !== 86) {
    return { status: 'invalid_signature' };
  }

  const signatureSegment = value.slice(signatureStart);
  const signatureBytes = Buffer.from(signatureSegment, 'base64url');
  if (signatureBytes.length !== 64) {
    return { status: 'invalid_signature' };
  }

  return { protectedSegment, signatureSegment };
}

/** The outcome of comparing bytes with a declared AI Catalog digest. */
export type DigestCheckResult =
  | { status: 'match' }
  | { status: 'mismatch' }
  | { status: 'invalid_digest' }
  | { status: 'algorithm_not_implemented'; algorithm: string };

/** Trusted caller policy and key material for a Trust Manifest signature check. */
export interface TrustManifestSignatureCheckOptions {
  /** The exact public key selected by the caller's trust policy. */
  publicKey: webcrypto.CryptoKey | KeyObject;

  /** The exact algorithm the caller expects the protected JWS header to use. */
  expectedAlgorithm: 'ES256';
}

/** The outcome of checking a Trust Manifest's detached JWS. */
export type TrustManifestSignatureCheckResult =
  | { status: 'valid' }
  | { status: 'missing_signature' }
  | { status: 'invalid_jws' }
  | { status: 'algorithm_mismatch'; algorithm: string }
  | { status: 'jws_feature_not_implemented' }
  | { status: 'invalid_signature' };

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
 * Checks a Trust Manifest's detached JWS using caller-selected public key
 * material and algorithm policy.
 *
 * The function snapshots the manifest payload, signature, options, and key
 * before its first asynchronous operation. It accepts only the ordinary
 * RFC 7515 detached compact form and currently implements only ES256. Header
 * fields never select or resolve a key, and this function performs no I/O.
 *
 * A `valid` result establishes only that the supplied key signed the exact
 * canonical manifest snapshot. It does not establish that the key belongs to
 * the claimed identity, evaluate trust, check the subject digest, validate the
 * manifest schema, or enforce timestamps.
 *
 * @throws {TypeError} If an argument, option, signature value, or public key
 * has the wrong runtime type, or if the key is not a public P-256 key usable
 * for ES256 verification.
 * @throws {TypeError} If `manifest` is not a plain I-JSON object.
 * @throws {RangeError} If `manifest` exceeds the SDK's supported node or
 * nesting depth limit.
 */
export async function checkTrustManifestSignature(
  manifest: TrustManifest,
  options: TrustManifestSignatureCheckOptions,
): Promise<TrustManifestSignatureCheckResult> {
  const { expectedAlgorithm, publicKey } =
    snapshotSignatureCheckOptions(options);
  const payload = createTrustManifestSignaturePayload(manifest);
  const signature = readOwnDataProperty(manifest, 'signature');

  if (signature === undefined) return { status: 'missing_signature' };
  if (typeof signature !== 'string') {
    throw new TypeError('manifest.signature must be a string when present.');
  }

  const inspected = inspectDetachedJws(signature, expectedAlgorithm);
  if ('status' in inspected) return inspected;

  try {
    await flattenedVerify(
      {
        protected: inspected.protectedSegment,
        payload: Buffer.from(payload).toString('base64url'),
        signature: inspected.signatureSegment,
      },
      publicKey,
      { algorithms: ['ES256'] },
    );
  } catch (cause) {
    if (cause instanceof joseErrors.JWSSignatureVerificationFailed) {
      return { status: 'invalid_signature' };
    }
    if (cause instanceof joseErrors.JWSInvalid) {
      return { status: 'invalid_jws' };
    }
    if (cause instanceof joseErrors.JOSEError) {
      throw new Error('The JWS verification backend failed unexpectedly.', {
        cause,
      });
    }
    throw cause;
  }

  return { status: 'valid' };
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
