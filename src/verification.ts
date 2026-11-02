import { Buffer } from 'node:buffer';
import { createHash, type KeyObject, type webcrypto } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import canonicalize from 'canonicalize';
import { flattenedVerify } from 'jose/jws/flattened/verify';
import * as joseErrors from 'jose/errors';

import { DIGEST_PATTERN, DIGEST_HEX_LENGTHS } from './internal/digest.js';
import { preflightJsonValue } from './internal/json-value.js';
import { resolveDidWeb } from './internal/did-web.js';
import {
  inspectSignerProfile,
  publisherIdentityFor,
  authorizePublisherKey,
  checkManifestTime,
  IssuerCheckError,
} from './internal/publisher-profile.js';
import {
  safeParseCatalogEntry,
  safeParseTrustManifest,
} from './internal/parser.js';
import { validateTrustManifest } from './internal/validation.js';
import { CatalogParseError, CatalogValidationError } from './types.js';
import type {
  Signature,
  AICatalog,
  CatalogEntry,
  CatalogEntryWithData,
  CatalogEntryWithUrl,
  JsonValue,
  TrustManifest,
} from './types.js';

const utf8Encoder = new TextEncoder();
const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true });
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  'buffer',
)?.get;

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

/** Digest algorithms supported for creating AI Catalog digests. */
export type DigestAlgorithm = 'sha256' | 'sha384' | 'sha512';

interface ParsedDetachedJws {
  protectedHeader: Record<string, unknown>;
  protectedSegment: string;
  signatureSegment: string;
}

export type SignatureCheckFailure = Exclude<
  SignatureCheckResult,
  { status: 'valid' }
>;

interface SignaturePayloadSnapshot {
  payload: Uint8Array;
  jws: ParsedDetachedJws;
}

interface SignatureCheckSnapshot extends SignaturePayloadSnapshot {
  publicKey: webcrypto.CryptoKey | KeyObject;
}

function isImplementedDigestAlgorithm(
  algorithm: string,
): algorithm is DigestAlgorithm {
  return Object.hasOwn(DIGEST_HEX_LENGTHS, algorithm);
}

function assertStableBytes(bytes: unknown): asserts bytes is Uint8Array {
  if (!utilTypes.isUint8Array(bytes)) {
    throw new TypeError('bytes must be a Uint8Array.');
  }
  const buffer = typedArrayBufferGetter?.call(bytes);
  if (buffer === undefined) {
    throw new TypeError('bytes must be a Uint8Array.');
  }
  if (utilTypes.isSharedArrayBuffer(buffer)) {
    throw new TypeError('bytes must not be backed by a SharedArrayBuffer.');
  }
  try {
    Uint8Array.prototype.subarray.call(bytes, 0, 0);
  } catch {
    throw new TypeError('bytes must not have a detached ArrayBuffer.');
  }
}

function canonicalizationArrayMap(
  this: JsonValue[],
  callback: (value: JsonValue) => string,
): { join(separator: string): string } {
  const mapped = new Array<string>(this.length);
  for (let index = 0; index < this.length; index += 1) {
    const value = this[index];
    if (value === undefined) {
      throw new TypeError('Sparse JSON arrays are not supported.');
    }
    mapped[index] = callback(value);
  }
  return {
    join(separator: string) {
      let result = '';
      for (let index = 0; index < mapped.length; index += 1) {
        if (index > 0) result += separator;
        result += mapped[index];
      }
      return result;
    },
  };
}

function createCanonicalizationSnapshot(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    const snapshot = new Array<JsonValue>(value.length);
    Object.setPrototypeOf(snapshot, null);
    Object.defineProperty(snapshot, 'map', {
      value: canonicalizationArrayMap,
    });
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor)) {
        throw new TypeError('Sparse JSON arrays are not supported.');
      }
      snapshot[index] = createCanonicalizationSnapshot(
        descriptor.value as JsonValue,
      );
    }
    return snapshot;
  }
  if (value !== null && typeof value === 'object') {
    const snapshot = Object.create(null) as Record<string, JsonValue>;
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor)) {
        throw new TypeError(
          'JSON object members must be enumerable data properties.',
        );
      }
      snapshot[key] = createCanonicalizationSnapshot(
        descriptor.value as JsonValue,
      );
    }
    return snapshot;
  }
  return value;
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
  name: string,
): asserts value is Record<string, JsonValue> {
  if (
    value === null ||
    typeof value !== 'object' ||
    utilTypes.isProxy(value) ||
    Array.isArray(value)
  ) {
    throw new TypeError(`${name} must be a plain JSON object.`);
  }
  const issue = preflightJsonValue(value, {
    allowOwnProtoMember: true,
    isDisallowedObject: utilTypes.isProxy,
    requireIJsonStrings: false,
  });
  if (issue)
    throw new (issue.code === 'resource_limit' ? RangeError : TypeError)(
      issue.message,
    );
}

function createDetachedJwsPayload(value: unknown, name: string): Uint8Array {
  assertCanonicalizableJsonObject(value, name);

  const descriptors = Object.getOwnPropertyDescriptors(value);
  delete descriptors.additionalSignatures;
  const signature = descriptors.signature;
  if (signature && 'value' in signature) {
    const metadata = signature.value;
    if (
      metadata === null ||
      typeof metadata !== 'object' ||
      Array.isArray(metadata)
    ) {
      throw new TypeError(`${name}.signature must be an object when present.`);
    }
    const signatureDescriptors = Object.getOwnPropertyDescriptors(metadata);
    delete signatureDescriptors.jws;
    descriptors.signature = {
      ...signature,
      value: Object.defineProperties(Object.create(null), signatureDescriptors),
    };
  }
  const payload = Object.defineProperties(
    Object.create(null),
    descriptors,
  ) as Record<string, JsonValue>;

  return canonicalizeJsonValueToBytes(payload);
}

function readOwnDataProperty(value: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (!descriptor || !('value' in descriptor)) return undefined;
  return descriptor.value;
}

function assertCatalogEntryObject(
  entry: unknown,
): asserts entry is CatalogEntry {
  if (
    entry === null ||
    typeof entry !== 'object' ||
    utilTypes.isProxy(entry) ||
    Array.isArray(entry) ||
    (Object.getPrototypeOf(entry) !== Object.prototype &&
      Object.getPrototypeOf(entry) !== null)
  ) {
    throw new TypeError('entry must be a plain object.');
  }
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
): SignatureCheckOptions {
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

function decodeProtectedHeader(
  value: string,
): Record<string, unknown> | undefined {
  const separator = value.indexOf('.');
  if (separator < 0 || !hasCanonicalBase64UrlSyntax(value, 0, separator)) {
    return undefined;
  }
  try {
    const header: unknown = JSON.parse(
      strictUtf8Decoder.decode(
        Buffer.from(value.slice(0, separator), 'base64url'),
      ),
    );
    if (
      header === null ||
      typeof header !== 'object' ||
      Array.isArray(header)
    ) {
      return undefined;
    }
    return header as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function inspectDetachedJws(
  value: string,
  expectedAlgorithm: 'ES256',
  expectedTyp: string,
): ParsedDetachedJws | SignatureCheckFailure {
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
  const protectedHeader = decodeProtectedHeader(value);
  if (!protectedHeader) return { status: 'invalid_jws' };

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
      unsupportedCriticalFeature = true;
    }
  }

  if (
    Object.hasOwn(protectedHeader, 'b64') ||
    readOwnDataProperty(protectedHeader, 'typ') !== expectedTyp
  )
    return { status: 'invalid_jws' };

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
  const signatureSegment = value.slice(signatureStart);

  return { protectedHeader, protectedSegment, signatureSegment };
}

/** The outcome of comparing bytes with a declared AI Catalog digest. */
export type DigestCheckResult =
  | { status: 'match' }
  | { status: 'mismatch' }
  | { status: 'invalid_digest' }
  | { status: 'algorithm_not_implemented'; algorithm: string };

/**
 * Trusted caller policy and key material shared by AI Catalog and Trust
 * Manifest detached-JWS signature checks.
 */
export interface SignatureCheckOptions {
  /** The exact public key selected by the caller's trust policy. */
  publicKey: webcrypto.CryptoKey | KeyObject;

  /** The exact algorithm the caller expects the protected JWS header to use. */
  expectedAlgorithm: 'ES256';
}

/**
 * The result shared by AI Catalog and Trust Manifest detached-JWS signature
 * checks.
 */
export type SignatureCheckResult =
  | { status: 'valid' }
  | { status: 'unsigned' }
  | { status: 'invalid_jws' }
  | { status: 'algorithm_mismatch'; algorithm: string }
  | { status: 'jws_feature_not_implemented' }
  | { status: 'invalid_signature' };

type ArtifactCheckFailure =
  | { status: 'artifact_digest_mismatch' }
  | { status: 'invalid_digest' }
  | { status: 'digest_algorithm_not_implemented'; algorithm: string };

type EntryStructureFailure = {
  status: 'invalid_entry';
  error: CatalogParseError;
};

type EntryCheckFailure = EntryStructureFailure | ArtifactCheckFailure;

/** The outcome of checking one explicit manifest using a caller-selected key. */
export type CatalogEntryTrustManifestCheckResult =
  | { status: 'passed' }
  | EntryCheckFailure
  | { status: 'invalid_manifest'; error: CatalogValidationError }
  | SignatureCheckFailure
  | { status: 'not_yet_valid' }
  | { status: 'expired' };

/** Caller-selected key and time controls for one explicit manifest. */
export interface CatalogEntryTrustManifestCheckOptions
  extends SignatureCheckOptions {
  /** Nonnegative safe integer milliseconds of clock skew. Defaults to 60,000. */
  clockToleranceMs?: number;
  /** Evaluation instant as safe integer UTC epoch milliseconds; defaults to the clock near completion. */
  nowMs?: number;
}

/** Selection, time, and DID-resolution controls for an entry check. */
export interface CatalogEntryCheckOptions {
  /**
   * Omitted checks all; an empty array checks none. Values match exactly.
   * Unselected manifests receive `not_checked`.
   */
  contributors?: readonly string[];
  /** Adds the entry's derived publisher manifests to the contributor selection. */
  alwaysCheckPublisherManifests?: boolean;
  /** Nonnegative integer milliseconds of clock skew. Defaults to 60,000. */
  clockToleranceMs?: number;
  /** Evaluation instant as safe integer UTC epoch milliseconds; defaults to the clock near completion. */
  nowMs?: number;
  /** Cancels the whole operation; cancellation rejects with the signal reason. */
  signal?: AbortSignal;
  /** Deadline for each DID resolution, including DNS/redirects/body. Defaults to 60,000 ms. */
  timeoutMs?: number;
  /** Maximum decoded body size per DID document. Defaults to 16 MiB. */
  maxResponseBytes?: number;
}

/** One contribution's outcome; a valid contribution need not be from the publisher. */
export type TrustManifestCheckResult =
  | { status: 'not_checked' }
  | { status: 'passed'; isPublisherEndorsement: boolean }
  | { status: 'invalid_manifest'; error: CatalogValidationError }
  | SignatureCheckFailure
  | { status: 'profile_not_implemented'; profile: string }
  | { status: 'profile_check_failed'; error: Error }
  | { status: 'issuer_check_failed'; error: Error }
  | { status: 'not_yet_valid' }
  | { status: 'expired' };

/** A captured contribution; excluded or invalid input need not have manifest structure. */
export type TrustManifestEvaluation =
  | (Extract<
      TrustManifestCheckResult,
      { status: 'not_checked' | 'invalid_manifest' }
    > & { manifest: JsonValue })
  | (Exclude<
      TrustManifestCheckResult,
      { status: 'not_checked' | 'invalid_manifest' }
    > & { manifest: TrustManifest });

/** A report of the requested checks, without an application acceptance policy. */
export type CatalogEntryCheckResult =
  | EntryCheckFailure
  | { status: 'checked'; manifests: TrustManifestEvaluation[] };

/** Signature metadata before JWS creation, or a completed signature. */
export type SignaturePayloadInput = Omit<Signature, 'jws'> & { jws?: string };
export type CatalogSignaturePayloadInput = Omit<AICatalog, 'signature'> & {
  signature?: SignaturePayloadInput;
};
export type TrustManifestSignaturePayloadInput = Omit<
  TrustManifest,
  'signature'
> & { signature?: SignaturePayloadInput };

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
 * parse, invoke inherited serialization hooks, remove signature fields, or
 * hash the result.
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
    canonicalJson = canonicalize(createCanonicalizationSnapshot(value));
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
 * Creates the RFC 8785 payload covered by an AI Catalog's detached JWS.
 *
 * The input is an already-materialized catalog. The function omits exactly its
 * immediate `signature.jws` and top-level `additionalSignatures` members. It
 * preserves every other JSON member, including entry order, unknown members, inline data, and nested
 * members named `signature`. It does not mutate the catalog or validate its
 * schema. The input must be bounded plain JSON; the resulting covered payload
 * must also satisfy I-JSON requirements.
 *
 * The returned bytes are the detached JWS payload, not a base64url encoding or
 * complete JWS signing input. This function does not parse, create, or verify a
 * JWS, select keys or algorithms, or establish trust.
 *
 * @throws {TypeError} If `catalog` contains non-JSON values, cycles, accessors,
 * proxies, exotic objects, or forbidden Unicode in the covered payload.
 * @throws {RangeError} If `catalog` exceeds the SDK's supported node or nesting
 * depth limit.
 */
export function createCatalogSignaturePayload(
  catalog: CatalogSignaturePayloadInput,
): Uint8Array {
  return createDetachedJwsPayload(catalog, 'catalog');
}

/**
 * Creates the RFC 8785 payload covered by a Trust Manifest's detached JWS.
 *
 * The input is an already-materialized Trust Manifest. The function omits
 * exactly its immediate `signature.jws` and top-level `additionalSignatures`
 * members. It preserves every other JSON member, including unknown members and nested members named
 * `signature`. It does not mutate the manifest or validate its schema.
 * The input must be bounded plain JSON; the covered payload must also satisfy
 * I-JSON requirements.
 *
 * The returned bytes are the detached JWS payload, not a base64url encoding or
 * complete JWS signing input. This function does not parse, create, or verify a
 * JWS, select keys or algorithms, or establish trust.
 *
 * @throws {TypeError} If `manifest` contains non-JSON values, cycles, accessors,
 * proxies, exotic objects, or forbidden Unicode in the covered payload.
 * @throws {RangeError} If `manifest` exceeds the SDK's supported node or
 * nesting depth limit.
 */
export function createTrustManifestSignaturePayload(
  manifest: TrustManifestSignaturePayloadInput,
): Uint8Array {
  return createDetachedJwsPayload(manifest, 'manifest');
}

function snapshotSignaturePayload(
  value: object,
  valueName: 'catalog' | 'manifest',
): SignaturePayloadSnapshot | SignatureCheckFailure {
  const payload = createDetachedJwsPayload(value, valueName);
  const signature = readOwnDataProperty(value, 'signature');

  if (signature === undefined) return { status: 'unsigned' };
  if (
    signature === null ||
    typeof signature !== 'object' ||
    Array.isArray(signature)
  ) {
    throw new TypeError(
      `${valueName}.signature must be an object when present.`,
    );
  }
  const rawJws = readOwnDataProperty(signature, 'jws');
  if (typeof rawJws !== 'string')
    throw new TypeError(`${valueName}.signature.jws must be a string.`);
  const jws = inspectDetachedJws(
    rawJws,
    'ES256',
    valueName === 'catalog'
      ? 'ai-catalog+jws'
      : 'ai-catalog-trust-manifest+jws',
  );
  if ('status' in jws) return jws;
  return { payload, jws };
}

function snapshotSignatureCheck(
  value: object,
  valueName: 'catalog' | 'manifest',
  options: SignatureCheckOptions,
): SignatureCheckSnapshot | SignatureCheckResult {
  const snapshot = snapshotSignaturePayload(value, valueName);
  if ('status' in snapshot) return snapshot;
  return { ...snapshot, publicKey: options.publicKey };
}

function snapshotCatalogSignatureCheck(
  catalog: AICatalog,
  options: SignatureCheckOptions,
): SignatureCheckSnapshot | SignatureCheckResult {
  return snapshotSignatureCheck(catalog, 'catalog', options);
}

function snapshotTrustManifestSignatureCheck(
  manifest: TrustManifest,
  options: SignatureCheckOptions,
): SignatureCheckSnapshot | SignatureCheckResult {
  return snapshotSignatureCheck(manifest, 'manifest', options);
}

async function executeSignatureCheck(
  snapshot: SignatureCheckSnapshot | SignatureCheckResult,
): Promise<SignatureCheckResult> {
  if ('status' in snapshot) return snapshot;
  if (Buffer.from(snapshot.jws.signatureSegment, 'base64url').length !== 64)
    return { status: 'invalid_signature' };

  try {
    await flattenedVerify(
      {
        protected: snapshot.jws.protectedSegment,
        payload: Buffer.from(snapshot.payload).toString('base64url'),
        signature: snapshot.jws.signatureSegment,
      },
      snapshot.publicKey,
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
 * Checks an AI Catalog's detached JWS using caller-selected public key material
 * and algorithm policy.
 *
 * The function snapshots the catalog payload, signature, options, and key
 * before its first asynchronous operation. It accepts only the ordinary
 * RFC 7515 detached compact form and currently implements only ES256. Header
 * fields never select or resolve a key, and this function performs no I/O.
 *
 * A `valid` result establishes only that the supplied key signed the exact
 * canonical catalog snapshot. It does not establish that the key belongs to
 * the catalog operator, evaluate trust, check referenced artifact bytes or
 * Trust Manifests, validate the catalog schema, or enforce timestamps.
 *
 * @throws {TypeError} If an argument, option, signature value, or public key
 * has the wrong runtime type, or if the key is not a public P-256 key usable
 * for ES256 verification.
 * @throws {TypeError} If `catalog` is not a plain I-JSON object.
 * @throws {RangeError} If `catalog` exceeds the SDK's supported node or nesting
 * depth limit.
 */
export async function checkCatalogSignature(
  catalog: AICatalog,
  options: SignatureCheckOptions,
): Promise<SignatureCheckResult> {
  const optionsSnapshot = snapshotSignatureCheckOptions(options);
  const snapshot = snapshotCatalogSignatureCheck(catalog, optionsSnapshot);
  return executeSignatureCheck(snapshot);
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
  options: SignatureCheckOptions,
): Promise<SignatureCheckResult> {
  const optionsSnapshot = snapshotSignatureCheckOptions(options);
  const snapshot = snapshotTrustManifestSignatureCheck(
    manifest,
    optionsSnapshot,
  );
  return executeSignatureCheck(snapshot);
}

/**
 * Checks entry/artifact preconditions, then reports manifest declaration,
 * supplied-key signature, and time-window failures in that order.
 * An `expired` or `not_yet_valid` result means the preceding checks passed.
 * The caller selects the signer profile and authenticates/authorizes the key;
 * this operation performs no network requests and ignores attached manifests.
 * URL entries take their supplied artifact bytes adjacent to the entry.
 */
export function checkCatalogEntryTrustManifest(
  entry: CatalogEntryWithData,
  manifest: TrustManifest,
  options: CatalogEntryTrustManifestCheckOptions,
): Promise<CatalogEntryTrustManifestCheckResult>;
export function checkCatalogEntryTrustManifest(
  entry: CatalogEntryWithUrl,
  artifactBytes: Uint8Array,
  manifest: TrustManifest,
  options: CatalogEntryTrustManifestCheckOptions,
): Promise<CatalogEntryTrustManifestCheckResult>;
export async function checkCatalogEntryTrustManifest(
  entry: CatalogEntry,
  bytesOrManifest: Uint8Array | TrustManifest,
  manifestOrOptions: TrustManifest | CatalogEntryTrustManifestCheckOptions,
  maybeOptions?: CatalogEntryTrustManifestCheckOptions,
): Promise<CatalogEntryTrustManifestCheckResult> {
  const isDataCall = maybeOptions === undefined;
  const rawOptions = isDataCall ? manifestOrOptions : maybeOptions;
  const options = snapshotSignatureCheckOptions(rawOptions);
  const timeOptions = snapshotTimeCheckOptions(rawOptions as object);
  const captured = captureEntryFields(entry, bytesOrManifest, isDataCall);
  if ('status' in captured) return captured;
  const artifact = precheckArtifact(captured.entry, bytesOrManifest);
  if (artifact !== undefined) return artifact;
  const input = isDataCall ? bytesOrManifest : manifestOrOptions;
  assertJsonInput(input);
  const parsed = safeParseTrustManifest(input);
  if (!parsed.success)
    return {
      status: 'invalid_manifest',
      error: new CatalogValidationError(
        parsed.error.issues,
        parsed.error.cause,
      ),
    };
  const manifest = parsed.data;
  const error = validateTrustManifest(manifest, captured.entry);
  if (error !== undefined) return { status: 'invalid_manifest', error };
  if (manifest.signature === undefined) return { status: 'unsigned' };
  const signature = snapshotSignaturePayload(manifest, 'manifest');
  const signatureResult = await executeSignatureCheck(
    'status' in signature
      ? signature
      : { ...signature, publicKey: options.publicKey },
  );
  if (signatureResult.status !== 'valid') return signatureResult;
  if (manifest.signature !== undefined) {
    const time = checkManifestTime(
      manifest.signature,
      timeOptions.nowMs ?? Date.now(),
      timeOptions.clockToleranceMs,
    );
    if (time !== undefined) return { status: time };
  }
  return { status: 'passed' };
}

function assertJsonInput(value: unknown): void {
  const inputIssue = preflightJsonValue(value, {
    allowOwnProtoMember: true,
    isDisallowedObject: utilTypes.isProxy,
    requireIJsonStrings: false,
  });
  if (inputIssue)
    throw new (inputIssue.code === 'resource_limit' ? RangeError : TypeError)(
      inputIssue.message,
    );
}

/** Validate and capture entry-owned fields without reading attachment values. */
function captureEntryFields(
  entry: CatalogEntry,
  bytes: unknown,
  isDataCall: boolean,
): { entry: CatalogEntry } | EntryStructureFailure {
  assertCatalogEntryObject(entry);
  const descriptors = Object.getOwnPropertyDescriptors(entry);
  delete descriptors.trustManifests;
  const fields = Object.defineProperties(Object.create(null), descriptors);
  assertJsonInput(fields);
  const hasData = Object.hasOwn(fields, 'data');
  const hasUrl = Object.hasOwn(fields, 'url');
  if (hasData !== hasUrl && hasData !== isDataCall)
    throw new TypeError(
      'URL entries require artifact bytes; inline entries do not accept artifact bytes.',
    );
  if (!isDataCall) assertStableBytes(bytes);
  const parsed = safeParseCatalogEntry(fields);
  return parsed.success
    ? { entry: parsed.data }
    : { status: 'invalid_entry', error: parsed.error };
}

/** Copy already preflighted JSON without invoking serialization hooks. */
function captureJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    const captured: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1)
      captured[index] = captureJson(
        readOwnDataProperty(value, String(index)) as JsonValue,
      );
    return captured;
  }
  if (value !== null && typeof value === 'object') {
    const captured: Record<string, JsonValue> = {};
    for (const key of Object.keys(value))
      Object.defineProperty(captured, key, {
        value: captureJson(readOwnDataProperty(value, key) as JsonValue),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    return captured;
  }
  return value;
}

/** Check the artifact against the captured entry's declared digest. */
function precheckArtifact(
  entry: CatalogEntry,
  bytes: unknown,
): EntryCheckFailure | undefined {
  if (Object.hasOwn(entry, 'digest')) {
    const hasData = Object.hasOwn(entry, 'data');
    const data = readOwnDataProperty(entry, 'data');
    if (hasData) {
      const issue = preflightJsonValue(data, {
        allowOwnProtoMember: true,
        isDisallowedObject: utilTypes.isProxy,
        requireIJsonStrings: true,
      });
      if (issue)
        return {
          status: 'invalid_entry',
          error: new CatalogParseError([
            { ...issue, path: ['data', ...issue.path] },
          ]),
        };
    }
    const artifactBytes = hasData
      ? canonicalizeJsonValueToBytes(data as JsonValue)
      : (bytes as Uint8Array);
    const result = checkDigest(
      artifactBytes,
      readOwnDataProperty(entry, 'digest') as string,
    );
    if (result.status === 'mismatch')
      return { status: 'artifact_digest_mismatch' };
    if (result.status === 'invalid_digest') return result;
    if (result.status === 'algorithm_not_implemented')
      return {
        status: 'digest_algorithm_not_implemented',
        algorithm: result.algorithm,
      };
  }
}

function throwIfCanceled(signal: AbortSignal | undefined): void {
  if (signal !== undefined) AbortSignal.prototype.throwIfAborted.call(signal);
}

interface CapturedTimeCheckOptions {
  clockToleranceMs: number;
  nowMs?: number;
}

function snapshotTimeCheckOptions(value: object): CapturedTimeCheckOptions {
  const options: Record<string, unknown> = Object.create(null);
  for (const name of ['clockToleranceMs', 'nowMs']) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) continue;
    if (!('value' in descriptor))
      throw new TypeError(`options.${name} must be an own data property.`);
    options[name] = descriptor.value;
  }
  const clockToleranceMs =
    options.clockToleranceMs === undefined ? 60_000 : options.clockToleranceMs;
  if (
    typeof clockToleranceMs !== 'number' ||
    !Number.isSafeInteger(clockToleranceMs) ||
    clockToleranceMs < 0
  )
    throw new TypeError('clockToleranceMs must be a nonnegative safe integer.');
  const nowMs = options.nowMs;
  if (
    nowMs !== undefined &&
    (typeof nowMs !== 'number' || !Number.isSafeInteger(nowMs))
  )
    throw new TypeError('nowMs must be safe integer UTC epoch milliseconds.');
  return {
    clockToleranceMs,
    ...(nowMs === undefined ? {} : { nowMs }),
  };
}

interface CapturedEntryCheckOptions extends CapturedTimeCheckOptions {
  contributors?: readonly string[];
  alwaysCheckPublisherManifests: boolean;
  signal?: AbortSignal;
  timeoutMs: number;
  maxResponseBytes: number;
}

function snapshotEntryCheckOptions(value: unknown): CapturedEntryCheckOptions {
  if (value === undefined)
    return {
      alwaysCheckPublisherManifests: false,
      clockToleranceMs: 60_000,
      timeoutMs: 60_000,
      maxResponseBytes: 16 * 1024 * 1024,
    };
  if (
    value === null ||
    typeof value !== 'object' ||
    utilTypes.isProxy(value) ||
    Array.isArray(value)
  )
    throw new TypeError('options must be an object.');
  const options: Record<string, unknown> = Object.create(null);
  for (const name of [
    'contributors',
    'alwaysCheckPublisherManifests',
    'clockToleranceMs',
    'nowMs',
    'signal',
    'timeoutMs',
    'maxResponseBytes',
  ]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) continue;
    if (!('value' in descriptor))
      throw new TypeError(`options.${name} must be an own data property.`);
    options[name] = descriptor.value;
  }
  const timeoutMs =
    options.timeoutMs === undefined ? 60_000 : options.timeoutMs;
  const maxResponseBytes =
    options.maxResponseBytes === undefined
      ? 16 * 1024 * 1024
      : options.maxResponseBytes;
  const timeOptions = snapshotTimeCheckOptions(options);
  const alwaysCheckPublisherManifests =
    options.alwaysCheckPublisherManifests === undefined
      ? false
      : options.alwaysCheckPublisherManifests;
  if (
    typeof timeoutMs !== 'number' ||
    !Number.isFinite(timeoutMs) ||
    timeoutMs <= 0
  )
    throw new TypeError('timeoutMs must be a positive finite number.');
  if (
    typeof maxResponseBytes !== 'number' ||
    !Number.isSafeInteger(maxResponseBytes) ||
    maxResponseBytes <= 0
  )
    throw new TypeError('maxResponseBytes must be a positive safe integer.');
  if (typeof alwaysCheckPublisherManifests !== 'boolean')
    throw new TypeError('alwaysCheckPublisherManifests must be a boolean.');
  let contributors: string[] | undefined;
  if (options.contributors !== undefined) {
    const issue = preflightJsonValue(options.contributors, {
      allowOwnProtoMember: true,
      isDisallowedObject: utilTypes.isProxy,
      requireIJsonStrings: false,
    });
    if (
      issue ||
      !Array.isArray(options.contributors) ||
      !options.contributors.every(
        (contributor) => typeof contributor === 'string',
      )
    )
      throw new TypeError('contributors must be an array of strings.');
    contributors = [...options.contributors];
  }
  const signal = options.signal;
  if (signal !== undefined) {
    if (
      signal === null ||
      typeof signal !== 'object' ||
      utilTypes.isProxy(signal)
    )
      throw new TypeError('signal must be an AbortSignal.');
    try {
      Object.getOwnPropertyDescriptor(
        AbortSignal.prototype,
        'aborted',
      )?.get?.call(signal);
    } catch {
      throw new TypeError('signal must be an AbortSignal.');
    }
  }
  return {
    ...(contributors === undefined ? {} : { contributors }),
    alwaysCheckPublisherManifests,
    ...timeOptions,
    timeoutMs,
    maxResponseBytes,
    ...(signal === undefined ? {} : { signal: signal as AbortSignal }),
  };
}

/**
 * Validates entry structure and its declared artifact digest, then reports
 * every contribution, using `not_checked` for unselected manifests.
 * `checked` is a completed report, not a trust decision; an empty list or
 * failed endorsements can still yield `checked`.
 * Inputs are captured before I/O. Each signer is resolved once per invocation.
 */
export function checkCatalogEntry(
  entry: CatalogEntryWithData,
  options?: CatalogEntryCheckOptions,
): Promise<CatalogEntryCheckResult>;
export function checkCatalogEntry(
  entry: CatalogEntryWithUrl,
  artifactBytes: Uint8Array,
  options?: CatalogEntryCheckOptions,
): Promise<CatalogEntryCheckResult>;
export async function checkCatalogEntry(
  entry: CatalogEntry,
  bytesOrOptions?: Uint8Array | CatalogEntryCheckOptions,
  maybeOptions?: CatalogEntryCheckOptions,
): Promise<CatalogEntryCheckResult> {
  const isDataCall = !utilTypes.isUint8Array(bytesOrOptions);
  if (isDataCall && maybeOptions !== undefined)
    throw new TypeError('Inline entries take options as the second argument.');
  const options = snapshotEntryCheckOptions(
    isDataCall ? bytesOrOptions : maybeOptions,
  );
  throwIfCanceled(options.signal);
  assertCatalogEntryObject(entry);
  // Preserve the invocation-wide JSON defenses and work limit before copying
  // raw attachments. Their schema checks belong to individual results below.
  assertJsonInput(entry);
  const captured = captureEntryFields(entry, bytesOrOptions, isDataCall);
  if ('status' in captured) return captured;
  const attached = readOwnDataProperty(entry, 'trustManifests');
  if (Object.hasOwn(entry, 'trustManifests') && !Array.isArray(attached))
    return {
      status: 'invalid_entry',
      error: new CatalogParseError([
        {
          code: 'invalid_type',
          path: ['trustManifests'],
          message: 'The value is not the required JSON array.',
        },
      ]),
    };
  const manifests = captureJson((attached ?? []) as JsonValue) as JsonValue[];
  const artifact = precheckArtifact(captured.entry, bytesOrOptions);
  if (artifact !== undefined) return artifact;
  const snapshot = captured.entry;
  const publisher = publisherIdentityFor(snapshot.identifier);
  const resolutions = new Map<string, Promise<unknown>>();
  const resolutionOptions = {
    timeoutMs: options.timeoutMs,
    maxResponseBytes: options.maxResponseBytes,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
  const results: TrustManifestEvaluation[] = [];
  for (const input of manifests) {
    const contributor =
      input !== null && typeof input === 'object' && !Array.isArray(input)
        ? readOwnDataProperty(input, 'contributor')
        : undefined;
    const selected =
      options.contributors === undefined ||
      (typeof contributor === 'string' &&
        options.contributors.includes(contributor)) ||
      (options.alwaysCheckPublisherManifests &&
        contributor !== undefined && contributor === publisher);
    if (!selected) {
      results.push({ manifest: input, status: 'not_checked' });
      continue;
    }
    const parsed = safeParseTrustManifest(input);
    if (!parsed.success) {
      results.push({
        manifest: input,
        status: 'invalid_manifest',
        error: new CatalogValidationError(
          parsed.error.issues,
          parsed.error.cause,
        ),
      });
      continue;
    }
    const manifest = parsed.data;
    let result: Exclude<TrustManifestCheckResult, { status: 'not_checked' }>;
    const error = validateTrustManifest(manifest, snapshot);
    if (error !== undefined) result = { status: 'invalid_manifest', error };
    else if (manifest.signature === undefined)
      result = { status: 'unsigned' };
    else if (manifest.signature.profile !== 'did-web-v1')
      result = {
        status: 'profile_not_implemented',
        profile: manifest.signature.profile,
      };
    else {
      const signature = snapshotSignaturePayload(manifest, 'manifest');
      if ('status' in signature) result = signature;
      else {
        const profile = inspectSignerProfile(
          manifest,
          signature.jws.protectedHeader,
        );
        if (profile instanceof Error)
          result = { status: 'profile_check_failed', error: profile };
        else {
          try {
            let document = resolutions.get(profile.identity);
            if (document === undefined) {
              document = resolveDidWeb(profile.identity, resolutionOptions);
              resolutions.set(profile.identity, document);
            }
            const publicKey = authorizePublisherKey(
              await document,
              profile.identity,
              profile.kid,
            );
            throwIfCanceled(options.signal);
            const signatureResult = await executeSignatureCheck({
              ...signature,
              publicKey,
            });
            throwIfCanceled(options.signal);
            result =
              signatureResult.status === 'valid'
                ? {
                    status: 'passed',
                    isPublisherEndorsement:
                      manifest.contributor === publisher,
                  }
                : signatureResult;
          } catch (error) {
            throwIfCanceled(options.signal);
            if (!(error instanceof IssuerCheckError)) throw error;
            result = { status: 'issuer_check_failed', error };
          }
        }
      }
    }
    if (result.status === 'invalid_manifest')
      results.push({ manifest: input, ...result });
    else results.push({ manifest, ...result });
  }
  throwIfCanceled(options.signal);
  const now = options.nowMs ?? Date.now();
  for (let index = 0; index < results.length; index += 1) {
    const evaluation = results[index];
    if (
      evaluation?.status !== 'passed' ||
      evaluation.manifest.signature === undefined
    )
      continue;
    const time = checkManifestTime(
      evaluation.manifest.signature,
      now,
      options.clockToleranceMs,
    );
    if (time !== undefined)
      results[index] = {
        manifest: evaluation.manifest,
        status: time,
      };
  }
  return { status: 'checked', manifests: results };
}

function digestHex(bytes: Uint8Array, algorithm: DigestAlgorithm): string {
  try {
    return createHash(algorithm).update(bytes).digest('hex');
  } catch (cause) {
    throw new DigestAlgorithmUnavailableError(algorithm, cause);
  }
}

/**
 * Creates an AI Catalog digest in `algorithm:lowercase-hex` form.
 *
 * Uint8Array and Buffer inputs are hashed as their exact byte range. Logical
 * JSON values are JCS-canonicalized before hashing. Strings are JSON string
 * values, not JSON source text or raw text; ordinary arrays are JSON arrays.
 * SHA-256 is the default algorithm.
 *
 * @throws {TypeError} If the algorithm is unsupported, byte storage is shared
 * or detached, or the value cannot be canonicalized as plain I-JSON.
 * @throws {RangeError} If a JSON value exceeds canonicalization limits.
 * @throws {DigestAlgorithmUnavailableError} If the runtime cannot execute the
 * selected algorithm.
 */
export function createDigest(
  value: Uint8Array | JsonValue,
  algorithm: DigestAlgorithm = 'sha256',
): string {
  if (typeof algorithm !== 'string' || !isImplementedDigestAlgorithm(algorithm))
    throw new TypeError('algorithm must be sha256, sha384, or sha512.');
  const bytes = utilTypes.isUint8Array(value)
    ? value
    : canonicalizeJsonValueToBytes(value);
  assertStableBytes(bytes);
  return `${algorithm}:${digestHex(bytes, algorithm)}`;
}

/**
 * Compares caller-supplied bytes with an AI Catalog digest.
 *
 * The exact byte range represented by `bytes` is hashed without fetching,
 * decoding, serialization, or JCS canonicalization. A matching digest proves
 * only that those bytes match the declaration; it does not establish that the
 * declaration is authentic or that the content is trustworthy.
 *
 * This SDK currently implements the exact, case-sensitive `sha256`, `sha384`,
 * and `sha512` algorithm tokens. Other syntactically valid tokens produce an
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

  if (expectedHex.length !== DIGEST_HEX_LENGTHS[algorithm]) {
    return { status: 'invalid_digest' };
  }

  const actualHex = digestHex(bytes, algorithm);

  return { status: actualHex === expectedHex ? 'match' : 'mismatch' };
}

export {
  signTrustManifest,
  type UnsignedTrustManifest,
  type EntryTrustManifest,
  type TrustManifestSignatureMetadata,
  type JwsSigningResult,
  type TrustManifestSigningInput,
  type TrustManifestSigner,
} from './internal/signing.js';
