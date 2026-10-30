import { Buffer } from 'node:buffer';
import { createHash, type KeyObject, type webcrypto } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import canonicalize from 'canonicalize';
import { flattenedVerify } from 'jose/jws/flattened/verify';
import * as joseErrors from 'jose/errors';

import { DIGEST_PATTERN } from './internal/digest.js';
import { preflightJsonValue } from './internal/json-value.js';
import { resolveDidWeb } from './internal/did-web.js';
import {
  inspectSignerProfile,
  publisherIdentityFor,
  authorizePublisherKey,
  checkManifestTime,
  IssuerCheckError,
} from './internal/publisher-profile.js';
import { safeParseCatalogEntry } from './internal/parser.js';
import type {
  CatalogParseError,
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

const digestImplementations = {
  sha256: {
    nodeName: 'sha256',
    hexLength: 64,
  },
  sha384: {
    nodeName: 'sha384',
    hexLength: 96,
  },
  sha512: {
    nodeName: 'sha512',
    hexLength: 128,
  },
} as const;

type ImplementedDigestAlgorithm = keyof typeof digestImplementations;

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

type TrustSubjectSnapshot =
  | { kind: 'missing' }
  | { kind: 'invalid' }
  | {
      kind: 'present';
      identifier: unknown;
      hasVersion: boolean;
      version: unknown;
      type: unknown;
      digest: unknown;
    };

function isImplementedDigestAlgorithm(
  algorithm: string,
): algorithm is ImplementedDigestAlgorithm {
  return Object.hasOwn(digestImplementations, algorithm);
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

function readRequiredEntryProperty(entry: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(entry, name);
  if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
    throw new TypeError(
      `entry.${name} must be an enumerable own data property.`,
    );
  }
  return descriptor.value;
}

function readOptionalEntryProperty(
  entry: object,
  name: string,
): { present: boolean; value: unknown } {
  const descriptor = Object.getOwnPropertyDescriptor(entry, name);
  if (!descriptor) return { present: false, value: undefined };
  if (!descriptor.enumerable || !('value' in descriptor)) {
    throw new TypeError(
      `entry.${name} must be an enumerable own data property when present.`,
    );
  }
  return { present: true, value: descriptor.value };
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

function snapshotTrustSubject(manifest: TrustManifest): TrustSubjectSnapshot {
  const descriptor = Object.getOwnPropertyDescriptor(manifest, 'subject');
  if (!descriptor) return { kind: 'missing' };

  // The signature payload preflight has already rejected accessors, proxies,
  // and non-JSON members throughout the manifest.
  const subject = 'value' in descriptor ? descriptor.value : undefined;
  if (
    subject === null ||
    typeof subject !== 'object' ||
    Array.isArray(subject)
  ) {
    return { kind: 'invalid' };
  }

  const versionDescriptor = Object.getOwnPropertyDescriptor(subject, 'version');
  return {
    kind: 'present',
    identifier: readOwnDataProperty(subject, 'identifier'),
    hasVersion: versionDescriptor !== undefined,
    version:
      versionDescriptor && 'value' in versionDescriptor
        ? versionDescriptor.value
        : undefined,
    type: readOwnDataProperty(subject, 'type'),
    digest: readOwnDataProperty(subject, 'digest'),
  };
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
  if (value.length - signatureStart !== 86) {
    return { status: 'invalid_signature' };
  }

  const signatureSegment = value.slice(signatureStart);
  const signatureBytes = Buffer.from(signatureSegment, 'base64url');
  if (signatureBytes.length !== 64) {
    return { status: 'invalid_signature' };
  }

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
  | { status: 'missing_signature' }
  | { status: 'invalid_jws' }
  | { status: 'algorithm_mismatch'; algorithm: string }
  | { status: 'jws_feature_not_implemented' }
  | { status: 'invalid_signature' };

/** A failed comparison between a signed subject and its entry/artifact. */
export type SubjectCheckFailure =
  | { status: 'missing_subject' }
  | { status: 'identifier_mismatch' }
  | { status: 'version_mismatch' }
  | { status: 'type_mismatch' }
  | { status: 'digest_mismatch' }
  | Exclude<DigestCheckResult, { status: 'match' }>;

/** The outcome of checking one explicit manifest using a caller-selected key. */
export type CatalogEntryArtifactBindingCheckResult =
  | { status: 'valid' }
  | { status: 'signature_check_failed'; signatureResult: SignatureCheckFailure }
  | { status: 'subject_check_failed'; subjectResult: SubjectCheckFailure };

/** Selection, time, and DID-resolution controls for an entry check. */
export interface CatalogEntryCheckOptions {
  /** Omitted selects all; an empty array selects none. Values match exactly. */
  contributors?: readonly string[];
  /** Adds the entry's derived publisher manifests to the contributor selection. */
  alwaysCheckPublisherManifests?: boolean;
  /** Nonnegative integer milliseconds of clock skew. Defaults to 60,000. */
  clockToleranceMs?: number;
  /** Cancels the whole operation; cancellation rejects with the signal reason. */
  signal?: AbortSignal;
  /** Deadline for each DID resolution, including DNS/redirects/body. Defaults to 60,000 ms. */
  timeoutMs?: number;
  /** Maximum decoded body size per DID document. Defaults to 16 MiB. */
  maxResponseBytes?: number;
}

/** One contribution's outcome; a valid contribution need not be from the publisher. */
export type TrustManifestCheckResult =
  | { status: 'valid'; isPublisherEndorsement: boolean }
  | { status: 'missing_signature' }
  | { status: 'profile_not_implemented'; profile: string }
  | { status: 'profile_check_failed'; error: Error }
  | { status: 'issuer_check_failed'; error: Error }
  | { status: 'signature_check_failed'; signatureResult: SignatureCheckFailure }
  | { status: 'subject_check_failed'; subjectResult: SubjectCheckFailure }
  | { status: 'not_yet_valid' }
  | { status: 'expired' };

/** The captured manifest and its original position, with its individual outcome. */
export type TrustManifestEvaluation = TrustManifestCheckResult & {
  index: number;
  manifest: TrustManifest;
};

/** A report of the requested checks, without an application acceptance policy. */
export type CatalogEntryCheckResult =
  | { status: 'invalid_entry'; error: CatalogParseError }
  | {
      status: 'artifact_check_failed';
      digestResult: Exclude<DigestCheckResult, { status: 'match' }>;
    }
  | { status: 'publisher_selection_failed'; error: Error }
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

  if (signature === undefined) return { status: 'missing_signature' };
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
 * Checks one explicit manifest's signature and artifact binding with the
 * caller-selected key. It does not resolve identity or enforce currentness.
 * URL entries take their supplied artifact bytes adjacent to the entry.
 */
export function checkCatalogEntryArtifactBinding(
  entry: CatalogEntryWithData,
  manifest: TrustManifest,
  options: SignatureCheckOptions,
): Promise<CatalogEntryArtifactBindingCheckResult>;
export function checkCatalogEntryArtifactBinding(
  entry: CatalogEntryWithUrl,
  artifactBytes: Uint8Array,
  manifest: TrustManifest,
  options: SignatureCheckOptions,
): Promise<CatalogEntryArtifactBindingCheckResult>;
export async function checkCatalogEntryArtifactBinding(
  entry: CatalogEntry,
  bytesOrManifest: Uint8Array | TrustManifest,
  manifestOrOptions: TrustManifest | SignatureCheckOptions,
  maybeOptions?: SignatureCheckOptions,
): Promise<CatalogEntryArtifactBindingCheckResult> {
  const isDataCall = maybeOptions === undefined;
  const options = snapshotSignatureCheckOptions(
    isDataCall ? manifestOrOptions : maybeOptions,
  );
  const artifact = captureArtifactContext(entry, bytesOrManifest, isDataCall);
  const manifest = (
    isDataCall ? bytesOrManifest : manifestOrOptions
  ) as TrustManifest;
  const signature = snapshotSignaturePayload(manifest, 'manifest');
  const subjectResult = checkSubject(artifact.entry, manifest, artifact.bytes);
  const signatureResult = await executeSignatureCheck(
    'status' in signature
      ? signature
      : { ...signature, publicKey: options.publicKey },
  );
  if (signatureResult.status !== 'valid')
    return { status: 'signature_check_failed', signatureResult };
  if (subjectResult.status !== 'match')
    return { status: 'subject_check_failed', subjectResult };
  return { status: 'valid' };
}

function captureArtifactContext(
  entry: CatalogEntry,
  bytes: unknown,
  isDataCall: boolean,
): { entry: CatalogEntry; bytes: Uint8Array } {
  assertCatalogEntryObject(entry);
  const identifier = readRequiredEntryProperty(entry, 'identifier');
  const type = readRequiredEntryProperty(entry, 'type');
  const version = readOptionalEntryProperty(entry, 'version');
  const digest = readOptionalEntryProperty(entry, 'digest');
  if (
    typeof identifier !== 'string' ||
    typeof type !== 'string' ||
    (version.present && typeof version.value !== 'string') ||
    (digest.present && typeof digest.value !== 'string')
  )
    throw new TypeError(
      'Entry coordinates and digest must be strings when present.',
    );
  const data = readOptionalEntryProperty(entry, 'data');
  const url = readOptionalEntryProperty(entry, 'url');
  if (data.present === url.present)
    throw new TypeError('entry must contain exactly one of data or url.');
  if (isDataCall !== data.present)
    throw new TypeError(
      'URL entries require artifact bytes; inline entries do not accept artifact bytes.',
    );
  if (url.present && typeof url.value !== 'string')
    throw new TypeError('entry.url must be a string.');
  let artifactBytes: Uint8Array;
  if (data.present)
    artifactBytes = canonicalizeJsonValueToBytes(data.value as JsonValue);
  else {
    assertStableBytes(bytes);
    artifactBytes = bytes;
  }
  const captured = {
    identifier,
    type,
    ...(version.present ? { version: version.value as string } : {}),
    ...(digest.present ? { digest: digest.value as string } : {}),
    ...(data.present ? { data: null } : { url: url.value as string }),
  } as CatalogEntry;
  return { entry: captured, bytes: artifactBytes };
}

function checkSubject(
  entry: CatalogEntry,
  manifest: TrustManifest,
  bytes: Uint8Array,
  digestResult?: DigestCheckResult,
): { status: 'match' } | SubjectCheckFailure {
  const subject = snapshotTrustSubject(manifest);
  if (subject.kind === 'missing') return { status: 'missing_subject' };
  if (subject.kind === 'invalid')
    throw new TypeError('manifest.subject must be an object.');
  if (
    typeof subject.identifier !== 'string' ||
    typeof subject.type !== 'string' ||
    typeof subject.digest !== 'string' ||
    (subject.hasVersion && typeof subject.version !== 'string')
  )
    throw new TypeError('Subject coordinates and digest must be strings.');
  if (subject.identifier !== entry.identifier)
    return { status: 'identifier_mismatch' };
  if (
    subject.hasVersion !== Object.hasOwn(entry, 'version') ||
    subject.version !== entry.version
  )
    return { status: 'version_mismatch' };
  if (subject.type !== entry.type) return { status: 'type_mismatch' };
  if (subject.digest !== entry.digest) return { status: 'digest_mismatch' };
  return digestResult ?? checkDigest(bytes, subject.digest);
}

function throwIfCanceled(signal: AbortSignal | undefined): void {
  if (signal !== undefined) AbortSignal.prototype.throwIfAborted.call(signal);
}

interface CapturedEntryCheckOptions {
  contributors?: readonly string[];
  alwaysCheckPublisherManifests: boolean;
  clockToleranceMs: number;
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
  const clockToleranceMs =
    options.clockToleranceMs === undefined ? 60_000 : options.clockToleranceMs;
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
  if (
    typeof clockToleranceMs !== 'number' ||
    !Number.isSafeInteger(clockToleranceMs) ||
    clockToleranceMs < 0
  )
    throw new TypeError('clockToleranceMs must be a nonnegative safe integer.');
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
    clockToleranceMs,
    timeoutMs,
    maxResponseBytes,
    ...(signal === undefined ? {} : { signal: signal as AbortSignal }),
  };
}

/** Copy accepted JSON data without adding canonicalization-only restrictions. */
function captureJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    const result: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1)
      result[index] = captureJson(
        readOwnDataProperty(value, String(index)) as JsonValue,
      );
    return result;
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, JsonValue> = Object.create(null);
    for (const key of Object.keys(value))
      result[key] = captureJson(readOwnDataProperty(value, key) as JsonValue);
    return result;
  }
  return value;
}

/**
 * Validates entry structure and its declared artifact digest, then reports
 * every selected contribution. `checked` is a completed report, not a trust
 * decision; an empty list or failed endorsements can still yield `checked`.
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
  const inputIssue = preflightJsonValue(entry, {
    allowOwnProtoMember: true,
    isDisallowedObject: utilTypes.isProxy,
    requireIJsonStrings: false,
  });
  if (inputIssue)
    throw new (inputIssue.code === 'resource_limit' ? RangeError : TypeError)(
      inputIssue.message,
    );
  const captured = captureJson(
    entry as unknown as JsonValue,
  ) as unknown as CatalogEntry;
  // Validate overload shape before reporting structural failures.
  const hasData = Object.hasOwn(captured, 'data');
  if ((hasData || Object.hasOwn(captured, 'url')) && hasData !== isDataCall)
    throw new TypeError(
      'URL entries require artifact bytes; inline entries do not accept artifact bytes.',
    );
  if (!isDataCall) assertStableBytes(bytesOrOptions);
  const parsed = safeParseCatalogEntry(captured);
  if (!parsed.success) return { status: 'invalid_entry', error: parsed.error };
  const snapshot = parsed.data;
  const publisher = publisherIdentityFor(snapshot.identifier);
  if (
    options.contributors !== undefined &&
    options.alwaysCheckPublisherManifests &&
    publisher === undefined
  )
    return {
      status: 'publisher_selection_failed',
      error: new Error(
        'Publisher selection requires a standard urn:air identifier with a supported publisher domain.',
      ),
    };
  const manifests = (snapshot.trustManifests ?? [])
    .map((manifest, index) => ({ manifest, index }))
    .filter(
      ({ manifest }) =>
        options.contributors === undefined ||
        options.contributors.includes(manifest.contributor) ||
        (options.alwaysCheckPublisherManifests &&
          manifest.contributor === publisher),
    );
  let artifactBytes: Uint8Array = new Uint8Array();
  let digestResult: DigestCheckResult = { status: 'match' };
  if (snapshot.digest !== undefined) {
    artifactBytes = hasData
      ? canonicalizeJsonValueToBytes((snapshot as CatalogEntryWithData).data)
      : (bytesOrOptions as Uint8Array);
    digestResult = checkDigest(artifactBytes, snapshot.digest);
    if (digestResult.status !== 'match')
      return { status: 'artifact_check_failed', digestResult };
  }
  const resolutions = new Map<string, Promise<unknown>>();
  const resolutionOptions = {
    timeoutMs: options.timeoutMs,
    maxResponseBytes: options.maxResponseBytes,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
  const results: TrustManifestEvaluation[] = [];
  for (const { manifest, index } of manifests) {
    let result: TrustManifestCheckResult;
    if (manifest.signature === undefined)
      result = { status: 'missing_signature' };
    else if (manifest.signature.profile !== 'did-web-v1')
      result = {
        status: 'profile_not_implemented',
        profile: manifest.signature.profile,
      };
    else {
      const signature = snapshotSignaturePayload(manifest, 'manifest');
      const header =
        'status' in signature
          ? decodeProtectedHeader(manifest.signature.jws)
          : signature.jws.protectedHeader;
      const profile =
        header === undefined
          ? undefined
          : inspectSignerProfile(manifest, header);
      if (profile instanceof Error)
        result = { status: 'profile_check_failed', error: profile };
      else if ('status' in signature)
        result = {
          status: 'signature_check_failed',
          signatureResult: signature,
        };
      else if (profile === undefined)
        result = {
          status: 'signature_check_failed',
          signatureResult: { status: 'invalid_jws' },
        };
      else {
        const subjectResult = checkSubject(
          snapshot,
          manifest,
          artifactBytes,
          digestResult,
        );
        if (subjectResult.status !== 'match')
          result = { status: 'subject_check_failed', subjectResult };
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
                    status: 'valid',
                    isPublisherEndorsement: manifest.contributor === publisher,
                  }
                : { status: 'signature_check_failed', signatureResult };
          } catch (error) {
            throwIfCanceled(options.signal);
            if (!(error instanceof IssuerCheckError)) throw error;
            result = { status: 'issuer_check_failed', error };
          }
        }
      }
    }
    results.push({ index, manifest, ...result });
  }
  throwIfCanceled(options.signal);
  const now = Date.now();
  for (let index = 0; index < results.length; index += 1) {
    const evaluation = results[index];
    if (
      evaluation?.status !== 'valid' ||
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
        index: evaluation.index,
        manifest: evaluation.manifest,
        status: time,
      };
  }
  return { status: 'checked', manifests: results };
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

  const implementation = digestImplementations[algorithm];
  if (expectedHex.length !== implementation.hexLength) {
    return { status: 'invalid_digest' };
  }

  let actualHex: string;
  try {
    actualHex = createHash(implementation.nodeName).update(bytes).digest('hex');
  } catch (cause) {
    throw new DigestAlgorithmUnavailableError(algorithm, cause);
  }

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
