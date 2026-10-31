import { Buffer } from 'node:buffer';
import { types as utilTypes } from 'node:util';

import type {
  CatalogEntry,
  JsonValue,
  SignedTrustManifest,
  TrustManifest,
  TrustSubject,
} from '../types.js';
import { createTrustManifestSignaturePayload } from '../verification.js';
import { preflightJsonValue } from './json-value.js';
import { concreteTrustManifestSchema } from './schemas.js';

const signatureTyp = 'ai-catalog-trust-manifest+jws';
const strictUtf8Decoder = new TextDecoder('utf-8', { fatal: true });

/** Manifest content to sign with an explicitly supplied subject. */
export type UnsignedTrustManifest = Omit<TrustManifest, 'signature' | 'subject'> & {
  subject: TrustSubject;
  signature?: never;
};

/** Manifest content whose subject will be derived from an entry. */
export type EntryTrustManifest = Omit<TrustManifest, 'signature' | 'subject'> & {
  subject?: never;
  signature?: never;
};

/** Signature metadata; the signer is derived from the manifest's contributor. */
export interface TrustManifestSignatureMetadata {
  profile: string;
  issuedAt: string;
  expiresAt?: string;
  signer?: never;
  jws?: never;
}

/** A compact (attached or detached) or flattened JWS serialization. */
export type JwsSigningResult = string | {
  protected?: string;
  payload: string;
  signature: string;
};

/** Canonical payload bytes and the required protected JWS type. */
export interface TrustManifestSigningInput {
  payload: Uint8Array;
  typ: typeof signatureTyp;
}

/** Creates a JWS over the exact supplied payload using caller-selected keys. */
export type TrustManifestSigner = (
  input: TrustManifestSigningInput,
) => JwsSigningResult | PromiseLike<JwsSigningResult>;

function cloneJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    const result: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      result.push(cloneJson(value[index] as JsonValue));
    }
    return result;
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, JsonValue> = Object.create(null);
    for (const key of Object.keys(value)) {
      Object.defineProperty(result, key, {
        value: cloneJson(value[key] as JsonValue),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return result;
  }
  return value;
}

function snapshotObject(
  value: unknown,
  name: string,
  requireIJsonStrings = true,
): Record<string, JsonValue> {
  const issue = preflightJsonValue(value, {
    allowOwnProtoMember: true,
    isDisallowedObject: utilTypes.isProxy,
    requireIJsonStrings,
  });
  if (issue) {
    const ErrorClass = issue.code === 'resource_limit' ? RangeError : TypeError;
    throw new ErrorClass(issue.message);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${name} must be a plain JSON object.`);
  }
  return cloneJson(value as JsonValue) as Record<string, JsonValue>;
}

function rejectOwn(value: object, names: string[], name: string): void {
  for (const field of names) {
    if (Object.hasOwn(value, field)) {
      throw new TypeError(`${name}.${field} must be absent.`);
    }
  }
}

function base64UrlSegment(value: unknown, name: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    !/^[A-Za-z0-9_-]+$/.test(value) ||
    Buffer.from(value, 'base64url').toString('base64url') !== value
  ) {
    throw new TypeError(`The JWS ${name} must be canonical unpadded base64url.`);
  }
  return value;
}

function detachJws(value: unknown, expectedPayload: string): string {
  let protectedSegment: unknown;
  let payloadSegment: unknown;
  let signatureSegment: unknown;
  let detached = false;
  if (typeof value === 'string') {
    const parts = value.split('.');
    if (parts.length !== 3) {
      throw new TypeError('The signing callback must return a compact or flattened JWS.');
    }
    [protectedSegment, payloadSegment, signatureSegment] = parts;
    detached = payloadSegment === '';
  } else {
    const result = snapshotObject(value, 'JWS');
    rejectOwn(result, ['header'], 'JWS');
    for (const field of ['protected', 'payload', 'signature']) {
      if (!Object.hasOwn(result, field)) {
        throw new TypeError(`The flattened JWS must contain its own ${field} member.`);
      }
    }
    protectedSegment = result.protected;
    payloadSegment = result.payload;
    signatureSegment = result.signature;
  }
  const encodedHeader = base64UrlSegment(protectedSegment, 'protected header');
  const encodedSignature = base64UrlSegment(signatureSegment, 'signature');
  if (!detached && payloadSegment !== expectedPayload) {
    throw new TypeError('The JWS payload must match the bytes supplied to the signing callback.');
  }
  let header: Record<string, JsonValue>;
  try {
    const decoded: unknown = JSON.parse(
      strictUtf8Decoder.decode(Buffer.from(encodedHeader, 'base64url')),
    );
    header = snapshotObject(decoded, 'JWS protected header');
  } catch (cause) {
    throw new TypeError('The protected JWS header must be a UTF-8 JSON object.', { cause });
  }
  if (typeof header.alg !== 'string' || header.alg.length === 0 || header.alg === 'none') {
    throw new TypeError('The protected JWS alg must name a signature algorithm other than none.');
  }
  if (header.typ !== signatureTyp) {
    throw new TypeError(`The protected JWS typ must be ${signatureTyp}.`);
  }
  if (Object.hasOwn(header, 'b64')) {
    throw new TypeError('AI Catalog signatures forbid the protected b64 parameter.');
  }
  if (Object.hasOwn(header, 'crit')) {
    const critical = header.crit;
    const registered = new Set(['alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'typ', 'cty', 'crit']);
    if (
      !Array.isArray(critical) ||
      critical.length === 0 ||
      critical.some((field) => typeof field !== 'string' || field.length === 0 || registered.has(field) || !Object.hasOwn(header, field)) ||
      new Set(critical).size !== critical.length
    ) {
      throw new TypeError('The protected JWS crit declaration is invalid.');
    }
  }
  return `${encodedHeader}..${encodedSignature}`;
}

/**
 * Signs a Trust Manifest using caller-supplied signing code.
 *
 * Inputs are captured before the callback. The callback receives canonical
 * payload bytes and supplies the required protected type in its JWS header.
 * Attached payloads are checked and detached; already-detached JWS values must
 * have been signed over those exact bytes. This helper does not verify the
 * cryptographic signature, authenticate a key, or enforce current acceptance.
 */
export function signTrustManifest(
  manifest: UnsignedTrustManifest,
  metadata: TrustManifestSignatureMetadata,
  createJws: TrustManifestSigner,
): Promise<SignedTrustManifest>;
/**
 * Derives the subject from the entry's identifier, type, declared digest, and
 * version. The entry is not modified; no artifact is fetched or hashed.
 */
export function signTrustManifest(
  entry: CatalogEntry,
  manifest: EntryTrustManifest,
  metadata: TrustManifestSignatureMetadata,
  createJws: TrustManifestSigner,
): Promise<SignedTrustManifest>;
export async function signTrustManifest(
  entryOrManifest: CatalogEntry | UnsignedTrustManifest,
  manifestOrMetadata: EntryTrustManifest | TrustManifestSignatureMetadata,
  metadataOrCreateJws: TrustManifestSignatureMetadata | TrustManifestSigner,
  maybeCreateJws?: TrustManifestSigner,
): Promise<SignedTrustManifest> {
  const entryForm = maybeCreateJws !== undefined;
  const createJws = entryForm ? maybeCreateJws : metadataOrCreateJws;
  if (typeof createJws !== 'function') {
    throw new TypeError('createJws must be a function.');
  }
  const manifest = snapshotObject(
    entryForm ? manifestOrMetadata : entryOrManifest,
    'manifest',
    false,
  );
  rejectOwn(manifest, entryForm ? ['signature', 'subject'] : ['signature'], 'manifest');
  if (!Object.hasOwn(manifest, 'contributor') || (!entryForm && !Object.hasOwn(manifest, 'subject'))) {
    throw new TypeError(entryForm
      ? 'The manifest must contain its own contributor.'
      : 'The manifest must contain its own contributor and subject.');
  }
  const metadata = snapshotObject(
    entryForm ? metadataOrCreateJws : manifestOrMetadata,
    'metadata',
  );
  rejectOwn(metadata, ['signer', 'jws'], 'metadata');
  if (!Object.hasOwn(metadata, 'profile') || !Object.hasOwn(metadata, 'issuedAt')) {
    throw new TypeError('Signature metadata must contain its own profile and issuedAt.');
  }
  if (entryForm) {
    const entry = entryOrManifest;
    if (
      entry === null || typeof entry !== 'object' || utilTypes.isProxy(entry) ||
      Array.isArray(entry) ||
      (Object.getPrototypeOf(entry) !== Object.prototype && Object.getPrototypeOf(entry) !== null)
    ) throw new TypeError('entry must be a plain object.');
    const subject: Record<string, JsonValue> = {};
    for (const field of ['identifier', 'type', 'digest', 'version']) {
      const descriptor = Object.getOwnPropertyDescriptor(entry, field);
      if (!descriptor && field === 'version') continue;
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor) || typeof descriptor.value !== 'string') {
        throw new TypeError(`entry.${field} must be an enumerable own string property.`);
      }
      subject[field] = descriptor.value;
    }
    manifest.subject = subject;
  }
  const signature = {
    ...metadata,
    signer: manifest.contributor,
    jws: '',
  };
  const completed = { ...manifest, signature };
  const validation = concreteTrustManifestSchema.safeParse(completed);
  if (!validation.success) {
    throw new TypeError('The manifest and signature metadata must form a valid signed Trust Manifest.', { cause: validation.error });
  }
  const signed = completed as unknown as SignedTrustManifest;
  const payload = createTrustManifestSignaturePayload(signed);
  const expectedPayload = Buffer.from(payload).toString('base64url');
  const result = await createJws({ payload: new Uint8Array(payload), typ: signatureTyp });
  signed.signature.jws = detachJws(result, expectedPayload);
  return signed;
}
