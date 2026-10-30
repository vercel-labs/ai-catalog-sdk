import { Buffer } from 'node:buffer';
import { createPublicKey, type KeyObject } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

import type { Signature, TrustManifest } from '../types.js';
import { compareRfc3339DateTimes, isRfc3339DateTime } from './rfc3339.js';

export class IssuerCheckError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'IssuerCheckError';
  }
}

const uriCharacter = "(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})";
const airTail = new RegExp(`^${uriCharacter}+$`);
const fragmentPattern = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+$/;
const didCharacter = '(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})';
const didPattern = new RegExp(
  `^did:[a-z0-9]+:(?:${didCharacter}|:)*${didCharacter}$`,
);
const uriReferencePattern =
  /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?#-]|%[0-9A-Fa-f]{2})*$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function own(value: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(value, name) ? value[name] : undefined;
}

function validPublisherDomain(domain: string): boolean {
  if (
    domain.length > 253 ||
    !/^[a-z0-9.-]+$/.test(domain) ||
    domainToASCII(domain) !== domain ||
    isIP(domain) !== 0
  )
    return false;

  if (
    !domain
      .split('.')
      .every(
        (label) =>
          label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
      )
  )
    return false;

  // WHATWG also recognizes shortened, hexadecimal, and integer IPv4 forms.
  try {
    return isIP(new URL(`https://${domain}/`).hostname) === 0;
  } catch {
    return false;
  }
}

/** Derives the publisher selected by the standard urn:air Publisher Profile. */
export function publisherIdentityFor(identifier: string): string | undefined {
  const components = identifier.split(':');
  const publisher = components[2];
  if (
    !identifier.startsWith('urn:air:') ||
    components.length < 5 ||
    publisher === undefined ||
    !validPublisherDomain(publisher) ||
    !components.slice(3).every((component) => airTail.test(component))
  )
    return undefined;
  return `did:web:${publisher}`;
}

/** Receives captured, structurally validated JSON manifest/header values. */
export function inspectSignerProfile(
  manifest: TrustManifest,
  header: Record<string, unknown>,
): { identity: string; kid: string } | Error {
  const identity = manifest.contributor;
  if (typeof identity !== 'string')
    throw new TypeError('Trust Manifest contributor must be a string.');
  if (
    !identity.startsWith('did:web:') ||
    !validPublisherDomain(identity.slice('did:web:'.length))
  )
    return new Error(
      'The did:web Signer Profile requires a root DID with a supported lowercase domain.',
    );
  if (manifest.signature?.signer !== identity)
    return new Error(
      'The signature signer must exactly equal the contributor.',
    );
  for (const parameter of ['b64', 'jku', 'jwk', 'x5u', 'x5c']) {
    if (Object.hasOwn(header, parameter))
      return new Error(`The Signer Profile forbids protected ${parameter}.`);
  }
  const kid = own(header, 'kid');
  if (
    typeof kid !== 'string' ||
    !kid.startsWith(`${identity}#`) ||
    !fragmentPattern.test(kid.slice(identity.length + 1))
  )
    return new Error(
      'The protected kid must be the exact signer DID followed by a non-empty URI fragment.',
    );
  return { identity, kid };
}

function resolveDidUrl(value: unknown, identity: string): string {
  if (typeof value !== 'string' || !uriReferencePattern.test(value)) {
    throw new IssuerCheckError('A DID verification-method identifier or reference is not a URI reference.');
  }
  const hash = value.indexOf('#');
  if (hash >= 0 && value.indexOf('#', hash + 1) >= 0) throw new IssuerCheckError('A DID URL has more than one fragment delimiter.');
  if (value.startsWith('did:')) {
    const did = value.split(/[/?#]/, 1)[0];
    if (did === undefined || !didPattern.test(did)) throw new IssuerCheckError('A verification-method identifier is not a valid DID URL.');
    return value;
  }
  if (/^[^/?#]*:/.test(value) || value.startsWith('//')) {
    throw new IssuerCheckError('A verification-method reference must resolve to a DID URL.');
  }
  // Only a fragment reference can resolve to the pathless, queryless kid this
  // profile permits. Other references preserve their distinct path/query.
  if (value === '' || value.startsWith('#') || value.startsWith('?')) return identity + value;
  const resolved = new URL(value, 'https://did.invalid/');
  return identity + resolved.pathname + resolved.search + resolved.hash;
}

function readMethod(value: unknown, identity: string): { id: string; method: Record<string, unknown> } {
  if (!isRecord(value)) throw new IssuerCheckError('A DID verification method must be an object.');
  const id = resolveDidUrl(own(value, 'id'), identity);
  const type = own(value, 'type');
  const controller = own(value, 'controller');
  if (typeof type !== 'string' || type.length === 0 || typeof controller !== 'string' || !didPattern.test(controller)) {
    throw new IssuerCheckError('A DID verification method requires a type and a DID controller.');
  }
  return { id, method: value };
}

const p256Prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const p256B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function coordinate(value: unknown): bigint | undefined {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return undefined;
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) return undefined;
  return BigInt(`0x${bytes.toString('hex')}`);
}

function importPublisherKey(method: Record<string, unknown>, identity: string): KeyObject {
  if (own(method, 'controller') !== identity) throw new IssuerCheckError('The assertion key controller must exactly equal the issuer DID.');
  const jwk = own(method, 'publicKeyJwk');
  if (!isRecord(jwk) || own(jwk, 'kty') !== 'EC' || own(jwk, 'crv') !== 'P-256') {
    throw new IssuerCheckError('The assertion key must contain an EC P-256 publicKeyJwk.');
  }
  if (Object.hasOwn(method, 'publicKeyMultibase')) throw new IssuerCheckError('A verification method cannot contain both JWK and multibase key material.');
  for (const parameter of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    if (Object.hasOwn(jwk, parameter)) throw new IssuerCheckError('A DID publicKeyJwk must not contain private key material.');
  }
  if ((Object.hasOwn(jwk, 'alg') && own(jwk, 'alg') !== 'ES256') || (Object.hasOwn(jwk, 'use') && own(jwk, 'use') !== 'sig')) {
    throw new IssuerCheckError('The assertion JWK algorithm and use must permit ES256 signatures.');
  }
  if (Object.hasOwn(jwk, 'key_ops')) {
    const operations = own(jwk, 'key_ops');
    if (!Array.isArray(operations) || !operations.every((operation) => typeof operation === 'string') || new Set(operations).size !== operations.length || !operations.includes('verify')) {
      throw new IssuerCheckError('The assertion JWK key_ops must permit verify.');
    }
  }
  if (Object.hasOwn(jwk, 'kid') && typeof own(jwk, 'kid') !== 'string') throw new IssuerCheckError('A JWK kid, when present, must be a string.');
  const x = coordinate(own(jwk, 'x'));
  const y = coordinate(own(jwk, 'y'));
  if (x === undefined || y === undefined || x >= p256Prime || y >= p256Prime || (y * y) % p256Prime !== ((x * x * x - 3n * x + p256B) % p256Prime + p256Prime) % p256Prime) {
    throw new IssuerCheckError('The assertion JWK must contain canonical P-256 coordinates on the curve.');
  }
  // Mathematical validation above separates malformed points from unexpected
  // failures in the crypto backend; the latter must propagate to the caller.
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string }, format: 'jwk' });
}

/** Authorizes a key from the current resolved DID document, without further I/O. */
export function authorizePublisherKey(document: unknown, identity: string, kid: string): KeyObject {
  if (!isRecord(document) || own(document, 'id') !== identity) throw new IssuerCheckError('The DID document id must exactly equal the issuer DID.');
  if (Object.hasOwn(document, '@context')) {
    const context = own(document, '@context');
    const contexts = Array.isArray(context) ? context : [context];
    if (contexts[0] !== 'https://www.w3.org/ns/did/v1' ||
      !contexts.every((value) => typeof value === 'string' || isRecord(value))) {
      throw new IssuerCheckError('A JSON-LD DID document requires the DID Core context first.');
    }
  }
  const methods = new Map<string, Record<string, unknown>>();
  const addMethod = (value: unknown): string => {
    const { id, method } = readMethod(value, identity);
    if (methods.has(id)) throw new IssuerCheckError('The DID document contains duplicate verification-method identifiers.');
    methods.set(id, method);
    return id;
  };
  if (Object.hasOwn(document, 'verificationMethod')) {
    const collection = own(document, 'verificationMethod');
    if (!Array.isArray(collection)) throw new IssuerCheckError('DID verificationMethod must be a collection.');
    for (const method of collection) addMethod(method);
  }
  const topLevelIds = new Set(methods.keys());
  const assertions = own(document, 'assertionMethod');
  if (!Array.isArray(assertions)) throw new IssuerCheckError('The issuer DID document must contain an assertionMethod collection.');
  const authorized = new Set<string>();
  const references: string[] = [];
  for (const assertion of assertions) {
    if (typeof assertion === 'string') references.push(resolveDidUrl(assertion, identity));
    else authorized.add(addMethod(assertion));
  }
  for (const reference of references) {
    if (!topLevelIds.has(reference)) throw new IssuerCheckError('An assertionMethod reference has no top-level verification method in this DID document.');
    authorized.add(reference);
  }
  const method = methods.get(kid);
  if (!authorized.has(kid) || method === undefined) throw new IssuerCheckError('The current issuer DID document does not authorize kid for assertions.');
  return importPublisherKey(method, identity);
}

/** Apply currentness only after authentication, sharing the invocation clock. */
export function checkManifestTime(
  signature: Signature,
  now: number,
  toleranceMs: number,
): 'not_yet_valid' | 'expired' | undefined {
  if (
    !isRfc3339DateTime(signature.issuedAt) ||
    (signature.expiresAt !== undefined &&
      !isRfc3339DateTime(signature.expiresAt))
  )
    throw new TypeError(
      'Signature timestamps must be valid RFC 3339 instants.',
    );
  if (
    signature.expiresAt !== undefined &&
    compareRfc3339DateTimes(signature.expiresAt, signature.issuedAt) <= 0
  )
    throw new TypeError('Signature expiration must follow issuance.');
  if (
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(toleranceMs) ||
    toleranceMs < 0
  )
    throw new TypeError('Clock and tolerance must be integer milliseconds.');
  // Safe-integer tolerances can exceed the Date range. Saturation outside the
  // parser's four-digit year range preserves comparisons without rounding.
  const earliest = Date.parse('0000-01-01T00:00:00Z');
  const latest = Date.parse('9999-12-31T23:59:59.999Z');
  if (
    now + toleranceMs < earliest ||
    (now + toleranceMs <= latest &&
      compareRfc3339DateTimes(
        signature.issuedAt,
        new Date(now + toleranceMs).toISOString(),
      ) > 0)
  )
    return 'not_yet_valid';
  if (
    signature.expiresAt !== undefined &&
    (now - toleranceMs > latest ||
      (now - toleranceMs >= earliest &&
        compareRfc3339DateTimes(
          signature.expiresAt,
          new Date(now - toleranceMs).toISOString(),
        ) <= 0))
  )
    return 'expired';
  return undefined;
}
