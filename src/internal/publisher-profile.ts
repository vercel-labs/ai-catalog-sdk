import { Buffer } from 'node:buffer';
import { createPublicKey, type KeyObject } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

import type { TrustManifest } from '../types.js';
import { isRfc3339DateTime, RFC3339_PATTERN_SOURCE } from './rfc3339.js';

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
const didPattern = new RegExp(`^did:[a-z0-9]+:(?:${didCharacter}|:)*${didCharacter}$`);
const uriReferencePattern = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?#-]|%[0-9A-Fa-f]{2})*$/;
const rfc3339Pattern = new RegExp(RFC3339_PATTERN_SOURCE);

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
  ) return false;

  if (!domain.split('.').every((label) =>
    label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  )) return false;

  // WHATWG also recognizes shortened, hexadecimal, and integer IPv4 forms.
  try {
    return isIP(new URL(`https://${domain}/`).hostname) === 0;
  } catch {
    return false;
  }
}

/** Receives the invocation's already-captured, plain JSON manifest and header. */
export function inspectPublisherProfile(
  identifier: string,
  manifest: TrustManifest,
  header: Record<string, unknown>,
): { identity: string; kid: string } | Error {
  if (typeof identifier !== 'string' || !isRecord(manifest) || !isRecord(header)) {
    throw new TypeError('Publisher Profile inputs must contain an identifier and JSON objects.');
  }
  const identity = own(manifest, 'identity');
  if (typeof identity !== 'string') throw new TypeError('Trust Manifest identity must be a string.');
  const components = identifier.split(':');
  const publisher = components[2];
  if (
    !identifier.startsWith('urn:air:') ||
    components.length < 5 ||
    publisher === undefined ||
    !validPublisherDomain(publisher) ||
    !components.slice(3).every((component) => airTail.test(component))
  ) return new Error('Publisher verification requires a standard urn:air identifier and a lowercase domain publisher.');
  if (identity !== `did:web:${publisher}`) {
    return new Error('Trust Manifest identity must exactly equal the root did:web publisher identity.');
  }
  if (Object.hasOwn(manifest, 'identityType')) {
    const identityType = own(manifest, 'identityType');
    if (typeof identityType !== 'string') throw new TypeError('Trust Manifest identityType must be a string.');
    if (identityType !== 'did') return new Error('Publisher Profile identityType must be did.');
  }
  const issuedAt = own(manifest, 'issuedAt');
  if (!Object.hasOwn(manifest, 'issuedAt')) return new Error('A signed Trust Manifest requires issuedAt.');
  if (typeof issuedAt !== 'string') throw new TypeError('Trust Manifest issuedAt must be a string.');
  if (!isRfc3339DateTime(issuedAt)) return new Error('Trust Manifest issuedAt must be a valid RFC 3339 timestamp.');
  if (Object.hasOwn(manifest, 'expiresAt')) {
    const expiresAt = own(manifest, 'expiresAt');
    if (typeof expiresAt !== 'string') throw new TypeError('Trust Manifest expiresAt must be a string.');
    if (!isRfc3339DateTime(expiresAt)) return new Error('Trust Manifest expiresAt must be a valid RFC 3339 timestamp.');
  }
  for (const parameter of ['b64', 'jku', 'jwk', 'x5u', 'x5c']) {
    if (Object.hasOwn(header, parameter)) return new Error(`The Publisher Profile forbids protected ${parameter}.`);
  }
  const kid = own(header, 'kid');
  if (typeof kid !== 'string' || !kid.startsWith(`${identity}#`) || !fragmentPattern.test(kid.slice(identity.length + 1))) {
    return new Error('The protected kid must be the exact issuer DID followed by a non-empty URI fragment.');
  }
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

/** Compare accepted RFC 3339 instants without discarding sub-millisecond digits. */
export function isManifestExpired(expiresAt: string, now: number): boolean {
  if (typeof expiresAt !== 'string' || !isRfc3339DateTime(expiresAt)) throw new TypeError('expiresAt must be a valid RFC 3339 timestamp.');
  if (!Number.isFinite(now) || !Number.isInteger(now) || Number.isNaN(new Date(now).getTime())) throw new TypeError('The current time must be a valid integer millisecond timestamp.');
  const match = rfc3339Pattern.exec(expiresAt);
  if (match === null) throw new TypeError('expiresAt must be a valid RFC 3339 timestamp.');
  const offset = (match[8] === '-' ? -1 : 1) * (Number(match[9] ?? 0) * 60 + Number(match[10] ?? 0));
  const second = Number(match[6]);
  const instant = new Date(0);
  instant.setUTCFullYear(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  instant.setUTCHours(Number(match[4]), Number(match[5]) - offset, Math.min(second, 59), 0);
  const seconds = instant.getTime() / 1000;
  const nowSeconds = Math.floor(now / 1000);
  // UTC's leap second lies after :59 and before the following :00. JavaScript's
  // wall clock cannot express that second, but it can order the adjacent times.
  if (second === 60) return nowSeconds > seconds;
  if (seconds !== nowSeconds) return seconds < nowSeconds;
  const fraction = match[7] ?? '';
  const nowFraction = String(now - nowSeconds * 1000).padStart(3, '0');
  const width = Math.max(3, fraction.length);
  return fraction.padEnd(width, '0') < nowFraction.padEnd(width, '0');
}
