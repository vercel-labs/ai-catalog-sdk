import { Buffer } from 'node:buffer';
import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  authorizePublisherKey,
  inspectSignerProfile,
  publisherIdentityFor,
  checkManifestTime,
  IssuerCheckError,
} from '../src/internal/publisher-profile.js';
import type { TrustManifest } from '../src/types.js';

const identity = 'did:web:example.com';
const kid = `${identity}#release-key`;
const identifier = 'urn:air:example.com:finance:agent:billing';
const publicKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
}).publicKey;
const publicJwk = publicKey.export({ format: 'jwk' });

function manifest(overrides: Partial<TrustManifest> = {}): TrustManifest {
  return {
    contributor: identity,
    signature: {
      signer: identity,
      profile: 'did-web-v1',
      issuedAt: '2026-01-01T00:00:00Z',
      jws: 'test',
    },
    subject: {
      identifier,
      type: 'text/plain',
      digest: `sha256:${'0'.repeat(64)}`,
    },
    ...overrides,
  };
}

function method(overrides: Record<string, unknown> = {}) {
  return {
    id: kid,
    type: 'JsonWebKey2020',
    controller: identity,
    publicKeyJwk: { ...publicJwk },
    ...overrides,
  };
}

function document(overrides: Record<string, unknown> = {}) {
  return {
    id: identity,
    verificationMethod: [method()],
    assertionMethod: [kid],
    ...overrides,
  };
}

describe('Signer and Publisher Profile requirements', () => {
  it('derives the publisher independently from signer authentication', () => {
    expect(publisherIdentityFor(identifier)).toBe(identity);
    expect(inspectSignerProfile(manifest(), { alg: 'ES256', kid })).toEqual({
      identity,
      kid,
    });
    const assessor = 'did:web:assessor.example';
    const independent = manifest({
      contributor: assessor,
      signature: {
        signer: assessor,
        profile: 'did-web-v1',
        issuedAt: '2026-01-01T00:00:00Z',
        jws: '',
      },
    });
    expect(
      inspectSignerProfile(independent, { kid: `${assessor}#key` }),
    ).toEqual({ identity: assessor, kid: `${assessor}#key` });
  });

  it.each([
    'https://example.com/agent/billing',
    'URN:air:example.com:agent:billing',
    'urn:air:example.com:billing',
    'urn:air:example.com:agent:',
    'urn:air:example.com::billing',
    'urn:air:example.com:agent:bill ing',
    'urn:air:example.com:agent:billing#key',
    'urn:air:example.com:agent:billing?query',
    'urn:air:example.com:agent:billing%zz',
  ])('cannot derive a standard publisher from %s', (value) => {
    expect(publisherIdentityFor(value)).toBeUndefined();
  });

  it.each([
    'Example.com',
    'example.com.',
    'example..com',
    '-example.com',
    'example-.com',
    'example_com',
    'bücher.example',
    '127.0.0.1',
    '127.1',
    '2130706433',
    '0x7f000001',
    'example.com%3A443',
    '[::1]',
    'xn--.example',
    `${'a'.repeat(64)}.com`,
  ])('rejects excluded domain %s', (domain) => {
    expect(
      publisherIdentityFor(`urn:air:${domain}:agent:billing`),
    ).toBeUndefined();
    expect(
      inspectSignerProfile(manifest({ contributor: `did:web:${domain}` }), {
        kid: `did:web:${domain}#key`,
      }),
    ).toBeInstanceOf(Error);
  });

  it('accepts IDNA A-labels without normalizing the signed identity', () => {
    const value = 'did:web:xn--bcher-kva.example';
    expect(
      publisherIdentityFor('urn:air:xn--bcher-kva.example:agent:billing'),
    ).toBe(value);
    expect(
      inspectSignerProfile(
        manifest({
          contributor: value,
          signature: {
            signer: value,
            profile: 'did-web-v1',
            issuedAt: '2026-01-01T00:00:00Z',
            jws: '',
          },
        }),
        { kid: `${value}#key` },
      ),
    ).toEqual({ identity: value, kid: `${value}#key` });
  });

  it.each([
    'b64',
    'jwk',
    'jku',
    'x5u',
    'x5c',
  ])('rejects protected %s regardless of value', (parameter) => {
    expect(
      inspectSignerProfile(manifest(), { kid, [parameter]: null }),
    ).toBeInstanceOf(Error);
  });

  it.each([
    undefined,
    4,
    '#release-key',
    `${identity}#`,
    `${identity}/#key`,
    `${identity}?version=1#key`,
    `${identity}#key#extra`,
    `${identity}#key space`,
    `${identity}#bad%xx`,
    'did:web:attacker.com#key',
  ])('requires an exact absolute DID kid: %s', (value) => {
    expect(inspectSignerProfile(manifest(), { kid: value })).toBeInstanceOf(
      Error,
    );
  });
});

describe('DID assertion-key authorization', () => {
  it('imports real assertion-authorized P-256 keys from absolute or relative references', () => {
    for (const reference of [kid, '#release-key']) {
      const result = authorizePublisherKey(
        document({ assertionMethod: [reference] }),
        identity,
        kid,
      );
      expect(result.export({ format: 'jwk' })).toEqual(publicJwk);
    }
    expect(
      authorizePublisherKey(
        document({
          verificationMethod: [method({ id: '#release-key' })],
          assertionMethod: ['#release-key'],
        }),
        identity,
        kid,
      ).export({ format: 'jwk' }),
    ).toEqual(publicJwk);
  });

  it('supports directly embedded assertion methods and ignores a conflicting JWK kid', () => {
    const result = authorizePublisherKey(
      {
        id: identity,
        assertionMethod: [
          method({
            id: '#release-key',
            publicKeyJwk: {
              ...publicJwk,
              kid: 'attacker-key',
              alg: 'ES256',
              use: 'sig',
              key_ops: ['verify'],
            },
          }),
        ],
      },
      identity,
      kid,
    );
    expect(result.export({ format: 'jwk' })).toEqual(publicJwk);
  });

  it('accepts DID Core JSON-LD context forms and rejects invalid core contexts', () => {
    for (const context of [
      'https://www.w3.org/ns/did/v1',
      [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
    ]) {
      expect(
        authorizePublisherKey(
          document({ '@context': context }),
          identity,
          kid,
        ).export({ format: 'jwk' }),
      ).toEqual(publicJwk);
    }
    for (const context of [
      null,
      42,
      [],
      'https://example.com/context',
      ['https://example.com/context', 'https://www.w3.org/ns/did/v1'],
    ]) {
      expect(() =>
        authorizePublisherKey(document({ '@context': context }), identity, kid),
      ).toThrow(IssuerCheckError);
    }
  });

  it('never authorizes authentication-only, removed, or foreign-controlled keys', () => {
    expect(() =>
      authorizePublisherKey(
        document({ assertionMethod: [], authentication: [kid] }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
    expect(() =>
      authorizePublisherKey(
        document({ verificationMethod: [] }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
    expect(() =>
      authorizePublisherKey(
        document({
          verificationMethod: [method({ controller: 'did:web:attacker.com' })],
        }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
  });

  it('rejects duplicate definitions while a repeated reference still identifies one method', () => {
    expect(() =>
      authorizePublisherKey(
        document({
          verificationMethod: [method(), method({ id: '#release-key' })],
        }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
    expect(() =>
      authorizePublisherKey(
        document({ assertionMethod: [method()] }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
    expect(
      authorizePublisherKey(
        document({ assertionMethod: [kid, '#release-key'] }),
        identity,
        kid,
      ).export({ format: 'jwk' }),
    ).toEqual(publicJwk);
  });

  it('requires assertion references to target the top-level method collection', () => {
    expect(() =>
      authorizePublisherKey(
        { id: identity, assertionMethod: [method(), '#release-key'] },
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
  });

  it.each([
    null,
    [],
    { id: 'did:web:attacker.com', assertionMethod: [method()] },
    document({ assertionMethod: 'key' }),
    document({ verificationMethod: {} }),
    document({ verificationMethod: [method({ type: undefined })] }),
    document({ verificationMethod: [method({ controller: '#controller' })] }),
    document({ verificationMethod: [method({ id: `${identity}#key#other` })] }),
    document({ assertionMethod: ['https://example.com/key'] }),
    document({ assertionMethod: ['#missing'] }),
  ])('rejects malformed DID or authorization structure %#', (value) => {
    expect(() => authorizePublisherKey(value, identity, kid)).toThrow(
      IssuerCheckError,
    );
  });

  it.each([
    { kty: 'RSA' },
    { crv: 'P-384' },
    { x: 'bad' },
    { y: `${publicJwk.y}=` },
    {
      x: Buffer.alloc(32).toString('base64url'),
      y: Buffer.alloc(32).toString('base64url'),
    },
    { x: Buffer.alloc(32, 255).toString('base64url') },
    { alg: 'ES384' },
    { use: 'enc' },
    { key_ops: ['sign'] },
    { key_ops: 'verify' },
    { key_ops: ['verify', 1] },
    { key_ops: ['verify', 'verify'] },
    { kid: 123 },
    { d: undefined },
    { p: 'private' },
    { k: 'private' },
  ])('rejects unsuitable JWK material or metadata %#', (overrides) => {
    expect(() =>
      authorizePublisherKey(
        document({
          verificationMethod: [
            method({ publicKeyJwk: { ...publicJwk, ...overrides } }),
          ],
        }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
  });

  it('rejects a method that describes its key in multiple representations', () => {
    expect(() =>
      authorizePublisherKey(
        document({
          verificationMethod: [method({ publicKeyMultibase: 'zabc' })],
        }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
  });

  it('does not equate encoded fragments with unencoded kid values', () => {
    expect(() =>
      authorizePublisherKey(
        document({
          verificationMethod: [method({ id: '#release%2Dkey' })],
          assertionMethod: ['#release%2Dkey'],
        }),
        identity,
        kid,
      ),
    ).toThrow(IssuerCheckError);
  });
});

describe('RFC 3339 expiration comparison', () => {
  const boundary = Date.UTC(2026, 0, 1);
  function isManifestExpired(expiresAt: string, now: number): boolean {
    return (
      checkManifestTime(
        {
          signer: identity,
          profile: 'did-web-v1',
          issuedAt: '0000-01-01T00:00:00Z',
          expiresAt,
          jws: '',
        },
        now,
        0,
      ) === 'expired'
    );
  }

  it('rejects exactly at expiration and after it', () => {
    expect(isManifestExpired('2026-01-01T00:00:00Z', boundary - 1)).toBe(false);
    expect(isManifestExpired('2026-01-01T00:00:00Z', boundary)).toBe(true);
    expect(isManifestExpired('2026-01-01T00:00:00Z', boundary + 1)).toBe(true);
  });

  it('retains arbitrary decimal precision rather than rounding/truncating milliseconds', () => {
    expect(isManifestExpired('2026-01-01T00:00:00.0001Z', boundary)).toBe(
      false,
    );
    expect(isManifestExpired('2026-01-01T00:00:00.0001Z', boundary + 1)).toBe(
      true,
    );
    expect(
      isManifestExpired(
        '2026-01-01T00:00:00.0010000000000000000001Z',
        boundary + 1,
      ),
    ).toBe(false);
    expect(
      isManifestExpired(
        '2026-01-01T00:00:00.0009999999999999999999Z',
        boundary + 1,
      ),
    ).toBe(true);
    expect(isManifestExpired('2026-01-01T00:00:00.001000Z', boundary + 1)).toBe(
      true,
    );
  });

  it.each([
    '2026-01-01T01:00:00+01:00',
    '2025-12-31T23:00:00-01:00',
    '2026-01-01t00:00:00z',
    '2026-01-01T00:00:00-00:00',
  ])('normalizes accepted offsets and casing for %s', (value) => {
    expect(isManifestExpired(value, boundary)).toBe(true);
    expect(isManifestExpired(value, boundary + 1)).toBe(true);
  });

  it('orders leap seconds after :59 and before the next UTC midnight', () => {
    const next = Date.UTC(2017, 0, 1);
    for (const value of [
      '2016-12-31T23:59:60Z',
      '2016-12-31T23:59:60.999999Z',
      '2017-01-01T00:59:60+01:00',
    ]) {
      expect(isManifestExpired(value, next - 1)).toBe(false);
      expect(isManifestExpired(value, next)).toBe(true);
    }
  });

  it('compares the parser-supported year range and instants before the Unix epoch', () => {
    expect(isManifestExpired('0000-01-01T00:00:00.0001Z', 0)).toBe(true);
    expect(isManifestExpired('9999-12-31T23:59:59.999999Z', boundary)).toBe(
      false,
    );
    expect(isManifestExpired('1969-12-31T23:59:59.9991Z', -1)).toBe(false);
    expect(isManifestExpired('1969-12-31T23:59:59.9989Z', -1)).toBe(true);
    expect(
      isManifestExpired(
        '0099-01-01T00:00:00Z',
        Date.parse('0099-01-01T00:00:00Z'),
      ),
    ).toBe(true);
  });

  it('rejects invalid calendar dates, unsupported leap seconds, and invalid runtime time values', () => {
    for (const value of [
      '2026-02-29T00:00:00Z',
      '2026-01-01T23:59:60Z',
      'no date',
    ])
      expect(() => isManifestExpired(value, boundary)).toThrow(TypeError);
    for (const now of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      0.5,
      Number.MAX_VALUE,
    ])
      expect(() => isManifestExpired('2026-01-01T00:00:00Z', now)).toThrow(
        TypeError,
      );
  });
});
