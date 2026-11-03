import { Buffer } from 'node:buffer';
import { generateKeyPairSync, sign } from 'node:crypto';
import canonicalize from 'canonicalize';
import { describe, expect, it } from 'vitest';

import {
  validateSignatureDeclarations,
  validateSignedPayload,
} from '../src/internal/signature-declarations.js';
import type { JsonValue } from '../src/types.js';

const signer = 'did:web:assessor.example';
const metadata = {
  signer,
  profile: 'did-web-v1',
  issuedAt: '2026-01-01T00:00:00Z',
};
const manifestTyp = 'ai-catalog-trust-manifest+jws';

function jws(
  header: Record<string, JsonValue>,
  bytes = new Uint8Array(64),
): string {
  return `${Buffer.from(JSON.stringify(header)).toString('base64url')}..${Buffer.from(bytes).toString('base64url')}`;
}

function manifest(
  header: Record<string, JsonValue> = {
    alg: 'ES256',
    typ: manifestTyp,
    kid: `${signer}#key`,
  },
): Record<string, JsonValue> {
  return {
    contributor: signer,
    subject: {
      identifier: 'urn:air:publisher.example:agent:billing',
      type: 'application/json',
      digest: `sha256:${'0'.repeat(64)}`,
    },
    signature: { ...metadata, jws: jws(header) },
  };
}

describe('static signature declarations', () => {
  it('accepts a real detached ES256 signature from an assessor without requiring publisher identity', () => {
    const value = manifest();
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const protectedSegment = Buffer.from(
      JSON.stringify({
        alg: 'ES256',
        typ: manifestTyp,
        kid: `${signer}#key`,
      }),
    ).toString('base64url');
    const payload = Buffer.from(
      canonicalize({ ...value, signature: metadata }) as string,
    ).toString('base64url');
    const signature = sign(
      'sha256',
      Buffer.from(`${protectedSegment}.${payload}`),
      {
        key: keys.privateKey,
        dsaEncoding: 'ieee-p1363',
      },
    );
    value.signature = {
      ...metadata,
      jws: `${protectedSegment}..${signature.toString('base64url')}`,
    };
    expect(validateSignatureDeclarations(value, 'manifest')).toEqual([]);
  });

  it('does not mistake static validation for signature verification', () => {
    expect(validateSignatureDeclarations(manifest(), 'manifest')).toEqual([]);
  });

  it('permits unfamiliar profiles, algorithms, and critical extensions with valid representation', () => {
    const value = manifest();
    value.signature = {
      ...metadata,
      profile: 'https://example.com/profiles/private-v2',
      jws: jws(
        { alg: 'FutureAlg', typ: manifestTyp, crit: ['future'], future: true },
        new Uint8Array([1]),
      ),
    };
    expect(validateSignatureDeclarations(value, 'manifest')).toEqual([]);
  });

  it('requires an absolute URI identifier for independently defined profiles', () => {
    const value = manifest();
    value.signature = {
      ...metadata,
      profile: 'private-v2',
      jws: jws({ alg: 'FutureAlg', typ: manifestTyp }),
    };
    expect(validateSignatureDeclarations(value, 'manifest')).toEqual([
      expect.objectContaining({ path: ['signature', 'profile'] }),
    ]);
  });

  it.each([
    { alg: 'none', typ: manifestTyp },
    { alg: 'ES256', typ: 'ai-catalog+jws' },
    { alg: 'ES256', typ: manifestTyp, b64: true },
    { alg: 'ES256', typ: manifestTyp, crit: ['future'] },
    {
      alg: 'ES256',
      typ: manifestTyp,
      crit: ['future', 'future'],
      future: true,
    },
    { alg: 'ES256', typ: manifestTyp, crit: ['alg'] },
  ] as Record<
    string,
    JsonValue
  >[])('rejects invalid common headers: %j', (header) => {
    expect(
      validateSignatureDeclarations(manifest(header), 'manifest'),
    ).not.toEqual([]);
  });

  it('rejects noncanonical base64url padding bits and invalid protected-header UTF-8', () => {
    const value = manifest();
    const signature = value.signature as Record<string, JsonValue>;
    const encodedHeader = Buffer.from(
      JSON.stringify({ alg: 'ES256', typ: manifestTyp }),
    ).toString('base64url');
    for (const representation of [
      `${encodedHeader}..Zh`,
      '_w..AA',
      `${encodedHeader}.payload.AA`,
    ]) {
      signature.jws = representation;
      expect(validateSignatureDeclarations(value, 'manifest')).toEqual([
        expect.objectContaining({ path: ['signature', 'jws'] }),
      ]);
    }
  });

  it('enforces the declared known profile without authenticating any key', () => {
    for (const header of [
      { alg: 'ES384', typ: manifestTyp, kid: `${signer}#key` },
      { alg: 'ES256', typ: manifestTyp, kid: 'did:web:other.example#key' },
      { alg: 'ES256', typ: manifestTyp, kid: `${signer}#key`, jwk: {} },
    ])
      expect(
        validateSignatureDeclarations(manifest(header), 'manifest'),
      ).not.toEqual([]);
  });

  it.each([
    'did:web:127.0.0.1',
    'did:web:0x7f000001',
    'did:web:1234',
    'did:web:Example.com',
    'did:web:example.com.',
    'did:web:example.com:path',
    'did:web:xn--a',
    'did:web:xn--a.example',
    'did:web:xn--g6h.example',
    'did:web:xn--e28h.example',
    'did:web:xn--u-ccb.example',
    'did:web:xn--u-bcb.example',
    'did:web:xn--ab-j1t.example',
    'did:web:xn--ab-0ea.example',
    'did:web:xn--a-0hc.example',
    'did:web:xn--0.example',
  ])('rejects signer syntax outside the known profile: %s', (identity) => {
    const value = manifest();
    value.signature = {
      ...metadata,
      signer: identity,
      jws: jws({ alg: 'ES256', typ: manifestTyp, kid: `${identity}#key` }),
    };
    expect(validateSignatureDeclarations(value, 'manifest')).toContainEqual(
      expect.objectContaining({ path: ['signature', 'signer'] }),
    );
  });

  it('accepts an internationalized root DID serialized as an ASCII A-label', () => {
    const identity = 'did:web:xn--bcher-kva.example';
    const value = manifest();
    value.contributor = identity;
    value.signature = {
      ...metadata,
      signer: identity,
      jws: jws({ alg: 'ES256', typ: manifestTyp, kid: `${identity}#key` }),
    };
    expect(validateSignatureDeclarations(value, 'manifest')).toEqual([]);
  });

  it('checks the containing object-specific typ', () => {
    const value: Record<string, JsonValue> = {
      specVersion: '1.0',
      entries: [],
      signature: {
        ...metadata,
        jws: jws({ alg: 'ES256', typ: 'ai-catalog+jws', kid: `${signer}#key` }),
      },
    };
    expect(validateSignatureDeclarations(value, 'catalog')).toEqual([]);
    expect(validateSignatureDeclarations(value, 'manifest')).not.toEqual([]);
  });
});

describe('exact signed payload eligibility', () => {
  it('omits only immediate additionalSignatures and immediate signature.jws', () => {
    const value = manifest();
    value.additionalSignatures = '\ud800';
    (value.signature as Record<string, JsonValue>).jws = '\ud800';
    expect(validateSignedPayload(value)).toBeUndefined();
    value.extensions = { additionalSignatures: '\ud800' };
    expect(validateSignedPayload(value)).toMatchObject({
      path: ['extensions', 'additionalSignatures'],
    });
  });

  it('covers nested manifest signatures in a signed catalog', () => {
    const nested = manifest();
    (nested.signature as Record<string, JsonValue>).jws = '\ud800';
    expect(validateSignedPayload(nested)).toBeUndefined();
    const catalog: Record<string, JsonValue> = {
      specVersion: '1.0',
      entries: [{ trustManifests: [nested] }],
      signature: { ...metadata, jws: '' },
    };
    expect(validateSignedPayload(catalog)).toMatchObject({
      path: ['entries', 0, 'trustManifests', 0, 'signature', 'jws'],
    });
  });

  it('preserves unknown payload members and reports their invalid Unicode', () => {
    const value = manifest();
    value.future = { note: '\ud800' };
    expect(validateSignedPayload(value)).toMatchObject({
      path: ['future', 'note'],
    });
  });

  it('does not impose signing restrictions on unsigned JSON', () => {
    expect(
      validateSignatureDeclarations(
        { extensions: { note: '\ud800' } },
        'catalog',
      ),
    ).toEqual([]);
    expect(
      validateSignedPayload({ extensions: { note: '\ud800' } }),
    ).toBeUndefined();
  });
});
