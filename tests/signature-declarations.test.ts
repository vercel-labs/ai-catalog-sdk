import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';

import {
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
      validateSignedPayload({ extensions: { note: '\ud800' } }),
    ).toBeUndefined();
  });
});
