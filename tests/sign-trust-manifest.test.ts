import { Buffer } from 'node:buffer';
import { generateKeyPairSync, sign } from 'node:crypto';
import { CompactSign, FlattenedSign } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import type { CatalogEntry, JsonValue } from '../src/index.js';
import {
  signTrustManifest,
  type JwsSigningResult,
  type TrustManifestSigner,
} from '../src/internal/signing.js';
import {
  checkTrustManifestSignature,
  createTrustManifestSignaturePayload,
} from '../src/verification.js';

const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const body = () => ({
  contributor: 'did:web:auditor.example',
  subject: {
    identifier: 'urn:air:publisher.example:agent:example',
    type: 'application/json',
    digest: `sha256:${'0'.repeat(64)}`,
  },
});
const metadata = () => ({
  profile: 'did-web-v1',
  issuedAt: '2026-10-30T00:00:00Z',
});

function nodeJws(payload: Uint8Array, header: Record<string, JsonValue>): string {
  const protectedSegment = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadSegment = Buffer.from(payload).toString('base64url');
  const signatureSegment = sign('sha256', Buffer.from(`${protectedSegment}.${payloadSegment}`), {
    key: keys.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  return `${protectedSegment}.${payloadSegment}.${signatureSegment}`;
}

const compactSigner: TrustManifestSigner = ({ payload, typ }) =>
  new CompactSign(payload).setProtectedHeader({ alg: 'ES256', typ }).sign(keys.privateKey);

describe('signTrustManifest', () => {
  it.each(['compact', 'detached', 'flattened'] as const)('accepts native %s JWS and returns a verifiable detached manifest', async (format) => {
    const result = await signTrustManifest(body(), metadata(), async ({ payload, typ }) => {
      if (format === 'flattened') {
        return new FlattenedSign(payload).setProtectedHeader({ alg: 'ES256', typ }).sign(keys.privateKey);
      }
      const compact = await new CompactSign(payload).setProtectedHeader({ alg: 'ES256', typ }).sign(keys.privateKey);
      return format === 'compact' ? compact : compact.replace(/\.[^.]+\./, '..');
    });
    expect(result.signature.signer).toBe(body().contributor);
    expect(result.signature.jws.split('.')[1]).toBe('');
    expect(await checkTrustManifestSignature(result, {
      publicKey: keys.publicKey,
      expectedAlgorithm: 'ES256',
    })).toEqual({ status: 'valid' });
  });

  it('supports synchronous signing callbacks', async () => {
    const result = await signTrustManifest(body(), metadata(), ({ payload, typ }) =>
      nodeJws(payload, { alg: 'ES256', typ }));
    expect(result.signature.jws).toContain('..');
  });

  it('derives only the defined subject fields and preserves an empty version', async () => {
    const manifest = body();
    const entry = {
      ...manifest.subject,
      version: '',
      url: 'https://mirror.example/artifact',
      extensions: { 'example.com': { hidden: true } },
    };
    const before = structuredClone(entry);
    const signed = await signTrustManifest(entry, { contributor: manifest.contributor }, metadata(), compactSigner);
    expect(signed.subject).toEqual({ ...manifest.subject, version: '' });
    expect(entry).toEqual(before);
    expect(signed.contributor).toBe('did:web:auditor.example');
  });

  it('does not traverse unrelated artifact data to project the subject', async () => {
    const entry = { ...body().subject, data: null };
    Object.defineProperty(entry, 'data', { get() { throw new Error('must not read data'); } });
    const signed = await signTrustManifest(entry, { contributor: body().contributor }, metadata(), compactSigner);
    expect(signed.subject).toEqual(body().subject);
  });

  it('requires a declared entry digest before calling the signer', async () => {
    const signer = vi.fn(compactSigner);
    await expect(signTrustManifest({ identifier: 'x', type: 'application/json', data: {} }, {
      contributor: body().contributor,
    }, metadata(), signer)).rejects.toThrow(TypeError);
    expect(signer).not.toHaveBeenCalled();
  });

  it('captures manifest content and metadata before asynchronous signing', async () => {
    const manifest = { ...body(), extensions: { 'example.com': { value: 1 } }, unknown: { signature: { jws: 'covered' } } };
    const signatureMetadata = metadata();
    let callbackPayload: Uint8Array | undefined;
    const signed = await signTrustManifest(manifest, signatureMetadata, async ({ payload, typ }) => {
      callbackPayload = payload;
      manifest.extensions['example.com'].value = 2;
      manifest.unknown.signature.jws = 'changed';
      signatureMetadata.issuedAt = '2030-01-01T00:00:00Z';
      const compact = await new CompactSign(payload).setProtectedHeader({ alg: 'ES256', typ }).sign(keys.privateKey);
      payload.fill(0);
      return compact;
    });
    expect(callbackPayload?.every((byte) => byte === 0)).toBe(true);
    expect((signed.extensions?.['example.com'] as { value: number }).value).toBe(1);
    expect((signed as unknown as { unknown: unknown }).unknown).toEqual({ signature: { jws: 'covered' } });
    expect(signed.signature.issuedAt).toBe('2026-10-30T00:00:00Z');
    expect(await checkTrustManifestSignature(signed, { publicKey: keys.publicKey, expectedAlgorithm: 'ES256' })).toEqual({ status: 'valid' });
  });

  it('rejects a payload changed by the callback before signing', async () => {
    await expect(signTrustManifest(body(), metadata(), ({ payload, typ }) => {
      payload.fill(0);
      return nodeJws(payload, { alg: 'ES256', typ });
    })).rejects.toThrow(/payload must match/);
  });

  it('leaves cryptographic agreement to verification for already-detached output', async () => {
    const signed = await signTrustManifest(body(), metadata(), ({ typ }) =>
      nodeJws(new Uint8Array([1]), { alg: 'ES256', typ }).replace(/\.[^.]+\./, '..'));
    expect(await checkTrustManifestSignature(signed, { publicKey: keys.publicKey, expectedAlgorithm: 'ES256' })).toEqual({ status: 'invalid_signature' });
  });

  it.each([
    { alg: 'none', typ: 'ai-catalog-trust-manifest+jws' },
    { alg: '', typ: 'ai-catalog-trust-manifest+jws' },
    { alg: 'ES256' },
    { alg: 'ES256', typ: 'wrong' },
    { alg: 'ES256', typ: 'ai-catalog-trust-manifest+jws', b64: true },
    { alg: 'ES256', typ: 'ai-catalog-trust-manifest+jws', b64: false },
    { alg: 'ES256', typ: 'ai-catalog-trust-manifest+jws', crit: [] },
    { alg: 'ES256', typ: 'ai-catalog-trust-manifest+jws', crit: ['typ'] },
    { alg: 'ES256', typ: 'ai-catalog-trust-manifest+jws', crit: ['absent'] },
  ] as Record<string, JsonValue>[])('rejects invalid or forbidden protected metadata: %j', async (header) => {
    await expect(signTrustManifest(body(), metadata(), ({ payload }) => nodeJws(payload, header))).rejects.toThrow(TypeError);
  });

  it('requires encoded protected fields even when similarly named properties are inherited', async () => {
    Object.defineProperty(Object.prototype, 'alg', { value: 'ES256', configurable: true });
    Object.defineProperty(Object.prototype, 'typ', { value: 'ai-catalog-trust-manifest+jws', configurable: true });
    try {
      await expect(signTrustManifest(body(), metadata(), ({ payload }) => ({
        protected: 'e30',
        payload: Buffer.from(payload).toString('base64url'),
        signature: 'AA',
      }))).rejects.toThrow(TypeError);
    } finally {
      Reflect.deleteProperty(Object.prototype, 'alg');
      Reflect.deleteProperty(Object.prototype, 'typ');
    }
  });

  it('does not restrict authoring to the verification helper algorithm', async () => {
    const signed = await signTrustManifest(body(), { ...metadata(), profile: 'custom' }, ({ payload, typ }) => {
      const compact = nodeJws(payload, { alg: 'custom-algorithm', typ });
      return compact;
    });
    expect(signed.signature.profile).toBe('custom');
  });

  it('rejects flattened unprotected headers and mismatched payloads', async () => {
    for (const malformed of [
      { protected: Buffer.from('{"alg":"ES256","typ":"ai-catalog-trust-manifest+jws"}').toString('base64url'), payload: 'AA', signature: 'AA' },
      { protected: 'e30', payload: 'AA', signature: 'AA', header: {} },
      { payload: 'AA', signature: 'AA' },
    ]) {
      await expect(signTrustManifest(body(), metadata(), () => malformed)).rejects.toThrow(TypeError);
    }
  });

  it.each(['a.b.c.d', 'e30..AA=', 'e31..AA', '.e30.AA', 'e30..', `${Buffer.from('{').toString('base64url')}..AA`])('rejects malformed callback JWS %s', async (jws) => {
    await expect(signTrustManifest(body(), metadata(), () => jws)).rejects.toThrow(TypeError);
  });

  it('does not invoke the signer with invalid, already-signed, or hostile authoring inputs', async () => {
    const signer = vi.fn(compactSigner);
    const invalidBodies = [
      { ...body(), signature: { ...metadata(), signer: body().contributor, jws: '' } },
      { contributor: body().contributor },
      { ...body(), contributor: 'not an absolute URI' },
      Object.defineProperty(body(), 'contributor', { get() { throw new Error('getter invoked'); } }),
      new Proxy(body(), {}),
    ];
    for (const invalid of invalidBodies) {
      await expect(signTrustManifest(invalid as ReturnType<typeof body>, metadata(), signer)).rejects.toThrow(TypeError);
    }
    await expect(signTrustManifest(body(), { ...metadata(), signer: 'other' } as ReturnType<typeof metadata>, signer)).rejects.toThrow(TypeError);
    await expect(signTrustManifest(body(), { ...metadata(), expiresAt: '2026-10-29T00:00:00Z' }, signer)).rejects.toThrow(TypeError);
    expect(signer).not.toHaveBeenCalled();
  });

  it('rejects an entry overload body with its own subject', async () => {
    const entry = { ...body().subject, data: null };
    await expect(signTrustManifest(entry, body() as never, metadata(), compactSigner)).rejects.toThrow(/subject must be absent/);
  });

  it('preserves callback errors', async () => {
    const failure = new Error('signing service unavailable');
    await expect(signTrustManifest(body(), metadata(), () => { throw failure; })).rejects.toBe(failure);
  });

  it('accepts non-I-JSON Unicode only in the omitted additionalSignatures value', async () => {
    const signed = await signTrustManifest({
      ...body(),
      additionalSignatures: { arbitrary: '\ud800' },
    }, metadata(), compactSigner);
    expect((signed.additionalSignatures as { arbitrary: string }).arbitrary).toBe('\ud800');
    expect(await checkTrustManifestSignature(signed, {
      publicKey: keys.publicKey,
      expectedAlgorithm: 'ES256',
    })).toEqual({ status: 'valid' });

    const signer = vi.fn(compactSigner);
    for (const manifest of [
      { ...body(), unknown: '\ud800' },
      { ...body(), extensions: { 'example.com': { additionalSignatures: '\ud800' } } },
    ]) {
      await expect(signTrustManifest(manifest, metadata(), signer)).rejects.toThrow(TypeError);
    }
    expect(signer).not.toHaveBeenCalled();
  });

  it('excludes only top-level additional signatures from its signing payload', async () => {
    const manifest = { ...body(), additionalSignatures: { arbitrary: true }, extensions: { 'example.com': { additionalSignatures: 'covered' } } };
    const signed = await signTrustManifest(manifest, metadata(), compactSigner);
    const payload = JSON.parse(new TextDecoder().decode(createTrustManifestSignaturePayload(signed)));
    expect(payload.additionalSignatures).toBeUndefined();
    expect(payload.extensions['example.com'].additionalSignatures).toBe('covered');
    expect(payload.signature.jws).toBeUndefined();
    expect(payload.signature.signer).toBe(manifest.contributor);
  });
});

// Public callbacks accept native jose serialization types without adapters.
const nativeFlattenedSigner: TrustManifestSigner = ({ payload, typ }) =>
  new FlattenedSign(payload).setProtectedHeader({ alg: 'ES256', typ }).sign(keys.privateKey);
void nativeFlattenedSigner;
const standardResult: JwsSigningResult = { payload: 'AA', signature: 'AA' };
void standardResult;
const inlineEntry: CatalogEntry = { ...body().subject, data: {} };
void inlineEntry;
