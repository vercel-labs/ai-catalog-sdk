import { Buffer } from 'node:buffer';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CatalogEntryWithData,
  CatalogEntryWithUrl,
  TrustManifest,
} from '../src/index.js';
import { IssuerCheckError } from '../src/internal/publisher-profile.js';
import { resolveDidWeb } from '../src/internal/did-web.js';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntryTrustManifest,
  createTrustManifestSignaturePayload,
} from '../src/verification.js';

vi.mock('../src/internal/did-web.js', () => ({ resolveDidWeb: vi.fn() }));

const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const identity = 'did:web:example.com';
const kid = `${identity}#release`;
const identifier = 'urn:air:example.com:agent:billing';
const type = 'application/json';
const artifact = new Uint8Array([1, 2, 3]);
const resolver = vi.mocked(resolveDidWeb);

function documentFor() {
  return {
    id: identity,
    verificationMethod: [
      {
        id: kid,
        controller: identity,
        type: 'JsonWebKey2020',
        publicKeyJwk: keys.publicKey.export({ format: 'jwk' }),
      },
    ],
    assertionMethod: [kid],
  };
}

function signManifest(
  manifest: TrustManifest,
  header: Record<string, unknown> = { alg: 'ES256', kid },
) {
  const protectedSegment = Buffer.from(JSON.stringify(header)).toString(
    'base64url',
  );
  const payload = Buffer.from(
    createTrustManifestSignaturePayload(manifest),
  ).toString('base64url');
  const signature = sign(
    'sha256',
    Buffer.from(`${protectedSegment}.${payload}`),
    { key: keys.privateKey, dsaEncoding: 'ieee-p1363' },
  ).toString('base64url');
  return { ...manifest, signature: `${protectedSegment}..${signature}` };
}

function entryFor(
  bytes = artifact,
  fields: Partial<TrustManifest> = {},
  header?: Record<string, unknown>,
): CatalogEntryWithUrl {
  return {
    identifier,
    type,
    url: 'https://cdn.example.com/billing.json',
    trustManifest: signManifest(
      {
        identity,
        issuedAt: '2026-01-01T00:00:00Z',
        subject: {
          identifier,
          type,
          digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
        },
        ...fields,
      },
      header,
    ),
  };
}

beforeEach(() => {
  resolver.mockReset();
  resolver.mockResolvedValue(documentFor());
});

describe('checkCatalogEntryTrustManifest', () => {
  it('authorizes the current DID key and verifies caller-owned URL bytes', async () => {
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), artifact),
    ).resolves.toEqual({ status: 'valid' });
    expect(resolver).toHaveBeenCalledWith(identity, {
      timeoutMs: 60_000,
      maxResponseBytes: 16 * 1024 * 1024,
    });
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it('canonicalizes inline data and needs no caller key or byte argument', async () => {
    const data = { z: 1, a: [true, null] };
    const urlEntry = entryFor(canonicalizeJsonValueToBytes(data));
    const entry: CatalogEntryWithData = {
      identifier,
      type,
      data,
      trustManifest: urlEntry.trustManifest as TrustManifest,
    };
    await expect(checkCatalogEntryTrustManifest(entry)).resolves.toEqual({
      status: 'valid',
    });
  });

  it('preserves existing missing-manifest, signature, and subject diagnostics without I/O', async () => {
    const missing = entryFor();
    delete missing.trustManifest;
    await expect(
      checkCatalogEntryTrustManifest(missing, artifact),
    ).resolves.toEqual({ status: 'missing_trust_manifest' });
    const unsigned = entryFor();
    if (unsigned.trustManifest) delete unsigned.trustManifest.signature;
    await expect(
      checkCatalogEntryTrustManifest(unsigned, artifact),
    ).resolves.toEqual({
      status: 'signature_check_failed',
      signatureResult: { status: 'missing_signature' },
    });
    const noSubject = entryFor();
    if (noSubject.trustManifest) {
      delete noSubject.trustManifest.subject;
      noSubject.trustManifest = signManifest(noSubject.trustManifest);
    }
    await expect(
      checkCatalogEntryTrustManifest(noSubject, artifact),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'missing_subject' },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it.each([
    { identity: 'did:web:other.example' },
    { identityType: 'dns' },
    { issuedAt: 'not-a-date' },
    { expiresAt: '2026-02-30T00:00:00Z' },
  ])('returns a local profile diagnostic for %j', async (fields) => {
    await expect(
      checkCatalogEntryTrustManifest(entryFor(artifact, fields), artifact),
    ).resolves.toEqual({
      status: 'profile_check_failed',
      error: expect.any(Error),
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('requires issuedAt even when typed input bypasses a parser', async () => {
    const entry = entryFor();
    const manifest = entry.trustManifest as TrustManifest;
    delete manifest.issuedAt;
    entry.trustManifest = signManifest(manifest);
    await expect(
      checkCatalogEntryTrustManifest(entry, artifact),
    ).resolves.toEqual({
      status: 'profile_check_failed',
      error: expect.any(Error),
    });
  });

  it.each([
    { alg: 'ES256' },
    { alg: 'ES256', kid: `${identity}/path#release` },
    { alg: 'ES256', kid, jwk: {} },
    { alg: 'ES256', kid, jku: 'https://other.example/key' },
    { alg: 'ES256', kid, x5u: 'https://other.example/cert' },
    { alg: 'ES256', kid, x5c: [] },
    { alg: 'ES256', kid, b64: true, crit: ['b64'] },
    { alg: 'ES256', kid, b64: false, crit: ['b64'] },
  ])('rejects unsupported profile headers before resolution: %j', async (header) => {
    await expect(
      checkCatalogEntryTrustManifest(entryFor(artifact, {}, header), artifact),
    ).resolves.toEqual({
      status: 'profile_check_failed',
      error: expect.any(Error),
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('preserves unsupported algorithm and malformed JWS diagnostics', async () => {
    await expect(
      checkCatalogEntryTrustManifest(
        entryFor(artifact, {}, { alg: 'ES384', kid }),
        artifact,
      ),
    ).resolves.toEqual({
      status: 'signature_check_failed',
      signatureResult: { status: 'algorithm_mismatch', algorithm: 'ES384' },
    });
    const malformed = entryFor();
    (malformed.trustManifest as TrustManifest).signature = 'no-jws';
    await expect(
      checkCatalogEntryTrustManifest(malformed, artifact),
    ).resolves.toEqual({
      status: 'signature_check_failed',
      signatureResult: { status: 'invalid_jws' },
    });
  });

  it('rejects an incorrect artifact binding without requesting an issuer document', async () => {
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), new Uint8Array([4])),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'mismatch' },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('reports an expected resolution error and its underlying cause', async () => {
    const cause = new Error('DNS unavailable');
    const error = new IssuerCheckError('Could not resolve issuer.', { cause });
    resolver.mockRejectedValue(error);
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), artifact),
    ).resolves.toEqual({ status: 'issuer_check_failed', error });
    expect(error.cause).toBe(cause);
  });

  it('rejects unexpected resolver failures', async () => {
    const error = new Error('Unexpected implementation failure');
    resolver.mockRejectedValue(error);
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), artifact),
    ).rejects.toBe(error);
  });

  it('requires a currently assertion-authorized key', async () => {
    resolver.mockResolvedValue({ ...documentFor(), assertionMethod: [] });
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), artifact),
    ).resolves.toEqual({
      status: 'issuer_check_failed',
      error: expect.any(Error),
    });
  });

  it('reports invalid signatures under an authorized key', async () => {
    const entry = entryFor();
    (entry.trustManifest as TrustManifest).issuedAt = '2026-01-02T00:00:00Z';
    await expect(
      checkCatalogEntryTrustManifest(entry, artifact),
    ).resolves.toEqual({
      status: 'signature_check_failed',
      signatureResult: { status: 'invalid_signature' },
    });
  });

  it('samples expiration after DID resolution and signature verification', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-10-06T00:00:00Z'));
      const entry = entryFor(artifact, { expiresAt: '2026-10-06T00:00:01Z' });
      resolver.mockImplementation(async () => {
        vi.setSystemTime(new Date('2026-10-06T00:00:02Z'));
        return documentFor();
      });
      await expect(
        checkCatalogEntryTrustManifest(entry, artifact),
      ).resolves.toEqual({ status: 'expired' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('captures entry, manifest, options, and artifact digest before awaiting resolution', async () => {
    const entry = entryFor();
    const bytes = new Uint8Array(artifact);
    const options = { timeoutMs: 123_456, maxResponseBytes: 789_012 };
    let complete: ((value: unknown) => void) | undefined;
    resolver.mockImplementation(
      () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
    );
    const result = checkCatalogEntryTrustManifest(entry, bytes, options);
    entry.identifier = 'urn:air:other.example:agent:other';
    (entry.trustManifest as TrustManifest).identity = 'did:web:other.example';
    (entry.trustManifest as TrustManifest).expiresAt = '2000-01-01T00:00:00Z';
    bytes.fill(0);
    options.timeoutMs = 1;
    options.maxResponseBytes = 1;
    expect(resolver).toHaveBeenCalledWith(identity, {
      timeoutMs: 123_456,
      maxResponseBytes: 789_012,
    });
    complete?.(documentFor());
    await expect(result).resolves.toEqual({ status: 'valid' });
  });

  it('rejects preexisting and in-flight cancellation with the caller reason', async () => {
    const reason = new Error('Stop');
    const controller = new AbortController();
    controller.abort(reason);
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), artifact, {
        signal: controller.signal,
      }),
    ).rejects.toBe(reason);
    expect(resolver).not.toHaveBeenCalled();
    const inFlight = new AbortController();
    resolver.mockImplementation(async () => {
      inFlight.abort(reason);
      return documentFor();
    });
    await expect(
      checkCatalogEntryTrustManifest(entryFor(), artifact, {
        signal: inFlight.signal,
      }),
    ).rejects.toBe(reason);
  });

  it.each([
    { timeoutMs: 0 },
    { timeoutMs: -1 },
    { timeoutMs: Number.POSITIVE_INFINITY },
    { maxResponseBytes: 0 },
    { maxResponseBytes: 1.5 },
    { signal: {} },
  ])('rejects invalid runtime options: %j', async (options) => {
    await expect(
      checkCatalogEntryTrustManifest(
        entryFor(),
        artifact,
        options as Parameters<typeof checkCatalogEntryTrustManifest>[2],
      ),
    ).rejects.toBeInstanceOf(TypeError);
  });
});
