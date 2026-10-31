import { Buffer } from 'node:buffer';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CatalogEntryWithData,
  CatalogEntryWithUrl,
  Signature,
  TrustManifest,
} from '../src/index.js';
import { IssuerCheckError } from '../src/internal/publisher-profile.js';
import { resolveDidWeb } from '../src/internal/did-web.js';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntry,
  createTrustManifestSignaturePayload,
  type CatalogEntryCheckOptions,
} from '../src/verification.js';

vi.mock('../src/internal/did-web.js', () => ({ resolveDidWeb: vi.fn() }));
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publisher = 'did:web:example.com';
const assessor = 'did:web:assessor.example';
const identifier = 'urn:air:example.com:agent:billing';
const type = 'application/json';
const artifact = new Uint8Array([1, 2, 3]);
const resolver = vi.mocked(resolveDidWeb);
const digestOf = (bytes: Uint8Array) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function documentFor(identity = publisher) {
  return {
    id: identity,
    verificationMethod: [1, 2].map((number) => ({
      id: `${identity}#key${number}`,
      controller: identity,
      type: 'JsonWebKey2020',
      publicKeyJwk: keys.publicKey.export({ format: 'jwk' }),
    })),
    assertionMethod: [`${identity}#key1`, `${identity}#key2`],
  };
}

function signManifest(
  manifest: TrustManifest,
  header: Record<string, unknown> = {},
): TrustManifest {
  const metadata: Signature = manifest.signature ?? {
    signer: manifest.contributor,
    profile: 'did-web-v1',
    issuedAt: '2026-01-01T00:00:00Z',
    jws: '',
  };
  const input = { ...manifest, signature: metadata };
  const protectedSegment = Buffer.from(
    JSON.stringify({
      alg: 'ES256',
      typ: 'ai-catalog-trust-manifest+jws',
      kid: `${manifest.contributor}#key1`,
      ...header,
    }),
  ).toString('base64url');
  const payload = Buffer.from(
    createTrustManifestSignaturePayload(input),
  ).toString('base64url');
  const signature = sign(
    'sha256',
    Buffer.from(`${protectedSegment}.${payload}`),
    { key: keys.privateKey, dsaEncoding: 'ieee-p1363' },
  ).toString('base64url');
  return {
    ...input,
    signature: { ...metadata, jws: `${protectedSegment}..${signature}` },
  };
}

function manifestFor(
  contributor = publisher,
  signature: Partial<Signature> = {},
  header: Record<string, unknown> = {},
): TrustManifest {
  return signManifest(
    {
      contributor,
      subject: { identifier, type, digest: digestOf(artifact) },
      signature: {
        signer: contributor,
        profile: 'did-web-v1',
        issuedAt: '2026-01-01T00:00:00Z',
        jws: '',
        ...signature,
      },
    },
    header,
  );
}

function entryFor(
  manifests: TrustManifest[] = [manifestFor()],
): CatalogEntryWithUrl {
  return {
    identifier,
    type,
    url: 'https://cdn.example.com/billing.json',
    digest: digestOf(artifact),
    trustManifests: manifests,
  };
}

async function statuses(
  entry = entryFor(),
  options?: CatalogEntryCheckOptions,
) {
  const report = await checkCatalogEntry(entry, artifact, options);
  expect(report.status).toBe('checked');
  if (report.status !== 'checked') throw new Error('Expected completed report');
  return report.manifests;
}

beforeEach(() => {
  resolver.mockReset();
  resolver.mockImplementation(async (identity) => documentFor(identity));
});

describe('checkCatalogEntry', () => {
  it('authenticates publisher and independent contributions with separate publisher evidence', async () => {
    const reports = await statuses(
      entryFor([manifestFor(), manifestFor(assessor)]),
    );
    expect(reports.map(({ status }) => status)).toEqual(['valid', 'valid']);
    expect(reports[0]).toMatchObject({
      index: 0,
      status: 'valid',
      isPublisherEndorsement: true,
    });
    expect(reports[1]).toMatchObject({
      index: 1,
      status: 'valid',
      isPublisherEndorsement: false,
    });
    expect(resolver).toHaveBeenCalledTimes(2);
    expect(resolver).toHaveBeenCalledWith(publisher, {
      timeoutMs: 60_000,
      maxResponseBytes: 16 * 1024 * 1024,
    });
  });

  it('canonicalizes inline data without downloading an artifact', async () => {
    const data = { z: 1, a: [true, null] };
    const digest = digestOf(canonicalizeJsonValueToBytes(data));
    const manifest = signManifest({
      contributor: publisher,
      subject: { identifier, type, digest },
    });
    const entry: CatalogEntryWithData = {
      identifier,
      type,
      digest,
      data,
      trustManifests: [manifest],
    };
    await expect(checkCatalogEntry(entry)).resolves.toMatchObject({
      status: 'checked',
      manifests: [{ status: 'valid' }],
    });
  });

  it('permits absent manifests, empty arrays, unsigned metadata, and failed endorsements', async () => {
    for (const trustManifests of [undefined, []]) {
      const entry = entryFor();
      if (trustManifests === undefined) delete entry.trustManifests;
      else entry.trustManifests = trustManifests;
      delete entry.digest;
      await expect(checkCatalogEntry(entry, artifact)).resolves.toEqual({
        status: 'checked',
        manifests: [],
      });
    }
    const unsigned = {
      contributor: publisher,
      extensions: { 'example.com': true },
    };
    const failed = manifestFor(assessor);
    if (failed.signature) failed.signature.jws = 'not-jws';
    expect(await statuses(entryFor([unsigned, failed]))).toMatchObject([
      { status: 'missing_signature' },
      {
        status: 'signature_check_failed',
        signatureResult: { status: 'invalid_jws' },
      },
    ]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('validates structure across unselected manifests and reports the original path', async () => {
    const entry = entryFor([{ contributor: publisher }]);
    const report = await checkCatalogEntry(entry, artifact, {
      contributors: [],
    });
    expect(report).toMatchObject({
      status: 'invalid_entry',
      error: {
        issues: expect.arrayContaining([
          expect.objectContaining({ path: ['trustManifests', 0] }),
        ]),
      },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('checks the declared artifact digest even when no manifests are selected', async () => {
    await expect(
      checkCatalogEntry(entryFor(), new Uint8Array([4]), { contributors: [] }),
    ).resolves.toEqual({
      status: 'artifact_check_failed',
      digestResult: { status: 'mismatch' },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('selects exact contributors and adds all publisher manifests without duplicate outcomes', async () => {
    const entry = entryFor([
      manifestFor(),
      manifestFor(assessor),
      manifestFor(),
      { contributor: publisher, extensions: { 'example.com': true } },
    ]);
    expect((await statuses(entry, { contributors: [] })).length).toBe(0);
    expect(
      (await statuses(entry, { contributors: [assessor] })).map(
        ({ index }) => index,
      ),
    ).toEqual([1]);
    expect(
      (
        await statuses(entry, {
          contributors: [],
          alwaysCheckPublisherManifests: true,
        })
      ).map(({ index }) => index),
    ).toEqual([0, 2, 3]);
    expect(
      (
        await statuses(entry, {
          contributors: [assessor, publisher],
          alwaysCheckPublisherManifests: true,
        })
      ).map(({ index }) => index),
    ).toEqual([0, 1, 2, 3]);
    expect(
      (await statuses(entry, { alwaysCheckPublisherManifests: false })).map(
        ({ index }) => index,
      ),
    ).toEqual([0, 1, 2, 3]);
  });

  it('publisher-only selection does not require a publisher manifest to exist', async () => {
    await expect(
      checkCatalogEntry(entryFor([manifestFor(assessor)]), artifact, {
        contributors: [],
        alwaysCheckPublisherManifests: true,
      }),
    ).resolves.toEqual({ status: 'checked', manifests: [] });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('leaves contributor selection unchanged when no publisher identity can be derived', async () => {
    const entry = entryFor();
    entry.identifier = 'https://example.com/artifact';
    entry.trustManifests = [
      signManifest({
        contributor: assessor,
        subject: {
          identifier: entry.identifier,
          type,
          digest: digestOf(artifact),
        },
      }),
    ];
    expect(await statuses(entry)).toMatchObject([
      { status: 'valid', isPublisherEndorsement: false },
    ]);
    expect(
      await statuses(entry, { alwaysCheckPublisherManifests: true }),
    ).toMatchObject([{ status: 'valid', isPublisherEndorsement: false }]);
    resolver.mockClear();
    await expect(
      checkCatalogEntry(entry, artifact, {
        contributors: [],
        alwaysCheckPublisherManifests: true,
      }),
    ).resolves.toEqual({ status: 'checked', manifests: [] });
    expect(resolver).not.toHaveBeenCalled();
    expect(
      await statuses(entry, {
        contributors: [assessor],
        alwaysCheckPublisherManifests: true,
      }),
    ).toMatchObject([{ index: 0, status: 'valid', isPublisherEndorsement: false }]);
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it('resolves each signer once while authorizing every distinct key separately', async () => {
    const first = manifestFor();
    const second = manifestFor(publisher, {}, { kid: `${publisher}#key2` });
    expect(await statuses(entryFor([first, second]))).toMatchObject([
      { status: 'valid' },
      { status: 'valid' },
    ]);
    expect(resolver).toHaveBeenCalledTimes(1);
    resolver.mockClear();
    await statuses();
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it('reports unsupported profiles and malformed profile constraints without I/O', async () => {
    expect(
      await statuses(
        entryFor([
          manifestFor(publisher, { profile: 'custom-v1' }),
          manifestFor(publisher, {}, { kid: 'did:web:other.example#key' }),
          manifestFor(publisher, {}, { b64: true, crit: ['b64'] }),
        ]),
      ),
    ).toMatchObject([
      { status: 'profile_not_implemented', profile: 'custom-v1' },
      { status: 'profile_check_failed', error: expect.any(Error) },
      { status: 'profile_check_failed', error: expect.any(Error) },
    ]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('reports expected resolution failures individually and preserves their causes', async () => {
    const cause = new Error('DNS unavailable');
    const error = new IssuerCheckError('Resolution failed', { cause });
    resolver.mockRejectedValue(error);
    expect(
      await statuses(entryFor([manifestFor(), manifestFor()])),
    ).toMatchObject([
      { status: 'issuer_check_failed', error },
      { status: 'issuer_check_failed', error },
    ]);
    expect(resolver).toHaveBeenCalledTimes(1);
    expect(error.cause).toBe(cause);
  });

  it('rejects unexpected resolver failures', async () => {
    const error = new Error('Backend failure');
    resolver.mockRejectedValue(error);
    await expect(checkCatalogEntry(entryFor(), artifact)).rejects.toBe(error);
  });

  it('does not authenticate an assertion key removed from the current DID document', async () => {
    resolver.mockResolvedValue({ ...documentFor(), assertionMethod: [] });
    expect(await statuses()).toMatchObject([{ status: 'issuer_check_failed' }]);
  });

  it('reports payload tampering after authorized-key resolution', async () => {
    const entry = entryFor();
    const signature = entry.trustManifests?.[0]?.signature;
    if (!signature) throw new Error('Expected signature');
    signature.issuedAt = '2026-01-02T00:00:00Z';
    expect(await statuses(entry)).toMatchObject([
      {
        status: 'signature_check_failed',
        signatureResult: { status: 'invalid_signature' },
      },
    ]);
  });

  it('shares one completion-time sample and applies default tolerance', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-10-06T00:00:00Z'));
      const entry = entryFor([
        manifestFor(publisher, { expiresAt: '2026-10-06T00:00:00Z' }),
        manifestFor(assessor, { issuedAt: '2026-10-06T00:00:30Z' }),
      ]);
      expect(await statuses(entry)).toMatchObject([
        { status: 'valid' },
        { status: 'valid' },
      ]);
      expect(await statuses(entry, { clockToleranceMs: 0 })).toMatchObject([
        { status: 'expired' },
        { status: 'not_yet_valid' },
      ]);
      resolver.mockImplementation(async (identity) => {
        vi.setSystemTime(new Date('2026-10-06T00:01:00Z'));
        return documentFor(identity);
      });
      expect(await statuses(entry)).toMatchObject([
        { status: 'expired' },
        { status: 'valid' },
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('preserves submillisecond currentness at tolerance boundaries', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-10-06T00:00:00Z'));
      const entry = entryFor([
        manifestFor(publisher, { issuedAt: '2026-10-06T00:01:00.0001Z' }),
        manifestFor(assessor, { expiresAt: '2026-10-05T23:59:00.0001Z' }),
      ]);
      expect(await statuses(entry)).toMatchObject([
        { status: 'not_yet_valid' },
        { status: 'valid' },
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects static timestamp ordering before I/O regardless of tolerance', async () => {
    const entry = entryFor([
      manifestFor(publisher, {
        issuedAt: '2026-01-01T00:00:00Z',
        expiresAt: '2026-01-01T00:00:00Z',
      }),
    ]);
    await expect(checkCatalogEntry(entry, artifact)).resolves.toMatchObject({
      status: 'invalid_entry',
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('captures entry, selected manifests, artifact digest and options before I/O', async () => {
    const entry = entryFor();
    const bytes = artifact.slice();
    const contributors = [publisher];
    const options = {
      contributors,
      timeoutMs: 123_456,
      maxResponseBytes: 789_012,
    };
    let complete: ((value: unknown) => void) | undefined;
    resolver.mockImplementation(
      () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
    );
    const pending = checkCatalogEntry(entry, bytes, options);
    entry.identifier = 'mutated';
    const manifest = entry.trustManifests?.[0];
    if (!manifest?.signature) throw new Error('Expected signed manifest');
    manifest.contributor = assessor;
    manifest.signature.expiresAt = '2000-01-01T00:00:00Z';
    bytes.fill(0);
    contributors.length = 0;
    options.timeoutMs = 1;
    expect(resolver).toHaveBeenCalledWith(publisher, {
      timeoutMs: 123_456,
      maxResponseBytes: 789_012,
    });
    complete?.(documentFor());
    const result = await pending;
    expect(result).toMatchObject({
      status: 'checked',
      manifests: [{ status: 'valid', manifest: { contributor: publisher } }],
    });
  });

  it('rejects existing and in-flight cancellation with the caller reason', async () => {
    const reason = new Error('Stop');
    const controller = new AbortController();
    controller.abort(reason);
    await expect(
      checkCatalogEntry(entryFor(), artifact, { signal: controller.signal }),
    ).rejects.toBe(reason);
    expect(resolver).not.toHaveBeenCalled();
    const inFlight = new AbortController();
    resolver.mockImplementation(async () => {
      inFlight.abort(reason);
      return documentFor();
    });
    await expect(
      checkCatalogEntry(entryFor(), artifact, { signal: inFlight.signal }),
    ).rejects.toBe(reason);
  });

  it.each([
    { timeoutMs: 0 },
    { timeoutMs: null },
    { maxResponseBytes: null },
    { clockToleranceMs: null },
    { alwaysCheckPublisherManifests: null },
    { timeoutMs: -1 },
    { timeoutMs: Infinity },
    { maxResponseBytes: 0 },
    { maxResponseBytes: 1.5 },
    { clockToleranceMs: -1 },
    { clockToleranceMs: 0.5 },
    { signal: {} },
    { contributors: [4] },
  ])('rejects invalid options: %j', async (options) => {
    await expect(
      checkCatalogEntry(
        entryFor(),
        artifact,
        options as CatalogEntryCheckOptions,
      ),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it('keeps unsigned unrelated metadata outside I-JSON restrictions', async () => {
    const entry = {
      identifier,
      type,
      url: 'https://example.com/a',
      extensions: { 'example.com': '\ud800' },
    };
    await expect(checkCatalogEntry(entry, artifact)).resolves.toEqual({
      status: 'checked',
      manifests: [],
    });
  });

  it('reports missing artifact representations as structural failures', async () => {
    await expect(
      checkCatalogEntry({ identifier, type } as CatalogEntryWithData),
    ).resolves.toMatchObject({ status: 'invalid_entry' });
  });
});
