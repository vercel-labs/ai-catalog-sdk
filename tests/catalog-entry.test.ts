import { Buffer } from 'node:buffer';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CatalogParseError,
  CatalogValidationError,
  isCatalogEntryWithUrl,
  parseCatalogJson,
  type CatalogEntryWithData,
  type CatalogEntryWithUrl,
  type Signature,
  type TrustManifest,
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
const publisher = 'did:web:example.com';
const assessor = 'did:web:assessor.example';
const signerKeys = new Map(
  [publisher, assessor].map((identity) => [identity, [
    generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  ]] as const),
);
const identifier = 'urn:air:example.com:agent:billing';
const type = 'application/json';
const artifact = new Uint8Array([1, 2, 3]);
const resolver = vi.mocked(resolveDidWeb);
const digestOf = (bytes: Uint8Array) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function documentFor(identity = publisher) {
  const keys = signerKeys.get(identity);
  if (!keys) throw new Error('Unknown fixture identity');
  return {
    id: identity,
    verificationMethod: [1, 2].map((number) => ({
      id: `${identity}#key${number}`,
      controller: identity,
      type: 'JsonWebKey2020',
      publicKeyJwk: keys[number - 1]?.publicKey.export({ format: 'jwk' }),
    })),
    assertionMethod: [`${identity}#key1`, `${identity}#key2`],
  };
}

function signManifest(
  manifest: TrustManifest,
  header: Record<string, unknown> = {},
): TrustManifest {
  const keys = signerKeys.get(manifest.contributor)?.[
    header.kid === `${manifest.contributor}#key2` ? 1 : 0
  ];
  if (!keys) throw new Error('Unknown fixture identity');
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

function entryWithRawManifests(manifests: unknown[]): CatalogEntryWithUrl {
  return { ...entryFor([]), trustManifests: manifests as TrustManifest[] };
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
    expect(reports.map(({ status }) => status)).toEqual(['passed', 'passed']);
    expect(reports[0]).toMatchObject({
      status: 'passed',
      isPublisherEndorsement: true,
    });
    expect(reports[1]).toMatchObject({
      status: 'passed',
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
      manifests: [{ status: 'passed' }],
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
      { status: 'unsigned' },
      { status: 'invalid_jws' },
    ]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('preserves every attached JSON value when no manifests are selected', async () => {
    const manifests = [
      null, 42, 'manifest', false, [],
      { contributor: assessor, signature: { issuedAt: 42 } },
      manifestFor(),
    ];
    const entry = entryWithRawManifests(manifests);
    const report = await checkCatalogEntry(entry, artifact, {
      contributors: [],
    });
    expect(report).toEqual({
      status: 'checked',
      manifests: manifests.map(manifest => ({ status: 'not_checked', manifest })),
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it.each([
    ['null', null, []],
    ['number', 42, []],
    ['string', 'manifest', []],
    ['boolean', false, []],
    ['array', [], []],
    ['contributor', { contributor: 42 }, ['contributor']],
    ['signature', { contributor: assessor, signature: null }, ['signature']],
    ['issuedAt', { contributor: assessor, signature: { signer: assessor, profile: 'did-web-v1', issuedAt: 42, jws: '' } }, ['signature', 'issuedAt']],
    ['expiresAt', { contributor: assessor, signature: { signer: assessor, profile: 'did-web-v1', issuedAt: '2026-01-01T00:00:00Z', expiresAt: 42, jws: '' } }, ['signature', 'expiresAt']],
    ['subject', { contributor: assessor, subject: { identifier: 42, type, digest: digestOf(artifact) } }, ['subject', 'identifier']],
    ['attestations', { contributor: assessor, attestations: [null] }, ['attestations', 0]],
    ['extensions', { contributor: assessor, extensions: 42 }, ['extensions']],
  ])('isolates a selected malformed %s value and still authenticates the publisher', async (_name, malformed, path) => {
    const results = await statuses(entryWithRawManifests([malformed, manifestFor()]));
    expect(results).toMatchObject([
      {
        status: 'invalid_manifest',
        manifest: malformed,
        error: expect.any(CatalogValidationError),
      },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    const result = results[0];
    if (result?.status !== 'invalid_manifest') throw new Error('Expected invalid manifest');
    expect(result.error.issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ path }),
    ]));
    expect(() => parseCatalogJson(JSON.stringify({
      specVersion: '1.0',
      entries: [entryWithRawManifests([malformed])],
    }))).toThrow(CatalogParseError);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it.each([
    ['entry metadata', { updatedAt: 42 }],
    ['manifest collection', { trustManifests: {} }],
  ])('keeps malformed %s an entry-level failure', async (_name, fields) => {
    const report = await checkCatalogEntry(
      { ...entryFor(), ...fields } as CatalogEntryWithUrl,
      artifact,
      { contributors: [] },
    );
    expect(report).toMatchObject({ status: 'invalid_entry', error: expect.any(CatalogParseError) });
    if (report.status !== 'invalid_entry') throw new Error('Expected invalid entry');
    expect(report.error.issues.length).toBeGreaterThan(0);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('checks the declared artifact digest even when no manifests are selected', async () => {
    await expect(
      checkCatalogEntry(entryFor(), new Uint8Array([4]), { contributors: [] }),
    ).resolves.toEqual({
      status: 'artifact_digest_mismatch',
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('reports a shared artifact failure before a malformed manifest', async () => {
    await expect(
      checkCatalogEntry(entryWithRawManifests([null]), new Uint8Array([4])),
    ).resolves.toEqual({ status: 'artifact_digest_mismatch' });
    expect(resolver).not.toHaveBeenCalled();
  });

  it.each([
    { issuedAt: 'yesterday' },
    { expiresAt: '2025-01-01T00:00:00Z' },
    { signer: publisher },
    { profile: '' },
  ])('isolates malformed contribution metadata without blocking the publisher: %j', async (fields) => {
    const malformed = manifestFor(assessor);
    if (!malformed.signature) throw new Error('Expected signed manifest');
    Object.assign(malformed.signature, fields);
    const parsed = parseCatalogJson(JSON.stringify({
      specVersion: '1.0',
      entries: [entryFor([malformed, manifestFor()])],
    }));
    const entry = parsed.entries[0];
    if (!entry || !isCatalogEntryWithUrl(entry)) throw new Error('Expected URL entry');
    const results = await statuses(entry);
    expect(results).toMatchObject([
      { status: 'invalid_manifest', error: expect.any(CatalogValidationError) },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it.each([
    'contributor URI',
    'subject digest',
    'missing subject',
    'empty content',
    'attestation size',
  ])('reports invalid %s on its contribution rather than rejecting the entry', async (defect) => {
    let malformed = manifestFor(assessor);
    if (!malformed.signature || !malformed.subject) throw new Error('Expected signed subject');
    switch (defect) {
      case 'contributor URI':
        malformed.contributor = 'not-a-uri';
        malformed.signature.signer = malformed.contributor;
        break;
      case 'subject digest':
        malformed.subject.digest = 'sha256:zz';
        break;
      case 'missing subject':
        delete malformed.subject;
        break;
      case 'empty content':
        malformed = { contributor: assessor };
        break;
      case 'attestation size':
        malformed.attestations = [{ type: 'test', uri: 'https://assessor.example/report', size: -1 }];
        break;
    }
    expect(await statuses(entryFor([malformed, manifestFor()]))).toMatchObject([
      { status: 'invalid_manifest', error: expect.any(CatalogValidationError) },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it('does not validate excluded contribution shapes or declarations', async () => {
    const malformed = {
      contributor: assessor,
      signature: { issuedAt: 42 },
      subject: false,
    };
    const invalidDeclaration = manifestFor(assessor);
    if (!invalidDeclaration.signature) throw new Error('Expected signed manifest');
    invalidDeclaration.signature.issuedAt = 'yesterday';
    const entry = entryWithRawManifests([malformed, invalidDeclaration, null, 42, manifestFor()]);
    expect(await statuses(entry, {
      contributors: [publisher],
    })).toMatchObject([
      { status: 'not_checked', manifest: malformed },
      { status: 'not_checked', manifest: invalidDeclaration },
      { status: 'not_checked', manifest: null },
      { status: 'not_checked', manifest: 42 },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it('isolates an unusable signed payload and continues evaluating other contributions', async () => {
    const malformed = manifestFor(assessor);
    malformed.extensions = { 'assessor.example': '\ud800' };
    expect(await statuses(entryFor([malformed, manifestFor()]))).toMatchObject([
      { status: 'invalid_manifest', error: expect.any(CatalogValidationError) },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it('does not impose signed-payload Unicode restrictions on unsigned metadata', async () => {
    const unsigned = {
      contributor: assessor,
      extensions: { 'assessor.example': '\ud800' },
    };
    expect(await statuses(entryFor([unsigned, manifestFor()]))).toMatchObject([
      { status: 'unsigned' },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it('reports a subject for another release as an individual manifest failure', async () => {
    const malformed = manifestFor(assessor);
    if (!malformed.subject) throw new Error('Expected subject');
    malformed.subject.identifier = 'urn:air:example.com:agent:other';
    expect(await statuses(entryFor([malformed, manifestFor()]))).toMatchObject([
      { status: 'invalid_manifest', error: expect.any(CatalogValidationError) },
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it('does not require a digest merely to report unsigned metadata', async () => {
    const signed = manifestFor();
    const unsigned = { contributor: assessor, extensions: { 'assessor.example': true } };
    const entry = entryFor([signed, unsigned]);
    delete entry.digest;
    expect(await statuses(entry)).toMatchObject([
      { status: 'invalid_manifest', error: expect.any(CatalogValidationError) },
      { status: 'unsigned' },
    ]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('does not apply authoring validation to unrelated entry timestamps', async () => {
    const entry = { ...entryFor(), updatedAt: 'not-a-timestamp' };
    expect(await statuses(entry)).toMatchObject([{ status: 'passed' }]);
  });

  it('can verify an unaffected entry after parsing a catalog with invalid optional declarations', async () => {
    const malformed = manifestFor(assessor);
    if (!malformed.signature || !malformed.subject) throw new Error('Expected signed subject');
    malformed.signature.issuedAt = 'yesterday';
    const affected = entryFor([malformed]);
    affected.identifier = 'urn:air:example.com:agent:other';
    malformed.subject.identifier = affected.identifier;
    const catalog = parseCatalogJson(JSON.stringify({
      specVersion: '1.0',
      signature: {
        signer: publisher,
        profile: 'did-web-v1',
        issuedAt: 'yesterday',
        jws: 'not-a-jws',
      },
      entries: [affected, entryFor()],
    }));
    const entry = catalog.entries[1];
    if (!entry || !isCatalogEntryWithUrl(entry)) throw new Error('Expected URL entry');
    expect(await statuses(entry)).toMatchObject([
      { status: 'passed', isPublisherEndorsement: true },
    ]);
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it.each([
    ['sha256:00', { status: 'invalid_digest' }],
    ['blake3:00', { status: 'digest_algorithm_not_implemented', algorithm: 'blake3' }],
    ['sha256:zz', { status: 'invalid_digest' }],
  ])('reports the entry digest failure for %s before manifest checks', async (digest, expected) => {
    const entry = { ...entryFor([]), digest };
    await expect(
      checkCatalogEntry(entry, artifact, { contributors: [] }),
    ).resolves.toEqual(expected);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('selects exact contributors and adds all publisher manifests without duplicate outcomes', async () => {
    const entry = entryFor([
      manifestFor(),
      manifestFor(assessor),
      manifestFor(),
      { contributor: publisher, extensions: { 'example.com': true } },
    ]);
    const cases: [CatalogEntryCheckOptions, string[], string[]][] = [
      [{ contributors: [] }, ['not_checked', 'not_checked', 'not_checked', 'not_checked'], []],
      [{ contributors: [assessor] }, ['not_checked', 'passed', 'not_checked', 'not_checked'], [assessor]],
      [
        { contributors: [], alwaysCheckPublisherManifests: true },
        ['passed', 'not_checked', 'passed', 'unsigned'],
        [publisher],
      ],
      [
        { contributors: [assessor, publisher], alwaysCheckPublisherManifests: true },
        ['passed', 'passed', 'passed', 'unsigned'],
        [publisher, assessor],
      ],
      [
        { alwaysCheckPublisherManifests: false },
        ['passed', 'passed', 'passed', 'unsigned'],
        [publisher, assessor],
      ],
    ];
    for (const [options, expectedStatuses, expectedSigners] of cases) {
      resolver.mockClear();
      const results = await statuses(entry, options);
      expect(results.map(({ status }) => status)).toEqual(expectedStatuses);
      expect(results.map(({ manifest }) => manifest)).toEqual(entry.trustManifests);
      expect(results.every(result => !Object.hasOwn(result, 'index'))).toBe(true);
      expect(resolver.mock.calls.map(([identity]) => identity)).toEqual(expectedSigners);
    }
  });

  it('publisher-only selection does not require a publisher manifest to exist', async () => {
    const manifest = manifestFor(assessor);
    await expect(
      checkCatalogEntry(entryFor([manifest]), artifact, {
        contributors: [],
        alwaysCheckPublisherManifests: true,
      }),
    ).resolves.toEqual({
      status: 'checked',
      manifests: [{ status: 'not_checked', manifest }],
    });
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
      { status: 'passed', isPublisherEndorsement: false },
    ]);
    expect(
      await statuses(entry, { alwaysCheckPublisherManifests: true }),
    ).toMatchObject([{ status: 'passed', isPublisherEndorsement: false }]);
    resolver.mockClear();
    await expect(
      checkCatalogEntry(entry, artifact, {
        contributors: [],
        alwaysCheckPublisherManifests: true,
      }),
    ).resolves.toEqual({
      status: 'checked',
      manifests: [{ status: 'not_checked', manifest: entry.trustManifests[0] }],
    });
    expect(resolver).not.toHaveBeenCalled();
    expect(
      await statuses(entry, {
        contributors: [assessor],
        alwaysCheckPublisherManifests: true,
      }),
    ).toMatchObject([{ status: 'passed', isPublisherEndorsement: false }]);
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it('resolves each signer once while authorizing every distinct key separately', async () => {
    const first = manifestFor();
    const second = manifestFor(publisher, {}, { kid: `${publisher}#key2` });
    expect(await statuses(entryFor([first, second]))).toMatchObject([
      { status: 'passed' },
      { status: 'passed' },
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
      { status: 'invalid_jws' },
    ]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('reports common signature failures directly before DID resolution', async () => {
    expect(await statuses(entryFor([
      manifestFor(publisher, {}, { alg: 'ES384' }),
      manifestFor(assessor, {}, { crit: ['future'], future: true }),
    ]))).toMatchObject([
      { status: 'algorithm_mismatch', algorithm: 'ES384' },
      { status: 'jws_feature_not_implemented' },
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
      { status: 'invalid_signature' },
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
        { status: 'passed' },
        { status: 'passed' },
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
        { status: 'passed' },
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses an explicit evaluation instant for every selected endorsement', async () => {
    const entry = entryFor([
      manifestFor(publisher, { expiresAt: '2026-10-06T00:00:00Z' }),
      manifestFor(assessor, { issuedAt: '2026-10-06T00:00:30Z' }),
    ]);
    const nowMs = Date.parse('2026-10-06T00:00:00Z');
    expect(await statuses(entry, { nowMs })).toMatchObject([
      { status: 'passed' },
      { status: 'passed' },
    ]);
    expect(await statuses(entry, { nowMs, clockToleranceMs: 0 })).toMatchObject([
      { status: 'expired' },
      { status: 'not_yet_valid' },
    ]);
  });

  it('captures the explicit evaluation instant and tolerance before DID resolution', async () => {
    const entry = entryFor([
      manifestFor(publisher, { issuedAt: '2026-10-06T00:00:30Z' }),
    ]);
    const options = {
      nowMs: Date.parse('2026-10-06T00:00:00Z'),
      clockToleranceMs: 60_000,
    };
    resolver.mockImplementation(async (identity) => {
      options.nowMs = Date.parse('2000-01-01T00:00:00Z');
      options.clockToleranceMs = 0;
      return documentFor(identity);
    });
    expect(await statuses(entry, options)).toMatchObject([{ status: 'passed' }]);
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
        { status: 'passed' },
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
      status: 'checked',
      manifests: [{ status: 'invalid_manifest', error: expect.any(CatalogValidationError) }],
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('captures entry, checked and unchecked manifests, artifact digest and options before I/O', async () => {
    const unchecked = manifestFor(assessor);
    if (!unchecked.signature) throw new Error('Expected signed manifest');
    unchecked.signature.jws = 'not-jws';
    const manifests = [manifestFor(), unchecked];
    const capturedManifests = structuredClone(manifests);
    const entry = entryFor(manifests);
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
    const uncheckedManifest = manifests[1];
    if (!uncheckedManifest) throw new Error('Expected unchecked manifest');
    uncheckedManifest.contributor = publisher;
    bytes.fill(0);
    contributors.length = 0;
    options.timeoutMs = 1;
    expect(resolver).toHaveBeenCalledWith(publisher, {
      timeoutMs: 123_456,
      maxResponseBytes: 789_012,
    });
    complete?.(documentFor());
    const result = await pending;
    expect(result).toEqual({
      status: 'checked',
      manifests: [
        { status: 'passed', isPublisherEndorsement: true, manifest: capturedManifests[0] },
        { status: 'not_checked', manifest: capturedManifests[1] },
      ],
    });
  });

  it('captures raw invalid and excluded manifest values before the first await', async () => {
    const malformed = { contributor: assessor, signature: { issuedAt: 42 } };
    const excluded = { contributor: 'did:web:excluded.example', subject: false };
    const manifests = [manifestFor(), malformed, excluded, null];
    const captured = structuredClone(manifests);
    let complete: ((value: unknown) => void) | undefined;
    resolver.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    const pending = checkCatalogEntry(entryWithRawManifests(manifests), artifact, {
      contributors: [publisher, assessor],
    });
    expect(resolver).toHaveBeenCalledTimes(1);
    malformed.contributor = publisher;
    malformed.signature.issuedAt = 0;
    excluded.contributor = publisher;
    excluded.subject = true;
    manifests[3] = manifestFor();
    manifests.push(manifestFor());
    complete?.(documentFor());
    await expect(pending).resolves.toEqual({
      status: 'checked',
      manifests: [
        { status: 'passed', manifest: captured[0], isPublisherEndorsement: true },
        { status: 'invalid_manifest', manifest: captured[1], error: expect.any(CatalogValidationError) },
        { status: 'not_checked', manifest: captured[2] },
        { status: 'not_checked', manifest: null },
      ],
    });
    expect(resolver.mock.calls.map(([identity]) => identity)).toEqual([publisher]);
  });

  it.each([
    ['non-JSON value', () => undefined, TypeError],
    ['non-finite number', () => NaN, TypeError],
    ['non-plain object', () => new Date(), TypeError],
    ['cycle', () => {
      const value: Record<string, unknown> = {};
      value.self = value;
      return value;
    }, TypeError],
    ['excessive depth', () => {
      let value: unknown = null;
      for (let depth = 0; depth < 130; depth += 1) value = { nested: value };
      return value;
    }, RangeError],
  ])('rejects an excluded %s before resolving a selected publisher', async (_name, createValue, errorType) => {
    await expect(checkCatalogEntry(
      entryWithRawManifests([manifestFor(), createValue()]),
      artifact,
      { contributors: [publisher] },
    )).rejects.toBeInstanceOf(errorType);
    expect(resolver).not.toHaveBeenCalled();
  });

  it('rejects excluded proxies and accessors without running caller code', async () => {
    const read = vi.fn(() => { throw new Error('must not inspect'); });
    const proxy = new Proxy({}, {
      get: read,
      getOwnPropertyDescriptor: read,
      ownKeys: read,
    });
    const accessor = Object.defineProperty({}, 'contributor', { enumerable: true, get: read });
    for (const value of [proxy, accessor]) {
      await expect(checkCatalogEntry(
        entryWithRawManifests([manifestFor(), value]),
        artifact,
        { contributors: [publisher] },
      )).rejects.toBeInstanceOf(TypeError);
    }
    expect(read).not.toHaveBeenCalled();
    expect(resolver).not.toHaveBeenCalled();
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
    { clockToleranceMs: Infinity },
    { nowMs: null },
    { nowMs: Infinity },
    { nowMs: NaN },
    { nowMs: 0.5 },
    { nowMs: Number.MAX_SAFE_INTEGER + 1 },
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
    ).resolves.toMatchObject({ status: 'invalid_entry', error: expect.any(CatalogParseError) });
  });

  it('reports both artifact representations as structural failures through either overload', async () => {
    const entry = { ...entryFor(), data: null };
    await expect(
      checkCatalogEntry(entry as unknown as CatalogEntryWithData),
    ).resolves.toMatchObject({ status: 'invalid_entry', error: expect.any(CatalogParseError) });
    await expect(
      checkCatalogEntry(entry as unknown as CatalogEntryWithUrl, artifact),
    ).resolves.toMatchObject({ status: 'invalid_entry', error: expect.any(CatalogParseError) });
    expect(resolver).not.toHaveBeenCalled();
  });

  it('rejects overloads for the opposite unambiguous artifact representation', async () => {
    await expect(
      checkCatalogEntry(entryFor() as unknown as CatalogEntryWithData),
    ).rejects.toBeInstanceOf(TypeError);
    const inline = { identifier, type, data: null };
    await expect(
      checkCatalogEntry(inline as unknown as CatalogEntryWithUrl, artifact),
    ).rejects.toBeInstanceOf(TypeError);
    expect(resolver).not.toHaveBeenCalled();
  });
});
