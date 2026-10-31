import { Buffer } from 'node:buffer';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type {
  CatalogEntryWithData,
  CatalogEntryWithUrl,
  JsonValue,
  TrustManifest,
  TrustSubject,
} from '../src/index.js';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntryArtifactBinding,
  createTrustManifestSignaturePayload,
  type SignatureCheckOptions,
} from '../src/verification.js';

const trustedKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const otherKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const typ = 'ai-catalog-trust-manifest+jws';
const contributor = 'did:example:publisher';
const metadata = {
  signer: contributor,
  profile: 'custom-profile',
  issuedAt: '2026-08-31T00:00:00Z',
};

function digest(
  bytes: Uint8Array,
  algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256',
): string {
  return `${algorithm}:${createHash(algorithm).update(bytes).digest('hex')}`;
}
function signManifest(
  manifest: TrustManifest,
  header: Record<string, unknown> = { alg: 'ES256', typ },
  privateKey = trustedKeys.privateKey,
): TrustManifest {
  const input = {
    ...manifest,
    signature: { ...metadata, ...manifest.signature, jws: '' },
  };
  const protectedSegment = Buffer.from(JSON.stringify(header)).toString(
    'base64url',
  );
  const payload = Buffer.from(
    createTrustManifestSignaturePayload(input),
  ).toString('base64url');
  const signatureSegment = sign(
    'sha256',
    Buffer.from(`${protectedSegment}.${payload}`),
    { key: privateKey, dsaEncoding: 'ieee-p1363' },
  ).toString('base64url');
  return {
    ...input,
    signature: {
      ...input.signature,
      jws: `${protectedSegment}..${signatureSegment}`,
    },
  };
}
function optionsFor(): SignatureCheckOptions {
  return { publicKey: trustedKeys.publicKey, expectedAlgorithm: 'ES256' };
}
function manifestFor(subject?: TrustSubject): TrustManifest {
  return signManifest({
    contributor,
    ...(subject === undefined ? {} : { subject }),
  });
}
function urlFixture(bytes: Uint8Array, fields: Partial<TrustSubject> = {}) {
  const entry: CatalogEntryWithUrl = {
    identifier: 'example-artifact',
    type: 'application/example',
    url: 'https://example.com/artifact.bin',
    digest: fields.digest ?? digest(bytes),
  };
  return {
    entry,
    manifest: manifestFor({
      identifier: entry.identifier,
      type: entry.type,
      digest: entry.digest as string,
      ...fields,
    }),
  };
}
function dataFixture(data: JsonValue, fields: Partial<TrustSubject> = {}) {
  const entry: CatalogEntryWithData = {
    identifier: 'example-artifact-with-data',
    type: 'application/example+json',
    data,
    digest: fields.digest ?? digest(canonicalizeJsonValueToBytes(data)),
  };
  return {
    entry,
    manifest: manifestFor({
      identifier: entry.identifier,
      type: entry.type,
      digest: entry.digest as string,
      ...fields,
    }),
  };
}

describe('checkCatalogEntryArtifactBinding', () => {
  it('checks exact caller-supplied byte range against an explicit, unattached manifest', async () => {
    const backing = new Uint8Array([255, 116, 101, 115, 116, 0]);
    const bytes = backing.subarray(1, 5);
    const { entry, manifest } = urlFixture(bytes);
    expect(entry.trustManifests).toBeUndefined();
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });
  it.each([
    'sha384',
    'sha512',
  ] as const)('supports the %s digest implementation compositionally', async (algorithm) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, {
      digest: digest(bytes, algorithm),
    });
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });
  it('JCS-canonicalizes inline data', async () => {
    const { entry, manifest } = dataFixture({ b: 2, a: 1 });
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });
  it('does not enforce identity authorization, currentness, or a built-in profile', async () => {
    const { entry, manifest } = dataFixture(null);
    if (!manifest.signature) throw new Error('fixture');
    manifest.signature.issuedAt = '2000-01-01T00:00:00Z';
    manifest.signature.expiresAt = '2001-01-01T00:00:00Z';
    const signed = signManifest(manifest);
    await expect(
      checkCatalogEntryArtifactBinding(entry, signed, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });
  it('preserves every signature failure as a nested result', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    const { signature: _signature, ...unsigned } = manifest;
    const cases: [TrustManifest, object][] = [
      [unsigned, { status: 'missing_signature' }],
      [
        { ...manifest, signature: { ...metadata, jws: 'not-a-jws' } },
        { status: 'invalid_jws' },
      ],
      [
        signManifest(unsigned, { alg: 'ES384', typ }),
        { status: 'algorithm_mismatch', algorithm: 'ES384' },
      ],
      [
        signManifest(unsigned, {
          alg: 'ES256',
          typ,
          crit: ['future'],
          future: true,
        }),
        { status: 'jws_feature_not_implemented' },
      ],
      [
        signManifest(unsigned, { alg: 'ES256', typ }, otherKeys.privateKey),
        { status: 'invalid_signature' },
      ],
    ];
    for (const [candidate, signatureResult] of cases) {
      await expect(
        checkCatalogEntryArtifactBinding(entry, bytes, candidate, optionsFor()),
      ).resolves.toEqual({ status: 'signature_check_failed', signatureResult });
    }
  });
  it('reports a signature failure before a subject failure', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, {
      identifier: 'wrong',
      version: 'wrong',
      type: 'wrong',
      digest: 'sha256:abc',
    });
    manifest.signature = { ...metadata, jws: 'not-a-jws' };
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({
      status: 'signature_check_failed',
      signatureResult: { status: 'invalid_jws' },
    });
  });
  it('reports a missing subject after a valid signature', async () => {
    const { entry } = dataFixture(null);
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifestFor(), optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'missing_subject' },
    });
  });
  it.each([
    ['identifier', 'EXAMPLE-artifact', 'identifier_mismatch'],
    ['type', 'application/wrong', 'type_mismatch'],
  ] as const)('requires subject %s equality', async (field, value, status) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, { [field]: value });
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status },
    });
  });
  it.each([
    ['1.0', '1.0', 'valid'],
    ['1.0', '1.0.0', 'version_mismatch'],
    ['1.0', undefined, 'version_mismatch'],
    [undefined, '1.0', 'version_mismatch'],
    ['', '', 'valid'],
    ['', undefined, 'version_mismatch'],
    [undefined, '', 'version_mismatch'],
  ] as const)('checks entry version %j against subject version %j', async (entryVersion, subjectVersion, status) => {
    const { entry, manifest } = dataFixture(
      null,
      subjectVersion === undefined ? {} : { version: subjectVersion },
    );
    if (entryVersion !== undefined) entry.version = entryVersion;
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).resolves.toEqual(
      status === 'valid'
        ? { status }
        : { status: 'subject_check_failed', subjectResult: { status } },
    );
  });
  it('requires entry digest and signed subject digest to match', async () => {
    const { entry, manifest } = dataFixture(null);
    entry.digest = digest(new Uint8Array([1]));
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'digest_mismatch' },
    });
  });
  it('does not accept a signed binding without an entry digest', async () => {
    const { entry, manifest } = dataFixture(null);
    delete entry.digest;
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'digest_mismatch' },
    });
  });
  it('treats a legacy subject URL as signed, uninterpreted data', async () => {
    const { entry, manifest } = dataFixture(null);
    const subject = manifest.subject as TrustSubject &
      Record<string, JsonValue>;
    subject.url = 'https://different.example/mirror';
    await expect(
      checkCatalogEntryArtifactBinding(
        entry,
        signManifest(manifest),
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'valid' });
  });
  it.each([
    [
      'different bytes',
      digest(new TextEncoder().encode('different')),
      { status: 'mismatch' },
    ],
    ['invalid length', 'sha256:abc', { status: 'invalid_digest' }],
    [
      'unimplemented algorithm',
      'sha3-256:a',
      { status: 'algorithm_not_implemented', algorithm: 'sha3-256' },
    ],
  ])('preserves artifact digest failure for %s', async (_label, value, subjectResult) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, { digest: value as string });
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'subject_check_failed', subjectResult });
  });
  it('captures inline data, entry coordinates, manifest, and options before yielding', async () => {
    const data = { nested: { value: 'original' } };
    const { entry, manifest } = dataFixture(data);
    const options = optionsFor();
    const pending = checkCatalogEntryArtifactBinding(entry, manifest, options);
    data.nested.value = 'mutated';
    entry.identifier = 'mutated';
    entry.version = 'later';
    entry.type = 'mutated';
    entry.digest = digest(new Uint8Array([2]));
    entry.data = null;
    if (manifest.subject) {
      manifest.subject.identifier = 'mutated';
      manifest.subject.digest = entry.digest;
    }
    manifest.signature = { ...metadata, jws: 'mutated' };
    options.publicKey = otherKeys.publicKey;
    await expect(pending).resolves.toEqual({ status: 'valid' });
  });
  it('hashes URL bytes and captures context before yielding', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    const pending = checkCatalogEntryArtifactBinding(
      entry,
      bytes,
      manifest,
      optionsFor(),
    );
    bytes.fill(0);
    entry.identifier = 'mutated';
    entry.url = 'https://other.example';
    if (manifest.subject) manifest.subject.digest = digest(bytes);
    await expect(pending).resolves.toEqual({ status: 'valid' });
  });
  it('validates the selected key before capturing entry context', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    const key = createPublicKey({
      key: trustedKeys.publicKey.export({ format: 'jwk' }),
      format: 'jwk',
    });
    let reads = 0;
    Object.defineProperty(key, 'type', {
      configurable: true,
      get() {
        reads += 1;
        entry.type = 'application/mutated';
        return 'public';
      },
    });
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, {
        publicKey: key,
        expectedAlgorithm: 'ES256',
      }),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'type_mismatch' },
    });
    expect(reads).toBeGreaterThan(0);
  });
  it('does not invoke an overridden byte-view buffer getter', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    let reads = 0;
    Object.defineProperty(bytes, 'buffer', {
      get() {
        reads += 1;
        throw new Error('must not invoke');
      },
    });
    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
    expect(reads).toBe(0);
  });
  it.each([
    ['entry', 'identifier'],
    ['entry', 'version'],
    ['entry', 'data'],
    ['subject', 'identifier'],
    ['subject', 'version'],
  ] as const)('rejects %s.%s accessors without invoking them', async (location, property) => {
    const { entry, manifest } = dataFixture(null);
    const target =
      location === 'entry' ? entry : (manifest.subject as TrustSubject);
    let reads = 0;
    Object.defineProperty(target, property, {
      enumerable: true,
      get() {
        reads += 1;
        return 'value';
      },
    });
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).rejects.toThrow(TypeError);
    expect(reads).toBe(0);
  });
  it.each([
    'entry',
    'subject',
  ] as const)('rejects missing or malformed %s release coordinates', async (location) => {
    for (const [property, value] of [
      ['identifier', undefined],
      ['identifier', null],
      ['identifier', 1],
      ['version', undefined],
      ['version', null],
      ['version', 1],
    ] as const) {
      const { entry, manifest } = dataFixture(null);
      const target =
        location === 'entry' ? entry : (manifest.subject as TrustSubject);
      Object.defineProperty(target, property, {
        configurable: true,
        enumerable: true,
        writable: true,
        value,
      });
      await expect(
        checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
      ).rejects.toThrow(TypeError);
    }
    const { entry, manifest } = dataFixture(null);
    Reflect.deleteProperty(
      location === 'entry' ? entry : (manifest.subject as TrustSubject),
      'identifier',
    );
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).rejects.toThrow(TypeError);
  });
  it.each([
    'entry',
    'subject',
  ] as const)('rejects a proxied %s without invoking traps', async (location) => {
    const { entry, manifest } = dataFixture(null);
    let reads = 0;
    const handler = {
      getOwnPropertyDescriptor() {
        reads += 1;
        throw new Error('must not inspect');
      },
      get() {
        reads += 1;
        throw new Error('must not read');
      },
    };
    const input = location === 'entry' ? new Proxy(entry, handler) : entry;
    if (location === 'subject')
      manifest.subject = new Proxy(manifest.subject as TrustSubject, handler);
    await expect(
      checkCatalogEntryArtifactBinding(input, manifest, optionsFor()),
    ).rejects.toThrow(TypeError);
    expect(reads).toBe(0);
  });
  it('rejects calls that do not match the entry artifact representation', async () => {
    const bytes = new TextEncoder().encode('test');
    const url = urlFixture(bytes);
    const inline = dataFixture(null);
    await expect(
      checkCatalogEntryArtifactBinding(
        url.entry as unknown as CatalogEntryWithData,
        url.manifest,
        optionsFor(),
      ),
    ).rejects.toThrow(TypeError);
    await expect(
      checkCatalogEntryArtifactBinding(
        inline.entry as unknown as CatalogEntryWithUrl,
        bytes,
        inline.manifest,
        optionsFor(),
      ),
    ).rejects.toThrow(TypeError);
  });
  it('rejects shared or detached URL byte views', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    await expect(
      checkCatalogEntryArtifactBinding(
        entry,
        new Uint8Array(new SharedArrayBuffer(4)),
        manifest,
        optionsFor(),
      ),
    ).rejects.toThrow('bytes must not be backed by a SharedArrayBuffer.');
    const detached = bytes.slice();
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    await expect(
      checkCatalogEntryArtifactBinding(entry, detached, manifest, optionsFor()),
    ).rejects.toThrow('bytes must not have a detached ArrayBuffer.');
  });
  it('preserves canonicalization resource errors for inline data', async () => {
    const { entry, manifest } = dataFixture(null);
    let data: JsonValue = null;
    for (let depth = 0; depth < 130; depth += 1) data = { nested: data };
    entry.data = data;
    await expect(
      checkCatalogEntryArtifactBinding(entry, manifest, optionsFor()),
    ).rejects.toThrow(RangeError);
  });
});
