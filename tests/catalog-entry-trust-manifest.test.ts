import { Buffer } from 'node:buffer';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  CatalogParseError,
  CatalogValidationError,
  type CatalogEntryWithData,
  type CatalogEntryWithUrl,
  type JsonValue,
  type TrustManifest,
  type TrustSubject,
} from '../src/index.js';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntryTrustManifest,
  createTrustManifestSignaturePayload,
  type CatalogEntryTrustManifestCheckOptions,
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
function optionsFor(): CatalogEntryTrustManifestCheckOptions {
  return {
    publicKey: trustedKeys.publicKey,
    expectedAlgorithm: 'ES256',
    nowMs: Date.parse('2026-10-31T12:00:00Z'),
  };
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

describe('checkCatalogEntryTrustManifest', () => {
  it('checks exact caller-supplied byte range against an explicit, unattached manifest', async () => {
    const backing = new Uint8Array([255, 116, 101, 115, 116, 0]);
    const bytes = backing.subarray(1, 5);
    const { entry, manifest } = urlFixture(bytes);
    expect(entry.trustManifests).toBeUndefined();
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'passed' });
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
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'passed' });
  });
  it('JCS-canonicalizes inline data', async () => {
    const { entry, manifest } = dataFixture({ b: 2, a: 1 });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'passed' });
  });
  it('accepts a caller-selected key and custom profile while enforcing currentness', async () => {
    const { entry, manifest } = dataFixture(null);
    if (!manifest.signature) throw new Error('fixture');
    manifest.signature.issuedAt = '2000-01-01T00:00:00Z';
    manifest.signature.expiresAt = '2001-01-01T00:00:00Z';
    const signed = signManifest(manifest);
    await expect(
      checkCatalogEntryTrustManifest(entry, signed, {
        ...optionsFor(),
        nowMs: Date.parse('2000-06-01T00:00:00Z'),
      }),
    ).resolves.toEqual({ status: 'passed' });
  });
  it.each([
    { signer: 'did:example:someone-else' },
    { issuedAt: 'not-a-timestamp' },
    { issuedAt: '2026-01-01T00:00:00Z', expiresAt: '2026-01-01T00:00:00Z' },
  ])('validates manifest attribution and static timestamps before the signature: %j', async (fields) => {
    const { entry, manifest } = dataFixture(null);
    manifest.signature = { ...metadata, ...fields, jws: 'not-a-jws' };
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it('rejects empty manifests while allowing unsigned substantive metadata', async () => {
    const { entry } = dataFixture(null);
    await expect(
      checkCatalogEntryTrustManifest(entry, { contributor }, optionsFor()),
    ).resolves.toMatchObject({ status: 'invalid_manifest' });
    for (const value of [true, '\ud800'])
      await expect(
        checkCatalogEntryTrustManifest(entry, {
          contributor,
          extensions: { 'example.com': value },
        }, optionsFor()),
      ).resolves.toEqual({ status: 'unsigned' });
  });
  it('applies the same explicit instant and tolerance to issuance and expiration', async () => {
    const { entry, manifest } = dataFixture(null);
    const future = signManifest({
      ...manifest,
      signature: { ...metadata, issuedAt: '2026-10-31T12:00:30Z', jws: '' },
    });
    const expired = signManifest({
      ...manifest,
      signature: { ...metadata, expiresAt: '2026-10-31T12:00:00Z', jws: '' },
    });
    for (const candidate of [future, expired])
      await expect(
        checkCatalogEntryTrustManifest(entry, candidate, optionsFor()),
      ).resolves.toEqual({ status: 'passed' });
    await expect(
      checkCatalogEntryTrustManifest(entry, future, { ...optionsFor(), clockToleranceMs: 0 }),
    ).resolves.toEqual({ status: 'not_yet_valid' });
    await expect(
      checkCatalogEntryTrustManifest(entry, expired, { ...optionsFor(), clockToleranceMs: 0 }),
    ).resolves.toEqual({ status: 'expired' });
  });
  it('reports temporal rejection only after signature and artifact binding succeed', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    const expired = signManifest({
      ...manifest,
      signature: { ...metadata, expiresAt: '2001-01-01T00:00:00Z', issuedAt: '2000-01-01T00:00:00Z', jws: '' },
    });
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, expired, {
        ...optionsFor(), publicKey: otherKeys.publicKey,
      }),
    ).resolves.toEqual({ status: 'invalid_signature' });
    await expect(
      checkCatalogEntryTrustManifest(entry, new Uint8Array([0]), expired, optionsFor()),
    ).resolves.toEqual({ status: 'artifact_digest_mismatch' });
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, expired, optionsFor()),
    ).resolves.toEqual({ status: 'expired' });
  });
  it('reports the entry artifact failure before malformed manifest declarations', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    if (!manifest.signature) throw new Error('Expected signature');
    manifest.signature.issuedAt = 'yesterday';
    await expect(
      checkCatalogEntryTrustManifest(entry, new Uint8Array([0]), manifest, optionsFor()),
    ).resolves.toEqual({ status: 'artifact_digest_mismatch' });
  });
  it.each([
    ['type', null],
    ['displayName', 1],
    ['description', []],
    ['tags', ['valid', 1]],
    ['publisher', { identifier: 'did:example:publisher' }],
    ['updatedAt', 42],
    ['extensions', []],
    ['digest', 1],
  ])('reports ordinary JSON entry.%s shape errors before artifact and manifest failures', async (property, value) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    Object.defineProperty(entry, property, { enumerable: true, value });
    manifest.signature = { ...metadata, jws: 'not-a-jws' };
    const result = await checkCatalogEntryTrustManifest(
      entry, new Uint8Array([0]), manifest, optionsFor(),
    );
    expect(result).toMatchObject({
      status: 'invalid_entry', error: expect.any(CatalogParseError),
    });
  });
  it.each([null, 1, []])('reports an ordinary JSON URL field %j as an invalid entry', async (url) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    Object.defineProperty(entry, 'url', { enumerable: true, value: url });
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_entry', error: expect.any(CatalogParseError),
    });
  });
  it.each(['missing', 'both'] as const)('reports %s artifact representations as an invalid entry for either overload', async (representation) => {
    const { entry, manifest } = dataFixture(null);
    if (representation === 'missing') Reflect.deleteProperty(entry, 'data');
    else Object.defineProperty(entry, 'url', {
      enumerable: true, value: 'https://example.com/artifact',
    });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_entry', error: expect.any(CatalogParseError),
    });
    await expect(
      checkCatalogEntryTrustManifest(
        entry as unknown as CatalogEntryWithUrl,
        new Uint8Array([0]), manifest, optionsFor(),
      ),
    ).resolves.toMatchObject({
      status: 'invalid_entry', error: expect.any(CatalogParseError),
    });
  });
  it('validates options before reporting invalid entry declarations', async () => {
    const { entry, manifest } = dataFixture(null);
    Object.defineProperty(entry, 'tags', { enumerable: true, value: 1 });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, {
        ...optionsFor(), clockToleranceMs: -1,
      }),
    ).rejects.toThrow(TypeError);
  });
  it.each([null, [], 1, { contributor, subject: null }])('reports explicit manifest shape %j as invalid_manifest without returning a manifest', async (candidate) => {
    const { entry } = dataFixture(null);
    const result = await checkCatalogEntryTrustManifest(
      entry, candidate as unknown as TrustManifest, optionsFor(),
    );
    expect(result).toEqual({
      status: 'invalid_manifest', error: expect.any(CatalogValidationError),
    });
  });
  it.each([
    ['wrong type', 'not-an-array'],
    ['null', null],
    ['null array item', [null]],
    ['invalid manifest', [{ contributor }]],
    ['overlarge array', new Array(100_001).fill(null)],
  ])('ignores attached trustManifests with %s and checks only the explicit manifest', async (_label, attached) => {
    const { entry, manifest } = dataFixture(null);
    Object.defineProperty(entry, 'trustManifests', {
      enumerable: true, value: attached,
    });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'passed' });
    await expect(
      checkCatalogEntryTrustManifest(entry, { contributor }, optionsFor()),
    ).resolves.toEqual({
      status: 'invalid_manifest', error: expect.any(CatalogValidationError),
    });
  });
  it('does not read or traverse attached trustManifests', async () => {
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    let reads = 0;
    const proxy = new Proxy([], {
      getOwnPropertyDescriptor() {
        reads += 1;
        throw new Error('must not inspect');
      },
      get() {
        reads += 1;
        throw new Error('must not read');
      },
    });
    for (const attached of [cyclic, proxy]) {
      const { entry, manifest } = dataFixture(null);
      Object.defineProperty(entry, 'trustManifests', {
        enumerable: true, value: attached,
      });
      await expect(
        checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
      ).resolves.toEqual({ status: 'passed' });
    }
    const { entry, manifest } = dataFixture(null);
    Object.defineProperty(entry, 'trustManifests', {
      enumerable: true,
      get() {
        reads += 1;
        throw new Error('must not invoke');
      },
    });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'passed' });
    expect(reads).toBe(0);
  });
  it('reports a signed payload that cannot be canonicalized as an invalid manifest', async () => {
    const { entry, manifest } = dataFixture(null);
    manifest.extensions = { 'example.com': '\ud800' };
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it('uses the completion-time clock when nowMs is omitted', async () => {
    const { entry, manifest } = dataFixture(null);
    const candidate = signManifest({
      ...manifest,
      signature: { ...metadata, expiresAt: '2026-10-31T12:00:00Z', jws: '' },
    });
    const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-31T11:00:00Z'));
    try {
      const { nowMs: _nowMs, ...options } = optionsFor();
      options.clockToleranceMs = 0;
      const pending = checkCatalogEntryTrustManifest(entry, candidate, options);
      clock.mockReturnValue(Date.parse('2026-10-31T12:00:00Z'));
      await expect(pending).resolves.toEqual({ status: 'expired' });
    } finally {
      clock.mockRestore();
    }
  });
  it.each(['1960-06-01T00:00:00Z', '1970-01-01T00:00:00Z'])('supports evaluation at %s, including nonpositive epoch milliseconds', async (instant) => {
    const { entry, manifest } = dataFixture(null);
    const candidate = signManifest({
      ...manifest,
      signature: { ...metadata, issuedAt: '1960-01-01T00:00:00Z', expiresAt: '1971-01-01T00:00:00Z', jws: '' },
    });
    await expect(
      checkCatalogEntryTrustManifest(entry, candidate, {
        ...optionsFor(), nowMs: Date.parse(instant), clockToleranceMs: 0,
      }),
    ).resolves.toEqual({ status: 'passed' });
  });
  it.each([
    { nowMs: Infinity },
    { nowMs: NaN },
    { nowMs: 0.5 },
    { nowMs: Number.MAX_SAFE_INTEGER + 1 },
    { clockToleranceMs: Infinity },
    { clockToleranceMs: -1 },
  ])('rejects invalid time options: %j', async (timeOptions) => {
    const { entry, manifest } = dataFixture(null);
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, { ...optionsFor(), ...timeOptions }),
    ).rejects.toBeInstanceOf(TypeError);
  });
  it('reports signature failures directly', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    const { signature: _signature, ...unsignedManifest } = manifest;
    const unsigned = { ...unsignedManifest, extensions: { 'example.com': true } };
    const cases: [TrustManifest, object][] = [
      [unsigned, { status: 'unsigned' }],
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
    for (const [candidate, expected] of cases) {
      await expect(
        checkCatalogEntryTrustManifest(entry, bytes, candidate, optionsFor()),
      ).resolves.toEqual(expected);
    }
  });
  it('reports manifest applicability before signature failure', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, {
      identifier: 'wrong',
      version: 'wrong',
      type: 'application/wrong',
    });
    manifest.signature = { ...metadata, jws: 'not-a-jws' };
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it('rejects a signed manifest without a subject before signature verification', async () => {
    const { entry } = dataFixture(null);
    await expect(
      checkCatalogEntryTrustManifest(entry, manifestFor(), optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it.each([
    ['identifier', 'EXAMPLE-artifact'],
    ['type', 'application/wrong'],
  ] as const)('requires subject %s equality', async (field, value) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, { [field]: value });
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it.each([
    ['1.0', '1.0', 'passed'],
    ['1.0', '1.0.0', 'invalid_manifest'],
    ['1.0', undefined, 'invalid_manifest'],
    [undefined, '1.0', 'invalid_manifest'],
    ['', '', 'passed'],
    ['', undefined, 'invalid_manifest'],
    [undefined, '', 'invalid_manifest'],
  ] as const)('checks entry version %j against subject version %j', async (entryVersion, subjectVersion, status) => {
    const { entry, manifest } = dataFixture(
      null,
      subjectVersion === undefined ? {} : { version: subjectVersion },
    );
    if (entryVersion !== undefined) entry.version = entryVersion;
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toMatchObject(
      status === 'passed'
        ? { status }
        : { status: 'invalid_manifest', error: expect.any(CatalogValidationError) },
    );
  });
  it('requires the signed subject digest to match the entry declaration', async () => {
    const { entry, manifest } = dataFixture(null);
    if (!manifest.subject) throw new Error('Expected subject');
    manifest.subject.digest = digest(new Uint8Array([1]));
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it('does not accept a signed binding without an entry digest', async () => {
    const { entry, manifest } = dataFixture(null);
    delete entry.digest;
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
    });
  });
  it('treats a legacy subject URL as signed, uninterpreted data', async () => {
    const { entry, manifest } = dataFixture(null);
    const subject = manifest.subject as TrustSubject &
      Record<string, JsonValue>;
    subject.url = 'https://different.example/mirror';
    await expect(
      checkCatalogEntryTrustManifest(
        entry,
        signManifest(manifest),
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'passed' });
  });
  it.each([
    [
      'different bytes',
      digest(new TextEncoder().encode('different')),
      { status: 'artifact_digest_mismatch' },
    ],
    ['invalid length', 'sha256:abc', { status: 'invalid_digest' }],
    [
      'unimplemented algorithm',
      'sha3-256:a',
      { status: 'digest_algorithm_not_implemented', algorithm: 'sha3-256' },
    ],
  ])('reports artifact digest failure directly for %s', async (_label, value, expected) => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes, { digest: value as string });
    await expect(
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual(expected);
  });
  it('captures inline data, entry coordinates, manifest, and options before yielding', async () => {
    const data = { nested: { value: 'original' } };
    const { entry, manifest } = dataFixture(data);
    entry.tags = ['original'];
    entry.publisher = { identifier: contributor, displayName: 'Original' };
    const options = optionsFor();
    const pending = checkCatalogEntryTrustManifest(entry, manifest, options);
    data.nested.value = 'mutated';
    entry.identifier = 'mutated';
    entry.version = 'later';
    entry.type = 'mutated';
    entry.digest = digest(new Uint8Array([2]));
    entry.data = null;
    Object.defineProperty(entry, 'tags', { value: [1] });
    Object.defineProperty(entry.publisher, 'displayName', { value: null });
    if (manifest.subject) {
      manifest.subject.identifier = 'mutated';
      manifest.subject.digest = entry.digest;
    }
    if (manifest.signature)
      manifest.signature.issuedAt = '2100-01-01T00:00:00Z';
    manifest.signature = { ...metadata, jws: 'mutated' };
    options.publicKey = otherKeys.publicKey;
    options.nowMs = Date.parse('1900-01-01T00:00:00Z');
    options.clockToleranceMs = 0;
    await expect(pending).resolves.toEqual({ status: 'passed' });
  });
  it('hashes URL bytes and captures context before yielding', async () => {
    const bytes = new TextEncoder().encode('test');
    const { entry, manifest } = urlFixture(bytes);
    const pending = checkCatalogEntryTrustManifest(
      entry,
      bytes,
      manifest,
      optionsFor(),
    );
    bytes.fill(0);
    entry.identifier = 'mutated';
    entry.url = 'https://other.example';
    if (manifest.subject) manifest.subject.digest = digest(bytes);
    await expect(pending).resolves.toEqual({ status: 'passed' });
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
      checkCatalogEntryTrustManifest(entry, bytes, manifest, {
        publicKey: key,
        expectedAlgorithm: 'ES256',
      }),
    ).resolves.toMatchObject({
      status: 'invalid_manifest',
      error: expect.any(CatalogValidationError),
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
      checkCatalogEntryTrustManifest(entry, bytes, manifest, optionsFor()),
    ).resolves.toEqual({ status: 'passed' });
    expect(reads).toBe(0);
  });
  it.each([
    ['entry', 'identifier'],
    ['entry', 'version'],
    ['entry', 'data'],
    ['entry', 'displayName'],
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
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
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
      const pending = checkCatalogEntryTrustManifest(entry, manifest, optionsFor());
      if (value !== undefined)
        await expect(pending).resolves.toMatchObject({
          status: location === 'entry' ? 'invalid_entry' : 'invalid_manifest',
          error: expect.any(
            location === 'entry' ? CatalogParseError : CatalogValidationError,
          ),
        });
      else await expect(pending).rejects.toThrow(TypeError);
    }
    const { entry, manifest } = dataFixture(null);
    Reflect.deleteProperty(
      location === 'entry' ? entry : (manifest.subject as TrustSubject),
      'identifier',
    );
    const pending = checkCatalogEntryTrustManifest(entry, manifest, optionsFor());
    await expect(pending).resolves.toMatchObject({
      status: location === 'entry' ? 'invalid_entry' : 'invalid_manifest',
      error: expect.any(
        location === 'entry' ? CatalogParseError : CatalogValidationError,
      ),
    });
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
      checkCatalogEntryTrustManifest(input, manifest, optionsFor()),
    ).rejects.toThrow(TypeError);
    expect(reads).toBe(0);
  });
  it('rejects calls that do not match the entry artifact representation', async () => {
    const bytes = new TextEncoder().encode('test');
    const url = urlFixture(bytes);
    const inline = dataFixture(null);
    await expect(
      checkCatalogEntryTrustManifest(
        url.entry as unknown as CatalogEntryWithData,
        url.manifest,
        optionsFor(),
      ),
    ).rejects.toThrow(TypeError);
    await expect(
      checkCatalogEntryTrustManifest(
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
      checkCatalogEntryTrustManifest(
        entry,
        new Uint8Array(new SharedArrayBuffer(4)),
        manifest,
        optionsFor(),
      ),
    ).rejects.toThrow('bytes must not be backed by a SharedArrayBuffer.');
    const detached = bytes.slice();
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    await expect(
      checkCatalogEntryTrustManifest(entry, detached, manifest, optionsFor()),
    ).rejects.toThrow('bytes must not have a detached ArrayBuffer.');
  });
  it('preserves canonicalization resource errors for inline data', async () => {
    const { entry, manifest } = dataFixture(null);
    let data: JsonValue = null;
    for (let depth = 0; depth < 130; depth += 1) data = { nested: data };
    entry.data = data;
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).rejects.toThrow(RangeError);
  });
  it.each([undefined, () => null, Symbol('non-JSON')])('rejects a non-JSON entry field value %s', async (value) => {
    const { entry, manifest } = dataFixture(null);
    Object.defineProperty(entry, 'futureField', { enumerable: true, value });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).rejects.toThrow(TypeError);
  });
  it('rejects cyclic and overdeep entry metadata outside the artifact', async () => {
    const { entry, manifest } = dataFixture(null);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    Object.defineProperty(entry, 'futureField', {
      configurable: true, enumerable: true, value: cyclic,
    });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).rejects.toThrow(TypeError);
    let nested: JsonValue = null;
    for (let depth = 0; depth < 130; depth += 1) nested = { nested };
    Object.defineProperty(entry, 'futureField', { value: nested });
    await expect(
      checkCatalogEntryTrustManifest(entry, manifest, optionsFor()),
    ).rejects.toThrow(RangeError);
  });
});
