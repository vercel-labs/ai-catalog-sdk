import { Buffer } from 'node:buffer';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type {
  InlineCatalogEntry,
  JsonValue,
  ReferencedCatalogEntry,
  TrustManifest,
  TrustSubject,
} from '../src/index.js';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntryArtifactBinding,
  createTrustManifestSignaturePayload,
  type TrustManifestSignatureCheckOptions,
} from '../src/verification.js';
import { catalogEntrySchema } from '../src/zod.js';

const trustedKeys = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});
const otherKeys = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});

function digest(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function encodeHeader(header: unknown): string {
  return Buffer.from(JSON.stringify(header)).toString('base64url');
}

function signManifest(
  manifest: TrustManifest,
  protectedHeader: Record<string, unknown> = { alg: 'ES256' },
  privateKey = trustedKeys.privateKey,
): TrustManifest {
  const protectedSegment = encodeHeader(protectedHeader);
  const payloadSegment = Buffer.from(
    createTrustManifestSignaturePayload(manifest),
  ).toString('base64url');
  const signatureSegment = sign(
    'sha256',
    Buffer.from(`${protectedSegment}.${payloadSegment}`),
    { key: privateKey, dsaEncoding: 'ieee-p1363' },
  ).toString('base64url');
  return {
    ...manifest,
    signature: `${protectedSegment}..${signatureSegment}`,
  };
}

function optionsFor(): TrustManifestSignatureCheckOptions {
  return {
    publicKey: trustedKeys.publicKey,
    expectedAlgorithm: 'ES256',
  };
}

function manifestFor(subject?: TrustSubject): TrustManifest {
  return signManifest({
    identity: 'did:example:publisher',
    issuedAt: '2026-08-31T00:00:00Z',
    ...(subject === undefined ? {} : { subject }),
  });
}

function referencedEntry(
  bytes: Uint8Array,
  subject: Partial<TrustSubject> = {},
): ReferencedCatalogEntry {
  const url = 'https://example.com/artifact.bin';
  return {
    identifier: 'example-artifact',
    type: 'application/example',
    url,
    trustManifest: manifestFor({
      type: 'application/example',
      url,
      digest: digest(bytes),
      ...subject,
    }),
  };
}

function inlineEntry(
  data: JsonValue,
  subject: Partial<TrustSubject> = {},
): InlineCatalogEntry {
  return {
    identifier: 'example-inline-artifact',
    type: 'application/example+json',
    data,
    trustManifest: manifestFor({
      type: 'application/example+json',
      digest: digest(canonicalizeJsonValueToBytes(data)),
      ...subject,
    }),
  };
}

describe('checkCatalogEntryArtifactBinding', () => {
  it('checks exact referenced bytes with an optional matching subject URL', async () => {
    const backing = new Uint8Array([255, 116, 101, 115, 116, 0]);
    const bytes = backing.subarray(1, 5);

    await expect(
      checkCatalogEntryArtifactBinding(
        referencedEntry(bytes),
        bytes,
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'valid' });

    const withoutSubjectUrl = referencedEntry(bytes);
    if (withoutSubjectUrl.trustManifest?.subject) {
      delete withoutSubjectUrl.trustManifest.subject.url;
      withoutSubjectUrl.trustManifest = signManifest(
        withoutSubjectUrl.trustManifest,
      );
    }
    await expect(
      checkCatalogEntryArtifactBinding(
        withoutSubjectUrl,
        bytes,
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'valid' });
  });

  it('canonicalizes inline JSON before checking its digest', async () => {
    const data = { b: 2, a: 1 };
    expect(JSON.stringify(data)).toBe('{"b":2,"a":1}');

    await expect(
      checkCatalogEntryArtifactBinding(inlineEntry(data), optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });

  it('reports an absent Trust Manifest', async () => {
    const entry: InlineCatalogEntry = {
      identifier: 'unsigned',
      type: 'application/example+json',
      data: null,
    };

    await expect(
      checkCatalogEntryArtifactBinding(entry, optionsFor()),
    ).resolves.toEqual({ status: 'missing_trust_manifest' });
  });

  it('preserves every signature failure as a nested result', async () => {
    const bytes = new TextEncoder().encode('test');
    const base = referencedEntry(bytes);
    const manifest = base.trustManifest as TrustManifest;
    const { signature: _signature, ...unsigned } = manifest;
    const cases: [TrustManifest, object][] = [
      [unsigned, { status: 'missing_signature' }],
      [{ ...manifest, signature: 'not-a-jws' }, { status: 'invalid_jws' }],
      [
        signManifest(unsigned, { alg: 'ES384' }),
        { status: 'algorithm_mismatch', algorithm: 'ES384' },
      ],
      [
        signManifest(unsigned, {
          alg: 'ES256',
          crit: ['future'],
          future: true,
        }),
        { status: 'jws_feature_not_implemented' },
      ],
      [
        signManifest(unsigned, { alg: 'ES256' }, otherKeys.privateKey),
        { status: 'invalid_signature' },
      ],
    ];

    for (const [trustManifest, signatureResult] of cases) {
      await expect(
        checkCatalogEntryArtifactBinding(
          { ...base, trustManifest },
          bytes,
          optionsFor(),
        ),
      ).resolves.toEqual({
        status: 'signature_check_failed',
        signatureResult,
      });
    }
  });

  it('reports a signature failure before a subject failure', async () => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes, {
      type: 'application/wrong',
      digest: 'sha256:abc',
    });
    entry.trustManifest = {
      ...(entry.trustManifest as TrustManifest),
      signature: 'not-a-jws',
    };

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, optionsFor()),
    ).resolves.toEqual({
      status: 'signature_check_failed',
      signatureResult: { status: 'invalid_jws' },
    });
  });

  it('reports a missing subject after a valid signature', async () => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes);
    entry.trustManifest = manifestFor();

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'missing_subject' },
    });
  });

  it('checks subject type before its URL or digest', async () => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes, {
      type: 'application/wrong',
      url: 'https://example.com/wrong',
      digest: 'sha256:abc',
    });

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'type_mismatch' },
    });
  });

  it('requires a present subject URL to match a referenced entry', async () => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes, {
      url: 'https://example.com/other.bin',
    });

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'url_mismatch' },
    });
  });

  it('rejects a subject URL on an inline entry', async () => {
    const entry = inlineEntry({ ok: true }, {
      url: 'https://example.com/inline.json',
    });

    await expect(
      checkCatalogEntryArtifactBinding(entry, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'url_mismatch' },
    });
  });

  it.each([
    [
      'different bytes',
      digest(new TextEncoder().encode('different')),
      { status: 'mismatch' },
    ],
    ['an invalid digest', 'sha256:abc', { status: 'invalid_digest' }],
    [
      'an unimplemented algorithm',
      'sha512:a',
      { status: 'algorithm_not_implemented', algorithm: 'sha512' },
    ],
  ])('preserves the digest failure for %s', async (_label, value, result) => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes, { digest: value });

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, optionsFor()),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: result,
    });
  });

  it('enforces context omitted by direct /zod entry parsing', async () => {
    const bytes = new TextEncoder().encode('test');
    const typeMismatch = catalogEntrySchema.parse(
      referencedEntry(bytes, { type: 'application/wrong' }),
    );
    const urlMismatch = catalogEntrySchema.parse(
      referencedEntry(bytes, {
        url: 'https://example.com/other.bin',
      }),
    );

    await expect(
      checkCatalogEntryArtifactBinding(
        typeMismatch as ReferencedCatalogEntry,
        bytes,
        optionsFor(),
      ),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'type_mismatch' },
    });
    await expect(
      checkCatalogEntryArtifactBinding(
        urlMismatch as ReferencedCatalogEntry,
        bytes,
        optionsFor(),
      ),
    ).resolves.toEqual({
      status: 'subject_check_failed',
      subjectResult: { status: 'url_mismatch' },
    });
  });

  it('checks one coherent inline entry snapshot', async () => {
    const data = { nested: { value: 'original' } };
    const entry = inlineEntry(data) as InlineCatalogEntry &
      Record<string, JsonValue>;
    const manifest = entry.trustManifest as TrustManifest &
      Record<string, JsonValue>;
    manifest.future = { state: 'original' };
    entry.trustManifest = signManifest(manifest);
    const signedManifest = entry.trustManifest;
    const options = optionsFor();

    const pending = checkCatalogEntryArtifactBinding(entry, options);
    data.nested.value = 'mutated';
    entry.type = 'application/mutated';
    entry.data = { replacement: true };
    entry.trustManifest = manifestFor({
      type: entry.type,
      digest: digest(canonicalizeJsonValueToBytes(entry.data)),
    });
    if (signedManifest?.subject) {
      signedManifest.subject.type = 'application/mutated';
      signedManifest.subject.digest = `sha256:${'0'.repeat(64)}`;
    }
    signedManifest.future = { state: 'mutated' };
    options.publicKey = otherKeys.publicKey;

    await expect(pending).resolves.toEqual({ status: 'valid' });
  });

  it('checks referenced bytes and entry context before yielding', async () => {
    const backing = new Uint8Array([255, 116, 101, 115, 116, 0]);
    const bytes = backing.subarray(1, 5);
    const entry = referencedEntry(bytes);
    const manifest = entry.trustManifest as TrustManifest;
    const options = optionsFor();

    const pending = checkCatalogEntryArtifactBinding(entry, bytes, options);
    backing.fill(0);
    entry.type = 'application/mutated';
    entry.url = 'https://example.com/mutated';
    entry.trustManifest = manifestFor({
      type: entry.type,
      url: entry.url,
      digest: digest(bytes),
    });
    if (manifest.subject) {
      manifest.subject.type = entry.type;
      manifest.subject.url = entry.url;
      manifest.subject.digest = digest(bytes);
    }
    manifest.signature = 'mutated';
    options.publicKey = otherKeys.publicKey;

    await expect(pending).resolves.toEqual({ status: 'valid' });
  });

  it('validates the selected key before capturing entry context', async () => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes);
    const key = createPublicKey({
      key: trustedKeys.publicKey.export({ format: 'jwk' }),
      format: 'jwk',
    });
    const replacementManifest = entry.trustManifest as TrustManifest;
    let reads = 0;
    Object.defineProperty(key, 'type', {
      configurable: true,
      get() {
        reads += 1;
        entry.type = 'application/mutated';
        entry.trustManifest = replacementManifest;
        return 'public';
      },
    });

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, {
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
    const entry = referencedEntry(bytes);
    const backingBuffer = bytes.buffer;
    let reads = 0;
    Object.defineProperty(bytes, 'buffer', {
      configurable: true,
      get() {
        reads += 1;
        entry.trustManifest = manifestFor({
          type: 'application/wrong',
          digest: digest(bytes),
        });
        return backingBuffer;
      },
    });

    await expect(
      checkCatalogEntryArtifactBinding(entry, bytes, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
    expect(reads).toBe(0);
  });

  it('rejects accessors without invoking them', async () => {
    let reads = 0;
    const entry = inlineEntry(null);
    Object.defineProperty(entry, 'data', {
      enumerable: true,
      get() {
        reads += 1;
        return null;
      },
    });

    await expect(
      checkCatalogEntryArtifactBinding(entry, optionsFor()),
    ).rejects.toThrow(TypeError);
    expect(reads).toBe(0);
  });

  it('rejects shared and detached referenced byte views', async () => {
    const bytes = new TextEncoder().encode('test');
    const entry = referencedEntry(bytes);
    const shared = new Uint8Array(new SharedArrayBuffer(4));
    await expect(
      checkCatalogEntryArtifactBinding(entry, shared, optionsFor()),
    ).rejects.toThrow('bytes must not be backed by a SharedArrayBuffer.');

    const detached = bytes.slice();
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    await expect(
      checkCatalogEntryArtifactBinding(entry, detached, optionsFor()),
    ).rejects.toThrow('bytes must not have a detached ArrayBuffer.');
  });

  it('preserves inline canonicalization resource errors', async () => {
    let data: JsonValue = null;
    for (let depth = 0; depth < 130; depth += 1) {
      data = { nested: data };
    }
    const entry = {
      identifier: 'deep-inline',
      type: 'application/example+json',
      data,
      trustManifest: {
        identity: 'did:example:publisher',
        issuedAt: '2026-08-31T00:00:00Z',
        subject: {
          type: 'application/example+json',
          digest: `sha256:${'0'.repeat(64)}`,
        },
        signature: 'not-a-jws',
      },
    } satisfies InlineCatalogEntry;

    await expect(
      checkCatalogEntryArtifactBinding(entry, optionsFor()),
    ).rejects.toThrow(RangeError);
  });
});
