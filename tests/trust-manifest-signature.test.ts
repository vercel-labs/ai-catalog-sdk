import { Buffer } from 'node:buffer';
import {
  createPublicKey,
  createSecretKey,
  generateKeyPairSync,
  sign,
  webcrypto,
} from 'node:crypto';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { JsonValue, TrustManifest } from '../src/index.js';
import {
  checkTrustManifestSignature,
  createTrustManifestSignaturePayload,
  type SignatureCheckOptions,
} from '../src/verification.js';

// The public key is from RFC 7515 Appendix A.3. The detached signature below
// was independently produced with node:crypto and cross-checked with jose.
const fixedPublicJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
} satisfies JsonWebKey;
const fixedSignature =
  'eyJhbGciOiJFUzI1NiJ9..' +
  'NKmmKrtfVExTyrPwimVozLDtLRAZP0r29iJYkrBRAR7rFsM3UqsXFFH3htDDVUKWPJ-UjvgFQqOWDT97iDzT0A';
const fixedManifest: TrustManifest = {
  identity: 'did:example:alice',
  issuedAt: '2026-03-15T10:00:00Z',
  subject: {
    digest:
      'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    type: 'application/json',
  },
  signature: fixedSignature,
};
const fixedPublicKey = createPublicKey({ key: fixedPublicJwk, format: 'jwk' });
const fixedOptions: SignatureCheckOptions = {
  publicKey: fixedPublicKey,
  expectedAlgorithm: 'ES256',
};

const trustedKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const otherKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

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

function optionsFor(
  publicKey: SignatureCheckOptions['publicKey'] =
    trustedKeys.publicKey,
): SignatureCheckOptions {
  return { publicKey, expectedAlgorithm: 'ES256' };
}

function replaceSignatureSegment(
  manifest: TrustManifest,
  signatureSegment: string,
): TrustManifest {
  const [protectedSegment] = manifest.signature?.split('.') ?? [];
  return {
    ...manifest,
    signature: `${protectedSegment ?? ''}..${signatureSegment}`,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('checkTrustManifestSignature', () => {
  it('checks an independently signed AI Catalog vector with both native key handles', async () => {
    await expect(
      checkTrustManifestSignature(fixedManifest, fixedOptions),
    ).resolves.toEqual({ status: 'valid' });

    const cryptoKey = await webcrypto.subtle.importKey(
      'jwk',
      fixedPublicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    await expect(
      checkTrustManifestSignature(fixedManifest, optionsFor(cryptoKey)),
    ).resolves.toEqual({ status: 'valid' });
  });

  it('canonicalizes member order and covers all retained manifest members', async () => {
    const reordered: TrustManifest = {
      signature: fixedManifest.signature,
      subject: fixedManifest.subject,
      issuedAt: fixedManifest.issuedAt,
      identity: fixedManifest.identity,
    };
    await expect(
      checkTrustManifestSignature(reordered, fixedOptions),
    ).resolves.toEqual({ status: 'valid' });

    const changedKnown = structuredClone(fixedManifest);
    changedKnown.identity = 'did:example:mallory';
    await expect(
      checkTrustManifestSignature(changedKnown, fixedOptions),
    ).resolves.toEqual({ status: 'invalid_signature' });

    const changedUnknown = structuredClone(fixedManifest) as TrustManifest &
      Record<string, JsonValue>;
    changedUnknown.future = { nested: { signature: 'retained' } };
    await expect(
      checkTrustManifestSignature(changedUnknown, fixedOptions),
    ).resolves.toEqual({ status: 'invalid_signature' });
  });

  it('reports an absent signature after validating the manifest input', async () => {
    await expect(
      checkTrustManifestSignature(
        { identity: 'did:example:unsigned' },
        fixedOptions,
      ),
    ).resolves.toEqual({ status: 'missing_signature' });

    await expect(
      checkTrustManifestSignature(
        {
          identity: 'did:example:unsigned',
          future: Number.NaN,
        } as unknown as TrustManifest,
        fixedOptions,
      ),
    ).rejects.toThrow(TypeError);
  });

  it.each([
    '',
    'one.two',
    'one.two.three',
    'one..two.three',
    `${fixedSignature}=`,
    `${fixedSignature}\n`,
    'e30..A',
    'e30.._x',
  ])('rejects a malformed detached compact serialization: %j', async (signature) => {
    await expect(
      checkTrustManifestSignature(
        { ...fixedManifest, signature },
        fixedOptions,
      ),
    ).resolves.toEqual({ status: 'invalid_jws' });
  });

  it('classifies an oversized canonical signature without decoding it', async () => {
    const oversizedSignature = 'A'.repeat(1_000_000);
    await expect(
      checkTrustManifestSignature(
        {
          ...fixedManifest,
          signature: `eyJhbGciOiJFUzI1NiJ9..${oversizedSignature}`,
        },
        fixedOptions,
      ),
    ).resolves.toEqual({ status: 'invalid_signature' });

    await expect(
      checkTrustManifestSignature(
        {
          ...fixedManifest,
          signature: `${encodeHeader({ alg: 'HS256' })}..${oversizedSignature}`,
        },
        fixedOptions,
      ),
    ).resolves.toEqual({
      status: 'algorithm_mismatch',
      algorithm: 'HS256',
    });

    await expect(
      checkTrustManifestSignature(
        {
          ...fixedManifest,
          signature: `${encodeHeader({ alg: 'ES256', crit: ['future'], future: true })}..${oversizedSignature}`,
        },
        fixedOptions,
      ),
    ).resolves.toEqual({ status: 'jws_feature_not_implemented' });
  });

  it.each([
    [`${Buffer.from([0xff]).toString('base64url')}..${'A'.repeat(86)}`],
    [`${encodeHeader(null)}..${'A'.repeat(86)}`],
    [`${encodeHeader([])}..${'A'.repeat(86)}`],
    [`${encodeHeader('header')}..${'A'.repeat(86)}`],
    [`${encodeHeader({})}..${'A'.repeat(86)}`],
    [`${encodeHeader({ alg: 1 })}..${'A'.repeat(86)}`],
  ])('rejects an invalid protected header', async (signature) => {
    await expect(
      checkTrustManifestSignature(
        { ...fixedManifest, signature },
        fixedOptions,
      ),
    ).resolves.toEqual({ status: 'invalid_jws' });
  });

  it.each(['none', 'HS256', 'ES384', 'es256']) (
    'reports the exact untrusted algorithm claim %s as a mismatch',
    async (algorithm) => {
      const manifest = signManifest(fixedManifest, { alg: algorithm });
      await expect(
        checkTrustManifestSignature(manifest, optionsFor()),
      ).resolves.toEqual({ status: 'algorithm_mismatch', algorithm });
    },
  );

  it('distinguishes unsupported critical features from malformed declarations', async () => {
    const unsupported = [
      signManifest(fixedManifest, {
        alg: 'ES256',
        b64: false,
        crit: ['b64'],
      }),
      signManifest(fixedManifest, {
        alg: 'ES256',
        crit: ['future'],
        future: true,
      }),
    ];
    for (const manifest of unsupported) {
      await expect(
        checkTrustManifestSignature(manifest, optionsFor()),
      ).resolves.toEqual({ status: 'jws_feature_not_implemented' });
    }

    const malformedHeaders = [
      { alg: 'ES256', crit: [] },
      { alg: 'ES256', crit: 'future', future: true },
      { alg: 'ES256', crit: ['future', 'future'], future: true },
      { alg: 'ES256', crit: ['missing'] },
      { alg: 'ES256', crit: ['alg'] },
      { alg: 'ES256', b64: false },
      { alg: 'ES256', b64: true },
      { alg: 'ES256', b64: 'true', crit: ['b64'] },
    ];
    for (const header of malformedHeaders) {
      await expect(
        checkTrustManifestSignature(
          signManifest(fixedManifest, header),
          optionsFor(),
        ),
      ).resolves.toEqual({ status: 'invalid_jws' });
    }

    await expect(
      checkTrustManifestSignature(
        signManifest(fixedManifest, {
          alg: 'ES256',
          b64: true,
          crit: ['b64'],
        }),
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'valid' });
  });

  it('does not resolve keys or follow key and certificate header fields', async () => {
    const fetch = vi.fn(() => {
      throw new Error('fetch must not be called');
    });
    vi.stubGlobal('fetch', fetch);
    const attackerJwk = otherKeys.publicKey.export({ format: 'jwk' });
    const protectedHeader = {
      alg: 'ES256',
      kid: 'attacker-key',
      jwk: attackerJwk,
      jku: 'https://attacker.example/keys.json',
      x5u: 'https://attacker.example/certificate.pem',
    };

    await expect(
      checkTrustManifestSignature(
        signManifest(fixedManifest, protectedHeader),
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'valid' });
    await expect(
      checkTrustManifestSignature(
        signManifest(fixedManifest, protectedHeader, otherKeys.privateKey),
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'invalid_signature' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('reports wrong keys, changed signatures, and wrong ES256 lengths', async () => {
    const manifest = signManifest(fixedManifest);
    await expect(
      checkTrustManifestSignature(manifest, optionsFor(otherKeys.publicKey)),
    ).resolves.toEqual({ status: 'invalid_signature' });

    const signatureBytes = Buffer.from(
      manifest.signature?.split('.')[2] ?? '',
      'base64url',
    );
    signatureBytes[0] ^= 1;
    await expect(
      checkTrustManifestSignature(
        replaceSignatureSegment(manifest, signatureBytes.toString('base64url')),
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'invalid_signature' });

    for (const length of [0, 63, 65]) {
      await expect(
        checkTrustManifestSignature(
          replaceSignatureSegment(
            manifest,
            Buffer.alloc(length).toString('base64url'),
          ),
          optionsFor(),
        ),
      ).resolves.toEqual({ status: 'invalid_signature' });
    }
  });

  it('rejects invalid options and incompatible native keys', async () => {
    const privateKey = trustedKeys.privateKey;
    const secretKey = createSecretKey(Buffer.alloc(32));
    const p384Key = generateKeyPairSync('ec', {
      namedCurve: 'secp384r1',
    }).publicKey;
    const noUsageCryptoKey = await webcrypto.subtle.importKey(
      'jwk',
      trustedKeys.publicKey.export({ format: 'jwk' }),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      [],
    );

    for (const publicKey of [
      privateKey,
      secretKey,
      p384Key,
      noUsageCryptoKey,
      {},
    ]) {
      await expect(
        checkTrustManifestSignature(fixedManifest, {
          publicKey,
          expectedAlgorithm: 'ES256',
        } as SignatureCheckOptions),
      ).rejects.toThrow(TypeError);
    }

    await expect(
      checkTrustManifestSignature(fixedManifest, null as never),
    ).rejects.toThrow(TypeError);
    await expect(
      checkTrustManifestSignature(fixedManifest, {
        publicKey: fixedPublicKey,
        expectedAlgorithm: 'ES384',
      } as unknown as SignatureCheckOptions),
    ).rejects.toThrow(TypeError);

    let getterReads = 0;
    const accessorOptions = { publicKey: fixedPublicKey };
    Object.defineProperty(accessorOptions, 'expectedAlgorithm', {
      get() {
        getterReads += 1;
        return 'ES256';
      },
    });
    await expect(
      checkTrustManifestSignature(
        fixedManifest,
        accessorOptions as SignatureCheckOptions,
      ),
    ).rejects.toThrow(TypeError);
    expect(getterReads).toBe(0);
  });

  it('snapshots the manifest and options before asynchronous verification', async () => {
    const manifest = signManifest({
      identity: 'did:example:snapshot',
      future: { nested: 'original' },
    } as TrustManifest & Record<string, JsonValue>) as TrustManifest &
      Record<string, JsonValue>;
    const options = optionsFor();

    const pending = checkTrustManifestSignature(manifest, options);
    manifest.identity = 'did:example:mutated';
    manifest.future = { nested: 'mutated' };
    manifest.signature = 'mutated';
    options.publicKey = otherKeys.publicKey;
    options.expectedAlgorithm = 'ES256';

    await expect(pending).resolves.toEqual({ status: 'valid' });
  });

  it('checks signatures without requiring schema-valid trust claims', async () => {
    const schemaInvalid = signManifest({ identity: 'not-a-uri' });
    await expect(
      checkTrustManifestSignature(schemaInvalid, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });
});
