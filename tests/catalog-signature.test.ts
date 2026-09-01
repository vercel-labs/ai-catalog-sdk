import { Buffer } from 'node:buffer';
import { generateKeyPairSync, sign, webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { AICatalog, JsonValue } from '../src/index.js';
import {
  checkCatalogSignature,
  createCatalogSignaturePayload,
  type SignatureCheckOptions,
} from '../src/verification.js';

const trustedKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const otherKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

function signCatalog(
  catalog: AICatalog,
  privateKey = trustedKeys.privateKey,
): AICatalog {
  const protectedSegment = Buffer.from(
    JSON.stringify({ alg: 'ES256' }),
  ).toString('base64url');
  const payloadSegment = Buffer.from(
    createCatalogSignaturePayload(catalog),
  ).toString('base64url');
  const signatureSegment = sign(
    'sha256',
    Buffer.from(`${protectedSegment}.${payloadSegment}`),
    { key: privateKey, dsaEncoding: 'ieee-p1363' },
  ).toString('base64url');
  return {
    ...catalog,
    signature: `${protectedSegment}..${signatureSegment}`,
  };
}

function optionsFor(
  publicKey: SignatureCheckOptions['publicKey'] = trustedKeys.publicKey,
): SignatureCheckOptions {
  return { publicKey, expectedAlgorithm: 'ES256' };
}

const unsignedCatalog = {
  specVersion: '1.0',
  host: {
    displayName: 'Example Catalog',
    identifier: 'example.com',
  },
  entries: [
    {
      identifier: 'remote',
      type: 'application/example',
      url: 'https://example.com/artifact',
      trustManifest: {
        identity: 'did:example:publisher',
        issuedAt: '2026-09-01T00:00:00Z',
        subject: {
          type: 'application/example',
          digest: `sha256:${'a'.repeat(64)}`,
        },
        signature: 'nested-trust-manifest-signature',
      },
    },
    {
      identifier: 'inline',
      type: 'application/example',
      data: { value: true },
    },
  ],
  extensions: { 'example.com/catalog': { environment: 'production' } },
  future: { retained: true },
} satisfies AICatalog & { future: JsonValue };

describe('checkCatalogSignature', () => {
  it('checks a catalog signature with both native public-key handles', async () => {
    const catalog = signCatalog(unsignedCatalog);

    await expect(
      checkCatalogSignature(catalog, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });

    const cryptoKey = await webcrypto.subtle.importKey(
      'jwk',
      trustedKeys.publicKey.export({ format: 'jwk' }),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    await expect(
      checkCatalogSignature(catalog, optionsFor(cryptoKey)),
    ).resolves.toEqual({ status: 'valid' });
  });

  it('covers catalog metadata, entry membership and order, and artifact locations', async () => {
    const catalog = signCatalog(unsignedCatalog);
    const [remoteEntry, inlineEntry] = catalog.entries;
    if (
      remoteEntry === undefined ||
      inlineEntry === undefined ||
      remoteEntry.trustManifest === undefined
    ) {
      throw new Error('The test catalog must contain two entries.');
    }
    const tamperedCatalogs: AICatalog[] = [
      { ...catalog, host: { displayName: 'Impostor Catalog' } },
      { ...catalog, entries: catalog.entries.slice(1) },
      { ...catalog, entries: [...catalog.entries].reverse() },
      {
        ...catalog,
        entries: [
          { ...remoteEntry, url: 'https://attacker.example/artifact' },
          inlineEntry,
        ],
      } as AICatalog,
      {
        ...catalog,
        entries: [remoteEntry, { ...inlineEntry, data: { value: false } }],
      } as AICatalog,
      {
        ...catalog,
        entries: [
          {
            ...remoteEntry,
            trustManifest: {
              ...remoteEntry.trustManifest,
              signature: 'tampered-nested-signature',
            },
          },
          inlineEntry,
        ],
      } as AICatalog,
      { ...catalog, extensions: { 'example.com/catalog': { environment: 'test' } } },
      { ...catalog, future: { retained: false } } as AICatalog,
    ];

    for (const tampered of tamperedCatalogs) {
      await expect(
        checkCatalogSignature(tampered, optionsFor()),
      ).resolves.toEqual({ status: 'invalid_signature' });
    }
  });

  it('integrates missing and malformed signature classification', async () => {
    await expect(
      checkCatalogSignature(unsignedCatalog, optionsFor()),
    ).resolves.toEqual({ status: 'missing_signature' });
    await expect(
      checkCatalogSignature(
        { ...unsignedCatalog, future: Number.NaN } as unknown as AICatalog,
        optionsFor(),
      ),
    ).rejects.toThrow(TypeError);
    await expect(
      checkCatalogSignature(
        { ...unsignedCatalog, signature: null } as unknown as AICatalog,
        optionsFor(),
      ),
    ).rejects.toThrow(
      new TypeError('catalog.signature must be a string when present.'),
    );
    await expect(
      checkCatalogSignature(
        { ...unsignedCatalog, signature: 'not-a-detached-jws' },
        optionsFor(),
      ),
    ).resolves.toEqual({ status: 'invalid_jws' });
    await expect(
      checkCatalogSignature(
        signCatalog(unsignedCatalog),
        optionsFor(otherKeys.publicKey),
      ),
    ).resolves.toEqual({ status: 'invalid_signature' });
  });

  it('checks signatures without requiring a schema-valid catalog', async () => {
    const schemaInvalid = signCatalog({
      specVersion: 'future',
      entries: [],
    } as AICatalog);

    await expect(
      checkCatalogSignature(schemaInvalid, optionsFor()),
    ).resolves.toEqual({ status: 'valid' });
  });

  it('snapshots the complete catalog and options before asynchronous verification', async () => {
    const catalog = signCatalog(structuredClone(unsignedCatalog)) as AICatalog & {
      future: JsonValue;
    };
    const options = optionsFor();

    const pending = checkCatalogSignature(catalog, options);
    catalog.host = { displayName: 'Mutated Catalog' };
    catalog.entries.reverse();
    catalog.future = { retained: false };
    catalog.signature = 'mutated';
    options.publicKey = otherKeys.publicKey;
    options.expectedAlgorithm = 'ES256';

    await expect(pending).resolves.toEqual({ status: 'valid' });
  });
});
