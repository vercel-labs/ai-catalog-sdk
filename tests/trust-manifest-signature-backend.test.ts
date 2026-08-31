import { createPublicKey } from 'node:crypto';

import {
  JOSEAlgNotAllowed,
  JOSEError,
  JOSENotSupported,
} from 'jose/errors';
import { describe, expect, it, vi } from 'vitest';

const backend = vi.hoisted(() => ({ failure: undefined as unknown }));

vi.mock('jose/jws/flattened/verify', () => ({
  async flattenedVerify() {
    throw backend.failure;
  },
}));

import type { TrustManifest } from '../src/index.js';
import { checkTrustManifestSignature } from '../src/verification.js';

const manifest: TrustManifest = {
  identity: 'did:example:alice',
  issuedAt: '2026-03-15T10:00:00Z',
  subject: {
    digest:
      'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    type: 'application/json',
  },
  signature:
    'eyJhbGciOiJFUzI1NiJ9..' +
    'NKmmKrtfVExTyrPwimVozLDtLRAZP0r29iJYkrBRAR7rFsM3UqsXFFH3htDDVUKWPJ-UjvgFQqOWDT97iDzT0A',
};
const publicKey = createPublicKey({
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  },
  format: 'jwk',
});

describe('checkTrustManifestSignature backend boundary', () => {
  it('does not expose an unexpected jose error as its thrown error', async () => {
    const cause = new JOSEAlgNotAllowed('backend failure');
    backend.failure = cause;

    let thrown: unknown;
    try {
      await checkTrustManifestSignature(manifest, {
        publicKey,
        expectedAlgorithm: 'ES256',
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).not.toBeInstanceOf(JOSEError);
    expect(thrown).toMatchObject({
      message: 'The JWS verification backend failed unexpectedly.',
      cause,
    });
  });

  it('does not classify a backend capability error as a message feature', async () => {
    const cause = new JOSENotSupported('backend capability failure');
    backend.failure = cause;

    await expect(
      checkTrustManifestSignature(manifest, {
        publicKey,
        expectedAlgorithm: 'ES256',
      }),
    ).rejects.toMatchObject({
      message: 'The JWS verification backend failed unexpectedly.',
      cause,
    });
  });

  it('does not misclassify an unknown backend exception as a JWS result', async () => {
    const cause = new Error('unknown backend failure');
    backend.failure = cause;

    await expect(
      checkTrustManifestSignature(manifest, {
        publicKey,
        expectedAlgorithm: 'ES256',
      }),
    ).rejects.toBe(cause);
  });
});
