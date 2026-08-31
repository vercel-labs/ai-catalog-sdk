import { Buffer } from 'node:buffer';
import { createHash as createNodeHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';

import { afterEach, describe, expect, it, vi } from 'vitest';

const backend = vi.hoisted(() => ({ failure: undefined as unknown }));

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    createHash(algorithm: string) {
      if (backend.failure !== undefined) throw backend.failure;
      return actual.createHash(algorithm);
    },
  };
});

import {
  checkDigest,
  DigestAlgorithmUnavailableError,
} from '../src/verification.js';

const emptySha256 =
  'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const abcSha256 =
  'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

afterEach(() => {
  backend.failure = undefined;
});

describe('checkDigest', () => {
  it('matches fixed SHA-256 vectors and detects different bytes', () => {
    expect(checkDigest(new Uint8Array(), emptySha256)).toEqual({
      status: 'match',
    });
    expect(checkDigest(new TextEncoder().encode('abc'), abcSha256)).toEqual({
      status: 'match',
    });
    expect(checkDigest(new TextEncoder().encode('abd'), abcSha256)).toEqual({
      status: 'mismatch',
    });
  });

  it('accepts Buffer, cross-realm arrays, and the exact range of subviews', () => {
    expect(checkDigest(Buffer.from('abc'), abcSha256).status).toBe('match');

    const crossRealm = runInNewContext(
      'new Uint8Array([97, 98, 99])',
    ) as Uint8Array;
    expect(checkDigest(crossRealm, abcSha256).status).toBe('match');

    const backing = new Uint8Array([255, 97, 98, 99, 0]);
    expect(checkDigest(backing.subarray(1, 4), abcSha256).status).toBe('match');
  });

  it('does not mutate the supplied bytes', () => {
    const bytes = new Uint8Array([0, 255, 1, 254]);
    const before = bytes.slice();
    const expected = `sha256:${createNodeHash('sha256').update(bytes).digest('hex')}`;

    expect(checkDigest(bytes, expected).status).toBe('match');
    expect(bytes).toEqual(before);
  });

  it.each([
    '',
    'sha256',
    ':abc',
    'sha256:',
    'sha256:ABC',
    'sha256:abc:def',
    ' sha256:abc',
    'sha?256:abc',
    'sha256:abc',
    `sha256:${'a'.repeat(63)}`,
    `sha256:${'a'.repeat(65)}`,
  ])('reports malformed or incorrectly sized digest %j', (digest) => {
    expect(checkDigest(new Uint8Array(), digest)).toEqual({
      status: 'invalid_digest',
    });
  });

  it.each([
    ['SHA256', 'abc'],
    ['sha-256', 'a'],
    ['md5', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['sha512', 'a'],
  ])(
    'reports syntactically valid %s as not implemented',
    (algorithm, hex) => {
      expect(checkDigest(new Uint8Array(), `${algorithm}:${hex}`)).toEqual({
        status: 'algorithm_not_implemented',
        algorithm,
      });
    },
  );

  it('rejects wrong runtime argument types', () => {
    expect(() =>
      checkDigest(new Uint16Array() as unknown as Uint8Array, emptySha256),
    ).toThrow(TypeError);
    expect(() =>
      checkDigest(new Uint8Array(), 1 as unknown as string),
    ).toThrow(TypeError);
  });

  it('rejects detached and shared byte views', () => {
    const detached = new Uint8Array([1]);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    expect(() => checkDigest(detached, emptySha256)).toThrow(
      'bytes must not have a detached ArrayBuffer.',
    );

    const shared = new Uint8Array(new SharedArrayBuffer(1));
    expect(() => checkDigest(shared, emptySha256)).toThrow(
      'bytes must not be backed by a SharedArrayBuffer.',
    );
  });

  it('chains a registered backend failure', () => {
    const cause = new Error('backend failure');
    backend.failure = cause;

    let thrown: unknown;
    try {
      checkDigest(new Uint8Array(), emptySha256);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(DigestAlgorithmUnavailableError);
    expect(thrown).toMatchObject({
      name: 'DigestAlgorithmUnavailableError',
      algorithm: 'sha256',
      cause,
    });
  });

  it('classifies input before attempting to use the backend', () => {
    backend.failure = new Error('backend failure');

    expect(checkDigest(new Uint8Array(), 'sha256:abc')).toEqual({
      status: 'invalid_digest',
    });
    expect(checkDigest(new Uint8Array(), 'sha512:a')).toEqual({
      status: 'algorithm_not_implemented',
      algorithm: 'sha512',
    });
  });
});
