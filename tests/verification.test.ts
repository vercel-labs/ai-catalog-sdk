import { Buffer } from 'node:buffer';
import { createHash as createNodeHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { JsonValue } from '../src/index.js';

const backend = vi.hoisted(() => ({ failure: undefined as unknown }));

beforeEach(() => {
  const digest = crypto.subtle.digest.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, 'digest').mockImplementation((...arguments_) => {
    if (backend.failure !== undefined) return Promise.reject(backend.failure);
    return digest(...arguments_);
  });
});

import {
  checkDigest,
  createDigest,
  DigestAlgorithmUnavailableError,
  type DigestAlgorithm,
} from '../src/verification.js';

const emptySha256 =
  'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const abcSha256 =
  'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const abcSha384 =
  'sha384:cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7';
const abcSha512 =
  'sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';

afterEach(() => {
  backend.failure = undefined;
  vi.restoreAllMocks();
});

describe('createDigest', () => {
  it('defaults to SHA-256 and formats a fixed byte vector', async () => {
    expect(await createDigest(new TextEncoder().encode('abc'))).toBe(abcSha256);
  });

  it.each([
    ['sha256', abcSha256],
    ['sha384', abcSha384],
    ['sha512', abcSha512],
  ] as const)('creates a fixed %s digest', async (algorithm, expected) => {
    expect(await createDigest(Buffer.from('abc'), algorithm)).toBe(expected);
  });

  it('hashes byte subviews and cross-realm byte arrays without JSON encoding', async () => {
    const backing = new Uint8Array([255, 97, 98, 99, 0]);
    expect(await createDigest(backing.subarray(1, 4))).toBe(abcSha256);
    expect(await createDigest(runInNewContext('new Uint8Array([97, 98, 99])')))
      .toBe(abcSha256);
  });

  it('canonicalizes object keys, strings, and ordinary arrays as JSON values', async () => {
    const cases: [JsonValue, string][] = [
      [{ b: 2, a: 1 }, '{"a":1,"b":2}'],
      ['abc', '"abc"'],
      ['{"a":1}', '"{\\"a\\":1}"'],
      [[97, 98, 99], '[97,98,99]'],
    ];
    for (const [value, canonicalJson] of cases) {
      const expected = `sha256:${createNodeHash('sha256')
        .update(canonicalJson)
        .digest('hex')}`;
      expect(await createDigest(value)).toBe(expected);
    }
  });

  it('rejects invalid JSON values and unstable byte storage', async () => {
    await expect(createDigest(Number.NaN)).rejects.toThrow(TypeError);
    const detached = new Uint8Array([1]);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    await expect(createDigest(detached)).rejects.toThrow(TypeError);
    await expect(createDigest(new Uint8Array(new SharedArrayBuffer(1)))).rejects
      .toThrow(TypeError);
  });

  it('rejects unsupported algorithm arguments', async () => {
    await expect(createDigest(null, 'md5' as DigestAlgorithm)).rejects.toThrow(TypeError);
  });

  it('preserves the algorithm and cause when hashing is unavailable', async () => {
    const cause = new Error('backend failure');
    backend.failure = cause;
    let thrown: unknown;
    try {
      await createDigest(Buffer.from('abc'), 'sha384');
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(DigestAlgorithmUnavailableError);
    expect(thrown).toMatchObject({ algorithm: 'sha384', cause });
  });
});

describe('checkDigest', () => {
  it('matches fixed SHA-256 vectors and detects different bytes', async () => {
    expect(await checkDigest(new Uint8Array(), emptySha256)).toEqual({
      status: 'match',
    });
    expect(await checkDigest(new TextEncoder().encode('abc'), abcSha256)).toEqual({
      status: 'match',
    });
    expect(await checkDigest(new TextEncoder().encode('abd'), abcSha256)).toEqual({
      status: 'mismatch',
    });
  });

  it.each([
    ['SHA-384', abcSha384],
    ['SHA-512', abcSha512],
  ])('matches a fixed %s vector and detects different bytes', async (_name, digest) => {
    expect(await checkDigest(new TextEncoder().encode('abc'), digest)).toEqual({
      status: 'match',
    });
    expect(await checkDigest(new TextEncoder().encode('abd'), digest)).toEqual({
      status: 'mismatch',
    });
  });

  it.each(['sha256', 'sha384', 'sha512'] as const)(
    'checks canonical JSON with %s and detects a different value',
    async (algorithm) => {
      const expected = `${algorithm}:${createNodeHash(algorithm)
        .update('{"a":1,"b":2}')
        .digest('hex')}`;
      const value = Object.freeze({ b: 2, a: 1 });
      expect(await checkDigest(value, expected)).toEqual({ status: 'match' });
      expect(await checkDigest({ a: 1, b: 3 }, expected)).toEqual({
        status: 'mismatch',
      });
    },
  );

  it('checks strings, ordinary arrays, and primitives as JSON values', async () => {
    const cases: [JsonValue, string][] = [
      ['abc', '"abc"'],
      ['{"a":1}', '"{\\"a\\":1}"'],
      [[97, 98, 99], '[97,98,99]'],
      [null, 'null'],
      [true, 'true'],
      [false, 'false'],
      [-0, '0'],
      [1.5, '1.5'],
    ];
    for (const [value, canonicalJson] of cases) {
      const expected = `sha256:${createNodeHash('sha256')
        .update(canonicalJson)
        .digest('hex')}`;
      expect(await checkDigest(value, expected)).toEqual({ status: 'match' });
    }
    expect(await checkDigest('abc', abcSha256)).toEqual({ status: 'mismatch' });
    expect(await checkDigest([97, 98, 99], abcSha256)).toEqual({
      status: 'mismatch',
    });
  });

  it('rejects invalid JSON without executing accessors', async () => {
    const forbidden = vi.fn(() => {
      throw new Error('must not execute');
    });
    const accessor = Object.defineProperty({}, 'value', {
      enumerable: true,
      get: forbidden,
    });
    const cyclic: JsonValue[] = [];
    cyclic.push(cyclic);
    for (const value of [
      undefined,
      Number.NaN,
      '\ud800',
      new Date(),
      Array(1),
      cyclic,
      accessor,
    ]) {
      await expect(checkDigest(value as JsonValue, emptySha256)).rejects.toThrow(
        TypeError,
      );
    }
    expect(forbidden).not.toHaveBeenCalled();
  });

  it('validates the value before classifying malformed or unsupported digests', async () => {
    let tooDeep: JsonValue = null;
    for (let index = 0; index < 129; index += 1) tooDeep = [tooDeep];
    const detached = new Uint8Array([1]);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    const shared = new Uint8Array(new SharedArrayBuffer(1));
    for (const digest of ['sha256:abc', 'future:a']) {
      for (const value of [Number.NaN, detached, shared]) {
        await expect(checkDigest(value, digest)).rejects.toThrow(TypeError);
      }
      await expect(checkDigest(tooDeep, digest)).rejects.toThrow(RangeError);
    }
    await expect(checkDigest(Array(100_000).fill(null), emptySha256)).rejects.toThrow(
      RangeError,
    );
  });

  it('accepts Buffer, cross-realm arrays, and the exact range of subviews', async () => {
    expect((await checkDigest(Buffer.from('abc'), abcSha256)).status).toBe('match');

    const crossRealm = runInNewContext(
      'new Uint8Array([97, 98, 99])',
    ) as Uint8Array;
    expect((await checkDigest(crossRealm, abcSha256)).status).toBe('match');

    const backing = new Uint8Array([255, 97, 98, 99, 0]);
    expect((await checkDigest(backing.subarray(1, 4), abcSha256)).status).toBe('match');
  });

  it('does not mutate the supplied bytes', async () => {
    const bytes = new Uint8Array([0, 255, 1, 254]);
    const before = bytes.slice();
    const expected = `sha256:${createNodeHash('sha256').update(bytes).digest('hex')}`;

    expect((await checkDigest(bytes, expected)).status).toBe('match');
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
    `sha384:${'a'.repeat(95)}`,
    `sha384:${'a'.repeat(97)}`,
    `sha512:${'a'.repeat(127)}`,
    `sha512:${'a'.repeat(129)}`,
  ])('reports malformed or incorrectly sized digest %j', async (digest) => {
    expect(await checkDigest(new Uint8Array(), digest)).toEqual({
      status: 'invalid_digest',
    });
  });

  it.each([
    ['SHA256', 'abc'],
    ['sha-256', 'a'],
    ['md5', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['sha3-256', 'a'],
  ])(
    'reports syntactically valid %s as not implemented',
    async (algorithm, hex) => {
      expect(await checkDigest(new Uint8Array(), `${algorithm}:${hex}`)).toEqual({
        status: 'algorithm_not_implemented',
        algorithm,
      });
    },
  );

  it('rejects wrong runtime argument types', async () => {
    await expect(checkDigest(new Uint16Array() as unknown as Uint8Array, emptySha256)).rejects.toThrow(TypeError);
    await expect(checkDigest(new Uint8Array(), 1 as unknown as string)).rejects.toThrow(TypeError);
  });

  it('rejects detached and shared byte views', async () => {
    const detached = new Uint8Array([1]);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    await expect(checkDigest(detached, emptySha256)).rejects.toThrow(
      'bytes must not have a detached ArrayBuffer.',
    );

    const shared = new Uint8Array(new SharedArrayBuffer(1));
    await expect(checkDigest(shared, emptySha256)).rejects.toThrow(
      'bytes must not be backed by a SharedArrayBuffer.',
    );
  });

  it.each([
    ['sha256', emptySha256],
    ['sha384', abcSha384],
    ['sha512', abcSha512],
  ])('chains a registered %s backend failure', async (algorithm, digest) => {
    const cause = new Error('backend failure');
    backend.failure = cause;

    let thrown: unknown;
    try {
      await checkDigest(new TextEncoder().encode('abc'), digest);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(DigestAlgorithmUnavailableError);
    expect(thrown).toMatchObject({
      name: 'DigestAlgorithmUnavailableError',
      algorithm,
      cause,
    });
  });

  it('classifies input before attempting to use the backend', async () => {
    backend.failure = new Error('backend failure');

    expect(await checkDigest(new Uint8Array(), 'sha256:abc')).toEqual({
      status: 'invalid_digest',
    });
    expect(await checkDigest(new Uint8Array(), 'sha512:a')).toEqual({
      status: 'invalid_digest',
    });
    expect(await checkDigest(new Uint8Array(), 'sha3-256:a')).toEqual({
      status: 'algorithm_not_implemented',
      algorithm: 'sha3-256',
    });
  });

  it('preserves JSON digest backend failures and skips hashing invalid declarations', async () => {
    const cause = new Error('backend failure');
    backend.failure = cause;
    expect(await checkDigest({ a: 1 }, 'sha256:abc')).toEqual({
      status: 'invalid_digest',
    });
    expect(await checkDigest({ a: 1 }, 'future:a')).toEqual({
      status: 'algorithm_not_implemented',
      algorithm: 'future',
    });
    let thrown: unknown;
    try {
      await checkDigest({ a: 1 }, abcSha384);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(DigestAlgorithmUnavailableError);
    expect(thrown).toMatchObject({ algorithm: 'sha384', cause });
  });
});
