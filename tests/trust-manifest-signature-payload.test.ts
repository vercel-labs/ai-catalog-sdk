import { describe, expect, it } from 'vitest';

import type { TrustManifest, JsonValue } from '../src/index.js';
import { createTrustManifestSignaturePayload } from '../src/verification.js';

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
const metadata = {
  signer: 'did:example:alice',
  profile: 'custom-profile',
  issuedAt: '2026-08-31T00:00:00Z',
};
const manifestWithFutureDepth = (depth: number): TrustManifest => {
  let future: JsonValue = null;
  for (let index = 0; index < depth; index += 1) future = { next: future };
  return { contributor: 'did:example:alice', future } as TrustManifest;
};

describe('createTrustManifestSignaturePayload', () => {
  it('omits only immediate signature.jws and additionalSignatures while retaining metadata', () => {
    const manifest = {
      ...{ contributor: 'did:example:alice' },
      signature: { ...metadata, jws: 'detached-jws', future: true },
      additionalSignatures: [{ anything: true }],
      Signature: 'case-sensitive',
      future: {
        signature: { jws: 'nested' },
        additionalSignatures: ['nested'],
      },
    } as TrustManifest & Record<string, JsonValue>;
    const payload = JSON.parse(
      decode(createTrustManifestSignaturePayload(manifest)),
    );
    expect(payload).toEqual({
      ...{ contributor: 'did:example:alice' },
      signature: { ...metadata, future: true },
      Signature: 'case-sensitive',
      future: {
        signature: { jws: 'nested' },
        additionalSignatures: ['nested'],
      },
    });
    expect(decode(createTrustManifestSignaturePayload(manifest))).toMatch(
      /"issuedAt":"2026-08-31T00:00:00Z","profile":"custom-profile","signer":"did:example:alice"/,
    );
  });

  it('accepts pre-sign metadata and produces the same payload after adding jws', () => {
    const preSign = {
      ...{ contributor: 'did:example:alice' },
      signature: metadata,
    };
    const signed = {
      ...preSign,
      signature: { ...metadata, jws: 'detached-jws' },
    };
    expect(createTrustManifestSignaturePayload(signed)).toEqual(
      createTrustManifestSignaturePayload(preSign),
    );
    const changed = {
      ...signed,
      signature: { ...signed.signature, profile: 'another-profile' },
    };
    expect(createTrustManifestSignaturePayload(changed)).not.toEqual(
      createTrustManifestSignaturePayload(signed),
    );
  });

  it('does not require a schema-valid document to create a payload', () => {
    const manifest = { contributor: 'did:example:alice' };
    expect(
      JSON.parse(decode(createTrustManifestSignaturePayload(manifest))),
    ).toEqual(manifest);
  });

  it('returns fresh bytes and preserves frozen null-prototype inputs', () => {
    const manifest = Object.assign(Object.create(null), {
      ...{ contributor: 'did:example:alice' },
      signature: Object.freeze({ ...metadata, jws: 'detached-jws' }),
    }) as TrustManifest;
    Object.freeze(manifest);
    const before = Object.getOwnPropertyDescriptors(manifest);
    const first = createTrustManifestSignaturePayload(manifest);
    const second = createTrustManifestSignaturePayload(manifest);
    expect(first).not.toBe(second);
    first[0] = 0;
    expect(second[0]).toBe(123);
    expect(Object.getOwnPropertyDescriptors(manifest)).toEqual(before);
  });

  it('preserves an own __proto__ member safely', () => {
    const manifest = JSON.parse(
      '{"contributor":"did:example:alice","signature":{"jws":"omitted"},"__proto__":{"signature":"nested"}}',
    ) as TrustManifest;
    const payload = JSON.parse(
      decode(createTrustManifestSignaturePayload(manifest)),
    );
    expect(Object.hasOwn(payload, '__proto__')).toBe(true);
    expect(payload.__proto__).toEqual({ signature: 'nested' });
    expect(payload.signature).toEqual({});
  });

  it('rejects top-level, nested, and signature accessors without reading them', () => {
    let reads = 0;
    const accessor = (key: string): TrustManifest => {
      const manifest = { contributor: 'did:example:alice' };
      Object.defineProperty(manifest, key, {
        enumerable: true,
        get() {
          reads += 1;
          return 'value';
        },
      });
      return manifest;
    };
    const nested = { contributor: 'did:example:alice', future: {} };
    Object.defineProperty(nested.future, 'value', {
      enumerable: true,
      get() {
        reads += 1;
        return true;
      },
    });

    expect(() =>
      createTrustManifestSignaturePayload(accessor('future')),
    ).toThrow(TypeError);
    expect(() =>
      createTrustManifestSignaturePayload(nested as TrustManifest),
    ).toThrow(TypeError);
    expect(() =>
      createTrustManifestSignaturePayload(accessor('signature')),
    ).toThrow(TypeError);
    expect(reads).toBe(0);
  });

  it('rejects root, nested, and signature proxies without invoking traps', () => {
    let traps = 0;
    const proxied = () =>
      new Proxy(
        { value: true },
        {
          get(target, key, receiver) {
            traps += 1;
            return Reflect.get(target, key, receiver);
          },
          getOwnPropertyDescriptor(target, key) {
            traps += 1;
            return Reflect.getOwnPropertyDescriptor(target, key);
          },
          getPrototypeOf(target) {
            traps += 1;
            return Reflect.getPrototypeOf(target);
          },
          ownKeys(target) {
            traps += 1;
            return Reflect.ownKeys(target);
          },
        },
      );

    expect(() =>
      createTrustManifestSignaturePayload(
        proxied() as unknown as TrustManifest,
      ),
    ).toThrow(TypeError);
    expect(() =>
      createTrustManifestSignaturePayload({
        contributor: 'did:example:alice',
        future: proxied(),
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
    expect(() =>
      createTrustManifestSignaturePayload({
        contributor: 'did:example:alice',
        signature: proxied(),
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
    expect(traps).toBe(0);
  });

  it('rejects non-enumerable and non-JSON signature members', () => {
    const hidden = { contributor: 'did:example:alice' };
    Object.defineProperty(hidden, 'signature', {
      value: 'detached-jws',
    });
    expect(() => createTrustManifestSignaturePayload(hidden)).toThrow(
      TypeError,
    );

    expect(() =>
      createTrustManifestSignaturePayload({
        contributor: 'did:example:alice',
        signature: () => 'detached-jws',
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
  });

  it.each([
    null,
    'manifest',
    1,
    true,
    [],
  ])('rejects a non-object manifest root: %#', (value) => {
    expect(() =>
      createTrustManifestSignaturePayload(value as unknown as TrustManifest),
    ).toThrow(TypeError);
  });

  it('rejects a representative retained non-JSON member', () => {
    expect(() =>
      createTrustManifestSignaturePayload({
        contributor: 'did:example:alice',
        future: Number.NaN,
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
  });

  it('retains the canonicalization resource limits', () => {
    expect(() =>
      createTrustManifestSignaturePayload(manifestWithFutureDepth(127)),
    ).not.toThrow();
    expect(() =>
      createTrustManifestSignaturePayload(manifestWithFutureDepth(128)),
    ).toThrow(RangeError);
  });
});
