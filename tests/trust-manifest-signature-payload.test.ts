import { describe, expect, it } from 'vitest';

import type { JsonValue, TrustManifest } from '../src/index.js';
import { createTrustManifestSignaturePayload } from '../src/verification.js';

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const manifestWithFutureDepth = (depth: number): TrustManifest => {
  let future: JsonValue = null;
  for (let index = 0; index < depth; index += 1) {
    future = { next: future };
  }
  return { identity: 'did:example:alice', future } as TrustManifest;
};

describe('createTrustManifestSignaturePayload', () => {
  it('omits only the own top-level case-sensitive signature member', () => {
    const manifest = {
      identity: 'did:example:alice',
      signature: 'detached-jws',
      Signature: 'case-sensitive',
      extensions: {
        'example.com/trust': { signature: 'nested-extension', z: 1 },
      },
      future: { signature: 'nested-future' },
    } as TrustManifest & Record<string, JsonValue>;

    expect(decode(createTrustManifestSignaturePayload(manifest))).toBe(
      '{"Signature":"case-sensitive","extensions":{"example.com/trust":' +
        '{"signature":"nested-extension","z":1}},"future":' +
        '{"signature":"nested-future"},"identity":"did:example:alice"}',
    );
  });

  it('preserves an own __proto__ member safely', () => {
    const manifest = JSON.parse(
      '{"identity":"did:example:alice","signature":"detached-jws",' +
        '"__proto__":{"signature":"nested"}}',
    ) as TrustManifest;

    expect(decode(createTrustManifestSignaturePayload(manifest))).toBe(
      '{"__proto__":{"signature":"nested"},"identity":"did:example:alice"}',
    );
  });

  it('produces identical payloads for signed and unsigned forms', () => {
    const unsigned: TrustManifest = {
      identity: 'did:example:alice',
      issuedAt: '2026-08-31T00:00:00Z',
      subject: {
        identifier: 'example-artifact',
        type: 'application/example',
        digest: `sha256:${'a'.repeat(64)}`,
      },
    };
    const signed: TrustManifest = {
      ...unsigned,
      signature: 'detached-jws',
    };

    expect(createTrustManifestSignaturePayload(signed)).toEqual(
      createTrustManifestSignaturePayload(unsigned),
    );
  });

  it('does not require schema-valid evidence to create a payload', () => {
    const manifest: TrustManifest = { identity: 'did:example:alice' };
    expect(decode(createTrustManifestSignaturePayload(manifest))).toBe(
      '{"identity":"did:example:alice"}',
    );
  });

  it('returns fresh bytes without mutating the manifest', () => {
    const manifest: TrustManifest = {
      identity: 'did:example:alice',
      signature: 'detached-jws',
      trustSchema: { identifier: 'example', version: '1' },
    };
    const before = structuredClone(manifest);

    const first = createTrustManifestSignaturePayload(manifest);
    const second = createTrustManifestSignaturePayload(manifest);

    expect(first).not.toBe(second);
    first[0] = 0;
    expect(decode(second)).toBe(
      '{"identity":"did:example:alice","trustSchema":' +
        '{"identifier":"example","version":"1"}}',
    );
    expect(manifest).toEqual(before);
  });

  it('preserves frozen null-prototype inputs and their descriptors', () => {
    const manifest = Object.assign(Object.create(null), {
      identity: 'did:example:alice',
      signature: 'detached-jws',
      trustSchema: Object.freeze({ identifier: 'example', version: '1' }),
    }) as TrustManifest;
    Object.freeze(manifest);
    const before = Object.getOwnPropertyDescriptors(manifest);

    expect(decode(createTrustManifestSignaturePayload(manifest))).toBe(
      '{"identity":"did:example:alice","trustSchema":' +
        '{"identifier":"example","version":"1"}}',
    );
    expect(Object.getOwnPropertyDescriptors(manifest)).toEqual(before);
  });

  it('rejects top-level, nested, and signature accessors without reading them', () => {
    let reads = 0;
    const accessor = (key: string): TrustManifest => {
      const manifest = { identity: 'did:example:alice' };
      Object.defineProperty(manifest, key, {
        enumerable: true,
        get() {
          reads += 1;
          return 'value';
        },
      });
      return manifest;
    };
    const nested = { identity: 'did:example:alice', future: {} };
    Object.defineProperty(nested.future, 'value', {
      enumerable: true,
      get() {
        reads += 1;
        return true;
      },
    });

    expect(() => createTrustManifestSignaturePayload(accessor('future'))).toThrow(
      TypeError,
    );
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
      createTrustManifestSignaturePayload(proxied() as unknown as TrustManifest),
    ).toThrow(TypeError);
    expect(() =>
      createTrustManifestSignaturePayload({
        identity: 'did:example:alice',
        future: proxied(),
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
    expect(() =>
      createTrustManifestSignaturePayload({
        identity: 'did:example:alice',
        signature: proxied(),
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
    expect(traps).toBe(0);
  });

  it('rejects non-enumerable and non-JSON signature members', () => {
    const hidden = { identity: 'did:example:alice' };
    Object.defineProperty(hidden, 'signature', {
      value: 'detached-jws',
    });
    expect(() => createTrustManifestSignaturePayload(hidden)).toThrow(TypeError);

    expect(() =>
      createTrustManifestSignaturePayload({
        identity: 'did:example:alice',
        signature: () => 'detached-jws',
      } as unknown as TrustManifest),
    ).toThrow(TypeError);
  });

  it.each([null, 'manifest', 1, true, []])(
    'rejects a non-object manifest root: %#',
    (value) => {
      expect(() =>
        createTrustManifestSignaturePayload(value as unknown as TrustManifest),
      ).toThrow(TypeError);
    },
  );

  it('rejects a representative retained non-JSON member', () => {
    expect(() =>
      createTrustManifestSignaturePayload({
        identity: 'did:example:alice',
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
