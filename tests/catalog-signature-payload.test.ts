import { describe, expect, it } from 'vitest';

import type { AICatalog, JsonValue } from '../src/index.js';
import { createCatalogSignaturePayload } from '../src/verification.js';

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
const metadata = {
  signer: 'did:example:alice',
  profile: 'custom-profile',
  issuedAt: '2026-08-31T00:00:00Z',
};
const catalogWithFutureDepth = (depth: number): AICatalog => {
  let future: JsonValue = null;
  for (let index = 0; index < depth; index += 1) future = { next: future };
  return { specVersion: '1.0', entries: [], future } as AICatalog;
};

describe('createCatalogSignaturePayload', () => {
  it('omits only immediate signature.jws and additionalSignatures while retaining metadata', () => {
    const catalog = {
      ...{ specVersion: '1.0', entries: [] },
      signature: { ...metadata, jws: 'detached-jws', future: true },
      additionalSignatures: [{ anything: true }],
      Signature: 'case-sensitive',
      future: {
        signature: { jws: 'nested' },
        additionalSignatures: ['nested'],
      },
    } as AICatalog & Record<string, JsonValue>;
    const payload = JSON.parse(decode(createCatalogSignaturePayload(catalog)));
    expect(payload).toEqual({
      ...{ specVersion: '1.0', entries: [] },
      signature: { ...metadata, future: true },
      Signature: 'case-sensitive',
      future: {
        signature: { jws: 'nested' },
        additionalSignatures: ['nested'],
      },
    });
    expect(decode(createCatalogSignaturePayload(catalog))).toMatch(
      /"issuedAt":"2026-08-31T00:00:00Z","profile":"custom-profile","signer":"did:example:alice"/,
    );
  });

  it('accepts pre-sign metadata and produces the same payload after adding jws', () => {
    const preSign = {
      ...{ specVersion: '1.0', entries: [] },
      signature: metadata,
    };
    const signed = {
      ...preSign,
      signature: { ...metadata, jws: 'detached-jws' },
    };
    expect(createCatalogSignaturePayload(signed)).toEqual(
      createCatalogSignaturePayload(preSign),
    );
    const changed = {
      ...signed,
      signature: { ...signed.signature, profile: 'another-profile' },
    };
    expect(createCatalogSignaturePayload(changed)).not.toEqual(
      createCatalogSignaturePayload(signed),
    );
  });

  it('does not require a schema-valid document to create a payload', () => {
    const catalog = { specVersion: '1.0', entries: [] };
    expect(JSON.parse(decode(createCatalogSignaturePayload(catalog)))).toEqual(
      catalog,
    );
  });

  it('returns fresh bytes and preserves frozen null-prototype inputs', () => {
    const catalog = Object.assign(Object.create(null), {
      ...{ specVersion: '1.0', entries: [] },
      signature: Object.freeze({ ...metadata, jws: 'detached-jws' }),
    }) as AICatalog;
    Object.freeze(catalog);
    const before = Object.getOwnPropertyDescriptors(catalog);
    const first = createCatalogSignaturePayload(catalog);
    const second = createCatalogSignaturePayload(catalog);
    expect(first).not.toBe(second);
    first[0] = 0;
    expect(second[0]).toBe(123);
    expect(Object.getOwnPropertyDescriptors(catalog)).toEqual(before);
  });

  it('preserves an own __proto__ member safely', () => {
    const catalog = JSON.parse(
      '{"specVersion":"1.0","entries":[],"signature":{"jws":"omitted"},"__proto__":{"signature":"nested"}}',
    ) as AICatalog;
    const payload = JSON.parse(decode(createCatalogSignaturePayload(catalog)));
    expect(Object.hasOwn(payload, '__proto__')).toBe(true);
    expect(payload.__proto__).toEqual({ signature: 'nested' });
    expect(payload.signature).toEqual({});
  });

  it('rejects accessors without reading them, including the omitted member', () => {
    let reads = 0;
    const catalog: AICatalog = { specVersion: '1.0', entries: [] };
    Object.defineProperty(catalog, 'signature', {
      enumerable: true,
      get() {
        reads += 1;
        return 'detached-jws';
      },
    });

    expect(() => createCatalogSignaturePayload(catalog)).toThrow(TypeError);
    expect(reads).toBe(0);
  });

  it('rejects proxies without invoking traps, including nested values', () => {
    let traps = 0;
    const proxied = () =>
      new Proxy(
        { value: true },
        {
          get() {
            traps += 1;
            return true;
          },
          getOwnPropertyDescriptor() {
            traps += 1;
            return undefined;
          },
          getPrototypeOf() {
            traps += 1;
            return Object.prototype;
          },
          ownKeys() {
            traps += 1;
            return [];
          },
        },
      );

    expect(() =>
      createCatalogSignaturePayload(proxied() as unknown as AICatalog),
    ).toThrow(TypeError);
    expect(() =>
      createCatalogSignaturePayload({
        specVersion: '1.0',
        entries: [],
        signature: proxied(),
      } as unknown as AICatalog),
    ).toThrow(TypeError);
    expect(traps).toBe(0);
  });

  it('rejects non-enumerable and non-JSON signature members', () => {
    const hidden: AICatalog = { specVersion: '1.0', entries: [] };
    Object.defineProperty(hidden, 'signature', {
      value: 'detached-jws',
    });
    expect(() => createCatalogSignaturePayload(hidden)).toThrow(TypeError);

    expect(() =>
      createCatalogSignaturePayload({
        specVersion: '1.0',
        entries: [],
        signature: () => 'detached-jws',
      } as unknown as AICatalog),
    ).toThrow(TypeError);
  });

  it.each([
    null,
    'catalog',
    1,
    true,
    [],
  ])('rejects a non-object catalog root: %#', (value) => {
    expect(() =>
      createCatalogSignaturePayload(value as unknown as AICatalog),
    ).toThrow(new TypeError('catalog must be a plain JSON object.'));
  });

  it('retains the canonicalization resource limits', () => {
    expect(() =>
      createCatalogSignaturePayload(catalogWithFutureDepth(127)),
    ).not.toThrow();
    expect(() =>
      createCatalogSignaturePayload(catalogWithFutureDepth(128)),
    ).toThrow(RangeError);
  });
});
