import { describe, expect, it } from 'vitest';

import type { AICatalog, JsonValue } from '../src/index.js';
import { createCatalogSignaturePayload } from '../src/verification.js';

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const catalogWithFutureDepth = (depth: number): AICatalog => {
  let future: JsonValue = null;
  for (let index = 0; index < depth; index += 1) {
    future = { next: future };
  }
  return { specVersion: '1.0', entries: [], future } as AICatalog;
};

describe('createCatalogSignaturePayload', () => {
  it('omits only the own top-level case-sensitive signature member', () => {
    const catalog = {
      specVersion: '1.0',
      signature: 'detached-jws',
      Signature: 'case-sensitive',
      entries: [
        {
          identifier: 'remote',
          type: 'application/example',
          url: 'https://example.com/artifact',
          trustManifest: {
            identity: 'did:example:alice',
            signature: 'nested-trust-manifest-signature',
          },
        },
        {
          identifier: 'inline',
          type: 'application/example',
          data: { signature: 'inline-data-signature', z: 1 },
        },
      ],
      extensions: {
        'example.com/catalog': { signature: 'nested-extension' },
      },
      future: { signature: 'nested-future' },
      host: {
        displayName: 'Example Catalog',
        identifier: 'example.com',
      },
    } satisfies AICatalog & {
      Signature: string;
      future: { signature: string };
    };

    expect(decode(createCatalogSignaturePayload(catalog))).toBe(
      '{"Signature":"case-sensitive","entries":[' +
        '{"identifier":"remote","trustManifest":' +
        '{"identity":"did:example:alice","signature":' +
        '"nested-trust-manifest-signature"},"type":' +
        '"application/example","url":"https://example.com/artifact"},' +
        '{"data":{"signature":"inline-data-signature","z":1},' +
        '"identifier":"inline","type":"application/example"}],' +
        '"extensions":{"example.com/catalog":{"signature":' +
        '"nested-extension"}},"future":{"signature":"nested-future"},' +
        '"host":{"displayName":"Example Catalog","identifier":' +
        '"example.com"},"specVersion":"1.0"}',
    );
  });

  it('produces identical payloads for signed and unsigned forms', () => {
    const unsigned: AICatalog = {
      specVersion: '1.0',
      entries: [],
      host: { displayName: 'Example Catalog' },
    };
    const signed: AICatalog = {
      ...unsigned,
      signature: 'detached-jws',
    };

    expect(createCatalogSignaturePayload(signed)).toEqual(
      createCatalogSignaturePayload(unsigned),
    );
  });

  it('does not require a schema-valid catalog to create a payload', () => {
    const catalog = { specVersion: 'future', entries: [] } as AICatalog;

    expect(decode(createCatalogSignaturePayload(catalog))).toBe(
      '{"entries":[],"specVersion":"future"}',
    );
  });

  it('returns fresh bytes without mutating the catalog', () => {
    const catalog: AICatalog = {
      specVersion: '1.0',
      signature: 'detached-jws',
      entries: [
        {
          identifier: 'inline',
          type: 'application/example',
          data: { z: 1, a: 2 },
        },
      ],
    };
    const before = structuredClone(catalog);

    const first = createCatalogSignaturePayload(catalog);
    const second = createCatalogSignaturePayload(catalog);

    expect(first).not.toBe(second);
    first[0] = 0;
    expect(decode(second)).toBe(
      '{"entries":[{"data":{"a":2,"z":1},"identifier":"inline",' +
        '"type":"application/example"}],"specVersion":"1.0"}',
    );
    expect(catalog).toEqual(before);
  });

  it('preserves an own __proto__ member safely', () => {
    const catalog = JSON.parse(
      '{"specVersion":"1.0","entries":[],"signature":"detached-jws",' +
        '"__proto__":{"signature":"nested"}}',
    ) as AICatalog;

    expect(decode(createCatalogSignaturePayload(catalog))).toBe(
      '{"__proto__":{"signature":"nested"},"entries":[],' +
        '"specVersion":"1.0"}',
    );
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

  it.each([null, 'catalog', 1, true, []])(
    'rejects a non-object catalog root: %#',
    (value) => {
      expect(() =>
        createCatalogSignaturePayload(value as unknown as AICatalog),
      ).toThrow(new TypeError('catalog must be a plain JSON object.'));
    },
  );

  it('retains the canonicalization resource limits', () => {
    expect(() =>
      createCatalogSignaturePayload(catalogWithFutureDepth(127)),
    ).not.toThrow();
    expect(() =>
      createCatalogSignaturePayload(catalogWithFutureDepth(128)),
    ).toThrow(RangeError);
  });
});
