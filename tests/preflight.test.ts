import { describe, expect, it } from 'vitest';

import { safeParseCatalog } from '../src/index.js';

const minimal = (future?: unknown) => ({
  specVersion: '1.0',
  entries: [],
  ...(future === undefined ? {} : { future }),
});

describe('programmatic JSON preflight', () => {
  it('rejects direct and indirect cycles', () => {
    const direct: Record<string, unknown> = {};
    direct.self = direct;
    expect(safeParseCatalog(minimal(direct)).success).toBe(false);

    const first: Record<string, unknown> = {};
    const second: Record<string, unknown> = { first };
    first.second = second;
    expect(safeParseCatalog(minimal(first)).success).toBe(false);
  });

  it('accepts shared acyclic subobjects and null-prototype objects', () => {
    const shared = { value: true };
    expect(
      safeParseCatalog(minimal({ first: shared, second: shared })).success,
    ).toBe(true);
    const catalog = Object.assign(Object.create(null), {
      specVersion: '1.0',
      entries: [],
    });
    expect(safeParseCatalog(catalog).success).toBe(true);
    expect(safeParseCatalog(Object.freeze(minimal())).success).toBe(true);
  });

  it('counts a shared subobject on every occurrence at the node boundary', () => {
    const shared = Object.freeze({});
    expect(safeParseCatalog(minimal(Array(99_996).fill(shared))).success).toBe(
      true,
    );
    expect(safeParseCatalog(minimal(Array(99_997).fill(shared))).success).toBe(
      false,
    );
  });

  it('rejects non-JSON primitives and non-finite numbers', () => {
    for (const value of [undefined, 1n, Symbol('x'), () => {}, NaN, Infinity]) {
      expect(
        safeParseCatalog({ specVersion: '1.0', entries: [], future: value })
          .success,
      ).toBe(false);
    }
  });

  it('rejects sparse arrays, extra array properties, and custom prototypes', () => {
    expect(safeParseCatalog(minimal(Array(1_000_000))).success).toBe(false);
    const extra = [1] as number[] & { extra?: number };
    extra.extra = 2;
    expect(safeParseCatalog(minimal(extra)).success).toBe(false);
    expect(safeParseCatalog(minimal(new Date())).success).toBe(false);
    expect(
      safeParseCatalog(minimal(Object.create({ inherited: true }))).success,
    ).toBe(false);
  });

  it('rejects accessors without invoking them', () => {
    let reads = 0;
    const value = {};
    Object.defineProperty(value, 'secret', {
      enumerable: true,
      get() {
        reads += 1;
        return true;
      },
    });
    expect(safeParseCatalog(minimal(value)).success).toBe(false);
    expect(reads).toBe(0);
  });

  it('rejects non-enumerable values, symbols, and own __proto__', () => {
    const hidden = {};
    Object.defineProperty(hidden, 'value', { value: true });
    expect(safeParseCatalog(minimal(hidden)).success).toBe(false);
    expect(safeParseCatalog(minimal({ [Symbol('x')]: true })).success).toBe(
      false,
    );
    expect(
      safeParseCatalog(
        JSON.parse(
          '{"specVersion":"1.0","entries":[],"future":{"__proto__":{}}}',
        ),
      ).success,
    ).toBe(false);
  });

  it('enforces exact nesting depth boundaries', () => {
    let atBoundary: unknown = null;
    for (let index = 0; index < 128; index += 1) {
      atBoundary = { next: atBoundary };
    }
    expect(safeParseCatalog(minimal(atBoundary)).success).toBe(false);

    let accepted: unknown = null;
    for (let index = 0; index < 127; index += 1) {
      accepted = { next: accepted };
    }
    expect(safeParseCatalog(minimal(accepted)).success).toBe(true);
  });

  it('enforces exact node-count boundaries root-inclusively', () => {
    expect(safeParseCatalog(minimal(Array(99_996).fill(null))).success).toBe(
      true,
    );
    expect(safeParseCatalog(minimal(Array(99_997).fill(null))).success).toBe(
      false,
    );
  });

  it('rejects oversized dense arrays before enumerating their keys', () => {
    const result = safeParseCatalog(minimal(Array(2_000_000).fill(null)));
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.code).toBe('resource_limit');
    }
  });

  it('does not claim to sandbox hostile proxies', () => {
    const proxy = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('proxy trap');
        },
      },
    );
    expect(() => safeParseCatalog(minimal(proxy))).toThrow('proxy trap');
  });
});
