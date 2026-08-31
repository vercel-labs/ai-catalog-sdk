import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';

import type { JsonValue } from '../src/index.js';
import {
  canonicalizeJsonValueToBytes,
  checkDigest,
} from '../src/verification.js';

// Conformance vectors come from RFC 8785 and the RFC authors' Apache-2.0
// reference suite at commit 19d51d7fe467d4706a3ff08adf8a748f29fc21e0.
const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

const nestedValue = (depth: number): JsonValue => {
  let value: JsonValue = null;
  for (let index = 0; index < depth; index += 1) {
    value = { next: value };
  }
  return value;
};

const numberFromIeee754 = (hex: string): number => {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
};

describe('canonicalizeJsonValueToBytes', () => {
  it('matches the RFC 8785 primitive and UTF-8 vector', () => {
    const value = {
      numbers: [Number('333333333.33333329'), 1e30, 4.5, 2e-3, 1e-27],
      string: `€$\u000f\nA'B"\\\\"/`,
      literals: [null, true, false],
    };
    const expectedHex =
      '7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c' +
      '226e756d62657273223a5b3333333333333333332e333333333333332c3165' +
      '2b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22' +
      'e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d';

    expect(Buffer.from(canonicalizeJsonValueToBytes(value)).toString('hex')).toBe(
      expectedHex,
    );
  });

  it('sorts property names by UTF-16 code units', () => {
    const value = {
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '\ufb33': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '\ud83d\ude00': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      '\u00f6': 'Latin Small Letter O With Diaeresis',
    };
    const expected =
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control",' +
      '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",' +
      '"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}';

    expect(decode(canonicalizeJsonValueToBytes(value))).toBe(expected);
  });

  it('matches reference-suite structure vectors and preserves array order', () => {
    const value = [56, { d: true, '10': null, '1': [] }];
    expect(decode(canonicalizeJsonValueToBytes(value))).toBe(
      '[56,{"1":[],"10":null,"d":true}]',
    );

    const structure = {
      '1': { f: { f: 'hi', F: 5 }, '\n': 56 },
      '10': {},
      '': 'empty',
      a: {},
      '111': [{ e: 'yes', E: 'no' }],
      A: {},
    };
    expect(decode(canonicalizeJsonValueToBytes(structure))).toBe(
      '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},' +
        '"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}',
    );
  });

  it('matches the reference-suite locale and Unicode vectors', () => {
    const french = {
      peach: 'This sorting order',
      péché: 'is wrong according to French',
      pêche: 'but canonicalization MUST',
      sin: 'ignore locale',
    };
    expect(decode(canonicalizeJsonValueToBytes(french))).toBe(
      '{"peach":"This sorting order","péché":"is wrong according to French",' +
        '"pêche":"but canonicalization MUST","sin":"ignore locale"}',
    );
    expect(
      decode(
        canonicalizeJsonValueToBytes({
          'Unnormalized Unicode': 'A\u030a',
        }),
      ),
    ).toBe('{"Unnormalized Unicode":"Å"}');
  });

  it('matches the reference-suite weird-property vector', () => {
    const value = {
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '\n': 'Newline',
      '1': 'One',
      '\u0080': 'Control\u007f',
      '\ud83d\ude02': 'Smiley',
      '\u00f6': 'Latin Small Letter O With Diaeresis',
      '\ufb33': 'Hebrew Letter Dalet With Dagesh',
      '</script>': 'Browser Challenge',
    };
    const expected =
      '{"\\n":"Newline","\\r":"Carriage Return","1":"One",' +
      '"</script>":"Browser Challenge","\u0080":"Control\u007f",' +
      '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",' +
      '"😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}';
    expect(decode(canonicalizeJsonValueToBytes(value))).toBe(expected);
  });

  it('preserves Unicode normalization form and canonicalizes negative zero', () => {
    expect(decode(canonicalizeJsonValueToBytes('A\u030a'))).toBe('"Å"');
    expect(decode(canonicalizeJsonValueToBytes(-0))).toBe('0');
  });

  it('canonicalizes a string as a value instead of parsing it as source', () => {
    expect(decode(canonicalizeJsonValueToBytes('{"x":1}'))).toBe(
      '"{\\"x\\":1}"',
    );
  });

  it.each([
    ['0000000000000000', '0'],
    ['8000000000000000', '0'],
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555554', '333333333.33333325'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555556', '333333333.3333334'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
  ])('matches RFC 8785 number vector %s', (hex, expected) => {
    const value = numberFromIeee754(hex);
    expect(decode(canonicalizeJsonValueToBytes(value))).toBe(expected);
  });

  it('accepts frozen, null-prototype, shared, and own __proto__ values', () => {
    const shared = Object.freeze({ value: true });
    const nullPrototype = Object.assign(Object.create(null), {
      second: shared,
      first: shared,
    }) as JsonValue;
    expect(decode(canonicalizeJsonValueToBytes(nullPrototype))).toBe(
      '{"first":{"value":true},"second":{"value":true}}',
    );

    const ownProto = JSON.parse('{"__proto__":{"b":1}}') as JsonValue;
    expect(decode(canonicalizeJsonValueToBytes(ownProto))).toBe(
      '{"__proto__":{"b":1}}',
    );
  });

  it('returns fresh bytes without mutating the input', () => {
    const value = { b: [2, 1], a: true };
    const before = structuredClone(value);
    const first = canonicalizeJsonValueToBytes(value);
    const second = canonicalizeJsonValueToBytes(value);

    expect(first).not.toBe(second);
    first[0] = 0;
    expect(decode(second)).toBe('{"a":true,"b":[2,1]}');
    expect(value).toEqual(before);
  });

  it('composes its exact output bytes with checkDigest', () => {
    const bytes = canonicalizeJsonValueToBytes({ b: 2, a: 1 });
    const result = checkDigest(
      bytes,
      'sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777',
    );
    expect(result).toEqual({ status: 'match' });
  });

  it.each([
    undefined,
    1n,
    Symbol('x'),
    () => {},
    Number.NaN,
    Number.POSITIVE_INFINITY,
    new Date(0),
  ])('rejects non-JSON input %# with TypeError', (value) => {
    expect(() =>
      canonicalizeJsonValueToBytes(value as unknown as JsonValue),
    ).toThrow(TypeError);
  });

  it('rejects cycles, sparse and decorated arrays, and custom prototypes', () => {
    const circular: Record<string, JsonValue> = {};
    circular.self = circular;
    expect(() => canonicalizeJsonValueToBytes(circular)).toThrow(TypeError);
    expect(() =>
      canonicalizeJsonValueToBytes(Array(1) as JsonValue[]),
    ).toThrow(TypeError);

    const decorated = [1] as number[] & { extra?: number };
    decorated.extra = 2;
    expect(() => canonicalizeJsonValueToBytes(decorated)).toThrow(TypeError);

    const inherited = Object.create({ inherited: true }) as JsonValue;
    expect(() => canonicalizeJsonValueToBytes(inherited)).toThrow(TypeError);
  });

  it('rejects accessors, toJSON methods, and proxies without invoking them', () => {
    let reads = 0;
    const accessor = {};
    Object.defineProperty(accessor, 'secret', {
      enumerable: true,
      get() {
        reads += 1;
        return true;
      },
    });
    expect(() =>
      canonicalizeJsonValueToBytes(accessor as JsonValue),
    ).toThrow(TypeError);
    expect(reads).toBe(0);

    const withToJson = {
      value: true,
      toJSON() {
        reads += 1;
        return { value: false };
      },
    };
    expect(() =>
      canonicalizeJsonValueToBytes(withToJson as unknown as JsonValue),
    ).toThrow(TypeError);
    expect(reads).toBe(0);

    const proxy = new Proxy(
      { value: true },
      {
        get(target, key, receiver) {
          reads += 1;
          return Reflect.get(target, key, receiver);
        },
      },
    );
    expect(() => canonicalizeJsonValueToBytes(proxy)).toThrow(TypeError);
    expect(reads).toBe(0);
  });

  it('rejects non-enumerable and symbol members', () => {
    const hidden = {};
    Object.defineProperty(hidden, 'value', { value: true });
    expect(() => canonicalizeJsonValueToBytes(hidden as JsonValue)).toThrow(
      TypeError,
    );
    expect(() =>
      canonicalizeJsonValueToBytes({
        [Symbol('x')]: true,
      } as unknown as JsonValue),
    ).toThrow(TypeError);
  });

  it.each([
    '\ud800',
    '\udead',
    '\ufdd0',
    '\ufffe',
    String.fromCodePoint(0x1fffe),
    String.fromCodePoint(0x10ffff),
  ])('rejects forbidden I-JSON code points in values and names', (text) => {
    expect(() => canonicalizeJsonValueToBytes(text)).toThrow(TypeError);
    expect(() => canonicalizeJsonValueToBytes({ [text]: true })).toThrow(
      TypeError,
    );
  });

  it('accepts valid supplementary-plane Unicode scalar values', () => {
    expect(
      decode(
        canonicalizeJsonValueToBytes({
          [String.fromCodePoint(0x10fffd)]: '😀',
        }),
      ),
    ).toBe('{"􏿽":"😀"}');
  });

  it('enforces exact nesting-depth limits', () => {
    expect(() => canonicalizeJsonValueToBytes(nestedValue(128))).not.toThrow();
    expect(() => canonicalizeJsonValueToBytes(nestedValue(129))).toThrow(
      RangeError,
    );
  });

  it('enforces exact occurrence-count limits for shared values', () => {
    const shared = Object.freeze({});
    expect(() =>
      canonicalizeJsonValueToBytes(Array(99_999).fill(shared)),
    ).not.toThrow();
    expect(() =>
      canonicalizeJsonValueToBytes(Array(100_000).fill(shared)),
    ).toThrow(RangeError);
  });
});
