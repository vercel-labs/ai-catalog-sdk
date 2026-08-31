import type { CatalogIssue } from '../types.js';

const MAX_DEPTH = 128;
const MAX_NODES = 100_000;

type Path = readonly (string | number)[];

interface EnterFrame {
  kind: 'enter';
  value: unknown;
  path: Path;
  depth: number;
}

interface ExitFrame {
  kind: 'exit';
  value: object;
}

type PreflightFrame = EnterFrame | ExitFrame;

interface JsonValuePreflightOptions {
  allowOwnProtoMember: boolean;
  isDisallowedObject: ((value: object) => boolean) | undefined;
  requireIJsonStrings: boolean;
}

function issue(code: string, path: Path, message: string): CatalogIssue {
  return { code, path, message };
}

function isUnicodeNoncharacter(codePoint: number): boolean {
  return (
    (codePoint >= 0xfdd0 && codePoint <= 0xfdef) ||
    (codePoint & 0xffff) >= 0xfffe
  );
}

function hasInvalidIJsonCodePoint(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      const codePoint =
        ((codeUnit - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
      if (isUnicodeNoncharacter(codePoint)) return true;
      index += 1;
      continue;
    }
    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) return true;
    if (isUnicodeNoncharacter(codeUnit)) return true;
  }
  return false;
}

/**
 * Checks whether programmatic input is a bounded JSON value without invoking
 * accessors. Options keep parser preservation rules separate from I-JSON
 * canonicalization rules.
 */
export function preflightJsonValue(
  input: unknown,
  options: JsonValuePreflightOptions,
): CatalogIssue | undefined {
  const active = new WeakSet<object>();
  const stack: PreflightFrame[] = [
    { kind: 'enter', value: input, path: [], depth: 0 },
  ];
  let nodeCount = 0;

  while (stack.length > 0) {
    const frame = stack.pop();
    if (!frame) break;

    if (frame.kind === 'exit') {
      active.delete(frame.value);
      continue;
    }

    nodeCount += 1;
    if (nodeCount > MAX_NODES) {
      return issue(
        'resource_limit',
        frame.path,
        'The JSON value exceeds the supported node limit.',
      );
    }
    if (frame.depth > MAX_DEPTH) {
      return issue(
        'resource_limit',
        frame.path,
        'The JSON value exceeds the supported nesting depth.',
      );
    }

    const value = frame.value;
    if (value === null || typeof value === 'boolean') continue;
    if (typeof value === 'string') {
      if (
        options.requireIJsonStrings &&
        hasInvalidIJsonCodePoint(value)
      ) {
        return issue(
          'invalid_json_value',
          frame.path,
          'I-JSON strings must not contain Unicode surrogates or noncharacters.',
        );
      }
      continue;
    }
    if (typeof value === 'number') {
      if (Number.isFinite(value)) continue;
      return issue(
        'invalid_json_value',
        frame.path,
        'JSON numbers must be finite.',
      );
    }
    if (typeof value !== 'object') {
      return issue(
        'invalid_json_value',
        frame.path,
        'The value contains a type that JSON cannot represent.',
      );
    }

    if (active.has(value)) {
      return issue(
        'invalid_json_value',
        frame.path,
        'The value contains a cycle.',
      );
    }

    if (options.isDisallowedObject?.(value)) {
      return issue(
        'invalid_json_value',
        frame.path,
        'Programmatic input must not contain Proxy objects.',
      );
    }

    const isArray = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (
      (isArray && prototype !== Array.prototype) ||
      (!isArray && prototype !== Object.prototype && prototype !== null)
    ) {
      return issue(
        'invalid_json_value',
        frame.path,
        'Programmatic input must use plain JSON objects and arrays.',
      );
    }

    active.add(value);
    stack.push({ kind: 'exit', value });

    if (isArray) {
      if (nodeCount + value.length > MAX_NODES) {
        return issue(
          'resource_limit',
          frame.path,
          'The JSON value exceeds the supported node limit.',
        );
      }
      const keys = Reflect.ownKeys(value);
      let indexCount = 0;
      for (const key of keys) {
        if (key === 'length') continue;
        if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key)) {
          return issue(
            'invalid_json_value',
            frame.path,
            'JSON arrays cannot contain extra properties.',
          );
        }
        const index = Number(key);
        if (!Number.isSafeInteger(index) || index >= value.length) {
          return issue(
            'invalid_json_value',
            frame.path,
            'JSON arrays contain only canonical array indexes.',
          );
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
          return issue(
            'invalid_json_value',
            [...frame.path, index],
            'JSON array items must be enumerable data properties.',
          );
        }
        indexCount += 1;
        stack.push({
          kind: 'enter',
          value: descriptor.value,
          path: [...frame.path, index],
          depth: frame.depth + 1,
        });
      }
      if (indexCount !== value.length) {
        return issue(
          'invalid_json_value',
          frame.path,
          'Sparse JSON arrays are not supported.',
        );
      }
      continue;
    }

    const keys = Reflect.ownKeys(value);
    for (const key of keys) {
      if (typeof key !== 'string') {
        return issue(
          'invalid_json_value',
          frame.path,
          'JSON objects cannot contain symbol keys.',
        );
      }
      if (
        options.requireIJsonStrings &&
        hasInvalidIJsonCodePoint(key)
      ) {
        return issue(
          'invalid_json_value',
          [...frame.path, key],
          'I-JSON strings must not contain Unicode surrogates or noncharacters.',
        );
      }
      if (!options.allowOwnProtoMember && key === '__proto__') {
        return issue(
          'invalid_json_value',
          [...frame.path, key],
          'An own __proto__ member cannot be preserved safely.',
        );
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
        return issue(
          'invalid_json_value',
          [...frame.path, key],
          'JSON object members must be enumerable data properties.',
        );
      }
      stack.push({
        kind: 'enter',
        value: descriptor.value,
        path: [...frame.path, key],
        depth: frame.depth + 1,
      });
    }
  }

  return undefined;
}
