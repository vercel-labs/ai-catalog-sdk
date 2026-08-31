import { describe, expect, it, vi } from 'vitest';

const backend = vi.hoisted(() => ({ failure: undefined as unknown }));

vi.mock('canonicalize', () => ({
  default() {
    throw backend.failure;
  },
}));

import { canonicalizeJsonValueToBytes } from '../src/verification.js';

describe('canonicalizeJsonValueToBytes backend boundary', () => {
  it('normalizes an unexpected implementation error and preserves its cause', () => {
    const cause = new Error('backend failure');
    backend.failure = cause;

    let thrown: unknown;
    try {
      canonicalizeJsonValueToBytes({ value: true });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(TypeError);
    expect(thrown).toMatchObject({
      name: 'TypeError',
      message: 'The value could not be canonicalized as JSON.',
      cause,
    });
  });
});
