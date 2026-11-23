import { afterEach, describe, expect, it } from 'vitest';

import { configure } from '../src/configure.js';

afterEach(() => configure({ requirePublicAccessHeaders: false }));

describe('configure', () => {
  it.each([null, [], 'enabled', 1, { requirePublicAccessHeaders: 'true' }, { requirePublicAccessHeaders: 1 }])(
    'rejects malformed configuration: %j',
    (value) => expect(() => configure(value as never)).toThrow(TypeError),
  );
});
