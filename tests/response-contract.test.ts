import { describe, expect, it } from 'vitest';

import { hasPublicAccessHeaders } from '../src/internal/response-contract.js';

const declarations = 'Access-Control-Allow-Origin, Access-Control-Expose-Headers';
const headers = {
  'access-control-allow-origin': '*',
  'access-control-expose-headers': declarations,
};

describe('public response contract', () => {
  it('permits document access without requiring an advertisement', () => {
    expect(hasPublicAccessHeaders(headers)).toBe(true);
    expect(hasPublicAccessHeaders(headers, true)).toBe(false);
    expect(hasPublicAccessHeaders({
      ...headers,
      'access-control-expose-headers': `${declarations}, Link`,
    }, true)).toBe(true);
  });

  it('accepts case-insensitive exposure names and surrounding whitespace', () => {
    expect(hasPublicAccessHeaders({
      'access-control-allow-origin': ' * ',
      'access-control-expose-headers': ' LINK, ACCESS-Control-Allow-Origin , Access-Control-Expose-Headers ',
    }, true)).toBe(true);
  });

  it('accepts wildcard exposure for credential-free requests', () => {
    expect(hasPublicAccessHeaders({ ...headers, 'access-control-expose-headers': '*' }, true)).toBe(true);
  });

  it.each([
    {},
    { ...headers, 'access-control-allow-origin': undefined },
    { ...headers, 'access-control-allow-origin': 'https://application.example' },
    { ...headers, 'access-control-allow-origin': '*, *' },
    { ...headers, 'access-control-expose-headers': undefined },
    { ...headers, 'access-control-expose-headers': 'Link' },
    { ...headers, 'access-control-expose-headers': 'Access-Control-Allow-Origin' },
    { ...headers, 'access-control-expose-headers': `${declarations}, not a header` },
  ])('rejects an incomplete or invalid declaration: %j', (response) => {
    expect(hasPublicAccessHeaders(response)).toBe(false);
  });
});
