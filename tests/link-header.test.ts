import { describe, expect, it } from 'vitest';

import { firstCatalogLink } from '../src/internal/link-header.js';

describe('HTTP Link catalog selection', () => {
  it('finds the first exact case-insensitive relation token across header lines', () => {
    expect(firstCatalogLink([
      '<wrong>; rel="ai-catalog-extra", <also-wrong>; rel="other-ai-catalog"',
      '<first>; ReL="alternate\tAI-CATALOG next", <second>; rel=ai-catalog',
    ])).toBe('first');
    expect(firstCatalogLink(undefined)).toBeUndefined();
  });

  it('handles commas and semicolons in targets and quoted parameters', () => {
    expect(firstCatalogLink(
      '<ignored>; title="comma, and semi; colon"; rel=alternate, ' +
      '<catalog,part;version.json>; title="escaped \\" quote, comma; semi"; rel="ai-catalog"',
    )).toBe('catalog,part;version.json');
  });

  it('uses only the first rel parameter and skips links with an anchor', () => {
    expect(firstCatalogLink(
      '<wrong>; rel=alternate; rel=ai-catalog, ' +
      '<anchored>; rel=ai-catalog; AnChOr="/different", ' +
      '<selected>; rel=ai-catalog; rel=alternate',
    )).toBe('selected');
    expect(firstCatalogLink('<wrong>; rel=""; rel=ai-catalog')).toBeUndefined();
  });

  it('decodes quoted escapes while matching tokens', () => {
    expect(firstCatalogLink('<catalog>; rel="ai-\\catalog"')).toBe('catalog');
  });

  it('returns selected references without URL validation or skipping unsafe targets', () => {
    expect(firstCatalogLink(
      '<http://127.0.0.1/catalog>; rel=ai-catalog, <https://safe.example/catalog>; rel=ai-catalog',
    )).toBe('http://127.0.0.1/catalog');
    expect(firstCatalogLink('<https://[malformed>; rel=ai-catalog')).toBe('https://[malformed');
    expect(firstCatalogLink('<>; rel=ai-catalog')).toBe('');
  });

  it('ignores malformed link syntax and relations without a matching token', () => {
    expect(firstCatalogLink('not-a-link; rel=ai-catalog, <catalog>; rel="alternate"')).toBeUndefined();
    expect(firstCatalogLink('<catalog> junk; rel=ai-catalog')).toBeUndefined();
    expect(firstCatalogLink('<catalog>; rel="ai-catalog"junk')).toBeUndefined();
  });
});
