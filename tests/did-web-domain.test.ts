import { describe, expect, it } from 'vitest';
import { isDidWebDomain } from '../src/internal/did-web-domain.js';

describe('did:web IDNA domains', () => {
  it.each([
    'example.com',
    'ab--cd.example', // Ordinary ASCII hostname, without IDNA labels.
    'xn--bcher-kva.example',
    'xn--fa-hia.example',
    'xn--3xa.example',
    'xn--ll-0ea.example', // l·l: valid middle-dot context.
    '123.xn--bcher-kva.example',
    'a123.xn--4db.example',
  ])('accepts %s', (domain) => {
    expect(isDidWebDomain(domain)).toBe(true);
  });
  it.each([
    'xn--a', // Decodes to the disallowed U+0080 control character.
    'xn--a.example',
    'xn--g6h.example', // Heart symbol: UTS #46 accepts it, IDNA2008 does not.
    'xn--e28h.example', // Disallowed emoji.
    'xn--u-ccb.example', // Decoded label is not NFC.
    'xn--u-bcb.example', // Leading combining mark.
    'xn--ab-j1t.example', // Invalid zero-width non-joiner context.
    'xn--ab-0ea.example', // a·b: invalid middle-dot context.
    'xn--a-0hc.example', // Invalid mixture of Latin and Hebrew.
    'xn--0.example', // Invalid Punycode.
    '123.xn--4db.example', // Bidi rules also constrain ASCII sibling labels.
    'xn--4db.123.example',
  ])('rejects %s', (domain) => {
    expect(isDidWebDomain(domain)).toBe(false);
  });
});
