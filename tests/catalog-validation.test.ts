import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';

import {
  type AICatalog,
  assertValidCatalog,
  type CatalogIssue,
  CatalogValidationError,
  parseCatalog,
  type Signature,
  type TrustManifest,
} from '../src/index.js';
import { invalidDeclarationFixtures } from './fixtures.js';

const digest = `sha256:${'a'.repeat(64)}`;
const contributor = 'did:web:example.com';
const typ = 'ai-catalog-trust-manifest+jws';

function detachedJws(
  header: Record<string, unknown> = { alg: 'ES256', typ },
): string {
  return `${Buffer.from(JSON.stringify(header)).toString('base64url')}..${Buffer.alloc(64).toString('base64url')}`;
}

function signature(fields: Partial<Signature> = {}): Signature {
  return {
    signer: contributor,
    profile: 'https://example.com/profiles/custom-v1',
    issuedAt: '2026-01-01T00:00:00Z',
    jws: detachedJws(),
    ...fields,
  };
}

function catalogFor(manifest?: TrustManifest): AICatalog {
  return {
    specVersion: '1.0',
    entries: [
      {
        identifier: 'urn:air:example.com:artifact:one',
        type: 'application/json',
        data: null,
        digest,
        trustManifests: [
          manifest ?? {
            contributor,
            subject: {
              identifier: 'urn:air:example.com:artifact:one',
              type: 'application/json',
              digest,
            },
            signature: signature(),
          },
        ],
      },
    ],
  };
}

function validationIssues(input: unknown): readonly CatalogIssue[] {
  try {
    assertValidCatalog(input);
  } catch (error) {
    expect(error).toBeInstanceOf(CatalogValidationError);
    return (error as CatalogValidationError).issues;
  }
  throw new Error('Expected author validation to fail.');
}

function firstManifest(catalog: AICatalog): TrustManifest {
  const manifest = catalog.entries[0]?.trustManifests?.[0];
  if (!manifest) throw new Error('Missing fixture manifest.');
  return manifest;
}

describe('assertValidCatalog', () => {
  it('accepts unsigned catalogs and returns no useful value', () => {
    const catalog = {
      specVersion: '1.0',
      entries: [{ identifier: 'x', type: 'custom', data: null }],
    };
    expect(assertValidCatalog(catalog)).toBeUndefined();
    expect(catalog).toEqual({
      specVersion: '1.0',
      entries: [{ identifier: 'x', type: 'custom', data: null }],
    });
  });

  it('accepts an assembled signed catalog without checking signature cryptography or current time', () => {
    const catalog = catalogFor();
    const manifest = firstManifest(catalog);
    manifest.signature = signature({
      issuedAt: '2000-01-01T00:00:00Z',
      expiresAt: '2001-01-01T00:00:00Z',
    });
    const before = structuredClone(catalog);
    assertValidCatalog(catalog);
    expect(catalog).toEqual(before);
    expect(manifest.signature.jws).toBe(detachedJws());
  });

  it('preserves rather than transforms compatible unknown fields', () => {
    const input = {
      ...catalogFor(),
      specVersion: '1.99',
      futureCatalog: { nested: ['x', null] },
    };
    const originalFuture = input.futureCatalog;
    assertValidCatalog(input);
    expect(input.futureCatalog).toBe(originalFuture);
    expect(input.futureCatalog).toEqual({ nested: ['x', null] });
  });

  it.each(
    invalidDeclarationFixtures.map((input, index) => [index, input] as const),
  )('rejects invalid author fixture %s', (_index, input) => {
    expect(validationIssues(input).length).toBeGreaterThan(0);
  });

  it.each([
    [undefined, undefined, true],
    ['1.0', '1.0', true],
    ['', '', true],
    ['1.0', '1.0.0', false],
    ['1.0', undefined, false],
    [undefined, '1.0', false],
    ['', undefined, false],
    [undefined, '', false],
  ] as const)('checks exact version presence and values: entry=%j subject=%j', (entryVersion, subjectVersion, valid) => {
    const catalog = catalogFor();
    const entry = catalog.entries[0];
    const manifest = firstManifest(catalog);
    if (!entry || !manifest.subject) throw new Error('Missing fixture entry.');
    if (entryVersion !== undefined) entry.version = entryVersion;
    if (subjectVersion !== undefined) manifest.subject.version = subjectVersion;
    if (valid) expect(() => assertValidCatalog(catalog)).not.toThrow();
    else
      expect(validationIssues(catalog)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            code: 'inconsistent_value',
            path: ['entries', 0, 'trustManifests', 0, 'subject', 'version'],
          }),
        ]),
      );
  });

  it.each([
    ['identifier', 'other'],
    ['type', 'application/other'],
    ['digest', `sha256:${'b'.repeat(64)}`],
  ] as const)('identifies the mismatched subject %s', (field, value) => {
    const catalog = catalogFor();
    const subject = firstManifest(catalog).subject;
    if (!subject) throw new Error('Missing fixture subject.');
    subject[field] = value;
    expect(validationIssues(catalog)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'inconsistent_value',
          path: ['entries', 0, 'trustManifests', 0, 'subject', field],
        }),
      ]),
    );
  });

  it('checks contributor attribution without authenticating either identity', () => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature({
      signer: 'did:web:another.example',
    });
    expect(validationIssues(catalog)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ['entries', 0, 'trustManifests', 0, 'signature', 'signer'],
        }),
      ]),
    );
  });

  it.each([
    { issuedAt: 'yesterday' },
    { expiresAt: 'not a timestamp' },
  ])('checks signature timestamp syntax: %j', (fields) => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature(fields);
    expect(
      validationIssues(catalog).some((issue) =>
        issue.path.includes('signature'),
      ),
    ).toBe(true);
  });

  it('requires an entry digest when a signed contribution is attached', () => {
    const catalog = catalogFor();
    const entry = catalog.entries[0];
    if (!entry) throw new Error('Missing fixture entry.');
    delete entry.digest;
    expect(validationIssues(catalog)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: ['entries', 0, 'digest'] }),
      ]),
    );
  });

  it('reports duplicate paths using original input indexes', () => {
    const entry = { identifier: 'x', type: 'custom', data: null };
    const input = {
      specVersion: '1.0',
      entries: [{ ...entry, identifier: 'other' }, entry, entry],
    };
    expect(validationIssues(input)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'duplicate_entry',
          path: ['entries', 2, 'identifier'],
        }),
      ]),
    );
  });

  it.each([
    [undefined, undefined, false],
    ['1', '1', false],
    ['1', '2', true],
    ['1', undefined, false],
  ] as const)('checks catalog release uniqueness: %j and %j', (first, second, valid) => {
    const entry = { identifier: 'x', type: 'custom', data: null };
    const input = {
      specVersion: '1.0',
      entries: [
        { ...entry, ...(first === undefined ? {} : { version: first }) },
        { ...entry, ...(second === undefined ? {} : { version: second }) },
      ],
    };
    if (valid) expect(() => assertValidCatalog(input)).not.toThrow();
    else
      expect(
        validationIssues(input).some(
          (issue) => issue.code === 'duplicate_entry',
        ),
      ).toBe(true);
  });

  it.each([
    ['2026-01-01T00:00:00.0001Z', '2026-01-01T00:00:00.0002Z', true],
    ['2026-01-01T00:00:00.0002Z', '2026-01-01T00:00:00.0001Z', false],
    ['2026-01-01T00:00:00Z', '2026-01-01T01:00:00+01:00', false],
    ['2016-12-31T23:59:59.99999Z', '2016-12-31T23:59:60Z', true],
    ['2016-12-31T23:59:60.5Z', '2017-01-01T00:00:00Z', true],
    ['2017-01-01T00:00:00Z', '2016-12-31T23:59:60.5Z', false],
  ] as const)('orders signature instants %s and %s', (issuedAt, expiresAt, valid) => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature({ issuedAt, expiresAt });
    if (valid) expect(() => assertValidCatalog(catalog)).not.toThrow();
    else
      expect(
        validationIssues(catalog).some((issue) =>
          issue.path.includes('expiresAt'),
        ),
      ).toBe(true);
  });

  it('permits a did:web assessor without treating it as the entry publisher', () => {
    const catalog = catalogFor();
    const assessor = 'did:web:auditor.example';
    const manifest = firstManifest(catalog);
    manifest.contributor = assessor;
    manifest.signature = signature({
      signer: assessor,
      profile: 'did-web-v1',
      jws: detachedJws({ alg: 'ES256', typ, kid: `${assessor}#key1` }),
    });
    expect(() => assertValidCatalog(catalog)).not.toThrow();
  });

  it.each([
    { alg: 'ES384', typ, kid: `${contributor}#key1` },
    { alg: 'ES256', typ, kid: 'did:web:someone-else.example#key1' },
  ])('checks local requirements of a declared known profile: %j', (header) => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature({
      profile: 'did-web-v1',
      jws: detachedJws(header),
    });
    expect(
      validationIssues(catalog).some((issue) =>
        issue.path.includes('signature'),
      ),
    ).toBe(true);
  });

  it('checks catalog signature representation without assigning catalog-operator authority', () => {
    const catalog = catalogFor();
    catalog.host = {
      displayName: 'Operator',
      identifier: 'did:web:another.example',
    };
    catalog.signature = signature({
      profile: 'did-web-v1',
      jws: detachedJws({
        alg: 'ES256',
        typ: 'ai-catalog+jws',
        kid: `${contributor}#key1`,
      }),
    });
    expect(() => assertValidCatalog(catalog)).not.toThrow();
    catalog.signature.jws = detachedJws({
      alg: 'ES256',
      typ,
      kid: `${contributor}#key1`,
    });
    expect(validationIssues(catalog)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: ['signature', 'jws'] }),
      ]),
    );
  });

  it('allows unknown well-formed profiles, algorithms, and critical extensions', () => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature({
      profile: 'https://example.com/profiles/future-v1',
      jws: detachedJws({
        alg: 'FutureAlgorithm',
        typ,
        crit: ['future'],
        future: true,
      }),
    });
    expect(() => assertValidCatalog(catalog)).not.toThrow();
  });

  it('preserves independent profile names when parsing but requires absolute URI identifiers when authoring', () => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature({ profile: 'future-profile' });
    expect(parseCatalog(catalog)).toEqual(catalog);
    expect(validationIssues(catalog)).toEqual([
      expect.objectContaining({
        path: ['entries', 0, 'trustManifests', 0, 'signature', 'profile'],
      }),
    ]);
  });

  it.each([
    'not-a-jws',
    detachedJws({ alg: 'none', typ }),
    detachedJws({ alg: 'ES256', typ: 'wrong' }),
    detachedJws({ alg: 'ES256', typ, b64: true }),
  ])('rejects malformed or forbidden JWS declarations: %s', (jws) => {
    const catalog = catalogFor();
    firstManifest(catalog).signature = signature({ jws });
    expect(
      validationIssues(catalog).some((issue) => issue.path.includes('jws')),
    ).toBe(true);
  });

  it('rejects incorrect known digest lengths without hashing artifact content', () => {
    const catalog = catalogFor();
    const entry = catalog.entries[0];
    const manifest = firstManifest(catalog);
    if (!entry || !manifest.subject) throw new Error('Missing fixture entry.');
    entry.digest = 'sha256:00';
    manifest.subject.digest = entry.digest;
    expect(
      validationIssues(catalog).some((issue) => issue.path.includes('digest')),
    ).toBe(true);
    entry.digest = digest;
    manifest.subject.digest = digest;
    expect(() => assertValidCatalog(catalog)).not.toThrow();
  });

  it('rejects unencodable signed payloads but preserves unrelated unsigned metadata', () => {
    const unsigned = { specVersion: '1.0', entries: [], future: '\ud800' };
    expect(() => assertValidCatalog(unsigned)).not.toThrow();
    const signedCatalog = {
      ...unsigned,
      signature: signature({
        jws: detachedJws({ alg: 'ES256', typ: 'ai-catalog+jws' }),
      }),
    };
    expect(
      validationIssues(signedCatalog).some((issue) =>
        issue.path.includes('future'),
      ),
    ).toBe(true);
    const catalog = catalogFor();
    firstManifest(catalog).extensions = { 'example.com': '\ud800' };
    expect(
      validationIssues(catalog).some((issue) =>
        issue.path.includes('extensions'),
      ),
    ).toBe(true);
  });

  it('provides bounded diagnostics for invalid declarations throughout the assembled document', () => {
    const input = {
      specVersion: '1.0',
      entries: Array.from({ length: 120 }, () => ({
        identifier: 'x',
        type: 'custom',
        data: null,
      })),
    };
    const issues = validationIssues(input);
    expect(issues).toHaveLength(101);
    expect(issues.at(-1)?.code).toBe('diagnostics_truncated');
  });

  it('diagnoses invalid declarations before serialization', () => {
    const input = catalogFor({
      contributor: 'not a URI',
      extensions: { 'example.com': true },
    });
    expect(() => parseCatalog(input)).toThrow();
    expect(validationIssues(input).length).toBeGreaterThan(0);
  });
});
