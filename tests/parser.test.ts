import { describe, expect, it } from 'vitest';
import { ZodError } from 'zod';

import {
  CatalogParseError,
  entryTypes,
  isEntryType,
  isCatalogEntryWithData,
  isCatalogEntryWithUrl,
  mediaTypes,
  parseCatalog,
  parseCatalogEntry,
  parseCatalogJson,
  safeParseCatalog,
  safeParseCatalogEntry,
  safeParseCatalogJson,
} from '../src/index.js';
import { structurallyInvalidFixtures, validFixtures } from './fixtures.js';

const sha256 = `sha256:${'a'.repeat(64)}`;

function countNestedIssues(value: unknown): number {
  if (Array.isArray(value)) {
    return value.reduce((total, item) => total + countNestedIssues(item), 0);
  }
  if (value === null || typeof value !== 'object') return 0;
  const record = value as Record<string, unknown>;
  return ('code' in record ? 1 : 0) + countNestedIssues(record.errors);
}

describe('root parsing', () => {
  it.each(
    validFixtures.map((value, index) => [index, value] as const),
  )('accepts valid fixture %s', (_index, value) => {
    const result = safeParseCatalog(value);
    expect(result.success).toBe(true);
  });

  it.each(
    structurallyInvalidFixtures.map((value, index) => [index, value] as const),
  )('rejects invalid fixture %s', (_index, value) => {
    const result = safeParseCatalog(value);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBeInstanceOf(CatalogParseError);
      expect(result.error.issues.length).toBeGreaterThan(0);
    }
  });

  it('preserves unknown JSON fields and returns mutable values', () => {
    const parsed = parseCatalog(validFixtures[1]);
    expect(
      (parsed as unknown as Record<string, unknown>).futureCatalogField,
    ).toEqual({ preserved: true });
    expect(
      (parsed.entries[0] as unknown as Record<string, unknown>)
        .futureEntryField,
    ).toEqual({ preserved: true });
    parsed.entries.push({ identifier: 'new', type: 'custom', data: 0 });
    expect(parsed.entries).toHaveLength(3);
  });

  it('accepts every JSON value as data in an entry with `data`', () => {
    const values = [null, false, 0, 'text', [], {}];
    for (const data of values) {
      expect(
        parseCatalogEntry({ identifier: 'x', type: 'custom', data }).data,
      ).toEqual(data);
    }
  });

  it('dispatches supported majors without numeric precision loss', () => {
    expect(
      safeParseCatalog({ specVersion: '01.999', entries: [] }).success,
    ).toBe(true);
    const result = safeParseCatalog({
      specVersion: '999999999999999999999.0',
      entries: [],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.code).toBe('unsupported_spec_version');
    }
  });

  it('requires a snapshot-known substantive member in higher 1.x minors', () => {
    expect(
      safeParseCatalog({
        specVersion: '1.99',
        entries: [
          {
            identifier: 'x',
            type: 'custom',
            url: 'u',
            digest: sha256,
            trustManifests: [
              {
                contributor: 'did:web:example.com',
                futureEvidence: { proof: true },
              },
            ],
          },
        ],
      }).success,
    ).toBe(false);
  });

  it('enforces entry uniqueness for versioned and unversioned groups', () => {
    const entry = { identifier: 'x', type: 'custom', url: 'u' };
    expect(
      safeParseCatalog({ specVersion: '1.0', entries: [entry, entry] }).success,
    ).toBe(false);
    expect(
      safeParseCatalog({
        specVersion: '1.0',
        entries: [
          { ...entry, version: '1' },
          { ...entry, version: '1' },
        ],
      }).success,
    ).toBe(false);
    expect(
      safeParseCatalog({
        specVersion: '1.0',
        entries: [
          { ...entry, version: '1' },
          { ...entry, version: '2' },
        ],
      }).success,
    ).toBe(true);
    expect(
      safeParseCatalog({
        specVersion: '1.0',
        entries: [{ ...entry, version: '1' }, entry],
      }).success,
    ).toBe(false);
  });

  it('reports duplicate paths using original input indexes', () => {
    const result = safeParseCatalog({
      specVersion: '1.0',
      entries: [
        {},
        { identifier: 'x', type: 'custom', url: 'first' },
        { identifier: 'x', type: 'custom', url: 'second' },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(
        result.error.issues.find(({ code }) => code === 'duplicate_entry')
          ?.path,
      ).toEqual(['entries', 2, 'identifier']);
    }
  });

  it('enforces contextual subject type without binding legacy URL metadata', () => {
    const base = {
      specVersion: '1.0',
      entries: [
        {
          identifier: 'x',
          type: 'application/example+json',
          url: 'https://example.com/artifact',
          digest: sha256,
          trustManifests: [
            {
              contributor: 'did:web:example.com',
              subject: {
                identifier: 'x',
                type: 'application/other+json',
                url: 'https://example.com/other',
                digest: sha256,
              },

              signature: {
                signer: 'did:web:example.com',
                profile: 'did-web-v1',
                issuedAt: '2026-08-20T00:00:00Z',
                jws: 'signed',
              },
            },
          ],
        },
      ],
    };
    const result = safeParseCatalog(base);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map(({ code }) => code)).toEqual([
        'inconsistent_value',
      ]);
    }
  });

  it.each([
    false,
    true,
  ])('requires exact subject identifier equality with signed=%s', (signed) => {
    const entry = {
      identifier: 'urn:air:example.com:artifact:one',
      type: 'custom',
      data: null,
      digest: sha256,
      trustManifests: [
        {
          contributor: 'did:web:example.com',
          trustSchema: { identifier: 'urn:trust:example', version: '1' },
          attestations: [],
          subject: {
            identifier: 'urn:air:EXAMPLE.com:artifact:one',
            type: 'custom',
            digest: sha256,
          },
          ...(signed
            ? {
                signature: {
                  signer: 'did:web:example.com',
                  profile: 'did-web-v1',
                  issuedAt: '2026-08-20T00:00:00Z',
                  jws: 'signed',
                },
              }
            : {}),
        },
      ],
    };
    const standalone = safeParseCatalogEntry(entry);
    const catalog = safeParseCatalog({ specVersion: '1.0', entries: [entry] });
    expect(standalone.success).toBe(false);
    expect(catalog.success).toBe(false);
    if (!standalone.success && !catalog.success) {
      expect(standalone.error.issues).toMatchObject([
        {
          code: 'inconsistent_value',
          path: ['trustManifests', 0, 'subject', 'identifier'],
        },
      ]);
      expect(catalog.error.issues).toMatchObject([
        {
          code: 'inconsistent_value',
          path: ['entries', 0, 'trustManifests', 0, 'subject', 'identifier'],
        },
      ]);
    }
  });

  it.each([
    ['both absent', undefined, undefined, true],
    ['exact match', '1.0.0', '1.0.0', true],
    ['empty strings match', '', '', true],
    ['subject absent', '1.0.0', undefined, false],
    ['entry absent', undefined, '1.0.0', false],
    ['different values', '1.0.0', '2.0.0', false],
    ['no version normalization', '1.0.0', '1.0', false],
    ['empty subject is present', undefined, '', false],
    ['empty entry is present', '', undefined, false],
  ] as const)('checks signed release versions: %s', (_name, entryVersion, subjectVersion, accepted) => {
    const entry = {
      identifier: 'x',
      type: 'custom',
      data: null,
      ...(entryVersion === undefined ? {} : { version: entryVersion }),
      digest: sha256,
      trustManifests: [
        {
          contributor: 'did:web:example.com',
          signature: {
            signer: 'did:web:example.com',
            profile: 'did-web-v1',
            issuedAt: '2026-08-20T00:00:00Z',
            jws: 'signed',
          },

          subject: {
            identifier: 'x',
            type: 'custom',
            digest: sha256,
            ...(subjectVersion === undefined
              ? {}
              : { version: subjectVersion }),
          },
        },
      ],
    };
    const standalone = safeParseCatalogEntry(entry);
    const catalog = safeParseCatalog({ specVersion: '1.0', entries: [entry] });
    expect(standalone.success).toBe(accepted);
    expect(catalog.success).toBe(accepted);
    if (!standalone.success && !catalog.success) {
      expect(standalone.error.issues).toMatchObject([
        {
          code: 'inconsistent_value',
          path: ['trustManifests', 0, 'subject', 'version'],
        },
      ]);
      expect(catalog.error.issues).toMatchObject([
        {
          code: 'inconsistent_value',
          path: ['entries', 0, 'trustManifests', 0, 'subject', 'version'],
        },
      ]);
    }
  });

  it.each([
    ['1.0.0', '2.0.0'],
    ['1.0.0', undefined],
    [undefined, '1.0.0'],
  ] as const)('rejects unsigned version differences: entry=%s subject=%s', (entryVersion, subjectVersion) => {
    const entry = {
      identifier: 'x',
      type: 'custom',
      data: null,
      ...(entryVersion === undefined ? {} : { version: entryVersion }),
      digest: sha256,
      trustManifests: [
        {
          contributor: 'did:web:example.com',
          trustSchema: { identifier: 'urn:trust:example', version: '1' },
          attestations: [],
          subject: {
            identifier: 'x',
            type: 'custom',
            digest: sha256,
            ...(subjectVersion === undefined
              ? {}
              : { version: subjectVersion }),
          },
        },
      ],
    };
    expect(safeParseCatalogEntry(entry).success).toBe(false);
    expect(
      safeParseCatalog({ specVersion: '1.0', entries: [entry] }).success,
    ).toBe(false);
  });

  it('keeps empty identifiers as structural strings', () => {
    expect(
      safeParseCatalogEntry({
        identifier: '',
        type: 'custom',
        data: null,
        digest: sha256,
        trustManifests: [
          {
            contributor: 'did:web:example.com',
            signature: {
              signer: 'did:web:example.com',
              profile: 'did-web-v1',
              issuedAt: '2026-08-20T00:00:00Z',
              jws: '',
            },

            subject: { identifier: '', type: 'custom', digest: sha256 },
          },
        ],
      }).success,
    ).toBe(true);
  });

  it.each(
    [null, false, 42, 'opaque', [], { subject: 'uninterpreted' }].map(
      (value) => [value] as const,
    ),
  )('preserves host.trustManifest as any unknown JSON property: %j', (value) => {
    const parsed = parseCatalog({
      specVersion: '1.0',
      entries: [],
      host: { displayName: 'Host', trustManifest: value, arbitrary: value },
    });
    expect(parsed.host).toEqual({
      displayName: 'Host',
      trustManifest: value,
      arbitrary: value,
    });
  });

  it('rejects non-JSON host.trustManifest through generic unknown-field validation', () => {
    for (const value of [undefined, () => null, new Date()]) {
      expect(
        safeParseCatalog({
          specVersion: '1.0',
          entries: [],
          host: { displayName: 'Host', trustManifest: value },
        }).success,
      ).toBe(false);
    }
  });

  it('keeps helper narrowing limited to declared entry properties', () => {
    const entryWithData = parseCatalogEntry({
      identifier: 'x',
      type: 'with-data',
      data: {},
    });
    const entryWithUrl = parseCatalogEntry({
      identifier: 'y',
      type: mediaTypes.mcpServerCard,
      url: 'https://example.com/card',
    });
    expect(isCatalogEntryWithData(entryWithData)).toBe(true);
    expect(isCatalogEntryWithUrl(entryWithUrl)).toBe(true);
    expect(isEntryType(mediaTypes.mcpServerCard)(entryWithUrl)).toBe(true);
  });

  it('groups recognized representations by entry concept', () => {
    const entries = [
      parseCatalogEntry({
        identifier: 'zip',
        type: mediaTypes.agentPluginZip,
        url: 'https://example.com/plugin.zip',
      }),
      parseCatalogEntry({
        identifier: 'gzip',
        type: mediaTypes.agentPluginGzip,
        url: 'https://example.com/plugin.tar.gz',
      }),
      parseCatalogEntry({
        identifier: 'index',
        type: mediaTypes.agentSkillIndexJson,
        url: 'https://example.com/.well-known/agent-skills/index.json',
      }),
      parseCatalogEntry({
        identifier: 'skill',
        type: mediaTypes.agentSkillZip,
        url: 'https://example.com/skill.zip',
      }),
    ];

    const pluginEntries = entries.filter(isEntryType(entryTypes.agentPlugin));
    const skillEntries = entries.filter(isEntryType(entryTypes.agentSkill));

    expect(pluginEntries.map(({ identifier }) => identifier)).toEqual([
      'zip',
      'gzip',
    ]);
    expect(skillEntries.map(({ identifier }) => identifier)).toEqual([
      'index',
      'skill',
    ]);
  });
});

describe('JSON text parsing', () => {
  it('returns stable malformed-JSON diagnostics and a SyntaxError cause', () => {
    const result = safeParseCatalogJson('{');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toEqual([
        {
          code: 'invalid_json',
          path: [],
          message: 'The catalog text is not valid JSON.',
        },
      ]);
      expect(result.error.cause).toBeInstanceOf(SyntaxError);
    }
    expect(() => parseCatalogJson('{')).toThrow(CatalogParseError);
  });

  it('rejects non-strings without invoking coercion hooks', () => {
    let coercions = 0;
    const value = {
      toString() {
        coercions += 1;
        return '{"specVersion":"1.0","entries":[]}';
      },
    };
    const result = safeParseCatalogJson(value as unknown as string);
    expect(result.success).toBe(false);
    expect(coercions).toBe(0);
  });
});

describe('bounded diagnostics', () => {
  it('does not label exactly the issue budget as truncated', () => {
    const result = safeParseCatalog({
      specVersion: '1.0',
      entries: Array.from({ length: 100 }, () => ({})),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toHaveLength(100);
      expect(result.error.issues.at(-1)?.code).not.toBe(
        'diagnostics_truncated',
      );
      expect(result.error.cause).toBeInstanceOf(ZodError);
      expect((result.error.cause as ZodError).issues.length).toBeLessThan(20);
      expect(
        countNestedIssues((result.error.cause as ZodError).issues),
      ).toBeLessThan(50);
    }
  });

  it('inspects one issue beyond the budget and appends truncation', () => {
    const result = safeParseCatalog({
      specVersion: '1.0',
      entries: Array.from({ length: 101 }, () => ({})),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toHaveLength(101);
      expect(result.error.issues.at(-1)?.code).toBe('diagnostics_truncated');
    }
  });

  it.each([
    [
      'tags',
      {
        identifier: 'x',
        type: 'custom',
        url: 'u',
        tags: Array.from({ length: 101 }, () => 1),
      },
    ],
    [
      'attestations',
      {
        identifier: 'x',
        type: 'custom',
        url: 'u',
        digest: sha256,
        trustManifests: [
          {
            contributor: 'urn:x',
            trustSchema: { identifier: 'x', version: '1' },
            attestations: Array.from({ length: 101 }, () => ({})),
          },
        ],
      },
    ],
    [
      'provenance',
      {
        identifier: 'x',
        type: 'custom',
        url: 'u',
        digest: sha256,
        trustManifests: [
          {
            contributor: 'urn:x',
            trustSchema: { identifier: 'x', version: '1' },
            provenance: Array.from({ length: 101 }, () => ({})),
          },
        ],
      },
    ],
    [
      'verificationMethods',
      {
        identifier: 'x',
        type: 'custom',
        url: 'u',
        digest: sha256,
        trustManifests: [
          {
            contributor: 'urn:x',
            trustSchema: {
              identifier: 'x',
              version: '1',
              verificationMethods: Array.from({ length: 101 }, () => 1),
            },
          },
        ],
      },
    ],
  ] as const)('bounds issues in %s', (_name, entry) => {
    const result = safeParseCatalog({ specVersion: '1.0', entries: [entry] });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toHaveLength(101);
      expect(result.error.issues.at(-1)?.code).toBe('diagnostics_truncated');
    }
  });
});

describe('independent contributions', () => {
  const base = { identifier: 'x', type: 'custom', data: null, digest: sha256 };
  const manifest = {
    contributor: 'did:web:example.com',
    subject: { identifier: 'x', type: 'custom', digest: sha256 },
    signature: {
      signer: 'did:web:example.com',
      profile: 'did-web-v1',
      issuedAt: '2026-01-01T00:00:00Z',
      jws: '',
    },
  };

  it('allows no contributions, repeated contributors, and extension-only contributions', () => {
    for (const trustManifests of [
      [],
      [manifest, manifest],
      [
        {
          contributor: 'urn:auditor:one',
          extensions: { 'example.audit': true },
        },
      ],
    ]) {
      expect(safeParseCatalogEntry({ ...base, trustManifests }).success).toBe(
        true,
      );
    }
  });

  it('rejects empty individual manifests and does not count reserved signatures as evidence', () => {
    for (const extra of [
      {},
      { extensions: {} },
      { additionalSignatures: ['anything'] },
    ]) {
      const result = safeParseCatalogEntry({
        ...base,
        trustManifests: [{ contributor: 'urn:auditor:one', ...extra }],
      });
      expect(result.success).toBe(false);
      if (!result.success)
        expect(result.error.issues[0]?.path.slice(0, 2)).toEqual([
          'trustManifests',
          0,
        ]);
    }
  });

  it('requires exact contributor attribution and an entry digest for signed claims', () => {
    expect(
      safeParseCatalogEntry({
        ...base,
        trustManifests: [{ ...manifest, contributor: 'did:web:EXAMPLE.com' }],
      }).success,
    ).toBe(false);
    expect(
      safeParseCatalogEntry({
        identifier: 'x',
        type: 'custom',
        data: null,
        trustManifests: [manifest],
      }).success,
    ).toBe(false);
  });

  it.each([
    '',
    'relative/path',
    'not a uri',
    'did:web:bad%escape',
    'did:web:example.com\n',
    'https://example.com/a#b#c',
    'https://example.com/[x]',
    'https://[not-an-ip]/',
    'https://a@b@c/',
    'https://example.com:bad/',
  ])('rejects non-absolute contributor %s', (contributor) => {
    expect(
      safeParseCatalogEntry({
        ...base,
        trustManifests: [
          { contributor, extensions: { 'example.audit': true } },
        ],
      }).success,
    ).toBe(false);
  });

  it('preserves removed fields as opaque JSON without their old meaning', () => {
    const value = {
      ...base,
      trustManifest: { arbitrary: true },
      trustManifests: [
        {
          ...manifest,
          identity: { old: true },
          identityType: false,
          issuedAt: 42,
          expiresAt: [],
          privacyPolicyUrl: null,
          termsOfServiceUrl: { future: true },
          subject: { ...manifest.subject, url: { opaque: true } },
          additionalSignatures: [false, null, 1],
        },
      ],
    };
    expect(parseCatalogEntry(value)).toEqual(value);
  });

  it.each([
    ['2026-01-01T00:00:00.0001Z', '2026-01-01T00:00:00.0002Z', true],
    ['2026-01-01T00:00:00.0002Z', '2026-01-01T00:00:00.0001Z', false],
    ['2026-01-01T00:00:00Z', '2026-01-01T01:00:00+01:00', false],
    ['2016-12-31T23:59:59.99999Z', '2016-12-31T23:59:60Z', true],
    ['2016-12-31T23:59:60.5Z', '2017-01-01T00:00:00Z', true],
    ['2017-01-01T00:00:00Z', '2016-12-31T23:59:60.5Z', false],
  ])('orders signature instants %s and %s', (issuedAt, expiresAt, accepted) => {
    const signature = { ...manifest.signature, issuedAt, expiresAt };
    expect(
      safeParseCatalogEntry({
        ...base,
        trustManifests: [{ ...manifest, signature }],
      }).success,
    ).toBe(accepted);
    expect(
      safeParseCatalog({ specVersion: '1.0', entries: [], signature }).success,
    ).toBe(accepted);
  });
});

describe('absolute contributor URI forms', () => {
  it.each([
    'urn:auditor:one',
    'mailto:auditor@example.com',
    'custom:',
    'https://example.com/path?query#fragment',
    'https://[::]/',
    'https://[::ffff:192.0.2.1]/',
    'custom://[v1.future]/',
  ])('retains %s exactly', (contributor) => {
    const entry = {
      identifier: 'x',
      type: 'custom',
      data: null,
      trustManifests: [{ contributor, extensions: { 'example.audit': true } }],
    };
    expect(parseCatalogEntry(entry)).toEqual(entry);
  });
});
