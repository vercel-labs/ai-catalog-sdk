import { describe, expect, it } from 'vitest';
import { ZodError } from 'zod';

import {
  CatalogParseError,
  entryTypes,
  isEntryType,
  isInlineCatalogEntry,
  isReferencedCatalogEntry,
  mediaTypes,
  parseCatalog,
  parseCatalogEntry,
  parseCatalogJson,
  safeParseCatalog,
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

  it('accepts every JSON value as inline artifact data', () => {
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
            trustManifest: {
              identity: 'did:web:example.com',
              futureEvidence: { proof: true },
            },
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

  it('enforces contextual subject type and URL parity', () => {
    const base = {
      specVersion: '1.0',
      entries: [
        {
          identifier: 'x',
          type: 'application/example+json',
          url: 'https://example.com/artifact',
          trustManifest: {
            identity: 'did:web:example.com',
            subject: {
              type: 'application/other+json',
              url: 'https://example.com/other',
              digest: sha256,
            },
            issuedAt: '2026-08-20T00:00:00Z',
            signature: 'signed',
          },
        },
      ],
    };
    const result = safeParseCatalog(base);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map(({ code }) => code)).toEqual([
        'inconsistent_value',
        'inconsistent_value',
      ]);
    }
  });

  it('keeps helper narrowing limited to declared entry properties', () => {
    const inline = parseCatalogEntry({
      identifier: 'x',
      type: 'inline',
      data: {},
    });
    const referenced = parseCatalogEntry({
      identifier: 'y',
      type: mediaTypes.mcpServerCard,
      url: 'https://example.com/card',
    });
    expect(isInlineCatalogEntry(inline)).toBe(true);
    expect(isReferencedCatalogEntry(referenced)).toBe(true);
    expect(isEntryType(mediaTypes.mcpServerCard)(referenced)).toBe(true);
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
        trustManifest: {
          identity: 'x',
          trustSchema: { identifier: 'x', version: '1' },
          attestations: Array.from({ length: 101 }, () => ({})),
        },
      },
    ],
    [
      'provenance',
      {
        identifier: 'x',
        type: 'custom',
        url: 'u',
        trustManifest: {
          identity: 'x',
          trustSchema: { identifier: 'x', version: '1' },
          provenance: Array.from({ length: 101 }, () => ({})),
        },
      },
    ],
    [
      'verificationMethods',
      {
        identifier: 'x',
        type: 'custom',
        url: 'u',
        trustManifest: {
          identity: 'x',
          trustSchema: {
            identifier: 'x',
            version: '1',
            verificationMethods: Array.from({ length: 101 }, () => 1),
          },
        },
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
