import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

import { aiCatalogJsonSchema } from '../src/json-schema.js';
import {
  aiCatalogSchema,
  catalogEntrySchema,
  trustManifestSchema,
} from '../src/zod.js';
import { isRfc3339DateTime } from '../src/internal/rfc3339.js';
import { implementedSpecRevision, safeParseCatalog } from '../src/index.js';
import rawSchema from '../schema/ai-catalog.schema.json';
import { structurallyInvalidFixtures, validFixtures } from './fixtures.js';

function createValidator(validateFormats: boolean) {
  const ajv = new Ajv2020({ strict: false, validateFormats });
  if (validateFormats) {
    ajv.addFormat('date-time', { validate: isRfc3339DateTime });
  }
  return ajv.compile(rawSchema);
}

describe('shared structural fixtures', () => {
  const withFormats = createValidator(true);
  const withoutFormats = createValidator(false);

  it.each(
    validFixtures.map((value, index) => [index, value] as const),
  )('accepts valid fixture %s across root, Zod, and JSON Schema', (_index, value) => {
    expect(safeParseCatalog(value).success).toBe(true);
    expect(aiCatalogSchema.safeParse(value).success).toBe(true);
    expect(withFormats(value)).toBe(true);
    expect(withoutFormats(value)).toBe(true);
  });

  it.each(
    structurallyInvalidFixtures.map((value, index) => [index, value] as const),
  )('rejects invalid fixture %s across root, Zod, and JSON Schema', (_index, value) => {
    expect(safeParseCatalog(value).success).toBe(false);
    expect(aiCatalogSchema.safeParse(value).success).toBe(false);
    expect(withFormats(value)).toBe(false);
    expect(withoutFormats(value)).toBe(false);
  });

  it('documents calendar validation as format-dependent in JSON Schema', () => {
    const invalidCalendar = {
      specVersion: '1.0',
      entries: [
        {
          identifier: 'x',
          type: 'custom',
          url: 'u',
          updatedAt: '2026-02-30T00:00:00Z',
        },
      ],
    };
    expect(safeParseCatalog(invalidCalendar).success).toBe(false);
    expect(aiCatalogSchema.safeParse(invalidCalendar).success).toBe(false);
    expect(withFormats(invalidCalendar)).toBe(false);
    expect(withoutFormats(invalidCalendar)).toBe(true);
  });
});

describe('public schemas and generated artifact', () => {
  it('exports only complete, independently meaningful Zod schemas', () => {
    expect(
      aiCatalogSchema.safeParse({ specVersion: '1.0', entries: [] }).success,
    ).toBe(true);
    expect(
      catalogEntrySchema.safeParse({ identifier: 'x', type: 'x', data: null })
        .success,
    ).toBe(true);
    expect(
      trustManifestSchema.safeParse({
        identity: 'x',
        trustSchema: { identifier: 'x', version: '1' },
      }).success,
    ).toBe(true);
  });

  it('preserves unknown fields but rejects explicit undefined', () => {
    const value = {
      specVersion: '1.0',
      entries: [],
      future: { retained: true },
    };
    const parsed = aiCatalogSchema.parse(value) as unknown as Record<
      string,
      unknown
    >;
    expect(parsed.future).toEqual({ retained: true });
    expect(
      aiCatalogSchema.safeParse({ ...value, signature: undefined }).success,
    ).toBe(false);
  });

  it('keeps JavaScript and raw schema artifacts identical', () => {
    expect(aiCatalogJsonSchema).toEqual(rawSchema);
    expect(rawSchema.$schema).toBe(
      'https://json-schema.org/draft/2020-12/schema',
    );
    expect(rawSchema.$id).toBe(
      `urn:ai-catalog-sdk:schema:ai-catalog:${implementedSpecRevision.commit}`,
    );
    expect(rawSchema['x-ai-catalog-specification']).toEqual(
      implementedSpecRevision,
    );
    for (const name of [
      'CatalogEntry',
      'HostInfo',
      'Publisher',
      'TrustManifest',
      'TrustSubject',
      'TrustSchema',
      'Attestation',
      'ProvenanceLink',
    ]) {
      expect(rawSchema.$defs).toHaveProperty(name);
    }
  });
});

describe('RFC 3339 profile', () => {
  it.each([
    '2026-08-20T12:30:45Z',
    '2026-08-20t12:30:45z',
    '2026-08-20T12:30:45.123+05:30',
    '2016-12-31T23:59:60Z',
    '2016-12-31T18:59:60-05:00',
  ])('accepts %s', (updatedAt) => {
    expect(
      catalogEntrySchema.safeParse({
        identifier: 'x',
        type: 'custom',
        url: 'u',
        updatedAt,
      }).success,
    ).toBe(true);
  });

  it.each([
    '2026-08-20T12:30Z',
    '2026-08-20 12:30:45Z',
    '2026-13-20T12:30:45Z',
    '2026-01-00T12:30:45Z',
    '2026-02-29T12:30:45Z',
    '2026-08-20T24:00:00Z',
    '2026-08-20T12:30:61Z',
    '2026-08-20T12:30:60Z',
  ])('rejects %s', (updatedAt) => {
    expect(
      catalogEntrySchema.safeParse({
        identifier: 'x',
        type: 'custom',
        url: 'u',
        updatedAt,
      }).success,
    ).toBe(false);
  });
});
