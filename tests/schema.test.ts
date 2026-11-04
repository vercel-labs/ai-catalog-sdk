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
import { invalidDeclarationFixtures, validFixtures } from './fixtures.js';

function createValidator(validateFormats: boolean) {
  const ajv = new Ajv2020({ strict: false, validateFormats });
  if (validateFormats) {
    ajv.addFormat('date-time', { validate: isRfc3339DateTime });
  }
  return ajv.compile(rawSchema);
}

describe('schema declaration fixtures', () => {
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
    invalidDeclarationFixtures.map((value, index) => [index, value] as const),
  )('rejects invalid declaration fixture %s in Zod and JSON Schema', (_index, value) => {
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
    expect(safeParseCatalog(invalidCalendar).success).toBe(true);
    expect(aiCatalogSchema.safeParse(invalidCalendar).success).toBe(false);
    expect(withFormats(invalidCalendar)).toBe(false);
    expect(withoutFormats(invalidCalendar)).toBe(true);
  });

  it.each([
    ['identifier mismatch', 'other', '1.0.0'],
    ['version mismatch', 'x', '2.0.0'],
    ['version absent', 'x', undefined],
  ] as const)('does not apply contextual %s checks during ingestion or schema validation', (_name, identifier, version) => {
    const entry = {
      identifier: 'x',
      version: '1.0.0',
      type: 'custom',
      data: null,
      digest: `sha256:${'a'.repeat(64)}`,
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
            identifier,
            ...(version === undefined ? {} : { version }),
            type: 'custom',
            digest: `sha256:${'a'.repeat(64)}`,
          },
        },
      ],
    };
    const value = { specVersion: '1.0', entries: [entry] };
    expect(safeParseCatalog(value).success).toBe(true);
    expect(aiCatalogSchema.safeParse(value).success).toBe(true);
    expect(catalogEntrySchema.safeParse(entry).success).toBe(true);
    expect(trustManifestSchema.safeParse(entry.trustManifests[0]).success).toBe(
      true,
    );
    expect(withFormats(value)).toBe(true);
    expect(withoutFormats(value)).toBe(true);
  });

  it.each(
    [null, false, 42, 'opaque', [], { subject: 'uninterpreted' }].map(
      (value) => [value] as const,
    ),
  )('treats host.trustManifest as generic JSON across schemas: %j', (trustManifest) => {
    const value = {
      specVersion: '1.0',
      entries: [],
      host: { displayName: 'Host', trustManifest },
    };
    expect(aiCatalogSchema.parse(value)).toEqual(value);
    expect(withFormats(value)).toBe(true);
    expect(withoutFormats(value)).toBe(true);
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
        contributor: 'urn:x',
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

describe('signature structure and schema coverage', () => {
  const validate = createValidator(true);
  const signature = {
    signer: 'did:web:example.com',
    profile: 'did-web-v1',
    issuedAt: '2026-01-01T00:00:00Z',
    jws: '',
  };
  const digest = `sha256:${'a'.repeat(64)}`;
  const subject = { identifier: 'x', type: 'custom', digest };

  it('does not count known metadata or empty evidence as substantive', () => {
    for (const [content, accepted] of [
      [{}, false],
      [{ subject }, false],
      [{ subject: { ...subject, futureClaim: true } }, false],
      [{ attestations: [] }, false],
      [{ provenance: [] }, false],
      [{ additionalSignatures: { futureClaim: true } }, false],
      [{ extensions: {} }, false],
      [{ extensions: { 'example.audit': null } }, true],
    ] as const) {
      const manifest = { contributor: 'urn:auditor:one', ...content };
      const value = {
        specVersion: '1.0',
        entries: [
          {
            identifier: 'x',
            type: 'custom',
            data: null,
            digest,
            trustManifests: [manifest],
          },
        ],
      };
      expect(safeParseCatalog(value).success).toBe(true);
      expect(aiCatalogSchema.safeParse(value).success).toBe(accepted);
      expect(trustManifestSchema.safeParse(manifest).success).toBe(accepted);
      expect(validate(value)).toBe(accepted);
    }
  });

  it.each([
    [{ contributor: 'relative' }, true],
    [{ trustSchema: { identifier: 'x' } }, false],
    [{ attestations: [{ type: 'evidence', uri: 42 }] }, false],
    [{ provenance: [{ relation: 'source', sourceId: 42 }] }, false],
    [{ extensions: [] }, false],
    [{ subject: { ...subject, digest: false } }, false],
    [{ subject, signature: { ...signature, profile: '' } }, true],
  ] as const)('unknown content does not change interpretation of known fields: %j', (malformed, parseable) => {
    for (const unknownContent of [{}, { futureEvidence: null }]) {
      const manifest = {
        contributor: 'did:web:example.com',
        ...malformed,
        ...unknownContent,
      };
      const entry = {
        identifier: 'x',
        type: 'custom',
        data: null,
        digest,
        trustManifests: [manifest],
      };
      const value = { specVersion: '1.0', entries: [entry] };
      expect(safeParseCatalog(value).success).toBe(parseable);
      expect(aiCatalogSchema.safeParse(value).success).toBe(false);
      expect(catalogEntrySchema.safeParse(entry).success).toBe(false);
      expect(trustManifestSchema.safeParse(manifest).success).toBe(false);
      expect(validate(value)).toBe(false);
    }
  });

  it('preserves unknown-content subject disagreements during ingestion', () => {
    const entry = {
      identifier: 'x',
      type: 'custom',
      data: null,
      digest,
      trustManifests: [
        {
          contributor: 'urn:auditor:one',
          subject: { ...subject, identifier: 'different' },
          futureEvidence: false,
        },
      ],
    };
    const value = { specVersion: '1.0', entries: [entry] };
    expect(safeParseCatalog(value).success).toBe(true);
    expect(aiCatalogSchema.safeParse(value).success).toBe(true);
    expect(validate(value)).toBe(true);
  });

  it('enforces timestamp ordering in Zod, beyond ingestion and JSON Schema coverage', () => {
    const value = {
      specVersion: '1.0',
      entries: [],
      signature: { ...signature, expiresAt: signature.issuedAt },
    };
    expect(safeParseCatalog(value).success).toBe(true);
    expect(aiCatalogSchema.safeParse(value).success).toBe(false);
    expect(validate(value)).toBe(true);
  });

  it('enforces contributor attribution in Zod, beyond ingestion and JSON Schema coverage', () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    const value = {
      specVersion: '1.0',
      entries: [
        {
          identifier: 'x',
          type: 'custom',
          data: null,
          digest,
          trustManifests: [
            {
              contributor: 'did:web:assessor.example',
              signature,
              subject: { identifier: 'x', type: 'custom', digest },
            },
          ],
        },
      ],
    };
    expect(safeParseCatalog(value).success).toBe(true);
    expect(aiCatalogSchema.safeParse(value).success).toBe(false);
    expect(validate(value)).toBe(true);
  });
});
