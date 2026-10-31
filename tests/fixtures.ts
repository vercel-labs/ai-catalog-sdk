const sha256 = `sha256:${'a'.repeat(64)}`;

export const validFixtures: readonly unknown[] = [
  { specVersion: '1.0', entries: [] },
  {
    specVersion: '1.99',
    futureCatalogField: { preserved: true },
    host: {
      displayName: 'Example Host',
      futureHostField: ['preserved'],
      trustManifest: ['opaque', null, { arbitrary: true }],
    },
    entries: [
      {
        identifier: 'urn:air:example.com:agent:weather',
        displayName: 'Weather Agent',
        type: 'application/a2a-agent-card+json',
        url: 'https://example.com/weather.json',
        version: '1.0.0',
        tags: ['weather'],
        publisher: {
          identifier: 'did:web:example.com',
          displayName: 'Example',
        },
        digest: sha256,
        trustManifests: [
          {
            contributor: 'did:web:example.com',
            subject: {
              identifier: 'urn:air:example.com:agent:weather',
              version: '1.0.0',
              type: 'application/a2a-agent-card+json',
              url: 'https://example.com/weather.json',
              digest: sha256,
            },

            signature: {
              signer: 'did:web:example.com',
              profile: 'did-web-v1',
              issuedAt: '2016-12-31T23:59:60Z',
              expiresAt: '2027-01-01T00:00:00+00:00',
              jws: 'detached-jws',
            },
          },
        ],
        futureEntryField: { preserved: true },
      },
      {
        identifier: 'urn:air:example.com:data:inline',
        type: 'application/custom+json',
        data: null,
        updatedAt: '2026-08-20t12:30:45.123z',
      },
    ],
  },
  {
    specVersion: '1.0',
    entries: [
      {
        identifier: 'urn:air:example.com:artifact:trust-schema',
        type: 'application/custom+json',
        data: false,
        digest: sha256,
        trustManifests: [
          {
            contributor: 'did:web:example.com',
            trustSchema: {
              identifier: 'urn:trust:example',
              version: '1.0',
              verificationMethods: [],
            },
            attestations: [],
            provenance: [],
          },
        ],
      },
    ],
  },
  {
    specVersion: '1.99',
    entries: [
      {
        identifier: 'future-content',
        type: 'custom',
        data: null,
        trustManifests: [null, false, 0, '', [], {}, { claim: true }].map(
          (futureEvidence) => ({
            contributor: 'urn:auditor:future',
            futureEvidence,
          }),
        ),
      },
    ],
  },
];

export const structurallyInvalidFixtures: readonly unknown[] = [
  {},
  { specVersion: '1', entries: [] },
  { specVersion: '1.0', entries: [{}] },
  {
    specVersion: '1.0',
    entries: [{ identifier: 'x', type: 'x', url: 'u', data: null }],
  },
  {
    specVersion: '1.0',
    entries: [{ identifier: 'x', type: 'x' }],
  },
  {
    specVersion: '1.0',
    entries: [
      {
        identifier: 'x',
        type: 'x',
        url: 'u',
        digest: sha256,
        trustManifests: [{ contributor: 'did:web:example.com' }],
      },
    ],
  },
  {
    specVersion: '1.0',
    entries: [
      {
        identifier: 'x',
        type: 'x',
        url: 'u',
        digest: sha256,
        trustManifests: [
          {
            contributor: 'did:web:example.com',
            attestations: [{}],
          },
        ],
      },
    ],
  },
  {
    specVersion: '1.0',
    entries: [
      {
        identifier: 'x',
        type: 'x',
        url: 'u',
        updatedAt: '2026-08-20T12:30Z',
      },
    ],
  },
  {
    specVersion: '1.0',
    entries: [
      {
        identifier: 'x',
        type: 'x',
        url: 'u',
        digest: sha256,
        trustManifests: [
          {
            contributor: 'did:web:example.com',
            trustSchema: { identifier: 'x', version: '1' },
            signature: {
              signer: 'did:web:example.com',
              profile: 'did-web-v1',
              issuedAt: '2026-08-20T00:00:00Z',
              jws: 'unbound',
            },
          },
        ],
      },
    ],
  },
  ...[
    { type: 'custom', digest: sha256 },
    { identifier: 42, type: 'custom', digest: sha256 },
    { identifier: 'x', version: null, type: 'custom', digest: sha256 },
    { identifier: 'x', version: 42, type: 'custom', digest: sha256 },
  ].map((subject) => ({
    specVersion: '1.0',
    entries: [
      {
        identifier: 'x',
        type: 'custom',
        data: null,
        digest: sha256,
        trustManifests: [
          {
            contributor: 'did:web:example.com',
            trustSchema: { identifier: 'urn:trust:example', version: '1' },
            attestations: [],
            subject,
          },
        ],
      },
    ],
  })),
];
