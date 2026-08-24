const sha256 = `sha256:${'a'.repeat(64)}`;

export const validFixtures: readonly unknown[] = [
  { specVersion: '1.0', entries: [] },
  {
    specVersion: '1.99',
    futureCatalogField: { preserved: true },
    host: {
      displayName: 'Example Host',
      futureHostField: ['preserved'],
      trustManifest: {
        identity: 'did:web:example.com',
        attestations: [
          {
            type: 'SOC2-Type2',
            uri: 'https://example.com/soc2.pdf',
            digest: sha256,
            size: 42,
          },
        ],
      },
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
        trustManifest: {
          identity: 'did:web:example.com',
          subject: {
            type: 'application/a2a-agent-card+json',
            url: 'https://example.com/weather.json',
            digest: sha256,
          },
          issuedAt: '2016-12-31T23:59:60Z',
          expiresAt: '2027-01-01T00:00:00+00:00',
          signature: 'detached-jws',
        },
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
        trustManifest: {
          identity: 'did:web:example.com',
          trustSchema: {
            identifier: 'urn:trust:example',
            version: '1.0',
            verificationMethods: [],
          },
          attestations: [],
          provenance: [],
        },
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
        trustManifest: { identity: 'did:web:example.com' },
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
        trustManifest: {
          identity: 'did:web:example.com',
          attestations: [{}],
        },
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
        trustManifest: {
          identity: 'did:web:example.com',
          trustSchema: { identifier: 'x', version: '1' },
          signature: 'unbound',
        },
      },
    ],
  },
];
