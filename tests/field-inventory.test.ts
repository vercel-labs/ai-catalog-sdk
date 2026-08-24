import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { implementedSpecRevision, parseCatalog } from '../src/index.js';
import rawSchema from '../schema/ai-catalog.schema.json';

interface SchemaNode {
  properties?: Record<string, unknown>;
  required?: string[];
  anyOf?: SchemaNode[];
}

const inventory = {
  AICatalog: {
    properties: ['entries', 'extensions', 'host', 'signature', 'specVersion'],
    requiredBranches: [['entries', 'specVersion']],
  },
  HostInfo: {
    properties: [
      'displayName',
      'documentationUrl',
      'identifier',
      'logoUrl',
      'trustManifest',
    ],
    requiredBranches: [['displayName']],
  },
  CatalogEntry: {
    properties: [
      'data',
      'description',
      'displayName',
      'extensions',
      'identifier',
      'publisher',
      'tags',
      'trustManifest',
      'type',
      'updatedAt',
      'url',
      'version',
    ],
    requiredBranches: [
      ['identifier', 'type', 'url'],
      ['data', 'identifier', 'type'],
    ],
  },
  Publisher: {
    properties: ['displayName', 'identifier', 'identityType'],
    requiredBranches: [['displayName', 'identifier']],
  },
  TrustManifest: {
    properties: [
      'attestations',
      'expiresAt',
      'extensions',
      'identity',
      'identityType',
      'issuedAt',
      'privacyPolicyUrl',
      'provenance',
      'signature',
      'subject',
      'termsOfServiceUrl',
      'trustSchema',
    ],
    requiredBranches: [
      ['identity', 'issuedAt', 'signature', 'subject'],
      ['identity', 'trustSchema'],
      ['attestations', 'identity'],
      ['identity', 'provenance'],
    ],
  },
  TrustSubject: {
    properties: ['digest', 'type', 'url'],
    requiredBranches: [['digest', 'type']],
  },
  TrustSchema: {
    properties: [
      'governanceUri',
      'identifier',
      'verificationMethods',
      'version',
    ],
    requiredBranches: [['identifier', 'version']],
  },
  Attestation: {
    properties: ['description', 'digest', 'size', 'type', 'uri'],
    requiredBranches: [['type', 'uri']],
  },
  ProvenanceLink: {
    properties: [
      'registryUri',
      'relation',
      'signatureRef',
      'sourceDigest',
      'sourceId',
      'statementUri',
    ],
    requiredBranches: [['relation', 'sourceId']],
  },
} as const;

function branches(node: SchemaNode): SchemaNode[] {
  return node.anyOf ?? [node];
}

function properties(node: SchemaNode): string[] {
  return [
    ...new Set(
      branches(node).flatMap((branch) => Object.keys(branch.properties ?? {})),
    ),
  ].sort();
}

function requiredBranches(node: SchemaNode): string[][] {
  return branches(node)
    .map((branch) => [...(branch.required ?? [])].sort())
    .sort((left, right) => left.join().localeCompare(right.join()));
}

describe('pinned specification field inventory', () => {
  it('accounts mechanically for every known field and required branch', () => {
    const defs = rawSchema.$defs as Record<string, SchemaNode>;
    for (const [name, expected] of Object.entries(inventory)) {
      const node =
        name === 'AICatalog' ? (rawSchema as SchemaNode) : defs[name];
      expect(node, name).toBeDefined();
      expect(properties(node as SchemaNode), `${name} properties`).toEqual(
        [...expected.properties].sort(),
      );
      expect(requiredBranches(node as SchemaNode), `${name} required`).toEqual(
        expected.requiredBranches
          .map((branch) => [...branch].sort())
          .sort((left, right) => left.join().localeCompare(right.join())),
      );
    }
  });

  it('preserves unknown fields at every nested object boundary', () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    const parsed = parseCatalog({
      specVersion: '1.0',
      futureCatalog: true,
      host: {
        displayName: 'Host',
        futureHost: true,
      },
      entries: [
        {
          identifier: 'urn:air:example.com:artifact:one',
          type: 'custom',
          url: 'https://example.com/one',
          futureEntry: true,
          publisher: {
            identifier: 'did:web:example.com',
            displayName: 'Example',
            futurePublisher: true,
          },
          trustManifest: {
            identity: 'did:web:example.com',
            futureManifest: true,
            trustSchema: {
              identifier: 'urn:trust:example',
              version: '1',
              futureTrustSchema: true,
            },
            attestations: [
              {
                type: 'evidence',
                uri: 'https://example.com/evidence',
                futureAttestation: true,
              },
            ],
            provenance: [
              {
                relation: 'publishedFrom',
                sourceId: 'source',
                futureProvenance: true,
              },
            ],
            subject: {
              type: 'custom',
              url: 'https://example.com/one',
              digest,
              futureSubject: true,
            },
          },
        },
      ],
    }) as unknown as Record<string, unknown>;

    expect(JSON.stringify(parsed)).toContain('futureCatalog');
    expect(JSON.stringify(parsed)).toContain('futureHost');
    expect(JSON.stringify(parsed)).toContain('futureEntry');
    expect(JSON.stringify(parsed)).toContain('futurePublisher');
    expect(JSON.stringify(parsed)).toContain('futureManifest');
    expect(JSON.stringify(parsed)).toContain('futureTrustSchema');
    expect(JSON.stringify(parsed)).toContain('futureAttestation');
    expect(JSON.stringify(parsed)).toContain('futureProvenance');
    expect(JSON.stringify(parsed)).toContain('futureSubject');
  });

  it('keeps public metadata and checked rationale pinned to one commit', () => {
    expect(rawSchema['x-ai-catalog-specification']).toEqual(
      implementedSpecRevision,
    );
    const changelog = readFileSync(
      join(process.cwd(), 'CHANGELOG.md'),
      'utf8',
    );
    const unreleased = changelog
      .split(/^## /m)
      .find((section) => section.startsWith('Unreleased'));
    expect(unreleased).toContain(implementedSpecRevision.commit);

    const interpretation = readFileSync(
      join(process.cwd(), 'docs/spec-interpretation.md'),
      'utf8',
    );
    const upstreamSnapshot = `https://github.com/Agent-Card/ai-catalog/blob/${implementedSpecRevision.commit}/${implementedSpecRevision.source}`;
    expect(interpretation).toContain(upstreamSnapshot);
    expect(interpretation).toContain(
      'https://github.com/vercel-labs/ai-catalog-sdk/blob/main/src/spec-revision.ts',
    );
    expect(interpretation).toContain('../schema/ai-catalog.schema.json');
  });
});
