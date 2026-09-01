import * as z from 'zod';

import type { AICatalog, CatalogEntry, TrustManifest } from '../types.js';
import { DIGEST_PATTERN } from './digest.js';
import { isRfc3339DateTime, RFC3339_PATTERN_SOURCE } from './rfc3339.js';

const jsonObjectSchema = z.object({}).catchall(z.json());
const digestSchema = z.string().regex(DIGEST_PATTERN);

export const rfc3339DateTimeSchema = z
  .string()
  .regex(new RegExp(RFC3339_PATTERN_SOURCE))
  .refine(isRfc3339DateTime)
  .meta({ format: 'date-time' });

export const concreteTrustSubjectSchema = z
  .object({
    type: z.string(),
    digest: digestSchema,
    url: z.string().exactOptional(),
  })
  .catchall(z.json());

export const concreteTrustSchemaSchema = z
  .object({
    identifier: z.string(),
    version: z.string(),
    governanceUri: z.string().exactOptional(),
    verificationMethods: z.array(z.string()).exactOptional(),
  })
  .catchall(z.json());

export const concreteAttestationSchema = z
  .object({
    type: z.string(),
    uri: z.string(),
    digest: digestSchema.exactOptional(),
    size: z.number().int().nonnegative().exactOptional(),
    description: z.string().exactOptional(),
  })
  .catchall(z.json());

export const concreteProvenanceLinkSchema = z
  .object({
    relation: z.string(),
    sourceId: z.string(),
    sourceDigest: digestSchema.exactOptional(),
    registryUri: z.string().exactOptional(),
    statementUri: z.string().exactOptional(),
    signatureRef: z.string().exactOptional(),
  })
  .catchall(z.json());

const trustCommonShape = {
  identity: z.string(),
  identityType: z.string().exactOptional(),
  privacyPolicyUrl: z.string().exactOptional(),
  termsOfServiceUrl: z.string().exactOptional(),
  expiresAt: rfc3339DateTimeSchema.exactOptional(),
  extensions: jsonObjectSchema.exactOptional(),
};

function signedTrustShape(
  trustSchema: z.ZodType,
  attestations: z.ZodType,
  provenance: z.ZodType,
) {
  return z
    .object({
      ...trustCommonShape,
      trustSchema: trustSchema.exactOptional(),
      attestations: attestations.exactOptional(),
      provenance: provenance.exactOptional(),
      subject: concreteTrustSubjectSchema,
      issuedAt: rfc3339DateTimeSchema,
      signature: z.string(),
    })
    .catchall(z.json());
}

function unsignedTrustShapes(
  trustSchema: z.ZodType,
  attestations: z.ZodType,
  substantiveAttestations: z.ZodType,
  provenance: z.ZodType,
  substantiveProvenance: z.ZodType,
) {
  const unsignedCommon = {
    ...trustCommonShape,
    subject: concreteTrustSubjectSchema.exactOptional(),
    issuedAt: rfc3339DateTimeSchema.exactOptional(),
    signature: z.never().exactOptional(),
  };

  return [
    z
      .object({
        ...unsignedCommon,
        trustSchema,
        attestations: attestations.exactOptional(),
        provenance: provenance.exactOptional(),
      })
      .catchall(z.json()),
    z
      .object({
        ...unsignedCommon,
        trustSchema: trustSchema.exactOptional(),
        attestations: substantiveAttestations,
        provenance: provenance.exactOptional(),
      })
      .catchall(z.json()),
    z
      .object({
        ...unsignedCommon,
        trustSchema: trustSchema.exactOptional(),
        attestations: attestations.exactOptional(),
        provenance: substantiveProvenance,
      })
      .catchall(z.json()),
  ] as const;
}

const completeAttestationsSchema = z.array(concreteAttestationSchema).min(1);
const completeProvenanceSchema = z.array(concreteProvenanceLinkSchema).min(1);

export const concreteTrustManifestSchema = z.union([
  signedTrustShape(
    concreteTrustSchemaSchema,
    z.array(concreteAttestationSchema),
    z.array(concreteProvenanceLinkSchema),
  ),
  ...unsignedTrustShapes(
    concreteTrustSchemaSchema,
    z.array(concreteAttestationSchema),
    completeAttestationsSchema,
    z.array(concreteProvenanceLinkSchema),
    completeProvenanceSchema,
  ),
]);

export const concretePublisherSchema = z
  .object({
    identifier: z.string(),
    displayName: z.string(),
    identityType: z.string().exactOptional(),
  })
  .catchall(z.json());

export const concreteHostInfoSchema = z
  .object({
    displayName: z.string(),
    identifier: z.string().exactOptional(),
    documentationUrl: z.string().exactOptional(),
    logoUrl: z.string().exactOptional(),
    trustManifest: concreteTrustManifestSchema.exactOptional(),
  })
  .catchall(z.json());

const entryCommonShape = {
  identifier: z.string(),
  displayName: z.string().exactOptional(),
  type: z.string(),
  version: z.string().exactOptional(),
  description: z.string().exactOptional(),
  tags: z.array(z.string()).exactOptional(),
  publisher: concretePublisherSchema.exactOptional(),
  trustManifest: concreteTrustManifestSchema.exactOptional(),
  updatedAt: rfc3339DateTimeSchema.exactOptional(),
  extensions: jsonObjectSchema.exactOptional(),
};

export const concreteCatalogEntrySchema = z.union([
  z
    .object({
      ...entryCommonShape,
      url: z.string(),
      data: z.never().exactOptional(),
    })
    .catchall(z.json()),
  z
    .object({
      ...entryCommonShape,
      data: z.json(),
      url: z.never().exactOptional(),
    })
    .catchall(z.json()),
]);

export const concreteAICatalogSchema = z
  .object({
    specVersion: z.string().regex(/^[0-9]+\.[0-9]+$/),
    host: concreteHostInfoSchema.exactOptional(),
    entries: z.array(concreteCatalogEntrySchema),
    extensions: jsonObjectSchema.exactOptional(),
    signature: z.string().exactOptional(),
  })
  .catchall(z.json());

const trustEnvelopeAttestationsSchema = z.array(z.unknown()).min(1);
const trustEnvelopeProvenanceSchema = z.array(z.unknown()).min(1);

export const trustManifestEnvelopeSchema = z.union([
  signedTrustShape(z.unknown(), z.array(z.unknown()), z.array(z.unknown())),
  ...unsignedTrustShapes(
    z.unknown(),
    z.array(z.unknown()),
    trustEnvelopeAttestationsSchema,
    z.array(z.unknown()),
    trustEnvelopeProvenanceSchema,
  ),
]);

export const trustSchemaEnvelopeSchema = z
  .object({
    identifier: z.string(),
    version: z.string(),
    governanceUri: z.string().exactOptional(),
    verificationMethods: z.array(z.unknown()).exactOptional(),
  })
  .catchall(z.json());

export const hostInfoEnvelopeSchema = z
  .object({
    displayName: z.string(),
    identifier: z.string().exactOptional(),
    documentationUrl: z.string().exactOptional(),
    logoUrl: z.string().exactOptional(),
    trustManifest: z.unknown().exactOptional(),
  })
  .catchall(z.json());

const entryEnvelopeCommonShape = {
  identifier: z.string(),
  displayName: z.string().exactOptional(),
  type: z.string(),
  version: z.string().exactOptional(),
  description: z.string().exactOptional(),
  tags: z.array(z.unknown()).exactOptional(),
  publisher: concretePublisherSchema.exactOptional(),
  trustManifest: z.unknown().exactOptional(),
  updatedAt: rfc3339DateTimeSchema.exactOptional(),
  extensions: jsonObjectSchema.exactOptional(),
};

export const catalogEntryEnvelopeSchema = z.union([
  z
    .object({
      ...entryEnvelopeCommonShape,
      url: z.string(),
      data: z.never().exactOptional(),
    })
    .catchall(z.json()),
  z
    .object({
      ...entryEnvelopeCommonShape,
      data: z.json(),
      url: z.never().exactOptional(),
    })
    .catchall(z.json()),
]);

export const aiCatalogEnvelopeSchema = z
  .object({
    specVersion: z.string().regex(/^[0-9]+\.[0-9]+$/),
    host: z.unknown().exactOptional(),
    entries: z.array(z.unknown()),
    extensions: jsonObjectSchema.exactOptional(),
    signature: z.string().exactOptional(),
  })
  .catchall(z.json());

export const stringItemSchema = z.string();

export const aiCatalogSchema = concreteAICatalogSchema as z.ZodType<
  AICatalog,
  AICatalog
>;
export const catalogEntrySchema = concreteCatalogEntrySchema as z.ZodType<
  CatalogEntry,
  CatalogEntry
>;
export const trustManifestSchema = concreteTrustManifestSchema as z.ZodType<
  TrustManifest,
  TrustManifest
>;

export const schemaRegistry = z.registry<{
  id: string;
  title: string;
  description: string;
  format?: string;
}>();

schemaRegistry.add(rfc3339DateTimeSchema, {
  id: 'Rfc3339DateTime',
  title: 'RFC 3339 Date-Time',
  description: 'An RFC 3339 timestamp with required seconds.',
  format: 'date-time',
});
schemaRegistry.add(concreteAICatalogSchema, {
  id: 'AICatalog',
  title: 'AI Catalog',
  description: 'An SDK-maintained structural schema for an AI Catalog.',
});
schemaRegistry.add(concreteCatalogEntrySchema, {
  id: 'CatalogEntry',
  title: 'Catalog Entry',
  description: 'An AI artifact catalog entry with `url` or inline `data`.',
});
schemaRegistry.add(concreteHostInfoSchema, {
  id: 'HostInfo',
  title: 'Host Info',
  description: 'Information identifying an AI Catalog host.',
});
schemaRegistry.add(concretePublisherSchema, {
  id: 'Publisher',
  title: 'Publisher',
  description: 'Information identifying an artifact publisher.',
});
schemaRegistry.add(concreteTrustManifestSchema, {
  id: 'TrustManifest',
  title: 'Trust Manifest',
  description: 'Structured but unverified trust metadata.',
});
schemaRegistry.add(concreteTrustSubjectSchema, {
  id: 'TrustSubject',
  title: 'Trust Subject',
  description: 'A digest binding between a Trust Manifest and an artifact.',
});
schemaRegistry.add(concreteTrustSchemaSchema, {
  id: 'TrustSchema',
  title: 'Trust Schema',
  description: 'A trust framework applied to an artifact.',
});
schemaRegistry.add(concreteAttestationSchema, {
  id: 'Attestation',
  title: 'Attestation',
  description: 'A reference to evidence supporting a trust claim.',
});
schemaRegistry.add(concreteProvenanceLinkSchema, {
  id: 'ProvenanceLink',
  title: 'Provenance Link',
  description: 'A link in an artifact provenance chain.',
});
