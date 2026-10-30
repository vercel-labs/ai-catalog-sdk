import * as z from 'zod';

import type { AICatalog, CatalogEntry, TrustManifest } from '../types.js';
import { DIGEST_PATTERN } from './digest.js';
import {
  compareRfc3339DateTimes,
  isRfc3339DateTime,
  RFC3339_PATTERN_SOURCE,
} from './rfc3339.js';

const jsonObjectSchema = z.object({}).catchall(z.json());
const digestSchema = z.string().regex(DIGEST_PATTERN);

export const rfc3339DateTimeSchema = z
  .string()
  .regex(new RegExp(RFC3339_PATTERN_SOURCE))
  .refine(isRfc3339DateTime)
  .meta({ format: 'date-time' });

export const concreteTrustSubjectSchema = z
  .object({
    identifier: z.string(),
    version: z.string().exactOptional(),
    type: z.string(),
    digest: digestSchema,
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

// RFC 3986 Appendix A grammar, allowing one fragment on a URI with a scheme.
const uriToken = "(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2}|[!$&'()*+,;=])";
const uriPchar = `(?:${uriToken}|[:@])`;
const decimalOctet = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const ipv4 = `${decimalOctet}(?:\\.${decimalOctet}){3}`;
const hex16 = '[A-Fa-f0-9]{1,4}';
const last32 = `(?:${hex16}:${hex16}|${ipv4})`;
const ipv6 = [
  `(?:${hex16}:){6}${last32}`,
  `::(?:${hex16}:){5}${last32}`,
  `(?:${hex16})?::(?:${hex16}:){4}${last32}`,
  `(?:(?:${hex16}:){0,1}${hex16})?::(?:${hex16}:){3}${last32}`,
  `(?:(?:${hex16}:){0,2}${hex16})?::(?:${hex16}:){2}${last32}`,
  `(?:(?:${hex16}:){0,3}${hex16})?::${hex16}:${last32}`,
  `(?:(?:${hex16}:){0,4}${hex16})?::${last32}`,
  `(?:(?:${hex16}:){0,5}${hex16})?::${hex16}`,
  `(?:(?:${hex16}:){0,6}${hex16})?::`,
].join('|');
const ipvFuture = `[vV][A-Fa-f0-9]+\\.(?:[A-Za-z0-9._~-]|[!$&'()*+,;=:])+`;
const uriHost = `(?:\\[(?:${ipv6}|${ipvFuture})\\]|${uriToken}*)`;
const uriAuthority = `(?:(?:${uriToken}|:)*@)?${uriHost}(?::[0-9]*)?`;
const uriHierarchy = `(?://${uriAuthority}(?:/${uriPchar}*)*|/(?:${uriPchar}+(?:/${uriPchar}*)*)?|${uriPchar}+(?:/${uriPchar}*)*|)`;
const absoluteUriSchema = z
  .string()
  .regex(
    new RegExp(
      `^[A-Za-z][A-Za-z0-9+.-]*:${uriHierarchy}(?:\\?(?:${uriPchar}|[/?])*)?(?:#(?:${uriPchar}|[/?])*)?$(?![\\s\\S])`,
    ),
  );

export const concreteSignatureSchema = z
  .object({
    signer: absoluteUriSchema,
    profile: z.string().min(1),
    issuedAt: rfc3339DateTimeSchema,
    expiresAt: rfc3339DateTimeSchema.exactOptional(),
    jws: z.string(),
  })
  .catchall(z.json())
  .refine(
    (signature) =>
      signature.expiresAt === undefined ||
      !isRfc3339DateTime(signature.issuedAt) ||
      !isRfc3339DateTime(signature.expiresAt) ||
      compareRfc3339DateTimes(signature.expiresAt, signature.issuedAt) > 0,
    {
      path: ['expiresAt'],
      message: 'expiresAt must be strictly after issuedAt.',
    },
  );

const trustCommonShape = {
  contributor: absoluteUriSchema,
  additionalSignatures: z.json().exactOptional(),
  extensions: jsonObjectSchema.exactOptional(),
};

const substantiveExtensionsSchema = jsonObjectSchema
  .refine((extensions) => Object.keys(extensions).length > 0)
  .meta({ minProperties: 1 });

function trustManifestShapes(
  trustSchema: z.ZodType,
  attestations: z.ZodType,
  substantiveAttestations: z.ZodType,
  provenance: z.ZodType,
  substantiveProvenance: z.ZodType,
) {
  const unsignedCommon = {
    ...trustCommonShape,
    subject: concreteTrustSubjectSchema.exactOptional(),
    signature: z.never().exactOptional(),
  };
  return [
    z
      .object({
        ...trustCommonShape,
        trustSchema: trustSchema.exactOptional(),
        attestations: attestations.exactOptional(),
        provenance: provenance.exactOptional(),
        subject: concreteTrustSubjectSchema,
        signature: concreteSignatureSchema,
      })
      .catchall(z.json()),
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
    z
      .object({
        ...unsignedCommon,
        trustSchema: trustSchema.exactOptional(),
        attestations: attestations.exactOptional(),
        provenance: provenance.exactOptional(),
        extensions: substantiveExtensionsSchema,
      })
      .catchall(z.json()),
  ] as const;
}

function contributorMatchesSigner(manifest: {
  contributor: string;
  signature?: { signer: string };
}): boolean {
  return (
    manifest.signature === undefined ||
    manifest.signature.signer === manifest.contributor
  );
}

export const concreteTrustManifestSchema = z
  .union(
    trustManifestShapes(
      concreteTrustSchemaSchema,
      z.array(concreteAttestationSchema),
      z.array(concreteAttestationSchema).min(1),
      z.array(concreteProvenanceLinkSchema),
      z.array(concreteProvenanceLinkSchema).min(1),
    ),
  )
  .refine(contributorMatchesSigner, {
    path: ['signature', 'signer'],
    message: 'Signature signer must exactly equal contributor.',
  });

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
  digest: digestSchema.exactOptional(),
  trustManifests: z.array(concreteTrustManifestSchema).exactOptional(),
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
    signature: concreteSignatureSchema.exactOptional(),
    additionalSignatures: z.json().exactOptional(),
  })
  .catchall(z.json());

export const trustManifestEnvelopeSchema = z
  .union(
    trustManifestShapes(
      z.unknown(),
      z.array(z.unknown()),
      z.array(z.unknown()).min(1),
      z.array(z.unknown()),
      z.array(z.unknown()).min(1),
    ),
  )
  .refine(contributorMatchesSigner, {
    path: ['signature', 'signer'],
    message: 'Signature signer must exactly equal contributor.',
  });

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
  digest: digestSchema.exactOptional(),
  trustManifests: z.array(z.unknown()).exactOptional(),
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
    signature: concreteSignatureSchema.exactOptional(),
    additionalSignatures: z.json().exactOptional(),
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
  minProperties?: number;
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

schemaRegistry.add(concreteSignatureSchema, {
  id: 'Signature',
  title: 'Signature',
  description: 'Signature metadata and a detached compact JWS.',
});

schemaRegistry.add(substantiveExtensionsSchema, {
  id: 'SubstantiveExtensions',
  title: 'Substantive Extensions',
  description: 'A non-empty object of namespaced contributor claims.',
  minProperties: 1,
});
