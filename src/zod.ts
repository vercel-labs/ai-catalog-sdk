import type * as z from 'zod';

import {
  aiCatalogSchema as internalAICatalogSchema,
  catalogEntrySchema as internalCatalogEntrySchema,
  trustManifestSchema as internalTrustManifestSchema,
} from './internal/schemas.js';
import type { AICatalog, CatalogEntry, TrustManifest } from './types.js';

/**
 * Zod schema for structural validation of a complete AI Catalog document.
 *
 * Uses native Zod behavior and errors. Unlike `parseCatalog()`, it does not
 * require a supported specification major, enforce entry uniqueness, compare
 * a Trust Manifest subject with its containing entry, or apply defensive input
 * checks and resource limits.
 */
export const aiCatalogSchema: z.ZodType<AICatalog, AICatalog> =
  internalAICatalogSchema;

/**
 * Zod schema for structural validation of one inline or referenced catalog
 * entry.
 *
 * Uses native Zod behavior and errors. Unlike `parseCatalogEntry()`, it does
 * not compare a Trust Manifest subject with its containing entry or apply
 * defensive input checks and resource limits.
 */
export const catalogEntrySchema: z.ZodType<CatalogEntry, CatalogEntry> =
  internalCatalogEntrySchema;

/**
 * Zod schema for structural validation of a Trust Manifest.
 *
 * Uses native Zod behavior and errors without defensive input checks or
 * resource limits. It does not compare its subject with a containing entry or
 * verify the claims or referenced evidence it contains.
 */
export const trustManifestSchema: z.ZodType<TrustManifest, TrustManifest> =
  internalTrustManifestSchema;
