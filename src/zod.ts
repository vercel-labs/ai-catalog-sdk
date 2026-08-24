import type * as z from 'zod';

import {
  aiCatalogSchema as internalAICatalogSchema,
  catalogEntrySchema as internalCatalogEntrySchema,
  trustManifestSchema as internalTrustManifestSchema,
} from './internal/schemas.js';
import type { AICatalog, CatalogEntry, TrustManifest } from './types.js';

export const aiCatalogSchema: z.ZodType<AICatalog, AICatalog> =
  internalAICatalogSchema;
export const catalogEntrySchema: z.ZodType<CatalogEntry, CatalogEntry> =
  internalCatalogEntrySchema;
export const trustManifestSchema: z.ZodType<TrustManifest, TrustManifest> =
  internalTrustManifestSchema;
