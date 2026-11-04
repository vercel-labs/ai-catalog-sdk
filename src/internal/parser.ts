import type * as z from 'zod';

import { implementedSpecRevision } from '../spec-revision.js';
import {
  CatalogParseError,
  type AICatalog,
  type Attestation,
  type CatalogEntry,
  type HostInfo,
  type ParseResult,
  type ProvenanceLink,
  type TrustManifest,
  type TrustSchema,
} from '../types.js';
import { preflightJsonValue } from './json-value.js';
import { IssueCollector, issue, type Path } from './issues.js';
import {
  aiCatalogEnvelopeSchema,
  catalogEntryEnvelopeSchema,
  parsedAttestationSchema,
  parsedProvenanceLinkSchema,
  hostInfoEnvelopeSchema,
  stringItemSchema,
  trustManifestEnvelopeSchema,
  trustSchemaEnvelopeSchema,
} from './schemas.js';

const hasOwn = (value: object, key: PropertyKey): boolean =>
  Object.hasOwn(value, key);

function parseStringArray(
  values: readonly unknown[],
  path: Path,
  collector: IssueCollector,
): string[] | undefined {
  const output: string[] = [];
  let valid = true;
  for (let index = 0; index < values.length && !collector.stopped; index += 1) {
    const result = stringItemSchema.safeParse(values[index]);
    if (result.success) output.push(result.data);
    else {
      valid = false;
      collector.addZod(result.error, [...path, index]);
    }
  }
  return valid ? output : undefined;
}

function parseTrustSchema(
  input: unknown,
  path: Path,
  collector: IssueCollector,
): TrustSchema | undefined {
  const result = trustSchemaEnvelopeSchema.safeParse(input);
  if (!result.success) {
    collector.addZod(result.error, path);
    return undefined;
  }
  const output = result.data as TrustSchema;
  if (hasOwn(result.data, 'verificationMethods')) {
    const methods = parseStringArray(
      result.data.verificationMethods as unknown[],
      [...path, 'verificationMethods'],
      collector,
    );
    if (!methods) return undefined;
    output.verificationMethods = methods;
  }
  return output;
}

function parseItemArray<T>(
  values: readonly unknown[],
  schema: z.ZodType<T>,
  path: Path,
  collector: IssueCollector,
): T[] | undefined {
  const output: T[] = [];
  let valid = true;
  for (let index = 0; index < values.length && !collector.stopped; index += 1) {
    const result = schema.safeParse(values[index]);
    if (result.success) output.push(result.data);
    else {
      valid = false;
      collector.addZod(result.error, [...path, index]);
    }
  }
  return valid ? output : undefined;
}

function parseTrustManifest(
  input: unknown,
  path: Path,
  collector: IssueCollector,
): TrustManifest | undefined {
  const result = trustManifestEnvelopeSchema.safeParse(input);
  if (!result.success) {
    collector.addZod(result.error, path);
    return undefined;
  }

  const output = result.data as TrustManifest;
  let valid = true;
  if (hasOwn(result.data, 'trustSchema')) {
    const parsed = parseTrustSchema(
      result.data.trustSchema,
      [...path, 'trustSchema'],
      collector,
    );
    if (parsed) output.trustSchema = parsed;
    else valid = false;
  }
  if (collector.stopped) return undefined;
  if (hasOwn(result.data, 'attestations')) {
    const parsed = parseItemArray<Attestation>(
      result.data.attestations as unknown[],
      parsedAttestationSchema as z.ZodType<Attestation>,
      [...path, 'attestations'],
      collector,
    );
    if (parsed) output.attestations = parsed;
    else valid = false;
  }
  if (collector.stopped) return undefined;
  if (hasOwn(result.data, 'provenance')) {
    const parsed = parseItemArray<ProvenanceLink>(
      result.data.provenance as unknown[],
      parsedProvenanceLinkSchema as z.ZodType<ProvenanceLink>,
      [...path, 'provenance'],
      collector,
    );
    if (parsed) output.provenance = parsed;
    else valid = false;
  }
  return valid ? output : undefined;
}

function parseHostInfo(
  input: unknown,
  path: Path,
  collector: IssueCollector,
): HostInfo | undefined {
  const result = hostInfoEnvelopeSchema.safeParse(input);
  if (!result.success) {
    collector.addZod(result.error, path);
    return undefined;
  }
  return result.data as HostInfo;
}

function parseCatalogEntryValue(
  input: unknown,
  path: Path,
  collector: IssueCollector,
): CatalogEntry | undefined {
  const result = catalogEntryEnvelopeSchema.safeParse(input);
  if (!result.success) {
    collector.addZod(result.error, path);
    return undefined;
  }

  const output = result.data as CatalogEntry;
  let valid = true;
  if (hasOwn(result.data, 'tags')) {
    const tags = parseStringArray(
      result.data.tags as unknown[],
      [...path, 'tags'],
      collector,
    );
    if (tags) output.tags = tags;
    else valid = false;
  }
  if (collector.stopped) return undefined;
  if (hasOwn(result.data, 'trustManifests')) {
    const manifests: TrustManifest[] = [];
    const values = result.data.trustManifests as unknown[];
    for (
      let index = 0;
      index < values.length && !collector.stopped;
      index += 1
    ) {
      const manifestPath = [...path, 'trustManifests', index];
      const manifest = parseTrustManifest(
        values[index],
        manifestPath,
        collector,
      );
      if (!manifest) {
        valid = false;
        continue;
      }
      manifests.push(manifest);
    }
    output.trustManifests = manifests;
  }
  return valid ? output : undefined;
}

function normalizedDecimal(value: string): string {
  return value.replace(/^0+(?=[0-9])/, '');
}

function parseCatalogValue(
  input: unknown,
  collector: IssueCollector,
): AICatalog | undefined {
  const result = aiCatalogEnvelopeSchema.safeParse(input);
  if (!result.success) {
    collector.addZod(result.error, []);
    return undefined;
  }

  const [major] = result.data.specVersion.split('.');
  const [supportedMajor] = implementedSpecRevision.specVersion.split('.');
  if (
    major === undefined ||
    supportedMajor === undefined ||
    normalizedDecimal(major) !== normalizedDecimal(supportedMajor)
  ) {
    collector.add(
      issue(
        'unsupported_spec_version',
        ['specVersion'],
        `This SDK supports AI Catalog major version ${supportedMajor}.`,
      ),
    );
    return undefined;
  }

  const output = result.data as AICatalog;
  let valid = true;
  if (hasOwn(result.data, 'host')) {
    const host = parseHostInfo(result.data.host, ['host'], collector);
    if (host) output.host = host;
    else valid = false;
  }
  if (collector.stopped) return undefined;

  const entries: CatalogEntry[] = [];
  for (
    let index = 0;
    index < result.data.entries.length && !collector.stopped;
    index += 1
  ) {
    const entry = parseCatalogEntryValue(
      result.data.entries[index],
      ['entries', index],
      collector,
    );
    if (entry) {
      entries.push(entry);
    } else valid = false;
  }
  output.entries = entries;
  return valid ? output : undefined;
}

function safeParseWith<T>(
  input: unknown,
  parser: (input: unknown, collector: IssueCollector) => T | undefined,
): ParseResult<T> {
  const preflightIssue = preflightJsonValue(input, {
    allowOwnProtoMember: false,
    isDisallowedObject: undefined,
    requireIJsonStrings: false,
  });
  if (preflightIssue) {
    return {
      success: false,
      error: new CatalogParseError([preflightIssue]),
    };
  }
  const collector = new IssueCollector();
  const data = parser(input, collector);
  const error = collector.finish(CatalogParseError);
  if (error || data === undefined) {
    return {
      success: false,
      error:
        error ??
        new CatalogParseError([
          issue('invalid_value', [], 'The value is not a valid AI Catalog.'),
        ]),
    };
  }
  return { success: true, data };
}

/**
 * Validates an already-parsed JSON value as an AI Catalog.
 *
 * Applies the SDK's defensive input checks and supported-version handling.
 *
 * @param input - The already-parsed JSON value to validate.
 * @returns A {@link ParseResult} containing the validated catalog or validation
 * diagnostics.
 * @see {@link parseCatalog} for the throwing variant.
 */
export function safeParseCatalog(input: unknown): ParseResult<AICatalog> {
  return safeParseWith(input, parseCatalogValue);
}

/**
 * Validates and returns an already-parsed JSON value as an AI Catalog.
 *
 * @param input - The already-parsed JSON value to validate.
 * @returns The validated catalog.
 * @throws `CatalogParseError` if validation fails.
 * @see {@link safeParseCatalog} for the non-throwing variant.
 */
export function parseCatalog(input: unknown): AICatalog {
  const result = safeParseCatalog(input);
  if (!result.success) throw result.error;
  return result.data;
}

/**
 * Validates an already-parsed JSON value as a single AI Catalog entry.
 *
 * @param input - The already-parsed JSON value to validate.
 * @returns A {@link ParseResult} containing the validated entry or validation
 * diagnostics.
 * @see {@link parseCatalogEntry} for the throwing variant.
 */
export function safeParseCatalogEntry(
  input: unknown,
): ParseResult<CatalogEntry> {
  return safeParseWith(input, (entryInput, collector) =>
    parseCatalogEntryValue(entryInput, [], collector),
  );
}

/** Internal manifest validation with the root parsers' bounded diagnostics. */
export function safeParseTrustManifest(
  input: unknown,
): ParseResult<TrustManifest> {
  return safeParseWith(input, (manifestInput, collector) =>
    parseTrustManifest(manifestInput, [], collector),
  );
}

/**
 * Validates and returns an already-parsed JSON value as a single AI Catalog
 * entry.
 *
 * @param input - The already-parsed JSON value to validate.
 * @returns The validated catalog entry.
 * @throws `CatalogParseError` if validation fails.
 * @see {@link safeParseCatalogEntry} for the non-throwing variant.
 */
export function parseCatalogEntry(input: unknown): CatalogEntry {
  const result = safeParseCatalogEntry(input);
  if (!result.success) throw result.error;
  return result.data;
}

/**
 * Parses and validates an AI Catalog JSON string.
 *
 * @param json - The JSON text to parse and validate.
 * @returns A {@link ParseResult} containing the validated catalog or parsing
 * and validation diagnostics.
 * @see {@link parseCatalogJson} for the throwing variant.
 */
export function safeParseCatalogJson(json: string): ParseResult<AICatalog> {
  if (typeof json !== 'string') {
    return {
      success: false,
      error: new CatalogParseError([
        issue('invalid_type', [], 'Catalog JSON input must be a string.'),
      ]),
    };
  }
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch (cause) {
    if (!(cause instanceof SyntaxError)) throw cause;
    return {
      success: false,
      error: new CatalogParseError(
        [issue('invalid_json', [], 'The catalog text is not valid JSON.')],
        cause,
      ),
    };
  }
  return safeParseCatalog(value);
}

/**
 * Parses and validates an AI Catalog JSON string.
 *
 * @param json - The JSON text to parse and validate.
 * @returns The validated catalog.
 * @throws `CatalogParseError` if the text is not valid JSON or catalog
 * validation fails.
 * @see {@link safeParseCatalogJson} for the non-throwing variant.
 */
export function parseCatalogJson(json: string): AICatalog {
  const result = safeParseCatalogJson(json);
  if (!result.success) throw result.error;
  return result.data;
}
