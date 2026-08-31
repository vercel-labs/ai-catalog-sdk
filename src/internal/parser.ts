import type * as z from 'zod';

import { implementedSpecRevision } from '../spec-revision.js';
import {
  CatalogParseError,
  type AICatalog,
  type Attestation,
  type CatalogEntry,
  type CatalogIssue,
  type HostInfo,
  type ParseResult,
  type ProvenanceLink,
  type TrustManifest,
  type TrustSchema,
} from '../types.js';
import { preflightJsonValue } from './json-value.js';
import {
  aiCatalogEnvelopeSchema,
  catalogEntryEnvelopeSchema,
  concreteAttestationSchema,
  concreteProvenanceLinkSchema,
  hostInfoEnvelopeSchema,
  stringItemSchema,
  trustManifestEnvelopeSchema,
  trustSchemaEnvelopeSchema,
} from './schemas.js';

const MAX_ISSUES = 100;

type Path = readonly (string | number)[];

const hasOwn = (value: object, key: PropertyKey): boolean =>
  Object.hasOwn(value, key);

function issue(code: string, path: Path, message: string): CatalogIssue {
  return { code, path, message };
}

function stableZodIssue(raw: z.core.$ZodIssue, prefix: Path): CatalogIssue {
  const rawPath = raw.path.filter(
    (part): part is string | number =>
      typeof part === 'string' || typeof part === 'number',
  );
  const path = [...prefix, ...rawPath];

  switch (raw.code) {
    case 'invalid_type':
      return issue(
        'invalid_type',
        path,
        'The value is not the required JSON type.',
      );
    case 'invalid_format':
      return issue(
        'invalid_value',
        path,
        'The string does not use the required format.',
      );
    case 'invalid_union':
      return issue(
        'invalid_value',
        path,
        'The value does not match any allowed structure.',
      );
    case 'too_big':
    case 'too_small':
      return issue(
        'invalid_value',
        path,
        'The value is outside the allowed range.',
      );
    default:
      return issue(
        'invalid_value',
        path,
        'The value violates an AI Catalog structural rule.',
      );
  }
}

class IssueCollector {
  readonly issues: CatalogIssue[] = [];
  cause: unknown;
  truncated = false;

  get stopped(): boolean {
    return this.truncated;
  }

  add(catalogIssue: CatalogIssue, cause?: unknown): void {
    if (this.truncated) return;
    if (this.cause === undefined && cause !== undefined) this.cause = cause;
    if (this.issues.length < MAX_ISSUES) {
      this.issues.push(catalogIssue);
      return;
    }
    this.truncated = true;
  }

  addZod(error: z.ZodError, prefix: Path): void {
    if (this.cause === undefined) this.cause = error;
    for (const rawIssue of error.issues) {
      this.add(stableZodIssue(rawIssue, prefix));
      if (this.stopped) break;
    }
  }

  finish(): CatalogParseError | undefined {
    if (this.truncated) {
      this.issues.push(
        issue(
          'diagnostics_truncated',
          [],
          'Additional validation issues were omitted.',
        ),
      );
    }
    if (this.issues.length === 0) return undefined;
    return new CatalogParseError(this.issues, this.cause);
  }
}

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
      concreteAttestationSchema as z.ZodType<Attestation>,
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
      concreteProvenanceLinkSchema as z.ZodType<ProvenanceLink>,
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
  const output = result.data as HostInfo;
  if (hasOwn(result.data, 'trustManifest')) {
    const manifest = parseTrustManifest(
      result.data.trustManifest,
      [...path, 'trustManifest'],
      collector,
    );
    if (!manifest) return undefined;
    output.trustManifest = manifest;
  }
  return output;
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
  if (hasOwn(result.data, 'trustManifest')) {
    const manifest = parseTrustManifest(
      result.data.trustManifest,
      [...path, 'trustManifest'],
      collector,
    );
    if (manifest) {
      output.trustManifest = manifest;
      const { subject } = manifest;
      if (subject && subject.type !== output.type) {
        valid = false;
        collector.add(
          issue(
            'inconsistent_value',
            [...path, 'trustManifest', 'subject', 'type'],
            'Trust Manifest subject.type must match the catalog entry type.',
          ),
        );
      }
      if (subject?.url !== undefined) {
        if (!('url' in output) || subject.url !== output.url) {
          valid = false;
          collector.add(
            issue(
              'inconsistent_value',
              [...path, 'trustManifest', 'subject', 'url'],
              'Trust Manifest subject.url must match a referenced entry URL.',
            ),
          );
        }
      }
    } else valid = false;
  }
  return valid ? output : undefined;
}

function normalizedDecimal(value: string): string {
  return value.replace(/^0+(?=[0-9])/, '');
}

function validateEntryUniqueness(
  indexedEntries: readonly { entry: CatalogEntry; index: number }[],
  collector: IssueCollector,
): void {
  const seen = new Map<
    string,
    { unversioned: boolean; versions: Set<string> }
  >();
  for (
    let index = 0;
    index < indexedEntries.length && !collector.stopped;
    index += 1
  ) {
    const indexedEntry = indexedEntries[index];
    if (!indexedEntry) continue;
    const { entry, index: inputIndex } = indexedEntry;
    const state = seen.get(entry.identifier) ?? {
      unversioned: false,
      versions: new Set<string>(),
    };
    const version = entry.version;
    const duplicate =
      version === undefined
        ? state.unversioned || state.versions.size > 0
        : state.unversioned || state.versions.has(version);
    if (duplicate) {
      collector.add(
        issue(
          'duplicate_entry',
          [
            'entries',
            inputIndex,
            version === undefined ? 'identifier' : 'version',
          ],
          'Catalog entry identifiers and versions must be unique.',
        ),
      );
    }
    if (version === undefined) state.unversioned = true;
    else state.versions.add(version);
    seen.set(entry.identifier, state);
  }
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
  const indexedEntries: { entry: CatalogEntry; index: number }[] = [];
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
      indexedEntries.push({ entry, index });
    } else valid = false;
  }
  output.entries = entries;
  validateEntryUniqueness(indexedEntries, collector);
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
  const error = collector.finish();
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
 * Applies the SDK's defensive input checks and catalog-wide validation.
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
