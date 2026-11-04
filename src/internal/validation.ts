import {
  CatalogValidationError,
  type AICatalog,
  type CatalogEntry,
  type JsonValue,
  type TrustManifest,
} from '../types.js';
import { DIGEST_HEX_LENGTHS, DIGEST_PATTERN } from './digest.js';
import { IssueCollector, issue, type Path } from './issues.js';
import { safeParseCatalog } from './parser.js';
import {
  absoluteUriSchema,
  concreteSignatureSchema,
  rfc3339DateTimeSchema,
} from './schemas.js';
import {
  validateSignatureDeclarations,
  validateSignedPayload,
} from './signature-declarations.js';

const manifestFields = new Set([
  'contributor',
  'subject',
  'signature',
  'additionalSignatures',
  'trustSchema',
  'attestations',
  'provenance',
  'extensions',
]);

function validateDigest(
  value: string,
  path: Path,
  collector: IssueCollector,
): void {
  if (!DIGEST_PATTERN.test(value)) {
    collector.add(
      issue(
        'invalid_value',
        path,
        'The digest must use algorithm:lowercase-hex form.',
      ),
    );
    return;
  }
  const separator = value.indexOf(':');
  const algorithm = value.slice(0, separator);
  const length = Object.hasOwn(DIGEST_HEX_LENGTHS, algorithm)
    ? DIGEST_HEX_LENGTHS[algorithm as keyof typeof DIGEST_HEX_LENGTHS]
    : undefined;
  if (length !== undefined && value.length - separator - 1 !== length)
    collector.add(
      issue(
        'invalid_value',
        path,
        `The ${algorithm} digest must contain ${length} hexadecimal characters.`,
      ),
    );
}

function validateSignatureMetadata(
  signature: TrustManifest['signature'],
  path: Path,
  collector: IssueCollector,
): void {
  if (signature === undefined) return;
  const result = concreteSignatureSchema.safeParse(signature);
  if (!result.success) collector.addZod(result.error, path);
}

function validateManifestDeclarations(
  manifest: TrustManifest,
  path: Path,
  collector: IssueCollector,
  entry?: CatalogEntry,
  entryPath?: Path,
): void {
  const contributor = absoluteUriSchema.safeParse(manifest.contributor);
  if (!contributor.success)
    collector.addZod(contributor.error, [...path, 'contributor']);
  validateSignatureMetadata(
    manifest.signature,
    [...path, 'signature'],
    collector,
  );
  if (
    manifest.signature !== undefined &&
    manifest.signature.signer !== manifest.contributor
  )
    collector.add(
      issue(
        'inconsistent_value',
        [...path, 'signature', 'signer'],
        'Signature signer must exactly equal contributor.',
      ),
    );

  const substantive =
    manifest.signature !== undefined ||
    manifest.trustSchema !== undefined ||
    (manifest.attestations?.length ?? 0) > 0 ||
    (manifest.provenance?.length ?? 0) > 0 ||
    Object.keys(manifest.extensions ?? {}).length > 0 ||
    Object.keys(manifest).some((key) => !manifestFields.has(key));
  if (!substantive)
    collector.add(
      issue(
        'invalid_value',
        path,
        'A Trust Manifest must contain substantive content.',
      ),
    );
  if (manifest.signature !== undefined && manifest.subject === undefined)
    collector.add(
      issue(
        'invalid_value',
        [...path, 'subject'],
        'A signed Trust Manifest requires a subject.',
      ),
    );

  const subject = manifest.subject;
  if (subject !== undefined) {
    validateDigest(subject.digest, [...path, 'subject', 'digest'], collector);
    if (entry !== undefined) {
      for (const field of ['identifier', 'type', 'digest'] as const)
        if (subject[field] !== entry[field])
          collector.add(
            issue(
              'inconsistent_value',
              [...path, 'subject', field],
              `Trust Manifest subject.${field} must match the containing entry.`,
            ),
          );
      if (
        Object.hasOwn(subject, 'version') !== Object.hasOwn(entry, 'version') ||
        subject.version !== entry.version
      )
        collector.add(
          issue(
            'inconsistent_value',
            [...path, 'subject', 'version'],
            'Subject and entry versions must both be absent or both be present and exactly equal.',
          ),
        );
    }
  }
  if (
    entry !== undefined &&
    manifest.signature !== undefined &&
    entry.digest === undefined
  )
    collector.add(
      issue(
        'inconsistent_value',
        entryPath === undefined
          ? [...path, 'subject', 'digest']
          : [...entryPath, 'digest'],
        'The containing entry must declare a digest for a signed Trust Manifest.',
      ),
    );

  for (
    let index = 0;
    index < (manifest.attestations?.length ?? 0) && !collector.stopped;
    index += 1
  ) {
    const attestation = manifest.attestations?.[index];
    if (attestation === undefined) continue;
    const itemPath = [...path, 'attestations', index];
    if (attestation.digest !== undefined)
      validateDigest(attestation.digest, [...itemPath, 'digest'], collector);
    if (
      attestation.size !== undefined &&
      (!Number.isSafeInteger(attestation.size) || attestation.size < 0)
    )
      collector.add(
        issue(
          'invalid_value',
          [...itemPath, 'size'],
          'Attestation size must be a nonnegative safe integer.',
        ),
      );
  }
  for (
    let index = 0;
    index < (manifest.provenance?.length ?? 0) && !collector.stopped;
    index += 1
  ) {
    const link = manifest.provenance?.[index];
    if (link?.sourceDigest !== undefined)
      validateDigest(
        link.sourceDigest,
        [...path, 'provenance', index, 'sourceDigest'],
        collector,
      );
  }
}

/** Validate captured manifest declarations without imposing JWS/profile capability policy. */
export function validateTrustManifest(
  manifest: TrustManifest,
  entry?: CatalogEntry,
): CatalogValidationError | undefined {
  const collector = new IssueCollector();
  validateManifestDeclarations(manifest, [], collector, entry);
  const payloadIssue = validateSignedPayload(
    manifest as unknown as Record<string, JsonValue>,
  );
  if (payloadIssue !== undefined) collector.add(payloadIssue);
  return collector.finish(CatalogValidationError);
}

function validateEntryUniqueness(
  entries: readonly CatalogEntry[],
  collector: IssueCollector,
): void {
  const seen = new Map<
    string,
    { unversioned: boolean; versions: Set<string> }
  >();
  for (
    let index = 0;
    index < entries.length && !collector.stopped;
    index += 1
  ) {
    const entry = entries[index];
    if (entry === undefined) continue;
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
            index,
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

/**
 * Check an assembled catalog's declarations before serialization.
 *
 * Checks field structure, supported specification major, entry uniqueness,
 * contributor/signer URI formats, timestamp syntax and ordering, subject/entry
 * relationships, digest syntax and known output lengths, signature
 * representations and known-profile static rules, and signed-payload
 * JCS/I-JSON eligibility. It accepts unsigned content and does not require
 * verification support for an unfamiliar profile or algorithm.
 *
 * This synchronous assertion does not mutate or return the catalog. It does not
 * hash artifact content, verify cryptographic signatures, authenticate keys,
 * resolve identities, evaluate current endorsement windows, or fetch evidence.
 *
 * @throws {CatalogValidationError} With bounded, path-specific diagnostics when
 * the catalog fails these checks.
 */
export function assertValidCatalog(
  catalog: unknown,
): asserts catalog is AICatalog {
  const parsed = safeParseCatalog(catalog);
  if (!parsed.success)
    throw new CatalogValidationError(parsed.error.issues, parsed.error.cause);
  const snapshot = parsed.data;
  const collector = new IssueCollector();
  validateSignatureMetadata(snapshot.signature, ['signature'], collector);
  for (const signatureIssue of validateSignatureDeclarations(
    snapshot as unknown as Record<string, JsonValue>,
    'catalog',
  ))
    collector.add(signatureIssue);
  for (
    let index = 0;
    index < snapshot.entries.length && !collector.stopped;
    index += 1
  ) {
    const entry = snapshot.entries[index];
    if (entry === undefined) continue;
    const entryPath = ['entries', index];
    if (entry.digest !== undefined)
      validateDigest(entry.digest, [...entryPath, 'digest'], collector);
    if (entry.updatedAt !== undefined) {
      const updatedAt = rfc3339DateTimeSchema.safeParse(entry.updatedAt);
      if (!updatedAt.success)
        collector.addZod(updatedAt.error, [...entryPath, 'updatedAt']);
    }
    for (
      let manifestIndex = 0;
      manifestIndex < (entry.trustManifests?.length ?? 0) && !collector.stopped;
      manifestIndex += 1
    ) {
      const manifest = entry.trustManifests?.[manifestIndex];
      if (manifest === undefined) continue;
      const manifestPath = [...entryPath, 'trustManifests', manifestIndex];
      validateManifestDeclarations(
        manifest,
        manifestPath,
        collector,
        entry,
        entryPath,
      );
      for (const signatureIssue of validateSignatureDeclarations(
        manifest as unknown as Record<string, JsonValue>,
        'manifest',
      ))
        collector.add({
          ...signatureIssue,
          path: [...manifestPath, ...signatureIssue.path],
        });
    }
  }
  validateEntryUniqueness(snapshot.entries, collector);
  const error = collector.finish(CatalogValidationError);
  if (error !== undefined) throw error;
}
