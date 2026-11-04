import {
  CatalogValidationError,
  type CatalogEntry,
  type JsonValue,
  type TrustManifest,
} from '../types.js';
import { DIGEST_HEX_LENGTHS, DIGEST_PATTERN } from './digest.js';
import { IssueCollector, issue, type Path } from './issues.js';
import {
  absoluteUriSchema,
  concreteSignatureSchema,
} from './schemas.js';
import {
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
