export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export interface AICatalog {
  specVersion: string;
  host?: HostInfo;
  entries: CatalogEntry[];
  extensions?: JsonObject;
  signature?: string;
}

export interface HostInfo {
  displayName: string;
  identifier?: string;
  documentationUrl?: string;
  logoUrl?: string;
  trustManifest?: TrustManifest;
}

interface CatalogEntryFields {
  identifier: string;
  displayName?: string;
  type: string;
  version?: string;
  description?: string;
  tags?: string[];
  publisher?: Publisher;
  trustManifest?: TrustManifest;
  updatedAt?: string;
  extensions?: JsonObject;
}

export interface ReferencedCatalogEntry extends CatalogEntryFields {
  url: string;
  data?: never;
}

export interface InlineCatalogEntry extends CatalogEntryFields {
  data: JsonValue;
  url?: never;
}

export type CatalogEntry = ReferencedCatalogEntry | InlineCatalogEntry;

export interface Publisher {
  identifier: string;
  displayName: string;
  identityType?: string;
}

export interface TrustManifest {
  identity: string;
  identityType?: string;
  trustSchema?: TrustSchema;
  attestations?: Attestation[];
  provenance?: ProvenanceLink[];
  privacyPolicyUrl?: string;
  termsOfServiceUrl?: string;
  subject?: TrustSubject;
  issuedAt?: string;
  expiresAt?: string;
  signature?: string;
  extensions?: JsonObject;
}

export interface TrustSubject {
  type: string;
  digest: string;
  url?: string;
}

export interface TrustSchema {
  identifier: string;
  version: string;
  governanceUri?: string;
  verificationMethods?: string[];
}

export interface Attestation {
  type: string;
  uri: string;
  digest?: string;
  size?: number;
  description?: string;
}

export interface ProvenanceLink {
  relation: string;
  sourceId: string;
  sourceDigest?: string;
  registryUri?: string;
  statementUri?: string;
  signatureRef?: string;
}

/** A parsing or validation issue reported by an SDK parser. */
export interface CatalogIssue {
  /** Machine-readable category for programmatic classification. */
  code: string;

  /** Location in the input as property names and array indexes; empty means root. */
  path: readonly (string | number)[];

  /** Human-readable explanation; exact wording is not guaranteed. */
  message: string;
}

/**
 * The result of a non-throwing parsing operation.
 *
 * A failed result contains a {@link CatalogParseError}.
 *
 * @typeParam T - The validated value type.
 */
export type ParseResult<T> =
  | { success: true; data: T }
  | { success: false; error: CatalogParseError };

/** Represents a failure while parsing or validating AI Catalog input. */
export class CatalogParseError extends Error {
  /** The machine-readable validation issues that caused the failure. */
  readonly issues: readonly CatalogIssue[];

  /** The underlying error, when a lower-level operation supplied one. */
  readonly cause?: unknown;

  constructor(issues: readonly CatalogIssue[], cause?: unknown) {
    super('The value is not a valid AI Catalog document.');
    this.name = 'CatalogParseError';
    this.issues = issues;
    if (cause !== undefined) this.cause = cause;
  }
}
