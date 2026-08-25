export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

/** An AI Catalog document. */
export interface AICatalog {
  /** AI Catalog specification version in `Major.Minor` form. */
  specVersion: string;

  /** Information identifying the operator of this catalog. */
  host?: HostInfo;
  entries: CatalogEntry[];
  extensions?: JsonObject;

  /**
   * Detached JWS over the JCS-canonicalized catalog without this field.
   *
   * When verified, it covers every other catalog member, including entry order,
   * URLs, and inline `data`, but not artifact bytes fetched from an entry URL.
   * SDK validation checks only that this value is a string; it does not parse or
   * verify the JWS.
   */
  signature?: string;
}

/** Information identifying the operator of an AI Catalog. */
export interface HostInfo {
  displayName: string;

  /** Identifier for the catalog operator, such as a DID or domain name. Parsing does not verify it. */
  identifier?: string;
  documentationUrl?: string;
  logoUrl?: string;

  /** Trust metadata for the catalog operator. SDK validation does not verify its claims. */
  trustManifest?: TrustManifest;
}

/** Fields shared by inline and referenced catalog entries. */
interface CatalogEntryFields {
  identifier: string;
  displayName?: string;

  /** Type identifier indicating how to interpret the entry's artifact. */
  type: string;

  /** Version of the entry's artifact, when recorded in the catalog. */
  version?: string;
  description?: string;
  tags?: string[];

  /** Information identifying the entity responsible for this artifact. */
  publisher?: Publisher;

  /** Trust metadata for this artifact. SDK validation does not verify its claims. */
  trustManifest?: TrustManifest;

  /** RFC 3339 timestamp indicating when this catalog entry was last modified. */
  updatedAt?: string;
  extensions?: JsonObject;
}

/** A catalog entry that references an artifact by URL. */
export interface ReferencedCatalogEntry extends CatalogEntryFields {
  /** Location of the referenced artifact. */
  url: string;

  /** Referenced entries cannot contain inline data. */
  data?: never;
}

/** A catalog entry that embeds the complete artifact document in `data`. */
export interface InlineCatalogEntry extends CatalogEntryFields {
  /** The complete artifact document, embedded as a JSON value. */
  data: JsonValue;

  /** Inline entries cannot reference an artifact URL. */
  url?: never;
}

/** An AI Catalog entry that references an artifact by URL or embeds it as inline data. */
export type CatalogEntry = ReferencedCatalogEntry | InlineCatalogEntry;

/** Identifies the entity responsible for a catalog entry's artifact. */
export interface Publisher {
  /** Identifier for the publisher. Parsing does not verify it. */
  identifier: string;
  displayName: string;

  /** Type hint for the publisher identifier, such as `did` or `dns`. */
  identityType?: string;
}

/**
 * Structured but unverified identity and trust metadata for a catalog operator or artifact.
 *
 * SDK validation requires `identity` plus at least one of `signature`,
 * `trustSchema`, non-empty `attestations`, or non-empty `provenance`. A
 * `signature` also requires `subject` and `issuedAt`.
 *
 * Validation does not verify signatures, digests, identities, trust anchors,
 * attestations, provenance, expiration policy, or artifact content.
 */
export interface TrustManifest {
  /** Claimed globally unique URI identifying the catalog operator or artifact. */
  identity: string;

  /** Type hint for `identity`, such as `did`, `spiffe`, or `dns`. */
  identityType?: string;
  trustSchema?: TrustSchema;
  attestations?: Attestation[];
  provenance?: ProvenanceLink[];
  privacyPolicyUrl?: string;
  termsOfServiceUrl?: string;

  /** Content description included in the signed payload; required with `signature`. */
  subject?: TrustSubject;

  /** RFC 3339 issuance timestamp; required with `signature`. */
  issuedAt?: string;

  /** RFC 3339 timestamp after which the manifest is stale; validation does not enforce expiration. */
  expiresAt?: string;

  /**
   * Detached JWS over the JCS-canonicalized manifest without this field.
   *
   * SDK validation does not parse or verify the JWS. This signature does not
   * cover the surrounding catalog.
   */
  signature?: string;
  extensions?: JsonObject;
}

/**
 * Describes content referenced by a Trust Manifest and included in its signed
 * payload when a signature is present.
 */
export interface TrustSubject {
  /** Type identifier for the content; catalog-entry parsing requires it to match the containing entry's `type`. */
  type: string;

  /**
   * Digest of the content in `algorithm:lowercase-hex` form.
   *
   * For a referenced artifact, this covers the exact bytes served. For inline
   * `data`, it covers the JCS-canonicalized JSON value. SDK validation checks
   * syntax only, not algorithm strength or artifact content.
   */
  digest: string;

  /** Content URL; catalog-entry parsing requires it to match a referenced entry's `url`. */
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
