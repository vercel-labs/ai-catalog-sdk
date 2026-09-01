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

  /**
   * Custom catalog data keyed by an extension namespace.
   *
   * The specification requires each key to be a valid URL or reverse-DNS
   * string. SDK validation preserves the JSON values but does not validate key
   * syntax or interpret their contents.
   */
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

/** Fields shared by catalog entries with `url` and catalog entries with `data`. */
interface CatalogEntryFields {
  /**
   * Open-text identifier for the artifact; SDK validation does not interpret
   * its format.
   *
   * Within a catalog, multiple entries may share an identifier only when every
   * entry provides a distinct `version`. Whole-catalog parsing enforces this
   * rule; standalone entry and schema validation do not.
   */
  identifier: string;
  displayName?: string;

  /** Type identifier indicating how to interpret the entry's artifact. */
  type: string;

  /**
   * Version of the entry's artifact, when recorded in the catalog.
   *
   * Used with `identifier` to distinguish multiple versions within one catalog.
   */
  version?: string;
  description?: string;
  tags?: string[];

  /** Information identifying the entity responsible for this artifact. */
  publisher?: Publisher;

  /** Trust metadata for this artifact. SDK validation does not verify its claims. */
  trustManifest?: TrustManifest;

  /** RFC 3339 timestamp indicating when this catalog entry was last modified. */
  updatedAt?: string;

  /**
   * Custom entry data keyed by an extension namespace.
   *
   * The specification requires each key to be a valid URL or reverse-DNS
   * string. SDK validation preserves the JSON values but does not validate key
   * syntax or interpret their contents.
   */
  extensions?: JsonObject;
}

/** A catalog entry that provides its artifact through `url`. */
export interface CatalogEntryWithUrl extends CatalogEntryFields {
  /** Location from which to retrieve the complete artifact. */
  url: string;

  /** An entry with `url` cannot also contain `data`. */
  data?: never;
}

/** A catalog entry that embeds the complete artifact document in `data`. */
export interface CatalogEntryWithData extends CatalogEntryFields {
  /** The complete artifact document, embedded as a JSON value. */
  data: JsonValue;

  /** An entry with `data` cannot also contain `url`. */
  url?: never;
}

/** An AI Catalog entry whose artifact is provided through `url` or inline `data`. */
export type CatalogEntry = CatalogEntryWithUrl | CatalogEntryWithData;

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

  /**
   * Custom trust data included in the signed payload when `signature` is present.
   *
   * The specification requires each key to be a valid URL or reverse-DNS
   * string. SDK validation preserves the JSON values but does not validate key
   * syntax or interpret their contents.
   */
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
   * For an artifact provided through an entry's `url`, this covers the exact
   * bytes served. For inline `data`, it covers the JCS-canonicalized JSON
   * value. SDK validation checks syntax only, not algorithm strength or
   * artifact content.
   */
  digest: string;

  /** Content URL; catalog-entry parsing requires it to match the containing entry's `url`. */
  url?: string;
}

/**
 * Identifies the trust framework that a Trust Manifest claims to apply.
 *
 * SDK validation does not retrieve or evaluate the framework.
 */
export interface TrustSchema {
  identifier: string;
  version: string;

  /**
   * URI of the framework's governance policy document.
   *
   * SDK validation does not validate URI syntax or fetch the document.
   */
  governanceUri?: string;

  /** Open-text verification methods supported by the framework, such as `did`, `x509`, or `dns-01`. */
  verificationMethods?: string[];
}

/**
 * Metadata locating evidence intended to support a trust claim.
 *
 * SDK validation does not fetch or verify the attestation document.
 */
export interface Attestation {
  /** Open-text identifier for the kind of attestation; SDK validation does not interpret it. */
  type: string;

  /**
   * Location of the attestation document.
   *
   * The specification supports HTTPS and inline `data:` URIs. SDK validation
   * does not validate the string as a URI or fetch the document.
   */
  uri: string;

  /** Declared digest in `algorithm:lowercase-hex` form; SDK validation checks syntax only. */
  digest?: string;

  /**
   * Declared size in bytes.
   *
   * SDK validation requires a non-negative safe integer but does not compare it
   * with the document.
   */
  size?: number;
  description?: string;
}

/**
 * Records a claimed link in an artifact's upstream provenance chain.
 *
 * SDK validation does not validate URI syntax, resolve referenced resources,
 * compare digests, or verify provenance statements.
 */
export interface ProvenanceLink {
  /** Open-text relationship to the source; SDK validation does not constrain its vocabulary. */
  relation: string;

  /** Identifier of the source artifact or data; no particular format is required. */
  sourceId: string;

  /**
   * Digest of the upstream source in `algorithm:lowercase-hex` form.
   *
   * This complements rather than replaces the artifact digest in
   * `TrustSubject`. SDK validation checks syntax only.
   */
  sourceDigest?: string;

  /** URI of the registry holding the source. */
  registryUri?: string;

  /** URI of a provenance statement document. */
  statementUri?: string;

  /** Reference to the key used to sign the provenance statement, not the signature itself; SDK validation does not resolve it. */
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
