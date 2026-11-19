/**
 * Metadata identifying the exact upstream AI Catalog specification snapshot
 * interpreted by this SDK.
 *
 * The SDK-maintained JSON Schema copies this metadata under
 * `x-ai-catalog-specification`.
 */
export const implementedSpecRevision = {
  /**
   * Catalog specification version represented by this snapshot.
   *
   * Whole-catalog parsers accept `Major.Minor` versions with the same major
   * component, not only this exact value.
   */
  specVersion: '0.9',

  /** Status of the upstream specification at this snapshot. */
  status: 'release-candidate',

  /** Path to the specification source within the upstream repository. */
  source: 'specification/ai-catalog.md',

  /** Full Git commit identifying the exact upstream source revision. */
  commit: '19208af2f8adbc0a6457e3ff36ce691a304fbd97',
} as const;
