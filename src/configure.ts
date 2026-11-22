/** Settings shared by all network operations in this SDK instance. */
export interface SDKConfiguration {
  /**
   * Require public, credential-free access and exposed access declarations on
   * final HTTP responses; advertisement discovery also requires `Link` exposure.
   * In Node.js, the SDK also requires `Access-Control-Allow-Origin: *` on redirects.
   * Browsers use native redirect permissions and may accept requests the SDK rejects
   * in Node.js.
   * Defaults to false; omitted settings are unchanged.
   */
  requirePublicAccessHeaders?: boolean;
}

let requirePublicAccessHeaders = false;

/**
 * Updates SDK-wide settings. Configure once during application startup.
 * Each operation captures the settings before asynchronous work, including
 * for requests it makes later while resolving signer identities.
 */
export function configure(options: SDKConfiguration): void {
  if (options === null || typeof options !== 'object' || Array.isArray(options))
    throw new TypeError('configuration must be an object.');
  const value = options.requirePublicAccessHeaders;
  if (value === undefined) return;
  if (typeof value !== 'boolean')
    throw new TypeError('requirePublicAccessHeaders must be a boolean.');
  requirePublicAccessHeaders = value;
}

/** Captures one policy for every request made by an operation. */
export function captureSdkConfiguration(): Readonly<{ requirePublicAccessHeaders: boolean }> {
  return { requirePublicAccessHeaders };
}
