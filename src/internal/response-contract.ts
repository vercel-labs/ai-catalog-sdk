/** Checks the public response contract without inferring a browser origin. */
export function hasPublicAccessHeaders(
  headers: Readonly<Record<string, string | undefined>>,
  requireLinkExposure = false,
): boolean {
  if (headers['access-control-allow-origin']?.trim() !== '*') return false;
  const declaration = headers['access-control-expose-headers'];
  if (declaration === undefined) return false;
  const names = declaration.split(',').map((name) => name.trim().toLowerCase());
  if (names.some((name) => name.length > 0 && !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)))
    return false;
  const exposed = new Set(names);
  if (exposed.has('*')) return true;
  return exposed.has('access-control-allow-origin') &&
    exposed.has('access-control-expose-headers') &&
    (!requireLinkExposure || exposed.has('link'));
}
