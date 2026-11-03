import { isIdnHostname } from 'idn-hostname';

/** Validates the exact ASCII domain permitted by the did:web Signer Profile. */
export function isDidWebDomain(domain: string): boolean {
  if (domain.length > 253 || !/^[a-z0-9.-]+$/.test(domain) || domain.endsWith('.'))
    return false;

  const labels = domain.split('.');
  if (
    !labels.every(
      (label) =>
        label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  )
    return false;

  // URL parsing permits ASCII hosts with invalid IDNA labels. Establish
  // label validity separately without normalizing the signed identity.
  if (labels.some((label) => label.startsWith('xn--'))) {
    try {
      isIdnHostname(domain);
    } catch (error) {
      if (error instanceof SyntaxError) return false;
      throw error;
    }
  }

  // WHATWG also recognizes shortened, hexadecimal, and integer IPv4 forms.
  try {
    const hostname = new URL(`https://${domain}/`).hostname;
    return hostname === domain && !/^(?:[0-9]+\.){3}[0-9]+$/.test(hostname);
  } catch {
    return false;
  }
}
