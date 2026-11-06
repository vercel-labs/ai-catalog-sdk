import type { CatalogEntry } from './types.js';

/**
 * Type identifiers listed as known types by the implemented specification
 * snapshot.
 *
 * These constants are conveniences, not an allowlist: catalog parsing accepts
 * any string for an entry's `type`.
 */
export const mediaTypes = {
  aiCatalog: 'application/ai-catalog+json',
  agentCard: 'application/agent-card+json',
  a2aAgentCard: 'application/a2a-agent-card+json',
  mcpServerCard: 'application/mcp-server-card+json',
  agentSkillIndexJson: 'application/agent-skills+json',
  agentSkillMarkdown: 'application/agent-skills+md',
  agentSkillZip: 'application/agent-skills+zip',
  agentSkillGzip: 'application/agent-skills+gzip',
  agentPluginZip: 'application/agent-plugins+zip',
  agentPluginGzip: 'application/agent-plugins+gzip',
} as const;

/** Groups related `mediaTypes` values for exact entry-type matching. */
export const entryTypes = {
  aiCatalog: [mediaTypes.aiCatalog],
  agentCard: [mediaTypes.agentCard],
  a2aAgentCard: [mediaTypes.a2aAgentCard],
  mcpServerCard: [mediaTypes.mcpServerCard],
  agentSkill: [
    mediaTypes.agentSkillIndexJson,
    mediaTypes.agentSkillMarkdown,
    mediaTypes.agentSkillZip,
    mediaTypes.agentSkillGzip,
  ],
  agentPlugin: [mediaTypes.agentPluginZip, mediaTypes.agentPluginGzip],
} as const satisfies Record<string, readonly string[]>;

type MatchedEntryType<Type extends string | readonly string[]> =
  Type extends readonly string[] ? Type[number] : Type;

/**
 * Creates a predicate that matches entries with any supplied exact `type` value.
 *
 * Matching is case-sensitive and does not parse or normalize the type value.
 * This helper filters entries; it does not validate catalog input.
 *
 * @param type - One type value or a group of type values to match.
 * @returns A predicate that preserves the entry shape and narrows its `type` to
 * the supplied values' union.
 */
export function isEntryType<const Type extends string | readonly string[]>(
  type: Type,
): <Entry extends CatalogEntry>(
  entry: Entry,
) => entry is Entry & { type: MatchedEntryType<Type> };
/**
 * Checks whether an entry matches any supplied exact `type` value.
 *
 * Matching is case-sensitive and does not parse or normalize the type values.
 * This helper filters entries; it does not validate catalog input.
 *
 * @param entry - The entry to check.
 * @param type - One type value or a group of type values to match.
 * @returns Whether the entry matches, preserving its shape and narrowing `type` to
 * the supplied values' union.
 */
export function isEntryType<
  Entry extends CatalogEntry,
  const Type extends string | readonly string[],
>(
  entry: Entry,
  type: Type,
): entry is Entry & { type: MatchedEntryType<Type> };
export function isEntryType(
  entryOrType: CatalogEntry | string | readonly string[],
  type?: string | readonly string[],
) {
  if (type !== undefined) {
    return matchesEntryType(entryOrType as CatalogEntry, type);
  }
  return (entry: CatalogEntry) =>
    matchesEntryType(entry, entryOrType as string | readonly string[]);
}

/**
 * Creates a predicate that matches entries with none of the supplied exact
 * `type` values.
 *
 * Matching is case-sensitive and does not parse or normalize the type values.
 * This helper filters entries; it does not validate catalog input.
 */
export function isNotEntryType(
  type: string | readonly string[],
): (entry: CatalogEntry) => boolean;
/**
 * Checks whether an entry matches none of the supplied exact `type` values.
 *
 * Matching is case-sensitive and does not parse or normalize the type values.
 * This helper filters entries; it does not validate catalog input.
 */
export function isNotEntryType(
  entry: CatalogEntry,
  type: string | readonly string[],
): boolean;
export function isNotEntryType(
  entryOrType: CatalogEntry | string | readonly string[],
  type?: string | readonly string[],
) {
  if (type !== undefined) {
    return !matchesEntryType(entryOrType as CatalogEntry, type);
  }
  return (entry: CatalogEntry) =>
    !matchesEntryType(entry, entryOrType as string | readonly string[]);
}

function matchesEntryType(entry: CatalogEntry, type: string | readonly string[]) {
  return typeof type === 'string'
    ? entry.type === type
    : type.includes(entry.type);
}

/**
 * Checks whether a catalog entry contains its artifact in `data`.
 *
 * Prior entry narrowing, including an exact `type`, is preserved. This helper
 * checks property presence; it does not validate catalog input or inspect the
 * embedded artifact.
 */
export function isCatalogEntryWithData<Entry extends CatalogEntry>(
  entry: Entry,
): entry is Entry & Extract<CatalogEntry, { data: unknown }> {
  return 'data' in entry;
}

/**
 * Checks whether a catalog entry provides its artifact through `url`.
 *
 * Prior entry narrowing, including an exact `type`, is preserved. This helper
 * checks property presence; it does not validate catalog input or retrieve the
 * artifact.
 */
export function isCatalogEntryWithUrl<Entry extends CatalogEntry>(
  entry: Entry,
): entry is Entry & Extract<CatalogEntry, { url: string }> {
  return 'url' in entry;
}
