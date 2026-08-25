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
  agentSkillJson: 'application/agent-skills+json',
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
    mediaTypes.agentSkillJson,
    mediaTypes.agentSkillMarkdown,
    mediaTypes.agentSkillZip,
    mediaTypes.agentSkillGzip,
  ],
  agentPlugin: [mediaTypes.agentPluginZip, mediaTypes.agentPluginGzip],
} as const satisfies Record<string, readonly string[]>;

/**
 * Creates a predicate that matches entries with one exact `type` value.
 *
 * Matching is case-sensitive and does not parse or normalize the type value.
 * This helper filters entries; it does not validate catalog input.
 *
 * @param type - The type value to match.
 * @returns A predicate that preserves the entry shape and narrows its `type` to
 * the supplied value.
 */
export function isEntryType<const Type extends string>(
  type: Type,
): <Entry extends CatalogEntry>(
  entry: Entry,
) => entry is Entry & { type: Type };
/**
 * Creates a predicate that matches entries with any exact `type` value in a
 * group.
 *
 * Matching is case-sensitive and does not parse or normalize the type values.
 * This helper filters entries; it does not validate catalog input.
 *
 * @param types - The type values to match.
 * @returns A predicate that preserves the entry shape and narrows its `type` to
 * the supplied values' union.
 */
export function isEntryType<const Types extends readonly string[]>(
  types: Types,
): <Entry extends CatalogEntry>(
  entry: Entry,
) => entry is Entry & { type: Types[number] };
export function isEntryType(type: string | readonly string[]) {
  return <Entry extends CatalogEntry>(entry: Entry) =>
    typeof type === 'string' ? entry.type === type : type.includes(entry.type);
}

/**
 * Checks whether a catalog entry embeds its artifact in `data`.
 *
 * Prior entry narrowing, including an exact `type`, is preserved. This helper
 * checks property presence; it does not validate catalog input or inspect the
 * embedded artifact.
 */
export function isInlineCatalogEntry<Entry extends CatalogEntry>(
  entry: Entry,
): entry is Entry & Extract<CatalogEntry, { data: unknown }> {
  return 'data' in entry;
}

/**
 * Checks whether a catalog entry references its artifact by `url`.
 *
 * Prior entry narrowing, including an exact `type`, is preserved. This helper
 * checks property presence; it does not validate catalog input or retrieve the
 * referenced artifact.
 */
export function isReferencedCatalogEntry<Entry extends CatalogEntry>(
  entry: Entry,
): entry is Entry & Extract<CatalogEntry, { url: string }> {
  return 'url' in entry;
}
