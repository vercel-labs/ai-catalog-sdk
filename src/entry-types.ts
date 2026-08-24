import type { CatalogEntry } from './types.js';

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

export function isEntryType<const Type extends string>(
  type: Type,
): <Entry extends CatalogEntry>(
  entry: Entry,
) => entry is Entry & { type: Type };
export function isEntryType<const Types extends readonly string[]>(
  types: Types,
): <Entry extends CatalogEntry>(
  entry: Entry,
) => entry is Entry & { type: Types[number] };
export function isEntryType(type: string | readonly string[]) {
  return <Entry extends CatalogEntry>(entry: Entry) =>
    typeof type === 'string' ? entry.type === type : type.includes(entry.type);
}

export function isInlineCatalogEntry<Entry extends CatalogEntry>(
  entry: Entry,
): entry is Entry & Extract<CatalogEntry, { data: unknown }> {
  return 'data' in entry;
}

export function isReferencedCatalogEntry<Entry extends CatalogEntry>(
  entry: Entry,
): entry is Entry & Extract<CatalogEntry, { url: string }> {
  return 'url' in entry;
}
