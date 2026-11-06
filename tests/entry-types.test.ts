import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  entryTypes,
  isEntryType,
  isNotEntryType,
  mediaTypes,
  type CatalogEntry,
  type CatalogEntryWithData,
  type CatalogEntryWithUrl,
} from '../src/index.js';

const entry: CatalogEntryWithData = {
  identifier: 'urn:air:example.com:agent:billing',
  type: mediaTypes.agentPluginZip,
  data: null,
};

describe('entry type predicates', () => {
  it.each([
    [mediaTypes.agentPluginZip, true],
    [mediaTypes.agentPluginGzip, false],
    [entryTypes.agentPlugin, true],
    [entryTypes.agentSkill, false],
    [[mediaTypes.agentPluginZip, mediaTypes.agentPluginZip], true],
    [[], false],
    [mediaTypes.agentPluginZip.toUpperCase(), false],
    [` ${mediaTypes.agentPluginZip}`, false],
    [`${mediaTypes.agentPluginZip}; charset=utf-8`, false],
    ['application/*', false],
  ] as const)('matches %j exactly in both call forms', (type, matches) => {
    expect(isEntryType(entry, type)).toBe(matches);
    expect(isEntryType(type)(entry)).toBe(matches);
    expect(isNotEntryType(entry, type)).toBe(!matches);
    expect(isNotEntryType(type)(entry)).toBe(!matches);
  });

  it('matches custom and empty type strings without validating the entry', () => {
    for (const type of ['application/x-custom', '']) {
      const custom = { ...entry, identifier: 'not a valid identifier', type };
      expect(isEntryType(custom, type)).toBe(true);
      expect(isEntryType([type])(custom)).toBe(true);
      expect(isNotEntryType(custom, type)).toBe(false);
      expect(isNotEntryType([type])(custom)).toBe(false);
    }
  });

  it('selects entries in order and preserves their references', () => {
    const other = { ...entry, type: mediaTypes.agentSkillMarkdown };
    const entries = [entry, other, entry];
    expect(entries.filter(isEntryType(entryTypes.agentPlugin))).toEqual([entry, entry]);
    expect(entries.filter(isNotEntryType(entryTypes.agentPlugin))).toEqual([other]);
    expect(entries.find(isEntryType(entryTypes.agentPlugin))).toBe(entry);
    expect(entries.find(isNotEntryType(entryTypes.agentPlugin))).toBe(other);
  });

  it('preserves specialized entry shapes and literal types in both positive forms', () => {
    const entries: CatalogEntryWithData[] = [entry];
    const plugins = entries.filter(isEntryType(entryTypes.agentPlugin));
    expectTypeOf(plugins).toEqualTypeOf<Array<CatalogEntryWithData & {
      type: typeof entryTypes.agentPlugin[number];
    }>>();
    const zipPlugins = entries.filter(isEntryType(mediaTypes.agentPluginZip));
    expectTypeOf(zipPlugins).toEqualTypeOf<Array<CatalogEntryWithData & {
      type: typeof mediaTypes.agentPluginZip;
    }>>();
    if (isEntryType(entry, entryTypes.agentPlugin)) {
      expectTypeOf(entry.data).toEqualTypeOf<CatalogEntryWithData['data']>();
      expectTypeOf(entry.type).toEqualTypeOf<typeof entryTypes.agentPlugin[number]>();
    }
    if (isEntryType(entry, mediaTypes.agentPluginZip)) {
      expectTypeOf(entry.type).toEqualTypeOf<typeof mediaTypes.agentPluginZip>();
    }
  });

  it('supports readonly, widened, union and generic criteria', () => {
    const entries: CatalogEntryWithUrl[] = [{
      identifier: entry.identifier,
      type: entry.type,
      url: 'https://example.com/plugin.zip',
    }];
    const types: readonly string[] = entryTypes.agentPlugin;
    expectTypeOf(entries.filter(isEntryType(types))).toEqualTypeOf<Array<CatalogEntryWithUrl & { type: string }>>();
    const criteria: string | readonly string[] = entry.type ? entryTypes.agentPlugin : mediaTypes.agentPluginZip;
    expectTypeOf(isEntryType(criteria)(entry)).toEqualTypeOf<boolean>();
    expectTypeOf(isEntryType(entry, criteria)).toEqualTypeOf<boolean>();
    expectTypeOf(isNotEntryType(criteria)(entry)).toEqualTypeOf<boolean>();
    expectTypeOf(isNotEntryType(entry, criteria)).toEqualTypeOf<boolean>();

    function matches<Type extends string | readonly string[]>(type: Type) {
      return [isEntryType(type)(entry), isEntryType(entry, type)];
    }
    expect(matches(mediaTypes.agentPluginZip)).toEqual([true, true]);
    expect(matches(entryTypes.agentSkill)).toEqual([false, false]);
  });

  it('retains explicit factory type parameters and infers inline literal groups', () => {
    const entries: CatalogEntry[] = [entry];
    const single = entries.filter(isEntryType<typeof mediaTypes.agentPluginZip>(mediaTypes.agentPluginZip));
    expectTypeOf(single).toEqualTypeOf<Array<CatalogEntry & { type: typeof mediaTypes.agentPluginZip }>>();
    const group = entries.filter(isEntryType<typeof entryTypes.agentPlugin>(entryTypes.agentPlugin));
    expectTypeOf(group).toEqualTypeOf<Array<CatalogEntry & { type: typeof entryTypes.agentPlugin[number] }>>();
    const inline = entries.filter(isEntryType(['custom/one', 'custom/two']));
    expectTypeOf(inline).toEqualTypeOf<Array<CatalogEntry & { type: 'custom/one' | 'custom/two' }>>();
  });

  it('narrows literal union criteria to the possible matching type values', () => {
    function matchingEntries(
      type: 'custom/one' | readonly ['custom/two'],
      candidate: CatalogEntry,
    ) {
      const filtered = [candidate].filter(isEntryType(type));
      expectTypeOf(filtered).toEqualTypeOf<Array<CatalogEntry & { type: 'custom/one' | 'custom/two' }>>();
      if (isEntryType(candidate, type)) {
        expectTypeOf(candidate.type).toEqualTypeOf<'custom/one' | 'custom/two'>();
      }
      return filtered;
    }
    const custom = { ...entry, type: 'custom/two' };
    expect(matchingEntries(['custom/two'], custom)).toEqual([custom]);
    expect(matchingEntries('custom/one', custom)).toEqual([]);
  });

  it('leaves negative checks boolean without excluding an open string type', () => {
    const entries: CatalogEntryWithData[] = [entry];
    expectTypeOf(entries.filter(isNotEntryType(mediaTypes.agentPluginZip))).toEqualTypeOf<CatalogEntryWithData[]>();
    if (isNotEntryType(entry, mediaTypes.agentPluginZip)) {
      expectTypeOf(entry).toEqualTypeOf<CatalogEntryWithData>();
      expectTypeOf(entry.type).toEqualTypeOf<string>();
    }
  });
});
