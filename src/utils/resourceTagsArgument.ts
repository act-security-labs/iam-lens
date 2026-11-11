/**
 * Convert CLI map entries into a complete resource tag set.
 *
 * @param tags parsed tag entries, or undefined when no tags were supplied
 * @param empty whether the caller explicitly declared the resource untagged
 * @returns the supplied tag set, or undefined to defer to collected tags
 */
export function resourceTagsFromCli(
  tags: Record<string, string[]> | undefined,
  empty: boolean
): Record<string, string> | undefined {
  if (empty && tags !== undefined) {
    throw new Error('--resource-tags and --untagged cannot be used together.')
  }
  if (empty) {
    return {}
  }
  if (tags === undefined) {
    return undefined
  }
  const entries: [string, string][] = []
  for (const [key, values] of Object.entries(tags)) {
    if (values.length !== 1) {
      throw new Error(`--resource-tags requires exactly one value for ${key}.`)
    }
    entries.push([key, values[0]])
  }
  return Object.fromEntries(entries)
}
