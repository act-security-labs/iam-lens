import { describe, expect, it } from 'vitest'
import { resourceTagsFromCli } from './resourceTagsArgument.js'

describe('resourceTagsFromCli', () => {
  it('defers to collected tags when neither option is supplied', () => {
    //Given no tag options
    //When translating the CLI values
    const result = resourceTagsFromCli(undefined, false)

    //Then no tag override is supplied
    expect(result).toBeUndefined()
  })

  it('converts each tag to its single string value', () => {
    //Given multiple entries parsed by mapArgument
    const tags = { env: ['dev'], team: ['security'] }

    //When translating the CLI values
    const result = resourceTagsFromCli(tags, false)

    //Then the complete tag map is returned
    expect(result).toEqual({ env: 'dev', team: 'security' })
  })

  it('expresses a known empty tag set', () => {
    //Given an explicit untagged option
    //When translating the CLI values
    const result = resourceTagsFromCli(undefined, true)

    //Then the API receives a known-empty map
    expect(result).toEqual({})
  })

  it('rejects multiple values for a tag', () => {
    //Given an entry with two values
    //When and Then translating it fails instead of discarding a value
    expect(() => resourceTagsFromCli({ env: ['dev', 'prod'] }, false)).toThrow(
      '--resource-tags requires exactly one value for env.'
    )
  })

  it('rejects combining tags with the empty option', () => {
    //Given conflicting tag options
    //When and Then translating them reports the conflict
    expect(() => resourceTagsFromCli({ env: ['dev'] }, true)).toThrow(
      '--resource-tags and --untagged cannot be used together.'
    )
  })
})
