import { describe, expect, it } from 'vitest'
import { oaiSimulationActions } from './oaiActions.js'

describe('oaiSimulationActions', () => {
  it('omits wildcard-only actions and preserves the order of other actions', async () => {
    //Given supported actions surrounding a wildcard-only action
    const actions = ['s3:GetObject', 's3:ListAllMyBuckets', 's3:PutObject']

    //When filtering actions for an OAI simulation
    const result = await oaiSimulationActions(actions)

    //Then only the non-wildcard-only actions remain, in order
    expect(result).toEqual(['s3:GetObject', 's3:PutObject'])
  })
})
