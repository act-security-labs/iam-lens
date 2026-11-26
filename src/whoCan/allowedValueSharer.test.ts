import { describe, expect, it } from 'vitest'
import { AllowedValueSharer } from './allowedValueSharer.js'
import { type WhoCanAllowed } from './whoCan.js'

function allowedFor(principal: string, prefix: string): WhoCanAllowed {
  return {
    principal,
    service: 's3',
    action: 'GetObject',
    level: 'object',
    conditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 's3:prefix',
      values: [prefix],
      sources: [{ policyType: 'identity', effect: 'Allow', statementIndex: 1 }]
    },
    ignoredConditions: {
      identity: { allow: [{ op: 'StringEquals', key: 's3:prefix', values: [prefix] }] }
    }
  }
}

describe('AllowedValueSharer', () => {
  it('should share equal values that arrive as separate copies', () => {
    //Given two results with equal values, each its own copy as after a worker postMessage
    const sharer = new AllowedValueSharer()
    const first = structuredClone(allowedFor('arn:aws:iam::123456789012:role/RoleA', 'test/'))
    const second = structuredClone(allowedFor('arn:aws:iam::123456789012:role/RoleB', 'test/'))
    expect(second.conditions).not.toBe(first.conditions)

    //When both are shared
    const sharedFirst = sharer.share(first)
    const sharedSecond = sharer.share(second)

    //Then they reference the same instances
    expect(sharedSecond.conditions).toBe(sharedFirst.conditions)
    expect(sharedSecond.ignoredConditions).toBe(sharedFirst.ignoredConditions)
  })

  it('should keep different values apart', () => {
    //Given two results with different conditions
    const sharer = new AllowedValueSharer()
    const first = sharer.share(allowedFor('arn:aws:iam::123456789012:role/RoleA', 'test/'))
    const second = sharer.share(allowedFor('arn:aws:iam::123456789012:role/RoleB', 'other/'))

    //Then each keeps its own value
    expect(second.conditions).not.toBe(first.conditions)
    expect(second.conditions).toEqual(allowedFor('', 'other/').conditions)
  })

  it('should leave the result equal to the original', () => {
    //Given a result with conditions, ignored conditions, details, and resource patterns
    const sharer = new AllowedValueSharer()
    const pattern = {
      pattern: 'arn:aws:s3:::bucket/*',
      resourceType: 'object',
      conditions: allowedFor('', 'test/').conditions,
      details: []
    }
    const original: WhoCanAllowed = {
      ...allowedFor('arn:aws:iam::123456789012:role/RoleA', 'test/'),
      allowedPatterns: [pattern, structuredClone(pattern)]
    }
    const expected = structuredClone(original)

    //When it is shared
    const shared = sharer.share(original)

    //Then it is deeply equal to the original and its patterns share the same values
    expect(shared).toEqual(expected)
    expect(shared.allowedPatterns![1].conditions).toBe(shared.conditions)
    expect(shared.allowedPatterns![1].details).toBe(shared.allowedPatterns![0].details)
  })

  it('should not add fields that were absent', () => {
    //Given a result without conditions
    const sharer = new AllowedValueSharer()
    const allowed: WhoCanAllowed = {
      principal: 'arn:aws:iam::123456789012:role/RoleA',
      service: 's3',
      action: 'GetObject',
      level: 'object'
    }

    //When it is shared
    const shared = sharer.share(allowed)

    //Then no keys are added
    expect(Object.keys(shared)).toEqual(['principal', 'service', 'action', 'level'])
  })
})
