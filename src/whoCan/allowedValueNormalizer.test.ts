import { describe, expect, it } from 'vitest'
import { AllowedValueNormalizer } from './allowedValueNormalizer.js'
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

describe('AllowedValueNormalizer', () => {
  it('should normalize equal values that arrive as separate copies', () => {
    //Given two results with equal values, each its own copy as after a worker postMessage
    const normalizer = new AllowedValueNormalizer()
    const first = structuredClone(allowedFor('arn:aws:iam::123456789012:role/RoleA', 'test/'))
    const second = structuredClone(allowedFor('arn:aws:iam::123456789012:role/RoleB', 'test/'))
    expect(second.conditions).not.toBe(first.conditions)

    //When both are normalized
    const normalizedFirst = normalizer.normalize(first)
    const normalizedSecond = normalizer.normalize(second)

    //Then they reference the same instances
    expect(normalizedSecond.conditions).toBe(normalizedFirst.conditions)
    expect(normalizedSecond.ignoredConditions).toBe(normalizedFirst.ignoredConditions)
  })

  it('should keep different values apart', () => {
    //Given two results with different conditions
    const normalizer = new AllowedValueNormalizer()
    const first = normalizer.normalize(allowedFor('arn:aws:iam::123456789012:role/RoleA', 'test/'))
    const second = normalizer.normalize(
      allowedFor('arn:aws:iam::123456789012:role/RoleB', 'other/')
    )

    //Then each keeps its own value
    expect(second.conditions).not.toBe(first.conditions)
    expect(second.conditions).toEqual(allowedFor('', 'other/').conditions)
  })

  it('should leave the result equal to the original', () => {
    //Given a result with conditions, ignored conditions, details, and resource patterns
    const normalizer = new AllowedValueNormalizer()
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

    //When it is normalized
    const normalized = normalizer.normalize(original)

    //Then it is deeply equal to the original and its patterns have the same values
    expect(normalized).toEqual(expected)
    expect(normalized.allowedPatterns![1].conditions).toBe(normalized.conditions)
    expect(normalized.allowedPatterns![1].details).toBe(normalized.allowedPatterns![0].details)
  })

  it('should not add fields that were absent', () => {
    //Given a result without conditions
    const normalizer = new AllowedValueNormalizer()
    const allowed: WhoCanAllowed = {
      principal: 'arn:aws:iam::123456789012:role/RoleA',
      service: 's3',
      action: 'GetObject',
      level: 'object'
    }

    //When it is normalized
    const normalized = normalizer.normalize(allowed)

    //Then no keys are added
    expect(Object.keys(normalized)).toEqual(['principal', 'service', 'action', 'level'])
  })
})
