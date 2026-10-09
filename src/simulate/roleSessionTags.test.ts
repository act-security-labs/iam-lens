import { createValidatedPolicy, validateTrustPolicy } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import {
  immutablePrincipalTagPattern,
  roleSessionCanSetTagKey,
  roleSessionTagCapability,
  type RoleSessionTagCapability
} from './roleSessionTags.js'

/**
 * Creates a validated synthetic role trust policy for session-tag tests.
 *
 * @param statements the trust-policy statements to validate
 * @returns a validated trust policy
 */
function trustPolicy(statements: any[]) {
  return createValidatedPolicy(
    { Version: '2012-10-17', Statement: statements },
    validateTrustPolicy,
    { name: 'synthetic-role' }
  )
}

/**
 * Creates a trust-policy statement with defaults suitable for TagSession tests.
 *
 * @param overrides fields that replace the default Allow statement
 * @returns a synthetic trust-policy statement
 */
function statement(overrides: Record<string, unknown> = {}) {
  const result: Record<string, unknown> = {
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:root' },
    Action: 'sts:TagSession',
    ...overrides
  }
  for (const [key, value] of Object.entries(result)) {
    if (value === undefined) {
      delete result[key]
    }
  }
  return result
}

/**
 * Compiles the slash-delimited pattern emitted for iam-simulate constraints.
 *
 * @param pattern the slash-delimited constraint pattern
 * @returns the equivalent case-insensitive regular expression
 */
function compilePattern(pattern: string): RegExp {
  return new RegExp(pattern.slice(1, -1), 'i')
}

type TrustPolicy = ReturnType<typeof trustPolicy>

interface CapabilityTestCase {
  name: string
  policy: TrustPolicy | undefined
  expected: RoleSessionTagCapability
  invalidPolicy?: boolean
}

const unrestrictedActionCases: CapabilityTestCase[] = [
  'sts:TagSession',
  'sts:*',
  '*',
  'StS:tAgSeSsIoN'
].map((action) => ({
  name: `returns any for unrestricted Action ${action}`,
  policy: trustPolicy([statement({ Action: action })]),
  expected: { type: 'any' }
}))

const nonExhaustiveOperatorCases: CapabilityTestCase[] = [
  'ForAnyValue:StringEquals',
  'ForAnyValue:StringEqualsIgnoreCase',
  'ForAllValues:StringEqualsIfExists',
  'ForAllValues:StringLike',
  'ForAllValues:StringNotEquals',
  'StringEquals'
].map((operator) => ({
  name: `returns any for non-exhaustive operator ${operator}`,
  policy: trustPolicy([statement({ Condition: { [operator]: { 'aws:TagKeys': 'Department' } } })]),
  expected: { type: 'any' }
}))

const capabilityCases: CapabilityTestCase[] = [
  {
    name: 'returns none when the trust policy was not collected',
    policy: undefined,
    expected: { type: 'none' }
  },
  {
    name: 'returns any when the collected trust policy is invalid',
    policy: trustPolicy([
      statement({
        Condition: { 'ForAllValues:StringEquals:Invalid': { 'aws:TagKeys': 'Department' } }
      })
    ]),
    expected: { type: 'any' },
    invalidPolicy: true
  },
  {
    name: 'returns none when no Allow includes TagSession',
    policy: trustPolicy([statement({ Action: 'sts:AssumeRole' })]),
    expected: { type: 'none' }
  },
  ...unrestrictedActionCases,
  {
    name: 'returns none when NotAction excludes TagSession',
    policy: trustPolicy([
      statement({ Action: undefined, NotAction: ['sts:TagSession', 'sts:SetSourceIdentity'] })
    ]),
    expected: { type: 'none' }
  },
  {
    name: 'returns none when wildcard NotAction excludes TagSession',
    policy: trustPolicy([statement({ Action: undefined, NotAction: 'sts:*' })]),
    expected: { type: 'none' }
  },
  {
    name: 'returns any when NotAction does not exclude TagSession',
    policy: trustPolicy([statement({ Action: undefined, NotAction: 'sts:SetSourceIdentity' })]),
    expected: { type: 'any' }
  },
  {
    name: 'returns a case-sensitive ForAllValues:StringEquals allowlist',
    policy: trustPolicy([
      statement({
        Condition: {
          'ForAllValues:StringEquals': { 'aws:TagKeys': ['Department', 'Project'] }
        }
      })
    ]),
    expected: {
      type: 'allowlist',
      tagKeys: [
        { tagKey: 'Department', ignoreCase: false },
        { tagKey: 'Project', ignoreCase: false }
      ]
    }
  },
  {
    name: 'returns a case-insensitive ForAllValues:StringEqualsIgnoreCase allowlist',
    policy: trustPolicy([
      statement({
        Condition: {
          'ForAllValues:StringEqualsIgnoreCase': { 'AWS:TAGKEYS': 'department' }
        }
      })
    ]),
    expected: {
      type: 'allowlist',
      tagKeys: [{ tagKey: 'department', ignoreCase: true }]
    }
  },
  {
    name: 'intersects multiple ForAllValues allowlists within one statement',
    policy: trustPolicy([
      statement({
        Condition: {
          'ForAllValues:StringEquals': {
            'aws:TagKeys': ['Department', 'Environment', 'Project']
          },
          'ForAllValues:StringEqualsIgnoreCase': {
            'AWS:TAGKEYS': ['department', 'environment']
          }
        }
      })
    ]),
    expected: {
      type: 'allowlist',
      tagKeys: [
        { tagKey: 'Department', ignoreCase: false },
        { tagKey: 'Environment', ignoreCase: false }
      ]
    }
  },
  {
    name: 'returns an empty allowlist for disjoint ForAllValues conditions',
    policy: trustPolicy([
      statement({
        Condition: {
          'ForAllValues:StringEquals': { 'aws:TagKeys': 'Department' },
          'ForAllValues:StringEqualsIgnoreCase': { 'AWS:TAGKEYS': 'Environment' }
        }
      })
    ]),
    expected: { type: 'allowlist', tagKeys: [] }
  },
  {
    name: 'unions TagKeys allowlists across multiple Allow statements',
    policy: trustPolicy([
      statement({
        Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': 'Department' } }
      }),
      statement({
        Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': 'Environment' } }
      })
    ]),
    expected: {
      type: 'allowlist',
      tagKeys: [
        { tagKey: 'Department', ignoreCase: false },
        { tagKey: 'Environment', ignoreCase: false }
      ]
    }
  },
  {
    name: 'returns any when one of multiple Allows is unrestricted',
    policy: trustPolicy([
      statement({
        Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': 'Department' } }
      }),
      statement()
    ]),
    expected: { type: 'any' }
  },
  ...nonExhaustiveOperatorCases,
  {
    name: 'returns any for policy-variable TagKeys values',
    policy: trustPolicy([
      statement({
        Condition: {
          'ForAllValues:StringEquals': { 'aws:TagKeys': '${aws:PrincipalTag/AllowedKey}' }
        }
      })
    ]),
    expected: { type: 'any' }
  },
  {
    name: 'ignores non-TagKeys conditions when finding possible session tags',
    policy: trustPolicy([
      statement({ Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-example' } } })
    ]),
    expected: { type: 'any' }
  },
  {
    name: 'ignores TagKeys Deny statements when an unrestricted Allow exists',
    policy: trustPolicy([
      statement(),
      statement({
        Effect: 'Deny',
        Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': 'Department' } }
      })
    ]),
    expected: { type: 'any' }
  },
  {
    name: 'does not create session-tag capability from a TagKeys Deny alone',
    policy: trustPolicy([
      statement({
        Effect: 'Deny',
        Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': 'Department' } }
      })
    ]),
    expected: { type: 'none' }
  }
]

describe('roleSessionTagCapability', () => {
  it.each(capabilityCases)('$name', ({ policy, expected, invalidPolicy }) => {
    //Given a validated trust policy representing the scenario
    if (invalidPolicy) {
      expect(policy?.errors).not.toEqual([])
    }

    //When deriving session-tag capability
    const result = roleSessionTagCapability(policy)

    //Then the complete capability matches the expected trust-policy interpretation
    expect(result).toEqual(expected)
  })
})

interface CanSetTagKeyTestCase {
  name: string
  capability: RoleSessionTagCapability
  tagKey: string
  expected: boolean
}

const canSetTagKeyCases: CanSetTagKeyTestCase[] = [
  {
    name: 'none rejects an arbitrary tag key',
    capability: { type: 'none' },
    tagKey: 'Department',
    expected: false
  },
  {
    name: 'any accepts an arbitrary tag key',
    capability: { type: 'any' },
    tagKey: 'Department',
    expected: true
  },
  {
    name: 'case-sensitive allowlist accepts exact spelling',
    capability: {
      type: 'allowlist',
      tagKeys: [{ tagKey: 'Department', ignoreCase: false }]
    },
    tagKey: 'Department',
    expected: true
  },
  {
    name: 'case-sensitive allowlist rejects different spelling',
    capability: {
      type: 'allowlist',
      tagKeys: [{ tagKey: 'Department', ignoreCase: false }]
    },
    tagKey: 'department',
    expected: false
  },
  {
    name: 'case-insensitive allowlist accepts different spelling',
    capability: {
      type: 'allowlist',
      tagKeys: [{ tagKey: 'environment', ignoreCase: true }]
    },
    tagKey: 'Environment',
    expected: true
  },
  {
    name: 'finite allowlist rejects an unrelated tag key',
    capability: {
      type: 'allowlist',
      tagKeys: [
        { tagKey: 'Department', ignoreCase: false },
        { tagKey: 'environment', ignoreCase: true }
      ]
    },
    tagKey: 'Project',
    expected: false
  }
]

describe('roleSessionCanSetTagKey', () => {
  it.each(canSetTagKeyCases)('$name', ({ capability, tagKey, expected }) => {
    //Given trust-policy-derived capability and an arbitrary key independent of stored tags
    //When checking whether a session can set the key
    const result = roleSessionCanSetTagKey(capability, tagKey)

    //Then matching follows the capability's case semantics
    expect(result).toBe(expected)
  })
})

interface ImmutablePatternTestCase {
  name: string
  capability: RoleSessionTagCapability
  expectedPattern?: string
  strictKeys?: string[]
  mutableKeys?: string[]
}

const immutablePatternCases: ImmutablePatternTestCase[] = [
  {
    name: 'makes present and absent PrincipalTag keys strict when session tags are impossible',
    capability: { type: 'none' },
    expectedPattern: '/^aws:PrincipalTag\/.*/',
    strictKeys: ['aws:PrincipalTag/Department', 'aws:PrincipalTag/NotStored']
  },
  {
    name: 'returns no strict pattern when any session-tag key is possible',
    capability: { type: 'any' },
    expectedPattern: undefined
  },
  {
    name: 'makes every PrincipalTag key strict except allowlisted mutable names',
    capability: {
      type: 'allowlist',
      tagKeys: [
        { tagKey: 'Department', ignoreCase: false },
        { tagKey: 'Project.Name', ignoreCase: true }
      ]
    },
    strictKeys: ['aws:PrincipalTag/ProjectXName', 'aws:PrincipalTag/Environment'],
    mutableKeys: [
      'aws:PrincipalTag/Department',
      'aws:PrincipalTag/department',
      'aws:PrincipalTag/Project.Name'
    ]
  },
  {
    name: 'makes every PrincipalTag key strict for an empty allowlist',
    capability: { type: 'allowlist', tagKeys: [] },
    expectedPattern: '/^aws:PrincipalTag\/.*/',
    strictKeys: ['aws:PrincipalTag/Department', 'aws:PrincipalTag/NotStored']
  }
]

describe('immutablePrincipalTagPattern', () => {
  it.each(immutablePatternCases)(
    '$name',
    ({ capability, expectedPattern, strictKeys = [], mutableKeys = [] }) => {
      //Given a trust-policy-derived session-tag capability
      //When building immutable PrincipalTag knowledge
      const pattern = immutablePrincipalTagPattern(capability)

      //Then the expected pattern and key classifications are produced
      if (expectedPattern !== undefined || capability.type === 'any') {
        expect(pattern).toBe(expectedPattern)
      }
      if (!pattern) {
        return
      }

      const regex = compilePattern(pattern)
      for (const key of strictKeys) {
        expect(regex.test(key), `${key} should be strict`).toBe(true)
      }
      for (const key of mutableKeys) {
        expect(regex.test(key), `${key} should be mutable`).toBe(false)
      }
    }
  )
})
