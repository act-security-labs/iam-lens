import { type EvaluationResult } from '@actsecurity/iam-simulate'
import { assert, describe, expect, it } from 'vitest'
import { testStore } from '../collect/inMemoryClient.js'
import { saveRole, saveUser } from '../utils/testUtils.js'
import {
  discoveryConstraintForStrictKey,
  resultMatchesExpectation,
  simulateRequest,
  type SimulationRequest
} from './simulate.js'

describe('simulateRequest', () => {
  it('should throw an error if the resource account id cannot be determined', async () => {
    const { client } = testStore()
    // Given a request with an unknown resource ARN
    const req: SimulationRequest = {
      simulationMode: 'Strict',
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:s3:::unknown-bucket',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {}
    }
    //When simulating the request
    // Then it should throw an error indicating the account ID cannot be found
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find account ID for resource/
    )
  })

  it('should throw an error if the action service cannot be found', async () => {
    const { client } = testStore()
    // Given a request with an unknown action service
    const req: SimulationRequest = {
      simulationMode: 'Strict',
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:iam::123456789012:test-bucket',
      resourceAccount: '123456789012',
      action: 'unknown:action',
      customContextKeys: {}
    }

    // When simulating the request
    // Then it should throw an error indicating the action service cannot be found
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find action details for unknown:action/
    )
  })

  it('should throw an error if the action details cannot be found', async () => {
    const { client } = testStore()
    const req: SimulationRequest = {
      simulationMode: 'Strict',
      principal: 'arn:aws:iam::123456789012:user/test-user',
      resourceArn: 'arn:aws:iam::123456789012:test-bucket',
      resourceAccount: '123456789012',
      action: 's3:fakeaction',
      customContextKeys: {}
    }
    await expect(simulateRequest(req, client)).rejects.toThrow(
      /Unable to find action details for s3:fakeaction/
    )
  })

  it('should use underlying role tags for assumed-role session principals', async () => {
    //Given an assumed-role session whose role has a tag-gated identity policy
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/TestSession'
    await saveRole(store, {
      arn: roleArn,
      inlinePolicies: [
        {
          PolicyName: 'AllowTaggedRoleAccess',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::example-bucket/*',
                Condition: {
                  StringEquals: {
                    'aws:PrincipalTag/Department': 'Engineering'
                  }
                }
              }
            ]
          }
        }
      ]
    })
    await store.saveResourceMetadata('123456789012', roleArn, 'tags', {
      Department: 'Engineering'
    })

    //When simulating as the assumed-role session
    const { request, result } = await simulateRequest(
      {
        simulationMode: 'Strict',
        principal: sessionArn,
        resourceArn: 'arn:aws:s3:::example-bucket/private.txt',
        resourceAccount: '123456789012',
        action: 's3:GetObject',
        customContextKeys: {}
      },
      client
    )

    //Then the simulation should preserve the session principal but use role-backed context
    expect(request.principal).toBe(sessionArn)
    expect(request.contextVariables['aws:PrincipalArn']).toBe(roleArn)
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    expect(result.overallResult).toBe('Allowed')
  })

  it('should use canonical path-qualified role tags for pathless assumed-role session principals', async () => {
    //Given a pathless assumed-role session whose collected IAM role has a path
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/TestRole'
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/TestSession'
    await saveRole(store, {
      arn: roleArn,
      inlinePolicies: [
        {
          PolicyName: 'AllowTaggedPathRoleAccess',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::example-bucket/*',
                Condition: {
                  StringEquals: {
                    'aws:PrincipalTag/Department': 'Engineering'
                  }
                }
              }
            ]
          }
        }
      ]
    })
    await store.saveResourceMetadata('123456789012', roleArn, 'tags', {
      Department: 'Engineering'
    })

    //When simulating as the assumed-role session
    const { request, result } = await simulateRequest(
      {
        simulationMode: 'Strict',
        principal: sessionArn,
        resourceArn: 'arn:aws:s3:::example-bucket/private.txt',
        resourceAccount: '123456789012',
        action: 's3:GetObject',
        customContextKeys: {}
      },
      client
    )

    //Then context keys should use the canonical collected role ARN and its tags
    expect(request.principal).toBe(sessionArn)
    expect(request.contextVariables['aws:PrincipalArn']).toBe(roleArn)
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    expect(result.overallResult).toBe('Allowed')
  })

  it('should return structured validation errors for invalid trust policies', async () => {
    const { store, client } = testStore()
    const principalArn = 'arn:aws:iam::123456789012:user/test-user'
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'

    await saveUser(store, { arn: principalArn })
    await saveRole(store, {
      arn: roleArn,
      trustPolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'sts:AssumeRole'
          }
        ]
      }
    })

    const { request, result } = await simulateRequest(
      {
        simulationMode: 'Strict',
        principal: principalArn,
        resourceArn: roleArn,
        resourceAccount: '123456789012',
        action: 'sts:AssumeRole',
        customContextKeys: {}
      },
      client
    )

    expect(request).toMatchObject({
      action: 'sts:AssumeRole',
      principal: principalArn,
      resource: {
        resource: roleArn,
        accountId: '123456789012'
      }
    })
    expect(result.resultType).toBe('error')
    if (result.resultType !== 'error') {
      assert.fail(`Expected error result type, got ${result.resultType}`)
    }

    expect(result.errors.message).toBe('policy.errors')
    expect(result.errors.resourcePolicyErrors).toEqual([
      {
        path: 'Statement[0]',
        message: 'One of Principal or NotPrincipal is required in a trust policy'
      }
    ])
  })
})

describe('aws:userid strict context key behavior', () => {
  const useridConditionPolicy = [
    {
      PolicyName: 'ConditionalAccess',
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'dynamodb:GetItem',
            Resource: '*',
            Condition: {
              StringLike: { 'aws:userid': '*:expected-session' }
            }
          }
        ]
      }
    }
  ]

  it('should not treat aws:userid as strict for role principals in Discovery mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, {
      arn: roleArn,
      inlinePolicies: useridConditionPolicy
    })

    //When simulating in Discovery mode as the role
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: roleArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {}
      },
      client
    )

    //Then access should be allowed because aws:userid is not strict for roles
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    expect(result.overallResult).toBe('Allowed')

    //And aws:userid should be reported as an ignored condition on the identity allow
    if (result.resultType === 'single') {
      const ignoredConditions = result.result.analysis.ignoredConditions
      expect(ignoredConditions?.identity?.allow).toEqual(
        expect.arrayContaining([expect.objectContaining({ key: 'aws:userid' })])
      )
    } else {
      assert.fail(`Expected single result type, got ${result.resultType}`)
    }
  })

  it('should treat aws:userid as strict for user principals in Discovery mode', async () => {
    //Given a user whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const userArn = 'arn:aws:iam::123456789012:user/TestUser'
    await saveUser(store, {
      arn: userArn,
      inlinePolicies: useridConditionPolicy
    })

    //When simulating in Discovery mode as the user
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: userArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {}
      },
      client
    )

    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be denied because aws:userid is strict and the value doesn't match
    expect(result.overallResult).toBe('ImplicitlyDenied')
  })

  it('should treat aws:userid as strict for assumed-role session principals in Discovery mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, { arn: roleArn, inlinePolicies: useridConditionPolicy })

    //And an assumed-role session ARN whose session name does not match the condition
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/wrong-session'

    //When simulating in Discovery mode as the session
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: sessionArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {},
        ignoreMissingPrincipal: true
      },
      client
    )
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be denied because aws:userid is strict for sessions and the value doesn't match
    expect(result.overallResult).toBe('ImplicitlyDenied')
  })

  it('should allow assumed-role session when aws:userid condition matches in Discovery mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, { arn: roleArn, inlinePolicies: useridConditionPolicy })

    //And an assumed-role session ARN whose session name matches the condition
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/expected-session'

    //When simulating in Discovery mode as the session
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: sessionArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {},
        ignoreMissingPrincipal: true
      },
      client
    )
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be allowed because the userid matches
    expect(result.overallResult).toBe('Allowed')
  })

  it('should allow assumed-role session when aws:userid condition matches in Strict mode', async () => {
    //Given a role whose only Allow is gated by an aws:userid condition
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/TestRole'
    await saveRole(store, { arn: roleArn, inlinePolicies: useridConditionPolicy })

    //And an assumed-role session ARN whose session name matches the condition
    const sessionArn = 'arn:aws:sts::123456789012:assumed-role/TestRole/expected-session'

    //When simulating in Strict mode as the session
    const { result } = await simulateRequest(
      {
        simulationMode: 'Strict',
        principal: sessionArn,
        resourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
        resourceAccount: '123456789012',
        action: 'dynamodb:GetItem',
        customContextKeys: {},
        ignoreMissingPrincipal: true
      },
      client
    )
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    //Then access should be allowed because the userid matches the condition
    expect(result.overallResult).toBe('Allowed')
  })
})

describe('caller-provided Discovery context keys', () => {
  it('should evaluate a caller-provided SourceVpc value exactly', async () => {
    // Given a role whose Allow requires a specific source VPC
    const { store, client } = testStore()
    const roleArn = 'arn:aws:iam::123456789012:role/VpcRole'
    await saveRole(store, {
      arn: roleArn,
      inlinePolicies: [
        {
          PolicyName: 'SourceVpcAccess',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:ListBucket',
                Resource: '*',
                Condition: {
                  StringEquals: {
                    'aws:SourceVpc': 'vpc-expected'
                  }
                }
              }
            ]
          }
        }
      ]
    })

    // When simulating with a caller-provided nonmatching source VPC in Discovery mode
    const { result } = await simulateRequest(
      {
        simulationMode: 'Discovery',
        principal: roleArn,
        resourceArn: 'arn:aws:s3:::example-bucket',
        resourceAccount: '123456789012',
        action: 's3:ListBucket',
        customContextKeys: {
          'aws:SourceVpc': 'vpc-other'
        }
      },
      client
    )

    // Then the precise caller value should make the conditional Allow not apply
    if (result.resultType === 'error') {
      assert.fail(`Simulation resulted in error: ${result.errors.message}`)
    }
    expect(result.overallResult).toBe('ImplicitlyDenied')
  })

  it('should treat a caller-provided KMS caller account as known', () => {
    // Given a Discovery service-principal request with an alternate-case caller account
    const request: SimulationRequest = {
      simulationMode: 'Discovery',
      principal: 'ecr.amazonaws.com',
      resourceArn: 'arn:aws:kms:us-east-1:123456789012:key/example',
      resourceAccount: '123456789012',
      action: 'kms:Encrypt',
      customContextKeys: {
        'KMS:calleraccount': '999999999999'
      }
    }

    // When resolving the constraint for the canonical key spelling
    const constraint = discoveryConstraintForStrictKey('kms:CallerAccount', request)

    // Then the caller-supplied value should be authoritative
    expect(constraint).toEqual({
      keyName: 'kms:CallerAccount',
      presenceIsKnown: true,
      valueIsKnown: true
    })
  })
})

describe('resultMatchesExpectation', () => {
  it('should return true if the expected result is undefined', () => {
    //Given an expected result of undefined
    const expected = undefined

    //When checking against any actual result
    const result = resultMatchesExpectation(expected, 'Allowed')

    //Then it should return true
    expect(result).toBe(true)
  })
  it('should return true if the expected result matches the actual result', () => {
    //Given a set of expected values
    const expectedValues = ['Allowed', 'ExplicitlyDeny', 'ImplicitlyDeny'] as EvaluationResult[]

    //When checking against each expected value
    const actualValues = expectedValues.map((expected) => {
      return resultMatchesExpectation(expected, expected)
    })

    //Then it should return true for each match
    expect(actualValues).toEqual(expectedValues.map(() => true))
  })
  it('should return true if AnyDeny is expected and the actual result is ImplicitlyDeny', () => {
    // Given AnyDeny as the expected result
    const expected = 'AnyDeny'

    // When checking against ImplicitlyDeny
    const result = resultMatchesExpectation(expected, 'ImplicitlyDenied')

    // Then it should return true
    expect(result).toBe(true)
  })

  it('should return true if AnyDeny is expected and the actual result is ExplicitlyDeny', () => {
    // Given AnyDeny as the expected result
    const expected = 'AnyDeny'

    // When checking against ExplicitlyDenied
    const result = resultMatchesExpectation(expected, 'ExplicitlyDenied')

    // Then it should return true
    expect(result).toBe(true)
  })
})
