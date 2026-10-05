import { describe, expect, it, vi } from 'vitest'
import { testStore } from './collect/inMemoryClient.js'
import { getAllPoliciesForPrincipal, isServiceLinkedRole } from './principals.js'
import { saveRole } from './utils/testUtils.js'

describe('isServiceLinkedRole', () => {
  it('should return true for service-linked role ARNs', () => {
    //Given a service-linked role ARN
    const serviceLinkedRoleArn =
      'arn:aws:iam::123456789012:role/aws-service-role/some-service.amazonaws.com/AWSServiceRoleForSomeService'

    //When checking if it is a service-linked role
    const result = isServiceLinkedRole(serviceLinkedRoleArn)

    //Then it should return true
    expect(result).toBe(true)
  })

  it('should return false for non-service-linked role ARNs', () => {
    //Given a non-service-linked role ARN
    const nonServiceLinkedRoleArn = 'arn:aws:iam::123456789012:role/some-other-role'

    //When checking if it is a service-linked role
    const result = isServiceLinkedRole(nonServiceLinkedRoleArn)

    //Then it should return false
    expect(result).toBe(false)
  })

  it('should return false for non-ARN principals', () => {
    //Given a non-ARN principal
    const nonArnPrincipal = 'some-principal.amazonaws.com'

    //When checking if it is a service-linked role
    const result = isServiceLinkedRole(nonArnPrincipal)

    //Then it should return false
    expect(result).toBe(false)
  })
})

describe('getAllPoliciesForPrincipal', () => {
  it('should omit SCPs for a service-linked role', async () => {
    //Given a service-linked role in an account with an SCP hierarchy
    const { store, client } = testStore()
    const serviceLinkedRoleArn =
      'arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample'
    await saveRole(store, { arn: serviceLinkedRoleArn })
    vi.spyOn(client, 'getScpHierarchyForAccount').mockResolvedValue([
      { orgIdentifier: 'o-example', policies: [] }
    ])

    //When loading all policies for the service-linked role
    const policies = await getAllPoliciesForPrincipal(client, serviceLinkedRoleArn)

    //Then SCPs should be excluded from the applicable principal policies
    expect(policies.scps).toEqual([])
  })

  it('should load policies from a path-qualified role for a pathless assumed-role ARN', async () => {
    //Given a path-qualified role and an assumed-role session ARN that omits the IAM role path
    const { store, client } = testStore()
    const accountId = '123456789012'
    const roleArn = `arn:aws:iam::${accountId}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_engineer_abcdef1234567890`
    await saveRole(store, {
      arn: roleArn,
      inlinePolicies: [
        {
          PolicyName: 'AllowListBucket',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: 's3:ListBucket', Resource: '*' }]
          }
        }
      ],
      managedPolicies: []
    })
    const assumedRoleArn = `arn:aws:sts::${accountId}:assumed-role/AWSReservedSSO_engineer_abcdef1234567890/session`

    //When loading policies for the assumed-role session principal
    const policies = await getAllPoliciesForPrincipal(client, assumedRoleArn)

    //Then the path-qualified role policies should be loaded
    expect(policies.inlinePolicies).toHaveLength(1)
    expect(policies.inlinePolicies[0].name).toBe('AllowListBucket')
  })
})
