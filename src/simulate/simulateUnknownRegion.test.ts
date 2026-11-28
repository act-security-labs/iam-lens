import { describe, expect, it, vi } from 'vitest'
import { testStore } from '../collect/inMemoryClient.js'
import { simulateExternalResourceRequest } from './simulate.js'

const principalAccount = '111111111111'
const externalAccount = '222222222222'
const roleArn = `arn:aws:iam::${principalAccount}:role/Writer`
const objectArn = 'arn:aws:s3:::external-drop-us-west-2/exports/file'

/**
 * A common region guardrail: deny everything outside us-west-2, except a few global services.
 */
const regionDenyScp = {
  orgIdentifier: 'o-example',
  policies: [
    {
      name: 'region-restriction',
      policy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'DenyOutsideUsWest2',
            Effect: 'Deny',
            NotAction: ['iam:*', 'organizations:*', 's3:Get*', 's3:List*'],
            Resource: '*',
            Condition: { StringNotEquals: { 'aws:RequestedRegion': 'us-west-2' } }
          }
        ]
      }
    },
    {
      name: 'FullAWSAccess',
      policy: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }]
      }
    }
  ]
}

async function writerRoleStore() {
  const { store, client } = testStore()
  await store.saveResourceMetadata(principalAccount, roleArn, 'metadata', {
    arn: roleArn,
    name: 'Writer',
    id: 'AROAEXAMPLEWRITER',
    path: '/'
  })
  await store.saveResourceMetadata(principalAccount, roleArn, 'inline-policies', [
    {
      PolicyName: 'write-to-external-drop',
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::external-drop-*' }
        ]
      }
    }
  ])
  vi.spyOn(client, 'getScpHierarchyForAccount').mockResolvedValue([regionDenyScp])
  return client
}

describe('aws:RequestedRegion for an S3 bucket whose region is unknown', () => {
  it('control: a request in the allowed region is allowed', async () => {
    //Given a role allowed to write to an external bucket and a region-deny SCP
    const client = await writerRoleStore()

    //When the request region is supplied
    const { result } = await simulateExternalResourceRequest(
      {
        principal: roleArn,
        resourceArn: objectArn,
        resourceAccount: externalAccount,
        action: 's3:PutObject',
        customContextKeys: { 'aws:RequestedRegion': 'us-west-2' },
        simulationMode: 'Strict'
      },
      client
    )

    //Then the write is allowed
    expect(result.overallResult).toBe('Allowed')
  })

  it('does not report an unknown-region request as denied by a region guardrail', async () => {
    //Given the same role and SCP, and an external bucket whose region was never collected
    const client = await writerRoleStore()

    //When whoCan's Strict pass simulates the write without a known region
    const { result } = await simulateExternalResourceRequest(
      {
        principal: roleArn,
        resourceArn: objectArn,
        resourceAccount: externalAccount,
        action: 's3:PutObject',
        customContextKeys: {},
        simulationMode: 'Strict'
      },
      client
    )

    //Then the guardrail must not be decided as denying: every real S3 request carries a region,
    //and this one can be in us-west-2. Today aws:RequestedRegion is omitted, StringNotEquals
    //matches the missing key, and the SCP denies.
    expect(result.overallResult).not.toBe('ExplicitlyDenied')
  })
})
