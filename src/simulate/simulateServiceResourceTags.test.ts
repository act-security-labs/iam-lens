import type { EvaluationResult } from '@actsecurity/iam-simulate'
import { describe, expect, it } from 'vitest'
import { testStore } from '../collect/inMemoryClient.js'
import { saveUser } from '../utils/testUtils.js'
import { simulateRequest, type SimulationRequest } from './simulate.js'

const accountId = '111122223333'
const managementAccountId = '999988887777'
const orgId = 'o-tagkeys'
const userArn = `arn:aws:iam::${accountId}:user/alice`
const scpArn = `arn:aws:organizations::${managementAccountId}:policy/${orgId}/service_control_policy/p-tagkeys`

/**
 * A service whose resources AWS also exposes under a service-prefixed resource tag key.
 */
interface ServiceTagKeyCase {
  /** The service-prefixed tag key, as written in the SCP. */
  tagKey: string

  /** The request action. */
  action: string

  /** The collected resource. */
  resourceArn: string
}

const serviceTagKeyCases: ServiceTagKeyCase[] = [
  {
    tagKey: 'ec2:ResourceTag/env',
    action: 'ec2:TerminateInstances',
    resourceArn: `arn:aws:ec2:us-east-1:${accountId}:instance/i-0123456789abcdef0`
  },
  {
    tagKey: 'secretsmanager:ResourceTag/env',
    action: 'secretsmanager:GetSecretValue',
    resourceArn: `arn:aws:secretsmanager:us-east-1:${accountId}:secret:db-AbCdEf`
  },
  {
    tagKey: 'ssm:resourceTag/env',
    action: 'ssm:GetParameter',
    resourceArn: `arn:aws:ssm:us-east-1:${accountId}:parameter/db`
  }
]

/**
 * Collect a user allowed every action, under an SCP that denies `action` unless `tagKey` is `dev`.
 *
 * @param tagKey the tag key the SCP's deny condition reads
 * @param action the action the SCP denies
 * @param resource the resource to collect, with its tags; tags are unknown when omitted
 * @returns the collect client
 */
async function collectDenyUnlessDev({
  tagKey,
  action,
  resource
}: {
  tagKey: string
  action: string
  resource?: { arn: string; tags: Record<string, string> }
}) {
  const { store, client } = testStore()
  await saveUser(store, {
    arn: userArn,
    inlinePolicies: [
      {
        PolicyName: 'AllowAll',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: { Effect: 'Allow', Action: '*', Resource: '*' }
        }
      }
    ]
  })

  await store.saveOrganizationMetadata(orgId, 'metadata', { rootAccountId: managementAccountId })
  await store.saveIndex('accounts-to-orgs', { [accountId]: orgId }, '')
  await store.saveOrganizationMetadata(orgId, 'ous', { 'r-root': { scps: [scpArn], rcps: [] } })
  await store.saveOrganizationMetadata(orgId, 'accounts', {
    [accountId]: { ou: 'r-root', scps: [scpArn], rcps: [] }
  })
  await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-tagkeys', 'metadata', {
    arn: scpArn,
    name: 'DenyUnlessDev'
  })
  await store.saveOrganizationPolicyMetadata(orgId, 'scps', 'p-tagkeys', 'policy', {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: '*', Resource: '*' },
      {
        Effect: 'Deny',
        Action: action,
        Resource: '*',
        Condition: { StringNotEquals: { [tagKey]: 'dev' } }
      }
    ]
  })

  if (resource) {
    await store.saveResourceMetadata(accountId, resource.arn, 'metadata', { arn: resource.arn })
    await store.saveResourceMetadata(accountId, resource.arn, 'tags', resource.tags)
  }
  return client
}

/**
 * Simulate the user's request and return its overall result and Discovery conditions.
 *
 * @param request the action, resource and mode to simulate
 * @param client the collect client
 * @returns the overall result and the conditions it depends on
 */
async function simulate(
  request: Pick<SimulationRequest, 'action' | 'resourceArn' | 'simulationMode'>,
  client: Awaited<ReturnType<typeof collectDenyUnlessDev>>
): Promise<{ overallResult: EvaluationResult; conditions: unknown }> {
  const { result } = await simulateRequest(
    { ...request, principal: userArn, resourceAccount: accountId, customContextKeys: {} },
    client
  )
  if (result.resultType !== 'single') {
    throw new Error(`Expected a single result, got ${result.resultType}`)
  }
  return { overallResult: result.overallResult, conditions: result.result.analysis.conditions }
}

describe('service-prefixed resource tag keys', () => {
  describe.each(serviceTagKeyCases)('$tagKey', ({ tagKey, action, resourceArn }) => {
    it.each<{ tags: Record<string, string>; expected: EvaluationResult }>([
      { tags: { env: 'dev' }, expected: 'Allowed' },
      { tags: { env: 'prod' }, expected: 'ExplicitlyDenied' },
      { tags: {}, expected: 'ExplicitlyDenied' }
    ])(
      'should decide the SCP from the collected tags $tags in both modes',
      async ({ tags, expected }) => {
        //Given an SCP that denies the action unless the service tag key is dev, and a resource with known tags
        const client = await collectDenyUnlessDev({
          tagKey,
          action,
          resource: { arn: resourceArn, tags }
        })

        //When the request is simulated in Strict and Discovery modes
        const strict = await simulate({ action, resourceArn, simulationMode: 'Strict' }, client)
        const discovery = await simulate(
          { action, resourceArn, simulationMode: 'Discovery' },
          client
        )

        //Then both modes should reach the same definite result
        expect(strict).toEqual({ overallResult: expected, conditions: undefined })
        expect(discovery).toEqual({ overallResult: expected, conditions: undefined })
      }
    )
  })

  it('should leave the tag key undecided in Discovery when the resource tags are unknown', async () => {
    //Given the ec2 SCP and an instance with no collected metadata
    const { tagKey, action, resourceArn } = serviceTagKeyCases[0]
    const client = await collectDenyUnlessDev({ tagKey, action })

    //When the request is simulated in Discovery mode
    const discovery = await simulate({ action, resourceArn, simulationMode: 'Discovery' }, client)

    //Then the result should be allowed only if the instance is tagged env=dev
    expect(discovery).toEqual({
      overallResult: 'Allowed',
      conditions: expect.objectContaining({
        conditions: expect.arrayContaining([
          expect.objectContaining({ key: tagKey, values: ['dev'] })
        ])
      })
    })
  })
})
