import { describe, expect, it } from 'vitest'
import { getTestDatasetConfigs } from '../test-datasets/testClient.js'
import { WhoCanProcessor, type WhoCanSettledEvent } from './WhoCanProcessor.js'
import { whoCan, type WhoCanResponse, type WhoCanPrincipalScope } from './whoCan.js'

/** An unsigned access scenario isolated from collected-principal enumeration. */
interface AnonymousWhoCanCase {
  name: string
  resource?: string
  resourceAccount?: string
  dataset?: string
  action?: string
  scope?: WhoCanPrincipalScope
  simulationCount?: number
  /** Whether the final response should include an anonymous allowed result. */
  expectedAnonymousAllowed: boolean
  wildcard?: boolean
  skipped?: boolean
}

/** Data-backed access scenarios, including scope boundaries for unsigned callers. */
const cases: AnonymousWhoCanCase[] = [
  {
    name: 'public object',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    expectedAnonymousAllowed: true
  },
  {
    name: 'public object prefix',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::no-bpa-public-bucket/*',
    expectedAnonymousAllowed: true,
    wildcard: true
  },
  {
    name: 'account BPA denial',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::account-bpa-public-bucket/report.txt',
    expectedAnonymousAllowed: false
  },
  {
    name: 'bucket BPA denial',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::bucket-bpa-public-bucket/*',
    expectedAnonymousAllowed: false,
    wildcard: true
  },
  {
    name: 'canonical anonymous context',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::anonymous-context-bucket/matching/*',
    expectedAnonymousAllowed: true,
    wildcard: true
  },
  {
    name: 'incompatible principal type',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::anonymous-context-bucket/non-anonymous/report.txt',
    expectedAnonymousAllowed: false
  },
  {
    name: 'specific principal only',
    scope: { anonymous: true },
    simulationCount: 0,
    resource: 'arn:aws:s3:::bucket-bpa-specific-principal-bucket/report.txt',
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'resource without a policy',
    scope: { anonymous: true },
    simulationCount: 0,
    resource: 'arn:aws:s3:::restricted-bucket',
    dataset: '1',
    action: 's3:GetBucketPolicy',
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'resource-less wildcard-only action',
    scope: { anonymous: true },
    simulationCount: 0,
    resourceAccount: '500000000003',
    action: 's3:ListAllMyBuckets',
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'explicit policy denial with an absent anonymous org key',
    scope: { anonymous: true },
    simulationCount: 1,
    resource: 'arn:aws:s3:::anonymous-principal-org-conditions/string-not-equals',
    dataset: '1',
    expectedAnonymousAllowed: false
  },
  {
    name: 'public object without a scope',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    expectedAnonymousAllowed: true
  },
  {
    name: 'public object with empty scope',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: {},
    simulationCount: 0,
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'public object with empty principal list',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: { principals: [] },
    simulationCount: 0,
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'public object with account-only scope',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: { accounts: ['500000000003'] },
    simulationCount: 0,
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'public object with OU-only scope',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: { ous: ['o-example/r-example/ou-example'] },
    simulationCount: 0,
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'public object with ARN-only scope',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: { principals: ['arn:aws:iam::400000000001:role/alpha-role'] },
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'public object with anonymous explicitly disabled',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: { anonymous: false },
    simulationCount: 0,
    expectedAnonymousAllowed: false,
    skipped: true
  },
  {
    name: 'public object with mixed scope',
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    scope: { anonymous: true, principals: ['arn:aws:iam::400000000001:role/alpha-role'] },
    expectedAnonymousAllowed: true
  }
]

it('schedules one unsigned scenario per distinct action', async () => {
  //Given a public read-only object policy and no collected principals in scope
  const configs = getTestDatasetConfigs('2')

  //When multiple actions include a duplicate, wildcard-only, and anonymous-blocked actions
  const result = await whoCan(configs, 'aws', {
    resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
    actions: [
      's3:GetObject',
      's3:PutObject',
      's3:GetObject',
      's3:ListAllMyBuckets',
      'ecr:BatchCheckLayerAvailability'
    ],
    principalScope: { anonymous: true },
    workerThreads: 0,
    denyDetailsCallback: () => true
  })

  //Then the unique resource actions are counted and separately allowed or denied
  expect(result.simulationCount).toBe(2)
  expect(result.allowed).toEqual([
    {
      principal: 'anonymous',
      service: 's3',
      action: 'GetObject',
      level: 'read',
      resourceType: 'object'
    }
  ])
  expect(result.denyDetails).toEqual([
    expect.objectContaining({
      type: 'single',
      principal: 'anonymous',
      service: 's3',
      action: 'PutObject'
    })
  ])
})

for (const workerThreads of [0, 1]) {
  for (const ignorePrincipalIndex of [false, true]) {
    describe(`anonymous whoCan (workers: ${workerThreads}, ignoreIndex: ${ignorePrincipalIndex})`, () => {
      for (const scenario of cases) {
        it(scenario.name, async () => {
          //Given collected S3 policies and the scenario's optional principal scope
          let settled: WhoCanSettledEvent | undefined
          const processor = await WhoCanProcessor.create({
            collectConfigs: getTestDatasetConfigs(scenario.dataset ?? '2'),
            partition: 'aws',
            tuning: { workerThreads, mainThreadConcurrency: workerThreads ? 0 : 10 },
            ignorePrincipalIndex,
            collectGrantDetails: true,
            onRequestSettled: async (event) => {
              settled = event
            }
          })
          try {
            //When anonymous access is evaluated through the shared scheduler
            processor.enqueueWhoCan({
              resource: scenario.resource,
              resourceAccount: scenario.resourceAccount,
              actions: [scenario.action ?? 's3:GetObject'],
              principalScope: scenario.scope,
              sort: true,
              denyDetailsCallback: () => true
            })
            await processor.waitForIdle()

            //Then anonymous results respect the supplied scope and preserve access details
            expect(settled?.status).toBe('fulfilled')
            if (settled?.status !== 'fulfilled') {
              throw new Error('Anonymous request failed to settle successfully')
            }
            const result: WhoCanResponse = settled.result
            if (scenario.simulationCount !== undefined) {
              expect(result.simulationCount).toBe(scenario.simulationCount)
            }
            expect(result.principalsNotFound).toEqual([])
            const anonymousAllowed = result.allowed.filter(
              (entry) => entry.principal === 'anonymous'
            )
            const anonymousDenials = result.denyDetails?.filter(
              (entry) => entry.principal === 'anonymous'
            )
            if (scenario.scope?.principals) {
              const scopedPrincipals = [...scenario.scope.principals]
              if (scenario.scope.anonymous) {
                scopedPrincipals.push('anonymous')
              }
              for (const entry of result.allowed) {
                expect(scopedPrincipals).toContain(entry.principal)
              }
            }
            if (scenario.expectedAnonymousAllowed) {
              expect(anonymousAllowed).toHaveLength(1)
              const allowed = anonymousAllowed[0]
              expect(allowed).toMatchObject({
                principal: 'anonymous',
                service: 's3',
                action: 'GetObject',
                level: 'read'
              })
              if (scenario.wildcard) {
                expect(allowed.resourceType).toBeUndefined()
                expect(allowed.allowedPatterns).toEqual([
                  expect.objectContaining({
                    pattern: scenario.resource,
                    resourceType: 'object',
                    details: expect.any(Array)
                  })
                ])
                expect(allowed.allowedPatterns?.[0].details).not.toEqual([])
              } else {
                expect(allowed.resourceType).toBe('object')
                expect(allowed.allowedPatterns).toBeUndefined()
                expect(allowed.details).not.toEqual([])
              }
              expect(anonymousDenials).toEqual([])
            } else {
              expect(anonymousAllowed).toEqual([])
              if (scenario.skipped) {
                expect(anonymousDenials).toEqual([])
              } else {
                expect(anonymousDenials).toEqual([
                  expect.objectContaining({
                    principal: 'anonymous',
                    service: 's3',
                    action: 'GetObject',
                    type: scenario.wildcard ? 'wildcard' : 'single'
                  })
                ])
              }
            }
          } finally {
            await processor.shutdown()
          }
        })
      }
    })
  }
}
