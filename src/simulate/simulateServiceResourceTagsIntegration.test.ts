import type { EvaluationResult } from '@actsecurity/iam-simulate'
import { describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import { simulateRequest, type SimulationRequest } from './simulate.js'

/**
 * Dataset 4 collects two accounts of one organization alike: an operator user, and a Secrets
 * Manager secret, an EC2 instance and an SSM parameter tagged `env=dev`, tagged `env=prod`, and
 * untagged. Each account's SCP denies DescribeSecret and GetParameter unless the resource is tagged
 * `env=dev`, and its user may terminate an instance only if it is tagged `env=dev`. One account's
 * conditions read the service-prefixed tag keys, the other's `aws:ResourceTag`.
 */
const DATASET = '4'
const REGION = 'us-east-1'
const MANAGEMENT_ACCOUNT_ID = '500000000001'
const ORG_ID = 'o-55555555'
const DESCRIBE_ONLY_DEV_SECRETS = 'DescribeOnlyDevSecrets'
const READ_ONLY_DEV_PARAMETERS = 'ReadOnlyDevParameters'

type ResourceKind = 'secret' | 'instance' | 'parameter'

const KEY_SETS: readonly {
  keys: string
  accountId: string
  scpId: string
  tagKeys: Record<ResourceKind, string>
}[] = [
  {
    keys: 'service-prefixed keys',
    accountId: '500000000002',
    scpId: 'p-servicetagkeys',
    tagKeys: {
      secret: 'secretsmanager:ResourceTag/env',
      instance: 'ec2:ResourceTag/env',
      parameter: 'ssm:resourceTag/env'
    }
  },
  {
    keys: 'aws:ResourceTag',
    accountId: '500000000003',
    scpId: 'p-globaltagkeys',
    tagKeys: {
      secret: 'aws:ResourceTag/env',
      instance: 'aws:ResourceTag/env',
      parameter: 'aws:ResourceTag/env'
    }
  }
]

/**
 * The resource ids: `dev` and `prod` are collected with their `env` tag, `untagged` is collected
 * with no tags, and `uncollected` is not collected.
 */
const RESOURCE_IDS = {
  dev: { secret: 'dev-db-AbCdEf', instance: 'i-0de00000000000000', parameter: 'dev/db-host' },
  prod: { secret: 'prod-db-AbCdEf', instance: 'i-0b0d0000000000000', parameter: 'prod/db-host' },
  untagged: {
    secret: 'untagged-db-AbCdEf',
    instance: 'i-0aa00000000000000',
    parameter: 'untagged/db-host'
  },
  uncollected: {
    secret: 'new-db-AbCdEf',
    instance: 'i-0ff00000000000000',
    parameter: 'new/db-host'
  }
} as const satisfies Record<string, Record<ResourceKind, string>>

const resourceArn = ({
  kind,
  accountId,
  resource
}: {
  kind: ResourceKind
  accountId: string
  resource: keyof typeof RESOURCE_IDS
}): string => {
  const id = RESOURCE_IDS[resource][kind]
  return {
    secret: `arn:aws:secretsmanager:${REGION}:${accountId}:secret:${id}`,
    instance: `arn:aws:ec2:${REGION}:${accountId}:instance/${id}`,
    parameter: `arn:aws:ssm:${REGION}:${accountId}:parameter/${id}`
  }[kind]
}

const operatorArn = (accountId: string) => `arn:aws:iam::${accountId}:user/operator`

const scpArn = (scpId: string) =>
  `arn:aws:organizations::${MANAGEMENT_ACCOUNT_ID}:policy/${ORG_ID}/service_control_policy/${scpId}`

/**
 * Each kind's action, and the condition of the statement that guards it on the resource's `env`
 * tag, but its key: an SCP statement that denies unless the tag is `dev`, or the operator's
 * identity statement that allows only if it is.
 */
const GUARDS: Record<
  ResourceKind,
  { action: string; condition: (args: { accountId: string; scpId: string }) => object }
> = {
  secret: {
    action: 'secretsmanager:DescribeSecret',
    condition: ({ accountId, scpId }) =>
      deniedUnlessDev({
        accountId,
        scpId,
        statementId: DESCRIBE_ONLY_DEV_SECRETS,
        statementIndex: 1
      })
  },
  instance: {
    action: 'ec2:TerminateInstances',
    condition: ({ accountId }) => ({
      conditionType: 'condition',
      op: 'StringEquals',
      values: ['dev'],
      sources: [
        {
          effect: 'Allow',
          policyType: 'identity',
          policyIdentifier: `${operatorArn(accountId)}#Operator`,
          statementIndex: 1
        }
      ]
    })
  },
  parameter: {
    action: 'ssm:GetParameter',
    condition: ({ accountId, scpId }) =>
      deniedUnlessDev({
        accountId,
        scpId,
        statementId: READ_ONLY_DEV_PARAMETERS,
        statementIndex: 2
      })
  }
}

/** The condition under which the account's SCP statement does not deny: `env=dev`. */
function deniedUnlessDev({
  accountId,
  scpId,
  statementId,
  statementIndex
}: {
  accountId: string
  scpId: string
  statementId: string
  statementIndex: number
}) {
  return {
    conditionType: 'condition',
    op: 'StringEquals',
    values: ['dev'],
    inverted: true,
    sources: [
      {
        effect: 'Deny',
        policyType: 'scp',
        policyIdentifier: scpArn(scpId),
        orgIdentifier: accountId,
        statementId,
        statementIndex
      }
    ]
  } as const
}

/** Each collected resource, AWS's result for the operator, and the SCP statements that deny it. */
const COLLECTED: readonly {
  kind: ResourceKind
  resource: 'dev' | 'prod' | 'untagged'
  expected: EvaluationResult
  deniedBy: string[]
}[] = [
  { kind: 'secret', resource: 'dev', expected: 'Allowed', deniedBy: [] },
  {
    kind: 'secret',
    resource: 'prod',
    expected: 'ExplicitlyDenied',
    deniedBy: [DESCRIBE_ONLY_DEV_SECRETS]
  },
  {
    kind: 'secret',
    resource: 'untagged',
    expected: 'ExplicitlyDenied',
    deniedBy: [DESCRIBE_ONLY_DEV_SECRETS]
  },
  { kind: 'instance', resource: 'dev', expected: 'Allowed', deniedBy: [] },
  { kind: 'instance', resource: 'prod', expected: 'ImplicitlyDenied', deniedBy: [] },
  { kind: 'instance', resource: 'untagged', expected: 'ImplicitlyDenied', deniedBy: [] },
  { kind: 'parameter', resource: 'dev', expected: 'Allowed', deniedBy: [] },
  {
    kind: 'parameter',
    resource: 'prod',
    expected: 'ExplicitlyDenied',
    deniedBy: [READ_ONLY_DEV_PARAMETERS]
  },
  {
    kind: 'parameter',
    resource: 'untagged',
    expected: 'ExplicitlyDenied',
    deniedBy: [READ_ONLY_DEV_PARAMETERS]
  }
]

/**
 * Simulate the operator's request of `kind`'s action on `resource` in `mode`.
 *
 * @returns the overall result, the Discovery conditions it depends on, and the SCP statements
 *   that deny it
 */
async function simulateOperator({
  accountId,
  kind,
  resource,
  mode
}: {
  accountId: string
  kind: ResourceKind
  resource: string
  mode: SimulationRequest['simulationMode']
}) {
  const collectClient = await getTestDatasetClient(DATASET)
  const { result } = await simulateRequest(
    {
      principal: operatorArn(accountId),
      action: GUARDS[kind].action,
      resourceArn: resource,
      resourceAccount: undefined,
      customContextKeys: {},
      simulationMode: mode
    },
    collectClient
  )
  if (result.resultType !== 'single') {
    throw new Error(`Expected a single simulation result, received ${result.resultType}`)
  }
  const { analysis } = result.result
  return {
    overallResult: result.overallResult,
    conditions: analysis.conditions,
    scpDenyStatementIds: (analysis.scpAnalysis?.ouAnalysis ?? []).flatMap((ou) =>
      ou.denyStatements.map(({ statement }) => statement.sid())
    )
  }
}

describe('service-prefixed resource tag keys Integration', () => {
  describe.each(KEY_SETS)('conditions on $keys', ({ accountId, scpId, tagKeys }) => {
    it.each(COLLECTED)(
      'the $resource $kind is $expected in Strict and Discovery',
      async ({ kind, resource: collected, expected, deniedBy }) => {
        //Given the collected resource and its tags
        const resource = resourceArn({ kind, accountId, resource: collected })

        //When the operator's request is simulated in both modes
        const strict = await simulateOperator({ accountId, kind, resource, mode: 'Strict' })
        const discovery = await simulateOperator({ accountId, kind, resource, mode: 'Discovery' })

        //Then both modes reach AWS's result from the collected tags
        const expectedResult = {
          overallResult: expected,
          conditions: undefined,
          scpDenyStatementIds: deniedBy
        }
        expect(strict).toEqual(expectedResult)
        expect(discovery).toEqual(expectedResult)
      }
    )

    it.each(['secret', 'instance', 'parameter'] as const)(
      'a %s with no collected tags is allowed in Discovery only if tagged env=dev',
      async (kind) => {
        //Given a resource the dataset does not collect
        const resource = resourceArn({ kind, accountId, resource: 'uncollected' })

        //When the operator's request is simulated in Discovery mode
        const discovery = await simulateOperator({ accountId, kind, resource, mode: 'Discovery' })

        //Then it is allowed on the condition the guarding statement puts on the tag key
        expect(discovery).toEqual({
          overallResult: 'Allowed',
          conditions: { ...GUARDS[kind].condition({ accountId, scpId }), key: tagKeys[kind] },
          scpDenyStatementIds: []
        })
      }
    )
  })
})
