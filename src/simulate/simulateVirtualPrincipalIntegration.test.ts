import type { AllowedConditionExpression, EvaluationResult } from '@actsecurity/iam-simulate'
import { assert, describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import {
  simulateVirtualPrincipal,
  type SimulateRequestResult,
  type VirtualPrincipalSimulationRequest
} from './simulate.js'

/**
 * A dataset-backed virtual-principal authorization scenario.
 */
interface VirtualPrincipalIntegrationCase {
  /** Human-readable behavior under test. */
  name: string

  /** Sanitized collected dataset identifier. */
  data: string

  /** Virtual-principal request to simulate. */
  request: VirtualPrincipalSimulationRequest

  /** Expected final authorization decision. */
  expected: EvaluationResult

  /** Exact unresolved Discovery conditions expected in the result. */
  expectedConditions?: AllowedConditionExpression

  /** Optional policy analysis that must explain the decision. */
  expectedAnalysis?: 'scp-deny' | 'scp-allow' | 'rcp-deny'
}

const virtualPrincipalIntegrationCases: VirtualPrincipalIntegrationCase[] = [
  {
    name: 'applies an inherited SCP deny to an uncollected principal in a collected account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000002:role/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:PutBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'scp-deny'
  },
  {
    name: 'allows an uncollected principal from an organization-only account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000003:role/VirtualReader',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'applies an inherited SCP deny to an uncollected principal in an organization-only account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000003:role/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:PutBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'scp-deny'
  },
  {
    name: 'replaces the default allow-all identity policy with the supplied inline policy',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000002:role/VirtualReader',
      resourceArn: 'arn:aws:ec2:us-east-1:100000000002:instance/i-virtual-principal',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      customContextKeys: {},
      simulationMode: 'Strict',
      inlinePolicy: {
        Version: '2012-10-17',
        Statement: { Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' }
      }
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'returns an unresolved principal tag condition for a virtual IAM role',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/team',
      values: ['security'],
      sources: [
        {
          policyType: 'resource',
          effect: 'Allow',
          policyIdentifier: undefined,
          statementId: 'AllowSecurityTeam',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'does not trust collected tags when a role is simulated as a virtual principal',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000002:role/tagged-role',
      resourceArn: 'arn:aws:s3:::external-principal-tag-cross-account-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/team',
      values: ['security'],
      sources: [
        {
          policyType: 'resource',
          effect: 'Allow',
          policyIdentifier: undefined,
          statementId: 'AllowSecurityTeam',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'returns an unresolved principal tag condition for a virtual role session',
    data: '2',
    request: {
      principal: 'arn:aws:sts::400000000001:assumed-role/VirtualAdministrator/integration-test',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/team',
      values: ['security'],
      sources: [
        {
          policyType: 'resource',
          effect: 'Allow',
          policyIdentifier: undefined,
          statementId: 'AllowSecurityTeam',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'returns an unresolved principal tag condition for a virtual IAM user',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:user/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/team',
      values: ['security'],
      sources: [
        {
          policyType: 'resource',
          effect: 'Allow',
          policyIdentifier: undefined,
          statementId: 'AllowSecurityTeam',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'allows a virtual IAM user with an explicit matching principal tag',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:user/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: { 'aws:PrincipalTag/team': 'security' },
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'applies a captured resource RCP to a virtual principal',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000002:role/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::restricted-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'rcp-deny'
  },
  {
    name: 'supports wildcard-only actions with the virtual principal account SCP hierarchy',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000002:role/VirtualAdministrator',
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedAnalysis: 'scp-allow'
  }
]

describe('simulateVirtualPrincipal integration', () => {
  for (const testCase of virtualPrincipalIntegrationCases) {
    it(testCase.name, async () => {
      //Given a collected organization dataset and a virtual principal request
      const collectClient = await getTestDatasetClient(testCase.data)

      //When simulating with a synthetic or caller-provided identity policy
      const response = await simulateVirtualPrincipal(testCase.request, collectClient)

      //Then the expected decision and applicable organization controls are returned
      assertSuccessfulResult(response)
      expect(response.request.principal).toBe(testCase.request.principal)
      expect(response.result.overallResult).toBe(testCase.expected)
      if (Object.hasOwn(testCase, 'expectedConditions')) {
        if (response.result.resultType !== 'single') {
          assert.fail(`Expected single result, got ${response.result.resultType}`)
        }
        expect(response.result.result.analysis.conditions).toEqual(testCase.expectedConditions)
      }
      assertExpectedAnalysis(response, testCase.expectedAnalysis)
    })
  }

  it('rejects a virtual principal without an account ID', async () => {
    //Given a virtual principal ARN without an account ID
    const collectClient = await getTestDatasetClient('1')
    const request: VirtualPrincipalSimulationRequest = {
      principal: 'arn:aws:iam:::role/VirtualAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    //When the virtual principal is simulated
    const simulation = simulateVirtualPrincipal(request, collectClient)

    //Then the request is rejected before policy evaluation
    await expect(simulation).rejects.toThrow('must contain an account ID')
  })
})

/**
 * Assert that a virtual-principal integration response completed policy evaluation.
 *
 * @param response simulation response to narrow
 */
function assertSuccessfulResult(
  response: SimulateRequestResult
): asserts response is SimulateRequestResult & {
  result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
} {
  if (response.result.resultType === 'error') {
    assert.fail(`Simulation error: ${response.result.errors.message}`)
  }
}

/**
 * Assert the policy analysis that makes a virtual-principal scenario meaningful.
 *
 * @param response successful simulation response
 * @param expectedAnalysis policy analysis expected for the scenario
 */
function assertExpectedAnalysis(
  response: SimulateRequestResult & {
    result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
  },
  expectedAnalysis: VirtualPrincipalIntegrationCase['expectedAnalysis']
): void {
  if (!expectedAnalysis) {
    return
  }
  if (response.result.resultType !== 'single') {
    assert.fail(`Expected single result, got ${response.result.resultType}`)
  }
  if (expectedAnalysis === 'scp-deny') {
    expect(response.result.result.analysis.scpAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'rcp-deny') {
    expect(response.result.result.analysis.rcpAnalysis?.result).toBe('ExplicitlyDenied')
  } else {
    expect(response.result.result.analysis.scpAnalysis?.result).toBe('Allowed')
    expect(response.result.result.analysis.scpAnalysis?.ouAnalysis).not.toEqual([])
  }
}
