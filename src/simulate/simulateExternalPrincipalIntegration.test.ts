import type { AllowedConditionExpression, EvaluationResult } from '@actsecurity/iam-simulate'
import { assert, describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import {
  simulateExternalPrincipalRequest,
  type SimulateRequestResult,
  type SimulationRequest
} from './simulate.js'

/**
 * A dataset-backed external-principal authorization scenario.
 */
interface ExternalPrincipalIntegrationCase {
  /**
   * Human-readable behavior under test.
   */
  name: string

  /**
   * Sanitized collected dataset identifier.
   */
  data: string

  /**
   * External-principal request to simulate.
   */
  request: SimulationRequest

  /**
   * Expected final authorization decision.
   */
  expected?: EvaluationResult

  /**
   * Expected error pattern for an unsupported request.
   */
  expectedError?: string

  /**
   * Exact unresolved Discovery conditions expected in the result.
   */
  expectedConditions?: AllowedConditionExpression

  /**
   * Optional policy analysis that must explain a denial.
   */
  expectedAnalysis?:
    'no-scp' | 'rcp' | 'resource-deny' | 'session-deny' | 'endpoint-deny' | 's3-bpa'
}

const externalPrincipalIntegrationCases: ExternalPrincipalIntegrationCase[] = [
  {
    name: 'allows an uncollected principal through a public resource policy',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'returns an unresolved principal tag condition in Discovery mode',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
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
    name: 'does not trust collected tags when a role is simulated as an external principal',
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
    name: 'returns an unresolved principal tag condition for an uncollected role session',
    data: '2',
    request: {
      principal: 'arn:aws:sts::999999999999:assumed-role/ExternalAdministrator/integration-test',
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
    name: 'returns an unresolved principal tag condition for an uncollected IAM user',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:user/ExternalAdministrator',
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
    name: 'allows an uncollected IAM user with an explicit matching principal tag',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:user/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: { 'aws:PrincipalTag/team': 'security' },
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'allows when a matching principal tag is supplied in Discovery mode',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: { 'aws:PrincipalTag/team': 'security' },
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'implicitly denies when a nonmatching principal tag is supplied in Discovery mode',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::external-principal-tag-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: { 'aws:PrincipalTag/team': 'engineering' },
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'uses the synthetic administrator identity policy for a principal in an external account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'does not apply a collected permission boundary',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000002:role/EC2Admin',
      resourceArn: 'arn:aws:ec2:us-east-1:100000000002:instance/i-external',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'does not apply a collected SCP to an external-principal simulation',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:PutBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedAnalysis: 'no-scp'
  },
  {
    name: 'rejects wildcard-only actions for a principal in an external account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expectedError: 'External principal simulations do not support wildcard-only actions'
  },
  {
    name: 'still applies a collected resource RCP deny to an external account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::restricted-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'rcp'
  },
  {
    name: 'still applies an explicit resource policy deny to an external account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'resource-deny'
  },
  {
    name: 'constrains an external account with a session policy allow-list',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: { Effect: 'Allow', Action: 'ec2:*', Resource: '*' }
      }
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'explicitly denies an external account with a session policy',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Action: '*', Resource: '*' },
          { Effect: 'Deny', Action: 's3:*', Resource: '*' }
        ]
      }
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'session-deny'
  },
  {
    name: 'still applies a denying VPC endpoint policy to an external account',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: { 'aws:SourceVpc': 'vpc-00000000002' },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'endpoint-deny'
  },
  {
    name: 'still applies collected S3 Block Public Access settings',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::account-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 's3-bpa'
  },
  {
    name: 'does not infer tags or fail when external principal metadata is absent',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/UntaggedExternalAdministrator',
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  }
]

describe('simulateExternalPrincipalRequest integration', () => {
  for (const testCase of externalPrincipalIntegrationCases) {
    it(testCase.name, async () => {
      //Given a collected resource dataset and an external principal request
      const collectClient = await getTestDatasetClient(testCase.data)

      //When simulating with the synthetic administrator identity
      const simulation = simulateExternalPrincipalRequest(testCase.request, collectClient)

      if (testCase.expectedError) {
        //Then the unsupported request should be rejected
        await expect(simulation).rejects.toThrow(new RegExp(testCase.expectedError))
        return
      }

      const response = await simulation

      //Then the expected decision and relevant policy analysis should be returned
      assertSuccessfulResult(response)
      expect(response.request.principal).toBe(testCase.request.principal)
      expect(response.result.overallResult).toBe(testCase.expected)
      assertExpectedConditions(response, testCase.expectedConditions)
      assertExpectedAnalysis(response, testCase.expectedAnalysis)
    })
  }
})

/**
 * Assert that an external-principal integration response completed policy evaluation.
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
 * Assert the exact unresolved Discovery conditions expected by a scenario.
 *
 * @param response successful simulation response
 * @param expectedConditions exact conditions expected in the result
 */
function assertExpectedConditions(
  response: SimulateRequestResult & {
    result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
  },
  expectedConditions: AllowedConditionExpression | undefined
): void {
  if (expectedConditions === undefined) {
    return
  }
  if (response.result.resultType !== 'single') {
    assert.fail(`Expected single result, got ${response.result.resultType}`)
  }
  expect(response.result.result.analysis.conditions).toEqual(expectedConditions)
}

/**
 * Assert the policy analysis that makes an integration scenario meaningful.
 *
 * @param response successful simulation response
 * @param expectedAnalysis policy analysis expected to deny the request
 */
function assertExpectedAnalysis(
  response: SimulateRequestResult & {
    result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
  },
  expectedAnalysis: ExternalPrincipalIntegrationCase['expectedAnalysis']
): void {
  if (!expectedAnalysis) {
    return
  }
  if (response.result.resultType !== 'single') {
    assert.fail(`Expected single result, got ${response.result.resultType}`)
  }
  const analysis = response.result.result.analysis
  if (expectedAnalysis === 'no-scp') {
    expect(analysis.scpAnalysis?.result).toBe('Allowed')
    expect(analysis.scpAnalysis?.ouAnalysis).toEqual([])
  } else if (expectedAnalysis === 'rcp') {
    expect(analysis.rcpAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'resource-deny') {
    expect(analysis.resourceAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'session-deny') {
    expect(analysis.sessionAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'endpoint-deny') {
    expect(analysis.endpointAnalysis?.result).toBe('ExplicitlyDenied')
  } else {
    expect(analysis.blockedBy).toContain('s3-bpa')
  }
}
