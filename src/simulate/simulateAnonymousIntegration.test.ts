import { anonymousPrincipal, type EvaluationResult } from '@actsecurity/iam-simulate'
import { assert, describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import {
  simulateAnonymousRequest,
  type AnonymousSimulationRequest,
  type SimulateRequestResult
} from './simulate.js'

/**
 * A dataset-backed anonymous authorization scenario.
 */
interface AnonymousIntegrationCase {
  /**
   * Human-readable behavior under test.
   */
  name: string

  /**
   * Sanitized collected dataset identifier.
   */
  data: string

  /**
   * Anonymous request to simulate.
   */
  request: AnonymousSimulationRequest

  /**
   * Expected final decision for a successful simulation.
   */
  expected?: EvaluationResult

  /**
   * Expected thrown error pattern for an unsupported request.
   */
  expectedError?: string

  /**
   * Optional guardrail that must explain a denial.
   */
  expectedGuardrail?: 'rcp' | 'resource-policy' | 's3-bpa' | 'vpc-endpoint'
}

const anonymousIntegrationCases: AnonymousIntegrationCase[] = [
  {
    name: 'allows public object access when S3 Block Public Access is disabled',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'normalizes an S3 object to its collected bucket metadata',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/nested/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'blocks public access when account-level S3 Block Public Access is enabled',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::account-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedGuardrail: 's3-bpa'
  },
  {
    name: 'blocks public access when bucket-level S3 Block Public Access is enabled',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::bucket-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedGuardrail: 's3-bpa'
  },
  {
    name: 'applies a collected RCP deny to an anonymous request',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::restricted-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedGuardrail: 'rcp'
  },
  {
    name: 'applies a denying VPC endpoint policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      customContextKeys: { 'aws:SourceVpce': 'vpce-00000000002' },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedGuardrail: 'vpc-endpoint'
  },
  {
    name: 'uses an authoritative caller context value in a resource policy deny',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::source-arn-deny-bucket/log.json',
      resourceAccount: undefined,
      action: 's3:PutObject',
      customContextKeys: { 'aws:SourceArn': 'arn:aws:events:us-east-1:200000000002:rule/example' },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'does not apply a StringEquals principal organization deny when the key is absent',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::anonymous-principal-org-conditions/string-equals',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'applies a StringEqualsIfExists principal organization deny when the key is absent',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::anonymous-principal-org-conditions/string-equals-if-exists',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied',
    expectedGuardrail: 'resource-policy'
  },
  {
    name: 'applies a StringNotEquals principal organization deny when the key is absent',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::anonymous-principal-org-conditions/string-not-equals',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied',
    expectedGuardrail: 'resource-policy'
  },
  {
    name: 'supports Discovery mode without authenticated principal context',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'matches canonical anonymous userid and principal type values',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::anonymous-context-bucket/matching/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'does not ignore a nonmatching anonymous principal type condition',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::anonymous-context-bucket/non-anonymous/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'rejects principal-derived caller context',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      customContextKeys: { 'AWS:PrincipalOrgId': 'o-example' },
      simulationMode: 'Strict'
    },
    expectedError:
      'Anonymous simulations cannot specify principal-derived context key AWS:PrincipalOrgId'
  },
  {
    name: 'rejects wildcard-only actions',
    data: '2',
    request: {
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket',
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expectedError: 'Anonymous simulations do not support wildcard-only actions'
  }
]

describe('simulateAnonymousRequest integration', () => {
  for (const testCase of anonymousIntegrationCases) {
    it(testCase.name, async () => {
      //Given a collected IAM dataset and an anonymous request scenario
      const collectClient = await getTestDatasetClient(testCase.data)

      //When simulating the anonymous request
      const simulation = simulateAnonymousRequest(testCase.request, collectClient)

      if (testCase.expectedError) {
        //Then the unsupported request should be rejected
        await expect(simulation).rejects.toThrow(new RegExp(testCase.expectedError))
        return
      }

      const response = await simulation

      //Then the unsigned principal and expected authorization result should be returned
      expect(response.request.principal).toEqual(anonymousPrincipal)
      assertSuccessfulResult(response)
      expect(response.result.overallResult).toBe(testCase.expected)
      assertExpectedGuardrail(response, testCase.expectedGuardrail)
    })
  }
})

/**
 * Assert that an anonymous integration response completed policy evaluation.
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
 * Assert the meaningful guardrail analysis for a scenario.
 *
 * @param response successful simulation response
 * @param guardrail guardrail expected to have denied the request
 */
function assertExpectedGuardrail(
  response: SimulateRequestResult & {
    result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
  },
  guardrail: AnonymousIntegrationCase['expectedGuardrail']
): void {
  if (!guardrail) {
    return
  }
  if (response.result.resultType !== 'single') {
    assert.fail(`Expected single result, got ${response.result.resultType}`)
  }
  const analysis = response.result.result.analysis
  if (guardrail === 'rcp') {
    expect(analysis.rcpAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (guardrail === 'resource-policy') {
    expect(analysis.resourceAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (guardrail === 'vpc-endpoint') {
    expect(analysis.endpointAnalysis?.result).toBe('ExplicitlyDenied')
  } else {
    expect(analysis.blockedBy).toContain('s3-bpa')
  }
}
