import type { EvaluationResult } from '../../../iam-simulate/src/index.js'
import { assert, describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import {
  simulateExternalResourceRequest,
  simulateVirtualResourceRequest,
  type SimulateRequestResult,
  type VirtualResourceSimulationRequest
} from './simulate.js'

/**
 * A dataset-backed virtual-resource authorization scenario.
 */
interface VirtualResourceIntegrationCase {
  /** Human-readable behavior under test. */
  name: string

  /** Sanitized collected dataset identifier. */
  data: string

  /** Virtual-resource request to simulate. */
  request: VirtualResourceSimulationRequest

  /** Expected final authorization decision. */
  expected?: EvaluationResult

  /** Expected error pattern for an unsupported request or missing collected principal. */
  expectedError?: string

  /** Optional policy analysis that must explain the decision. */
  expectedAnalysis?: 'rcp-deny' | 'rcp-none' | 'scp-deny'
}

const virtualResourceIntegrationCases: VirtualResourceIntegrationCase[] = [
  {
    name: 'allows an uncollected KMS key when its account has no matching RCP deny',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:100000000002:key/virtual-key',
      resourceAccount: undefined,
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'allows an uncollected resource in an organization-only account',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:100000000003:key/virtual-key',
      resourceAccount: undefined,
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'applies no RCPs for a resource account outside the organization data',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:999999999999:key/virtual-key',
      resourceAccount: undefined,
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedAnalysis: 'rcp-none'
  },
  {
    name: 'does not apply an unrelated collected SCP to a virtual KMS key',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:100000000003:key/virtual-key',
      resourceAccount: undefined,
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'uses a caller-supplied resource policy explicit deny',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:100000000003:key/virtual-key',
      resourceAccount: undefined,
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Deny',
          Principal: '*',
          Action: 'kms:DescribeKey',
          Resource: 'arn:aws:kms:us-east-1:100000000003:key/virtual-key'
        }
      }
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'rejects wildcard-only actions',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:100000000003:key/virtual-key',
      resourceAccount: undefined,
      action: 'iam:ListUsers',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expectedError: 'Virtual resource simulations do not support wildcard-only actions'
  },
  {
    name: 'rejects a request without a resource account',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:s3:::abucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expectedError: 'must contain an account ID'
  },
  {
    name: 'rejects a principal that is not present in the collected dataset',
    data: '1',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:kms:us-east-1:100000000003:key/virtual-key',
      resourceAccount: undefined,
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expectedError: 'Principal arn:aws:iam::999999999999:role/ExternalAdministrator does not exist'
  }
]

describe('simulateVirtualResourceRequest Integration', () => {
  for (const testCase of virtualResourceIntegrationCases) {
    it(testCase.name, async () => {
      //Given a collected organization dataset and a virtual resource request
      const collectClient = await getTestDatasetClient(testCase.data)

      //When simulating with a synthetic or caller-provided resource policy
      const simulation = simulateVirtualResourceRequest(testCase.request, collectClient)

      if (testCase.expectedError) {
        //Then the unsupported request or missing principal should be rejected
        await expect(simulation).rejects.toThrow(new RegExp(testCase.expectedError))
        return
      }

      const response = await simulation

      //Then the expected decision and applicable organization controls are returned
      assertSuccessfulResult(response)
      expect(response.request.resource.accountId).toBe(testCase.request.resourceArn.split(':')[4])
      expect(response.result.overallResult).toBe(testCase.expected)
      assertExpectedAnalysis(response, testCase.expectedAnalysis)
    })
  }

  it("allows the owner account's RCP-denied request through the external resource variant", async () => {
    //Given the request that the owner account's captured RCP denies as a virtual resource
    const collectClient = await getTestDatasetClient('1')
    const request: VirtualResourceSimulationRequest = {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:kms:us-east-1:100000000002:key/virtual-key',
      resourceAccount: '100000000002',
      action: 'kms:DescribeKey',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    //When the same request is simulated as an external resource
    const response = await simulateExternalResourceRequest(request, collectClient)

    //Then no RCP applies and the request is allowed
    assertSuccessfulResult(response)
    expect(response.result.overallResult).toBe('Allowed')
    assertExpectedAnalysis(response, 'rcp-none')
  })
})

/**
 * Assert that a virtual-resource integration response completed policy evaluation.
 *
 * @param response simulation response to narrow
 */
function assertSuccessfulResult(
  response: SimulateRequestResult
): asserts response is SimulateRequestResult & {
  result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
} {
  if (response.result.resultType === 'error') {
    assert.fail(`Simulation error: ${JSON.stringify(response.result.errors)}`)
  }
}

/**
 * Assert the policy analysis that makes a virtual-resource scenario meaningful.
 *
 * @param response successful simulation response
 * @param expectedAnalysis policy analysis expected for the scenario
 */
function assertExpectedAnalysis(
  response: SimulateRequestResult & {
    result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
  },
  expectedAnalysis: VirtualResourceIntegrationCase['expectedAnalysis']
): void {
  if (!expectedAnalysis) {
    return
  }
  if (response.result.resultType !== 'single') {
    assert.fail(`Expected single result, got ${response.result.resultType}`)
  }
  const analysis = response.result.result.analysis
  if (expectedAnalysis === 'rcp-deny') {
    expect(analysis.rcpAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'scp-deny') {
    expect(analysis.scpAnalysis?.result).toBe('ExplicitlyDenied')
  } else {
    expect(analysis.rcpAnalysis?.ouAnalysis ?? []).toEqual([])
  }
}
