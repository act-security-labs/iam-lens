import type { EvaluationResult } from '@actsecurity/iam-simulate'
import { assert, describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import {
  simulateExternalResourceRequest,
  type ExternalResourceSimulationRequest,
  type SimulateRequestResult
} from './simulate.js'

/**
 * A dataset-backed external-resource authorization scenario.
 */
interface ExternalResourceIntegrationCase {
  /**
   * Human-readable behavior under test.
   */
  name: string

  /**
   * Sanitized collected dataset identifier.
   */
  data: string

  /**
   * External-resource request to simulate.
   */
  request: ExternalResourceSimulationRequest

  /**
   * Expected final authorization decision.
   */
  expected?: EvaluationResult

  /**
   * Expected error pattern for an unsupported request or missing collected principal.
   */
  expectedError?: string

  /**
   * Expected normalized resource account.
   */
  expectedResourceAccount?: string

  /**
   * Optional policy analysis that must explain the result.
   */
  expectedAnalysis?:
    | 'identity-deny'
    | 'identity-implicit-deny'
    | 'permission-boundary'
    | 'resource-deny'
    | 'resource-implicit-deny'
    | 'scp'
    | 'session-deny'
    | 'session-policy'
    | 'trust-policy'
}

const externalResourceIntegrationCases: ExternalResourceIntegrationCase[] = [
  {
    name: 'allows access to an uncollected resource with the synthetic resource policy',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'implicitly denies cross-account access when the identity does not allow the action',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:PutObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied',
    expectedAnalysis: 'identity-implicit-deny'
  },
  {
    name: 'still applies a collected permission boundary',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000002:role/EC2Admin',
      resourceArn: 'arn:aws:ec2:us-east-1:999999999999:instance/i-external',
      resourceAccount: '999999999999',
      action: 'ec2:TerminateInstances',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied',
    expectedAnalysis: 'permission-boundary'
  },
  {
    name: 'still applies a supplied session policy',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: { Effect: 'Allow', Action: 'ec2:*', Resource: '*' }
      }
    },
    expected: 'ImplicitlyDenied',
    expectedAnalysis: 'session-policy'
  },
  {
    name: 'still applies an explicit session policy deny',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
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
    name: 'still applies an explicit identity policy deny',
    data: '1',
    request: {
      principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole',
      resourceArn: 'arn:aws:s3:::wildcard-bucket/reports/private/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'identity-deny'
  },
  {
    name: 'still applies a collected SCP deny',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:s3:::external-bucket',
      resourceAccount: '999999999999',
      action: 's3:PutBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'scp'
  },
  {
    name: 'does not load RCPs for a resource account outside the dataset',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:s3:::external-bucket',
      resourceAccount: '999999999999',
      action: 's3:GetBucketPolicy',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'uses a caller-supplied resource policy allow',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::external-bucket/*'
        }
      }
    },
    expected: 'Allowed'
  },
  {
    name: 'implicitly denies when a supplied resource policy does not match the principal',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::888888888888:role/OtherRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::external-bucket/*'
        }
      }
    },
    expected: 'ImplicitlyDenied',
    expectedAnalysis: 'resource-implicit-deny'
  },
  {
    name: 'uses a caller-supplied resource policy explicit deny',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::external-bucket/*'
        }
      }
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'resource-deny'
  },
  {
    name: 'infers the external account from an external role ARN',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:iam::999999999999:role/ExternalRole',
      resourceAccount: undefined,
      action: 'sts:AssumeRole',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedAnalysis: 'trust-policy',
    expectedResourceAccount: '999999999999'
  },
  {
    name: 'uses a caller-supplied trust policy explicit deny without a Resource field',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:iam::999999999999:role/ExternalRole',
      resourceAccount: '999999999999',
      action: 'sts:AssumeRole',
      customContextKeys: {},
      simulationMode: 'Strict',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Deny',
          Principal: '*',
          Action: 'sts:AssumeRole'
        }
      }
    },
    expected: 'ExplicitlyDenied',
    expectedAnalysis: 'resource-deny'
  },
  {
    name: 'rejects wildcard-only actions',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      customContextKeys: {},
      simulationMode: 'Strict'
    } as unknown as ExternalResourceSimulationRequest,
    expectedError: 'External resource simulations do not support wildcard-only actions'
  },
  {
    name: 'rejects a non-wildcard request without a concrete resource ARN',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: undefined,
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    } as unknown as ExternalResourceSimulationRequest,
    expectedError: 'External resource simulations require a concrete resource ARN'
  },
  {
    name: 'rejects a principal that is not present in the collected dataset',
    data: '2',
    request: {
      principal: 'arn:aws:iam::999999999999:role/ExternalAdministrator',
      resourceArn: 'arn:aws:s3:::external-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expectedError: 'Principal arn:aws:iam::999999999999:role/ExternalAdministrator does not exist'
  },
  {
    name: 'still applies a VPC endpoint policy selected by caller context',
    data: '1',
    request: {
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      resourceArn: 'arn:aws:s3:::external-bucket',
      resourceAccount: '999999999999',
      action: 's3:GetBucketPolicy',
      customContextKeys: { 'aws:SourceVpce': 'vpce-00000000002' },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'defaults S3 Block Public Access off for a resource account outside the dataset',
    data: '2',
    request: {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:s3:::external-bpa-bucket/report.txt',
      resourceAccount: '999999999999',
      action: 's3:GetObject',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'honors an enabled S3 ABAC override with caller-provided resource tags',
    data: '1',
    request: {
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      resourceArn: 'arn:aws:s3:::external-finance-bucket',
      resourceAccount: '999999999999',
      action: 's3:GetBucketPolicy',
      customContextKeys: { 'aws:ResourceTag/Dept': 'Finance' },
      simulationMode: 'Strict',
      s3AbacOverride: 'enabled'
    },
    expected: 'Allowed'
  },
  {
    name: 'honors a disabled S3 ABAC override with caller-provided resource tags',
    data: '1',
    request: {
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      resourceArn: 'arn:aws:s3:::external-finance-bucket',
      resourceAccount: '999999999999',
      action: 's3:GetBucketPolicy',
      customContextKeys: { 'aws:ResourceTag/Dept': 'Finance' },
      simulationMode: 'Strict',
      s3AbacOverride: 'disabled'
    },
    expected: 'ImplicitlyDenied'
  }
]

describe('simulateExternalResourceRequest integration', () => {
  for (const testCase of externalResourceIntegrationCases) {
    it(testCase.name, async () => {
      //Given a collected principal dataset and an external resource request
      const collectClient = await getTestDatasetClient(testCase.data)

      //When simulating the request without collected resource-side data
      const simulation = simulateExternalResourceRequest(testCase.request, collectClient)

      if (testCase.expectedError) {
        //Then the unsupported request or missing principal should be rejected
        await expect(simulation).rejects.toThrow(new RegExp(testCase.expectedError))
        return
      }

      const response = await simulation

      //Then the expected decision and relevant policy analysis should be returned
      assertSuccessfulResult(response)
      expect(response.result.overallResult).toBe(testCase.expected)
      if (testCase.expectedResourceAccount) {
        expect(response.request.resource.accountId).toBe(testCase.expectedResourceAccount)
      }
      assertExpectedAnalysis(response, testCase.expectedAnalysis)
    })
  }

  it('should validate an STS policy as a trust policy', async () => {
    //Given an external role request with an invalid trust policy that has no Principal
    const collectClient = await getTestDatasetClient('2')
    const request: ExternalResourceSimulationRequest = {
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      resourceArn: 'arn:aws:iam::999999999999:role/ExternalRole',
      resourceAccount: '999999999999',
      action: 'sts:AssumeRole',
      customContextKeys: {},
      simulationMode: 'Strict',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: { Effect: 'Allow', Action: 'sts:AssumeRole' }
      }
    }

    //When simulating with the caller-supplied policy
    const response = await simulateExternalResourceRequest(request, collectClient)

    //Then iam-simulate should return trust-policy-specific validation diagnostics
    expect(response.result).toEqual({
      resultType: 'error',
      errors: {
        message: 'policy.errors',
        resourcePolicyErrors: [
          {
            path: 'Statement',
            message: 'One of Principal or NotPrincipal is required in a trust policy'
          }
        ]
      }
    })
  })
})

/**
 * Assert that an external-resource integration response completed policy evaluation.
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
 * Assert the policy analysis that makes an integration scenario meaningful.
 *
 * @param response successful simulation response
 * @param expectedAnalysis policy analysis expected for the request
 */
function assertExpectedAnalysis(
  response: SimulateRequestResult & {
    result: Exclude<SimulateRequestResult['result'], { resultType: 'error' }>
  },
  expectedAnalysis: ExternalResourceIntegrationCase['expectedAnalysis']
): void {
  if (!expectedAnalysis) {
    return
  }
  if (response.result.resultType !== 'single') {
    assert.fail(`Expected single result, got ${response.result.resultType}`)
  }
  const analysis = response.result.result.analysis
  if (expectedAnalysis === 'identity-deny') {
    expect(analysis.identityAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'identity-implicit-deny') {
    expect(analysis.identityAnalysis?.result).toBe('ImplicitlyDenied')
  } else if (expectedAnalysis === 'permission-boundary') {
    expect(analysis.permissionBoundaryAnalysis?.result).toBe('ImplicitlyDenied')
  } else if (expectedAnalysis === 'scp') {
    expect(analysis.scpAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'session-policy') {
    expect(analysis.sessionAnalysis?.result).toBe('ImplicitlyDenied')
  } else if (expectedAnalysis === 'session-deny') {
    expect(analysis.sessionAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'resource-deny') {
    expect(analysis.resourceAnalysis?.result).toBe('ExplicitlyDenied')
  } else if (expectedAnalysis === 'resource-implicit-deny') {
    expect(analysis.resourceAnalysis?.result).toBe('ImplicitlyDenied')
  } else {
    expect(analysis.resourceAnalysis?.result).toBe('Allowed')
  }
}
