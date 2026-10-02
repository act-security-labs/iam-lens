import { EvaluationResult, RunSimulationResults } from '@actsecurity/iam-simulate'
import { describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import { simulateRequest, SimulationRequest } from './simulate.js'

const simulateIntegrationTest: {
  only?: true
  name: string
  comment?: string

  data: string
  request: SimulationRequest

  expected: EvaluationResult
  expectedError?: string
}[] = [
  {
    name: 'same account resource request with resource policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'same account resource request implicitly denied by session policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Allow',
          Action: 'ec2:*',
          Resource: '*'
        }
      }
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'same account resource request explicitly denied by session policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: '*',
            Resource: '*'
          },
          {
            Effect: 'Deny',
            Action: 's3:*',
            Resource: '*'
          }
        ]
      }
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'cross account allowed only by resource policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal:
        'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'request blocked by SCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:PutBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'request blocked by RCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::restricted-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Wildcard blocked by SCP',
    data: '1',
    request: {
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      principal: 'arn:aws:iam::100000000002:user/user1',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Wildcard blocked by RCP',
    data: '1',
    request: {
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      principal: 'arn:aws:iam::100000000002:user/user2',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Implicit deny by Permission Boundary',
    data: '1',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:100000000002:instance/i-1234567890abcdef0',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::100000000002:role/EC2Admin',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Cross org request allowed',
    comment: "This uses a user in the root account, so SCPs don't apply",
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal:
        'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'Cross org blocked by SCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:user/user1',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Cross org blocked by RCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734/data.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal:
        'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Delete AWS Managed Policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
      resourceAccount: '200000000001',
      action: 'iam:DeletePolicy',
      principal:
        'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpc allowed',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-00000000001'
      },
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'Get VPCE from aws:SourceVpc ExplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-00000000002'
      },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpc ImplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-00000000003'
      },
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpce Allowed',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpce': 'vpce-00000000001'
      },
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'Get VPCE from aws:SourceVpce ExplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpce': 'vpce-00000000002'
      },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpce ImplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpce': 'vpce-00000000003'
      },
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Get S3 Object with bucket policy allowing access',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::who-can-principal/an-object.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal:
        'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'vpc condition ignored in Discovery mode without additionalStrictContextKeys',
    comment:
      'VpcBucketRole has an Allow for s3:ListBucket conditioned on aws:SourceVpc. In Discovery mode the condition key is not in knownContextKeys, so it is ignored and the Allow applies.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'additionalStrictContextKeys causes vpc condition to be evaluated and deny access',
    comment:
      'Same request as above, but with aws:SourceVpc added to additionalStrictContextKeys. Now the condition is enforced: no value is present, so it fails and the Allow does not apply.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {},
      simulationMode: 'Discovery',
      additionalStrictContextKeys: ['aws:SourceVpc']
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'resource policy Deny with aws:SourceArn treats presence as known and value as unknown',
    comment:
      'The role has an identity Allow for s3:PutObject, but the bucket policy has a Deny gated by ArnNotEquals aws:SourceArn. SourceArn is absent for an IAM principal request, so the negated condition matches and the explicit Deny applies.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::source-arn-deny-bucket/object.txt',
      resourceAccount: undefined,
      action: 's3:PutObject',
      principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'service principal can write when aws:SourceArn is present with an unknown value',
    comment:
      'The bucket policy allows CloudTrail to write for a matching SourceArn and denies writes for a nonmatching SourceArn. In Discovery mode a service request has a present SourceArn whose exact value is unknown, so the possible Allow matches while the negated Deny cannot definitively apply. No custom context is required.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::source-arn-deny-bucket/object.txt',
      resourceAccount: undefined,
      action: 's3:PutObject',
      principal: 'cloudtrail.amazonaws.com',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'caller-provided matching SourceArn is authoritative in Discovery mode',
    comment:
      'An explicit matching SourceArn must be evaluated exactly rather than as the service-principal placeholder value.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::source-arn-deny-bucket/object.txt',
      resourceAccount: undefined,
      action: 's3:PutObject',
      principal: 'cloudtrail.amazonaws.com',
      customContextKeys: {
        'aws:SourceArn': 'arn:aws:cloudtrail:us-east-1:200000000002:trail/example'
      },
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'caller-provided nonmatching SourceArn is authoritative in Discovery mode',
    comment:
      'An explicit nonmatching SourceArn must trigger the bucket policy Deny rather than remain conditionally allowed.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::source-arn-deny-bucket/object.txt',
      resourceAccount: undefined,
      action: 's3:PutObject',
      principal: 'cloudtrail.amazonaws.com',
      customContextKeys: {
        'aws:SourceArn': 'arn:aws:cloudtrail:us-east-1:200000000002:channel/example'
      },
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'caller-provided matching SourceVpc is authoritative in Discovery mode',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-123456789'
      },
      simulationMode: 'Discovery'
    },
    expected: 'Allowed'
  },
  {
    name: 'alternate-case caller-provided nonmatching SourceVpc is authoritative in Discovery mode',
    comment:
      'IAM context key matching is case-insensitive, so this custom value must replace derived context and make the Allow fail.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {
        'AWS:sourceVpc': 'vpc-other'
      },
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'resource policy Allow without Principal does not allow cross-account access',
    comment:
      'The Allow statement on no-principal-bucket has no Principal element. Cross-account access requires both identity and resource policy allows; with the Allow silent, the request is ImplicitlyDenied.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::no-principal-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'resource policy Deny without Principal does not deny same-account access',
    comment:
      'The Deny statement on no-principal-bucket has no Principal element. The SSO admin on account 100000000002 has *:* via AdministratorAccess; the Deny must not fire because its principal element is absent.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::no-principal-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'sibling statement in no-Principal resource policy still matches',
    comment:
      'IAMCollect has no s3:ListBucket in identity and no permission boundary; the sole grant for s3:ListBucket on no-principal-bucket is the third (sibling) statement in the bucket policy that names IAMCollect explicitly.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::no-principal-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::100000000002:role/IAMCollect',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  }
]

describe('simulateIntegrationTest', () => {
  for (const test of simulateIntegrationTest) {
    const { name, only, data, request, expected } = test
    const testFn = only ? it.only : it

    testFn(name, async () => {
      // Given a client
      const collectClient = await getTestDatasetClient(test.data)

      if (test.expectedError) {
        //If an error is expected
        // Then it should match the expected error
        await expect(simulateRequest(request, collectClient)).rejects.toThrow(
          new RegExp('/' + test.expectedError + '/')
        )
      } else {
        // When we run the simulation
        const { result } = await simulateRequest(request, collectClient)

        // Then the result should not have errors
        assertSuccessfulResult(result)

        // And the result should match the expected result
        if (result.overallResult !== expected) {
          console.log(JSON.stringify(getRcpAnalysisForLogging(result), null, 2))
        }
        expect(result.overallResult).toEqual(test.expected)
      }
    })
  }
})

describe('simulatePrincipalDoesNotExist', () => {
  it('should throw an error if the principal does not exist', async () => {
    // Given a request with a non-existent principal
    const collectClient = await getTestDatasetClient('1')
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::100000000002:role/NonExistentRole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    await expect(simulateRequest(request, collectClient)).rejects.toThrow(
      new RegExp('Principal arn:aws:iam::100000000002:role/NonExistentRole does not exist.*')
    )
  })

  it('should not throw an error if ignoreMissingPrincipal is true', async () => {
    // Given a request with a non-existent principal and ignoreMissingPrincipal set to true
    const collectClient = await getTestDatasetClient('1')
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::100000000002:role/NonExistentRole',
      customContextKeys: {},
      simulationMode: 'Strict',
      ignoreMissingPrincipal: true
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)
  })
})

describe('s3 ABAC', () => {
  it('strict mode should not allow ABAC access when ABAC is not enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with matching tags but ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (ABAC conditions are not evaluated when ABAC is not enabled)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  it('strict mode should allow ABAC access when ABAC is enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with matching tags and ABAC enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be Allowed (ABAC conditions match)
    expect(result.overallResult).toEqual('Allowed')
  })

  it('strict mode should not allow ABAC access when ABAC is not enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags and ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (no matching policy)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  it('strict mode should not allow ABAC access when ABAC is enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags even though ABAC is enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (tags don't match the condition)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  ///
  it('discovery mode should not allow ABAC access when ABAC is not enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with matching tags but ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (ABAC conditions are not evaluated when ABAC is not enabled)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  it('discovery mode should not allow ABAC access to a bucket object when ABAC is not enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket object with matching tags but ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket/report.pdf',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (ABAC conditions are not evaluated when ABAC is not enabled)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  it('discovery mode should allow ABAC access to a bucket object when ABAC is enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with matching tags and ABAC enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket-w-abac/report.pdf',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be Allowed (ABAC conditions match)
    expect(result.overallResult).toEqual('Allowed')
  })

  it('discovery mode should allow ABAC access when ABAC is enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with matching tags and ABAC enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be Allowed (ABAC conditions match)
    expect(result.overallResult).toEqual('Allowed')
  })

  it('discovery mode should not allow ABAC access when ABAC is not enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags and ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (no matching policy)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  it('discovery mode should not allow ABAC access when ABAC is enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = await getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags even though ABAC is enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    assertSuccessfulResult(result)

    // And the result should be ImplicitlyDenied (tags don't match the condition)
    expect(result.overallResult).toEqual('ImplicitlyDenied')
  })

  describe('overrides', () => {
    it('strict mode should use ABAC override when ABAC is not enabled on the bucket and tags match', async () => {
      // Given a client with test data
      const collectClient = await getTestDatasetClient('1')

      // And a request to access a bucket with matching tags but ABAC not enabled
      const request: SimulationRequest = {
        resourceArn: 'arn:aws:s3:::finance-bucket',
        resourceAccount: undefined,
        action: 's3:GetBucketPolicy',
        principal: 'arn:aws:iam::200000000002:role/s3abacrole',
        customContextKeys: {},
        simulationMode: 'Strict',
        s3AbacOverride: 'enabled'
      }

      // When we run the simulation
      const { result } = await simulateRequest(request, collectClient)

      // Then the result should not have errors
      assertSuccessfulResult(result)

      // And the result should be Allowed (ABAC override is enabled)
      expect(result.overallResult).toEqual('Allowed')
    })

    it('strict mode should use ABAC override when ABAC is enabled on the bucket and tags match', async () => {
      // Given a client with test data
      const collectClient = await getTestDatasetClient('1')

      // And a request to access a bucket with matching tags and ABAC enabled
      const request: SimulationRequest = {
        resourceArn: 'arn:aws:s3:::finance-bucket-w-abac',
        resourceAccount: undefined,
        action: 's3:GetBucketPolicy',
        principal: 'arn:aws:iam::200000000002:role/s3abacrole',
        customContextKeys: {},
        simulationMode: 'Strict',
        s3AbacOverride: 'disabled'
      }

      // When we run the simulation
      const { result } = await simulateRequest(request, collectClient)

      // Then the result should not have errors
      assertSuccessfulResult(result)

      // And the result should be ImplicitlyDenied because ABAC is disabled by the override
      expect(result.overallResult).toEqual('ImplicitlyDenied')
    })
  })
})

describe('s3 Block Public Access', () => {
  it('should deny cross-account public bucket access when only bucket-level RestrictPublicBuckets is enabled', async () => {
    // Given a client with a public bucket policy, bucket-level Block Public Access enabled,
    // and account-level Block Public Access disabled
    const collectClient = await getTestDatasetClient('2')

    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::bucket-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should be denied by the effective S3 BPA setting
    assertSuccessfulResult(result)
    expect(result.overallResult).toEqual('ExplicitlyDenied')
  })

  it('should deny cross-account public bucket access when account-level RestrictPublicBuckets is enabled', async () => {
    // Given a client with a public bucket policy and account-level Block Public Access enabled
    const collectClient = await getTestDatasetClient('2')

    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::account-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should be denied by the effective S3 BPA setting
    assertSuccessfulResult(result)
    expect(result.overallResult).toEqual('ExplicitlyDenied')
  })

  it('should allow cross-account public bucket access when RestrictPublicBuckets is disabled', async () => {
    // Given a client with a public bucket policy and Block Public Access disabled
    const collectClient = await getTestDatasetClient('2')

    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::400000000001:role/alpha-role',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should remain allowed without an effective S3 BPA restriction
    assertSuccessfulResult(result)
    expect(result.overallResult).toEqual('Allowed')
  })
})

function assertSuccessfulResult(
  result: RunSimulationResults
): asserts result is Exclude<RunSimulationResults, { resultType: 'error' }> {
  if (result.resultType === 'error') {
    throw new Error(`Simulation error: ${result.errors.message}`)
  }
}

function getRcpAnalysisForLogging(result: RunSimulationResults) {
  if (result.resultType === 'single') {
    return result.result.analysis.rcpAnalysis
  }
  if (result.resultType === 'wildcard') {
    return result.results.map((entry) => entry.analysis.rcpAnalysis)
  }
  return result.errors
}
