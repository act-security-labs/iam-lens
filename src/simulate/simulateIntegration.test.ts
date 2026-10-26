import {
  EvaluationResult,
  type RequestAnalysis,
  RunSimulationResults
} from '@actsecurity/iam-simulate'
import { describe, expect, it } from 'vitest'
import { type IamCollectClient } from '../collect/client.js'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import {
  simulateExternalPrincipalRequest,
  simulateRequest,
  simulateVirtualPrincipal,
  SimulationRequest
} from './simulate.js'

type IntegrationSimulationVariant = 'normal' | 'externalPrincipal' | 'virtualPrincipal'

const simulateIntegrationTest: {
  only?: true
  name: string
  comment?: string

  data: string
  variant?: IntegrationSimulationVariant
  request: SimulationRequest

  expected: EvaluationResult
  expectedError?: string
  expectedConditions?: RequestAnalysis['conditions']
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
    name: 'AWS-managed KMS key ignores an otherwise applicable RCP deny',
    data: '2',
    request: {
      resourceArn: 'arn:aws:kms:us-east-1:400000000002:key/test-key-aws-managed',
      resourceAccount: undefined,
      action: 'kms:Decrypt',
      principal: 'arn:aws:iam::400000000002:role/kms-user',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'kms:RetireGrant ignores an otherwise applicable RCP deny',
    data: '2',
    request: {
      resourceArn: 'arn:aws:kms:us-east-1:400000000002:key/test-key-retire-grant',
      resourceAccount: undefined,
      action: 'kms:RetireGrant',
      principal: 'arn:aws:iam::400000000002:role/kms-user',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'service principal assuming a service-linked role ignores an otherwise applicable RCP deny',
    data: '3',
    request: {
      resourceArn:
        'arn:aws:iam::400000000002:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample',
      resourceAccount: undefined,
      action: 'sts:AssumeRole',
      principal: 'example.amazonaws.com',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
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
    name: 'vpc condition ignored in Discovery mode without a context-key constraint',
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
    name: 'fully-known Discovery constraint causes vpc condition to be evaluated and deny access',
    comment:
      'Same request as above, but with aws:SourceVpc marked fully known. The condition is enforced: no value is present, so it fails and the Allow does not apply.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {},
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 'aws:SourceVpc', presenceIsKnown: true, valueIsKnown: true }
      ]
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'caller known-value constraint preserves a mismatching custom context value',
    comment:
      'The caller marks an alternate-case SourceVpc key as fully known, so the mismatching custom value remains authoritative and the conditional Allow does not apply.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: { 'aws:SourceVpc': 'vpc-not-allowed' },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 'AWS:sourcevpc', presenceIsKnown: true, valueIsKnown: true }
      ]
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'caller unknown-value constraint overrides a known custom context value',
    comment:
      'The caller keeps SourceVpc presence known but declares its mismatching custom value non-authoritative, so Discovery returns the conditional Allow.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: { 'aws:SourceVpc': 'vpc-not-allowed' },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 'AWS:sourcevpc', presenceIsKnown: true, valueIsKnown: false }
      ]
    },
    expected: 'Allowed'
  },
  {
    name: 'caller unknown-presence constraint overrides a known custom context value',
    comment:
      'The caller declares both SourceVpc presence and value non-authoritative, so Discovery returns the conditional Allow despite the mismatching custom value.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::vpc-bucket',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: { 'aws:SourceVpc': 'vpc-not-allowed' },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 'AWS:sourcevpc', presenceIsKnown: false, valueIsKnown: false }
      ]
    },
    expected: 'Allowed'
  },
  {
    name: 'caller can model a present s3:authType with an unknown value',
    comment:
      'The placeholder custom values establish both keys as present. The caller marks only authType non-authoritative, so its nonmatching condition remains a conditional Allow while the TLS condition is denied.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::context-key-bucket',
      resourceAccount: '200000000002',
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {
        's3:authType': 'placeholder-auth-type',
        's3:TlsVersion': '1.1'
      },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 's3:authType', presenceIsKnown: true, valueIsKnown: false }
      ]
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 's3:authType',
      values: ['REST-HEADER'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: 'arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket',
          policyType: 'identity',
          statementIndex: 2
        }
      ]
    }
  },
  {
    name: 'caller can model a present s3:TlsVersion with an unknown value',
    comment:
      'The placeholder custom values establish both keys as present. The caller marks only TlsVersion non-authoritative, so its nonmatching condition remains a conditional Allow while the authType condition is denied.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::context-key-bucket',
      resourceAccount: '200000000002',
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: {
        's3:authType': 'placeholder-auth-type',
        's3:TlsVersion': '1.1'
      },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 's3:TlsVersion', presenceIsKnown: true, valueIsKnown: false }
      ]
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'NumericGreaterThanEquals',
      key: 's3:TlsVersion',
      values: ['1.2'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: 'arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket',
          policyType: 'identity',
          statementIndex: 3
        }
      ]
    }
  },
  {
    name: 'known presence allows a Null false condition when authType value is unknown',
    comment:
      'The custom placeholder establishes authType presence while the caller marks its value unknown. Null false only depends on presence, so the Allow applies without a conditional result.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::context-key-present-bucket',
      resourceAccount: '200000000002',
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: { 's3:authType': 'placeholder-auth-type' },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 's3:authType', presenceIsKnown: true, valueIsKnown: false }
      ]
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'known presence rejects a Null true condition when TlsVersion value is unknown',
    comment:
      'The custom placeholder establishes TlsVersion presence while the caller marks its value unknown. Null true only depends on absence, so the Allow does not apply.',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::context-key-absent-bucket',
      resourceAccount: '200000000002',
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
      customContextKeys: { 's3:TlsVersion': '1.1' },
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 's3:TlsVersion', presenceIsKnown: true, valueIsKnown: false }
      ]
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
  },
  {
    name: 'Discovery treats a matching stored tag as strict without TagSession',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/static-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Discovery treats a matching stored tag as conditional with unrestricted TagSession',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/dynamic-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/Department',
      values: ['Engineering'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: undefined,
          policyType: 'resource',
          statementId: 'AllowEngineeringDepartment',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Discovery keeps a stored tag strict when a finite allowlist excludes it',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/limited-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Discovery makes a stored tag conditional when unioned finite allowlists include it',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/union-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/Department',
      values: ['Engineering'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: undefined,
          policyType: 'resource',
          statementId: 'AllowEngineeringDepartment',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Discovery treats an absent tag as authoritatively absent without TagSession',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/absent-static-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery treats an absent tag as conditional with unrestricted TagSession',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/absent-dynamic-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/Department',
      values: ['Engineering'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: undefined,
          policyType: 'resource',
          statementId: 'AllowEngineeringDepartment',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Discovery treats an absent tag as conditional when a finite allowlist includes it',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/absent-allowlisted-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/Department',
      values: ['Engineering'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: undefined,
          policyType: 'resource',
          statementId: 'AllowEngineeringDepartment',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Discovery treats an absent tag as strict when a finite allowlist excludes it',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/absent-excluded-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery can satisfy a nonmatching stored tag through a mutable session tag',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/mismatched-dynamic-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/Department',
      values: ['Engineering'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: undefined,
          policyType: 'resource',
          statementId: 'AllowEngineeringDepartment',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Discovery denies a nonmatching stored tag when it is immutable',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/mismatched-static-tag-role',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery keeps collected IAM user tags strict',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:user/tagged-user',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies an IAM user with a nonmatching stored tag',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:user/mismatched-tag-user',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies an IAM user with a missing tag',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:user/untagged-user',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery uses the canonical role trust policy for an assumed-role session',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:sts::600000000001:assumed-role/dynamic-tag-role/integration-test',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'aws:PrincipalTag/Department',
      values: ['Engineering'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: undefined,
          policyType: 'resource',
          statementId: 'AllowEngineeringDepartment',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Strict mode uses a matching stored tag even when sessions may override it',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/dynamic-tag-role',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'root principal can use a same-account KMS key whose key policy delegates to its account',
    data: '2',
    request: {
      resourceArn: 'arn:aws:kms:us-east-1:400000000002:key/test-key-account-root',
      resourceAccount: undefined,
      action: 'kms:Decrypt',
      principal: 'arn:aws:iam::400000000002:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'root principal cannot assume a same-account role even when the trust policy allows its account',
    data: '2',
    request: {
      resourceArn: 'arn:aws:iam::400000000002:role/account-root-trust-target',
      resourceAccount: undefined,
      action: 'sts:AssumeRole',
      principal: 'arn:aws:iam::400000000002:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'root principal cannot assume a cross-account role even when the trust policy allows its account',
    data: '2',
    request: {
      resourceArn: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
      resourceAccount: undefined,
      action: 'sts:AssumeRole',
      principal: 'arn:aws:iam::400000000001:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'external root principal can use a KMS key that allows its account',
    data: '2',
    variant: 'externalPrincipal',
    request: {
      resourceArn: 'arn:aws:kms:us-east-1:400000000002:key/test-key-account-root',
      resourceAccount: undefined,
      action: 'kms:Decrypt',
      principal: 'arn:aws:iam::400000000002:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'external root principal cannot assume a role even when its trust policy allows the account',
    data: '2',
    variant: 'externalPrincipal',
    request: {
      resourceArn: 'arn:aws:iam::400000000002:role/account-root-trust-target',
      resourceAccount: undefined,
      action: 'sts:AssumeRole',
      principal: 'arn:aws:iam::400000000002:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'virtual root principal can use a KMS key that allows its account',
    data: '2',
    variant: 'virtualPrincipal',
    request: {
      resourceArn: 'arn:aws:kms:us-east-1:400000000002:key/test-key-account-root',
      resourceAccount: undefined,
      action: 'kms:Decrypt',
      principal: 'arn:aws:iam::400000000002:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'virtual root principal cannot assume a role even when its trust policy allows the account',
    data: '2',
    variant: 'virtualPrincipal',
    request: {
      resourceArn: 'arn:aws:iam::400000000002:role/account-root-trust-target',
      resourceAccount: undefined,
      action: 'sts:AssumeRole',
      principal: 'arn:aws:iam::400000000002:root',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Strict mode denies an absent tag even when a session could supply it',
    data: '3',
    request: {
      resourceArn: 'arn:aws:s3:::conditional-bucket/report.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal: 'arn:aws:iam::600000000001:role/absent-dynamic-tag-role',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode allows a secret whose secretsmanager:ResourceTag/env is dev',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:dev-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Discovery allows a secret whose secretsmanager:ResourceTag/env is dev',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:dev-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode denies a secret whose secretsmanager:ResourceTag/env is prod',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:prod-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies a secret whose secretsmanager:ResourceTag/env is prod',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:prod-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode denies an untagged secret on secretsmanager:ResourceTag/env',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:untagged-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies an untagged secret on secretsmanager:ResourceTag/env',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:untagged-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery makes secretsmanager:ResourceTag/env conditional for an uncollected secret',
    comment: 'The dataset does not collect this secret, so its tags are unknown.',
    data: '3',
    request: {
      resourceArn: 'arn:aws:secretsmanager:us-east-1:400000000002:secret:new-db-AbCdEf',
      resourceAccount: undefined,
      action: 'secretsmanager:DescribeSecret',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'secretsmanager:ResourceTag/env',
      values: ['dev'],
      inverted: true,
      sources: [
        {
          effect: 'Deny',
          policyIdentifier:
            'arn:aws:organizations::400000000001:policy/o-44444444/service_control_policy/p-servicetagkeys',
          policyType: 'scp',
          orgIdentifier: '400000000002',
          statementId: 'DescribeOnlyDevSecrets',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Strict mode allows an instance whose ec2:ResourceTag/env is dev',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0de00000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Discovery allows an instance whose ec2:ResourceTag/env is dev',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0de00000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode denies an instance whose ec2:ResourceTag/env is prod',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0b0d0000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies an instance whose ec2:ResourceTag/env is prod',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0b0d0000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode denies an untagged instance on ec2:ResourceTag/env',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0aa00000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies an untagged instance on ec2:ResourceTag/env',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0aa00000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ImplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery makes ec2:ResourceTag/env conditional for an uncollected instance',
    comment: 'The dataset does not collect this instance, so its tags are unknown.',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:400000000002:instance/i-0ff00000000000000',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'ec2:ResourceTag/env',
      values: ['dev'],
      sources: [
        {
          effect: 'Allow',
          policyIdentifier: 'arn:aws:iam::400000000002:user/operator#Operator',
          policyType: 'identity',
          statementIndex: 1
        }
      ]
    }
  },
  {
    name: 'Strict mode allows a parameter whose ssm:resourceTag/env is dev',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/dev/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Discovery allows a parameter whose ssm:resourceTag/env is dev',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/dev/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode denies a parameter whose ssm:resourceTag/env is prod',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/prod/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies a parameter whose ssm:resourceTag/env is prod',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/prod/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Strict mode denies an untagged parameter on ssm:resourceTag/env',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/untagged/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery denies an untagged parameter on ssm:resourceTag/env',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/untagged/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'ExplicitlyDenied',
    expectedConditions: undefined
  },
  {
    name: 'Discovery makes ssm:resourceTag/env conditional for an uncollected parameter',
    comment: 'The dataset does not collect this parameter, so its tags are unknown.',
    data: '3',
    request: {
      resourceArn: 'arn:aws:ssm:us-east-1:400000000002:parameter/new/db-host',
      resourceAccount: undefined,
      action: 'ssm:GetParameter',
      principal: 'arn:aws:iam::400000000002:user/operator',
      customContextKeys: {},
      simulationMode: 'Discovery'
    },
    expected: 'Allowed',
    expectedConditions: {
      conditionType: 'condition',
      op: 'StringEquals',
      key: 'ssm:resourceTag/env',
      values: ['dev'],
      inverted: true,
      sources: [
        {
          effect: 'Deny',
          policyIdentifier:
            'arn:aws:organizations::400000000001:policy/o-44444444/service_control_policy/p-servicetagkeys',
          policyType: 'scp',
          orgIdentifier: '400000000002',
          statementId: 'ReadOnlyDevParameters',
          statementIndex: 2
        }
      ]
    }
  }
]

/**
 * Execute the selected public simulation entry point with a shared integration-test request.
 *
 * @param variant the public iam-lens simulation variant to run
 * @param request the request common to every tested variant
 * @param collectClient the dataset-backed IAM collection client
 * @returns the normalized simulation request and result
 */
async function runIntegrationSimulation(
  variant: IntegrationSimulationVariant,
  request: SimulationRequest,
  collectClient: IamCollectClient
) {
  switch (variant) {
    case 'externalPrincipal': {
      return simulateExternalPrincipalRequest(request, collectClient)
    }
    case 'virtualPrincipal': {
      return simulateVirtualPrincipal(request, collectClient)
    }
    case 'normal': {
      return simulateRequest(request, collectClient)
    }
  }
}

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
        await expect(
          runIntegrationSimulation(test.variant ?? 'normal', request, collectClient)
        ).rejects.toThrow(new RegExp('/' + test.expectedError + '/'))
      } else {
        // When we run the simulation
        const { result } = await runIntegrationSimulation(
          test.variant ?? 'normal',
          request,
          collectClient
        )

        // Then the result should not have errors
        assertSuccessfulResult(result)

        // And the result should match the expected result
        if (result.overallResult !== expected) {
          console.log(JSON.stringify(getRcpAnalysisForLogging(result), null, 2))
        }
        expect(result.overallResult).toEqual(test.expected)

        if (Object.hasOwn(test, 'expectedConditions')) {
          if (result.resultType !== 'single') {
            throw new Error(`Expected a single simulation result, received ${result.resultType}`)
          }
          expect(result.result.analysis.conditions).toEqual(test.expectedConditions)
        }
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

  it('should throw an error if the removed ignoreMissingPrincipal option is true', async () => {
    //Given a request with a non-existent principal and the removed legacy option
    const collectClient = await getTestDatasetClient('1')
    const request: SimulationRequest & { ignoreMissingPrincipal: boolean } = {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::100000000002:role/NonExistentRole',
      customContextKeys: {},
      simulationMode: 'Strict',
      ignoreMissingPrincipal: true
    }

    //When running the simulation with the legacy runtime property
    const simulation = simulateRequest(request, collectClient)

    //Then the missing principal should still be rejected
    await expect(simulation).rejects.toThrow(
      new RegExp('Principal arn:aws:iam::100000000002:role/NonExistentRole does not exist.*')
    )
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
