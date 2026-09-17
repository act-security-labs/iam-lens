import { assert, beforeAll, describe, expect, it } from 'vitest'
import { makePrincipalIndex } from '../principalIndex/makePrincipalIndex.js'
import { getTestDatasetClient, getTestDatasetConfigs } from '../test-datasets/testClient.js'
import {
  type ResourceAccessRequest,
  whoCan,
  type WhoCanAllowed,
  type WhoCanDenyDetail,
  type WhoCanResponse
} from './whoCan.js'
import { WhoCanProcessor } from './WhoCanProcessor.js'

/**
 * Build the expected iam-simulate source metadata for a resource-policy allow statement.
 *
 * @param statementId the expected statement ID
 * @returns the expected resource-policy source metadata
 */
function resourceAllowSource(statementId: string) {
  return {
    effect: 'Allow',
    policyIdentifier: undefined,
    policyType: 'resource',
    statementId,
    statementIndex: 1
  }
}

/**
 * Build the expected iam-simulate source metadata for an identity-policy allow statement.
 *
 * @param policyIdentifier the expected identity policy identifier
 * @returns the expected identity-policy source metadata
 */
function identityAllowSource(policyIdentifier: string) {
  return {
    effect: 'Allow',
    policyIdentifier,
    policyType: 'identity',
    statementIndex: 1
  }
}

/**
 * Build the expected allowed-condition expression for a required role session name.
 *
 * @param sessionName the expected role session name
 * @param statementId the resource-policy statement requiring the session name
 * @returns the expected session-name condition expression
 */
function sessionNameCondition(sessionName: string, statementId: string) {
  return {
    conditionType: 'sessionName',
    sessionName: [sessionName],
    sources: [resourceAllowSource(statementId)]
  }
}

/**
 * Build the expected allowed-condition expression for a policy condition.
 *
 * @param op the IAM condition operator
 * @param key the IAM condition key
 * @param values the expected condition values
 * @param source the expected source statement metadata
 * @returns the expected policy-condition expression
 */
function conditionExpression(
  op: string,
  key: string,
  values: string[],
  source: ReturnType<typeof resourceAllowSource> | ReturnType<typeof identityAllowSource>
) {
  return {
    conditionType: 'condition',
    op,
    key,
    values,
    sources: [source]
  }
}

/**
 * Build the expected ignored-condition diagnostics for an allow-side condition.
 *
 * @param policyType the policy type that contained the ignored condition
 * @param op the IAM condition operator
 * @param key the IAM condition key
 * @param values the ignored condition values
 * @returns the expected ignored-condition diagnostics
 */
function ignoredAllowCondition(
  policyType: 'identity' | 'resource',
  op: string,
  key: string,
  values: string[]
) {
  return {
    [policyType]: {
      allow: [
        {
          key,
          op,
          values
        }
      ]
    }
  }
}

interface WhoCanIntegrationTest {
  only?: true
  name: string
  description?: string
  comment?: string
  data: string
  request: ResourceAccessRequest
  expected: {
    who: WhoCanAllowed[]
    allAccountsChecked?: true
    accountsNotFound?: string[]
    organizationsNotFound?: string[]
    organizationalUnitsNotFound?: string[]
    principalsNotFound?: string[]
  }
  expectedDenyDetails?: WhoCanDenyDetail[]
  simulationCounts?: {
    withIndex: number
    withoutIndex: number
  }
}

const whoCanIntegrationTests: WhoCanIntegrationTest[] = [
  {
    name: 'within account and no resource policy',
    simulationCounts: { withoutIndex: 3, withIndex: 1 },
    data: '1',
    request: {
      actions: ['ec2:TerminateInstances'],
      resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0'
    },
    expected: {
      who: [
        {
          action: 'TerminateInstances',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 'ec2',
          level: 'write',
          resourceType: 'instance'
        }
      ]
    }
  },
  {
    name: 'within account wildcard action',
    simulationCounts: { withoutIndex: 5, withIndex: 2 },
    data: '1',
    request: {
      resourceAccount: '100000000002',
      actions: ['ec2:DescribeInstances']
    },
    expected: {
      who: [
        {
          action: 'DescribeInstances',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 'ec2',
          level: 'list'
        },
        {
          action: 'DescribeInstances',
          principal: 'arn:aws:iam::100000000002:role/EC2Admin',
          service: 'ec2',
          level: 'list'
        }
      ]
    }
  },
  {
    name: 'within an organization',
    simulationCounts: { withoutIndex: 7, withIndex: 7 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-org',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/DynamoDbRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      organizationsNotFound: ['o-33333333']
    }
  },
  {
    name: 'shared with an account',
    simulationCounts: { withoutIndex: 11, withIndex: 5 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'shared with specific principals',
    simulationCounts: { withoutIndex: 7, withIndex: 5 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-principal',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      principalsNotFound: [
        'arn:aws:iam::999999999999:role/missing-role',
        'arn:aws:sts::999999999999:federated-user/Bob'
      ]
    }
  },
  {
    name: 'same-account session ARN grants access via resource policy only',
    simulationCounts: { withoutIndex: 6, withIndex: 5 },
    description:
      'DynamoDbRole has no S3 identity permissions. It only gets access because the resource policy grants to its session ARN.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-session',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/DynamoDbRole',
          service: 's3',
          resourceType: 'bucket',
          dependsOnSessionName: true,
          conditions: sessionNameCondition('my-session', 'SharingWithSessionArn')
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'session ARN principal with PrincipalArn condition returns role ARN',
    description:
      'Resource policy grants a session ARN principal and constrains aws:PrincipalArn to the attached role ARN. The whoCan result should be the IAM role ARN, not the STS session ARN.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-session-principalarn',
      resourceAccount: '200000000002',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/DynamoDbRole',
          service: 's3',
          resourceType: 'bucket',
          dependsOnSessionName: true,
          conditions: sessionNameCondition(
            'my-session',
            'SharingWithSessionArnAndPrincipalArnCondition'
          )
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'session ARN principal with aws:userid condition surfaces both flags',
    simulationCounts: { withoutIndex: 6, withIndex: 5 },
    description:
      'Resource policy grants via a session ARN principal and has an aws:userid condition. ' +
      'DynamoDbRole has no S3 identity permissions, so access comes entirely from the resource policy. ' +
      'The result should carry dependsOnSessionName and surface the aws:userid condition.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-session-userid',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/DynamoDbRole',
          service: 's3',
          resourceType: 'bucket',
          dependsOnSessionName: true,
          conditions: {
            conditionType: 'group',
            operator: 'and',
            conditions: [
              conditionExpression(
                'StringLike',
                'aws:userid',
                ['*:my-session'],
                resourceAllowSource('SessionWithUserIdCondition')
              ),
              sessionNameCondition('my-session', 'SessionWithUserIdCondition')
            ]
          },
          ignoredConditions: ignoredAllowCondition('resource', 'StringLike', 'aws:userid', [
            '*:my-session'
          ])
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'cross-account session ARN principal converts to role',
    simulationCounts: { withoutIndex: 7, withIndex: 5 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-session-xacct',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          dependsOnSessionName: true,
          conditions: sessionNameCondition('session-abc', 'SharingWithCrossAccountSessionArn')
        }
      ]
    }
  },
  {
    name: 'path-qualified role referenced by pathless session ARN resolves to role ARN',
    description:
      'Resource policy grants a pathless STS assumed-role session ARN. The matching IAM role is stored with an aws-reserved SSO path, and the whoCan result should use that path-qualified role ARN.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-session-pathless',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          dependsOnSessionName: true,
          conditions: sessionNameCondition(
            'session-abc',
            'AllowPathQualifiedRoleSessionWithoutPath'
          )
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      principalsNotFound: []
    }
  },
  {
    name: 'resource policy account and pathless session grants do not duplicate path-qualified role results',
    description:
      'Resource policy grants an account and also names a pathless STS assumed-role session for a path-qualified role in that account. The same resolved role should only be returned once.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-account-and-session',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'S3 object wildcard (prefix)',
    simulationCounts: { withoutIndex: 3, withIndex: 3 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/*',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/*',
              resourceType: 'object'
            },
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/2024/*',
              resourceType: 'object'
            }
          ]
        },
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object wildcard with policy question marks and request wildcard',
    simulationCounts: { withoutIndex: 3, withIndex: 2 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::eu-example-data-lake/db_tables/v5/table/_delta_log/*',
      actions: ['s3:DeleteObject']
    },
    expected: {
      who: [
        {
          action: 'DeleteObject',
          principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
          service: 's3',
          level: 'write',
          allowedPatterns: [
            {
              pattern: 'arn:aws:s3:::??-example-data-lake/db_tables/v5/*/_delta_log/*',
              resourceType: 'object'
            }
          ]
        },
        {
          action: 'DeleteObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'write',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object wildcard (different prefix)',
    simulationCounts: { withoutIndex: 3, withIndex: 3 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/other/*',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object wildcard (explicit deny subset)',
    simulationCounts: { withoutIndex: 3, withIndex: 3 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
      actions: ['s3:GetObject'],
      denyDetailsCallback: (details) => details.overallResult === 'ExplicitlyDenied'
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    },
    expectedDenyDetails: [
      {
        action: 'GetObject',
        deniedResources: [
          {
            details: [
              {
                denialType: 'Explicit',
                policyIdentifier:
                  'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole#S3ObjectWildcardDeny',
                policyType: 'identity',
                statementId: 'DenyPrivate',
                statementIndex: 2
              }
            ],
            pattern: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
            resourceType: 'object'
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole',
        service: 's3',
        type: 'wildcard'
      },
      {
        action: 'GetObject',
        deniedResources: [
          {
            details: [
              {
                denialType: 'Explicit',
                policyIdentifier:
                  'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
                policyType: 'identity',
                statementIndex: 2
              }
            ],
            pattern: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
            resourceType: 'object'
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
        service: 's3',
        type: 'wildcard'
      }
    ]
  },
  {
    name: 'S3 object wildcard (explicit deny subset) with grant details',
    simulationCounts: { withoutIndex: 3, withIndex: 3 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
      actions: ['s3:GetObject'],
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier: 'arn:aws:iam::100000000001:policy/CustomS3Policy',
                  policyType: 'identity',
                  statementId: 'VisualEditor0',
                  statementIndex: 1
                },
                {
                  policyIdentifier: 'arn:aws:iam::aws:policy/AdministratorAccess',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object single resource (explicit deny)',
    simulationCounts: { withoutIndex: 3, withIndex: 3 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/private/report.pdf',
      actions: ['s3:GetObject'],
      denyDetailsCallback: (details) => details.overallResult === 'ExplicitlyDenied'
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        }
      ]
    },
    expectedDenyDetails: [
      {
        action: 'GetObject',
        details: [
          {
            denialType: 'Explicit',
            policyIdentifier:
              'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole#S3ObjectWildcardDeny',
            policyType: 'identity',
            statementId: 'DenyPrivate',
            statementIndex: 2
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole',
        service: 's3',
        type: 'single'
      },
      {
        action: 'GetObject',
        details: [
          {
            denialType: 'Explicit',
            policyIdentifier:
              'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
            policyType: 'identity',
            statementIndex: 2
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
        service: 's3',
        type: 'single'
      }
    ]
  },
  {
    name: 'trust policy with service principal',
    simulationCounts: { withoutIndex: 7, withIndex: 1 },
    data: '1',
    request: {
      resource: 'arn:aws:iam::200000000002:role/LambdaRole',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'service principal with different SourceAccount is conditional access',
    description:
      'Bucket policy names lambda.amazonaws.com and requires aws:SourceAccount from a different account than the bucket. whoCan should keep the service principal and report the SourceAccount condition instead of denying based on the resource-account placeholder value.',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::service-sourceaccount-bucket/example.txt',
      resourceAccount: '400000000002',
      actions: ['s3:PutObject']
    },
    expected: {
      who: [
        {
          action: 'PutObject',
          principal: 'lambda.amazonaws.com',
          service: 's3',
          level: 'write',
          resourceType: 'object',
          conditions: conditionExpression(
            'StringEquals',
            'aws:SourceAccount',
            ['400000000001'],
            resourceAllowSource('AllowLambdaFromDifferentSourceAccount')
          ),
          ignoredConditions: ignoredAllowCondition(
            'resource',
            'StringEquals',
            'aws:SourceAccount',
            ['400000000001']
          )
        }
      ]
    }
  },
  {
    name: 'ListBucket with condition',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          conditions: conditionExpression(
            'StringEquals',
            'aws:SourceVpc',
            ['vpc-123456789'],
            identityAllowSource('arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket')
          ),
          ignoredConditions: ignoredAllowCondition('identity', 'StringEquals', 'aws:SourceVpc', [
            'vpc-123456789'
          ])
        }
      ]
    }
  },
  {
    name: 'ListBucket with condition and no strictContextKeys',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          conditions: conditionExpression(
            'StringEquals',
            'aws:SourceVpc',
            ['vpc-123456789'],
            identityAllowSource('arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket')
          ),
          ignoredConditions: ignoredAllowCondition('identity', 'StringEquals', 'aws:SourceVpc', [
            'vpc-123456789'
          ])
        }
      ]
    }
  },
  {
    name: 'ListBucket with condition and strictContextKeys aws:SourceVpc',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket'],
      strictContextKeys: ['aws:SourceVpc'],
      denyDetailsCallback: (details) => details.overallResult === 'ImplicitlyDenied'
    },
    expected: {
      who: []
    },
    expectedDenyDetails: [
      {
        type: 'single',
        principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
        service: 's3',
        action: 'ListBucket',
        details: [
          {
            denialType: 'Implicit',
            policyType: 'identity'
          },
          {
            denialType: 'Implicit',
            policyType: 'resource'
          }
        ]
      }
    ]
  },
  {
    name: 'ListBucket with tags and ABAC',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    description:
      'This checks against a bucket with tags that has ABAC enabled so the ABAC role should have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::finance-bucket-w-abac',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'ListBucket with tags and ABAC but no matching users',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    description:
      'This checks against a bucket with tags that has ABAC enabled but with different tags, so the ABAC role should not have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::sales-bucket-w-abac',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'ListBucket with public policy and bucket-level S3 BPA enabled',
    description:
      'This checks that bucket-level RestrictPublicBuckets blocks cross-account access granted only by a public bucket policy',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::bucket-bpa-public-bucket/report.txt',
      actions: ['s3:GetObject'],
      principalScope: {
        principals: ['arn:aws:iam::400000000001:role/alpha-role']
      }
    },
    expected: {
      who: []
    }
  },
  {
    name: 'ListBucket with public policy and account-level S3 BPA enabled',
    description:
      'This checks that account-level RestrictPublicBuckets blocks cross-account access granted only by a public bucket policy',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::account-bpa-public-bucket/report.txt',
      actions: ['s3:GetObject'],
      principalScope: {
        principals: ['arn:aws:iam::400000000001:role/alpha-role']
      }
    },
    expected: {
      who: []
    }
  },
  {
    name: 'GetObject with non-public policy and bucket-level S3 BPA enabled',
    description:
      'This checks that bucket-level RestrictPublicBuckets does not block cross-account access granted to a specific principal by a non-public bucket policy',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::bucket-bpa-specific-principal-bucket/report.txt',
      actions: ['s3:GetObject'],
      principalScope: {
        principals: ['arn:aws:iam::400000000001:role/alpha-role']
      }
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          level: 'read',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 's3',
          resourceType: 'object'
        }
      ]
    }
  },
  {
    name: 'GetObject with non-public policy and account-level S3 BPA enabled',
    description:
      'This checks that account-level RestrictPublicBuckets does not block cross-account access granted to a specific principal by a non-public bucket policy',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::account-bpa-specific-principal-bucket/report.txt',
      actions: ['s3:GetObject'],
      principalScope: {
        principals: ['arn:aws:iam::400000000001:role/alpha-role']
      }
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          level: 'read',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 's3',
          resourceType: 'object'
        }
      ]
    }
  },
  {
    name: 'ListBucket with tags and ABAC, override s3Abac to disabled',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    description:
      'This checks against a bucket with tags that has ABAC enabled but the override is set to disabled, so the ABAC role should not have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::finance-bucket-w-abac',
      actions: ['s3:ListBucket'],
      s3AbacOverride: 'disabled'
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'ListBucket with tags and no ABAC, override s3Abac to enabled',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    description:
      'This checks against a bucket with tags that has ABAC disabled, but override is set to enabled, so the ABAC role should have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::finance-bucket',
      actions: ['s3:ListBucket'],
      s3AbacOverride: 'enabled'
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'single resource with grant details',
    simulationCounts: { withoutIndex: 3, withIndex: 1 },
    data: '1',
    request: {
      actions: ['ec2:TerminateInstances'],
      resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0',
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'TerminateInstances',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 'ec2',
          level: 'write',
          resourceType: 'instance',
          details: [
            {
              policyIdentifier: 'arn:aws:iam::aws:policy/AdministratorAccess',
              policyType: 'identity',
              statementIndex: 1
            },
            {
              policyIdentifier:
                'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5#AwsSSOInlinePolicy',
              policyType: 'identity',
              statementId: 'Statement1',
              statementIndex: 1
            }
          ]
        }
      ]
    }
  },
  {
    name: 'single resource with grant details (s3 list bucket)',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket'],
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          conditions: conditionExpression(
            'StringEquals',
            'aws:SourceVpc',
            ['vpc-123456789'],
            identityAllowSource('arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket')
          ),
          ignoredConditions: ignoredAllowCondition('identity', 'StringEquals', 'aws:SourceVpc', [
            'vpc-123456789'
          ]),
          details: [
            {
              policyIdentifier: 'arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket',
              policyType: 'identity',
              statementIndex: 1
            },
            {
              orgIdentifier: 'r-dh2e',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
              policyType: 'rcp',
              statementIndex: 1
            },
            {
              orgIdentifier: 'ou-dh2e-aps19rip',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
              policyType: 'rcp',
              statementIndex: 1
            },
            {
              orgIdentifier: '200000000002',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
              policyType: 'rcp',
              statementIndex: 1
            },
            {
              orgIdentifier: 'r-dh2e',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policyType: 'scp',
              statementIndex: 1
            },
            {
              orgIdentifier: 'ou-dh2e-aps19rip',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policyType: 'scp',
              statementIndex: 1
            },
            {
              orgIdentifier: '200000000002',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policyType: 'scp',
              statementIndex: 1
            }
          ]
        }
      ]
    }
  },
  {
    name: 'wildcard resource with grant details',
    simulationCounts: { withoutIndex: 3, withIndex: 3 },
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/*',
      actions: ['s3:GetObject'],
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier:
                    'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            },
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/2024/*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier:
                    'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            }
          ]
        },
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier: 'arn:aws:iam::100000000001:policy/CustomS3Policy',
                  policyType: 'identity',
                  statementId: 'VisualEditor0',
                  statementIndex: 1
                },
                {
                  policyIdentifier: 'arn:aws:iam::aws:policy/AdministratorAccess',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    name: 'principalScope with matching account limits results',
    simulationCounts: { withoutIndex: 6, withIndex: 4 },
    description:
      'Same as "shared with an account" but with principalScope limiting to only account 200000000002',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: { accounts: ['200000000002'] }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with specific principals limits to those principals',
    simulationCounts: { withoutIndex: 1, withIndex: 1 },
    description:
      'Same as "shared with specific principals" but scope limits to just one of the cross-account principals. Missing principals from the resource policy are filtered out by the scope intersection.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-principal',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: ['arn:aws:iam::200000000002:role/S3CrossAccountRole']
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'principalScope with no overlap returns empty allowed',
    simulationCounts: { withoutIndex: 0, withIndex: 0 },
    description: 'When scope accounts do not overlap with resource policy accounts, no results',
    data: '1',
    request: {
      resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0',
      actions: ['ec2:TerminateInstances'],
      principalScope: { accounts: ['999999999999'] }
    },
    expected: {
      who: []
    }
  },
  {
    name: 'principalScope with same-account principal only does not widen to whole account',
    simulationCounts: { withoutIndex: 1, withIndex: 1 },
    description:
      'When scope contains only a specific principal ARN, only that principal is tested — the account is not searched broadly',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-principal',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: [
          'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5'
        ]
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'principalScope with account and principal for same account does not duplicate results',
    simulationCounts: { withoutIndex: 5, withIndex: 1 },
    description:
      'When scope has both accounts and principals for the same account, the principal is covered by the account loop and should not appear twice',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {
        accounts: ['100000000002'],
        principals: [
          'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5'
        ]
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with service principal when resource policy names it',
    simulationCounts: { withoutIndex: 1, withIndex: 1 },
    description:
      'LambdaRole trust policy names lambda.amazonaws.com. Scoping to that service principal should find it.',
    data: '1',
    request: {
      resource: 'arn:aws:iam::200000000002:role/LambdaRole',
      actions: ['sts:AssumeRole'],
      principalScope: {
        principals: ['lambda.amazonaws.com']
      }
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'principalScope with service principal when resource policy does not name it',
    simulationCounts: { withoutIndex: 0, withIndex: 0 },
    description:
      'The who-can-acct bucket policy does not name any service principal. Scoping to lambda.amazonaws.com should find nothing.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: ['lambda.amazonaws.com']
      }
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with bad OU path returns empty results',
    simulationCounts: { withoutIndex: 0, withIndex: 0 },
    description:
      'When the scope contains an OU path that does not exist, it resolves to no accounts and produces no results',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {
        ous: ['o-11111111/r-dh2e/ou-nonexistent']
      }
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with empty scope returns empty results',
    simulationCounts: { withoutIndex: 0, withIndex: 0 },
    description:
      'An empty principalScope ({}) resolves to no accounts and no principals, so nothing is tested',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {}
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },

  // ===== PrincipalArn filter integration tests (dataset 2) =====

  {
    name: 'same-account exact PrincipalArn trust policy',
    simulationCounts: { withoutIndex: 24, withIndex: 1 },
    description:
      'Trust policy with Principal:"*" and StringEquals aws:PrincipalArn narrows to exactly one same-account principal. Duplicate canary: the principal must appear exactly once.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/exact-match-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'cross-account wildcard PrincipalArn trust policy',
    simulationCounts: { withoutIndex: 25, withIndex: 1 },
    description:
      'Trust policy with Principal:"*" and ArnLike aws:PrincipalArn narrows to cross-account principals matching the wildcard pattern.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/wildcard-match-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'wildcard trust policy with PrincipalServiceName condition',
    simulationCounts: { withoutIndex: 25, withIndex: 1 },
    description:
      'Trust policy with Principal:"*" and StringEquals aws:PrincipalServiceName extracts the named service principal. Functional delta from main branch.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/service-name-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'mixed wildcard-account and fixed-account PrincipalArn resource policy',
    description:
      'Bucket policy with Principal:"*" and StringLike aws:PrincipalArn includes both wildcard-account and fixed-account patterns. Expected: alpha-role from account 400000000001 is checked and allowed even though only account 400000000002 is explicitly named in a condition value.',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::mixed-principalarn-bucket/object.txt',
      resourceAccount: '400000000002',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        },
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'mixed explicit account grant plus wildcard PrincipalArn',
    simulationCounts: { withoutIndex: 26, withIndex: 26 },
    description:
      'Trust policy with two statements: one granting an explicit account, another with wildcard + ArnLike PrincipalArn. Expected: union of account-granted principals and pattern-matched principals. Index/non-index divergence canary.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/mixed-grant-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'NotPrincipal trust policy excludes named principal',
    simulationCounts: { withoutIndex: 26, withIndex: 26 },
    description:
      'Trust policy with Allow + NotPrincipal excludes the named principal. PrincipalArn filter is not built (safety: NotPrincipal). All eligible principals except the excluded one should appear. Same-account roles can assume without identity-side sts:AssumeRole permission.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/not-principal-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/account-root-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/org-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-only-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/unnamed-service-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'wildcard trust policy with no conditions (safety valve)',
    simulationCounts: { withoutIndex: 26, withIndex: 26 },
    description:
      'Trust policy with Principal:"*" and no conditions. PrincipalArn filter is not built. All principals with sts:AssumeRole permission are checked. Same-account roles can assume without identity-side sts:AssumeRole permission.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/no-condition-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/account-root-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/org-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-only-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/unnamed-service-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },

  {
    name: 'service-only trust policy returns no IAM principals',
    simulationCounts: { withoutIndex: 25, withIndex: 1 },
    description:
      'Trust policy with only a Service principal (s3.amazonaws.com). No IAM principals should be checked because the trust policy does not trust the resource account.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/service-only-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 's3.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },

  // ===== Deny-side and edge-case PrincipalArn filter tests (dataset 2) =====

  {
    name: 'deny-derived allow via StringNotLike narrows to matching principals',
    simulationCounts: { withoutIndex: 1, withIndex: 1 },
    description:
      'Trust policy with Allow (broad PrincipalArn) + Deny with StringNotLike PrincipalArn. The deny blocks everyone NOT matching the pattern, creating an effective allow-list. Only principals matching the deny pattern survive. Deny-derived filtering applies to ALL principals including resource-account.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'explicit deny via StringLike blocks matching principal including resource-account',
    simulationCounts: { withoutIndex: 25, withIndex: 25 },
    description:
      'Trust policy with Allow (broad PrincipalArn) + Deny with StringLike PrincipalArn targeting local-alpha. Verifies that resource-account principals are NOT exempt from deny-side filtering (asymmetry with allow-side exemption). local-alpha should be denied even though it is in the resource account.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/deny-explicit-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/account-root-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/org-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-only-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/unnamed-service-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'replacement variable in PrincipalArn prevents filter from being built',
    simulationCounts: { withoutIndex: 26, withIndex: 26 },
    description:
      'Trust policy has two wildcard-Allow statements: one with a replacement variable in PrincipalArn (unusable for static filtering) and one with a literal pattern. Because the first statement lacks a usable filter, buildPrincipalArnFilter returns undefined and no pre-filtering occurs. All principals are simulated; alpha-role matches stmt2 literal pattern, tagged-role matches stmt1 because its team tag resolves to its own ARN.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/replacement-var-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'principalScope intersects with PrincipalArn filter',
    simulationCounts: { withoutIndex: 2, withIndex: 2 },
    description:
      'Mixed-grant trust policy (account grant for 400000000001 + wildcard ArnLike for local-*) combined with principalScope limiting to account 400000000001. Only the intersection is returned: principals in 400000000001 that the trust policy allows. The pattern-matched local-* principals in 400000000002 are excluded by scope.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/mixed-grant-target',
      actions: ['sts:AssumeRole'],
      principalScope: {
        accounts: ['400000000001']
      }
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },

  // ===== Resource-account bypass, service-name precedence, PrincipalAccount StringLike, KMS =====

  {
    name: 'resource-account principals bypass allow-side PrincipalArn filter',
    simulationCounts: { withoutIndex: 25, withIndex: 4 },
    description:
      'Trust policy grants the resource account explicitly (stmt1) and has a wildcard PrincipalArn pattern matching only cross-account roles (stmt2). Resource-account principals do not match the PrincipalArn pattern but must still appear because (a) they bypass the allow-side filter via the resource-account / exemptAccounts exemption and (b) the account grant in stmt1 allows them in simulation. Note: Principal:{"AWS":"ACCOUNT"} (unlike Principal:"*") requires identity-side sts:AssumeRole — only roles with that permission appear.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'named service principal wins over unnamed service-only keys',
    simulationCounts: { withoutIndex: 25, withIndex: 1 },
    description:
      'Trust policy with both aws:PrincipalIsAWSService=true and aws:PrincipalServiceName=lambda.amazonaws.com in the same statement. The named service key (PrincipalServiceName) takes precedence over the unnamed service-only key (PrincipalIsAWSService) and the statement is treated as granting the named service principal, not as an unnamed service-only statement to skip.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/service-name-wins-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'wildcard principal with unnamed service-only condition returns no principals',
    simulationCounts: { withoutIndex: 24, withIndex: 0 },
    description:
      'Trust policy with Principal:"*" and Bool aws:PrincipalIsAWSService=true (no PrincipalServiceName). The unnamed-service-only branch continues without setting resourceAccountTrustedByPolicy, so no IAM principals or named service principals are found.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/unnamed-service-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: []
    }
  },
  {
    name: 'mixed service-only statement plus IAM account grant returns union',
    simulationCounts: { withoutIndex: 27, withIndex: 3 },
    description:
      'Trust policy with two statements: one wildcard + named PrincipalServiceName (service-only) and one explicit cross-account root principal. Expected: union of the named service principal and the cross-account IAM principals, with no accidental same-account IAM roles.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'literal PrincipalAccount via StringLike narrows to matching account',
    simulationCounts: { withoutIndex: 26, withIndex: 2 },
    description:
      'Trust policy with StringLike aws:PrincipalAccount = "400000000001" (literal value, no wildcards). The StringLike-with-literal narrowing is new and was previously only unit-tested. Expected: only principals in account 400000000001 with sts:AssumeRole permission.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'KMS kms:CallerAccount positive — principals in matching account are allowed',
    simulationCounts: { withoutIndex: 26, withIndex: 2 },
    description:
      'KMS key policy with kms:CallerAccount = 400000000001. Only principals in that account with kms:Decrypt identity permission should be allowed. This is the first end-to-end KMS coverage for the CallerAccount narrowing logic.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-positive',
      actions: ['kms:Decrypt']
    },
    expected: {
      who: [
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        }
      ]
    }
  },
  {
    name: 'KMS service principal with kms:CallerAccount is conditionally allowed',
    description:
      'A KMS key policy allows ecr.amazonaws.com only for calls associated with the key account and a matching ECR encryption context. whoCan must retain the service-principal grant as conditional rather than treating the caller account as absent.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-service-caller-account',
      actions: ['kms:Encrypt']
    },
    expected: {
      who: [
        {
          action: 'Encrypt',
          principal: 'ecr.amazonaws.com',
          service: 'kms',
          level: 'write',
          resourceType: 'key',
          conditions: {
            conditionType: 'group',
            operator: 'and',
            conditions: [
              conditionExpression(
                'StringEquals',
                'kms:CallerAccount',
                ['400000000002'],
                resourceAllowSource('AllowEcrServiceUse')
              ),
              conditionExpression(
                'StringLike',
                'kms:EncryptionContext:aws:ecr:arn',
                ['arn:aws:ecr:us-east-1:400000000002:repository/example'],
                resourceAllowSource('AllowEcrServiceUse')
              )
            ]
          },
          ignoredConditions: {
            resource: {
              allow: [
                {
                  key: 'kms:CallerAccount',
                  op: 'StringEquals',
                  values: ['400000000002']
                },
                {
                  key: 'kms:EncryptionContext:aws:ecr:arn',
                  op: 'StringLike',
                  values: ['arn:aws:ecr:us-east-1:400000000002:repository/example']
                }
              ]
            }
          }
        }
      ]
    }
  },
  {
    name: 'KMS kms:CallerAccount negative — non-existent account returns empty',
    simulationCounts: { withoutIndex: 24, withIndex: 0 },
    description:
      'KMS key policy with kms:CallerAccount = 999999999999 (account not in dataset). Expected: no principals found, account reported as not found.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-negative',
      actions: ['kms:Decrypt']
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'KMS same-account CallerAccount — all same-account principals allowed by key policy',
    simulationCounts: { withoutIndex: 24, withIndex: 24 },
    description:
      'KMS key policy with kms:CallerAccount = resource account. resourceAccountTrustedByPolicy is true, so allFromAccount is set and all same-account principals are enumerated. The key policy grants access to the entire account, so all same-account principals are allowed regardless of identity-side kms:Decrypt permission.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-same-account',
      actions: ['kms:Decrypt']
    },
    expected: {
      who: [
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/account-root-trust-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/org-trust-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/service-only-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/unnamed-service-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        }
      ]
    }
  },
  {
    name: 'KMS account-root principal — only principals with identity-side kms:Decrypt are checked',
    simulationCounts: { withoutIndex: 24, withIndex: 1 },
    description:
      'KMS key policy with Principal set to the resource account root (arn:aws:iam::400000000002:root), not a wildcard. Only principals with the permission in their identity policy should be tested on the principal index path.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-account-root',
      actions: ['kms:Decrypt']
    },
    expected: {
      who: [
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        }
      ]
    }
  },
  {
    name: 'STS account-root trust — only principals with identity-side sts:AssumeRole are checked',
    simulationCounts: { withoutIndex: 24, withIndex: 3 },
    description:
      'Trust policy with Principal set to the resource account root (arn:aws:iam::400000000002:root), should only return principals with identity policies that grant access.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/account-root-trust-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'negative ArnNotLike PrincipalArn — same-account principals still found',
    simulationCounts: { withoutIndex: 26, withIndex: 26 },
    description:
      'Trust policy with Principal:"*" and ArnNotLike aws:PrincipalArn excluding a cross-account pattern. ' +
      'The negative operator does not narrow, so checkAllFromResourceAccount is true and all same-account ' +
      'principals are enumerated. Same-account principals with sts:AssumeRole identity permissions are allowed. ' +
      'This guards against negative PrincipalArn operators being incorrectly treated as narrowing conditions.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      allAccountsChecked: true,
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/account-root-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/org-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-only-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/unnamed-service-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'org trust — PrincipalOrgID conservative trust includes same-account principals',
    simulationCounts: { withoutIndex: 26, withIndex: 26 },
    description:
      'Trust policy with Principal:"*" and aws:PrincipalOrgID = o-44444444. resourceAccountTrustedByPolicy is conservatively true (org may include the resource account). allFromAccount is set, so all same-account principals are enumerated. Both accounts (400000000001, 400000000002) are in the org, so cross-account principals with identity-side sts:AssumeRole are also included.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/org-trust-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/account-root-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/kms-user',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-service-iam-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/negative-arnnotlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/org-trust-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-only-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/unnamed-service-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'principalScope aimed at same-account principal with service-only trust returns empty',
    simulationCounts: { withoutIndex: 1, withIndex: 1 },
    description:
      'Scope to a same-account IAM principal against a role whose trust policy only allows a service principal. The scoped principal is enqueued but the simulation denies it because the trust policy does not match. The service principal is not in the scope so it is also excluded.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/service-only-target',
      actions: ['sts:AssumeRole'],
      principalScope: {
        principals: ['arn:aws:iam::400000000002:role/local-alpha']
      }
    },
    expected: {
      who: []
    }
  },
  {
    name: 'duplicate specific principal from explicit principal + PrincipalArn condition',
    simulationCounts: { withoutIndex: 24, withIndex: 1 },
    description:
      'Trust policy where the same principal appears in specificPrincipals twice: once from an explicit Principal element (stmt1) and once from a StringEquals aws:PrincipalArn condition (stmt2). The result must contain the principal exactly once.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'S3 bucket with no bucket policy — same-account identity-based access found',
    simulationCounts: { withoutIndex: 24, withIndex: 1 },
    description:
      'S3 bucket with no bucket policy. Same-account principals with identity-based s3:ListBucket permission should still be found because the resource account is always included in the search for non-untrusting actions.',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::no-policy-bucket',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'bucket policy Allow with NotResource — PrincipalArn filter narrows on resource outside excluded prefix',
    simulationCounts: { withoutIndex: 25, withIndex: 25 },
    description:
      'Bucket policy has a wildcard-Allow with NotResource on a private prefix and a StringLike PrincipalArn pattern. For an object outside the excluded prefix the Allow applies; the filter narrows cross-account candidates to the pattern match and alpha-role is granted via the bucket policy while s3-reader is granted via same-account identity.',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::alpha-only-bucket/public/report.txt',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        },
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'bucket policy Allow with NotResource — simulation denies cross-account on resource inside excluded prefix',
    simulationCounts: { withoutIndex: 25, withIndex: 25 },
    description:
      'Same bucket policy as the previous test but whoCan queries an object inside the excluded prefix; the filter still admits alpha-role as a candidate but the simulator correctly denies it, while same-account s3-reader remains allowed via its identity grant.',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::alpha-only-bucket/private/secret.txt',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'resource policy Allow without Principal adds no principal to whoCan',
    description:
      'The bucket policy Allow on no-principal-bucket has no Principal element. EC2Admin has no identity grant for s3:GetBucketPolicy, so with principalScope limited to EC2Admin the result set is empty.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::no-principal-bucket',
      actions: ['s3:GetBucketPolicy'],
      principalScope: {
        principals: ['arn:aws:iam::100000000002:role/EC2Admin']
      }
    },
    expected: {
      who: []
    }
  },
  {
    name: 'sibling statement in no-Principal resource policy still yields the expected principal',
    description:
      'The third statement of the no-principal-bucket policy explicitly names IAMCollect as a principal for s3:ListBucket. IAMCollect has no s3:ListBucket in identity and no permission boundary, so with principalScope limited to IAMCollect, that sibling statement is the only grant and IAMCollect should be returned.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::no-principal-bucket',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: ['arn:aws:iam::100000000002:role/IAMCollect']
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::100000000002:role/IAMCollect',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'resource policy Deny without Principal does not suppress same-account access',
    description:
      'The no-principal-bucket policy has a Deny for s3:GetBucketPolicy with no Principal element. The Deny must not fire, so the SSO admin on 100000000002 (identity *:* via AdministratorAccess) remains allowed when principalScope is limited to that admin.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::no-principal-bucket',
      actions: ['s3:GetBucketPolicy'],
      principalScope: {
        principals: [
          'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5'
        ]
      }
    },
    expected: {
      who: [
        {
          action: 'GetBucketPolicy',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'full whoCan on no-principal-bucket across s3:ListBucket and s3:GetBucketPolicy (no principalScope)',
    description:
      'Without principalScope, whoCan enumerates all principals in the organization. The no-Principal Allow and Deny statements on no-principal-bucket must neither add nor remove anyone; the sibling resource-policy statement adds IAMCollect for ListBucket only; cross-account admins have no path because the resource policy does not grant them.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::no-principal-bucket',
      actions: ['s3:ListBucket', 's3:GetBucketPolicy']
    },
    expected: {
      who: [
        {
          action: 'GetBucketPolicy',
          principal: 'arn:aws:iam::100000000002:role/IAMCollect',
          service: 's3',
          level: 'read',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::100000000002:role/IAMCollect',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'GetBucketPolicy',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  }
]

beforeAll(async () => {
  for (const datasetId of new Set(whoCanIntegrationTests.map((test) => test.data))) {
    const client = await getTestDatasetClient(datasetId)
    await makePrincipalIndex(client)
  }
})

/**
 * Sort who can results for comparison in tests
 *
 * @param who Array of WhoCanAllowed objects to sort
 * @returns Sorted array of WhoCanAllowed objects
 */
function sortWhoCanResults(who: WhoCanAllowed[]) {
  const sorted = who.map((result) => {
    const allowedPatterns = result.allowedPatterns
      ? [...result.allowedPatterns]
          .map((pattern) => ({
            ...pattern,
            details: pattern.details ? [...pattern.details].sort(compareGrantDetails) : undefined
          }))
          .sort((a, b) => {
            if (a.pattern < b.pattern) return -1
            if (a.pattern > b.pattern) return 1
            if (a.resourceType < b.resourceType) return -1
            if (a.resourceType > b.resourceType) return 1
            return 0
          })
      : undefined

    return {
      ...result,
      details: result.details ? [...result.details].sort(compareGrantDetails) : undefined,
      allowedPatterns
    }
  })

  return sorted.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })
}

type GrantDetail = {
  policyType: string
  policyIdentifier?: string
  statementId?: string
  statementIndex: number
}

type DenialDetail = {
  policyType: string
  policyIdentifier?: string
  statementId?: string
  denialType: string
}

function sortDenyDetails(details: WhoCanDenyDetail[] | undefined): WhoCanDenyDetail[] {
  const sorted = (details || []).map((detail) => {
    if (detail.type === 'single') {
      return {
        ...detail,
        details: [...detail.details].sort(compareDenialDetails)
      }
    }

    return {
      ...detail,
      deniedResources: [...detail.deniedResources]
        .map((resource) => ({
          ...resource,
          details: [...resource.details].sort(compareDenialDetails)
        }))
        .sort((a, b) => {
          if (a.pattern < b.pattern) return -1
          if (a.pattern > b.pattern) return 1
          if (a.resourceType < b.resourceType) return -1
          if (a.resourceType > b.resourceType) return 1
          return 0
        })
    }
  })

  return sorted.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })
}

function compareDenialDetails(a: DenialDetail, b: DenialDetail) {
  if (a.policyType < b.policyType) return -1
  if (a.policyType > b.policyType) return 1
  const aPolicy = a.policyIdentifier ?? ''
  const bPolicy = b.policyIdentifier ?? ''
  if (aPolicy < bPolicy) return -1
  if (aPolicy > bPolicy) return 1
  const aStmt = a.statementId ?? ''
  const bStmt = b.statementId ?? ''
  return 0
}

function compareGrantDetails(a: GrantDetail, b: GrantDetail) {
  if (a.policyType < b.policyType) return -1
  if (a.policyType > b.policyType) return 1
  const aPolicy = a.policyIdentifier ?? ''
  const bPolicy = b.policyIdentifier ?? ''
  if (aPolicy < bPolicy) return -1
  if (aPolicy > bPolicy) return 1
  const aStmt = a.statementId ?? ''
  const bStmt = b.statementId ?? ''
  if (aStmt < bStmt) return -1
  if (aStmt > bStmt) return 1
  return a.statementIndex - b.statementIndex
}

/**
 * Runs all test cases for a dataset through a single processor with the given
 * tuning, then asserts each settled result matches the expected output.
 *
 * @param datasetId - The test dataset to use.
 * @param withIndex - Whether to use the principal index.
 * @param tuning - Processor tuning overrides.
 */
async function runParallelProcessorTest(
  datasetId: string,
  withIndex: boolean,
  tuning: {
    workerThreads?: number
    mainThreadConcurrency?: number
    perWorkerConcurrency?: number
    maxRequestsInProgress?: number
  }
): Promise<void> {
  //Given a set of configs
  const configs = getTestDatasetConfigs(datasetId)

  const resultsMap = new Map<string, WhoCanResponse | string>()
  const requestIdMap = new Map<string, { testIndex: number; testName: string }>()

  //And a processor with the specified tuning
  const processor = await WhoCanProcessor.create({
    collectConfigs: configs,
    partition: 'aws',
    tuning,
    ignorePrincipalIndex: !withIndex,
    onRequestSettled: async (event) => {
      if (event.status === 'fulfilled') {
        resultsMap.set(event.requestId, event.result)
      } else {
        resultsMap.set(event.requestId, event.error.message)
      }
    }
  })

  try {
    //When we send all the requests
    for (let i = 0; i < whoCanIntegrationTests.length; i++) {
      const test = whoCanIntegrationTests[i]
      const { name, request, data } = test
      if (data !== datasetId) {
        continue
      }

      const requestId = processor.enqueueWhoCan({
        actions: request.actions,
        resource: request.resource,
        resourceAccount: request.resourceAccount,
        principalScope: request.principalScope,
        strictContextKeys: request.strictContextKeys,
        denyDetailsCallback: request.denyDetailsCallback
      })
      requestIdMap.set(requestId, { testIndex: i, testName: name })
    }

    //And wait for all results to be processed
    await processor.waitForIdle()

    //Then all results should be present and without errors
    for (const [requestId, requestInfo] of requestIdMap.entries()) {
      const result = resultsMap.get(requestId)
      expect(
        result,
        `No result found for ${requestInfo.testName} (index ${requestInfo.testIndex})`
      ).toBeDefined()

      if (typeof result === 'string') {
        assert.fail(`Error for ${requestInfo.testName} (index ${requestInfo.testIndex}): ${result}`)
      }
    }

    //And the results should match the expected output for each test
    for (const [requestId, result] of resultsMap.entries()) {
      const { testIndex, testName } = requestIdMap.get(requestId)!
      const test = whoCanIntegrationTests[testIndex]
      const { expected, expectedDenyDetails } = test
      if (typeof result !== 'string') {
        if (test.request.s3AbacOverride) {
          // Skip verifying results for tests with s3AbacOverride in the parallel test since it is a processor level setting and won't match
          continue
        }
        const message = `Results do not match for test "${testName}" (index ${testIndex})`
        assertWhoCanResponse(
          result,
          removeExpectedGrantDetails(expected),
          expectedDenyDetails,
          message
        )
        if (test.simulationCounts !== undefined && !test.request.s3AbacOverride && !withIndex) {
          expect(result.simulationCount, `simulation count mismatch for "${testName}"`).toBe(
            test.simulationCounts.withoutIndex
          )
        } else if (
          test.simulationCounts !== undefined &&
          !test.request.s3AbacOverride &&
          withIndex
        ) {
          expect(
            result.simulationCount,
            `simulation count (withIndex) mismatch for "${testName}"`
          ).toBe(test.simulationCounts.withIndex)
        }
      }
    }
  } finally {
    await processor.shutdown()
  }
}

const processorTuningConfigs = [
  {
    label: 'default',
    tuning: { workerThreads: 2, mainThreadConcurrency: 0, perWorkerConcurrency: 10 }
  },
  {
    label: 'serial admission (maxRequestsInProgress: 1)',
    tuning: {
      workerThreads: 1,
      mainThreadConcurrency: 0,
      perWorkerConcurrency: 10,
      maxRequestsInProgress: 1
    }
  },
  {
    label: 'limited parallelism (maxRequestsInProgress: 2)',
    tuning: {
      workerThreads: 1,
      mainThreadConcurrency: 0,
      perWorkerConcurrency: 10,
      maxRequestsInProgress: 2
    }
  },
  {
    label: 'main thread only (workerThreads: 0)',
    tuning: { workerThreads: 0, mainThreadConcurrency: 50 }
  }
]

describe('whoCan Integration Tests', () => {
  for (const withIndex of [false, true]) {
    describe('running tests in parallel', () => {
      const uniqueDatasetIds = new Set(whoCanIntegrationTests.map((test) => test.data))
      for (const datasetId of uniqueDatasetIds) {
        for (const { label, tuning } of processorTuningConfigs) {
          it(`dataset ${datasetId}, ${label} (withIndex: ${withIndex})`, async () => {
            await runParallelProcessorTest(datasetId, withIndex, tuning)
          })
        }
      }
    })

    for (const test of whoCanIntegrationTests) {
      const { name, request, expected, expectedDenyDetails, only, data } = test

      // Set worker threads to 1 for tests so it gets tested but doesn't saturate CPUs
      request.workerThreads = 1
      const func = only ? it.only : it
      const testName = `${name} (withIndex: ${withIndex})`
      func(testName, async () => {
        //Given a client
        const configs = getTestDatasetConfigs(data)

        //When we call whoCan
        const requestCopy = { ...request }
        requestCopy.ignorePrincipalIndex = !withIndex
        const result = await whoCan(configs, 'aws', requestCopy)

        //Then we expect the result to match the expected output
        if (test.simulationCounts !== undefined && !withIndex) {
          expect(result.simulationCount, `simulation count mismatch for "${name}"`).toBe(
            test.simulationCounts.withoutIndex
          )
        }
        if (test.simulationCounts !== undefined && withIndex) {
          expect(
            result.simulationCount,
            `simulation count (withIndex) mismatch for "${name}"`
          ).toBe(test.simulationCounts.withIndex)
        }
        assertWhoCanResponse(result, expected, expectedDenyDetails)
      })
    }
  }
})

function removeExpectedGrantDetails(
  expected: WhoCanIntegrationTest['expected']
): WhoCanIntegrationTest['expected'] {
  // This is used for snapshot testing where we want to exclude the deny details from the snapshot but still test them in the test itself
  const copy = structuredClone(expected)
  for (const who of copy.who) {
    if (who.allowedPatterns) {
      for (const pattern of who.allowedPatterns) {
        delete pattern.details
      }
    }
    delete who.details
  }
  return copy
}

/**
 * Helper function to assert that the WhoCanResponse matches the expected output, including sorting results for comparison
 *
 * @param result - The actual WhoCanResponse returned by the whoCan function.
 * @param expected - The expected output for the test case.
 * @param expectedDenyDetails - The expected deny details for the test case, if any.
 * @param message - Optional message to include in assertion errors for better context.
 */
function assertWhoCanResponse(
  result: WhoCanResponse,
  expected: WhoCanIntegrationTest['expected'],
  expectedDenyDetails: WhoCanDenyDetail[] | 'ignore' | undefined,
  message?: string
) {
  expect(sortWhoCanResults(result.allowed), message).toEqual(sortWhoCanResults(expected.who))
  expect(result.allAccountsChecked, message).toEqual(!!expected.allAccountsChecked)
  expect(result.organizationalUnitsNotFound, message).toEqual(
    expected.organizationalUnitsNotFound || []
  )
  expect(result.accountsNotFound, message).toEqual(expected.accountsNotFound || [])
  expect(result.organizationsNotFound, message).toEqual(expected.organizationsNotFound || [])
  expect(result.principalsNotFound.sort(), message).toEqual(
    expected.principalsNotFound?.sort() || []
  )
  if (expectedDenyDetails !== 'ignore') {
    if (expectedDenyDetails) {
      expect(sortDenyDetails(result.denyDetails), message).toEqual(
        sortDenyDetails(expectedDenyDetails)
      )
    } else {
      expect(result.denyDetails, message).toBeUndefined()
    }
  }
}
