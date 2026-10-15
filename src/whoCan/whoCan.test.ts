import { describe, expect, it } from 'vitest'
import { IamCollectClient } from '../collect/client.js'
import {
  type AccountsToCheck,
  accountsToCheckBasedOnResourcePolicy,
  actionsForWhoCan,
  findResourceTypeForArn,
  type ResourceAccessRequest,
  sortWhoCanResults,
  uniqueAccountsToCheck,
  type WhoCanResponse
} from './whoCan.js'

const noPrincipalResolutionClient = {
  resolvePrincipalArn: async () => undefined
} as unknown as IamCollectClient

describe('anonymous candidate statements', () => {
  const cases = [
    { name: 'plain wildcard', principal: { Principal: '*' }, candidate: true },
    { name: 'AWS wildcard', principal: { Principal: { AWS: '*' } }, candidate: true },
    {
      name: 'mixed wildcard array',
      principal: { Principal: { AWS: ['*', '123456789012'] } },
      candidate: true
    },
    {
      name: 'excluded principal',
      principal: { NotPrincipal: { AWS: '123456789012' } },
      candidate: true
    },
    {
      name: 'specific account',
      principal: { Principal: { AWS: '123456789012' } },
      candidate: false
    },
    {
      name: 'service principal',
      principal: { Principal: { Service: 's3.amazonaws.com' } },
      candidate: false
    },
    {
      name: 'federated principal',
      principal: { Principal: { Federated: 'accounts.google.com' } },
      candidate: false
    },
    {
      name: 'canonical user',
      principal: { Principal: { CanonicalUser: 'example-canonical-user' } },
      candidate: false
    },
    { name: 'missing principal', principal: {}, candidate: false }
  ]
  for (const scenario of cases) {
    for (const effect of ['Allow', 'Deny']) {
      it(`${effect} with ${scenario.name}`, async () => {
        //Given one resource-policy statement
        const policy = {
          Statement: [{ Effect: effect, ...scenario.principal, Action: '*', Resource: '*' }]
        }

        //When discovering possible unsigned-access grants
        const result = await accountsToCheckBasedOnResourcePolicy(
          policy,
          '123456789012',
          noPrincipalResolutionClient
        )

        //Then only an Allow with a potentially anonymous principal is a candidate
        expect(result.checkAnonymous).toBe(effect === 'Allow' && scenario.candidate)
      })
    }
  }
  it('does not check anonymous access without a resource policy', async () => {
    //Given no collected resource policy
    //When preparing the policy-derived search scope
    const result = await accountsToCheckBasedOnResourcePolicy(
      undefined,
      '123456789012',
      noPrincipalResolutionClient
    )
    //Then no unsigned scenario is warranted
    expect(result.checkAnonymous).toBe(false)
  })
})

const findResourceTypeForArnTests: {
  only?: boolean
  input: string
  expected: {
    service: string
    key: string
  }
}[] = [
  {
    input: 'arn:aws:s3:::my-bucket',
    expected: {
      service: 's3',
      key: 'bucket'
    }
  },
  {
    input: 'arn:aws:S3:::my-bucket',
    expected: {
      service: 's3',
      key: 'bucket'
    }
  },
  {
    input: 'arn:aws:s3:::my-bucket/a',
    expected: {
      service: 's3',
      key: 'object'
    }
  },
  {
    input: 'arn:aws:s3:::my-bucket/a/b/c',
    expected: {
      service: 's3',
      key: 'object'
    }
  },
  {
    input: 'arn:aws:iam::123456789012:user/DavidKerber',
    expected: {
      service: 'iam',
      key: 'user'
    }
  },
  {
    input: 'arn:aws:iam::123456789012:user/Admin/DavidKerber',
    expected: {
      service: 'iam',
      key: 'user'
    }
  },
  {
    input: 'arn:aws:iam::123456789012:group/Admins',
    expected: {
      service: 'iam',
      key: 'group'
    }
  },
  {
    input: 'arn:aws:ec2:us-west-2:123456789012:instance/i-0123456789abcdef0',
    expected: {
      service: 'ec2',
      key: 'instance'
    }
  },
  {
    input: 'arn:aws:dynamodb:us-east-1:123456789012:table/Books',
    expected: {
      service: 'dynamodb',
      key: 'table'
    }
  },
  {
    input: 'arn:aws:kinesis:us-east-1:123456789012:stream/data-stream',
    expected: {
      service: 'kinesis',
      key: 'stream'
    }
  },
  {
    input: 'arn:aws:sns:us-east-1:123456789012:my-topic',
    expected: {
      service: 'sns',
      key: 'topic'
    }
  },
  {
    input: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/myFunction',
    expected: {
      service: 'logs',
      key: 'log-group'
    }
  },
  {
    input:
      'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/myFunction:log-stream:fh389r7cj292h',
    expected: {
      service: 'logs',
      key: 'log-stream'
    }
  },
  {
    input: 'arn:aws:ecr:us-west-2:123456789012:repository/my-repo',
    expected: { service: 'ecr', key: 'repository' }
  },
  {
    input: 'arn:aws:ecr:us-west-2:123456789012:repository/my-repo:latest',
    expected: { service: 'ecr', key: 'repository' }
  },
  {
    input:
      'arn:aws:ecr:us-west-2:123456789012:repository/my-repo@sha256:abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef1234',
    expected: { service: 'ecr', key: 'repository' }
  },
  {
    input: 'arn:aws:lambda:us-east-1:123456789012:function:my-function',
    expected: { service: 'lambda', key: 'function' }
  },
  {
    input: 'arn:aws:lambda:us-east-1:123456789012:function:my-function:PROD',
    expected: { service: 'lambda', key: 'function version' }
  },
  {
    input: 'arn:aws:iam::aws:policy/ReadOnlyAccess',
    expected: { service: 'iam', key: 'policy' }
  },
  {
    input: 'arn:aws:kms:us-east-1:123456789012:alias/my-key',
    expected: { service: 'kms', key: 'alias' }
  },
  {
    input: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    expected: { service: 'kms', key: 'key' }
  },
  {
    input: 'arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine',
    expected: { service: 'states', key: 'statemachine' }
  },
  {
    input: 'arn:aws:sqs:us-east-1:123456789012:my-queue',
    expected: { service: 'sqs', key: 'queue' }
  }
]

describe('findResourceTypeForArn', () => {
  for (const test of findResourceTypeForArnTests) {
    const func = test.only ? it.only : it
    func(`should find the right type for ${test.input}`, async () => {
      // Given an ARN
      const arn = test.input

      // When findResourceTypeForArn is called
      const [service, details] = await findResourceTypeForArn(arn)

      // Then it should return the expected service and key
      expect(service).toEqual(test.expected.service)
      expect(details.key).toEqual(test.expected.key)
    })
  }
})

describe('actionsForWhoCan', () => {
  it('if given actions, should return the actions as long as they are valid', async () => {
    // Given a request with valid and invalid actions
    const request: ResourceAccessRequest = {
      resource: 'arn:aws:s3:::my-bucket',
      actions: ['s3:GetObject', 's3:PutObject', 'invalid:Action', 's3:NonExistent']
    }

    // When actionsForWhoCan is called
    const result = await actionsForWhoCan(request)

    // Then it should return only the valid actions
    expect(result).toContain('s3:GetObject')
    expect(result).toContain('s3:PutObject')
    expect(result).not.toContain('invalid:Action')
    expect(result).not.toContain('s3:NonExistent')
  })

  it('if not given actions, should return all actions for the resource type', async () => {
    // Given a request with no actions
    const request = {
      resource: 'arn:aws:s3:::my-bucket',
      actions: []
    }

    // When actionsForWhoCan is called
    const result = await actionsForWhoCan(request)

    // Then it should return some known actions for the resource type
    expect(result).toContain('s3:GetBucketPolicy')
    expect(result).toContain('s3:GetBucketLocation')
    expect(result).toContain('s3:GetBucketPublicAccessBlock')
  })

  it('should return sts assume role actions for IAM roles', async () => {
    // Given a request with no actions
    const request = {
      resource: 'arn:aws:iam::123456789012:role/MyRole',
      actions: []
    }

    // When actionsForWhoCan is called
    const result = await actionsForWhoCan(request)

    // Then it should return some known actions for the resource type
    // Expect some IAM role actions and all three sts assume role actions
    expect(result).toContain('iam:GetRole')
    expect(result).toContain('iam:PassRole')
    expect(result).toContain('sts:AssumeRole'.toLowerCase())
    expect(result).toContain('sts:AssumeRoleWithWebIdentity'.toLowerCase())
    expect(result).toContain('sts:AssumeRoleWithSAML'.toLowerCase())
  })
})

const accountsToCheckBasedOnResourcePolicyTests: {
  only?: boolean
  name: string
  resourcePolicy: any
  resourceAccountId: string
  expected: Partial<AccountsToCheck>
}[] = [
  {
    name: 'should return all accounts if resource policy allows it',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        }
      ]
    },
    resourceAccountId: '123456789012',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should pick up a specific account ID principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '111111111111' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['111111111111'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should extract account from root ARN principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:root' },
          Action: 'sts:AssumeRole',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should extract account from account number',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '222222222222' },
          Action: 'sts:AssumeRole',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should pick up organization ID condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': ['o-aaaaaaaaaa', 'o-bbbbbbbbbb'] } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: ['o-aaaaaaaaaa', 'o-bbbbbbbbbb'],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should pick up organizational unit paths with ForAnyValue operator',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': { 'aws:PrincipalOrgPaths': ['o-aaa/r-bbb/ou-ccc'] }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-ccc'],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- Precedence: multiple narrowing keys in one statement ---
  {
    name: 'precedence: PrincipalAccount wins over PrincipalOrgID in same statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalAccount': '111111111111',
              'aws:PrincipalOrgID': 'o-aaaaaaaaaa'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['111111111111'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'precedence: PrincipalAccount wins over PrincipalOrgPaths in same statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalAccount': '222222222222'
            },
            'ForAnyValue:StringEquals': {
              'aws:PrincipalOrgPaths': ['o-aaa/r-bbb/ou-ccc']
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'precedence: PrincipalOrgPaths wins over PrincipalOrgID in same statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': {
              'aws:PrincipalOrgPaths': ['o-aaa/r-bbb/ou-ccc']
            },
            StringEquals: {
              'aws:PrincipalOrgID': 'o-aaaaaaaaaa'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-ccc'],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should pick up aws:PrincipalAccount condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalAccount': ['444444444444'] } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['444444444444'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should pick up aws:PrincipalAccount with StringLike and literal value',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: { StringLike: { 'aws:PrincipalAccount': '018153356262' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['018153356262'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should pick up aws:PrincipalAccount with StringLike and multiple literal values',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalAccount': ['111111111111', '222222222222'] }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['111111111111', '222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should NOT pick up aws:PrincipalAccount with StringLike when value has wildcard',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringLike: { 'aws:PrincipalAccount': '01815335*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should NOT narrow when StringLike PrincipalAccount has mixed literal and wildcard values',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalAccount': ['111111111111', '2222*'] }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should NOT pick up aws:PrincipalAccount with StringLike when value has ? wildcard',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringLike: { 'aws:PrincipalAccount': '01815335626?' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should NOT pick up aws:PrincipalAccount with StringLike when value has dynamic variable',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringLike: { 'aws:PrincipalAccount': '${aws:PrincipalAccount}' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- kms:CallerAccount ---
  {
    name: 'should pick up kms:CallerAccount with StringEquals',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: { StringEquals: { 'kms:CallerAccount': '555555555555' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['555555555555'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should pick up kms:CallerAccount with StringLike and literal value',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: { StringLike: { 'kms:CallerAccount': '555555555555' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['555555555555'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should NOT pick up kms:CallerAccount with StringLike when value has wildcard',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: { StringLike: { 'kms:CallerAccount': '55555*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should NOT pick up kms:CallerAccount with StringLike when value has ? wildcard',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: { StringLike: { 'kms:CallerAccount': '55555555555?' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should NOT pick up kms:CallerAccount with StringLike when value has dynamic variable',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: { StringLike: { 'kms:CallerAccount': '${aws:PrincipalAccount}' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should NOT narrow kms:CallerAccount StringLike with mixed literal and wildcard values',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'kms:*',
          Resource: '*',
          Condition: {
            StringLike: { 'kms:CallerAccount': ['555555555555', '6666*'] }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'should include service principal as specificPrincipal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '555555555555',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['lambda.amazonaws.com'],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should include full ARN principal as specificPrincipal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::666666666666:role/MyRole' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['arn:aws:iam::666666666666:role/MyRole'],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'if there is a NotPrincipal, check all accounts',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotPrincipal: { AWS: 'arn:aws:iam::666666666666:role/MyRole' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- aws:PrincipalArn: Exact match operators → specificPrincipals ---
  {
    name: 'PrincipalArn: StringEquals single ARN',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/SpecificRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/SpecificRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: StringEquals multiple ARNs',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': [
                'arn:aws:iam::777777777777:role/RoleA',
                'arn:aws:iam::888888888888:user/UserB'
              ]
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: [
        'arn:aws:iam::777777777777:role/RoleA',
        'arn:aws:iam::888888888888:user/UserB'
      ],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: StringEqualsIgnoreCase',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEqualsIgnoreCase: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/MyRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/MyRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: Root ARN via StringEquals',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:root' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:root'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- aws:PrincipalArn: Pattern operators without wildcards → specificPrincipals ---
  {
    name: 'PrincipalArn: ArnEquals exact ARN',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/ExactRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/ExactRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: ArnLike exact ARN',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/ExactRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/ExactRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: StringLike exact ARN',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/ExactRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/ExactRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- aws:PrincipalArn: Wildcards with specific account → specificAccounts ---
  {
    name: 'PrincipalArn: ArnLike wildcard resource',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['999999999999'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: StringLike wildcard resource path',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/Admin*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['999999999999'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: ArnLike ? wildcard',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/Role?' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['999999999999'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- aws:PrincipalArn: Wildcards in account → allAccounts ---
  {
    name: 'PrincipalArn: ArnLike wildcard account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/MyRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'PrincipalArn: StringLike full wildcard',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'PrincipalArn: StringLike mixed wildcard-account and fixed-account role paths',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'ExplicitlyAllowWildCardRolePaths',
          Effect: 'Allow',
          Action: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
          Principal: { AWS: '*' },
          Resource: '*',
          Condition: {
            StringLike: {
              'aws:PrincipalArn': [
                'arn:aws:iam::*:role/ecs-tasks/*',
                'arn:aws:iam::*:role/k8s-pod/cicd/*',
                'arn:aws:iam::*:role/lambda/util/*',
                'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_engineer_*',
                'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_super_*',
                'arn:aws:iam::123456789012:role/bx_admin',
                'arn:aws:iam::123456789012:role/bx_super',
                'arn:aws:iam::123456789012:role/engineer',
                'arn:aws:iam::123456789012:role/security_controls/*',
                'arn:aws:iam::123456789012:role/xa-tfe/dply/tfe-deployment'
              ]
            }
          }
        },
        {
          Sid: 'ExplicitlyDenyOtherWildCardRolePaths',
          Effect: 'Deny',
          Action: 'secretsmanager:GetSecretValue',
          Principal: { AWS: '*' },
          Resource: '*',
          Condition: {
            StringNotLike: {
              'aws:PrincipalArn': [
                'arn:aws:iam::*:role/ecs-tasks/*',
                'arn:aws:iam::*:role/k8s-pod/cicd/*',
                'arn:aws:iam::*:role/lambda/util/*',
                'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_engineer_*',
                'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_super_*',
                'arn:aws:iam::123456789012:role/bx_admin',
                'arn:aws:iam::123456789012:role/bx_super',
                'arn:aws:iam::123456789012:role/engineer',
                'arn:aws:iam::123456789012:role/security_controls/*',
                'arn:aws:iam::123456789012:role/xa-tfe/dply/tfe-deployment'
              ]
            }
          }
        }
      ]
    },
    resourceAccountId: '123456789012',
    expected: {
      allAccounts: true,
      // Each fixed-account wildcard role path contributes an account entry; literal ARNs contribute specific principals, and later account resolution deduplicates account entries.
      specificAccounts: ['123456789012', '123456789012', '123456789012'],
      specificPrincipals: [
        'arn:aws:iam::123456789012:role/bx_admin',
        'arn:aws:iam::123456789012:role/bx_super',
        'arn:aws:iam::123456789012:role/engineer',
        'arn:aws:iam::123456789012:role/xa-tfe/dply/tfe-deployment'
      ],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'PrincipalArn: wildcard account still narrows when PrincipalAccount is present',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: {
              'aws:PrincipalArn': 'arn:aws:iam::*:role/ApplicationRole'
            },
            StringEquals: {
              'aws:PrincipalAccount': '123456789012'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['123456789012'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- aws:PrincipalArn: Dynamic variables ---
  {
    name: 'PrincipalArn: dynamic variable with no account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: { 'aws:PrincipalArn': '${aws:PrincipalArn}' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'PrincipalArn: dynamic variable after specific account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/${aws:username}'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['999999999999'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: dynamic variable in account portion',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::${aws:PrincipalAccount}:role/MyRole'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'PrincipalArn: dynamic variable in partition with specific account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:${aws:Partition}:iam::999999999999:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['999999999999'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- aws:PrincipalArn: IfExists (anonymous tracking) ---
  {
    name: 'PrincipalArn: StringEqualsIfExists with specific ARN',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEqualsIfExists: {
              'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/MyRole'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/MyRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: ArnLikeIfExists with wildcard resource',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLikeIfExists: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['999999999999'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: ArnLikeIfExists with no extractable narrowing',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLikeIfExists: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- aws:PrincipalArn: Other edge cases ---
  {
    name: 'PrincipalArn: ForAnyValue set operator',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAnyValue:ArnLike': { 'aws:PrincipalArn': 'arn:aws:iam::888888888888:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['888888888888'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: coexists with PrincipalAccount',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/MyRole',
              'aws:PrincipalAccount': '888888888888'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/MyRole'],
      specificAccounts: ['888888888888'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: mixed exact + wildcard values',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: {
              'aws:PrincipalArn': [
                'arn:aws:iam::777777777777:role/ExactRole',
                'arn:aws:iam::888888888888:role/*'
              ]
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/ExactRole'],
      specificAccounts: ['888888888888'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'PrincipalArn: negative operator ignored',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringNotEquals: { 'aws:PrincipalArn': 'arn:aws:iam::777777777777:role/MyRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'PrincipalArn: case-insensitive key',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: { 'AWS:PRINCIPALARN': 'arn:aws:iam::777777777777:role/MyRole' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:iam::777777777777:role/MyRole'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- Service-principal-only: Unnamed keys (statement skipped) ---
  {
    name: 'Service-only: aws:SourceAccount StringEquals skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceAccount': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: aws:SourceOwner StringEquals skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceOwner': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: aws:SourceOrgID StringEquals skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceOrgID': 'o-abc123' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: aws:SourceOrgPaths ForAnyValue:StringEquals skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': { 'aws:SourceOrgPaths': 'o-abc/r-root/ou-dept' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: case-insensitive key detection',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'AWS:SOURCEACCOUNT': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: aws:SourceAccount StringLike skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringLike: { 'aws:SourceAccount': '111*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: aws:SourceOrgID StringLike skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringLike: { 'aws:SourceOrgID': 'o-*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: aws:SourceOrgPaths ForAnyValue:StringLike skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { 'ForAnyValue:StringLike': { 'aws:SourceOrgPaths': 'o-abc/*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- Service-only: IfExists does NOT skip ---
  {
    name: 'Service-only: aws:SourceAccount IfExists does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEqualsIfExists: { 'aws:SourceAccount': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: aws:SourceOrgID IfExists does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEqualsIfExists: { 'aws:SourceOrgID': 'o-abc123' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- Service-only: Negative operators do NOT skip ---
  {
    name: 'Service-only: aws:SourceAccount StringNotEquals does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringNotEquals: { 'aws:SourceAccount': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: aws:SourceOrgID StringNotEquals does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringNotEquals: { 'aws:SourceOrgID': 'o-abc123' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: aws:SourceAccount StringNotEqualsIgnoreCase does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringNotEqualsIgnoreCase: { 'aws:SourceAccount': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- Service-only: aws:SourceOrgPaths operator restrictions ---
  {
    name: 'Service-only: aws:SourceOrgPaths ForAllValues:StringEquals does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAllValues:StringEquals': { 'aws:SourceOrgPaths': 'o-abc/r-root/ou-dept' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: aws:SourceOrgPaths ForAllValues:StringLike does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { 'ForAllValues:StringLike': { 'aws:SourceOrgPaths': 'o-abc/*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: aws:SourceOrgPaths plain StringEquals does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceOrgPaths': 'o-abc/r-root/ou-dept' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: aws:SourceOrgPaths plain StringLike does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringLike: { 'aws:SourceOrgPaths': 'o-abc/*' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- Service-only: aws:PrincipalIsAWSService ---
  {
    name: 'Service-only: Bool PrincipalIsAWSService true skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { Bool: { 'aws:PrincipalIsAWSService': 'true' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: StringEquals PrincipalIsAWSService true skips statement',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalIsAWSService': 'true' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: Bool PrincipalIsAWSService false does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { Bool: { 'aws:PrincipalIsAWSService': 'false' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: BoolIfExists PrincipalIsAWSService true does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { BoolIfExists: { 'aws:PrincipalIsAWSService': 'true' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: StringNotEquals PrincipalIsAWSService true does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringNotEquals: { 'aws:PrincipalIsAWSService': 'true' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: PrincipalIsAWSService mixed true/false values does NOT skip',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { Bool: { 'aws:PrincipalIsAWSService': ['true', 'false'] } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- Service-only: Named service principal (aws:PrincipalServiceName) ---
  {
    name: 'Service-only: PrincipalServiceName extracts service principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: { 'aws:PrincipalServiceName': 'lambda.amazonaws.com' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['lambda.amazonaws.com'],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: PrincipalServiceName multiple values',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalServiceName': ['lambda.amazonaws.com', 'sns.amazonaws.com']
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['lambda.amazonaws.com', 'sns.amazonaws.com'],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: PrincipalServiceName IfExists does NOT extract',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEqualsIfExists: { 'aws:PrincipalServiceName': 'lambda.amazonaws.com' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: PrincipalServiceName with StringLike does NOT extract',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalServiceName': 'lambda.amazonaws.com' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: PrincipalServiceName with StringNotEquals does NOT extract',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringNotEquals: { 'aws:PrincipalServiceName': 'lambda.amazonaws.com' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: PrincipalServiceName with dynamic value does NOT extract',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: { 'aws:PrincipalServiceName': '${aws:PrincipalTag/service}' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  // --- Service-only: Mixed conditions ---
  {
    name: 'Service-only: unnamed key alongside PrincipalAccount — statement skipped',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:SourceAccount': '111111111111',
              'aws:PrincipalAccount': '222222222222'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: unnamed key alongside named key — named wins (extract)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:SourceAccount': '111111111111',
              'aws:PrincipalServiceName': 'lambda.amazonaws.com'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['lambda.amazonaws.com'],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- Service-only: Multiple statements ---
  {
    name: 'Service-only: service-only + narrowed wildcard statements',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceAccount': '111111111111' } }
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalAccount': '333333333333' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['333333333333'],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'Service-only: service-only + unscoped wildcard statements',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceAccount': '111111111111' } }
        },
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'Service-only: service-only + explicit principal statements',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceAccount': '111111111111' } }
        },
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::444444444444:role/R' },
          Action: 's3:GetObject',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['arn:aws:iam::444444444444:role/R'],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- Session ARN conversion (assumed-role) ---
  {
    name: 'should keep unresolved assumed-role session ARN in Principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:sts::666666666666:assumed-role/MyRole/my-session'
          },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['arn:aws:sts::666666666666:assumed-role/MyRole/my-session'],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should keep unresolved path-containing assumed-role session ARN in Principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:sts::666666666666:assumed-role/path/to/MyRole/my-session'
          },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['arn:aws:sts::666666666666:assumed-role/path/to/MyRole/my-session'],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should keep unresolved assumed-role session ARN in PrincipalArn condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:sts::777777777777:assumed-role/SpecificRole/session-123'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:sts::777777777777:assumed-role/SpecificRole/session-123'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should keep unresolved path-containing assumed-role session ARN in PrincipalArn condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn':
                'arn:aws:sts::777777777777:assumed-role/path/to/SpecificRole/session-123'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: [
        'arn:aws:sts::777777777777:assumed-role/path/to/SpecificRole/session-123'
      ],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should keep unresolved exact assumed-role session ARN under ArnLike PrincipalArn condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: {
              'aws:PrincipalArn': 'arn:aws:sts::777777777777:assumed-role/SpecificRole/session-123'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificPrincipals: ['arn:aws:sts::777777777777:assumed-role/SpecificRole/session-123'],
      specificAccounts: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should pass through non-session ARN unchanged in Principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:iam::666666666666:role/RegularRole'
          },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: ['arn:aws:iam::666666666666:role/RegularRole'],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'should handle mix of session ARN and regular ARN in Principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: [
              'arn:aws:sts::666666666666:assumed-role/RoleA/session-1',
              'arn:aws:iam::777777777777:role/RoleB'
            ]
          },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [
        'arn:aws:sts::666666666666:assumed-role/RoleA/session-1',
        'arn:aws:iam::777777777777:role/RoleB'
      ],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  // --- Cross-statement composition ---
  {
    name: 'explicit account principal statement + wildcard PrincipalArn statement unions correctly',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '111111111111' },
          Action: 'sts:AssumeRole',
          Condition: {}
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::222222222222:role/deploy/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['111111111111', '222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'service-only statement skipped + PrincipalArn-narrowed statement narrows correctly',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceAccount': '111111111111' } }
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::333333333333:role/admin-*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['333333333333'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: true,
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },

  // ===== resourceAccountTrustedByPolicy tests =====

  // --- true: open same-account trust ---

  {
    name: 'resourceAccountTrustedByPolicy: true for NotPrincipal Allow',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotPrincipal: { AWS: 'arn:aws:iam::999999999999:role/Excluded' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      allAccounts: true,
      specificAccounts: [],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for wildcard Principal with no conditions',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' }]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      allAccounts: true,
      specificAccounts: [],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for explicit account principal equal to resource account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '000000000000' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['000000000000'],
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for wildcard + PrincipalAccount equal to resource account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalAccount': '000000000000' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['000000000000'],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for wildcard + kms:CallerAccount equal to resource account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'kms:Decrypt',
          Resource: '*',
          Condition: { StringEquals: { 'kms:CallerAccount': '000000000000' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['000000000000'],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for wildcard + PrincipalArn narrowing to resource account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::000000000000:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['000000000000'],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for wildcard + org narrowing (conservative)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-myorg' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: [],
      specificOrganizations: ['o-myorg'],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: true for wildcard + OU narrowing (conservative)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': { 'aws:PrincipalOrgPaths': ['o-aaa/r-bbb/ou-ccc'] }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-ccc'],
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },

  // --- false: should not trigger bulk same-account search ---

  {
    name: 'resourceAccountTrustedByPolicy: false for explicit account principal of another account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '111111111111' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: ['111111111111'],
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for wildcard + PrincipalAccount narrowing to another account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalAccount': '111111111111' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['111111111111'],
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for wildcard + PrincipalArn narrowing to another account',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['111111111111'],
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'checkAllFromResourceAccount: false when same-account explicit grant is combined with unrelated wildcard PrincipalArn narrowing',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '000000000000' },
          Action: '*',
          Resource: '*'
        },
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['000000000000', '111111111111'],
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for wildcard + named service-only condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sts:AssumeRole',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalServiceName': 'lambda.amazonaws.com' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: [],
      specificPrincipals: ['lambda.amazonaws.com'],
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for wildcard + unnamed service-only condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sts:AssumeRole',
          Resource: '*',
          Condition: { Bool: { 'aws:PrincipalIsAWSService': 'true' } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: [],
      specificPrincipals: [],
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for exact same-account role ARN in Principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::000000000000:role/SpecificRole' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: [],
      specificPrincipals: ['arn:aws:iam::000000000000:role/SpecificRole'],
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for exact same-account ARN in PrincipalArn condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::000000000000:role/SpecificRole'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: [],
      specificPrincipals: ['arn:aws:iam::000000000000:role/SpecificRole'],
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  },
  {
    name: 'resourceAccountTrustedByPolicy: false for service-only Principal (not wildcard)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 's3.amazonaws.com' },
          Action: 'sts:AssumeRole',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      specificAccounts: [],
      specificPrincipals: ['s3.amazonaws.com'],
      resourceAccountTrustedByPolicy: false
    }
  },

  // --- negative PrincipalArn operators (should not narrow) ---

  {
    name: 'checkAllFromResourceAccount: true for wildcard + ArnNotLike PrincipalArn (negative operator does not narrow)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sts:AssumeRole',
          Resource: '*',
          Condition: {
            ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/Blocked' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      allAccounts: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'checkAllFromResourceAccount: true for wildcard + StringNotEquals PrincipalArn (negative operator does not narrow)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sts:AssumeRole',
          Resource: '*',
          Condition: {
            StringNotEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::000000000000:role/SpecificRole'
            }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      allAccounts: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'checkAllFromResourceAccount: true for wildcard + StringNotLike PrincipalArn (negative operator does not narrow)',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'kms:Decrypt',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/Blocked*' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      allAccounts: true,
      checkAllFromResourceAccount: true,
      resourceAccountTrustedByPolicy: true
    }
  },
  {
    name: 'negative PrincipalArn combined with positive PrincipalAccount narrows to the account only',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sts:AssumeRole',
          Resource: '*',
          Condition: {
            ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/Blocked' },
            StringEquals: { 'aws:PrincipalAccount': '111111111111' }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      checkAnonymous: true,
      specificAccounts: ['111111111111'],
      checkAllFromResourceAccount: false,
      resourceAccountTrustedByPolicy: false
    }
  }
]

describe('accountsToCheckBasedOnResourcePolicy', () => {
  it('should resolve session principals from resource policies through the collect client', async () => {
    // Given a resource policy that names an STS session ARN without the IAM role path
    const resourcePolicy = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:sts::111122223333:assumed-role/ExampleRole/example-session'
          },
          Action: 's3:ListBucket',
          Resource: 'arn:aws:s3:::example-bucket'
        }
      ]
    }
    const resolvedRoleArn = 'arn:aws:iam::111122223333:role/path/to/ExampleRole'
    const client = {
      resolvePrincipalArn: async (principalArn: string) => {
        if (principalArn === 'arn:aws:sts::111122223333:assumed-role/ExampleRole/example-session') {
          return resolvedRoleArn
        }
        return undefined
      }
    } as unknown as IamCollectClient

    // When accountsToCheckBasedOnResourcePolicy derives the specific principals to search
    const result = await accountsToCheckBasedOnResourcePolicy(
      resourcePolicy,
      '999988887777',
      client
    )

    // Then it should use the fully resolved principal ARN so scoped whoCan calls de-duplicate it correctly
    expect(result.specificPrincipals).toEqual([resolvedRoleArn])
  })

  it('should keep unresolved session principal ARN so it is reported as not found later', async () => {
    // Given a resource policy that names an STS session ARN and a client that cannot resolve the role
    const resourcePolicy = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: 'arn:aws:sts::111122223333:assumed-role/ExampleRole/example-session'
          },
          Action: 's3:ListBucket',
          Resource: 'arn:aws:s3:::example-bucket'
        }
      ]
    }
    const client = {
      resolvePrincipalArn: async () => undefined
    } as unknown as IamCollectClient

    // When accountsToCheckBasedOnResourcePolicy derives the specific principals to search
    const result = await accountsToCheckBasedOnResourcePolicy(
      resourcePolicy,
      '999988887777',
      client
    )

    // Then it should keep the unresolved session ARN for later principalsNotFound reporting
    expect(result.specificPrincipals).toEqual([
      'arn:aws:sts::111122223333:assumed-role/ExampleRole/example-session'
    ])
  })

  it('should resolve session principals extracted from PrincipalArn conditions through the collect client', async () => {
    // Given a wildcard-principal resource policy narrowed by an exact PrincipalArn session condition
    const resourcePolicy = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:ListBucket',
          Resource: 'arn:aws:s3:::example-bucket',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn':
                'arn:aws:sts::111122223333:assumed-role/ExampleRole/example-session'
            }
          }
        }
      ]
    }
    const resolvedRoleArn = 'arn:aws:iam::111122223333:role/path/to/ExampleRole'
    const client = {
      resolvePrincipalArn: async (principalArn: string) => {
        if (principalArn === 'arn:aws:sts::111122223333:assumed-role/ExampleRole/example-session') {
          return resolvedRoleArn
        }
        return undefined
      }
    } as unknown as IamCollectClient

    // When accountsToCheckBasedOnResourcePolicy extracts the condition principal scope
    const result = await accountsToCheckBasedOnResourcePolicy(
      resourcePolicy,
      '999988887777',
      client
    )

    // Then it should use the fully resolved principal ARN from the collect client
    expect(result.specificPrincipals).toEqual([resolvedRoleArn])
  })

  for (const test of accountsToCheckBasedOnResourcePolicyTests) {
    const func = test.only ? it.only : it
    func(test.name, async () => {
      // Given a resource policy and account ID
      const { resourcePolicy, resourceAccountId } = test

      // When accountsToCheckBasedOnResourcePolicy is called
      const result = await accountsToCheckBasedOnResourcePolicy(
        resourcePolicy,
        resourceAccountId,
        noPrincipalResolutionClient
      )

      // Then it should return the expected accounts
      const expected = test.expected
      expect(result.allAccounts).toEqual(!!expected.allAccounts)
      expect(result.specificAccounts).toEqual(expected.specificAccounts || [])
      expect(result.specificPrincipals).toEqual(expected.specificPrincipals || [])
      expect(result.specificOrganizations).toEqual(expected.specificOrganizations || [])
      expect(result.specificOrganizationalUnits).toEqual(expected.specificOrganizationalUnits || [])
      expect(result.checkAnonymous).toEqual(!!expected.checkAnonymous)
      expect(result.checkAllFromResourceAccount).toEqual(!!expected.checkAllFromResourceAccount)
      expect(result.resourceAccountTrustedByPolicy).toEqual(
        !!expected.resourceAccountTrustedByPolicy
      )
    })
  }
})

describe('uniqueAccountsToCheck', () => {
  it('should return all accounts when allAccounts is true', async () => {
    // Given accountsToCheck with allAccounts set to true
    const accountsToCheck: AccountsToCheck = {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }

    // And a client that returns a list of accounts
    const allAccounts = ['11111111111', '222222222222', '333333333333']
    const client = {
      allAccounts: async () => allAccounts
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return an array with a single entry 'all'
    expect(result.accounts).toEqual(allAccounts)
  })

  it('should return unique accounts from specificAccounts', async () => {
    // Given accountsToCheck with specificAccounts
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: ['100000000001', '100000000002', '100000000003'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }

    // And a client that returns which accounts exist
    const client = {
      accountExists: async (accountId: string) => accountId !== '100000000003'
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the unique accounts from specificAccounts
    expect(result.accounts).toEqual(['100000000001', '100000000002'])
  })

  it('should return accounts from an OU', async () => {
    // Given accountsToCheck with specificOrganizationalUnits
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-ccc'],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }

    // And a client that returns accounts for the OU path
    const client = {
      getAccountsForOrgPath: async (orgId: string, ouPath: string[]) => [true, ['111', '222']]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the accounts from the OU
    expect(result.accounts).toEqual(['111', '222'])
    expect(result.organizationalUnitsNotFound).toEqual([])
  })

  it('should return OUs not found', async () => {
    // Given accountsToCheck with specificOrganizationalUnits
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-missing'],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }

    // And a client that returns not found for the OU path
    const client = {
      getAccountsForOrgPath: async (orgId: string, ouPath: string[]) => [false, []]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the OU as not found
    expect(result.accounts).toEqual([])
    expect(result.organizationalUnitsNotFound).toEqual(['o-aaa/r-bbb/ou-missing'])
  })

  it('should return accounts from an organization', async () => {
    // Given accountsToCheck with specificOrganizations
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: ['o-xyz'],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }

    // And a client that returns accounts for the organization
    const client = {
      getAccountsForOrganization: async (orgId: string) => [true, ['123', '456']]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the accounts from the organization
    expect(result.accounts).toEqual(['123', '456'])
    expect(result.organizationsNotFound).toEqual([])
  })

  it('should return organizations not found', async () => {
    // Given accountsToCheck with specificOrganizations
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: ['o-missing'],
      specificOrganizationalUnits: [],
      checkAnonymous: false,
      resourceAccountTrustedByPolicy: false
    }

    // And a client that returns not found for the organization
    const client = {
      getAccountsForOrganization: async (orgId: string) => [false, []]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the organization as not found
    expect(result.accounts).toEqual([])
    expect(result.organizationsNotFound).toEqual(['o-missing'])
  })
})

describe('sortWhoCanResults', () => {
  it('sorts unsigned access alongside principal ARNs', () => {
    //Given collected and anonymous access to the same action
    const allowed = [
      {
        principal: 'arn:aws:iam::123456789012:role/Reader',
        service: 's3',
        action: 'GetObject',
        level: 'read'
      },
      { principal: 'anonymous', service: 's3', action: 'GetObject', level: 'read' }
    ]
    const response: WhoCanResponse = {
      allowed,
      simulationCount: 2,
      allAccountsChecked: false,
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      principalsNotFound: []
    }
    //When sorting for deterministic output
    sortWhoCanResults(response)
    //Then unsigned access sorts lexically before principal ARNs
    expect(response.allowed.map((entry) => entry.principal)).toEqual([
      'anonymous',
      'arn:aws:iam::123456789012:role/Reader'
    ])
  })
  it('should sort allowed results by principal, then service, then action', () => {
    // Given a WhoCanResponse with unsorted allowed results
    const response: WhoCanResponse = {
      simulationCount: 6,
      allowed: [
        {
          principal: 'arn:aws:iam::123456789012:role/RoleC',
          service: 's3',
          action: 'GetObject',
          level: 'object'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'PutObject',
          level: 'object'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'GetObject',
          level: 'object'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleB',
          service: 'dynamodb',
          action: 'GetItem',
          level: 'table'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 'dynamodb',
          action: 'PutItem',
          level: 'table'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 'dynamodb',
          action: 'GetItem',
          level: 'table'
        }
      ],
      allAccountsChecked: true,
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      principalsNotFound: [],
      denyDetails: []
    }

    // When we sort the results
    sortWhoCanResults(response)

    // Then the results should be sorted by principal, then service, then action
    expect(response.allowed).toEqual([
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 'dynamodb',
        action: 'GetItem',
        level: 'table'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 'dynamodb',
        action: 'PutItem',
        level: 'table'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'GetObject',
        level: 'object'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'PutObject',
        level: 'object'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleB',
        service: 'dynamodb',
        action: 'GetItem',
        level: 'table'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleC',
        service: 's3',
        action: 'GetObject',
        level: 'object'
      }
    ])
  })

  it('should sort not found arrays alphabetically', () => {
    // Given a WhoCanResponse with unsorted not found arrays
    const response: WhoCanResponse = {
      simulationCount: 0,
      allowed: [],
      allAccountsChecked: false,
      accountsNotFound: ['333333333333', '111111111111', '222222222222'],
      organizationsNotFound: ['o-zzz', 'o-aaa', 'o-mmm'],
      organizationalUnitsNotFound: ['ou-xxx', 'ou-bbb', 'ou-qqq'],
      principalsNotFound: [
        'arn:aws:iam::123456789012:role/RoleZ',
        'arn:aws:iam::123456789012:role/RoleA',
        'arn:aws:iam::123456789012:role/RoleM'
      ],
      denyDetails: []
    }

    // When we sort the results
    sortWhoCanResults(response)

    // Then all not found arrays should be sorted alphabetically
    expect(response.accountsNotFound).toEqual(['111111111111', '222222222222', '333333333333'])
    expect(response.organizationsNotFound).toEqual(['o-aaa', 'o-mmm', 'o-zzz'])
    expect(response.organizationalUnitsNotFound).toEqual(['ou-bbb', 'ou-qqq', 'ou-xxx'])
    expect(response.principalsNotFound).toEqual([
      'arn:aws:iam::123456789012:role/RoleA',
      'arn:aws:iam::123456789012:role/RoleM',
      'arn:aws:iam::123456789012:role/RoleZ'
    ])
  })

  it('should handle empty arrays', () => {
    // Given a WhoCanResponse with empty arrays
    const response: WhoCanResponse = {
      simulationCount: 0,
      allowed: [],
      allAccountsChecked: true,
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      principalsNotFound: [],
      denyDetails: []
    }

    // When we sort the results
    sortWhoCanResults(response)

    // Then all arrays should remain empty
    expect(response.allowed).toEqual([])
    expect(response.accountsNotFound).toEqual([])
    expect(response.organizationsNotFound).toEqual([])
    expect(response.organizationalUnitsNotFound).toEqual([])
    expect(response.principalsNotFound).toEqual([])
  })

  it('should handle allowed results with identical principals but different services', () => {
    // Given allowed results with same principal but different services
    const response: WhoCanResponse = {
      simulationCount: 3,
      allowed: [
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'GetObject',
          level: 'object'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 'ec2',
          action: 'DescribeInstances',
          level: 'instance'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 'dynamodb',
          action: 'Query',
          level: 'table'
        }
      ],
      allAccountsChecked: true,
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      principalsNotFound: [],
      denyDetails: []
    }

    // When we sort the results
    sortWhoCanResults(response)

    // Then results should be sorted by service
    expect(response.allowed).toEqual([
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 'dynamodb',
        action: 'Query',
        level: 'table'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 'ec2',
        action: 'DescribeInstances',
        level: 'instance'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'GetObject',
        level: 'object'
      }
    ])
  })

  it('should handle allowed results with identical principals and services but different actions', () => {
    // Given allowed results with same principal and service but different actions
    const response: WhoCanResponse = {
      simulationCount: 3,
      allowed: [
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'PutObject',
          level: 'object'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'DeleteObject',
          level: 'object'
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'GetObject',
          level: 'object'
        }
      ],
      allAccountsChecked: true,
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      principalsNotFound: [],
      denyDetails: []
    }

    // When we sort the results
    sortWhoCanResults(response)

    // Then results should be sorted by action
    expect(response.allowed).toEqual([
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'DeleteObject',
        level: 'object'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'GetObject',
        level: 'object'
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'PutObject',
        level: 'object'
      }
    ])
  })

  it('should preserve conditions and other properties during sorting', () => {
    // Given allowed results with conditions and other properties
    const response: WhoCanResponse = {
      simulationCount: 2,
      allowed: [
        {
          principal: 'arn:aws:iam::123456789012:role/RoleB',
          service: 's3',
          action: 'GetObject',
          level: 'object',
          conditions: {
            conditionType: 'condition',
            op: 'StringEquals',
            key: 's3:prefix',
            values: ['test/'],
            sources: [
              {
                policyType: 'identity',
                effect: 'Allow',
                statementIndex: 1
              }
            ]
          },
          ignoredConditions: {
            identity: { allow: [{ op: 'StringEquals', key: 's3:prefix', values: ['test/'] }] }
          },
          dependsOnSessionName: true
        },
        {
          principal: 'arn:aws:iam::123456789012:role/RoleA',
          service: 's3',
          action: 'PutObject',
          level: 'object',
          conditions: {
            conditionType: 'condition',
            op: 'IpAddress',
            key: 'aws:SourceIp',
            values: ['192.168.1.0/24'],
            sources: [
              {
                policyType: 'identity',
                effect: 'Allow',
                statementIndex: 1
              }
            ]
          },
          ignoredConditions: {
            identity: {
              allow: [{ op: 'IpAddress', key: 'aws:SourceIp', values: ['192.168.1.0/24'] }]
            }
          }
        }
      ],
      allAccountsChecked: true,
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      principalsNotFound: [],
      denyDetails: []
    }

    // When we sort the results
    sortWhoCanResults(response)

    // Then results should be sorted and properties preserved
    expect(response.allowed).toEqual([
      {
        principal: 'arn:aws:iam::123456789012:role/RoleA',
        service: 's3',
        action: 'PutObject',
        level: 'object',
        conditions: {
          conditionType: 'condition',
          op: 'IpAddress',
          key: 'aws:SourceIp',
          values: ['192.168.1.0/24'],
          sources: [
            {
              policyType: 'identity',
              effect: 'Allow',
              statementIndex: 1
            }
          ]
        },
        ignoredConditions: {
          identity: {
            allow: [{ op: 'IpAddress', key: 'aws:SourceIp', values: ['192.168.1.0/24'] }]
          }
        }
      },
      {
        principal: 'arn:aws:iam::123456789012:role/RoleB',
        service: 's3',
        action: 'GetObject',
        level: 'object',
        conditions: {
          conditionType: 'condition',
          op: 'StringEquals',
          key: 's3:prefix',
          values: ['test/'],
          sources: [
            {
              policyType: 'identity',
              effect: 'Allow',
              statementIndex: 1
            }
          ]
        },
        ignoredConditions: {
          identity: { allow: [{ op: 'StringEquals', key: 's3:prefix', values: ['test/'] }] }
        },
        dependsOnSessionName: true
      }
    ])
  })
})
