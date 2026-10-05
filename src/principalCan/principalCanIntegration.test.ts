import { expect, test } from 'vitest'
import { getCollectClient } from '../collect/collect.ts'
import { getTestDatasetConfigs } from '../test-datasets/testClient.ts'
import { principalCan, PrincipalCanInput } from './principalCan.ts'

const principalCanIntegrationTests: {
  name: string
  only?: true
  data: string
  input: PrincipalCanInput
  expected: any
}[] = [
  {
    name: 'IAMCollect Role',
    data: '1',
    input: {
      principal: 'arn:aws:iam::100000000002:role/IAMCollect',
      shrinkActionLists: false
    },
    expected: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:ListBucket',
          Resource: ['arn:aws:s3:::no-principal-bucket']
        },
        {
          Effect: 'Allow',
          Action: 'sts:AssumeRole',
          Resource: [
            'arn:aws:iam::100000000002:role/EC2Admin',
            'arn:aws:iam::100000000002:role/IAMCollect'
          ]
        },
        {
          Effect: 'Allow',
          Action: [
            'account:ListRegions',
            'apigateway:GET',
            'dynamodb:GetResourcePolicy',
            'dynamodb:ListTables',
            'dynamodb:ListTagsOfResource',
            'ec2:DescribeVpcEndpoints',
            'ecr:DescribeRepositories',
            'ecr:GetRegistryPolicy',
            'ecr:GetRepositoryPolicy',
            'ecr:ListTagsForResource',
            'elasticfilesystem:DescribeFileSystemPolicy',
            'elasticfilesystem:DescribeFileSystems',
            'elasticfilesystem:ListTagsForResource',
            'glacier:GetVaultAccessPolicy',
            'glacier:ListVaults',
            'iam:GetAccountAuthorizationDetails',
            'iam:GetOpenIDConnectProvider',
            'iam:GetSAMLProvider',
            'iam:ListInstanceProfiles',
            'iam:ListOpenIDConnectProviders',
            'iam:ListOpenIDConnectProviderTags',
            'iam:ListPolicyTags',
            'iam:ListSAMLProviders',
            'iam:ListSAMLProviderTags',
            'kms:ListKeys',
            'lambda:GetPolicy',
            'lambda:ListFunctions',
            'lambda:ListTags',
            'organizations:DescribeOrganization',
            'organizations:DescribePolicy',
            'organizations:DescribeResourcePolicy',
            'organizations:ListAccountsForParent',
            'organizations:ListOrganizationalUnitsForParent',
            'organizations:ListPolicies',
            'organizations:ListPoliciesForTarget',
            'organizations:ListRoots',
            'organizations:ListTagsForResource',
            'ram:GetResourcePolicies',
            'ram:ListResources',
            's3:GetAccessPoint',
            's3:GetAccessPointPolicy',
            's3:GetAccountPublicAccessBlock',
            's3:GetBucketPolicy',
            's3:GetBucketPublicAccessBlock',
            's3:GetBucketTagging',
            's3:GetEncryptionConfiguration',
            's3:GetMultiRegionAccessPointPolicy',
            's3:ListAccessPoints',
            's3:ListAllMyBuckets',
            's3:ListMultiRegionAccessPoints',
            's3:ListTagsForResource',
            's3express:GetBucketPolicy',
            's3express:GetEncryptionConfiguration',
            's3express:ListAllMyDirectoryBuckets',
            's3tables:GetTableBucketEncryption',
            's3tables:GetTableBucketPolicy',
            's3tables:ListTableBuckets',
            'secretsmanager:GetResourcePolicy',
            'secretsmanager:ListSecrets',
            'sns:GetTopicAttributes',
            'sns:ListTagsForResource',
            'sns:ListTopics',
            'sqs:GetQueueAttributes',
            'sqs:ListQueues',
            'sqs:ListQueueTags',
            'sso:DescribePermissionSet',
            'sso:GetInlinePolicyForPermissionSet',
            'sso:GetPermissionsBoundaryForPermissionSet',
            'sso:ListAccountsForProvisionedPermissionSet',
            'sso:ListCustomerManagedPolicyReferencesInPermissionSet',
            'sso:ListInstances',
            'sso:ListManagedPoliciesInPermissionSet',
            'sso:ListPermissionSets',
            'sso:ListTagsForResource'
          ],
          Resource: ['*']
        },
        {
          Effect: 'Allow',
          Action: ['s3:DeleteObject', 's3:GetObject', 's3:ListBucket', 's3:PutObject'],
          Condition: {
            stringequals: {
              'aws:principalorgid': ['o-11111111']
            }
          },
          Resource: ['arn:aws:s3:::iam-data-482734', 'arn:aws:s3:::iam-data-482734/iam-data/*']
        },
        {
          Effect: 'Deny',
          Action: [
            's3:GetAccessPoint',
            's3:GetAccessPointPolicy',
            's3:GetAccountPublicAccessBlock',
            's3:GetBucketPolicy',
            's3:GetBucketPublicAccessBlock',
            's3:GetBucketTagging',
            's3:GetEncryptionConfiguration',
            's3:GetMultiRegionAccessPointPolicy',
            's3:ListAccessPoints',
            's3:ListAllMyBuckets',
            's3:ListMultiRegionAccessPoints',
            's3:ListTagsForResource'
          ],
          Resource: ['arn:aws:s3:::restricted-bucket', 'arn:aws:s3:::restricted-bucket/*']
        }
      ]
    }
  },
  {
    name: 'Role with cross account S3 access',
    data: '1',
    input: {
      principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
      shrinkActionLists: true
    },
    expected: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Condition: {
            stringequals: {
              'aws:principalorgid': ['o-22222222']
            }
          },
          Resource: ['arn:aws:s3:::iam-data-482734']
        },
        {
          Effect: 'Allow',
          Action: ['s3:DeleteObject', 's3:GetObject', 's3:ListBucket', 's3:PutObject'],
          Resource: ['*']
        },
        {
          Effect: 'Allow',
          Action: ['s3:DeleteObject', 's3:ListBucket', 's3:PutObject'],
          Condition: {
            stringequals: {
              'aws:principalorgid': ['o-22222222']
            }
          },
          Resource: ['arn:aws:s3:::iam-data-482734', 'arn:aws:s3:::iam-data-482734/iam-data/*']
        },
        {
          Effect: 'Deny',
          Action: 's3:GetObject',
          Condition: {
            stringequals: {
              'aws:principalorgid': ['o-22222222']
            }
          },
          Resource: ['arn:aws:s3:::anonymous-principal-org-conditions/string-equals']
        },
        {
          Effect: 'Deny',
          Action: 's3:GetObject',
          Condition: {
            stringequalsifexists: {
              'aws:principalorgid': ['o-22222222']
            }
          },
          Resource: ['arn:aws:s3:::anonymous-principal-org-conditions/string-equals-if-exists']
        },
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Condition: {
            arnnotequals: {
              'aws:sourcearn': ['arn:aws:cloudtrail:*:*:trail/*']
            }
          },
          Resource: ['arn:aws:s3:::source-arn-deny-bucket/*']
        },
        {
          Effect: 'Deny',
          Action: ['s3:DeleteObject', 's3:GetObject', 's3:ListBucket', 's3:PutObject'],
          Condition: {
            stringnotequals: {
              'aws:principalarn': ['arn:aws:iam::200000000002:role/VpcBucketRole']
            }
          },
          Resource: ['arn:aws:s3:::vpc-bucket', 'arn:aws:s3:::vpc-bucket/*']
        }
      ]
    }
  }
]

for (const testCase of principalCanIntegrationTests) {
  const testFn = testCase.only ? test.only : test
  testFn(`principalCan Integration Test: ${testCase.name}`, async () => {
    // Given a test data set
    const configs = getTestDatasetConfigs(testCase.data)
    const collectClient = await getCollectClient(configs, 'aws')

    // When we run principalCan
    const result = await principalCan(collectClient, testCase.input)

    // Then the results should match the expected output
    expect(deepSort(result)).toEqual(deepSort(testCase.expected))
  })
}

/**
 * Deep sort an object in place.
 * This will lower case keys for the Condition key objects.
 *
 * @param obj the object to deep sort
 * @param lowerCaseKeys whether to lowercase the keys of objects
 */
function deepSort(obj: any, lowerCaseKeys = false): any {
  if (Array.isArray(obj)) {
    obj.sort(policyComparator)
  } else if (obj !== null && typeof obj === 'object') {
    const keys = Object.keys(obj)
    for (const key of keys) {
      const val = deepSort(obj[key], key === 'Condition' || lowerCaseKeys)
      if (lowerCaseKeys) {
        delete obj[key]
        obj[key.toLowerCase()] = val
      } else {
        obj[key] = val
      }
    }
  }
  return obj
}

/**
 * Compare two policy objects for sorting using deepSort
 *
 * @param a the first object
 * @param b the second object
 * @returns an integer indicating the sort order
 */
function policyComparator(a: any, b: any): number {
  if (typeof a === 'string' && typeof b === 'string') {
    return a.localeCompare(b)
  }

  deepSort(a)
  deepSort(b)

  const aStr = JSON.stringify(a)
  const bStr = JSON.stringify(b)
  return aStr.localeCompare(bStr)
}
