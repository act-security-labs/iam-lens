import { describe, expect, it } from 'vitest'
import {
  applyDenyConditionsToAllow,
  intersectConditions,
  invertConditions,
  Permission,
  PermissionConditions
} from './permission.js'
import {
  convertTestPermissionToPermission,
  expectPermissionsToMatch
} from './permissionSetTestUtils.js'

interface TestPermission {
  effect: 'Allow' | 'Deny'
  action: string
  resource?: string[]
  notResource?: string[]
  conditions?: PermissionConditions
}

const permissionIncludesTests: {
  only?: true
  name: string
  permission: TestPermission
  otherPermission: TestPermission
  included: boolean
}[] = [
  {
    name: 'Wildcard resource matches specific resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    },
    included: true
  },
  {
    name: 'Specific resource does not include wildcard resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    included: false
  },
  {
    name: 'Resource array with multiple patterns includes specific resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*', 'arn:aws:s3:::otherbucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::otherbucket/somefile']
    },
    included: true
  },
  {
    name: 'Resource array with multiple patterns does not include non-matching resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*', 'arn:aws:s3:::otherbucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::thirdbucket/file']
    },
    included: false
  },
  {
    name: 'Permission with resource wildcard includes other permission with notResource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file']
    },
    included: true
  },
  {
    name: 'Permission with notResource includes other permission with resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::otherbucket/file']
    },
    included: true
  },
  {
    name: 'Both permissions using notResource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file', 'arn:aws:s3:::otherbucket/file']
    },
    included: true
  },
  {
    name: 'NotResource with wildcard includes specific not resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    },
    included: true
  },
  {
    name: 'Conditions: StringEquals superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: StringEquals with disjoint values (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['bob']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: Different operators (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringLike: {
          'aws:username': ['alice*']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: NumericLessThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: {
          's3:max-keys': ['100']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: {
          's3:max-keys': ['50']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: NumericGreaterThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericGreaterThan: {
          's3:min-keys': ['10']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericGreaterThan: {
          's3:min-keys': ['20']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: DateLessThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateLessThan: {
          'aws:CurrentTime': ['2024-12-31T23:59:59Z']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateLessThan: {
          'aws:CurrentTime': ['2024-06-30T23:59:59Z']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: DateGreaterThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateGreaterThan: {
          'aws:CurrentTime': ['2024-01-01T00:00:00Z']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateGreaterThan: {
          'aws:CurrentTime': ['2024-06-01T00:00:00Z']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: Bool equals (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: Bool not equal (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['false']
        }
      }
    },
    included: false
  },
  {
    //TODO: Eventually would like to support CIDR overlap checking
    name: 'Conditions: IpAddress superset includes subset (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['192.168.0.0/16']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['192.168.1.1/32']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: ForAllValues:StringEquals superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAllValues:StringEquals': {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAllValues:StringEquals': {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: ForAnyValue:StringEquals superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAnyValue:StringEquals': {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAnyValue:StringEquals': {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: StringEqualsIfExists superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: StringEqualsIfExists with disjoint values (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['alice']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['bob']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: NumericLessThanIfExists superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['100']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['50']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: NumericLessThanIfExists with disjoint boundary (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['50']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['100']
        }
      }
    },
    included: false
  },
  {
    name: 'both notresource permissions',
    permission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/private*', 'arn:aws:s3:::config/*']
    },
    // intersection of notResource => ['arn:aws:s3:::config/*']
    included: true
  },
  {
    name: 'narrower resource with conditions on broader resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['alice'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1']
    },
    included: false
  }
]

describe('Permission#includes', () => {
  for (const test of permissionIncludesTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given a permission and another permission
      const permission = convertTestPermissionToPermission(test.permission)
      const otherPermission = convertTestPermissionToPermission(test.otherPermission)

      //When we check if the permission includes the other permission
      const result = permission.includes(otherPermission)

      //Then the result should match the expected value
      expect(result).toBe(test.included)
    })
  }
})

const permissionUnionTests: {
  only?: true
  name: string

  first: TestPermission
  second: TestPermission
  merged?: boolean | TestPermission
}[] = [
  {
    name: 'merge two with similar resources',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2', 'arn:aws:s3:::mybucket/file3']
    },

    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: [
        'arn:aws:s3:::mybucket/file1',
        'arn:aws:s3:::mybucket/file2',
        'arn:aws:s3:::mybucket/file3'
      ]
    }
  },
  {
    name: 'merge two notResource permissions',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2', 'arn:aws:s3:::mybucket/file3']
    },
    // union of notResource is intersection of arrays => ['arn:aws:s3:::mybucket/file2']
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    }
  },
  {
    name: 'resource and notResource cannot merge, return both',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    }
  },
  {
    name: 'conditions merge for StringEquals',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['alice'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['bob'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:username': ['alice', 'bob'] }
      }
    }
  },
  {
    name: 'do not merge correlated differences in two condition keys',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-a'], 'aws:SourceVpce': ['vpce-a'] } }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-b'], 'aws:SourceVpce': ['vpce-b'] } }
    },
    merged: false
  },
  {
    name: 'do not merge correlated differences across operators',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-a'] },
        NumericLessThan: { 'example:limit': ['10'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-b'] },
        NumericLessThan: { 'example:limit': ['20'] }
      }
    },
    merged: false
  },
  {
    name: 'merge one varying key when another value set is reordered and duplicated',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-a', 'vpc-b'], 'aws:SourceVpce': ['vpce-a'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-b', 'vpc-a', 'vpc-a'], 'aws:SourceVpce': ['vpce-b'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        stringequals: {
          'aws:sourcevpc': ['vpc-a', 'vpc-b'],
          'aws:sourcevpce': ['vpce-a', 'vpce-b']
        }
      }
    }
  },
  {
    name: 'merge one varying key with an unchanged numeric condition',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-a'] },
        NumericLessThan: { 'example:limit': ['10'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-b'] },
        NumericLessThan: { 'example:limit': ['10'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:sourcevpc': ['vpc-a', 'vpc-b'] },
        numericlessthan: { 'example:limit': ['10'] }
      }
    }
  },
  {
    name: 'do not merge opposing subset differences in two condition keys',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-a', 'vpc-b'], 'aws:SourceVpce': ['vpce-a'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-a'], 'aws:SourceVpce': ['vpce-a', 'vpce-b'] }
      }
    },
    merged: false
  },
  {
    name: 'conditions cannot merge different operators',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['alice'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 's3:max-keys': ['50'] }
      }
    },
    merged: false
  },
  {
    name: 'merge wildcard and specific resources',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    }
  },
  {
    name: 'merge notResource wildcards intersection',
    first: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    second: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::stuff/*', 'arn:aws:s3:::config/*']
    },
    // intersection of notResource => ['arn:aws:s3:::config/*']
    merged: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::config/*']
    }
  },
  {
    name: 'merge multiple condition operators',
    first: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] },
        Bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-456'] },
        Bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123', 'o-456'] },
        bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    }
  },
  {
    name: 'cannot merge condition if values disjoint under different keys',
    first: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:sourcevpce': ['vpce-1a2b'] }
      }
    },
    merged: false
  },
  {
    name: 'merge ForAllValues and ForAnyValue conditions',
    first: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        'forallvalues:stringequals': { 'aws:lambdaexecpolicies': ['PolicyA', 'PolicyB'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        'forallvalues:stringequals': { 'aws:lambdaexecpolicies': ['PolicyC'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        'forallvalues:stringequals': { 'aws:lambdaexecpolicies': ['PolicyA', 'PolicyB', 'PolicyC'] }
      }
    }
  },
  {
    name: 'non overlapping',
    first: {
      action: 's3:ListBucket',
      effect: 'Allow',
      resource: ['*'],
      conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
    },
    second: {
      action: 's3:ListBucket',
      effect: 'Allow',
      resource: ['*'],
      conditions: { StringEquals: { 'aws:RequestTag/Department': ['Test'] } }
    },
    merged: false
  }
]

describe('Permission#union', () => {
  for (const test of permissionIncludesTests.filter((t) => t.included)) {
    const func = test.only ? it.only : it
    func(`includes test for: ${test.name}`, () => {
      //Given a permission and another permission that includes it
      const [thisService, thisAction] = test.permission.action.split(':')
      const firstPermission = new Permission(
        test.permission.effect,
        thisService,
        thisAction,
        test.permission.resource,
        test.permission.notResource,
        test.permission.conditions
      )

      const [secondService, secondAction] = test.otherPermission.action.split(':')
      const secondPermission = new Permission(
        test.otherPermission.effect,
        secondService,
        secondAction,
        test.otherPermission.resource,
        test.otherPermission.notResource,
        test.otherPermission.conditions
      )

      //When we check if the permission includes the other permission
      const result = firstPermission.union(secondPermission)

      //Then they should be merged
      expect(result.length).toEqual(1)
      const mergedPermission = result[0]
      expect(mergedPermission.effect).toBe(firstPermission.effect)
      expect(mergedPermission.action).toBe(firstPermission.action)
      expect(mergedPermission.resource).toEqual(firstPermission.resource)
      expect(mergedPermission.notResource).toEqual(firstPermission.notResource)
      expect(mergedPermission.conditions).toEqual(firstPermission.conditions)
    })
  }

  for (const test of permissionUnionTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given two permissions
      const [firstService, firstAction] = test.first.action.split(':')
      const firstPermission = new Permission(
        test.first.effect,
        firstService,
        firstAction,
        test.first.resource,
        test.first.notResource,
        test.first.conditions
      )

      const [secondService, secondAction] = test.second.action.split(':')
      const secondPermission = new Permission(
        test.second.effect,
        secondService,
        secondAction,
        test.second.resource,
        test.second.notResource,
        test.second.conditions
      )

      //When we merge the permissions
      let result: Permission[] | null = null
      result = firstPermission.union(secondPermission)

      //Then the result should match the expected value
      if (test.merged === false) {
        expectPermissionsToMatch(result, [test.first, test.second])
      } else if (test.merged) {
        expect(result.length).toEqual(1)
        const expectedMerge = test.merged as TestPermission
        const [expectedService, expectedAction] = expectedMerge.action.split(':')
        const actualMerge = result[0]
        expect(actualMerge.effect).toBe(expectedMerge.effect)
        expect(actualMerge.service).toBe(expectedService)
        expect(actualMerge.action).toBe(expectedAction)
        expect(actualMerge.resource).toEqual(expectedMerge.resource)
        expect(actualMerge.notResource).toEqual(expectedMerge.notResource)
        expect(actualMerge.conditions).toEqual(expectedMerge.conditions)
      } else {
        expect(true, 'This should never happen').toBe(false)
      }
    })
  }
})

const intersectionTests: {
  only?: true
  name: string
  permission: TestPermission
  otherPermission: TestPermission
  intersection: TestPermission | false
}[] = [
  {
    name: 'one includes the other (wildcard)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    }
  },
  {
    name: 'intersection of two specific resource lists',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2', 'arn:aws:s3:::mybucket/file3']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2']
    }
  },
  {
    name: 'intersection of two notResource lists with overlap',
    permission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/private*', 'arn:aws:s3:::config/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    }
  },

  {
    name: 'intersection of two notResource lists without overlap',
    permission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::logs/*', 'arn:aws:s3:::config/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*', 'arn:aws:s3:::logs/*']
    }
  },
  {
    name: 'intersection with matching conditions',
    permission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123', 'o-456'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    }
  },
  {
    name: 'intersection with different conditions merges conditions',
    permission: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-abc'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123'], 'aws:sourcevpc': ['vpc-abc'] }
      }
    }
  },
  {
    name: 'intersection of wildcard resource patterns',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file*']
    }
  },
  {
    name: 'intersection of disjoint wildcard resources (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::otherbucket/*']
    },
    intersection: false
  },
  {
    name: 'intersection carries through distinct condition keys',
    permission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        Bool: { 'aws:MultiFactorAuthPresent': ['true'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123'] },
        bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    }
  },
  {
    name: 'intersection of numeric and date conditions',
    permission: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 'lambda:timeout': ['300'] },
        DateGreaterThanEquals: { 'aws:CurrentTime': ['2024-01-01T00:00:00Z'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 'lambda:timeout': ['200'] },
        DateGreaterThanEquals: { 'aws:CurrentTime': ['2024-06-01T00:00:00Z'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 'lambda:timeout': ['200'] },
        DateGreaterThanEquals: { 'aws:CurrentTime': ['2024-06-01T00:00:00Z'] }
      }
    }
  },
  {
    name: 'intersection of notResource with wildcard and specific',
    permission: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/secure-*']
    },
    intersection: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/*']
    }
  },
  {
    name: 'intersection with no overlapping notResource (union exclusions)',
    permission: {
      effect: 'Allow',
      action: 'sqs:ReceiveMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/alpha']
    },
    otherPermission: {
      effect: 'Allow',
      action: 'sqs:ReceiveMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/beta']
    },
    intersection: {
      effect: 'Allow',
      action: 'sqs:ReceiveMessage',
      notResource: [
        'arn:aws:sqs:us-east-1:123456789012:queue/alpha',
        'arn:aws:sqs:us-east-1:123456789012:queue/beta'
      ]
    }
  },
  {
    name: 'intersection of two StringEquals with overlap',
    permission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['111111111111', '222222222222'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['222222222222', '333333333333'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalaccountid': ['222222222222'] }
      }
    }
  },
  {
    name: 'intersection of two StringEquals with no overlap (false)',
    permission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['111111111111'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['222222222222'] }
      }
    },
    intersection: false
  },
  {
    name: 'intersection of two StringNotEquals',
    permission: {
      effect: 'Allow',
      action: 'iam:CreateUser',
      resource: ['*'],
      conditions: {
        StringNotEquals: { 'aws:username': ['alice'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'iam:CreateUser',
      resource: ['*'],
      conditions: {
        StringNotEquals: { 'aws:username': ['bob'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'iam:CreateUser',
      resource: ['*'],
      conditions: {
        stringnotequals: { 'aws:username': ['alice', 'bob'] }
      }
    }
  },
  {
    name: 'intersection of StringEquals and StringNotEquals on same key',
    permission: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['111111111111', '222222222222'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        StringNotEquals: { 'aws:principalaccountid': ['222222222222'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalaccountid': ['111111111111', '222222222222'] },
        stringnotequals: { 'aws:principalaccountid': ['222222222222'] }
      }
    }
  },
  {
    name: 'intersection of resource and notResource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1', 'arn:aws:s3:::bucket1/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1']
    }
  },
  {
    name: 'intersection of notResource and resource reversed',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1', 'arn:aws:s3:::bucket1/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1']
    }
  },
  {
    name: 'intersection of resource list and notResource exclusion',
    permission: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::mybucket/logs/*', 'arn:aws:s3:::mybucket/data/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::mybucket/data/private/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::mybucket/logs/*', 'arn:aws:s3:::mybucket/data/*']
    }
  },
  {
    name: 'intersection of notResource exclusion and resource list',
    permission: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      notResource: ['arn:aws:dynamodb:us-west-2:123456789012:table/private-*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      resource: [
        'arn:aws:dynamodb:us-west-2:123456789012:table/public-users',
        'arn:aws:dynamodb:us-west-2:123456789012:table/private-data'
      ]
    },
    intersection: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      resource: ['arn:aws:dynamodb:us-west-2:123456789012:table/public-users']
    }
  },

  {
    name: 'intersection resource fully excluded by notResource yields undefined',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    intersection: false
  },
  {
    name: 'intersection of narrower resource with conditions on broader resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['alice'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1'],
      conditions: {
        stringequals: { 'aws:username': ['alice'] }
      }
    }
  },
  {
    name: 'intersection of wildcard resource with specific resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket', 'arn:aws:s3:::mybucket/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket', 'arn:aws:s3:::mybucket/*']
    }
  },
  {
    name: 'intersection of specific resource with wildcard resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket', 'arn:aws:s3:::mybucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket', 'arn:aws:s3:::mybucket/*']
    }
  }
]

describe('Permission#intersection', () => {
  for (const test of intersectionTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given two permissions
      const [firstService, firstAction] = test.permission.action.split(':')
      const firstPermission = new Permission(
        test.permission.effect,
        firstService,
        firstAction,
        test.permission.resource,
        test.permission.notResource,
        test.permission.conditions
      )

      const [secondService, secondAction] = test.otherPermission.action.split(':')
      const secondPermission = new Permission(
        test.otherPermission.effect,
        secondService,
        secondAction,
        test.otherPermission.resource,
        test.otherPermission.notResource,
        test.otherPermission.conditions
      )

      //When we get the intersection of the permissions
      const result = firstPermission.intersection(secondPermission)

      //Then the result should match the expected value
      if (test.intersection === false) {
        expect(result).toBeUndefined()
      } else {
        expect(result).toBeDefined()
        const actualResult = result as Permission
        const expectedIntersection = test.intersection as TestPermission
        const [expectedService, expectedAction] = expectedIntersection.action.split(':')
        expect(actualResult.effect).toBe(expectedIntersection.effect)
        expect(actualResult.service).toBe(expectedService)
        expect(actualResult.action).toBe(expectedAction)
        expect(actualResult.resource).toEqual(expectedIntersection.resource)
        expect(actualResult.notResource).toEqual(expectedIntersection.notResource)
        expect(actualResult.conditions).toEqual(expectedIntersection.conditions)
      }
    })
  }
})

const subtractTests: {
  only?: true
  name: string
  allow: TestPermission
  deny: TestPermission
  expected: TestPermission[]
}[] = [
  /**
   * Scenario 1: Allow.Resource & Deny.Resource
   **/
  {
    name: 'Allow.Resource & Deny.Resource - Deny subset of allowed strings',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::mybucket/file1']
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.Resource with Conditions - Deny has multiple conditions',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/MyRole'],
      conditions: {
        StringNotLike: {
          'aws:PrincipalArn': ['arn:aws:iam::*:root']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        Null: {
          'sts:ExternalId': ['true']
        },
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-11111111']
        },
        BoolIfExists: {
          'aws:PrincipalIsAWSService': ['false']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/MyRole'],
        conditions: {
          StringNotLike: {
            'aws:PrincipalArn': ['arn:aws:iam::*:root']
          },
          Null: {
            'sts:ExternalId': ['false']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/MyRole'],
        conditions: {
          StringNotLike: {
            'aws:PrincipalArn': ['arn:aws:iam::*:root']
          },
          StringEquals: {
            'aws:PrincipalOrgId': ['o-11111111']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/MyRole'],
        conditions: {
          StringNotLike: {
            'aws:PrincipalArn': ['arn:aws:iam::*:root']
          },
          BoolIfExists: {
            'aws:PrincipalIsAWSService': ['true']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource - Identical resources',
    allow: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      resource: ['arn:aws:sqs:us-east-1:123:queue/myqueue']
    },
    deny: {
      effect: 'Deny',
      action: 'sqs:SendMessage',
      resource: ['arn:aws:sqs:us-east-1:123:queue/myqueue']
    },
    expected: []
  },
  {
    name: 'Allow.Resource & Deny.Resource - Both wildcards',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['*']
    },
    expected: []
  },
  {
    name: 'Allow.Resource with Conditions & Deny.Resource with Conditions - Identical conditions',
    allow: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    expected: []
  },
  {
    name: 'Allow.Resource with Conditions & Deny.Resource with Conditions - Allow conditions superset',
    allow: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123', 'o-456'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'ec2:StartInstances',
        resource: ['*'],
        conditions: {
          stringequals: { 'aws:principalorgid': ['o-456'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource - Deny is subset',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/private/extra-private/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket2/private/*']
      },
      {
        effect: 'Deny',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket2/private/extra-private/*']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource - Deny nested wildcard',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/private/extra/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket/private/*']
      },
      {
        effect: 'Deny',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket/private/extra/*']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource - Identical specific resource',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/file']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/file']
    },
    expected: []
  },
  {
    name: 'Allow.Resource & Deny.Resource with Conditions - Both wildcard, deny has conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-abc123']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        conditions: {
          StringEquals: {
            'aws:PrincipalOrgId': ['o-abc123']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource with Conditions - Multiple deny conditions',
    allow: { effect: 'Allow', action: 'backup:GetBackupVaultAccessPolicy', resource: ['*'] },
    deny: {
      effect: 'Deny',
      action: 'backup:GetBackupVaultAccessPolicy',
      resource: ['*'],
      conditions: {
        StringLike: { 'aws:PrincipalArn': ['arn:aws:iam::*:root'] },
        Null: { 'aws:AssumedRoot': ['true'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'backup:GetBackupVaultAccessPolicy',
        resource: ['*'],
        conditions: {
          StringNotLike: { 'aws:PrincipalArn': ['arn:aws:iam::*:root'] }
        }
      },
      {
        effect: 'Allow',
        action: 'backup:GetBackupVaultAccessPolicy',
        resource: ['*'],
        conditions: {
          Null: { 'aws:AssumedRoot': ['false'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource with Conditions - Subset with multiple conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/sensitive/*'],
      conditions: {
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-abc123']
        },
        IpAddress: {
          'aws:SourceIp': ['10.0.0.0/8']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::mybucket/*']
      },
      {
        effect: 'Deny',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::mybucket/sensitive/*'],
        conditions: {
          StringNotEquals: {
            'aws:PrincipalOrgId': ['o-abc123']
          },
          IpAddress: {
            'aws:SourceIp': ['10.0.0.0/8']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource - Disjointed resources',
    allow: {
      effect: 'Allow',
      action: 's3:ListBucket',
      resource: ['arn:aws:s3:::mybucket']
    },
    deny: {
      effect: 'Deny',
      action: 's3:ListBucket',
      resource: ['arn:aws:s3:::otherbucket']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:ListBucket',
        resource: ['arn:aws:s3:::mybucket']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource with Conditions - Disjoint resources',
    allow: {
      effect: 'Allow',
      action: 's3:ListBucket',
      resource: ['arn:aws:s3:::mybucket']
    },
    deny: {
      effect: 'Deny',
      action: 's3:ListBucket',
      resource: ['arn:aws:s3:::otherbucket'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgId': ['o-abc123']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:ListBucket',
        resource: ['arn:aws:s3:::mybucket']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource with Conditions - Wildcard allow, subset deny',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::vpc-bucket/*', 'arn:aws:s3:::vpc-bucket'],
      conditions: {
        StringNotEquals: {
          'aws:PrincipalArn': ['arn:aws:iam::200000000002:role/VpcBucketRole']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['*']
      },
      {
        effect: 'Deny',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::vpc-bucket/*', 'arn:aws:s3:::vpc-bucket'],
        conditions: {
          StringNotEquals: {
            'aws:PrincipalArn': ['arn:aws:iam::200000000002:role/VpcBucketRole']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.Resource with Conditions - Deny superset resources',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::iam-data-482734/iam-data/*', 'arn:aws:s3:::iam-data-482734'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgId': ['o-22222222']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::iam-data-482734/*'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgId': ['o-22222222']
        }
      }
    },
    // Everything in the allow is denied by the deny, should return nothing
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::iam-data-482734'],
        conditions: {
          StringEquals: {
            'aws:PrincipalOrgId': ['o-22222222']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.Resource with Conditions - Multiple deny conditions invert',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['*'],
      conditions: {
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-abc123']
        },
        IpAddress: {
          'aws:SourceIp': ['185.7.16.19']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::mybucket/*'],
        conditions: {
          StringEquals: {
            'aws:PrincipalOrgId': ['o-abc123']
          }
        }
      },
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::mybucket/*'],
        conditions: {
          NotIpAddress: {
            'aws:SourceIp': ['185.7.16.19']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.Resource with Conditions - Both have conditions, deny inverts',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::mybucket/*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['*'],
      conditions: {
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-abc123']
        },
        IpAddress: {
          'aws:SourceIp': ['185.7.16.19']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::mybucket/*'],
        conditions: {
          Bool: {
            'aws:SecureTransport': ['true']
          },
          StringEquals: {
            'aws:PrincipalOrgId': ['o-abc123']
          }
        }
      },
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::mybucket/*'],
        conditions: {
          Bool: {
            'aws:SecureTransport': ['true']
          },
          NotIpAddress: {
            'aws:SourceIp': ['185.7.16.19']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.Resource with Conditions - Subset deny with multiple conditions',
    allow: {
      effect: 'Allow',
      action: 'dynamodb:GetItem',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': ['us-west-2']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'dynamodb:GetItem',
      resource: ['arn:aws:dynamodb:*:*:table/SensitiveTable'],
      conditions: {
        Null: {
          'dynamodb:LeadingKeys': ['true']
        },
        Bool: {
          'aws:SecureTransport': ['false']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'dynamodb:GetItem',
        resource: ['*'],
        conditions: {
          StringEquals: {
            'aws:RequestedRegion': ['us-west-2']
          }
        }
      },
      {
        effect: 'Deny',
        action: 'dynamodb:GetItem',
        resource: ['arn:aws:dynamodb:*:*:table/SensitiveTable'],
        conditions: {
          Null: {
            'dynamodb:LeadingKeys': ['true']
          },
          Bool: {
            'aws:SecureTransport': ['false']
          }
        }
      }
    ]
  },
  /**
   * Scenario 2: Allow.Resource & Deny.NotResource
   **/
  {
    name: 'Allow.Resource & Deny.NotResource - Deny excludes part of allowed strings',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1', 'arn:aws:s3:::bucket1/file2']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket1/file2']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource - Deny subsets of allowed wildcard',
    allow: {
      effect: 'Allow',
      action: 's3:ListBucket',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:ListBucket',
      notResource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-*/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:ListBucket',
        resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-*/*']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource with Conditions - Deny subsets of allowed wildcard',
    allow: {
      effect: 'Allow',
      action: 's3:ListBucket',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:ListBucket',
      notResource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-*/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:ListBucket',
        resource: ['*'],
        conditions: {
          StringNotEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      },
      {
        effect: 'Allow',
        action: 's3:ListBucket',
        resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-*/*']
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - No overlap, identical conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*', 'arn:aws:s3:::test-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: []
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - No overlap, different conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*', 'arn:aws:s3:::test-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-bucket/*'],
        conditions: {
          StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] },
          StringNotEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Allow conditions superset of deny',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: {
          'aws:SourceVpc': ['vpc-12345678', 'vpc-87654321']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-bucket/*'],
        conditions: {
          stringequals: {
            'aws:sourcevpc': ['vpc-87654321']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Deny conditions superset of allow',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: {
          'aws:SourceVpc': ['vpc-12345678', 'vpc-87654321']
        }
      }
    },
    expected: []
  },
  {
    name: 'Allow.Resource & Deny.NotResource with Conditions - No overlap',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-bucket/*'],
        conditions: {
          StringNotEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Allow superset, identical conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Allow superset, different conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::*'],
        conditions: {
          StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] },
          StringNotEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      },
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*'],
        conditions: {
          StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Allow superset, allow conditions superset',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::*'],
      conditions: {
        StringEquals: {
          'aws:SourceVpc': ['vpc-12345678', 'vpc-87654321']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::*'],
        conditions: {
          StringEquals: {
            'aws:SourceVpc': ['vpc-87654321']
          }
        }
      },
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*'],
        conditions: {
          StringEquals: {
            'aws:SourceVpc': ['vpc-12345678', 'vpc-87654321']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Resource in NotResource, identical conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::dev-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::dev-bucket/*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Resource in NotResource, different conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::dev-bucket/*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::dev-bucket/*'],
        conditions: {
          StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Partial overlap, identical conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::stage-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Partial overlap, different conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::stage-*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*'],
        conditions: {
          StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
        }
      },
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::stage-*'],
        conditions: {
          StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] },
          StringNotEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Full overlap, allow has multiple conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: {
          'aws:SourceVpc': ['vpc-12345678'],
          'aws:PrincipalOrgId': ['o-abc123']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    expected: []
  },
  {
    name: 'Allow.Resource & Deny.NotResource with Conditions - Deny has multiple conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: {
          'aws:SourceVpc': ['vpc-12345678'],
          'aws:PrincipalOrgId': ['o-abc123']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-bucket/*'],
        conditions: {
          StringNotEquals: {
            'aws:PrincipalOrgId': ['o-abc123']
          }
        }
      },
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-bucket/*'],
        conditions: {
          StringNotEquals: {
            'aws:SourceVpc': ['vpc-12345678']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Conflicting condition',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*'],
      conditions: {
        StringEquals: {
          'aws:SourceVpc': ['vpc-12345678'],
          'aws:PrincipalOrgId': ['o-abc123']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-bucket/*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] },
          StringNotEquals: {
            'aws:PrincipalOrgId': ['o-abc123']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource - Full overlap',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::prod-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-*']
    },
    expected: []
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Resource in NotResource',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::dev-bucket/*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::dev-bucket/*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-abc123'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::dev-bucket/*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource - Allow superset',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::stage-*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::stage-*']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource with Conditions - Multiple deny conditions',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/MyRole']
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      notResource: ['arn:aws:iam::100000000002:role/TestCrossAccount'],
      conditions: {
        StringLike: {
          'aws:PrincipalArn': ['arn:aws:iam::*:root']
        },
        Null: {
          'aws:AssumedRoot': ['true']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/MyRole'],
        conditions: {
          StringNotLike: {
            'aws:PrincipalArn': ['arn:aws:iam::*:root']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/MyRole'],
        conditions: {
          Null: {
            'aws:AssumedRoot': ['false']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Wildcard allow',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::prod-*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-111111'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] },
          StringNotEquals: { 'aws:PrincipalOrgId': ['o-111111'] }
        }
      },
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::prod-*'],
        conditions: {
          StringEquals: { 'aws:SourceVpc': ['vpc-12345678'] }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource - Resource in NotResource',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket/*']
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource - Disjoint patterns',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/data/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/logs/*']
    },
    expected: []
  },
  {
    name: 'Allow.Resource & Deny.NotResource with Conditions - Wildcard allow, multiple deny conditions',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      notResource: ['arn:aws:iam::519455788571:role/TestCrossAccount'],
      conditions: {
        Null: {
          'sts:ExternalId': ['true']
        },
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-uch56v3mmz']
        },
        BoolIfExists: {
          'aws:PrincipalIsAWSService': ['false']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['*'],
        conditions: {
          Null: {
            'sts:externalid': ['false']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['*'],
        conditions: {
          StringEquals: {
            'aws:principalorgid': ['o-uch56v3mmz']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['*'],
        conditions: {
          BoolIfExists: {
            'aws:principalisawsservice': ['true']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::519455788571:role/TestCrossAccount']
      }
    ]
  },
  {
    name: 'Allow.Resource with Conditions & Deny.NotResource with Conditions - Wildcard allow with condition',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': ['us-east-1']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      notResource: ['arn:aws:iam::519455788571:role/TestCrossAccount'],
      conditions: {
        Null: {
          'sts:ExternalId': ['true']
        },
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-uch56v3mmz']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['*'],
        conditions: {
          StringEquals: {
            'aws:RequestedRegion': ['us-east-1']
          },
          Null: {
            'sts:ExternalId': ['false']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['*'],
        conditions: {
          StringEquals: {
            'aws:RequestedRegion': ['us-east-1'],
            'aws:PrincipalOrgId': ['o-uch56v3mmz']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::519455788571:role/TestCrossAccount'],
        conditions: {
          StringEquals: {
            'aws:RequestedRegion': ['us-east-1']
          }
        }
      }
    ]
  },
  {
    name: 'Allow.Resource & Deny.NotResource with Conditions - Different NotResource, multiple conditions',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::100000000002:role/EC2Admin']
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      notResource: ['arn:aws:iam::100000000002:role/TestCrossAccount'],
      conditions: {
        Null: {
          'sts:ExternalId': ['true']
        },
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-11111111']
        },
        BoolIfExists: {
          'aws:PrincipalIsAWSService': ['false']
        }
      }
    },
    expected: [
      // We invert all deny conditions with separate allows
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::100000000002:role/EC2Admin'],
        conditions: {
          Null: {
            'sts:externalid': ['false']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::100000000002:role/EC2Admin'],
        conditions: {
          StringEquals: {
            'aws:PrincipalOrgId': ['o-11111111']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::100000000002:role/EC2Admin'],
        conditions: {
          //TODO: This should be Bool, not BoolIfExists
          BoolIfExists: {
            'aws:PrincipalIsAWSService': ['true']
          }
        }
      }
    ]
  },
  /**
   * Scenario 3: Allow.NotResource & Deny.Resource
   **/
  {
    name: 'Allow.NotResource & Deny.Resource - Disjointed patterns',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket2/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/logs/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket2/private/*', 'arn:aws:s3:::bucket2/logs/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - Deny already excluded',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket2/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/private/extra-private/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket2/private/*']
      }
    ]
  },
  // ============================================================================
  // Allow NotResource & Deny Resource - Category Tests
  // ============================================================================
  {
    name: 'Allow.NotResource & Deny.Resource - Identical patterns',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/secret/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket/secret/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource with Conditions & Deny.Resource with Conditions - Identical patterns, different conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*'],
      conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-123'] } }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/secret/*'],
      conditions: { StringEquals: { 'aws:PrincipalTag/team': ['admin'] } }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket/secret/*'],
        conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-123'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - NotResource covers Resource',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::bucket/logs/app.log']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        notResource: ['arn:aws:s3:::bucket/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource with Conditions & Deny.Resource with Conditions - NotResource covers Resource, different conditions',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/*'],
      conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-abc'] } }
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::bucket/logs/*'],
      conditions: { Bool: { 'aws:SecureTransport': ['false'] } }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        notResource: ['arn:aws:s3:::bucket/*'],
        conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-abc'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - Deny expands exclusion',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/private/file.txt']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/private/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket/private/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource with Conditions - Deny expands exclusion conditionally',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/private/file.txt']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/private/*'],
      conditions: { StringEquals: { 'aws:PrincipalTag/role': ['intern'] } }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket/private/file.txt'],
        conditions: { StringNotEquals: { 'aws:PrincipalTag/role': ['intern'] } }
      },
      // When role = intern: expanded exclusion (deny applies, must exclude more)
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket/private/*'],
        conditions: { StringEquals: { 'aws:PrincipalTag/role': ['intern'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - No overlap',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket-a/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket-b/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource with Conditions - No overlap',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket-a/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket-b/*'],
      conditions: { IpAddress: { 'aws:SourceIp': ['192.168.1.0/24'] } }
    },
    expected: [
      // When SourceIp ≠ 192.168.1.0/24: original allow (deny doesn't apply)
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket-a/*'],
        conditions: { NotIpAddress: { 'aws:SourceIp': ['192.168.1.0/24'] } }
      },
      // When SourceIp = 192.168.1.0/24: expanded exclusion (deny applies)
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - Multiple patterns',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/*', 'arn:aws:s3:::bucket/logs/app.log']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::bucket/logs/*', 'arn:aws:s3:::bucket/archive/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        notResource: [
          'arn:aws:s3:::bucket/private/*',
          'arn:aws:s3:::bucket/logs/*',
          'arn:aws:s3:::bucket/archive/*'
        ]
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - All deny patterns covered',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/a/*', 'arn:aws:s3:::bucket/b/*', 'arn:aws:s3:::bucket/c/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource with Conditions & Deny.Resource - Allow has conditions',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/keep/*'],
      conditions: { StringEquals: { 'aws:PrincipalTag/team': ['ops'] } }
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/protected/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket/keep/*', 'arn:aws:s3:::bucket/protected/*'],
        conditions: { StringEquals: { 'aws:PrincipalTag/team': ['ops'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource with Conditions - Deny has multiple operators',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/data/*'],
      conditions: {
        StringEquals: { 'aws:PrincipalTag/team': ['external'] },
        Bool: { 'aws:SecureTransport': ['false'] }
      }
    },
    expected: [
      // When team ≠ external: original allow (deny doesn't apply)
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket/secret/*'],
        conditions: { StringNotEquals: { 'aws:PrincipalTag/team': ['external'] } }
      },
      // When SecureTransport ≠ false: original allow (deny doesn't apply)
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket/secret/*'],
        conditions: { Bool: { 'aws:SecureTransport': ['true'] } }
      },
      // Expanded exclusion - no conditions needed since deny resource is excluded
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::bucket/secret/*', 'arn:aws:s3:::bucket/data/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - Wildcard notResource',
    allow: {
      effect: 'Allow',
      action: 'dynamodb:GetItem',
      notResource: ['arn:aws:dynamodb:*:*:table/admin-*']
    },
    deny: {
      effect: 'Deny',
      action: 'dynamodb:GetItem',
      resource: ['arn:aws:dynamodb:us-east-1:123:table/users']
    },
    expected: [
      {
        effect: 'Allow',
        action: 'dynamodb:GetItem',
        notResource: [
          'arn:aws:dynamodb:*:*:table/admin-*',
          'arn:aws:dynamodb:us-east-1:123:table/users'
        ]
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.Resource - Union exclusions',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/data/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::bucket/logs/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        notResource: ['arn:aws:s3:::bucket/data/*', 'arn:aws:s3:::bucket/logs/*']
      }
    ]
  },
  /*
   * Allow NotResource & Deny NotResource - Scenario 4 Tests
   *
   * SEMANTICS:
   *   Allow.notResource: "allow everything EXCEPT these patterns"
   *   Deny.notResource: "deny everything EXCEPT these patterns"
   *
   *   The deny applies to resources NOT in denyNotResource.
   *   Result: allow only resources that are allowed AND not denied
   *           = NOT in allowNotResource AND IN denyNotResource
   *
   * Allow NotResource = U \ A
   * Deny NotResource = U \ B
   *
   * Identity Formula:
   * X \ (U \ Y) = X ∩ Y
   *
   * Replace Variables:
   * X = U \ A
   * Y = B
   *
   * (U \ A) \ (U \ B) = (U \ A) ∩ B
   *
   * Simplify:
   * (U \ A) \ (U \ B) = B \ A
   *
   */
  {
    name: 'Allow.NotResource & Deny.NotResource - Allow excludes more',
    allow: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      notResource: [
        'arn:aws:dynamodb:us-west-2:123:table/data/*',
        'arn:aws:dynamodb:us-west-2:123:table/logs/*'
      ]
    },
    deny: {
      effect: 'Deny',
      action: 'dynamodb:PutItem',
      notResource: ['arn:aws:dynamodb:us-west-2:123:table/logs/*']
    },
    // All deny patterns (logs/*) are covered by allow patterns (logs/*)
    // Deny protects logs/* but allow excludes logs/* → no resources survive
    expected: []
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Identical patterns',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*']
    },
    expected: []
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Deny excludes more',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/*', 'arn:aws:s3:::bucket/logs/*']
    },
    // Surviving = (NOT private) ∩ (private OR logs) = logs only
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::bucket/logs/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Allow excludes more',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/private/*', 'arn:aws:s3:::bucket/logs/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/logs/*']
    },
    // All deny patterns are covered by allow patterns, so no resources can survive
    // (allowed AND protected from deny) = ∅
    expected: []
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - No overlap in exclusions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket-a/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket-b/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket-b/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Deny pattern is superset of allow pattern',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/file.txt']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/*']
    },
    // Surviving = (NOT file.txt) ∩ (private/*) = private/* (file.txt is within private/*)
    // We can't subtract file.txt from private/*, so we return the full protected zone
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::bucket/private/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Allow pattern is superset of deny pattern',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/logs/*']
    },
    expected: []
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Multiple patterns mixed',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/private/*', 'arn:aws:s3:::bucket/archive/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/archive/*', 'arn:aws:s3:::bucket/logs/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket/logs/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - With same conditions',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*'],
      conditions: { StringEquals: { 'aws:PrincipalTag/team': ['engineering'] } }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*', 'arn:aws:s3:::bucket/logs/*'],
      conditions: { StringEquals: { 'aws:PrincipalTag/team': ['engineering'] } }
    },
    // Surviving = (NOT secret) ∩ (secret OR logs) = logs only
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket/logs/*'],
        conditions: { StringEquals: { 'aws:PrincipalTag/team': ['engineering'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Different conditions (deny has condition)',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/private/*', 'arn:aws:s3:::bucket/logs/*'],
      conditions: { StringEquals: { 'aws:PrincipalTag/role': ['intern'] } }
    },
    expected: [
      // When role ≠ intern: original allow (deny doesn't apply)
      {
        effect: 'Allow',
        action: 's3:PutObject',
        notResource: ['arn:aws:s3:::bucket/private/*'],
        conditions: { StringNotEquals: { 'aws:PrincipalTag/role': ['intern'] } }
      },
      // When role = intern: surviving = (NOT private) ∩ (private OR logs) = logs only
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['arn:aws:s3:::bucket/logs/*'],
        conditions: { StringEquals: { 'aws:PrincipalTag/role': ['intern'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Allow has condition, deny does not',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*'],
      conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-123'] } }
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/secret/*', 'arn:aws:s3:::bucket/logs/*']
    },
    // Surviving = (NOT secret) ∩ (secret OR logs) = logs only
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket/logs/*'],
        conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-123'] } }
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Deny with multiple condition operators',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/archive/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket/archive/*', 'arn:aws:s3:::bucket/temp/*'],
      conditions: {
        StringEquals: { 'aws:PrincipalTag/team': ['external'] },
        Bool: { 'aws:SecureTransport': ['false'] }
      }
    },
    expected: [
      // When team ≠ external: original allow (deny doesn't apply)
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket/archive/*'],
        conditions: { StringNotEquals: { 'aws:PrincipalTag/team': ['external'] } }
      },
      // When SecureTransport ≠ false: original allow (deny doesn't apply)
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket/archive/*'],
        conditions: { Bool: { 'aws:SecureTransport': ['true'] } }
      },
      // When both conditions met: surviving = (NOT archive) ∩ (archive OR temp) = temp only
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket/temp/*']
      }
    ]
  },
  {
    name: 'Allow.NotResource & Deny.NotResource - Wildcard patterns',
    allow: {
      effect: 'Allow',
      action: 'dynamodb:Query',
      notResource: ['arn:aws:dynamodb:*:*:table/admin-*']
    },
    deny: {
      effect: 'Deny',
      action: 'dynamodb:Query',
      notResource: ['arn:aws:dynamodb:*:*:table/admin-*', 'arn:aws:dynamodb:*:*:table/audit-*']
    },
    // Surviving = (NOT admin-*) ∩ (admin-* OR audit-*) = audit-* only
    expected: [
      {
        effect: 'Allow',
        action: 'dynamodb:Query',
        resource: ['arn:aws:dynamodb:*:*:table/audit-*']
      }
    ]
  }
]

describe('Permission#subtract', () => {
  for (const test of subtractTests) {
    const func = test.only ? it.only : it
    func('subtract: ' + test.name, () => {
      //Given an allow and deny permission
      const [allowService, allowAction] = test.allow.action.split(':')
      const allowPermission = new Permission(
        test.allow.effect,
        allowService,
        allowAction,
        test.allow.resource,
        test.allow.notResource,
        test.allow.conditions
      )

      const [denyService, denyAction] = test.deny.action.split(':')
      const denyPermission = new Permission(
        test.deny.effect,
        denyService,
        denyAction,
        test.deny.resource,
        test.deny.notResource,
        test.deny.conditions
      )

      //When we subtract the deny from the allow
      const result = allowPermission.subtract(denyPermission)

      //Then the permissions should match
      expectPermissionsToMatch(result, test.expected)
    })
  }
})

const invertConditionsTests: {
  only?: true
  name: string
  initial: PermissionConditions
  expected: PermissionConditions
}[] = [
  {
    name: 'invert StringEquals conditions',
    initial: {
      StringEquals: { 'aws:username': ['alice', 'bob'] }
    },
    expected: {
      stringnotequals: { 'aws:username': ['alice', 'bob'] }
    }
  },
  {
    name: 'invert Bool condition remains same',
    initial: {
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    expected: {
      bool: { 'aws:securetransport': ['false'] }
    }
  },
  {
    name: 'invert Null condition',
    initial: {
      Null: { 'aws:TokenIssueTime': ['true'] }
    },
    expected: {
      null: { 'aws:tokenissuetime': ['false'] }
    }
  },
  {
    name: 'invert NotNull condition',
    initial: {
      Null: { 'aws:TokenIssueTime': ['false'] }
    },
    expected: {
      null: { 'aws:tokenissuetime': ['true'] }
    }
  },
  {
    name: 'invert ForAnyValue:StringEquals',
    initial: {
      'ForAnyValue:StringEquals': { 'aws:TagKeys': ['r1', 'r2', 'r3'] }
    },
    expected: {
      'forallvalues:stringnotequals': { 'aws:tagkeys': ['r1', 'r2', 'r3'] }
    }
  },
  {
    name: 'invert ForAllValues:StringEquals',
    initial: {
      'ForAllValues:StringEquals': { 'aws:TagKeys': ['r1', 'r2'] }
    },
    expected: {
      'foranyvalue:stringnotequals': { 'aws:tagkeys': ['r1', 'r2'] }
    }
  },
  {
    name: 'invert ForAllValues:StringEqualsIfExists',
    initial: {
      'ForAllValues:StringEqualsIfExists': { 'aws:TagKeys': ['prod'] }
    },
    expected: {
      'foranyvalue:stringnotequalsifexists': { 'aws:tagkeys': ['prod'] }
    }
  },
  {
    name: 'invert ForAnyValue:NumericLessThan',
    initial: {
      'ForAnyValue:NumericLessThan': { 's3:max-keys': ['100'] }
    },
    expected: {
      'forallvalues:numericgreaterthanequals': { 's3:max-keys': ['100'] }
    }
  },
  {
    name: 'invert ForAnyValue:StringLikeIfExists',
    initial: {
      'ForAnyValue:StringLikeIfExists': { 'aws:TagValues': ['Confidential*'] }
    },
    expected: {
      'forallvalues:stringnotlikeifexists': { 'aws:tagvalues': ['Confidential*'] }
    }
  },
  {
    name: 'invert ForAllValues:NumericGreaterThan',
    initial: {
      'ForAllValues:NumericGreaterThan': { 'lambda:memory-size': ['128'] }
    },
    expected: {
      'foranyvalue:numericlessthanequals': { 'lambda:memory-size': ['128'] }
    }
  },
  {
    name: 'invert IpAddressIfExists',
    initial: {
      IpAddressIfExists: { 'aws:SourceIp': ['10.0.0.0/8'] }
    },
    expected: {
      notipaddressifexists: { 'aws:sourceip': ['10.0.0.0/8'] }
    }
  },
  {
    name: 'invert Bool false to true',
    initial: {
      Bool: { 'aws:SecureTransport': ['false'] }
    },
    expected: {
      bool: { 'aws:securetransport': ['true'] }
    }
  }
]

describe('invertConditions', () => {
  for (const test of invertConditionsTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given a set of conditions
      const conditions = test.initial

      //When we invert the conditions
      const result = invertConditions(conditions)

      //Then the result should match the expected inverted conditions
      expect(result).toEqual(test.expected)
    })
  }
})

const intersectConditionsTests: {
  name: string
  only?: true
  initialA: PermissionConditions
  initialB: PermissionConditions
  expected: PermissionConditions | null
}[] = [
  // StringEquals tests
  {
    name: 'intersect two StringEquals conditions with different keys',
    initialA: {
      StringEquals: { 'aws:username': ['alice', 'bob'] }
    },
    initialB: {
      StringEquals: { 'aws:PrincipalOrgId': ['o-12345678'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['alice', 'bob'],
        'aws:principalorgid': ['o-12345678']
      }
    }
  },
  {
    name: 'intersect StringEquals with same key - common values',
    initialA: {
      StringEquals: { 'aws:username': ['alice', 'bob', 'charlie'] }
    },
    initialB: {
      StringEquals: { 'aws:username': ['bob', 'charlie', 'dave'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['bob', 'charlie']
      }
    }
  },
  {
    name: 'intersect StringEquals with same key - no common values returns null',
    initialA: {
      StringEquals: { 'aws:username': ['alice'] }
    },
    initialB: {
      StringEquals: { 'aws:username': ['bob'] }
    },
    expected: null
  },
  // StringLike tests
  {
    name: 'intersect StringLike with same key - common patterns',
    initialA: {
      StringLike: { 'aws:userid': ['admin-*', 'user-*'] }
    },
    initialB: {
      StringLike: { 'aws:userid': ['user-*', 'guest-*'] }
    },
    expected: {
      stringlike: {
        'aws:userid': ['user-*']
      }
    }
  },
  // StringNotEquals tests (union of exclusions)
  {
    name: 'intersect StringNotEquals - union of exclusions',
    initialA: {
      StringNotEquals: { 'aws:username': ['alice'] }
    },
    initialB: {
      StringNotEquals: { 'aws:username': ['bob'] }
    },
    expected: {
      stringnotequals: {
        'aws:username': ['alice', 'bob']
      }
    }
  },
  // ArnEquals tests
  {
    name: 'intersect ArnEquals with same key - common ARNs',
    initialA: {
      ArnEquals: { 'aws:SourceArn': ['arn:aws:s3:::bucket1', 'arn:aws:s3:::bucket2'] }
    },
    initialB: {
      ArnEquals: { 'aws:SourceArn': ['arn:aws:s3:::bucket2', 'arn:aws:s3:::bucket3'] }
    },
    expected: {
      arnequals: {
        'aws:sourcearn': ['arn:aws:s3:::bucket2']
      }
    }
  },
  // ArnNotLike tests (union of exclusions)
  {
    name: 'intersect ArnNotLike - union of exclusions',
    initialA: {
      ArnNotLike: { 'aws:SourceArn': ['arn:aws:s3:::bucket1/*'] }
    },
    initialB: {
      ArnNotLike: { 'aws:SourceArn': ['arn:aws:s3:::bucket2/*'] }
    },
    expected: {
      arnnotlike: {
        'aws:sourcearn': ['arn:aws:s3:::bucket1/*', 'arn:aws:s3:::bucket2/*']
      }
    }
  },
  // NumericLessThan tests
  {
    name: 'intersect NumericLessThan - take minimum boundary',
    initialA: {
      NumericLessThan: { 'aws:MultiFactorAuthAge': ['3600'] }
    },
    initialB: {
      NumericLessThan: { 'aws:MultiFactorAuthAge': ['7200'] }
    },
    expected: {
      numericlessthan: {
        'aws:multifactorauthage': ['3600']
      }
    }
  },
  {
    name: 'intersect NumericLessThanEquals - take minimum boundary',
    initialA: {
      NumericLessThanEquals: { 'aws:MultiFactorAuthAge': ['1800'] }
    },
    initialB: {
      NumericLessThanEquals: { 'aws:MultiFactorAuthAge': ['3600'] }
    },
    expected: {
      numericlessthanequals: {
        'aws:multifactorauthage': ['1800']
      }
    }
  },
  // NumericGreaterThan tests
  {
    name: 'intersect NumericGreaterThan - take maximum boundary',
    initialA: {
      NumericGreaterThan: { 'aws:MultiFactorAuthAge': ['100'] }
    },
    initialB: {
      NumericGreaterThan: { 'aws:MultiFactorAuthAge': ['200'] }
    },
    expected: {
      numericgreaterthan: {
        'aws:multifactorauthage': ['200']
      }
    }
  },
  {
    name: 'intersect NumericGreaterThanEquals - take maximum boundary',
    initialA: {
      NumericGreaterThanEquals: { 'aws:MultiFactorAuthAge': ['50'] }
    },
    initialB: {
      NumericGreaterThanEquals: { 'aws:MultiFactorAuthAge': ['150'] }
    },
    expected: {
      numericgreaterthanequals: {
        'aws:multifactorauthage': ['150']
      }
    }
  },
  // Bool tests
  {
    name: 'intersect Bool with same value - true',
    initialA: {
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    initialB: {
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    expected: {
      bool: {
        'aws:securetransport': ['true']
      }
    }
  },
  {
    name: 'intersect Bool with same value - false',
    initialA: {
      Bool: { 'aws:SecureTransport': ['false'] }
    },
    initialB: {
      Bool: { 'aws:SecureTransport': ['false'] }
    },
    expected: {
      bool: {
        'aws:securetransport': ['false']
      }
    }
  },
  {
    name: 'intersect Bool with different values - returns null',
    initialA: {
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    initialB: {
      Bool: { 'aws:SecureTransport': ['false'] }
    },
    expected: null
  },
  // IpAddress tests
  {
    name: 'intersect IpAddress with same key - common CIDRs',
    initialA: {
      IpAddress: { 'aws:SourceIp': ['192.168.1.0/24', '10.0.0.0/8'] }
    },
    initialB: {
      IpAddress: { 'aws:SourceIp': ['10.0.0.0/8', '172.16.0.0/12'] }
    },
    expected: {
      ipaddress: {
        'aws:sourceip': ['10.0.0.0/8']
      }
    }
  },
  {
    name: 'intersect IpAddress with no common CIDRs - returns null',
    initialA: {
      IpAddress: { 'aws:SourceIp': ['192.168.1.0/24'] }
    },
    initialB: {
      IpAddress: { 'aws:SourceIp': ['10.0.0.0/8'] }
    },
    expected: null
  },
  // NotIpAddress tests (intersection of allowed)
  {
    name: 'intersect NotIpAddress with same key - common CIDRs',
    initialA: {
      NotIpAddress: { 'aws:SourceIp': ['192.168.1.0/24', '10.0.0.0/8'] }
    },
    initialB: {
      NotIpAddress: { 'aws:SourceIp': ['10.0.0.0/8', '172.16.0.0/12'] }
    },
    expected: {
      notipaddress: {
        'aws:sourceip': ['10.0.0.0/8']
      }
    }
  },
  // DateLessThan tests
  {
    name: 'intersect DateLessThan - take earlier date',
    initialA: {
      DateLessThan: { 'aws:TokenIssueTime': ['2024-01-15T00:00:00Z'] }
    },
    initialB: {
      DateLessThan: { 'aws:TokenIssueTime': ['2024-01-20T00:00:00Z'] }
    },
    expected: {
      datelessthan: {
        'aws:tokenissuetime': ['2024-01-15T00:00:00Z']
      }
    }
  },
  {
    name: 'intersect DateLessThanEquals - take earlier date',
    initialA: {
      DateLessThanEquals: { 'aws:TokenIssueTime': ['2024-06-01T00:00:00Z'] }
    },
    initialB: {
      DateLessThanEquals: { 'aws:TokenIssueTime': ['2024-03-01T00:00:00Z'] }
    },
    expected: {
      datelessthanequals: {
        'aws:tokenissuetime': ['2024-03-01T00:00:00Z']
      }
    }
  },
  // DateGreaterThan tests
  {
    name: 'intersect DateGreaterThan - take later date',
    initialA: {
      DateGreaterThan: { 'aws:TokenIssueTime': ['2024-01-01T00:00:00Z'] }
    },
    initialB: {
      DateGreaterThan: { 'aws:TokenIssueTime': ['2024-02-01T00:00:00Z'] }
    },
    expected: {
      dategreaterthan: {
        'aws:tokenissuetime': ['2024-02-01T00:00:00Z']
      }
    }
  },
  {
    name: 'intersect DateGreaterThanEquals - take later date',
    initialA: {
      DateGreaterThanEquals: { 'aws:TokenIssueTime': ['2024-03-15T00:00:00Z'] }
    },
    initialB: {
      DateGreaterThanEquals: { 'aws:TokenIssueTime': ['2024-01-15T00:00:00Z'] }
    },
    expected: {
      dategreaterthanequals: {
        'aws:tokenissuetime': ['2024-03-15T00:00:00Z']
      }
    }
  },
  // Different operators tests
  {
    name: 'intersect different operators - combine all',
    initialA: {
      StringEquals: { 'aws:username': ['alice'] }
    },
    initialB: {
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['alice']
      },
      bool: {
        'aws:securetransport': ['true']
      }
    }
  },
  {
    name: 'intersect multiple operators from both sides',
    initialA: {
      StringEquals: { 'aws:username': ['alice'] },
      NumericLessThan: { 'aws:MultiFactorAuthAge': ['3600'] }
    },
    initialB: {
      Bool: { 'aws:SecureTransport': ['true'] },
      IpAddress: { 'aws:SourceIp': ['10.0.0.0/8'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['alice']
      },
      numericlessthan: {
        'aws:multifactorauthage': ['3600']
      },
      bool: {
        'aws:securetransport': ['true']
      },
      ipaddress: {
        'aws:sourceip': ['10.0.0.0/8']
      }
    }
  },
  // Key only in one side tests
  {
    name: 'key only in A is carried through',
    initialA: {
      StringEquals: { 'aws:username': ['alice'], 'aws:PrincipalAccount': ['123456789012'] }
    },
    initialB: {
      StringEquals: { 'aws:username': ['alice'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['alice'],
        'aws:principalaccount': ['123456789012']
      }
    }
  },
  {
    name: 'key only in B is carried through',
    initialA: {
      StringEquals: { 'aws:username': ['alice'] }
    },
    initialB: {
      StringEquals: { 'aws:username': ['alice'], 'aws:PrincipalAccount': ['123456789012'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['alice'],
        'aws:principalaccount': ['123456789012']
      }
    }
  },
  // Empty conditions tests
  {
    name: 'intersect empty A with non-empty B',
    initialA: {},
    initialB: {
      StringEquals: { 'aws:username': ['alice'] }
    },
    expected: {
      stringequals: {
        'aws:username': ['alice']
      }
    }
  },
  {
    name: 'intersect non-empty A with empty B',
    initialA: {
      StringEquals: { 'aws:username': ['alice'] }
    },
    initialB: {},
    expected: {
      stringequals: {
        'aws:username': ['alice']
      }
    }
  },
  {
    name: 'intersect both empty returns empty',
    initialA: {},
    initialB: {},
    expected: {}
  },
  // ForAllValues/ForAnyValue prefix tests
  {
    name: 'intersect ForAllValues:StringEquals with same key - common values',
    initialA: {
      'ForAllValues:StringEquals': { 'aws:TagKeys': ['env', 'project', 'team'] }
    },
    initialB: {
      'ForAllValues:StringEquals': { 'aws:TagKeys': ['project', 'team', 'owner'] }
    },
    expected: {
      'forallvalues:stringequals': {
        'aws:tagkeys': ['project', 'team']
      }
    }
  },
  {
    name: 'intersect ForAnyValue:StringLike with same key - common values',
    initialA: {
      'ForAnyValue:StringLike': { 'aws:TagKeys': ['env-*', 'project-*'] }
    },
    initialB: {
      'ForAnyValue:StringLike': { 'aws:TagKeys': ['project-*', 'team-*'] }
    },
    expected: {
      'foranyvalue:stringlike': {
        'aws:tagkeys': ['project-*']
      }
    }
  },
  // IfExists suffix tests
  {
    name: 'intersect StringEqualsIfExists with same key - common values',
    initialA: {
      StringEqualsIfExists: { 'aws:username': ['alice', 'bob'] }
    },
    initialB: {
      StringEqualsIfExists: { 'aws:username': ['bob', 'charlie'] }
    },
    expected: {
      stringequalsifexists: {
        'aws:username': ['bob']
      }
    }
  },
  {
    name: 'intersect BoolIfExists with same value',
    initialA: {
      BoolIfExists: { 'aws:PrincipalIsAWSService': ['true'] }
    },
    initialB: {
      BoolIfExists: { 'aws:PrincipalIsAWSService': ['true'] }
    },
    expected: {
      boolifexists: {
        'aws:principalisawsservice': ['true']
      }
    }
  },
  // Null condition tests
  {
    name: 'intersect Null condition with same value',
    initialA: {
      Null: { 'aws:TokenIssueTime': ['true'] }
    },
    initialB: {
      Null: { 'aws:TokenIssueTime': ['true'] }
    },
    expected: {
      null: {
        'aws:tokenissuetime': ['true']
      }
    }
  },
  {
    name: 'intersect Null condition with different values - returns null',
    initialA: {
      Null: { 'aws:TokenIssueTime': ['true'] }
    },
    initialB: {
      Null: { 'aws:TokenIssueTime': ['false'] }
    },
    expected: null
  },
  // Complex combined tests
  {
    name: 'complex intersection with multiple operators and keys',
    initialA: {
      StringEquals: { 'aws:PrincipalOrgId': ['o-12345678'] },
      NumericLessThan: { 'aws:MultiFactorAuthAge': ['3600'] },
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    initialB: {
      StringEquals: { 'aws:PrincipalOrgId': ['o-12345678'] },
      NumericLessThan: { 'aws:MultiFactorAuthAge': ['7200'] },
      IpAddress: { 'aws:SourceIp': ['10.0.0.0/8'] }
    },
    expected: {
      stringequals: {
        'aws:principalorgid': ['o-12345678']
      },
      numericlessthan: {
        'aws:multifactorauthage': ['3600']
      },
      bool: {
        'aws:securetransport': ['true']
      },
      ipaddress: {
        'aws:sourceip': ['10.0.0.0/8']
      }
    }
  },
  {
    name: 'intersection fails when one overlapping key has no common values',
    initialA: {
      StringEquals: { 'aws:PrincipalOrgId': ['o-12345678'], 'aws:username': ['alice'] }
    },
    initialB: {
      StringEquals: { 'aws:PrincipalOrgId': ['o-87654321'] }
    },
    expected: null
  }
]

for (const test of intersectConditionsTests) {
  const func = test.only ? it.only : it

  func('intersectConditions: ' + test.name, () => {
    //Given two sets of conditions
    const conditionsA = test.initialA
    const conditionsB = test.initialB

    //When we merge the conditions
    const result = intersectConditions(conditionsA, conditionsB)

    //Then the result should match the expected merged conditions
    expect(result).toEqual(test.expected)
  })
}

const applyDenyConditionsToAllowTests: {
  name: string
  only?: true
  allow: TestPermission
  deny: TestPermission
  expected: TestPermission[]
}[] = [
  // Basic single condition tests
  {
    name: 'Apply deny with single IpAddress condition from allow without condition',
    allow: {
      effect: 'Allow',
      action: 's3:ListBucket',
      resource: ['arn:aws:s3:::mybucket']
    },
    deny: {
      effect: 'Deny',
      action: 's3:ListBucket',
      resource: ['arn:aws:s3:::mybucket'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['192.168.1.0/24']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:ListBucket',
        resource: ['arn:aws:s3:::mybucket'],
        conditions: {
          notipaddress: {
            'aws:sourceip': ['192.168.1.0/24']
          }
        }
      }
    ]
  },
  {
    name: 'Apply deny with single StringEquals condition',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/Admin']
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/Admin'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgId': ['o-external']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/Admin'],
        conditions: {
          stringnotequals: {
            'aws:principalorgid': ['o-external']
          }
        }
      }
    ]
  },
  {
    name: 'Apply deny with single Bool condition',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::mybucket/*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['false']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::mybucket/*'],
        conditions: {
          bool: {
            'aws:securetransport': ['true']
          }
        }
      }
    ]
  },
  {
    name: 'Apply deny with single Null condition',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/CrossAccount']
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/CrossAccount'],
      conditions: {
        Null: {
          'sts:ExternalId': ['true']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/CrossAccount'],
        conditions: {
          null: {
            'sts:externalid': ['false']
          }
        }
      }
    ]
  },

  // Multiple conditions tests (AND -> OR inversion)
  {
    name: 'Apply deny with two conditions creates two separate allows',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::iam-data-482734']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::iam-data-482734'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgId': ['o-98765432']
        },
        IpAddress: {
          'aws:SourceIp': ['192.168.1.0/24']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::iam-data-482734'],
        conditions: {
          stringnotequals: {
            'aws:principalorgid': ['o-98765432']
          }
        }
      },
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::iam-data-482734'],
        conditions: {
          notipaddress: {
            'aws:sourceip': ['192.168.1.0/24']
          }
        }
      }
    ]
  },
  {
    name: 'Apply deny with three conditions creates three separate allows',
    allow: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/EC2Admin']
    },
    deny: {
      effect: 'Deny',
      action: 'sts:AssumeRole',
      resource: ['arn:aws:iam::123456789012:role/EC2Admin'],
      conditions: {
        Null: {
          'sts:ExternalId': ['true']
        },
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-myorg']
        },
        BoolIfExists: {
          'aws:PrincipalIsAWSService': ['false']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/EC2Admin'],
        conditions: {
          null: {
            'sts:externalid': ['false']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/EC2Admin'],
        conditions: {
          stringequals: {
            'aws:principalorgid': ['o-myorg']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'sts:AssumeRole',
        resource: ['arn:aws:iam::123456789012:role/EC2Admin'],
        conditions: {
          boolifexists: {
            'aws:principalisawsservice': ['true']
          }
        }
      }
    ]
  },

  // Allow with existing conditions - merge with inverted deny
  {
    name: 'Allow with existing condition merges with inverted deny condition',
    allow: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': ['us-east-1', 'us-west-2']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['10.0.0.0/8']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'ec2:StartInstances',
        resource: ['*'],
        conditions: {
          stringequals: {
            'aws:requestedregion': ['us-east-1', 'us-west-2']
          },
          notipaddress: {
            'aws:sourceip': ['10.0.0.0/8']
          }
        }
      }
    ]
  },
  {
    name: 'Allow with multiple existing conditions merges with inverted deny conditions',
    allow: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['arn:aws:lambda:us-east-1:123456789012:function:*'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgId': ['o-myorg']
        },
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'lambda:InvokeFunction',
      resource: ['arn:aws:lambda:us-east-1:123456789012:function:*'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['192.168.0.0/16']
        },
        StringEquals: {
          'aws:username': ['badactor']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'lambda:InvokeFunction',
        resource: ['arn:aws:lambda:us-east-1:123456789012:function:*'],
        conditions: {
          stringequals: {
            'aws:principalorgid': ['o-myorg']
          },
          bool: {
            'aws:securetransport': ['true']
          },
          notipaddress: {
            'aws:sourceip': ['192.168.0.0/16']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'lambda:InvokeFunction',
        resource: ['arn:aws:lambda:us-east-1:123456789012:function:*'],
        conditions: {
          stringequals: {
            'aws:principalorgid': ['o-myorg']
          },
          bool: {
            'aws:securetransport': ['true']
          },
          stringnotequals: {
            'aws:username': ['badactor']
          }
        }
      }
    ]
  },

  // Deny without conditions - returns allow unchanged
  {
    name: 'Deny without conditions returns allow unchanged',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::mybucket/*']
      }
    ]
  },

  // Conflicting conditions - should produce empty result when inverted condition conflicts with allow
  {
    name: 'Deny Bool condition that conflicts with Allow Bool condition produces no result for that branch',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    expected: []
  },
  {
    name: 'Deny with multiple conditions where one conflicts produces only non-conflicting branches',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        },
        IpAddress: {
          'aws:SourceIp': ['10.0.0.0/8']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        resource: ['*'],
        conditions: {
          bool: {
            'aws:securetransport': ['true']
          },
          notipaddress: {
            'aws:sourceip': ['10.0.0.0/8']
          }
        }
      }
    ]
  },

  // ForAllValues/ForAnyValue prefix tests
  {
    name: 'Apply deny with ForAnyValue:StringEquals condition',
    allow: {
      effect: 'Allow',
      action: 'dynamodb:Query',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 'dynamodb:Query',
      resource: ['*'],
      conditions: {
        'ForAnyValue:StringEquals': {
          'dynamodb:Attributes': ['SSN', 'CreditCard']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'dynamodb:Query',
        resource: ['*'],
        conditions: {
          'forallvalues:stringnotequals': {
            'dynamodb:attributes': ['SSN', 'CreditCard']
          }
        }
      }
    ]
  },
  {
    name: 'Apply deny with ForAllValues:StringEquals condition',
    allow: {
      effect: 'Allow',
      action: 's3:PutObjectTagging',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObjectTagging',
      resource: ['*'],
      conditions: {
        'ForAllValues:StringEquals': {
          'aws:TagKeys': ['Environment', 'Project']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObjectTagging',
        resource: ['*'],
        conditions: {
          'foranyvalue:stringnotequals': {
            'aws:tagkeys': ['Environment', 'Project']
          }
        }
      }
    ]
  },

  // Multiple context keys under same operator
  {
    name: 'Deny with multiple context keys under same operator creates separate allows per key',
    allow: {
      effect: 'Allow',
      action: 'ec2:RunInstances',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 'ec2:RunInstances',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': ['eu-west-1'],
          'ec2:InstanceType': ['t2.micro']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'ec2:RunInstances',
        resource: ['*'],
        conditions: {
          stringnotequals: {
            'aws:requestedregion': ['eu-west-1']
          }
        }
      },
      {
        effect: 'Allow',
        action: 'ec2:RunInstances',
        resource: ['*'],
        conditions: {
          stringnotequals: {
            'ec2:instancetype': ['t2.micro']
          }
        }
      }
    ]
  },

  // IfExists suffix tests
  {
    name: 'Apply deny with StringEqualsIfExists condition preserves IfExists',
    allow: {
      effect: 'Allow',
      action: 'kms:Decrypt',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 'kms:Decrypt',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'kms:ViaService': ['s3.us-east-1.amazonaws.com']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'kms:Decrypt',
        resource: ['*'],
        conditions: {
          stringnotequalsifexists: {
            'kms:viaservice': ['s3.us-east-1.amazonaws.com']
          }
        }
      }
    ]
  },

  // Numeric condition tests
  {
    name: 'Apply deny with NumericLessThan condition',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: {
          'aws:MultiFactorAuthAge': ['3600']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['*'],
        conditions: {
          numericgreaterthanequals: {
            'aws:multifactorauthage': ['3600']
          }
        }
      }
    ]
  },

  // notResource tests
  {
    name: 'Apply deny to allow with notResource',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::restricted-bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::restricted-bucket/*'],
      conditions: {
        StringNotEquals: {
          'aws:PrincipalOrgId': ['o-myorg']
        }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        notResource: ['arn:aws:s3:::restricted-bucket/*'],
        conditions: {
          stringequals: {
            'aws:principalorgid': ['o-myorg']
          }
        }
      }
    ]
  }
]

for (const test of applyDenyConditionsToAllowTests) {
  const func = test.only ? it.only : it

  func('applyDenyConditionsToAllow: ' + test.name, () => {
    //Given allow and deny conditions
    const allowPermission = convertTestPermissionToPermission(test.allow)
    const denyPermission = convertTestPermissionToPermission(test.deny)

    //When we apply the deny conditions to the allow conditions
    const result = applyDenyConditionsToAllow(allowPermission, denyPermission)

    //Then the result should match the expected resulting conditions
    expectPermissionsToMatch(result, test.expected)
  })
}
