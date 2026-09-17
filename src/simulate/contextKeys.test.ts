import { describe, expect, it } from 'vitest'
import { testStore } from '../collect/inMemoryClient.js'
import { createContextKeys, servicePrincipalKmsCallerAccountPlaceholder } from './contextKeys.js'
import { SimulationRequest } from './simulate.js'

const defaultSimulationRequest: SimulationRequest = {
  simulationMode: 'Strict',
  principal: 'arn:aws:iam::123456789012:user/test-user',
  resourceArn: 'arn:aws:s3:::test-bucket',
  resourceAccount: '123456789012',
  action: 's3:GetObject',
  customContextKeys: {}
}

describe('createContextKeys', () => {
  describe('aws:PrincipalArn', () => {
    it('should set aws:PrincipalArn to the principal ARN for IAM users', async () => {
      // Given a simulation request with an IAM user principal ARN
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalArn should be set to the IAM user ARN
      expect(contextKeys['aws:PrincipalArn']).toBe(principalArn)
    })

    it('should set aws:PrincipalArn to the role ARN for assumed-role principals', async () => {
      // Given a simulation request with an assumed-role session ARN
      const principalArn = 'arn:aws:sts::123456789012:assumed-role/MyRole/MySession'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalArn should be set to the base role ARN
      expect(contextKeys['aws:PrincipalArn']).toBe('arn:aws:iam::123456789012:role/MyRole')
    })

    it('should not set aws:PrincipalArn for service principal', async () => {
      // Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalArn should not be set
      expect(contextKeys['aws:PrincipalArn']).toBeUndefined()
    })
  })

  describe('aws:PrincipalAccount', () => {
    it('should set aws:PrincipalAccount on the principals account id', async () => {
      //Given a simulation request with a principal ARN
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalAccount should be set to the account ID from the principal ARN
      expect(contextKeys['aws:PrincipalAccount']).toBe('123456789012')
    })
    it('should not set aws:PrincipalAccount for a service principal', async () => {
      //Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalAccount should not be set
      expect(contextKeys['aws:PrincipalAccount']).toBeUndefined()
    })
  })

  describe('aws:PrincipalOrgPaths', () => {
    it('should set aws:PrincipalOrgPaths to the organization paths for the principal', async () => {
      // Given a simulation request with a principal ARN that is part of an organization
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      // Mock the collect client to return org structure
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:PrincipalOrgPaths should be set to the org path
      expect(contextKeys['aws:PrincipalOrgPaths']).toEqual([`${orgId}/${rootOu}/${ou1}/${ou2}/`])
    })

    it('should not set aws:PrincipalOrgPaths users not in an organization', async () => {
      // Given a simulation request with a principal ARN not in an org
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }
      const { client } = testStore()

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:PrincipalOrgPaths should not be set
      expect(contextKeys['aws:PrincipalOrgPaths']).toBeUndefined()
    })

    it('should not set aws:PrincipalOrgPaths for service principals', async () => {
      // Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalOrgPaths should not be set
      expect(contextKeys['aws:PrincipalOrgPaths']).toBeUndefined()
    })
    //it.todo('should not set aws:PrincipalOrgPaths for anonymous requests', async () => {})
  })

  describe('aws:PrincipalOrgID', () => {
    it('should set aws:PrincipalOrgID if the principal is an organization', async () => {
      //Given a simulation request with a principal ARN that is part of an organization
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const organizationId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'

      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      //Mock the collect client to return an organization ID
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: organizationId
        },
        ''
      )
      await store.saveOrganizationMetadata(organizationId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(organizationId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      //When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      //Then aws:PrincipalOrgID should be set to the organization ID
      expect(contextKeys['aws:PrincipalOrgId']).toBe(organizationId)
    })

    it('should not set aws:PrincipalOrgID if the principal is not in an organization', async () => {
      //Given a simulation request with a principal ARN that is not part of an organization
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      //An empty store simulating no organization
      const { store, client } = testStore()

      //When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      //Then aws:PrincipalOrgID should not be set
      expect(contextKeys['aws:PrincipalOrgId']).toBeUndefined()
    })

    it('should not set aws:PrincipalOrgID for service principals', async () => {
      //Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalOrgID should not be set
      expect(contextKeys['aws:PrincipalOrgId']).toBeUndefined()
    })
  })

  describe('aws:PrincipalTag/tag-key', () => {
    it('should set aws:PrincipalTag/tag-key for each tag on the principal', async () => {
      //Given a simulation request with a principal ARN that has tags
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      //Mock the collect client to return tags for the principal
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', principalArn, 'tags', {
        Department: 'Engineering',
        Project: 'Copilot'
      })

      //When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      //Then aws:PrincipalTag/Department and aws:PrincipalTag/Project should be set
      expect(contextKeys['aws:PrincipalTag/Department']).toBe('Engineering')
      expect(contextKeys['aws:PrincipalTag/Project']).toBe('Copilot')
    })

    it('should not set any key starting with aws:PrincipalTag/ if the principal has no tags', async () => {
      //Given a simulation request with a principal ARN that has no tags
      const principalArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      //Mock the collect client to return no tags for the principal
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', principalArn, 'tags', {})

      //When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      //Then no aws:PrincipalTag/ keys should be set
      const tagKeys = Object.keys(contextKeys).filter((key) => key.startsWith('aws:PrincipalTag/'))
      expect(tagKeys.length).toBe(0)
    })

    it('should not set aws:PrincipalTag/tag-key for service principals', async () => {
      //Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then no aws:PrincipalTag/ keys should be set
      const tagKeys = Object.keys(contextKeys).filter((key) => key.startsWith('aws:PrincipalTag/'))
      expect(tagKeys.length).toBe(0)
    })
  })

  describe('aws:PrincipalIsAWSService', () => {
    it('should set aws:PrincipalIsAWSService to true for service principals', async () => {
      //Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalIsAWSService should be true
      expect(contextKeys['aws:PrincipalIsAWSService']).toBe('true')
    })

    it('should not set aws:PrincipalIsAWSService to false for an IAM user or role', async () => {
      //Given a simulation request with an IAM user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalIsAWSService should not be set
      expect(contextKeys['aws:PrincipalIsAWSService']).toEqual('false')
    })
  })

  describe('aws:PrincipalServiceName', () => {
    it('should set aws:PrincipalServiceName for service principals', async () => {
      //Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalServiceName should be set to the service name
      expect(contextKeys['aws:PrincipalServiceName']).toBe('lambda.amazonaws.com')
    })
    it('should not set aws:PrincipalServiceName for IAM users or roles', async () => {
      //Given a simulation request with an IAM user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:PrincipalServiceName should not be set
      expect(contextKeys['aws:PrincipalServiceName']).toBeUndefined()
    })
  })

  describe('aws:PrincipalType', () => {
    it('should set aws:PrincipalType to Account for a root user', async () => {
      // Given a simulation request with a root user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:root'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalType should be 'Account'
      expect(contextKeys['aws:PrincipalType']).toBe('Account')
    })

    it('should set aws:PrincipalType to User for IAM users', async () => {
      // Given a simulation request with an IAM user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalType should be 'User'
      expect(contextKeys['aws:PrincipalType']).toBe('User')
    })

    it('should set aws:PrincipalType to AssumedRole for Assumed roles roles', async () => {
      // Given a simulation request with an assumed role principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:sts::123456789012:assumed-role/MyRole/MySession'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalType should be 'AssumedRole'
      expect(contextKeys['aws:PrincipalType']).toBe('AssumedRole')
    })

    it('should set aws:PrincipalType to AssumedRole for IAM roles', async () => {
      // Given a simulation request with an assumed role principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:role/MyRole'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalType should be 'AssumedRole'
      expect(contextKeys['aws:PrincipalType']).toBe('AssumedRole')
    })

    it('should set aws:PrincipalType to FederatedUser for federated user ARNs', async () => {
      // Given a simulation request with a federated user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:sts::123456789012:federated-user/Bob'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalType should be 'FederatedUser'
      expect(contextKeys['aws:PrincipalType']).toBe('FederatedUser')
    })

    it.todo('should set aws:PrincipalType to Anonymous for anonymous requests', async () => {
      // Not implemented yet
    })

    it('should not set aws:PrincipalType for service principals', async () => {
      // Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:PrincipalType should not be set
      expect(contextKeys['aws:PrincipalType']).toBeUndefined()
    })
  })

  describe('aws:userid', () => {
    it('should set aws:userid to the account Id for a root user', async () => {
      // Given a simulation request with a root user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:root'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:userid should be the account ID
      expect(contextKeys['aws:userid']).toBe('123456789012')
    })

    it('should set aws:userid to the user unique ID for IAM users', async () => {
      // Given a simulation request with an IAM user principal
      const userArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: userArn
      }

      // Mock the collect client to return user metadata with a unique ID
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', userArn, 'metadata', {
        arn: userArn,
        id: 'AIDAEXAMPLE',
        name: 'test-user',
        path: '/',
        created: '2024-01-01T00:00:00Z'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:userid should be the user unique ID
      expect(contextKeys['aws:userid']).toBe('AIDAEXAMPLE')
    })

    it('should set aws:userid to `account:caller-specified-name` for federated users', async () => {
      // Given a simulation request with a federated user principal
      const principalArn = 'arn:aws:sts::123456789012:federated-user/Bob'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:userid should be '123456789012:Bob'
      expect(contextKeys['aws:userid']).toBe('123456789012:Bob')
    })

    it('should set aws:userid to `role-id:caller-specified-role-name` for assumed roles', async () => {
      // Given a simulation request with an assumed role principal
      const principalArn = 'arn:aws:sts::123456789012:assumed-role/MyRole/MySession'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: principalArn
      }

      // Mock the collect client to return role metadata with a unique ID
      const { store, client } = testStore()
      const roleArn = 'arn:aws:iam::123456789012:role/MyRole'
      await store.saveResourceMetadata('123456789012', roleArn, 'metadata', {
        arn: roleArn,
        id: 'AROAROLEID',
        name: 'MyRole',
        path: '/',
        created: '2024-01-01T00:00:00Z'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:userid should be 'AROAROLEID:MySession'
      expect(contextKeys['aws:userid']).toBe('AROAROLEID:MySession')
    })

    it('should not set aws:userid for IAM role principals', async () => {
      //Given a simulation request with a bare role ARN
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:role/MyRole'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:userid should not be set
      expect(contextKeys['aws:userid']).toBeUndefined()
    })

    it('should not set aws:userid for IAM role principals with a path', async () => {
      //Given a simulation request with a role ARN that includes a path
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:role/path/to/MyRole'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:userid should not be set
      expect(contextKeys['aws:userid']).toBeUndefined()
    })

    it('should not set aws:userid for service principals', async () => {
      // Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:userid should not be set
      expect(contextKeys['aws:userid']).toBeUndefined()
    })
    it.todo('should set aws:userid to `role-id:ec2-instance-id` for EC2 instances', async () => {})
    it.todo('should set aws:userid to anonymous for anonymous requests', async () => {})
  })

  describe('aws:username', () => {
    it('should set aws:username to the IAM user name for IAM users', async () => {
      // Given a simulation request with an IAM user principal
      const userArn = 'arn:aws:iam::123456789012:user/test-user'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: userArn
      }

      // Mock the collect client to return user metadata with a name
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', userArn, 'metadata', {
        arn: userArn,
        id: 'AIDAEXAMPLE',
        name: 'test-user',
        path: '/',
        created: '2024-01-01T00:00:00Z'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:username should be the IAM user name
      expect(contextKeys['aws:username']).toBe('test-user')
    })

    it('should not set aws:username for assumed roles', async () => {
      // Given a simulation request with an assumed role principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:sts::123456789012:assumed-role/MyRole/MySession'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:username should not be set
      expect(contextKeys['aws:username']).toBeUndefined()
    })

    it('should not set aws:username for service principals', async () => {
      // Given a simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:username should not be set
      expect(contextKeys['aws:username']).toBeUndefined()
    })
  })

  describe('aws:ResourceAccount', () => {
    it('should set aws:ResourceAccount to the account ID of the resource on the request', async () => {
      // Given a simulation request with a resource ARN containing an account ID
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn: 'arn:aws:s3:::test-bucket',
        resourceAccount: '123456789012'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:ResourceAccount should be set to the account ID
      expect(contextKeys['aws:ResourceAccount']).toBe('123456789012')
    })

    it('should not set aws:ResourceAccount for specific exceptions', async () => {
      // For example, ec2:CopySnapshot is a cross-account action and should not set aws:ResourceAccount
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        action: 'ec2:CopySnapshot',
        resourceAccount: '123456789012',
        principal: 'arn:aws:iam::123456789012:user/test-user'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:ResourceAccount should not be set
      expect(contextKeys['aws:ResourceAccount']).toBeUndefined()
    })
  })

  describe('aws:ResourceOrgPaths', () => {
    it('should set aws:ResourceOrgPaths to the organization paths for the resource', async () => {
      // Given a simulation request with a resource in an org
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:ResourceOrgPaths should be set to the org path
      expect(contextKeys['aws:ResourceOrgPaths']).toEqual([`${orgId}/${rootOu}/${ou1}/${ou2}/`])
    })

    it('should not set aws:ResourceOrgPaths for resources not in an organization', async () => {
      // Given a simulation request with a resource not in an org
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }
      const { client } = testStore()

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:ResourceOrgPaths should not be set
      expect(contextKeys['aws:ResourceOrgPaths']).toBeUndefined()
    })

    it('should not set aws:ResourceOrgPaths for specific actions', async () => {
      // For example, ec2:CopySnapshot is a cross-account action and should not set aws:ResourceOrgPaths
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012',
        action: 'ec2:CopySnapshot'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:ResourceOrgPaths should not be set
      expect(contextKeys['aws:ResourceOrgPaths']).toBeUndefined()
    })
  })

  describe('aws:ResourceOrgID', () => {
    it('should set aws:ResourceOrgID to the organization ID for the resource account', async () => {
      // Given a simulation request with a resource in an org
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:ResourceOrgId should be set to the organization ID
      expect(contextKeys['aws:ResourceOrgID']).toBe(orgId)
    })

    it('should not set aws:ResourceOrgID for resources not in an organization', async () => {
      // Given a simulation request with a resource not in an org
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }
      const { client } = testStore()

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:ResourceOrgID should not be set
      expect(contextKeys['aws:ResourceOrgID']).toBeUndefined()
    })

    it('should not set aws:ResourceOrgID for specific actions', async () => {
      // For example, ec2:CopySnapshot is a cross-account action and should not set aws:ResourceOrgID
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012',
        action: 'ec2:CopySnapshot'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:ResourceOrgID should not be set
      expect(contextKeys['aws:ResourceOrgID']).toBeUndefined()
    })
  })

  describe('aws:ResourceTag/tag-key', () => {
    it('should set aws:ResourceTag/tag-key for each tag on the resource', async () => {
      // Given a simulation request with a resource that has tags
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return tags for the resource
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', resourceArn, 'tags', {
        Environment: 'prod',
        Owner: 'alice'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:ResourceTag/Environment and aws:ResourceTag/Owner should be set
      expect(contextKeys['aws:ResourceTag/Environment']).toBe('prod')
      expect(contextKeys['aws:ResourceTag/Owner']).toBe('alice')
    })

    it('should not set any key starting with aws:ResourceTag/ if the resource has no tags', async () => {
      // Given a simulation request with a resource that has no tags
      const resourceArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return no tags for the resource
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', resourceArn, 'tags', {})

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then no aws:ResourceTag/ keys should be set
      const tagKeys = Object.keys(contextKeys).filter((key) => key.startsWith('aws:ResourceTag/'))
      expect(tagKeys.length).toBe(0)
    })
  })

  describe('s3:BucketTag/tag-key', () => {
    it('should set s3:BucketTag/tag-key for each tag on an S3 bucket', async () => {
      // Given a simulation request with an S3 bucket ARN that has tags
      const bucketArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn: bucketArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return tags for the bucket
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', bucketArn, 'tags', {
        Environment: 'production',
        Owner: 'data-team'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then s3:BucketTag/Environment and s3:BucketTag/Owner should be set
      expect(contextKeys['s3:BucketTag/Environment']).toBe('production')
      expect(contextKeys['s3:BucketTag/Owner']).toBe('data-team')
    })

    it('should set s3:BucketTag/tag-key for each tag on an S3 object ARN', async () => {
      // Given a simulation request with an S3 object ARN that has tags on the bucket
      const bucketArn = 'arn:aws:s3:::test-bucket'
      const objectArn = `${bucketArn}/path/to/object.txt`
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn: objectArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return tags for the bucket
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', bucketArn, 'tags', {
        Project: 'analytics',
        CostCenter: '12345'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then s3:BucketTag/Project and s3:BucketTag/CostCenter should be set
      expect(contextKeys['s3:BucketTag/Project']).toBe('analytics')
      expect(contextKeys['s3:BucketTag/CostCenter']).toBe('12345')
    })

    it('should not set any key starting with s3:BucketTag/ if the bucket has no tags', async () => {
      // Given a simulation request with an S3 bucket ARN that has no tags
      const bucketArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn: bucketArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return no tags for the bucket
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', bucketArn, 'tags', {})

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then no s3:BucketTag/ keys should be set
      const tagKeys = Object.keys(contextKeys).filter((key) => key.startsWith('s3:BucketTag/'))
      expect(tagKeys.length).toBe(0)
    })

    it('should not set s3:BucketTag/tag-key for non-S3 resources', async () => {
      // Given a simulation request with a non-S3 resource ARN
      const resourceArn = 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return tags for the resource
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', resourceArn, 'tags', {
        Environment: 'test',
        Owner: 'app-team'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 'dynamodb', {})

      // Then no s3:BucketTag/ keys should be set (but aws:ResourceTag/ should be set)
      const s3TagKeys = Object.keys(contextKeys).filter((key) => key.startsWith('s3:BucketTag/'))
      expect(s3TagKeys.length).toBe(0)
      expect(contextKeys['aws:ResourceTag/Environment']).toBe('test')
      expect(contextKeys['aws:ResourceTag/Owner']).toBe('app-team')
    })

    it('should set both aws:ResourceTag/ and s3:BucketTag/ for S3 buckets', async () => {
      // Given a simulation request with an S3 bucket ARN
      const bucketArn = 'arn:aws:s3:::test-bucket'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        resourceArn: bucketArn,
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return tags for the bucket
      const { store, client } = testStore()
      await store.saveResourceMetadata('123456789012', bucketArn, 'tags', {
        Team: 'platform',
        Compliance: 'required'
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then both aws:ResourceTag/ and s3:BucketTag/ should be set with the same values
      expect(contextKeys['aws:ResourceTag/Team']).toBe('platform')
      expect(contextKeys['aws:ResourceTag/Compliance']).toBe('required')
      expect(contextKeys['s3:BucketTag/Team']).toBe('platform')
      expect(contextKeys['s3:BucketTag/Compliance']).toBe('required')
    })
  })

  describe('aws:SecureTransport', () => {
    it('should always set aws:SecureTransport to true', async () => {
      // Given a simulation request
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceArn: 'arn:aws:s3:::test-bucket',
        action: 's3:GetObject'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:SecureTransport should always be true
      expect(contextKeys['aws:SecureTransport']).toBe('true')
    })
  })

  describe('aws:CurrentTime', () => {
    it('should set aws:CurrentTime to the current time in ISO format', async () => {
      // Given a simulation request
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceArn: 'arn:aws:s3:::test-bucket',
        action: 's3:GetObject'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:CurrentTime should be set to the current time in ISO format
      const currentTime = new Date(contextKeys['aws:CurrentTime'] as string)
      expect(currentTime.toISOString()).toBeDefined()
    })
  })

  describe('aws:EpochTime', () => {
    it('should set aws:EpochTime to the current time in seconds since epoch', async () => {
      // Given a simulation request
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:EpochTime should be set to the current time in seconds since epoch
      const epochTime = parseInt(contextKeys['aws:EpochTime'] as string, 10)
      expect(epochTime).toBeGreaterThan(0)
    })
  })

  describe('aws:SourceAccount', () => {
    it('should set aws:SourceAccount to the account ID of the resource for service principals', async () => {
      // Given a simulation request with a service principal and a resource account
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com',
        resourceAccount: '123456789012'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:SourceAccount should be set to the resource account ID
      expect(contextKeys['aws:SourceAccount']).toBe('123456789012')
    })

    it('should not set aws:SourceAccount for IAM users or roles', async () => {
      // Given a simulation request with an IAM user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceAccount: '123456789012'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:SourceAccount should not be set
      expect(contextKeys['aws:SourceAccount']).toBeUndefined()
    })
  })

  describe('aws:SourceArn', () => {
    it('should set aws:SourceArn for service principals in Discovery mode', async () => {
      //Given a Discovery simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        simulationMode: 'Discovery',
        principal: 'cloudtrail.amazonaws.com',
        resourceAccount: '123456789012'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:SourceArn should be present so Discovery can treat its value as unknown
      expect(contextKeys['aws:SourceArn']).toMatch(/^arn:aws:/)
    })

    it('should not set aws:SourceArn for IAM users or roles in Discovery mode', async () => {
      //Given a Discovery simulation request with an IAM user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        simulationMode: 'Discovery',
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceAccount: '123456789012'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:SourceArn should not be set
      expect(contextKeys['aws:SourceArn']).toBeUndefined()
    })

    it('should not set aws:SourceArn for service principals in Strict mode', async () => {
      //Given a Strict simulation request with a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        simulationMode: 'Strict',
        principal: 'cloudtrail.amazonaws.com',
        resourceAccount: '123456789012'
      }

      //When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      //Then aws:SourceArn should not be set without an explicit context override
      expect(contextKeys['aws:SourceArn']).toBeUndefined()
    })
  })

  describe('aws:SourceOwner', () => {
    it('should set aws:SourceOwner to the owner of the resource account for service principals', async () => {
      // Given a simulation request with a service principal and a resource account
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com',
        resourceAccount: '123456789012'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:SourceAccount should be set to the resource account ID
      expect(contextKeys['aws:SourceOwner']).toBe('123456789012')
    })

    it('should not set aws:SourceOwner for IAM users or roles', async () => {
      // Given a simulation request with an IAM user principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceAccount: '123456789012'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then aws:SourceAccount should not be set
      expect(contextKeys['aws:SourceOwner']).toBeUndefined()
    })
  })

  describe('aws:SourceOrgID', () => {
    it('should set aws:SourceOrgID to the organization ID of the resource account for service principals', async () => {
      // Given a simulation request with a service principal and a resource account in an org
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com',
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:SourceOrgID should be set to the org ID
      expect(contextKeys['aws:SourceOrgID']).toBe(orgId)
    })

    it('should not set aws:SourceOrgID for IAM users or roles', async () => {
      // Given a simulation request with an IAM user principal and a resource account in an org
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:SourceOrgID should not be set
      expect(contextKeys['aws:SourceOrgID']).toBeUndefined()
    })

    it('should not set aws:SourceOrgID for resources not in an organization', async () => {
      // Given a simulation request with a service principal and a resource account not in an org
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com',
        resourceAccount: '123456789012'
      }
      const { client } = testStore()

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:SourceOrgID should not be set
      expect(contextKeys['aws:SourceOrgID']).toBeUndefined()
    })
  })

  describe('aws:SourceOrgPaths', () => {
    it('should set aws:SourceOrgPaths to the organization paths for the resource account for service principals', async () => {
      // Given a simulation request with a service principal and a resource account in an org
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com',
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:SourceOrgPaths should be set to the org path
      expect(contextKeys['aws:SourceOrgPaths']).toEqual([`${orgId}/${rootOu}/${ou1}/${ou2}/`])
    })

    it('should not set aws:SourceOrgPaths for IAM users or roles', async () => {
      // Given a simulation request with an IAM user principal and a resource account in an org
      const orgId = 'o-1234567890'
      const rootOu = 'r-root'
      const ou1 = 'ou-root-1'
      const ou2 = 'ou-root-2'
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        resourceAccount: '123456789012'
      }

      // Mock the collect client to return org structure for the resource account
      const { store, client } = testStore()
      await store.saveIndex(
        'accounts-to-orgs',
        {
          ['123456789012']: orgId
        },
        ''
      )
      await store.saveOrganizationMetadata(orgId, 'accounts', {
        ['123456789012']: { ou: ou2 }
      })
      await store.saveOrganizationMetadata(orgId, 'ous', {
        [rootOu]: {},
        [ou1]: { parent: rootOu },
        [ou2]: { parent: ou1 }
      })

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:SourceOrgPaths should not be set
      expect(contextKeys['aws:SourceOrgPaths']).toBeUndefined()
    })

    it('should not set aws:SourceOrgPaths for resources not in an organization', async () => {
      // Given a simulation request with a service principal and a resource account not in an org
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'lambda.amazonaws.com',
        resourceAccount: '123456789012'
      }
      const { client } = testStore()

      // When creating context keys
      const { contextKeys } = await createContextKeys(client, simulationRequest, 's3', {})

      // Then aws:SourceOrgPaths should not be set
      expect(contextKeys['aws:SourceOrgPaths']).toBeUndefined()
    })
  })

  describe('kms:CallerAccount', () => {
    it('should set kms:CallerAccount for KMS actions', async () => {
      // Given a simulation request with a KMS action
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        action: 'kms:Encrypt'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        'kms',
        {}
      )

      // Then kms:CallerAccount should be set to the principal's account ID
      expect(contextKeys['kms:CallerAccount']).toBe('123456789012')
    })

    it('should set a placeholder kms:CallerAccount for KMS service-principal requests', async () => {
      // Given a KMS request made by a service on behalf of an unknown caller account
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'ecr.amazonaws.com',
        action: 'kms:Encrypt'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        'kms',
        {}
      )

      // Then discovery should model the service-mediated caller account as unknown
      expect(contextKeys['kms:CallerAccount']).toBe(servicePrincipalKmsCallerAccountPlaceholder)
    })

    it('should not set kms:CallerAccount for non-KMS service-principal requests', async () => {
      // Given a non-KMS request made by a service principal
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'ecr.amazonaws.com',
        action: 's3:PutObject'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then kms:CallerAccount should not be set
      expect(contextKeys['kms:CallerAccount']).toBeUndefined()
    })

    it('should not set kms:CallerAccount for non-KMS actions', async () => {
      // Given a simulation request with a non-KMS action
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest,
        principal: 'arn:aws:iam::123456789012:user/test-user',
        action: 's3:GetObject'
      }

      // When creating context keys
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        {}
      )

      // Then kms:CallerAccount should not be set
      expect(contextKeys['kms:CallerAccount']).toBeUndefined()
    })
  })

  describe('overrides', () => {
    it('should apply overrides to context keys', async () => {
      // Given a simulation request and an override for a context key
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest
      }
      const overrides = {
        'aws:PrincipalAccount': 'override-account',
        'aws:CustomKey': 'custom-value'
      }

      // When creating context keys with overrides
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        overrides
      )

      // Then the override should take precedence
      expect(contextKeys['aws:PrincipalAccount']).toBe('override-account')
      expect(contextKeys['aws:CustomKey']).toBe('custom-value')
    })

    it('should add keys that are in the overrides only', async () => {
      // Given a simulation request and an override for a key not otherwise set
      const simulationRequest: SimulationRequest = {
        ...defaultSimulationRequest
      }
      const overrides = {
        'aws:ExtraKey': 'extra-value'
      }

      // When creating context keys with overrides
      const { contextKeys } = await createContextKeys(
        testStore().client,
        simulationRequest,
        's3',
        overrides
      )

      // Then the override key should be present
      expect(contextKeys['aws:ExtraKey']).toBe('extra-value')
    })
  })

  describe('VPC Endpoint Data', () => {
    describe('aws:SourceVpc', () => {
      it('should set aws:SourceVpc when VPC endpoint ID is provided and VPC ID is not', async () => {
        // Given a simulation request with a VPC endpoint ID in context overrides
        const vpcEndpointId = 'vpce-12345678'
        const vpcId = 'vpc-87654321'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: vpcId
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:SourceVpc should be set to the VPC ID
        expect(contextKeys['aws:SourceVpc']).toBe(vpcId)
        expect(contextKeys['aws:SourceVpce']).toBe(vpcEndpointId)
      })

      it('should not override aws:SourceVpc if already provided in context', async () => {
        // Given a simulation request with both VPC ID and VPC endpoint ID in context
        const vpcEndpointId = 'vpce-12345678'
        const providedVpcId = 'vpc-provided'
        const lookupVpcId = 'vpc-87654321'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: lookupVpcId
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpc': providedVpcId,
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:SourceVpc should remain the provided value
        expect(contextKeys['aws:SourceVpc']).toBe(providedVpcId)
        expect(contextKeys['aws:SourceVpce']).toBe(vpcEndpointId)
      })
    })

    describe('aws:SourceVpce', () => {
      it('should lookup VPC endpoint ID when VPC ID is provided but endpoint ID is not', async () => {
        // Given a simulation request with a VPC ID but no endpoint ID
        const vpcId = 'vpc-87654321'
        const vpcEndpointId = 'vpce-12345678'
        const service = 's3'

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC data with an endpoint for the service
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: `arn:aws:ec2:us-east-1:123456789012:vpc/${vpcId}`,
                endpoints: [
                  {
                    id: vpcEndpointId,
                    service: service
                  },
                  {
                    id: 'vpce-99999999',
                    service: 'lambda'
                  }
                ]
              }
            },
            endpoints: {}
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpc': vpcId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          service,
          contextOverrides
        )

        // Then aws:SourceVpce should be set to the looked up endpoint ID
        expect(contextKeys['aws:SourceVpc']).toBe(vpcId)
        expect(contextKeys['aws:SourceVpce']).toBe(vpcEndpointId)
      })

      it('should not override aws:SourceVpce if already provided in context', async () => {
        // Given a simulation request with both VPC ID and VPC endpoint ID already provided
        const vpcId = 'vpc-87654321'
        const providedEndpointId = 'vpce-provided'
        const lookupEndpointId = 'vpce-12345678'
        const service = 's3'

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: `arn:aws:ec2:us-east-1:123456789012:vpc/${vpcId}`,
                endpoints: [
                  {
                    id: lookupEndpointId,
                    service: service
                  }
                ]
              }
            },
            endpoints: {}
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpc': vpcId,
          'aws:SourceVpce': providedEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          service,
          contextOverrides
        )

        // Then aws:SourceVpce should remain the provided value
        expect(contextKeys['aws:SourceVpc']).toBe(vpcId)
        expect(contextKeys['aws:SourceVpce']).toBe(providedEndpointId)
      })
    })

    describe('aws:VpceAccount', () => {
      it('should set aws:VpceAccount for services that support extra VPC endpoint data', async () => {
        // Given a simulation request for a service that supports extra VPC endpoint data
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject' // s3 supports extra VPC endpoint data
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: 'vpc-87654321'
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:VpceAccount should be set to the account ID from the VPC endpoint ARN
        expect(contextKeys['aws:VpceAccount']).toBe(accountId)
      })

      it('should not set aws:VpceAccount for services that do not support extra VPC endpoint data', async () => {
        // Given a simulation request for a service that does not support extra VPC endpoint data
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 'ec2:DescribeInstances' // ec2 does not support extra VPC endpoint data
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: 'vpc-87654321'
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          'ec2',
          contextOverrides
        )

        // Then aws:VpceAccount should not be set
        expect(contextKeys['aws:VpceAccount']).toBeUndefined()
      })

      it('should not override aws:VpceAccount if already provided in context', async () => {
        // Given a simulation request with aws:VpceAccount already in context
        const vpcEndpointId = 'vpce-12345678'
        const providedAccount = '999999999999'
        const lookupAccount = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${lookupAccount}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: 'vpc-87654321'
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId,
          'aws:VpceAccount': providedAccount
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:VpceAccount should remain the provided value
        expect(contextKeys['aws:VpceAccount']).toBe(providedAccount)
      })
    })

    describe('aws:SourceVpcArn', () => {
      it('should set aws:SourceVpcArn for services that support extra VPC endpoint data', async () => {
        // Given a simulation request for a service that supports extra VPC endpoint data
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`
        const vpcId = 'vpc-87654321'
        const vpcArn = `arn:aws:ec2:us-east-1:${accountId}:vpc/${vpcId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject' // s3 supports extra VPC endpoint data
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: vpcArn,
                endpoints: [
                  {
                    id: vpcEndpointId,
                    service: 's3'
                  }
                ]
              }
            },
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: vpcId
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:SourceVpcArn should be set to the VPC ARN
        expect(contextKeys['aws:SourceVpcArn']).toBe(vpcArn)
      })

      it('should not set aws:SourceVpcArn for services that do not support extra VPC endpoint data', async () => {
        // Given a simulation request for a service that does not support extra VPC endpoint data
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`
        const vpcId = 'vpc-87654321'
        const vpcArn = `arn:aws:ec2:us-east-1:${accountId}:vpc/${vpcId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 'ec2:DescribeInstances' // ec2 does not support extra VPC endpoint data
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: vpcArn,
                endpoints: [
                  {
                    id: vpcEndpointId,
                    service: 's3'
                  }
                ]
              }
            },
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: vpcId
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          'ec2',
          contextOverrides
        )

        // Then aws:SourceVpcArn should not be set
        expect(contextKeys['aws:SourceVpcArn']).toBeUndefined()
      })

      it('should not override aws:SourceVpcArn if already provided in context', async () => {
        // Given a simulation request with aws:SourceVpcArn already in context
        const vpcEndpointId = 'vpce-12345678'
        const lookupAccount = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${lookupAccount}:vpc-endpoint/${vpcEndpointId}`
        const vpcId = 'vpc-87654321'
        const vpcArn = `arn:aws:ec2:us-east-1:${lookupAccount}:vpc/${vpcId}`
        const providedVpcArn = `arn:aws:ec2:us-east-1:999999999999:vpc/vpc-provided`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: vpcArn,
                endpoints: [
                  {
                    id: vpcEndpointId,
                    service: 's3'
                  }
                ]
              }
            },
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: vpcId
              }
            }
          },
          ''
        )

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId,
          'aws:SourceVpcArn': providedVpcArn
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:SourceVpcArn should remain the provided value
        expect(contextKeys['aws:SourceVpcArn']).toBe(providedVpcArn)
      })
    })

    describe('aws:VpceOrgID', () => {
      it('should set aws:VpceOrgID when VPC endpoint account is in an organization', async () => {
        // Given a VPC endpoint in an account that belongs to an organization
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const orgId = 'o-87654321'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint and organization data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: 'vpc-87654321'
              }
            }
          },
          ''
        )
        await store.saveIndex(
          'accounts-to-orgs',
          {
            [accountId]: orgId
          },
          ''
        )
        await store.saveOrganizationMetadata(orgId, 'accounts', {
          [accountId]: { ou: 'ou-root-1' }
        })
        await store.saveOrganizationMetadata(orgId, 'ous', {
          'r-root': {},
          'ou-root-1': { parent: 'r-root' }
        })

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:VpceOrgID should be set to the organization ID
        expect(contextKeys['aws:VpceOrgID']).toBe(orgId)
      })

      it('should not set aws:VpceOrgID when VPC endpoint account is not in an organization', async () => {
        // Given a VPC endpoint in an account that is not in an organization
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint data (no organization mapping)
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: 'vpc-87654321'
              }
            }
          },
          ''
        )
        await store.saveIndex('accounts-to-orgs', {}, '')

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:VpceOrgID should not be set
        expect(contextKeys['aws:VpceOrgID']).toBeUndefined()
      })
    })

    describe('aws:VpceOrgPaths', () => {
      it('should set aws:VpceOrgPaths when VPC endpoint account has organization unit hierarchy', async () => {
        // Given a VPC endpoint in an account with organizational unit hierarchy
        const vpcEndpointId = 'vpce-12345678'
        const accountId = '123456789012'
        const orgId = 'o-87654321'
        const rootOu = 'r-root'
        const ou1 = 'ou-root-1'
        const ou2 = 'ou-root-2'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock the VPC endpoint and organization data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {},
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: 'vpc-87654321'
              }
            }
          },
          ''
        )
        await store.saveIndex(
          'accounts-to-orgs',
          {
            [accountId]: orgId
          },
          ''
        )
        await store.saveOrganizationMetadata(orgId, 'accounts', {
          [accountId]: { ou: ou2 }
        })
        await store.saveOrganizationMetadata(orgId, 'ous', {
          [rootOu]: {},
          [ou1]: { parent: rootOu },
          [ou2]: { parent: ou1 }
        })

        const contextOverrides = {
          'aws:SourceVpce': vpcEndpointId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then aws:VpceOrgPaths should be set to the organization path
        expect(contextKeys['aws:VpceOrgPaths']).toEqual([`${orgId}/${rootOu}/${ou1}/${ou2}/`])
      })
    })

    describe('integration tests', () => {
      it('should set all VPC endpoint context keys when aws:SourceVpc is set', async () => {
        // Given a complete VPC endpoint setup
        const vpcEndpointId = 'vpce-12345678'
        const vpcId = 'vpc-87654321'
        const accountId = '123456789012'
        const orgId = 'o-87654321'
        const rootOu = 'r-root'
        const ou1 = 'ou-root-1'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`
        const vpcArn = `arn:aws:ec2:us-east-1:${accountId}:vpc/${vpcId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock complete VPC endpoint and organization data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: vpcArn,
                endpoints: [
                  {
                    id: vpcEndpointId,
                    service: 's3'
                  }
                ]
              }
            },
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: vpcId
              }
            }
          },
          ''
        )
        await store.saveIndex(
          'accounts-to-orgs',
          {
            [accountId]: orgId
          },
          ''
        )
        await store.saveOrganizationMetadata(orgId, 'accounts', {
          [accountId]: { ou: ou1 }
        })
        await store.saveOrganizationMetadata(orgId, 'ous', {
          [rootOu]: {},
          [ou1]: { parent: rootOu }
        })

        const contextOverrides = {
          'aws:SourceVpc': vpcId
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then all VPC endpoint context keys should be set
        expect(contextKeys['aws:SourceVpc']).toBe(vpcId)
        expect(contextKeys['aws:SourceVpce']).toBe(vpcEndpointId)
        expect(contextKeys['aws:VpceAccount']).toBe(accountId)
        expect(contextKeys['aws:VpceOrgID']).toBe(orgId)
        expect(contextKeys['aws:VpceOrgPaths']).toEqual([`${orgId}/${rootOu}/${ou1}/`])
        expect(contextKeys['aws:SourceVpcArn']).toBe(vpcArn)
      })

      it('should set all VPC endpoint context keys when aws:SourceVpcArn is set', async () => {
        // Given a complete VPC endpoint setup
        const vpcEndpointId = 'vpce-12345678'
        const vpcId = 'vpc-87654321'
        const accountId = '123456789012'
        const orgId = 'o-87654321'
        const rootOu = 'r-root'
        const ou1 = 'ou-root-1'
        const vpcEndpointArn = `arn:aws:ec2:us-east-1:${accountId}:vpc-endpoint/${vpcEndpointId}`
        const vpcArn = `arn:aws:ec2:us-east-1:${accountId}:vpc/${vpcId}`

        const simulationRequest: SimulationRequest = {
          ...defaultSimulationRequest,
          principal: 'arn:aws:iam::123456789012:user/test-user',
          action: 's3:GetObject'
        }

        // Mock complete VPC endpoint and organization data
        const { store, client } = testStore()
        await store.saveIndex(
          'vpcs',
          {
            vpcs: {
              [vpcId]: {
                arn: vpcArn,
                endpoints: [
                  {
                    id: vpcEndpointId,
                    service: 's3'
                  }
                ]
              }
            },
            endpoints: {
              [vpcEndpointId]: {
                arn: vpcEndpointArn,
                vpc: vpcId
              }
            }
          },
          ''
        )
        await store.saveIndex(
          'accounts-to-orgs',
          {
            [accountId]: orgId
          },
          ''
        )
        await store.saveOrganizationMetadata(orgId, 'accounts', {
          [accountId]: { ou: ou1 }
        })
        await store.saveOrganizationMetadata(orgId, 'ous', {
          [rootOu]: {},
          [ou1]: { parent: rootOu }
        })

        const contextOverrides = {
          'aws:SourceVpcArn': vpcArn
        }

        // When creating context keys
        const { contextKeys } = await createContextKeys(
          client,
          simulationRequest,
          's3',
          contextOverrides
        )

        // Then all VPC endpoint context keys should be set
        expect(contextKeys['aws:SourceVpc']).toBe(vpcId)
        expect(contextKeys['aws:SourceVpce']).toBe(vpcEndpointId)
        expect(contextKeys['aws:VpceAccount']).toBe(accountId)
        expect(contextKeys['aws:VpceOrgID']).toBe(orgId)
        expect(contextKeys['aws:VpceOrgPaths']).toEqual([`${orgId}/${rootOu}/${ou1}/`])
        expect(contextKeys['aws:SourceVpcArn']).toBe(vpcArn)
      })
    })
  })
})
