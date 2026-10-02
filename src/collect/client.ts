import { type AwsIamStore } from '@actsecurity/iam-collect'
import { log } from '@actsecurity/log'
import { actionMatchesPattern } from '@actsecurity/iam-expand'
import {
  createValidatedPolicy,
  loadPolicy,
  type Policy,
  type ValidatedPolicy,
  validateIdentityPolicy,
  validateResourceControlPolicy,
  validateResourcePolicy,
  validateServiceControlPolicy,
  validateEndpointPolicy,
  validateTrustPolicy
} from '@actsecurity/iam-policy'
import {
  convertAssumedRoleArnToRoleArn,
  isAssumedRoleArn,
  splitArnParts
} from '@actsecurity/iam-utils'
import BitSet from 'bitset'
import { gunzipSync, gzipSync } from 'zlib'
import { decodeBitSet, decompressPrincipalString } from '../utils/bitset.js'

//TODO: Import this from iam-simulate
export interface SimulationOrgPolicies {
  orgIdentifier: string
  policies: { name: string; policy: ValidatedPolicy<{ name: string }> }[]
}

interface IamUserMetadata {
  arn: string
  path: string
  permissionBoundary: string
  id: string
  name: string
  created: string
}

interface ResourceMetadata {
  arn: string
}

/**
 * Collected metadata that determines whether a KMS key is AWS-managed.
 */
interface KmsKeyMetadata {
  awsManaged?: boolean
}

/**
 * Collected S3 Public Access Block configuration metadata for an account or bucket.
 */
interface S3PublicAccessBlockMetadata {
  /** Whether public ACLs are blocked when new ACLs are applied. */
  BlockPublicAcls?: boolean
  /** Whether public ACLs are ignored when evaluating access. */
  IgnorePublicAcls?: boolean
  /** Whether public bucket policies are blocked when new policies are applied. */
  BlockPublicPolicy?: boolean
  /** Whether public and cross-account bucket policies are restricted at authorization time. */
  RestrictPublicBuckets?: boolean
}

interface InlinePolicyMetadata {
  PolicyName: string
  PolicyDocument: any
}

export interface OrgPolicy {
  arn: string
  name: string
  policy: ValidatedPolicy<{ name: string }>
}

interface ManagedPolicyMetadata {
  arn: string
  name: string
}

export interface ManagedPolicy {
  arn: string
  name: string
  policy: ValidatedPolicy<{ name: string }>
}

export interface InlinePolicy {
  name: string
  policy: ValidatedPolicy<{ name: string }>
}

interface OrgAccount {
  ou: string
  rcps: string[]
  scps: string[]
}

type OrgAccounts = Record<string, OrgAccount>

interface StoredOrgPolicyMetadata {
  arn: string
  name: string
  awsManaged: boolean
}

interface OrgUnitDetails {
  parent: string | undefined
  scps: string[]
  rcps: string[]
}

type OrgUnits = Record<string, OrgUnitDetails>

export type OrgPolicyType = 'scps' | 'rcps'

interface OrganizationMetadata {
  id: string
  arn: string
  rootOu: string
  rootAccountArn: string
  rootAccountId: string
  features: {
    AISERVICES_OPT_OUT_POLICY?: boolean
    BACKUP_POLICY?: boolean
    RESOURCE_CONTROL_POLICY?: boolean
    SERVICE_CONTROL_POLICY?: boolean
    TAG_POLICY?: boolean
  }
}

interface RAMShare {
  arn: string
  shares: string[]
  policy: any
}

interface OrgStructureNode {
  children?: OrgStructure | undefined
  accounts?: string[] | undefined
}

interface OrgStructure {
  [key: string]: OrgStructureNode
}

export interface VpcIndex {
  vpcs: Record<string, { arn: string; endpoints: { id: string; service: string }[] }>

  endpoints: Record<string, { arn: string; vpc: string }>
}

type Service = string
type Action = string

export type ServiceIamActionCache = {
  action?: Record<Action, BitSet>
  notAction?: Record<Action, BitSet>
}

export type IamActionCache = {
  prefix: string
  principals: string[]
  accounts: Record<string, number[]>
  action: Record<Service, Record<Action, BitSet>>
  notAction: Record<Service, Record<Action, BitSet>>
}

/**
 * Normalize an S3 bucket or object ARN to the bucket ARN used by iam-collect bucket metadata.
 *
 * @param bucketOrObjectArn The S3 bucket or object ARN to normalize
 * @returns The bucket ARN without an object key suffix
 */
function bucketArnFromBucketOrObjectArn(bucketOrObjectArn: string): string {
  // S3 bucket ARNs use the first slash to separate the bucket name from the object key.
  if (bucketOrObjectArn.includes('/')) {
    return bucketOrObjectArn.split('/').at(0)!
  }
  return bucketOrObjectArn
}

/**
 * Options for the IamCollectClient.
 */
export interface IamCollectClientOptions {
  /**
   * Which {@link CacheProvider} to use for caching results.
   */
  cacheProvider?: CacheProvider
}

/**
 * An interface for a cache provider that can be used to cache results.
 */
export interface CacheProvider {
  withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T>
}

/**
 * A cache provider that stores results in memory for a single worker.
 */
export class InMemoryCacheProvider implements CacheProvider {
  private cache: Record<string, any> = {}

  public async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    if (cacheKey in this.cache) {
      return this.cache[cacheKey]
    }
    const value = await fetcher()
    this.cache[cacheKey] = value
    return value
  }
}

/**
 * A cache provider that does not cache results.
 */
export class NoCacheProvider implements CacheProvider {
  public async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    return fetcher()
  }
}

/**
 * A client for simplifying access to the IAM collect data store.
 */
export class IamCollectClient {
  private cacheProvider: CacheProvider

  /**
   * Creates a new instance of the IamCollectClient.
   *
   * @param storageClient the iam-collect storage client to use for data access
   * @param clientOptions optional configuration options for the client. By default, uses an in-memory cache provider.
   */
  constructor(
    private storageClient: AwsIamStore,
    clientOptions?: IamCollectClientOptions
  ) {
    if (clientOptions?.cacheProvider === undefined) {
      this.cacheProvider = new InMemoryCacheProvider()
    } else {
      this.cacheProvider = clientOptions.cacheProvider
    }
  }

  public getStore(): AwsIamStore {
    return this.storageClient
  }

  /**
   * Returns the cache provider used by this client.
   *
   * @returns The {@link CacheProvider} instance in use.
   */
  public getCacheProvider(): CacheProvider {
    return this.cacheProvider
  }

  private async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    return this.cacheProvider.withCache<T>(cacheKey, fetcher)
  }

  /**
   * Checks if an account exists in the store.
   * @param accountId The ID of the account to check.
   * @returns True if the account exists, false otherwise.
   */
  async accountExists(accountId: string): Promise<boolean> {
    const cacheKey = `accountExists:${accountId}`
    return this.withCache(cacheKey, async () => {
      const accounts = await this.storageClient.listAccountIds()
      return accounts.includes(accountId)
    })
  }

  /**
   * Get all account IDs in the store.
   *
   * @returns all account IDs in the store
   */
  async allAccounts(): Promise<string[]> {
    const cacheKey = `allAccounts`
    return this.withCache(cacheKey, async () => {
      return this.storageClient.listAccountIds()
    })
  }

  /**
   * Resolves a principal ARN to the canonical ARN stored in the collect data.
   *
   * STS assumed-role ARNs are first converted to their IAM role ARN form. Exact metadata
   * matches are returned first. If an IAM role ARN is not found exactly, the role is
   * resolved by role name within the same account. This supports STS assumed-role
   * session ARNs because those session ARNs do not include the IAM role path.
   *
   * @param principalArn The ARN of the principal to resolve.
   * @returns The canonical stored principal ARN, or undefined if no matching principal exists.
   */
  async resolvePrincipalArn(principalArn: string): Promise<string | undefined> {
    const cacheKey = `resolvePrincipalArn:${principalArn}`
    return this.withCache(cacheKey, async () => {
      const lookupPrincipalArn = isAssumedRoleArn(principalArn)
        ? convertAssumedRoleArnToRoleArn(principalArn)
        : principalArn
      const arnParts = splitArnParts(lookupPrincipalArn)
      const accountId = arnParts.accountId!
      const principalData = await this.storageClient.getResourceMetadata<
        ResourceMetadata,
        ResourceMetadata
      >(accountId, lookupPrincipalArn, 'metadata')
      if (principalData) {
        return principalData.arn ?? lookupPrincipalArn
      }

      if (arnParts.service !== 'iam' || arnParts.resourceType !== 'role') {
        return undefined
      }

      const roleName = arnParts.resourcePath?.split('/').at(-1)?.toLowerCase()
      if (!roleName) {
        return undefined
      }

      const accountPrincipals = await this.getAllPrincipalsInAccount(accountId)
      const matchingRole = accountPrincipals.find((candidateArn) => {
        const candidateParts = splitArnParts(candidateArn)
        return (
          candidateParts.service === 'iam' &&
          candidateParts.resourceType === 'role' &&
          candidateParts.resourcePath?.split('/').at(-1)?.toLowerCase() === roleName
        )
      })

      return matchingRole
    })
  }

  /**
   * Checks if a principal exists in the store.
   * @param principalArn The ARN of the principal to check.
   * @returns True if the principal exists, false otherwise.
   */
  async principalExists(principalArn: string): Promise<boolean> {
    const cacheKey = `principalExists:${principalArn}`
    return this.withCache(cacheKey, async () => {
      return !!(await this.resolvePrincipalArn(principalArn))
    })
  }

  /**
   * Gets the SCP Hierarchy for an account. The first element is the root, the last element is the account itself.
   * @param accountId The ID of the account to get the SCP Hierarchy for.
   * @returns The SCP Hierarchy for the account.
   */
  async getScpHierarchyForAccount(accountId: string): Promise<SimulationOrgPolicies[]> {
    return this.getOrgPolicyHierarchyForAccount(accountId, 'scps')
  }

  /**
   * Gets the policy hierarchy for an account for a given policy type.
   * @param accountId The ID of the account.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @returns The policy hierarchy for the account.
   */
  async getOrgPolicyHierarchyForAccount(
    accountId: string,
    policyType: OrgPolicyType
  ): Promise<SimulationOrgPolicies[]> {
    const cacheKey = `orgPolicyHierarchy:${accountId}:${policyType}`
    return this.withCache(cacheKey, async () => {
      const orgId = await this.getOrgIdForAccount(accountId)
      if (!orgId) {
        return []
      }
      // SCPs and RCPs do not apply to the root account
      const orgMetadata = await this.getOrganizationMetadata(orgId)
      if (orgMetadata.rootAccountId === accountId) {
        return []
      }

      const policyHierarchy: SimulationOrgPolicies[] = []
      const orgHierarchy = await this.getOrgUnitHierarchyForAccount(accountId)

      for (const ouId of orgHierarchy) {
        const policies = await this.getOrgPoliciesForOrgUnit(orgId, ouId, policyType)

        policyHierarchy.push({
          orgIdentifier: ouId,
          policies: policies.map((p) => ({
            name: p.arn,
            policy: p.policy
          }))
        })
      }

      const accountPolicies = await this.getOrgPoliciesForAccount(accountId, policyType)
      policyHierarchy.push({
        orgIdentifier: accountId,
        policies: accountPolicies.map((p) => ({
          name: p.arn,
          policy: p.policy
        }))
      })

      return policyHierarchy
    })
  }

  /**
   * Gets the OUs for an account. The first element is the root,
   * the last element is the parent OU of the account.
   * @param accountId The ID of the account to get the OUs for.
   * @returns The OUs for the account.
   */
  async getOrgUnitHierarchyForAccount(accountId: string): Promise<string[]> {
    const cacheKey = `orgUnitHierarchy:${accountId}`
    return this.withCache(cacheKey, async () => {
      const orgId = await this.getOrgIdForAccount(accountId)
      if (!orgId) {
        return []
      }
      const ouIds: string[] = []
      let ouId = await this.getOrgUnitIdForAccount(accountId)
      ouIds.push(ouId!)
      while (ouId) {
        const parentOuId = await this.getParentOrgUnitIdForOrgUnit(orgId, ouId)
        if (parentOuId) {
          ouIds.unshift(parentOuId)
        }
        ouId = parentOuId
      }
      return ouIds
    })
  }

  /**
   * Gets the org unit ID for an account.
   * @param accountId The ID of the account.
   * @returns The org unit ID for the account, or undefined if not found.
   */
  async getOrgUnitIdForAccount(accountId: string): Promise<string | undefined> {
    const cacheKey = `orgUnitId:${accountId}`
    return this.withCache(cacheKey, async () => {
      const orgId = await this.getOrgIdForAccount(accountId)
      if (!orgId) {
        return undefined
      }

      const accounts = (await this.getAccountDataForOrg(orgId))!
      return accounts[accountId].ou
    })
  }

  /**
   * Gets the parent org unit ID for a given org unit.
   * @param orgId The ID of the organization.
   * @param ouId The ID of the org unit.
   * @returns The parent org unit ID, or undefined if not found.
   */
  async getParentOrgUnitIdForOrgUnit(orgId: string, ouId: string): Promise<string | undefined> {
    const cacheKey = `parentOrgUnit:${orgId}:${ouId}`
    return this.withCache(cacheKey, async () => {
      const ouData = await this.getOrgUnitsDataForOrg(orgId)
      const ou = ouData[ouId]
      return ou.parent
    })
  }

  /**
   * Gets the SCPs for an account.
   * @param accountId The ID of the account.
   * @returns The SCPs for the account.
   */
  async getScpsForAccount(accountId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForAccount(accountId, 'scps')
  }

  /**
   * Gets the org policies for an account for a given policy type.
   * @param accountId The ID of the account.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @returns The org policies for the account.
   */
  async getOrgPoliciesForAccount(
    accountId: string,
    policyType: OrgPolicyType
  ): Promise<OrgPolicy[]> {
    const cacheKey = `orgPoliciesForAccount:${accountId}:${policyType}`
    return this.withCache(cacheKey, async () => {
      const orgId = await this.getOrgIdForAccount(accountId)
      if (!orgId) {
        return []
      }

      const accounts = (await this.getAccountDataForOrg(orgId))!
      const orgInformation = accounts[accountId]
      const policyArns = orgInformation[policyType]
      const policies: OrgPolicy[] = []
      for (const policyArn of policyArns) {
        const policyInfo = await this.getOrgPolicy(orgId, policyType, policyArn)
        policies.push(policyInfo)
      }

      return policies
    })
  }

  /**
   * Gets the account data for an organization.
   * @param orgId The ID of the organization.
   * @returns The account data for the organization.
   */
  async getAccountDataForOrg(orgId: string): Promise<OrgAccounts | undefined> {
    const cacheKey = `accountDataForOrg:${orgId}`
    return this.withCache(cacheKey, async () => {
      return this.storageClient.getOrganizationMetadata<OrgAccounts, OrgAccounts>(orgId, 'accounts')
    })
  }

  /**
   * Gets the org units data for an organization.
   * @param orgId The ID of the organization.
   * @returns The org units data for the organization.
   */
  async getOrgUnitsDataForOrg(orgId: string): Promise<OrgUnits> {
    const cacheKey = `orgUnitsDataForOrg:${orgId}`
    return this.withCache(cacheKey, async () => {
      return this.storageClient.getOrganizationMetadata<OrgUnits, OrgUnits>(orgId, 'ous')
    })
  }

  /**
   * Gets a specific org policy.
   * @param orgId The ID of the organization.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @param policyArn The ARN of the policy.
   * @returns The org policy.
   */
  async getOrgPolicy(
    orgId: string,
    policyType: OrgPolicyType,
    policyArn: string
  ): Promise<OrgPolicy> {
    const cacheKey = `orgPolicy:${orgId}:${policyType}:${policyArn}`
    return this.withCache(cacheKey, async () => {
      const policyId = policyArn.split('/').at(-1)!
      const policyData = await this.storageClient.getOrganizationPolicyMetadata<
        StoredOrgPolicyMetadata,
        StoredOrgPolicyMetadata
      >(orgId, policyType, policyId, 'metadata')
      const policyDocument = await this.storageClient.getOrganizationPolicyMetadata(
        orgId,
        policyType,
        policyId,
        'policy'
      )
      if (!policyDocument) {
        log.warn(`Policy document not found for ${policyArn} in org ${orgId}`)
      }

      const validateFn =
        policyType === 'scps' ? validateServiceControlPolicy : validateResourceControlPolicy
      return {
        arn: policyData.arn,
        name: policyData.name,
        policy: createValidatedPolicy(policyDocument, validateFn, { name: policyData.arn })
      }
    })
  }

  /**
   * Gets the RCPs for an account.
   * @param accountId The ID of the account.
   * @returns The RCPs for the account.
   */
  async getRcpsForAccount(accountId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForAccount(accountId, 'rcps')
  }

  /**
   * Gets the RCP hierarchy for an account.
   * @param accountId The ID of the account.
   * @returns The RCP hierarchy for the account.
   */
  async getRcpHierarchyForAccount(accountId: string): Promise<SimulationOrgPolicies[]> {
    return this.getOrgPolicyHierarchyForAccount(accountId, 'rcps')
  }

  /**
   * Gets the SCPs for an org unit.
   * @param orgId The ID of the organization.
   * @param orgUnitId The ID of the org unit.
   * @returns The SCPs for the org unit.
   */
  async getScpsForOrgUnit(orgId: string, orgUnitId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForOrgUnit(orgId, orgUnitId, 'scps')
  }

  /**
   * Gets the org policies for an org unit for a given policy type.
   * @param orgId The ID of the organization.
   * @param orgUnitId The ID of the org unit.
   * @param policyType The type of policy ('scps' or 'rcps').
   * @returns The org policies for the org unit.
   */
  async getOrgPoliciesForOrgUnit(
    orgId: string,
    orgUnitId: string,
    policyType: OrgPolicyType
  ): Promise<OrgPolicy[]> {
    const cacheKey = `orgPoliciesForOrgUnit:${orgId}:${orgUnitId}:${policyType}`
    return this.withCache(cacheKey, async () => {
      const orgUnitInformation = await this.getOrgUnitsDataForOrg(orgId)
      const orgUnit = orgUnitInformation[orgUnitId]
      const orgPolicies = orgUnit[policyType]
      const policies: OrgPolicy[] = []
      for (const policyArn of orgPolicies) {
        const policyInfo = await this.getOrgPolicy(orgId, policyType, policyArn)
        policies.push(policyInfo)
      }

      return policies
    })
  }

  /**
   * Gets the RCPs for an org unit.
   * @param orgId The ID of the organization.
   * @param orgUnitId The ID of the org unit.
   * @returns The RCPs for the org unit.
   */
  async getRcpsForOrgUnit(orgId: string, orgUnitId: string): Promise<OrgPolicy[]> {
    return this.getOrgPoliciesForOrgUnit(orgId, orgUnitId, 'rcps')
  }

  /**
   * Gets the org ID for an account.
   * @param accountId The ID of the account.
   * @returns The org ID for the account, or undefined if not found.
   */
  async getOrgIdForAccount(accountId: string): Promise<string | undefined> {
    const index = await this.getIndex<Record<string, string>>('accounts-to-orgs', {})
    const accountToOrgMap = index.data
    return accountToOrgMap[accountId]
  }

  async getIndex<T>(indexName: string, defaultValue: T): Promise<{ lockId: string; data: T }> {
    const cacheKey = `index:${indexName}`
    return this.withCache(cacheKey, async () => {
      return this.storageClient.getIndex<T>(indexName, defaultValue)
    })
  }

  /**
   * Get the account ID for a given S3 bucket name.
   *
   * @param bucketName The name of the bucket.
   * @returns The account ID for the bucket, or undefined if not found.
   */
  async getAccountIdForBucket(bucketName: string): Promise<string | undefined> {
    const index = await this.getIndex<Record<string, { accountId: string }>>(
      'buckets-to-accounts',
      {}
    )
    const bucketToAccountMap = index.data
    return bucketToAccountMap[bucketName]?.accountId
  }

  /**
   * Check if ABAC is enabled for a specific S3 bucket
   *
   * @param accountId The account ID of the bucket
   * @param bucketOrObjectArn The ARN of the bucket or object
   * @returns true if ABAC is enabled for the bucket, false otherwise
   */

  async getAbacEnabledForBucket(accountId: string, bucketOrObjectArn: string): Promise<boolean> {
    const bucketArn = bucketArnFromBucketOrObjectArn(bucketOrObjectArn)
    return this.withCache(`abacEnabledForBucket:${bucketArn}`, async () => {
      const bucketMetadata = await this.storageClient.getResourceMetadata<
        { abacEnabled?: boolean },
        {}
      >(accountId, bucketArn, 'metadata', {})

      return !!bucketMetadata.abacEnabled
    })
  }

  /**
   * Check if S3 Block Public Access RestrictPublicBuckets is enabled for a specific S3 bucket.
   * Bucket-level and account-level settings both apply, so the effective setting is enabled
   * when either collected metadata source has RestrictPublicBuckets set to true.
   *
   * @param accountId The account ID of the bucket
   * @param bucketOrObjectArn The ARN of the bucket or object
   * @returns true if RestrictPublicBuckets is enabled at the bucket or account level
   */
  async getBlockPublicAccessEnabledForBucket(
    accountId: string,
    bucketOrObjectArn: string
  ): Promise<boolean> {
    const bucketArn = bucketArnFromBucketOrObjectArn(bucketOrObjectArn)
    return this.withCache(`bpaEnabledForBucket:${accountId}:${bucketArn}`, async () => {
      const [bucketBpa, accountBpa] = await Promise.all([
        this.storageClient.getResourceMetadata<S3PublicAccessBlockMetadata, {}>(
          accountId,
          bucketArn,
          'bpa',
          {}
        ),
        this.storageClient.getAccountMetadata<S3PublicAccessBlockMetadata, {}>(
          accountId,
          's3-bpa',
          {}
        )
      ])

      return bucketBpa.RestrictPublicBuckets === true || accountBpa.RestrictPublicBuckets === true
    })
  }

  /**
   * Gets the account ID for a given API Gateway ARN.
   * @param apiArn The ARN of the API Gateway.
   * @returns The account ID for the API Gateway, or undefined if not found.
   */
  async getAccountIdForRestApi(apiArn: string): Promise<string | undefined> {
    const index = await this.getIndex<Record<string, string>>('apigateways-to-accounts', {})
    const gatewayToAccountMap = index.data
    return gatewayToAccountMap[apiArn]
  }

  /**
   * Gets the managed policies attached to a user.
   * @param userArn The ARN of the user.
   * @returns The managed policies for the user.
   */
  async getManagedPoliciesForUser(userArn: string): Promise<ManagedPolicy[]> {
    const cacheKey = `userManagedPolicies:${userArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(userArn).accountId!
      const managedPolicies = await this.storageClient.getResourceMetadata<string[], string[]>(
        accountId,
        userArn,
        'managed-policies',
        []
      )

      const results: ManagedPolicy[] = []

      for (const policyArn of managedPolicies) {
        results.push(await this.getManagedPolicy(accountId, policyArn))
      }

      return results
    })
  }

  async getManagedPolicy(accountId: string, policyArn: string): Promise<ManagedPolicy> {
    const cacheKey = `managedPolicy:${accountId}:${policyArn}`
    return this.withCache(cacheKey, async () => {
      const policyMetadata = await this.storageClient.getResourceMetadata<
        ManagedPolicyMetadata,
        ManagedPolicyMetadata
      >(accountId, policyArn, 'metadata')
      const policyDocument = await this.storageClient.getResourceMetadata(
        accountId,
        policyArn,
        'current-policy'
      )
      if (!policyDocument) {
        log.warn(`Policy document not found for ${policyArn} in account ${accountId}`)
      }
      return {
        arn: policyMetadata.arn,
        name: policyMetadata.name,
        policy: createValidatedPolicy(policyDocument, validateIdentityPolicy, {
          name: policyArn
        })
      }
    })
  }

  /**
   * Gets the inline policies attached to a user.
   * @param userArn The ARN of the user.
   * @returns The inline policies for the user.
   */
  async getInlinePoliciesForUser(userArn: string): Promise<InlinePolicy[]> {
    const cacheKey = `userInlinePolicies:${userArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(userArn).accountId!
      const inlinePolicies = await this.storageClient.getResourceMetadata<
        InlinePolicyMetadata[],
        InlinePolicyMetadata[]
      >(accountId, userArn, 'inline-policies', [])

      return inlinePolicies.map((p) => ({
        name: p.PolicyName,
        policy: createValidatedPolicy(p.PolicyDocument, validateIdentityPolicy, {
          name: `${userArn}#${p.PolicyName}`
        })
      }))
    })
  }

  /**
   * Gets metadata for an IAM user.
   *
   * @param userArn the ARN of the user.
   * @returns the metadata for the user, or undefined if not found.
   */
  async getIamUserMetadata(userArn: string): Promise<IamUserMetadata | undefined> {
    const cacheKey = `iamUserMetadata:${userArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(userArn).accountId!
      // The permissions boundary is stored as a policy ARN on the user resource metadata
      return this.storageClient.getResourceMetadata<IamUserMetadata, IamUserMetadata>(
        accountId,
        userArn,
        'metadata'
      )
    })
  }

  /**
   * Gets the permissions boundary policy attached to a user, if any.
   *
   * @param userArn The ARN of the user.
   * @returns The permissions boundary policy as an OrgPolicy, or undefined if none is set.
   */
  async getPermissionsBoundaryForUser(userArn: string): Promise<ManagedPolicy | undefined> {
    const cacheKey = `userPermissionBoundary:${userArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(userArn).accountId!
      // The permissions boundary is stored as a policy ARN on the user resource metadata
      const userMetadata = await this.getIamUserMetadata(userArn)
      if (!userMetadata) {
        return undefined
      }

      const permissionsBoundaryArn = userMetadata.permissionBoundary
      if (!permissionsBoundaryArn) {
        return undefined
      }

      return this.getManagedPolicy(accountId, permissionsBoundaryArn)
    })
  }

  /**
   * Gets the group ARNs that the user is a member of.
   * @param userArn The ARN of the user.
   * @returns An array of group ARNs the user belongs to.
   */
  async getGroupsForUser(userArn: string): Promise<string[]> {
    const cacheKey = `groupsForUser:${userArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(userArn).accountId!
      const groups = await this.storageClient.getResourceMetadata<string[], string[]>(
        accountId,
        userArn,
        'groups',
        []
      )
      return groups
    })
  }

  /**
   * Gets the managed policies attached to a group.
   *
   * @param groupArn The ARN of the group.
   * @returns The managed policies for the group.
   */
  async getManagedPoliciesForGroup(groupArn: string): Promise<ManagedPolicy[]> {
    const cacheKey = `groupManagedPolicies:${groupArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(groupArn).accountId!
      const managedPolicies = await this.storageClient.getResourceMetadata<string[], string[]>(
        accountId,
        groupArn,
        'managed-policies',
        []
      )

      const results: ManagedPolicy[] = []

      for (const policyArn of managedPolicies) {
        results.push(await this.getManagedPolicy(accountId, policyArn))
      }

      return results
    })
  }

  /**
   * Get the inline policies attached to a group.
   *
   * @param groupArn the ARN of the group.
   * @returns the inline policies for the group.
   */
  async getInlinePoliciesForGroup(groupArn: string): Promise<InlinePolicy[]> {
    const cacheKey = `groupInlinePolicies:${groupArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(groupArn).accountId!
      const inlinePolicies = await this.storageClient.getResourceMetadata<
        InlinePolicyMetadata[],
        InlinePolicyMetadata[]
      >(accountId, groupArn, 'inline-policies', [])

      return inlinePolicies.map((p) => ({
        name: p.PolicyName,
        policy: createValidatedPolicy(p.PolicyDocument, validateIdentityPolicy, {
          name: `${groupArn}#${p.PolicyName}`
        })
      }))
    })
  }

  /**
   * Gets the managed policies attached to a role.
   * @param roleArn the ARN of the role.
   * @returns the managed policies attached to the role.
   */
  async getManagedPoliciesForRole(roleArn: string): Promise<ManagedPolicy[]> {
    const cacheKey = `managedPoliciesForRole:${roleArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(roleArn).accountId!
      const managedPolicies = await this.storageClient.getResourceMetadata<string[], string[]>(
        accountId,
        roleArn,
        'managed-policies',
        []
      )

      const results: ManagedPolicy[] = []

      for (const policyArn of managedPolicies) {
        results.push(await this.getManagedPolicy(accountId, policyArn))
      }

      return results
    })
  }

  /**
   * Get the inline policies attached to a role.
   *
   * @param roleArn the ARN of the role.
   * @returns the inline policies for the role.
   */
  async getInlinePoliciesForRole(roleArn: string): Promise<InlinePolicy[]> {
    const cacheKey = `inlinePoliciesForRole:${roleArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(roleArn).accountId!
      const inlinePolicies = await this.storageClient.getResourceMetadata<
        InlinePolicyMetadata[],
        InlinePolicyMetadata[]
      >(accountId, roleArn, 'inline-policies', [])

      return inlinePolicies.map((p) => ({
        name: p.PolicyName,
        policy: createValidatedPolicy(p.PolicyDocument, validateIdentityPolicy, {
          name: `${roleArn}#${p.PolicyName}`
        })
      }))
    })
  }

  /**
   * Get the permissions boundary policy attached to a role, if any.
   * @param roleArn the ARN of the role.
   * @returns the permissions boundary policy as a ManagedPolicy, or undefined if none is set.
   */
  async getPermissionsBoundaryForRole(roleArn: string): Promise<ManagedPolicy | undefined> {
    const cacheKey = `permissionBoundaryForRole:${roleArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(roleArn).accountId!
      // The permissions boundary is stored as a policy ARN on the user resource metadata
      const roleMetadata = await this.getIamUserMetadata(roleArn)
      if (!roleMetadata) {
        return undefined
      }

      const permissionsBoundaryArn = roleMetadata.permissionBoundary
      if (!permissionsBoundaryArn) {
        return undefined
      }

      return this.getManagedPolicy(accountId, permissionsBoundaryArn)
    })
  }

  /**
   * Get the metadata for an organization.
   *
   * @param organizationId the id of the organization
   * @returns the metadata for the organization
   */
  async getOrganizationMetadata(organizationId: string): Promise<OrganizationMetadata> {
    const cacheKey = `organizationMetadata:${organizationId}`
    return this.withCache(cacheKey, async () => {
      return this.storageClient.getOrganizationMetadata<OrganizationMetadata, OrganizationMetadata>(
        organizationId,
        'metadata'
      )
    })
  }

  /**
   * Gets the resource policy for a given resource ARN and account.
   *
   * @param resourceArn The ARN of the resource.
   * @param accountId The ID of the account.
   * @returns The resource policy, or undefined if not found.
   */
  async getResourcePolicyForArn(
    resourceArn: string,
    accountId: string
  ): Promise<ValidatedPolicy<{ name: string }> | undefined> {
    const arnParts = splitArnParts(resourceArn)
    if (arnParts.service === 's3' && arnParts.region === '' && arnParts.accountId === '') {
      resourceArn = resourceArn.split('/')[0]
    }

    const cacheKey = `resourcePolicy:${accountId}:${resourceArn}`
    return this.withCache(cacheKey, async () => {
      const isTrustPolicy = arnParts.service === 'iam' && arnParts.resourceType === 'role'
      const metadataKey = isTrustPolicy ? 'trust-policy' : 'policy'
      const validateFn = isTrustPolicy ? validateTrustPolicy : validateResourcePolicy

      const rawPolicy = await this.storageClient.getResourceMetadata<string, string>(
        accountId,
        resourceArn,
        metadataKey
      )
      if (!rawPolicy) return undefined

      return createValidatedPolicy(rawPolicy, validateFn, { name: resourceArn })
    })
  }

  /**
   * Gets the RAM share policy for a given resource ARN and account.
   *
   * @param resourceArn The ARN of the resource.
   * @param accountId The ID of the account.
   * @returns The RAM share policy, or undefined if not found.
   */
  async getRamSharePolicyForArn(
    resourceArn: string,
    accountId: string
  ): Promise<ValidatedPolicy<{ name: string }> | undefined> {
    const cacheKey = `ramSharePolicy:${accountId}:${resourceArn}`
    return this.withCache(cacheKey, async () => {
      const armSharePolicy = await this.storageClient.getRamResource<RAMShare, RAMShare>(
        accountId,
        resourceArn
      )
      if (!armSharePolicy?.policy) return undefined
      return createValidatedPolicy(armSharePolicy.policy, validateResourcePolicy, {
        name: resourceArn
      })
    })
  }

  /**
   * Determines whether a KMS key is marked as AWS-managed in collected resource metadata.
   *
   * @param resourceArn the ARN of the KMS key
   * @param accountId the ID of the account that owns the KMS key
   * @returns true only when the key metadata explicitly sets `awsManaged` to true
   */
  async isAwsManagedKmsKey(resourceArn: string, accountId: string): Promise<boolean> {
    const cacheKey = `kmsKeyAwsManaged:${accountId}:${resourceArn}`
    return this.withCache(cacheKey, async () => {
      const metadata = await this.storageClient.getResourceMetadata<KmsKeyMetadata, KmsKeyMetadata>(
        accountId,
        resourceArn,
        'metadata'
      )
      return metadata?.awsManaged === true
    })
  }

  /**
   * Gets the tags for a given resource ARN and account.
   *
   * @param resourceArn The ARN of the resource.
   * @param accountId The ID of the account.
   * @returns an object to indicate if the resource is present and its tags (if any)
   */
  async getTagsForResource(
    resourceArn: string,
    accountId: string
  ): Promise<{ present: boolean; tags: Record<string, string> }> {
    const cacheKey = `tagsForResource:${accountId}:${resourceArn}`
    return this.withCache(cacheKey, async () => {
      const presentPromise = this.storageClient.getResourceMetadata(
        accountId,
        resourceArn,
        'metadata'
      )

      const tagsPromise = this.storageClient.getResourceMetadata<
        Record<string, string>,
        Record<string, string>
      >(accountId, resourceArn, 'tags')

      const [present, tags] = await Promise.all([presentPromise, tagsPromise])
      return { present: !!present, tags: tags || {} }
    })
  }

  /**
   * Gets a unique ID for an IAM resource based on its ARN and account ID.
   * Used specifically for IAM Users and Roles
   *
   * @param resourceArn the ARN of the IAM resource
   * @param accountId the ID of the account the resource belongs to
   * @returns a unique ID for the resource, or undefined if not found
   */
  async getUniqueIdForIamResource(resourceArn: string): Promise<string | undefined> {
    const cacheKey = `uniqueIdForIamResource:${resourceArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(resourceArn).accountId!
      const resourceMetadata = await this.storageClient.getResourceMetadata<
        IamUserMetadata,
        IamUserMetadata
      >(accountId, resourceArn, 'metadata')

      return resourceMetadata?.id
    })
  }

  /**
   * Get the account IDs for an organization.
   *
   * @param organizationId the ID of the organization
   * @returns a tuple containing a boolean indicating success and an array of account IDs
   */
  async getAccountsForOrganization(organizationId: string): Promise<[boolean, string[]]> {
    const organizationAccounts = await this.getAccountDataForOrg(organizationId)
    if (!organizationAccounts) {
      return [false, []]
    }
    const accountIds = Object.keys(organizationAccounts)
    return [true, accountIds]
  }

  /**
   * Get the organization structure or an organization.
   *
   * @param orgId the ID of the organization
   * @returns returns the organization structure or undefined if not found
   */
  async getOrganizationStructure(orgId: string): Promise<OrgStructure | undefined> {
    const cacheKey = `organizationStructure:${orgId}`
    return this.withCache(cacheKey, async () => {
      return this.storageClient.getOrganizationMetadata<OrgStructure, OrgStructure>(
        orgId,
        'structure'
      )
    })
  }

  /**
   * Get the accounts for a given organization path, includes
   * accounts directly under the OU and in child OUs.
   *
   * @param orgId the ID of the organization
   * @param ouIds the ids of the organizational units in the path
   * @returns a tuple containing a boolean indicating success and an array of account IDs
   */
  async getAccountsForOrgPath(orgId: string, ouIds: string[]): Promise<[boolean, string[]]> {
    const cacheKey = `accountsForOrgPath:${orgId}:${ouIds.join('/')}`
    return this.withCache(cacheKey, async () => {
      const orgUnits = await this.getOrganizationStructure(orgId)
      if (!orgUnits || ouIds.length === 0) {
        return [false, []]
      }

      const rootOu = orgUnits[ouIds[0]]

      // Now look through the structure to find the OU
      let currentStructure: OrgStructureNode | undefined = rootOu
      for (const ou of ouIds.slice(1)) {
        currentStructure = currentStructure.children?.[ou]
        if (!currentStructure) {
          return [false, []] // OU not found in the structure
        }
      }

      const getAccountId = (a: string) => a.split('/').at(-1)!

      const accounts = []
      if (currentStructure.accounts) {
        accounts.push(...currentStructure.accounts?.map(getAccountId))
      }

      const children = Object.values(currentStructure.children || {})

      // Traverse the children to collect all accounts
      while (children.length > 0) {
        const child = children.shift()
        if (child?.accounts) {
          accounts.push(...child.accounts.map(getAccountId))
        }
        if (child?.children) {
          children.push(...Object.values(child.children))
        }
      }

      return [true, accounts]
    })
  }

  /**
   * Get all the principals (users and roles) in a given account.
   *
   * @param accountId the ID of the account
   * @returns a list of all principal ARNs in the account
   */
  async getAllPrincipalsInAccount(accountId: string): Promise<string[]> {
    const cacheKey = `allPrincipalsInAccount:${accountId}`
    return this.withCache(cacheKey, async () => {
      const iamUsers = await this.storageClient.findResourceMetadata<ResourceMetadata>(accountId, {
        service: 'iam',
        resourceType: 'user',
        account: accountId
      })

      const iamRoles = await this.storageClient.findResourceMetadata<ResourceMetadata>(accountId, {
        service: 'iam',
        resourceType: 'role',
        account: accountId
      })

      return [...iamUsers.map((user) => user.arn), ...iamRoles.map((role) => role.arn)]
    })
  }

  /**
   * Get the VPC endpoint policy for a given VPC endpoint ARN.
   *
   * @param vpcEndpointArn the ARN of the VPC endpoint
   * @returns the VPC endpoint policy, or undefined if not found
   */
  async getVpcEndpointPolicyForArn(
    vpcEndpointArn: string
  ): Promise<ValidatedPolicy<{ name: string }> | undefined> {
    const cacheKey = `vpcEndpointPolicy:${vpcEndpointArn}`
    return this.withCache(cacheKey, async () => {
      const accountId = splitArnParts(vpcEndpointArn).accountId!
      const rawPolicy = await this.storageClient.getResourceMetadata<any, any>(
        accountId,
        vpcEndpointArn,
        'endpoint-policy'
      )
      if (!rawPolicy) return undefined
      return createValidatedPolicy(rawPolicy, validateEndpointPolicy, { name: vpcEndpointArn })
    })
  }

  /**
   * Get the ARN of a VPC endpoint given its ID.
   * @param vpcEndpointId the ID of the VPC endpoint
   * @returns the ARN of the VPC endpoint, or undefined if not found
   */
  async getVpcEndpointArnForVpcEndpointId(vpcEndpointId: string): Promise<string | undefined> {
    const index = await this.getIndex<VpcIndex>('vpcs', {
      endpoints: {},
      vpcs: {}
    })
    return index.data.endpoints[vpcEndpointId]?.arn
  }

  /**
   * Gets the VPC endpoint ID for a given VPC ID and service name.
   *
   * @param vpcIdOrArn the ID or ARN of the VPC
   * @param service the service name of the VPC endpoint (e.g., s3, ec2, etc.)
   * @returns the VPC endpoint ID, or undefined if not found
   */
  async getVpcEndpointIdForVpcService(
    vpcIdOrArn: string,
    service: string
  ): Promise<string | undefined> {
    const index = await this.getIndex<VpcIndex>('vpcs', {
      endpoints: {},
      vpcs: {}
    })
    if (vpcIdOrArn.startsWith('arn:')) {
      const arnParts = splitArnParts(vpcIdOrArn)
      vpcIdOrArn = arnParts.resourcePath!
    }

    const vpc = index.data.vpcs[vpcIdOrArn]
    if (!vpc) {
      return undefined
    }
    const endpoint = vpc.endpoints.find((ep) => ep.service === service)
    return endpoint?.id
  }

  /**
   * Lookup the VPC ID for a given VPC endpoint ID.
   *
   * @param vpcEndpointId the ID of the VPC endpoint
   * @returns the VPC ID, or undefined if not found
   */
  async getVpcIdForVpcEndpointId(vpcEndpointId: string): Promise<string | undefined> {
    const index = await this.getIndex<VpcIndex>('vpcs', {
      endpoints: {},
      vpcs: {}
    })
    return index.data.endpoints[vpcEndpointId]?.vpc
  }

  /**
   * Lookup the VPC ARN for a given VPC endpoint ID.
   *
   * @param vpcEndpointId the ID of the VPC endpoint
   * @returns the VPC ARN, or undefined if not found
   */
  async getVpcArnForVpcEndpointId(vpcEndpointId: string): Promise<string | undefined> {
    const vpcId = await this.getVpcIdForVpcEndpointId(vpcEndpointId)
    if (!vpcId) {
      return undefined
    }
    const index = await this.getIndex<VpcIndex>('vpcs', {
      endpoints: {},
      vpcs: {}
    })
    return index.data.vpcs[vpcId]?.arn
  }

  /**
   * Lookup the account ID for a given VPC endpoint ID.
   *
   * @param vpcEndpointId the ID of the VPC endpoint
   * @returns the account ID, or undefined if not found
   */
  async getAccountIdForVpcEndpointId(vpcEndpointId: string): Promise<string | undefined> {
    const index = await this.getIndex<VpcIndex>('vpcs', {
      endpoints: {},
      vpcs: {}
    })
    const vpcArn = index.data.endpoints[vpcEndpointId]?.arn
    if (!vpcArn) {
      return undefined
    }
    return splitArnParts(vpcArn).accountId
  }

  /**
   * Get the organization ID for a given VPC endpoint ID.
   *
   * @param vpcEndpointId the ID of the VPC endpoint
   * @returns the organization ID, or undefined if not found
   */
  async getOrgIdForVpcEndpointId(vpcEndpointId: string): Promise<string | undefined> {
    const accountId = await this.getAccountIdForVpcEndpointId(vpcEndpointId)
    if (!accountId) {
      return undefined
    }
    return this.getOrgIdForAccount(accountId)
  }

  /**
   * Get the organization unit hierarchy for a given VPC endpoint ID.
   *
   * @param vpcEndpointId the ID of the VPC endpoint
   * @returns the organization unit hierarchy, or undefined if not found
   */
  async getOrgUnitHierarchyForVpcEndpointId(vpcEndpointId: string): Promise<string[] | undefined> {
    const accountId = await this.getAccountIdForVpcEndpointId(vpcEndpointId)
    if (!accountId) {
      return undefined
    }
    const hierarchy = await this.getOrgUnitHierarchyForAccount(accountId)
    if (hierarchy.length === 0) {
      return undefined
    }
    return hierarchy
  }

  /**
   * Get all the policies for a principal that should be used to populate the cache
   *
   * @param collectClient The IAM collect client to use for data access
   * @param accountId The ID of the account
   * @param principalArn The ARN of the principal
   * @returns An array of policies for the principal
   */
  async getAllowPoliciesForPrincipal(principalArn: string): Promise<Policy[]> {
    const arnParts = splitArnParts(principalArn)
    const policies: Policy[] = []
    if (arnParts.resourceType === 'user') {
      const managedPolicies = await this.getManagedPoliciesForUser(principalArn)
      managedPolicies.forEach((mp) => policies.push(loadPolicy(mp.policy)))

      const inlinePolicies = await this.getInlinePoliciesForUser(principalArn)
      inlinePolicies.forEach((ip) => policies.push(loadPolicy(ip.policy)))
      const groups = await this.getGroupsForUser(principalArn)
      for (const group of groups) {
        const groupManagedPolicies = await this.getManagedPoliciesForGroup(group)
        const groupInlinePolicies = await this.getInlinePoliciesForGroup(group)

        groupManagedPolicies.forEach((mp) => policies.push(loadPolicy(mp.policy)))
        groupInlinePolicies.forEach((ip) => policies.push(loadPolicy(ip.policy)))
      }
    } else if (arnParts.resourceType === 'role') {
      const managedPolicies = await this.getManagedPoliciesForRole(principalArn)
      managedPolicies.forEach((mp) => policies.push(loadPolicy(mp.policy)))

      const inlinePolicies = await this.getInlinePoliciesForRole(principalArn)
      inlinePolicies.forEach((ip) => policies.push(loadPolicy(ip.policy)))
    }

    return policies
  }

  async savePrincipalIndex(type: string, principalIndex: any): Promise<void> {
    const indexName = `principal-index-${type}`
    const currentData = await this.storageClient.getIndex(indexName, {})
    const currentLockId = currentData.lockId

    // Stringify and compress the data, then convert to base64 string before saving
    const jsonString = JSON.stringify(principalIndex)
    const compressedBuffer = gzipSync(Buffer.from(jsonString, 'utf8'))
    const base64String = compressedBuffer.toString('base64')

    await this.storageClient.saveIndex(indexName, base64String, currentLockId)
  }

  async getPrincipalIndex(
    type: string
  ): Promise<
    | Partial<IamActionCache>
    | IamActionCache['accounts']
    | IamActionCache['principals']
    | IamActionCache['action'][string]
    | IamActionCache['notAction']
    | undefined
  > {
    const key = `principal-index-${type}`
    return this.withCache(key, async () => {
      const rawIndex = await this.storageClient.getIndex<string>(key, undefined as any)
      if (!rawIndex.data) {
        return undefined
      }

      try {
        // Convert base64 string back to buffer, then decompress and parse
        const compressedBuffer = Buffer.from(rawIndex.data, 'base64')
        const decompressedData = gunzipSync(compressedBuffer)
        const jsonString = decompressedData.toString('utf8')
        return JSON.parse(jsonString) as IamActionCache
      } catch (error) {
        log.error('Failed to decompress or parse principal index', { error })
        return undefined
      }
    })
  }

  async principalIndexExists(): Promise<boolean> {
    const index = await this.getPrincipalIndex('principals')
    return !!index
  }

  /**
   * Get the principals that may have permission to perform a specific action.
   *
   * If the data is available it will return a subset of principals that may
   * have permission to perform the action. If the data is not available, it
   * will return undefined.
   *
   * @param allFromAccount The account ID from which to include all principals in the result, regardless of the action filter. When `undefined`, no account receives this treatment — only principals matching the action filter are returned.
   * @param accountIds The list of account IDs to check for principals that may have permission to perform the specified action. Only principals from these accounts that may have the action allowed will be included.
   * @param action The action to check.
   * @returns A list of principals that may have permission to perform the action, or undefined if the data is not available.
   */
  async getPrincipalsWithActionAllowed(
    allFromAccount: string | undefined,
    accountIds: string[],
    action: string
  ): Promise<string[] | undefined> {
    const principals = (await this.getPrincipalIndex('principals')) as
      Pick<IamActionCache, 'principals' | 'prefix'> | undefined
    if (!principals) {
      return undefined
    }
    const principalBitSets: any[] = []

    const wildcardIndex = (await this.getPrincipalIndex(
      'actions-wildcard'
    )) as IamActionCache['action'][string]

    const [service, serviceAction] = action.toLowerCase().split(':')

    //Global wildcards match
    if (wildcardIndex?.['*']) {
      principalBitSets.push(wildcardIndex['*'])
    }

    const serviceIndex = (await this.getPrincipalIndex(`actions-${service}`)) as
      IamActionCache['action'][string] | undefined

    // Look through service actions
    if (serviceIndex) {
      for (const [actionPattern, bitset] of Object.entries(serviceIndex)) {
        if (actionMatchesPattern(serviceAction, actionPattern)) {
          principalBitSets.push(bitset)
        }
      }
    }

    const notActionIndex = (await this.getPrincipalIndex(`not-actions`)) as
      IamActionCache['notAction'] | undefined

    if (notActionIndex) {
      for (const [notActionService, notActions] of Object.entries(notActionIndex)) {
        if (notActionService === service) {
          for (const [notActionPattern, bitset] of Object.entries(notActions)) {
            if (!actionMatchesPattern(serviceAction, notActionPattern)) {
              principalBitSets.push(bitset)
            }
          }
        } else {
          for (const bitset of Object.values(notActions)) {
            principalBitSets.push(bitset)
          }
        }
      }
    }

    const actionBitset = principalBitSets.reduce(
      (acc, bs) => acc.or(decodeBitSet(bs)),
      new BitSet()
    )

    const accountsIndex = (await this.getPrincipalIndex('accounts')) as
      IamActionCache['accounts'] | undefined

    if (!accountsIndex) {
      throw new Error('Accounts index not found in principal index')
    }

    const accountBitset = accountIds.reduce((acc, accountId) => {
      const bs = accountsIndex[accountId]
      if (bs) {
        return acc.or(decodeBitSet(bs))
      }
      return acc
    }, new BitSet())

    let finalBitset = accountBitset.and(actionBitset)

    if (allFromAccount && accountsIndex[allFromAccount]) {
      finalBitset = finalBitset.or(decodeBitSet(accountsIndex[allFromAccount]))
    }

    return finalBitset
      .toArray()
      .map((i) => decompressPrincipalString(principals.principals[i]!, principals.prefix))
  }

  async listResources(
    accountId: string,
    service: string,
    resourceType: string,
    region: string | undefined
  ): Promise<string[]> {
    if (service === 's3' && resourceType === 'bucket') {
      const resources = await this.storageClient.findResourceMetadata<ResourceMetadata>(accountId, {
        account: accountId,
        service,
        region
      })

      return resources.map((r) => r.arn)
    }

    const resources = await this.storageClient.findResourceMetadata<ResourceMetadata>(accountId, {
      account: accountId,
      service,
      resourceType,
      region
    })

    return resources.map((r) => r.arn)
  }
}
