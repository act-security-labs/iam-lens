import { type TopLevelConfig } from '@actsecurity/iam-collect'
import { IamCollectClient } from '../collect/client.js'
import { type ClientFactoryPlugin } from '../collect/collect.js'
import {
  iamActionDetails,
  iamActionExists,
  iamActionsForService,
  iamResourceTypeDetails,
  iamResourceTypesForService,
  iamServiceExists,
  type ResourceType
} from '@actsecurity/iam-data'
import {
  type Condition,
  type ConditionOperation,
  type Statement,
  loadPolicy
} from '@actsecurity/iam-policy'
import {
  type AllowedConditionExpression,
  type DiscoveryContextKeyConstraint,
  type IgnoredConditions,
  type RequestDenial,
  type RequestGrant
} from '@actsecurity/iam-simulate'
import { mostSpecificMatchingResourceTypePatterns, splitArnParts } from '@actsecurity/iam-utils'
import { Arn } from '../utils/arn.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { AssumeRoleActions } from '../utils/sts.js'
import { type LightRequestAnalysis } from './requestAnalysis.js'
import {
  WhoCanProcessor,
  type WhoCanSettledEvent,
  type WorkerBootstrapPlugin
} from './WhoCanProcessor.js'

/**
 * Limits the set of principals that `whoCan` tests. The scope is a union of
 * principal ARNs, account IDs, and OU paths. It is **intersected** with the
 * resource-policy-derived scope so that principals outside the resource
 * policy's reach are still excluded. An empty scope (`{}`) excludes all principals,
 * including anonymous. To include only unsigned access, use
 * `{ anonymous: true }`. Without a scope, anonymous access is considered
 * whenever the resource policy contains a candidate Allow statement.
 */
export interface WhoCanPrincipalScope {
  /**
   * Exact principal ARNs/service names to test individually.
   */
  principals?: string[]
  /**
   * Whether to include unsigned-access simulations when the resource policy has a
   * candidate Allow statement. Defaults to false when a principal scope is supplied.
   */
  anonymous?: boolean

  /**
   * Account IDs — test all principals in these accounts.
   **/
  accounts?: string[]

  /**
   * OU paths — test all principals in accounts under these OUs. Each string is a slash-separated path like `o-aaa/r-bbb/ou-ccc`, matching the format used by `aws:PrincipalOrgPaths` and `specificOrganizationalUnits`.
   **/
  ous?: string[]
}

export interface ResourceAccessRequest {
  /**
   * The ARN of the resource to check access for. If not provided, actions must be specified.
   */
  resource?: string

  /**
   * The account ID the resource belongs to.
   * By default this will be looked up based on the resource ARN, but that may
   * not be possible for all actions, such as wildcard actions like `s3:ListAllMyBuckets`.
   */
  resourceAccount?: string

  /**
   * The actions to check access for. If not provided, actions will be looked up based on the resource ARN.
   */
  actions: string[]

  /**
   * Whether to sort the results for consistent output.
   */
  sort?: boolean

  /**
   * An override for S3 ABAC being enabled when checking access to S3 Bucket resources.
   */
  s3AbacOverride?: S3AbacOverride

  /**
   * The number of worker threads to use for simulations beyond the main thread.
   * If not provided, defaults to number of CPUs - 1.
   */
  workerThreads?: number

  /**
   * Deny details callback for simulations. If the callback returns true, deny details will be included for that simulation.
   */
  denyDetailsCallback?: (details: LightRequestAnalysis) => boolean

  /**
   * If true, grant details will be collected for allowed simulations.
   */
  collectGrantDetails?: boolean

  /**
   * Caller-provided Discovery context-key certainty constraints for every simulation in this request.
   */
  discoveryContextKeyConstraints?: DiscoveryContextKeyConstraint[]

  /**
   * Optional plugin to wrap the collect client with a custom implementation.
   * Used for scenario testing where a layered client needs to be used in worker threads.
   */
  clientFactoryPlugin?: ClientFactoryPlugin

  /**
   * Optional plugin that runs once per worker thread at startup before any work
   * is processed. Use this for loading instrumentation, initializing logging
   * context, or other worker-lifetime setup.
   */
  workerBootstrapPlugin?: WorkerBootstrapPlugin

  /**
   * Optional scope to limit the set of principals tested. When provided, the
   * scope is intersected with the resource-policy-derived scope to narrow the
   * search space.
   */
  principalScope?: WhoCanPrincipalScope

  /**
   * Whether to ignore an existing principal index. This is for testing purposes.
   */
  ignorePrincipalIndex?: boolean
}

/**
 * Represents a resource pattern that is allowed for a principal, used when wildcards
 * are in the simulation request.
 */
export interface WhoCanAllowedResourcePattern {
  /**
   * The resource pattern that allows access.
   */
  pattern: string

  /**
   * The resource type for the pattern.
   */
  resourceType: string

  /**
   * The structured expression describing the conditions under which access is allowed
   * for this pattern. Undefined when access is unconditional.
   */
  conditions?: AllowedConditionExpression

  /**
   * Discovery-mode condition diagnostics that were ignored while determining this
   * pattern could be allowed. This was returned in `conditions` in earlier versions.
   */
  ignoredConditions?: IgnoredConditions

  /**
   * If true, access is only allowed when the session has a specific session name.
   */
  dependsOnSessionName?: boolean

  /**
   * The policy statements that granted access for this resource pattern.
   */
  details?: RequestGrant[]
}

/**
 * Effective access for a collected principal, service, or unsigned caller.
 */
export interface WhoCanAllowed {
  /**
   * Principal ARN/service name, or "anonymous" for unsigned access.
   */
  principal: string
  service: string
  action: string
  level: string

  /**
   * The structured expression describing the conditions under which access is allowed.
   * This will be undefined if access is allowed unconditionally or if `allowedPatterns`
   * are provided.
   */
  conditions?: AllowedConditionExpression

  /**
   * Discovery-mode condition diagnostics that were ignored while determining access
   * could be allowed. This was returned in `conditions` in earlier versions.
   */
  ignoredConditions?: IgnoredConditions

  /**
   * The resource type for the allowed action. This will be undefined if `allowedPatterns` are provided,
   * since those patterns specify the resource type directly.
   */
  resourceType?: string

  /**
   * If true, indicates that access is only allowed when the session has a specific session name.
   * This will be false or undefined if `allowedPatterns` are provided, since those patterns would specify the session name condition directly.
   */
  dependsOnSessionName?: boolean

  /**
   * If there are multiple "allowed" patterns for a single principal because of wildcards
   * in the simulation request, this array will contain the different resource patterns that allow access.
   */
  allowedPatterns?: WhoCanAllowedResourcePattern[]

  /**
   * The policy statements that granted access for this result.
   * Only populated for single resource simulations. For wildcard
   * simulations, see `details` on each entry in `allowedPatterns`.
   */
  details?: RequestGrant[]
}

/**
 * Base type for WhoCanDenyDetails
 */
interface BaseWhoCanDenyDetail {
  /**
   * Principal ARN/service name that was denied, or "anonymous" for unsigned access.
   */
  principal: string

  /**
   * The service the denied action belongs to
   */
  service: string

  /**
   * The action that was denied, without the service prefix (e.g. "GetObject" instead of "s3:GetObject")
   */
  action: string
}

/**
 * Denial details for a single resource request.
 */
export interface SingleWhoCanDenyDetail extends BaseWhoCanDenyDetail {
  type: 'single'

  /**
   * The specific details of why the request was denied
   */
  details: RequestDenial[]
}

/**
 * Denial details for a wildcard resource request that may have matched multiple patterns.
 */
export interface WildcardWhoCanDenyDetail extends BaseWhoCanDenyDetail {
  type: 'wildcard'

  /**
   * The resource patterns that were denied. Could be empty if there
   * were no patterns found that matched the resource for the principal and action.
   *
   * The same pattern can be returned multiple times if there are multiple resource
   * types for that pattern/action combination.
   */
  deniedResources: {
    /**
     * The pattern tested in the simulation that resulted in a denial.
     */
    pattern: string

    /**
     * The resource type the pattern was tested against.
     */
    resourceType: string

    /**
     * The specific details of why the request was denied for this pattern.
     */
    details: RequestDenial[]
  }[]
}

/**
 * Details on why a principal was denied access to a resource for a specific action, including the specific patterns that were tested and resulted in denials.
 */
export type WhoCanDenyDetail = SingleWhoCanDenyDetail | WildcardWhoCanDenyDetail

export interface WhoCanResponse {
  simulationCount: number
  allowed: WhoCanAllowed[]
  allAccountsChecked: boolean
  accountsNotFound: string[]
  organizationsNotFound: string[]
  organizationalUnitsNotFound: string[]
  principalsNotFound: string[]
  denyDetails?: WhoCanDenyDetail[] | undefined
}

/**
 * Processes a single whoCan request by creating a temporary WhoCanProcessor,
 * enqueuing the request, waiting for it to settle, and shutting down. This
 * preserves the original one-shot behavior where workers and cache are created
 * and destroyed per call.
 *
 * For better performance when running multiple requests, use WhoCanProcessor
 * directly to keep workers and cache alive across calls.
 *
 * @param collectConfigs the collect configurations for loading IAM data
 * @param partition the AWS partition (e.g. 'aws', 'aws-cn')
 * @param request the whoCan request parameters
 * @returns the whoCan response with allowed principals and optional deny details
 */
export async function whoCan(
  collectConfigs: TopLevelConfig[],
  partition: string,
  request: ResourceAccessRequest
): Promise<WhoCanResponse> {
  let settledEvent: WhoCanSettledEvent | undefined

  const processor = await WhoCanProcessor.create({
    collectConfigs,
    partition,
    tuning: {
      workerThreads: request.workerThreads
    },
    ignorePrincipalIndex: request.ignorePrincipalIndex,
    clientFactoryPlugin: request.clientFactoryPlugin,
    workerBootstrapPlugin: request.workerBootstrapPlugin,
    s3AbacOverride: request.s3AbacOverride,
    collectGrantDetails: !!request.collectGrantDetails,
    onRequestSettled: async (event) => {
      settledEvent = event
    }
  })

  try {
    processor.enqueueWhoCan({
      resource: request.resource,
      resourceAccount: request.resourceAccount,
      actions: request.actions,
      sort: request.sort,
      denyDetailsCallback: request.denyDetailsCallback,
      principalScope: request.principalScope,
      discoveryContextKeyConstraints: request.discoveryContextKeyConstraints
    })

    await processor.waitForIdle()

    if (!settledEvent) {
      throw new Error('whoCan request did not settle')
    }

    if (settledEvent.status === 'rejected') {
      throw settledEvent.error
    }

    return settledEvent.result
  } finally {
    await processor.shutdown()
  }
}

export async function uniqueAccountsToCheck(
  collectClient: IamCollectClient,
  accountsToCheck: AccountsToCheck
): Promise<{
  accountsNotFound: string[]
  organizationsNotFound: string[]
  organizationalUnitsNotFound: string[]
  accounts: string[]
}> {
  const returnValue = {
    accountsNotFound: [] as string[],
    organizationsNotFound: [] as string[],
    organizationalUnitsNotFound: [] as string[],
    accounts: [] as string[]
  }

  if (accountsToCheck.allAccounts) {
    returnValue.accounts = await collectClient.allAccounts()
    return returnValue
  }

  const uniqueAccounts = new Set<string>()
  for (const account of accountsToCheck.specificAccounts || []) {
    const accountExists = await collectClient.accountExists(account)
    if (accountExists) {
      uniqueAccounts.add(account)
    } else {
      returnValue.accountsNotFound.push(account)
    }
  }

  for (const ouPath of accountsToCheck.specificOrganizationalUnits || []) {
    const parts = ouPath.split('/')
    const orgId = parts[0]
    const pathParts = parts.slice(1)

    const [found, accounts] = await collectClient.getAccountsForOrgPath(orgId, pathParts)
    for (const account of accounts) {
      uniqueAccounts.add(account)
    }
    if (!found) {
      returnValue.organizationalUnitsNotFound.push(ouPath)
    }
  }

  for (const orgId of accountsToCheck.specificOrganizations || []) {
    const [found, accounts] = await collectClient.getAccountsForOrganization(orgId)
    for (const account of accounts) {
      uniqueAccounts.add(account)
    }
    if (!found) {
      returnValue.organizationsNotFound.push(orgId)
    }
  }

  returnValue.accounts = Array.from(uniqueAccounts)
  return returnValue
}

export interface AccountsToCheck {
  allAccounts: boolean
  specificAccounts: string[]
  specificPrincipals: string[]
  specificOrganizations: string[]
  specificOrganizationalUnits: string[]
  /** Whether an Allow statement may grant unsigned access; simulation decides effectiveness. */
  checkAnonymous: boolean
  /**
   * Whether every principal from the resource account should be checked.
   */
  checkAllFromResourceAccount: boolean
  /**
   * Whether the resource policy explicitly grants access to principals in the
   * resource account. This is true when:
   * - The policy has no narrowing conditions (open wildcard or NotPrincipal), or
   * - The policy conditions explicitly reference the resource account, or
   * - The policy narrows to orgs/OUs (which may include the resource account).
   */
  resourceAccountTrustedByPolicy: boolean
}

/**
 * Splits an ARN-like string on `:` while treating `${...}` blocks as opaque.
 * Colons inside `${...}` dynamic variable references are not used as split points.
 *
 * For example, `arn:${aws:Partition}:iam::999999999999:role/*` splits into
 * `['arn', '${aws:Partition}', 'iam', '', '999999999999', 'role/*']`.
 *
 * @param value - The raw ARN string, possibly containing `${...}` references.
 * @returns An array of colon-delimited segments.
 */
function splitArnIgnoringDynamicVars(value: string): string[] {
  const segments: string[] = []
  let current = ''
  let depth = 0

  for (let i = 0; i < value.length; i++) {
    const ch = value[i]
    if (ch === '$' && i + 1 < value.length && value[i + 1] === '{') {
      depth++
      current += '${'
      i++ // skip the '{'
    } else if (ch === '}' && depth > 0) {
      depth--
      current += '}'
    } else if (ch === ':' && depth === 0) {
      segments.push(current)
      current = ''
    } else {
      current += ch
    }
  }
  segments.push(current)
  return segments
}

const PRINCIPAL_ARN_PATTERN_OPERATORS = new Set(['stringlike', 'arnequals', 'arnlike'])

/**
 * Checks whether a string contains any wildcard or dynamic variable characters
 * (`*`, `?`, or `$`).
 *
 * @param value - The string to check.
 * @returns `true` if the string contains `*`, `?`, or `$`.
 */
function hasWildcardOrDynamic(value: string): boolean {
  return value.includes('*') || value.includes('?') || value.includes('$')
}

/**
 * Classification of a wildcard-principal statement's service-principal conditions.
 *
 * - `not-service-only`: the statement does not require a service principal.
 * - `unnamed-service-only`: the statement requires a service principal but doesn't name which one.
 * - `named-service-only`: the statement names specific service principals that can be simulated.
 */
type ServicePrincipalCheck =
  | { type: 'not-service-only' }
  | { type: 'unnamed-service-only' }
  | { type: 'named-service-only'; principals: string[] }

/** The 3 scalar condition keys that are only populated for service principal requests. */
const UNNAMED_SERVICE_SCALAR_KEYS = new Set([
  'aws:sourceaccount',
  'aws:sourceowner',
  'aws:sourceorgid'
])

/**
 * Checks whether a positive operator is used on a scalar service-principal-only key.
 * Accepts `StringEquals` family and `StringLike`.
 *
 * @param op - The condition operation to check.
 * @returns `true` if the operator is a positive match for a scalar key.
 */
function isPositiveScalarOperator(op: ConditionOperation): boolean {
  return (
    op.value().toLowerCase().startsWith('stringequals') ||
    op.baseOperator().toLowerCase() === 'stringlike'
  )
}

/**
 * Checks whether a positive operator is used on the `aws:SourceOrgPaths` array key.
 * Only `ForAnyValue:StringEquals*` and `ForAnyValue:StringLike` qualify.
 * `ForAllValues` and plain operators without a set operator do not.
 *
 * @param op - The condition operation to check.
 * @returns `true` if the operator is a valid positive match for the array key.
 */
function isPositiveOrgPathsOperator(op: ConditionOperation): boolean {
  if (op.setOperator() !== 'ForAnyValue') return false
  const base = op.baseOperator().toLowerCase()
  return base.startsWith('stringequals') || base === 'stringlike'
}

/**
 * Inspects a statement's conditions to determine if the statement effectively
 * requires an AWS service principal. Used for wildcard-principal Allow statements
 * to avoid unnecessarily widening the whoCan search scope.
 *
 * @param conditions - The conditions from the statement to inspect.
 * @returns A classification indicating whether the statement is not service-only,
 *   requires an unnamed service principal (skip entirely), or names specific
 *   service principals (extract for simulation).
 */
function checkForServicePrincipalConditions(conditions: Condition[]): ServicePrincipalCheck {
  let hasUnnamedServiceKey = false
  const namedServicePrincipals: string[] = []

  for (const cond of conditions) {
    const key = cond.conditionKey().toLowerCase()
    const op = cond.operation()

    if (op.isIfExists()) continue

    // Category 1a: Scalar unnamed keys (aws:SourceAccount, aws:SourceOwner, aws:SourceOrgID)
    if (UNNAMED_SERVICE_SCALAR_KEYS.has(key) && isPositiveScalarOperator(op)) {
      hasUnnamedServiceKey = true
    }

    // Category 1b: Array unnamed key (aws:SourceOrgPaths) — requires ForAnyValue
    if (key === 'aws:sourceorgpaths' && isPositiveOrgPathsOperator(op)) {
      hasUnnamedServiceKey = true
    }

    // Category 1c: aws:PrincipalIsAWSService with Bool or StringEquals and value 'true'
    // Multiple condition values are ORed, so mixed ['true', 'false'] is NOT service-only.
    // All values must be 'true' for the condition to exclusively require a service principal.
    if (key === 'aws:principalisawsservice') {
      const baseOp = op.baseOperator().toLowerCase()
      const opVal = op.value().toLowerCase()
      const isBoolOrStringEquals = baseOp === 'bool' || opVal.startsWith('stringequals')
      const values = cond.conditionValues()
      if (
        isBoolOrStringEquals &&
        values.length > 0 &&
        values.every((v) => v.toLowerCase() === 'true')
      ) {
        hasUnnamedServiceKey = true
      }
    }

    // Category 2: aws:PrincipalServiceName — extract named service principals
    if (
      key === 'aws:principalservicename' &&
      op.value().toLowerCase().startsWith('stringequals') &&
      !cond.conditionValues().some((v: string) => v.includes('$'))
    ) {
      namedServicePrincipals.push(...cond.conditionValues())
    }
  }

  // Named takes priority — the simulator fills aws:SourceAccount etc. for service principals
  if (namedServicePrincipals.length > 0) {
    return { type: 'named-service-only', principals: namedServicePrincipals }
  }
  if (hasUnnamedServiceKey) {
    return { type: 'unnamed-service-only' }
  }
  return { type: 'not-service-only' }
}

/**
 * Conservatively identify an Allow that could grant unsigned access.
 * Arbitrary conditions, action/resource patterns, and denies are left to simulation.
 *
 * @param statement parsed resource-policy statement
 * @returns whether anonymous simulation may find an effective grant
 */
function mayAllowAnonymous(statement: Statement): boolean {
  if (!statement.isAllow()) {
    return false
  }
  // NotPrincipal excludes identities; keep it as a candidate without condition narrowing.
  if (statement.isNotPrincipalStatement()) {
    return true
  }
  return (
    statement.isPrincipalStatement() &&
    statement.principals().some((principal) => principal.isWildcardPrincipal()) &&
    checkForServicePrincipalConditions(statement.conditions()).type === 'not-service-only'
  )
}

/**
 * Derives the accounts and specific principals that should be considered from a resource policy.
 *
 * Specific STS session principals are resolved through collect data so account-enumeration
 * paths can de-duplicate path-qualified roles that resolve from pathless session ARNs.
 *
 * @param resourcePolicy The resource policy document to inspect.
 * @param resourceAccount The account ID that owns the resource, when known.
 * @param collectClient The collect client used to resolve canonical principal ARNs.
 * @returns The accounts, principals, organizations, and related flags to consider for whoCan.
 */
export async function accountsToCheckBasedOnResourcePolicy(
  resourcePolicy: any,
  resourceAccount: string | undefined,
  collectClient: IamCollectClient
): Promise<AccountsToCheck> {
  const accountsToCheck: AccountsToCheck = {
    allAccounts: false,
    specificAccounts: [],
    specificPrincipals: [],
    specificOrganizations: [],
    specificOrganizationalUnits: [],
    checkAnonymous: false,
    checkAllFromResourceAccount: false,
    resourceAccountTrustedByPolicy: false
  }
  if (!resourcePolicy) {
    return accountsToCheck
  }

  const policy = loadPolicy(resourcePolicy)
  for (const statement of policy.statements()) {
    if (mayAllowAnonymous(statement)) {
      accountsToCheck.checkAnonymous = true
    }
    if (statement.isAllow() && statement.isNotPrincipalStatement()) {
      accountsToCheck.allAccounts = true
      accountsToCheck.checkAllFromResourceAccount = true
      accountsToCheck.resourceAccountTrustedByPolicy = true
    }
    if (statement.isAllow() && statement.isPrincipalStatement()) {
      const principals = statement.principals()
      let hasWildcardPrincipal = false
      for (const principal of principals) {
        if (principal.isWildcardPrincipal()) {
          hasWildcardPrincipal = true
        } else if (principal.isAccountPrincipal()) {
          accountsToCheck.specificAccounts.push(principal.accountId())
          if (principal.accountId() === resourceAccount) {
            accountsToCheck.resourceAccountTrustedByPolicy = true
          }
        } else {
          accountsToCheck.specificPrincipals.push(
            await resolveResourcePolicyPrincipalArn(principal.value(), collectClient)
          )
        }
      }

      if (hasWildcardPrincipal) {
        const serviceCheck = checkForServicePrincipalConditions(statement.conditions())

        if (serviceCheck.type === 'unnamed-service-only') {
          continue
        }

        if (serviceCheck.type === 'named-service-only') {
          accountsToCheck.specificPrincipals.push(...serviceCheck.principals)
          continue
        }

        const specificOrgs: string[] = []
        const specificOus: string[] = []
        const specificAccounts: string[] = []
        const specificPrincipals: string[] = []
        let principalArnRequiresAllAccounts = false
        let hasNonPrincipalArnAccountNarrowing = false

        const conditions = statement.conditions()
        for (const cond of conditions) {
          const condKey = cond.conditionKey().toLowerCase()
          if (
            condKey === 'aws:principalorgid' &&
            cond.operation().value().toLowerCase().startsWith('stringequals') &&
            !cond.conditionValues().some((v: string) => v.includes('$'))
          ) {
            specificOrgs.push(...cond.conditionValues())
          }
          if (
            condKey === 'aws:principalorgpaths' &&
            cond.operation().baseOperator().toLowerCase().startsWith('stringequals') &&
            !cond.conditionValues().some((v: string) => v.includes('$'))
          ) {
            specificOus.push(...cond.conditionValues())
          }
          if (condKey === 'aws:principalaccount' || condKey === 'kms:calleraccount') {
            const opVal = cond.operation().value().toLowerCase()
            const baseOp = cond.operation().baseOperator().toLowerCase()
            const values = cond.conditionValues()
            const hasDynamic = values.some((v: string) => v.includes('$'))

            if (opVal.startsWith('stringequals') && !hasDynamic) {
              // StringEquals family — all values are literal account IDs
              specificAccounts.push(...values)
              hasNonPrincipalArnAccountNarrowing = true
            } else if (
              baseOp === 'stringlike' &&
              !hasDynamic &&
              values.every((v: string) => !v.includes('*') && !v.includes('?'))
            ) {
              // StringLike where ALL values are literal (no wildcards or dynamic vars)
              specificAccounts.push(...values)
              hasNonPrincipalArnAccountNarrowing = true
            }
          }

          if (condKey === 'aws:principalarn') {
            const opValue = cond.operation().value().toLowerCase()
            const baseOp = cond.operation().baseOperator().toLowerCase()
            const isExactOperator = opValue.startsWith('stringequals')
            const isPatternOperator = PRINCIPAL_ARN_PATTERN_OPERATORS.has(baseOp)

            if (!isExactOperator && !isPatternOperator) {
              continue
            }

            for (const value of cond.conditionValues()) {
              let extractedPrincipalArnScope = false
              if (!hasWildcardOrDynamic(value)) {
                // Exact literal — push as a specific principal
                specificPrincipals.push(
                  await resolveResourcePolicyPrincipalArn(value, collectClient)
                )
                extractedPrincipalArnScope = true
              } else if (isExactOperator && !value.includes('*') && !value.includes('?')) {
                // Exact operator with a dynamic variable but no wildcards — try account extraction
                const segments = splitArnIgnoringDynamicVars(value)
                if (segments.length >= 6 && segments[0].toLowerCase() === 'arn') {
                  const account = segments[4]
                  if (account && !hasWildcardOrDynamic(account)) {
                    specificAccounts.push(account)
                    extractedPrincipalArnScope = true
                  }
                }
              } else {
                // Pattern operator or value with wildcards — try account extraction
                const segments = splitArnIgnoringDynamicVars(value)
                if (segments.length >= 6 && segments[0].toLowerCase() === 'arn') {
                  const account = segments[4]
                  if (account && !hasWildcardOrDynamic(account)) {
                    specificAccounts.push(account)
                    extractedPrincipalArnScope = true
                  }
                }
              }

              if (!extractedPrincipalArnScope) {
                // Wildcard-account or otherwise non-extractable PrincipalArn patterns can match any account.
                principalArnRequiresAllAccounts = true
              }
            }
          }
        }

        if (specificPrincipals.length > 0) {
          accountsToCheck.specificPrincipals.push(...specificPrincipals)
        }
        if (
          principalArnRequiresAllAccounts &&
          specificOus.length === 0 &&
          specificOrgs.length === 0 &&
          !hasNonPrincipalArnAccountNarrowing
        ) {
          accountsToCheck.allAccounts = true
          accountsToCheck.resourceAccountTrustedByPolicy = true
          accountsToCheck.checkAllFromResourceAccount = true
          if (specificAccounts.length > 0) {
            accountsToCheck.specificAccounts.push(...specificAccounts)
          }
        } else if (specificAccounts.length > 0) {
          accountsToCheck.specificAccounts.push(...specificAccounts)
          if (resourceAccount && specificAccounts.includes(resourceAccount)) {
            accountsToCheck.resourceAccountTrustedByPolicy = true
            accountsToCheck.checkAllFromResourceAccount = true
          }
        } else if (specificOus.length > 0) {
          accountsToCheck.specificOrganizationalUnits.push(...specificOus)
          // The resource account may be in these OUs; conservatively assume trusted
          accountsToCheck.resourceAccountTrustedByPolicy = true
          accountsToCheck.checkAllFromResourceAccount = true
        } else if (specificOrgs.length > 0) {
          accountsToCheck.specificOrganizations.push(...specificOrgs)
          // The resource account may be in these orgs; conservatively assume trusted
          accountsToCheck.resourceAccountTrustedByPolicy = true
          accountsToCheck.checkAllFromResourceAccount = true
        } else if (specificPrincipals.length === 0) {
          accountsToCheck.allAccounts = true
          accountsToCheck.resourceAccountTrustedByPolicy = true
          accountsToCheck.checkAllFromResourceAccount = true
        }
      }
    }
  }

  return accountsToCheck
}

/**
 * Resolves a resource-policy principal to the canonical collected principal ARN.
 *
 * Resource policies can name STS assumed-role sessions, including pathless session
 * ARNs for path-qualified IAM roles. Resolve through collect data first so
 * whoCan can de-duplicate those principals before simulation, then preserve the
 * previous session-to-role conversion behavior when the principal is not found.
 *
 * @param principalArn The resource-policy principal ARN or service principal to resolve.
 * @param collectClient The collect client used to resolve canonical principal ARNs.
 * @returns The canonical collected ARN when found, otherwise the original principal ARN.
 */
async function resolveResourcePolicyPrincipalArn(
  principalArn: string,
  collectClient: IamCollectClient
): Promise<string> {
  if (!principalArn.startsWith('arn:')) {
    return principalArn
  }

  return (await collectClient.resolvePrincipalArn(principalArn)) ?? principalArn
}

export async function actionsForWhoCan(
  request: Pick<ResourceAccessRequest, 'actions' | 'resource'>
): Promise<string[]> {
  const { actions } = request

  if (actions && actions.length > 0) {
    const validActions: string[] = []
    for (const action of actions) {
      const parts = action.split(':')
      if (parts.length !== 2) {
        continue
      }
      const [service, actionName] = parts
      const serviceExists = await iamServiceExists(service)
      if (!serviceExists) {
        continue
      }
      const actionExists = await iamActionExists(service, actionName)
      if (!actionExists) {
        continue
      }

      validActions.push(action)
    }
    return validActions
  }
  if (!request.resource) {
    return []
  }
  return lookupActionsForResourceArn(request.resource)
}

/**
 * Get the the possible resource types for an action and resource
 *
 * @param service the service the action belongs to
 * @param action the action to get the resource type for
 * @param resourceArn the resource type matching the action, if any
 * @throws an error if the service or action does not exist, or if the action is a wildcard only action
 */
export async function lookupActionsForResourceArn(resourceArn: string): Promise<string[]> {
  const [service, resourceType] = await findResourceTypeForArn(resourceArn)
  const resourceTypeKey = resourceType.key

  const selectedActions: string[] = []
  const serviceActions = await iamActionsForService(service)
  for (const action of serviceActions) {
    const actionDetails = await iamActionDetails(service, action)
    for (const rt of actionDetails.resourceTypes) {
      if (rt.name == resourceTypeKey) {
        selectedActions.push(`${service}:${action}`)
        break // No need to check other resource types for this action
      }
    }
  }

  const isRole = new Arn(resourceArn).matches({ service: 'iam', resourceType: 'role' })
  if (isRole) {
    selectedActions.push(...AssumeRoleActions.values())
  }

  return selectedActions
}

export async function findResourceTypeForArn(resourceArn: string): Promise<[string, ResourceType]> {
  const arnParts = splitArnParts(resourceArn)
  const service = arnParts.service!.toLowerCase()

  const serviceExists = await iamServiceExists(service)
  if (!serviceExists) {
    throw new Error(`Unable to find service ${service} for resource ${resourceArn}`)
  }

  const sortedResourceTypes = await allResourceTypesByArnLength(service)
  const matchingPatterns = mostSpecificMatchingResourceTypePatterns(
    resourceArn,
    sortedResourceTypes.map((resourceType) => resourceType.arn)
  )
  const resourceType = sortedResourceTypes.find((rt) => matchingPatterns.includes(rt.arn))
  if (resourceType) {
    return [service, resourceType]
  }

  throw new Error(
    `Unable to find resource type for service ${service} and resource ${resourceArn}.`
  )
}

async function allResourceTypesByArnLength(service: string): Promise<ResourceType[]> {
  const resourceTypeKeys = await iamResourceTypesForService(service)
  const sortedResourceTypes: ResourceType[] = []
  for (const key of resourceTypeKeys) {
    const details = await iamResourceTypeDetails(service, key)
    sortedResourceTypes.push(details)
  }
  return sortedResourceTypes.sort((a, b) => {
    return b.arn.length - a.arn.length
  })
}

/**
 * Sort the results in a WhoCanResponse in place for consistent output
 *
 * @param whoCanResponse the WhoCanResponse to sort
 */
export function sortWhoCanResults(whoCanResponse: WhoCanResponse) {
  whoCanResponse.allowed.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })

  whoCanResponse.denyDetails?.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })

  whoCanResponse.accountsNotFound.sort()
  whoCanResponse.organizationsNotFound.sort()
  whoCanResponse.organizationalUnitsNotFound.sort()
  whoCanResponse.principalsNotFound.sort()
}
