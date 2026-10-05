import { iamActionDetails, iamActionExists, iamServiceExists } from '@actsecurity/iam-data'
import { type ValidatedPolicy } from '@actsecurity/iam-policy'
import {
  anonymousPrincipal,
  type DiscoveryContextKeyConstraint,
  type EvaluationResult,
  type RunSimulationResults,
  runSimulation,
  type Simulation,
  type SimulationMode
} from '@actsecurity/iam-simulate'
import {
  convertAssumedRoleArnToRoleArn,
  isAssumedRoleArn,
  isIamRoleArn,
  isS3BucketOrObjectArn,
  splitArnParts
} from '@actsecurity/iam-utils'
import { IamCollectClient, type SimulationOrgPolicies } from '../collect/client.js'
import {
  getAllPoliciesForPrincipal,
  isServiceLinkedRole,
  isServicePrincipal,
  principalExists,
  type PrincipalPolicies
} from '../principals.js'
import {
  getAccountIdForResource,
  getRcpsForResource,
  getResourcePolicyForResource
} from '../resources.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { AssumeRoleActions } from '../utils/sts.js'
import {
  CONTEXT_KEYS,
  type ContextKeys,
  contextValue,
  createContextKeys,
  isAnonymousPrincipalContextKey,
  knownContextKeys
} from './contextKeys.js'
import { externalResourcePolicy, syntheticIdentityPolicy } from './generatedPolicies.js'

const kmsRetireGrantAction = 'kms:retiregrant'

/**
 * The request details for simulating an IAM request from a collected principal.
 */
export interface SimulationRequest {
  /**
   * The ARN of the resource to simulate access to. Can be undefined for wildcard actions.
   */
  resourceArn: string | undefined

  /**
   * The account ID of the resource, only required if it cannot be determined from the resource ARN.
   */
  resourceAccount: string | undefined

  /**
   * The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`.
   */
  action: string

  /**
   * The ARN of the principal to simulate. Can be a user, role, session, or AWS service.
   */
  principal: string

  /**
   * Caller-provided context values for the simulation. These override generated values
   * case-insensitively and are authoritative in Discovery mode.
   */
  customContextKeys: ContextKeys

  /**
   * The simulation mode to use for the request.
   */
  simulationMode: SimulationMode

  /**
   * Override for S3 ABAC settings for the simulation.
   */
  s3AbacOverride?: S3AbacOverride

  /**
   * The session policy to use for the simulation, if the principal type supports it.
   */
  sessionPolicy?: any

  /**
   * Additional strict context keys to include for the simulation. These will be added to the default strict context keys.
   */
  additionalStrictContextKeys?: string[]
}

/**
 * An unsigned simulation request against a concrete resource ARN.
 * Anonymous requests have no identity, session, permission-boundary, or SCP inputs.
 */
export interface AnonymousSimulationRequest extends Omit<
  SimulationRequest,
  'principal' | 'resourceArn' | 'sessionPolicy'
> {
  /**
   * The concrete resource ARN to access. Anonymous wildcard-only requests are unsupported.
   */
  resourceArn: string
}

/**
 * A simulation request targeting a resource that is not expected to exist in the collected dataset.
 */
export interface ExternalResourceSimulationRequest extends Omit<SimulationRequest, 'resourceArn'> {
  /**
   * The concrete ARN of the resource outside the collected dataset.
   */
  resourceArn: string

  /**
   * Optional raw resource policy, or trust policy for an STS assume-role action, to use instead of
   * the synthetic allow-all policy.
   */
  resourcePolicy?: Record<string, unknown>
}

/**
 * The result of a simulation request, containing the normalized request and evaluation result.
 */
export interface SimulateRequestResult {
  /**
   * The simulation request that was evaluated.
   */
  request: Simulation['request']

  /**
   * The result of the simulation, which may be an error, a single result, or a wildcard result.
   */
  result: RunSimulationResults
}

/**
 * Identifies which collected or synthetic policy sources apply to a simulation.
 */
type SimulationVariant = 'normal' | 'anonymous' | 'externalPrincipal' | 'externalResource'

/**
 * Normalized request shape shared by authenticated and anonymous orchestration.
 */
export type InternalSimulationRequest = Omit<SimulationRequest, 'principal'> & {
  /**
   * Authenticated principal string, or undefined for an anonymous request.
   */
  principal: string | undefined

  /**
   * Caller-supplied external resource or trust policy.
   */
  resourcePolicy?: Record<string, unknown>
}

/**
 * Fully prepared principal-side policy inputs for an iam-simulate request.
 */
export interface PrincipalPolicyInputs {
  /**
   * Identity policies applicable to the request principal.
   */
  identityPolicies: { name: string; policy: any }[]

  /**
   * Service control policy hierarchies applicable to the principal.
   */
  serviceControlPolicies: SimulationOrgPolicies[]

  /**
   * Permission boundary applicable to the principal, when one exists.
   */
  permissionBoundaryPolicies: { name: string; policy: any }[] | undefined

  /**
   * RCP hierarchy for the principal account, used by collected wildcard-only requests.
   */
  principalAccountRcps: SimulationOrgPolicies[]
}

/**
 * Fully prepared resource-side policy inputs for an iam-simulate request.
 */
interface ResourcePolicyInputs {
  /**
   * Resource or trust policy applicable to the requested resource.
   */
  resourcePolicy: ValidatedPolicy<{ name: string }> | undefined

  /**
   * Filtered resource control policy hierarchies applicable to the request.
   */
  resourceControlPolicies: SimulationOrgPolicies[]
}

/**
 * Simulate an IAM request using the collected policies for both the principal and resource.
 *
 * @param simulationRequest the simulation request details
 * @param collectClient the IAM collect client to use for data access
 * @returns the normalized request and simulation result
 */
export async function simulateRequest(
  simulationRequest: SimulationRequest,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  return simulateRequestInternal({ ...simulationRequest }, 'normal', collectClient)
}

/**
 * Simulate an unsigned request against a concrete resource ARN.
 *
 * @param simulationRequest the anonymous request details
 * @param collectClient the IAM collect client to use for data access
 * @returns the normalized anonymous request and simulation result
 */
export async function simulateAnonymousRequest(
  simulationRequest: AnonymousSimulationRequest,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  return simulateRequestInternal(
    { ...simulationRequest, principal: undefined },
    'anonymous',
    collectClient
  )
}

/**
 * Simulate a request from an uncollected principal that has a synthetic administrator identity policy.
 * SCPs and permission boundaries do not apply, while resource-side controls still apply.
 * Wildcard-only actions are unsupported.
 *
 * @param simulationRequest the external principal request details
 * @param collectClient the IAM collect client to use for resource-side data access
 * @returns the normalized request and simulation result
 */
export async function simulateExternalPrincipalRequest(
  simulationRequest: SimulationRequest,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  return simulateRequestInternal({ ...simulationRequest }, 'externalPrincipal', collectClient)
}

/**
 * Simulate a collected principal accessing a resource outside the collected dataset.
 * Wildcard-only actions are unsupported.
 *
 * @param simulationRequest the external resource request and optional resource/trust policy
 * @param collectClient the IAM collect client to use for principal-side data access
 * @returns the normalized request and simulation result
 */
export async function simulateExternalResourceRequest(
  simulationRequest: ExternalResourceSimulationRequest,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  return simulateRequestInternal({ ...simulationRequest }, 'externalResource', collectClient)
}

/**
 * Assemble and run every simulation variant through one policy and context processing path.
 *
 * @param input the normalized caller input
 * @param variant the policy-source behavior selected by the public entry point
 * @param collectClient the IAM collect client used for applicable data lookups
 * @returns the normalized request and simulation result
 */
async function simulateRequestInternal(
  input: InternalSimulationRequest,
  variant: SimulationVariant,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  const simulationRequest = { ...input }
  if (variant === 'anonymous') {
    const invalidContextKey = Object.keys(simulationRequest.customContextKeys).find(
      isAnonymousPrincipalContextKey
    )
    if (invalidContextKey) {
      throw new Error(
        `Anonymous simulations cannot specify principal-derived context key ${invalidContextKey}.`
      )
    }
  }

  const [service, serviceAction] = simulationRequest.action.split(':')
  const serviceExists = await iamServiceExists(service)
  const actionExists = serviceExists && (await iamActionExists(service, serviceAction))
  if (!serviceExists || !actionExists) {
    throw new Error(`Unable to find action details for ${simulationRequest.action}`)
  }
  const actionDetails = await iamActionDetails(service, serviceAction)

  if (actionDetails.isWildcardOnly && variant !== 'normal') {
    const variantName =
      variant === 'anonymous'
        ? 'Anonymous'
        : variant === 'externalPrincipal'
          ? 'External principal'
          : 'External resource'
    throw new Error(`${variantName} simulations do not support wildcard-only actions.`)
  }

  if (variant === 'anonymous' && !simulationRequest.resourceArn) {
    throw new Error('Anonymous simulations require a concrete resource ARN.')
  }
  if (variant === 'externalResource' && !simulationRequest.resourceArn) {
    throw new Error('External resource simulations require a concrete resource ARN.')
  }

  if (actionDetails.isWildcardOnly) {
    simulationRequest.resourceAccount = splitArnParts(simulationRequest.principal!).accountId
  }

  if (!simulationRequest.resourceAccount && !simulationRequest.resourceArn) {
    throw new Error(
      'Non wildcard actions require a resource ARN or resource account to be specified.'
    )
  }
  simulationRequest.resourceAccount =
    simulationRequest.resourceAccount ||
    (await getAccountIdForResource(collectClient, simulationRequest.resourceArn!))

  if (!simulationRequest.resourceAccount) {
    throw new Error(`Unable to find account ID for resource ${simulationRequest.resourceArn}`)
  }

  const requiresCollectedPrincipal = variant === 'normal' || variant === 'externalResource'
  if (requiresCollectedPrincipal) {
    const principalFound = await principalExists(simulationRequest.principal!, collectClient)
    if (!principalFound) {
      throw new Error(
        `Principal ${simulationRequest.principal} does not exist. Use --external-principal to test principals outside your dataset.`
      )
    }
  }

  const principalPolicyInputs = await principalPoliciesForVariant(
    variant,
    simulationRequest,
    collectClient
  )
  const resourcePolicyInputs = await resourcePoliciesForVariant(
    variant,
    simulationRequest,
    service,
    actionDetails.isWildcardOnly,
    principalPolicyInputs.principalAccountRcps,
    collectClient
  )

  const request: Simulation['request'] = {
    action: simulationRequest.action,
    resource: {
      resource: simulationRequest.resourceArn || '*',
      accountId: simulationRequest.resourceAccount
    },
    principal: variant === 'anonymous' ? anonymousPrincipal : simulationRequest.principal!,
    contextVariables: {}
  }

  const principalArnForContext = simulationRequest.principal
    ? await resolvePrincipalArnForContext(collectClient, simulationRequest.principal)
    : undefined
  const includeResourceMetadata = variant !== 'externalResource'
  const { contextKeys, resourceTagsAreKnown } = await createContextKeys(
    collectClient,
    simulationRequest,
    service,
    simulationRequest.customContextKeys,
    principalArnForContext,
    { includeResourceMetadata }
  )

  const vpcEndpointPolicy = await getVpcEndpointPolicy(collectClient, contextKeys)
  request.contextVariables = contextKeys

  const simulation: Simulation = {
    request,
    sessionPolicy: variant === 'anonymous' ? undefined : simulationRequest.sessionPolicy,
    identityPolicies: principalPolicyInputs.identityPolicies,
    serviceControlPolicies: principalPolicyInputs.serviceControlPolicies,
    resourceControlPolicies: resourcePolicyInputs.resourceControlPolicies,
    resourcePolicy: resourcePolicyInputs.resourcePolicy,
    permissionBoundaryPolicies: principalPolicyInputs.permissionBoundaryPolicies,
    vpcEndpointPolicies: vpcEndpointPolicy ? [vpcEndpointPolicy] : undefined
  }

  await applyS3Settings(simulation, simulationRequest, variant, collectClient)

  const strictContextKeys = makeStrictContextKeys(
    simulationRequest,
    contextKeys,
    resourceTagsAreKnown,
    isS3BucketOrObjectArn(simulationRequest.resourceArn || '')
  )
  const discoveryContextKeyConstraints = strictContextKeys.map((keyName) =>
    discoveryConstraintForStrictKey(keyName, simulationRequest)
  )

  const result = await runSimulation(simulation, {
    simulationMode: simulationRequest.simulationMode,
    discoveryContextKeyConstraints
  })

  return { request, result }
}

/**
 * Build all principal-side policy inputs for the selected simulation variant.
 *
 * Collected-principal variants prepare collected identity policies, SCPs, and permission
 * boundaries. External principals receive only a synthetic administrator identity policy, while
 * anonymous requests receive no principal-side policies.
 *
 * @param variant the simulation policy-source variant
 * @param request the normalized request
 * @param collectClient the data client
 * @returns fully prepared principal-side simulation inputs
 */
async function principalPoliciesForVariant(
  variant: SimulationVariant,
  request: InternalSimulationRequest,
  collectClient: IamCollectClient
): Promise<PrincipalPolicyInputs> {
  if (variant === 'anonymous') {
    return emptyPrincipalPolicyInputs()
  }

  if (variant === 'externalPrincipal') {
    return {
      ...emptyPrincipalPolicyInputs(),
      identityPolicies: [syntheticIdentityPolicy]
    }
  }

  const principalArn = request.principal!
  const collectedPolicies = await getAllPoliciesForPrincipal(collectClient, principalArn)
  return {
    identityPolicies: prepareIdentityPolicies(principalArn, collectedPolicies),
    serviceControlPolicies: collectedPolicies.scps,
    permissionBoundaryPolicies: preparePermissionBoundary(collectedPolicies),
    principalAccountRcps: collectedPolicies.rcps
  }
}

/**
 * Return principal-side policy inputs with no applicable policies.
 *
 * @returns empty principal-side simulation inputs
 */
function emptyPrincipalPolicyInputs(): PrincipalPolicyInputs {
  return {
    identityPolicies: [],
    serviceControlPolicies: [],
    permissionBoundaryPolicies: undefined,
    principalAccountRcps: []
  }
}

/**
 * Build all resource-side policy inputs for the selected simulation variant.
 *
 * This selects external versus collected resource policy behavior. All collected resource-policy
 * and RCP applicability is delegated to `getResourcePolicies`.
 *
 * @param variant the simulation policy-source variant
 * @param request the normalized request
 * @param service the requested IAM service prefix
 * @param actionIsWildcard whether the action uses the account-wide wildcard resource
 * @param principalAccountRcps RCP hierarchy used by collected wildcard-only requests
 * @param collectClient the data client
 * @returns fully prepared resource-side simulation inputs
 */
async function resourcePoliciesForVariant(
  variant: SimulationVariant,
  request: InternalSimulationRequest,
  service: string,
  actionIsWildcard: boolean,
  principalAccountRcps: SimulationOrgPolicies[],
  collectClient: IamCollectClient
): Promise<ResourcePolicyInputs> {
  if (variant === 'externalResource') {
    return {
      resourcePolicy: externalResourcePolicy(request),
      resourceControlPolicies: []
    }
  }

  return getResourcePolicies(
    collectClient,
    request.action,
    service,
    request.resourceArn,
    request.resourceAccount,
    request.principal,
    actionIsWildcard,
    principalAccountRcps
  )
}

/**
 * Look up the VPC endpoint policy selected by generated or caller-provided context.
 *
 * @param collectClient the data client
 * @param contextKeys the normalized request context
 * @returns the named endpoint policy when one is available
 */
async function getVpcEndpointPolicy(
  collectClient: IamCollectClient,
  contextKeys: ContextKeys
): Promise<{ name: string; policy: any } | undefined> {
  const vpcEndpointId = contextValue(contextKeys, CONTEXT_KEYS.vpcEndpointId)
  if (!vpcEndpointId || typeof vpcEndpointId !== 'string') {
    return undefined
  }
  const vpcEndpointArn = await collectClient.getVpcEndpointArnForVpcEndpointId(vpcEndpointId)
  if (!vpcEndpointArn) {
    return undefined
  }
  const policy = await collectClient.getVpcEndpointPolicyForArn(vpcEndpointArn)
  return policy ? { name: vpcEndpointArn, policy } : undefined
}

/**
 * Apply S3 ABAC and Block Public Access settings appropriate to the simulation variant.
 *
 * @param simulation the iam-simulate input to update
 * @param request the normalized request
 * @param variant the simulation policy-source variant
 * @param collectClient the data client
 */
async function applyS3Settings(
  simulation: Simulation,
  request: InternalSimulationRequest,
  variant: SimulationVariant,
  collectClient: IamCollectClient
): Promise<void> {
  if (!request.resourceArn || !isS3BucketOrObjectArn(request.resourceArn)) {
    return
  }

  if (variant === 'externalResource') {
    simulation.additionalSettings = {
      s3: {
        bucketAbacEnabled: request.s3AbacOverride === 'enabled',
        blockPublicAccess: false
      }
    }
    return
  }

  const [bucketAbacEnabled, blockPublicAccess] = await Promise.all([
    evaluateAbacForBucket(
      request.s3AbacOverride,
      collectClient,
      request.resourceAccount!,
      request.resourceArn
    ),
    collectClient.getBlockPublicAccessEnabledForBucket(
      request.resourceAccount!,
      request.resourceArn
    )
  ])
  simulation.additionalSettings = { s3: { bucketAbacEnabled, blockPublicAccess } }
}

/**
 * Assemble strict Discovery context-key constraints for a normalized request.
 *
 * @param request the normalized request
 * @param contextKeys generated and caller-provided context values
 * @param resourceTagsAreKnown whether all resource tags are known
 * @param s3BucketOrObjectRequest whether S3 bucket tag keys apply
 * @returns strict literal keys and key patterns
 */
function makeStrictContextKeys(
  request: InternalSimulationRequest,
  contextKeys: ContextKeys,
  resourceTagsAreKnown: boolean,
  s3BucketOrObjectRequest: boolean
): string[] {
  const strictContextKeys = [...knownContextKeys, ...(request.additionalStrictContextKeys ?? [])]

  if (!request.principal) {
    strictContextKeys.push(CONTEXT_KEYS.userId, CONTEXT_KEYS.assumedRoot, '/^aws:PrincipalTag\/.*/')
  } else {
    if (!isIamRoleArn(request.principal)) {
      strictContextKeys.push(CONTEXT_KEYS.userId)
    }
    if (!request.principal.endsWith(':root')) {
      strictContextKeys.push(CONTEXT_KEYS.assumedRoot)
    }
  }
  if (request.action.startsWith('s3:')) {
    strictContextKeys.push('s3:DataAccessPointAccount', 's3:DataAccessPointArn')
  }
  strictContextKeys.push(...Object.keys(request.customContextKeys))

  if (resourceTagsAreKnown) {
    strictContextKeys.push('/^aws:ResourceTag\/.*/')
    if (s3BucketOrObjectRequest) {
      strictContextKeys.push('/^s3:BucketTag\/.*/')
    }
  }
  for (const key of Object.keys(contextKeys)) {
    if (key.toLowerCase().includes('tag/')) {
      strictContextKeys.push(key)
    }
  }

  return strictContextKeys
}

const awsSourceKeyPrefix = 'aws:source'
const anonymousAbsentContextKeys = new Set([
  'aws:principalarn',
  'aws:principalaccount',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:username',
  'aws:userid',
  'aws:principalisawsservice',
  'aws:principalservicename',
  'aws:sourceaccount',
  'aws:sourceorgid',
  'aws:sourceorgpaths',
  'aws:sourceowner',
  'aws:sourcearn',
  'aws:assumedroot',
  'kms:calleraccount',
  '/^aws:principaltag\/.*/'
])

/**
 * Convert an iam-lens strict context key into an iam-simulate Discovery constraint.
 *
 * @param keyName the literal context key or slash-delimited key pattern
 * @param simulationRequest the normalized request whose context certainty is modeled
 * @returns the Discovery constraint to pass to iam-simulate
 * @internal
 */
export function discoveryConstraintForStrictKey(
  keyName: string,
  simulationRequest: Pick<
    InternalSimulationRequest,
    'customContextKeys' | 'simulationMode' | 'principal'
  >
): DiscoveryContextKeyConstraint {
  if (hasCustomContextKey(simulationRequest.customContextKeys, keyName)) {
    return { keyName, presenceIsKnown: true, valueIsKnown: true }
  }

  if (
    simulationRequest.principal === undefined &&
    anonymousAbsentContextKeys.has(keyName.toLowerCase())
  ) {
    return { keyName, presenceIsKnown: true, valueIsKnown: true }
  }

  const isServiceCallerAccountInDiscovery =
    keyName.localeCompare('kms:CallerAccount', undefined, { sensitivity: 'base' }) === 0 &&
    simulationRequest.simulationMode === 'Discovery' &&
    simulationRequest.principal !== undefined &&
    isServicePrincipal(simulationRequest.principal)

  if (isServiceCallerAccountInDiscovery) {
    return { keyName, presenceIsKnown: true, valueIsKnown: false }
  }

  if (
    keyName.slice(0, 10).localeCompare(awsSourceKeyPrefix, undefined, { sensitivity: 'base' }) === 0
  ) {
    return { keyName, presenceIsKnown: true, valueIsKnown: false }
  }

  return { keyName, presenceIsKnown: true, valueIsKnown: true }
}

/**
 * Check whether a caller supplied a context key using IAM's case-insensitive matching.
 *
 * @param customContextKeys caller-provided context values
 * @param keyName context key to look up
 * @returns whether the caller supplied the key
 */
function hasCustomContextKey(customContextKeys: ContextKeys, keyName: string): boolean {
  if (Object.hasOwn(customContextKeys, keyName)) {
    return true
  }
  return Object.keys(customContextKeys).some(
    (customKey) => customKey.toLowerCase() === keyName.toLowerCase()
  )
}

/**
 * Retrieve a collected resource policy and all applicable RCPs for a request.
 *
 * This applies non-variant resource-policy and RCP rules, including trust-policy requirements,
 * IAM role identity-policy resources, wildcard-only actions, service-linked roles,
 * `kms:RetireGrant`, AWS-managed KMS keys, and the implicit full-access RCP.
 *
 * @param collectClient the data client
 * @param action the action being simulated
 * @param service the requested IAM service prefix
 * @param resourceArn the resource ARN
 * @param resourceAccount the resource account
 * @param principalArn the authenticated principal ARN, when present
 * @param actionIsWildcard whether the action uses the account-wide wildcard resource
 * @param principalAccountRcps RCP hierarchy for the principal account
 * @returns the resource policy and filtered RCP hierarchies applicable to the request
 */
async function getResourcePolicies(
  collectClient: IamCollectClient,
  action: string,
  service: string,
  resourceArn: string | undefined,
  resourceAccount: string | undefined,
  principalArn: string | undefined,
  actionIsWildcard: boolean,
  principalAccountRcps: SimulationOrgPolicies[]
): Promise<ResourcePolicyInputs> {
  const resourcePolicy = resourceArn
    ? await getResourcePolicyForResource(collectClient, resourceArn, resourceAccount)
    : undefined

  // AWS does not apply RCPs when a service principal assumes a service-linked role.
  const servicePrincipalAssumesServiceLinkedRole =
    principalArn !== undefined &&
    resourceArn !== undefined &&
    isServicePrincipal(principalArn) &&
    isServiceLinkedRole(resourceArn)

  let resourceRcps: SimulationOrgPolicies[] = []
  if (
    resourceArn &&
    !servicePrincipalAssumesServiceLinkedRole &&
    action.localeCompare(kmsRetireGrantAction, undefined, { sensitivity: 'base' }) !== 0
  ) {
    const resourceArnParts = splitArnParts(resourceArn)
    const isAwsManagedKmsKey =
      resourceArnParts.service === 'kms' &&
      resourceArnParts.resourceType === 'key' &&
      resourceAccount !== undefined &&
      (await collectClient.isAwsManagedKmsKey(resourceArn, resourceAccount))
    if (!isAwsManagedKmsKey) {
      resourceRcps = await getRcpsForResource(collectClient, resourceArn, resourceAccount)
    }
  }

  const applicableRcps =
    principalArn && isServiceLinkedRole(principalArn)
      ? []
      : actionIsWildcard
        ? principalAccountRcps
        : resourceRcps

  if (AssumeRoleActions.has(action.toLowerCase()) && !resourcePolicy) {
    throw new Error(
      `Trust policy not found for resource ${resourceArn}. sts assume role actions require a trust policy.`
    )
  }

  const useResourcePolicy =
    resourceArn !== undefined && !(isIamRoleArn(resourceArn) && service.toLowerCase() === 'iam')

  return {
    resourcePolicy: useResourcePolicy ? resourcePolicy : undefined,
    resourceControlPolicies: applicableRcps.map((rcp) => ({
      orgIdentifier: rcp.orgIdentifier,
      policies: rcp.policies.filter(
        (policy) => !policy.name.toLowerCase().endsWith('rcpfullawsaccess')
      )
    }))
  }
}

/**
 * Resolve the canonical role ARN used for role-backed context keys.
 *
 * @param collectClient the data client
 * @param principalArn the request principal ARN
 * @returns the canonical role ARN for an assumed-role session, otherwise undefined
 */
async function resolvePrincipalArnForContext(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<string | undefined> {
  if (!isAssumedRoleArn(principalArn)) {
    return undefined
  }
  return (
    (await collectClient.resolvePrincipalArn(principalArn)) ??
    convertAssumedRoleArnToRoleArn(principalArn)
  )
}

/**
 * Flatten collected managed, inline, and group policies into iam-simulate identity inputs.
 *
 * @param principalArn the principal whose inline policy names are qualified
 * @param principalPolicies collected policies for the principal
 * @returns named identity policy inputs
 */
function prepareIdentityPolicies(
  principalArn: string,
  principalPolicies: PrincipalPolicies
): { name: string; policy: any }[] {
  const uniqueIdentityPolicies: Record<string, { name: string; policy: any }> = {}
  principalPolicies.managedPolicies.forEach((policy) => {
    if (!uniqueIdentityPolicies[policy.arn]) {
      uniqueIdentityPolicies[policy.arn] = { name: policy.arn, policy: policy.policy }
    }
  })
  principalPolicies.groupPolicies?.forEach((groupPolicy) => {
    groupPolicy.managedPolicies.forEach((policy) => {
      if (!uniqueIdentityPolicies[policy.arn]) {
        uniqueIdentityPolicies[policy.arn] = { name: policy.arn, policy: policy.policy }
      }
    })
  })

  const identityPolicies = Object.values(uniqueIdentityPolicies)
  principalPolicies.inlinePolicies.forEach((policy) => {
    identityPolicies.push({ name: `${principalArn}#${policy.name}`, policy: policy.policy })
  })
  principalPolicies.groupPolicies?.forEach((groupPolicy) => {
    groupPolicy.inlinePolicies.forEach((policy) => {
      identityPolicies.push({
        name: `${groupPolicy.group}#${policy.name}`,
        policy: policy.policy
      })
    })
  })
  return identityPolicies
}

/**
 * Convert a collected permission boundary into iam-simulate inputs.
 *
 * @param principalPolicies collected policies for the principal
 * @returns the named boundary policy or undefined
 */
function preparePermissionBoundary(
  principalPolicies: PrincipalPolicies
): { name: string; policy: any }[] | undefined {
  if (!principalPolicies.permissionBoundary) {
    return undefined
  }
  return [
    {
      name: principalPolicies.permissionBoundary.arn,
      policy: principalPolicies.permissionBoundary.policy
    }
  ]
}

/**
 * Compare an actual simulation decision with an optional expected result.
 *
 * @param expected expected result or AnyDeny
 * @param result actual evaluation result
 * @returns whether the result satisfies the expectation
 */
export function resultMatchesExpectation(
  expected: EvaluationResult | 'AnyDeny' | undefined,
  result: EvaluationResult
): boolean {
  if (!expected) {
    return true
  }
  if (expected === 'AnyDeny') {
    return result.includes('Denied')
  }
  return expected === result
}

/**
 * Evaluate whether S3 ABAC is enabled for a bucket or object.
 *
 * @param s3AbacOverride caller override or undefined for collected detection
 * @param collectClient the data client
 * @param bucketAccountId the bucket account
 * @param bucketOrObjectArn the bucket or object ARN
 * @returns whether S3 ABAC is enabled
 */
async function evaluateAbacForBucket(
  s3AbacOverride: S3AbacOverride | undefined,
  collectClient: IamCollectClient,
  bucketAccountId: string,
  bucketOrObjectArn: string
): Promise<boolean> {
  if (s3AbacOverride === 'enabled') {
    return true
  }
  if (s3AbacOverride === 'disabled') {
    return false
  }
  return collectClient.getAbacEnabledForBucket(bucketAccountId, bucketOrObjectArn)
}
