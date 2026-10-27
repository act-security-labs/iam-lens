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
  isIamUserArn,
  isRootArn,
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
  anonymousKnownAbsentContextKeyNames,
  type ContextKeys,
  contextValue,
  createContextKeys,
  isAnonymousPrincipalContextKey,
  knownContextKeys,
  RESOURCE_TAG_KEY_PATTERNS
} from './contextKeys.js'
import { externalResourcePolicy, syntheticIdentityPolicy } from './generatedPolicies.js'
import {
  immutablePrincipalTagPattern,
  roleSessionCanSetTagKey,
  roleSessionTagCapability,
  type RoleSessionTagCapability
} from './roleSessionTags.js'

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
   * Caller-provided Discovery-only knowledge constraints. Matching caller
   * constraints override iam-lens-generated constraints case-insensitively;
   * iam-simulate ignores them in Strict mode.
   */
  discoveryContextKeyConstraints?: DiscoveryContextKeyConstraint[]
}

/**
 * An unsigned simulation request against a resource ARN or resource pattern.
 * Anonymous requests have no identity, session, permission-boundary, or SCP inputs.
 */
export interface AnonymousSimulationRequest extends Omit<
  SimulationRequest,
  'principal' | 'resourceArn' | 'sessionPolicy'
> {
  /**
   * Resource ARN to access, including wildcard patterns. Wildcard-only actions are unsupported.
   */
  resourceArn: string
}

/**
 * A simulation request for a principal ARN that is not collected as an IAM identity.
 *
 * The principal's captured organization policy hierarchies still apply. Its identity policies
 * and permission boundary are replaced by one synthetic allow-all policy or `inlinePolicy`.
 */
export interface VirtualPrincipalSimulationRequest extends SimulationRequest {
  /**
   * Raw inline identity policy that replaces the default synthetic allow-all policy.
   */
  inlinePolicy?: Record<string, unknown>
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
 * A simulation request for an uncollected resource whose organization controls should apply.
 *
 * This has the same contract as an external-resource request: a concrete resource ARN and an
 * optional caller-supplied resource or trust policy replace the synthetic allow-all policy.
 */
export type VirtualResourceSimulationRequest = ExternalResourceSimulationRequest

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
type SimulationVariant =
  | 'normal'
  | 'anonymous'
  | 'externalPrincipal'
  | 'virtualPrincipal'
  | 'externalResource'
  | 'virtualResource'

/**
 * Normalized request shape shared by authenticated and anonymous orchestration.
 */
export type InternalSimulationRequest = Omit<SimulationRequest, 'principal'> & {
  /**
   * Authenticated principal string, or undefined for an anonymous request.
   */
  principal: string | undefined

  /**
   * Caller-supplied inline identity policy for a virtual principal.
   */
  inlinePolicy?: Record<string, unknown>

  /**
   * Caller-supplied external or virtual resource policy, or trust policy.
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
 * Simulate an unsigned request against a resource ARN or wildcard resource pattern.
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
 * Simulate an uncollected IAM principal while applying organization controls for its account.
 *
 * The principal receives a synthetic allow-all identity policy unless `inlinePolicy` replaces it.
 * Permission boundaries and collected identity policies do not apply; supplied session policies still
 * constrain the request.
 *
 * @param simulationRequest the virtual principal request details
 * @param collectClient the IAM collect client to use for organization and resource-side data access
 * @returns the normalized request and simulation result
 */
export async function simulateVirtualPrincipal(
  simulationRequest: VirtualPrincipalSimulationRequest,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  return simulateRequestInternal({ ...simulationRequest }, 'virtualPrincipal', collectClient)
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
 * Simulate a collected principal accessing an uncollected resource while applying organization
 * controls for the resource's account.
 *
 * The resource receives the synthetic allow-all resource (or trust) policy of an external resource
 * unless `resourcePolicy` replaces it, and its tags, metadata, and S3 settings are unknown. The RCP
 * hierarchy captured for `resourceAccount`, or the account in `resourceArn` when no account is
 * supplied, still applies. An account outside the collected organization data has none. Wildcard-only
 * actions are unsupported.
 *
 * @param simulationRequest the virtual resource request and optional resource/trust policy
 * @param collectClient the IAM collect client to use for principal-side and organization data access
 * @returns the normalized request and simulation result
 */
export async function simulateVirtualResourceRequest(
  simulationRequest: VirtualResourceSimulationRequest,
  collectClient: IamCollectClient
): Promise<SimulateRequestResult> {
  return simulateRequestInternal({ ...simulationRequest }, 'virtualResource', collectClient)
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

  if (variant === 'virtualPrincipal' && !splitArnParts(simulationRequest.principal!).accountId) {
    throw new Error(`Virtual principal ${simulationRequest.principal} must contain an account ID.`)
  }

  if (
    actionDetails.isWildcardOnly &&
    (variant === 'anonymous' ||
      variant === 'externalPrincipal' ||
      variant === 'externalResource' ||
      variant === 'virtualResource')
  ) {
    const variantName =
      variant === 'anonymous'
        ? 'Anonymous'
        : variant === 'externalPrincipal'
          ? 'External principal'
          : variant === 'externalResource'
            ? 'External resource'
            : 'Virtual resource'
    throw new Error(`${variantName} simulations do not support wildcard-only actions.`)
  }

  if (variant === 'anonymous' && !simulationRequest.resourceArn) {
    throw new Error('Anonymous simulations require a concrete resource ARN.')
  }
  if (variant === 'externalResource' && !simulationRequest.resourceArn) {
    throw new Error('External resource simulations require a concrete resource ARN.')
  }
  if (variant === 'virtualResource' && !simulationRequest.resourceArn) {
    throw new Error('Virtual resource simulations require a concrete resource ARN.')
  }
  if (variant === 'virtualResource' && !simulationRequest.resourceAccount) {
    const resourceAccount = splitArnParts(simulationRequest.resourceArn!).accountId
    if (!resourceAccount) {
      throw new Error(
        `Virtual resource ${simulationRequest.resourceArn} must contain an account ID.`
      )
    }
    simulationRequest.resourceAccount = resourceAccount
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

  const requiresCollectedPrincipal =
    (variant === 'normal' || variant === 'externalResource' || variant === 'virtualResource') &&
    !isRootArn(simulationRequest.principal ?? '')
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
  const includeResourceMetadata = variant !== 'externalResource' && variant !== 'virtualResource'
  const { contextKeys, resourceTagsAreKnown } = await createContextKeys(
    collectClient,
    simulationRequest,
    service,
    simulationRequest.customContextKeys,
    principalArnForContext,
    {
      includePrincipalTags: requiresCollectedPrincipal,
      includeResourceMetadata
    }
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

  const sessionTagCapability = await sessionTagCapabilityForRequest(
    collectClient,
    simulationRequest,
    principalArnForContext,
    requiresCollectedPrincipal
  )
  const mutableExistingPrincipalTagKeys = mutableStoredPrincipalTagKeys(
    sessionTagCapability,
    contextKeys,
    simulationRequest.customContextKeys
  )
  const principalTagsAreUnknown = variant === 'externalPrincipal' || variant === 'virtualPrincipal'
  const generatedDiscoveryContextKeyNames = makeGeneratedDiscoveryContextKeyNames(
    simulationRequest,
    contextKeys,
    resourceTagsAreKnown,
    isS3BucketOrObjectArn(simulationRequest.resourceArn || ''),
    principalTagsAreUnknown,
    sessionTagCapability,
    mutableExistingPrincipalTagKeys
  )
  const discoveryContextKeyNames = new Set([
    ...generatedDiscoveryContextKeyNames,
    ...mutableExistingPrincipalTagKeys
  ])
  const generatedDiscoveryContextKeyConstraints = [...discoveryContextKeyNames].map((keyName) =>
    discoveryConstraintForGeneratedKey(keyName, simulationRequest, mutableExistingPrincipalTagKeys)
  )
  const discoveryContextKeyConstraints = mergeDiscoveryContextKeyConstraints(
    generatedDiscoveryContextKeyConstraints,
    simulationRequest.discoveryContextKeyConstraints ?? []
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
 * boundaries. Root principals receive the synthetic administrator identity policy plus their
 * account's organization policies because they are not stored IAM identities. External principals
 * receive only a synthetic administrator identity policy, virtual principals receive a synthetic or
 * caller-provided identity policy plus captured organization policies, and anonymous requests
 * receive no principal-side policies.
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
  if (variant === 'virtualPrincipal') {
    const accountId = splitArnParts(principalArn).accountId
    if (!accountId) {
      throw new Error(`Virtual principal ${principalArn} must contain an account ID.`)
    }
    const [serviceControlPolicies, principalAccountRcps] = await Promise.all([
      collectClient.getScpHierarchyForAccount(accountId),
      collectClient.getRcpHierarchyForAccount(accountId)
    ])
    return {
      identityPolicies: [
        request.inlinePolicy
          ? { name: 'iam-lens:virtual-inline-policy', policy: request.inlinePolicy }
          : syntheticIdentityPolicy
      ],
      serviceControlPolicies,
      permissionBoundaryPolicies: undefined,
      principalAccountRcps
    }
  }

  if (isRootArn(principalArn)) {
    const accountId = splitArnParts(principalArn).accountId!
    const [serviceControlPolicies, principalAccountRcps] = await Promise.all([
      collectClient.getScpHierarchyForAccount(accountId),
      collectClient.getRcpHierarchyForAccount(accountId)
    ])
    return {
      identityPolicies: [syntheticIdentityPolicy],
      serviceControlPolicies,
      permissionBoundaryPolicies: undefined,
      principalAccountRcps
    }
  }

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

  if (variant === 'virtualResource') {
    return {
      resourcePolicy: externalResourcePolicy(request),
      resourceControlPolicies: await getResourceControlPolicies(
        collectClient,
        request.action,
        request.resourceArn,
        request.resourceAccount,
        request.principal,
        actionIsWildcard,
        principalAccountRcps
      )
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

  if (variant === 'externalResource' || variant === 'virtualResource') {
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
 * Assemble the names of Discovery context keys whose presence is generated by iam-lens.
 *
 * @param request the normalized request
 * @param contextKeys generated and caller-provided context values
 * @param resourceTagsAreKnown whether all resource tags are known
 * @param s3BucketOrObjectRequest whether S3 bucket tag keys apply
 * @param principalTagsAreUnknown whether synthetic principal tag presence and values are unknown
 * @param sessionTagCapability trust-policy-derived role session-tag capability, when applicable
 * @param mutablePrincipalTagKeys stored PrincipalTag keys whose values are not authoritative
 * @returns generated literal context-key names and key patterns
 */
function makeGeneratedDiscoveryContextKeyNames(
  request: InternalSimulationRequest,
  contextKeys: ContextKeys,
  resourceTagsAreKnown: boolean,
  s3BucketOrObjectRequest: boolean,
  principalTagsAreUnknown: boolean,
  sessionTagCapability: RoleSessionTagCapability | undefined,
  mutablePrincipalTagKeys: ReadonlySet<string>
): string[] {
  const generatedContextKeyNames = [...knownContextKeys]

  if (!request.principal) {
    generatedContextKeyNames.push(
      CONTEXT_KEYS.userId,
      CONTEXT_KEYS.assumedRoot,
      '/^aws:PrincipalTag\/.*/',
      ...anonymousKnownAbsentContextKeyNames
    )
  } else {
    if (!isIamRoleArn(request.principal)) {
      generatedContextKeyNames.push(CONTEXT_KEYS.userId)
    }
    if (!request.principal.endsWith(':root')) {
      generatedContextKeyNames.push(CONTEXT_KEYS.assumedRoot)
    }
  }
  if (!principalTagsAreUnknown && request.principal && isIamUserArn(request.principal)) {
    generatedContextKeyNames.push('/^aws:PrincipalTag\/.*/')
  }
  if (sessionTagCapability) {
    const immutableTagPattern = immutablePrincipalTagPattern(sessionTagCapability)
    if (immutableTagPattern) {
      generatedContextKeyNames.push(immutableTagPattern)
    }
  }
  if (request.action.startsWith('s3:')) {
    generatedContextKeyNames.push('s3:DataAccessPointAccount', 's3:DataAccessPointArn')
  }
  generatedContextKeyNames.push(...Object.keys(request.customContextKeys))

  if (resourceTagsAreKnown) {
    generatedContextKeyNames.push(
      RESOURCE_TAG_KEY_PATTERNS.resourceTag,
      RESOURCE_TAG_KEY_PATTERNS.serviceResourceTag
    )
    if (s3BucketOrObjectRequest) {
      generatedContextKeyNames.push(RESOURCE_TAG_KEY_PATTERNS.bucketTag)
    }
  }

  // There also may be other tag context keys, so add those too. Mutable role tags must not
  // receive a generated fully-known constraint because iam-simulate merges constraints with
  // true-winning semantics.
  for (const key of Object.keys(contextKeys)) {
    if (
      isTagContextKey(key) &&
      !(principalTagsAreUnknown && isPrincipalTagContextKey(key)) &&
      !mutablePrincipalTagKeys.has(key)
    ) {
      generatedContextKeyNames.push(key)
    }
  }

  return generatedContextKeyNames
}

/**
 * Checks whether a context key's first slash-delimited namespace ends in `Tag`.
 *
 * @param key context-key name to inspect
 * @returns true for tag context keys such as `aws:PrincipalTag/Department`
 */
function isTagContextKey(key: string): boolean {
  const slashIndex = key.indexOf('/')
  return (
    slashIndex >= 3 &&
    key
      .slice(slashIndex - 3, slashIndex + 1)
      .localeCompare('tag/', undefined, { sensitivity: 'base' }) === 0
  )
}

const awsSourceKeyPrefix = 'aws:source'
const awsPrincipalTagPrefix = 'aws:principaltag/'

/**
 * Checks whether a context key is in the PrincipalTag namespace.
 *
 * @param key context-key name to inspect
 * @returns true when the key starts with `aws:PrincipalTag/`, ignoring case
 */
function isPrincipalTagContextKey(key: string): boolean {
  return (
    key
      .slice(0, awsPrincipalTagPrefix.length)
      .localeCompare(awsPrincipalTagPrefix, undefined, { sensitivity: 'base' }) === 0
  )
}

const anonymousAbsentContextKeys = new Set([
  'aws:principalarn',
  'aws:principalaccount',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:username',
  'aws:principalisawsservice',
  'aws:principalservicename',
  'aws:sourceaccount',
  'aws:sourceorgid',
  'aws:sourceorgpaths',
  'aws:sourceowner',
  'aws:sourcearn',
  'aws:assumedroot',
  'kms:calleraccount',
  ...anonymousKnownAbsentContextKeyNames.map((key) => key.toLowerCase()),
  '/^aws:principaltag\/.*/'
])

/**
 * Derives role session-tag capability independently from tags stored on the role.
 *
 * This lookup applies only to Discovery simulations for IAM roles and assumed-role sessions. IAM
 * user tags are handled separately as fully strict because users cannot receive role-session tags.
 *
 * @param collectClient the collect client used to load the canonical role trust policy
 * @param simulationRequest the request whose principal-tag certainty is being modeled
 * @param resolvedPrincipalArnForContext the canonical role ARN resolved for an assumed-role session
 * @param principalIsCollected whether absent principal metadata is authoritative
 * @returns the role's session-tag capability, or undefined when role metadata is not applicable
 */
async function sessionTagCapabilityForRequest(
  collectClient: IamCollectClient,
  simulationRequest: InternalSimulationRequest,
  resolvedPrincipalArnForContext: string | undefined,
  principalIsCollected: boolean
): Promise<RoleSessionTagCapability | undefined> {
  if (simulationRequest.simulationMode !== 'Discovery' || !principalIsCollected) {
    return undefined
  }

  const requestPrincipal = simulationRequest.principal
  const roleArn =
    requestPrincipal && isIamRoleArn(requestPrincipal)
      ? requestPrincipal
      : resolvedPrincipalArnForContext
  if (!roleArn || !isIamRoleArn(roleArn)) {
    return undefined
  }

  const accountId = splitArnParts(roleArn).accountId
  if (!accountId) {
    return undefined
  }

  const trustPolicy = await collectClient.getResourcePolicyForArn(roleArn, accountId)
  return roleSessionTagCapability(trustPolicy)
}

/**
 * Finds stored role-tag values that a session may override.
 *
 * Stored tags determine baseline presence, while the independent trust-policy capability determines
 * mutability. A mutable stored tag is always present, but its effective session value is unknown.
 *
 * @param capability the role's session-tag capability, or undefined for non-role requests
 * @param contextKeys generated and caller-provided request context
 * @param customContextKeys authoritative caller-provided context values
 * @returns existing non-custom PrincipalTag context-key names whose values are mutable
 */
function mutableStoredPrincipalTagKeys(
  capability: RoleSessionTagCapability | undefined,
  contextKeys: ContextKeys,
  customContextKeys: ContextKeys
): Set<string> {
  if (!capability || capability.type === 'none') {
    return new Set()
  }

  const storedPrincipalTagKeys = Object.keys(contextKeys).filter(
    (key) => isPrincipalTagContextKey(key) && !hasCustomContextKey(customContextKeys, key)
  )
  if (capability.type === 'any') {
    return new Set(storedPrincipalTagKeys)
  }

  return new Set(
    storedPrincipalTagKeys.filter((key) => {
      const tagKey = key.slice(awsPrincipalTagPrefix.length)
      return roleSessionCanSetTagKey(capability, tagKey)
    })
  )
}

/**
 * Merge iam-lens-generated and caller-provided Discovery constraints.
 *
 * Caller constraints replace generated constraints with the same key-name
 * string, compared case-insensitively. Regex patterns are compared as strings;
 * regex-overlap precedence can be added later without changing the public
 * request contract.
 *
 * @param generatedConstraints constraints derived from iam-lens request context
 * @param callerConstraints constraints supplied by the simulation caller
 * @returns caller constraints followed by generated constraints not overridden by callers
 * @internal
 */
export function mergeDiscoveryContextKeyConstraints(
  generatedConstraints: DiscoveryContextKeyConstraint[],
  callerConstraints: DiscoveryContextKeyConstraint[]
): DiscoveryContextKeyConstraint[] {
  return [
    ...callerConstraints,
    ...generatedConstraints.filter((generatedConstraint) => {
      return !callerConstraints.some((callerConstraint) => {
        return constraintKeyNamesMatch(callerConstraint.keyName, generatedConstraint.keyName)
      })
    })
  ]
}

/**
 * Determine whether caller and generated constraint key names match.
 *
 * The comparison is intentionally lexical: literal names and slash-delimited
 * regex patterns are both compared as strings with case-insensitive matching.
 *
 * @param callerKeyName caller-provided literal key name or slash-delimited regex pattern
 * @param generatedKeyName iam-lens-generated literal key name or slash-delimited regex pattern
 * @returns whether the caller constraint overrides the generated constraint
 */
function constraintKeyNamesMatch(callerKeyName: string, generatedKeyName: string): boolean {
  return callerKeyName.localeCompare(generatedKeyName, undefined, { sensitivity: 'base' }) === 0
}

/**
 * Convert an iam-lens-generated context key into an iam-simulate Discovery constraint.
 *
 * Caller-provided context values remain fully authoritative. A stored PrincipalTag whose role
 * session may override it has known presence but an unknown value. All other generated keys remain
 * fully known except for the documented service-source exceptions.
 *
 * @param keyName the literal context key or slash-delimited key pattern
 * @param simulationRequest the normalized request whose context certainty is modeled
 * @param mutablePrincipalTagKeys stored PrincipalTag keys whose values are non-authoritative
 * @returns the Discovery constraint to pass to iam-simulate
 * @internal
 */
export function discoveryConstraintForGeneratedKey(
  keyName: string,
  simulationRequest: Pick<
    InternalSimulationRequest,
    'customContextKeys' | 'simulationMode' | 'principal'
  >,
  mutablePrincipalTagKeys?: ReadonlySet<string>
): DiscoveryContextKeyConstraint {
  if (hasCustomContextKey(simulationRequest.customContextKeys, keyName)) {
    return { keyName, presenceIsKnown: true, valueIsKnown: true }
  }

  if (mutablePrincipalTagKeys?.has(keyName)) {
    return { keyName, presenceIsKnown: true, valueIsKnown: false }
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

  const resourceControlPolicies = await getResourceControlPolicies(
    collectClient,
    action,
    resourceArn,
    resourceAccount,
    principalArn,
    actionIsWildcard,
    principalAccountRcps
  )

  if (AssumeRoleActions.has(action.toLowerCase()) && !resourcePolicy) {
    throw new Error(
      `Trust policy not found for resource ${resourceArn}. sts assume role actions require a trust policy.`
    )
  }

  const useResourcePolicy =
    resourceArn !== undefined && !(isIamRoleArn(resourceArn) && service.toLowerCase() === 'iam')

  return {
    resourcePolicy: useResourcePolicy ? resourcePolicy : undefined,
    resourceControlPolicies
  }
}

/**
 * Retrieve the RCP hierarchies applicable to a request from the resource account's organization
 * placement, or from the principal account for a wildcard-only action.
 *
 * This applies the non-variant RCP rules for wildcard-only actions, service-linked roles,
 * `kms:RetireGrant`, AWS-managed KMS keys, and the implicit full-access RCP. An account outside the
 * collected organization data has no RCPs.
 *
 * @param collectClient the data client
 * @param action the action being simulated
 * @param resourceArn the resource ARN
 * @param resourceAccount the resource account
 * @param principalArn the authenticated principal ARN, when present
 * @param actionIsWildcard whether the action uses the account-wide wildcard resource
 * @param principalAccountRcps RCP hierarchy for the principal account
 * @returns the filtered RCP hierarchies applicable to the request
 */
async function getResourceControlPolicies(
  collectClient: IamCollectClient,
  action: string,
  resourceArn: string | undefined,
  resourceAccount: string | undefined,
  principalArn: string | undefined,
  actionIsWildcard: boolean,
  principalAccountRcps: SimulationOrgPolicies[]
): Promise<SimulationOrgPolicies[]> {
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

  return applicableRcps.map((rcp) => ({
    orgIdentifier: rcp.orgIdentifier,
    policies: rcp.policies.filter(
      (policy) => !policy.name.toLowerCase().endsWith('rcpfullawsaccess')
    )
  }))
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
