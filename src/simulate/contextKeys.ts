import {
  actionSupportsAwsResourceInfoContextKeys,
  bucketArn,
  convertAssumedRoleArnToRoleArn,
  isS3BucketOrObjectArn,
  splitArnParts
} from '@actsecurity/iam-utils'
import { IamCollectClient } from '../collect/client.js'
import { isArnPrincipal, isServicePrincipal } from '../principals.js'
import { type SimulationRequest } from './simulate.js'

/**
 * Context keys for IAM simulation requests.
 *
 * These keys are used to provide additional context for the simulation, such as
 * the principal making the request, the resource being accessed, and any additional
 * context keys that may be required for the simulation.
 */
export type ContextKeys = Record<string, string | string[]>

/**
 * Placeholder for the caller account AWS supplies on a service-mediated KMS request.
 *
 * iam-lens does not know the actual account, so Discovery treats this value as non-authoritative.
 */
export const servicePrincipalKmsCallerAccountPlaceholder = '111111111111'

export const knownContextKeys: readonly string[] = [
  'aws:SecureTransport',
  'aws:CurrentTime',
  'aws:EpochTime',

  'aws:PrincipalArn',
  'aws:PrincipalAccount',
  'aws:PrincipalOrgId',
  'aws:PrincipalOrgPaths',
  'aws:PrincipalType',
  'aws:username',

  'aws:ResourceAccount',
  'aws:ResourceOrgID',
  'aws:ResourceOrgPaths',

  'aws:PrincipalIsAWSService',
  'aws:PrincipalServiceName',
  'aws:SourceAccount',
  'aws:SourceOrgID',
  'aws:SourceOrgPaths',
  'aws:SourceOwner',
  'aws:SourceArn',

  'kms:CallerAccount'
]

export const CONTEXT_KEYS = {
  assumedRoot: 'aws:AssumedRoot',
  userId: 'aws:userid',
  vpc: 'aws:SourceVpc',
  vpcEndpointId: 'aws:SourceVpce',
  vpcEndpointAccount: 'aws:VpceAccount',
  vpcEndpointOrgId: 'aws:VpceOrgID',
  vpcEndpointOrgPaths: 'aws:VpceOrgPaths',
  vpcArn: 'aws:SourceVpcArn'
}

/**
 * Checks if a context has a specific key (case-insensitive).
 *
 * @param context - The context to check.
 * @param key - The key to check for.
 * @returns True if the context has the key, false otherwise.
 */
export function contextHasKey(context: ContextKeys, key: string): boolean {
  return !!contextValue(context, key)
}

/**
 * Get the value of a context key (case-insensitive).
 *
 * @param context - The context to check.
 * @param key - The key to get the value for.
 * @returns The value of the context key, or undefined if it doesn't exist.
 */
export function contextValue(context: ContextKeys, key: string): string | string[] | undefined {
  const matchingKey = Object.keys(context).find(
    (contextKey) => contextKey.toLowerCase() === key.toLowerCase()
  )
  return matchingKey ? context[matchingKey] : undefined
}

/**
 * Get the context keys for a simulation request.
 *
 * @param collectClient the collect client to use for fetching data
 * @param simulationRequest the simulation request to create context keys for
 * @param service the service the request is for
 * @param contextKeyOverrides the context key overrides to apply
 * @param resolvedPrincipalArnForContext canonical principal ARN to use for role-backed context keys
 * @returns a promise that resolves to the context keys for the simulation request
 */
export async function createContextKeys(
  collectClient: IamCollectClient,
  simulationRequest: SimulationRequest,
  service: string,
  contextKeyOverrides: ContextKeys,
  resolvedPrincipalArnForContext?: string
): Promise<{ resourceTagsAreKnown: boolean; contextKeys: ContextKeys }> {
  const contextKeys: ContextKeys = {
    'aws:SecureTransport': 'true',
    'aws:CurrentTime': new Date().toISOString(),
    'aws:EpochTime': Math.floor(Date.now() / 1000).toString()
  }

  if (isArnPrincipal(simulationRequest.principal)) {
    const arnParts = splitArnParts(simulationRequest.principal)
    const principalArnForContext =
      resolvedPrincipalArnForContext ??
      (arnParts.resourceType === 'assumed-role'
        ? convertAssumedRoleArnToRoleArn(simulationRequest.principal)
        : simulationRequest.principal)
    contextKeys['aws:PrincipalArn'] = principalArnForContext
    const principalAccountId = arnParts.accountId!
    contextKeys['aws:PrincipalAccount'] = arnParts.accountId || ''

    const orgId = await collectClient.getOrgIdForAccount(principalAccountId)
    if (orgId) {
      contextKeys['aws:PrincipalOrgId'] = orgId

      const orgStructure = await collectClient.getOrgUnitHierarchyForAccount(principalAccountId)
      contextKeys['aws:PrincipalOrgPaths'] = makeOrgPaths(orgId, orgStructure)
    }

    const { tags } = await collectClient.getTagsForResource(
      principalArnForContext,
      principalAccountId
    )

    for (const [key, value] of Object.entries(tags)) {
      contextKeys[`aws:PrincipalTag/${key}`] = value
    }

    contextKeys['aws:PrincipalIsAWSService'] = 'false'

    if (service.toLowerCase() === 'kms') {
      contextKeys['kms:CallerAccount'] = principalAccountId
    }

    if (simulationRequest.principal.endsWith(':root')) {
      contextKeys['aws:PrincipalType'] = 'Account'
      contextKeys['aws:userid'] = principalAccountId
    } else if (arnParts.resourceType === 'user') {
      contextKeys['aws:PrincipalType'] = 'User'
      const userUniqueId = await collectClient.getUniqueIdForIamResource(
        simulationRequest.principal
      )
      contextKeys['aws:userid'] = userUniqueId || 'UNKNOWN'
      const userName = arnParts.resourcePath?.split('/').at(-1)!
      contextKeys['aws:username'] = userName
    } else if (arnParts.resourceType === 'federated-user') {
      contextKeys['aws:PrincipalType'] = 'FederatedUser'
      contextKeys['aws:userid'] = `${arnParts.accountId}:${arnParts.resourcePath}`
    } else if (arnParts.resourceType === 'assumed-role' || arnParts.resourceType === 'role') {
      contextKeys['aws:PrincipalType'] = 'AssumedRole'

      //TODO: Set aws:userId for role principals
      if (arnParts.resourceType === 'assumed-role') {
        const sessionName = arnParts.resourcePath?.split('/').at(-1)!
        const roleArn = convertAssumedRoleArnToRoleArn(simulationRequest.principal)
        const roleUniqueId = await collectClient.getUniqueIdForIamResource(roleArn)
        contextKeys['aws:userid'] = `${roleUniqueId || 'UNKNOWN'}:${sessionName}`
      }
    }
  }

  //Resource context keys
  if (actionSupportsAwsResourceInfoContextKeys(simulationRequest.action)) {
    contextKeys['aws:ResourceAccount'] = simulationRequest.resourceAccount!

    const resourceOrgId = await collectClient.getOrgIdForAccount(simulationRequest.resourceAccount!)
    if (resourceOrgId) {
      contextKeys['aws:ResourceOrgID'] = resourceOrgId

      const orgStructure = await collectClient.getOrgUnitHierarchyForAccount(
        simulationRequest.resourceAccount!
      )

      contextKeys['aws:ResourceOrgPaths'] = makeOrgPaths(resourceOrgId, orgStructure)
    }
  }

  let resourceTagsAreKnown = false
  if (simulationRequest.resourceArn) {
    const isBucket = isS3BucketOrObjectArn(simulationRequest.resourceArn)
    const { tags: resourceTags, present: resourceTagsPreset } =
      await collectClient.getTagsForResource(
        isBucket ? bucketArn(simulationRequest.resourceArn) : simulationRequest.resourceArn,
        simulationRequest.resourceAccount!
      )
    resourceTagsAreKnown = resourceTagsPreset
    for (const [key, value] of Object.entries(resourceTags)) {
      contextKeys[`aws:ResourceTag/${key}`] = value
      if (isBucket) {
        contextKeys[`s3:BucketTag/${key}`] = value
      }
    }
  }

  //Service Principal context keys
  if (isServicePrincipal(simulationRequest.principal)) {
    contextKeys['aws:PrincipalIsAWSService'] = 'true'
    contextKeys['aws:PrincipalServiceName'] = simulationRequest.principal
    contextKeys['aws:SourceAccount'] = simulationRequest.resourceAccount!
    contextKeys['aws:SourceOwner'] = simulationRequest.resourceAccount!
    contextKeys['aws:SourceOrgID'] = contextKeys['aws:ResourceOrgID']
    contextKeys['aws:SourceOrgPaths'] = contextKeys['aws:ResourceOrgPaths']

    if (service.toLowerCase() === 'kms') {
      contextKeys['kms:CallerAccount'] = servicePrincipalKmsCallerAccountPlaceholder
    }

    if (simulationRequest.simulationMode === 'Discovery') {
      // Source key Discovery constraints make the concrete value non-authoritative;
      // this placeholder only marks the key as present for service-originated requests.
      contextKeys['aws:SourceArn'] = 'arn:aws:iam::000000000000:role/unknown-source'
    }
  }

  //Apply any custom context key overrides
  for (const [key, value] of Object.entries(contextKeyOverrides)) {
    contextKeys[key] = value
  }

  //Add VPC context keys
  const vpcKeys = await getVpcKeys(contextKeys, service, collectClient)
  for (const [key, value] of Object.entries(vpcKeys)) {
    contextKeys[key] = value
  }

  return {
    resourceTagsAreKnown,
    contextKeys
  }
}

/**
 * Get the VPC keys that should be added to the context for a simulation.
 *
 * @param context the existing context
 * @param service the service the request is for
 * @param collectClient the IAM collect client
 * @returns a record of VPC context keys
 */
export async function getVpcKeys(
  context: ContextKeys,
  service: string,
  collectClient: IamCollectClient
): Promise<ContextKeys> {
  const vpcKeys: ContextKeys = {}

  let vpcEndpointId = contextValue(context, CONTEXT_KEYS.vpcEndpointId)
  const hasVpcEndpoint = !!vpcEndpointId
  let vpcId = contextValue(context, CONTEXT_KEYS.vpc)
  let vpcArn = contextValue(context, CONTEXT_KEYS.vpcArn)

  //If we know the VPC ID but not the endpoint, lookup the endpoint
  if (!vpcEndpointId && vpcId && typeof vpcId === 'string') {
    vpcEndpointId = await collectClient.getVpcEndpointIdForVpcService(vpcId, service)
  }

  //If we know the VPC ARN but not the endpoint, lookup the endpoint
  if (!vpcEndpointId && vpcArn && typeof vpcArn === 'string') {
    vpcEndpointId = await collectClient.getVpcEndpointIdForVpcService(vpcArn, service)
  }

  if (vpcEndpointId && !vpcId) {
    if (typeof vpcEndpointId == 'string') {
      const vpcId = await collectClient.getVpcIdForVpcEndpointId(vpcEndpointId)
      if (vpcId) {
        vpcKeys[CONTEXT_KEYS.vpc] = vpcId
      }
    }
  }

  if (vpcEndpointId && !hasVpcEndpoint) {
    vpcKeys[CONTEXT_KEYS.vpcEndpointId] = vpcEndpointId
  }

  if (
    vpcEndpointId &&
    typeof vpcEndpointId === 'string' &&
    serviceSupportsExtraVpcEndpointData(service)
  ) {
    const vpcEndpointAccount = await collectClient.getAccountIdForVpcEndpointId(vpcEndpointId)
    const vpcEndpointOrgId = await collectClient.getOrgIdForVpcEndpointId(vpcEndpointId)
    const vpcEndpointOrgStructure =
      await collectClient.getOrgUnitHierarchyForVpcEndpointId(vpcEndpointId)
    const vpcArn = await collectClient.getVpcArnForVpcEndpointId(vpcEndpointId)

    if (vpcEndpointAccount && !contextHasKey(context, CONTEXT_KEYS.vpcEndpointAccount)) {
      vpcKeys[CONTEXT_KEYS.vpcEndpointAccount] = vpcEndpointAccount
    }
    if (vpcEndpointOrgId && !contextHasKey(context, CONTEXT_KEYS.vpcEndpointOrgId)) {
      vpcKeys[CONTEXT_KEYS.vpcEndpointOrgId] = vpcEndpointOrgId
    }
    if (vpcArn && !contextHasKey(context, CONTEXT_KEYS.vpcArn)) {
      vpcKeys[CONTEXT_KEYS.vpcArn] = vpcArn
    }
    if (
      vpcEndpointOrgId &&
      vpcEndpointOrgStructure &&
      !contextHasKey(context, CONTEXT_KEYS.vpcEndpointOrgPaths)
    ) {
      vpcKeys[CONTEXT_KEYS.vpcEndpointOrgPaths] = makeOrgPaths(
        vpcEndpointOrgId,
        vpcEndpointOrgStructure
      )
    }
  }

  return vpcKeys
}

const servicesThatSupportExtraVpcEndpointData = new Set([
  'apprunner',
  'discovery',
  'athena',
  'servicediscovery',
  'applicationinsights',
  'cloudformation',
  'comprehendmedical',
  'compute-optimizer',
  'ecr',
  'ecs',
  'kinesisanalytics',
  'route53',
  'datasync',
  'ebs',
  'scheduler',
  'firehose',
  'medical-imaging',
  'healthlake',
  'omics',
  'iam',
  'iotfleetwise',
  'iotwireless',
  'kms',
  'lambda',
  'payment-cryptography',
  'polly',
  'acm-pca',
  'rbin',
  'rekognition',
  'servicequotas',
  's3',
  'storagegateway',
  'ssm-contacts',
  'textract',
  'transcribe',
  'transfer'
])

/**
 * Check if a service supports extra VPC endpoint data.
 *
 * @param service the service to check
 * @returns true if the service supports extra VPC endpoint data, false otherwise
 */
export function serviceSupportsExtraVpcEndpointData(service: string): boolean {
  return servicesThatSupportExtraVpcEndpointData.has(service.toLowerCase())
}

/**
 * Create a string array for an aws:xxOrgPaths context key value.
 *
 * @param orgId the organization ID
 * @param hierarchy the organizational hierarchy
 * @returns a string array representing the organizational paths
 */
function makeOrgPaths(orgId: string, hierarchy: string[]): string[] {
  return [`${orgId}/${hierarchy.join('/')}/`]
}
