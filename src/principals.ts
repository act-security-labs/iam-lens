import {
  convertAssumedRoleArnToRoleArn,
  isAssumedRoleArn,
  isIamRoleArn,
  isIamUserArn,
  splitArnParts
} from '@actsecurity/iam-utils'
import {
  IamCollectClient,
  type InlinePolicy,
  type ManagedPolicy,
  type SimulationOrgPolicies
} from './collect/client.js'

export interface PrincipalPolicies {
  managedPolicies: ManagedPolicy[]
  inlinePolicies: InlinePolicy[]
  permissionBoundary: ManagedPolicy | undefined
  scps: SimulationOrgPolicies[]
  rcps: SimulationOrgPolicies[]
  groupPolicies?: {
    group: string
    managedPolicies: ManagedPolicy[]
    inlinePolicies: InlinePolicy[]
  }[]
}

/**
 * Get all the IAM policies for a user, including managed and inline policies, permission boundaries, and group policies.
 *
 * @param collectClient the IAM collect client to use for retrieving policies
 * @param principalArn the ARN of the user to get policies for
 * @returns an object containing the managed policies, inline policies, permission boundary, and group policies
 */
export async function getAllPoliciesForUser(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<PrincipalPolicies> {
  const accountId = splitArnParts(principalArn).accountId!

  const managedPolicies = await collectClient.getManagedPoliciesForUser(principalArn)
  const inlinePolicies = await collectClient.getInlinePoliciesForUser(principalArn)
  const permissionBoundary = await collectClient.getPermissionsBoundaryForUser(principalArn)
  const groups = await collectClient.getGroupsForUser(principalArn)
  const scps = await collectClient.getScpHierarchyForAccount(accountId)
  const rcps = await collectClient.getRcpHierarchyForAccount(accountId)
  const groupPolicies = []
  for (const group of groups) {
    const groupManagedPolicies = await collectClient.getManagedPoliciesForGroup(group)
    const groupInlinePolicies = await collectClient.getInlinePoliciesForGroup(group)
    groupPolicies.push({
      group,
      managedPolicies: groupManagedPolicies,
      inlinePolicies: groupInlinePolicies
    })
  }
  return {
    scps,
    rcps,
    managedPolicies,
    inlinePolicies,
    permissionBoundary,
    groupPolicies
  }
}

/**
 * Get all the IAM policies for a role, including managed and inline policies and permission boundaries.
 *
 * @param collectClient the IAM collect client to use for retrieving policies
 * @param principalArn the ARN of the role to get policies for
 * @returns an object containing the managed policies, inline policies, and permission boundary
 */
export async function getAllPoliciesForRole(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<PrincipalPolicies> {
  const accountId = splitArnParts(principalArn).accountId!

  const managedPolicies = await collectClient.getManagedPoliciesForRole(principalArn)
  const inlinePolicies = await collectClient.getInlinePoliciesForRole(principalArn)
  const permissionBoundary = await collectClient.getPermissionsBoundaryForRole(principalArn)
  const scps = await collectClient.getScpHierarchyForAccount(accountId)
  const rcps = await collectClient.getRcpHierarchyForAccount(accountId)

  return {
    scps,
    rcps,
    managedPolicies,
    inlinePolicies,
    permissionBoundary
  }
}

/**
 * Get all IAM policies for a supported principal.
 *
 * IAM role and assumed-role principals are resolved to their canonical stored ARN before
 * loading policies so pathless STS session principals can use path-qualified IAM role data.
 * SCPs are omitted for service-linked roles because they are not subject to SCP enforcement.
 *
 * @param collectClient the IAM collect client to use for retrieving policies
 * @param principalArn the ARN or service principal to get policies for
 * @returns all policies that apply directly to the principal
 */
export async function getAllPoliciesForPrincipal(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<PrincipalPolicies> {
  if (
    isServicePrincipal(principalArn) ||
    isSamlPrincipal(principalArn) ||
    isOidcPrincipal(principalArn)
  ) {
    return {
      scps: [],
      rcps: [],
      managedPolicies: [],
      inlinePolicies: [],
      permissionBoundary: undefined,
      groupPolicies: []
    }
  }

  if (isIamUserArn(principalArn)) {
    return getAllPoliciesForUser(collectClient, principalArn)
  } else if (isIamRoleArn(principalArn)) {
    const roleArn = (await collectClient.resolvePrincipalArn(principalArn)) ?? principalArn
    const policies = await getAllPoliciesForRole(collectClient, roleArn)
    return isServiceLinkedRole(roleArn) ? { ...policies, scps: [] } : policies
  } else if (isAssumedRoleArn(principalArn)) {
    const roleArn =
      (await collectClient.resolvePrincipalArn(principalArn)) ??
      convertAssumedRoleArnToRoleArn(principalArn)
    const policies = await getAllPoliciesForRole(collectClient, roleArn)
    return isServiceLinkedRole(roleArn) ? { ...policies, scps: [] } : policies
  }
  throw new Error(`Unsupported principal type: ${principalArn}`)
}

export function isArnPrincipal(principal: string): boolean {
  return principal.startsWith('arn:')
}

export function isServicePrincipal(principal: string): boolean {
  return !isArnPrincipal(principal) && principal.endsWith('amazonaws.com')
}

export function isServiceLinkedRole(principal: string): boolean {
  const arnParts = splitArnParts(principal)
  return isArnPrincipal(principal) && !!arnParts.resourcePath?.startsWith('aws-service-role/')
}

export function isOidcPrincipal(principal: string): boolean {
  if (!isArnPrincipal(principal)) {
    return false
  }
  const parts = splitArnParts(principal)
  return parts.service === 'iam' && parts.resourceType === 'oidc-provider'
}

export function isSamlPrincipal(principal: string): boolean {
  if (!isArnPrincipal(principal)) {
    return false
  }
  const parts = splitArnParts(principal)
  return parts.service === 'iam' && parts.resourceType === 'saml-provider'
}

/**
 * Check to see if a principal exists or is an AWS service principal.
 *
 * @param principal the principal to check
 * @param collectClient the IAM collect client to use for checking existence
 * @returns true if the principal exists or is a service principal, false otherwise
 */
export async function principalExists(
  principal: string,
  collectClient: IamCollectClient
): Promise<boolean> {
  if (isServicePrincipal(principal)) {
    return true
  }

  return collectClient.principalExists(principal)
}
