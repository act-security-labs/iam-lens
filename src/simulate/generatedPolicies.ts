import {
  createValidatedPolicy,
  validateResourcePolicy,
  validateTrustPolicy,
  type ValidatedPolicy
} from '@actsecurity/iam-policy'
import { AssumeRoleActions } from '../utils/sts.js'
import type { InternalSimulationRequest, PrincipalPolicyInputs } from './simulate.js'

export const syntheticResourcePolicyName = 'iam-lens:synthetic-resource-allow-all'
export const syntheticTrustPolicyName = 'iam-lens:synthetic-trust-allow-all'

export const syntheticIdentityPolicy: PrincipalPolicyInputs['identityPolicies'][number] = {
  name: 'iam-lens:synthetic-identity-allow-all',
  policy: {
    Version: '2012-10-17',
    Statement: {
      Effect: 'Allow',
      Action: '*',
      Resource: '*'
    }
  }
} as const

export const syntheticTrustPolicy = {
  Version: '2012-10-17',
  Statement: {
    Effect: 'Allow',
    Principal: '*',
    Action: '*'
  }
} as const

/**
 * Build and validate the caller-supplied or synthetic external resource policy.
 *
 * @param request the external-resource request
 * @returns a validated resource or trust policy
 */
export function externalResourcePolicy(
  request: InternalSimulationRequest
): ValidatedPolicy<{ name: string }> {
  const useTrustPolicy = AssumeRoleActions.has(request.action.toLowerCase())
  const policyDocument =
    request.resourcePolicy ??
    (useTrustPolicy
      ? syntheticTrustPolicy
      : makeSyntheticResourcePolicy(request.resourceArn || '*'))
  const name = useTrustPolicy ? syntheticTrustPolicyName : syntheticResourcePolicyName
  return createValidatedPolicy(
    policyDocument,
    useTrustPolicy ? validateTrustPolicy : validateResourcePolicy,
    { name }
  )
}

/**
 * Build the default resource policy for an external resource.
 *
 * @param resourceArn the concrete or wildcard resource to allow
 * @returns an allow-all resource policy document
 */
function makeSyntheticResourcePolicy(resourceArn: string): Record<string, unknown> {
  return {
    Version: '2012-10-17',
    Statement: {
      Effect: 'Allow',
      Principal: '*',
      Action: '*',
      Resource: resourceArn
    }
  }
}
