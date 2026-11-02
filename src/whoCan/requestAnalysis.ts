import {
  getDenialReasons,
  type BlockedReason,
  type EvaluationResult,
  type RequestAnalysis
} from '@actsecurity/iam-simulate'
import type { WhoCanExecutionResultWithAnalysis } from './WhoCanWorker.js'
import type { WhoCanDenyDetail } from './whoCan.js'

/**
 * A lightweight representation of RequestAnalysis containing only the result fields
 * of the various policy analyses (identity, resource, SCP, RCP, permission boundary).
 */
export interface LightResourceAnalysis {
  result: RequestAnalysis['result']
  sameAccount?: boolean
  identityAnalysis?: Pick<NonNullable<RequestAnalysis['identityAnalysis']>, 'result'>
  resourceAnalysis?: Pick<NonNullable<RequestAnalysis['resourceAnalysis']>, 'result'>
  scpAnalysis?: Pick<NonNullable<RequestAnalysis['scpAnalysis']>, 'result'>
  rcpAnalysis?: Pick<NonNullable<RequestAnalysis['rcpAnalysis']>, 'result'>
  permissionBoundaryAnalysis?: Pick<
    NonNullable<RequestAnalysis['permissionBoundaryAnalysis']>,
    'result'
  >
  blockedBy: Set<BlockedReason>
}

/**
 * A LightResourceAnalysis extended with resource pattern and type information.
 * Used for wildcard resource analyses to provide details on each matched pattern.
 */
export interface LightResourceAnalysisWithPattern extends LightResourceAnalysis {
  /**
   * The specific resource pattern that was analyzed, most likely found in a policy statement's Resource field. This is used to provide more granular details in wildcard resource analyses, where multiple patterns may match the requested resource.
   */
  pattern: string
  /**
   * The resource type that was tested.
   */
  resourceType: string
}

/**
 * A light request analysis for a single resource.
 */
export interface SingleResourceLightRequestAnalysis extends LightResourceAnalysis {
  type: 'single'
  overallResult: EvaluationResult
}

/**
 * A light request analysis for a wildcard resource with multiple patterns.
 * Used for wildcard resource analyses to provide details on each matched pattern.
 */
export interface WildcardResourceLightRequestAnalysis {
  type: 'wildcard'

  /** The requested resource pattern, when specified by the caller. */
  requestedResourcePattern?: string

  /**
   * The overall result of the wildcard resource analysis, which is typically a combination of the results of the individual pattern analyses. This provides a high-level summary of whether the requested action is allowed or denied across all matched patterns, while the individual pattern analyses provide more granular details.
   */
  overallResult: EvaluationResult

  /**
   * Returns true if the overallResult is 'Allowed' but some of the patterns are any variant of 'Denied'
   */
  mixedResult?: true

  /**
   * The details of the analyses for each matched resource pattern/resource type pair.
   */
  patterns: LightResourceAnalysisWithPattern[]
}

/**
 * A light version of RequestAnalysis containing only the result and sameAccount fields,
 * along with the result fields of the various analyses.
 */
export type LightRequestAnalysis =
  SingleResourceLightRequestAnalysis | WildcardResourceLightRequestAnalysis

/**
 * Convert a RequestAnalysis to a LightResourceAnalysis.
 *
 * @param analysis - The full RequestAnalysis to convert
 * @returns A LightResourceAnalysis with only the essential result fields
 */
function toLightResourceAnalysis(analysis: RequestAnalysis): LightResourceAnalysis {
  return {
    result: analysis.result,
    sameAccount: analysis.sameAccount,
    identityAnalysis: analysis.identityAnalysis
      ? { result: analysis.identityAnalysis.result }
      : undefined,
    resourceAnalysis: analysis.resourceAnalysis
      ? { result: analysis.resourceAnalysis.result }
      : undefined,
    scpAnalysis: analysis.scpAnalysis ? { result: analysis.scpAnalysis.result } : undefined,
    rcpAnalysis: analysis.rcpAnalysis ? { result: analysis.rcpAnalysis.result } : undefined,
    permissionBoundaryAnalysis: analysis.permissionBoundaryAnalysis
      ? { result: analysis.permissionBoundaryAnalysis.result }
      : undefined,
    blockedBy: new Set(analysis.blockedBy)
  }
}

/**
 * Convert a full RequestAnalysis to a LightRequestAnalysis.
 *
 * @param executionResult - The execution result containing the analyses to convert
 * @returns A LightRequestAnalysis with only the essential fields
 */
export function toLightRequestAnalysis(
  executionResult: WhoCanExecutionResultWithAnalysis
): LightRequestAnalysis {
  if (executionResult.type === 'denied_single') {
    return {
      type: 'single',
      overallResult: executionResult.analysis.result,
      ...toLightResourceAnalysis(executionResult.analysis)
    }
  }

  // Wildcard case
  const resourcePatterns =
    executionResult.type === 'allowed_mixed_wildcard'
      ? executionResult.patterns
      : executionResult.deniedPatterns
  const patterns = resourcePatterns.map((details) => ({
    pattern: details.pattern,
    resourceType: details.resourceType,
    ...toLightResourceAnalysis(details.analysis)
  }))

  return {
    type: 'wildcard',
    overallResult:
      executionResult.type === 'allowed_mixed_wildcard' ? 'Allowed' : executionResult.overallResult,
    ...(executionResult.type === 'allowed_mixed_wildcard' && { mixedResult: true as const }),
    ...(executionResult.workItem.resource && {
      requestedResourcePattern: executionResult.workItem.resource
    }),
    patterns
  }
}

/**
 * Gets the denial reasons for a denied SimulationResult.
 *
 * @param executionResult - The execution result containing analyses with denial reasons
 * @returns A WhoCanDenyDetail object containing the denial reasons and other details to be returned to the user
 */
export function convertToDenialDetails(
  executionResult: WhoCanExecutionResultWithAnalysis
): WhoCanDenyDetail {
  const { principal: simulatedPrincipal, resultPrincipal, action } = executionResult.workItem
  const principal =
    executionResult.type === 'allowed_mixed_wildcard'
      ? (resultPrincipal ?? simulatedPrincipal)
      : simulatedPrincipal
  const [service, actionName] = action.split(':')

  if (executionResult.type === 'denied_single') {
    return {
      type: 'single',
      principal,
      service,
      action: actionName,
      details: getDenialReasons(executionResult.analysis)
    }
  }

  // Wildcard case
  return {
    type: 'wildcard',
    principal,
    service,
    action: actionName,
    deniedResources: executionResult.deniedPatterns.map((pattern) => ({
      pattern: pattern.pattern,
      resourceType: pattern.resourceType,
      details: getDenialReasons(pattern.analysis)
    }))
  }
}
