import type { S3AbacOverride } from '../utils/s3Abac.js'
import { isAnonymousPrincipalContextKey, type ContextKeys } from './contextKeys.js'
import type {
  AnonymousSimulationRequest,
  ExternalResourceSimulationRequest,
  SimulationRequest
} from './simulate.js'

/**
 * Parsed CLI values used to select and construct a simulation request variant.
 */
export interface SimulateCliOptions {
  /**
   * Whether to simulate an unsigned request.
   */
  anonymous?: boolean

  /**
   * Whether to simulate a synthetic administrator principal.
   */
  externalPrincipal?: boolean

  /**
   * Whether to simulate a resource outside the collected dataset.
   */
  externalResource?: boolean

  /**
   * Authenticated principal for non-anonymous simulations.
   */
  principal?: string

  /**
   * Resource ARN supplied on the command line.
   */
  resource?: string

  /**
   * Explicit resource account supplied on the command line.
   */
  resourceAccount?: string

  /**
   * IAM action supplied on the command line.
   */
  action?: string

  /**
   * Caller-provided IAM context values.
   */
  customContextKeys: ContextKeys

  /**
   * Optional session policy parsed from JSON or a file.
   */
  sessionPolicy?: any

  /**
   * Optional external resource or trust policy parsed from JSON or a file.
   */
  resourcePolicy?: unknown

  /**
   * Optional S3 ABAC behavior override.
   */
  s3AbacOverride?: S3AbacOverride
}

/**
 * A validated normal simulation selected by CLI options.
 */
export interface NormalSimulateCliSelection {
  /**
   * Discriminant identifying normal collected-principal and collected-resource simulation.
   */
  variant: 'normal'

  /**
   * Request passed to {@link simulateRequest}.
   */
  request: SimulationRequest
}

/**
 * A validated anonymous simulation selected by CLI options.
 */
export interface AnonymousSimulateCliSelection {
  /**
   * Discriminant identifying unsigned simulation.
   */
  variant: 'anonymous'

  /**
   * Request passed to {@link simulateAnonymousRequest}.
   */
  request: AnonymousSimulationRequest
}

/**
 * A validated external-principal simulation selected by CLI options.
 */
export interface ExternalPrincipalSimulateCliSelection {
  /**
   * Discriminant identifying synthetic administrator-principal simulation.
   */
  variant: 'externalPrincipal'

  /**
   * Request passed to {@link simulateExternalPrincipalRequest}.
   */
  request: SimulationRequest
}

/**
 * A validated external-resource simulation selected by CLI options.
 */
export interface ExternalResourceSimulateCliSelection {
  /**
   * Discriminant identifying simulation against an uncollected resource.
   */
  variant: 'externalResource'

  /**
   * Request passed to {@link simulateExternalResourceRequest}.
   */
  request: ExternalResourceSimulationRequest
}

/**
 * Validated simulation selection produced from CLI arguments.
 */
export type SimulateCliSelection =
  | NormalSimulateCliSelection
  | AnonymousSimulateCliSelection
  | ExternalPrincipalSimulateCliSelection
  | ExternalResourceSimulateCliSelection

/**
 * Validate simulation CLI options and construct the corresponding library request.
 *
 * @param options parsed CLI simulation options
 * @returns a discriminated simulation selection ready for dispatch
 */
export function selectSimulateCliVariant(options: SimulateCliOptions): SimulateCliSelection {
  const variants = [options.anonymous, options.externalPrincipal, options.externalResource].filter(
    Boolean
  )
  if (variants.length > 1) {
    throw new Error(
      'Only one of --anonymous, --external-principal, or --external-resource may be specified.'
    )
  }
  if (!options.action) {
    throw new Error('--action is required for simulate.')
  }
  if (options.resourcePolicy !== undefined && !options.externalResource) {
    throw new Error('--resource-policy may only be used with --external-resource.')
  }

  const commonRequest = {
    resourceArn: options.resource,
    resourceAccount: options.resourceAccount,
    action: options.action,
    customContextKeys: options.customContextKeys,
    simulationMode: 'Strict' as const,
    s3AbacOverride: options.s3AbacOverride
  }

  if (options.anonymous) {
    if (options.principal) {
      throw new Error('--principal cannot be used with --anonymous.')
    }
    if (options.sessionPolicy !== undefined) {
      throw new Error('--session-policy cannot be used with --anonymous.')
    }
    if (!options.resource) {
      throw new Error('--resource is required with --anonymous.')
    }
    const invalidContextKey = Object.keys(options.customContextKeys).find(
      isAnonymousPrincipalContextKey
    )
    if (invalidContextKey) {
      throw new Error(
        `Anonymous simulations cannot specify principal-derived context key ${invalidContextKey}.`
      )
    }
    return {
      variant: 'anonymous',
      request: { ...commonRequest, resourceArn: options.resource }
    }
  }

  if (!options.principal) {
    throw new Error('--principal is required unless --anonymous is specified.')
  }

  const authenticatedRequest: SimulationRequest = {
    ...commonRequest,
    principal: options.principal,
    sessionPolicy: options.sessionPolicy
  }

  if (options.externalPrincipal) {
    return { variant: 'externalPrincipal', request: authenticatedRequest }
  }

  if (options.externalResource) {
    if (!options.resource) {
      throw new Error('--resource is required with --external-resource.')
    }
    if (options.resourcePolicy !== undefined && !isJsonObject(options.resourcePolicy)) {
      throw new Error('--resource-policy must contain a JSON object.')
    }
    return {
      variant: 'externalResource',
      request: {
        ...authenticatedRequest,
        resourceArn: options.resource,
        resourcePolicy: options.resourcePolicy
      }
    }
  }

  return { variant: 'normal', request: authenticatedRequest }
}

/**
 * Check whether a parsed JSON value is an object suitable for policy validation.
 *
 * @param value parsed JSON value
 * @returns true for non-null, non-array objects
 */
function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
