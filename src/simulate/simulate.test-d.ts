import type { RunSimulationResults, Simulation } from '@actsecurity/iam-simulate'
import { describe, expectTypeOf, it } from 'vitest'
import type {
  AnonymousSimulationRequest,
  ExternalResourceSimulationRequest,
  SimulateRequestResult,
  SimulationRequest
} from './simulate.js'

describe('simulation request type contracts', () => {
  it('should expose the iam-simulate result and normalized request', () => {
    expectTypeOf<SimulateRequestResult['result']>().toEqualTypeOf<RunSimulationResults>()
    expectTypeOf<SimulateRequestResult['request']>().toEqualTypeOf<Simulation['request']>()
  })

  it('should remove the legacy ignoreMissingPrincipal option', () => {
    expectTypeOf<SimulationRequest>().not.toHaveProperty('ignoreMissingPrincipal')
  })

  it('should omit principal and session policy from anonymous requests', () => {
    expectTypeOf<AnonymousSimulationRequest>().not.toHaveProperty('principal')
    expectTypeOf<AnonymousSimulationRequest>().not.toHaveProperty('sessionPolicy')
    expectTypeOf<AnonymousSimulationRequest['resourceArn']>().toEqualTypeOf<string>()
  })

  it('should require a concrete ARN and accept an optional raw object policy for external resources', () => {
    expectTypeOf<ExternalResourceSimulationRequest['resourceArn']>().toEqualTypeOf<string>()
    expectTypeOf<ExternalResourceSimulationRequest['resourcePolicy']>().toEqualTypeOf<
      Record<string, unknown> | undefined
    >()
  })
})
