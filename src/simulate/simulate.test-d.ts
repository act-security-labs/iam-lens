import type {
  DiscoveryContextKeyConstraint,
  RunSimulationResults,
  Simulation
} from '@actsecurity/iam-simulate'
import { describe, expectTypeOf, it } from 'vitest'
import { simulateVirtualResourceRequest } from './simulate.js'
import type {
  AnonymousSimulationRequest,
  ExternalResourceSimulationRequest,
  SimulateRequestResult,
  SimulationRequest,
  VirtualPrincipalSimulationRequest,
  VirtualResourceSimulationRequest
} from './simulate.js'

describe('simulation request type contracts', () => {
  it('should expose the iam-simulate result and normalized request', () => {
    expectTypeOf<SimulateRequestResult['result']>().toEqualTypeOf<RunSimulationResults>()
    expectTypeOf<SimulateRequestResult['request']>().toEqualTypeOf<Simulation['request']>()
  })

  it('should remove legacy request options', () => {
    expectTypeOf<SimulationRequest>().not.toHaveProperty('ignoreMissingPrincipal')
    expectTypeOf<SimulationRequest>().not.toHaveProperty('additionalStrictContextKeys')
  })

  it('should accept iam-simulate Discovery context-key constraints', () => {
    expectTypeOf<SimulationRequest['discoveryContextKeyConstraints']>().toEqualTypeOf<
      DiscoveryContextKeyConstraint[] | undefined
    >()
  })

  it('should omit principal and session policy from anonymous requests', () => {
    expectTypeOf<AnonymousSimulationRequest>().not.toHaveProperty('principal')
    expectTypeOf<AnonymousSimulationRequest>().not.toHaveProperty('sessionPolicy')
    expectTypeOf<AnonymousSimulationRequest['resourceArn']>().toEqualTypeOf<string>()
  })

  it('should keep a virtual principal required and accept an optional raw inline policy', () => {
    expectTypeOf<VirtualPrincipalSimulationRequest['principal']>().toEqualTypeOf<string>()
    expectTypeOf<VirtualPrincipalSimulationRequest['inlinePolicy']>().toEqualTypeOf<
      Record<string, unknown> | undefined
    >()
  })

  it('should require a concrete ARN and accept an optional raw object policy for external resources', () => {
    expectTypeOf<ExternalResourceSimulationRequest['resourceArn']>().toEqualTypeOf<string>()
    expectTypeOf<ExternalResourceSimulationRequest['resourcePolicy']>().toEqualTypeOf<
      Record<string, unknown> | undefined
    >()
  })

  it('should use the external resource contract for virtual resources', () => {
    expectTypeOf<
      Parameters<typeof simulateVirtualResourceRequest>[0]
    >().toEqualTypeOf<VirtualResourceSimulationRequest>()
    expectTypeOf<VirtualResourceSimulationRequest>().toEqualTypeOf<ExternalResourceSimulationRequest>()
  })
})
