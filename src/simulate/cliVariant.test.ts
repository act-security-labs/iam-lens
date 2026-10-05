import { describe, expect, it } from 'vitest'
import { selectSimulateCliVariant, type SimulateCliOptions } from './cliVariant.js'

const baseOptions: SimulateCliOptions = {
  principal: 'arn:aws:iam::123456789012:role/ExampleRole',
  resource: 'arn:aws:s3:::example-bucket',
  action: 's3:ListBucket',
  customContextKeys: {}
}

describe('selectSimulateCliVariant', () => {
  it('should select normal simulation when no variant flag is set', () => {
    //Given standard simulation options
    //When selecting the CLI variant
    const selection = selectSimulateCliVariant(baseOptions)

    //Then normal simulation and its authenticated request should be selected
    expect(selection).toEqual({
      variant: 'normal',
      request: {
        principal: baseOptions.principal,
        resourceArn: baseOptions.resource,
        resourceAccount: undefined,
        action: baseOptions.action,
        customContextKeys: {},
        simulationMode: 'Strict',
        s3AbacOverride: undefined,
        sessionPolicy: undefined
      }
    })
  })

  it('should select anonymous simulation without a principal or session policy', () => {
    //Given anonymous CLI options with a concrete resource
    //When selecting the CLI variant
    const selection = selectSimulateCliVariant({
      ...baseOptions,
      anonymous: true,
      principal: undefined
    })

    //Then an anonymous request should be returned
    expect(selection).toMatchObject({
      variant: 'anonymous',
      request: {
        resourceArn: baseOptions.resource,
        action: baseOptions.action
      }
    })
    expect(selection.request).not.toHaveProperty('principal')
    expect(selection.request).not.toHaveProperty('sessionPolicy')
  })

  it('should select external-principal simulation and preserve a session policy', () => {
    //Given external-principal options with a session policy
    const sessionPolicy = { Version: '2012-10-17', Statement: [] }

    //When selecting the CLI variant
    const selection = selectSimulateCliVariant({
      ...baseOptions,
      externalPrincipal: true,
      sessionPolicy
    })

    //Then the external-principal request should retain the policy
    expect(selection).toMatchObject({
      variant: 'externalPrincipal',
      request: { principal: baseOptions.principal, sessionPolicy }
    })
  })

  it('should select external-resource simulation and preserve an object policy', () => {
    //Given external-resource options with a raw policy document
    const resourcePolicy = { Version: '2012-10-17', Statement: [] }

    //When selecting the CLI variant
    const selection = selectSimulateCliVariant({
      ...baseOptions,
      externalResource: true,
      resourcePolicy
    })

    //Then the external-resource request should retain the policy document
    expect(selection).toMatchObject({
      variant: 'externalResource',
      request: { resourcePolicy }
    })
  })

  it('should reject multiple simulation variant flags', () => {
    //Given two simulation variants
    const options = { ...baseOptions, anonymous: true, externalResource: true }

    //When and Then selecting a variant should reject the conflict
    expect(() => selectSimulateCliVariant(options)).toThrow(
      'Only one of --anonymous, --external-principal, or --external-resource may be specified.'
    )
  })

  it('should reject a principal for anonymous simulation', () => {
    //Given anonymous options with a principal
    //When and Then selecting a variant should reject the principal
    expect(() => selectSimulateCliVariant({ ...baseOptions, anonymous: true })).toThrow(
      '--principal cannot be used with --anonymous.'
    )
  })

  it('should reject a session policy for anonymous simulation', () => {
    //Given anonymous options with a session policy
    const options = {
      ...baseOptions,
      anonymous: true,
      principal: undefined,
      sessionPolicy: { Version: '2012-10-17', Statement: [] }
    }

    //When and Then selecting a variant should reject the session policy
    expect(() => selectSimulateCliVariant(options)).toThrow(
      '--session-policy cannot be used with --anonymous.'
    )
  })

  it('should require a resource for anonymous simulation', () => {
    //Given anonymous options without a resource
    const options = { ...baseOptions, anonymous: true, principal: undefined, resource: undefined }

    //When and Then selecting a variant should require the resource
    expect(() => selectSimulateCliVariant(options)).toThrow(
      '--resource is required with --anonymous.'
    )
  })

  it('should reject principal-derived context for anonymous simulation', () => {
    //Given anonymous options with an impossible principal tag context key
    const options = {
      ...baseOptions,
      anonymous: true,
      principal: undefined,
      customContextKeys: { 'AWS:PrincipalTag/team': 'security' }
    }

    //When and Then selecting a variant should reject the principal-derived context
    expect(() => selectSimulateCliVariant(options)).toThrow(
      'Anonymous simulations cannot specify principal-derived context key AWS:PrincipalTag/team.'
    )
  })

  it('should require a principal for authenticated simulation variants', () => {
    //Given external-resource options without a principal
    const options = { ...baseOptions, externalResource: true, principal: undefined }

    //When and Then selecting a variant should require a principal
    expect(() => selectSimulateCliVariant(options)).toThrow(
      '--principal is required unless --anonymous is specified.'
    )
  })

  it('should require a resource for external-resource simulation', () => {
    //Given external-resource options without a concrete resource ARN
    const options = { ...baseOptions, externalResource: true, resource: undefined }

    //When and Then selecting a variant should require the resource
    expect(() => selectSimulateCliVariant(options)).toThrow(
      '--resource is required with --external-resource.'
    )
  })

  it('should reject resource policy without external-resource simulation', () => {
    //Given normal options with a resource policy
    const options = { ...baseOptions, resourcePolicy: { Version: '2012-10-17' } }

    //When and Then selecting a variant should reject the policy
    expect(() => selectSimulateCliVariant(options)).toThrow(
      '--resource-policy may only be used with --external-resource.'
    )
  })

  it.each([null, [], 'policy', 42])(
    'should reject a non-object external resource policy: %j',
    (resourcePolicy) => {
      //Given external-resource options with a non-object JSON value
      const options = { ...baseOptions, externalResource: true, resourcePolicy }

      //When and Then selecting a variant should reject the value
      expect(() => selectSimulateCliVariant(options)).toThrow(
        '--resource-policy must contain a JSON object.'
      )
    }
  )
})
