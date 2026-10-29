import { describe, expect, it } from 'vitest'
import { isAwsFoundationModelArn } from './bedrock.js'

describe('isAwsFoundationModelArn', () => {
  it.each([
    ['arn:aws:bedrock:us-east-1::foundation-model/example.model-v1:0', true],
    ['arn:aws-us-gov:bedrock:::foundation-model/example', true],
    ['arn:aws:bedrock:us-east-1:123456789012:foundation-model/example', false],
    ['arn:aws:bedrock:us-east-1::inference-profile/example', false],
    ['arn:aws:bedrock:us-east-1::foundation-model/*', false],
    ['arn:aws:bedrock:us-east-1::foundation-model/', false],
    ['arn:aws:s3:::example', false]
  ])('classifies %s as %s', (arn, expected) => {
    //Given a candidate resource ARN
    //When the model classifier evaluates it
    const result = isAwsFoundationModelArn(arn)
    //Then only concrete accountless foundation models are recognized
    expect(result).toBe(expected)
  })
})
