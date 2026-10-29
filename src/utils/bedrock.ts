const awsFoundationModelArnPattern = /^arn:[^:]+:bedrock:[^:]*::foundation-model\/[^:]+(?::[^:]+)*$/

/**
 * Identify concrete AWS-owned Bedrock foundation model ARNs.
 *
 * @param arn the resource ARN, if specified
 * @returns whether the ARN identifies an accountless foundation model
 */
export function isAwsFoundationModelArn(arn: string | undefined): boolean {
  if (!arn || /[*?${}]/.test(arn)) {
    return false
  }
  return awsFoundationModelArnPattern.test(arn)
}
