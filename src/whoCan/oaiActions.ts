import { iamActionDetails } from '@actsecurity/iam-data'

/**
 * Select actions that can be simulated for a CloudFront origin access identity.
 *
 * @param actions - The validated, fully qualified actions requested by whoCan.
 * @returns The actions that are not wildcard-only, in their original order.
 */
export async function oaiSimulationActions(actions: string[]): Promise<string[]> {
  const eligibleActions = await Promise.all(
    actions.map(async (action) => {
      const [service, actionName] = action.split(':')
      const details = await iamActionDetails(service, actionName)
      return details.isWildcardOnly ? undefined : action
    })
  )
  return eligibleActions.filter((action): action is string => action !== undefined)
}
