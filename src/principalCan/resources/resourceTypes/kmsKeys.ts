import { loadPolicy, type Statement } from '@actsecurity/iam-policy'
import { equalsIgnoreCase, splitArnParts } from '@actsecurity/iam-utils'
import { IamCollectClient } from '../../../collect/client.js'
import { Permission } from '../../permission.js'
import { addStatementToPermissionSet, PermissionSet } from '../../permissionSet.js'
import { actionsForResourceType } from '../actions.js'
import { statementAppliesToPrincipal } from '../statements.js'

/**
 * Get the list of KMS actions.
 *
 * @returns All options available for KMS keys.
 */
export async function kmsKeyActions(): Promise<string[]> {
  return actionsForResourceType('kms', 'key')
}

/**
 * Create permission sets that include all KMS key actions on all resources.
 *
 * @returns Permission sets that include all KMS key actions on all resources both for Allow and Deny.
 */
export async function allKmsKeysAllActionsPermissionSets(): Promise<{
  keyAllows: PermissionSet
  keyDenies: PermissionSet
}> {
  const keyActions = await kmsKeyActions()
  const allowPerimeter = new PermissionSet('Allow')
  const denyPerimeter = new PermissionSet('Deny')
  for (const action of keyActions) {
    allowPerimeter.addPermission(
      new Permission('Allow', 'kms', action, ['*'], undefined, undefined)
    )
    denyPerimeter.addPermission(new Permission('Deny', 'kms', action, ['*'], undefined, undefined))
  }

  return { keyAllows: allowPerimeter, keyDenies: denyPerimeter }
}

/**
 * Get the permissions a principal has on KMS keys in the same account.
 *
 * @param collectClient the IAM collect client to use for retrieving policies.
 * @param principal the principal to check permissions for.
 * @returns the permissions the principal has on KMS keys in the same account.
 */
export async function kmsKeysSameAccount(
  collectClient: IamCollectClient,
  principal: string
): Promise<{
  accountAllows: PermissionSet[]
  principalAllows: PermissionSet[]
  denies: PermissionSet[]
}> {
  const principalArnParts = splitArnParts(principal)
  const principalAccountId = principalArnParts.accountId!

  const keyActions = await kmsKeyActions()
  const allKeys = await collectClient.listResources(principalAccountId, 'kms', 'key', '*')

  const accountAllows: PermissionSet[] = []
  const principalAllows: PermissionSet[] = []
  const denies: PermissionSet[] = []

  for (const keyArn of allKeys) {
    const rawKeyPolicy = await collectClient.getResourcePolicyForArn(keyArn, principalAccountId)
    if (!rawKeyPolicy) {
      continue
    }

    const allowPerimeter = new PermissionSet('Allow')
    const denyPerimeter = new PermissionSet('Deny')
    for (const action of keyActions) {
      allowPerimeter.addPermission(
        new Permission('Allow', 'kms', action, [keyArn], undefined, undefined)
      )
      denyPerimeter.addPermission(
        new Permission('Deny', 'kms', action, [keyArn], undefined, undefined)
      )
    }

    const keyAcctAllow = new PermissionSet('Allow')
    const keyPrincipalAllow = new PermissionSet('Allow')
    const keyDeny = new PermissionSet('Deny')

    const keyPolicy = loadPolicy(rawKeyPolicy)

    for (const statement of keyPolicy.statements()) {
      const applies = await statementAppliesToPrincipal(statement, principal, collectClient)
      const hasViaService = statementHasViaServiceCondition(statement)
      if (applies === 'PrincipalMatch') {
        if (statement.isAllow()) {
          if (!hasViaService) {
            await addStatementToPermissionSet(statement, keyPrincipalAllow)
          }
        } else {
          await addStatementToPermissionSet(statement, keyDeny)
        }
      } else if (applies === 'AccountMatch' && statement.isAllow() && !hasViaService) {
        await addStatementToPermissionSet(statement, keyAcctAllow)
      }
    }

    const effectivePrincipalAllow = keyPrincipalAllow.intersection(allowPerimeter)
    const effectiveAccountAllow = keyAcctAllow.intersection(allowPerimeter)
    const effectiveDeny = keyDeny.intersection(denyPerimeter)

    if (!effectivePrincipalAllow.isEmpty()) {
      principalAllows.push(effectivePrincipalAllow)
    }
    if (!effectiveAccountAllow.isEmpty()) {
      accountAllows.push(effectiveAccountAllow)
    }
    if (!effectiveDeny.isEmpty()) {
      denies.push(effectiveDeny)
    }
  }

  return {
    accountAllows,
    principalAllows,
    denies
  }
}

/**
 * Check if the statement has the condition key kms:ViaService.
 *
 * @param statement the statement to check
 * @returns true if the statement has a kms:ViaService condition, false otherwise
 */
function statementHasViaServiceCondition(statement: Statement): boolean {
  return statement.conditions().some((c) => equalsIgnoreCase(c.conditionKey(), 'kms:viaservice'))
}
