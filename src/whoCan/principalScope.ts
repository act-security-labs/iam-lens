import {
  isCloudFrontIdentityArn,
  isCloudFrontOriginAccessUserArn,
  isServicePrincipal,
  splitArnParts
} from '@actsecurity/iam-utils'
import { IamCollectClient } from '../collect/client.js'
import { type WhoCanPrincipalScope } from './whoCan.js'

/**
 * Resolves a `WhoCanPrincipalScope` into concrete sets of account IDs and principal ARNs
 * using the collect client for OU lookups.
 *
 * `scope.principals` are kept separate from `scope.accounts` — a scope like
 * `{ principals: ['arn:...:role/Foo'] }` tests only that one role and does NOT
 * expand to search every principal in Foo's account.
 *
 * @param client The collect client used to resolve OU paths to account IDs.
 * @param scope The principal scope to resolve.
 * @returns An object with `accounts` and `principals` sets.
 */
export async function resolvePrincipalScope(
  client: IamCollectClient,
  scope: WhoCanPrincipalScope
): Promise<{ accounts: Set<string>; principals: Set<string> }> {
  const accounts = new Set<string>()
  const principals = new Set<string>()

  for (const p of scope.principals ?? []) {
    if (isCloudFrontOriginAccessUserArn(p)) {
      principals.add((await client.getCloudFrontOriginAccessIdentity(p))?.arn ?? p)
    } else {
      principals.add(p)
    }
  }

  for (const a of scope.accounts ?? []) {
    accounts.add(a)
  }

  for (const ouPath of scope.ous ?? []) {
    const parts = ouPath.split('/')
    const orgId = parts[0]
    const pathParts = parts.slice(1)
    const [, ouAccounts] = await client.getAccountsForOrgPath(orgId, pathParts)
    for (const a of ouAccounts) {
      accounts.add(a)
    }
  }

  return { accounts, principals }
}

/**
 * Intersects the resource-policy-derived scope with a caller-supplied principal scope.
 * Returns the narrowed set of accounts (for full-account search) and principals
 * (for individual principal testing).
 *
 * @param resourcePolicyAccounts Account IDs derived from the resource policy.
 * @param resourcePolicyPrincipals Individual principal ARNs derived from the resource policy.
 * @param resourcePolicyCheckAllAccounts Whether the resource policy implies all accounts should be checked.
 * @param scopeAccounts Account IDs from the resolved principal scope.
 * @param suggestedPrincipals Principal ARNs from the resolved principal scope.
 * @returns The intersected accounts and principals to search.
 */
export function intersectWithPrincipalScope(
  resourcePolicyAccounts: string[],
  resourcePolicyPrincipals: string[],
  resourcePolicyCheckAllAccounts: boolean,
  scopeAccounts: Set<string>,
  scopePrincipals: Set<string>
): { accounts: string[]; principals: string[] } {
  // Accounts: intersection of resource policy accounts and scope accounts
  const rpAccountSet = new Set(resourcePolicyAccounts)
  const accounts = resourcePolicyCheckAllAccounts
    ? Array.from(scopeAccounts)
    : resourcePolicyAccounts.filter((a) => scopeAccounts.has(a))

  const accountsResultSet = new Set(accounts)

  // Principals: merge from both sides, filtering by the other side's scope
  const principalSet = new Set<string>()

  // From resource policy principals: keep if the principal's account is in scopeAccounts,
  // OR the principal ARN is in scopePrincipals.
  for (const p of resourcePolicyPrincipals) {
    if (isServicePrincipal(p)) {
      if (scopePrincipals.has(p)) {
        principalSet.add(p)
      }
    } else {
      const accountId = splitArnParts(p).accountId
      if (accountId && accountsResultSet.has(accountId) && !isCloudFrontIdentityArn(p)) {
        // The IAM account loop covers ordinary principals, but not OAIs.
        continue
      }
      if (accountId && scopeAccounts.has(accountId)) {
        principalSet.add(p)
      } else if (scopePrincipals.has(p)) {
        principalSet.add(p)
      }
    }
  }

  const rpPrincipalSet = new Set(resourcePolicyPrincipals)

  // From scope principals: keep if the principal's account is in resource policy accounts
  // or resourcePolicyCheckAllAccounts is true. Exclude if account is already in accounts result.
  // Service principals only survive if resourcePolicyCheckAllAccounts or the resource policy named them.
  for (const p of scopePrincipals) {
    if (isServicePrincipal(p)) {
      if (resourcePolicyCheckAllAccounts || rpPrincipalSet.has(p)) {
        principalSet.add(p)
      }
    } else {
      const accountId = splitArnParts(p).accountId
      if (accountId && accountsResultSet.has(accountId) && !isCloudFrontIdentityArn(p)) {
        // The IAM account loop covers ordinary principals, but not OAIs.
        continue
      }
      if (resourcePolicyCheckAllAccounts || (accountId && rpAccountSet.has(accountId))) {
        principalSet.add(p)
      }
    }
  }

  return { accounts, principals: Array.from(principalSet) }
}
