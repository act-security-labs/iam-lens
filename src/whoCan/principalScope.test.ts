import { describe, expect, it } from 'vitest'
import { IamCollectClient } from '../collect/client.js'
import { type WhoCanPrincipalScope } from './whoCan.js'
import { intersectWithPrincipalScope, resolvePrincipalScope } from './principalScope.js'

describe('resolvePrincipalScope', () => {
  it('keeps anonymous selection separate from collected-principal resolution', async () => {
    //Given a scope containing both unsigned access and a collected identity
    const principal = 'arn:aws:iam::111111111111:role/Reader'
    const client = {} as unknown as IamCollectClient

    //When normalizing the scope for collected-principal enumeration
    const result = await resolvePrincipalScope(client, {
      principals: [principal],
      accounts: ['111111111111'],
      anonymous: true
    })

    //Then the boolean does not affect the collected identity or account sets
    expect(result.principals).toEqual(new Set([principal]))
    expect(result.accounts).toEqual(new Set(['111111111111']))
  })
  it('should return only principals when scope has only principals', async () => {
    //Given a scope with only principals
    const scope: WhoCanPrincipalScope = {
      principals: ['arn:aws:iam::111111111111:role/RoleA', 'arn:aws:iam::222222222222:user/UserB']
    }
    const client = {} as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then principals should be populated and accounts should be empty
    expect(result.principals).toEqual(
      new Set(['arn:aws:iam::111111111111:role/RoleA', 'arn:aws:iam::222222222222:user/UserB'])
    )
    expect(result.accounts).toEqual(new Set())
  })

  it('should return only accounts when scope has only accounts', async () => {
    //Given a scope with accounts
    const scope: WhoCanPrincipalScope = { accounts: ['111111111111', '222222222222'] }
    const client = {} as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then accounts should be populated and principals should be empty
    expect(result.accounts).toEqual(new Set(['111111111111', '222222222222']))
    expect(result.principals).toEqual(new Set())
  })

  it('should resolve OU paths to accounts via client', async () => {
    //Given a scope with an OU path
    const scope: WhoCanPrincipalScope = { ous: ['o-aaa/r-bbb/ou-ccc'] }
    const client = {
      getAccountsForOrgPath: async (orgId: string, pathParts: string[]) => {
        expect(orgId).toBe('o-aaa')
        expect(pathParts).toEqual(['r-bbb', 'ou-ccc'])
        return [true, ['333333333333', '444444444444']]
      }
    } as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then accounts should contain the resolved OU accounts
    expect(result.accounts).toEqual(new Set(['333333333333', '444444444444']))
    expect(result.principals).toEqual(new Set())
  })

  it('should correctly split nested OU paths', async () => {
    //Given a scope with a deeply nested OU path
    const scope: WhoCanPrincipalScope = { ous: ['o-aaa/r-bbb/ou-parent/ou-child'] }
    const client = {
      getAccountsForOrgPath: async (orgId: string, pathParts: string[]) => {
        expect(orgId).toBe('o-aaa')
        expect(pathParts).toEqual(['r-bbb', 'ou-parent', 'ou-child'])
        return [true, ['555555555555']]
      }
    } as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then accounts should contain the resolved account
    expect(result.accounts).toEqual(new Set(['555555555555']))
  })

  it('should combine all three scope types', async () => {
    //Given a scope with principals, accounts, and OUs
    const scope: WhoCanPrincipalScope = {
      principals: ['arn:aws:iam::111111111111:role/RoleA'],
      accounts: ['222222222222'],
      ous: ['o-aaa/r-bbb/ou-ccc']
    }
    const client = {
      getAccountsForOrgPath: async () => [true, ['333333333333']]
    } as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then principals and accounts should be the union of each source
    expect(result.principals).toEqual(new Set(['arn:aws:iam::111111111111:role/RoleA']))
    expect(result.accounts).toEqual(new Set(['222222222222', '333333333333']))
  })

  it('should deduplicate accounts from direct and OU sources', async () => {
    //Given a scope where the same account appears directly and via an OU
    const scope: WhoCanPrincipalScope = {
      accounts: ['111111111111', '111111111111', '222222222222'],
      principals: ['arn:aws:iam::333333333333:role/RoleA', 'arn:aws:iam::333333333333:role/RoleA'],
      ous: ['o-aaa/r-bbb/ou-ccc']
    }
    const client = {
      getAccountsForOrgPath: async () => [true, ['111111111111', '444444444444']]
    } as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then accounts and principals should be deduplicated
    expect(result.accounts).toEqual(new Set(['111111111111', '222222222222', '444444444444']))
    expect(result.principals).toEqual(new Set(['arn:aws:iam::333333333333:role/RoleA']))
  })

  it('should keep service principals in the principals set', async () => {
    //Given a scope with a service principal
    const scope: WhoCanPrincipalScope = {
      principals: ['lambda.amazonaws.com']
    }
    const client = {} as unknown as IamCollectClient

    //When we resolve the scope
    const result = await resolvePrincipalScope(client, scope)

    //Then the service principal should be in the principals set with no account extracted
    expect(result.principals).toEqual(new Set(['lambda.amazonaws.com']))
    expect(result.accounts).toEqual(new Set())
  })
})

describe('intersectWithPrincipalScope', () => {
  it('should use all suggested accounts when allAccountsChecked is true', () => {
    //Given allAccountsChecked is true and suggested accounts
    const scopeAccounts = new Set(['111111111111', '222222222222'])

    //When we intersect
    const result = intersectWithPrincipalScope(['333333333333'], [], true, scopeAccounts, new Set())

    //Then all suggested accounts should be returned
    expect(result.accounts).toEqual(['111111111111', '222222222222'])
  })

  it('should return only the intersection of accounts when allAccountsChecked is false', () => {
    //Given specific resource policy accounts and suggested accounts
    const rpAccounts = ['111111111111', '222222222222', '333333333333']
    const scopeAccounts = new Set(['222222222222', '444444444444'])

    //When we intersect
    const result = intersectWithPrincipalScope(rpAccounts, [], false, scopeAccounts, new Set())

    //Then only the overlapping account should be returned
    expect(result.accounts).toEqual(['222222222222'])
  })

  it('should return empty accounts and principals when account sets are disjoint', () => {
    //Given disjoint account sets and no explicit principals
    const rpAccounts = ['111111111111']
    const scopeAccounts = new Set(['222222222222'])

    //When we intersect
    const result = intersectWithPrincipalScope(rpAccounts, [], false, scopeAccounts, new Set())

    //Then both accounts and principals should be empty
    expect(result.accounts).toEqual([])
    expect(result.principals).toEqual([])
  })

  it('should filter resource policy principals by scope accounts and scope principals', () => {
    //Given resource policy principals and suggested accounts/principals
    const rpPrincipals = [
      'arn:aws:iam::111111111111:role/RoleA',
      'arn:aws:iam::222222222222:role/RoleB',
      'arn:aws:iam::333333333333:role/RoleC'
    ]
    const scopeAccounts = new Set(['222222222222'])
    const scopePrincipals = new Set(['arn:aws:iam::333333333333:role/RoleC'])

    //When we intersect with no accounts in result (disjoint account sets with RP)
    const result = intersectWithPrincipalScope(
      ['444444444444'],
      rpPrincipals,
      false,
      scopeAccounts,
      scopePrincipals
    )

    //Then RoleB's account matches suggested accounts, and RoleC matches suggested principals
    expect(result.accounts).toEqual([])
    expect(result.principals.sort()).toEqual([
      'arn:aws:iam::222222222222:role/RoleB',
      'arn:aws:iam::333333333333:role/RoleC'
    ])
  })

  it('should add scope principals whose account is in resource policy accounts', () => {
    //Given a suggested principal whose account is in resource policy accounts but not in result accounts
    const rpAccounts = ['111111111111']
    const scopeAccounts = new Set(['222222222222'])
    const scopePrincipals = new Set(['arn:aws:iam::111111111111:role/SpecificRole'])

    //When we intersect (accounts are disjoint so result accounts is empty)
    const result = intersectWithPrincipalScope(
      rpAccounts,
      [],
      false,
      scopeAccounts,
      scopePrincipals
    )

    //Then the suggested principal should be in the principals result
    expect(result.accounts).toEqual([])
    expect(result.principals).toEqual(['arn:aws:iam::111111111111:role/SpecificRole'])
  })

  it('should exclude scope principal whose account is already in accounts result', () => {
    //Given a suggested principal whose account is already in the accounts result
    const rpAccounts = ['111111111111']
    const scopeAccounts = new Set(['111111111111'])
    const scopePrincipals = new Set(['arn:aws:iam::111111111111:role/RoleA'])

    //When we intersect (accounts overlap, so 111111111111 is in result accounts)
    const result = intersectWithPrincipalScope(
      rpAccounts,
      [],
      false,
      scopeAccounts,
      scopePrincipals
    )

    //Then the principal should NOT be in principals since its account is already searched
    expect(result.accounts).toEqual(['111111111111'])
    expect(result.principals).toEqual([])
  })

  it('should exclude resource-policy principal whose account is in accounts result even if in scopePrincipals', () => {
    //Given a principal that appears in both resourcePolicyPrincipals and scopePrincipals,
    //and its account is already in the accounts result
    const rpAccounts = ['111111111111']
    const rpPrincipals = ['arn:aws:iam::111111111111:role/RoleA']
    const scopeAccounts = new Set(['111111111111'])
    const scopePrincipals = new Set(['arn:aws:iam::111111111111:role/RoleA'])

    //When we intersect (accounts overlap, so 111111111111 is in result accounts)
    const result = intersectWithPrincipalScope(
      rpAccounts,
      rpPrincipals,
      false,
      scopeAccounts,
      scopePrincipals
    )

    //Then the principal should NOT appear in principals — the account loop covers it
    expect(result.accounts).toEqual(['111111111111'])
    expect(result.principals).toEqual([])
  })

  it('should keep service principals from resource policy only if in scope principals', () => {
    //Given a service principal in resource policy principals
    const rpPrincipals = ['lambda.amazonaws.com', 'ec2.amazonaws.com']
    const scopePrincipals = new Set(['lambda.amazonaws.com'])

    //When we intersect
    const result = intersectWithPrincipalScope([], rpPrincipals, false, new Set(), scopePrincipals)

    //Then only the matching service principal should be kept
    expect(result.principals).toContain('lambda.amazonaws.com')
    expect(result.principals).not.toContain('ec2.amazonaws.com')
  })

  it('should include service principals from scope when allAccountsChecked is true', () => {
    //Given a service principal in scope principals and allAccountsChecked
    const scopePrincipals = new Set(['lambda.amazonaws.com'])

    //When we intersect with allAccountsChecked true
    const result = intersectWithPrincipalScope([], [], true, new Set(), scopePrincipals)

    //Then the service principal should be included
    expect(result.principals).toEqual(['lambda.amazonaws.com'])
  })

  it('should include service principals from scope when resource policy named them', () => {
    //Given a service principal in both scope and resource policy principals
    const rpPrincipals = ['lambda.amazonaws.com']
    const scopePrincipals = new Set(['lambda.amazonaws.com'])

    //When we intersect
    const result = intersectWithPrincipalScope([], rpPrincipals, false, new Set(), scopePrincipals)

    //Then the service principal should be included
    expect(result.principals).toEqual(['lambda.amazonaws.com'])
  })

  it('should exclude service principals from scope when not in resource policy and allAccountsChecked is false', () => {
    //Given a service principal in scope but NOT in resource policy, and allAccountsChecked is false
    const scopePrincipals = new Set(['lambda.amazonaws.com'])

    //When we intersect with empty resource policy
    const result = intersectWithPrincipalScope([], [], false, new Set(), scopePrincipals)

    //Then the service principal should be excluded
    expect(result.principals).toEqual([])
  })

  it('should deduplicate principals from both sides', () => {
    //Given the same principal appearing in both resource policy and scope
    const rpPrincipals = ['arn:aws:iam::111111111111:role/RoleA']
    const scopeAccounts = new Set<string>()
    const scopePrincipals = new Set(['arn:aws:iam::111111111111:role/RoleA'])

    //When we intersect with allAccountsChecked so the suggested principal qualifies
    const result = intersectWithPrincipalScope(
      ['111111111111'],
      rpPrincipals,
      false,
      scopeAccounts,
      scopePrincipals
    )

    //Then the principal should appear only once
    expect(result.principals).toEqual(['arn:aws:iam::111111111111:role/RoleA'])
  })
})
