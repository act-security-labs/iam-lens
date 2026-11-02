import { loadPolicy } from '@actsecurity/iam-policy'
import { actionMatchesPattern, equalsIgnoreCase, splitArnParts } from '@actsecurity/iam-utils'

/**
 * Set of condition operators that can be used with aws:PrincipalArn to
 * constrain which principals are allowed. These are the base operators
 * (lowercase) without set modifiers or IfExists.
 */
const ALLOW_PRINCIPAL_ARN_OPERATORS = new Set([
  'stringlike',
  'stringequals',
  'arnlike',
  'arnequals'
])

/**
 * Negative condition operators on `aws:PrincipalArn` in Deny statements.
 * The deny applies to principals NOT matching the patterns, so the patterns
 * become an allow-list (only those principals are worth simulating).
 */
const DENY_NEGATIVE_OPERATORS = new Set([
  'stringnotlike',
  'stringnotequals',
  'arnnotlike',
  'arnnotequals'
])

/**
 * Positive condition operators on `aws:PrincipalArn` in Deny statements.
 * The deny applies to principals matching the patterns, so those principals
 * can be skipped for the deny statement's actions.
 */
const DENY_POSITIVE_OPERATORS = new Set(['stringlike', 'stringequals', 'arnlike', 'arnequals'])

/**
 * An action-scoped set of principal ARN patterns extracted from a Deny statement.
 * The patterns only apply when the action being simulated matches one of the
 * entry's action patterns.
 */
export interface DenyFilterEntry {
  /** Action patterns from the deny statement (e.g., 'secretsmanager:GetSecretValue', 's3:*'). */
  actionPatterns: string[]
  /** Principal ARN patterns extracted from the condition. */
  principalPatterns: RegExp[]
}

/**
 * A pre-simulation filter that uses aws:PrincipalArn condition patterns
 * from a resource policy to skip principals that cannot possibly be allowed.
 */
export interface PrincipalArnFilter {
  /**
   * Allow patterns extracted from resource policy Allow statements.
   * If non-empty, a principal must match at least one pattern to be
   * worth simulating.
   */
  allowPatterns: RegExp[]

  /**
   * From Deny statements with negative operators (StringNotLike, etc.).
   * For each entry, if the simulation action matches one of the entry's
   * action patterns, the principal must match at least one of the entry's
   * principal patterns to be worth simulating.
   */
  denyDerivedAllowEntries: DenyFilterEntry[]

  /**
   * From Deny statements with positive operators (StringLike, etc.).
   * For each entry, if the simulation action matches one of the entry's
   * action patterns AND the principal matches one of the entry's principal
   * patterns, the simulation can be skipped (the principal is explicitly denied).
   */
  denyEntries: DenyFilterEntry[]

  /**
   * Account IDs that are explicitly named as account principals in the
   * resource policy's Allow statements. Principals in these accounts
   * must bypass the filter because the account-level principal grant
   * is independent of any PrincipalArn conditions on wildcard statements.
   */
  exemptAccounts: Set<string>
}

/**
 * Converts an IAM wildcard pattern to a case-sensitive anchored RegExp.
 * Handles `*` (any characters) and `?` (single character) wildcards.
 * Does not handle replacement variables — callers must ensure patterns
 * with variables are excluded before calling this.
 *
 * @param pattern the IAM pattern string (e.g. `arn:aws:iam::*:role/ec2/*`)
 * @returns an anchored case-sensitive RegExp
 */
export function iamPatternToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const withWildcards = escaped.replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`^${withWildcards}$`)
}

/**
 * Checks whether any value in an array contains a replacement variable (`${...}`).
 *
 * @param values the condition values to check
 * @returns true if any value contains a replacement variable
 */
function hasAnyReplacementVariable(values: string[]): boolean {
  return values.some((v) => v.includes('${'))
}

/**
 * Builds a PrincipalArnFilter from a resource policy by extracting
 * aws:PrincipalArn patterns from Allow statements with wildcard principals.
 *
 * The filter is only constructed if **every** wildcard-Allow statement has
 * a usable aws:PrincipalArn condition. If any wildcard-Allow statement lacks
 * one, the filter cannot safely exclude principals and undefined is returned.
 *
 * @param resourcePolicy the raw resource policy document, or undefined/null if none
 * @returns a PrincipalArnFilter if filtering is possible, undefined otherwise
 */
export function buildPrincipalArnFilter(resourcePolicy: any): PrincipalArnFilter | undefined {
  if (!resourcePolicy) {
    return undefined
  }

  const policy = loadPolicy(resourcePolicy)
  const allAllowPatterns: RegExp[] = []
  const exemptAccounts = new Set<string>()
  let hasAnyWildcardAllow = false

  for (const statement of policy.statements()) {
    if (!statement.isAllow()) {
      continue
    }

    // Check if this Allow statement has a wildcard principal, and collect
    // explicit account principals whose accounts should be exempt from filtering
    let hasWildcardPrincipal = false
    if (statement.isPrincipalStatement()) {
      for (const principal of statement.principals()) {
        if (principal.isWildcardPrincipal()) {
          hasWildcardPrincipal = true
        } else if (principal.isAccountPrincipal()) {
          exemptAccounts.add(principal.accountId())
        }
      }
    } else if (statement.isNotPrincipalStatement()) {
      // NotPrincipal Allow effectively allows everyone except the named principals,
      // so it acts like a wildcard — we can't filter
      return undefined
    }

    if (!hasWildcardPrincipal) {
      continue
    }

    hasAnyWildcardAllow = true

    // Look for aws:PrincipalArn conditions with supported operators
    let statementHasUsableFilter = false
    const conditions = statement.conditions()

    for (const cond of conditions) {
      if (!equalsIgnoreCase(cond.conditionKey(), 'aws:principalarn')) {
        continue
      }

      const baseOp = cond.operation().baseOperator().toLowerCase()
      if (!ALLOW_PRINCIPAL_ARN_OPERATORS.has(baseOp)) {
        continue
      }

      const values = cond.conditionValues()

      // If any value has a replacement variable, ignore the entire condition
      if (hasAnyReplacementVariable(values)) {
        continue
      }

      // All values count as a usable filter for the statement — even literal
      // ARNs constrain which principals can match. However, only wildcard
      // values are added as filter patterns; literal ARNs are already handled
      // as specific principals by accountsToCheckBasedOnResourcePolicy.
      for (const value of values) {
        statementHasUsableFilter = true
        if (value.includes('*') || value.includes('?')) {
          allAllowPatterns.push(iamPatternToRegex(value))
        }
      }
    }

    // If this wildcard-Allow has no usable PrincipalArn condition,
    // it could allow any principal — filtering is not safe
    if (!statementHasUsableFilter) {
      return undefined
    }
  }

  // --- Deny statement extraction ---
  const denyDerivedAllowEntries: DenyFilterEntry[] = []
  const denyEntries: DenyFilterEntry[] = []

  for (const statement of policy.statements()) {
    if (statement.isAllow()) continue
    if (!statement.isActionStatement()) continue
    if (statement.isNotResourceStatement()) continue
    if (statement.isNotPrincipalStatement()) continue

    // Must have a wildcard principal
    let hasWildcardPrincipal = false
    if (statement.isPrincipalStatement()) {
      for (const principal of statement.principals()) {
        if (principal.isWildcardPrincipal()) {
          hasWildcardPrincipal = true
          break
        }
      }
    }
    if (!hasWildcardPrincipal) continue

    // Resource must include '*' or be non-existent
    if (statement.isResourceStatement()) {
      if (!statement.resources().some((r) => r.isAllResources())) continue
    }

    // Must have exactly one condition and it must be aws:PrincipalArn
    const conditions = statement.conditions()
    if (conditions.length !== 1) continue

    const cond = conditions[0]
    if (!equalsIgnoreCase(cond.conditionKey(), 'aws:principalarn')) {
      continue
    }
    if (cond.operation().isIfExists()) continue

    const values = cond.conditionValues()
    if (hasAnyReplacementVariable(values)) continue

    const baseOp = cond.operation().baseOperator().toLowerCase()
    const actionPatterns = statement.actions().map((a) => a.value())
    const principalPatterns = values.map(iamPatternToRegex)

    if (DENY_NEGATIVE_OPERATORS.has(baseOp)) {
      denyDerivedAllowEntries.push({ actionPatterns, principalPatterns })
    } else if (DENY_POSITIVE_OPERATORS.has(baseOp)) {
      denyEntries.push({ actionPatterns, principalPatterns })
    }
  }

  // Return a filter if there's anything useful
  const hasAllowPatterns = hasAnyWildcardAllow && allAllowPatterns.length > 0
  const hasDenyInfo = denyDerivedAllowEntries.length > 0 || denyEntries.length > 0

  if (!hasAllowPatterns && !hasDenyInfo) {
    return undefined
  }

  return {
    allowPatterns: hasAllowPatterns ? allAllowPatterns : [],
    denyDerivedAllowEntries,
    denyEntries,
    exemptAccounts
  }
}

/**
 * Checks whether an action matches any of the given action patterns using
 * IAM wildcard semantics.
 *
 * @param action the action being simulated (e.g., 'secretsmanager:GetSecretValue')
 * @param patterns the action patterns from a deny statement
 * @returns true if the action matches at least one pattern
 */
function actionMatchesAnyPattern(action: string, patterns: string[]): boolean {
  return patterns.some((pattern) => actionMatchesPattern(action, pattern))
}

/**
 * Tests whether a principal ARN passes the PrincipalArnFilter for a given action.
 *
 * Principals in the resource account or an exempt account bypass the positive
 * allow-side filtering (allow patterns and deny-derived allow entries) because
 * they may be granted access through account-level principal grants independent
 * of any PrincipalArn conditions. However, they are still subject to deny-side
 * filtering (deny entries) because an explicit deny in a resource policy applies
 * regardless of the principal's account.
 *
 * @param principal the principal ARN to test
 * @param action the action being simulated
 * @param resourceAccount the account that owns the resource being checked
 * @param filter the filter to apply
 * @returns true if the principal should be simulated, false if it can be skipped
 */
export function principalMatchesFilter(
  principal: string,
  action: string,
  resourceAccount: string,
  filter: PrincipalArnFilter
): boolean {
  const accountId = splitArnParts(principal).accountId
  const isExempt = accountId === resourceAccount || filter.exemptAccounts.has(accountId ?? '')

  // Allow patterns from Allow statements: exempt principals bypass this check
  // because they may be granted access through account-level principal grants
  // independent of any PrincipalArn conditions on wildcard statements.
  if (!isExempt && filter.allowPatterns.length > 0) {
    if (!filter.allowPatterns.some((pattern) => pattern.test(principal))) return false
  }

  // Deny-derived filtering applies to ALL principals regardless of account.
  // An explicit deny in a resource policy applies universally.

  // For each deny-derived allow entry whose actions match,
  // the principal must match at least one principal pattern
  for (const entry of filter.denyDerivedAllowEntries) {
    if (actionMatchesAnyPattern(action, entry.actionPatterns)) {
      if (!entry.principalPatterns.some((p) => p.test(principal))) return false
    }
  }

  // For each deny entry whose actions match,
  // skip if the principal matches any principal pattern
  for (const entry of filter.denyEntries) {
    if (actionMatchesAnyPattern(action, entry.actionPatterns)) {
      if (entry.principalPatterns.some((p) => p.test(principal))) return false
    }
  }

  return true
}
