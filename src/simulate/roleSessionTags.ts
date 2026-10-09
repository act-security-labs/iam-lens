import {
  loadPolicy,
  type Condition,
  type Statement,
  type ValidatedPolicy
} from '@actsecurity/iam-policy'
import { actionMatchesPattern } from '@actsecurity/iam-utils'

const tagSessionAction = 'sts:TagSession'
const tagKeysConditionKey = 'aws:tagkeys'
const policyVariablePattern = /\$\{[^}]+\}/

/** A tag-key value permitted by a role trust policy. */
export interface SessionTagKey {
  /** Tag-key spelling from the trust policy. */
  tagKey: string

  /** Whether the trust-policy comparison ignores case. */
  ignoreCase: boolean
}

/** Describes which tag keys a role session may supply, independently of the role's stored tags. */
export type RoleSessionTagCapability =
  { type: 'none' } | { type: 'any' } | { type: 'allowlist'; tagKeys: SessionTagKey[] }

/** No trust-policy Allow permits session tags. */
const noSessionTags: RoleSessionTagCapability = { type: 'none' }

/** At least one trust-policy Allow may permit any session-tag key. */
const anySessionTag: RoleSessionTagCapability = { type: 'any' }

/**
 * Determines which tag keys a role session may supply from the role's trust policy.
 *
 * This result intentionally does not depend on tags currently stored on the role. Deny statements
 * and conditions unrelated to `aws:TagKeys` are ignored. Supported
 * `ForAllValues:StringEquals` operators form a finite allowlist for one Allow statement, while
 * `ForAnyValue`, unsupported operators, and policy-variable values conservatively permit any key.
 *
 * @param trustPolicy the role's validated trust policy, or undefined when it was not collected
 * @returns the role's session-tag key capability
 */
export function roleSessionTagCapability(
  trustPolicy: ValidatedPolicy<{ name: string }> | undefined
): RoleSessionTagCapability {
  if (!trustPolicy) {
    return noSessionTags
  }
  if (trustPolicy.errors.length > 0) {
    return anySessionTag
  }

  const allowedTagKeys: SessionTagKey[] = []
  let hasTagSessionAllow = false
  for (const statement of loadPolicy(trustPolicy).statements()) {
    if (!statement.isAllow() || !statementAllowsTagSession(statement)) {
      continue
    }

    hasTagSessionAllow = true
    const statementCapability = tagCapabilityForStatement(statement)
    if (statementCapability.type === 'any') {
      return anySessionTag
    }
    if (statementCapability.type === 'allowlist') {
      allowedTagKeys.push(...statementCapability.tagKeys)
    }
  }

  if (!hasTagSessionAllow) {
    return noSessionTags
  }

  return {
    type: 'allowlist',
    tagKeys: uniqueTagKeys(allowedTagKeys)
  }
}

/**
 * Determines whether a tag key can be supplied by a role session.
 *
 * @param capability the trust-policy-derived session-tag capability
 * @param tagKey the tag key to test
 * @returns true when a role session may supply the key
 */
export function roleSessionCanSetTagKey(
  capability: RoleSessionTagCapability,
  tagKey: string
): boolean {
  if (capability.type === 'any') {
    return true
  }
  if (capability.type === 'none') {
    return false
  }

  return capability.tagKeys.some((entry) => tagKeyMatchesEntry(tagKey, entry))
}

/**
 * Builds a slash-delimited regex constraint for PrincipalTag keys that cannot be session supplied.
 *
 * The iam-simulate constraint matcher is case-insensitive. Consequently, case variants of a
 * case-sensitive allowlist entry are also excluded from this strict pattern. That may preserve
 * extra conditional results, but it cannot incorrectly make a mutable tag strict.
 *
 * @param capability the trust-policy-derived session-tag capability
 * @returns a strict PrincipalTag pattern, or undefined when every tag key may be supplied
 */
export function immutablePrincipalTagPattern(
  capability: RoleSessionTagCapability
): string | undefined {
  if (capability.type === 'any') {
    return undefined
  }
  if (capability.type === 'none' || capability.tagKeys.length === 0) {
    return '/^aws:PrincipalTag\/.*/'
  }

  const mutableNames = capability.tagKeys.map((entry) => escapeRegex(entry.tagKey)).join('|')
  return `/^aws:PrincipalTag\\/(?!(?:${mutableNames})$).*/`
}

/**
 * Determines whether an Allow statement's Action or NotAction includes `sts:TagSession`.
 *
 * @param statement the parsed trust-policy statement to inspect
 * @returns true when the statement applies to the TagSession action
 */
function statementAllowsTagSession(statement: Statement): boolean {
  if (statement.isActionStatement()) {
    return statement
      .actions()
      .some((action) => actionMatchesPattern(tagSessionAction, action.value()))
  }

  if (statement.isNotActionStatement()) {
    return !statement
      .notActions()
      .some((action) => actionMatchesPattern(tagSessionAction, action.value()))
  }

  return false
}

/**
 * Determines which tag keys one TagSession Allow statement may supply.
 *
 * @param statement a parsed Allow statement that includes TagSession
 * @returns the statement's session-tag capability
 */
function tagCapabilityForStatement(statement: Statement): RoleSessionTagCapability {
  const tagKeysConditions = statement
    .conditions()
    .filter((condition) => stringsEqualIgnoreCase(condition.conditionKey(), tagKeysConditionKey))

  if (tagKeysConditions.length === 0 || tagKeysConditions.some(conditionIsUnbounded)) {
    return anySessionTag
  }

  return {
    type: 'allowlist',
    tagKeys: intersectTagKeyConditions(tagKeysConditions)
  }
}

/**
 * Determines whether a TagKeys condition cannot prove a finite exhaustive key allowlist.
 *
 * @param condition the parsed `aws:TagKeys` condition
 * @returns true when the statement must conservatively be treated as permitting any key
 */
function conditionIsUnbounded(condition: Condition): boolean {
  const operation = condition.operation()
  if (operation.isIfExists() || operation.setOperator() !== 'ForAllValues') {
    return true
  }

  const baseOperator = operation.baseOperator()
  if (
    !stringsEqualIgnoreCase(baseOperator, 'StringEquals') &&
    !stringsEqualIgnoreCase(baseOperator, 'StringEqualsIgnoreCase')
  ) {
    return true
  }

  return condition.conditionValues().some((value) => policyVariablePattern.test(value))
}

/**
 * Intersects finite ForAllValues TagKeys allowlists within one statement.
 *
 * @param conditions supported TagKeys conditions from one statement
 * @returns tag keys capable of satisfying every condition
 */
function intersectTagKeyConditions(conditions: Condition[]): SessionTagKey[] {
  const conditionEntries = conditions.map(entriesForCondition)
  const hasCaseSensitiveCondition = conditionEntries.some((entries) =>
    entries.some((entry) => !entry.ignoreCase)
  )
  const candidates = hasCaseSensitiveCondition
    ? conditionEntries.flat().filter((entry) => !entry.ignoreCase)
    : conditionEntries[0]

  return uniqueTagKeys(
    candidates.filter((candidate) =>
      conditionEntries.every((entries) =>
        entries.some((entry) => tagKeyMatchesEntry(candidate.tagKey, entry))
      )
    )
  )
}

/**
 * Converts one supported TagKeys condition into comparable entries.
 *
 * @param condition the parsed supported condition
 * @returns entries carrying the condition's case-comparison semantics
 */
function entriesForCondition(condition: Condition): SessionTagKey[] {
  const ignoreCase = stringsEqualIgnoreCase(
    condition.operation().baseOperator(),
    'StringEqualsIgnoreCase'
  )
  return condition.conditionValues().map((tagKey) => ({ tagKey, ignoreCase }))
}

/**
 * Tests a concrete tag key against a trust-policy allowlist entry.
 *
 * @param tagKey the concrete tag key
 * @param entry the allowlist entry and its comparison semantics
 * @returns true when the key matches the entry
 */
function tagKeyMatchesEntry(tagKey: string, entry: SessionTagKey): boolean {
  return entry.ignoreCase ? stringsEqualIgnoreCase(tagKey, entry.tagKey) : tagKey === entry.tagKey
}

/**
 * Removes semantically duplicate tag-key entries while preserving case-sensitive alternatives.
 *
 * @param entries tag-key entries to deduplicate
 * @returns unique entries
 */
function uniqueTagKeys(entries: SessionTagKey[]): SessionTagKey[] {
  const unique: SessionTagKey[] = []
  for (const entry of entries) {
    if (
      !unique.some(
        (existing) =>
          existing.ignoreCase === entry.ignoreCase &&
          (entry.ignoreCase
            ? stringsEqualIgnoreCase(existing.tagKey, entry.tagKey)
            : existing.tagKey === entry.tagKey)
      )
    ) {
      unique.push(entry)
    }
  }
  return unique
}

/**
 * Compares strings without case sensitivity or normalized string allocations.
 *
 * @param left first value to compare
 * @param right second value to compare
 * @returns true when the values compare equally without case sensitivity
 */
function stringsEqualIgnoreCase(left: string, right: string): boolean {
  return left.localeCompare(right, undefined, { sensitivity: 'base' }) === 0
}

/**
 * Escapes a literal string for use inside a regular expression.
 *
 * @param value the literal value to escape
 * @returns a regex-safe representation
 */
function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
