import type { WhoCanAllowed, WhoCanAllowedResourcePattern } from './whoCan.js'

/**
 * Replaces the condition expressions, ignored conditions, and grant details of allowed
 * results with one normalized instance per distinct value.
 *
 * Results posted from worker threads are structured-cloned, so each result arrives with
 * its own copy of these values even when thousands of results carry identical ones. A
 * request that matches every principal in an organization can accumulate hundreds of
 * thousands of results that differ only by principal and action; normalization keeps their
 * memory proportional to the number of distinct values rather than the number of results.
 *
 * The normalized values must not be mutated after they are passed in.
 */
export class AllowedValueNormalizer {
  private readonly normalizedValues = new Map<string, unknown>()

  /**
   * Normalizes the values of an allowed result in place.
   *
   * @param allowed - The allowed result to update.
   * @returns the same allowed result, now referencing normalized values.
   */
  public normalize(allowed: WhoCanAllowed): WhoCanAllowed {
    this.normalizeFields(allowed)
    for (const pattern of allowed.allowedPatterns ?? []) {
      this.normalizeFields(pattern)
    }
    return allowed
  }

  private normalizeFields(target: WhoCanAllowed | WhoCanAllowedResourcePattern): void {
    if (target.conditions !== undefined) {
      target.conditions = this.normalizedValue(target.conditions)
    }
    if (target.ignoredConditions !== undefined) {
      target.ignoredConditions = this.normalizedValue(target.ignoredConditions)
    }
    if (target.details !== undefined) {
      target.details = this.normalizedValue(target.details)
    }
  }

  private normalizedValue<T>(value: T): T {
    const key = JSON.stringify(value)
    if (this.normalizedValues.has(key)) {
      return this.normalizedValues.get(key) as T
    }
    this.normalizedValues.set(key, value)
    return value
  }
}
