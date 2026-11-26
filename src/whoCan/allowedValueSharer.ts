import type { WhoCanAllowed, WhoCanAllowedResourcePattern } from './whoCan.js'

/**
 * Replaces the condition expressions, ignored conditions, and grant details of allowed
 * results with one shared instance per distinct value.
 *
 * Results posted from worker threads are structured-cloned, so each result arrives with
 * its own copy of these values even when thousands of results carry identical ones. A
 * request that matches every principal in an organization can accumulate hundreds of
 * thousands of results that differ only by principal and action; sharing keeps their
 * memory proportional to the number of distinct values rather than the number of results.
 *
 * The shared values must not be mutated after they are passed in.
 */
export class AllowedValueSharer {
  private readonly sharedValues = new Map<string, unknown>()

  /**
   * Shares the values of an allowed result in place.
   *
   * @param allowed - The allowed result to update.
   * @returns the same allowed result, now referencing shared values.
   */
  public share(allowed: WhoCanAllowed): WhoCanAllowed {
    this.shareFields(allowed)
    for (const pattern of allowed.allowedPatterns ?? []) {
      this.shareFields(pattern)
    }
    return allowed
  }

  private shareFields(target: WhoCanAllowed | WhoCanAllowedResourcePattern): void {
    if (target.conditions !== undefined) {
      target.conditions = this.sharedValue(target.conditions)
    }
    if (target.ignoredConditions !== undefined) {
      target.ignoredConditions = this.sharedValue(target.ignoredConditions)
    }
    if (target.details !== undefined) {
      target.details = this.sharedValue(target.details)
    }
  }

  private sharedValue<T>(value: T): T {
    const key = JSON.stringify(value)
    if (this.sharedValues.has(key)) {
      return this.sharedValues.get(key) as T
    }
    this.sharedValues.set(key, value)
    return value
  }
}
