import { equalsIgnoreCase } from '@actsecurity/iam-utils'
import {
  intersectPrincipalConstraints,
  normalizePrincipalConstraint,
  principalArgsForConstraint,
  principalConstraintsOverlap,
  principalIncludes,
  subtractPrincipalConstraint,
  unionPrincipalConstraints,
  type PermissionPrincipals,
  type PrincipalConstraint
} from './principalConstraints.js'

export type { PermissionPrincipals, PermissionPrincipalType } from './principalConstraints.js'

export type PermissionEffect = 'Allow' | 'Deny'

export type PermissionConditions = Record<string, Record<string, string[]>>

/**
 * Convert an AWS wildcard ARN pattern (e.g. "arn:aws:s3:::bucket/*") into a RegExp.
 */
function wildcardToRegex(pattern: string): RegExp {
  const parts = pattern.split('*').map((s) => s.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&'))
  return new RegExp('^' + parts.join('.*') + '$')
}

/**
 * An immutable representation of a single permission for a specific action.
 *
 * This will eventually have methods like "merge with another permission",
 * "check if overlaps with another permission", "subtract a deny permission",
 * etc and those will all return a new Permission instance.
 */
export class Permission {
  constructor(
    public readonly effect: PermissionEffect,
    public readonly service: string,
    public readonly action: string,
    public readonly resource: string[] | undefined,
    public readonly notResource: string[] | undefined,
    public readonly conditions: Record<string, Record<string, string[]>> | undefined,
    public readonly principal: PermissionPrincipals | undefined = undefined,
    public readonly notPrincipal: PermissionPrincipals | undefined = undefined
  ) {
    if (resource !== undefined && notResource !== undefined) {
      throw new Error('Permission must have a resource or notResource, not both.')
    } else if (resource === undefined && notResource === undefined) {
      throw new Error('Permission must have a resource or notResource, one must be defined.')
    }
    normalizePrincipalConstraint(principal, notPrincipal)
  }

  /**
   * Return this permission's principal constraint normalized for set algebra.
   *
   * @returns The normalized principal constraint.
   */
  public principalConstraint(): PrincipalConstraint {
    return normalizePrincipalConstraint(this.principal, this.notPrincipal)
  }

  /**
   * Returns true if this Permission completely includes the other Permission.
   * Only supports merging of "Allow" permissions (same effect, service, action).
   */
  public includes(other: Permission): boolean {
    // 1. Effects, service, and action must match
    if (
      this.effect !== other.effect ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      return false
    }

    if (!principalIncludes(this.principalConstraint(), other.principalConstraint())) {
      return false
    }

    // 2. Conditions: every condition in this must be implied by the other permission’s conditions
    //    That is, for each operator and context key in this.conditions, other.conditions must have it,
    //    and the values must satisfy inclusion logic per operator.
    const condsA = normalizeConditionKeys(this.conditions || {})
    const condsB = normalizeConditionKeys(other.conditions || {})
    for (const op of Object.keys(condsA)) {
      if (!(op in condsB)) return false
      const keysA = Object.keys(condsA[op])
      const keysB = Object.keys(condsB[op])
      // Every key in A must appear in B
      for (const key of keysA) {
        if (!keysB.includes(key)) return false
        const valsA = condsA[op][key]
        const valsB = condsB[op][key]
        const baseOp = conditionBaseOperator(op)
        switch (baseOp) {
          case 'stringequals':
          case 'stringlike':
          case 'arnequals':
          case 'arnlike':
            // other must be at least as restrictive: B_vals ⊆ A_vals
            if (!valsB.every((v) => valsA.includes(v))) return false
            break
          case 'stringnotequals':
          case 'stringnotlike':
          case 'arnnotequals':
          case 'arnnotlike':
            // other must exclude at least what A excludes: A_vals ⊆ B_vals
            if (!valsA.every((v) => valsB.includes(v))) return false
            break
          case 'numericlessthan':
          case 'numericlessthanequals':
            // other boundary <= this boundary
            const numA = Number(valsA[0])
            const numB = Number(valsB[0])
            if (isNaN(numA) || isNaN(numB)) return false
            if (numB > numA) return false
            break
          case 'numericgreaterthan':
          case 'numericgreaterthanequals':
            // other boundary >= this boundary
            const ngA = Number(valsA[0])
            const ngB = Number(valsB[0])
            if (isNaN(ngA) || isNaN(ngB)) return false
            if (ngB < ngA) return false
            break
          case 'bool':
            // other must have the same boolean value
            if (valsA[0] !== valsB[0]) return false
            break
          case 'ipaddress':
          case 'notipaddress':
            // every CIDR in B must be contained in some CIDR in A
            for (const cidrB of valsB) {
              if (!valsA.some((cidrA) => cidrA === cidrB)) {
                return false
              }
            }
            break
          case 'datelessthan':
          case 'datelessthanequals':
            // other date <= this date lexically (ISO)
            const dA = valsA[0]
            const dB = valsB[0]
            if (dB > dA) return false
            break
          case 'dategreaterthan':
          case 'dategreaterthanequals':
            // other date >= this date
            const dgA = valsA[0]
            const dgB = valsB[0]
            if (dgB < dgA) return false
            break
          default:
            return false
        }
      }
    }

    // 3. Resources / NotResources

    const thisResource = this.resource
    const thisNotResource = this.notResource
    const otherResource = other.resource
    const otherNotResource = other.notResource

    // 3a. If both have resource[]
    if (thisResource !== undefined && otherResource !== undefined) {
      return otherResource.every((r2) => thisResource.some((r1) => wildcardToRegex(r1).test(r2)))
    }
    // 3b. Both have notResource[]
    if (thisNotResource !== undefined && otherNotResource !== undefined) {
      return thisNotResource.every((n1) =>
        otherNotResource.some((n2) => wildcardToRegex(n1).test(n2))
      )
    }

    // 3c. A.resource & B.notResource -> B allows almost all, A allows only R1 -> true iff every N2 is matched by some R1
    if (thisResource !== undefined && otherNotResource !== undefined) {
      return otherNotResource.every((n2) => thisResource.some((r1) => wildcardToRegex(r1).test(n2)))
    }

    // 3d. A.notResource & B.resource -> every r2 ∉ N1
    if (thisNotResource !== undefined && otherResource !== undefined) {
      return otherResource.every(
        (r2) => !thisNotResource.some((n1) => wildcardToRegex(n1).test(r2))
      )
    }
    return false
  }

  /**
   * Returns the union of this Permission with another.
   * If one includes the other, return the including Permission.
   * Otherwise, attempt to merge conditions and resource/notResource.
   * If merge yields a single Permission, return it; else return both.
   */
  public union(other: Permission): Permission[] {
    // 1. Ensure same effect, service, and action
    if (
      this.effect !== other.effect ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      return [this, other]
    }

    // 2. If one includes the other, return the including one
    if (this.includes(other)) {
      return [this]
    }
    if (other.includes(this)) {
      return [other]
    }

    // 3. Attempt to combine conditions
    const condsA = this.conditions || {}
    const condsB = other.conditions || {}
    const mergedConds = unionConditions(condsA, condsB)
    if (mergedConds === null) {
      return [this, other]
    }

    const principalUnions = unionPrincipalConstraints(
      this.principalConstraint(),
      other.principalConstraint()
    )
    if (principalUnions.length !== 1) {
      return [this, other]
    }
    const principalArgs = principalArgsForConstraint(principalUnions[0])

    // 4. Combine resource/notResource (constructor enforces exclusivity)
    const thisResource = this.resource
    const thisNotResource = this.notResource
    const otherResource = other.resource
    const otherNotResource = other.notResource
    const eff = this.effect
    const svc = this.service
    const act = this.action
    const conds = Object.keys(mergedConds).length > 0 ? mergedConds : undefined

    // Both have resource[]
    if (thisResource !== undefined && otherResource !== undefined) {
      const union = Array.from(new Set([...thisResource, ...otherResource]))
      return [
        new Permission(
          eff,
          svc,
          act,
          union,
          undefined,
          conds,
          principalArgs.principal,
          principalArgs.notPrincipal
        )
      ]
    }
    // Both have notResource[]
    if (thisNotResource !== undefined && otherNotResource !== undefined) {
      // Intersection of both notResource arrays
      const intersection = thisNotResource.filter((n) => otherNotResource.includes(n))
      return [
        new Permission(
          eff,
          svc,
          act,
          undefined,
          intersection,
          conds,
          principalArgs.principal,
          principalArgs.notPrincipal
        )
      ]
    }
    // One has resource, other has notResource
    if (thisResource !== undefined && otherNotResource !== undefined) {
      return [
        new Permission(
          eff,
          svc,
          act,
          thisResource,
          undefined,
          conds,
          principalArgs.principal,
          principalArgs.notPrincipal
        ),
        new Permission(
          eff,
          svc,
          act,
          undefined,
          otherNotResource,
          conds,
          principalArgs.principal,
          principalArgs.notPrincipal
        )
      ]
    }
    if (otherResource !== undefined && thisNotResource !== undefined) {
      return [
        new Permission(
          eff,
          svc,
          act,
          otherResource,
          undefined,
          conds,
          principalArgs.principal,
          principalArgs.notPrincipal
        ),
        new Permission(
          eff,
          svc,
          act,
          undefined,
          thisNotResource,
          conds,
          principalArgs.principal,
          principalArgs.notPrincipal
        )
      ]
    }

    // Otherwise cannot combine, return both
    return [this, other]
  }

  /**
   * Returns all representable intersections of this Permission with another.
   *
   * @param other The other Permission to intersect with.
   * @returns New Permissions representing the overlap, or an empty array if there is no intersection.
   */
  public intersections(other: Permission): Permission[] {
    const principalIntersections = intersectPrincipalConstraints(
      this.principalConstraint(),
      other.principalConstraint()
    )
    const results: Permission[] = []

    for (const principalIntersection of principalIntersections) {
      const principalArgs = principalArgsForConstraint(principalIntersection)
      const permissionWithIntersectionPrincipal = new Permission(
        this.effect,
        this.service,
        this.action,
        this.resource,
        this.notResource,
        this.conditions,
        principalArgs.principal,
        principalArgs.notPrincipal
      )
      const intersection = permissionWithIntersectionPrincipal.intersection(other)
      if (intersection) {
        results.push(intersection)
      }
    }

    return results
  }

  /**
   * Returns one intersection of this Permission with another.
   *
   * Prefer {@link intersections} when correctness depends on all possible overlaps. This
   * compatibility method returns at most one Permission and may omit additional representable
   * intersections if future principal algebra produces multiple principal residuals.
   *
   * @param other The other Permission to intersect with.
   * @returns A new Permission representing one intersection of other and this, or undefined if there is no intersection.
   */
  public intersection(other: Permission): Permission | undefined {
    // 1. Must match effect, service, and action
    if (
      this.effect !== other.effect ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      // No overlap at all—return a "zero-resource" permission
      return undefined
    }

    const principalIntersections = intersectPrincipalConstraints(
      this.principalConstraint(),
      other.principalConstraint()
    )
    if (principalIntersections.length === 0) {
      return undefined
    }
    const principalArgs = principalArgsForConstraint(principalIntersections[0])

    if (this.resource != undefined && other.resource != undefined) {
      // 2. If one includes the other, return the narrower one unless both are NotResource
      if (this.includes(other)) {
        return other
      }
      if (other.includes(this)) {
        return this
      }
    }

    // 3. Attempt to intersect/merge conditions
    const a = normalizeConditionKeys(this.conditions || {})
    const b = normalizeConditionKeys(other.conditions || {})
    const allOps = Array.from(new Set([...Object.keys(a), ...Object.keys(b)]))
    const intersectedConds: PermissionConditions = {}

    for (const op of allOps) {
      const condA = a[op] || {}
      const condB = b[op] || {}
      const allKeys = Array.from(new Set([...Object.keys(condA), ...Object.keys(condB)]))
      intersectedConds[op] = {}

      for (const key of allKeys) {
        const valsA = condA[key] || []
        const valsB = condB[key] || []

        // If key appears in both, intersect or combine based on operator
        if (key in condA && key in condB) {
          switch (conditionBaseOperator(op)) {
            case 'stringequals':
            case 'stringlike':
            case 'arnequals':
            case 'arnlike': {
              // Intersection of string lists
              const common = valsA.filter((v) => valsB.includes(v))
              if (common.length === 0) {
                return undefined
              }
              intersectedConds[op][key] = common
              break
            }
            case 'stringnotequals':
            case 'stringnotlike':
            case 'arnnotequals':
            case 'arnnotlike': {
              // Union of exclusions
              intersectedConds[op][key] = Array.from(new Set([...valsA, ...valsB]))
              break
            }
            case 'numericlessthan':
            case 'numericlessthanequals': {
              const numA = Number(valsA[0])
              const numB = Number(valsB[0])
              if (isNaN(numA) || isNaN(numB)) {
                return undefined
              }
              const boundary = Math.min(numA, numB)
              intersectedConds[op][key] = [String(boundary)]
              break
            }
            case 'numericgreaterthan':
            case 'numericgreaterthanequals': {
              const ngA = Number(valsA[0])
              const ngB = Number(valsB[0])
              if (isNaN(ngA) || isNaN(ngB)) {
                return undefined
              }
              const boundary = Math.max(ngA, ngB)
              intersectedConds[op][key] = [String(boundary)]
              break
            }
            case 'bool': {
              if (valsA[0] !== valsB[0]) {
                return undefined
              }
              intersectedConds[op][key] = [valsA[0]]
              break
            }
            case 'ipaddress':
            case 'notipaddress': {
              const common = valsA.filter((cidr) => valsB.includes(cidr))
              if (common.length === 0) {
                return undefined
              }
              intersectedConds[op][key] = common
              break
            }
            case 'datelessthan':
            case 'datelessthanequals': {
              const dA = valsA[0]
              const dB = valsB[0]
              intersectedConds[op][key] = [dA < dB ? dA : dB]
              break
            }
            case 'dategreaterthan':
            case 'dategreaterthanequals': {
              const dgA = valsA[0]
              const dgB = valsB[0]
              intersectedConds[op][key] = [dgA > dgB ? dgA : dgB]
              break
            }
            default:
              return undefined
          }
        } else {
          // Key only in one side: carry it through
          intersectedConds[op][key] = key in condA ? Array.from(valsA) : Array.from(valsB)
        }
      }
    }

    // 4. Combine resource/notResource:
    const thisResource = this.resource
    const thisNotResource = this.notResource
    const otherResource = other.resource
    const otherNotResource = other.notResource
    const eff = this.effect
    const svc = this.service
    const act = this.action
    const conds = Object.keys(intersectedConds).length > 0 ? intersectedConds : undefined

    // Both have resource[] => intersect patterns
    if (thisResource !== undefined && otherResource !== undefined) {
      // Keep any R1 that matches something in R2, and any R2 that matches something in R1
      const part1 = thisResource.filter((r1) =>
        otherResource.some((r2) => wildcardToRegex(r2).test(r1))
      )
      const part2 = otherResource.filter((r2) =>
        thisResource.some((r1) => wildcardToRegex(r1).test(r2))
      )
      const intersectR = Array.from(new Set([...part1, ...part2]))
      if (intersectR.length === 0) {
        return undefined
      }
      return new Permission(
        eff,
        svc,
        act,
        intersectR,
        undefined,
        conds,
        principalArgs.principal,
        principalArgs.notPrincipal
      )
    }

    // Both have notResource[] => union of exclusions (more restrictive), but remove subsumed patterns
    if (thisNotResource !== undefined && otherNotResource !== undefined) {
      // Compute union of both exclusion lists
      const combined = Array.from(new Set([...thisNotResource, ...otherNotResource]))
      // Remove any pattern that is subsumed by a more general pattern
      const filtered = combined.filter(
        (pat) =>
          !combined.some((otherPat) => otherPat !== pat && wildcardToRegex(otherPat).test(pat))
      )
      return new Permission(
        eff,
        svc,
        act,
        undefined,
        filtered,
        conds,
        principalArgs.principal,
        principalArgs.notPrincipal
      )
    }

    // One has resource, other has notResource

    const resource = thisResource || otherResource
    const notResource = thisNotResource || otherNotResource
    if (resource !== undefined || notResource !== undefined) {
      const filtered = resource!.filter(
        (r1) => !notResource!.some((n2) => wildcardToRegex(n2).test(r1))
      )
      if (filtered.length === 0) {
        return undefined
      }
      return new Permission(
        eff,
        svc,
        act,
        filtered,
        undefined,
        conds,
        principalArgs.principal,
        principalArgs.notPrincipal
      )
    }

    // This should never happen
    return undefined
  }

  /**
   * Subtract a Deny permission from this Allow permission.
   *
   * Returns the resulting permissions, this can be:
   * - An empty array if the Allow is fully denied by the Deny
   * - A modified Allow permission or multiple Allow permissions
   * - It could also return the original Allow and Deny permission if subtraction cannot be expressed purely in Allow statements
   *
   * @param other the Deny permission to subtract
   */
  public subtract(other: Permission): Permission[] {
    // Only subtract Deny from Allow for the same service/action
    if (
      this.effect !== 'Allow' ||
      other.effect !== 'Deny' ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      // No subtraction applies
      return [this]
    }

    const allowCondsNorm = normalizeConditionKeys(this.conditions || {})
    const denyCondsNorm = normalizeConditionKeys(other.conditions || {})
    const conditionsMatch = JSON.stringify(allowCondsNorm) === JSON.stringify(denyCondsNorm)
    const allowPrincipalConstraint = this.principalConstraint()
    const denyPrincipalConstraint = other.principalConstraint()
    if (!principalConstraintsOverlap(allowPrincipalConstraint, denyPrincipalConstraint)) {
      return [this]
    }

    const allowResource = this.resource
    const allowNotResource = this.notResource
    const denyResource = other.resource
    const denyNotResource = other.notResource

    const eff = this.effect
    const svc = this.service
    const act = this.action
    const principalResiduals = subtractPrincipalConstraint(
      allowPrincipalConstraint,
      denyPrincipalConstraint
    )
    const sameResourceShape =
      JSON.stringify([...(allowResource ?? [])].sort()) ===
        JSON.stringify([...(denyResource ?? [])].sort()) &&
      JSON.stringify([...(allowNotResource ?? [])].sort()) ===
        JSON.stringify([...(denyNotResource ?? [])].sort())
    const denyFullyCoversPrincipal = principalIncludes(
      denyPrincipalConstraint,
      allowPrincipalConstraint
    )
    const allowPrincipalArgs = principalArgsForConstraint(allowPrincipalConstraint)
    const denyPrincipalArgs = principalArgsForConstraint(denyPrincipalConstraint)

    if (!denyFullyCoversPrincipal && sameResourceShape && conditionsMatch) {
      const principalResidualsEqualAllow =
        principalResiduals.length === 1 &&
        JSON.stringify(principalArgsForConstraint(principalResiduals[0])) ===
          JSON.stringify(allowPrincipalArgs)
      if (principalResidualsEqualAllow) {
        return [this, other]
      }

      return principalResiduals.map((constraint) => {
        const args = principalArgsForConstraint(constraint)
        return new Permission(
          eff,
          svc,
          act,
          allowResource,
          allowNotResource,
          this.conditions,
          args.principal,
          args.notPrincipal
        )
      })
    }

    if (!denyFullyCoversPrincipal) {
      return [this, other]
    }

    // Case: Allow.resource & Deny.resource
    if (allowResource !== undefined && denyResource !== undefined) {
      const overlappingResources = allowResource.some((a) => {
        return denyResource.some((d) => {
          return wildcardToRegex(d).test(a) || wildcardToRegex(a).test(d)
        })
      })

      // If the resources in the allow and deny do not overlap, return the allow as is
      if (!overlappingResources) {
        return [this]
      }

      // Categories for allows, a single allow could be more than one, because the deny could have multiple
      // Without Conditions:
      //1. Exactly the same as a deny - remove the allow
      //2. A subset of a deny - remove the allow
      //3. A superset of a deny - keep the allow and the deny
      //4. No overlap with any deny - keep the allow as is
      //
      // With Conditions:
      //1. Exactly the same as a deny - invert the conditions and keep the allow
      //2. A subset of a deny - invert the conditions and keep the allow
      //3. A superset of a deny - keep the allow and the deny
      //4. No overlap with any deny - keep the allow as is

      const allowMatches: string[] = []
      const allowSubsets: string[] = []
      const allowSupersets: string[] = []
      const allowNoOverlap: string[] = []
      const denySubsets: string[] = []
      for (const allowedResource of allowResource) {
        let isMatch = false
        let isSubset = false
        let isSuperset = false
        for (const deniedResource of denyResource) {
          if (deniedResource === allowedResource) {
            isMatch = true
            break
          }
          if (wildcardToRegex(deniedResource).test(allowedResource)) {
            isSubset = true
            break
          }
          if (wildcardToRegex(allowedResource).test(deniedResource)) {
            isSuperset = true
            denySubsets.push(deniedResource)
          }
        }

        if (isMatch) {
          allowMatches.push(allowedResource)
        } else if (isSubset) {
          allowSubsets.push(allowedResource)
        } else if (isSuperset) {
          allowSupersets.push(allowedResource)
        } else {
          allowNoOverlap.push(allowedResource)
        }
      }

      const permissionsToReturn: Permission[] = []
      if (allowNoOverlap.length > 0) {
        permissionsToReturn.push(
          new Permission(
            eff,
            svc,
            act,
            allowNoOverlap,
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        )
      }
      if (allowSupersets.length > 0) {
        permissionsToReturn.push(
          new Permission(
            eff,
            svc,
            act,
            allowSupersets,
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        )
      }
      if (allowMatches.length > 0 || allowSubsets.length > 0) {
        // If conditions are identical, these are fully dropped from the Allow. If not, they need to be kept with inverted conditions
        if (!conditionsMatch) {
          const newAllow = new Permission(
            eff,
            svc,
            act,
            [...allowMatches, ...allowSubsets],
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
          permissionsToReturn.push(...applyDenyConditionsToAllow(newAllow, other))
        }
      }
      if (denySubsets.length > 0) {
        permissionsToReturn.push(
          new Permission(
            'Deny',
            svc,
            act,
            denySubsets,
            undefined,
            other.conditions,
            denyPrincipalArgs.principal,
            denyPrincipalArgs.notPrincipal
          )
        )
      }
      return permissionsToReturn
    }

    // Case: Allow.resource & Deny.notResource
    // =======================================================================
    // SEMANTICS:
    //   Deny.notResource means: "deny everything EXCEPT these patterns"
    //   So the deny APPLIES to resources that do NOT match denyNotResource patterns
    //   And the deny does NOT apply to resources that DO match denyNotResource patterns
    // =======================================================================
    if (allowResource !== undefined && denyNotResource !== undefined) {
      // STEP 1: Categorize each allow resource based on relationship to denyNotResource patterns
      //
      // Categories:
      //   ExcludedFromDeny - Matches a denyNotResource pattern (deny doesn't apply to these)
      //   AffectedByDeny   - Does NOT match any denyNotResource (deny applies to these)
      //   Superset         - Covers (is broader than) a denyNotResource pattern
      //
      // Also track which denyNotResource patterns are covered by superset allow resources

      const excludedFromDeny: string[] = []
      const affectedByDeny: string[] = []
      const supersets: string[] = []
      const coveredDenyNotResourcePatterns: string[] = []

      for (const allowedResource of allowResource) {
        let isExcluded = false
        let isSuperset = false

        for (const deniedNotResource of denyNotResource) {
          // Check if allowResource exactly matches or is covered by denyNotResource pattern
          if (
            allowedResource === deniedNotResource ||
            wildcardToRegex(deniedNotResource).test(allowedResource)
          ) {
            isExcluded = true
            break
          }
          // Check if allowResource covers (is broader than) denyNotResource pattern
          if (wildcardToRegex(allowedResource).test(deniedNotResource)) {
            isSuperset = true
            if (!coveredDenyNotResourcePatterns.includes(deniedNotResource)) {
              coveredDenyNotResourcePatterns.push(deniedNotResource)
            }
          }
        }

        if (isExcluded) {
          excludedFromDeny.push(allowedResource)
        } else if (isSuperset) {
          supersets.push(allowedResource)
        } else {
          affectedByDeny.push(allowedResource)
        }
      }

      // STEP 2: Early exit - if all allow resources are excluded from deny, return unchanged
      if (excludedFromDeny.length === allowResource.length) {
        return [this]
      }

      const denyHasConditions = other.conditions && Object.keys(other.conditions).length > 0

      // STEP 3: Build output permissions by category
      const permissionsToReturn: Permission[] = []

      // ExcludedFromDeny: Keep as-is with original conditions (deny doesn't touch these)
      if (excludedFromDeny.length > 0) {
        permissionsToReturn.push(
          new Permission(
            eff,
            svc,
            act,
            excludedFromDeny,
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        )
      }

      // Superset: Allow resource is broader than denyNotResource patterns
      // - The covered denyNotResource patterns are excluded from deny (allow unconditionally)
      // - The superset allow resources are affected by deny (apply inverted conditions)
      if (supersets.length > 0) {
        // First: Allow the covered patterns unconditionally (they're excluded from deny)
        if (coveredDenyNotResourcePatterns.length > 0) {
          permissionsToReturn.push(
            new Permission(
              eff,
              svc,
              act,
              coveredDenyNotResourcePatterns,
              undefined,
              this.conditions,
              allowPrincipalArgs.principal,
              allowPrincipalArgs.notPrincipal
            )
          )
        }

        // Second: Apply inverted deny conditions to the superset resources
        if (denyHasConditions && !conditionsMatch) {
          const supersetAllow = new Permission(
            eff,
            svc,
            act,
            supersets,
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
          permissionsToReturn.push(...applyDenyConditionsToAllow(supersetAllow, other))
        }
        // If no conditions or conditions match, the superset is fully denied (nothing to add)
      }

      // AffectedByDeny: These resources are hit by the deny
      if (affectedByDeny.length > 0) {
        // If there are no conditions on deny - these are fully denied (drop them)
        // If the conditions match - these are fully denied (drop them)
        if (denyHasConditions && !conditionsMatch) {
          // Different conditions - keep with inverted deny conditions
          const newAllow = new Permission(
            eff,
            svc,
            act,
            affectedByDeny,
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
          permissionsToReturn.push(...applyDenyConditionsToAllow(newAllow, other))
        }
      }

      return permissionsToReturn
    }

    // Scenario 3: Allow.notResource & Deny.resource
    if (allowNotResource !== undefined && denyResource !== undefined) {
      // STEP 1: Categorize relationships and track which denyResources are already covered
      const coveredDenyResources = new Set<string>() // denyResources already excluded by allowNotResource
      const uncoveredDenyResources: string[] = [] // denyResources that affect allowed resources
      const subsetReplacements: { allowPattern: string; denyPattern: string }[] = []

      // For each denyResource, check if it's covered by any allowNotResource
      for (const denyPattern of denyResource) {
        let isCovered = false
        for (const allowPattern of allowNotResource) {
          // ExactMatch or Superset - denyResource is already excluded
          if (allowPattern === denyPattern || wildcardToRegex(allowPattern).test(denyPattern)) {
            isCovered = true
            coveredDenyResources.add(denyPattern)
            break
          }
        }
        if (!isCovered) {
          uncoveredDenyResources.push(denyPattern)
        }
      }

      // Check for Subset patterns (denyResource covers allowNotResource)
      for (const allowPattern of allowNotResource) {
        for (const denyPattern of denyResource) {
          if (wildcardToRegex(denyPattern).test(allowPattern) && allowPattern !== denyPattern) {
            subsetReplacements.push({ allowPattern, denyPattern })
          }
        }
      }

      // Filter out subset deny patterns from uncoveredDenyResources to get true NoOverlap patterns
      const subsetDenyPatternsSet = new Set(subsetReplacements.map((s) => s.denyPattern))
      const noOverlapDenyResources = uncoveredDenyResources.filter(
        (dr) => !subsetDenyPatternsSet.has(dr)
      )

      // STEP 2: If all denyResources are covered, deny has no effect
      if (noOverlapDenyResources.length === 0 && subsetReplacements.length === 0) {
        return [this]
      }

      // STEP 3: Build output permissions
      const denyHasConditions = other.conditions && Object.keys(other.conditions).length > 0

      // Build the expanded notResource (original + noOverlap deny resources + subset replacements)
      const subsetAllowPatterns = new Set(subsetReplacements.map((s) => s.allowPattern))
      const keptPatterns = allowNotResource.filter((p) => !subsetAllowPatterns.has(p))
      const subsetDenyPatterns = Array.from(new Set(subsetReplacements.map((s) => s.denyPattern)))
      const expandedNotResource = Array.from(
        new Set([...keptPatterns, ...subsetDenyPatterns, ...noOverlapDenyResources])
      )

      // Same conditions or no deny conditions: simply expand notResource
      if (conditionsMatch || !denyHasConditions) {
        return [
          new Permission(
            eff,
            svc,
            act,
            undefined,
            expandedNotResource,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        ]
      }

      // Different conditions: handle Subset and NoOverlap cases separately
      const permissionsToReturn: Permission[] = []
      const hasSubsetReplacements = subsetReplacements.length > 0
      const hasNoOverlapAdditions = noOverlapDenyResources.length > 0

      // Part 1: Original allowNotResource with inverted deny conditions
      // (when deny condition is NOT met, original allow applies)
      const originalAllow = new Permission(
        eff,
        svc,
        act,
        undefined,
        allowNotResource,
        this.conditions,
        allowPrincipalArgs.principal,
        allowPrincipalArgs.notPrincipal
      )
      permissionsToReturn.push(...applyDenyConditionsToAllow(originalAllow, other))

      // Part 2a: For SUBSET replacements - expanded notResource WITH deny conditions
      // (replacing smaller exclusion with larger one, only valid when condition is met)
      if (hasSubsetReplacements) {
        // Build notResource with just the subset replacements (not the noOverlap additions)
        const subsetExpandedNotResource = Array.from(
          new Set([...keptPatterns, ...subsetDenyPatterns])
        )
        const subsetConditions = intersectConditions(this.conditions || {}, other.conditions || {})
        permissionsToReturn.push(
          new Permission(
            eff,
            svc,
            act,
            undefined,
            subsetExpandedNotResource,
            subsetConditions || other.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        )
      }

      // Part 2b: For NO OVERLAP additions - expanded notResource WITHOUT conditions
      // (adding new exclusion is always safe, no condition needed)
      if (hasNoOverlapAdditions) {
        permissionsToReturn.push(
          new Permission(
            eff,
            svc,
            act,
            undefined,
            expandedNotResource,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        )
      }

      return permissionsToReturn
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SCENARIO 4: Allow.NotResource & Deny.NotResource
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Semantics:
    //   Allow.notResource = [A]: allow ALL resources EXCEPT those matching A
    //   Deny.notResource  = [D]: deny  ALL resources EXCEPT those matching D
    //
    // The deny blocks everything except D (the "safe zone").
    // The allow permits everything except A.
    //
    // Surviving resources = (allowed) ∩ (not denied)
    //                     = (NOT in A) ∩ (in D)
    //                     = resources in D that are not covered by A
    //
    // Result: resource: [D patterns not covered by A]
    //
    // ═══════════════════════════════════════════════════════════════════════════
    if (allowNotResource !== undefined && denyNotResource !== undefined) {
      const denyHasConditions = other.conditions && Object.keys(other.conditions).length > 0

      // Helper: Check if pattern A covers pattern B (A is superset of or equal to B)
      const patternCovers = (a: string, b: string): boolean => {
        return a === b || wildcardToRegex(a).test(b)
      }

      // Find D patterns that survive (not covered by any A pattern)
      // These are the resources that are both allowed AND protected from deny
      const survivingResources = denyNotResource.filter(
        (dPattern) => !allowNotResource.some((aPattern) => patternCovers(aPattern, dPattern))
      )

      // If nothing survives, return empty
      if (survivingResources.length === 0) {
        return []
      }

      // Handle conditions
      if (!denyHasConditions || conditionsMatch) {
        // No deny conditions or same conditions: apply directly
        return [
          new Permission(
            eff,
            svc,
            act,
            survivingResources,
            undefined,
            this.conditions,
            allowPrincipalArgs.principal,
            allowPrincipalArgs.notPrincipal
          )
        ]
      }

      // Different conditions: split into two parts
      const permissionsToReturn: Permission[] = []

      // Part 1: When deny condition is NOT met → original allow applies
      const originalAllow = new Permission(
        eff,
        svc,
        act,
        undefined,
        allowNotResource,
        this.conditions,
        allowPrincipalArgs.principal,
        allowPrincipalArgs.notPrincipal
      )
      permissionsToReturn.push(...applyDenyConditionsToAllow(originalAllow, other))

      // Part 2: When deny condition IS met → surviving resources with deny's condition
      const denyConditionCount = Object.values(other.conditions || {}).reduce(
        (sum, keyMap) => sum + Object.keys(keyMap).length,
        0
      )
      const part2Conditions = denyConditionCount === 1 ? other.conditions : undefined
      permissionsToReturn.push(
        new Permission(
          eff,
          svc,
          act,
          survivingResources,
          undefined,
          part2Conditions,
          allowPrincipalArgs.principal,
          allowPrincipalArgs.notPrincipal
        )
      )

      return permissionsToReturn
    }

    // This should never happen
    throw new Error('Permission.subtract: This should never happen—invalid state.')
  }
}

/**
 * Attempt to union two sets of permission conditions.
 *
 * If the conditions can be merged into a single block that allows all cases allowed by either,
 * returns the merged conditions. If they cannot be merged cleanly (e.g., differing operators
 * or incompatible numeric boundaries), returns null.
 *
 * @param a First set of conditions
 * @param b Second set of conditions
 * @returns Merged conditions or null if they cannot be merged
 */
export function unionConditions(
  a: Record<string, Record<string, string[]>>,
  b: Record<string, Record<string, string[]>>
): Record<string, Record<string, string[]>> | null {
  // 1. If the set of operators in 'a' differs from the set in 'b', return null.
  a = normalizeConditionKeys(a)
  b = normalizeConditionKeys(b)
  const opsA = Object.keys(a).sort()
  const opsB = Object.keys(b).sort()
  if (JSON.stringify(opsA) !== JSON.stringify(opsB)) {
    return null
  }

  const merged: PermissionConditions = {}
  let differingEntries = 0

  // 2. For each operator op that appears in both:
  for (const op of opsA) {
    const keysA = Object.keys(a[op]).sort()
    const keysB = Object.keys(b[op]).sort()
    // If the set of context‐keys under this operator differs, we can't merge as one block
    if (JSON.stringify(keysA) !== JSON.stringify(keysB)) {
      return null
    }

    // Now we know op and its context keys align. Build the merged set for this operator:
    merged[op] = {}
    for (const key of keysA) {
      const valsA = a[op][key]
      const valsB = b[op][key]
      const valuesA = new Set(valsA)
      const valuesB = new Set(valsB)
      if (valuesA.size !== valuesB.size || [...valuesA].some((value) => !valuesB.has(value))) {
        differingEntries++
        // Independent unions of multiple entries would admit cross-pairs not present in either alternative.
        if (differingEntries > 1) {
          return null
        }
      }

      // How we combine depends on operator semantics:
      switch (conditionBaseOperator(op)) {
        case 'stringequals':
        case 'stringlike':
        case 'stringnotequals':
        case 'stringnotlike':
        case 'arnequals':
        case 'arnlike':
        case 'arnnotequals':
        case 'arnnotlike':
          // String‐based operators: just union the value arrays
          merged[op][key] = Array.from(new Set([...valsA, ...valsB]))
          break

        case 'numericlessthan':
        case 'numericlessthanequals':
        case 'numericgreaterthan':
        case 'numericgreaterthanequals':
        case 'numericequals':
        case 'numericnotequals':
          // Numeric operators: pick the “widest” comparison that still covers both sets
          // For simplicity, convert all valsA/valsB to numbers; find the min or max
          const numsA = valsA.map((v) => Number(v))
          const numsB = valsB.map((v) => Number(v))
          if (numsA.some(isNaN) || numsB.some(isNaN)) {
            // Malformed number—cannot merge
            return null
          }
          if (op === 'numericlessthan' || op === 'numericlessthanequals') {
            // We want the largest boundary
            const candidate = Math.max(...numsA, ...numsB)
            merged[op][key] = [String(candidate)]
          } else if (op === 'numericgreaterthan' || op === 'numericgreaterthanequals') {
            // We want the smallest boundary
            const candidate = Math.min(...numsA, ...numsB)
            merged[op][key] = [String(candidate)]
          } else if (op === 'numericequals' || op === 'numericnotequals') {
            // Union the sets of allowed/not‐allowed numbers
            merged[op][key] = Array.from(new Set([...valsA.map(String), ...valsB.map(String)]))
          }
          break

        case 'datelessthan':
        case 'datelessthanequals':
        case 'dategreaterthan':
        case 'dategreaterthanequals':
          // Similar idea: choose the “widest” date limit
          // Assume ISO‐8601 strings so lex‐compare works
          if (op === 'datelessthan' || op === 'datelessthanequals') {
            // pick the LARGEST date (latest) because “< latest” covers “< earlier”
            const candidate = [...valsA, ...valsB].sort().reverse()[0]
            merged[op][key] = [candidate]
          } else {
            // "DateGreaterThan"/"DateGreaterThanEquals": pick the EARLIEST date
            const candidate = [...valsA, ...valsB].sort()[0]
            merged[op][key] = [candidate]
          }
          break

        case 'bool':
          // Typically valsA and valsB are ["true"] or ["false"].
          // If either contains "true", then the union is ["true","false"]? No—
          // Bool doesn't make sense with an array. In IAM, Bool only works with a single value.
          // If values differ (one says ["true"], the other says ["false"]), you cannot
          // express (Bool==true OR Bool==false) as a single Bool. You’d need two separate
          // statements. So bail out.
          if (valsA[0] === valsB[0]) {
            merged[op][key] = [valsA[0]]
          } else {
            return null
          }
          break

        case 'ipaddress':
        case 'notipaddress':
          // You can pass multiple CIDR blocks under a single IpAddress. So union them.
          merged[op][key] = Array.from(new Set([...valsA, ...valsB]))
          break

        // Any other operators (e.g., “ArnNotLike” etc.) behave similarly to their base type
        default:
          // If we don’t explicitly handle the operator, reject merging
          return null
      }
    }
  }

  return merged
}

/**
 * Intersect two sets of permission conditions.
 *
 * Attempt to find the intersection of two sets of IAM condition clauses. This will
 * combine condition operators and context keys, retaining only values that satisfy
 * both sets of conditions. If the intersection is empty or cannot be expressed
 * cleanly, returns null.
 *
 * @param conditionsA First set of conditions
 * @param conditionsB Second set of conditions
 * @returns Intersected conditions or null if intersection is empty or cannot be expressed
 */
export function intersectConditions(
  a: Record<string, Record<string, string[]>>,
  b: Record<string, Record<string, string[]>>
): Record<string, Record<string, string[]>> | null {
  // Normalize both condition sets to lowercase operators and keys
  const normalizedA = normalizeConditionKeys(a)
  const normalizedB = normalizeConditionKeys(b)

  // Collect all unique operators from both sides
  const allOperators = Array.from(
    new Set([...Object.keys(normalizedA), ...Object.keys(normalizedB)])
  )

  const result: PermissionConditions = {}

  for (const operator of allOperators) {
    const keysA = normalizedA[operator] || {}
    const keysB = normalizedB[operator] || {}

    // Collect all unique context keys for this operator
    const allContextKeys = Array.from(new Set([...Object.keys(keysA), ...Object.keys(keysB)]))

    result[operator] = {}

    for (const contextKey of allContextKeys) {
      const valsA = keysA[contextKey]
      const valsB = keysB[contextKey]

      // If key exists in both sides, apply intersection logic based on operator type
      if (valsA !== undefined && valsB !== undefined) {
        const intersectedValues = intersectValuesForOperator(operator, valsA, valsB)
        if (intersectedValues === null) {
          // Empty intersection means no overlap - return null
          return null
        }
        result[operator][contextKey] = intersectedValues
      } else {
        // Key only exists in one side - carry it through (both conditions must be satisfied)
        result[operator][contextKey] = valsA !== undefined ? Array.from(valsA) : Array.from(valsB!)
      }
    }

    // Remove empty operator objects
    if (Object.keys(result[operator]).length === 0) {
      delete result[operator]
    }
  }

  const merged = mergeComplementaryConditions(result)

  // Check if any values array became empty after merging complementary conditions
  // (e.g., StringEquals: ['a'] merged with StringNotEquals: ['a'] results in StringEquals: [])
  for (const [, keyMap] of Object.entries(merged)) {
    for (const [, values] of Object.entries(keyMap)) {
      if (values.length === 0) {
        return null
      }
    }
  }

  return merged
}

/**
 * Intersect values for a specific operator type.
 *
 * Returns the intersected values, or null if the intersection is empty
 * (meaning the conditions are mutually exclusive).
 */
function intersectValuesForOperator(
  operator: string,
  valsA: string[],
  valsB: string[]
): string[] | null {
  const baseOp = conditionBaseOperator(operator)

  switch (baseOp) {
    // String/ARN equality operators: intersection of allowed values
    case 'stringequals':
    case 'stringlike':
    case 'arnequals':
    case 'arnlike': {
      const common = valsA.filter((v) => valsB.includes(v))
      return common.length > 0 ? common : null
    }

    // String/ARN negation operators: union of exclusions (more restrictive)
    case 'stringnotequals':
    case 'stringnotlike':
    case 'arnnotequals':
    case 'arnnotlike': {
      return Array.from(new Set([...valsA, ...valsB]))
    }

    // Numeric less-than operators: take the minimum (more restrictive)
    case 'numericlessthan':
    case 'numericlessthanequals': {
      const numA = Number(valsA[0])
      const numB = Number(valsB[0])
      if (isNaN(numA) || isNaN(numB)) {
        return null
      }
      return [String(Math.min(numA, numB))]
    }

    // Numeric greater-than operators: take the maximum (more restrictive)
    case 'numericgreaterthan':
    case 'numericgreaterthanequals': {
      const numA = Number(valsA[0])
      const numB = Number(valsB[0])
      if (isNaN(numA) || isNaN(numB)) {
        return null
      }
      return [String(Math.max(numA, numB))]
    }

    // Boolean operators: values must match exactly
    case 'bool':
    case 'null': {
      if (
        valsA[0] === undefined || valsB[0] === undefined
          ? valsA[0] !== valsB[0]
          : !equalsIgnoreCase(valsA[0], valsB[0])
      ) {
        return null
      }
      return [valsA[0]]
    }

    // IP address operators: intersection of CIDR blocks
    case 'ipaddress':
    case 'notipaddress': {
      const common = valsA.filter((cidr) => valsB.includes(cidr))
      return common.length > 0 ? common : null
    }

    // Date less-than operators: take the earlier date (more restrictive)
    case 'datelessthan':
    case 'datelessthanequals': {
      const dateA = valsA[0]
      const dateB = valsB[0]
      return [dateA < dateB ? dateA : dateB]
    }

    // Date greater-than operators: take the later date (more restrictive)
    case 'dategreaterthan':
    case 'dategreaterthanequals': {
      const dateA = valsA[0]
      const dateB = valsB[0]
      return [dateA > dateB ? dateA : dateB]
    }

    // Unknown operator - cannot handle
    default:
      return null
  }
}

/**
 * Checks if an IAM condition operator ends with "IfExists".
 *
 * @param op the IAM condition operator, e.g., "StringEqualsIfExists"
 * @returns true if the operator ends with "IfExists", false otherwise.
 */
function isIfExists(op: string): boolean {
  // Check if the operator ends with "IfExists"
  return op.toLowerCase().endsWith('ifexists')
}

/**
 * Get the set operator from an IAM condition operator such as "ForAllValues" or "ForAnyValue".
 *
 * @param op the IAM condition operator, e.g., "ForAllValues:StringEquals"
 * @returns the set operator, e.g., "forallvalues" or "foranyvalue", or undefined if no set operator is present.
 */
function conditionSetOperator(op: string): string | undefined {
  return op.includes(':') ? op.split(':')[0].toLowerCase() : undefined
}

/**
 * Gets the base operator name from an IAM condition operator. Removes any set operator prefix or
 * "IfExists" suffix.
 *
 * @param op the IAM condition operator, e.g., "ForAllValues:StringEqualsIfExists"
 * @returns the base operator name, e.g., "stringequals" or "arnequals".
 */
function conditionBaseOperator(op: string): string {
  // Return the base operator name for IAM condition operators
  return op
    .split(':')
    .at(-1)!
    .toLowerCase()
    .replace(/ifexists$/, '')
}

/**
 * Returns a new PermissionConditions object with all operator and context keys lowercased.
 */
export function normalizeConditionKeys(conds: PermissionConditions): PermissionConditions {
  const result: PermissionConditions = {}
  for (const [op, keyMap] of Object.entries(conds)) {
    const lowerOp = op.toLowerCase()
    result[lowerOp] = {}
    for (const [contextKey, values] of Object.entries(keyMap)) {
      const lowerContextKey = contextKey.toLowerCase()
      result[lowerOp][lowerContextKey] = Array.from(values)
    }
  }
  return result
}

const invertOperatorMap: Record<string, string> = {
  stringequals: 'StringNotEquals',
  stringlike: 'StringNotLike',
  arnequals: 'ArnNotEquals',
  arnlike: 'ArnNotLike',
  stringnotequals: 'StringEquals',
  stringnotlike: 'StringLike',
  arnnotequals: 'ArnEquals',
  arnnotlike: 'ArnLike',
  numericlessthan: 'NumericGreaterThanEquals',
  numericlessthanequals: 'NumericGreaterThan',
  numericgreaterthan: 'NumericLessThanEquals',
  numericgreaterthanequals: 'NumericLessThan',
  numericequals: 'NumericNotEquals',
  numericnotequals: 'NumericEquals',
  datelessthan: 'DateGreaterThanEquals',
  datelessthanequals: 'DateGreaterThan',
  dategreaterthan: 'DateLessThanEquals',
  dategreaterthanequals: 'DateLessThan',
  bool: 'Bool',
  ipaddress: 'NotIpAddress',
  notipaddress: 'IpAddress'
}

const invertedSetOperatorMap: Record<string, string> = {
  forallvalues: 'ForAnyValue',
  foranyvalue: 'ForAllValues'
}

/**
 * Invert a set of IAM condition clauses for Deny → allow inversion.
 * Preserves ForAllValues:/ForAnyValue: prefixes and IfExists suffixes.
 *
 * @param conds the condition clauses to invert
 * @return a new set of inverted conditions
 */
export function invertConditions(
  conds: Record<string, Record<string, string[]>>
): Record<string, Record<string, string[]>> {
  const normalized = normalizeConditionKeys(conds)
  const inverted: Record<string, Record<string, string[]>> = {}
  for (const [op, keyMap] of Object.entries(normalized)) {
    const setOperator = conditionSetOperator(op) || undefined
    const setOperatorPrefix = setOperator ? invertedSetOperatorMap[setOperator] + ':' : ''
    const hasIfExists = isIfExists(op)
    const coreOp = conditionBaseOperator(op)
    const invertedCore = invertOperatorMap[coreOp] || coreOp
    const invertedOp =
      `${setOperatorPrefix}${invertedCore}${hasIfExists ? 'IfExists' : ''}`.toLowerCase()
    inverted[invertedOp] = {}
    for (const [key, vals] of Object.entries(keyMap)) {
      if (coreOp === 'bool' || coreOp === 'null') {
        inverted[invertedOp][key] = vals.map((v) =>
          equalsIgnoreCase(v, 'true') ? 'false' : 'true'
        )
      } else {
        inverted[invertedOp][key] = Array.from(vals)
      }
    }
  }
  return inverted
}

function mergeComplementaryConditions(c: PermissionConditions): PermissionConditions {
  const complement: Record<string, string> = {
    stringequals: 'stringnotequals',
    stringlike: 'stringnotlike',
    arnequals: 'arnnotequals',
    arnlike: 'arnnotlike',
    numericequals: 'numericnotequals',
    numericnotequals: 'numericequals',
    numericlessthan: 'numericgreaterthanequals',
    numericgreaterthanequals: 'numericlessthan',
    numericlessthanequals: 'numericgreaterthan',
    numericgreaterthan: 'numericlessthanequals',
    datelessthan: 'dategreaterthanequals',
    dategreaterthanequals: 'datelessthan',
    datelessthanequals: 'dategreaterthan',
    dategreaterthan: 'datelessthanequals',
    ipaddress: 'notipaddress',
    notipaddress: 'ipaddress'
    // bool: 'bool'
  }
  const out = structuredClone(c)
  for (const [base, comp] of Object.entries(complement)) {
    if (out[base] && out[comp]) {
      for (const key of Object.keys(out[base])) {
        if (key in out[comp]) {
          out[base][key] = out[base][key].filter((v) => !out[comp][key].includes(v))
          delete out[comp][key]
        }
      }
      if (out[comp] && Object.keys(out[comp]).length === 0) delete out[comp]
    }
  }
  return out
}

/**
 * Apply Deny conditions to an Allow permission.
 *
 * A Deny permission with conditions (whether multiple operators or multiple keys under one
 * operator) acts as an AND, meaning the Allow needs to escape ANY one of them (OR when inverted).
 * Each condition key-value pair is inverted and creates a separate Allow permission.
 *
 * It is possible for any given condition to fully deny the Allow, in which case
 * that condition will produce no resulting Allow permission. The result is an array
 * of Allow permissions that apply after each Deny condition is applied.
 *
 * This may result in multiple Allow permission or an empty array if all are denied.
 *
 * @param allow the Allow permission
 * @param deny the Deny permission
 * @returns an array of resulting Allow permissions after applying Deny conditions
 */
export function applyDenyConditionsToAllow(allow: Permission, deny: Permission): Permission[] {
  // If Deny has no conditions, it fully denies the Allow
  if (!deny.conditions || Object.keys(deny.conditions).length === 0) {
    return [allow]
  }

  const results: Permission[] = []
  // Each Deny condition key-value pair creates a separate inverted condition for Allow
  // (multiple keys under the same operator are each inverted separately)
  for (const [operator, keyMap] of Object.entries(deny.conditions || {})) {
    for (const [contextKey, values] of Object.entries(keyMap)) {
      // Invert this specific condition
      const singleCondition = { [operator]: { [contextKey]: values } }
      const invertedCondition = invertConditions(singleCondition)

      // Merge with the original Allow conditions
      const mergedConditions = intersectConditions(allow.conditions || {}, invertedCondition)
      if (mergedConditions !== null) {
        results.push(
          new Permission(
            allow.effect,
            allow.service,
            allow.action,
            allow.resource,
            allow.notResource,
            mergedConditions,
            allow.principal,
            allow.notPrincipal
          )
        )
      }
    }
  }

  return results
}
