# Authoritative Caller Context for `simulateRequest`

## Feature Brief

- **Problem statement:** `simulateRequest` derives context from collected data and models some derived service-source values as uncertain in Discovery mode. A caller-supplied context value can therefore be shadowed by a differently cased derived key or be treated as value-unknown despite being explicitly supplied.
- **Goals:** Preserve every `SimulationRequest.customContextKeys` value against automatically derived context (case-insensitively); model each supplied key as present and value-known in Discovery mode.
- **Non-goals:** Change automatic context derivation, change uncertainty for context that was not caller-supplied, add CLI flags, or change iam-simulate.
- **Target package/API:** `@actsecurity/iam-lens`, exported `simulateRequest` / `SimulationRequest.customContextKeys`.
- **User-facing behavior:** An explicit context entry takes precedence over the automatically generated value of the same IAM context key regardless of spelling case. In Discovery mode, its presence and precise string/string-array value are authoritative, including `aws:Source*` and `kms:CallerAccount`.
- **Inputs:** Existing `customContextKeys: Record<string, string | string[]>`.
- **Outputs:** Existing `SimulateRequestResult`; only evaluated request context and condition-result certainty change.
- **Errors/diagnostics:** No new errors or diagnostics.
- **Edge cases:** IAM context-key names are case-insensitive; apply a differently cased override without retaining the derived duplicate. Preserve automatic VPC enrichment for keys the caller did not supply; existing case-insensitive `contextValue`/`contextHasKey` guards prevent it from adding a canonical duplicate of a caller VPC key. A supplied `aws:Source*` (including `aws:SourceOwner`) or `kms:CallerAccount` must override the special unknown-value rule.
- **Compatibility concerns:** This is a deliberate behavior correction for custom values. Simulations that relied on a caller-provided Source key being conditional rather than exact may become determinate.
- **Documentation/examples impact:** Clarify the `SimulationRequest.customContextKeys` JSDoc and the simulation docs' override section that explicit values are authoritative in Discovery callers. Extend the existing sanitized end-to-end simulation dataset cases; no production/customer data.
- **Open questions:** None.

## Discovery Findings

- `src/simulate/contextKeys.ts:createContextKeys` derives default, principal, resource, service, and VPC context; its custom merge is exact-key assignment.
- The existing VPC logic uses case-insensitive lookup in `contextValue` / `contextHasKey`, but exact-key custom merge can retain both a derived canonical key and a caller key with different casing.
- `src/simulate/simulate.ts` adds all custom keys to strict constraints, then `discoveryConstraintForStrictKey` deliberately gives `aws:Source*` an unknown value.
- iam-simulate merges constraint literals case-insensitively and uses true-winning semantics. A known-value constraint for a caller key safely supersedes the Source unknown-value constraint.
- Existing tests are Vitest co-located. `contextKeys.test.ts` covers automatic and custom context formation; `simulate.test.ts` covers Discovery strict-key behavior.

## Implementation Plan

1. In `src/simulate/contextKeys.ts`, introduce a small internal, documented case-insensitive override application helper. For each supplied custom key, remove any derived entry whose key equals it ignoring case, then retain the supplied key/value. Use it at the current override point before VPC enrichment so custom VPC source inputs still drive lookups.
2. In `src/simulate/simulate.ts`, make `discoveryConstraintForStrictKey` identify caller-supplied keys **case-insensitively** before special-case Source/KMS rules and emit `{ presenceIsKnown: true, valueIsKnown: true }` for them. Keep all non-caller behavior unchanged. Update touched JSDoc, including `SimulationRequest.customContextKeys`.
3. Add focused unit tests:
   - `contextKeys.test.ts`: an alternate-case custom default-key override produces exactly one case-insensitive key and keeps the caller value.
   - `simulate.test.ts`: a Discovery identity-policy condition on caller-supplied, nonmatching `aws:SourceVpc` is evaluated exactly and does not become a conditional allow; a matching value is allowed if needed to prove the positive path.
   - `simulate.test.ts`: a service-principal KMS Discovery request with a caller-supplied, nonmatching `kms:CallerAccount` is evaluated as known, covering precedence over the separate service-placeholder branch.
4. Add end-to-end `simulateIntegration.test.ts` dataset-1 cases that call the public `simulateRequest` pipeline:
   - CloudTrail requests with caller-supplied matching and nonmatching `aws:SourceArn` values must respectively be allowed and explicitly denied by the existing matching-SourceArn allow/nonmatching-SourceArn deny bucket policy;
   - VpcBucketRole requests with caller-supplied matching `aws:SourceVpc` and alternate-case nonmatching `AWS:sourceVpc` values must respectively be allowed and implicitly denied. The latter exercises case-insensitive caller replacement through the complete pipeline.
     These reuse sanitized repository fixtures and exercise collection, context construction, case-insensitive caller precedence, constraint creation, and policy evaluation. KMS caller-account coverage remains a focused unit test because the existing dataset-2 service-principal key policy is not independently simulatable as an Allowed request (it lacks the additional grant needed by `simulateRequest`), so it cannot distinguish this feature end to end without unrelated fixture/policy changes.
5. Update `docs/Simulate.md` to document Discovery authority for explicit context, without changing CLI behavior.
6. Run focused Vitest tests (unit and `simulateIntegration.test.ts`), then `npm run build`, `npm test`, and `npm run format-check`; format with `npm run format` only if necessary.

## Alternatives Considered

- **Only add a known-value constraint for custom keys:** rejected because it would not resolve differently cased duplicate derived context entries, violating caller precedence.
- **Treat every strict key as value-known:** rejected because Discovery intentionally retains uncertainty for automatically generated service source and KMS caller placeholders.
- **Change iam-simulate constraint merge priority:** rejected because existing true-winning merging already supports the required caller authority and changing the dependency would broaden scope.

## Risks and Rollback

- Case-insensitive de-duplication changes the spelling retained in `request.contextVariables` to the caller spelling. IAM context matching is case-insensitive, and this is necessary to prevent duplicate values.
- Discovery results can become more determinate for explicit caller values; removing the custom-key precedence in constraint construction rolls that aspect back.

## Pre-Implementation Confidence Gate

- [x] Discovery findings recorded
- [x] Product behavior is explicit
- [x] Inputs are final enough to implement
- [x] Outputs are final enough to implement
- [x] Exported types/APIs are final enough to implement
- [x] Error/diagnostic behavior is explicit
- [x] Test strategy is explicit
- [x] Docs/examples impact is explicit
- [x] Backwards compatibility impact is explicit
- [x] Claude plan review concerns resolved (test strategy amended)
- [x] Codex/current-model plan review concerns resolved (test strategy amended)
- [x] User approved implementation
