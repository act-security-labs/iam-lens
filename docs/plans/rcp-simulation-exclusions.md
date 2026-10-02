# RCP Simulation Exclusions Plan

## Feature Brief

- **Problem statement:** AWS Resource Control Policies (RCPs) do not apply to requests against AWS-managed KMS keys or to the `kms:RetireGrant` operation. iam-lens currently includes collected RCPs in every applicable simulation request, which can produce incorrect denials for these cases.
- **Goals:** Omit RCPs passed to `@actsecurity/iam-simulate` for either exclusion; retain existing RCP behavior for customer-managed KMS keys and all other actions/resources.
- **Non-goals:** Change SCP, identity, resource, permission-boundary, or KMS key-policy behavior; change collected data; alter `principalCan`'s separate permission-set analysis.
- **Target package/API:** Internal simulation construction in `src/simulate/simulate.ts`; an internal `IamCollectClient` metadata lookup in `src/collect/client.ts`. No public API change.
- **User-facing behavior:** `simulateRequest` and callers such as `whoCan` will no longer report an RCP denial for these AWS-excluded cases.
- **Inputs:** Existing `SimulationRequest.action`, `SimulationRequest.resourceArn`, resolved resource account, and KMS key metadata's `awsManaged` field.
- **Outputs:** Existing `SimulateRequestResult` unchanged; `Simulation.resourceControlPolicies` is empty when excluded.
- **Errors/diagnostics:** No new errors. Absent/unknown KMS metadata is treated conservatively as not AWS-managed, retaining RCPs.
- **Edge cases:** Action matching is case-insensitive; `kms:RetireGrant` excludes RCPs independently of resource/key metadata; only KMS resources of type `key` with `awsManaged: true` receive the managed-key exclusion; keys with missing/false metadata and non-KMS resources retain RCPs.
- **Compatibility concerns:** This corrects previously over-restrictive results without changing exported types or options.
- **Documentation/examples impact:** None; behavior is an AWS policy-evaluation correction to an existing API.
- **Open questions:** None.

## Discovery Findings

- `simulateRequest` obtains RCPs through `getResourcePolicies`, then sends `rcpsForRequest(...)` into `Simulation.resourceControlPolicies`.
- `rcpsForRequest` currently handles service-linked-role and wildcard behavior, but has no action or resource metadata context.
- `IamCollectClient` already owns resource-metadata access and caching. iam-collect will separately persist `metadata.awsManaged: true` for AWS-managed KMS keys; iam-lens will consume that contract.
- Existing `simulate.test.ts` uses an in-memory collect store, enabling synthetic KMS metadata and spies on `getRcpHierarchyForAccount` without customer data.

## Implementation Plan

1. Add a typed, cached internal `IamCollectClient.isAwsManagedKmsKey(resourceArn, accountId)` lookup. It reads the key's resource `metadata` (not the unrelated organization-policy `awsManaged` field), returns `metadata.awsManaged === true`, and treats absent/false metadata as not AWS-managed for backward compatibility with data collected before the upstream change.
2. Change private `getResourcePolicies` to accept `action: string`; pass `simulationRequest.action` at its only call site. It must first omit RCPs for a case-insensitive `kms:RetireGrant` action (without reading key metadata), then omit RCPs for a `kms:key` resource where `isAwsManagedKmsKey` is true. Continue fetching resource policies and preserve existing RCP behavior otherwise.
3. Add focused `simulateRequest` unit tests using synthetic user/key metadata and a spy on `getRcpHierarchyForAccount` to prove that RCP retrieval is skipped for a mixed-case `KMS:retiregrant` action and an AWS-managed KMS key, while it remains enabled for customer-managed and missing-metadata KMS keys with non-RetireGrant actions.
4. Run focused tests, then `npm run build`, `npm test`, and `npm run format-check`.

## Design Decisions and Alternatives

- **Chosen:** Gate RCP retrieval at simulation assembly, where action, resource ARN/account, and collected metadata are available.
- **Rejected:** Add special-case logic to `@actsecurity/iam-simulate`; applicability is AWS resource/context knowledge owned by iam-lens.
- **Rejected:** Infer AWS-managed keys from aliases or ARN naming; the upstream `metadata.awsManaged` contract is authoritative.
- **Rejected:** Apply the rule in `rcpsForRequest` alone; that function lacks resource metadata and would require mixing I/O into a currently pure transformation.

## Test Strategy

- Unit tests verify the exact dependency boundary: no resource RCP hierarchy is fetched for each exclusion, and hierarchy lookup remains for customer-managed and missing-metadata keys.
- Simulate and whoCan integration tests use synthetic KMS keys with an otherwise applicable, resource-scoped RCP deny. They prove both AWS-managed-key and `kms:RetireGrant` exclusions still return the key-policy/identity-policy grant.
- No external AWS calls or customer fixtures are used.

## Risks and Checks

- Risk: upstream collection rollout and missing metadata. Mitigate with a typed `awsManaged` lookup and conservative fallback that retains RCPs.
- Run: `npx vitest --run src/simulate/simulate.test.ts`, `npm run build`, `npm test`, `npm run format-check`.

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
- [x] Claude plan review concerns resolved
- [x] Codex/current-model plan review concerns resolved
- [x] User approved implementation
