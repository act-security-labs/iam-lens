export {
  IamCollectClient,
  InMemoryCacheProvider,
  NoCacheProvider,
  type CacheProvider,
  type IamCollectClientOptions
} from './collect/client.js'
export type {
  ManagedPolicy,
  InlinePolicy,
  OrgPolicy,
  SimulationOrgPolicies,
  OrgPolicyType,
  IamActionCache
} from './collect/client.js'
export {
  getCollectClient,
  loadCollectConfigs,
  type ClientFactoryPlugin,
  type CollectClientOptions
} from './collect/collect.js'
export { principalCan, type PrincipalCanInput } from './principalCan/principalCan.js'
export { makePrincipalIndex } from './principalIndex/makePrincipalIndex.js'
export type { ContextKeys } from './simulate/contextKeys.js'
export {
  simulateRequest,
  simulateAnonymousRequest,
  simulateExternalPrincipalRequest,
  simulateExternalResourceRequest,
  type SimulationRequest,
  type AnonymousSimulationRequest,
  type ExternalResourceSimulationRequest,
  type SimulateRequestResult
} from './simulate/simulate.js'
export {
  whoCan,
  type WhoCanPrincipalScope,
  type ResourceAccessRequest,
  type WhoCanAllowed,
  type WhoCanAllowedResourcePattern,
  type WhoCanResponse
} from './whoCan/whoCan.js'
export {
  WhoCanProcessor,
  type WhoCanProcessorConfig,
  type WhoCanProcessorRequest,
  type WhoCanSettledEvent,
  type WhoCanSettledSuccess,
  type WhoCanSettledError,
  type WorkerBootstrapPlugin
} from './whoCan/WhoCanProcessor.js'
export {
  type LightRequestAnalysis,
  type LightResourceAnalysis,
  type LightResourceAnalysisWithPattern,
  type SingleResourceLightRequestAnalysis,
  type WildcardResourceLightRequestAnalysis
} from './whoCan/requestAnalysis.js'
export {
  PermissionSet,
  buildPermissionSetFromPolicies,
  addPoliciesToPermissionSet,
  toPolicyStatements,
  type AddStatementToPermissionSetOptions
} from './principalCan/permissionSet.js'
export {
  Permission,
  type PermissionEffect,
  type PermissionConditions,
  type PermissionPrincipals,
  type PermissionPrincipalType
} from './principalCan/permission.js'
