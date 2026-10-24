import { type JobResult } from '@actsecurity/job'
import { IamCollectClient } from '../collect/client.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { PullBasedJobRunner } from '../workers/JobRunner.js'
import {
  convertToDenialDetails,
  type LightRequestAnalysis,
  toLightRequestAnalysis
} from './requestAnalysis.js'
import { type WhoCanAllowed, type WhoCanDenyDetail } from './whoCan.js'
import { executeWhoCan, type WhoCanExecutionResult, type WhoCanWorkItem } from './WhoCanWorker.js'

/**
 * A work item tagged with its owning request ID, used by the main-thread
 * runner so that simulation results can be routed back to the correct request.
 */
export type TaggedWhoCanWorkItem = WhoCanWorkItem & {
  /** The request ID this work item belongs to. */
  requestId: string
}

/**
 * Properties attached to each job so the requestId survives through to onComplete.
 */
interface MainThreadJobProperties {
  /** The request ID this job belongs to. */
  requestId: string

  /** Whether deny details should be collected for this work item's request. */
  collectDenyDetails: boolean
}

/**
 * Dequeues the next tagged work item from the processor's FIFO scheduler.
 *
 * @returns the next tagged work item, or undefined if none are ready.
 */
export type DequeueWork = () => TaggedWhoCanWorkItem | undefined

/**
 * Called when a simulation completes (allowed, denied, or error). Routes
 * the result back to the processor by requestId.
 *
 * @param requestId - The request this result belongs to.
 * @param result - The simulation result (fulfilled with WhoCanAllowed or undefined, or rejected).
 */
export type OnSimulationResult = (
  requestId: string,
  result: JobResult<WhoCanAllowed | undefined, Record<string, unknown>>
) => void

/**
 * Checks whether deny details should be included for a denied simulation.
 *
 * @param requestId - The request this check belongs to.
 * @param lightAnalysis - The light analysis for the denied simulation.
 * @returns true if deny details should be collected and delivered.
 */
export type OnCheckDenyDetails = (requestId: string, lightAnalysis: LightRequestAnalysis) => boolean

/**
 * Called when deny details are ready to be delivered.
 *
 * @param requestId - The request this detail belongs to.
 * @param detail - The deny detail record.
 */
export type OnDenyDetail = (requestId: string, detail: WhoCanDenyDetail) => void

/**
 * Creates a main-thread simulation runner that pulls tagged work items from
 * the processor's FIFO scheduler and routes results back by requestId.
 *
 * The requestId is threaded through the job's properties so it is available
 * in onComplete without needing the workerId.
 *
 * @param dequeueWork - Function to dequeue the next tagged work item.
 * @param onSimulationResult - Callback for simulation results.
 * @param onCheckDenyDetails - Callback to check whether to collect deny details.
 * @param onDenyDetail - Callback for deny detail delivery.
 * @param collectClient - The IAM collect client for fetching policy data.
 * @param s3AbacOverride - Optional override for S3 ABAC when checking S3 Bucket access.
 * @param collectGrantDetails - Whether to collect grant details for allowed simulations.
 * @param concurrency - The number of concurrent simulations to run on the main thread. Defaults to 50.
 * @returns a PullBasedJobRunner that processes tagged whoCan work items.
 */
export function createMainThreadStreamingWorkQueue(
  dequeueWork: DequeueWork,
  onSimulationResult: OnSimulationResult,
  onCheckDenyDetails: OnCheckDenyDetails,
  onDenyDetail: OnDenyDetail,
  collectClient: IamCollectClient,
  s3AbacOverride: S3AbacOverride | undefined,
  collectGrantDetails: boolean,
  concurrency: number = 50
) {
  return new PullBasedJobRunner<
    WhoCanExecutionResult,
    MainThreadJobProperties,
    TaggedWhoCanWorkItem
  >(
    concurrency,
    async () => {
      return dequeueWork()
    },
    (taggedItem) => {
      const { requestId, ...workItem } = taggedItem
      return {
        properties: { requestId, collectDenyDetails: workItem.collectDenyDetails },
        execute: async (context) => {
          return executeWhoCan(workItem, collectClient, {
            s3AbacOverride,
            collectDenyDetails: workItem.collectDenyDetails,
            collectGrantDetails,
            discoveryContextKeyConstraints: workItem.discoveryContextKeyConstraints
          })
        }
      }
    },
    async (result) => {
      const { requestId, collectDenyDetails } = result.properties

      if (result.status === 'fulfilled') {
        const executionResult = result.value
        if (executionResult.type === 'allowed') {
          onSimulationResult(requestId, {
            status: 'fulfilled',
            value: executionResult.allowed,
            properties: {}
          })
        } else {
          // Denied — handle deny details BEFORE reporting the simulation result,
          // because onSimulationResult may trigger request completion checks.
          const hasDetails =
            executionResult.type === 'denied_single' || executionResult.type === 'denied_wildcard'

          if (collectDenyDetails && hasDetails) {
            const lightAnalysis = toLightRequestAnalysis(executionResult)
            const shouldInclude = onCheckDenyDetails(requestId, lightAnalysis)

            if (shouldInclude) {
              onDenyDetail(requestId, convertToDenialDetails(executionResult))
            }
          }

          // Now report the denied simulation result (may trigger completion check)
          onSimulationResult(requestId, {
            status: 'fulfilled',
            value: undefined,
            properties: {}
          })
        }
      } else {
        // Error case
        onSimulationResult(requestId, {
          status: 'rejected',
          reason: result.reason,
          properties: {}
        })
      }
    }
  )
}
