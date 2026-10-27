import { iamActionDetails } from '@actsecurity/iam-data'
import { type TopLevelConfig } from '@actsecurity/iam-collect'
import { type DiscoveryContextKeyConstraint } from '@actsecurity/iam-simulate'
import { type ValidatedPolicy } from '@actsecurity/iam-policy'
import { type JobResult, numberOfCpus, StreamingJobQueue } from '@actsecurity/job'
import { Worker } from 'worker_threads'
import { type ClientFactoryPlugin, getCollectClient } from '../collect/collect.js'
import { IamCollectClient } from '../collect/client.js'
import { getAccountIdForResource, getResourcePolicyForResource } from '../resources.js'
import { Arn } from '../utils/arn.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { getWorkerScriptPath } from '../utils/workerScript.js'
import { SharedArrayBufferMainCache } from '../workers/SharedArrayBufferMainCache.js'
import { StreamingWorkQueue } from '../workers/StreamingWorkQueue.js'
import { createMainThreadStreamingWorkQueue } from './WhoCanMainThreadWorker.js'
import { type WhoCanWorkItem } from './WhoCanWorker.js'
import { intersectWithPrincipalScope, resolvePrincipalScope } from './principalScope.js'
import { type LightRequestAnalysis } from './requestAnalysis.js'
import {
  type WhoCanAllowed,
  type WhoCanDenyDetail,
  type WhoCanPrincipalScope,
  type WhoCanResponse,
  actionsForWhoCan,
  accountsToCheckBasedOnResourcePolicy,
  uniqueAccountsToCheck,
  sortWhoCanResults
} from './whoCan.js'
import {
  isAssumedRoleArn,
  isIamRoleArn,
  isIamUserArn,
  isServicePrincipal
} from '@actsecurity/iam-utils'
import { buildPrincipalArnFilter, principalMatchesFilter } from './principalArnFilter.js'
import { actionsThatDoNotAutomaticallyTrustTheCurrentAccount } from './untrustingActions.js'
import { type WorkerBootstrapPlugin } from './workerBootstrapPlugin.js'
import { log } from '@actsecurity/log'

export type { WorkerBootstrapPlugin } from './workerBootstrapPlugin.js'

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Configuration for creating a WhoCanProcessor. These settings are fixed
 * for the lifetime of the processor and baked into worker threads at creation time.
 */
export interface WhoCanProcessorConfig {
  /** The collect configurations for loading IAM data. */
  collectConfigs: TopLevelConfig[]

  /** The AWS partition to use (e.g. 'aws', 'aws-cn'). */
  partition: string

  tuning?: {
    /**
     * The number of worker threads to use beyond the main thread. Defaults to number of CPUs - 1.
     */
    workerThreads?: number

    /**
     * The concurrency level for processing simulations on the main thread. Defaults to 50.
     */
    mainThreadConcurrency?: number

    /**
     * The concurrency level for processing simulations on worker threads.
     * This is the value for EACH worker.
     * Defaults to 50.
     */
    perWorkerConcurrency?: number

    /**
     * The concurrency level for the shared preparation queue (account/principal fetches
     * across all active requests). Defaults to min(50, max(1, number of CPUs * 2)).
     */
    preparationConcurrency?: number

    /**
     * The maximum number of requests that may be actively expanded into scenarios
     * at once. Later requests remain as lightweight entries in pendingRequests.
     * Defaults to 30.
     */
    maxRequestsInProgress?: number
  }

  /** Optional plugin to wrap the collect client with a custom implementation. */
  clientFactoryPlugin?: ClientFactoryPlugin

  /**
   * Optional plugin that runs once per worker thread at startup before any work
   * is processed. Use this for loading instrumentation, initializing logging
   * context, or other worker-lifetime setup. If the bootstrap function throws,
   * the worker fails and the processor surfaces the error.
   */
  workerBootstrapPlugin?: WorkerBootstrapPlugin

  /** An override for S3 ABAC being enabled when checking access to S3 Bucket resources. */
  s3AbacOverride?: S3AbacOverride

  /** Whether workers should collect grant details for allowed simulations. */
  collectGrantDetails?: boolean

  /**
   * Async callback invoked when a request settles (succeeds or fails). The processor
   * awaits this callback before removing the request from active state and admitting
   * the next pending request. This allows consumers to perform async work with backpressure.
   *
   * @param event - The settlement event containing the request ID, original request,
   *   status, and either the result or the error.
   */
  onRequestSettled: (event: WhoCanSettledEvent) => Promise<void>

  /**
   * Optional async callback invoked when an `onRequestSettled` callback throws or rejects.
   * If this callback itself throws, the error is silently ignored. If not provided, a
   * warning is logged indicating that a settlement callback failed with no handler defined.
   *
   * @param event - The settlement event that was being delivered when the error occurred.
   * @param error - The error thrown by the `onRequestSettled` callback.
   */
  onSettlementFailure?: (event: WhoCanSettledEvent, error: Error) => Promise<void>

  /**
   * Whether the processor should ignore an existing principal index. Use this with testing.
   */
  ignorePrincipalIndex?: boolean
}

/**
 * Request parameters that vary per whoCan call on a processor.
 */
export interface WhoCanProcessorRequest {
  /** The ARN of the resource to check access for. */
  resource?: string

  /** The account ID the resource belongs to. */
  resourceAccount?: string

  /** The actions to check access for. */
  actions: string[]

  /** Whether to sort the results for consistent output. */
  sort?: boolean

  /**
   * Optional callback to filter which denied simulations should include detailed
   * denial analysis. If provided, deny details are collected for this request.
   * If the callback returns true for a given denial, the full deny details are
   * included in the response. If omitted, no deny details are collected for this request.
   *
   * @param details - A lightweight summary of the denied simulation.
   * @returns true to include full deny details for this denial.
   */
  denyDetailsCallback?: (details: LightRequestAnalysis) => boolean

  /** Optional scope to limit the set of principals tested. */
  principalScope?: WhoCanPrincipalScope

  /** Caller-provided Discovery context-key certainty constraints for each simulation. */
  discoveryContextKeyConstraints?: DiscoveryContextKeyConstraint[]
}

/**
 * Event delivered to the onRequestSettled callback when a request completes
 * (either successfully or with an error).
 */
export type WhoCanSettledEvent = WhoCanSettledSuccess | WhoCanSettledError

/**
 * Settlement event for a successfully completed request.
 */
export interface WhoCanSettledSuccess {
  /** Discriminator for the settlement outcome. */
  status: 'fulfilled'

  /** The unique ID assigned when the request was enqueued. */
  requestId: string

  /** The original request that was enqueued. */
  request: WhoCanProcessorRequest

  /** The whoCan result for this request. */
  result: WhoCanResponse
}

/**
 * Settlement event for a request that failed during preparation or simulation.
 */
export interface WhoCanSettledError {
  /** Discriminator for the settlement outcome. */
  status: 'rejected'

  /** The unique ID assigned when the request was enqueued. */
  requestId: string

  /** The original request that was enqueued. */
  request: WhoCanProcessorRequest

  /** The error that caused the request to fail. */
  error: Error
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal types
// ──────────────────────────────────────────────────────────────────────────────

/**
 * A lightweight entry representing a request that has been enqueued but not yet
 * admitted into active processing.
 */
interface SubmittedRequest {
  /** The unique ID assigned to this request. */
  requestId: string

  /** The original request parameters. */
  request: WhoCanProcessorRequest
}

/**
 * The mutable state for a request that has been admitted into active processing.
 * Created by the admission pump when a slot becomes available.
 */
interface RequestState {
  /** The unique ID for this request. */
  requestId: string

  /** The original request parameters. */
  request: WhoCanProcessorRequest

  /** Whether all scenarios have been created by preparation jobs. */
  allScenariosCreated: boolean

  /** Per-request scenario queue that simulation consumers pull from. */
  scenarios: StreamingWorkQueue<WhoCanWorkItem>

  /** Number of scenarios created (enqueued to the scenario queue). */
  created: number

  /** Number of scenarios whose simulation results have been processed. */
  completed: number

  /** Number of preparation jobs currently in flight for this request. */
  pendingPreparationJobs: number

  /** Accumulated allowed results for this request. */
  allowed: WhoCanAllowed[]

  /** Accumulated principals not found during preparation. */
  principalsNotFound: string[]

  /** Accounts not found during preparation. */
  accountsNotFound: string[]

  /** Organizations not found during preparation. */
  organizationsNotFound: string[]

  /** Organizational units not found during preparation. */
  organizationalUnitsNotFound: string[]

  /** Whether all accounts were checked (i.e., no principal scope narrowing). */
  allAccountsChecked: boolean

  /** Accumulated deny details for this request. */
  denyDetails: WhoCanDenyDetail[]

  /** Running count of completed simulations (both allowed and denied). */
  simulationCount: number

  /** Per-request deny details callback, if provided. */
  denyDetailsCallback?: (details: LightRequestAnalysis) => boolean

  /** Number of deny-detail check round trips still in flight for this request. */
  pendingDenyDetailsChecks: number

  /** Whether this request has been settled (success or failure). */
  settled: boolean

  /** Whether the onRequestSettled callback has been invoked and awaited. */
  callbackInvoked: boolean

  /** Accumulated simulation errors for this request. */
  simulationErrors: any[]
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

let nextRequestId = 0

/**
 * Generates a unique request ID for a new request.
 *
 * @returns a unique string ID
 */
function generateRequestId(): string {
  return `req-${++nextRequestId}`
}

/**
 * Get the number of worker threads to use, defaulting to number of CPUs - 1.
 *
 * @param overrideValue the override value, if any
 * @returns the override value if provided, otherwise number of CPUs - 1
 */
function getNumberOfWorkers(overrideValue: number | undefined): number {
  if (typeof overrideValue === 'number' && overrideValue >= 0) {
    return Math.floor(overrideValue)
  }
  return Math.max(0, numberOfCpus() - 1)
}

/**
 * A queue-first bulk processor that accepts many whoCan requests, expands
 * scenarios on the main thread, and feeds a shared simulation scheduler used
 * by worker threads and an optional main-thread runner.
 *
 * Results are delivered through the {@link WhoCanProcessorConfig.onRequestSettled}
 * callback as each request completes — they are not stored inside the processor.
 *
 * Use {@link enqueueWhoCan} to submit requests, then {@link waitForIdle} to
 * wait for all work to complete. Call {@link shutdown} when done to terminate
 * worker threads.
 */
export class WhoCanProcessor {
  private workers: Worker[]
  private collectClient: IamCollectClient
  private config: WhoCanProcessorConfig
  private isShutdown = false
  private workersDead = false

  // Admission state
  private pendingRequests: SubmittedRequest[] = []
  private activeRequestOrder: string[] = []
  private requestStates = new Map<string, RequestState>()
  private admissionPumpRunning = false
  private draining = false

  // Preparation queue
  private preparationQueue: StreamingJobQueue<void>

  // Idle / drain tracking
  private idleWaiters: { resolve: () => void; reject: (error: Error) => void }[] = []

  // Main thread simulation runner
  private mainThreadWorker: ReturnType<typeof createMainThreadStreamingWorkQueue> | undefined

  // Processor-fatal error
  private fatalError?: Error

  // Tracks a single in-progress shutdown so repeated calls are safe
  private shutdownPromise?: Promise<void>

  private constructor(
    workers: Worker[],
    collectClient: IamCollectClient,
    config: WhoCanProcessorConfig,
    preparationQueue: StreamingJobQueue<void>
  ) {
    this.workers = workers
    this.collectClient = collectClient
    this.config = config
    this.preparationQueue = preparationQueue
  }

  /**
   * Waits for every worker to post a `{ type: 'ready' }` message. If any
   * worker fails (error, non-zero exit, or explicit `startupError` message)
   * the remaining workers are terminated and the returned promise rejects.
   *
   * @param workers - The worker instances to wait on.
   */
  private static async awaitWorkersReady(workers: Worker[]): Promise<void> {
    // Each entry resolves on 'ready' or rejects on failure.
    const perWorker = workers.map(
      (worker) =>
        new Promise<void>((resolve, reject) => {
          const onMessage = (msg: any) => {
            if (msg.type === 'ready') {
              cleanup()
              resolve()
            } else if (msg.type === 'startupError') {
              cleanup()
              reject(new Error(`Worker startup failed: ${msg.error}`))
            }
          }
          const onError = (err: Error) => {
            cleanup()
            reject(new Error(`Worker error during startup: ${err.message}`))
          }
          const onExit = (code: number) => {
            cleanup()
            if (code !== 0) {
              reject(new Error(`Worker exited with code ${code} during startup`))
            }
          }
          const cleanup = () => {
            worker.off('message', onMessage)
            worker.off('error', onError)
            worker.off('exit', onExit)
          }
          worker.on('message', onMessage)
          worker.on('error', onError)
          worker.on('exit', onExit)
        })
    )

    try {
      await Promise.all(perWorker)
    } catch (err) {
      // At least one worker failed — terminate all workers so none are
      // left orphaned (no processor instance will be returned to the caller).
      await Promise.allSettled(workers.map((w) => w.terminate()))
      throw err
    }
  }

  /**
   * Creates a new WhoCanProcessor with worker threads, a shared cache, and
   * lifetime-scoped message routing. The processor is ready to accept requests
   * immediately after creation.
   *
   * @param config - The configuration for the processor, including collect configs,
   *   partition, simulation options, tuning, and the onRequestSettled callback.
   * @returns a new WhoCanProcessor instance
   */
  static async create(config: WhoCanProcessorConfig): Promise<WhoCanProcessor> {
    const numWorkers = getNumberOfWorkers(config.tuning?.workerThreads)
    const perWorkerConcurrency = config.tuning?.perWorkerConcurrency ?? 50
    const mainThreadConcurrency = config.tuning?.mainThreadConcurrency ?? 50
    const workerPath = getWorkerScriptPath('whoCan/WhoCanWorkerThreadWorker.js')

    if ((!workerPath || numWorkers === 0) && mainThreadConcurrency <= 0) {
      throw new Error(
        'WhoCanProcessor: no worker script found and mainThreadConcurrency is 0 — no work can be processed'
      )
    }

    const workers = !workerPath
      ? []
      : new Array(numWorkers).fill(undefined).map(() => {
          return new Worker(workerPath, {
            workerData: {
              collectConfigs: config.collectConfigs,
              partition: config.partition,
              concurrency: perWorkerConcurrency,
              s3AbacOverride: config.s3AbacOverride,
              collectGrantDetails: config.collectGrantDetails,
              clientFactoryPlugin: config.clientFactoryPlugin,
              workerBootstrapPlugin: config.workerBootstrapPlugin
            }
          })
        })

    // Install the shared-cache bridge before waiting for workers to become
    // ready. Workers may issue getCache messages during their getCollectClient()
    // call, which runs concurrently with the ready handshake. If the cache
    // listeners are not installed yet those messages are dropped and the worker
    // deadlocks waiting for a cache response.
    const sharedCache = new SharedArrayBufferMainCache(workers)

    // Wait for all workers to complete bootstrap and signal ready before
    // proceeding. This ensures bootstrap failures are caught reliably and
    // all workers are fully initialized before work is dispatched.
    if (workers.length > 0) {
      await WhoCanProcessor.awaitWorkersReady(workers)
    }

    const collectClient = await getCollectClient(config.collectConfigs, config.partition, {
      cacheProvider: sharedCache,
      clientFactoryPlugin: config.clientFactoryPlugin
    })

    const preparationConcurrency =
      config.tuning?.preparationConcurrency ?? Math.min(50, Math.max(1, numberOfCpus() * 2))

    const preparationQueue = new StreamingJobQueue<void>(
      preparationConcurrency,
      console,
      async () => {}
    )

    const processor = new WhoCanProcessor(workers, collectClient, config, preparationQueue)
    processor.installLifetimeWorkerListeners()

    // Signal workers to start pulling tasks. This must happen after
    // installLifetimeWorkerListeners() so the main thread's requestTask
    // handler is installed before the workers begin emitting requestTask
    // messages.
    for (const worker of workers) {
      worker.postMessage({ type: 'start' })
    }

    processor.createMainThreadRunner()
    return processor
  }

  /**
   * Enqueues a whoCan request for processing. Returns a unique request ID
   * that will appear in the corresponding {@link WhoCanSettledEvent}.
   *
   * This method never activates a request directly — it appends to
   * pendingRequests and signals the admission pump.
   *
   * @param request - The whoCan request parameters.
   * @returns the unique request ID assigned to this request.
   * @throws if the processor is shut down or draining via waitForIdle.
   */
  enqueueWhoCan(request: WhoCanProcessorRequest): string {
    if (this.isShutdown) {
      throw new Error('WhoCanProcessor has been shut down')
    }
    if (this.draining) {
      throw new Error('Cannot enqueue while draining — waitForIdle() is in progress')
    }

    const requestId = generateRequestId()
    this.pendingRequests.push({ requestId, request })
    this.wakeAdmissionPump()
    return requestId
  }

  /**
   * Returns a promise that resolves when all pending and active work has
   * completed and all onRequestSettled callbacks have finished.
   *
   * While draining, new calls to {@link enqueueWhoCan} will throw. Once
   * the drain completes, the processor re-opens for new enqueues.
   *
   * @returns a promise that resolves when idle, or rejects if a worker crashes.
   */
  async waitForIdle(): Promise<void> {
    if (this.isShutdown) {
      throw new Error('WhoCanProcessor has been shut down')
    }

    // If already idle, return immediately
    if (this.isIdle()) {
      return
    }

    this.draining = true

    try {
      await new Promise<void>((resolve, reject) => {
        this.idleWaiters.push({ resolve, reject })
      })
    } finally {
      // Only clear draining when the last waiter has been notified
      if (this.idleWaiters.length === 0) {
        this.draining = false
      }
    }
  }

  /**
   * Shuts down the processor by rejecting all pending requests, waiting for
   * active requests to settle, and terminating all worker threads.
   *
   * This method is idempotent — calling it multiple times is safe.
   */
  async shutdown(): Promise<void> {
    // If already shutting down or shut down, return the existing promise
    if (this.shutdownPromise) {
      return this.shutdownPromise
    }

    this.shutdownPromise = this.executeShutdown()
    return this.shutdownPromise
  }

  /**
   * Internal shutdown implementation. Rejects pending requests, waits for
   * active requests to drain, then terminates workers.
   */
  private async executeShutdown(): Promise<void> {
    this.isShutdown = true

    // Reject all pending requests that haven't been admitted
    while (this.pendingRequests.length > 0) {
      const submitted = this.pendingRequests.shift()!
      const event: WhoCanSettledEvent = {
        status: 'rejected',
        requestId: submitted.requestId,
        request: submitted.request,
        error: new Error('WhoCanProcessor was shut down before this request was processed')
      }
      try {
        await this.config.onRequestSettled(event)
      } catch (err) {
        await this.handleSettlementFailure(event, err)
      }
    }

    // Wait for active requests to finish naturally (includes draining in-flight work)
    if (this.activeRequestOrder.length > 0) {
      await new Promise<void>((resolve) => {
        if (this.activeRequestOrder.length === 0) {
          resolve()
        } else {
          this.idleWaiters.push({ resolve, reject: () => resolve() })
        }
      })
    }

    if (this.workersDead) {
      return
    }

    // Drain main thread worker
    if (this.mainThreadWorker) {
      await this.mainThreadWorker.finishAllWork()
      this.mainThreadWorker = undefined
    }

    // Gracefully shut down workers
    const workerPromises = this.workers.map((worker) => {
      return new Promise<void>((resolve) => {
        worker.on('message', (msg) => {
          if (msg.type === 'finished') {
            worker.terminate().then(() => resolve())
          }
        })
        worker.on('error', () => {
          worker
            .terminate()
            .then(() => resolve())
            .catch(() => resolve())
        })
        worker.postMessage({ type: 'finishWork' })
      })
    })

    await Promise.all(workerPromises)
    this.workersDead = true
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Lifetime worker listeners
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Installs lifetime-scoped message, error, and exit listeners on all workers.
   * Message listeners route simulation results and deny-detail checks to the
   * correct request state using requestId. Error/exit listeners detect crashes
   * and mark the processor as fatally failed.
   */
  private installLifetimeWorkerListeners(): void {
    for (const worker of this.workers) {
      worker.on('message', (msg: any) => {
        this.handleWorkerMessage(msg, worker)
      })
      worker.on('error', (err) => {
        if (!this.isShutdown) {
          this.handleWorkerFailure(new Error(`Worker error: ${err.message}`))
        }
      })
      worker.on('exit', (code) => {
        if (!this.isShutdown && code !== 0) {
          this.handleWorkerFailure(new Error(`Worker exited unexpectedly with code ${code}`))
        }
      })
    }
  }

  /**
   * Routes a message from a worker thread to the appropriate handler based
   * on message type and requestId.
   *
   * @param msg - The message received from the worker.
   * @param worker - The worker that sent the message.
   */
  private handleWorkerMessage(msg: any, worker: Worker): void {
    if (msg.type === 'requestTask') {
      const task = this.dequeueNextScenario()
      worker.postMessage({ type: 'task', workerId: msg.workerId, task })
    } else if (msg.type === 'result') {
      this.handleSimulationResult(msg.requestId, msg.result, !!msg.denyDetailsCheckWillFollow)
    } else if (msg.type === 'checkDenyDetails') {
      this.handleCheckDenyDetails(msg.requestId, msg.checkId, msg.lightAnalysis, worker)
    } else if (msg.type === 'denyDetailsResult') {
      this.handleDenyDetailsResult(msg.requestId, msg.denyDetail)
    }
  }

  /**
   * Creates the main-thread simulation runner if mainThreadConcurrency > 0.
   * The runner pulls from the FIFO scheduler and routes results by requestId.
   */
  private createMainThreadRunner(): void {
    const mainThreadConcurrency = this.config.tuning?.mainThreadConcurrency ?? 50
    if (mainThreadConcurrency <= 0) {
      return
    }

    const { collectGrantDetails, s3AbacOverride } = this.config

    this.mainThreadWorker = createMainThreadStreamingWorkQueue(
      () => this.dequeueNextScenario(),
      (requestId, result) => this.handleSimulationResult(requestId, result),
      (requestId, lightAnalysis) => {
        const state = this.requestStates.get(requestId)
        if (state && !state.settled) {
          return state.denyDetailsCallback?.(lightAnalysis) ?? false
        }
        return false
      },
      (requestId, detail) => this.handleDenyDetailsResult(requestId, detail),
      this.collectClient,
      s3AbacOverride,
      collectGrantDetails ?? false,
      mainThreadConcurrency
    )
  }

  // ──────────────────────────────────────────────────────────────────────────
  // FIFO queue-of-queues scheduler
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Dequeues the next simulation scenario using FIFO request priority.
   * Prefers the oldest active request that has ready scenarios. If the oldest
   * is temporarily empty (still preparing), falls back to the next request
   * with ready scenarios so cores do not idle. Queued scenarios for failed
   * requests are canceled and counted as completed without being simulated.
   *
   * @returns the next work item, or undefined if no scenarios are ready.
   */
  private dequeueNextScenario(): (WhoCanWorkItem & { requestId: string }) | undefined {
    for (const requestId of [...this.activeRequestOrder]) {
      const state = this.requestStates.get(requestId)
      if (!state) {
        continue
      }

      if (state.settled) {
        // The request failed after these scenarios were queued. Drain them
        // without simulation so created/completed remains balanced for cleanup.
        while (state.scenarios.dequeue()) {
          state.completed++
        }
        this.checkRequestDrain(state)
        continue
      }

      const item = state.scenarios.dequeue()
      if (item) {
        return { ...item, requestId }
      }
    }

    return undefined
  }

  /**
   * Notifies all simulation consumers (workers and main thread) that new
   * work may be available in the scheduler.
   */
  private notifySimulationConsumers(): void {
    this.mainThreadWorker?.notifyWorkAvailable()
    for (const worker of this.workers) {
      worker.postMessage({ type: 'workAvailable' })
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Admission pump
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Wakes the admission pump to process pending requests. If the pump is
   * already running, this is a no-op — the running pump will pick up new
   * pending requests on its next iteration.
   */
  private wakeAdmissionPump(): void {
    if (this.admissionPumpRunning) return
    this.admissionPumpRunning = true

    // Run asynchronously so enqueueWhoCan returns immediately
    void this.runAdmissionPump()
  }

  /**
   * The admission pump loop. Drains pendingRequests into active processing
   * up to maxRequestsInProgress. Only one instance of this loop runs at a time,
   * guarded by admissionPumpRunning.
   */
  private async runAdmissionPump(): Promise<void> {
    const maxActive = this.config.tuning?.maxRequestsInProgress ?? 30

    try {
      while (this.pendingRequests.length > 0 && this.activeRequestOrder.length < maxActive) {
        if (this.isShutdown) break

        const submitted = this.pendingRequests.shift()!
        const state = this.createRequestState(submitted)

        this.requestStates.set(submitted.requestId, state)
        this.activeRequestOrder.push(submitted.requestId)

        // Enqueue the root preparation job for this request
        this.enqueueRootPreparation(state)
      }
    } finally {
      this.admissionPumpRunning = false
    }

    // After admitting, check if we became idle
    this.checkIdle()
  }

  /**
   * Creates a fresh RequestState for an admitted request.
   *
   * @param submitted - The submitted request to create state for.
   * @returns the new RequestState.
   */
  private createRequestState(submitted: SubmittedRequest): RequestState {
    return {
      requestId: submitted.requestId,
      request: submitted.request,
      allScenariosCreated: false,
      scenarios: new StreamingWorkQueue<WhoCanWorkItem>(),
      created: 0,
      completed: 0,
      pendingPreparationJobs: 0,
      allowed: [],
      principalsNotFound: [],
      accountsNotFound: [],
      organizationsNotFound: [],
      organizationalUnitsNotFound: [],
      allAccountsChecked: false,
      denyDetails: [],
      simulationCount: 0,
      denyDetailsCallback: submitted.request.denyDetailsCallback,
      pendingDenyDetailsChecks: 0,
      settled: false,
      callbackInvoked: false,
      simulationErrors: []
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Preparation
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Enqueues the root preparation job for a request. This job performs resource
   * account resolution, resource policy lookup, action expansion, principal scope
   * handling, and then enqueues follow-up preparation jobs to enumerate principals.
   *
   * @param state - The request state to prepare.
   */
  private enqueueRootPreparation(state: RequestState): void {
    state.pendingPreparationJobs++

    this.preparationQueue.enqueue({
      properties: {},
      execute: async () => {
        try {
          await this.executeRootPreparation(state)
        } catch (err) {
          this.settleRequestAsError(state, err instanceof Error ? err : new Error(String(err)))
        } finally {
          state.pendingPreparationJobs--
          this.notifySimulationConsumers()
          this.checkRequestCompletion(state)
        }
      }
    })
  }

  /**
   * Executes the root preparation for a request: resolves the resource account,
   * fetches the resource policy, expands actions, determines which accounts and
   * principals to check, and enqueues follow-up preparation jobs.
   *
   * @param state - The request state to prepare.
   */
  private async executeRootPreparation(state: RequestState): Promise<void> {
    if (state.settled) return

    const { request } = state
    const { resource } = request
    const collectClient = this.collectClient

    if (!request.resourceAccount && !request.resource) {
      throw new Error('Either resourceAccount or resource must be provided in the request.')
    }

    const resourceAccount =
      request.resourceAccount || (await getAccountIdForResource(collectClient, resource!))

    if (!resourceAccount) {
      throw new Error(
        `Could not determine account ID for resource ${resource}. Please use a different ARN or specify resourceAccount.`
      )
    }

    const actions = await actionsForWhoCan({
      actions: request.actions,
      resource: request.resource
    })
    if (!actions || actions.length === 0) {
      throw new Error('No valid actions provided or found for the resource.')
    }

    const untrustingActions = await actionsThatDoNotAutomaticallyTrustTheCurrentAccount()

    let resourcePolicy: ValidatedPolicy<{ name: string }> | undefined = undefined
    if (resource) {
      resourcePolicy = await getResourcePolicyForResource(collectClient, resource, resourceAccount)
      const resourceArn = new Arn(resource)
      if (
        (resourceArn.matches({ service: 'iam', resourceType: 'role' }) ||
          resourceArn.matches({ service: 'kms', resourceType: 'key' })) &&
        !resourcePolicy
      ) {
        throw new Error(
          `Unable to find resource policy for ${resource}. Cannot determine who can access the resource.`
        )
      }

      if (resourcePolicy && resourcePolicy.errors.length > 0) {
        log.error({
          iamLensResourcePolicyValidationErrors: true,
          errors: resourcePolicy.errors,
          resource: resource
        })
        throw new Error(
          `Resource policy for ${resource} has validation errors and cannot be used for simulation.`
        )
      }
    }

    const accountsToCheck = await accountsToCheckBasedOnResourcePolicy(
      resourcePolicy,
      resourceAccount,
      collectClient
    )

    // An empty scope excludes anonymous too; a supplied scope must explicitly opt in.
    const anonymousInScope = !request.principalScope || request.principalScope.anonymous === true
    if (resource && accountsToCheck.checkAnonymous && anonymousInScope) {
      for (const action of new Set(actions)) {
        const [service, actionName] = action.split(':')
        if ((await iamActionDetails(service, actionName)).isWildcardOnly) {
          continue
        }
        state.scenarios.enqueue({
          simulationVariant: 'anonymous',
          principal: 'anonymous',
          resource,
          resourceAccount,
          action,
          discoveryContextKeyConstraints: request.discoveryContextKeyConstraints,
          collectDenyDetails: !!state.denyDetailsCallback
        })
        state.created++
      }
    }

    const principalArnFilter = buildPrincipalArnFilter(resourcePolicy)
    const uniqueAccounts = await uniqueAccountsToCheck(collectClient, accountsToCheck)

    // Store not-found arrays on the request state
    state.accountsNotFound = uniqueAccounts.accountsNotFound
    state.organizationsNotFound = uniqueAccounts.organizationsNotFound
    state.organizationalUnitsNotFound = uniqueAccounts.organizationalUnitsNotFound
    state.allAccountsChecked = request.principalScope ? false : accountsToCheck.allAccounts

    // The resource account is always a candidate for search — for non-untrusting
    // actions same-account principals can access via identity policy alone. Include
    // it in the base accounts list so the principalScope intersection can see it.
    const baseAccounts = uniqueAccounts.accounts.includes(resourceAccount)
      ? uniqueAccounts.accounts
      : [...uniqueAccounts.accounts, resourceAccount]

    let accountsForSearch = baseAccounts
    let principalsForSearch = accountsToCheck.specificPrincipals
    let scopeIncludesResourceAccount = true

    if (request.principalScope) {
      const resolved = await resolvePrincipalScope(collectClient, request.principalScope)
      const intersection = intersectWithPrincipalScope(
        baseAccounts,
        accountsToCheck.specificPrincipals,
        accountsToCheck.allAccounts,
        resolved.accounts,
        resolved.principals
      )
      accountsForSearch = intersection.accounts
      principalsForSearch = intersection.principals
      scopeIncludesResourceAccount = resolved.accounts.has(resourceAccount)
    }

    // Principals explicitly named in the resource policy are enqueued via the
    // specific-principals path (which skips the PrincipalArn filter). Track them
    // so the account-enumeration paths can skip duplicates without needing to
    // store all enumerated principals in memory.
    const specificPrincipalSet = new Set(principalsForSearch)

    // Enqueue follow-up preparation jobs for account/principal enumeration
    const principalIndexExists =
      !this.config.ignorePrincipalIndex && (await collectClient.principalIndexExists())

    if (principalIndexExists) {
      // Use the principal index to find relevant principals directly
      state.pendingPreparationJobs++
      this.preparationQueue.enqueue({
        properties: {},
        execute: async () => {
          try {
            if (state.settled) return

            // Pre-compute an accounts list without the resource account for
            // untrusting actions where the policy does not trust it.
            const accountsWithoutResourceAccount =
              scopeIncludesResourceAccount && !accountsToCheck.resourceAccountTrustedByPolicy
                ? accountsForSearch.filter((a) => a !== resourceAccount)
                : accountsForSearch

            for (const action of actions) {
              const isUntrusting = untrustingActions.has(action.toLowerCase())
              const allFromAccount =
                scopeIncludesResourceAccount && accountsToCheck.checkAllFromResourceAccount
                  ? resourceAccount
                  : undefined

              const actionAccountsForSearch = isUntrusting
                ? accountsWithoutResourceAccount
                : accountsForSearch

              const indexedPrincipals = await collectClient.getPrincipalsWithActionAllowed(
                allFromAccount,
                actionAccountsForSearch,
                action
              )
              for (const principal of indexedPrincipals || []) {
                if (specificPrincipalSet.has(principal)) continue
                if (
                  principalArnFilter &&
                  !isServicePrincipal(principal) &&
                  !principalMatchesFilter(principal, action, resourceAccount, principalArnFilter)
                ) {
                  continue
                }
                state.scenarios.enqueue({
                  simulationVariant: 'authenticated',
                  resource,
                  action,
                  principal,
                  resourceAccount,
                  discoveryContextKeyConstraints: state.request.discoveryContextKeyConstraints,
                  collectDenyDetails: !!state.denyDetailsCallback
                })
                state.created++
              }
            }

            this.notifySimulationConsumers()
          } catch (err) {
            this.settleRequestAsError(state, err instanceof Error ? err : new Error(String(err)))
          } finally {
            state.pendingPreparationJobs--
            this.checkRequestCompletion(state)
          }
        }
      })
    } else {
      // No principal index — enumerate all principals per account
      for (const account of accountsForSearch) {
        state.pendingPreparationJobs++
        this.preparationQueue.enqueue({
          properties: {},
          execute: async () => {
            try {
              if (state.settled) return

              const principals = await collectClient.getAllPrincipalsInAccount(account)
              for (const principal of principals) {
                if (specificPrincipalSet.has(principal)) continue
                const skipFilter = !principalArnFilter || isServicePrincipal(principal)
                for (const action of actions) {
                  if (
                    !skipFilter &&
                    !principalMatchesFilter(principal, action, resourceAccount, principalArnFilter!)
                  ) {
                    continue
                  }
                  state.scenarios.enqueue({
                    simulationVariant: 'authenticated',
                    resource,
                    action,
                    principal,
                    resourceAccount,
                    discoveryContextKeyConstraints: state.request.discoveryContextKeyConstraints,
                    collectDenyDetails: !!state.denyDetailsCallback
                  })
                  state.created++
                }
              }

              this.notifySimulationConsumers()
            } catch (err) {
              this.settleRequestAsError(state, err instanceof Error ? err : new Error(String(err)))
            } finally {
              state.pendingPreparationJobs--
              this.checkRequestCompletion(state)
            }
          }
        })
      }
    }

    // Enqueue specific principals from resource policy (iterate the Set to
    // deduplicate — the same principal can appear in the list more than once
    // when multiple statements reference it, e.g. an explicit Principal element
    // and a StringEquals aws:PrincipalArn condition).
    for (const principal of specificPrincipalSet) {
      state.pendingPreparationJobs++
      this.preparationQueue.enqueue({
        properties: {},
        execute: async () => {
          try {
            if (state.settled) return

            if (isServicePrincipal(principal)) {
              for (const action of actions) {
                state.scenarios.enqueue({
                  simulationVariant: 'authenticated',
                  resource,
                  action,
                  principal,
                  resourceAccount,
                  discoveryContextKeyConstraints: state.request.discoveryContextKeyConstraints,
                  collectDenyDetails: !!state.denyDetailsCallback
                })
                state.created++
              }
            } else if (
              isIamUserArn(principal) ||
              isIamRoleArn(principal) ||
              isAssumedRoleArn(principal)
            ) {
              const resolvedPrincipal = await collectClient.resolvePrincipalArn(principal)
              if (!resolvedPrincipal) {
                state.principalsNotFound.push(principal)
              } else {
                for (const action of actions) {
                  state.scenarios.enqueue({
                    simulationVariant: 'authenticated',
                    resource,
                    action,
                    principal,
                    resultPrincipal: resolvedPrincipal,
                    resourceAccount,
                    discoveryContextKeyConstraints: state.request.discoveryContextKeyConstraints,
                    collectDenyDetails: !!state.denyDetailsCallback
                  })
                  state.created++
                }
              }
            } else {
              state.principalsNotFound.push(principal)
            }

            this.notifySimulationConsumers()
          } catch (err) {
            this.settleRequestAsError(state, err instanceof Error ? err : new Error(String(err)))
          } finally {
            state.pendingPreparationJobs--
            this.checkRequestCompletion(state)
          }
        }
      })
    }

    // All follow-up prep jobs have been enqueued. Mark scenarios as fully specified
    // once the root prep and all follow-ups complete (tracked by pendingPreparationJobs).
    state.allScenariosCreated = true
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Simulation result handling
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Handles a simulation result from a worker or the main thread runner.
   * Routes the result to the correct request state and checks for completion.
   *
   * @param requestId - The ID of the request this result belongs to.
   * @param result - The simulation job result.
   */
  private handleSimulationResult(
    requestId: string,
    result: JobResult<WhoCanAllowed | undefined, Record<string, unknown>>,
    denyDetailsCheckWillFollow: boolean = false
  ): void {
    const state = this.requestStates.get(requestId)
    if (!state) return

    state.completed++

    if (denyDetailsCheckWillFollow) {
      state.pendingDenyDetailsChecks++
    }

    if (state.settled) {
      // Request already settled (e.g., failed). Still count the result so
      // the drain check can fire, but discard the actual data.
      this.checkRequestCompletion(state)
      return
    }

    state.simulationCount++

    if (result.status === 'fulfilled' && result.value) {
      state.allowed.push(result.value)
    } else if (result.status === 'rejected') {
      log.error('Error running simulation', { error: result.reason })
      state.simulationErrors.push(result)
    }

    this.checkRequestCompletion(state)
  }

  /**
   * Handles a checkDenyDetails request from a worker thread. Looks up the
   * request's denyDetailsCallback and responds.
   *
   * @param requestId - The ID of the request.
   * @param checkId - The unique check ID for this deny-details round trip.
   * @param lightAnalysis - The light analysis to pass to the callback.
   * @param worker - The worker to respond to.
   */
  private handleCheckDenyDetails(
    requestId: string,
    checkId: number,
    lightAnalysis: LightRequestAnalysis,
    worker: Worker
  ): void {
    const state = this.requestStates.get(requestId)
    const shouldInclude =
      state && !state.settled ? (state.denyDetailsCallback?.(lightAnalysis) ?? false) : false

    if (!shouldInclude && state) {
      // No denyDetailsResult message will follow — decrement the counter
      state.pendingDenyDetailsChecks--
      this.checkRequestCompletion(state)
    }

    worker.postMessage({
      type: 'denyDetailsCheckResult',
      checkId,
      shouldInclude
    })
  }

  /**
   * Handles a deny details result from a worker thread. Decrements the
   * pending deny-details counter and checks for request completion.
   *
   * @param requestId - The ID of the request.
   * @param denyDetail - The deny detail to store.
   */
  private handleDenyDetailsResult(requestId: string, denyDetail: WhoCanDenyDetail): void {
    const state = this.requestStates.get(requestId)
    if (!state) return

    if (state.pendingDenyDetailsChecks > 0) {
      state.pendingDenyDetailsChecks--
    }

    if (!state.settled) {
      state.denyDetails.push(denyDetail)
    }

    this.checkRequestCompletion(state)
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Request completion and settlement
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Checks whether a request has completed all preparation and simulation work.
   * If so, settles the request as successful.
   *
   * @param state - The request state to check.
   */
  private checkRequestCompletion(state: RequestState): void {
    if (state.settled) {
      this.checkRequestDrain(state)
      return
    }
    if (!state.allScenariosCreated) return
    if (state.pendingPreparationJobs > 0) return
    if (state.created !== state.completed) return
    if (state.pendingDenyDetailsChecks > 0) return

    // All work done — settle as success
    if (state.simulationErrors.length > 0) {
      this.settleRequestAsError(
        state,
        new Error(
          `Completed with ${state.simulationErrors.length} simulation errors. See previous logs.`
        )
      )
    } else {
      this.settleRequestAsSuccess(state)
    }
  }

  /**
   * Settles a request as successful: builds the WhoCanResponse, awaits
   * onRequestSettled, removes the request from active state, and wakes
   * the admission pump.
   *
   * @param state - The request state to settle.
   */
  private settleRequestAsSuccess(state: RequestState): void {
    if (state.settled) return
    state.settled = true

    const result: WhoCanResponse = {
      simulationCount: state.simulationCount,
      allowed: state.allowed,
      allAccountsChecked: state.allAccountsChecked,
      accountsNotFound: state.accountsNotFound,
      organizationsNotFound: state.organizationsNotFound,
      organizationalUnitsNotFound: state.organizationalUnitsNotFound,
      principalsNotFound: state.principalsNotFound,
      denyDetails: state.denyDetailsCallback ? state.denyDetails : undefined
    }

    if (state.request.sort) {
      sortWhoCanResults(result)
    }

    void this.invokeSettledCallbackAndCleanup(state, {
      status: 'fulfilled',
      requestId: state.requestId,
      request: state.request,
      result
    })
  }

  /**
   * Settles a request as failed: invokes onRequestSettled with the error
   * immediately, but keeps the request in active state until queued scenarios
   * are canceled and in-flight work drains (created === completed). Late
   * results for settled requests are discarded but still counted so the drain
   * completes.
   *
   * @param state - The request state to settle.
   * @param error - The error that caused the failure.
   */
  private settleRequestAsError(state: RequestState, error: Error): void {
    if (state.settled) {
      return
    }
    state.settled = true

    // Await the callback (backpressure), then mark it done so checkRequestDrain
    // can free the slot once all in-flight work also completes.
    void (async () => {
      await this.invokeSettledCallback({
        status: 'rejected',
        requestId: state.requestId,
        request: state.request,
        error
      })
      state.callbackInvoked = true
      this.checkRequestDrain(state)
    })()
  }

  /**
   * Invokes the onRequestSettled callback and routes any errors through
   * {@link handleSettlementFailure}.
   *
   * @param event - The settlement event to deliver.
   */
  private async invokeSettledCallback(event: WhoCanSettledEvent): Promise<void> {
    try {
      await this.config.onRequestSettled(event)
    } catch (err) {
      await this.handleSettlementFailure(event, err)
    }
  }

  /**
   * Awaits the onRequestSettled callback, then removes the request from
   * active state and wakes the admission pump. Used for successful settlements
   * where all work is already complete.
   *
   * @param state - The request state being settled.
   * @param event - The settlement event to deliver.
   */
  private async invokeSettledCallbackAndCleanup(
    state: RequestState,
    event: WhoCanSettledEvent
  ): Promise<void> {
    await this.invokeSettledCallback(event)
    this.removeFromActiveState(state)
  }

  /**
   * Checks whether a settled request has fully drained: the onRequestSettled
   * callback has been awaited, all preparation jobs have finished, all
   * simulation results have been received, and all deny-detail round trips
   * have completed. Only then is the request removed from active state.
   *
   * @param state - The request state to check.
   */
  private checkRequestDrain(state: RequestState): void {
    if (!state.settled) return
    if (!state.callbackInvoked) return
    if (state.pendingPreparationJobs > 0) return
    if (state.created !== state.completed) return
    if (state.pendingDenyDetailsChecks > 0) return

    this.removeFromActiveState(state)
  }

  /**
   * Removes a request from active state, wakes the admission pump to fill
   * the freed slot, and checks if the processor is now idle.
   *
   * @param state - The request state to remove.
   */
  private removeFromActiveState(state: RequestState): void {
    const idx = this.activeRequestOrder.indexOf(state.requestId)
    if (idx !== -1) {
      this.activeRequestOrder.splice(idx, 1)
    }
    this.requestStates.delete(state.requestId)

    this.wakeAdmissionPump()
    this.checkIdle()
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Idle checking
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Returns true if the processor has no pending, active, or in-flight work.
   *
   * @returns true if fully idle.
   */
  private isIdle(): boolean {
    return this.pendingRequests.length === 0 && this.activeRequestOrder.length === 0
  }

  /**
   * Checks whether the processor has become idle and resolves or rejects the
   * waitForIdle promise if so.
   */
  private checkIdle(): void {
    if (!this.isIdle()) return
    if (this.idleWaiters.length === 0) return

    const waiters = this.idleWaiters.splice(0)
    if (this.fatalError) {
      for (const waiter of waiters) {
        waiter.reject(this.fatalError)
      }
    } else {
      for (const waiter of waiters) {
        waiter.resolve()
      }
    }
  }

  /**
   * Handles an error thrown by the `onRequestSettled` callback. If the
   * `onSettlementFailure` callback is defined, it is invoked with the event
   * and error; any error it throws is silently ignored. If not defined, a
   * warning is logged.
   *
   * @param event - The settlement event that was being delivered.
   * @param err - The raw error thrown by the `onRequestSettled` callback.
   */
  private async handleSettlementFailure(event: WhoCanSettledEvent, err: unknown): Promise<void> {
    const error = err instanceof Error ? err : new Error(String(err))
    if (this.config.onSettlementFailure) {
      try {
        await this.config.onSettlementFailure(event, error)
      } catch {
        // onSettlementFailure itself failed — silently ignored
      }
    } else {
      log.warn('onRequestSettled callback failed and no onSettlementFailure handler is defined', {
        requestId: event.requestId,
        error
      })
    }
  }

  /**
   * Handles an unexpected worker failure by marking the processor as dead,
   * terminating remaining workers, and rejecting all active and pending requests.
   *
   * @param error - The error that caused the worker failure.
   */
  private handleWorkerFailure(error: Error): void {
    this.workersDead = true
    this.isShutdown = true
    this.fatalError = error

    // Terminate remaining workers (fire-and-forget)
    for (const worker of this.workers) {
      worker.terminate().catch(() => {})
    }

    // Settle all active requests as failed
    for (const requestId of [...this.activeRequestOrder]) {
      const state = this.requestStates.get(requestId)
      if (state && !state.settled) {
        this.settleRequestAsError(state, error)
      }
    }

    // Reject all pending requests
    while (this.pendingRequests.length > 0) {
      const submitted = this.pendingRequests.shift()!
      const event: WhoCanSettledEvent = {
        status: 'rejected',
        requestId: submitted.requestId,
        request: submitted.request,
        error
      }
      void this.config
        .onRequestSettled(event)
        .catch((err) => this.handleSettlementFailure(event, err))
        .catch(() => {})
    }

    // Reject all idle waiters
    const waiters = this.idleWaiters.splice(0)
    for (const waiter of waiters) {
      waiter.reject(error)
    }
  }
}
