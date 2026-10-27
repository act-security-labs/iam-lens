import { type Job, type JobContext, type JobResult } from '@actsecurity/job'

/**
 * A Job runner that pulls tasks from a source and executes them concurrently.
 *
 * This will run a fixed number of workers up to the specified concurrency.
 */
export class PullBasedJobRunner<T = void, P = Record<string, unknown>, TaskDetails = any> {
  private concurrency: number
  private getNextTask: (workerId: number) => Promise<TaskDetails | undefined>
  private makeJobForTask: (jobDetails: TaskDetails) => Job<T, P>
  private onComplete: (result: JobResult<T, P>) => Promise<void>

  private isAcceptingWork = true
  private activeJobs = 0
  private notificationGeneration = 0
  private workers: Promise<void>[] = []
  private idlePromise:
    | {
        resolve: () => void
        promise: Promise<void>
      }
    | undefined = undefined

  /**
   * Creates an instance of PullBasedJobRunner.
   *
   * @param concurrency the number of concurrent workers to run
   * @param getNextTask a function that returns the next task for a worker
   * @param makeJobForTask a function that creates a job for the given task details
   * @param onComplete a function that is called when a job is completed
   */
  constructor(
    concurrency: number,
    getNextTask: (workerId: number) => Promise<TaskDetails | undefined>,
    makeJobForTask: (taskDetails: TaskDetails) => Job<T, P>,
    onComplete: (result: JobResult<T, P>) => Promise<void>
  ) {
    this.concurrency = concurrency
    this.getNextTask = getNextTask
    this.makeJobForTask = makeJobForTask
    this.onComplete = onComplete

    for (let i = 0; i < this.concurrency; i++) {
      this.workers.push(this.worker(i))
    }
  }

  /**
   * Create a worker for running tasks from the queue.
   *
   * @param workerId the ID of the worker
   * @returns A promise that resolves when the worker is done processing tasks.
   */
  private async worker(workerId: number): Promise<void> {
    while (true) {
      const generation = this.notificationGeneration
      const task = await this.getNextTask(workerId)

      if (!task) {
        // If no more tasks are available, and we are not accepting work, exit the loop
        if (!this.isAcceptingWork) {
          return
        }
        if (generation !== this.notificationGeneration) {
          continue
        }
        await this.waitForWork()
        continue
      }

      this.activeJobs++
      const job = this.makeJobForTask(task)
      const context: JobContext = { workerId }

      try {
        const value = await job.execute({ ...context, properties: job.properties })
        await this.onComplete({ status: 'fulfilled', value, properties: job.properties })
      } catch (reason) {
        await this.onComplete({ status: 'rejected', reason, properties: job.properties })
      } finally {
        this.activeJobs--
      }
    }
  }

  /**
   * Waits for work to be available in the queue.
   *
   * @returns A promise that resolves when new jobs are available to work on.
   */
  private async waitForWork(): Promise<void> {
    if (this.idlePromise) {
      return this.idlePromise.promise
    }

    let resolve: () => void = () => {}
    let promise = new Promise<void>((res) => {
      resolve = res
    })
    this.idlePromise = { resolve, promise }

    return this.idlePromise.promise
  }

  /**
   * Finish all work and shut down the workers when no further tasks are available.
   */
  public async finishAllWork(): Promise<void> {
    this.isAcceptingWork = false
    this.notifyWorkAvailable()
    await Promise.all(this.workers)
    this.workers = []
  }

  /**
   * Notify the workers that new work is available.
   */
  public notifyWorkAvailable(): void {
    this.notificationGeneration++
    this.idlePromise?.resolve()
    this.idlePromise = undefined
  }
}
