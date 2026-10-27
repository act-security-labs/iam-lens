import { describe, expect, it } from 'vitest'
import { PullBasedJobRunner } from './JobRunner.js'

describe('PullBasedJobRunner', () => {
  it('wakes a worker already waiting for work', async () => {
    //Given a worker that has exhausted the initially empty queue
    const queue: number[] = []
    let signalCompleted!: () => void
    const completed = new Promise<void>((resolve) => {
      signalCompleted = resolve
    })
    const results: number[] = []
    const runner = new PullBasedJobRunner<number, Record<string, never>, number>(
      1,
      async () => queue.shift(),
      (task) => ({ properties: {}, execute: async () => task }),
      async (result) => {
        if (result.status === 'fulfilled') {
          results.push(result.value)
          signalCompleted()
        }
      }
    )
    await new Promise<void>((resolve) => setImmediate(resolve))

    //When work arrives after the worker has parked
    queue.push(42)
    runner.notifyWorkAvailable()
    const processed = await Promise.race([
      completed.then(() => true),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), 1000))
    ])

    //Then the waiting worker wakes and processes the task
    try {
      expect(processed).toBe(true)
      expect(results).toEqual([42])
    } finally {
      await runner.finishAllWork()
    }
  })

  it('wakes all workers when a notification arrives during their empty pulls', async () => {
    //Given two workers with outstanding pulls that will return no task
    const firstPullResolvers: Array<(task: number | undefined) => void> = []
    const queue: number[] = []
    const results: number[] = []
    let signalCompleted!: () => void
    const completed = new Promise<void>((resolve) => {
      signalCompleted = resolve
    })
    const runner = new PullBasedJobRunner<number, Record<string, never>, number>(
      2,
      async (workerId) => {
        if (!firstPullResolvers[workerId]) {
          return new Promise<number | undefined>((resolve) => {
            firstPullResolvers[workerId] = resolve
          })
        }
        return queue.shift()
      },
      (task) => ({ properties: {}, execute: async () => task }),
      async (result) => {
        if (result.status === 'fulfilled') {
          results.push(result.value)
          if (results.length === 2) {
            signalCompleted()
          }
        }
      }
    )

    //When both pulls are stale and a single notification announces two tasks
    queue.push(11, 22)
    runner.notifyWorkAvailable()
    firstPullResolvers[0](undefined)
    firstPullResolvers[1](undefined)
    const processed = await Promise.race([
      completed.then(() => true),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), 1000))
    ])

    //Then neither worker loses the wakeup and both tasks complete
    try {
      expect(processed).toBe(true)
      expect([...results].sort((a, b) => a - b)).toEqual([11, 22])
    } finally {
      await runner.finishAllWork()
    }
  })

  it('finishes when shutdown begins during an outstanding empty pull', async () => {
    //Given a worker waiting for its first pull to resolve
    let resolvePull!: (task: number | undefined) => void
    const runner = new PullBasedJobRunner<number, Record<string, never>, number>(
      1,
      async () =>
        new Promise<number | undefined>((resolve) => {
          resolvePull = resolve
        }),
      (task) => ({ properties: {}, execute: async () => task }),
      async () => {}
    )

    //When shutdown starts before that pull completes
    const shutdown = runner.finishAllWork()
    resolvePull(undefined)
    const finished = await Promise.race([
      shutdown.then(() => true),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), 1000))
    ])

    //Then the worker exits without waiting for a further notification
    expect(finished).toBe(true)
  })

  it('retries a pull when work is notified before an empty pull resolves', async () => {
    //Given an outstanding empty pull and a job that arrives before it resolves
    let resolveFirstPull!: (task: number | undefined) => void
    const firstPull = new Promise<number | undefined>((resolve) => {
      resolveFirstPull = resolve
    })
    let nextTask: number | undefined
    let pulls = 0
    let finishJob!: () => void
    const completed = new Promise<void>((resolve) => {
      finishJob = resolve
    })
    const runner = new PullBasedJobRunner<number, Record<string, never>, number>(
      1,
      async () => {
        pulls++
        if (pulls === 1) {
          return firstPull
        }
        const task = nextTask
        nextTask = undefined
        return task
      },
      (task) => ({ properties: {}, execute: async () => task }),
      async (result) => {
        expect(result).toMatchObject({ status: 'fulfilled', value: 42 })
        finishJob()
      }
    )

    //When the notification arrives while the empty pull is in flight
    nextTask = 42
    runner.notifyWorkAvailable()
    resolveFirstPull(undefined)
    const processed = await Promise.race([
      completed.then(() => true),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), 1000))
    ])

    //Then the job is processed without needing another notification
    try {
      expect(processed).toBe(true)
    } finally {
      await runner.finishAllWork()
    }
  })
})
