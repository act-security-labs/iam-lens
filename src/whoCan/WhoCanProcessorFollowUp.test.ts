import { describe, expect, it, vi } from 'vitest'
import { getTestDatasetConfigs } from '../test-datasets/testClient.js'
import { WhoCanProcessor, type WhoCanSettledEvent } from './WhoCanProcessor.js'

describe('WhoCanProcessor follow-up preparation', () => {
  it('admits the next request only after skipped work, preparation, and the error callback drain', async () => {
    //Given a failed request with pending preparation and a held error callback
    const events: WhoCanSettledEvent[] = []
    let releaseCallback!: () => void
    const callbackGate = new Promise<void>((resolve) => {
      releaseCallback = resolve
    })
    let signalCallback!: () => void
    const callbackStarted = new Promise<void>((resolve) => {
      signalCallback = resolve
    })
    const processor = await WhoCanProcessor.create({
      collectConfigs: getTestDatasetConfigs('2'),
      partition: 'aws',
      tuning: { workerThreads: 0, mainThreadConcurrency: 1, maxRequestsInProgress: 1 },
      onRequestSettled: async (event) => {
        events.push(event)
        if (event.status === 'rejected') {
          signalCallback()
          await callbackGate
        }
      }
    })
    vi.spyOn(processor['collectClient'], 'principalIndexExists').mockResolvedValue(true)
    let releaseLookup!: () => void
    const lookupGate = new Promise<void>((resolve) => {
      releaseLookup = resolve
    })
    let signalLookup!: () => void
    const lookupStarted = new Promise<void>((resolve) => {
      signalLookup = resolve
    })
    vi.spyOn(processor['collectClient'], 'getPrincipalsWithActionAllowed').mockImplementation(
      async () => {
        signalLookup()
        await lookupGate
        return []
      }
    )
    const resource = 'arn:aws:s3:::no-bpa-public-bucket/report.txt'
    try {
      const failedId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:GetObject'],
        principalScope: { accounts: ['500000000003'] }
      })
      await lookupStarted
      const failed = processor['requestStates'].get(failedId)!
      processor['enqueueScenario'](failed, {
        simulationVariant: 'authenticated',
        resource,
        resourceAccount: '500000000003',
        principal: 'arn:aws:iam::500000000003:role/example',
        action: 's3:GetObject',
        collectDenyDetails: false
      })
      processor['settleRequestAsError'](failed, new Error('preparation failed'))
      await callbackStarted
      const nextId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:GetObject'],
        principalScope: { anonymous: true }
      })

      //When the scheduler skips the settled scenario while the callback is held
      processor['dequeueNextScenario']()
      expect(failed).toMatchObject({ created: 1, completed: 1, callbackInvoked: false })
      expect(processor['activeRequestOrder']).toEqual([failedId])
      expect(processor['requestStates'].has(nextId)).toBe(false)
      releaseLookup()
      await new Promise<void>((resolve) => setImmediate(resolve))
      expect(failed.pendingPreparationJobs).toBe(0)
      expect(processor['activeRequestOrder']).toEqual([failedId])

      //Then releasing the callback admits and completes the next request
      releaseCallback()
      await processor.waitForIdle()
      expect(events).toEqual([
        expect.objectContaining({ requestId: failedId, status: 'rejected' }),
        expect.objectContaining({
          requestId: nextId,
          status: 'fulfilled',
          result: expect.objectContaining({
            simulationCount: 1,
            allowed: [expect.objectContaining({ principal: 'anonymous', action: 'GetObject' })]
          })
        })
      ])
    } finally {
      releaseLookup()
      releaseCallback()
      processor['notifySimulationConsumers']()
      await processor.shutdown()
      vi.restoreAllMocks()
    }
  })

  it('returns the next request after removing a drained settled request', async () => {
    //Given two requests whose preparation jobs are held open
    const events: WhoCanSettledEvent[] = []
    const processor = await WhoCanProcessor.create({
      collectConfigs: getTestDatasetConfigs('2'),
      partition: 'aws',
      tuning: { workerThreads: 0, mainThreadConcurrency: 1, preparationConcurrency: 2 },
      onRequestSettled: async (event) => {
        events.push(event)
      }
    })
    vi.spyOn(processor['collectClient'], 'principalIndexExists').mockResolvedValue(true)
    let releaseLookups!: () => void
    const lookupGate = new Promise<void>((resolve) => {
      releaseLookups = resolve
    })
    let bothLookupsStarted!: () => void
    const lookupsStarted = new Promise<void>((resolve) => {
      bothLookupsStarted = resolve
    })
    let lookupCount = 0
    vi.spyOn(processor['collectClient'], 'getPrincipalsWithActionAllowed').mockImplementation(
      async () => {
        lookupCount++
        if (lookupCount === 2) {
          bothLookupsStarted()
        }
        await lookupGate
        return []
      }
    )
    const resource = 'arn:aws:s3:::no-bpa-public-bucket/report.txt'
    try {
      const failedId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:GetObject'],
        principalScope: { accounts: ['500000000003'] }
      })
      const otherId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:GetObject'],
        principalScope: { accounts: ['500000000003'] }
      })
      await lookupsStarted
      const failed = processor['requestStates'].get(failedId)!
      const other = processor['requestStates'].get(otherId)!
      const scenario = {
        simulationVariant: 'authenticated' as const,
        resource,
        resourceAccount: '500000000003',
        principal: 'arn:aws:iam::500000000003:role/example',
        action: 's3:GetObject',
        collectDenyDetails: false
      }
      // Hold scheduler notifications while preparation and the error callback complete.
      const notify = processor['notifySimulationConsumers'].bind(processor)
      processor['notifySimulationConsumers'] = () => {}
      let signalPreparationDone!: () => void
      const preparationDone = new Promise<void>((resolve) => {
        signalPreparationDone = resolve
      })
      const checkCompletion = processor['checkRequestCompletion'].bind(processor)
      processor['checkRequestCompletion'] = (state) => {
        checkCompletion(state)
        if (state === failed && state.pendingPreparationJobs === 0) {
          signalPreparationDone()
        }
      }
      processor['enqueueScenario'](failed, scenario)
      processor['enqueueScenario'](failed, scenario)
      processor['enqueueScenario'](other, scenario)
      processor['settleRequestAsError'](failed, new Error('preparation failed'))
      releaseLookups()
      await preparationDone
      expect(failed).toMatchObject({ callbackInvoked: true, pendingPreparationJobs: 0 })

      //When the scheduler skips the settled scenarios and removes their request
      const next = processor['dequeueNextScenario']()

      //Then the shifted next request's work is still returned
      expect(failed).toMatchObject({ created: 2, completed: 2, settled: true })
      expect(processor['requestStates'].has(failedId)).toBe(false)
      expect(next).toEqual({ ...scenario, requestId: otherId })
      processor['notifySimulationConsumers'] = notify
      processor['handleSimulationResult'](otherId, {
        status: 'fulfilled',
        value: undefined,
        properties: {}
      })
      await processor.waitForIdle()
      expect(events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ requestId: failedId, status: 'rejected' }),
          expect.objectContaining({ requestId: otherId, status: 'fulfilled' })
        ])
      )
    } finally {
      releaseLookups()
      processor['notifySimulationConsumers']()
      await processor.shutdown()
      vi.restoreAllMocks()
    }
  })

  it('continues processing other requests after a preparation failure', async () => {
    //Given a processor whose indexed lookup fails only for one action
    const events: WhoCanSettledEvent[] = []
    const processor = await WhoCanProcessor.create({
      collectConfigs: getTestDatasetConfigs('2'),
      partition: 'aws',
      tuning: { workerThreads: 0, mainThreadConcurrency: 1, maxRequestsInProgress: 2 },
      onRequestSettled: async (event) => {
        events.push(event)
      }
    })
    vi.spyOn(processor['collectClient'], 'principalIndexExists').mockResolvedValue(true)
    vi.spyOn(processor['collectClient'], 'getPrincipalsWithActionAllowed').mockImplementation(
      async (_allFromAccount, _accounts, action) => {
        if (action === 's3:PutObject') {
          throw new Error('indexed lookup failed')
        }
        return []
      }
    )
    const resource = 'arn:aws:s3:::no-bpa-public-bucket/report.txt'
    try {
      //When a failing request and an unrelated anonymous request are submitted together
      const failedId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:PutObject'],
        principalScope: { accounts: ['500000000003'] }
      })
      const successfulId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:GetObject'],
        principalScope: { anonymous: true }
      })
      await processor.waitForIdle()

      //Then the failed request reports an error and the other yields its actual access result
      expect(events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            requestId: failedId,
            status: 'rejected',
            error: expect.objectContaining({ message: 'indexed lookup failed' })
          }),
          expect.objectContaining({
            requestId: successfulId,
            status: 'fulfilled',
            result: expect.objectContaining({
              simulationCount: 1,
              allowed: [
                expect.objectContaining({
                  service: 's3',
                  action: 'GetObject',
                  principal: 'anonymous'
                })
              ]
            })
          })
        ])
      )
      expect(events).toHaveLength(2)

      // A request submitted after the failure also completes on the same processor.
      const laterId = processor.enqueueWhoCan({
        resource,
        actions: ['s3:GetObject'],
        principalScope: { anonymous: true }
      })
      await processor.waitForIdle()
      expect(events).toHaveLength(3)
      expect(events[2]).toEqual(
        expect.objectContaining({
          requestId: laterId,
          status: 'fulfilled',
          result: expect.objectContaining({
            simulationCount: 1,
            allowed: [
              expect.objectContaining({
                service: 's3',
                action: 'GetObject',
                principal: 'anonymous'
              })
            ]
          })
        })
      )
    } finally {
      await processor.shutdown()
      vi.restoreAllMocks()
    }
  })

  it('skips queued and late scenarios after a request settles', async () => {
    //Given a request held in an indexed lookup while scenarios are queued
    const events: WhoCanSettledEvent[] = []
    const processor = await WhoCanProcessor.create({
      collectConfigs: getTestDatasetConfigs('2'),
      partition: 'aws',
      tuning: { workerThreads: 0, mainThreadConcurrency: 1 },
      onRequestSettled: async (event) => {
        events.push(event)
      }
    })
    vi.spyOn(processor['collectClient'], 'principalIndexExists').mockResolvedValue(true)
    let releaseLookup!: () => void
    const lookupGate = new Promise<void>((resolve) => {
      releaseLookup = resolve
    })
    let signalLookup!: () => void
    const lookupStarted = new Promise<void>((resolve) => {
      signalLookup = resolve
    })
    vi.spyOn(processor['collectClient'], 'getPrincipalsWithActionAllowed').mockImplementation(
      async () => {
        signalLookup()
        await lookupGate
        return []
      }
    )
    const processedActions: string[] = []
    const dequeue = processor['dequeueNextScenario'].bind(processor)
    processor['dequeueNextScenario'] = () => {
      const item = dequeue()
      if (item) {
        processedActions.push(item.action)
      }
      return item
    }
    let notifications = 0
    const notify = processor['notifySimulationConsumers'].bind(processor)
    processor['notifySimulationConsumers'] = () => {
      notifications++
      notify()
    }

    try {
      const requestId = processor.enqueueWhoCan({
        resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
        actions: ['s3:GetObject'],
        principalScope: { accounts: ['500000000003'] }
      })
      await lookupStarted
      const state = processor['requestStates'].get(requestId)!
      const scenario = {
        simulationVariant: 'authenticated' as const,
        resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
        resourceAccount: '500000000003',
        principal: 'arn:aws:iam::500000000003:role/example',
        action: 's3:GetObject',
        collectDenyDetails: false
      }

      //When two scenarios are queued and the request fails before the consumer runs
      processor['enqueueScenario'](state, scenario)
      processor['enqueueScenario'](state, scenario)
      processor['settleRequestAsError'](state, new Error('lookup failed'))
      processor['enqueueScenario'](state, scenario)
      await Promise.resolve()

      //Then the queued and late scenarios are counted without being simulated
      expect(state).toMatchObject({ created: 3, settled: true })
      expect(notifications).toBe(1)
      releaseLookup()
      await processor.waitForIdle()
      expect(state.completed).toBe(3)
      expect(processedActions).toEqual([])
      expect(events).toEqual([
        expect.objectContaining({
          status: 'rejected',
          error: expect.objectContaining({ message: 'lookup failed' })
        })
      ])
    } finally {
      releaseLookup()
      processor['notifySimulationConsumers']()
      await processor.shutdown()
      vi.restoreAllMocks()
    }
  })

  it('drains queued scenarios when an indexed follow-up lookup fails', async () => {
    //Given an indexed lookup held while the simulation consumer becomes idle
    const settledEvents: WhoCanSettledEvent[] = []
    const processor = await WhoCanProcessor.create({
      collectConfigs: getTestDatasetConfigs('2'),
      partition: 'aws',
      tuning: { workerThreads: 0, mainThreadConcurrency: 1, preparationConcurrency: 2 },
      onRequestSettled: async (event) => {
        settledEvents.push(event)
      }
    })
    const client = processor['collectClient']
    vi.spyOn(client, 'principalIndexExists').mockResolvedValue(true)
    let releaseFirstLookup!: () => void
    const firstLookupGate = new Promise<void>((resolve) => {
      releaseFirstLookup = resolve
    })
    let signalFirstLookup!: () => void
    const firstLookupStarted = new Promise<void>((resolve) => {
      signalFirstLookup = resolve
    })
    let firstLookupPending = false
    let signalConsumerIdle!: () => void
    const consumerIdle = new Promise<void>((resolve) => {
      signalConsumerIdle = resolve
    })
    const dequeue = processor['dequeueNextScenario'].bind(processor)
    processor['dequeueNextScenario'] = () => {
      const item = dequeue()
      if (firstLookupPending && !item) {
        signalConsumerIdle()
      }
      return item
    }
    const lookup = vi.spyOn(client, 'getPrincipalsWithActionAllowed')
    lookup.mockImplementationOnce(async () => {
      firstLookupPending = true
      signalFirstLookup()
      await firstLookupGate
      firstLookupPending = false
      return ['arn:aws:iam::500000000003:role/example']
    })
    lookup.mockRejectedValueOnce(new Error('indexed lookup failed'))

    try {
      const requestId = processor.enqueueWhoCan({
        resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
        actions: ['s3:GetObject', 's3:PutObject'],
        principalScope: { accounts: ['500000000003'] }
      })
      await firstLookupStarted
      // Ensure the consumer has pulled an empty queue before the lookup resumes.
      processor['notifySimulationConsumers']()
      await consumerIdle

      //When one action queues a scenario and the next indexed lookup fails
      releaseFirstLookup()
      const becameIdle = await Promise.race([
        processor.waitForIdle().then(() => true),
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000))
      ])

      //Then the request rejects and all created scenarios drain
      const state = processor['requestStates'].get(requestId)
      expect(settledEvents).toEqual([
        expect.objectContaining({
          status: 'rejected',
          error: expect.objectContaining({ message: 'indexed lookup failed' })
        })
      ])
      if (!becameIdle) {
        expect(state).toMatchObject({ created: 1, completed: 0, settled: true })
      }
      expect(becameIdle).toBe(true)
    } finally {
      releaseFirstLookup()
      // Wake any stranded work so teardown completes even if the assertion fails.
      processor['notifySimulationConsumers']()
      await processor.shutdown()
      vi.restoreAllMocks()
    }
  })
})
