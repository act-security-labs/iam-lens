import { log } from '@actsecurity/log'
import { randomBytes } from 'crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve } from 'path'
import { fileURLToPath } from 'url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getTestDatasetConfigs } from '../test-datasets/testClient.js'

const principalScopeFailure = vi.hoisted(() => ({ enabled: false }))

vi.mock('./principalScope.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./principalScope.js')>()
  return {
    ...actual,
    resolvePrincipalScope: async (...args: Parameters<typeof actual.resolvePrincipalScope>) => {
      if (principalScopeFailure.enabled) {
        throw new Error('principal scope lookup failed')
      }
      return actual.resolvePrincipalScope(...args)
    }
  }
})

import {
  WhoCanProcessor,
  type WhoCanProcessorConfig,
  type WhoCanSettledEvent
} from './WhoCanProcessor.js'

// @ts-ignore
const __dirname = fileURLToPath(new URL('.', import.meta.url))

/**
 * Creates a WhoCanProcessor configured for dataset 1, enqueues a single
 * known request, waits for idle, and shuts down.
 *
 * @param overrides - Partial config overrides.
 */
async function runSingleRequest(
  overrides: Partial<WhoCanProcessorConfig> & {
    onRequestSettled: WhoCanProcessorConfig['onRequestSettled']
    collectConfigs?: WhoCanProcessorConfig['collectConfigs']
    request?: Parameters<WhoCanProcessor['enqueueWhoCan']>[0]
  }
): Promise<void> {
  const processor = await WhoCanProcessor.create({
    collectConfigs: overrides.collectConfigs ?? getTestDatasetConfigs('1'),
    partition: 'aws',
    tuning: { workerThreads: 0 },
    ignorePrincipalIndex: true,
    ...overrides
  })

  try {
    processor.enqueueWhoCan(
      overrides.request ?? {
        actions: ['ec2:TerminateInstances'],
        resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0'
      }
    )

    await processor.waitForIdle()
  } finally {
    await processor.shutdown()
  }
}
describe('WhoCanProcessor Integration Tests', () => {
  describe('WhoCanProcessor request draining', () => {
    it('drains queued scenarios after root preparation fails', async () => {
      //Given multiple anonymous scenarios are queued before a later principal-scope lookup fails
      const settledEvents: WhoCanSettledEvent[] = []
      const processor = await WhoCanProcessor.create({
        collectConfigs: getTestDatasetConfigs('2'),
        partition: 'aws',
        tuning: { workerThreads: 0 },
        ignorePrincipalIndex: true,
        onRequestSettled: async (event) => {
          settledEvents.push(event)
        }
      })

      try {
        principalScopeFailure.enabled = true
        processor.enqueueWhoCan({
          resource: 'arn:aws:s3:::no-bpa-public-bucket/report.txt',
          actions: ['s3:GetObject', 's3:PutObject'],
          principalScope: { anonymous: true, accounts: ['500000000003'] }
        })

        //When the caller waits for the failed request to drain
        const becameIdle = await Promise.race([
          processor.waitForIdle().then(() => true),
          new Promise<false>((resolve) => setTimeout(() => resolve(false), 1_000))
        ])

        //Then the request reports its failure and does not retain queued anonymous work
        expect(becameIdle).toBe(true)
        expect(settledEvents).toEqual([
          expect.objectContaining({
            status: 'rejected',
            error: expect.objectContaining({ message: 'principal scope lookup failed' })
          })
        ])
      } finally {
        principalScopeFailure.enabled = false
        await processor.shutdown()
      }
    })
  })

  describe('WhoCanProcessor onSettlementFailure', () => {
    afterEach(() => {
      vi.restoreAllMocks()
    })

    it('should call onSettlementFailure when onRequestSettled throws', async () => {
      //Given an onRequestSettled that always throws
      const settledError = new Error('settled callback boom')
      const failureEvents: { event: WhoCanSettledEvent; error: Error }[] = []

      //When a request is processed
      await runSingleRequest({
        onRequestSettled: async () => {
          throw settledError
        },
        onSettlementFailure: async (event, error) => {
          failureEvents.push({ event, error })
        }
      })

      //Then onSettlementFailure should have been called with the event and error
      expect(failureEvents).toHaveLength(1)
      expect(failureEvents[0].error).toBe(settledError)
      expect(failureEvents[0].event.status).toBe('fulfilled')
      expect(failureEvents[0].event.requestId).toBeDefined()
    })

    it('should silently ignore errors thrown by onSettlementFailure', async () => {
      //Given an onRequestSettled that throws and an onSettlementFailure that also throws
      //When a request is processed
      //Then waitForIdle should resolve without throwing
      await expect(
        runSingleRequest({
          onRequestSettled: async () => {
            throw new Error('settled callback boom')
          },
          onSettlementFailure: async () => {
            throw new Error('failure handler boom')
          }
        })
      ).resolves.toBeUndefined()
    })

    it('should log a warning when onRequestSettled throws and no onSettlementFailure is defined', async () => {
      //Given an onRequestSettled that throws and no onSettlementFailure
      const warnSpy = vi.spyOn(log, 'warn')

      //When a request is processed
      await runSingleRequest({
        onRequestSettled: async () => {
          throw new Error('settled callback boom')
        }
      })

      //Then a warning should have been logged with the request ID and error
      expect(warnSpy).toHaveBeenCalledWith(
        'onRequestSettled callback failed and no onSettlementFailure handler is defined',
        expect.objectContaining({
          requestId: expect.any(String),
          error: expect.any(Error)
        })
      )
    })

    it('should not throw from waitForIdle when onRequestSettled throws', async () => {
      //Given an onRequestSettled that throws with no onSettlementFailure
      //When a request is processed and we await waitForIdle
      //Then it should resolve without throwing (errors are logged as warnings)
      await expect(
        runSingleRequest({
          onRequestSettled: async () => {
            throw new Error('settled callback boom')
          }
        })
      ).resolves.toBeUndefined()
    })
  })

  describe('WhoCanProcessor workerBootstrapPlugin', () => {
    const bootstrapFixturePath = resolve(__dirname, 'test-fixtures', 'testBootstrap.mjs')
    const failingFixturePath = resolve(__dirname, 'test-fixtures', 'failingBootstrap.mjs')

    it('should invoke the bootstrap module with data and threadId in each worker', async () => {
      //Given a bootstrap plugin that writes context to a temp file
      const outputPath = join(tmpdir(), `bootstrap-test-${Date.now()}-${Math.random()}.json`)

      try {
        //When a processor is created with a single worker (mainThreadConcurrency: 0
        //forces all work through the worker) and the bootstrap plugin
        const settledEvents: WhoCanSettledEvent[] = []
        await runSingleRequest({
          tuning: { workerThreads: 1, mainThreadConcurrency: 0 },
          workerBootstrapPlugin: {
            module: bootstrapFixturePath,
            factoryExport: 'testBootstrap',
            data: { outputPath, customField: 'hello' }
          },
          onRequestSettled: async (event) => {
            settledEvents.push(event)
          }
        })

        //Then the bootstrap module should have been invoked
        expect(existsSync(outputPath)).toBe(true)

        //And it should have received the correct context
        const context = JSON.parse(readFileSync(outputPath, 'utf-8'))
        expect(context.threadId).toBeGreaterThan(0)
        expect(context.isMainThread).toBe(false)
        expect(context.data.customField).toBe('hello')

        //And the request should have succeeded
        expect(settledEvents).toHaveLength(1)
        expect(settledEvents[0].status).toBe('fulfilled')
      } finally {
        if (existsSync(outputPath)) {
          rmSync(outputPath)
        }
      }
    })

    it('should fail processor creation when bootstrap module throws', async () => {
      //Given a bootstrap plugin that always throws
      //When a processor is created with the failing bootstrap
      //Then create() should reject with the bootstrap error
      await expect(
        WhoCanProcessor.create({
          collectConfigs: getTestDatasetConfigs('1'),
          partition: 'aws',
          tuning: { workerThreads: 1, mainThreadConcurrency: 0 },
          ignorePrincipalIndex: true,
          workerBootstrapPlugin: {
            module: failingFixturePath,
            factoryExport: 'failingBootstrap',
            data: {}
          },
          onRequestSettled: async () => {}
        })
      ).rejects.toThrow(/Worker startup failed|Worker exited with code/)
    })

    it('should work normally without a bootstrap plugin', async () => {
      //Given a processor with no bootstrap plugin and worker-only execution
      const settledEvents: WhoCanSettledEvent[] = []

      //When a request is processed with workers
      await runSingleRequest({
        tuning: { workerThreads: 1, mainThreadConcurrency: 0 },
        onRequestSettled: async (event) => {
          settledEvents.push(event)
        }
      })

      //Then the request should succeed normally
      expect(settledEvents).toHaveLength(1)
      expect(settledEvents[0].status).toBe('fulfilled')
    })
  })

  it('should settle the request as an error before enqueueing simulations when the resource policy is invalid', async () => {
    const sourceDataset = resolve(__dirname, '..', 'test-datasets', 'iam-data-1')
    const tempDataset = join(tmpdir(), `who-can-invalid-policy-${randomBytes(8).toString('hex')}`)
    mkdirSync(tempDataset, { recursive: true })
    const trustPolicyPath = join(
      tempDataset,
      'aws/aws/accounts/200000000002/iam/role/lambdarole/trust-policy.json'
    )

    try {
      cpSync(sourceDataset, tempDataset, { recursive: true })
      writeFileSync(
        trustPolicyPath,
        JSON.stringify(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'sts:AssumeRole'
              }
            ]
          },
          null,
          2
        )
      )

      const settledEvents: WhoCanSettledEvent[] = []
      await runSingleRequest({
        collectConfigs: [
          {
            iamCollectVersion: '0.0.0',
            storage: {
              type: 'file',
              path: tempDataset
            }
          }
        ],
        request: {
          resource: 'arn:aws:iam::200000000002:role/LambdaRole',
          actions: ['sts:AssumeRole']
        },
        onRequestSettled: async (event) => {
          settledEvents.push(event)
        }
      })

      expect(settledEvents).toHaveLength(1)
      expect(settledEvents[0].status).toBe('rejected')
      if (settledEvents[0].status !== 'rejected') {
        throw new Error(`Expected rejected settlement, got ${settledEvents[0].status}`)
      }

      expect(settledEvents[0].error.message).toContain('has validation errors')
    } finally {
      rmSync(tempDataset, { recursive: true, force: true })
    }
  })
})
