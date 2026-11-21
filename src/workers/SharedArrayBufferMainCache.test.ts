import { EventEmitter } from 'events'
import { Worker } from 'worker_threads'
import { describe, expect, it } from 'vitest'
import { convertArrayBufferToObject, convertObjectToArrayBuffer } from './buffers.js'
import { SharedArrayBufferMainCache } from './SharedArrayBufferMainCache.js'

class FakeWorker extends EventEmitter {
  readonly posted: any[] = []
  postMessage(message: any) {
    this.posted.push(message)
  }
}

const payload = (i: number) => ({ id: i, body: 'x'.repeat(1000) })

describe('SharedArrayBufferMainCache', () => {
  it('keeps the cached bytes within maxBytes as main-thread entries accumulate', async () => {
    //Given a cache capped at roughly ten entries
    const entryBytes = convertObjectToArrayBuffer(payload(0)).byteLength
    const cache = new SharedArrayBufferMainCache([], { maxBytes: entryBytes * 10 })

    //When a thousand distinct keys are cached
    for (let i = 0; i < 1000; i++) {
      await cache.withCache(`key-${i}`, async () => payload(i))
    }

    //Then the cache holds no more than the cap
    expect(cache.byteLength).toBeLessThanOrEqual(entryBytes * 10)
  })

  it('keeps the cached bytes within maxBytes as workers save entries', () => {
    //Given a cache capped at roughly ten entries and a worker
    const worker = new FakeWorker()
    const entryBytes = convertObjectToArrayBuffer(payload(0)).byteLength
    const cache = new SharedArrayBufferMainCache([worker as unknown as Worker], {
      maxBytes: entryBytes * 10
    })

    //When the worker saves a thousand distinct keys
    for (let i = 0; i < 1000; i++) {
      worker.emit('message', {
        type: 'saveCache',
        cacheKey: `key-${i}`,
        value: convertObjectToArrayBuffer(payload(i))
      })
    }

    //Then the cache holds no more than the cap
    expect(cache.byteLength).toBeLessThanOrEqual(entryBytes * 10)
  })

  it('evicts the least recently used entry first', async () => {
    //Given a cache that fits two entries, holding a and b, where a was read last
    const entryBytes = convertObjectToArrayBuffer(payload(0)).byteLength
    const cache = new SharedArrayBufferMainCache([], { maxBytes: entryBytes * 2 })
    await cache.withCache('a', async () => payload(0))
    await cache.withCache('b', async () => payload(1))
    await cache.withCache('a', async () => payload(99))

    //When a third entry is cached
    await cache.withCache('c', async () => payload(2))

    //Then b was evicted and a is still served from the cache
    let refetched = false
    const a = await cache.withCache('a', async () => {
      refetched = true
      return payload(99)
    })
    expect(refetched).toBe(false)
    expect(a).toEqual(payload(0))
    const b = await cache.withCache('b', async () => payload(42))
    expect(b).toEqual(payload(42))
  })

  it('answers a worker cache miss for an evicted key', () => {
    //Given a cache that fits one entry, after a second key pushed the first out
    const worker = new FakeWorker()
    const entryBytes = convertObjectToArrayBuffer(payload(0)).byteLength
    new SharedArrayBufferMainCache([worker as unknown as Worker], { maxBytes: entryBytes })
    worker.emit('message', {
      type: 'saveCache',
      cacheKey: 'a',
      value: convertObjectToArrayBuffer(payload(0))
    })
    worker.emit('message', {
      type: 'saveCache',
      cacheKey: 'b',
      value: convertObjectToArrayBuffer(payload(1))
    })

    //When the worker asks for both keys
    worker.emit('message', { type: 'getCache', cacheKey: 'a' })
    worker.emit('message', { type: 'getCache', cacheKey: 'b' })

    //Then a misses and b hits
    expect(worker.posted[0]).toEqual({ type: 'cacheMiss', cacheKey: 'a' })
    expect(worker.posted[1].type).toBe('cacheHit')
    expect(convertArrayBufferToObject(worker.posted[1].value)).toEqual(payload(1))
  })
})
