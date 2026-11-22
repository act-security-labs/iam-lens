import { Worker } from 'worker_threads'
import { convertArrayBufferToObject, convertObjectToArrayBuffer } from './buffers.js'

export interface Cache {
  withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T>
}

export interface SharedArrayBufferMainCacheOptions {
  /**
   * The most bytes of serialized entries the cache holds. Past it, the least recently
   * used entries are evicted. Defaults to 256 MiB.
   */
  maxBytes?: number
}

export const DEFAULT_SHARED_CACHE_MAX_BYTES = 256 * 1024 * 1024

//TODO: Add a Prefix to avoid collisions if there are multiple caches
export class SharedArrayBufferMainCache implements Cache {
  // Map iteration order is insertion order; reads re-insert, so the first key is the least recently used.
  private cache = new Map<string, SharedArrayBuffer>()
  private bytes = 0
  private readonly maxBytes: number

  constructor(workers: Worker[], options: SharedArrayBufferMainCacheOptions = {}) {
    this.maxBytes = options.maxBytes ?? DEFAULT_SHARED_CACHE_MAX_BYTES
    for (const worker of workers) {
      worker.on('message', (message) => {
        if (message.type === 'getCache') {
          const cacheKey = message.cacheKey
          const value = this.get(cacheKey)
          if (value) {
            worker.postMessage({ type: 'cacheHit', cacheKey, value })
          } else {
            worker.postMessage({ type: 'cacheMiss', cacheKey })
          }
        } else if (message.type === 'saveCache') {
          this.set(message.cacheKey, message.value)
        }
      })
    }
  }

  /** The bytes of serialized entries currently held. */
  get byteLength(): number {
    return this.bytes
  }

  async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    const cached = this.get(cacheKey)
    if (cached) {
      return convertArrayBufferToObject(cached)
    }

    const result = await fetcher()
    this.set(cacheKey, convertObjectToArrayBuffer(result))
    return result
  }

  private get(cacheKey: string): SharedArrayBuffer | undefined {
    const value = this.cache.get(cacheKey)
    if (value) {
      this.cache.delete(cacheKey)
      this.cache.set(cacheKey, value)
    }
    return value
  }

  private set(cacheKey: string, value: SharedArrayBuffer): void {
    const previous = this.cache.get(cacheKey)
    if (previous) {
      this.bytes -= previous.byteLength
      this.cache.delete(cacheKey)
    }
    this.cache.set(cacheKey, value)
    this.bytes += value.byteLength
    for (const [key, entry] of this.cache) {
      if (this.bytes <= this.maxBytes) break
      this.cache.delete(key)
      this.bytes -= entry.byteLength
    }
  }
}
