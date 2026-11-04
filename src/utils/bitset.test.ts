import BitSet from 'bitset'
import { describe, expect, it } from 'vitest'
import {
  compressHex,
  compressPrincipalString,
  decodeBitSet,
  decompressHex,
  decompressPrincipalString,
  encodeBitSet
} from './bitset.js'

describe('encodeBitSet', () => {
  it('should return sparse format for bitsets with few set bits', () => {
    //Given a sparse bitset with only a few bits set
    const sparseBitset = new BitSet()
    sparseBitset.set(6, 1).set(16, 1).set(43, 1).set(87, 1).set(119, 1)

    //When encoding the bitset
    const encoded = encodeBitSet(sparseBitset)

    //Then it should return a comma-separated string of positions
    expect(encoded).toBe(',6,16,43,87,119')
  })

  it('should return compressed hex for bitsets with long zero runs', () => {
    //Given a bitset with many consecutive zeros
    const bitset = new BitSet()
    bitset.set(0, 1).set(1, 1).set(100, 1) // Creates long runs of zeros

    //When encoding the bitset
    const encoded = encodeBitSet(bitset)

    //Then it should return compressed hex with zero run encoding
    expect(typeof encoded).toBe('string')
    expect(encoded).toMatch(/z\d+/)
  })

  it('should return raw hex when no compression is beneficial', () => {
    //Given a dense bitset where compression is not beneficial
    const denseBitset = new BitSet()
    denseBitset.setRange(0, 128, 1)

    //When encoding the bitset
    const encoded = encodeBitSet(denseBitset)

    //Then it should return the raw hex representation
    expect(typeof encoded).toBe('string')
    expect(encoded).toMatch(/^[0-9a-f]+$/i)
  })
})

describe('decodeBitSet', () => {
  it('should decode sparse format correctly', () => {
    //Given a sparse encoded bitset string
    const sparseString = ',6,16,43,87,119'

    //When decoding the bitset
    const decoded = decodeBitSet(sparseString)

    //Then it should recreate the original bitset
    expect(decoded.get(6)).toBe(1)
    expect(decoded.get(16)).toBe(1)
    expect(decoded.get(43)).toBe(1)
    expect(decoded.get(87)).toBe(1)
    expect(decoded.get(119)).toBe(1)
    expect(decoded.get(5)).toBe(0) // Should be 0
    expect(decoded.get(120)).toBe(0) // Should be 0
  })

  it('should decode compressed hex format correctly', () => {
    //Given a compressed hex string with zero runs
    const compressedHex = '3z8 1'

    //When decoding the bitset
    const decoded = decodeBitSet(compressedHex)

    //Then it should recreate the original bitset
    const expected = BitSet.fromHexString('3000000001')
    expect(decoded.toString()).toBe(expected.toString())
  })

  it('should decode raw hex format correctly', () => {
    //Given a raw hex string
    const rawHex = 'ff00'

    //When decoding the bitset
    const decoded = decodeBitSet(rawHex)

    //Then it should recreate the original bitset
    expect(decoded.toString(16)).toBe('ff00')
  })

  it('should decode array of two numbers as range correctly', () => {
    //Given an array with start and end positions for a range
    const rangeArray = [10, 15]

    //When decoding the bitset
    const decoded = decodeBitSet(rangeArray)

    //Then it should set all bits in the range (inclusive)
    expect(decoded.get(10)).toBe(1)
    expect(decoded.get(11)).toBe(1)
    expect(decoded.get(12)).toBe(1)
    expect(decoded.get(13)).toBe(1)
    expect(decoded.get(14)).toBe(1)
    expect(decoded.get(15)).toBe(1)
    expect(decoded.get(9)).toBe(0) // Should be 0 (outside range)
    expect(decoded.get(16)).toBe(0) // Should be 0 (outside range)
  })

  it('should decode array with single position range', () => {
    //Given an array where start and end are the same (single bit)
    const singleBitArray = [42, 42]

    //When decoding the bitset
    const decoded = decodeBitSet(singleBitArray)

    //Then it should set only that single bit
    expect(decoded.get(42)).toBe(1)
    expect(decoded.get(41)).toBe(0)
    expect(decoded.get(43)).toBe(0)
  })

  it.each([
    [0, 0],
    [30, 30],
    [30, 31],
    [31, 31],
    [31, 32],
    [32, 32],
    [0, 30],
    [0, 31],
    [0, 32],
    [0, 62],
    [0, 63],
    [30, 63],
    [31, 63],
    [32, 63],
    [62, 62],
    [62, 63],
    [63, 63],
    [63, 64],
    [64, 64],
    [0, 64],
    [0, 95],
    [95, 95]
  ])('decodes the inclusive range %i to %i exactly', (start, end) => {
    //Given an encoded range near a 32-bit word boundary
    const encoded = [start, end]
    const expected = Array.from({ length: end - start + 1 }, (_, index) => start + index)

    //When decoding the range
    const decoded = decodeBitSet(encoded)

    //Then only the inclusive range is set
    expect(decoded.toArray()).toEqual(expected)
  })

  it('should decode array with large range correctly', () => {
    //Given an array with a large range
    const largeRangeArray = [100, 200]

    //When decoding the bitset
    const decoded = decodeBitSet(largeRangeArray)

    //Then it should set all bits in the large range
    expect(decoded.get(100)).toBe(1)
    expect(decoded.get(150)).toBe(1)
    expect(decoded.get(200)).toBe(1)
    expect(decoded.get(99)).toBe(0)
    expect(decoded.get(201)).toBe(0)

    // Verify the range size
    const setBitsCount = decoded.toArray().length
    expect(setBitsCount).toBe(101) // 100 to 200 inclusive = 101 bits
  })

  it('should handle empty string as empty bitset', () => {
    //Given an empty string
    const emptyString = ''

    //When decoding the bitset
    const decoded = decodeBitSet(emptyString)

    //Then it should return an empty bitset
    expect(decoded.isEmpty()).toBe(true)
  })
})

describe('compressHex', () => {
  it('should compress long runs of zeros', () => {
    //Given a hex string with long runs of zeros
    const hexWithZeros = '30000000000001'

    //When compressing the hex
    const compressed = compressHex(hexWithZeros)

    //Then it should replace zero runs with z notation
    expect(compressed).toBe('3z12 1')
  })

  it('should not compress short runs of zeros', () => {
    //Given a hex string with short runs of zeros (less than 4)
    const hexWithShortZeros = '30001'

    //When compressing the hex
    const compressed = compressHex(hexWithShortZeros)

    //Then it should remain unchanged
    expect(compressed).toBe('30001')
  })

  it('should handle multiple zero runs', () => {
    //Given a hex string with multiple zero runs
    const hexWithMultipleRuns = '300000010000002'

    //When compressing the hex
    const compressed = compressHex(hexWithMultipleRuns)

    //Then it should compress both runs
    expect(compressed).toBe('3z6 1z6 2')
  })
})

describe('decompressHex', () => {
  it('should decompress z notation back to zeros', () => {
    //Given a compressed hex string with z notation
    const compressed = '3z5 1z3 2'

    //When decompressing the hex
    const decompressed = decompressHex(compressed)

    //Then it should expand z notation back to zeros
    expect(decompressed).toBe('30000010002')
  })

  it('should handle single z notation', () => {
    //Given a compressed hex with single z notation
    const compressed = 'z8 ff'

    //When decompressing the hex
    const decompressed = decompressHex(compressed)

    //Then it should expand to the correct number of zeros
    expect(decompressed).toBe('00000000ff')
  })

  it('should handle string without z notation', () => {
    //Given a string without any z notation
    const uncompressed = 'abc123'

    //When decompressing the hex
    const decompressed = decompressHex(uncompressed)

    //Then it should remain unchanged
    expect(decompressed).toBe('abc123')
  })
})

describe('compressPrincipalString', () => {
  it('should compress aws-reserved role paths', () => {
    //Given an AWS reserved role ARN
    const reservedRoleArn =
      'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Test'

    //When compressing the principal string
    const compressed = compressPrincipalString(reservedRoleArn)

    //Then it should use ar/ notation
    expect(compressed).toBe('123456789012:ar/sso.amazonaws.com/AWSReservedSSO_Test')
  })

  it('should compress aws-service-role paths', () => {
    //Given an AWS service role ARN
    const serviceRoleArn =
      'arn:aws:iam::123456789012:role/aws-service-role/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail'

    //When compressing the principal string
    const compressed = compressPrincipalString(serviceRoleArn)

    //Then it should use asr/ notation
    expect(compressed).toBe('123456789012:asr/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail')
  })

  it('should compress service-role paths', () => {
    //Given a service role ARN
    const serviceRoleArn = 'arn:aws:iam::123456789012:role/service-role/MyLambdaRole'

    //When compressing the principal string
    const compressed = compressPrincipalString(serviceRoleArn)

    //Then it should use sr/ notation
    expect(compressed).toBe('123456789012:sr/MyLambdaRole')
  })

  it('should compress regular role paths', () => {
    //Given a regular role ARN
    const roleArn = 'arn:aws:iam::123456789012:role/MyCustomRole'

    //When compressing the principal string
    const compressed = compressPrincipalString(roleArn)

    //Then it should use r/ notation
    expect(compressed).toBe('123456789012:r/MyCustomRole')
  })

  it('should compress user paths', () => {
    //Given a user ARN
    const userArn = 'arn:aws:iam::123456789012:user/MyUser'

    //When compressing the principal string
    const compressed = compressPrincipalString(userArn)

    //Then it should use u/ notation
    expect(compressed).toBe('123456789012:u/MyUser')
  })
})

describe('decompressPrincipalString', () => {
  it('should decompress ar/ notation back to aws-reserved path', () => {
    //Given a compressed principal with ar/ notation
    const compressed = '123456789012:ar/sso.amazonaws.com/AWSReservedSSO_Test'

    //When decompressing the principal string
    const decompressed = decompressPrincipalString(compressed)

    //Then it should expand to full aws-reserved path
    expect(decompressed).toBe(
      'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Test'
    )
  })

  it('should decompress asr/ notation back to aws-service-role path', () => {
    //Given a compressed principal with asr/ notation
    const compressed = '123456789012:asr/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail'

    //When decompressing the principal string
    const decompressed = decompressPrincipalString(compressed)

    //Then it should expand to full aws-service-role path
    expect(decompressed).toBe(
      'arn:aws:iam::123456789012:role/aws-service-role/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail'
    )
  })

  it('should decompress sr/ notation back to service-role path', () => {
    //Given a compressed principal with sr/ notation
    const compressed = '123456789012:sr/MyLambdaRole'

    //When decompressing the principal string
    const decompressed = decompressPrincipalString(compressed)

    //Then it should expand to full service-role path
    expect(decompressed).toBe('arn:aws:iam::123456789012:role/service-role/MyLambdaRole')
  })

  it('should decompress r/ notation back to role path', () => {
    //Given a compressed principal with r/ notation
    const compressed = '123456789012:r/MyCustomRole'

    //When decompressing the principal string
    const decompressed = decompressPrincipalString(compressed)

    //Then it should expand to full role path
    expect(decompressed).toBe('arn:aws:iam::123456789012:role/MyCustomRole')
  })

  it('should decompress u/ notation back to user path', () => {
    //Given a compressed principal with u/ notation
    const compressed = '123456789012:u/MyUser'

    //When decompressing the principal string
    const decompressed = decompressPrincipalString(compressed)

    //Then it should expand to full user path
    expect(decompressed).toBe('arn:aws:iam::123456789012:user/MyUser')
  })

  it('should use custom prefix when provided', () => {
    //Given a compressed principal and custom prefix
    const compressed = '123456789012:r/MyRole'
    const customPrefix = 'arn:aws:iam:us-west-2:'

    //When decompressing with custom prefix
    const decompressed = decompressPrincipalString(compressed, customPrefix)

    //Then it should use the custom prefix
    expect(decompressed).toBe('arn:aws:iam:us-west-2:123456789012:role/MyRole')
  })

  it('should throw error for invalid format', () => {
    //Given an invalid compressed principal format
    const invalidCompressed = 'invalid-format'

    //When attempting to decompress
    const decompress = () => decompressPrincipalString(invalidCompressed)

    //Then it should throw an error
    expect(decompress).toThrow('Invalid compressed principal format')
  })
})

describe('testBitSetRoundTrip', () => {
  it('should return true for successful round-trip with sparse encoding', () => {
    //Given a sparse bitset
    const sparseBitset = new BitSet()
    sparseBitset.set(10, 1).set(20, 1).set(30, 1)

    //When testing round-trip encoding/decoding
    const success = testBitSetRoundTrip(sparseBitset)

    //Then it should return true
    expect(success).toBe(true)
  })

  it('should return true for successful round-trip with compressed hex', () => {
    //Given a bitset that will use compressed hex
    const bitset = new BitSet()
    bitset.set(0, 1).set(1, 1).set(100, 1)

    //When testing round-trip encoding/decoding
    const success = testBitSetRoundTrip(bitset)

    //Then it should return true
    expect(success).toBe(true)
  })

  it('should return true for empty bitset', () => {
    //Given an empty bitset
    const emptyBitset = new BitSet()

    //When testing round-trip encoding/decoding
    const success = testBitSetRoundTrip(emptyBitset)

    //Then it should return true
    expect(success).toBe(true)
  })

  it('should handle array format in round-trip test', () => {
    //Given a bitset created from an array range
    const rangeArray = [5, 10]
    const originalBitset = decodeBitSet(rangeArray)

    //When testing round-trip encoding/decoding
    const success = testBitSetRoundTrip(originalBitset)

    //Then it should return true (maintaining data integrity)
    expect(success).toBe(true)
  })

  it('should roundtrip a single bit whose position is valid hex (position 14)', () => {
    //Given a bitset with only bit 14 set — the sparse encoding produces "14"
    //which is ambiguous with the hex string "14" (0x14 = bits 2 and 4)
    const original = new BitSet()
    original.set(14, 1)

    //When we encode and decode it
    const encoded = encodeBitSet(original)
    const decoded = decodeBitSet(encoded)

    //Then the decoded bitset should have exactly bit 14 set, not bits 2 and 4
    expect(decoded.toArray()).toEqual([14])
  })

  it('should roundtrip a single bit at position 10', () => {
    //Given a bitset with only bit 10 set — sparse encoding "10" is also valid hex
    const original = new BitSet()
    original.set(10, 1)

    //When we encode and decode it
    const encoded = encodeBitSet(original)
    const decoded = decodeBitSet(encoded)

    //Then the decoded bitset should have exactly bit 10 set
    expect(decoded.toArray()).toEqual([10])
  })
})

describe('testPrincipalRoundTrip', () => {
  it('should return true for successful principal round-trip', () => {
    //Given a valid principal ARN
    const principalArn =
      'arn:aws:iam::123456789012:role/aws-service-role/test.amazonaws.com/TestRole'

    //When testing round-trip compression/decompression
    const success = testPrincipalRoundTrip(principalArn)

    //Then it should return true
    expect(success).toBe(true)
  })

  it('should return false for invalid principal format', () => {
    //Given an invalid principal format
    const invalidPrincipal = 'not-a-valid-arn'

    //When testing round-trip compression/decompression
    const success = testPrincipalRoundTrip(invalidPrincipal)

    //Then it should return false
    expect(success).toBe(false)
  })
})

/**
 * Test round-trip encoding/decoding of bitsets
 */
export function testBitSetRoundTrip(bitset: BitSet): boolean {
  const encoded = encodeBitSet(bitset)
  const decoded = decodeBitSet(encoded)
  return bitset.toString() === decoded.toString()
}

/**
 * Test round-trip encoding/decoding of principal strings
 */
export function testPrincipalRoundTrip(principalArn: string): boolean {
  try {
    const compressed = compressPrincipalString(principalArn)
    const decompressed = decompressPrincipalString(compressed)
    return principalArn === decompressed
  } catch (error) {
    return false
  }
}

/**
 * Get compression statistics for a bitset
 */
export function getBitSetCompressionStats(bitset: BitSet): {
  original: string
  encoded: string
  compressionRatio: number
  method: 'sparse' | 'compressed-hex' | 'raw-hex'
} {
  const original = bitset.toString(16)
  const encoded = encodeBitSet(bitset)

  let method: 'sparse' | 'compressed-hex' | 'raw-hex'
  if (typeof encoded === 'string' && /^\d+(?:,\d+)*$/.test(encoded)) {
    method = 'sparse'
  } else if (typeof encoded === 'string' && encoded.includes('z')) {
    method = 'compressed-hex'
  } else {
    method = 'raw-hex'
  }

  return {
    original,
    encoded: encoded?.toString() || original,
    compressionRatio: encoded ? encoded.toString().length / original.length : 1,
    method
  }
}
