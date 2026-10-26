import BitSet from 'bitset'

/**
 * A BitSet instance compatible with every supported version of the bitset package.
 */
export type BitSetInstance = InstanceType<typeof BitSet>

/**
 * Encode a BitSet into a more compact representation
 *
 * @param bitset the BitSet to encode
 * @returns the encoded representation
 */
export function encodeBitSet(bitset: BitSetInstance): any {
  const rawHex = bitset.toString(16)
  const compressedHex = compressHex(rawHex)
  const sparseString = ',' + bitset.toArray().join(',')

  if (sparseString.length < compressedHex.length && sparseString.length < rawHex.length) {
    return sparseString
  }

  if (compressedHex.length < rawHex.length) {
    return compressedHex
  }

  return rawHex
}

/**
 * Decode a BitSet from a compact representation
 *
 * @param encoded the encoded representation
 * @returns the decoded BitSet
 */
export function decodeBitSet(encoded: any): BitSetInstance {
  if (Array.isArray(encoded)) {
    const bitset = new BitSet()
    bitset.setRange(encoded[0], encoded[1], 1)
    return bitset
  } else if (typeof encoded === 'string') {
    // Check if it's a sparse array (comma-separated numbers)
    if (encoded.startsWith(',')) {
      // It's a sparse array - convert to BitSet
      const positions = encoded.slice(1).split(',').map(Number)
      const bitset = new BitSet()
      positions.forEach((pos) => bitset.set(pos, 1))
      return bitset
    } else if (encoded.includes('z')) {
      // It's compressed hex - decompress first
      const decompressedHex = decompressHex(encoded)
      return BitSet.fromHexString(decompressedHex)
    } else if (encoded === '') {
      return new BitSet()
    } else {
      // Assume it's raw hex
      return BitSet.fromHexString(encoded)
    }
  }

  // Handle other formats if needed
  return BitSet.fromHexString(encoded)
}

/**
 * Compress a hexadecimal string by replacing runs of zeros with a compact representation
 *
 * @param rawHex the original hexadecimal string
 * @returns the compressed hexadecimal string
 */
export function compressHex(rawHex: string): string {
  const repeatedZeroPattern = /((0){4,})/g
  return rawHex.replace(repeatedZeroPattern, (match) => {
    return `z${match.length} `
  })
}

/**
 * Decompress a hexadecimal string
 *
 * @param compressedHex the compressed hexadecimal string
 * @returns the decompressed hexadecimal string
 */
export function decompressHex(compressedHex: string): string {
  // Handle the "z" compression pattern (z followed by number of zeros)
  const zeroPattern = /z(\d+)\s*/g
  return compressedHex.replace(zeroPattern, (match, count) => {
    return '0'.repeat(parseInt(count, 10))
  })
}

/**
 * Compress a principal string for storage
 *
 * @param principalString the full principal string
 * @returns the compressed principal string
 */
export function compressPrincipalString(principalString: string): string {
  const parts = principalString.split(':')
  let accountId = parts[4]
  let end = parts.slice(5).join(':')
  if (end.startsWith('role/aws-reserved/')) {
    end = end.replace('role/aws-reserved/', 'ar/')
  } else if (end.startsWith('role/aws-service-role/')) {
    end = end.replace('role/aws-service-role/', 'asr/')
  } else if (end.startsWith('role/service-role/')) {
    end = end.replace('role/service-role/', 'sr/')
  } else if (end.startsWith('role/')) {
    end = end.replace('role/', 'r/')
  } else if (end.startsWith('user/')) {
    end = end.replace('user/', 'u/')
  }
  return `${accountId}:${end}`
}

/**
 * Decompress a principal string
 *
 * @param compressedString the compressed principal string
 * @param prefix the ARN prefix to use
 * @returns the decompressed principal string
 */
export function decompressPrincipalString(
  compressedString: string,
  prefix: string = 'arn:aws:iam::'
): string {
  const parts = compressedString.split(':')
  if (parts.length !== 2) {
    throw new Error(`Invalid compressed principal format: ${compressedString}`)
  }

  const accountId = parts[0]
  let roleType = parts[1]

  // Expand compressed role types back to full paths
  if (roleType.startsWith('ar/')) {
    roleType = roleType.replace('ar/', 'role/aws-reserved/')
  } else if (roleType.startsWith('asr/')) {
    roleType = roleType.replace('asr/', 'role/aws-service-role/')
  } else if (roleType.startsWith('sr/')) {
    roleType = roleType.replace('sr/', 'role/service-role/')
  } else if (roleType.startsWith('r/')) {
    roleType = roleType.replace('r/', 'role/')
  } else if (roleType.startsWith('u/')) {
    roleType = roleType.replace('u/', 'user/')
  }

  return `${prefix}${accountId}:${roleType}`
}
