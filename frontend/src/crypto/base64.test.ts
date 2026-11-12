import { Buffer } from 'node:buffer'

import { beforeAll, describe, expect, it } from 'vitest'

import { InvalidInputError } from './errors'
import { fromBase64, toBase64 } from './internal'
import { ready } from './sodium'

/** Deterministic mulberry32 PRNG; no Math.random in these tests. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let value = Math.imul(state ^ (state >>> 15), 1 | state)
    value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value
    return (value ^ (value >>> 14)) >>> 0
  }
}

function seededBytes(length: number, seed: number): Uint8Array {
  const random = mulberry32(seed)
  const bytes = new Uint8Array(length)
  for (let index = 0; index < length; index += 1) {
    bytes[index] = random() & 0xff
  }
  return bytes
}

beforeAll(async () => {
  await ready()
})

describe('strict standard base64', () => {
  it('encodes and decodes exactly like Node Buffer for every length 0..257', () => {
    for (let length = 0; length <= 257; length += 1) {
      const bytes = seededBytes(length, 0x9e3779b9 ^ length)
      const encoded = toBase64(bytes)
      const expected = Buffer.from(bytes).toString('base64')

      expect(encoded, `encoded length ${length}`).toBe(expected)

      const decoded = fromBase64(expected, 'value')
      expect(Array.from(decoded), `decoded length ${length}`).toEqual(
        Array.from(bytes),
      )
    }
  })

  it('accepts the empty string as the canonical encoding of zero bytes', () => {
    expect(toBase64(new Uint8Array(0))).toBe('')
    expect(fromBase64('', 'value')).toHaveLength(0)
  })

  it.each([
    ['whitespace', 'T Q=='],
    ['leading newline', '\nTQ=='],
    ['trailing newline', 'TQ==\n'],
    ['tab', 'TQ\t=='],
    ['URL-safe dash', '-_8='],
    ['URL-safe underscore', 'T_8='],
    ['missing one padding byte', 'TQ='],
    ['missing two padding bytes', 'TQ'],
    ['missing padding on two bytes', 'TWE'],
    ['extra padding byte', 'TQ==='],
    ['extra padding bytes', 'TQ===='],
    ['non-canonical trailing bits', 'TR=='],
    ['non-canonical two-byte trailing bits', 'TWF='],
    ['character outside alphabet', 'TQ==!'],
    ['asterisk', '****'],
    ['lone padding', '='],
    ['only padding', '===='],
    ['length 1', 'A'],
    ['length 5', 'AAAAA'],
    ['length 3 unpadded', 'AAA'],
  ])('rejects %s with InvalidInputError', (_label, value) => {
    expect(() => fromBase64(value, 'value')).toThrow(InvalidInputError)
  })
})
