/*
 * SPDX-FileCopyrightText: 2026 Kazimierz Pogoda / Xemantic
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * noumen-crypto-bench - benchmarks for noumen's cryptographic primitives
 * Copyright (C) 2026 Kazimierz Pogoda / Xemantic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// SHA-256 written in plain Kotlin, to answer one question: is it worth owning
// the primitive rather than calling OpenSSL?
//
// SHA-256 is the best possible case for that argument. It is the dominant cost
// in the LFS path (git-lfs hashes the plaintext for the object id whether or
// not it is encrypted), it is small enough to write correctly in an afternoon,
// and its specification has not moved since 2001.
//
// The measurement is in the `aead` suite as the `kn-pure` column. Read it
// against `kn-evp` before deciding, and see the ARMv8 note in `compress`.
package com.xemantic.noumen.crypto.bench

private val K256 = intArrayOf(
    0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(),
    0x3956c25b, 0x59f111f1, 0x923f82a4.toInt(), 0xab1c5ed5.toInt(),
    0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe.toInt(), 0x9bdc06a7.toInt(), 0xc19bf174.toInt(),
    0xe49b69c1.toInt(), 0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152.toInt(), 0xa831c66d.toInt(), 0xb00327c8.toInt(), 0xbf597fc7.toInt(),
    0xc6e00bf3.toInt(), 0xd5a79147.toInt(), 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(),
    0xa2bfe8a1.toInt(), 0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(),
    0xd192e819.toInt(), 0xd6990624.toInt(), 0xf40e3585.toInt(), 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(),
    0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt()
)

private val INITIAL = intArrayOf(
    0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
    0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19
)

/** A plain-Kotlin SHA-256. Reusable: call [hash] as often as you like. */
class PureSha256 {

    private val h = IntArray(8)
    private val w = IntArray(64)
    private val tail = ByteArray(128)

    /**
     * Compresses one 64-byte block at [off].
     *
     * There is no way to do better than this from Kotlin/Native. A hardware
     * SHA-256 runs on the ARMv8 `sha256h`/`sha256h2`/`sha256su0`/`sha256su1`
     * instructions, and Kotlin/Native offers neither intrinsics for them nor
     * inline assembly — reaching them means cinterop into C, at which point
     * OpenSSL is already there and already does it.
     */
    private fun compress(block: ByteArray, off: Int) {
        val w = w
        for (i in 0 until 16) {
            val j = off + i * 4
            w[i] = ((block[j].toInt() and 0xff) shl 24) or
                ((block[j + 1].toInt() and 0xff) shl 16) or
                ((block[j + 2].toInt() and 0xff) shl 8) or
                (block[j + 3].toInt() and 0xff)
        }
        for (i in 16 until 64) {
            val x = w[i - 15]
            val y = w[i - 2]
            val s0 = x.rotateRight(7) xor x.rotateRight(18) xor (x ushr 3)
            val s1 = y.rotateRight(17) xor y.rotateRight(19) xor (y ushr 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        }

        var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
        var e = h[4]; var f = h[5]; var g = h[6]; var t = h[7]

        for (i in 0 until 64) {
            val s1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
            val ch = (e and f) xor (e.inv() and g)
            val t1 = t + s1 + ch + K256[i] + w[i]
            val s0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
            val maj = (a and b) xor (a and c) xor (b and c)
            t = g; g = f; f = e; e = d + t1
            d = c; c = b; b = a; a = t1 + s0 + maj
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d
        h[4] += e; h[5] += f; h[6] += g; h[7] += t
    }

    /** Hashes [data] into [out], which must be 32 bytes. */
    fun hash(data: ByteArray, out: ByteArray) {
        require(out.size == 32) { "digest must be 32 bytes, was ${out.size}" }
        INITIAL.copyInto(h)

        val whole = data.size and 63.inv()
        var off = 0
        while (off < whole) {
            compress(data, off)
            off += 64
        }

        // The tail: what is left, then 0x80, then zeros, then the length in
        // bits as a big-endian 64-bit word — one padded block, or two when the
        // remainder leaves no room for the length.
        val rest = data.size - whole
        tail.fill(0)
        data.copyInto(tail, 0, whole, data.size)
        tail[rest] = 0x80.toByte()
        val padded = if (rest >= 56) 128 else 64
        val bits = data.size.toLong() * 8
        for (i in 0 until 8) {
            tail[padded - 1 - i] = (bits ushr (8 * i)).toByte()
        }
        compress(tail, 0)
        if (padded == 128) compress(tail, 64)

        for (i in 0 until 8) {
            out[i * 4] = (h[i] ushr 24).toByte()
            out[i * 4 + 1] = (h[i] ushr 16).toByte()
            out[i * 4 + 2] = (h[i] ushr 8).toByte()
            out[i * 4 + 3] = h[i].toByte()
        }
    }
}
