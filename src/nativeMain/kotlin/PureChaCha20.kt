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

// ChaCha20 written in plain Kotlin — the strongest case for owning a primitive
// rather than calling OpenSSL.
//
// Unlike AES and SHA-256, ChaCha20 has no instruction anywhere: every
// implementation, OpenSSL's included, is add-rotate-xor over SIMD registers.
// So there is no hardware advantage to concede, and the only question is
// whether Kotlin/Native's code generation vectorises the quarter-round as well
// as OpenSSL's hand-written assembly does.
//
// This is the keystream only. Poly1305 is deliberately absent, which means the
// number it produces is an *upper bound* on a hand-written AEAD rather than a
// like-for-like comparison — a real one would be slower still. It is reported
// as `chacha20 / xor` rather than `chacha20poly1305` to keep that visible.
package com.xemantic.noumen.crypto.bench

/** A plain-Kotlin ChaCha20 keystream, keyed once. Not authenticated. */
class PureChaCha20(key: ByteArray) {

    private val state = IntArray(16)
    private val working = IntArray(16)

    init {
        require(key.size == 32) { "key must be 32 bytes, was ${key.size}" }
        state[0] = C0; state[1] = C1; state[2] = C2; state[3] = C3
        for (i in 0 until 8) state[4 + i] = le32(key, i * 4)
    }

    private fun block(counter: Int) {
        state[12] = counter
        state.copyInto(working)
        repeat(10) {
            working.quarterRound(0, 4, 8, 12); working.quarterRound(1, 5, 9, 13)
            working.quarterRound(2, 6, 10, 14); working.quarterRound(3, 7, 11, 15)
            working.quarterRound(0, 5, 10, 15); working.quarterRound(1, 6, 11, 12)
            working.quarterRound(2, 7, 8, 13); working.quarterRound(3, 4, 9, 14)
        }
        for (i in 0 until 16) working[i] += state[i]
    }

    /** XORs [len] bytes of [input] into [out] under [nonce], starting at block 1. */
    fun xor(nonce: ByteArray, input: ByteArray, len: Int, out: ByteArray) {
        require(nonce.size == 12) { "nonce must be 12 bytes, was ${nonce.size}" }
        state[13] = le32(nonce, 0)
        state[14] = le32(nonce, 4)
        state[15] = le32(nonce, 8)

        var off = 0
        var counter = 1
        while (off + 64 <= len) {
            block(counter++)
            for (i in 0 until 16) {
                val v = working[i]
                val j = off + i * 4
                out[j] = (input[j].toInt() xor v).toByte()
                out[j + 1] = (input[j + 1].toInt() xor (v ushr 8)).toByte()
                out[j + 2] = (input[j + 2].toInt() xor (v ushr 16)).toByte()
                out[j + 3] = (input[j + 3].toInt() xor (v ushr 24)).toByte()
            }
            off += 64
        }
        if (off < len) {
            block(counter)
            var k = 0
            while (off + k < len) {
                val v = working[k shr 2] ushr (8 * (k and 3))
                out[off + k] = (input[off + k].toInt() xor v).toByte()
                k++
            }
        }
    }
}
