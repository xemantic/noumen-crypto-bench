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

@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.xemantic.noumen.crypto.bench

import com.xemantic.kotlin.test.assert
import kotlinx.cinterop.usePinned
import kotlin.random.Random
import kotlin.test.Test

/**
 * Guards the EVP binding layer and the one property the `parallel` suite is
 * built on: that sealing chunks out of order, with separate cipher contexts,
 * produces byte-identical output to sealing them in order with one.
 */
class RawEvpTest {

    @Test
    fun `should round trip a stream whose last chunk is partial`() {
        val plain = Random(42).nextBytes(CHUNK * 2 + 1234)
        val ct = ByteArray(sealedSize(plain.size))
        val back = ByteArray(plain.size)

        RawAead("ChaCha20-Poly1305", testKey).use {
            it.sealAll(plain, ct)
            it.openAll(ct, back)
        }

        assert(plain.contentEquals(back))
    }

    @Test
    fun `should reject a stream whose tag was tampered with`() {
        val plain = Random(42).nextBytes(CHUNK + 7)
        val ct = ByteArray(sealedSize(plain.size))
        val back = ByteArray(plain.size)

        RawAead("AES-256-GCM", testKey).use { aead ->
            aead.sealAll(plain, ct)
            ct[ct.size - 1] = (ct[ct.size - 1].toInt() xor 1).toByte()
            assert(runCatching { aead.openAll(ct, back) }.isFailure)
        }
    }

    @Test
    fun `should seal chunks out of order into byte-identical output`() {
        val plain = Random(42).nextBytes(CHUNK * 4 + 99)
        val chunks = chunkCount(plain.size)
        val serial = ByteArray(sealedSize(plain.size))
        val shuffled = ByteArray(sealedSize(plain.size))

        RawAead("ChaCha20-Poly1305", testKey).use { it.sealAll(plain, serial) }

        // Each chunk sealed by its own context, in reverse order — the worst
        // case for any hidden dependency on sequencing or on shared state.
        for (i in (0 until chunks).reversed()) {
            RawAead("ChaCha20-Poly1305", testKey).use { aead ->
                aead.initEncrypt()
                val offset = i * CHUNK
                val len = minOf(CHUNK, plain.size - offset)
                plain.usePinned { pp ->
                    shuffled.usePinned { sp ->
                        aead.sealChunk(
                            i.toLong(), i == chunks - 1,
                            pp.at(offset), len, sp.at(i * CT_CHUNK)
                        )
                    }
                }
            }
        }

        assert(serial.contentEquals(shuffled))
    }

    @Test
    fun `should hash incrementally to the same digest as a single update`() {
        val data = Random(42).nextBytes(CHUNK + 4096)
        val once = ByteArray(32)
        val chunked = ByteArray(32)

        RawDigest().use { digest ->
            digest.reset()
            data.usePinned { digest.update(it.at(0), data.size) }
            digest.final(once)

            digest.reset()
            var offset = 0
            data.usePinned { dp ->
                while (offset < data.size) {
                    val len = minOf(4096, data.size - offset)
                    digest.update(dp.at(offset), len)
                    offset += len
                }
            }
            digest.final(chunked)
        }

        assert(once.contentEquals(chunked))
    }

}

private val testKey = Random(7).nextBytes(32)
