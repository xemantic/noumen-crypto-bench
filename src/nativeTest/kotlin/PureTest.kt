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
 * The hand-written primitives are only interesting if they are correct, and the
 * strongest available oracle is the OpenSSL sitting next to them — so most of
 * these tests check agreement with it across sizes rather than against a couple
 * of published vectors.
 */
class PureTest {

    @Test
    fun `should hash the published SHA-256 vectors`() {
        val out = ByteArray(32)
        val sha = PureSha256()

        sha.hash(ByteArray(0), out)
        assert(out.toHex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        sha.hash("abc".encodeToByteArray(), out)
        assert(out.toHex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test
    fun `should agree with OpenSSL SHA-256 around every padding boundary`() {
        val pure = ByteArray(32)
        val openssl = ByteArray(32)
        val sha = PureSha256()
        val differsAt = mutableListOf<Int>()

        RawDigest().use { digest ->
            // 55/56 and 119/120 are where the length word stops fitting in the
            // final block and a second padded block is needed.
            for (size in intArrayOf(0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 1000)) {
                val data = Random(size).nextBytes(size)
                sha.hash(data, pure)

                digest.reset()
                if (size > 0) data.usePinned { digest.update(it.at(0), size) }
                digest.final(openssl)

                if (!pure.contentEquals(openssl)) differsAt += size
            }
        }

        assert(differsAt.isEmpty())
    }

    @Test
    fun `should agree with OpenSSL ChaCha20 keystream`() {
        val key = Random(7).nextBytes(32)
        val nonce = Random(3).nextBytes(12)

        val differsAt = mutableListOf<Int>()

        for (size in intArrayOf(1, 63, 64, 65, 200, 4096)) {
            val data = Random(size).nextBytes(size)
            val pure = ByteArray(size)
            val openssl = ByteArray(size)

            PureChaCha20(key).xor(nonce, data, size, pure)
            RawChaCha20(key).use { it.xor(nonce, data, size, openssl) }

            if (!pure.contentEquals(openssl)) differsAt += size
        }

        assert(differsAt.isEmpty())
    }

    @Test
    fun `should reject a key or nonce of the wrong size`() {
        assert(runCatching { PureChaCha20(ByteArray(16)) }.isFailure)
        assert(
            runCatching {
                PureChaCha20(ByteArray(32)).xor(ByteArray(8), ByteArray(1), 1, ByteArray(1))
            }.isFailure
        )
    }

}

private fun ByteArray.toHex() = joinToString("") {
    val v = it.toInt() and 0xff
    "0123456789abcdef"[v shr 4].toString() + "0123456789abcdef"[v and 15]
}
