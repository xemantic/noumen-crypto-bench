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

package com.xemantic.noumen.crypto.bench

import com.xemantic.kotlin.test.assert
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.ChaCha20Poly1305
import dev.whyoleg.cryptography.providers.openssl3.Openssl3
import kotlin.random.Random
import kotlin.test.Test

/**
 * The benchmark asserts its own round trip at runtime, so these tests only guard
 * the parts which would otherwise be validated on a 256 MiB buffer: the nonce
 * encoding, and the fact that both ciphers survive a multi-chunk STREAM pass.
 */
class StreamTest {

    @Test
    fun `should encode the nonce as an 11-byte big-endian counter plus the last-chunk flag`() {
        val n = ByteArray(12)

        nonce(n, counter = 0, last = false)
        assert(n.toList() == List(12) { 0.toByte() })

        nonce(n, counter = 1, last = true)
        assert(n[10] == 1.toByte())
        assert(n[11] == 1.toByte())

        nonce(n, counter = 0x0102, last = false)
        assert(n[9] == 1.toByte())
        assert(n[10] == 2.toByte())
        assert(n[11] == 0.toByte())
    }

    @Test
    fun `should round trip multiple chunks with chacha20poly1305`() {
        assertRoundTrip(
            CryptographyProvider.Openssl3
                .get(ChaCha20Poly1305)
                .keyDecoder()
                .decodeFromByteArrayBlocking(ChaCha20Poly1305.Key.Format.RAW, testKey)
                .cipher()
        )
    }

    @Test
    fun `should round trip multiple chunks with aes256gcm`() {
        assertRoundTrip(
            CryptographyProvider.Openssl3
                .get(AES.GCM)
                .keyDecoder()
                .decodeFromByteArrayBlocking(AES.Key.Format.RAW, testKey)
                .cipher()
        )
    }

}

private val testKey = Random(7).nextBytes(32)

private fun assertRoundTrip(cipher: dev.whyoleg.cryptography.operations.IvAuthenticatedCipher) {
    // deliberately not a multiple of CHUNK, so that the last chunk is a partial one
    val plain = Random(42).nextBytes(CHUNK * 2 + 1234)
    val chunks = (plain.size + CHUNK - 1) / CHUNK
    val ct = ByteArray(plain.size + chunks * TAG)
    val back = ByteArray(plain.size)
    encrypt(cipher, plain, ct)
    decrypt(cipher, ct, back)
    assert(plain.contentEquals(back))
}
