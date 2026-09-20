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
import kotlin.test.Test

/**
 * HChaCha20 is hand-written in this project because nothing under
 * Kotlin/Native provides it, which means nothing else validates it either.
 * A fast but wrong cipher would be worse than no measurement at all, so the
 * derivation is pinned to the specification's own test vector.
 */
class XChaChaTest {

    @Test
    fun `should derive the HChaCha20 subkey from the specification test vector`() {
        // draft-irtf-cfrg-xchacha20poly1305, section 2.2.1
        val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val nonce = hex("000000090000004a0000000031415927")
        val expected = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

        assert(hChaCha20(key, nonce).contentEquals(expected))
    }

    @Test
    fun `should derive a distinct stream key for each object header`() {
        val key = ByteArray(32) { it.toByte() }
        val first = xChaCha20StreamKey(key, ByteArray(24) { 1 })
        val second = xChaCha20StreamKey(key, ByteArray(24) { 2 })

        assert(first.size == 32)
        assert(!first.contentEquals(second))
        // and the same header must always give the same key back
        assert(first.contentEquals(xChaCha20StreamKey(key, ByteArray(24) { 1 })))
    }

    @Test
    fun `should reject a header which is not 24 bytes`() {
        val key = ByteArray(32)
        val tooShort = runCatching { xChaCha20StreamKey(key, ByteArray(16)) }
        assert(tooShort.isFailure)
    }

}

private fun hex(s: String) = ByteArray(s.length / 2) {
    s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
}
