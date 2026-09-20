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

// HChaCha20, hand-written, because nothing under Kotlin/Native provides it.
//
// This is a measured finding rather than a workaround of convenience. Neither
// OpenSSL 3 (which exposes only `ChaCha20` and `ChaCha20-Poly1305`) nor
// cryptography-kotlin 0.6.0 offers XChaCha20-Poly1305, while Go gets it from
// `chacha20poly1305.NewX` and Rust from the `chacha20poly1305` crate. So if
// noumen picks the XChaCha20 framing that SCOPE.md §10 leaves open, this
// function — a cryptographic primitive — becomes the client's to own and test.
// The ~40 lines below are the price of that option, and they are the point.
//
// Framing used here: a random 24-byte per-object header derives a subkey once
// via HChaCha20, and chunks are then sealed with ordinary ChaCha20-Poly1305
// under the STREAM counter nonce. The subkey is fresh per object, so reusing
// the counter across objects is safe. That isolates exactly one difference
// from the age STREAM path — the one-time derivation — which is what makes the
// throughput comparison meaningful. It is a benchmark framing, not a proposed
// wire format.
package com.xemantic.noumen.crypto.bench

// "expand 32-byte k"
internal const val C0 = 0x61707865
internal const val C1 = 0x3320646e
internal const val C2 = 0x79622d32
internal const val C3 = 0x6b206574

internal fun le32(b: ByteArray, i: Int): Int =
    (b[i].toInt() and 0xff) or
        ((b[i + 1].toInt() and 0xff) shl 8) or
        ((b[i + 2].toInt() and 0xff) shl 16) or
        ((b[i + 3].toInt() and 0xff) shl 24)

internal fun putLe32(b: ByteArray, i: Int, v: Int) {
    b[i] = v.toByte()
    b[i + 1] = (v ushr 8).toByte()
    b[i + 2] = (v ushr 16).toByte()
    b[i + 3] = (v ushr 24).toByte()
}

internal fun IntArray.quarterRound(a: Int, b: Int, c: Int, d: Int) {
    this[a] += this[b]; this[d] = (this[d] xor this[a]).rotateLeft(16)
    this[c] += this[d]; this[b] = (this[b] xor this[c]).rotateLeft(12)
    this[a] += this[b]; this[d] = (this[d] xor this[a]).rotateLeft(8)
    this[c] += this[d]; this[b] = (this[b] xor this[c]).rotateLeft(7)
}

/**
 * Derives a 32-byte subkey from [key] and the first 16 bytes of [nonce].
 *
 * This is the ChaCha20 permutation without the feed-forward addition, keeping
 * words 0..3 and 12..15 of the final state, as specified in
 * draft-irtf-cfrg-xchacha20poly1305.
 */
fun hChaCha20(key: ByteArray, nonce: ByteArray): ByteArray {
    require(key.size == 32) { "key must be 32 bytes, was ${key.size}" }
    require(nonce.size >= 16) { "nonce must be at least 16 bytes, was ${nonce.size}" }

    val s = IntArray(16)
    s[0] = C0; s[1] = C1; s[2] = C2; s[3] = C3
    for (i in 0 until 8) s[4 + i] = le32(key, i * 4)
    for (i in 0 until 4) s[12 + i] = le32(nonce, i * 4)

    repeat(10) {
        s.quarterRound(0, 4, 8, 12); s.quarterRound(1, 5, 9, 13)
        s.quarterRound(2, 6, 10, 14); s.quarterRound(3, 7, 11, 15)
        s.quarterRound(0, 5, 10, 15); s.quarterRound(1, 6, 11, 12)
        s.quarterRound(2, 7, 8, 13); s.quarterRound(3, 4, 9, 14)
    }

    val out = ByteArray(32)
    for (i in 0 until 4) putLe32(out, i * 4, s[i])
    for (i in 0 until 4) putLe32(out, 16 + i * 4, s[12 + i])
    return out
}

/**
 * The per-object key that XChaCha20 STREAM chunks are sealed with, derived from
 * the long-term [key] and a random 24-byte [header] nonce.
 */
fun xChaCha20StreamKey(key: ByteArray, header: ByteArray): ByteArray {
    require(header.size == 24) { "header must be 24 bytes, was ${header.size}" }
    return hChaCha20(key, header)
}
