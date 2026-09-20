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

// The age-style STREAM framing every suite shares: fixed-size plaintext chunks,
// one 16-byte AEAD tag per chunk, and a 12-byte nonce built from an 11-byte
// big-endian chunk counter followed by a last-chunk flag.
//
// Chunks are independent by construction — the counter is the only thing that
// distinguishes them — which is what lets the parallel suite seal them out of
// order and still produce byte-identical output.
package com.xemantic.noumen.crypto.bench

const val TAG = 16

/** Plaintext chunk size. `CHUNK_KIB` probes per-call versus per-byte overhead. */
val CHUNK = env("CHUNK_KIB", 64) * 1024

/** Ciphertext chunk size: a full plaintext chunk plus its tag. */
val CT_CHUNK = CHUNK + TAG

fun nonce(n: ByteArray, counter: Long, last: Boolean) {
    var c = counter
    for (i in 10 downTo 0) { n[i] = c.toByte(); c = c ushr 8 }
    n[11] = if (last) 1 else 0
}

/** Number of chunks a plaintext of [size] bytes is split into. */
fun chunkCount(size: Int): Int = (size + CHUNK - 1) / CHUNK

/** Size of the ciphertext produced for a plaintext of [size] bytes. */
fun sealedSize(size: Int): Int = size + chunkCount(size) * TAG

// The in-memory suites are bounded by ByteArray's Int index anyway, but the
// stream suite is precisely the one that must cope with an object larger than
// RAM, so it counts chunks in Long.

/** Number of chunks a plaintext of [size] bytes is split into. */
fun chunkCount(size: Long): Long = (size + CHUNK - 1) / CHUNK

/** Size of the ciphertext produced for a plaintext of [size] bytes. */
fun sealedSize(size: Long): Long = size + chunkCount(size) * TAG

/**
 * One AEAD under test: the display name, the OpenSSL cipher that seals it, and
 * the key the chunks are sealed with.
 *
 * XChaCha20 is not a cipher OpenSSL knows. It appears here as ChaCha20-Poly1305
 * under a subkey derived once per object, which is exactly what the framing
 * amounts to — see XChaCha.kt for why that derivation has to be hand-written.
 */
class StreamAlgo(val name: String, val cipher: String, val key: ByteArray)

fun streamAlgos(key: ByteArray, xchachaHeader: ByteArray): List<StreamAlgo> = listOf(
    StreamAlgo("chacha20poly1305", "ChaCha20-Poly1305", key),
    StreamAlgo("aes256gcm", "AES-256-GCM", key),
    StreamAlgo(
        "xchacha20poly1305",
        "ChaCha20-Poly1305",
        xChaCha20StreamKey(key, xchachaHeader)
    )
)

/**
 * Worker counts the `parallel` suite sweeps, capped by `MAX_WORKERS`.
 *
 * Powers of two up to the cap, which is enough to show the shape of the curve
 * and where it flattens.
 */
val WORKER_COUNTS: List<Int> =
    generateSequence(1) { it * 2 }.takeWhile { it <= env("MAX_WORKERS", 8) }.toList()

/** Recipient counts the `envelope` suite sweeps. */
val RECIPIENT_COUNTS = listOf(1, 4, 16)
