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

// The `aead` suite: bulk AEAD over a buffer already in memory.
//
// This is the primitive ceiling the other suites are read against. It answers
// "how fast can these bytes possibly be sealed", deliberately excluding I/O,
// so that the gap between it and the `stream` suite is attributable to the
// read/write path rather than to the cipher.
//
// Both Kotlin/Native implementations run here: `kn-lib` goes through
// cryptography-kotlin's high-level API, `kn-evp` drives the same OpenSSL
// through EVP directly. The difference between them is the cost of the
// Kotlin wrapper, which is the whole reason this repository exists.
package com.xemantic.noumen.crypto.bench

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.ChaCha20Poly1305
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.operations.IvAuthenticatedCipher
import dev.whyoleg.cryptography.providers.openssl3.Openssl3
import kotlin.random.Random

/**
 * Seals [plain] into [out] chunk by chunk. Returns MiB/s of plaintext.
 *
 * The per-chunk `copyOfRange` is not an oversight: the high-level API takes and
 * returns whole ByteArrays, so a caller cannot avoid the copy. Measuring it is
 * the point.
 */
@OptIn(DelicateCryptographyApi::class)
fun encrypt(cipher: IvAuthenticatedCipher, plain: ByteArray, out: ByteArray): Double {
    val n = ByteArray(12)
    val chunks = chunkCount(plain.size)
    var ip = 0
    var op = 0
    return throughput(plain.size.toLong()) {
        for (i in 0 until chunks) {
            val len = minOf(CHUNK, plain.size - ip)
            nonce(n, i.toLong(), i == chunks - 1)
            val ct = cipher.encryptWithIvBlocking(n, plain.copyOfRange(ip, ip + len))
            ct.copyInto(out, op)
            op += ct.size; ip += len
        }
    }
}

/** Opens the STREAM in [ct] into [out]. Returns MiB/s of ciphertext. */
@OptIn(DelicateCryptographyApi::class)
fun decrypt(cipher: IvAuthenticatedCipher, ct: ByteArray, out: ByteArray): Double {
    val n = ByteArray(12)
    val chunks = (ct.size + CT_CHUNK - 1) / CT_CHUNK
    var ip = 0
    var op = 0
    return throughput(ct.size.toLong()) {
        for (i in 0 until chunks) {
            val len = minOf(CT_CHUNK, ct.size - ip)
            nonce(n, i.toLong(), i == chunks - 1)
            val pt = cipher.decryptWithIvBlocking(n, ct.copyOfRange(ip, ip + len))
            pt.copyInto(out, op)
            op += pt.size; ip += len
        }
    }
}

private fun benchLib(
    algo: String,
    cipher: IvAuthenticatedCipher,
    plain: ByteArray,
    iters: Int
) {
    val ct = ByteArray(sealedSize(plain.size))
    val back = ByteArray(plain.size)
    val enc = median(iters) { encrypt(cipher, plain, ct) }
    val dec = median(iters) { decrypt(cipher, ct, back) }
    check(plain.contentEquals(back)) { "roundtrip mismatch: kn-lib $algo" }
    emit("kn-lib", "aead", algo, "encrypt", "mib_s", enc.toLong())
    emit("kn-lib", "aead", algo, "decrypt", "mib_s", dec.toLong())
}

private fun benchEvp(algo: StreamAlgo, plain: ByteArray, iters: Int) {
    val ct = ByteArray(sealedSize(plain.size))
    val back = ByteArray(plain.size)
    RawAead(algo.cipher, algo.key).use { aead ->
        val enc = median(iters) { aead.sealAll(plain, ct) }
        val dec = median(iters) { aead.openAll(ct, back) }
        check(plain.contentEquals(back)) { "roundtrip mismatch: kn-evp ${algo.name}" }
        emit("kn-evp", "aead", algo.name, "encrypt", "mib_s", enc.toLong())
        emit("kn-evp", "aead", algo.name, "decrypt", "mib_s", dec.toLong())
    }
}

fun benchAead(sizeMib: Int, iters: Int) {
    val plain = Random(42).nextBytes(sizeMib shl 20)
    val key = Random(7).nextBytes(32)
    val provider = CryptographyProvider.Openssl3

    benchLib(
        "chacha20poly1305",
        provider.get(ChaCha20Poly1305).keyDecoder()
            .decodeFromByteArrayBlocking(ChaCha20Poly1305.Key.Format.RAW, key).cipher(),
        plain, iters
    )
    benchLib(
        "aes256gcm",
        provider.get(AES.GCM).keyDecoder()
            .decodeFromByteArrayBlocking(AES.Key.Format.RAW, key).cipher(),
        plain, iters
    )

    // XChaCha20 appears here as ChaCha20-Poly1305 under a per-object subkey,
    // so it should land on the ChaCha20 number. That is the expected result:
    // its real cost is the hand-written HChaCha20 in XChaCha.kt, which is
    // maintenance rather than throughput.
    for (algo in streamAlgos(key, Random(11).nextBytes(24))) {
        benchEvp(algo, plain, iters)
    }

    // git-lfs must hash the plaintext for the object id whether or not it is
    // encrypted, so SHA-256 shares the critical path with the cipher.
    val hasher = provider.get(SHA256).hasher()
    val hash = median(iters) {
        throughput(plain.size.toLong()) { hasher.hashBlocking(plain) }
    }
    emit("kn-lib", "aead", "sha256", "hash", "mib_s", hash.toLong())

    benchPure(plain, key, iters)
}

/**
 * The `kn-pure` column: the same two algorithms written in plain Kotlin, with
 * no OpenSSL underneath.
 *
 * This is here to answer whether noumen should own its simple primitives rather
 * than link a C library for them. SHA-256 is compared against OpenSSL's, and
 * ChaCha20 against OpenSSL's raw keystream — deliberately not against
 * ChaCha20-Poly1305, which would flatter the unauthenticated implementation.
 */
private fun benchPure(plain: ByteArray, key: ByteArray, iters: Int) {
    val digest = ByteArray(32)
    val sha = PureSha256()
    val shaRate = median(iters) {
        throughput(plain.size.toLong()) { sha.hash(plain, digest) }
    }
    emit("kn-pure", "aead", "sha256", "hash", "mib_s", shaRate.toLong())

    val nonce = ByteArray(12)
    val out = ByteArray(plain.size)
    val pure = PureChaCha20(key)
    val pureRate = median(iters) {
        throughput(plain.size.toLong()) { pure.xor(nonce, plain, plain.size, out) }
    }
    emit("kn-pure", "aead", "chacha20", "xor", "mib_s", pureRate.toLong())

    RawChaCha20(key).use { raw ->
        val rawRate = median(iters) {
            throughput(plain.size.toLong()) { raw.xor(nonce, plain, plain.size, out) }
        }
        emit("kn-evp", "aead", "chacha20", "xor", "mib_s", rawRate.toLong())
    }
}
