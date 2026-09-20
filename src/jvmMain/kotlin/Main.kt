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

// The JVM reference ceiling.
//
// SCOPE.md rules the JVM out as noumen's client runtime because git invokes a
// remote helper repeatedly and cannot afford JVM startup. It stays in the table
// for two reasons: javax.crypto's intrinsics are a strong throughput ceiling to
// measure Kotlin/Native against, and the `startup` suite quantifies exactly the
// latency that ruled it out — a number worth having rather than assuming.
//
// So this binary implements the `aead` suite and the two startup modes, and
// deliberately not `stream`, `parallel` or `envelope`.
package com.xemantic.noumen.crypto.bench

import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.time.TimeSource

const val CHUNK = 64 * 1024
const val TAG = 16

fun env(k: String, d: Int): Int = System.getenv(k)?.toIntOrNull() ?: d

fun emit(
    impl: String,
    suite: String,
    algo: String,
    pass: String,
    unit: String,
    value: Long,
    param: Any = "-"
) {
    println("$impl,$suite,$algo,$pass,$param,$unit,$value")
}

fun nonce(n: ByteArray, counter: Long, last: Boolean) {
    var c = counter
    for (i in 10 downTo 0) { n[i] = c.toByte(); c = c ushr 8 }
    n[11] = if (last) 1 else 0
}

class Aead(
    val name: String,
    private val transformation: String,
    private val keyAlgorithm: String,
    private val parameters: (nonce: ByteArray) -> AlgorithmParameterSpec
) {
    fun cipher(): Cipher = Cipher.getInstance(transformation)
    fun init(cipher: Cipher, mode: Int, key: ByteArray, nonce: ByteArray) {
        cipher.init(mode, SecretKeySpec(key, keyAlgorithm), parameters(nonce))
    }
}

val chaCha = Aead("chacha20poly1305", "ChaCha20-Poly1305", "ChaCha20") { IvParameterSpec(it) }
val aesGcm = Aead("aes256gcm", "AES/GCM/NoPadding", "AES") { GCMParameterSpec(TAG * 8, it) }

/** Returns MiB/s of *input* processed. */
fun measure(aead: Aead, mode: Int, key: ByteArray, input: ByteArray, out: ByteArray): Double {
    val cipher = aead.cipher()
    val n = ByteArray(12)
    val step = if (mode == Cipher.ENCRYPT_MODE) CHUNK else CHUNK + TAG
    val chunks = (input.size + step - 1) / step
    val mark = TimeSource.Monotonic.markNow()
    var ip = 0; var op = 0
    for (i in 0 until chunks) {
        val len = minOf(step, input.size - ip)
        nonce(n, i.toLong(), i == chunks - 1)
        aead.init(cipher, mode, key, n)
        op += cipher.doFinal(input, ip, len, out, op)
        ip += len
    }
    return ip / 1048576.0 / mark.elapsedNow().inWholeNanoseconds * 1e9
}

private fun benchAead(sizeMib: Int, iters: Int) {
    val plain = Random(42).nextBytes(sizeMib shl 20)
    val nChunks = (plain.size + CHUNK - 1) / CHUNK
    val ctBuf = ByteArray(plain.size + nChunks * TAG)
    val back = ByteArray(plain.size)
    val key = Random(7).nextBytes(32)

    for (aead in listOf(chaCha, aesGcm)) {
        // warm-up so the JIT and the crypto intrinsics are engaged before timing
        measure(aead, Cipher.ENCRYPT_MODE, key, plain, ctBuf)
        measure(aead, Cipher.DECRYPT_MODE, key, ctBuf, back)
        val enc = DoubleArray(iters); val dec = DoubleArray(iters)
        for (i in 0 until iters) {
            enc[i] = measure(aead, Cipher.ENCRYPT_MODE, key, plain, ctBuf)
            dec[i] = measure(aead, Cipher.DECRYPT_MODE, key, ctBuf, back)
        }
        check(plain.contentEquals(back)) { "roundtrip mismatch: ${aead.name}" }
        enc.sort(); dec.sort()
        emit("jvm", "aead", aead.name, "encrypt", "mib_s", enc[iters / 2].toLong())
        emit("jvm", "aead", aead.name, "decrypt", "mib_s", dec[iters / 2].toLong())
    }
}

/** See Startup.kt in the native source set for what these modes are for. */
private fun cryptoInit() {
    val key = Random(7).nextBytes(32)
    val cipher = chaCha.cipher()
    chaCha.init(cipher, Cipher.ENCRYPT_MODE, key, ByteArray(12))
}

fun main(args: Array<String>) {
    when (val suite = args.firstOrNull() ?: "all") {
        "noop" -> return
        "crypto-init" -> cryptoInit()
        "aead", "all" -> benchAead(env("SIZE_MIB", 256), env("ITERS", 5))
        // Suites this implementation deliberately does not carry.
        "stream", "parallel", "envelope" -> return
        else -> error("unknown suite: $suite")
    }
}
