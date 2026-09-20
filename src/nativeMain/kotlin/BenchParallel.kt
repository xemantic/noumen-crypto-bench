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

// The `parallel` suite: does fanning chunks across cores actually help?
//
// LFS objects are gigabytes and machines have cores, but the README used to
// wave this away as "a separate experiment". It matters for the local
// operations — verification, re-chunking — where a single core of ChaCha20 is
// slower than the NVMe underneath it.
//
// The STREAM construction makes this exact rather than approximate: a chunk is
// identified solely by its counter, so chunks are independent and may be sealed
// in any order. Every full chunk also occupies exactly CT_CHUNK bytes of
// output, and only the last chunk may be short, so chunk `i` always lands at
// `i * CT_CHUNK`. Parallel output is therefore byte-identical to serial output,
// which is what the test asserts.
//
// Each worker owns its RawAead, and so its own EVP_CIPHER_CTX: a context is
// not safe to share between threads.
@file:OptIn(kotlin.native.concurrent.ObsoleteWorkersApi::class)

package com.xemantic.noumen.crypto.bench

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.usePinned
import kotlin.native.concurrent.TransferMode
import kotlin.native.concurrent.Worker
import kotlin.random.Random

/**
 * One worker's share of an object: the chunks in `[from, until)`.
 *
 * Everything a worker needs travels in here, because the job lambda handed to
 * [Worker.execute] may not capture anything from its enclosing scope.
 */
private class Share(
    val cipher: String,
    val key: ByteArray,
    val plain: ByteArray,
    val out: ByteArray,
    val from: Int,
    val until: Int,
    val chunks: Int
)

@OptIn(ExperimentalForeignApi::class)
private fun Share.seal() {
    RawAead(cipher, key).use { aead ->
        aead.initEncrypt()
        plain.usePinned { pp ->
            out.usePinned { op ->
                for (i in from until until) {
                    val ip = i * CHUNK
                    val len = minOf(CHUNK, plain.size - ip)
                    aead.sealChunk(
                        i.toLong(), i == chunks - 1, pp.at(ip), len, op.at(i * CT_CHUNK)
                    )
                }
            }
        }
    }
}

/**
 * Seals [plain] into [out] across [workers] threads. Returns MiB/s.
 *
 * The pool is started by the caller and reused, because a real client would
 * keep one rather than pay thread creation per object.
 */
private fun sealParallel(
    algo: StreamAlgo,
    plain: ByteArray,
    out: ByteArray,
    pool: Array<Worker>
): Double {
    val chunks = chunkCount(plain.size)
    val per = (chunks + pool.size - 1) / pool.size
    return throughput(plain.size.toLong()) {
        pool.mapIndexed { w, worker ->
            worker.execute(
                TransferMode.SAFE,
                {
                    Share(
                        algo.cipher, algo.key, plain, out,
                        from = minOf(w * per, chunks),
                        until = minOf((w + 1) * per, chunks),
                        chunks = chunks
                    )
                }
            ) { it.seal() }
        }.forEach { it.result }
    }
}

fun benchParallel(sizeMib: Int, iters: Int) {
    val plain = Random(42).nextBytes(sizeMib shl 20)
    val key = Random(7).nextBytes(32)
    val out = ByteArray(sealedSize(plain.size))
    val reference = ByteArray(sealedSize(plain.size))

    for (algo in streamAlgos(key, Random(11).nextBytes(24))) {
        // The serial result every worker count must reproduce exactly.
        RawAead(algo.cipher, algo.key).use { it.sealAll(plain, reference) }

        for (workers in WORKER_COUNTS) {
            val pool = Array(workers) { Worker.start() }
            try {
                out.fill(0)
                val r = median(iters) { sealParallel(algo, plain, out, pool) }
                check(out.contentEquals(reference)) {
                    "parallel output differs from serial: ${algo.name} at $workers workers"
                }
                emit(
                    "kn-evp", "parallel", algo.name, "encrypt",
                    "mib_s", r.toLong(), workers
                )
            } finally {
                pool.forEach { it.requestTermination().result }
            }
        }
    }
}
