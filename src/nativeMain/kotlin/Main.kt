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

// Entry point and report format for the Kotlin/Native benchmark, which carries
// two implementations: `kn-lib` (cryptography-kotlin's high-level API) and
// `kn-evp` (OpenSSL EVP driven directly through the cinterop bindings).
//
// Every measurement is one CSV line on stdout:
//
//     impl,suite,algo,pass,param,unit,value
//
// `param` carries whatever the suite varies — worker count, recipient count —
// and is `-` when the suite varies nothing. bench.sh pivots those lines into
// per-suite tables; nothing here formats a table itself.
package com.xemantic.noumen.crypto.bench

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv
import kotlin.time.TimeSource

@OptIn(ExperimentalForeignApi::class)
fun env(k: String, d: Int): Int = getenv(k)?.toKString()?.toIntOrNull() ?: d

/** Emits one measurement line in the format documented above. */
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

/** MiB/s of [bytes] processed in [nanos] nanoseconds. */
fun mibPerS(bytes: Long, nanos: Long): Double = bytes / 1048576.0 / nanos * 1e9

/** Runs [pass] once to warm up, then [iters] times, and returns the median. */
inline fun median(iters: Int, pass: () -> Double): Double {
    pass()
    val results = DoubleArray(iters) { pass() }
    results.sort()
    return results[iters / 2]
}

/** Times [block] and returns MiB/s over [bytes]. */
inline fun throughput(bytes: Long, block: () -> Unit): Double {
    val mark = TimeSource.Monotonic.markNow()
    block()
    return mibPerS(bytes, mark.elapsedNow().inWholeNanoseconds)
}

/** Operations per second, given [ops] completed in [nanos] nanoseconds. */
fun opsPerS(ops: Int, nanos: Long): Double = ops / (nanos / 1e9)

/** Times [block], which performs [ops] operations, and returns operations/s. */
inline fun rate(ops: Int, block: () -> Unit): Double {
    val mark = TimeSource.Monotonic.markNow()
    block()
    return opsPerS(ops, mark.elapsedNow().inWholeNanoseconds)
}

private const val USAGE =
    "usage: crypto-bench [all|aead|stream|parallel|envelope|noop|crypto-init]"

fun main(args: Array<String>) {
    val suite = args.firstOrNull() ?: "all"

    // `noop` and `crypto-init` exist only for the startup suite: bench.sh times
    // the whole process, so they must do their one thing and return at once.
    when (suite) {
        "noop" -> return
        "crypto-init" -> { cryptoInit(); return }
    }

    check(suite in setOf("all", "aead", "stream", "parallel", "envelope")) {
        "unknown suite: $suite\n$USAGE"
    }
    val sizeMib = env("SIZE_MIB", 256)
    val iters = env("ITERS", 5)
    fun selected(name: String) = suite == "all" || suite == name

    if (selected("aead")) benchAead(sizeMib, iters)
    if (selected("stream")) benchStream(sizeMib, iters)
    if (selected("parallel")) benchParallel(sizeMib, iters)
    if (selected("envelope")) benchEnvelope(iters)
}
