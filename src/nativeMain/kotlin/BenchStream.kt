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

// The `stream` suite: what a git-lfs transfer agent actually does.
//
// The `aead` suite holds the whole object in memory and hashes it in a separate
// pass. A real client can do neither. It streams an object it cannot fit in
// RAM, and it must hash the plaintext for the LFS object id over the very same
// bytes it encrypts. So this suite runs in bounded memory — one plaintext chunk
// and one ciphertext chunk, no full-object allocation — and folds the digest
// into the cipher pass.
//
// Three sinks, because where the ciphertext goes decides what is being paid
// for: `null` is a write syscall to /dev/null with no storage behind it,
// `file` is real storage, and `pipe` feeds a child process and is the one that
// models streaming to object storage over a socket.
//
// Caveat, stated rather than hidden: the source file is read through a warm
// page cache. Dropping caches is not portable without root, so these numbers
// are a CPU-and-syscall ceiling, not a disk benchmark.
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.xemantic.noumen.crypto.bench

import kotlinx.cinterop.*
import platform.posix.*
import kotlin.random.Random

private const val SINK_NULL = "null"
private const val SINK_FILE = "file"
private const val SINK_PIPE = "pipe"

private val SINKS = listOf(SINK_NULL, SINK_FILE, SINK_PIPE)

// 0600, written as a literal rather than as S_IRUSR or S_IWUSR: those constants
// are commonized with different bit widths across targets, which only
// compileNativeMainKotlinMetadata rejects — and only -PallNativeTargets runs it,
// so the per-target compilations would happily accept them.
private const val MODE_RW_OWNER = 384

/**
 * Creates a unique scratch directory and returns its path.
 *
 * `mkdtemp` rather than `mkdir` for the same commonization reason: `mkdir`'s
 * `mode_t` parameter has a different width on Linux than on macOS, so calling it
 * from the shared source set fails the metadata compilation. `mkdtemp` takes no
 * mode, and a unique directory avoids colliding with a previous crashed run.
 */
private fun makeTempDir(): String = memScoped {
    val root = getenv("TMPDIR")?.toKString()?.trimEnd('/') ?: "/tmp"
    val template = "$root/noumen-crypto-bench-XXXXXX".cstr.getPointer(this)
    if (mkdtemp(template) == null) fail("mkdtemp")
    template.toKString()
}

private fun fail(what: String): Nothing =
    error("$what failed: ${strerror(errno)?.toKString() ?: "errno $errno"}")

private fun openRead(path: String): Int {
    val fd = open(path, O_RDONLY)
    if (fd < 0) fail("open($path)")
    return fd
}

private fun openWrite(path: String): Int {
    val fd = open(path, O_WRONLY or O_CREAT or O_TRUNC, MODE_RW_OWNER)
    if (fd < 0) fail("open($path) for writing")
    return fd
}

/** Reads up to [max] bytes into [buf]. Returns 0 only at end of file. */
private fun readFully(fd: Int, buf: Pinned<ByteArray>, max: Int): Int {
    var off = 0
    while (off < max) {
        val n = read(fd, buf.addressOf(off), (max - off).convert()).toInt()
        if (n < 0) fail("read")
        if (n == 0) break
        off += n
    }
    return off
}

private fun writeFully(fd: Int, buf: Pinned<ByteArray>, len: Int) {
    var off = 0
    while (off < len) {
        val n = write(fd, buf.addressOf(off), (len - off).convert()).toInt()
        if (n <= 0) fail("write")
        off += n
    }
}

/** Where sealed chunks go. See the sink discussion at the top of the file. */
private class Sink private constructor(
    val name: String,
    val fd: Int,
    private val pipe: CPointer<FILE>?,
    private val path: String?,
    private val owned: Boolean
) : AutoCloseable {

    override fun close() {
        if (!owned) return
        if (pipe != null) pclose(pipe) else close(fd)
        if (path != null) unlink(path)
    }

    companion object {
        fun open(name: String, dir: String): Sink = when (name) {
            SINK_NULL -> Sink(name, openWrite("/dev/null"), null, null, owned = true)
            SINK_FILE -> "$dir/sink.bin".let {
                Sink(name, openWrite(it), null, it, owned = true)
            }
            // A child draining the pipe, which is what writing to a socket
            // costs: a copy into the pipe buffer plus the reader's scheduling.
            SINK_PIPE -> {
                val f = popen("cat > /dev/null", "w") ?: fail("popen")
                Sink(name, fileno(f), f, null, owned = true)
            }
            else -> error("unknown sink: $name")
        }

        /** A sink over a descriptor owned by the caller. */
        fun wrapping(fd: Int) = Sink("fd", fd, null, null, owned = false)
    }
}

/** Hash the plaintext only — the pass git-lfs owes even without encryption. */
private fun oidPass(src: String, digest: RawDigest, size: Long, oid: ByteArray): Double {
    val buf = ByteArray(CHUNK)
    val fd = openRead(src)
    try {
        digest.reset()
        return throughput(size) {
            buf.usePinned { bp ->
                while (true) {
                    val n = readFully(fd, bp, CHUNK)
                    if (n == 0) break
                    digest.update(bp.at(0), n)
                }
            }
            digest.final(oid)
        }
    } finally {
        close(fd)
    }
}

/** Read, hash and seal in one pass, writing the STREAM to [sink]. */
private fun sealPass(
    src: String,
    sink: Sink,
    aead: RawAead,
    digest: RawDigest,
    size: Long,
    oid: ByteArray
): Double {
    val inBuf = ByteArray(CHUNK)
    val outBuf = ByteArray(CT_CHUNK)
    val chunks = chunkCount(size)
    val fd = openRead(src)
    try {
        aead.initEncrypt()
        digest.reset()
        return throughput(size) {
            inBuf.usePinned { ip ->
                outBuf.usePinned { op ->
                    var i = 0L
                    while (true) {
                        val n = readFully(fd, ip, CHUNK)
                        if (n == 0) break
                        digest.update(ip.at(0), n)
                        val w = aead.sealChunk(
                            i, i == chunks - 1, ip.at(0), n, op.at(0)
                        )
                        writeFully(sink.fd, op, w)
                        i++
                    }
                }
            }
            digest.final(oid)
        }
    } finally {
        close(fd)
    }
}

/**
 * Read the STREAM, open it, and hash the recovered plaintext.
 *
 * This verifies itself twice over: EVP_DecryptFinal_ex rejects a bad tag, and
 * the caller compares the recovered object id against the plaintext's.
 */
private fun openPass(
    sealed: String,
    sink: Sink,
    aead: RawAead,
    digest: RawDigest,
    plainSize: Long,
    sealedBytes: Long,
    oid: ByteArray
): Double {
    val inBuf = ByteArray(CT_CHUNK)
    val outBuf = ByteArray(CHUNK)
    val chunks = chunkCount(plainSize)
    val fd = openRead(sealed)
    try {
        aead.initDecrypt()
        digest.reset()
        return throughput(sealedBytes) {
            inBuf.usePinned { ip ->
                outBuf.usePinned { op ->
                    var i = 0L
                    while (true) {
                        val n = readFully(fd, ip, CT_CHUNK)
                        if (n == 0) break
                        val w = aead.openChunk(
                            i, i == chunks - 1, ip.at(0), n, op.at(0)
                        )
                        digest.update(op.at(0), w)
                        writeFully(sink.fd, op, w)
                        i++
                    }
                }
            }
            digest.final(oid)
        }
    } finally {
        close(fd)
    }
}

/** Writes [size] bytes of pseudo-random plaintext to [path]. */
private fun createSource(path: String, size: Long) {
    val random = Random(42)
    val buf = ByteArray(CHUNK)
    val fd = openWrite(path)
    try {
        var written = 0L
        while (written < size) {
            random.nextBytes(buf)
            val n = minOf(CHUNK.toLong(), size - written).toInt()
            buf.usePinned { writeFully(fd, it, n) }
            written += n
        }
    } finally {
        close(fd)
    }
}

fun benchStream(sizeMib: Int, iters: Int) {
    val size = sizeMib.toLong() shl 20
    val dir = makeTempDir()
    val src = "$dir/plain.bin"
    val sealed = "$dir/sealed.bin"
    val key = Random(7).nextBytes(32)
    val sealedBytes = sealedSize(size)
    val plainOid = ByteArray(32)
    val oid = ByteArray(32)

    try {
        createSource(src, size)

        RawDigest().use { digest ->
            val hash = median(iters) { oidPass(src, digest, size, plainOid) }
            emit("kn-evp", "stream", "sha256", "oid", "mib_s", hash.toLong())

            for (algo in streamAlgos(key, Random(11).nextBytes(24))) {
                RawAead(algo.cipher, algo.key).use { aead ->
                    for (sink in SINKS) {
                        Sink.open(sink, dir).use { s ->
                            val r = median(iters) {
                                sealPass(src, s, aead, digest, size, oid)
                            }
                            check(oid.contentEquals(plainOid)) {
                                "object id mismatch while sealing ${algo.name}"
                            }
                            emit(
                                "kn-evp", "stream", algo.name, "seal+oid",
                                "mib_s", r.toLong(), sink
                            )
                        }
                    }

                    // A real sealed file on disk, so the open pass reads real
                    // input rather than something synthesised in memory.
                    val out = openWrite(sealed)
                    try {
                        sealPass(src, Sink.wrapping(out), aead, digest, size, oid)
                    } finally {
                        close(out)
                    }

                    for (sink in SINKS) {
                        Sink.open(sink, dir).use { s ->
                            val r = median(iters) {
                                openPass(sealed, s, aead, digest, size, sealedBytes, oid)
                            }
                            check(oid.contentEquals(plainOid)) {
                                "object id mismatch while opening ${algo.name}"
                            }
                            emit(
                                "kn-evp", "stream", algo.name, "open+oid",
                                "mib_s", r.toLong(), sink
                            )
                        }
                    }
                }
            }
        }
    } finally {
        unlink(src)
        unlink(sealed)
        rmdir(dir)
    }
}
