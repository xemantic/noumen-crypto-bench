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

// OpenSSL EVP driven directly through the cinterop bindings that ship with
// cryptography-provider-openssl3-api. This is the binding layer only — the
// measurements live in the Bench*.kt files.
//
// One EVP_CIPHER_CTX per object, key set once, only the IV re-initialised per
// chunk, and the key and nonce buffers pinned for the lifetime of the object,
// so nothing is copied between the Kotlin heap and C memory per chunk. This is
// roughly what a hand-written noumen bulk path would do.
//
// A context is NOT safe to share between threads: the parallel suite gives each
// worker its own RawAead, which is why the nonce buffer is per-instance state.
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.xemantic.noumen.crypto.bench

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

// EVP_CTRL_AEAD_GET_TAG / SET_TAG are C macros, so cinterop does not export
// them; they are redeclared here with the values from <openssl/evp.h>.
private const val EVP_CTRL_AEAD_SET_TAG = 0x11
private const val EVP_CTRL_AEAD_GET_TAG = 0x10

internal fun ok(rc: Int, what: String) { check(rc == 1) { "$what failed: rc=$rc" } }

/** Convenience alias: the pointer type every EVP buffer argument wants. */
internal typealias Bytes = CPointer<UByteVar>

internal fun Pinned<ByteArray>.at(index: Int): Bytes =
    addressOf(index).reinterpret()

/**
 * An AEAD sealing/opening one STREAM object, keyed once at construction.
 *
 * The nonce is internal state: callers name a chunk by its counter and whether
 * it is the last one, exactly as the STREAM construction defines it.
 */
class RawAead(cipherName: String, key: ByteArray) : AutoCloseable {

    private val cipher = EVP_CIPHER_fetch(null, cipherName, null)
        ?: error("no such cipher: $cipherName")
    private val ctx = EVP_CIPHER_CTX_new() ?: error("EVP_CIPHER_CTX_new")
    private val keyPinned = key.pin()
    private val nonceBuf = ByteArray(12)
    private val noncePinned = nonceBuf.pin()
    private val outl = nativeHeap.alloc<IntVar>()

    private fun ivFor(counter: Long, last: Boolean): Bytes {
        nonce(nonceBuf, counter, last)
        return noncePinned.at(0)
    }

    fun initEncrypt() = ok(
        EVP_EncryptInit_ex2(ctx, cipher, keyPinned.at(0), null, null), "EncryptInit"
    )

    fun initDecrypt() = ok(
        EVP_DecryptInit_ex2(ctx, cipher, keyPinned.at(0), null, null), "DecryptInit"
    )

    /**
     * Seals [len] bytes at [inp] into [out] as `[ciphertext | tag]`.
     * Returns the number of bytes written.
     */
    fun sealChunk(counter: Long, last: Boolean, inp: Bytes, len: Int, out: Bytes): Int {
        ok(EVP_EncryptInit_ex2(ctx, null, null, ivFor(counter, last), null), "iv")
        ok(EVP_EncryptUpdate(ctx, out, outl.ptr, inp, len), "EncryptUpdate")
        var written = outl.value
        ok(EVP_EncryptFinal_ex(ctx, (out + written)!!, outl.ptr), "EncryptFinal")
        written += outl.value
        ok(
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG, (out + written)!!),
            "GetTag"
        )
        return written + TAG
    }

    /**
     * Opens a `[ciphertext | tag]` chunk of [len] bytes (tag included) into [out].
     * Returns the number of plaintext bytes written, and fails if the tag does
     * not verify.
     */
    fun openChunk(counter: Long, last: Boolean, inp: Bytes, len: Int, out: Bytes): Int {
        val ctLen = len - TAG
        ok(EVP_DecryptInit_ex2(ctx, null, null, ivFor(counter, last), null), "iv")
        ok(EVP_DecryptUpdate(ctx, out, outl.ptr, inp, ctLen), "DecryptUpdate")
        val written = outl.value
        ok(
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG, (inp + ctLen)!!),
            "SetTag"
        )
        ok(EVP_DecryptFinal_ex(ctx, (out + written)!!, outl.ptr), "DecryptFinal (auth)")
        return written + outl.value
    }

    /** Seals the whole of [plain] into [out]. Returns MiB/s of plaintext. */
    fun sealAll(plain: ByteArray, out: ByteArray): Double {
        val chunks = chunkCount(plain.size)
        initEncrypt()
        return plain.usePinned { pp ->
            out.usePinned { op ->
                var ip = 0
                var wp = 0
                throughput(plain.size.toLong()) {
                    for (i in 0 until chunks) {
                        val len = minOf(CHUNK, plain.size - ip)
                        wp += sealChunk(i.toLong(), i == chunks - 1, pp.at(ip), len, op.at(wp))
                        ip += len
                    }
                }
            }
        }
    }

    /** Opens the whole of [ct] into [out]. Returns MiB/s of ciphertext. */
    fun openAll(ct: ByteArray, out: ByteArray): Double {
        val chunks = (ct.size + CT_CHUNK - 1) / CT_CHUNK
        initDecrypt()
        return ct.usePinned { cp ->
            out.usePinned { op ->
                var ip = 0
                var wp = 0
                throughput(ct.size.toLong()) {
                    for (i in 0 until chunks) {
                        val len = minOf(CT_CHUNK, ct.size - ip)
                        wp += openChunk(i.toLong(), i == chunks - 1, cp.at(ip), len, op.at(wp))
                        ip += len
                    }
                }
            }
        }
    }

    override fun close() {
        nativeHeap.free(outl)
        noncePinned.unpin()
        keyPinned.unpin()
        EVP_CIPHER_CTX_free(ctx)
        EVP_CIPHER_free(cipher)
    }
}

/**
 * An incremental SHA-256, which the `stream` suite needs because a git-lfs
 * client hashes the plaintext for the object id while it streams, and cannot
 * hold the object in memory to hash it in one shot.
 */
class RawDigest(name: String = "SHA-256") : AutoCloseable {

    private val md = EVP_MD_fetch(null, name, null) ?: error("no such digest: $name")
    private val ctx = EVP_MD_CTX_new() ?: error("EVP_MD_CTX_new")

    fun reset() = ok(EVP_DigestInit_ex2(ctx, md, null), "DigestInit")

    fun update(inp: Bytes, len: Int) =
        ok(EVP_DigestUpdate(ctx, inp, len.convert()), "DigestUpdate")

    /** Writes the 32-byte digest into [out] and leaves the context spent. */
    fun final(out: ByteArray) = out.usePinned { op ->
        ok(EVP_DigestFinal_ex(ctx, op.at(0), null), "DigestFinal")
    }

    override fun close() {
        EVP_MD_CTX_free(ctx)
        EVP_MD_free(md)
    }
}

/**
 * Raw ChaCha20 keystream through OpenSSL, with no Poly1305.
 *
 * Exists purely so that [PureChaCha20] has a like-for-like opponent: comparing
 * a hand-written keystream against an authenticated cipher would flatter the
 * hand-written one. OpenSSL's `ChaCha20` takes a 16-byte IV of a 4-byte
 * little-endian block counter followed by the 12-byte nonce.
 */
class RawChaCha20(key: ByteArray) : AutoCloseable {

    private val cipher = EVP_CIPHER_fetch(null, "ChaCha20", null)
        ?: error("no such cipher: ChaCha20")
    private val ctx = EVP_CIPHER_CTX_new() ?: error("EVP_CIPHER_CTX_new")
    private val keyPinned = key.pin()
    private val iv = ByteArray(16)
    private val ivPinned = iv.pin()
    private val outl = nativeHeap.alloc<IntVar>()

    /** XORs [len] bytes of [input] into [out] under [nonce], starting at block 1. */
    fun xor(nonce: ByteArray, input: ByteArray, len: Int, out: ByteArray) {
        iv[0] = 1; iv[1] = 0; iv[2] = 0; iv[3] = 0
        nonce.copyInto(iv, 4)
        ok(
            EVP_EncryptInit_ex2(ctx, cipher, keyPinned.at(0), ivPinned.at(0), null),
            "ChaCha20 init"
        )
        input.usePinned { ip ->
            out.usePinned { op ->
                ok(EVP_EncryptUpdate(ctx, op.at(0), outl.ptr, ip.at(0), len), "ChaCha20 update")
            }
        }
    }

    override fun close() {
        nativeHeap.free(outl)
        ivPinned.unpin()
        keyPinned.unpin()
        EVP_CIPHER_CTX_free(ctx)
        EVP_CIPHER_free(cipher)
    }
}
