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

// The `envelope` suite: the per-object cost that bulk throughput hides.
//
// Wrapping the file key for each recipient is a one-off per object, so the
// `aead` and `stream` suites rightly exclude it. But "one-off per object" is
// only cheap when objects are large. A push carrying thousands of small git
// objects pays this cost thousands of times and never reaches the bulk path at
// all — the mirror image of the LFS case, and the reason it is measured here.
//
// This is the one suite that deliberately runs on `kn-lib`: SCOPE.md's plan is
// to use cryptography-kotlin for the envelope (X25519, HKDF) and drive EVP
// directly only for the STREAM path, so this measures the intended production
// code rather than an alternative to it.
//
// The construction follows age's X25519 stanza: a fresh ephemeral key pair per
// recipient, ECDH against the recipient's public key, HKDF over the shared
// secret, then the file key sealed under the result.
package com.xemantic.noumen.crypto.bench

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.ChaCha20Poly1305
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.XDH
import dev.whyoleg.cryptography.providers.openssl3.Openssl3
import kotlin.random.Random

private const val INFO = "noumen file key"

/** How many envelopes to seal per timed batch, so the clock has something to see. */
private const val BATCH = 50

fun benchEnvelope(iters: Int) {
    val provider = CryptographyProvider.Openssl3
    val xdh = provider.get(XDH).keyPairGenerator(XDH.Curve.X25519)
    val hkdf = provider.get(HKDF)
    val chacha = provider.get(ChaCha20Poly1305)
    val fileKey = Random(7).nextBytes(32)
    val nonce = ByteArray(12)

    @OptIn(DelicateCryptographyApi::class)
    fun wrapFor(recipient: XDH.PublicKey) {
        val ephemeral = xdh.generateKeyBlocking()
        val shared = ephemeral.privateKey
            .sharedSecretGenerator()
            .generateSharedSecretToByteArrayBlocking(recipient)
        val wrapKey = hkdf.secretDerivation(
            digest = SHA256,
            outputSize = 32.bytes,
            salt = null,
            info = INFO.encodeToByteArray()
        ).deriveSecretToByteArrayBlocking(shared)
        chacha.keyDecoder()
            .decodeFromByteArrayBlocking(ChaCha20Poly1305.Key.Format.RAW, wrapKey)
            .cipher()
            .encryptWithIvBlocking(nonce, fileKey)
    }

    for (count in RECIPIENT_COUNTS) {
        val recipients = List(count) {
            xdh.generateKeyBlocking().publicKey
        }
        val r = median(iters) {
            rate(BATCH) { repeat(BATCH) { recipients.forEach(::wrapFor) } }
        }
        emit("kn-lib", "envelope", "x25519-hkdf", "wrap", "ops_s", r.toLong(), count)
    }
}
