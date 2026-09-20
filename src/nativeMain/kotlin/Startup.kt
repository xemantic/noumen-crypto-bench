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

// Support for the `startup` suite, which is timed from the outside: bench.sh
// runs the whole process and measures wall-clock, because the thing being
// measured — runtime bring-up, dynamic loading, provider initialisation — has
// largely happened before any code here could start a timer.
//
// git invokes a remote helper repeatedly, so this cost is paid per invocation.
// It is the reason SCOPE.md requires a native client, and the one number that
// could still undermine that choice if OpenSSL's provider init turned out to
// cost milliseconds.
package com.xemantic.noumen.crypto.bench

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.ChaCha20Poly1305
import dev.whyoleg.cryptography.providers.openssl3.Openssl3

/**
 * Everything a helper invocation must pay before it can seal its first byte:
 * bring up the provider, decode the key, fetch the cipher.
 *
 * Subtracting the `noop` measurement from this one isolates the crypto share.
 */
fun cryptoInit() {
    val key = ByteArray(32)
    CryptographyProvider.Openssl3
        .get(ChaCha20Poly1305)
        .keyDecoder()
        .decodeFromByteArrayBlocking(ChaCha20Poly1305.Key.Format.RAW, key)
        .cipher()
    RawAead("ChaCha20-Poly1305", key).use { it.initEncrypt() }
}
