// Copyright 2016 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_crypto.
//
// libthekogans_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_crypto. If not, see <http://www.gnu.org/licenses/>.

/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#if !defined (__thekogans_crypto_Curve25519_h)
#define __thekogans_crypto_Curve25519_h

#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        // Curve25519.
        //
        // Curve25519 is an elliptic curve. See
        // https://tools.ietf.org/html/draft-irtf-cfrg-curves-11.

        // Ed25519.
        //
        // Ed25519 is a signature scheme using a twisted-Edwards curve that is
        // birationally equivalent to curve25519.

        /// \brief
        /// Sets publicKey and privateKey to a freshly generated, public–private key pair.
        /// \param[out] publicKey New public key.
        /// \param[out] privateKey New private key.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API ED25519_keypair (
            util::ui8 publicKey[32],
            util::ui8 privateKey[64]);

        /// \brief
        /// ED25519_sign sets signature to be a signature of messageLength bytes from
        /// message using privateKey.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API ED25519_sign (
            util::ui8 signature[64],
            const void *message,
            std::size_t messageLength,
            const util::ui8 privateKey[64]);

        /// \brief
        /// ED25519_verify returns one iff signature is a valid signature, by
        /// publicKey of messageLength bytes from message. It returns zero
        /// otherwise.
        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API ED25519_verify (
            const void *message,
            std::size_t messageLength,
            const util::ui8 signature[64],
            const util::ui8 publicKey[32]);

        // X25519.
        //
        // Curve25519 is an elliptic curve. The same name is also sometimes used for
        // the Diffie-Hellman primitive built from it but “X25519” is a more precise
        // name for that, which is the one used here. See http://cr.yp.to/ecdh.html and
        // https://tools.ietf.org/html/draft-irtf-cfrg-curves-11.

        /// \brief
        /// X25519_keypair sets publicKey and privateKey to a freshly
        /// generated, public–private key pair.
        /// \param[out] publicKey New public key.
        /// \param[out] privateKey New private key.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API X25519_keypair (
            util::ui8 publicKey[32],
            util::ui8 privateKey[32]);

        /// \brief
        /// X25519 writes a shared secret to sharedSecret that is calculated from the
        /// given private key and the peer's public key. It returns true on success and
        /// false on error.
        ///
        /// WARNING: Don't use the shared secret directly, rather use a KDF and also
        /// include the two public keys as inputs.
        /// \param[out] sharedSecret Shared secret computed from my private key and
        /// peer's public key.
        /// \param[in] privateKey My provate key.
        /// \param[in] peersPublicKey Peer's public key.
        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API X25519 (
            util::ui8 sharedSecret[32],
            const util::ui8 privateKey[32],
            const util::ui8 peersPublicKey[32]);

        /// \brief
        /// X25519_public_from_private calculates a Diffie-Hellman public value from the
        /// given private key and writes it to publicKey.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API X25519_public_from_private (
            util::ui8 publicKey[32],
            const util::ui8 privateKey[32]);

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Curve25519_h)
