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

        enum {
            /// \brief
            /// Public key length.
            ED25519_PUBLIC_KEY_LENGTH = 32,
            /// \brief
            /// Private key length.
            ED25519_PRIVATE_KEY_LENGTH = 64,
            /// \brief
            /// Signature length.
            ED25519_SIGNATURE_LENGTH = 64
        };

        /// \brief
        /// ED25519CreateKeyPair sets publicKey and privateKey to a freshly generated,
        /// public–private key pair.
        /// \param[out] publicKey New public key.
        /// \param[out] privateKey New private key.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API ED25519CreateKeyPair (
            util::ui8 publicKey[ED25519_PUBLIC_KEY_LENGTH],
            util::ui8 privateKey[ED25519_PRIVATE_KEY_LENGTH]);

        /// \brief
        /// ED25519SignBuffer sets signature to be a signature of bufferLength bytes from
        /// buffer using privateKey.
        /// \param[in] buffer Buffer to sign.
        /// \param[in] bufferLength Buffer length.
        /// \param[in] privateKey Private key used for signing.
        /// \param[out] signature Generated buffer signature.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API ED25519SignBuffer (
            const void *buffer,
            std::size_t bufferLength,
            const util::ui8 privateKey[ED25519_PRIVATE_KEY_LENGTH],
            util::ui8 signature[ED25519_SIGNATURE_LENGTH]);

        /// \brief
        /// ED25519VerifyBufferSignature returns true iff signature is a valid signature,
        /// by publicKey of bufferLength bytes from buffer. It returns false
        /// otherwise.
        /// \param[in] signature Signature to verify.
        /// \param[in] buffer Buffer whose signature to verify.
        /// \param[in] bufferLength Buffer length.
        /// \param[in] publicKey Public key used to verify the buffer signature.
        /// \return true == signature is valid, false == signature is invalid.
        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API ED25519VerifyBufferSignature (
            const util::ui8 signature[ED25519_SIGNATURE_LENGTH],
            const void *buffer,
            std::size_t bufferLength,
            const util::ui8 publicKey[ED25519_PUBLIC_KEY_LENGTH]);

        // X25519.
        //
        // Curve25519 is an elliptic curve. The same name is also sometimes used for
        // the Diffie-Hellman primitive built from it but “X25519” is a more precise
        // name for that, which is the one used here. See http://cr.yp.to/ecdh.html and
        // https://tools.ietf.org/html/draft-irtf-cfrg-curves-11.

        enum {
            /// \brief
            /// Public key length.
            X25519_PUBLIC_KEY_LENGTH = 32,
            /// \brief
            /// Private key length.
            X25519_PRIVATE_KEY_LENGTH = 32,
            /// \brief
            /// Shared secret length.
            X25519_SHARED_SECRET_LENGTH = 32
        };

        /// \brief
        /// X25519CreateKeyPair sets publicKey and privateKey to a freshly
        /// generated, public–private key pair.
        /// \param[out] publicKey New public key.
        /// \param[out] privateKey New private key.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API X25519CreateKeyPair (
            util::ui8 publicKey[X25519_PUBLIC_KEY_LENGTH],
            util::ui8 privateKey[X25519_PRIVATE_KEY_LENGTH]);

        /// \brief
        /// X25519ComputeSharedSecret writes a shared secret to sharedSecret that
        /// is calculated from the given private key and the peer's public key.
        ///
        /// WARNING: Don't use the shared secret directly, rather use a KDF and also
        /// include the two public keys as inputs.
        /// \param[out] sharedSecret Shared secret computed from my private key and
        /// peer's public key.
        /// \param[in] privateKey My private key.
        /// \param[in] peersPublicKey Peer's public key.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API X25519ComputeSharedSecret (
            util::ui8 sharedSecret[X25519_SHARED_SECRET_LENGTH],
            const util::ui8 privateKey[X25519_PRIVATE_KEY_LENGTH],
            const util::ui8 peersPublicKey[X25519_PUBLIC_KEY_LENGTH]);

        /// \brief
        /// X25519GetPublicFromPrivate calculates a Diffie-Hellman public value from the
        /// given private key and writes it to publicKey.
        /// \param[out] publicKey Public key to return.
        /// \param[in] privateKey Private key.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API X25519GetPublicFromPrivate (
            util::ui8 publicKey[X25519_PUBLIC_KEY_LENGTH],
            const util::ui8 privateKey[X25519_PRIVATE_KEY_LENGTH]);

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Curve25519_h)
