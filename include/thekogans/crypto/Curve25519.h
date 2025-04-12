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

#include <cstddef>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        // Curve25519.
        //
        // Curve25519 is an elliptic curve. See
        // https://tools.ietf.org/html/draft-irtf-cfrg-curves-11.

        /// \struct Ed25519 Curve25519.h thekogans/crypto/Curve25519.h
        ///
        /// \brief
        /// Ed25519 is a signature scheme using a twisted-Edwards curve that is
        /// birationally equivalent to Curve25519.

        struct _LIB_THEKOGANS_CRYPTO_DECL Ed25519 {
            /// \brief
            /// Private key length.
            static const std::size_t PRIVATE_KEY_LENGTH = 64;
            /// \brief
            /// Public key length.
            static const std::size_t PUBLIC_KEY_LENGTH = 32;
            /// \brief
            /// Signature length.
            static const std::size_t SIGNATURE_LENGTH = 64;

            /// \brief
            /// CreateKey sets privateKey to a freshly generated private key.
            /// \param[out] privateKey New private key.
            /// \return Number of bytes written to privateKey (PRIVATE_KEY_LENGTH).
            static std::size_t CreateKey (util::ui8 privateKey[PRIVATE_KEY_LENGTH]);

            /// \brief
            /// GetPublicKey get's the public key associated with the given private key.
            /// \param[in] privateKey Private key.
            /// \param[out] publicKey Public key to return.
            /// \return Number of bytes written to publicKey (PUBLIC_KEY_LENGTH).
            static std::size_t GetPublicKey (
                const util::ui8 privateKey[PRIVATE_KEY_LENGTH],
                util::ui8 publicKey[PUBLIC_KEY_LENGTH]);

            /// \brief
            /// SignBuffer sets signature to be a signature of bufferLength bytes from
            /// buffer using privateKey.
            /// \param[in] buffer Buffer to sign.
            /// \param[in] bufferLength Buffer length.
            /// \param[in] privateKey Private key used for signing.
            /// \param[out] signature Generated buffer signature.
            /// \return The number of bytes written to signature (SIGNATURE_LENGTH).
            static std::size_t SignBuffer (
                const void *buffer,
                std::size_t bufferLength,
                const util::ui8 privateKey[PRIVATE_KEY_LENGTH],
                util::ui8 signature[SIGNATURE_LENGTH]);

            /// \brief
            /// VerifyBufferSignature returns true iff signature is a valid signature
            /// by publicKey of bufferLength bytes from buffer. It returns false
            /// otherwise.
            /// \param[in] buffer Buffer whose signature to verify.
            /// \param[in] bufferLength Buffer length.
            /// \param[in] publicKey Public key used to verify the buffer signature.
            /// \param[in] signature Signature to verify.
            /// \return true == signature is valid, false == signature is invalid.
            static bool VerifyBufferSignature (
                const void *buffer,
                std::size_t bufferLength,
                const util::ui8 publicKey[PUBLIC_KEY_LENGTH],
                const util::ui8 signature[SIGNATURE_LENGTH]);
        };

        /// \struct X25519 Curve25519.h thekogans/crypto/Curve25519.h
        ///
        /// \brief
        /// Curve25519 is an elliptic curve. The same name is also sometimes used for
        /// the Diffie-Hellman primitive built from it but “X25519” is a more precise
        /// name for that, which is the one used here. See http://cr.yp.to/ecdh.html and
        /// https://tools.ietf.org/html/draft-irtf-cfrg-curves-11.

        struct _LIB_THEKOGANS_CRYPTO_DECL X25519 {
            /// \brief
            /// Private/Public key length.
            static const std::size_t KEY_LENGTH = 32;
            /// \brief
            /// Private key length.
            static const std::size_t PRIVATE_KEY_LENGTH = KEY_LENGTH;
            /// \brief
            /// Public key length.
            static const std::size_t PUBLIC_KEY_LENGTH = KEY_LENGTH;
            /// \brief
            /// Shared secret length.
            static const std::size_t SHARED_SECRET_LENGTH = 32;

            /// \brief
            /// CreateKey sets privateKey to a freshly generated private key.
            /// \param[out] privateKey New private key.
            /// \return Number of bytes written to privateKey (PRIVATE_KEY_LENGTH).
            static std::size_t CreateKey (
                util::ui8 privateKey[PRIVATE_KEY_LENGTH]);

            /// \brief
            /// GetPublicKey calculates a Diffie-Hellman public value from the
            /// given private key and writes it to publicKey.
            /// \param[in] privateKey Private key.
            /// \param[out] publicKey Public key to return.
            /// \return Number of bytes written to publicKey (PUBLIC_KEY_LENGTH).
            static std::size_t GetPublicKey (
                const util::ui8 privateKey[PRIVATE_KEY_LENGTH],
                util::ui8 publicKey[PUBLIC_KEY_LENGTH]);

            /// \brief
            /// ComputeSharedSecret writes a shared secret to sharedSecret that is
            /// calculated from the given private key and the peer's public key.
            /// WARNING: Don't use the shared secret directly, rather use a KDF and also
            /// include the two public keys as inputs.
            /// \param[in] privateKey My private key.
            /// \param[in] peersPublicKey Peer's public key.
            /// \param[out] sharedSecret Shared secret computed from my private key and
            /// peer's public key.
            /// \return The number of bytes written to sharedSecret (SHARED_SECRET_LENGTH).
            static std::size_t ComputeSharedSecret (
                const util::ui8 privateKey[PRIVATE_KEY_LENGTH],
                const util::ui8 peersPublicKey[PUBLIC_KEY_LENGTH],
                util::ui8 sharedSecret[SHARED_SECRET_LENGTH]);
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Curve25519_h)
