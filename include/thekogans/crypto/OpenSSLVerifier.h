// Copyright 2011 Boris Kogan (boris@thekogans.net)
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

#if !defined (__thekogans_crypto_OpenSSLVerifier_h)
#define __thekogans_crypto_OpenSSLVerifier_h

#include <cstddef>
#include <memory>
#include <openssl/evp.h>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Verifier.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLVerifier OpenSSLVerifier.h thekogans/crypto/OpenSSLVerifier.h
        ///
        /// \brief
        /// Verifier implements the public key signature verification operation using
        /// various OpenSSL EVP_PKEY keys (RSA, DSA, EC).

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLVerifier : public Verifier {
            /// \brief
            /// OpenSSLVerifier is a \see{Verifier}.
            THEKOGANS_CRYPTO_DECLARE_VERIFIER (OpenSSLVerifier)

        private:
            /// \brief
            /// Public key.
            AsymmetricKey::Ptr publicKey;
            /// \brief
            /// OpenSSL message digest object.
            const EVP_MD *md;
            /// \brief
            /// Message digest context.
            MDContext ctx;

        public:
            /// \brief
            /// ctor.
            /// \param[in] publicKey_ Public key.
            /// \param[in] md_ OpenSSL message digest to use.
            OpenSSLVerifier (
                AsymmetricKey::Ptr publicKey_,
                const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD);

            /// \brief
            /// Return the verifier key.
            /// \return \see{AsymmetricKey} key used for signature verification.
            virtual AsymmetricKey::Ptr GetKey () const {
                return publicKey;
            }

            /// \brief
            /// Initialize the verifier and get it ready for the next signature verification.
            virtual void Init ();
            /// \brief
            /// Call this method 1 or more time to verify the buffers.
            /// \param[in] buffer Buffer whose signature to verify.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Finalize the verification operation.
            /// \return true == signature matches, false == signature does not match..
            virtual bool Final (
                const void *signature,
                std::size_t signatureLength);

            /// \brief
            /// OpenSSLVerifier is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (OpenSSLVerifier)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLVerifier_h)
