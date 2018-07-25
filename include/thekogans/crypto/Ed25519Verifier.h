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

#if !defined (__thekogans_crypto_Ed25519Verifier_h)
#define __thekogans_crypto_Ed25519Verifier_h

#include <openssl/evp.h>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Verifier.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/MessageDigest.h"

namespace thekogans {
    namespace crypto {

        /// \struct Ed25519Verifier Ed25519Verifier.h thekogans/crypto/Ed25519Verifier.h
        ///
        /// \brief
        /// Verifier implements the public key signature verification operation
        /// using \see{Ed25519} keys.

        struct _LIB_THEKOGANS_CRYPTO_DECL Ed25519Verifier : public Verifier {
            /// \brief
            /// Ed25519Verifier is a \see{Verifier}.
            THEKOGANS_CRYPTO_DECLARE_VERIFIER (Ed25519Verifier)

        private:
            /// \brief
            /// Public key.
            AsymmetricKey::Ptr publicKey;
            /// \brief
            /// Message digest object.
            MessageDigest messageDigest;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ Public key.
            /// \param[in] md OpenSSL message digest to use.
            Ed25519Verifier (
                AsymmetricKey::Ptr key_,
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD);

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
            /// Ed25519Verifier is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Ed25519Verifier)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Ed25519Verifier_h)
