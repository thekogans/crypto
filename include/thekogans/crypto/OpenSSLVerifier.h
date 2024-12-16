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

#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Verifier.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLVerifier OpenSSLVerifier.h thekogans/crypto/OpenSSLVerifier.h
        ///
        /// \brief
        /// OpenSSLVerifier implements the public key signature verification operation using
        /// various OpenSSL EVP_PKEY keys (RSA, DSA, EC).

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLVerifier : public Verifier {
            /// \brief
            /// OpenSSLVerifier is a \see{Verifier}.
            THEKOGANS_UTIL_DECLARE_DYNAMIC_CREATABLE (OpenSSLVerifier)

            /// \brief
            /// ctor.
            /// \param[in] publicKey_ Public key.
            /// \param[in] messageDigest_ Message digest object.
            OpenSSLVerifier (
                AsymmetricKey::SharedPtr publicKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr);

            virtual bool HasKeyType (const std::string &keyType) override;

            /// \brief
            /// Initialize the verifier and get it ready for the next signature verification.
            /// \param[in] publicKey_ Public key.
            /// \param[in] messageDigest_ Message digest object.
            virtual void Init (
                AsymmetricKey::SharedPtr publicKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr) override;
            /// \brief
            /// Call this method 1 or more time to verify the buffers.
            /// \param[in] buffer Buffer whose signature to verify.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void *buffer,
                std::size_t bufferLength) override;
            /// \brief
            /// Finalize the verification operation.
            /// \param[in] signature Signature to verify.
            /// \param[in] signatureLength Signature length.
            /// \return true == signature matches, false == signature does not match.
            virtual bool Final (
                const void *signature,
                std::size_t signatureLength) override;
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLVerifier_h)
