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

#if !defined (__thekogans_crypto_Ed25519Signer_h)
#define __thekogans_crypto_Ed25519Signer_h

#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Signer.h"

namespace thekogans {
    namespace crypto {

        /// \struct Ed25519Signer Ed25519Signer.h thekogans/crypto/Ed25519Signer.h
        ///
        /// \brief
        /// Ed25519Signer implements the public key sign operation using \see{Ed25519} keys.

        struct _LIB_THEKOGANS_CRYPTO_DECL Ed25519Signer : public Signer {
            /// \brief
            /// Ed25519Signer is a \see{util::DynamicCreatable}.
            THEKOGANS_UTIL_DECLARE_DYNAMIC_CREATABLE (Ed25519Signer)

            /// \brief
            /// ctor.
            /// \param[in] privateKey Private key.
            /// \param[in] messageDigest Message digest object.
            Ed25519Signer (
                AsymmetricKey::SharedPtr privateKey = nullptr,
                MessageDigest::SharedPtr messageDigest = nullptr);

            virtual bool HasKeyType (const std::string &keyType) override;

            /// \brief
            /// Initialize the signer and get it ready for the next signature.
            /// \param[in] privateKey_ Private key.
            /// \param[in] messageDigest_ Message digest object.
            virtual void Init (
                AsymmetricKey::SharedPtr privateKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr) override;
            /// \brief
            /// Call this method 1 or more times to sign the buffers.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void *buffer,
                std::size_t bufferLength) override;
            /// \brief
            /// Finalize the signing operation and return the signature.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            virtual std::size_t Final (util::ui8 *signature) override;
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Ed25519Signer_h)
