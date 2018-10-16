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

#if !defined (__thekogans_crypto_OpenSSLSigner_h)
#define __thekogans_crypto_OpenSSLSigner_h

#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Signer.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLSigner OpenSSLSigner.h thekogans/crypto/OpenSSLSigner.h
        ///
        /// \brief
        /// OpenSSLSigner implements the public key sign operation using
        /// various OpenSSL EVP_PKEY keys (RSA, DSA, EC).

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLSigner : public Signer {
            /// \brief
            /// OpenSSLSigner is a \see{Signer}.
            THEKOGANS_CRYPTO_DECLARE_SIGNER (OpenSSLSigner)

            /// \brief
            /// ctor.
            /// \param[in] privateKey Private key.
            /// \param[in] messageDigest Message digest object.
            OpenSSLSigner (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest);

            /// \brief
            /// Initialize the signer and get it ready for the next signature.
            virtual void Init ();
            /// \brief
            /// Call this method 1 or more time to sign the buffers.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Finalize the signing operation and return the signature.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            virtual std::size_t Final (util::ui8 *signature);

            /// \brief
            /// OpenSSLSigner is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (OpenSSLSigner)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLSigner_h)
