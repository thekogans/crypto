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

#if !defined (__thekogans_crypto_Signer_h)
#define __thekogans_crypto_Signer_h

#include <memory>
#include <openssl/evp.h>
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct Signer Signer.h thekogans/crypto/Signer.h
        ///
        /// \brief
        /// Signer implements public key sign operation.

        struct _LIB_THEKOGANS_CRYPTO_DECL Signer {
            /// \brief
            /// Convenient typedef for std::unique_ptr<Signer>.
            typedef std::unique_ptr<Signer> Ptr;

        private:
            /// \brief
            /// Private key.
            AsymmetricKey::Ptr key;
            /// \brief
            /// OpenSSL message digest object.
            const EVP_MD *md;
            /// \brief
            /// Message digest context.
            MDContext ctx;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ Private key.
            /// \param[in] md_ OpenSSL message digest to use.
            Signer (
                AsymmetricKey::Ptr key_,
                const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD);

            /// \brief
            /// Initialize the signer and get it ready for the next signature.
            void Init ();
            /// \brief
            /// Call this method 1 or more time to sign the buffers.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            void Update (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Finalize the signing operation and return the signature.
            /// \return Signature.
            util::Buffer::UniquePtr Final ();

            /// \brief
            /// Signer is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Signer)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Signer_h)
