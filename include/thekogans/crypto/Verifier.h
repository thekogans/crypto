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

#if !defined (__thekogans_crypto_Verifier_h)
#define __thekogans_crypto_Verifier_h

#include <memory>
#include <openssl/evp.h>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct Verifier Verifier.h thekogans/crypto/Verifier.h
        ///
        /// \brief
        /// Verifier implements public key verify operation.

        struct _LIB_THEKOGANS_CRYPTO_DECL Verifier {
            /// \brief
            /// Convenient typedef for std::unique_ptr<Verifier>.
            typedef std::unique_ptr<Verifier> Ptr;

        private:
            /// \brief
            /// Public key.
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
            /// \param[in] key_ Public key.
            /// \param[in] md_ OpenSSL message digest to use.
            Verifier (
                AsymmetricKey::Ptr key_,
                const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD);

            /// \brief
            /// Initialize the verifier and get it ready for the next signature verification.
            void Init ();
            /// \brief
            /// Call this method 1 or more time to verify the buffers.
            /// \param[in] buffer Buffer whose signature to verify.
            /// \param[in] bufferLength Buffer length.
            void Update (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Finalize the verification operation.
            /// \return true == signature matches, false == signature does not match..
            bool Final (
                const void *signature,
                std::size_t signatureLength);

            /// \brief
            /// Verifier is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Verifier)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Verifier_h)
